//go:build linux

package tunx

import (
	"context"
	"os"
	"strings"
	"testing"
)

// 这一组在真网络命名空间里跑真的 ip 命令，验的是「内核收不收这条命令」。
//
// 单测里的替身只会验证命令的形状，形状对了内核不认的情况它照样绿。
// 而这一组踩过两次：v6 网关写成 fe80::5%网卡 被 iproute2 整条拒掉，
// 网关被当成 local 地址时又报 "Gateway can not be a local address"。
// 两条都是「看着对、内核不吃」，只有真跑一遍才会知道。
//
// 开关是显式的环境变量 WPS_NETNS=1：这类用例会建网卡、改默认路由，
// 在开发机的宿主 netns 里跑就会动到用户自己的网络。
// 只有 make test-offline（unshare -rn 起的私有 netns）会打开它。

// netnsReady 报告当前环境是否允许跑会改路由的用例。
func netnsReady() bool { return os.Getenv("WPS_NETNS") == "1" }

// runIP 跑一条 ip 命令，失败就把输出带出来。
func runIP(t *testing.T, runner Runner, args ...string) string {
	t.Helper()
	out, err := runner.Run(context.Background(), Cmd{Bin: "ip", Args: args})
	if err != nil {
		t.Fatalf("ip %s 失败: %v (%s)", strings.Join(args, " "), err, out)
	}
	return out
}

// TestNetnsDualStackTakeover 在真 netns 里把两族默认路由都接管一次，
// 再拆一次，验的是内核里的路由表，不是命令的字符串。
func TestNetnsDualStackTakeover(t *testing.T) {
	if !netnsReady() {
		t.Skip("需要私有网络命名空间（make test-offline 会打开 WPS_NETNS）")
	}
	ctx := context.Background()
	runner := ExecRunner{}

	// 物理网卡：一块 dummy。v4 给个地址，v6 只给自动生成的链路本地地址——
	// 网关不能是本机地址，否则内核会报 "Gateway can not be a local address"。
	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "add", "phys0", "type", "dummy"}}); err != nil {
		t.Skipf("建不了虚拟网卡（多半没有 CAP_NET_ADMIN）: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "phys0"}})
	})
	runIP(t, runner, "addr", "add", "192.168.5.42/24", "dev", "phys0")
	runIP(t, runner, "link", "set", "phys0", "up")

	// tun 网卡。生产里由 openLinkDevice 或 helper 建，这里用 ip tuntap 造一块同等的。
	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"tuntap", "add", "dev", "wps-tun", "mode", "tun"}}); err != nil {
		t.Skipf("建不了 tun 网卡（多半没有 /dev/net/tun）: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "wps-tun"}})
	})

	plan := RoutePlan{
		Device:       "wps-tun",
		Address:      "172.19.0.1/30",
		FakeIPRange:  "198.18.0.0/15",
		Address6:     "fd00:1::1/64",
		FakeIPRange6: "fc00::/18",
		MTU:          1500,
		StrictRoute:  true,
		Gateway:      "192.168.5.1",
		Interface:    "phys0",
		Gateway6:     "fe80::5",
		Interface6:   "phys0",
		Exclude:      []string{"192.168.5.1/32", "2001:db8::1/128"},
	}

	// 顺序与 provision 一致：v4 那组 → v6 假 IP → v6 接管。
	up4, _, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, runner, up4); err != nil {
		t.Fatalf("v4 那组装不上: %v", err)
	}
	up6, _, err := plan.PlanV6()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, runner, up6); err != nil {
		t.Fatalf("v6 假 IP 那组装不上: %v", err)
	}
	upRoute6, downRoute6, err := plan.PlanV6Route()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, runner, upRoute6); err != nil {
		t.Fatalf("v6 接管那组装不上: %v", err)
	}

	v4 := runIP(t, runner, "route", "show")
	v6 := runIP(t, runner, "-6", "route", "show")
	for _, want := range []string{
		"default dev wps-tun",
		"198.18.0.0/15 dev wps-tun",
		"224.0.0.0/4 dev phys0",
		// /32 的主机路由在表里显示时不带掩码长度。
		"192.168.5.1 via 192.168.5.1 dev phys0",
	} {
		if !strings.Contains(v4, want) {
			t.Errorf("v4 路由表里没有 %q:\n%s", want, v4)
		}
	}
	for _, want := range []string{
		"default dev wps-tun",
		"fc00::/18 dev wps-tun",
		"ff00::/8 dev phys0",
		"2001:db8::1 via fe80::5 dev phys0",
	} {
		if !strings.Contains(v6, want) {
			t.Errorf("v6 路由表里没有 %q:\n%s", want, v6)
		}
	}

	// 拆：v6 接管先拆，再拆 v6 假 IP，最后拆 v4。
	_, down4, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	_, down6, err := plan.PlanV6()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range append(append(downRoute6, down6...), down4...) {
		if _, err := runner.Run(ctx, c); err != nil && !c.Optional {
			t.Errorf("拆除 %s 失败: %v", c.Desc, err)
		}
	}

	v4 = runIP(t, runner, "route", "show")
	v6 = runIP(t, runner, "-6", "route", "show")
	if strings.Contains(v4, "default dev wps-tun") {
		t.Errorf("拆完还有 v4 默认路由:\n%s", v4)
	}
	if strings.Contains(v6, "default dev wps-tun") {
		t.Errorf("拆完还有 v6 默认路由:\n%s", v6)
	}
	if strings.Contains(v4, "224.0.0.0/4 dev phys0") {
		t.Errorf("拆完还有 v4 组播路由:\n%s", v4)
	}
	if strings.Contains(v6, "ff00::/8 dev phys0") {
		t.Errorf("拆完还有 v6 组播路由:\n%s", v6)
	}
	if strings.Contains(v6, "2001:db8::1 via fe80::5 dev phys0") {
		t.Errorf("拆完还有 v6 绕行路由:\n%s", v6)
	}
}

// TestNetnsGatewayChangeRepinsBypassRoutes 换网关之后，绕行路由要自己改钉。
//
// 这是「网络变化后恢复」的核心场景，也是最容易坏的地方：
// 绕行路由是按当时的网关钉死的，换了网关之后它还指着旧出口，
// 于是发往节点的包被送到一个不存在的出口——面板上只剩一句「节点超时」。
//
// 这里在真 netns 里换掉默认路由，然后让监视器跑两轮
// （第一轮看到变化、第二轮确认落定），最后验内核里的路由表。
func TestNetnsGatewayChangeRepinsBypassRoutes(t *testing.T) {
	if !netnsReady() {
		t.Skip("需要私有网络命名空间（make test-offline 会打开 WPS_NETNS）")
	}
	ctx := context.Background()
	runner := ExecRunner{}

	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "add", "phys0", "type", "dummy"}}); err != nil {
		t.Skipf("建不了虚拟网卡: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "phys0"}})
	})
	// 两个网段都在同一张卡上：换网关之后新网关仍然在链路内，
	// 否则内核会以 invalid gateway 拒绝新路由，测的就不是我们的问题了。
	runIP(t, runner, "addr", "add", "192.168.5.42/24", "dev", "phys0")
	runIP(t, runner, "addr", "add", "192.168.9.42/24", "dev", "phys0")
	runIP(t, runner, "link", "set", "phys0", "up")
	runIP(t, runner, "route", "add", "default", "via", "192.168.5.1", "dev", "phys0", "metric", "20600")

	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"tuntap", "add", "dev", "wps-tun", "mode", "tun"}}); err != nil {
		t.Skipf("建不了 tun 网卡: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "wps-tun"}})
	})

	plan := RoutePlan{
		Device:      "wps-tun",
		Address:     "172.19.0.1/30",
		MTU:         1500,
		StrictRoute: true,
		Gateway:     "192.168.5.1",
		Interface:   "phys0",
		Exclude:     []string{"192.168.5.1/32"},
	}
	up, _, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, runner, up); err != nil {
		t.Fatalf("装不上绕行路由: %v", err)
	}

	// 装好之后表里有两条默认路由：我们那条（dev wps-tun）与物理那条。
	// 探测必须跳过我们那条，否则会把 tun 当成出口网卡。
	tun := newWatchTUN(t, runner)
	tun.plan = plan
	tun.initNetWatch(plan)

	st := probeRouteState(ctx, runner, "wps-tun")
	if st.Gateway != "192.168.5.1" || st.Interface != "phys0" {
		t.Fatalf("探测把我们自己的 tun 当成了出口: %+v", st)
	}

	// 换网关：物理那条默认路由指向新网关。
	runIP(t, runner, "route", "del", "default", "via", "192.168.5.1", "dev", "phys0", "metric", "20600")
	runIP(t, runner, "route", "add", "default", "via", "192.168.9.1", "dev", "phys0", "metric", "20600")

	// 第一轮：看到变化了，但还没落定，不动手。
	tun.checkNetworkChanged(ctx)
	if tun.routeFixes.Load() != 0 {
		t.Fatalf("第一轮就动手了: %d", tun.routeFixes.Load())
	}
	// 第二轮：落定了，重钉。
	tun.checkNetworkChanged(ctx)
	if tun.routeFixes.Load() != 1 {
		t.Fatalf("落定后没有重钉: %d", tun.routeFixes.Load())
	}

	v4 := runIP(t, runner, "route", "show")
	if !strings.Contains(v4, "192.168.5.1 via 192.168.9.1 dev phys0") {
		t.Errorf("绕行路由还指着旧网关:\n%s", v4)
	}
	if strings.Contains(v4, "192.168.5.1 via 192.168.5.1 dev phys0") {
		t.Errorf("旧网关的那条还在:\n%s", v4)
	}
}

// 这是「重复启停」那条验收项的落点：每轮装上去的东西每轮都要拆干净，
// 否则第二次启停会撞上 File exists，而那类报错会把真正的原因盖住。
// TestNetnsIPv6OnlyTakeover 只有 v6 默认路由时，v6 接管照样要成立。
//
// 这一族独立于 v4：只有 v6 的机器（容器、部分校园网、企业专线）
// 之前会直接起不来——v4 那一族缺网关就把整个 TUN 掀了。
func TestNetnsIPv6OnlyTakeover(t *testing.T) {
	if !netnsReady() {
		t.Skip("需要私有网络命名空间（make test-offline 会打开 WPS_NETNS）")
	}
	ctx := context.Background()
	runner := ExecRunner{}

	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "add", "phys0", "type", "dummy"}}); err != nil {
		t.Skipf("建不了虚拟网卡: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "phys0"}})
	})
	runIP(t, runner, "link", "set", "phys0", "up")
	// 只有 v6：没有 v4 默认路由，也没有 v4 地址。
	runIP(t, runner, "-6", "route", "add", "default", "via", "fe80::5", "dev", "phys0", "metric", "20600")

	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"tuntap", "add", "dev", "wps-tun", "mode", "tun"}}); err != nil {
		t.Skipf("建不了 tun 网卡: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "wps-tun"}})
	})

	plan := RoutePlan{
		Device:       "wps-tun",
		Address:      "172.19.0.1/30",
		Address6:     "fd00:1::1/64",
		FakeIPRange6: "fc00::/18",
		MTU:          1500,
		StrictRoute:  true,
		Gateway6:     "fe80::5",
		Interface6:   "phys0",
		Exclude:      []string{"2001:db8::1/128"},
	}
	up4, _, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, runner, up4); err != nil {
		t.Fatalf("装不上 v4 那一组: %v", err)
	}
	up6, _, err := plan.PlanV6()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, runner, up6); err != nil {
		t.Fatalf("装不上 v6 假 IP 那一组: %v", err)
	}
	upRoute6, _, err := plan.PlanV6Route()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, runner, upRoute6); err != nil {
		t.Fatalf("装不上 v6 接管那一组: %v", err)
	}

	v4 := runIP(t, runner, "route", "show")
	v6 := runIP(t, runner, "-6", "route", "show")
	if strings.Contains(v4, "default dev wps-tun") {
		t.Errorf("没有 v4 网关却接管了 v4 默认路由:\n%s", v4)
	}
	if !strings.Contains(v6, "default dev wps-tun") {
		t.Errorf("v6 默认路由没接管:\n%s", v6)
	}
	if !strings.Contains(v6, "2001:db8::1 via fe80::5 dev phys0") {
		t.Errorf("v6 绕行路由没装上:\n%s", v6)
	}
}

func TestNetnsRepeatedStartStop(t *testing.T) {
	if !netnsReady() {
		t.Skip("需要私有网络命名空间（make test-offline 会打开 WPS_NETNS）")
	}
	ctx := context.Background()
	runner := ExecRunner{}

	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "add", "phys0", "type", "dummy"}}); err != nil {
		t.Skipf("建不了虚拟网卡: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "phys0"}})
	})
	runIP(t, runner, "addr", "add", "192.168.5.42/24", "dev", "phys0")
	runIP(t, runner, "link", "set", "phys0", "up")
	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"tuntap", "add", "dev", "wps-tun", "mode", "tun"}}); err != nil {
		t.Skipf("建不了 tun 网卡: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "wps-tun"}})
	})

	plan := RoutePlan{
		Device:       "wps-tun",
		Address:      "172.19.0.1/30",
		FakeIPRange:  "198.18.0.0/15",
		Address6:     "fd00:1::1/64",
		FakeIPRange6: "fc00::/18",
		MTU:          1500,
		StrictRoute:  true,
		Gateway:      "192.168.5.1",
		Interface:    "phys0",
		Gateway6:     "fe80::5",
		Interface6:   "phys0",
		Exclude:      []string{"192.168.5.1/32", "2001:db8::1/128"},
	}

	for round := 1; round <= 2; round++ {
		up4, _, err := plan.Plan()
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, runner, up4); err != nil {
			t.Fatalf("第 %d 轮 v4 装不上: %v", round, err)
		}
		up6, _, err := plan.PlanV6()
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, runner, up6); err != nil {
			t.Fatalf("第 %d 轮 v6 装不上: %v", round, err)
		}
		upR6, downR6, err := plan.PlanV6Route()
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, runner, upR6); err != nil {
			t.Fatalf("第 %d 轮 v6 接管装不上: %v", round, err)
		}
		_, down6, err := plan.PlanV6()
		if err != nil {
			t.Fatal(err)
		}
		_, down4, err := plan.Plan()
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range append(append(downR6, down6...), down4...) {
			if _, err := runner.Run(ctx, c); err != nil && !c.Optional {
				t.Errorf("第 %d 轮拆除 %s 失败: %v", round, c.Desc, err)
			}
		}
	}

	v4 := runIP(t, runner, "route", "show")
	v6 := runIP(t, runner, "-6", "route", "show")
	if strings.Contains(v4, "default dev wps-tun") || strings.Contains(v6, "default dev wps-tun") {
		t.Errorf("两轮之后还有默认路由指着 tun:\nv4:\n%s\nv6:\n%s", v4, v6)
	}
}

// TestNetnsWifiDropThenReconnect 把「Wi-Fi 断开再回来」这一条走完整：
// 断的时候不许乱动，回来的时候必须把绕行路由改钉到新网关。
//
// 断的时候乱动会怎样：没有网关就钉不了绕行路由，而把现有的拆掉
// 只会让「刚恢复的网络」又断一次——恢复反而更慢。
func TestNetnsWifiDropThenReconnect(t *testing.T) {
	if !netnsReady() {
		t.Skip("需要私有网络命名空间（make test-offline 会打开 WPS_NETNS）")
	}
	ctx := context.Background()
	runner := ExecRunner{}

	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "add", "phys0", "type", "dummy"}}); err != nil {
		t.Skipf("建不了虚拟网卡: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "phys0"}})
	})
	runIP(t, runner, "addr", "add", "192.168.5.42/24", "dev", "phys0")
	runIP(t, runner, "addr", "add", "192.168.9.42/24", "dev", "phys0")
	runIP(t, runner, "link", "set", "phys0", "up")
	runIP(t, runner, "route", "add", "default", "via", "192.168.5.1", "dev", "phys0", "metric", "20600")

	if out, err := runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"tuntap", "add", "dev", "wps-tun", "mode", "tun"}}); err != nil {
		t.Skipf("建不了 tun 网卡: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "del", "wps-tun"}})
	})

	plan := RoutePlan{
		Device:      "wps-tun",
		Address:     "172.19.0.1/30",
		FakeIPRange: "198.18.0.0/15",
		MTU:         1500,
		StrictRoute: true,
		Gateway:     "192.168.5.1",
		Interface:   "phys0",
		Exclude:     []string{"192.168.5.1/32"},
	}
	up, _, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, runner, up); err != nil {
		t.Fatalf("装不上绕行路由: %v", err)
	}

	tun := newWatchTUN(t, runner)
	tun.plan = plan
	tun.initNetWatch(plan)

	// --- Wi-Fi 断了：物理默认路由整条消失 ---
	runIP(t, runner, "route", "del", "default", "via", "192.168.5.1", "dev", "phys0", "metric", "20600")
	tun.checkNetworkChanged(ctx)
	tun.checkNetworkChanged(ctx)
	if tun.routeFixes.Load() != 0 {
		t.Fatalf("断网时不该重钉，却钉了 %d 次", tun.routeFixes.Load())
	}
	v4 := runIP(t, runner, "route", "show")
	if !strings.Contains(v4, "192.168.5.1 via 192.168.5.1 dev phys0") {
		t.Errorf("断网时把现有绕行路由拆掉了:\n%s", v4)
	}

	// --- 网回来了，但换了个网关（换了个热点）---
	runIP(t, runner, "route", "add", "default", "via", "192.168.9.1", "dev", "phys0", "metric", "20600")
	tun.checkNetworkChanged(ctx) // 看到变化，还没落定
	tun.checkNetworkChanged(ctx) // 落定 → 重钉
	if tun.routeFixes.Load() != 1 {
		t.Fatalf("网络回来后没有重钉绕行路由: %d", tun.routeFixes.Load())
	}
	v4 = runIP(t, runner, "route", "show")
	if !strings.Contains(v4, "192.168.5.1 via 192.168.9.1 dev phys0") {
		t.Errorf("绕行路由没跟上新的出口:\n%s", v4)
	}
}
