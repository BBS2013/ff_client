//go:build linux

package tunx

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 这一组在真 netns 里把故障断网保护挂进内核，然后用包计数证明它拦的是谁。
//
// 单元测试能证明命令的*形状*对，证不了内核认不认——这个坑这轮已经踩过两次
// （v6 网关带 %网卡、网关写成自己的地址）。保护这类东西更狠：
// 它的命令要是一条都装不上，界面照样能显示「已启用」，
// 而真实的差别只在故障那天出现。所以这里跑的是 iptables 本体，读的是它的计数器。
//
// 开关是 WPS_FW=1，只有 make test-netns-fw 会打开：它需要一个私有的挂载命名空间
// 并在里面把 /run 换成 tmpfs——iptables 开机第一句就要打开 /run/xtables.lock，
// 而那个文件属于宿主里的 root，非特权用户命名空间打不开它，
// 于是过去的结论一直是「netns 里验不了 iptables」。换掉 /run 之后就可以，
// 而且规则只活在这个私有 netns 里，宿主机的表一条都不动（跑完核对过）。
//
// 为什么开了 WPS_FW 还要失败而不是跳过：显式要求了这个环境却装不上链，
// 说明脚手架坏了；把「没验到」写成 skip 正是这一类缺口最难发现的样子。

// fwReady 报告当前环境是否被显式要求跑真防火墙用例。
func fwReady() bool { return os.Getenv("WPS_FW") == "1" }

const (
	fwAllowedAddr = "10.60.0.7" // 在白名单里：SYN 该被放行到规则链外
	fwBlockedAddr = "10.60.0.9" // 不在白名单里：SYN 该被 DROP 计数
	fwAllowed6    = "fd00:99::7"
	fwBlocked6    = "fd00:99::9"
	fwMAC         = "ee:ee:ee:ee:ee:ee"
)

// fwMust 跑一条命令，失败就把输出一起报出来。
func fwMust(t *testing.T, ctx context.Context, r Runner, args ...string) string {
	t.Helper()
	out, err := r.Run(ctx, Cmd{Bin: args[0], Args: args[1:]})
	if err != nil {
		t.Fatalf("%s 失败: %v（输出：%s）", strings.Join(args, " "), err, out)
	}
	return out
}

// fwChainUp 探一次 iptables 到底能不能用。用的是我们自己的链名，探完就删。
func fwChainUp(t *testing.T, ctx context.Context, r Runner, bin string) bool {
	t.Helper()
	_, err := r.Run(ctx, Cmd{Bin: bin, Args: []string{"-t", "filter", "-N", "wps_fw_probe"}})
	if err != nil {
		return false
	}
	_, _ = r.Run(ctx, Cmd{Bin: bin, Args: []string{"-t", "filter", "-X", "wps_fw_probe"}})
	return true
}

// fwRulePkts 从 `iptables -L <chain> -n -v -x` 里挑出一条规则的包数。
// want 是判据子串（目标 + 目的地址那种），找不到就直接失败——
// 读不到规则等于这个证据不存在，不能默默给个 0。
func fwRulePkts(t *testing.T, ctx context.Context, r Runner, bin, want string) uint64 {
	t.Helper()
	out := fwMust(t, ctx, r, bin, "-t", "filter", "-L", KillChain, "-n", "-v", "-x")
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, want) {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			t.Fatalf("%s 的包数读不出来: %q", want, line)
		}
		return n
	}
	t.Fatalf("链里找不到 %q，实际是:\n%s", want, out)
	return 0
}

// fwDial 朝 dst:9 发一次 SYN。成不成功不重要（两个地址都不会有人应答），
// 我们要的只是「有一个包经过了 OUTPUT 并被某条规则计数」。超时给足：
// 被 DROP 的那条会一直等在 SYN-SENT，这正说明它没出去。
func fwDial(dst string) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(dst, "9"), 400*time.Millisecond)
	if err == nil {
		_ = c.Close()
	}
}

// fwPlan 是一份两族齐全、白名单里放好了 fwAllowedAddr 的计划。
func fwPlan() RoutePlan {
	return RoutePlan{
		Device:       "wps-tun",
		Address:      "172.19.0.1/30",
		DNS:          "172.19.0.2",
		FakeIPRange:  "198.18.0.0/15",
		Address6:     "fd00:1::1/64",
		DNS6:         "fd00:1::2",
		FakeIPRange6: "fc00::/18",
		StrictRoute:  true,
		Gateway:      "10.60.0.1",
		Interface:    "fwphys0",
		Gateway6:     "fe80::1",
		Interface6:   "fwphys0",
		Exclude:      []string{fwAllowedAddr + "/32", fwAllowed6 + "/128"},
	}
}

// fwIdempotent 跑一条「再来一遍也不算错」的命令：File exists / 已存在 都算成功。
//
// 必须容重入是因为同一个 netns 会被多个用例共用（go test 里它们跑在一个进程、
// 一个命名空间里），第二个用例看到的网卡和地址是第一个用例留下的。
func fwIdempotent(t *testing.T, ctx context.Context, r Runner, args ...string) {
	t.Helper()
	out, err := r.Run(ctx, Cmd{Bin: args[0], Args: args[1:]})
	if err != nil && !strings.Contains(out, "File exists") && !strings.Contains(out, "already exists") {
		t.Fatalf("%s 失败: %v（输出：%s）", strings.Join(args, " "), err, out)
	}
}

// fwEnsureNIC 建（或复用）那块 dummy，并配上 v4/v6 两个测试网段。
func fwEnsureNIC(t *testing.T, ctx context.Context, r Runner) {
	t.Helper()
	fwIdempotent(t, ctx, r, "ip", "link", "add", "fwphys0", "type", "dummy")
	t.Cleanup(func() {
		_, _ = r.Run(context.Background(), Cmd{Bin: "ip", Args: []string{"link", "del", "fwphys0"}})
	})
	fwIdempotent(t, ctx, r, "ip", "addr", "add", "10.60.0.1/24", "dev", "fwphys0")
	fwIdempotent(t, ctx, r, "ip", "addr", "add", "fd00:99::1/64", "dev", "fwphys0")
	fwMust(t, ctx, r, "ip", "link", "set", "fwphys0", "up")
}

// fwSetupNIC 在 dummy 之外再给两个目标地址钉上静态邻居。
//
// 静态邻居是关键：没有它，发往 .7 的包会卡在地址解析上（EHOSTUNREACH），
// 而发往 .9 的包在 OUTPUT 就被丢了——两条路径的差别就不止「命中哪条规则」。
// 钉上之后两边都会真的把 SYN 送出去，唯一的变量是目的地址在白名单里还是外面。
func fwSetupNIC(t *testing.T, ctx context.Context, r Runner) {
	t.Helper()
	fwEnsureNIC(t, ctx, r)
	for _, a := range []string{fwAllowedAddr, fwBlockedAddr} {
		fwMust(t, ctx, r, "ip", "neigh", "replace", a, "lladdr", fwMAC, "dev", "fwphys0", "nud", "permanent")
	}
	for _, a := range []string{fwAllowed6, fwBlocked6} {
		fwMust(t, ctx, r, "ip", "-6", "neigh", "replace", a, "lladdr", fwMAC, "dev", "fwphys0", "nud", "permanent")
	}
}

// fwHookedOnOutput 断言 OUTPUT 链上只有我们那一条跳转，并且它就是跳转本身。
//
// 为什么不看命令行写法：`-I OUTPUT 1` 与 `-A OUTPUT` 在只有一条规则时是同一个状态，
// 而 nft 后端只肯回后者。这里要的证据是「本机出站确实会先经过我们的链」，
// 至于当初用哪条命令挂上去，不是内核关心的事。
func fwHookedOnOutput(t *testing.T, ctx context.Context, r Runner, bin string) {
	t.Helper()
	out := fwMust(t, ctx, r, bin, "-t", "filter", "-S", "OUTPUT")
	var ours, others int
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "-A OUTPUT -j "+KillChain):
			ours++
		case strings.HasPrefix(line, "-A OUTPUT "), strings.HasPrefix(line, "-I OUTPUT "):
			others++
		}
	}
	if ours == 0 || others != 0 {
		t.Fatalf("%s 的 OUTPUT 上不是只有我们那一条跳转（我们的 %d 条、别人的 %d 条）:\n%s", bin, ours, others, out)
	}
}

// TestNetnsKillSwitchReallyDropsUnlistedEgress 是这一整轮里最硬的一条证据：
// 白名单外的 SYN 被我们自己的规则丢弃，白名单内的被放行，差别只由目的地址决定。
func TestNetnsKillSwitchReallyDropsUnlistedEgress(t *testing.T) {
	if !fwReady() {
		t.Skip("需要私有 netns + 可写的 /run（make test-netns-fw 会打开 WPS_FW）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if !fwChainUp(t, ctx, r, "iptables") || !fwChainUp(t, ctx, r, "ip6tables") {
		t.Fatal("WPS_FW 开了却建不了链：脚手架不对（/run 没换成 tmpfs？），不是可以跳过的情况")
	}
	fwSetupNIC(t, ctx, r)

	kp, err := fwPlan().PlanKill([]string{fwAllowedAddr})
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	if !kp.V4 || !kp.V6 {
		t.Fatalf("两族都该挂上: %+v", kp)
	}
	// 这一步就是「内核认不认我们自己生成的命令行」。
	if err := Apply(ctx, r, kp.Arm); err != nil {
		t.Fatalf("挂保护失败: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		for _, c := range kp.Disarm {
			_, _ = r.Run(dctx, c)
		}
	})

	// 内核里的顺序也是放行走前、DROP 收尾——链建对了但顺序反了就等于全拦。
	order := fwMust(t, ctx, r, "iptables", "-t", "filter", "-S", KillChain)
	iDrop, iAllow := strings.Index(order, "-A "+KillChain+" -j DROP"), strings.Index(order, fwAllowedAddr)
	if iAllow < 0 || iDrop < 0 {
		t.Fatalf("链里少了规则:\n%s", order)
	}
	if iAllow > iDrop {
		t.Errorf("放行规则排在 DROP 之后，等于没放行:\n%s", order)
	}

	dropBefore := fwRulePkts(t, ctx, r, "iptables", "DROP")
	allowBefore := fwRulePkts(t, ctx, r, "iptables", fwAllowedAddr)
	fwDial(fwBlockedAddr)
	if got := fwRulePkts(t, ctx, r, "iptables", "DROP"); got <= dropBefore {
		t.Errorf("白名单外的 SYN 没被 DROP 计数：%d → %d", dropBefore, got)
	}
	if got := fwRulePkts(t, ctx, r, "iptables", fwAllowedAddr); got != allowBefore {
		t.Errorf("被拦的那个目的地址却动了放行计数：%d → %d", allowBefore, got)
	}

	allowBefore = fwRulePkts(t, ctx, r, "iptables", fwAllowedAddr)
	dropBefore = fwRulePkts(t, ctx, r, "iptables", "DROP")
	fwDial(fwAllowedAddr)
	if got := fwRulePkts(t, ctx, r, "iptables", fwAllowedAddr); got <= allowBefore {
		t.Errorf("白名单内的 SYN 没被放行计数：%d → %d", allowBefore, got)
	}
	if got := fwRulePkts(t, ctx, r, "iptables", "DROP"); got != dropBefore {
		t.Errorf("白名单内的地址被 DROP 拦了：%d → %d（放行名单不生效）", dropBefore, got)
	}
}

// TestNetnsKillSwitchV6ReallyDrops 单独看 v6 那一族：
// 它的规则走 ip6tables，放行名单里还多一条 ICMPv6——邻居发现被拦的话
// 整族都会瘫，所以这里既验「v6 的白名单外的确被丢」，也验「v6 的链真的挂着」。
func TestNetnsKillSwitchV6ReallyDrops(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if !fwChainUp(t, ctx, r, "ip6tables") {
		t.Fatal("ip6tables 用不了，v6 这一族的证据无从谈起")
	}
	fwSetupNIC(t, ctx, r)

	kp, err := fwPlan().PlanKill(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, kp.Arm); err != nil {
		t.Fatalf("挂保护失败: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		for _, c := range kp.Disarm {
			_, _ = r.Run(dctx, c)
		}
	})
	// 只断言「OUTPUT 上那条跳就是我们」，不断言 `-I OUTPUT 1` 这个写法：
	// nft 后端在 -S 里会把位置 1 归一化成 -A OUTPUT，两种写法在内核里是同一条规则，
	// 照抄命令行去断言等于把「怎么写的」当成了「装成了什么」。
	fwHookedOnOutput(t, ctx, r, "ip6tables")

	dropBefore := fwRulePkts(t, ctx, r, "ip6tables", "DROP")
	allowBefore := fwRulePkts(t, ctx, r, "ip6tables", fwAllowed6)
	fwDial(fwBlocked6)
	if got := fwRulePkts(t, ctx, r, "ip6tables", "DROP"); got <= dropBefore {
		t.Errorf("v6 白名单外的 SYN 没被丢弃：%d → %d", dropBefore, got)
	}
	fwDial(fwAllowed6)
	if got := fwRulePkts(t, ctx, r, "ip6tables", fwAllowed6); got <= allowBefore {
		t.Errorf("v6 白名单内却没被放行：%d → %d", allowBefore, got)
	}
}

// TestNetnsDisarmRemovesEveryTrace 验摘干净：链没了、OUTPUT 也不再引用它。
//
// 「解除了保护但链还挂着」的后果是出站被一条没人认领的规则压着，
// 而那台机器的用户只会看到「网络断了」，看不到任何软件痕迹。
func TestNetnsDisarmRemovesEveryTrace(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if !fwChainUp(t, ctx, r, "iptables") || !fwChainUp(t, ctx, r, "ip6tables") {
		t.Fatal("iptables 用不了，摘链证据无从谈起")
	}
	fwSetupNIC(t, ctx, r)

	kp, err := fwPlan().PlanKill(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, kp.Arm); err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, kp.Disarm); err != nil {
		t.Fatalf("摘链失败: %v", err)
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		if out := fwMust(t, ctx, r, bin, "-t", "filter", "-S"); strings.Contains(out, KillChain) {
			t.Errorf("%s 里还留着保护链:\n%s", bin, out)
		}
	}
	// 摘了还能再挂上：证明没有残链把 -N 卡住（重挂路径依赖这一步）。
	if err := Apply(ctx, r, kp.Arm); err != nil {
		t.Errorf("摘完再挂失败（残链没清干净？）: %v", err)
	}
}

// fwKillMounts 数 OUTPUT 上挂着断网保护链的跳转有几份。
func fwKillMounts(t *testing.T, ctx context.Context, r Runner, bin string) int {
	t.Helper()
	var n int
	for _, line := range strings.Split(fwMust(t, ctx, r, bin, "-t", "filter", "-S", "OUTPUT"), "\n") {
		if strings.Contains(strings.TrimSpace(line), "-j "+KillChain) {
			n++
		}
	}
	return n
}

// TestNetnsKillReArmKeepsOneMount 重挂（白名单一变就是一次重挂）不许把挂载点叠起来，
// 而摘一次必须一份都不剩。
//
// 为什么这条值得跑在内核里：链里的规则由 -F 清空过，所以「叠了几份」在包计数上
// 几乎看不出来（同一个空链过两遍而已），但它决定拆除能不能收敛——
// -D 一次只摘一份，摘完还剩几份，那条链就永远被引用着，-X 删不掉。
// 用户此刻看到的面板是「断网保护已关闭」，而内核里那条链还挂在 OUTPUT 上。
func TestNetnsKillReArmKeepsOneMount(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if !fwChainUp(t, ctx, r, "iptables") {
		t.Fatal("iptables 用不了，挂载点证据无从谈起")
	}
	fwSetupNIC(t, ctx, r)

	kp, err := fwPlan().PlanKill(nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		if err := Apply(ctx, r, kp.Arm); err != nil {
			t.Fatalf("第 %d 次挂载失败: %v", i, err)
		}
		if n := fwKillMounts(t, ctx, r, "iptables"); n != 1 {
			t.Errorf("挂了 %d 次之后 OUTPUT 上有 %d 份挂载点，应始终只有 1 份", i, n)
		}
	}
	// 拆除走产品那一条：CleanupKill（启动清理与停 TUN 用的都是它）。
	_ = CleanupKill(ctx, r)
	if n := fwKillMounts(t, ctx, r, "iptables"); n != 0 {
		t.Errorf("摘完之后还剩 %d 份挂载点——链被引用着，-X 删不掉它", n)
	}
	if out := fwMust(t, ctx, r, "iptables", "-t", "filter", "-S"); strings.Contains(out, KillChain) {
		t.Errorf("摘完之后 filter 表里还留着保护链:\n%s", out)
	}
}
