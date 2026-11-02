//go:build linux

package tunx

import (
	"context"
	"strings"
	"testing"
	"time"
)

// 这一组盯 tolerates() 里那几句措辞本身。
//
// 为什么措辞需要用例：判据是「命令失败了，但从内核的角度看效果已经达成」，
// 而"达成"这件事只能从工具打印的那句话认出来。认漏一种说法的后果不是报错变多，
// 是**正确状态被判成失败**——断网保护那一次，-N 报 "Chain already exists." 不被认，
// 于是每一次白名单变化都把刚挂上的保护回滚掉，界面上写的是「未生效」。
// 以前这些串只出现在我自己写的脱机用例里：那只能证明解析器认得我认识的那种写法。
// 这里让真工具把话说出来，判据必须接得住；接不住的那一句，红在这里而不是红在用户机器上。

const tolDevice = "toltest0"

// tolRun 跑一条命令，把「成没成」与「说了什么」一起交回来。
func tolRun(t *testing.T, ctx context.Context, r Runner, args ...string) (string, error) {
	t.Helper()
	return r.Run(ctx, Cmd{Bin: args[0], Args: args[1:]})
}

// tolRepeat 重复一条本来就不该重复的命令，返回第二次的输出。
// 第一次必须成功（否则演的是另一回事），第二次必须失败（否则没什么可容忍的）。
func tolRepeat(t *testing.T, ctx context.Context, r Runner, args ...string) string {
	t.Helper()
	if out, err := tolRun(t, ctx, r, args...); err != nil {
		t.Fatalf("第一次 %s 就该成功: %v（%s）", strings.Join(args, " "), err, out)
	}
	out, err := tolRun(t, ctx, r, args...)
	if err == nil {
		t.Fatalf("%s 重复执行居然也成功了：判据无从判起（输出：%s）", strings.Join(args, " "), out)
	}
	return out
}

// TestNetnsToleranceAcceptsWhatTheToolsActuallySay 三种「已经达成」的现场，
// 都要被现成的判据认下来。
func TestNetnsToleranceAcceptsWhatTheToolsActuallySay(t *testing.T) {
	if !netnsReady() {
		t.Skip("需要私有网络命名空间（make test-offline / test-netns-fw 会打开 WPS_NETNS）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}

	if out, err := tolRun(t, ctx, r, "ip", "link", "add", tolDevice, "type", "dummy"); err != nil && !strings.Contains(out, "File exists") {
		t.Skipf("建不了虚拟网卡（多半没有 CAP_NET_ADMIN）: %v（%s）", err, out)
	}
	t.Cleanup(func() {
		_, _ = r.Run(context.Background(), Cmd{Bin: "ip", Args: []string{"link", "del", tolDevice}})
	})
	if out, err := tolRun(t, ctx, r, "ip", "link", "set", tolDevice, "up"); err != nil {
		t.Fatalf("把 %s 拉起来失败: %v（%s）", tolDevice, err, out)
	}

	// 1) 重复挂地址：Plan 里两条 addr add 都写着 TolerateExists，
	//    而内核在这里说的是 "already assigned"——不是 "File exists"。
	addrArgs := []string{"ip", "addr", "add", "10.98.0.1/24", "dev", tolDevice}
	out := tolRepeat(t, ctx, r, addrArgs...)
	exists := Cmd{Bin: "ip", Args: addrArgs, Desc: "配置网卡地址", TolerateExists: true}
	if !tolerates(exists, out) {
		t.Errorf("重复挂地址被判成失败（内核说的是 %q）：网卡上已经有这个地址时重装本该当成功", strings.TrimSpace(out))
	}

	// 2) 重复加路由：这一句是 "RTNETLINK answers: File exists"。
	routeArgs := []string{"ip", "route", "add", "10.98.60.0/24", "dev", tolDevice}
	out = tolRepeat(t, ctx, r, routeArgs...)
	if !tolerates(Cmd{Bin: "ip", Args: routeArgs, TolerateExists: true}, out) {
		t.Errorf("重复加路由被判成失败（内核说的是 %q）", strings.TrimSpace(out))
	}

	// 3) 网卡已经没了之后再拆：协议栈销毁链路就在拆除命令之前，
	//    这三句说的都是 Cannot find device ——那正是我们要的效果已经达成。
	if out, err := tolRun(t, ctx, r, "ip", "link", "del", tolDevice); err != nil {
		t.Fatalf("先把网卡删掉失败，第三段无从判起: %v（%s）", err, out)
	}
	for _, args := range [][]string{
		{"ip", "addr", "del", "10.98.0.1/24", "dev", tolDevice},
		{"ip", "route", "del", "10.98.60.0/24", "dev", tolDevice},
		{"ip", "link", "set", tolDevice, "down"},
	} {
		out, err := tolRun(t, ctx, r, args...)
		if err == nil {
			t.Errorf("%s：网卡都没了，命令却报成功——判据接下来要对着没有失败的状态做事", strings.Join(args, " "))
			continue
		}
		gone := Cmd{Bin: args[0], Args: args[1:], TolerateMissingDevice: tolDevice}
		if !tolerates(gone, out) {
			t.Errorf("网卡没了这句没被认下来（跑的是 %s，内核说的是 %q）——那三次假错就是这么来的",
				strings.Join(args, " "), strings.TrimSpace(out))
		}
	}
}

// TestNetnsToleranceDoesNotSwallowRealFailure 反向守一句：
// 「容忍」不能退化成「这一整步都不算数」。真实的失败必须仍然报出来，
// 否则会留下「默认路由交给 tun 了、防环路却没装上」那种自环状态。
func TestNetnsToleranceDoesNotSwallowRealFailure(t *testing.T) {
	if !netnsReady() {
		t.Skip("需要私有网络命名空间（make test-offline / test-netns-fw 会打开 WPS_NETNS）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r := ExecRunner{}

	// 网关 192.0.2.99 在这个 netns 里没有任何链路可达：内核必定拒收。
	// 这条不给 skip 的余地——对照组一成立不了、二没人会去看一条 skip 的日志。
	args := []string{"ip", "route", "add", "10.98.77.0/24", "via", "192.0.2.99"}
	out, err := tolRun(t, ctx, r, args...)
	if err == nil {
		t.Fatalf("这台内核收了一条网关不可达的路由（%s）：对照组立不起来，判据可能正在吞真失败", out)
	}
	if strings.Contains(out, "File exists") || strings.Contains(out, "already exists") || strings.Contains(out, "already assigned") {
		t.Errorf("一个真实的失败说的话落在「已达成」那三个措辞里，判据会把它吞掉: %q", strings.TrimSpace(out))
	}
	// Optional=false 的命令必须把这种失败原样报出去（这才是回滚的触发条件）。
	if tolerates(Cmd{Bin: args[0], Args: args[1:], TolerateExists: true}, out) {
		t.Errorf("TolerateExists 把「网络不可达」也放过了: %q", strings.TrimSpace(out))
	}
	// 点名了另一块网卡的 TolerateMissingDevice 也不该认领这句失败。
	if tolerates(Cmd{Bin: args[0], Args: args[1:], TolerateMissingDevice: "wps-tun"}, out) {
		t.Errorf("TolerateMissingDevice 认领了一句与网卡无关的失败: %q", strings.TrimSpace(out))
	}
}
