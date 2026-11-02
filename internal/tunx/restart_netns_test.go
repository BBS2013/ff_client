//go:build linux

package tunx

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"wps_app/internal/config"
	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// 这一组验验收清单里那句「升级重启时的路由与 DNS 恢复」：
// 老进程装完一切就没了，新进程起来时系统里还留着它那份 nat 规则
// ——网卡随 fd 一起消失，iptables 可不会跟着消失。
//
// 为什么已有的那几条还不算这一条：
//   - TestNetnsRepeatedStartStop 走的是 Stop 正常拆除之后再 Start，表里本来就没有残留；
//   - TestNetnsStaleCleanupRemovesRealResidue 验到「CleanupStale 把规则删掉了」就收工，
//     没有接着把新版本那一次启动跑完。
//
// 而升级重启的判据是**终态**：每条劫持规则不多不少各一份，默认路由重新指着新网卡，
// 上游的绕行路由还在物理网卡上，真发一个查询仍然落得进我们的解析器。
// 这个终态不是显然成立的：残留没清掉时 `-A` 会再叠一条一模一样的，
// 双重 DNAT 在内核里完全合法（两个都会命中、计数翻倍），
// 而拆除时 `-D` 一次只删一份——从此每台机器上都留下删不掉的那一份。

const (
	restartGW   = "10.60.0.254" // 物理网关：必须不是本机地址，否则内核拒收绕行路由
	restartUpst = "223.5.5.5"   // 唯一那台 DNS 上游，既要被劫持豁免也要有绕行路由
)

// startHijackTUN 立起一份「全局接管 + DNS 劫持」的真 TUN：网卡、路由、劫持规则都走生产那条路径。
//
// IPv6 关掉：这一组要量的是「残留之上的终态」，而 v6 那套（ip6table_nat 常缺失）
// 有自己的用例，混进来只会让失败说不清是哪一族。
func startHijackTUN(t *testing.T, ctx context.Context, stopOnCleanup, ipv6 bool, extraBypass ...string) *TUN {
	t.Helper()
	yes := true
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.StrictRoute = true
	conf.HijackDNS = &yes
	conf.IPv6 = &ipv6

	direct := outbound.NewDirect(5 * time.Second)
	rt := router.New(mustEngine(t), outbound.NewSet(direct, direct), 5*time.Second)
	rt.SetMode(config.ModeRule)
	tun, err := New(Options{
		Conf:      conf,
		Router:    rt,
		Runner:    ExecRunner{},
		Reg:       metrics.NewRegistry(50, 0),
		Upstreams: []string{restartUpst},
		// Bypass 与生产同源：service 那边交的是「自己的出站目标」（节点 IP + DNS 上游），
		// 少了这一步，我们的解析请求会顺着被自己接管的默认路由掉回 tun，环路。
		// extraBypass 让调用方能塞进「一个双栈节点」这类目标：
		// v6 那一族的绕行路由会不会被错送进 v4 的命令，只有在这种组合里才看得出来。
		Bypass: append([]string{restartUpst}, extraBypass...),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("启用 TUN 失败: %v", err)
	}
	if stopOnCleanup {
		t.Cleanup(func() {
			sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer scancel()
			_ = tun.Stop(sctx)
		})
	}
	return tun
}

// fwWaitDeviceGone 等内核真的把那块网卡摘掉。
//
// 最后一个 fd 关闭之后 netdev 的注销是异步的：紧接着读一次经常还能读到，
// 而按这个名字再建一次会撞 "Device or resource busy"。
// 这个等待既是「进程没了」这半出戏的收尾，也是同一 netns 里下一条用例的前提。
func fwWaitDeviceGone(ctx context.Context, r Runner, name string, budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	for {
		if _, err := r.Run(ctx, Cmd{Bin: "ip", Args: []string{"link", "show", name}}); err != nil {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// fwCountNat 数 nat 表里同时命中所有这些子串的行数。
// 按行而不是按整表 strings.Count：一条规则在一行里，重复挂载就是重复的行。
func fwCountNat(t *testing.T, ctx context.Context, r Runner, subs ...string) int {
	t.Helper()
	var n int
	for _, line := range strings.Split(dnsNatDump(t, ctx, r, "iptables"), "\n") {
		matched := true
		for _, s := range subs {
			if !strings.Contains(line, s) {
				matched = false
				break
			}
		}
		if matched {
			n++
		}
	}
	return n
}

// fwHijackCounts 是「每个协议各一条」那张表的六个判据。
func fwHijackCounts(t *testing.T, ctx context.Context, r Runner) map[string]int {
	t.Helper()
	dns := config.DefaultTUN().DNS
	return map[string]int{
		// 跳转只认目标：装载用的是 -I OUTPUT 1，而 nft 后端回的是 -A OUTPUT，
		// 认前缀等于把这条判据绑死在一种后端上。
		"UDP 劫持跳转": fwCountNat(t, ctx, r, "-j "+DNSChain, "-p udp"),
		"TCP 劫持跳转": fwCountNat(t, ctx, r, "-j "+DNSChain, "-p tcp"),
		"UDP DNAT": fwCountNat(t, ctx, r, "-j DNAT", "--to-destination "+dns+":53", "-p udp"),
		"TCP DNAT": fwCountNat(t, ctx, r, "-j DNAT", "--to-destination "+dns+":53", "-p tcp"),
		"UDP SNAT": fwCountNat(t, ctx, r, "-A POSTROUTING", "-j SNAT", "-p udp"),
		"TCP SNAT": fwCountNat(t, ctx, r, "-A POSTROUTING", "-j SNAT", "-p tcp"),
	}
}

// TestNetnsUpgradeRestartOnTopOfResidue 老进程留下残留 → 新进程 Start → 断言终态。
func TestNetnsUpgradeRestartOnTopOfResidue(t *testing.T) {
	if !fwReady() || !netnsReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1 + 私有 netns）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	r := ExecRunner{}
	if !fwChainUp(t, ctx, r, "iptables") {
		t.Fatal("WPS_FW 开了却建不了链：脚手架不对")
	}
	fwEnsureNIC(t, ctx, r)
	fwMust(t, ctx, r, "ip", "route", "replace", "default", "via", restartGW, "dev", "fwphys0", "metric", "20600")

	// --- 老进程：正常装起一切 ---
	old := startHijackTUN(t, ctx, false, false)
	if got := fwHijackCounts(t, ctx, r); !allExactlyOne(got) {
		t.Fatalf("老进程装完之后劫持规则就不是各一条了：%v", got)
	}

	// --- 老进程没了：网卡随 fd 消失，nat 表里的规则原样留着 ---
	// 先掐掉它的网络监视器：否则它在后台看见「默认路由没了」就会去改路由表，
	// 最后那些断言就说不清是新进程做的还是老进程的幽灵做的。
	old.mu.Lock()
	old.stopNetWatchLocked()
	old.mu.Unlock()
	// 「进程退出」在内核里就一件事：fd 关了。非 persistent 的 tun 网卡在那一刻消失，
	// 而 iptables 与路由表里的规则谁也不会替它删。
	// 这里刻意不跑 down 列表——留的就是那份残留，那是这条用例的全部前提。
	old.stack.Close()
	old.dev.Close()
	if !fwWaitDeviceGone(ctx, r, config.DefaultTUN().Device, 5*time.Second) {
		t.Fatalf("fd 都关了网卡却还在，这一档没演成「进程没了」")
	}
	// 前提检查，不是被测行为：网卡都没了，规则却跟着没了的话，
	// 这个场景在本机上就立不起来，后面每一条断言都会绿得毫无意义。
	if got := fwHijackCounts(t, ctx, r); !allExactlyOne(got) {
		t.Fatalf("网卡消失之后残留规则变成了 %v——「升级重启」这个场景没演成，"+
			"要么内核自己清了（那这条用例该改判据），要么脚手架不对", got)
	}

	// --- 新进程起来：同一份配置，系统里全是上一次留下的东西 ---
	newTun := startHijackTUN(t, ctx, true, false)

	// 1) 终态：每条规则各一份。多出来的那份就是永久删不掉的那份。
	if got := fwHijackCounts(t, ctx, r); !allExactlyOne(got) {
		t.Errorf("重启之后劫持规则不是各一条：%v（残留没清掉时 -A 会再叠一条，"+
			"而拆除时 -D 一次只删一份）", got)
	}

	// 2) 路由恢复：默认路由重新指着新网卡，而且只有一条。
	v4 := fwMust(t, ctx, r, "ip", "route", "show", "default")
	if n := strings.Count(v4, "default dev "+config.DefaultTUN().Device); n != 1 {
		t.Errorf("指向 tun 的默认路由有 %d 条，应为 1:\n%s", n, v4)
	}
	// 上游的绕行路由必须在物理网卡上：少了它，我们发出的解析会顺着默认路由
	// 再掉回自己的 tun，症状是「面板说已接管，谁都解析不出来」。
	// 用 `ip route get` 而不是查表：要的就是内核选出来的那条路，
	// 绕行路由在不在、metric 压不压得过默认路由，一次问清。
	v4Up := fwMust(t, ctx, r, "ip", "route", "get", restartUpst)
	if !strings.Contains(v4Up, " dev fwphys0") || strings.Contains(v4Up, "dev wps-tun") {
		t.Errorf("上游 %s 的解析出口不是物理网卡，而是 %s——重启后我们自己问自己：\n%s",
			restartUpst, config.DefaultTUN().Device, v4Up)
	}
	if st := newTun.Status(); !st.Running || !st.TakeoverV4 {
		t.Errorf("重启后状态不是「已接管」：%+v", st)
	}

	// 3) DNS 真的恢复：一个查询发往 8.8.8.8:53，必须被改写进我们的解析器。
	//    计数器是唯一的判据——没被劫持时这个包会当成普通 UDP 走分流，
	//    那两个计数一动不动，而连接会静静地失败。
	query := queryFor(t, "example.com.", dnsmessage.TypeA)
	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.WriteTo(query, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}); err != nil {
		t.Fatalf("查询没发出去: %v", err)
	}
	var st Status
	if !waitSome(30*time.Second, func() bool {
		st = newTun.Status()
		return st.DNSServed+st.DNSFailed > 0
	}) {
		t.Errorf("查询发往 8.8.8.8:53，却没有落进重启后的解析器（served=%d failed=%d）："+
			"劫持规则在，路却不通，等于整机解析挂", st.DNSServed, st.DNSFailed)
	}
}

// TestNetnsRestartCleanupConverges 是上面那条用例的判据守卫，也是残留清理的下限：
// 把「新进程没清残留就直接装」这一份后果演出来（网卡照生产那样重建一份、
// nat 表里的残留原样留着），确认两件事——
//  1. 计数看得见重复。少了这一步，allExactlyOne 有可能对任何表都返回真，
//     上面那条绿就什么都证明不了。
//  2. 清残留必须把它**收敛回零**，而不是收敛回「还剩一份」。
//     重复挂载时 `-D` 一次只摘一份，剩下那一份让 `-X` 永远失败（链还有引用），
//     残留就此永久化——这正是这条路径存在的理由被自己废掉。
func TestNetnsRestartCleanupConverges(t *testing.T) {
	if !fwReady() || !netnsReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1 + 私有 netns）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if !fwChainUp(t, ctx, r, "iptables") {
		t.Fatal("WPS_FW 开了却建不了链：脚手架不对")
	}
	const device = "wps-tun"
	// 上一份用例（或它清理的收尾）可能还占着这个名字：先等它消失，等不到就自己摘。
	// 直接 Skip 是错的——WPS_FW 开了就说明环境要这些用例真跑，名字被占是脚手架的事。
	if !fwWaitDeviceGone(ctx, r, device, 5*time.Second) {
		fwIdempotent(t, ctx, r, "ip", "link", "del", device)
		if !fwWaitDeviceGone(ctx, r, device, 5*time.Second) {
			t.Fatalf("%s 这个名字被占着且摘不掉：后面建不了网卡，这条用例根本没跑", device)
		}
	}

	plan := dnsNetnsPlan(device)
	up, down, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	// 收尾：失败也要把表清干净——下一份用例不该接着这份表跑。
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer dcancel()
		_ = CleanupStale(dctx, r, os.Geteuid(), device, plan.Address)
		for _, c := range down {
			_, _ = r.Run(dctx, c)
		}
	})

	dnsNetnsTUN(t, ctx, r, device) // 老进程的网卡
	if err := Apply(ctx, r, up); err != nil {
		t.Fatalf("老进程装不上: %v", err)
	}
	if got := fwHijackCounts(t, ctx, r); !allExactly(got, 1) {
		t.Fatalf("装一遍之后就不是各一条了：%v——后面的「重复」无从判起", got)
	}

	// 老进程没了：网卡消失，nat 表里的规则留着。
	fwMust(t, ctx, r, "ip", "link", "del", device)
	if !fwWaitDeviceGone(ctx, r, device, 5*time.Second) {
		t.Fatalf("%s 摘不掉，这一档没演成「进程没了」", device)
	}
	// 新进程建起同名的新网卡，但这一遍**刻意跳过**清残留——要的就是没清的那份表。
	dnsNetnsTUN(t, ctx, r, device)
	if err := Apply(ctx, r, up); err != nil {
		t.Fatalf("重复装载失败: %v", err)
	}
	got := fwHijackCounts(t, ctx, r)
	if allExactly(got, 1) {
		t.Fatalf("重复装载之后规则仍然各一条：判据看不见重复，上面那条用例证明不了任何事：%v", got)
	}
	if !allExactly(got, 2) {
		t.Fatalf("重复装载之后应该是各两份：%v", got)
	}

	// 现在把清残留放回这条路径上：它必须收敛回零，一份都不留。
	CleanupStale(ctx, r, os.Geteuid(), device, plan.Address)
	if got := fwHijackCounts(t, ctx, r); !allExactly(got, 0) {
		t.Errorf("清残留没收敛回零，重复挂载的那一份留在了系统里：%v", got)
	}
	// 链本身也要没了：链还在（-X 失败）就是「删不掉的残留」的本体。
	if dump := dnsNatDump(t, ctx, r, "iptables"); strings.Contains(dump, "-N "+DNSChain) {
		t.Errorf("清残留之后自建链还挂在 nat 表里：\n%s", dump)
	}
}

func allExactly(got map[string]int, want int) bool {
	for _, n := range got {
		if n != want {
			return false
		}
	}
	return true
}

func allExactlyOne(got map[string]int) bool { return allExactly(got, 1) }
