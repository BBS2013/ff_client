package tunx

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// 这一组盯住「故障断网保护」生成的命令本身。
//
// 它的危险不在装不上，而在装错方向：白名单少了节点自己的地址，保护就把恢复的路
// 一起锁死；隧道内侧的假 IP 网段没放行，保护连正常通路都掐了；v6 的规则混进
// ip6tables 之外的那张表，内核直接拒掉整次挂载。
// 所以判据都是「规则表读起来对不对」，而不是「有没有报错」。

// killCmds 挑出某一族某一动作的命令，方便按表检查。
func killCmds(cmds []Cmd, bin string) []Cmd {
	var out []Cmd
	for _, c := range cmds {
		if c.Bin == bin {
			out = append(out, c)
		}
	}
	return out
}

// indexOf 返回第一条参数里含 needle 的命令下标，找不到给 -1。
func indexOf(cmds []Cmd, needle string) int {
	for i, c := range cmds {
		if strings.Contains(c.String(), needle) {
			return i
		}
	}
	return -1
}

// killDualPlan 在 dualPlan 之外补上两族的对外出口地址与 v6 的 DNS 落点。
func killDualPlan() RoutePlan {
	p := dualPlan()
	p.DNS6 = "fd00:1::2"
	p.Exclude = []string{"203.0.113.9/32", "2001:db8::9/128", "192.168.5.0/24"}
	return p
}

// TestKillPlanNeedsStrictRoute：选择性 TUN 下拒绝挂载。
//
// 那个模式里直连本来就该从物理网卡出去，挂上 DROP 等于把用户开这个模式
// 想要的功能关掉——这不是「保护没装上」，是根本不该装。
func TestKillPlanNeedsStrictRoute(t *testing.T) {
	p := dualPlan()
	p.StrictRoute = false
	kp, err := p.PlanKill(nil)
	if err == nil {
		t.Fatal("strict_route 关着也生成了保护计划")
	}
	if !kp.Empty() || len(kp.Arm) != 0 {
		t.Fatalf("拒绝时不该有任何命令: %+v", kp.Arm)
	}
	if !strings.Contains(err.Error(), "strict_route") {
		t.Errorf("失败原因没指向 strict_route: %v", err)
	}
}

// TestKillPlanKeepsFamiliesApart 是这一族的老毛病：v6 地址混进 iptables。
//
// 一条 ip6tables 参数写错会让整次挂载失败，而失败的是「保护」这种
// 平时看不出问题的东西——它只在故障那天才说话。
func TestKillPlanKeepsFamiliesApart(t *testing.T) {
	kp, err := killDualPlan().PlanKill(nil)
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	for _, c := range killCmds(kp.Arm, "iptables") {
		s := c.String()
		if strings.Contains(s, "2001:db8") {
			t.Errorf("v6 地址进了 iptables: %s", s)
		}
	}
	for _, c := range killCmds(kp.Arm, "ip6tables") {
		s := c.String()
		if strings.Contains(s, "203.0.113.9") || strings.Contains(s, "192.168.5.0") {
			t.Errorf("v4 网段进了 ip6tables: %s", s)
		}
	}
	if !kp.V4 || !kp.V6 {
		t.Errorf("双栈机器上两族都该挂上: %+v", kp)
	}
}

// TestKillPlanAllowsTunnelAndBackupNodes 检查放行集合与它的顺序。
//
// 顺序是语义本身：DROP 在所有 ACCEPT 之前，白名单就地失效，
// 而且失效得毫无声响——流量照旧通，谁也不会想到是这里。
func TestKillPlanAllowsTunnelAndBackupNodes(t *testing.T) {
	// allow 是调用方补的备用节点地址：它不在 route_exclude 里，
	// 却没有它的话自动切换会被自己的保护拒掉。
	kp, err := killDualPlan().PlanKill([]string{"198.51.100.7", "2001:db8::77"})
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	v4 := indexOf(kp.Arm, "-A wps_app_kill -j DROP")
	if v4 < 0 {
		t.Fatal("没有 DROP 规则")
	}
	must := []string{
		"-d 172.19.0.1/30",   // tun 网卡网段
		"-d 198.18.0.0/15",   // 假 IP 网段：流量进隧道的那条路
		"-d 172.19.0.2/32",   // DNS 劫持落点
		"-d 203.0.113.9/32",  // 活动节点
		"-d 198.51.100.7/32", // 备用节点（allow 传进来的裸 IP 要补成 /32）
	}
	for _, want := range must {
		i := indexOf(kp.Arm, want+" -j ACCEPT")
		if i < 0 {
			t.Errorf("v4 白名单少了 %s", want)
			continue
		}
		if i > v4 {
			t.Errorf("%s 排在 DROP 之后，等于没放行", want)
		}
	}
	// v6 那一族单独看：DROP 是这一族自己的边界，跨族比下标没有意义。
	v6 := killCmds(kp.Arm, "ip6tables")
	v6drop := indexOf(v6, "-A wps_app_kill -j DROP")
	if v6drop < 0 {
		t.Fatal("v6 没有 DROP")
	}
	for _, want := range []string{"-d fd00:1::1/64", "-d fc00::/18", "-d fd00:1::2/128",
		"-d 2001:db8::9/128", "-d 2001:db8::77/128"} {
		i := indexOf(v6, want+" -j ACCEPT")
		if i < 0 {
			t.Errorf("v6 白名单少了 %s", want)
			continue
		}
		if i > v6drop {
			t.Errorf("%s 排在 v6 的 DROP 之后，等于没放行", want)
		}
	}
	// 挂载点必须是 OUTPUT 的第 1 条：OUTPUT 默认策略是 ACCEPT，
	// 排在别人的放行规则后面，这条 DROP 永远轮不到。
	if indexOf(kp.Arm, "-I OUTPUT 1 -j wps_app_kill") < 0 {
		t.Error("没有把链挂到 OUTPUT 第 1 条")
	}
}

// TestKillPlanV6DNSLanding 检查 v6 的劫持落点用了 /128 而不是 /32。
//
// 照抄掩码会让 v6 落点变成一段网域（放行范围悄悄变大），
// 而 ip6tables 会直接拒绝这个写法。
func TestKillPlanV6DNSLanding(t *testing.T) {
	p := killDualPlan()
	p.DNS6 = "fd00:1::2"
	kp, err := p.PlanKill(nil)
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	if i := indexOf(kp.Arm, "-d fd00:1::2/128 -j ACCEPT"); i < 0 {
		t.Error("没有放行 v6 的 DNS 劫持落点")
	} else if !strings.HasPrefix(kp.Arm[i].String(), "ip6tables") {
		t.Errorf("v6 落点进了 %s: %s", kp.Arm[i].Bin, kp.Arm[i])
	}
}

// TestKillPlanSkipsFamilyWithoutEgress：节点只有 v4 地址时，v6 那一族不挂保护。
//
// 看起来更安全的做法是「v6 一个都不放行，全 DROP」，但那会把将来切到一个
// v6 节点的路也锁掉：白名单是挂上去那一刻算的，而新节点的地址那时候还不知道。
// 宁可这一族没保护，并把它如实报出来。
func TestKillPlanSkipsFamilyWithoutEgress(t *testing.T) {
	p := dualPlan()
	p.Exclude = []string{"203.0.113.9/32", "192.168.5.0/24"}
	kp, err := p.PlanKill(nil)
	if err != nil {
		t.Fatalf("v4 还能挂，不该整体失败: %v", err)
	}
	if !kp.V4 {
		t.Error("v4 该挂上")
	}
	if kp.V6 {
		t.Error("没有 v6 出口地址时不该挂 v6 保护")
	}
	if !strings.Contains(kp.V6Reason, "IPv6") {
		t.Errorf("没挂上的族必须给出原因，界面要能说清: %+v", kp)
	}
	for _, c := range killCmds(kp.Arm, "ip6tables") {
		t.Errorf("v6 没挂上却生成了命令: %s", c)
	}
}

// TestKillPlanRefusesWhenNothingIsArmable：既没有 v4 出口也没有 v6 出口 → 明确失败。
func TestKillPlanRefusesWhenNothingIsArmable(t *testing.T) {
	p := dualPlan()
	p.Exclude = nil
	kp, err := p.PlanKill(nil)
	if err == nil {
		t.Fatal("一个出口地址都没有，却报告挂载成功")
	}
	if !kp.Empty() {
		t.Errorf("什么都没挂上却报告 V4/V6: %+v", kp)
	}
	if !strings.Contains(kp.Error(), "IPv4") || !strings.Contains(kp.Error(), "IPv6") {
		t.Errorf("两族的原因都要说清: %s", kp.Error())
	}
}

// TestKillPlanV6OnlyMachine：只有 v6 出口的机器上，v6 要能单独挂上。
//
// 这一条和接管本身同构——v4 缺席是常态的镜像（纯 v6 网络），
// 不能因为 v4 装不上就把 v6 一起放弃。
func TestKillPlanV6OnlyMachine(t *testing.T) {
	p := killDualPlan()
	p.Gateway, p.Interface = "", ""
	kp, err := p.PlanKill(nil)
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	if kp.V4 || len(killCmds(kp.Arm, "iptables")) != 0 {
		t.Error("没有 v4 出口却生成了 iptables 规则")
	}
	if !kp.V6 {
		t.Error("v6 该挂上保护")
	}
}

// TestKillPlanAllowsLinkBootstrap：回环与「让网络能回来」的那几种。
//
// 少了回环，面板自己的端口与本地 SOCKS 入站一起断；少了 DHCP，
// 网络恢复时这台机器拿不到地址——保护就变成了故障本身。
func TestKillPlanAllowsLinkBootstrap(t *testing.T) {
	kp, err := killDualPlan().PlanKill(nil)
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	v4 := killCmds(kp.Arm, "iptables")
	drop := indexOf(v4, "-j DROP")
	if drop < 0 {
		t.Fatal("v4 没有 DROP")
	}
	for _, want := range []string{"-o lo -j ACCEPT", "--dport 67:68 -j ACCEPT"} {
		i := indexOf(v4, want)
		if i < 0 {
			t.Errorf("v4 少了 %s", want)
		} else if i > drop {
			t.Errorf("%s 排在 DROP 之后", want)
		}
	}
	v6 := killCmds(kp.Arm, "ip6tables")
	v6drop := indexOf(v6, "-j DROP")
	for _, want := range []string{"-o lo -j ACCEPT", "-p ipv6-icmp -j ACCEPT"} {
		i := indexOf(v6, want)
		if i < 0 {
			t.Errorf("v6 少了 %s", want)
		} else if i > v6drop {
			t.Errorf("%s 排在 DROP 之后", want)
		}
	}
	// ICMPv6 是 v6 的地基（邻居发现、PTMU），不能被写成 v4 的规则。
	for _, c := range v4 {
		if strings.Contains(c.String(), "ipv6-icmp") {
			t.Errorf("icmpv6 规则混进了 iptables: %s", c)
		}
	}
}

// TestKillPlanDedupesSharedAddress：同一个地址来自两处时只放行一次。
//
// 节点地址会同时出现在 route_exclude、bypass 和 allow 里。不去重的话
// 每次重挂都在同一条链上叠一行，而日志里全是看不出区别的行。
func TestKillPlanDedupesSharedAddress(t *testing.T) {
	p := killDualPlan()
	// 203.0.113.9 已经在 Exclude 里，allow 再给一次裸 IP（写法不同也算同一个）。
	kp, err := p.PlanKill([]string{"203.0.113.9", "203.0.113.9/32"})
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	n := 0
	for _, c := range killCmds(kp.Arm, "iptables") {
		if strings.Contains(c.String(), "-d 203.0.113.9/32 -j ACCEPT") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("同一个地址生成了 %d 条放行规则", n)
	}
}

// TestKillDisarmIsCompleteAndForgiving 检查摘链的形状。
//
// 每一步都必须 Optional：保护可能只挂上了一族，也可能早就被清理过。
// 一次「解除保护」失败会留下一串 DROP，而用户此刻最需要的正是流量恢复。
// 摘的顺序也要先解挂载再删链——链还被引用时 -X 会被内核拒绝。
func TestKillDisarmIsCompleteAndForgiving(t *testing.T) {
	kp, err := killDualPlan().PlanKill(nil)
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	if len(kp.Disarm) == 0 {
		t.Fatal("没有摘链命令")
	}
	for _, c := range kp.Disarm {
		if !c.Optional {
			t.Errorf("摘链这一步不允许失败，会把保护永久留下: %s", c)
		}
	}
	i := indexOf(kp.Disarm, "-D OUTPUT -j wps_app_kill")
	if i < 0 {
		t.Fatal("没有从 OUTPUT 摘掉链")
	}
	for _, want := range []string{"-F wps_app_kill", "-X wps_app_kill"} {
		if j := indexOf(kp.Disarm, want); j < i {
			t.Errorf("%s 排在摘挂载之前", want)
		}
	}
	// 摘的两族都在：只挂上一族时，另一族的摘除会因为「本来就没有」而失败，
	// 那是上面 Optional 已经容下的情况，不该少生成。
	if len(killCmds(kp.Disarm, "iptables")) == 0 || len(killCmds(kp.Disarm, "ip6tables")) == 0 {
		t.Error("摘链必须覆盖两族")
	}
}

// TestKillArmHeadIsReentrant 检查重复挂载的入口。
//
// 上一次异常退出会留下残链：-N 报 already exists 是预期的，不能因此拒绝挂保护；
// -F 把残链里的旧规则清掉，白名单才是这一轮算出来的那一份；
// 而挂载点必须先摘再挂——`-I OUTPUT 1` 是无条件往前插，重挂不摘就把跳转叠起来，
// 拆除时 -D 一次只删一份，剩下那些让链永远被引用着、-X 删不掉。
// 判据按内容找而不是按下标：这三条的相对顺序才是语义，写死下标只会挡住正常的增删。
func TestKillArmHeadIsReentrant(t *testing.T) {
	kp, err := killDualPlan().PlanKill(nil)
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	idx := func(cmds []Cmd, want ...string) []int {
		var got []int
		for i, c := range cmds {
			s := c.String()
			ok := true
			for _, w := range want {
				if !strings.Contains(s, w) {
					ok = false
					break
				}
			}
			if ok {
				got = append(got, i)
			}
		}
		return got
	}
	for _, bin := range []string{"iptables", "ip6tables"} {
		c := killCmds(kp.Arm, bin)
		if len(c) < 3 {
			t.Fatalf("%s 的规则太少: %v", bin, c)
		}
		unmount := idx(c, "-D OUTPUT", "-j wps_app_kill")
		mount := idx(c, "-I OUTPUT", "-j wps_app_kill")
		create := idx(c, "-N wps_app_kill")
		flush := idx(c, "-F wps_app_kill")
		if len(unmount) != 1 || len(mount) != 1 || len(create) != 1 || len(flush) != 1 {
			t.Fatalf("%s 的挂载点/建链/清链步骤不是各一条：摘 %v 挂 %v 建 %v 清 %v",
				bin, unmount, mount, create, flush)
		}
		if !c[unmount[0]].Optional {
			t.Errorf("%s 先摘挂载点这一步不允许失败（本来没挂过就是失败）: %s", bin, c[unmount[0]])
		}
		if unmount[0] > mount[0] {
			t.Errorf("%s 先挂后摘，叠上去的那份马上就被删了：挂载点摘不掉第二次", bin)
		}
		if !c[create[0]].TolerateExists {
			t.Errorf("%s 建链没容忍残链: %s", bin, c[create[0]])
		}
		if !c[flush[0]].Optional {
			t.Errorf("%s 清链不允许失败: %s", bin, c[flush[0]])
		}
	}
}

// TestKillChainNameIsNotTheDNSChain：两张表生命周期不同，不能同名。
//
// 劫持链跟着 TUN 启停拆，保护链只在故障期间挂着。同名会让拆 TUN 顺手
// 把保护摘掉（或反过来），而故障期间的 DROP 规则本来正是那一段时间要的东西。
func TestKillChainNameIsNotTheDNSChain(t *testing.T) {
	if KillChain == DNSChain {
		t.Fatal("保护链与 DNS 链同名")
	}
	kp, err := killDualPlan().PlanKill(nil)
	if err != nil {
		t.Fatalf("PlanKill: %v", err)
	}
	for _, c := range kp.Arm {
		if strings.Contains(c.String(), DNSChain) {
			t.Errorf("保护命令碰了 DNS 链: %s", c)
		}
		if c.Bin == "" {
			t.Errorf("生成了没有可执行文件的命令（会被 runner 当成命令去 exec）: %+v", c)
		}
	}
}

// ---------- TUN 侧：真正执行挂/摘 ----------

// runningKillTUN 造一个「正在运行、计划已生效」的 TUN：ArmKill 只在有网卡有路由时
// 才有意义，而 Start 需要真网卡，所以这里直接把状态摆好。
func runningKillTUN(t *testing.T, runner Runner) *TUN {
	t.Helper()
	tun := newDualTUN(t, runner)
	tun.running = true
	tun.plan = killDualPlan()
	return tun
}

func TestArmKillRunsRulesThroughTheLocalRunner(t *testing.T) {
	r := &recorderRunner{}
	tun := runningKillTUN(t, r)
	if err := tun.ArmKill(context.Background(), []string{"198.51.100.7"}); err != nil {
		t.Fatalf("ArmKill: %v", err)
	}
	st := tun.Kill()
	if !st.Armed || !st.V4 || !st.V6 || st.Reason != "" {
		t.Fatalf("挂载状态报错: %+v", st)
	}
	ran := strings.Join(r.snapshot(), "\n")
	for _, want := range []string{
		"iptables -t filter -I OUTPUT 1 -j wps_app_kill",
		"iptables -t filter -A wps_app_kill -d 198.51.100.7/32 -j ACCEPT",
		"ip6tables -t filter -A wps_app_kill -j DROP",
	} {
		if !strings.Contains(ran, want) {
			t.Errorf("没执行 %s", want)
		}
	}
	// 界面读的是 Status，四个字段必须都带上。
	s := tun.Status()
	if !s.KillArmed || !s.KillV4 || !s.KillV6 || s.KillReason != "" {
		t.Errorf("Status 没带上保护状态: %+v", s)
	}
}

// TestArmKillFailureRollsBackAndReportsNotInEffect 是最要紧的一条。
//
// 半条链意味着「界面说保护开着，实际出站照旧裸奔」——所以失败必须回滚、
// 必须把原因留下、必须让 Status 报出「未生效」。
func TestArmKillFailureRollsBackAndReportsNotInEffect(t *testing.T) {
	jump := "iptables -t filter -I OUTPUT 1 -j wps_app_kill"
	r := &recorderRunner{fail: map[string]error{jump: errors.New("no chain by that name")}}
	tun := runningKillTUN(t, r)
	err := tun.ArmKill(context.Background(), nil)
	if err == nil {
		t.Fatal("挂载失败却报告成功")
	}
	st := tun.Kill()
	if st.Armed {
		t.Error("失败不能留下一条「已挂上」的保护")
	}
	if !strings.Contains(st.Reason, "未生效") {
		t.Errorf("原因里要写清未生效: %q", st.Reason)
	}
	ran := strings.Join(r.snapshot(), "\n")
	if !strings.Contains(ran, "iptables -t filter -D OUTPUT -j wps_app_kill") {
		t.Error("失败后没回滚，半成品链会留在机器上")
	}
	if tun.Status().KillArmed {
		t.Error("Status 仍报告保护已挂上")
	}
}

// TestDisarmKillClearsBothFamiliesAndTheState 检查摘链。
//
// 没挂过时也要成功：这一步的语义是「出站不再受我们限制」，
// 报一个「本来就没有」的错会让调用方以为摘失败，从而不敢放行流量。
func TestDisarmKillClearsBothFamiliesAndTheState(t *testing.T) {
	r := &recorderRunner{}
	tun := runningKillTUN(t, r)
	ctx := context.Background()
	if err := tun.ArmKill(ctx, nil); err != nil {
		t.Fatal(err)
	}
	r.ran = nil
	if err := tun.DisarmKill(); err != nil {
		t.Fatalf("没挂过时摘除也应成功: %v", err)
	}
	ran := strings.Join(r.snapshot(), "\n")
	for _, want := range []string{
		"iptables -t filter -D OUTPUT -j wps_app_kill",
		"iptables -t filter -X wps_app_kill",
		"ip6tables -t filter -D OUTPUT -j wps_app_kill",
		"ip6tables -t filter -X wps_app_kill",
	} {
		if !strings.Contains(ran, want) {
			t.Errorf("没执行 %s", want)
		}
	}
	if tun.Kill().Armed || tun.Kill().Reason != "" {
		t.Errorf("摘完要把状态清干净: %+v", tun.Kill())
	}
}

// TestStopDisarmsKill 是「关了代理反而上不了网」那个形状的防线。
//
// 停在拆路由之前摘链：那条链拦的是本机所有出站，TUN 拆干净了却把 DROP 留下，
// 用户看到的就是断网，而且猜不到是这道保护。
func TestStopDisarmsKill(t *testing.T) {
	r := &recorderRunner{}
	tun := runningKillTUN(t, r)
	ctx := context.Background()
	if err := tun.ArmKill(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if err := tun.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	ran := strings.Join(r.snapshot(), "\n")
	if !strings.Contains(ran, "iptables -t filter -D OUTPUT -j wps_app_kill") {
		t.Error("停止时没有摘掉出站保护链")
	}
	if tun.Kill().Armed {
		t.Error("停止后仍报告保护挂着")
	}
}

// TestArmKillGoesThroughHelper 保证配了提权 helper 时规则由 root 侧执行。
//
// 面板以桌面用户跑（这是常态），自己执行 iptables 会全军覆没；
// 而「保护没装上」在故障现场看起来只是又一次切换失败。
func TestArmKillGoesThroughHelper(t *testing.T) {
	helperRunner := &recorderRunner{}
	devFD, _ := socketPair(t)
	tun := runningKillTUN(t, &recorderRunner{})
	// 只给 v4 出口：这正是「节点没有 v6 地址」的常见形状，helper 应该只挂 v4，
	// 并把 v6 那一族为什么没挂一起报回来。
	v4only := killDualPlan()
	v4only.Exclude = []string{"203.0.113.9/32"}
	tun.plan = v4only
	tun.helper = helperTestServer(&HelperServer{
		Runner:  helperRunner,
		Open:    func(string) (int, error) { return devFD, nil },
		MTU:     func(string) (uint32, error) { return 1500, nil },
		Timeout: 5 * time.Second,
	})
	if err := tun.ArmKill(context.Background(), []string{"198.51.100.7"}); err != nil {
		t.Fatalf("经 helper 挂载失败: %v", err)
	}
	ran := strings.Join(helperRunner.snapshot(), "\n")
	if !strings.Contains(ran, "iptables -t filter -I OUTPUT 1 -j wps_app_kill") {
		t.Errorf("helper 没执行挂载: %s", ran)
	}
	st := tun.Kill()
	if !st.Armed || !st.V4 {
		t.Errorf("helper 的结果没回到状态里: %+v", st)
	}
	if st.V6 {
		t.Error("这份计划没有 v6 出口，不该报告 v6 已保护")
	}
	if !strings.Contains(st.Reason, "IPv6") {
		t.Errorf("没挂上的那一族必须给出原因: %q", st.Reason)
	}
}

// TestKillRequestRejectsNonAddressAllow 检查白名单入参的校验。
//
// 这些值最后会成为 root 执行的 `iptables ... -d <值>`。exec 不经 shell，
// 注入不成立，但一个以 "-" 开头的值会被 iptables 当成选项——那是把参数
// 塞进了 root 的命令行，必须拒绝而不是静丢掉（静丢掉会把节点锁在门外）。
func TestKillRequestRejectsNonAddressAllow(t *testing.T) {
	plan := killDualPlan()
	for _, bad := range []string{"-j", "ACCEPT", "not-an-ip", "192.168.5.0/33"} {
		if err := KillRequest(plan, os.Geteuid(), []string{bad}, true).validate(); err == nil {
			t.Errorf("白名单里的 %q 应该被拒绝", bad)
		}
	}
	if err := KillRequest(plan, os.Geteuid(), []string{"198.51.100.7", "2001:db8::9/128"}, true).validate(); err != nil {
		t.Errorf("合法地址被拒: %v", err)
	}
}

// TestCleanupKillCoversBothFamilies 是异常退出后的那道兜底。
func TestCleanupKillCoversBothFamilies(t *testing.T) {
	r := &recorderRunner{}
	done := CleanupKill(context.Background(), r)
	if len(done) != len(KillDisarmCmds()) {
		t.Errorf("每一步都该报回来: %v", done)
	}
	ran := strings.Join(r.snapshot(), "\n")
	for _, want := range []string{"iptables", "ip6tables", "-X wps_app_kill", "-D OUTPUT -j wps_app_kill"} {
		if !strings.Contains(ran, want) {
			t.Errorf("残留清理少了 %s", want)
		}
	}
}

// TestArmKillNeedsRunningTUN：没在运行时不许挂。
//
// 那时既没有绕行路由也没有网卡，白名单算不出正确的集合，
// 挂上去只会让一次「TUN 没起来」再叠一层「出站被锁」。
func TestArmKillNeedsRunningTUN(t *testing.T) {
	tun := newDualTUN(t, &recorderRunner{})
	err := tun.ArmKill(context.Background(), nil)
	if err == nil {
		t.Fatal("TUN 没在运行时也挂了保护")
	}
	if !strings.Contains(err.Error(), "没在运行") {
		t.Errorf("原因要指向 TUN 未运行: %v", err)
	}
}
