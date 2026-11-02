package tunx

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// 这一组盯住「全局接管到底接管了什么」。
//
// 之前只有 v4 默认路由交给 tun，v6 一点没碰：面板上看着是全局模式，
// 实际上 v6 流量照旧从物理网卡出去，绕开了规则与节点——
// 用户以为在隧道里的东西，其实有一半在明面上。
//
// 所以这里的要求是两条：
//  1. 两族默认路由各自装、各自成败，界面上分别说清楚；
//  2. 绕行路由必须按地址族分开装：v6 网段混进 v4 命令里，内核会直接拒掉，
//     而那条命令失败会掀翻整个 TUN 启动。

// dualPlan 造一份两族齐全的计划：v4 网关 192.168.5.1，v6 网关是 RA 发的链路本地地址。
func dualPlan() RoutePlan {
	return RoutePlan{
		Device:       "wps-tun",
		Address:      "172.19.0.1/30",
		DNS:          "172.19.0.2",
		FakeIPRange:  "198.18.0.0/15",
		Address6:     "fd00:1::1/64",
		FakeIPRange6: "fc00::/18",
		MTU:          1500,
		StrictRoute:  true,
		Gateway:      "192.168.5.1",
		Interface:    "wlp3s0f0",
		Gateway6:     "fe80::5",
		Interface6:   "wlp3s0f0",
	}
}

// TestParseDefaultRoute6 v6 的默认路由也要能认出来。
//
// 它和 v4 的形状一样，但网关多半是 fe80:: 开头的链路本地地址，
// 而且可能压根没有网关（点对点链路）——所以判据是网卡名而不是网关。
func TestParseDefaultRoute6(t *testing.T) {
	dr, ok := ParseDefaultRoute("default via fe80::5 dev wlp3s0f0 proto ra metric 20600 pref medium\n")
	if !ok {
		t.Fatal("没认出 v6 默认路由")
	}
	if dr.Gateway != "fe80::5" || dr.Iface != "wlp3s0f0" {
		t.Fatalf("v6 默认路由解析错了: %+v", dr)
	}
	// 没有网关的 v6 默认路由也是有效的默认路由。
	dr, ok = ParseDefaultRoute("default dev ppp0 scope link\n")
	if !ok || dr.Gateway != "" || dr.Iface != "ppp0" {
		t.Fatalf("无网关的 v6 默认路由解析错了: %+v %v", dr, ok)
	}
	// 非默认路由不能被当成默认路由。
	if _, ok := ParseDefaultRoute("2409:8a1e::/64 dev wlp3s0f0 proto ra metric 600\n"); ok {
		t.Fatal("普通网段被当成了默认路由")
	}
}

// TestSplitExcludeByFamily 排除网段必须按地址族拆开。
//
// 这是双栈节点真正会踩的坑：节点域名解析出 v4 与 v6 两个地址，
// 两个都进了排除列表，而排除列表以前整体交给 v4 那组命令。
func TestSplitExcludeByFamily(t *testing.T) {
	v4, v6 := splitExclude([]string{
		"192.168.5.1/32",  // 节点 v4
		"2001:db8::1/128", // 节点 v6
		"223.5.5.5",       // 裸 IP 的 v4 上游
		"2400:3200::1",    // 裸 IP 的 v6 上游
		"10.0.0.0/8",      // 本地网段
		"fe80::/10",       // 链路本地
		"这不是网段",           // 垃圾
	})
	wantV4 := []string{"192.168.5.1/32", "223.5.5.5/32", "10.0.0.0/8"}
	wantV6 := []string{"2001:db8::1/128", "2400:3200::1/128", "fe80::/10"}
	if strings.Join(v4, ",") != strings.Join(wantV4, ",") {
		t.Errorf("v4 那一组 = %v, want %v", v4, wantV4)
	}
	if strings.Join(v6, ",") != strings.Join(wantV6, ",") {
		t.Errorf("v6 那一组 = %v, want %v", v6, wantV6)
	}
}

// TestPlanV4GroupHasNoV6Command 挡住那个会让整机代理陪葬的 bug：
// v6 网段混进 v4 的 `ip route add` 命令。
//
// 内核对 "ip route add 2001:db8::1/128 via 192.168.5.1" 的回答是 invalid gateway，
// 而这条命令不是 Optional——它失败就是整个 TUN 启动失败。
func TestPlanV4GroupHasNoV6Command(t *testing.T) {
	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	up, _, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range up {
		joined := strings.Join(c.Args, " ")
		if strings.Contains(joined, "2001:db8::1") || strings.Contains(joined, ":") {
			t.Errorf("v4 那组混进了 v6 参数: %s %s", c.Bin, joined)
		}
	}
	if !hasCmd(up, "ip", "route add 192.168.5.1/32 via 192.168.5.1 dev wlp3s0f0") {
		t.Errorf("v4 排除路由没装上: %v", up)
	}
}

// TestPlanV6RouteInstallsV6DefaultRoute v6 接管这一组要有三样东西：
// v6 绕行路由、组播留在物理网卡、v6 默认路由交给 tun。
func TestPlanV6RouteInstallsV6DefaultRoute(t *testing.T) {
	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	up, _, err := plan.PlanV6Route()
	if err != nil {
		t.Fatal(err)
	}
	// v6 网关写纯地址，不带 %网卡 的 zone 后缀：
	// iproute2 的 via 参数只认纯地址，带 zone 会被整条拒掉。
	if !hasCmd(up, "ip", "-6 route add 2001:db8::1/128 via fe80::5 dev wlp3s0f0") {
		t.Errorf("v6 绕行路由没装上: %v", up)
	}
	if !hasCmd(up, "ip", "-6 route add default dev wps-tun") {
		t.Errorf("v6 默认路由没交给 tun: %v", up)
	}
	if !hasCmd(up, "ip", "-6 route add ff00::/8 dev wlp3s0f0 metric 1000") {
		t.Errorf("v6 组播没留在物理网卡: %v", up)
	}
	// v4 网段不该出现在这一组里。
	for _, c := range up {
		if strings.Contains(strings.Join(c.Args, " "), "192.168.5.1/32") {
			t.Errorf("v6 那组混进了 v4 网段: %s", c.String())
		}
	}
}

// TestPlanV6RouteSkippedWithoutGateway 没有 v6 网关就不接管。
//
// 这时候装上 v6 默认路由是有害的：我们钉不回绕行路由，
// 自己发往 v6 节点的包也会被自己抓回来，形成环路。
// 宁可让 v6 走系统默认出口，也不能让整机 v6 卡死。
func TestPlanV6RouteSkippedWithoutGateway(t *testing.T) {
	plan := dualPlan()
	plan.Gateway6 = ""
	up, down, err := plan.PlanV6Route()
	if err != nil {
		t.Fatal(err)
	}
	if len(up) != 0 || len(down) != 0 {
		t.Fatalf("没有 v6 网关却生成了命令: %v", up)
	}
}

// TestPlanV6RouteNeedsStrictRoute 不用 strict_route 就不该碰默认路由。
func TestPlanV6RouteNeedsStrictRoute(t *testing.T) {
	plan := dualPlan()
	plan.StrictRoute = false
	up, _, err := plan.PlanV6Route()
	if err != nil {
		t.Fatal(err)
	}
	if len(up) != 0 {
		t.Fatalf("没开 strict_route 却装了 v6 默认路由: %v", up)
	}
}

// TestPlanV6RouteDownIsInverseOfUp 拆的时候要能把它装过的东西都拆掉。
//
// 漏拆的后果不是「多一条路由」：v6 默认路由还指着 tun，
// 而网卡一消失，内核把这条路由留着就等于把整机 v6 流量指向黑洞。
func TestPlanV6RouteDownIsInverseOfUp(t *testing.T) {
	plan := dualPlan()
	plan.Exclude = []string{"2001:db8::1/128"}
	up, down, err := plan.PlanV6Route()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range up {
		if c.Desc == "" {
			t.Fatalf("有命令没写说明: %s", c.String())
		}
	}
	if !hasCmd(down, "ip", "-6 route del default dev wps-tun") {
		t.Errorf("没撤销 v6 默认路由: %v", down)
	}
	if !hasCmd(down, "ip", "-6 route del 2001:db8::1/128 via fe80::5 dev wlp3s0f0") {
		t.Errorf("没撤销 v6 绕行路由: %v", down)
	}
	if !hasCmd(down, "ip", "-6 route del ff00::/8 dev wlp3s0f0 metric 1000") {
		t.Errorf("没撤销 v6 组播路由: %v", down)
	}
}

// TestV4GroupDownRemovesWhatItAdded v4 那一组也要能拆干净，
// 顺便盯住组播路由的 metric：拆的时候必须带上同样的 metric，
// 否则删的是内核自己那条组播路由。
func TestV4GroupDownRemovesWhatItAdded(t *testing.T) {
	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32"}
	up, down, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !hasCmd(up, "ip", "route add 224.0.0.0/4 dev wlp3s0f0 metric 1000") {
		t.Errorf("v4 组播没留在物理网卡: %v", up)
	}
	if !hasCmd(down, "ip", "route del 224.0.0.0/4 dev wlp3s0f0 metric 1000") {
		t.Errorf("v4 组播路由没撤: %v", down)
	}
	if !hasCmd(down, "ip", "route del default dev wps-tun") {
		t.Errorf("v4 默认路由没撤: %v", down)
	}
	if !hasCmd(down, "ip", "route del 192.168.5.1/32 via 192.168.5.1 dev wlp3s0f0") {
		t.Errorf("v4 绕行路由没撤: %v", down)
	}
}

// dualRunner 是一份会同时回答 v4 与 v6 默认路由查询的替身。
type dualRunner struct {
	ran    []Cmd
	failOn string
	// v6Default 为空表示本机没有 v6 默认路由。
	v6Default string
	// v4Default 非空时取代那句「默认路由在物理卡上」：用来演「内核说接管了」
	// 与「DHCP 把默认路由抢回去了」两种现场——接管那两格现在读的是内核，
	// 所以这两种现场必须由这里给。
	v4Default string
}

func (r *dualRunner) Run(_ context.Context, c Cmd) (string, error) {
	r.ran = append(r.ran, c)
	joined := strings.Join(c.Args, " ")
	if r.failOn != "" && strings.Contains(joined, r.failOn) {
		return "", errors.New("模拟失败")
	}
	switch joined {
	case "-o route show default":
		if r.v4Default != "" {
			return r.v4Default, nil
		}
		return "default via 192.168.5.1 dev wlp3s0f0 proto dhcp metric 20600", nil
	case "-6 -o route show default":
		return r.v6Default, nil
	}
	return "", nil
}

func (r *dualRunner) has(bin, argsJoined string) bool {
	return hasCmd(r.ran, bin, argsJoined)
}

// newDualTUN 起一个开着 strict_route 与 IPv6 的 TUN。
func newDualTUN(t *testing.T, runner Runner) *TUN {
	t.Helper()
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.StrictRoute = true
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(2*time.Second), outbound.NewDirect(2*time.Second)), 2*time.Second)
	tun, err := New(Options{
		Conf:      conf,
		Router:    rt,
		Runner:    runner,
		Upstreams: []string{"223.5.5.5"},
		// 一个双栈节点 + 一个 v4 的 DNS 上游：
		// service.selfEgressIPs 交给 bypass 的正是这两类地址（节点 + 上游），
		// 我们的出站不能被自己抓回去。
		Bypass: []string{"192.168.5.1", "2001:db8::1", "223.5.5.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tun
}

// TestBuildPlanDiscoversBothFamilies 两族默认路由要分别探测。
func TestBuildPlanDiscoversBothFamilies(t *testing.T) {
	r := &dualRunner{v6Default: "default via fe80::5 dev wlp3s0f0 proto ra metric 20600 pref medium"}
	tun := newDualTUN(t, r)
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Gateway != "192.168.5.1" || plan.Interface != "wlp3s0f0" {
		t.Fatalf("v4 默认路由没探到: %+v", plan)
	}
	if plan.Gateway6 != "fe80::5" || plan.Interface6 != "wlp3s0f0" {
		t.Fatalf("v6 默认路由没探到: %+v", plan)
	}
	// 排除列表里两族都有：节点的 v4 与 v6 地址、v4 的 DNS 上游。
	v4, v6 := splitExclude(plan.Exclude)
	if len(v4) != 2 || len(v6) != 1 {
		t.Fatalf("排除网段按族拆开不对: v4=%v v6=%v", v4, v6)
	}
}

// TestBuildPlanWithoutV6DefaultRoute 本机没有 v6 默认路由是常态，
// 此时 v6 接管不成，但 v4 那一路必须照常可用。
func TestBuildPlanWithoutV6DefaultRoute(t *testing.T) {
	r := &dualRunner{v6Default: ""}
	tun := newDualTUN(t, r)
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatalf("没有 v6 默认路由不该让整个 TUN 起不来: %v", err)
	}
	if plan.Gateway6 != "" || plan.Interface6 != "" {
		t.Fatalf("没有 v6 默认路由却探出了网关: %+v", plan)
	}
	up, _, err := plan.PlanV6Route()
	if err != nil {
		t.Fatal(err)
	}
	if len(up) != 0 {
		t.Fatalf("没有 v6 网关却生成了 v6 接管命令: %v", up)
	}
}

// TestApplyV6RouteRollsBackOnFailure v6 接管装不上时要撤干净并如实报告没接管。
func TestApplyV6RouteRollsBackOnFailure(t *testing.T) {
	r := &dualRunner{
		v6Default: "default via fe80::5 dev wlp3s0f0 proto ra metric 20600 pref medium",
		failOn:    "-6 route add default",
	}
	tun := newDualTUN(t, r)
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tun.applyV6Route(context.Background(), plan) {
		t.Fatal("命令失败却报告 v6 已接管")
	}
	if !r.has("ip", "-6 route del default dev wps-tun") {
		t.Error("失败后没有撤销 v6 默认路由")
	}
	if !r.has("ip", "-6 route del 2001:db8::1/128 via fe80::5 dev wlp3s0f0") {
		t.Error("失败后没有撤销 v6 绕行路由")
	}
	if tun.v6RouteReady {
		t.Error("失败后状态仍说 v6 已接管")
	}
}

// TestApplyV6RouteSucceeds 一切正常时 v6 默认路由要真的装上。
func TestApplyV6RouteSucceeds(t *testing.T) {
	r := &dualRunner{v6Default: "default via fe80::5 dev wlp3s0f0 proto ra metric 20600 pref medium"}
	tun := newDualTUN(t, r)
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !tun.applyV6Route(context.Background(), plan) {
		t.Fatal("v6 接管没成功")
	}
	if !r.has("ip", "-6 route add default dev wps-tun") {
		t.Errorf("v6 默认路由没装上: %v", r.ran)
	}
	if !tun.v6RouteReady {
		t.Error("状态没记下 v6 已接管")
	}
}

// TestBuildPlanIPv4Only 只有 v4 默认路由时，v6 那一族整组不装。
func TestBuildPlanIPv4Only(t *testing.T) {
	r := &netRunner{v4out: "default via 192.168.5.1 dev wlp3s0f0 proto dhcp metric 20600"}
	tun := newDualTUN(t, r)
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatalf("只有 v4 不该报错: %v", err)
	}
	if plan.Gateway == "" {
		t.Fatal("v4 网关没探到")
	}
	if plan.Gateway6 != "" {
		t.Fatalf("没有 v6 默认路由却探出了 v6 网关: %+v", plan)
	}
	up, _, err := plan.PlanV6Route()
	if err != nil {
		t.Fatal(err)
	}
	if len(up) != 0 {
		t.Fatalf("没有 v6 网关却装了 v6 接管: %v", up)
	}
	up4, _, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if !hasCmd(up4, "ip", "route add default dev wps-tun") {
		t.Errorf("v4 默认路由没装上: %v", up4)
	}
}

// TestBuildPlanIPv6Only 只有 v6 默认路由时，v4 那一族整组不装，
// 但 TUN 照样要能起来——「只有 v6 的机器用不了代理」是不能接受的。
func TestBuildPlanIPv6Only(t *testing.T) {
	r := &netRunner{
		v6out: "default via fe80::5 dev wlp3s0f0 proto ra metric 20600 pref medium",
	}
	tun := newDualTUN(t, r)
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatalf("只有 v6 不该报错: %v", err)
	}
	if plan.Gateway != "" {
		t.Fatalf("没有 v4 默认路由却探出了 v4 网关: %+v", plan)
	}
	if plan.Gateway6 != "fe80::5" {
		t.Fatalf("v6 网关没探到: %+v", plan)
	}
	up4, _, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range up4 {
		if strings.Contains(strings.Join(c.Args, " "), "route add default") {
			t.Errorf("没有 v4 网关却装了 v4 默认路由: %s", c.String())
		}
	}
	up6, _, err := plan.PlanV6Route()
	if err != nil {
		t.Fatal(err)
	}
	if !hasCmd(up6, "ip", "-6 route add default dev wps-tun") {
		t.Errorf("v6 默认路由没装上: %v", up6)
	}
}

// TestBuildPlanWithoutAnyDefaultRoute 两族都没有默认路由时，
// strict_route 装不了——这时必须报错，而不是装出一个指向空出口的默认路由。
func TestBuildPlanWithoutAnyDefaultRoute(t *testing.T) {
	r := &netRunner{}
	tun := newDualTUN(t, r)
	if _, err := tun.buildPlan(context.Background()); err == nil {
		t.Fatal("两族都没有网关时不该让它起")
	}
}

// TestStatusReportsPerFamilyTakeover 面板那两格说的是内核，不是本进程的记忆。
//
// 「开了 strict_route」「开了而且装上了」「装上了但随后被 DHCP 抢回去」
// 是三种不同的状态，合成一个布尔值只会让人以为全局接管已经生效。
// 现在这一格直接问内核：本进程相不相信自己在接管，都不算数。
func TestStatusReportsPerFamilyTakeover(t *testing.T) {
	// 建计划要在「默认路由还在物理卡上」的时候做——strict_route 得先有网关可钉。
	r := &dualRunner{v6Default: "default via fe80::5 dev wlp3s0f0 proto ra metric 20600"}
	tun := newDualTUN(t, r)
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// 内核：接管装好了，两族的默认路由都在 tun 上。
	r.v4Default = "default dev wps-tun metric 0"
	r.v6Default = "default dev wps-tun metric 1024"
	tun.plan = plan
	tun.running = true
	tun.setV6RouteReady(true)
	tun.publishTakeoverLocked(context.Background()) // 生产里这一步是 Start 末尾做的
	st := tun.Status()
	if !st.TakeoverV4 || !st.TakeoverV6 {
		t.Errorf("内核说两族都接管了，面板却说没接管：v4=%v v6=%v", st.TakeoverV4, st.TakeoverV6)
	}
	if st.TakeoverFrom != "kernel" {
		t.Errorf("读到了内核却标成别的来源: %q", st.TakeoverFrom)
	}

	// 只有 v4 在 tun 上、v6 在物理卡上：两族必须分开报。
	// 换完现场要重新问一次内核——生产里这是网络监视器每一轮顺手做的事。
	r.v6Default = "default via fe80::5 dev wlp3s0f0 proto ra metric 20600"
	tun.publishTakeoverLocked(context.Background())
	st = tun.Status()
	if !st.TakeoverV4 {
		t.Error("v6 变了不该影响 v4 的接管状态")
	}
	if st.TakeoverV6 {
		t.Error("内核说 v6 默认路由在物理卡上，却报成接管了")
	}

	// DHCP 把默认路由抢回去：进程还在跑、我们仍然「相信」自己接管着，
	// 面板必须跟着内核改口。这一句是本用例的重点。
	r.v4Default = "default via 192.168.5.1 dev wlp3s0f0 proto dhcp metric 20600"
	tun.publishTakeoverLocked(context.Background())
	st = tun.Status()
	if st.TakeoverV4 {
		t.Error("默认路由已经被抢回物理卡，还报成接管")
	}
	if !tun.conf.StrictRoute || tun.plan.Gateway == "" {
		t.Error("现场条件本身变了：这条用例的前提没守住")
	}

	// 读不到内核时不许冒充实测：退回进程记忆，并把来源写清。
	r.failOn = "-o route show default"
	tun.takeoverAt = time.Time{} // 演「一次都没问到」：监视器再努力也读不到
	st = tun.Status()
	if st.TakeoverFrom != "memory" {
		t.Errorf("读不到内核却把两格标成 %q，应当是 memory", st.TakeoverFrom)
	}
	if !st.TakeoverV4 {
		t.Error("退回记忆时应当仍按「我们装上了什么」报，否则读不到就等于没接管")
	}
}

// TestStatusWithoutStrictRouteTakesOverNothing 没开 strict_route 就没接管，
// 但面板仍然要报出「用户是想要全局接管的」这一层信息（StrictRoute 字段）。
func TestStatusWithoutStrictRouteTakesOverNothing(t *testing.T) {
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.StrictRoute = false
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(2*time.Second), outbound.NewDirect(2*time.Second)), 2*time.Second)
	tun, err := New(Options{Conf: conf, Router: rt, Runner: &dualRunner{}, Upstreams: []string{"223.5.5.5"}})
	if err != nil {
		t.Fatal(err)
	}
	tun.running = true
	tun.setV6RouteReady(true)
	st := tun.Status()
	if st.TakeoverV4 || st.TakeoverV6 {
		t.Errorf("没开 strict_route 却报接管: %+v", st)
	}
}

// TestRepeatedStartStopLeavesNoResidue 重复启停之后不能留下半套路由。
//
// 启一次、拆一次、再启一次：第二轮装上去的东西要和第一轮一样，
// 拆的时候要能全拆掉。「File exists」当成成功是对的（幂等），
// 但拆不干净就是下一次启动的暗雷。
func TestRepeatedStartStopLeavesNoResidue(t *testing.T) {
	r := &dualRunner{v6Default: "default via fe80::5 dev wlp3s0f0 proto ra metric 20600 pref medium"}
	tun := newDualTUN(t, r)
	ctx := context.Background()

	plan, err := tun.buildPlan(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tun.plan = plan

	for round := 1; round <= 2; round++ {
		up, _, err := plan.Plan()
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(ctx, r, up); err != nil {
			t.Fatalf("第 %d 轮启用失败: %v", round, err)
		}
		if !tun.applyV6Route(ctx, plan) {
			t.Fatalf("第 %d 轮 v6 接管失败", round)
		}
		// 拆：v6 接管那一组先拆，再拆 v4。
		_, down, err := plan.Plan()
		if err != nil {
			t.Fatal(err)
		}
		if _, v6down, verr := plan.PlanV6Route(); verr == nil {
			down = append(v6down, down...)
		}
		for _, c := range down {
			if _, err := r.Run(ctx, c); err != nil {
				t.Fatalf("第 %d 轮拆除 %s 失败: %v", round, c.Desc, err)
			}
		}
	}

	// 第二轮的每一条 up 命令都应该在第一轮出现过——
	// 说明启停是幂等的，而不是每轮多装一条。
	counts := map[string]int{}
	for _, c := range r.ran {
		counts[c.String()]++
	}
	for cmd, n := range counts {
		if n > 2 && strings.Contains(cmd, "route add") {
			t.Errorf("同一条 add 命令跑了 %d 次，说明启停不是幂等的: %s", n, cmd)
		}
	}
}

// TestHelperRequestRejectsBadV6Gateway helper 会用 root 去执行这些参数，
// 所以校验必须覆盖 v6 那一族。
func TestHelperRequestRejectsBadV6Gateway(t *testing.T) {
	base := HelperRequest{
		V:      helperProtoVersion,
		Action: ActionUp,
		Plan: RoutePlan{
			Device:    "wps-tun",
			Address:   "172.19.0.1/30",
			Gateway:   "192.168.5.1",
			Interface: "wlp3s0f0",
		},
	}
	if err := base.validate(); err != nil {
		t.Fatalf("合法的请求被拒了: %v", err)
	}

	bad := base
	bad.Plan.Gateway6 = "not-an-ip"
	bad.Plan.Interface6 = "wlp3s0f0"
	if err := bad.validate(); err == nil {
		t.Error("非法的 v6 网关被放过了")
	}

	bad = base
	bad.Plan.Gateway6 = "fe80::5"
	bad.Plan.Interface6 = "bad name/../x"
	if err := bad.validate(); err == nil {
		t.Error("非法的 v6 网卡名被放过了")
	}

	// 两族都留空表示「不做 v6 接管」，不该被当成配置错误。
	ok := base
	ok.Plan.Gateway6 = ""
	ok.Plan.Interface6 = ""
	if err := ok.validate(); err != nil {
		t.Errorf("不做 v6 接管被当成了错误: %v", err)
	}
}
