package tunx

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// 这一组盯住「换了网络之后能不能自己恢复」。
//
// 故障的样子极具误导性：绕行路由是按当时的网关钉死的，
// 换了 Wi-Fi 之后它还指着旧网关，于是发往节点的包被送到一个不存在的出口——
// 面板上显示的是「节点超时」，而故障切换只能换节点、换不动这条路由，
// 于是每个节点都超时，看起来像节点全挂了。
//
// 所以这里验三件事：
//  1. 变化要「落定」才动手（去抖）；
//  2. 动手时用的是 replace，不是先删后加；
//  3. 网卡换了，旧网卡上的组播路由要拆掉。

// netRunner 是一份会按脚本回答默认路由查询的替身。
type netRunner struct {
	ran    []Cmd
	failOn string
	// v4out/v6out 是两族默认路由查询的答案。
	v4out string
	v6out string
}

func (r *netRunner) Run(_ context.Context, c Cmd) (string, error) {
	r.ran = append(r.ran, c)
	joined := strings.Join(c.Args, " ")
	if r.failOn != "" && strings.Contains(joined, r.failOn) {
		return "", errors.New("模拟失败")
	}
	switch joined {
	case "-o route show default":
		return r.v4out, nil
	case "-6 -o route show default":
		return r.v6out, nil
	}
	return "", nil
}

func (r *netRunner) has(bin, argsJoined string) bool {
	return hasCmd(r.ran, bin, argsJoined)
}

// TestProbeRouteStateReadsBothFamilies 两族默认路由都要读到。
func TestProbeRouteStateReadsBothFamilies(t *testing.T) {
	r := &netRunner{
		v4out: "default via 192.168.5.1 dev wlp3s0f0 proto dhcp metric 20600",
		v6out: "default via fe80::5 dev wlp3s0f0 proto ra metric 20600 pref medium",
	}
	st := probeRouteState(context.Background(), r, "wps-tun")
	if st.Gateway != "192.168.5.1" || st.Interface != "wlp3s0f0" {
		t.Fatalf("v4 状态读错了: %+v", st)
	}
	if st.Gateway6 != "fe80::5" || st.Iface6 != "wlp3s0f0" {
		t.Fatalf("v6 状态读错了: %+v", st)
	}
	if !st.usable4() || !st.usable6() {
		t.Fatalf("两族都该可用: %+v", st)
	}
}

// TestProbeRouteStateWithoutDefaultRoute 网卡掉了的时候读不到网关，
// 那不是错误，只是「现在没法钉路由」。
func TestProbeRouteStateWithoutDefaultRoute(t *testing.T) {
	r := &netRunner{v4out: "", v6out: ""}
	st := probeRouteState(context.Background(), r, "wps-tun")
	if st.usable4() || st.usable6() {
		t.Fatalf("没有默认路由却报可用: %+v", st)
	}
}

// TestRepinRoutesUsesReplace 绕行路由必须用 replace 改钉。
//
// 先删后加有个致命歧义：加的时候内核会报 File exists，
// 而那条命令带 TolerateExists，于是「加不上」被当成「已经在位」——
// 绕行路由却还指着旧网关，节点照旧超时，日志却说一切正常。
func TestRepinRoutesUsesReplace(t *testing.T) {
	old := dualPlan()
	old.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	new := old
	new.Gateway = "192.168.1.1"
	new.Interface = "wlp3s0f1"

	up, cleanup := new.RepinRoutes(old)
	if !hasCmd(up, "ip", "route replace 192.168.5.1/32 via 192.168.1.1 dev wlp3s0f1") {
		t.Errorf("v4 绕行路由没有改钉: %v", up)
	}
	if !hasCmd(up, "ip", "-6 route replace 2001:db8::1/128 via fe80::5 dev wlp3s0f0") {
		t.Errorf("v6 绕行路由没有改钉: %v", up)
	}
	// 不该再有「先删后加」那种加法。
	for _, c := range up {
		if strings.Contains(strings.Join(c.Args, " "), "route add 192.168.5.1/32") {
			t.Errorf("绕行路由不该用 add: %s", c.String())
		}
	}
	// 换了网卡：旧网卡上的组播路由要拆，新网卡上的要补。
	if !hasCmd(cleanup, "ip", "route del 224.0.0.0/4 dev wlp3s0f0 metric 1000") {
		t.Errorf("旧网卡上的组播路由没拆: %v", cleanup)
	}
	if !hasCmd(up, "ip", "route add 224.0.0.0/4 dev wlp3s0f1 metric 1000") {
		t.Errorf("新网卡上的组播路由没补: %v", up)
	}
	// 默认路由要补一条（换网关时它可能已经不在了）。
	if !hasCmd(up, "ip", "route add default dev wps-tun") {
		t.Errorf("默认路由没补: %v", up)
	}
}

// TestRepinRoutesSameInterfaceKeepsMulticast 网卡没换时组播路由不用动。
func TestRepinRoutesSameInterfaceKeepsMulticast(t *testing.T) {
	old := dualPlan()
	old.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	new := old
	new.Gateway = "192.168.1.1"

	up, cleanup := new.RepinRoutes(old)
	if len(cleanup) != 0 {
		t.Errorf("网卡没换却要拆组播路由: %v", cleanup)
	}
	for _, c := range up {
		if strings.Contains(strings.Join(c.Args, " "), "224.0.0.0/4") {
			t.Errorf("网卡没换却动了组播路由: %s", c.String())
		}
	}
}

// TestRepinRoutesSkipsFamilyWithoutGateway 某一族没有网关就不碰那一族。
//
// 硬装 v6 默认路由而没有 v6 绕行路由，我们的出站会被自己抓回来形成环路。
func TestRepinRoutesSkipsFamilyWithoutGateway(t *testing.T) {
	old := dualPlan()
	old.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	new := old
	new.Gateway6 = ""
	new.Interface6 = ""

	up, _ := new.RepinRoutes(old)
	for _, c := range up {
		joined := strings.Join(c.Args, " ")
		if strings.Contains(joined, "-6") {
			t.Errorf("没有 v6 网关却动了 v6: %s", c.String())
		}
	}
	if !hasCmd(up, "ip", "route replace 192.168.5.1/32 via 192.168.5.1 dev wlp3s0f0") {
		t.Errorf("v4 那一族没动: %v", up)
	}
}

// newWatchTUN 起一个开着 strict_route 的 TUN，并把监视器的初始状态摆好。
func newWatchTUN(t *testing.T, runner Runner) *TUN {
	t.Helper()
	tun := newDualTUN(t, runner)
	tun.running = true
	return tun
}

// TestNetworkChangeDebounce 变化要落定才动手。
//
// 丢一次 DHCP 就会短暂地「没网关」，那种抖动不该换来两次重建。
// 所以第一轮看到新状态时不动手，第二轮看到同一个状态才动手。
func TestNetworkChangeDebounce(t *testing.T) {
	r := &netRunner{
		v4out: "default via 192.168.1.1 dev wlp3s0f1 proto dhcp metric 20600",
		v6out: "default via fe80::5 dev wlp3s0f1 proto ra metric 20600 pref medium",
	}
	tun := newWatchTUN(t, r)
	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	tun.plan = plan
	// 监视器的起点与 Start 时一样：已装的那一份。
	tun.initNetWatch(plan)

	ctx := context.Background()
	// 第一轮：看到了新状态，但还没稳——不动手。
	tun.checkNetworkChanged(ctx)
	if tun.routeFixes.Load() != 0 {
		t.Fatalf("第一轮就动手了: %d", tun.routeFixes.Load())
	}
	// 第二轮：同一个新状态又出现一次——落定了，重钉。
	tun.checkNetworkChanged(ctx)
	if tun.routeFixes.Load() != 1 {
		t.Fatalf("落定后没有重钉: %d", tun.routeFixes.Load())
	}
	if !r.has("ip", "route replace 192.168.5.1/32 via 192.168.1.1 dev wlp3s0f1") {
		t.Errorf("没有把绕行路由改钉到新网关: %v", r.ran)
	}
	if tun.plan.Gateway != "192.168.1.1" {
		t.Errorf("计划里的网关没更新: %+v", tun.plan)
	}
}

// TestNetworkChangeStableStateDoesNothing 网络没变就不该有任何动作。
func TestNetworkChangeStableStateDoesNothing(t *testing.T) {
	r := &netRunner{
		v4out: "default via 192.168.5.1 dev wlp3s0f0 proto dhcp metric 20600",
		v6out: "default via fe80::5 dev wlp3s0f0 proto ra metric 20600 pref medium",
	}
	tun := newWatchTUN(t, r)
	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	tun.plan = plan
	tun.initNetWatch(plan)

	ctx := context.Background()
	tun.checkNetworkChanged(ctx)
	tun.checkNetworkChanged(ctx)
	if tun.routeFixes.Load() != 0 {
		t.Fatalf("网络没变却重钉了: %d", tun.routeFixes.Load())
	}
	for _, c := range r.ran {
		if strings.Contains(strings.Join(c.Args, " "), "route replace") {
			t.Errorf("网络没变却执行了改钉: %s", c.String())
		}
	}
}

// TestNetworkLostKeepsExistingRoutes 网卡掉了的时候不能拆现有路由。
//
// 那时的正确处置是「别动」：绕行路由虽然还指着旧网关，
// 但拆掉它并不会让节点更快通，只会让「刚恢复的网络」又断一次。
func TestNetworkLostKeepsExistingRoutes(t *testing.T) {
	r := &netRunner{v4out: "", v6out: ""}
	tun := newWatchTUN(t, r)
	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	tun.plan = plan
	tun.initNetWatch(plan)

	ctx := context.Background()
	tun.checkNetworkChanged(ctx)
	tun.checkNetworkChanged(ctx)
	if tun.routeFixes.Load() != 0 {
		t.Fatalf("网络断了却重钉: %d", tun.routeFixes.Load())
	}
	if tun.plan.Gateway != "192.168.5.1" {
		t.Errorf("网络断了却把计划改了: %+v", tun.plan)
	}
}

// TestNetworkComesBackRepins 网卡回来之后要重钉。
func TestNetworkComesBackRepins(t *testing.T) {
	r := &netRunner{
		v4out: "default via 192.168.1.1 dev wlp3s0f1 proto dhcp metric 20600",
		v6out: "default via fe80::5 dev wlp3s0f1 proto ra metric 20600 pref medium",
	}
	tun := newWatchTUN(t, r)
	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	tun.plan = plan
	tun.initNetWatch(plan)

	ctx := context.Background()
	tun.checkNetworkChanged(ctx)
	tun.checkNetworkChanged(ctx)
	if tun.routeFixes.Load() != 1 {
		t.Fatalf("网络换了却没重钉: %d", tun.routeFixes.Load())
	}
	if tun.lastFixAt.Load() == 0 {
		t.Error("重钉时刻没记下来")
	}
}

// TestRepinFailureKeepsOldPlan 重钉失败时不能把计划改成新的。
//
// 改了计划就等于宣称「已经钉到新网关了」，而实际上一条都没装上——
// 下一次监视就会以为不用再钉，绕行路由永远停在旧网关上。
func TestRepinFailureKeepsOldPlan(t *testing.T) {
	r := &netRunner{
		v4out:  "default via 192.168.1.1 dev wlp3s0f1 proto dhcp metric 20600",
		v6out:  "default via fe80::5 dev wlp3s0f1 proto ra metric 20600 pref medium",
		failOn: "route replace",
	}
	tun := newWatchTUN(t, r)
	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	tun.plan = plan
	tun.initNetWatch(plan)

	ctx := context.Background()
	tun.checkNetworkChanged(ctx)
	tun.checkNetworkChanged(ctx)
	if tun.routeFixes.Load() != 0 {
		t.Fatalf("失败却记成重钉成功: %d", tun.routeFixes.Load())
	}
	if tun.plan.Gateway != "192.168.5.1" {
		t.Errorf("失败后却把计划改成新的: %+v", tun.plan)
	}
}
