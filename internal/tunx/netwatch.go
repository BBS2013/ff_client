package tunx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"wps_app/internal/logx"
)

// 网络变化后的恢复。
//
// 为什么要有它：strict_route 下，我们的绕行路由是「按当时的网关钉死」的——
// `ip route add <节点地址>/32 via <当时的网关> dev <当时的网卡>`。
// 换了 Wi-Fi、网关从 192.168.5.1 变成 192.168.1.1 之后，那条路由还指着旧网关，
// 于是发往节点的包被送到一个已经不存在的出口。
//
// 症状极具误导性：面板上是「节点超时」，而故障切换只能换节点、换不动这条路由，
// 于是每个节点都超时——看起来像节点全挂了，实际只是一条路由过期。
//
// 所以要盯着默认路由：变了就重新钉一遍。
//
// 一条纪律：只有「变化落定了」才动手（与网卡监视器同源，见 service/ifacewatch.go）。
// 丢一次 DHCP 就会短暂地「没网关」，那种抖动不该换来两次重建。

// routeWatchInterval 是看一次网络的时间。5 秒与网卡监视器一致：
// 「换网之后不用管它」与「不变成常驻轮询」之间的折中。
const routeWatchInterval = 5 * time.Second

// routeState 是「网络现在长什么样」的快照。
type routeState struct {
	// Gateway/Interface 是 v4 的网关与出口网卡。
	Gateway   string
	Interface string
	// Gateway6/Iface6 是 v6 的那一组。v6 的网关常常是 fe80:: 开头的链路本地地址。
	Gateway6 string
	Iface6   string
	// DNS 是系统解析器（/etc/resolv.conf 里的 nameserver）。
	// 它不参与路由决策，只是变了就该让人知道：本机的解析行为已经换人了。
	DNS string
	// TakeoverV4/V6 是「这一族此刻生效的默认路由指着谁」的另一半答案：
	// 上面的 Gateway/Interface 刻意跳过我们的网卡（要的是物理出口），
	// 而面板那两格要的是「接管还在不在」——同一份输出，两种读法，
	// 一次探测两份结论，不值得为界面再 fork 一次 ip。
	TakeoverV4 bool
	TakeoverV6 bool
	// ReadOK 标记两族的默认路由到底读到没有。没读到就不要把任何结论
	// 当成实测：界面上那一格必须退回「按进程记忆」并这么说。
	ReadOK bool
}

func (s routeState) same(o routeState) bool { return s == o }

// sameRoutes 只比路由相关的字段。
//
// 系统 DNS 不算在内：它不参与路由决策，拿它去比「装的是哪一份」，
// 就会得出「永远不一样」——于是每一轮都重钉一次。
func (s routeState) sameRoutes(o routeState) bool {
	return s.Gateway == o.Gateway && s.Interface == o.Interface &&
		s.Gateway6 == o.Gateway6 && s.Iface6 == o.Iface6
}

// usable4 报告 v4 那一族能不能拿来钉绕行路由。
func (s routeState) usable4() bool { return s.Gateway != "" && s.Interface != "" }

// usable6 报告 v6 那一族能不能拿来钉绕行路由。
func (s routeState) usable6() bool { return s.Gateway6 != "" && s.Iface6 != "" }

// describe 给出一个人能读的短描述，日志里用。
func (s routeState) describe() string {
	var parts []string
	if s.usable4() {
		parts = append(parts, "v4 "+s.Gateway+"@"+s.Interface)
	} else {
		parts = append(parts, "v4 无网关")
	}
	if s.usable6() {
		parts = append(parts, "v6 "+s.Gateway6+"@"+s.Iface6)
	} else {
		parts = append(parts, "v6 无网关")
	}
	if s.DNS != "" {
		parts = append(parts, "dns "+s.DNS)
	}
	return strings.Join(parts, " · ")
}

// state 把计划里已经落地的网关信息取出来，作为「当前装的是哪一份」的凭据。
func (p RoutePlan) state() routeState {
	return routeState{
		Gateway:   p.Gateway,
		Interface: p.Interface,
		Gateway6:  p.Gateway6,
		Iface6:    p.Interface6,
	}
}

// probeRouteState 读一次当前网络状态。
//
// 读不到不算错：网卡被拔了、DHCP 还没谈完，都会让查询没有答案。
// 那种时刻最该做的是「别动」，而不是「把路由拆了」。
//
// device 是我们的 tun 网卡名：接管默认路由之后表里有两条默认路由，
// 探测必须跳过我们那条，否则会把 tun 自己当成出口网卡。
func probeRouteState(ctx context.Context, r Runner, device string) routeState {
	var st routeState
	st.ReadOK = true
	if out, err := r.Run(ctx, Cmd{Bin: "ip", Args: []string{"-o", "route", "show", "default"}}); err != nil {
		st.ReadOK = false
	} else {
		// 两条读法来自同一份输出：Except 的那条给我们「物理出口是谁」，
		// 不过滤的那条给「此刻生效的默认路由指着谁」——接管就写在后者里。
		if dr, ok := ParseDefaultRouteExcept(out, device); ok {
			st.Gateway, st.Interface = dr.Gateway, dr.Iface
		}
		if dr, ok := ParseDefaultRoute(out); ok {
			st.TakeoverV4 = dr.Iface == device
		}
	}
	if out, err := r.Run(ctx, Cmd{Bin: "ip", Args: []string{"-6", "-o", "route", "show", "default"}}); err != nil {
		st.ReadOK = false
	} else {
		if dr, ok := ParseDefaultRouteExcept(out, device); ok {
			st.Gateway6, st.Iface6 = dr.Gateway, dr.Iface
		}
		if dr, ok := ParseDefaultRoute(out); ok {
			st.TakeoverV6 = dr.Iface == device
		}
	}
	st.DNS = readSystemDNS()
	return st
}

// readSystemDNS 读 /etc/resolv.conf 里的 nameserver，拼成一行便于比较。
func readSystemDNS() string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	var servers []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			servers = append(servers, fields[1])
		}
	}
	return strings.Join(servers, ",")
}

// usable4 报告这份计划的 v4 网关信息齐不齐。
func (p RoutePlan) usable4() bool { return p.Gateway != "" && p.Interface != "" }

// usable6 报告这份计划的 v6 网关信息齐不齐。
func (p RoutePlan) usable6() bool { return p.Gateway6 != "" && p.Interface6 != "" }

// RepinRoutes 生成「把绕行路由改钉到新网关」的命令。
//
// 为什么用 replace 而不是先删后加：同一个目标地址不能同时存在两条路由，
// 先加会被内核以 File exists 挡掉——而那条命令带 TolerateExists，
// 于是「加不上」被当成「已经在位」，绕行路由却还指着旧网关：
// 节点照旧超时，日志却说一切正常。replace 直接顶掉那一条，没有这个歧义。
//
// 组播那条不用 replace：内核自己可能也有一条 224.0.0.0/4，
// replace 会把内核那条一起顶掉——那是动别人的东西。
func (p RoutePlan) RepinRoutes(old RoutePlan) (up, cleanup []Cmd) {
	exclude4, exclude6 := splitExclude(p.Exclude)

	if p.usable4() {
		for _, cidr := range exclude4 {
			up = append(up, Cmd{
				Bin:  "ip",
				Args: []string{"route", "replace", cidr, "via", p.Gateway, "dev", p.Interface},
				Desc: "把 " + cidr + " 改钉到 " + p.Gateway + "（" + p.Interface + "）",
			})
		}
	}
	if p.usable6() {
		gateway := v6Gateway(p.Gateway6, p.Interface6)
		for _, cidr := range exclude6 {
			up = append(up, Cmd{
				Bin:  "ip",
				Args: []string{"-6", "route", "replace", cidr, "via", gateway, "dev", p.Interface6},
				Desc: "把 " + cidr + " 改钉到 " + gateway + "（" + p.Interface6 + "）",
			})
		}
	}

	// 换了网卡：钉在旧网卡上的组播路由要拆掉，新网卡上要补一条。
	// 只在这一族有网关时才动：没有网关就不知道该挪到哪张卡上，
	// 而空网卡名的命令内核根本不认。
	if p.usable4() && old.Interface != "" && old.Interface != p.Interface {
		cleanup = append(cleanup, Cmd{
			Bin:      "ip",
			Args:     []string{"route", "del", multicastV4, "dev", old.Interface, "metric", multicastMetric},
			Desc:     "拆掉旧网卡上的 IPv4 组播路由",
			Optional: true,
		})
		up = append(up, Cmd{
			Bin:            "ip",
			Args:           []string{"route", "add", multicastV4, "dev", p.Interface, "metric", multicastMetric},
			Desc:           "把 IPv4 组播留在物理网卡",
			TolerateExists: true,
		})
	}
	if p.usable6() && old.Interface6 != "" && old.Interface6 != p.Interface6 {
		cleanup = append(cleanup, Cmd{
			Bin:      "ip",
			Args:     []string{"-6", "route", "del", multicastV6, "dev", old.Interface6, "metric", multicastMetric},
			Desc:     "拆掉旧网卡上的 IPv6 组播路由",
			Optional: true,
		})
		up = append(up, Cmd{
			Bin:            "ip",
			Args:           []string{"-6", "route", "add", multicastV6, "dev", p.Interface6, "metric", multicastMetric},
			Desc:           "把 IPv6 组播留在物理网卡",
			TolerateExists: true,
		})
	}

	// 默认路由交给 tun：换网关时它可能已经不在了，补一条。
	// 已经在位时是 "File exists"，按成功处理。
	if p.usable4() {
		up = append(up, Cmd{Bin: "ip", Args: []string{"route", "add", "default", "dev", p.Device}, Desc: "默认路由交给 tun", TolerateExists: true})
	}
	if p.usable6() {
		up = append(up, Cmd{Bin: "ip", Args: []string{"-6", "route", "add", "default", "dev", p.Device}, Desc: "IPv6 默认路由交给 tun", TolerateExists: true})
	}
	return up, cleanup
}

// initNetWatch 记住「刚装的是哪一份」，作为监视器的起点。
//
// 起点必须是「已装的那份」而不是「零值」：零值会让监视器以为
// 从第一轮起网络就变过，然后一直等着它「落定」。
func (t *TUN) initNetWatch(plan RoutePlan) {
	t.netSeen = plan.state()
	t.netSeen.DNS = readSystemDNS()
	t.netPinnedDNS = t.netSeen.DNS
}

// startNetWatchLocked 启动网络监视。调用方必须持有 t.mu。
//
// 之所以是 Locked 版：Start 全程持锁，而 sync.Mutex 不可重入——
// 在持锁时再调一个会去抢同一把锁的方法，面板第一次启停就会把自己锁死。
//
// 只在 strict_route 下起：没有接管默认路由就没有「钉在旧网关上的绕行路由」，
// 也就没有需要重钉的东西。
func (t *TUN) startNetWatchLocked() {
	if t.watchCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.watchCancel = cancel
	t.watchWG.Add(1)
	go func() {
		defer t.watchWG.Done()
		t.netWatchLoop(ctx)
	}()
}

// stopNetWatchLocked 停掉网络监视。调用方必须持有 t.mu。
func (t *TUN) stopNetWatchLocked() {
	if t.watchCancel != nil {
		t.watchCancel()
		t.watchCancel = nil
	}
}

func (t *TUN) netWatchLoop(ctx context.Context) {
	ticker := time.NewTicker(routeWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.checkNetworkChanged(ctx)
		}
	}
}

// checkNetworkChanged 走一轮：探测 → 去抖 → 必要时重钉。
//
// 抽成方法是因为测试要能一轮一轮地驱动它，而不是睡 5 秒等定时器。
func (t *TUN) checkNetworkChanged(ctx context.Context) {
	t.mu.Lock()
	if !t.running {
		t.mu.Unlock()
		return
	}
	installed := t.plan.state()
	prev := t.netSeen
	pinnedDNS := t.netPinnedDNS
	t.mu.Unlock()

	now := probeRouteState(ctx, t.runner, t.conf.Device)

	t.mu.Lock()
	t.netSeen = now
	// 顺手把接管现状贴出去：面板那两格读的就是这里，而这一趟本来就要读路由表。
	// 贴的动作交给 takeover.go 那一个落笔处，别再抄一遍赋值。
	publishTakeoverStateLocked(t, now)
	t.mu.Unlock()

	// 变了但还没稳：下一轮再看。丢一次 DHCP 就会短暂地「没网关」，
	// 那种抖动不该换来两次重建。
	if !now.same(prev) {
		logx.Debugf("TUN: 网络状态在变（%s → %s），先看着", prev.describe(), now.describe())
		return
	}
	// 两件事值得动手：路由信息变了（绕行路由该改钉了），
	// 或者系统解析器换了人（多半是 DHCP 换了一整套配置，顺手重钉一遍）。
	routeChanged := !now.sameRoutes(installed)
	dnsChanged := now.DNS != pinnedDNS
	if !routeChanged && !dnsChanged {
		return
	}
	if !now.usable4() && !now.usable6() {
		// 网卡掉了：没有网关就钉不了绕行路由，也不该拆掉现有的。
		// 但**同一次中断只说一次**：面板每 5 秒问一轮，每轮一条一模一样的 WARN
		// 会把真正有用的行（拨不通、隧道故障）埋掉——2026-10-29 的现场就是这样，
		// 一张 USB 网卡消失之后，日志里只剩这一句在刷。
		t.mu.Lock()
		same := t.netDownDesc == now.describe()
		t.netDownDesc = now.describe()
		t.mu.Unlock()
		if same {
			logx.Debugf("TUN: 网络仍未回来（%s），绕行路由保持原样", now.describe())
		} else {
			logx.Warnf("TUN: 网络断了（%s），绕行路由保持原样，等网络回来", now.describe())
		}
		return
	}
	t.mu.Lock()
	wasDown := t.netDownDesc
	t.netDownDesc = ""
	t.mu.Unlock()
	if wasDown != "" {
		// 恢复也要说一次，而且只说一次：否则读日志的人只看见「断了」，
		// 永远不知道它什么时候回来的——那正是最难判断的一段。
		logx.Infof("TUN: 网络回来了（%s），断的那阵子绕行路由一直保持原样", now.describe())
	}
	if err := t.repinRoutes(ctx, now); err != nil {
		// 已知版本对不上时是我们自己没发这一趟，WARN 每 5 秒刷一条毫无新增信息的东西，
		// 只会把日志里真出事那几行埋掉。
		if errors.Is(err, errHelperMismatchSkip) {
			logx.Debugf("TUN: 网络变了但没有重钉: %v", err)
		} else {
			logx.Warnf("TUN: 网络变化后重钉绕行路由失败: %v", err)
		}
		return
	}
	logx.Infof("TUN: 检测到网络变化（%s），绕行路由已重新钉好", now.describe())
}

// repinRoutes 按新的网络状态重钉绕行路由。
func (t *TUN) repinRoutes(ctx context.Context, now routeState) error {
	t.mu.Lock()
	oldPlan := t.plan
	t.mu.Unlock()

	newPlan := oldPlan
	newPlan.Gateway, newPlan.Interface = now.Gateway, now.Interface
	newPlan.Gateway6, newPlan.Interface6 = now.Gateway6, now.Iface6

	if t.usesHelper() {
		// 已知对面会因为版本拒收：这一趟白跑，而且监视器每 5 秒就来一轮。
		// 跳过只意味着「绕行路由还按上一份计划」，机器上不会因此多出什么遗留——
		// 这一点和拆除那一路相反，拆除永远照发（见 releaseSystem）。
		if t.helperMismatchKnown() {
			return fmt.Errorf("%w：绕行路由仍按上一份计划，刷新 helper 或等它过期后再重钉", errHelperMismatchSkip)
		}
		reply, _, err := t.helper.Run(ctx, HelperRequest{
			V:      helperProtoVersion,
			Action: ActionReroute,
			Plan:   newPlan,
			Prev:   &oldPlan,
		})
		if err != nil {
			if advice := t.noteHelperMismatch(err.Error()); advice != "" {
				return fmt.Errorf("%w。%s", err, advice)
			}
			return err
		}
		if !reply.OK {
			if reply.Err == "" {
				return errors.New("helper 重钉绕行路由时报告失败")
			}
			return errors.New(reply.Err)
		}
		t.clearHelperMismatch()
		t.setV6RouteReady(reply.V6RouteOK)
	} else {
		up, cleanup := newPlan.RepinRoutes(oldPlan)
		for _, c := range cleanup {
			// 清理是尽力而为：旧的那条本来就不在了也不该拦住重钉。
			if _, err := t.runner.Run(ctx, c); err != nil {
				logx.Debugf("TUN: 重钉时清理旧路由失败（%s）: %v", c.Desc, err)
			}
		}
		if err := Apply(ctx, t.runner, up); err != nil {
			return fmt.Errorf("%w", err)
		}
	}

	t.mu.Lock()
	t.plan = newPlan
	t.netPinnedDNS = now.DNS
	t.routeFixes.Add(1)
	t.lastFixAt.Store(time.Now().UnixMilli())
	t.mu.Unlock()
	return nil
}
