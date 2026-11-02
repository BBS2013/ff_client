package tunx

import (
	"context"
	"time"
)

// 接管现状的「实测」这一侧。
//
// 面板那两格（IPv4/IPv6 是否已接管）以前读的是本进程的记忆：装上之后
// 只要默认路由被别人改回去（DHCP 续约、NetworkManager 重启、另一个 VPN 起来），
// 界面会继续显示「已接管」，而公网流量其实已经从物理卡出去了。现在它读内核。
//
// 但**不在 Status() 里 fork 进程**：网络监视器每 5 秒本来就要读这两张路由表
// （probeRouteState），同一份输出顺手给出第二份结论就够了。
// 面板按 1–2 秒轮询，每次状态查询都起一个 `ip` 的话，等于为一个数字把常驻开销翻倍。
// 换来的形状更值：读数最多旧一个监视周期，旧过时限就必须改口。

// takeoverStaleAfter 是「这个读数还能被称作实测」的时限：三个监视周期。
// 超过它说明监视器没在跑或读不到路由表——那时界面必须说这是推断，
// 不能继续拿一个过期的数字说「内核此刻如此」。
const takeoverStaleAfter = 3 * routeWatchInterval

// publishTakeoverLocked 单独问一次内核并贴出接管现状。
//
// 常规路径不需要它：监视器每一轮都会顺手贴（见 checkNetworkChanged）。
// 这里服务的是「刚装完接管、第一轮还没到」那一刻——用户最可能就在这之后看面板。
// 调用方必须持有 t.mu。
func (t *TUN) publishTakeoverLocked(ctx context.Context) {
	publishTakeoverStateLocked(t, probeRouteState(ctx, t.runner, t.conf.Device))
}

// publishTakeoverStateLocked 把一份已经读到的路由现状贴成面板那两格的读数。
//
// 唯一的落笔处——监视器和 Start 都走这里，两边各写一遍赋值迟早会漂。
// 读不到（ReadOK=false）时什么都不贴：留着「从没读到过」，takeoverReading 才会
// 退回记忆那一档并把来源一起交给界面。伪装成实测，正是
// 「面板说已接管、机器其实没出口」那种形态。
// 调用方必须持有 t.mu（它要改缓存字段）。
func publishTakeoverStateLocked(t *TUN, st routeState) {
	if !st.ReadOK {
		return
	}
	t.takeoverV4, t.takeoverV6, t.takeoverAt = st.TakeoverV4, st.TakeoverV6, time.Now()
}

// takeoverReading 交出「此刻该对用户说什么」：两族的值 + 这个值的来源。
//
// 三种来源是三句话：kernel=刚问过路由表；memory=问不到，只能按本进程装过什么推断；
// not-running=TUN 没在跑，两族自然都没接管。
func (t *TUN) takeoverReading() (v4, v6 bool, from string) {
	if !t.running {
		return false, false, "not-running"
	}
	if !t.takeoverAt.IsZero() && time.Since(t.takeoverAt) <= takeoverStaleAfter {
		return t.takeoverV4, t.takeoverV6, "kernel"
	}
	return t.conf.StrictRoute && t.plan.Gateway != "",
		t.conf.StrictRoute && t.v6RouteReady, "memory"
}
