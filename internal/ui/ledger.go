// 系统代理记账的读数翻译成界面能直接印的话。
//
// 放在没有构建标签的文件里，是为了让这五种判断能脱开 WebView 单测：
// 这一块讲的是"桌面现在归谁、退出会不会还原"，答错的代价是用户整机没网
// 而界面上还是一片绿色，所以它必须是能测的，而不是模板里的一串三元表达式。
package ui

import (
	"fmt"

	"wps_app/internal/logx"
	"wps_app/internal/sysproxy"
)

// SysProxyLedger 是界面上「记账」那一行的全部数据。
//
// 只投影这三项：State 决定配色，Text 是要说的话，Path 让用户知道去哪儿自查。
// Go 里那些 PID/exe/后端名不单独占字段——它们已经在那句话里了，
// 再投影一遍就是两份可能互相矛盾的真相。
type SysProxyLedger struct {
	// State 是 none | orphan | stale | live | unreadable 之一，前端按它上色。
	State string `json:"state"`
	Text  string `json:"text"`
	Path  string `json:"path"`
}

// sysProxyLedgerText 把一份记账读数（加上"桌面是不是正指着我们"这半个条件）说成一句人话。
//
// 五种情况必须五种话：把它们混成一类，用户就没法知道桌面到底
// 是被别人占着、等一次自动自愈，还是根本没人负责还原。
func sysProxyLedgerText(led sysproxy.Ledger, statePath string, desktopIsOurs bool) SysProxyLedger {
	ours := ""
	if led.AlreadyOurs {
		ours = "（改动前就指着本程序，还原等于关掉）"
	}
	switch {
	case led.ReadErr != "":
		return SysProxyLedger{"unreadable", fmt.Sprintf(
			"记账读不懂：%s — 先手工核对桌面设置，确认后再决定要不要删这个文件", led.ReadErr), statePath}
	case !led.Exists && desktopIsOurs:
		// 桌面指着我们、记账却不在：本进程退出时不会还原，而其它读数全是绿的。
		return SysProxyLedger{"orphan",
			"桌面正指着本程序的入站，但没有记账：本进程退出时不会还原桌面", statePath}
	case !led.Exists:
		return SysProxyLedger{"none", "没有记账：桌面上这组设置不是本程序改的，退出不欠还原", statePath}
	case led.Alive:
		return SysProxyLedger{"live", fmt.Sprintf(
			"%s — 崩溃时不会有下一个实例接手还原，正常退出时由它自己还%s", led.Holder, ours), statePath}
	default:
		return SysProxyLedger{"stale", fmt.Sprintf("%s，下次启动会自动还一次%s", led.Holder, ours), statePath}
	}
}

// SystemProxyLedger 返回记账那一行的读数。
//
// 只在读桌面那一路（pollSys）里调，不进两秒一轮的状态轮询：
// 「没有记账时桌面归谁」这一问要再读一次后端设置，那是启子进程的开销。
func (a *App) SystemProxyLedger() SysProxyLedger {
	statePath := sysproxy.StatePath(a.svc.ConfigPath())
	led, err := sysproxy.ReadLedger(statePath)
	if err != nil && led.ReadErr == "" {
		// 不该发生（ReadLedger 把读不懂都写在 ReadErr 里），真碰上了也不能退化成
		// 「没有记账」那种安慰人的读数。
		led.ReadErr = err.Error()
	}
	var v SysProxyLedger
	if led.Exists || led.ReadErr != "" {
		v = sysProxyLedgerText(led, statePath, false)
	} else {
		v = sysProxyLedgerText(led, statePath, a.desktopPointsAtUs())
	}
	// 这个字段是跨 goroutine 的：绑定方法可能跑在别的 goroutine 上，
	// 而 Close 在主 goroutine 上清它。上一次这里就是裸读写，-race 一压就中。
	a.ledgerMu.Lock()
	prev := a.lastLedger
	a.lastLedger = v
	a.ledgerMu.Unlock()
	if line := ledgerLogLine(prev, v); line != "" {
		logx.Warnf("%s", line)
	}
	return v
}

// ledgerLogLine 决定这次读数要不要往日志里补一句。
//
// 只在状态变化时写：pollSys 每次显示窗口都读一遍，每次都 WARN
// 就等于把日志刷成背景噪音，而那件事真正发生时反而没人再看第二遍。
func ledgerLogLine(prev, next SysProxyLedger) string {
	if prev.State == next.State {
		return ""
	}
	switch next.State {
	case "orphan":
		return fmt.Sprintf("%s（%s）", next.Text, next.Path)
	case "stale":
		return "系统代理欠一次还原：" + next.Text
	case "unreadable":
		return "读不懂系统代理记账：" + next.Text
	}
	return ""
}

// desktopPointsAtUs 读一次桌面设置，只为回答"这组设置是不是我们该负责的"。
func (a *App) desktopPointsAtUs() bool {
	ok, _ := a.desktopPointsAtUsDetail()
	return ok
}

// desktopPointsAtUsDetail 除了答案，还带一句"桌面现在写着什么"。
//
// 报错时用得上：只说"不是我们的"，用户无从判断是写歪了、读失败了，
// 还是桌面真被别的程序改了。
func (a *App) desktopPointsAtUsDetail() (bool, string) {
	ok, detail, _ := a.desktopPointsAtUsProbe()
	return ok, detail
}

// desktopPointsAtUsProbe 是 desktopPointsAtUsDetail 加上"读没读到"这一位。
//
// 三档必须分得开，因为调用方的动作完全不同：
//
//	读到了、是我们的   -> 继续
//	读到了、不是我们的 -> 这次写入没生效，可以撤账
//	**根本读不到**     -> 什么都不知道，绝不能撤账
//
// 第三档以前被并进第二档（"读不到就当不是我们的，免得冤枉人"），代价是：
// dconf 慢半拍、一次 D-Bus 抖动、或者后端恰好超时，都会让一次**已经写上桌面**
// 的开启被判失败，并把那份唯一的记账删掉。之后退出时就认不出桌面正指着我们，
// 那个指向已关闭端口的死指针留在桌面上——而全机应用只会报「代理连接被拒绝」。
func (a *App) desktopPointsAtUsProbe() (ok bool, detail string, readable bool) {
	st, err := a.withTimeoutRead()
	if err != nil {
		return false, "读不到桌面设置：" + err.Error(), false
	}
	c := a.desktopExpect()
	ok = sysproxy.LikesOurs(st, c)
	return ok, fmt.Sprintf("桌面当前 mode=%s http=%s socks=%s（本客户端应是 http=%s socks=%s）",
		st.Mode, st.HTTP, st.SOCKS, c.HTTPAddr, c.SOCKSAddr), true
}

// desktopExpect 给出"桌面该长什么样"。
//
// 比的是**实际在监听**的两个入站地址（服务跑着的时候），不是配置里声明的那些：
// 面板开关写的是 inboundAddrs，拿配置里的地址去比，`listen: 127.0.0.1:0`
// 那种配置下必然对不上，于是每次都判成"桌面不是我们的"——
// 后果是退出时把用户的设置当成别人的乱还原。
// 服务没跑的时候没有实际地址可问，退回配置里声明的地址，
// 否则启动时"收回残留指针"那一路会永远失效。
//
// 两个入站各自补：只开了 socks5 时，http 那一格退回配置里的 :0 没有意义，
// 而**已经对上的那一格绝不能跟着一起退**。以前是"缺一个就整份换成配置"，
// 于是同一个"只开一种入站"的配置下，读回永远对不上 → 判成开启失败 →
// 记账被删 → 退出时认不出桌面正指着我们，死指针留在桌面上。
func (a *App) desktopExpect() sysproxy.Config {
	c := a.sysProxyEnableConfig()
	if c.HTTPAddr == "" || c.SOCKSAddr == "" {
		_, cfgHTTP, cfgSOCKS := a.sysProxyTarget()
		// 只补拿不到实际地址的那一格；拿得到的那一格保持实际值。
		if c.HTTPAddr == "" {
			c.HTTPAddr = cfgHTTP
		}
		if c.SOCKSAddr == "" {
			c.SOCKSAddr = cfgSOCKS
		}
	}
	return c
}
