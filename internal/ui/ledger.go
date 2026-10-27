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
//
// 比的是配置里那两个入站地址。面板开关写的是**实际绑定**的地址（inboundAddrs），
// 两者只有在 `listen: 127.0.0.1:0`（让内核分配端口）这种配置下才会不一致，
// 那种情况下这一行会说"没有记账"而不是"没人负责还原"——少说一句，不会说错。
// 读不到设置时同样按"不是我们的"处理：宁可少说一句，也不要凭一份读不出来的设置报警。
func (a *App) desktopPointsAtUs() bool {
	st, err := a.withTimeoutRead()
	if err != nil {
		// 三条后端的 Read 在读失败时都会把原因写进 st.Error，所以这里只看 err；
		// 读不到就当不是我们的——凭一份读不出来的设置报警是冤枉人。
		return false
	}
	backend, httpAddr, socksAddr := a.sysProxyTarget()
	return sysproxy.LikesOurs(st, sysproxy.Config{
		Enable: true, Backend: backend, HTTPAddr: httpAddr, SOCKSAddr: socksAddr,
	})
}
