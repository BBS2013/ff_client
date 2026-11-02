package tunx

import "wps_app/internal/config"

// CapabilityNotes 列出 TUN 里"代码支持、但没有端到端证据"的组合。
//
// 这些不是错误，也不该拦住启动：它们只是还没被真机验过。写在启动日志与
// `-diag` 里，是为了让"不通"的第一步排查不落在错误的方向上——
// 用户至少知道该先换回哪条有证据的路，而不是怀疑 DHCP 或网卡坏了。
func CapabilityNotes(cfg *config.Config) []string {
	if cfg == nil || !cfg.TUN.Enable {
		return nil
	}
	var out []string
	if cfg.ActiveServer().Protocol() == config.ProtocolTrojan {
		out = append(out, "TUN + trojan：未做同机实链验证；不通时先把活动节点切回 hysteria2 再排查")
	}
	out = append(out, "TUN 全局接管按地址族分开：IPv4 与 IPv6 的默认路由各自安装，"+
		"装不上一族时那一族的流量仍走物理出口（面板会写明哪一族真接管了）")
	out = append(out, "TUN IPv6：v6 默认路由已支持，但还没有真实 v6 流量的端到端实链证据")
	if cfg.TUN.StrictRoute {
		// 这一条要说，因为 ping 正是人和脚本判断「网络好了没有」的默认信号，
		// 而全局接管下它给的是假信号：echo request 被默认路由吸进 tun，
		// 协议栈就地回一个应答（实测：接管后连不存在的 TEST-NET 地址都「通」，亚毫秒）。
		// 不进隧道、不在连接表里留行——看不见不等于没发生，更不等于对端可达。
		// 两族都量过（v4 与 v6 各一条 netns 用例），所以这句要写成两族；
		// 同时要说清没被吸走的那部分：ND 与组播命中的是直连路由和 local 表，
		// 不看默认路由，接管不会把本机自己的链路问断——那是另一回事，不能混着吓人。
		out = append(out, "全局接管下 ICMP（v4 与 v6）不进隧道：本机 ping 的 echo request 会被协议栈就地应答，"+
			"所以 ping 得通不代表对端可达；判断隧道通不通请看流量页的连接记录，不是看 ping"+
			"（链路本地的邻居发现与组播不受影响，仍走物理网卡）")
	}
	if cfg.TUN.KillSwitch && !cfg.TUN.StrictRoute {
		// 这是「开了但不会生效」的那种配置，必须现在说，不能等到故障那天才让人发现闸门根本没装。
		// 选择性 TUN 里直连本来就该从物理网卡出去，挂上保护等于把这个模式要的功能关掉。
		out = append(out, "故障断网保护已开启，但没有开启全局接管（strict_route）：它不会挂上，"+
			"故障期间的出站不会被收窄")
	}
	if cfg.TUN.KillSwitch && cfg.TUN.StrictRoute {
		out = append(out, "故障断网保护只在自动切换判定「没有可用节点」之后挂上，拦的是本机生成的出站；"+
			"它不改写也不解密流量，被转发的流量与已经建立的隧道内连接不在范围内")
	}
	return out
}
