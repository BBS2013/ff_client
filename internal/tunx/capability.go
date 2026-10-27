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
	out = append(out, "TUN IPv6：未做真实 v6 流量验证；路由装不上时会降级为 DNS NODATA（不声称可用）")
	return out
}
