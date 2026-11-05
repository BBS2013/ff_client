package tunx

import "strings"

// tunFailureReason 把 TUN 那侧的拨号错误压成稳定的原因类别，供日志聚合用。
//
// 与 inbound 的同名函数分开而不是共用一个：TUN 的失败面还多一层
// （假 IP 反查不到域名、出站不支持 UDP），而两个包的依赖方向不该为了省
// 十行代码被拉反（tunx 不依赖 inbound）。
//
// 类别粗到"处置方式不同"就够：用户要判断的是"该换节点、还是该改规则、
// 还是等一等"，不需要知道第 30 条超时是 14998ms 还是 15001ms。
func tunFailureReason(err error) string {
	if err == nil {
		return "其它"
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "重连退避") || strings.Contains(msg, "节点重连"),
		strings.Contains(msg, "handshake") || strings.Contains(msg, "握手"),
		strings.Contains(msg, "隧道故障"):
		return "节点不可用"
	case strings.Contains(lower, "connection refused"),
		strings.Contains(msg, "对端拒绝"):
		return "目标拒绝"
	case strings.Contains(lower, "no such host"),
		strings.Contains(msg, "解析"),
		// 假 IP 反查到不域名：这不是"目标不存在"，是"我们自己的记录没了"。
		strings.Contains(msg, "反查不到域名"):
		return "DNS"
	case strings.Contains(lower, "deadline exceeded"), strings.Contains(lower, "timeout"):
		return "超时"
	case strings.Contains(msg, "承载不了 UDP") || strings.Contains(msg, "不支持 UDP"):
		return "出站不支持"
	}
	return "其它"
}
