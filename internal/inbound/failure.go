package inbound

import "strings"

// failureReason 把一次拨号的错误压成**稳定的原因类别**，供日志聚合用。
//
// 为什么要压：聚合的键如果直接取错误原文，那就退化成不聚合——同一条
// 「节点重连退避中」的错误里带着「还需 28.88s」「还需 28.874s」这种每次
// 都不一样的数字，三十条就是三十个键。而用户要看的不是第 30 条的毫秒数，
// 是"这 30 条都是同一件事"。
//
// 类别划分刻意很粗（六个），因为它们的处置方式各不相同：
//
//	被拦截      规则命中，不是故障
//	节点不可用  节点/隧道的问题，会自动切换或重连
//	目标拒绝    服务端拨不通目标，换隧道没用
//	DNS         解析失败
//	超时        预算用完，说不清是谁的问题
//	其它        兜底，不猜
func failureReason(err error) string {
	if err == nil {
		return "其它"
	}
	if isBlocked(err) {
		return "被拦截"
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(msg, "重连退避") || strings.Contains(msg, "节点重连"),
		strings.Contains(msg, "handshake") || strings.Contains(msg, "握手"),
		strings.Contains(msg, "隧道故障"):
		return "节点不可用"
	case strings.Contains(lower, "connection refused"),
		strings.Contains(lower, "connect: connection refused"),
		strings.Contains(msg, "对端拒绝"):
		return "目标拒绝"
	case strings.Contains(lower, "no such host"),
		strings.Contains(msg, "解析"),
		strings.Contains(lower, "server misbehaving"):
		return "DNS"
	case strings.Contains(lower, "deadline exceeded"), strings.Contains(lower, "timeout"):
		return "超时"
	}
	return "其它"
}
