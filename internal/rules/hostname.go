package rules

// ValidHostName 判断一个字符串"结构上是不是个主机名"。
//
// 三个入口共用它（SOCKS5 的目标地址、SOCKS5 UDP 报文头里的地址、tun 上 DNS 查询的
// 名字），因为它们的下游是同一个：这个名字会被当成规则判定的键、被拼进 host:port
// 再被拆开。所以拒的必须是同一批字符，两边各写一份迟早漂开。
//
// 拒的是：控制字符与空白（NUL/换行/退格会被下游当成边界）、
// 以及 ':' '[' ']' '@' 这几个会把 host:port 切分带坏的结构性字符。
// 不拒非 ASCII：IDN 的 punycode 是 ASCII，但有些客户端会直接送 UTF-8 名字过来，
// 那属于"能不能解析出结果"的问题，不是"这串东西能不能安全地当键用"的问题。
func ValidHostName(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c == 0x7f {
			return false
		}
		switch c {
		case ':', '[', ']', '@':
			return false
		}
	}
	return true
}
