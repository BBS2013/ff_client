package tunx

import (
	"net"
	"net/netip"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	tunstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// upstreamCIDR 把一个上游地址写成 iptables 需要的「整主机」前缀。
// IPv4 是 /32、IPv6 是 /128——照抄 /32 会让 v6 上游变成一段网段，
// 放行范围悄悄变大，而我们自己的解析又被劫持回去。
func upstreamCIDR(s string) string {
	if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil && ip.To4() == nil {
		return ip.String() + "/128"
	}
	return strings.TrimSpace(s) + "/32"
}

// SecondHost 返回前缀里网卡的下一个可用地址，用作假 DNS 的落点。
// 172.19.0.1/30 → 172.19.0.2；只有一个可用地址时原样返回。
func SecondHost(address string) string {
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return ""
	}
	addr := prefix.Addr().Next()
	if !prefix.Contains(addr) {
		return prefix.Addr().String()
	}
	return addr.String()
}

// endpointAddrs 把协议栈的传输端点 ID 拆成（目标, 客户端字符串）。
//
// 命名很容易看反：协议栈是「被连接的那一方」，所以 LocalAddress 是应用真正
// 想去的地方，RemoteAddress 才是本机里发起连接的进程地址。
func endpointAddrs(id tunstack.TransportEndpointID) (dst netip.AddrPort, src string) {
	d, s := endpointFull(id)
	return d, s.String()
}

// endpointFull 与 endpointAddrs 同义，只是把客户端那端也留成可用的地址端口。
// UDP 回程要用它拼 *net.UDPAddr：gvisor 的 WriteTo 对参数做的是硬类型断言，
// 拿到字符串只能自己再转回去。
func endpointFull(id tunstack.TransportEndpointID) (dst, src netip.AddrPort) {
	return addrPort(id.LocalAddress, id.LocalPort), addrPort(id.RemoteAddress, id.RemotePort)
}

func addrPort(addr tcpip.Address, port uint16) netip.AddrPort {
	a, ok := netip.AddrFromSlice(addr.AsSlice())
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(a.WithZone(""), port)
}
