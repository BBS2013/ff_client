package service

import (
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"wps_app/internal/config"
)

// hopConn 是一个只会报 LocalAddr 的假连接。
//
// 它刻意**不**实现 SyscallConn：那是"拿不到底层 fd"的一类真实情形
// （QUIC stream、已被包装过的隧道流）。hopEvidence 在这种情况下该承认读不到，
// 而不是照着 intent 编一个设备名出来。
type hopConn struct {
	la net.Addr
}

func (h hopConn) LocalAddr() net.Addr              { return h.la }
func (h hopConn) RemoteAddr() net.Addr             { return h.la }
func (h hopConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (h hopConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (h hopConn) Close() error                     { return nil }
func (h hopConn) SetDeadline(time.Time) error      { return nil }
func (h hopConn) SetReadDeadline(time.Time) error  { return nil }
func (h hopConn) SetWriteDeadline(time.Time) error { return nil }

// TestHopEvidenceUsesDevNotPseudoAddrForQUIC 钉的是「hysteria2 不许把伪地址当源地址」。
//
// 线上现场（2026-10-30 15:2x）：节点页写着「这一跳实际从 43.156.119.19 出去」，
// 而 43.156.119.19 是节点自己，本机是 192.168.0.104 / 10.180.56.177。
// 那一格本该回答"测速到底走没走代理那张卡"，报出节点 IP 只会读成"没走"——
// 而 `ss -unpa` 里那条 QUIC socket 是 `*%wlx001f0578cdff`，钉得好好的。
func TestHopEvidenceUsesDevNotPseudoAddrForQUIC(t *testing.T) {
	// quic-go 的 Conn.LocalAddr() 被填成了隧道对端，这就是它回来的形状。
	pseudo := &net.UDPAddr{IP: net.ParseIP("43.156.119.19"), Port: 443}
	addr, dev := hopEvidence(config.ProtocolHysteria2, hopConn{la: pseudo}, "wlx001f0578cdff")
	if addr != "" {
		t.Fatalf("QUIC 流的 LocalAddr 是伪地址，不该当成源地址报出去: %q", addr)
	}
	if dev != "wlx001f0578cdff" {
		t.Fatalf("没报出钉住的设备，这一格就什么都没说: %q", dev)
	}
}

// TestHopEvidenceSilentWhenSplitInactive 分流没生效时宁可不说话。
//
// 没有钉卡就没有设备可报；这时拿伪地址顶上去，等于替一条没钉的隧道背书。
func TestHopEvidenceSilentWhenSplitInactive(t *testing.T) {
	pseudo := &net.UDPAddr{IP: net.ParseIP("43.156.119.19"), Port: 443}
	conn := hopConn{la: pseudo}
	if addr, dev := hopEvidence(config.ProtocolHysteria2, conn, ""); addr != "" || dev != "" {
		t.Fatalf("分流没生效却报了出网证据: addr=%q dev=%q", addr, dev)
	}
}

// TestHopEvidenceKeepsRealSourceForTCP trojan 那条路照旧报源地址（去端口）。
//
// 这一条是上一改动的护栏：修 UDP 的时候别把 TCP 已经说对的那句一起改坏。
func TestHopEvidenceKeepsRealSourceForTCP(t *testing.T) {
	la := &net.TCPAddr{IP: net.ParseIP("192.168.0.104"), Port: 44546}
	addr, dev := hopEvidence(config.ProtocolTrojan, hopConn{la: la}, "wlx001f0578cdff")
	if addr != "192.168.0.104" {
		t.Fatalf("TCP 的源地址没报对: %q", addr)
	}
	if dev != "" {
		t.Fatalf("拿不到 socket 时不能拿\"打算绑哪张卡\"顶替设备名: %q", dev)
	}
}

// TestHopEvidenceReadsDeviceOffTheTCPSocket 是 2026-10-30 那一问的下半句。
//
// 用户看着「这一跳实际从 192.168.0.104 出去」问：它到底走的是不是那张 USB 网卡？
// 光一个源地址回答不了这个问题——那是 IP 层的读数，读者还得自己拿 `ip addr`
// 反查这张卡叫什么。所以要写设备名，而且要写成 `192.168.0.104%wlx001f0578cdff`
// 这个形状：`ss -tnp` 用的就是这个记号，两边能直接对账。
//
// 这条用例验的是设备名从**真 socket** 上来：绑了 lo 的 TCP 连接必须报 "lo"，
// 没绑的必须报空——后者尤其重要，因为读不到时不许退化成配置里那张"打算绑"的卡。
func TestHopEvidenceReadsDeviceOffTheTCPSocket(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("本机起不了回环监听: %v", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("连不上回环监听: %v", err)
	}
	defer conn.Close()

	addr, dev := hopEvidence(config.ProtocolTrojan, conn, "wlx001f0578cdff")
	if addr != "127.0.0.1" {
		t.Fatalf("回环 TCP 的源地址应为 127.0.0.1，实际 %q", addr)
	}
	if dev != "" {
		t.Fatalf("这条 socket 没绑任何设备，设备名必须留空（不许拿配置顶替），实际 %q", dev)
	}

	// 绑过之后同一条连接必须把设备名说出来。
	bound := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	raw, err := bound.SyscallConn()
	if err != nil {
		t.Skipf("取不到 RawConn: %v", err)
	}
	var serr error
	if err := raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, "lo")
	}); err != nil {
		t.Skipf("拿不到 fd: %v", err)
	}
	if serr != nil {
		// 钉这张卡要 CAP_NET_RAW。拿不到就是不验，而不是"没证据也算通过"——
		// 所以这里写清楚缺什么，别让未来的读者把它当成一句粉饰。
		t.Skipf("没有 SO_BINDTODEVICE 的权限（需要 CAP_NET_RAW），带设备的那一半没验到: %v", serr)
	}
	if _, dev := hopEvidence(config.ProtocolTrojan, conn, "wlx001f0578cdff"); dev != "lo" {
		t.Fatalf("socket 明明绑在 lo 上，设备名却报成了 %q", dev)
	}
}

// TestHopEvidenceNeverInventsDeviceForTCP 是上一条里"不许顶替"那半句的专门护栏。
//
// hopConn 那种没有 fd 的隧道流（`profiles.testProfileCore` 里包过 TLS 之后
// 拿不到 raw socket 的情形就会出现），设备名必须是空串。
func TestHopEvidenceNeverInventsDeviceForTCP(t *testing.T) {
	la := &net.TCPAddr{IP: net.ParseIP("10.180.56.177"), Port: 51000}
	if _, dev := hopEvidence(config.ProtocolTrojan, hopConn{la: la}, "wlx001f0578cdff"); dev != "" {
		t.Fatalf("socket 不可读时不许凭配置报设备名，实际 %q", dev)
	}
}
