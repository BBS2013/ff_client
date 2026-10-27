package outbound

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// boundDevice 读回这条 socket 实际绑定的网卡名。
//
// 这是唯一能证明「真的钉上去了」的办法：查 Split 里的字段只能证明我们自己
// 记住了要看什么，而 getsockopt 读的是内核那边的状态。
func boundDevice(t *testing.T, c net.Conn) string {
	t.Helper()
	sc, ok := c.(syscall.Conn)
	if !ok {
		t.Fatalf("%T 不支持 syscall.Conn，读不回绑定的网卡", c)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var name string
	var callErr error
	if err := rc.Control(func(fd uintptr) {
		name, callErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if callErr != nil {
		t.Fatalf("getsockopt(SO_BINDTODEVICE): %v", callErr)
	}
	return name
}

// echoListener 起一个只接受连接、不说话的 TCP 监听：直连出站只需要拨通它。
func echoListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return ln
}

// 闸门开着时直连的 socket 必须钉在内置那张卡上。
func TestDirectBindsWhenSplitActive(t *testing.T) {
	ln := echoListener(t)
	sp := NewSplit("lo", "lo")
	sp.SetActive(true)

	d := NewDirect(0).WithSplit(sp)
	conn, err := d.DialContext(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if got := boundDevice(t, conn); got != "lo" {
		t.Fatalf("直连 socket 绑在 %q 上，期望 lo", got)
	}
}

// 闸门关着（也就是非规则模式）时不许钉：这一档必须与没开这个功能完全一样。
func TestDirectUnbindsWhenSplitOff(t *testing.T) {
	ln := echoListener(t)
	sp := NewSplit("lo", "lo")
	sp.SetActive(false)

	d := NewDirect(0).WithSplit(sp)
	conn, err := d.DialContext(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if got := boundDevice(t, conn); got != "" {
		t.Fatalf("闸门关着时不该绑网卡，实际绑在 %q", got)
	}
}

// 闸门是运行期开的：装配之后收放，下一次新连接立刻改走另一条路，不必重建出站。
func TestSplitGateFlipsWithoutRebuild(t *testing.T) {
	ln := echoListener(t)
	sp := NewSplit("lo", "lo")
	d := NewDirect(0).WithSplit(sp)

	conn, err := d.DialContext(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if got := boundDevice(t, conn); got != "" {
		t.Fatalf("默认不该绑网卡，实际 %q", got)
	}
	_ = conn.Close()

	sp.SetActive(true)
	conn2, err := d.DialContext(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("开闸后 DialContext: %v", err)
	}
	defer conn2.Close()
	if got := boundDevice(t, conn2); got != "lo" {
		t.Fatalf("开闸后应绑 lo，实际 %q", got)
	}
}

// hysteria2 走的是 UDP：那条 socket 由 ConnFactory 造，不经过 net.Dialer。
func TestProxyConnFactoryBindsWhenActive(t *testing.T) {
	sp := NewSplit("lo", "lo")
	sp.SetActive(true)

	pc, err := ProxyConnFactory{split: sp}.New(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer pc.Close()

	sc, ok := pc.(syscall.Conn)
	if !ok {
		t.Fatalf("%T 不支持 syscall.Conn", pc)
	}
	rc, err := sc.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var name string
	var callErr error
	if err := rc.Control(func(fd uintptr) {
		name, callErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if callErr != nil {
		t.Fatalf("getsockopt: %v", callErr)
	}
	if name != "lo" {
		t.Fatalf("QUIC 的 UDP socket 绑在 %q 上，期望 lo", name)
	}
}

// 没配到两张卡时设备名是空串，那就不该有任何绑定动作。
func TestEmptyDevicesMeanNoBinding(t *testing.T) {
	sp := NewSplit("", "")
	sp.SetActive(true)

	if sp.DirectDev() != "" || sp.ProxyDev() != "" {
		t.Fatalf("空设备名时不该给出网卡: %q / %q", sp.DirectDev(), sp.ProxyDev())
	}
	pc, err := ProxyConnFactory{split: sp}.New(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = pc.Close()
}

// 换网卡不必重建出站：SetDevices 之后新 socket 就走新卡了。
func TestSetDevicesAppliesWithoutRebuild(t *testing.T) {
	ln := echoListener(t)
	sp := NewSplit("", "")
	sp.SetActive(true)
	d := NewDirect(0).WithSplit(sp)

	sp.SetDevices("lo", "lo")
	conn, err := d.DialContext(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if got := boundDevice(t, conn); got != "lo" {
		t.Fatalf("SetDevices 之后应绑 lo，实际 %q", got)
	}
}

// 钉一张不存在的网卡必须报错，而不是安静地连出去——
// 那正是这个功能最坏的失败方式：界面写着「代理走 USB 无线」，实际走的还是内置。
func TestBindUnknownDeviceFails(t *testing.T) {
	if err := ProbeDeviceBind("wps-no-such-if"); err == nil {
		t.Fatal("对不存在的网卡应当报错")
	}
}

// 这台机器上到底能不能钉：面板是普通用户进程，探不到就该关掉而不是硬来。
func TestProbeDeviceBindOnLoopback(t *testing.T) {
	if err := ProbeDeviceBind("lo"); err != nil {
		t.Fatalf("绑定回环应当总是可以: %v", err)
	}
}

// DevForPolicy 是连接表「网卡」那一列的唯一来源：说错就是指错了方向。
func TestDevForPolicyFollowsPolicyAndGate(t *testing.T) {
	sp := NewSplit("wlp3s0f0", "wlx001f0578cdff")

	// 闸门没开时两张卡都该报空串——连接表上留一张卡名，
	// 用户会以为分流还在生效，而它早就收回了。
	if sp.DevForPolicy(PolicyDirect) != "" || sp.DevForPolicy(PolicyProxy) != "" {
		t.Fatalf("闸门关着时不该报网卡: %q / %q",
			sp.DevForPolicy(PolicyDirect), sp.DevForPolicy(PolicyProxy))
	}

	sp.SetActive(true)
	if got := sp.DevForPolicy(PolicyDirect); got != "wlp3s0f0" {
		t.Errorf("直连该拿内置无线，得到 %q", got)
	}
	if got := sp.DevForPolicy(PolicyProxy); got != "wlx001f0578cdff" {
		t.Errorf("代理该拿 USB 无线，得到 %q", got)
	}
	// REJECT 压根没有出站，硬给它安一张卡就是凭空编造。
	if got := sp.DevForPolicy(PolicyReject); got != "" {
		t.Errorf("拦截不该有网卡，得到 %q", got)
	}

	sp.SetActive(false)
	if got := sp.DevForPolicy(PolicyProxy); got != "" {
		t.Errorf("闸门收回后不该还报网卡，得到 %q", got)
	}
}

// nil 的 Split 也得答得出空串：服务层在没有分流时传的就是它。
func TestDevForPolicyOnNilSplit(t *testing.T) {
	var sp *Split
	if got := sp.DevForPolicy(PolicyDirect); got != "" {
		t.Errorf("nil Split 该答空串，得到 %q", got)
	}
}
