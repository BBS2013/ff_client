package outbound

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// Split 是「直连与代理分走两张网卡」这件事的运行时状态。
//
// 为什么在出站这一层做：绑网卡改的是**这条 socket 从哪个设备出去**，
// 路由、规则、协议栈都跟它无关。直连是每条连接现拨的 TCP，
// 代理是握手时建立的那一条到节点的连接（QUIC/UDP 或 TCP）——
// 两边各有一个 socket 能下手的地方，除此之外什么都不用改。
//
// active 是一个运行期开关而不是构造期常量：这张卡只在规则模式下才有意义
// （全局模式下全部流量都走隧道，直连那张卡压根不参与；直连模式下反过来），
// 而模式是可以在不重启的情况下切换的。
type Split struct {
	mu        sync.RWMutex
	directDev string
	proxyDev  string
	active    atomic.Bool
}

// NewSplit 造一份分流设置。directDev 与 proxyDev 都是接口名，留空表示这一侧不分流。
func NewSplit(directDev, proxyDev string) *Split {
	return &Split{directDev: directDev, proxyDev: proxyDev}
}

// SetDevices 换掉两张卡，出站不用重建。
//
// 用在「插拔了网卡之后重新探测」那条路上：USB 网卡是会被拔的，
// 而重新装配整套出站意味着掐断正在传的连接——换两张名字比换一整套出站便宜得多。
// 传空串即那一侧退回系统默认路由。
func (s *Split) SetDevices(directDev, proxyDev string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.directDev, s.proxyDev = directDev, proxyDev
}

// SetActive 开/关分流。关掉之后所有出站立刻回到系统默认路由。
func (s *Split) SetActive(on bool) { s.active.Store(on) }

// Active 报告分流是否正在生效。
func (s *Split) Active() bool { return s != nil && s.active.Load() }

// DirectDev 返回直连该绑的网卡；没在生效时返回空串。
func (s *Split) DirectDev() string {
	if !s.Active() {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.directDev
}

// ProxyDev 返回代理该绑的网卡；没在生效时返回空串。
func (s *Split) ProxyDev() string {
	if !s.Active() {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proxyDev
}

// Devices 返回配置时定的两张卡，与当前是否生效无关——界面要能区分
// 「开关是关的」和「压根没找到两张卡」。
func (s *Split) Devices() (direct, proxy string) {
	if s == nil {
		return "", ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.directDev, s.proxyDev
}

// DevForPolicy 回答某个策略的出站被钉在了哪张网卡上，空串表示没钉。
//
// 绑定是按策略做的（直连那只 dialer 与代理那只各自持有自己的 Split 视图），
// 所以「这条连接会走哪张卡」在拨号前就是确定的，不必等连接建起来再回读 socket。
func (s *Split) DevForPolicy(p Policy) string {
	switch p {
	case PolicyDirect:
		return s.DirectDev()
	case PolicyProxy:
		return s.ProxyDev()
	default:
		// REJECT 压根没有出站，更谈不上走哪张卡。
		return ""
	}
}

// Describe 给出给人看的一行摘要。
func (s *Split) Describe() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("直连走 %s，代理走 %s", s.directDev, s.proxyDev)
}

// DirectControl 装给 net.Dialer.Control 用：新建 socket 时把它钉到直连那张卡上。
//
// 每次建 socket 都重新看一眼闸门，而不是在装配时就把网卡名定死：
// 模式是运行期可切的，切完之后新连接必须立刻改走另一条路。
func (s *Split) DirectControl() func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		dev := s.DirectDev()
		if dev == "" {
			return nil
		}
		return bindDevice(c, dev)
	}
}

// ProxyControl 是 DirectControl 在代理那一侧的对应物（TCP 协议，例如 trojan）。
func (s *Split) ProxyControl() func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		dev := s.ProxyDev()
		if dev == "" {
			return nil
		}
		return bindDevice(c, dev)
	}
}

// ProxyConnFactory 是给 hysteria2 用的：QUIC 建在一条 UDP socket 上，
// 而那条 socket 由 hysteria 的 ConnFactory 造，不经过 net.Dialer。
type ProxyConnFactory struct{ split *Split }

// New 造一条准备发往 addr 的 UDP socket，已生效时把它钉在代理那张卡上。
//
// 监听地址照样留空（通配），与 hysteria 自带的工厂一致：
// 钉网卡由 SO_BINDTODEVICE 完成，源地址由内核从那张卡上挑，
// 自己挑反而会在只有 IPv6 地址的卡上挑不中。
func (f ProxyConnFactory) New(net.Addr) (net.PacketConn, error) {
	lc := &net.ListenConfig{}
	if dev := f.split.ProxyDev(); dev != "" {
		lc.Control = f.split.ProxyControl()
	}
	return lc.ListenPacket(context.Background(), "udp", "")
}

// bindDevice 在 socket 建立前把它钉到某张网卡上。
//
// 用 SO_BINDTODEVICE 而不是指定源地址：源地址会跟着 DHCP 变，
// 而且 IPv6 那张卡可能只有链路本地地址可用——那时指定源地址根本挑不出来，
// 而这里是「出这个 socket 的包只准从这张卡出去」，语义与地址无关。
func bindDevice(c syscall.RawConn, dev string) error {
	var setErr error
	if err := c.Control(func(fd uintptr) {
		setErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev)
	}); err != nil {
		return err
	}
	if setErr != nil {
		return fmt.Errorf("把 socket 钉到网卡 %s 失败: %w", dev, setErr)
	}
	return nil
}

// ProbeDeviceBind 探一次当前进程有没有权限钉网卡。
//
// 这不是多余的检查：SO_BINDTODEVICE 在 Linux 5.7 之前需要 CAP_NET_RAW，
// 而面板正是以普通用户跑的。探不出来还照样去绑的话，症状是**所有**连接一起失败，
// 而界面上只显示「分流已开启」——那比不分流糟糕得多。
func ProbeDeviceBind(dev string) error {
	lc := &net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error { return bindDevice(c, dev) },
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", "")
	if err != nil {
		return fmt.Errorf("钉网卡 %s 失败: %w", dev, err)
	}
	return pc.Close()
}
