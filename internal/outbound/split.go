package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

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
	// bind 是「请 root 替我造一条钉住的 socket」这条通道，由 service 注入
	// （实现是 tunx 的 dialbind）。为什么在这儿注入而不是每个协议自己拿：
	// 「什么时候该用特权通道」这个判据只有一处，散到三个协议里迟早各写一份。
	bind BindSocketFunc
	// bindDirect / bindProxy 是 service 对**两侧各自**判定「普通进程钉上之后包
	// 发不出去」的结论。分两侧而不是一个开关：这台机器上两侧的病可以不一样，
	// 而 2026-10-30 之前只有一个代理侧的结论，于是直连那一半同样是废的、
	// 界面上却写着"直连真的在干活"（实测 uid 1000 两台面板 via DIRECT 失败
	// 363/1244 条、成功 0 条；root 之后失败 0、成功 17）。
	// 没有这两条结论就一直走 setsockopt 自己绑——那是常态，特权通道是给被拦的机器准备的。
	bindDirect bool
	bindProxy  bool
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

// BindSocketFunc 由调用方（service）给：拿一条钉在 dev 上、已经连通 addr 的 TCP 连接。
type BindSocketFunc func(ctx context.Context, dev, addr string) (net.Conn, error)

// SetBindSocket 注入特权钉卡通道；传 nil 表示这台机器上没有（那就照旧自己绑）。
func (s *Split) SetBindSocket(f BindSocketFunc) {
	s.mu.Lock()
	s.bind = f
	s.mu.Unlock()
}

// SetBindNeeded 记下「普通进程钉上之后包发不出去」这条判定结果，**两侧各一份**。
// 它决定该不该走特权通道，也决定那一侧是被维持还是被退回默认路由（见 service 那侧）。
func (s *Split) SetBindNeeded(direct, proxy bool) {
	s.mu.Lock()
	s.bindDirect, s.bindProxy = direct, proxy
	s.mu.Unlock()
}

// ShouldUseBind 报告某一侧的拨号是否该让 root 代劳：
// 分流真的在跑、那一侧点名了网卡、判定说普通绑定发不出包，而且通道确实在。
// 四个条件少一个都不该用——每用一次是一次提权往返，不能当默认路径。
func (s *Split) ShouldUseBind(p Policy) bool {
	if s == nil || !s.Active() {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.bind == nil {
		return false
	}
	switch p {
	case PolicyDirect:
		return s.bindDirect && s.directDev != ""
	case PolicyProxy:
		return s.bindProxy && s.proxyDev != ""
	default:
		return false
	}
}

// BoundDialFor 向特权通道要一条钉在**那一侧点名的卡**上、已连通的 socket。
// 调用前请先问 ShouldUseBind。addr 必须是已解析的 ip:port——helper 里不许解析域名，
// 故障现场重解析会拿到假 IP，这条硬规矩写在 tunx 的 checkBindTarget 里。
func (s *Split) BoundDialFor(ctx context.Context, p Policy, addr string) (net.Conn, error) {
	s.mu.RLock()
	f := s.bind
	var dev string
	switch p {
	case PolicyDirect:
		dev = s.directDev
	case PolicyProxy:
		dev = s.proxyDev
	}
	s.mu.RUnlock()
	if f == nil || dev == "" {
		return nil, fmt.Errorf("没有可用的钉卡通道（%s）", dev)
	}
	return f(ctx, dev, addr)
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

// ProbeDeviceEgress 用一条 TCP 连接真的去拨一次 addr；dev 为空时不钉网卡，
// 给调用方当对照组（分不清"钉卡拨不通"和"节点本来就不通"的时候要用）。
//
// 为什么不能只探 setsockopt：这台机器上 `SO_BINDTODEVICE` 对普通用户是**成功返回**的，
// 包却一个都上不了线（2026-10-29 实测：uid 1000 绑 wlx/wlp 都超时，加上
// ambient CAP_NET_RAW 仍然超时，只有 uid 0 连得上）。只问"绑得上吗"就会得到
// 「分流已生效」这句假话，而症状是全部代理连接一起超时。
func ProbeDeviceEgress(dev, addr string, budget time.Duration) error {
	if addr == "" {
		return nil
	}
	if budget <= 0 {
		budget = 2 * time.Second
	}
	d := net.Dialer{Timeout: budget}
	if dev != "" {
		d.Control = func(_, _ string, c syscall.RawConn) error { return bindDevice(c, dev) }
	}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		// **ECONNREFUSED 算通路是通的**：那是对方主机自己回来的 RST，
		// 说明包确实从这张卡出去又回来了。这一步要分辨的从来不是"这个端口有没有人听"，
		// 而是"钉上之后包出不出得去"——只有没回答（超时）才是钉不上的形状。
		// 不加这一条，选中节点是 UDP-only（hysteria2）时探针就必然假报"两条都不通"。
		if errors.Is(err, syscall.ECONNREFUSED) {
			return nil
		}
		return err // Go 那句自带地址与原因；拼句子是 EgressPair 的事，别再包一层
	}
	_ = conn.Close()
	return nil
}

// EgressPair 把「钉着拨一次」和「不钉再拨一次（对照组）」凑成一条能下结论的证据。
//
// 两次都不能少：只问 `SO_BINDTODEVICE` 的返回值，会漏掉这台机器上那种
// "绑得上、包却一个都上不了线"的形状；而只看钉着那一次，又会把节点自己挂了
// 算到分流头上。返回 (是不是钉卡的锅, 一句事实)；分不清时 blocked=false，
// 事实里说清为什么不下结论——不猜。
//
// dial 是接缝：真实实现就是 ProbeDeviceEgress，单测与 `-diag` 各传自己的那份，
// 这样"绑得上≠钉得住"这条判据只有一个人写。
func EgressPair(dial func(dev, addr string, budget time.Duration) error, dev, addr string, budget time.Duration) (bool, string) {
	if dev == "" || addr == "" {
		return false, ""
	}
	berr := dial(dev, addr, budget)
	if berr == nil {
		return false, ""
	}
	if aerr := dial("", addr, budget); aerr != nil {
		return false, fmt.Sprintf("钉在 %s 上拨 %s 不通（%v），不钉也拨不通（%v）", dev, addr, berr, aerr)
	}
	return true, fmt.Sprintf("钉在 %s 上拨 %s 不通（%v），不钉时却拨得通", dev, addr, berr)
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
