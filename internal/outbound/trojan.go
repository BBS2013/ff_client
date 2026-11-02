package outbound

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/logx"
)

// Trojan 是 trojan 协议的出站。
//
// 协议本身就薄：一次 TLS 握手（ALPN 里带 "Trojan"），然后发一个头部，
// 之后连接上就是裸的字节流。头部把「目标地址」写给服务端，由服务端去解析并连接，
// 所以本地不需要知道目标的 IP——这一点和 hysteria2 完全一致，
// 也正是域名规则能免疫 DNS 污染的前提。
//
//	<sha224(口令) 的 56 位 hex> CRLF <CMD=0x01> <ATYP> <地址> <端口> CRLF
//
// 第二行是**裸字节**：公开规范把它写成 hex，而这台服务端（以及常见的几种发行版）
// 只认裸字节——写成 hex 会被判成"不是 trojan 请求"，然后被交给兼底 web 服务器。
// 头部之后**不等**服务端的应答：公开规范说这里会回 10 字节，这台 1.16 实测一个字节
// 都不发（隧道建好就等客户端先说话）。两处取舍的实测过程都写在 NewTrojan 里。
//
// 与 hysteria2 的差别在连接成本上：hysteria2 是「一条 QUIC 连接跑所有流」，
// trojan 每条流都要重新做一次 TLS 握手（一个 RTT）。所以这里不做连接复用，
// 也不该做——trojan 的服务端把 TLS 会话当成一条转发连接的边界。
type Trojan struct {
	serverAddr   string // 已解析好的 ip:port
	sni          string
	insecure     bool
	passwordHash string
	handshakeTO  time.Duration

	mu        sync.Mutex
	connected bool
	closed    bool

	// split 非空时把到节点的连接钉在那张卡上，见 WithSplit。
	split *Split
}

// WithSplit 让隧道从指定网卡出去，链式写法。
func (t *Trojan) WithSplit(s *Split) *Trojan {
	t.split = s
	return t
}

// trojan ALPN 与头部常量。
const (
	trojanALPN = "Trojan"
	// trojanCmdConnect 是 CONNECT 的命令字节（0x02 是 UDP ASSOCIATE，
	// 而这个客户端的 UDP 只走 hysteria2 节点，见 DialUDP）。
	trojanCmdConnect = 0x01
)

// NewTrojan 按配置构造 trojan 出站，不立即连接。
// reject 一般是本客户端的假 IP 段，理由见 resolveServerHost。
func NewTrojan(sc config.ServerConfig, handshakeTimeout time.Duration, resolver HostResolver, reject netip.Prefix) (*Trojan, error) {
	proto, err := config.ParseProtocol(sc.Type)
	if err != nil {
		return nil, err
	}
	if proto != config.ProtocolTrojan {
		return nil, fmt.Errorf("NewTrojan 收到协议 %q", sc.Type)
	}
	host, port, err := net.SplitHostPort(sc.Addr)
	if err != nil {
		return nil, fmt.Errorf("server.addr %q: %w", sc.Addr, err)
	}
	p, err := parsePort(port)
	if err != nil {
		return nil, fmt.Errorf("server.addr %q: %w", sc.Addr, err)
	}
	if strings.TrimSpace(sc.Auth) == "" {
		return nil, fmt.Errorf("server.auth is required")
	}
	if handshakeTimeout <= 0 {
		handshakeTimeout = 10 * time.Second
	}
	// 服务端地址走两种协议共用的那条解析路径（自己的直连 DNS 优先，失败退回系统解析），
	// 理由见 resolveServerHost。
	ip, err := resolveServerHost(context.Background(), resolver, host, reject)
	if err != nil {
		return nil, err
	}
	// 口令摘要用 SHA-224，即公开规范那一份。
	//
	// 这里原来写的是 SHA-1 + 命令字节 0x04，依据是 2026-10-16 那次
	// 「对 wbthinks.space:8443 自检通过」。今天两端对着查，那次是**假通过**：
	// 服务端把我们的流判成"不是 trojan 请求"、交给 nginx 兼底，兼底页照样回字节，
	// 而当时只验到"电路通了 + 读得到东西"（正是 pageProbe 后来要补的那个缺口）。
	// 2026-10-29 在服务器上按 ALPN × 摘要 × 第二行布局逐条对日志试：
	// 只有 SHA-224 + 裸字节第二行被接受，SHA-1、MD5 与 hex 编码的第二行
	// 一律记 "not trojan request"。
	sum := sha256.Sum224([]byte(sc.Auth))
	return &Trojan{
		serverAddr:   net.JoinHostPort(ip, strconv.Itoa(p)),
		sni:          trojanSNI(host, sc.TLS.SNI),
		insecure:     sc.TLS.Insecure,
		passwordHash: hex.EncodeToString(sum[:]),
		handshakeTO:  handshakeTimeout,
	}, nil
}

// trojanSNI 决定 ClientHello 里发出去的 SNI：显式配置优先，其次跟随主机名。
// 主机名是字面量 IP 时不能把它当 SNI 发（TLS 库会直接拒绝），
// 这类节点本来就靠 insecure: true + 一个假域名 SNI 工作。
func trojanSNI(host, configured string) string {
	if sni := strings.TrimSpace(configured); sni != "" {
		return sni
	}
	if net.ParseIP(host) != nil {
		return "localhost"
	}
	return host
}

// Name 返回策略名（面板与日志里显示为 PROXY）。
func (t *Trojan) Name() string { return string(PolicyProxy) }

// Connected 报告「是否曾经握手成功过且尚未关闭」。
// 面板用它区分「代理在跑」与「隧道建起来过」。
//
// 注意别把它当健康信号用：trojan 每条流都重新做一次 TLS 握手，没有后台重连，
// 所以这个标志一旦为 true 就一直为 true，之后每次握手都失败它也不回落。
// 判节点行不行要用 NodeFailure，别用 Connected。
func (t *Trojan) Connected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.closed && t.connected
}

// NodeFailure 实现 outbound.NodeFault。
//
// 规则粗得没法再粗：除了调用方放弃和自己关闭，全算节点的错。
// 因为 trojan 的服务端拨不通目标时不给任何信号，直接把 TLS 连接挂断——
// 这在客户端侧与「服务端自己不行」完全同形，谁都没有依据把它们分开。
//
// 高估而不是低估是有意的，但代价是误报：所以故障切换必须要求
// 「连续多次、且跨不同目标」才动手，绝不能一次失败就切。
func (t *Trojan) NodeFailure(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrClosed):
		return false
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return false
	}
	return true
}

// Status 是给人看的服务端摘要。
func (t *Trojan) Status() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.connected || t.closed {
		return t.serverAddr
	}
	return fmt.Sprintf("%s (SNI=%s TLS=已握手)", t.serverAddr, t.sni)
}

// DialContext 建立到 target（host:port）的转发连接。
func (t *Trojan) DialContext(ctx context.Context, target string) (net.Conn, error) {
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}

	d := net.Dialer{Timeout: t.handshakeTO}
	if t.split != nil {
		d.Control = t.split.ProxyControl()
	}
	raw, err := t.dialServer(ctx, d)
	if err != nil {
		// 与 hysteria 侧同样的区分：ctx 还活着而拨号超时，说明是我们自己的
		// 握手预算用完了 —— 地址上没人应答，这正是节点级故障。
		if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w after %v (tcp)", ErrHandshakeTimeout, t.handshakeTO)
		}
		return nil, fmt.Errorf("dial trojan server %s: %w", t.serverAddr, err)
	}
	header, err := trojanHeader(target, t.passwordHash)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}

	tc := tls.Client(raw, &tls.Config{
		ServerName:         t.sni,
		InsecureSkipVerify: t.insecure, //nolint:gosec // 由配置显式决定，trojan 节点常用自签证书
		NextProtos:         []string{trojanALPN},
	})
	if deadline, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(deadline)
	} else {
		_ = tc.SetDeadline(time.Now().Add(t.handshakeTO))
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		// 上面说过：把 SetDeadline 到点的错误原样递出去，会被 NodeFailure
		// 当成「调用方等不下去了」而放过，节点沉默死掉时反而不触发切换。
		if ctx.Err() == nil && errors.Is(err, os.ErrDeadlineExceeded) {
			return nil, fmt.Errorf("%w after %v (tls)", ErrHandshakeTimeout, t.handshakeTO)
		}
		return nil, fmt.Errorf("trojan tls handshake: %w", err)
	}
	if _, err := tc.Write(header); err != nil {
		_ = tc.Close()
		return nil, fmt.Errorf("write trojan header: %w", err)
	}
	// 头部发完就把超时清掉：之后的超时属于业务连接，不该由握手时间管着。
	//
	// 这里**不等**服务端的应答：公开规范说头部之后服务端回 10 字节（CRLF+8 保留），
	// 但这台 trojan 1.16 实测一个字节都不回——隧道建好就直接等我们的数据
	// （2026-10-29 在服务端上把隧道打到它自己的 nginx，请求前收到 0 字节、
	// 请求后第一字节已经是 "HTTP/1.1 301"）。等它等于把每条连接卡死到超时，
	// 症状还是"节点没响应"。真遇到会回应答头的节点，得按 profile 加开关再来读。
	_ = tc.SetDeadline(time.Time{})

	t.mu.Lock()
	t.connected = true
	t.mu.Unlock()
	logx.Debugf("trojan: 已连接 %s（SNI=%s, 目标 %s）", t.serverAddr, t.sni, target)
	return tc, nil
}

// dialServer 建立到节点的那条 TCP 连接。
//
// 默认是自己拨、按需把 socket 钉到代理卡上。只有一种情况例外：这台机器被判定
// 「普通进程钉上之后包发不出去」（2026-10-29 实测就是），而 service 又注入了特权通道——
// 那时改让 helper（root）造一条已钉好并连上的 socket 交回来。
// 不默认走它：每用一次就是一个提权进程（实测起进程 0.04s、RSS 51.9 MB），
// 常态下自己绑就够了。
func (t *Trojan) dialServer(ctx context.Context, d net.Dialer) (net.Conn, error) {
	if t.split.ShouldUseBind(PolicyProxy) {
		conn, err := t.split.BoundDialFor(ctx, PolicyProxy, t.serverAddr)
		if err != nil {
			return nil, fmt.Errorf("走提权通道钉卡失败: %w", err)
		}
		return conn, nil
	}
	return d.DialContext(ctx, "tcp", t.serverAddr)
}

// DialUDP 明确拒绝，而不是悄悄把 UDP 丢掉。
//
// trojan 的转发语义里只有一条 TLS 流，没有 UDP 承载：报文怎么封装都没有规定，
// 编出来的只能是「对端看不懂的东西」。这里给一句话把原因说清，是因为
// 丢掉的结果是应用干等到超时，而超时不告诉任何人为什么。
func (t *Trojan) DialUDP(context.Context) (PacketConn, error) {
	return nil, errUDPRefused("trojan 节点（UDP 转发只有 hysteria2 节点支持）")
}

// Close 关闭出站。已建立的连接不受影响，由它们自己走完。
func (t *Trojan) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	t.connected = false
	return nil
}

// trojanHeader 拼出请求头：口令摘要一行，然后是「命令字节 + 地址族 + 地址 + 端口」。
//
// 目标地址的编码要分三种：IPv4 直接 4 字节、域名是「1 字节长度 + ASCII」、
// IPv6 是 16 字节。域名这条最容易写错——把点分字符串按 IP 解析会静默变成
// 一个连不通的 IPv6 目标。
func trojanHeader(target, passwordHash string) ([]byte, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("bad target %q: %w", target, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return nil, fmt.Errorf("bad port in %q", target)
	}
	if len(passwordHash) != sha256.Size224*2 {
		return nil, fmt.Errorf("口令摘要长度不对: %d", len(passwordHash))
	}

	buf := []byte(passwordHash)
	buf = append(buf, '\r', '\n', trojanCmdConnect)

	// ATYP 三种编码：0x01 IPv4(4B) / 0x03 域名(1B 长度 + ASCII) / 0x04 IPv6(16B)。
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Is4() {
			v4 := a.As4()
			buf = append(buf, 0x01)
			buf = append(buf, v4[:]...)
		} else {
			v6 := a.As16()
			buf = append(buf, 0x04)
			buf = append(buf, v6[:]...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("目标域名长度非法: %d", len(host))
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(p>>8), byte(p))
	return append(buf, '\r', '\n'), nil
}
