package outbound

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/quic-go"

	"wps_app/internal/config"
	"wps_app/internal/logx"
)

// 重连退避参数：1s 起，指数翻倍，上限 30s，附加 ±20% 抖动避免多客户端同时重连风暴。
const (
	backoffBase    = 1 * time.Second
	backoffMax     = 30 * time.Second
	maxDialAttempt = 3
)

// ErrClosed 在出站已关闭后被使用。
var ErrClosed = errors.New("hysteria outbound closed")

// ErrHandshakeTimeout 表示「节点在我们的握手预算内没有完成建链」。
//
// 它必须与调用方自己的超时分开，否则故障切换会瞎：错误文本里一旦带上
// context.DeadlineExceeded，判据就会把它当成「调用方等不下去了」而放过，
// 可「对端不应答」恰恰是节点挂掉最常见的形态——地址上没有服务端时，
// QUIC 就是干等到超时，而不是立刻收到拒绝。
var ErrHandshakeTimeout = errors.New("handshake timeout")

// ErrInBackoff 表示「节点正在重连退避中，而这次拨号等不到它」。
//
// 它必须是一个自有身份的错误，不能借 context 的超时来表达：
// 故障切换的判据看到 DeadlineExceeded 会当成「调用方等不下去了、与节点无关」而放过
// （见 NodeFailure），可这条恰恰是节点连着挂掉时最该数进去的一次。
var ErrInBackoff = errors.New("节点重连退避中")

// remainingBudget 返回调用方还剩多少时间；ctx 没有截止时间时 ok=false。
func remainingBudget(ctx context.Context) (time.Duration, bool) {
	dl, ok := ctx.Deadline()
	if !ok {
		return 0, false
	}
	return time.Until(dl), true
}

// Hysteria 是 hysteria2 出站。整进程共享一条 QUIC 连接：
// 只有隧道本身坏了才重连，单条流的错误留在产生它的那条流上，
// 分级依据见 isConnectionFatal。
type Hysteria struct {
	template    client.Config
	handshakeTO time.Duration

	// connectMu 串行化握手，避免并发拨号同时打 QUIC 连接。
	connectMu sync.Mutex

	mu       sync.Mutex
	cli      client.Client
	info     *client.HandshakeInfo
	failures int
	retryAt  time.Time
	closed   bool

	// split 非空时把到节点的 QUIC 连接钉在那张卡上，见 WithSplit。
	split *Split
}

// WithSplit 让隧道从指定网卡出去，链式写法。
//
// hysteria2 的 QUIC 连接建在 UDP 上，而那条 socket 由客户端的 ConnFactory 造，
// 不经过 net.Dialer —— 所以这里换的是那个工厂，而不是拨号器的 Control。
func (h *Hysteria) WithSplit(s *Split) *Hysteria {
	h.split = s
	return h
}

// HostResolver 把主机名解析成 IP，签名与 dnsx.Resolver.LookupIP 一致。
type HostResolver interface {
	LookupIP(ctx context.Context, host string) ([]netip.Addr, error)
}

// resolveServerHost 把服务端主机名换成一个可拨的 IP 字符串，两种协议共用这一条规则：
// 字面量 IP 原样返回；有解析器就先用它（自己的直连 DNS），多候选优先 IPv4，
// 解析失败或结果为空再退回系统 resolver——宁可多一次降级，
// 也不让「自己的 DNS 坏了」变成开不起来。
//
// 必须用自己的直连解析而不是系统 resolver：TUN 模式下系统解析链路正是被我们
// 接管的那一条，靠它就会出现「要起 TUN 得先解析节点、解析节点得先有可用 DNS」的死锁——
// 真机上就这么卡死过一次：劫持规则残留 + 网卡已消失时，面板连启动都启动不了。
//
// reject 是这条路径上唯一的护栏，通常是本客户端自己的假 IP 段。
// 需要它的原因是真实发生过的一次故障：节点域名不在规则集里、落到 FINAL=PROXY，
// 于是我们的 DNS 把这个域名答成 198.18.0.9；任何走到系统解析的分支都会原样收下它，
// 接着把「连接节点」变成「连接自家网卡」——表现是一句莫名其妙的 connection reset。
// 假 IP 永远不可能是节点的真实地址，所以宁可报清原因，也不照着它连。
func resolveServerHost(ctx context.Context, r HostResolver, host string, reject netip.Prefix) (string, error) {
	if host == "" {
		return "", errors.New("服务端地址缺少主机名")
	}
	if ip := net.ParseIP(host); ip != nil {
		// Unmap 不是可选项：net.IP 里的 IPv4 常以 4-in-6 的 16 字节形式出现，
		// 而 netip.Prefix.Contains 要求族一致——不 Unmap 就等于放行一个假 IP。
		if a, ok := netip.AddrFromSlice(ip); ok {
			a = a.Unmap().WithZone("")
			if reject.IsValid() && reject.Contains(a) {
				return "", fakeIPRejectedError(host, reject)
			}
		}
		return ip.String(), nil
	}
	if r != nil {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err := r.LookupIP(dctx, host)
		cancel()
		if err == nil {
			if a := pickAddr(addrs, reject); a.IsValid() {
				return a.String(), nil
			}
			if onlyFake(addrs, reject) {
				return "", fakeIPRejectedError(host, reject)
			}
			err = errors.New("解析结果为空")
		}
		logx.Warnf("用自带 DNS 解析服务端 %s 失败，退回系统解析: %v", host, err)
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	list, err := net.DefaultResolver.LookupIPAddr(dctx, host)
	if err != nil {
		return "", fmt.Errorf("解析服务端 %s: %w", host, err)
	}
	var picked netip.Addr
	for _, a := range list {
		na, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		na = na.Unmap().WithZone("")
		if reject.IsValid() && reject.Contains(na) {
			continue
		}
		if picked.Is4() {
			continue
		}
		if picked.IsValid() && !na.Is4() {
			continue
		}
		picked = na
		if na.Is4() {
			break
		}
	}
	if !picked.IsValid() {
		if len(list) > 0 && reject.IsValid() {
			return "", fakeIPRejectedError(host, reject)
		}
		return "", fmt.Errorf("解析服务端 %s 无可用结果", host)
	}
	return picked.String(), nil
}

func fakeIPRejectedError(host string, reject netip.Prefix) error {
	return fmt.Errorf("解析服务端 %s 得到的地址全落在假 IP 段 %s 内："+
		"那是本客户端自己发出去的地址，TUN 的 DNS 劫持把它又答给了我们，照着连只会形成环路。"+
		"请检查 dns.servers 是否能直连；节点域名建议显式加一条规则", host, reject)
}

// onlyFake 区分两种「选不出地址」：候选本来就是空的，还是全被 reject 挡掉了。
// 后者的原因和处置完全不同，值得给一句专门的话。
func onlyFake(addrs []netip.Addr, reject netip.Prefix) bool {
	if !reject.IsValid() {
		return false
	}
	for _, a := range addrs {
		if !reject.Contains(a.Unmap()) {
			return false
		}
	}
	return len(addrs) > 0
}

// resolveServerAddr 是 resolveServerHost 的 UDP 版本，供 hysteria2 用。
// 优先 IPv4 的理由见 resolveServerHost：IPv6 在 TUN/strict_route 下更容易出现
// network is unreachable。
func resolveServerAddr(ctx context.Context, r HostResolver, addr string, reject netip.Prefix) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	p, err := parsePort(port)
	if err != nil {
		return nil, err
	}
	ip, err := resolveServerHost(ctx, r, host, reject)
	if err != nil {
		return nil, err
	}
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: p}, nil
}

// pickAddr 在候选里挑一个可拨的地址：跳过 reject 段，优先 IPv4。
func pickAddr(addrs []netip.Addr, reject netip.Prefix) netip.Addr {
	var first6 netip.Addr
	for _, a := range addrs {
		if reject.IsValid() && reject.Contains(a.Unmap()) {
			continue
		}
		if a.Is4() {
			return a
		}
		if !first6.IsValid() {
			first6 = a
		}
	}
	return first6
}

// parsePort 拒绝非数字端口。返回 0 端口去拨号只会变成一个看不懂的连接失败，
// 不如在这里就说清是配置写错了。
func parsePort(port string) (int, error) {
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("服务端端口 %q 不是数字", port)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("服务端端口 %d 超出范围", n)
	}
	return n, nil
}

// NewHysteria 按配置构造 hysteria2 出站，不立即连接。
// reject 一般是本客户端的假 IP 段，理由见 resolveServerHost。
func NewHysteria(sc config.ServerConfig, handshakeTimeout time.Duration, resolver HostResolver, reject netip.Prefix) (*Hysteria, error) {
	udpAddr, err := resolveServerAddr(context.Background(), resolver, sc.Addr, reject)
	if err != nil {
		return nil, fmt.Errorf("resolve server addr %q: %w", sc.Addr, err)
	}
	maxTx, err := sc.Bandwidth.MaxTx()
	if err != nil {
		return nil, err
	}
	maxRx, err := sc.Bandwidth.MaxRx()
	if err != nil {
		return nil, err
	}
	if handshakeTimeout <= 0 {
		handshakeTimeout = 10 * time.Second
	}
	return &Hysteria{
		template: client.Config{
			ServerAddr:       udpAddr,
			Auth:             sc.Auth,
			TLSConfig:        client.TLSConfig{ServerName: sc.TLS.SNI, InsecureSkipVerify: sc.TLS.Insecure},
			CongestionConfig: client.CongestionConfig{Type: sc.Congestion},
			BandwidthConfig:  client.BandwidthConfig{MaxTx: maxTx, MaxRx: maxRx},
			FastOpen:         sc.FastOpen,
		},
		handshakeTO: handshakeTimeout,
	}, nil
}

func (h *Hysteria) Name() string { return string(PolicyProxy) }

// Info 返回最近一次成功握手得到的服务端信息，可能为 nil。
func (h *Hysteria) Info() *client.HandshakeInfo {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.info
}

// Connected 报告共享 QUIC 连接当前是否可用，供 GUI 展示连接状态。
//
// cli 非 nil 表示最近一次握手成功且连接尚未失效。握手是懒触发的——
// 第一次真正拨号时才建立——所以刚启动、还没跑过任何流量时这里是 false，
// 那时确实还没连上，不是缺陷。出站关闭后一律 false。
func (h *Hysteria) Connected() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.closed && h.cli != nil
}

// Status 是给人看的服务端摘要：地址 + 拥塞算法，已握手时点明隧道在跑。
//
// 面板要能区分「配置好了」与「隧道真的通了」，光有 Connected() 的布尔值不够，
// 得有一行能贴上去的字。
func (h *Hysteria) Status() string {
	h.mu.Lock()
	connected := !h.closed && h.cli != nil
	h.mu.Unlock()
	if !connected {
		return h.template.ServerAddr.String()
	}
	return fmt.Sprintf("%s (QUIC 隧道已建, %s)", h.template.ServerAddr.String(), h.template.CongestionConfig.Type)
}

// DialContext 通过共享 QUIC 连接打开到 addr 的 TCP 流。
// addr 形如 "host:port"，域名直接交给服务端解析，避免本地 DNS 泄漏。
func (h *Hysteria) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	var lastErr error
	// nodeErr 留住第一次「节点级」失败。见函数末尾的解释：
	// 重试策略本身会把调用方的时限耗光，于是交出去的那条错误变成 context
	// deadline exceeded，而真实原因（节点不应答）被它盖住了。
	var nodeErr error
	for attempt := 1; attempt <= maxDialAttempt; attempt++ {
		cli, err := h.client(ctx)
		if err != nil {
			lastErr = err
			if h.NodeFailure(err) && nodeErr == nil {
				nodeErr = err
			}
			// 出站已关闭或调用方已放弃，重试只会白等退避。
			if errors.Is(err, ErrClosed) || ctx.Err() != nil {
				break
			}
		} else {
			conn, dialErr := cli.TCP(addr)
			if dialErr == nil {
				return &trackedConn{Conn: conn, h: h, gen: cli}, nil
			}
			lastErr = fmt.Errorf("tcp stream to %s: %w", addr, dialErr)
			switch {
			case isConnectionFatal(dialErr):
				h.invalidateCurrent(cli)
				h.recordFailure()
			case isTargetRefused(dialErr):
				// 是服务端拨不通这个目标，不是我们的隧道坏了。
				// 换隧道不会让它通，而拆掉共享连接会把别人正在传的连接一起打断；
				// 浏览器每页几十个请求里随时有这种目标，所以直接如实返回。
				return nil, lastErr
			case attempt == maxDialAttempt:
				// 连续开不了流却又报不出连接级原因（例如服务端的流数上限），
				// 不换一条隧道就会永久卡在这条连接上。这是唯一的兜底。
				h.invalidateCurrent(cli)
				h.recordFailure()
			}
		}
		if attempt == maxDialAttempt {
			break
		}
		if !h.waitBackoff(ctx, attempt) {
			break
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dial %s failed", addr)
	}
	// 交出去之前把原因换回真凶：重试要退避，三轮下来很容易把调用方的时限耗光，
	// 那时 lastErr 是「被调用方取消」，看起来像"这一路请求自己超时了、与节点无关"。
	// 可时限是被我们自己的重试吃掉的，节点没应答才是起因。
	// 不这么换，故障切换对「节点沉默死掉」这一种最常见的挂法永远不会触发。
	if nodeErr != nil && (errors.Is(lastErr, context.DeadlineExceeded) || errors.Is(lastErr, context.Canceled)) {
		return nil, fmt.Errorf("dial %s: %w", addr, nodeErr)
	}
	return nil, lastErr
}

// client 返回可用的客户端，必要时握手建立新连接。
func (h *Hysteria) client(ctx context.Context) (client.Client, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, ErrClosed
	}
	if h.cli != nil {
		cli := h.cli
		h.mu.Unlock()
		return cli, nil
	}
	retryAt := h.retryAt
	h.mu.Unlock()

	if !retryAt.IsZero() {
		if wait := time.Until(retryAt); wait > 0 {
			// 只在「等得到」的时候等。剩余预算比这段退避还短，这条连接注定超时，
			// 而干等到点会把它注定要输的那段时间全烧掉，最后交出去的是调用方那句
			// context deadline exceeded——真实原因（节点没应答、正在重连退避）反而盖住了。
			// 线上 2026-10-20 10:52–10:54:57 那 232 条「拨不通」就是这个形状：
			// 每条先等满 15s，再被时限掐掉，原因一个都没留下。
			if left, ok := remainingBudget(ctx); ok && left <= wait {
				return nil, fmt.Errorf("%w：还需 %v 才重试，而本次拨号只剩 %v，不再干等",
					ErrInBackoff, wait.Round(time.Millisecond), left.Round(time.Millisecond))
			}
			logx.Debugf("hysteria: 退避中，%v 后重试", wait.Round(time.Millisecond))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	h.connectMu.Lock()
	defer h.connectMu.Unlock()

	// 双重检查：可能已被并发的 goroutine 建立好。
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil, ErrClosed
	}
	if h.cli != nil {
		cli := h.cli
		h.mu.Unlock()
		return cli, nil
	}
	h.mu.Unlock()

	cfg := h.template // 副本，避免并发写 Config 的内部 filled 字段
	// 工厂在握手那一刻才装：分流是运行期可切的，装配期定死的话，
	// 用户切了模式之后这条隧道仍旧从旧网卡出去。
	if h.split != nil {
		cfg.ConnFactory = ProxyConnFactory{split: h.split}
	}
	hctx, cancel := context.WithTimeout(ctx, h.handshakeTO)
	defer cancel()

	type result struct {
		cli  client.Client
		info *client.HandshakeInfo
	}
	done := make(chan result, 1)
	go func() {
		cli, info, err := client.NewClient(&cfg)
		if err != nil {
			logx.Debugf("hysteria: 握手失败: %v", err)
			done <- result{}
			return
		}
		done <- result{cli: cli, info: info}
	}()

	var cli client.Client
	var info *client.HandshakeInfo
	select {
	case r := <-done:
		if r.cli == nil {
			h.recordFailure()
			return nil, fmt.Errorf("handshake with %v failed（检查地址/认证密码，或服务端是否可达）", h.template.ServerAddr)
		}
		cli, info = r.cli, r.info
	case <-hctx.Done():
		// 握手无法取消：丢弃其结果并在后台关闭，避免泄漏连接。
		go func() {
			if r := <-done; r.cli != nil {
				_ = r.cli.Close()
			}
		}()
		// 先分清是谁的时限到了：
		//   调用方放弃 —— 不是节点的错，也不该给它记一次失败；
		//   我们自己的握手预算用完 —— 节点没应答，这正是要触发故障切换的那种失败。
		// 早先这里不加区分地把 hctx.Err() 包装出去，于是错误里永远带着
		// context.DeadlineExceeded，节点级判据一看是超时就算了，
		// 结果节点彻底不应答时反而一次都不切。
		if ctx.Err() != nil {
			return nil, fmt.Errorf("握手被调用方取消: %w", ctx.Err())
		}
		h.recordFailure()
		return nil, fmt.Errorf("%w after %v", ErrHandshakeTimeout, h.handshakeTO)
	}

	h.mu.Lock()
	h.cli = cli
	h.info = info
	h.failures = 0
	h.retryAt = time.Time{}
	h.mu.Unlock()

	// BBR 模式下服务端不返回可用发送速率，info.Tx 为 0 属正常。
	logx.Infof("hysteria: 已连接 %v (UDPEnabled=%v, Tx=%d B/s)", cfg.ServerAddr, info.UDPEnabled, info.Tx)
	return cli, nil
}

// invalidateCurrent 丢弃 gen 这一代客户端，但仅当它仍然是当前连接。
//
// 代次校验是必需的：一条隧道被关掉时，挂在它上面的每条流都会在之后的某个时刻
// 报错，而那些迟到的错误针对的是旧客户端。若不加判断就无条件清空，
// 旧流的错误会把刚握手成功的新连接再拆一遍——一次流故障就此滚成持续重连，
// 而每次重连又打断一批正在传输的连接。
func (h *Hysteria) invalidateCurrent(gen client.Client) bool {
	if gen == nil {
		return false
	}
	h.mu.Lock()
	if h.cli != gen {
		h.mu.Unlock()
		return false
	}
	h.cli = nil
	h.mu.Unlock()
	_ = gen.Close()
	return true
}

// ResetBackoff 把"正在退避"这件事作废，让下一次拨号立刻尝试握手。
//
// 什么时候该调：**网络本身恢复了**（换了 Wi-Fi、网关重钉成功、网线插回去）。
// 退避的语义是"节点可能有毛病，别拿重试把它打穿"，而网络恢复不属于那件事——
// 那时节点一直是好的，只是我们连不出去。不调的话，恢复之后最长要干等
// backoffMax（30 秒）才重试，用户看到的是"网回来了但代理还要等半分钟"。
//
// 只清 retryAt 与失败计数，不动已建立的连接：如果此刻 h.cli 非空，
// 说明隧道本来就是通的，这次调用是空操作。
func (h *Hysteria) ResetBackoff() {
	h.mu.Lock()
	was := h.failures
	h.failures = 0
	h.retryAt = time.Time{}
	h.mu.Unlock()
	if was > 0 {
		logx.Infof("hysteria: 网络已恢复，退避清零（此前连续失败 %d 次），下一次拨号立即重试", was)
	}
}
func (h *Hysteria) recordFailure() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.failures++
	h.retryAt = time.Now().Add(backoffFor(h.failures))
}

// waitBackoff 在第 attempt 次失败后等待退避时间；ctx 取消则提前返回 false。
func (h *Hysteria) waitBackoff(ctx context.Context, attempt int) bool {
	h.mu.Lock()
	failures := h.failures
	h.mu.Unlock()
	if failures < attempt {
		failures = attempt
	}
	d := backoffFor(failures)
	// 与 client() 里那条同一判据：等不到的退避不要睡。
	// 睡了就是替调用方把预算耗光，下一圈拿到的仍是同一个还在退避的 retryAt，
	// 交出去的错误则从「节点在退避」退化成「调用方超时」。
	if left, ok := remainingBudget(ctx); ok && left <= d {
		return false
	}
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

func backoffFor(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	d := backoffBase
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= backoffMax {
			return backoffMax
		}
	}
	if d > backoffMax {
		d = backoffMax
	}
	// ±20% 抖动
	jitter := 1 + (rand.Float64()*0.4 - 0.2)
	return time.Duration(float64(d) * jitter)
}

// Close 关闭 QUIC 连接并标记出站不可用。
func (h *Hysteria) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	cli := h.cli
	h.cli = nil
	h.mu.Unlock()
	if cli != nil {
		return cli.Close()
	}
	return nil
}

// trackedConn 包装 hysteria2 提供的流：读写出错时，只有连接级错误才丢弃共享客户端。
// 注意：已经建立并传输过数据的流不做透明重放（TCP 语义不安全），只负责标记。
type trackedConn struct {
	net.Conn
	h *Hysteria
	// gen 是这条流所属的那一代客户端。失效判定要按代次比对，理由见 invalidateCurrent。
	gen client.Client

	mu     sync.Mutex
	broken bool
}

func (c *trackedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.noteError(err)
	return n, err
}

func (c *trackedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.noteError(err)
	return n, err
}

// noteError 只把连接级错误上报给共享客户端，其余都算这条流自己的归宿。
// 每条流最多报告一次，免得一条死流反复刷日志。
func (c *trackedConn) noteError(err error) {
	if !isConnectionFatal(err) {
		return
	}
	c.mu.Lock()
	if c.broken {
		c.mu.Unlock()
		return
	}
	c.broken = true
	c.mu.Unlock()
	// 只有真的换掉了当前连接才打 WARN。
	//
	// 一条 QUIC 连接坏掉时，挂在它上面的每条流都会报一次「连接级错误」，
	// 而它们全都在报同一件事。以前每一条都打一行，于是日志里是几十条
	// "隧道故障"——排障的人会以为隧道在反复抖动，实际只坏了一次。
	// 真正值得记的是"第几次换了连接"和"换掉的那次原因"。
	if c.h.invalidateCurrent(c.gen) {
		logx.Warnf("hysteria: 隧道故障，丢弃共享连接以便重连: %v", err)
		return
	}
	// 没能换掉（旧代次，或已经被别人换过）：这条只关涉它自己那条流。
	logx.Debugf("hysteria: 旧代次的流报错（共享连接已由别的流换掉）: %v", err)
}

// isConnectionFatal 判断错误是否意味着「整条 QUIC 连接已经不能再用」。
//
// 只能按真实类型判，不能看错误文本：连接关闭时 quic-go 会把连接级错误
// （空闲超时、无状态重置、传输/应用错误）原样报给挂在上面的每一条流，
// 而这些类型统统 Unwrap 出 net.ErrClosed；反过来流级错误
// （*quic.StreamError，含对端 RESET_STREAM）、目标级错误（下面的 DialError）、
// 以及自己设的读写超时（os.ErrDeadlineExceeded）都只关涉那一条流，
// 隧道本身完好。
//
// 早先这里不分级：任何非 EOF 的读写错误都拆隧道。代价是本机任何一个应用
// 的某条流出错，就会打断同一隧道上正在传的所有连接——表现是浏览器的
// 大文件下载随机在几十 KB 到几 MB 之间被掐断，而小请求几乎察觉不到。
func isConnectionFatal(err error) bool {
	if err == nil {
		return false
	}
	var (
		te              *quic.TransportError
		ae              *quic.ApplicationError
		idle            *quic.IdleTimeoutError
		handshake       *quic.HandshakeTimeoutError
		statelessReset  *quic.StatelessResetError
		versionMismatch *quic.VersionNegotiationError
	)
	switch {
	case errors.As(err, &te),
		errors.As(err, &ae),
		errors.As(err, &idle),
		errors.As(err, &handshake),
		errors.As(err, &statelessReset),
		errors.As(err, &versionMismatch):
		return true
	}
	var (
		connect coreErrs.ConnectError
		closed  coreErrs.ClosedError
		proto   coreErrs.ProtocolError
	)
	return errors.As(err, &connect) || errors.As(err, &closed) || errors.As(err, &proto)
}

// NodeFailure 实现 outbound.NodeFault。
//
// 用「排除法」而不是「只认连接级错误」：DialContext 在目标被拒时会明确早退
// （isTargetRefused），其余返回错误的路径都已经是重试满 maxDialAttempt 次之后的结果——
// 那里报出的可能是连接级错误、握手失败，也可能是服务端流数上限这类叫不出名字的错，
// 三者的结论一样：这个节点此刻服务不了我们。
// 只认连接级错误的白名单会漏掉最后一类，而它正是节点还在应答、却不再给新流时的形态。
//
// 一个这套判据看不见的情况：对端彻底不应答。那不产生错误，只有调用方的超时，
// 而这里会把 context.DeadlineExceeded 判成 false（不敢替调用方猜）。
// 所以故障切换还得自己主动探测，不能只靠转发路径上顺带收集的错误。
func (h *Hysteria) NodeFailure(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrClosed):
		// 是本进程自己关掉的（切节点、停机），不是节点的错。
		return false
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// 调用方放弃：入站那边等不下去了，与节点无关。
		return false
	}
	return !isTargetRefused(err)
}

// isTargetRefused 判断错误是否是「服务端拨不通这个目标」。
//
// 换一条隧道不会让这个目标变通，所以它既不该触发重连，也不该重试三轮：
// 浏览器每个页面都带着几个已经死掉的目标，为它们排队退避只是给自己添堵。
//
// 开了 fast_open 之后 hysteria 不在 TCP() 里等响应，这个错误要到第一次
// Read 才报出来（见 tcpConn.Read），所以它同样会走到 noteError 那边——
// 那里按「非连接级」处理，正是这里想要的结论。
func isTargetRefused(err error) bool {
	var de coreErrs.DialError
	return errors.As(err, &de)
}
