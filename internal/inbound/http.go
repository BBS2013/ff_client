package inbound

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/metrics"
	"wps_app/internal/router"
)

// HTTPProxy 是 HTTP 代理入口，支持 CONNECT 隧道与明文绝对 URI 请求。
type HTTPProxy struct {
	router *router.Router
	// reg 可为 nil。不统计时所有埋点都是空操作，行为与统计版完全一致。
	reg *metrics.Registry

	// blocked 处理命中拦截名单的连接（静默丢弃）。
	blocked blocker
}

// NewHTTPProxy 创建 HTTP 代理入口。
// reg 可选：传入连接注册表即可统计每条连接的上下行字节与命中规则。
func NewHTTPProxy(r *router.Router, reg ...*metrics.Registry) *HTTPProxy {
	h := &HTTPProxy{router: r}
	if len(reg) > 0 {
		h.reg = reg[0]
	}
	h.blocked = newBlocker("http", h.reg)
	return h
}

// Serve 接管已建立的监听器。
func (h *HTTPProxy) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			logx.Warnf("http accept: %v", err)
			continue
		}
		go h.handle(c)
	}
}

func (h *HTTPProxy) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))

	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		logx.Debugf("http 读取请求失败: %v", err)
		return
	}
	defer req.Body.Close()

	if strings.EqualFold(req.Method, http.MethodConnect) {
		// br 必须一起传下去：CONNECT 之后连接就变成裸隧道了，
		// 而 bufio.Reader 在解析请求头时通常已经预读走了后面若干字节
		// （客户端把 CONNECT 和首段隧道数据一次 write 出去时必然如此）。
		// 隧道若直接读裸 conn，这些字节就永远烂在 br 的缓冲区里。
		h.handleConnect(c, br, req)
		return
	}
	h.handleForward(c, req)
}

// bufferedConn 把一条 net.Conn 的读方向换成另一个 reader，写方向仍是原连接。
// CloseWrite 等方法由内嵌的 net.Conn 直接提升上来，转发与计数包装都不受影响。
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// handleConnect 处理 CONNECT host:port，建立隧道后双向裸转发。
func (h *HTTPProxy) handleConnect(c net.Conn, br *bufio.Reader, req *http.Request) {
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	if target == "" {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	// Host 头可以带端口，req.URL.Host 在 CONNECT 形态下可能只有主机名。
	// 交给 dial 去 SplitHostPort 统一处理，这里只挡明显非法的空主机。
	if host, _, herr := net.SplitHostPort(target); herr == nil && host == "" {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	remote, res, err := h.dial(target)
	if err != nil {
		if isBlocked(err) {
			h.blocked.drop(c, c.RemoteAddr().String(), target, res)
			return
		}
		// 失败按「目标 + 原因类别」聚合：浏览器对一个打不开的站会重试几十次，
		// 而每一次的原因里都带着不同的超时毫秒数——逐条打出来的结果是一天
		// 几万行同一条消息（现场实测 22139 行 / 3.7 万行），真正有用的那几行
		// 被埋在里面。同 key 60 秒内只打第一条，其余汇总。
		logx.NoteFailure("http CONNECT "+target, failureReason(err), err)
		h.reg.Refuse("http", c.RemoteAddr().String(), target, res, err.Error())
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	// 成功那条降到 Debug：浏览器开一个页面就是几十条 CONNECT，
	// 每条都打一行 Info 的结果是一天几万行，而排障时没人会去看
	// "刚才打开了哪些站"。连接表里有完整的一行（路径、命中、字节），
	// 那才是"这个站走了哪条路"该去的地方。
	logx.Debugf("http CONNECT %s [%s | %s]", target, res.Policy, res.Matched)
	if _, err := c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})
	rec := h.reg.Begin("http", c.RemoteAddr().String(), res)
	defer h.reg.End(rec)
	// 隧道从 br 读而不是从 c 读：br 里可能已经躺着客户端紧跟着 CONNECT
	// 发来的首段数据。绕过它就等于静默丢包——客户端表现为握手后卡死。
	tunnel := &bufferedConn{Conn: c, r: br}
	relay(metrics.Wrap(tunnel, upOf(rec)), metrics.Wrap(remote, downOf(rec)))
}

// handleForward 处理明文 HTTP 的绝对 URI 请求，转发后原样回传响应。
func (h *HTTPProxy) handleForward(c net.Conn, req *http.Request) {
	u, err := url.Parse(req.RequestURI)
	if err != nil || !u.IsAbs() {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	if u.Scheme != "http" {
		// https 绝对 URI 应走 CONNECT，这里直接拒绝避免明文泄露。
		_, _ = c.Write([]byte("HTTP/1.1 501 Not Implemented\r\n\r\n"))
		return
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	// authority 为空的绝对 URI 必须拒掉，不能让它一路走到拨号那一步。
	// `http://`、`http:/foo`、`http://:80/` 的 Hostname() 都是空串，
	// JoinHostPort("", "80") 得到 ":80"，而拨 ":80" 就是拨本机回环——
	// 于是任何能驱动这个代理的客户端都能借它去打本机任意端口。
	host := u.Hostname()
	if !forwardableHost(host) {
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	target := net.JoinHostPort(host, port)

	remote, res, err := h.dial(target)
	if err != nil {
		if isBlocked(err) {
			h.blocked.drop(c, c.RemoteAddr().String(), target, res)
			return
		}
		logx.Warnf("http %s %s 失败: %v", req.Method, target, err)
		h.reg.Refuse("http", c.RemoteAddr().String(), target, res, err.Error())
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()
	logx.Infof("http %s %s [%s | %s]", req.Method, target, res.Policy, res.Matched)

	// needEOF 必须在转发前定：req.Write 会把正文长度写进请求头，
	// 之后再看 ContentLength 拿到的就是它自己写出去的值，分不清原始分帧方式。
	needEOF := requestNeedsEOF(req)

	_ = remote.SetDeadline(time.Now().Add(2 * time.Minute))
	// 转发前先摘掉跳级头（RFC 7230 §6.1）。req.Write 原样照抄 req.Header，
	// 不摘的话 Proxy-Authorization 会一路送到源站——等于把代理口令
	// 泄露给每一个被访问的第三方服务器。
	stripHopByHop(req.Header)
	if err := req.Write(remote); err != nil {
		logx.Warnf("http 转发请求到 %s 失败: %v", target, err)
		return
	}
	_ = remote.SetDeadline(time.Time{})
	// 客户端侧的握手 deadline 同样要清掉：否则一个下载超过 2 分钟的正常
	// 请求会被连同这条连接一起掐掉（原先只清了 remote 的，c 的那份一直挂着）。
	_ = c.SetDeadline(time.Time{})

	rec := h.reg.Begin("http", c.RemoteAddr().String(), res)
	defer h.reg.End(rec)

	// 这里不走 relay：请求体与响应是两个独立的 io.Copy。
	// 上行从请求体读（请求头已被 http.ReadRequest 吃掉，不计入），
	// 下行从远端读，因此两个方向各自包一层只读计数即可。
	//
	// 关键在 needEOF：只有正文由 EOF 定界的请求才需要半关收尾。
	// 带 Content-Length 或压根没正文的请求，源站读完那几字节就知道正文结束了，
	// 这时补一个 FIN 不是「更规范」而是多余的——Tengine 这类源站收到 FIN 会
	// 当成客户端说完了，直接不回响应把连接关掉，客户端只看到一个空响应。
	go func() {
		_, _ = io.Copy(remote, metrics.CountReader(req.Body, upOf(rec)))
		if needEOF {
			halfClose(remote)
		}
	}()

	// 响应方向必须解析出分帧信息再回传，而不是无脑 io.Copy 到 EOF：
	// 源站按 keep-alive 留着连接时，那个 EOF 永远不会到，转发会一直挂着
	// （每请求泄漏一个 goroutine 和一个 fd）。解析之后正文长度是确定的，
	// 抄完就能收尾；顺带还能把响应侧的跳级头摘掉，原样转发是违规的。
	br := bufio.NewReader(metrics.Wrap(remote, downOf(rec)))
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		logx.Warnf("http 转发 %s 的响应不可读: %v", target, err)
		_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer resp.Body.Close()
	stripHopByHop(resp.Header)
	if err := resp.Write(c); err != nil {
		logx.Warnf("http 转发 %s 的响应中断: %v", target, err)
	}
}

// requestNeedsEOF 判断请求正文是否由 EOF 定界，也就是转发完必须补一个 FIN。
//
// 带 Content-Length（>=0）或 chunked 的请求，源站按长度或结尾块自己就能收尾，
// 这时补 FIN 是纯粹的副作用：Tengine 收到 FIN 会当成客户端说完了，
// 直接不回响应把连接关掉，客户端只看到一个空响应。
func requestNeedsEOF(req *http.Request) bool {
	return req.ContentLength < 0 && len(req.TransferEncoding) == 0
}

// hopByHopHeaders 是 RFC 7230 §6.1 规定必须由中间代理摘掉的头。
// Proxy-Authorization 也在内：它是给代理自己的凭据，
// 转发给源站等于把代理口令交出去。
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// stripHopByHop 摘掉跳级头。除了固定名单，还要摘掉 Connection 自己
// 点名的那几个——`Connection: X-Drop` 的语义就是「X-Drop 也是跳级的」，
// 漏掉它等于给了请求走私一个口子。
func stripHopByHop(h http.Header) {
	for _, f := range strings.Split(h.Get("Connection"), ",") {
		if name := strings.TrimSpace(f); name != "" {
			h.Del(name)
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// forwardableHost 判断请求里的主机名是否允许被转发。
//
// 空主机与「未指定地址」都要拒掉：前者的 URI 是 `http://`、`http:/foo` 这类
// 退化写法，后者是 `http://0.0.0.0/`、`http://[::]:80/`。两者拼出的拨号目标
// 分别落在回环上，等于给了一个能驱动本代理的客户端一条打本机任意端口的路。
//
// 这里刻意只挡「未指定地址」而不挡整个 127.0.0.0/8：把请求显式指向某个回环
// 端口是用户自己的意图（调试本机服务就是常见用法），不该由代理替他决定；
// 而上面那两种写法从来不是意图，只是畸形输入。
func forwardableHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil && ip.IsUnspecified() {
		return false
	}
	return true
}

func (h *HTTPProxy) dial(target string) (net.Conn, router.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, res, err := h.router.Dial(ctx, target)
	if err != nil {
		return nil, res, fmt.Errorf("dial %s: %w", target, err)
	}
	return conn, res, nil
}
