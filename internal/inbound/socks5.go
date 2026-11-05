// Package inbound 实现本地 SOCKS5 与 HTTP 代理入口。
package inbound

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/metrics"
	"wps_app/internal/router"
	"wps_app/internal/rules"
)

// SOCKS5 协议常量。
const (
	socks5Version = 0x05

	authNone     = 0x00
	authUserPass = 0x02
	authNoneAcc  = 0xff

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess              = 0x00
	repGeneralFailure       = 0x01
	repHostUnreachable      = 0x04
	repCmdNotSupported      = 0x07
	repAddrTypeNotSupported = 0x08
)

const (
	userPassVersion = 0x01
	userPassStatus  = 0x00
)

// SOCKS5 是 SOCKS5 入口。支持 CONNECT 与 UDP ASSOCIATE。
type SOCKS5 struct {
	router   *router.Router
	username string
	password string
	// reg 可为 nil。不统计时所有埋点都是空操作，行为与统计版完全一致。
	reg *metrics.Registry
	// blocked 处理命中拦截名单的连接（静默丢弃）。
	blocked blocker
}

// NewSOCKS5 创建入口。username 为空时不要求认证。
// reg 可选：传入连接注册表即可统计每条连接的上下行字节与命中规则。
func NewSOCKS5(r *router.Router, username, password string, reg ...*metrics.Registry) *SOCKS5 {
	s := &SOCKS5{router: r, username: username, password: password}
	if len(reg) > 0 {
		s.reg = reg[0]
	}
	s.blocked = newBlocker("socks5", s.reg)
	return s
}

// Serve 接管已建立的监听器。
func (s *SOCKS5) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			logx.Warnf("socks5 accept: %v", err)
			continue
		}
		go s.handle(c)
	}
}

// request 是一条 SOCKS5 请求解析后的结果。
type request struct {
	cmd  byte
	addr string
}

func (s *SOCKS5) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))

	req, err := s.negotiate(c)
	if err != nil {
		logx.Debugf("socks5 %s: 协商失败: %v", c.RemoteAddr(), err)
		return
	}
	_ = c.SetDeadline(time.Time{})

	if req.cmd == cmdUDPAssociate {
		s.serveUDPAssociate(c)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	remote, res, err := s.router.Dial(ctx, req.addr)
	cancel()
	if err != nil {
		if isBlocked(err) {
			s.blocked.drop(c, c.RemoteAddr().String(), req.addr, res)
			return
		}
		logx.NoteFailure("socks5 "+req.addr, failureReason(err), err)
		s.reg.Refuse("socks5", c.RemoteAddr().String(), req.addr, res, err.Error())
		_ = reply(c, repHostUnreachable)
		return
	}
	defer remote.Close()
	// 成功那条降到 Debug：理由见 http.go 里同一处（一天几万行，连接表才是
	// 查"这个站走了哪条路"的地方）。
	logx.Debugf("socks5 %s -> %s [%s | %s]", c.RemoteAddr(), req.addr, res.Policy, res.Matched)

	if err := reply(c, repSuccess); err != nil {
		return
	}
	// 埋点：从客户端读到的算上行，写向远端的算下行。
	rec := s.reg.Begin("socks5", c.RemoteAddr().String(), res)
	defer s.reg.End(rec)
	relay(metrics.Wrap(c, upOf(rec)), metrics.Wrap(remote, downOf(rec)))
}

// upOf/downOf 取连接记录上的上下行计数器，记录不存在时返回 nil（Wrap 原样返回连接）。
func upOf(c *metrics.Conn) *atomic.Uint64 {
	if c == nil {
		return nil
	}
	return &c.Up
}

func downOf(c *metrics.Conn) *atomic.Uint64 {
	if c == nil {
		return nil
	}
	return &c.Down
}

// negotiate 完成方法协商与请求解析。返回的零值表示该连接已处理完毕（错误响应）。
func (s *SOCKS5) negotiate(c net.Conn) (request, error) {
	// --- 阶段一：方法协商 ---
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return request{}, err
	}
	if hdr[0] != socks5Version {
		return request{}, fmt.Errorf("unsupported socks version %d", hdr[0])
	}
	n := int(hdr[1])
	if n == 0 {
		return request{}, errors.New("no auth methods offered")
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(c, methods); err != nil {
		return request{}, err
	}
	if s.username != "" {
		if !containsByte(methods, authUserPass) {
			_, _ = c.Write([]byte{socks5Version, authNoneAcc})
			return request{}, errors.New("client does not offer username/password auth")
		}
		if _, err := c.Write([]byte{socks5Version, authUserPass}); err != nil {
			return request{}, err
		}
		if err := s.authenticate(c); err != nil {
			return request{}, err
		}
	} else {
		if !containsByte(methods, authNone) {
			_, _ = c.Write([]byte{socks5Version, authNoneAcc})
			return request{}, errors.New("client does not offer no-auth")
		}
		if _, err := c.Write([]byte{socks5Version, authNone}); err != nil {
			return request{}, err
		}
	}

	// --- 阶段二：请求 ---
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return request{}, err
	}
	if req[0] != socks5Version {
		return request{}, fmt.Errorf("bad request version %d", req[0])
	}
	switch req[1] {
	case cmdConnect, cmdUDPAssociate:
	default:
		_ = reply(c, repCmdNotSupported)
		return request{}, fmt.Errorf("unknown command %d", req[1])
	}

	host, err := readAddr(c, req[3])
	if err != nil {
		_ = reply(c, repAddrTypeNotSupported)
		return request{}, err
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return request{}, err
	}
	return request{cmd: req[1], addr: net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))}, nil
}

func (s *SOCKS5) authenticate(c net.Conn) error {
	// RFC 1929: VER(1) ULEN(1) UNAME(ULEN) PLEN(1) PASSWD(PLEN)
	var v [2]byte
	if _, err := io.ReadFull(c, v[:]); err != nil {
		return err
	}
	if v[0] != userPassVersion {
		return fmt.Errorf("bad userpass auth version %d", v[0])
	}
	readSized := func(n byte) (string, error) {
		buf := make([]byte, n)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	}
	// v[1] 就是用户名长度，不能再读一个长度字节。
	user, err := readSized(v[1])
	if err != nil {
		return err
	}
	var pl [1]byte
	if _, err := io.ReadFull(c, pl[:]); err != nil {
		return err
	}
	pass, err := readSized(pl[0])
	if err != nil {
		return err
	}
	if user != s.username || !secureEqual(pass, s.password) {
		_, _ = c.Write([]byte{userPassVersion, 0x01})
		return fmt.Errorf("bad credentials for user %q", user)
	}
	if _, err := c.Write([]byte{userPassVersion, userPassStatus}); err != nil {
		return err
	}
	return nil
}

// secureEqual 定长比较口令。用 crypto/subtle 而不是 `!=`：
// 后者按字节提前返回，攻击者能用响应耗时逐字节猜出口令。
// 长度不同时也走恒定路径（先比长度只是把长度暴露出去，而 ULEN/PLEN
// 本来就是明文写在报文里的，没有额外信息可泄漏）。
func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// readAddr 按 ATYP 读取目标地址。
func readAddr(r io.Reader, atyp byte) (string, error) {
	host, _, err := readAddrN(r, atyp)
	return host, err
}

// readAddrN 与 readAddr 相同，只是多报出消耗了多少字节。
// UDP 关联的报文头里地址后面还跟着端口，没有这个长度就没法切正文。
func readAddrN(r io.Reader, atyp byte) (string, int, error) {
	switch atyp {
	case atypIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:]).String(), 4, nil
	case atypIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 0, err
		}
		return net.IP(b[:]).String(), 16, nil
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		if l[0] == 0 {
			return "", 0, errors.New("empty domain in socks5 request")
		}
		buf := make([]byte, l[0])
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host := string(buf)
		if !rules.ValidHostName(host) {
			return "", 0, fmt.Errorf("socks5 域名里出现了不可能出现在主机名里的字符")
		}
		return host, 1 + int(l[0]), nil
	default:
		return "", 0, fmt.Errorf("unsupported address type %d", atyp)
	}
}

// reply 写回 SOCKS5 应答。成功时 BND.ADDR/BND.PORT 用 0.0.0.0:0 占位。
func reply(c net.Conn, code byte) error {
	buf := []byte{socks5Version, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := c.Write(buf)
	return err
}

func containsByte(b []byte, v byte) bool {
	for _, x := range b {
		if x == v {
			return true
		}
	}
	return false
}

// relay 双向转发，任一侧结束即关闭两侧。
//
// 握手阶段的 deadline 已经在进 relay 前清掉了，因此这里必须自己兜住资源：
// 每条连接占两个 goroutine，没有上界的话一条彻底没人理的隧道会一直挂着。
// 用的是「空闲超时」而不是「总时长上限」——每次成功收发都会把窗口往后推，
// 于是长连接只要还有流量就不会被打断，真正闲置的才被回收。
func relay(client, remote net.Conn) {
	ci := newIdleConn(client, tunnelIdleTimeout)
	ri := newIdleConn(remote, tunnelIdleTimeout)
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(ri, ci)
		halfClose(ri)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(ci, ri)
		halfClose(ci)
		done <- struct{}{}
	}()
	<-done
	// 等待另一方向结束或客户端断开，避免过早关闭导致截断。
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	_ = ci.Close()
	_ = ri.Close()
}

// tunnelIdleTimeout 是隧道的空闲回收窗口。取足够大的值（半小时），
// 正常的长连接与「客户端连上不讲话」的怪癖都不会被它碰上；
// 它只是给「进程里永远挂着一条死隧道」这件事兜个底。
const tunnelIdleTimeout = 30 * time.Minute

func newIdleConn(c net.Conn, idle time.Duration) *idleConn {
	ic := &idleConn{Conn: c, idle: idle}
	ic.touched.Store(time.Now().UnixNano())
	_ = c.SetDeadline(time.Now().Add(idle))
	return ic
}

// idleConn 把空闲截止时间往后推，但不是每读一块就推一次。
// 两次之间至少隔 idle/4：一条忙连接不再每个 32KB 都做 setsockopt，
// 真正闲下来时，最初设下的截止时间仍然会到点。
type idleConn struct {
	net.Conn
	idle    time.Duration
	touched atomic.Int64
	// reads 只给测试用：splice 接上之后这里应当保持为 0。
	reads atomic.Int64
}

func (c *idleConn) bump(n int) {
	metrics.BumpDeadline(&c.touched, c.idle/4, c.idle, n, c.Conn.SetDeadline)
}

func (c *idleConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	n, err := c.Conn.Read(p)
	c.bump(n)
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.bump(n)
	return n, err
}

// Unwrap 让 splice 剥到里面的 *TCPConn。
func (c *idleConn) Unwrap() net.Conn { return c.Conn }

// CountRead 把 splice 搬过的字节补记到里面的计数包装上。
func (c *idleConn) CountRead(n int64) { metrics.CountRead(c.Conn, n) }

// ReadFrom 两端都是 TCP 时走内核 splice。源不是 TCP（QUIC、TLS）就退回用户态拷贝。
func (c *idleConn) ReadFrom(r io.Reader) (int64, error) {
	src, _ := r.(net.Conn)
	if metrics.TCPOf(c.Conn) == nil || metrics.TCPOf(src) == nil {
		return metrics.CopyPooled(c, r)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	if fd, ok := metrics.DupTCP(c.Conn); ok {
		go func() {
			defer close(done)
			metrics.WatchTCPWrite(fd, c.idle/4, func() {
				c.touched.Store(time.Now().UnixNano())
				_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
			}, stop)
			_ = syscall.Close(fd)
		}()
	} else {
		close(done)
	}
	n, _, err := metrics.CopySplice(c.Conn, r)
	close(stop)
	<-done
	if n > 0 {
		c.touched.Store(time.Now().UnixNano())
		_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

// SyscallConn 把底层 fd 交出去。包装层不转发的话，再套一层就拿不到。
func (c *idleConn) SyscallConn() (syscall.RawConn, error) {
	return metrics.RawConn(c.Conn)
}

// CloseWrite 透传给底层连接：relay 用类型断言决定能不能只关掉这一个方向，
// 包装层不实现它就等于把所有隧道都判成「不能半关」。
func (c *idleConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return metrics.ErrNoHalfClose
}

// halfClose 关掉写侧，让对端知道这一方向发完了；做不到就什么都不做。
//
// 这里曾经退化成 `c.Close()`，两种代价都很实在：
//   - 明文 HTTP 转发：请求刚写完就关掉整条连接，响应永远回不来，
//     浏览器只看到空响应（hysteria 的流不支持半关，于是这条路径全军覆没）；
//   - 隧道：一个方向收尾时顺手掐掉另一个还在传的方向。
//
// 少发一个 FIN 最多让对端晚一点收尾（relay 有 10s 宽限与最终 Close 兜底），
// 多关一条连接则会吃掉真实数据，所以宁可什么都不做。
func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
