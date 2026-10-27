package inbound

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
	"wps_app/internal/rules"
)

// TestMain 默认压掉日志，避免入站日志淹没断言输出；
// 排查时设 WPS_TEST_LOG=1 可恢复完整日志。
func TestMain(m *testing.M) {
	if os.Getenv("WPS_TEST_LOG") == "" {
		logx.SetOutput(io.Discard)
		logx.SetLevel(logx.LevelError)
	}
	os.Exit(m.Run())
}

func newReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

// rulesDirect 是「全部直连」的最小可编译规则集。rules.Load 会拒绝一条规则都没有的
// 文件，所以 FINAL 之外补一条不影响断言的 IP-CIDR。
const rulesDirect = "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,DIRECT"

// failingDialer 模拟不可用的 PROXY 出站，用于验证错误应答路径；
// 同时记录最后一次拨号地址，便于断言代理拼出的目标。
type failingDialer struct {
	mu   sync.Mutex
	addr string
	err  error
}

func (f *failingDialer) Name() string { return string(outbound.PolicyProxy) }

func (f *failingDialer) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.addr = addr
	f.mu.Unlock()
	return nil, f.err
}

func (f *failingDialer) Close() error { return nil }

func (f *failingDialer) lastAddr() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addr
}

// newTestRouter 用一段规则文本搭出路由器；PROXY 出站固定失败，
// 因此任何匹配 PROXY 的请求都会走到错误应答分支。
func newTestRouter(t *testing.T, ruleText string) *router.Router {
	rt, _ := newTestRouterWithProxy(t, ruleText)
	return rt
}

// newTestRouterWithProxy 同newTestRouter，但把 PROXY 出站一并返回给调用方。
func newTestRouterWithProxy(t *testing.T, ruleText string) (*router.Router, *failingDialer) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(path, []byte(ruleText), 0o644); err != nil {
		t.Fatalf("写规则文件: %v", err)
	}
	eng, err := rules.Load(path, nil, nil)
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	proxy := &failingDialer{err: errors.New("proxy unavailable in test")}
	out := outbound.NewSet(outbound.NewDirect(3*time.Second), proxy)
	t.Cleanup(func() { _ = out.Close() })
	return router.New(eng, out, 3*time.Second), proxy
}

// startEchoServer 起一个「原样回显」的 TCP 服务，充当 SOCKS5/HTTP 隧道的对端。
func startEchoServer(t *testing.T) net.Listener {
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
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln
}

// startSOCKS5 起一个走指定规则与认证的 SOCKS5 入口，返回监听地址。
func startSOCKS5(t *testing.T, ruleText, user, pass string) string {
	t.Helper()
	rt := newTestRouter(t, ruleText)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = NewSOCKS5(rt, user, pass).Serve(ln) }()
	return ln.Addr().String()
}

// startHTTPProxy 起一个走指定规则的 HTTP 代理入口，返回监听地址。
func startHTTPProxy(t *testing.T, ruleText string) string {
	t.Helper()
	rt := newTestRouter(t, ruleText)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = NewHTTPProxy(rt).Serve(ln) }()
	return ln.Addr().String()
}

// startHTTPProxyWithProxy 同 startHTTPProxy，但一并返回可观测的 PROXY 出站。
func startHTTPProxyWithProxy(t *testing.T, ruleText string) (string, *failingDialer) {
	t.Helper()
	rt, proxy := newTestRouterWithProxy(t, ruleText)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = NewHTTPProxy(rt).Serve(ln) }()
	return ln.Addr().String(), proxy
}

func dialProxy(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("连接代理 %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// socksGreeting 写方法协商：VER + NMETHODS + METHODS。
func socksGreeting(t *testing.T, c net.Conn, methods ...byte) {
	t.Helper()
	buf := []byte{socks5Version, byte(len(methods))}
	buf = append(buf, methods...)
	if _, err := c.Write(buf); err != nil {
		t.Fatalf("写协商: %v", err)
	}
}

func readSocksMethod(t *testing.T, c net.Conn) byte {
	t.Helper()
	var b [2]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		t.Fatalf("读协商应答: %v", err)
	}
	if b[0] != socks5Version {
		t.Fatalf("应答版本 = %d, want %d", b[0], socks5Version)
	}
	return b[1]
}

func socksConnectRequest(t *testing.T, c net.Conn, cmd byte, atyp byte, addr []byte, port uint16) {
	t.Helper()
	buf := []byte{socks5Version, cmd, 0x00, atyp}
	buf = append(buf, addr...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	buf = append(buf, p[:]...)
	if _, err := c.Write(buf); err != nil {
		t.Fatalf("写 CONNECT 请求: %v", err)
	}
}

func readSocksReply(t *testing.T, c net.Conn) byte {
	t.Helper()
	var b [10]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		t.Fatalf("读 CONNECT 应答: %v", err)
	}
	if b[0] != socks5Version {
		t.Fatalf("应答版本 = %d, want %d", b[0], socks5Version)
	}
	return b[1]
}

func domainAddr(host string) []byte { return append([]byte{byte(len(host))}, host...) }

func TestSOCKS5ConnectRelaysOverDomainTarget(t *testing.T) {
	echo := startEchoServer(t)
	host, sport, _ := net.SplitHostPort(echo.Addr().String())
	var sp uint16
	fmt.Sscanf(sport, "%d", &sp)

	proxyAddr := startSOCKS5(t, rulesDirect, "", "")
	c := dialProxy(t, proxyAddr)

	socksGreeting(t, c, authNone)
	if m := readSocksMethod(t, c); m != authNone {
		t.Fatalf("选中方法 = %#x, want %#x", m, authNone)
	}
	socksConnectRequest(t, c, cmdConnect, atypDomain, domainAddr(host), sp)

	if rep := readSocksReply(t, c); rep != repSuccess {
		t.Fatalf("CONNECT 应答 = %#x, want %#x", rep, repSuccess)
	}
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("写 payload: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("读回显: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("回显 = %q, want \"ping\"", buf)
	}
}

func TestSOCKS5ConnectAcceptsIPv4AndIPv6Targets(t *testing.T) {
	cases := []struct {
		name string
		atyp byte
		addr []byte
	}{
		{"IPv4", atypIPv4, []byte{127, 0, 0, 1}},
		{"IPv6", atypIPv6, net.ParseIP("::1").To16()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxyAddr := startSOCKS5(t, rulesDirect, "", "")
			c := dialProxy(t, proxyAddr)
			socksGreeting(t, c, authNone)
			if m := readSocksMethod(t, c); m != authNone {
				t.Fatalf("选中方法 = %#x", m)
			}
			// 指向一个没人监听的端口：期望走到「按目标地址拼装正确」的失败路径，
			// 即 repHostUnreachable 而不是协议层错误。
			socksConnectRequest(t, c, cmdConnect, tc.atyp, tc.addr, 1)
			rep := readSocksReply(t, c)
			if rep != repHostUnreachable && rep != repSuccess {
				t.Fatalf("应答 = %#x, 期望 %#x 或 %#x", rep, repHostUnreachable, repSuccess)
			}
		})
	}
}

func TestSOCKS5RejectsUnknownCommand(t *testing.T) {
	proxyAddr := startSOCKS5(t, rulesDirect, "", "")
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authNone)
	readSocksMethod(t, c)
	socksConnectRequest(t, c, 0x02 /* BIND */, atypDomain, domainAddr("example.com"), 80)
	if rep := readSocksReply(t, c); rep != repCmdNotSupported {
		t.Fatalf("未知命令应答 = %#x, want %#x", rep, repCmdNotSupported)
	}
}

func TestSOCKS5RejectsBadVersion(t *testing.T) {
	proxyAddr := startSOCKS5(t, rulesDirect, "", "")
	c := dialProxy(t, proxyAddr)
	if _, err := c.Write([]byte{0x04, 0x01, authNone}); err != nil {
		t.Fatalf("写: %v", err)
	}
	// 服务端应直接断开，不做应答。
	if _, err := c.Read(make([]byte, 2)); err == nil {
		t.Fatal("版本不为 5 时不应有应答，连接应被关闭")
	}
}

func TestSOCKS5RejectsOfferWithoutNoAuth(t *testing.T) {
	proxyAddr := startSOCKS5(t, rulesDirect, "", "")
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authUserPass) // 服务端不要求认证
	if m := readSocksMethod(t, c); m != authNoneAcc {
		t.Fatalf("应答方法 = %#x, want %#x（无可用方法）", m, authNoneAcc)
	}
}

func TestSOCKS5UserPassAuthSucceeds(t *testing.T) {
	echo := startEchoServer(t)
	host, sport, _ := net.SplitHostPort(echo.Addr().String())
	var sp uint16
	fmt.Sscanf(sport, "%d", &sp)

	proxyAddr := startSOCKS5(t, rulesDirect, "alice", "s3cret")
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authNone, authUserPass)
	if m := readSocksMethod(t, c); m != authUserPass {
		t.Fatalf("选中方法 = %#x, want %#x", m, authUserPass)
	}

	auth := []byte{userPassVersion, byte(len("alice"))}
	auth = append(auth, "alice"...)
	auth = append(auth, byte(len("s3cret")))
	auth = append(auth, "s3cret"...)
	if _, err := c.Write(auth); err != nil {
		t.Fatalf("写认证: %v", err)
	}
	var st [2]byte
	if _, err := io.ReadFull(c, st[:]); err != nil {
		t.Fatalf("读认证结果: %v", err)
	}
	if st[0] != userPassVersion || st[1] != userPassStatus {
		t.Fatalf("认证结果 = %#x, want %#x %#x", st, userPassVersion, userPassStatus)
	}

	socksConnectRequest(t, c, cmdConnect, atypDomain, domainAddr(host), sp)
	if rep := readSocksReply(t, c); rep != repSuccess {
		t.Fatalf("CONNECT 应答 = %#x, want %#x", rep, repSuccess)
	}
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatalf("写: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("读回显: %v", err)
	}
	if string(buf) != "hi" {
		t.Fatalf("回显 = %q", buf)
	}
}

func TestSOCKS5UserPassAuthRejectsWrongPassword(t *testing.T) {
	proxyAddr := startSOCKS5(t, rulesDirect, "alice", "s3cret")
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authUserPass)
	if m := readSocksMethod(t, c); m != authUserPass {
		t.Fatalf("选中方法 = %#x", m)
	}
	auth := []byte{userPassVersion, byte(len("alice"))}
	auth = append(auth, "alice"...)
	auth = append(auth, byte(len("wrong")))
	auth = append(auth, "wrong"...)
	if _, err := c.Write(auth); err != nil {
		t.Fatalf("写认证: %v", err)
	}
	var st [2]byte
	if _, err := io.ReadFull(c, st[:]); err != nil {
		t.Fatalf("读认证结果: %v", err)
	}
	if st[1] == userPassStatus {
		t.Fatal("错误口令不应通过认证")
	}
	// 认证失败后不得再建立隧道。
	if _, err := c.Read(make([]byte, 4)); err == nil {
		t.Fatal("认证失败后服务端应关闭连接")
	}
}

func TestSOCKS5RequiresUserPassMethodWhenConfigured(t *testing.T) {
	proxyAddr := startSOCKS5(t, rulesDirect, "alice", "s3cret")
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authNone) // 客户端只提供免认证
	if m := readSocksMethod(t, c); m != authNoneAcc {
		t.Fatalf("应答方法 = %#x, want %#x（服务端要求用户名密码）", m, authNoneAcc)
	}
}

func TestSOCKS5ReportsDialFailureAsHostUnreachable(t *testing.T) {
	// proxy.example 命中 PROXY，而测试里的 PROXY 出站必然失败。
	proxyAddr := startSOCKS5(t, "DOMAIN,proxy.example,PROXY\nFINAL,DIRECT", "", "")
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authNone)
	readSocksMethod(t, c)
	socksConnectRequest(t, c, cmdConnect, atypDomain, domainAddr("proxy.example"), 443)
	if rep := readSocksReply(t, c); rep != repHostUnreachable {
		t.Fatalf("拨号失败应答 = %#x, want %#x", rep, repHostUnreachable)
	}
}

func TestSOCKS5RejectsUnsupportedAddrType(t *testing.T) {
	proxyAddr := startSOCKS5(t, rulesDirect, "", "")
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authNone)
	readSocksMethod(t, c)
	socksConnectRequest(t, c, cmdConnect, 0x05, []byte{1, 2, 3, 4}, 80)
	if rep := readSocksReply(t, c); rep != repAddrTypeNotSupported {
		t.Fatalf("未知地址类型应答 = %#x, want %#x", rep, repAddrTypeNotSupported)
	}
}

func TestSOCKS5RejectsEmptyDomain(t *testing.T) {
	proxyAddr := startSOCKS5(t, rulesDirect, "", "")
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authNone)
	readSocksMethod(t, c)
	// ATYP=DOMAIN 但长度为 0。
	socksConnectRequest(t, c, cmdConnect, atypDomain, []byte{0}, 80)
	if rep := readSocksReply(t, c); rep != repAddrTypeNotSupported {
		t.Fatalf("空域名应答 = %#x, want %#x", rep, repAddrTypeNotSupported)
	}
}

func TestSOCKS5RejectsEmptyMethodList(t *testing.T) {
	proxyAddr := startSOCKS5(t, rulesDirect, "", "")
	c := dialProxy(t, proxyAddr)
	if _, err := c.Write([]byte{socks5Version, 0x00}); err != nil {
		t.Fatalf("写: %v", err)
	}
	if _, err := c.Read(make([]byte, 2)); err == nil {
		t.Fatal("方法列表为空时不应有应答，连接应被关闭")
	}
}

func TestReadAddr(t *testing.T) {
	cases := []struct {
		name    string
		atyp    byte
		payload []byte
		want    string
		wantErr bool
	}{
		{"IPv4", atypIPv4, []byte{1, 2, 3, 4}, "1.2.3.4", false},
		{"IPv6", atypIPv6, net.ParseIP("2001:db8::1").To16(), "2001:db8::1", false},
		{"domain", atypDomain, domainAddr("Example.COM"), "Example.COM", false},
		{"空域名", atypDomain, []byte{0}, "", true},
		{"未知类型", 0x09, nil, "", true},
		{"IPv4 截断", atypIPv4, []byte{1, 2}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readAddr(strings.NewReader(string(tc.payload)), tc.atyp)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望报错，得到 %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("readAddr: %v", err)
			}
			if got != tc.want {
				t.Fatalf("readAddr = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHTTPConnectTunnel(t *testing.T) {
	echo := startEchoServer(t)
	proxyAddr := startHTTPProxy(t, rulesDirect)
	c := dialProxy(t, proxyAddr)

	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr()); err != nil {
		t.Fatalf("写 CONNECT: %v", err)
	}
	buf := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("读 CONNECT 应答: %v", err)
	}
	if !strings.HasPrefix(string(buf), "HTTP/1.1 200") {
		t.Fatalf("CONNECT 应答 = %q", buf)
	}
	if _, err := c.Write([]byte("tunnel")); err != nil {
		t.Fatalf("写隧道数据: %v", err)
	}
	got := make([]byte, 6)
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("读隧道数据: %v", err)
	}
	if string(got) != "tunnel" {
		t.Fatalf("隧道回显 = %q", got)
	}
}

func TestHTTPForwardRewritesAbsoluteURI(t *testing.T) {
	var gotURI, gotHost, gotPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI = r.RequestURI
		gotHost = r.Host
		gotPath = r.URL.Path
		w.Header().Set("X-Origin", "upstream")
		fmt.Fprintf(w, "hello %s %s", r.Method, r.URL.Path)
	}))
	defer up.Close()

	proxyAddr := startHTTPProxy(t, rulesDirect)
	c := dialProxy(t, proxyAddr)

	upHost := strings.TrimPrefix(up.URL, "http://")
	if _, err := fmt.Fprintf(c, "GET http://%s/some/path?q=1 HTTP/1.1\r\nHost: %s\r\n\r\n", upHost, upHost); err != nil {
		t.Fatalf("写请求: %v", err)
	}
	resp, err := http.ReadResponse(newReader(c), nil)
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d, want 200", resp.StatusCode)
	}
	// 转发后必须是 origin-form，上游才不会把代理当客户端。
	if strings.HasPrefix(gotURI, "http://") {
		t.Fatalf("上游收到的 RequestURI = %q，应为 origin-form", gotURI)
	}
	if gotURI != "/some/path?q=1" {
		t.Fatalf("上游 RequestURI = %q, want \"/some/path?q=1\"", gotURI)
	}
	if gotHost != upHost {
		t.Fatalf("上游 Host = %q, want %q", gotHost, upHost)
	}
	if resp.Header.Get("X-Origin") != "upstream" {
		t.Fatal("响应头未原样回传")
	}
	if string(body) != "hello GET /some/path" {
		t.Fatalf("响应体 = %q", body)
	}
	_ = gotPath
}

// noHalfCloseConn 藏起底层连接的 CloseWrite，用来模拟 hysteria 的 QUIC 流：
// 这类连接只能整条关掉，做不到只关掉写侧。
type noHalfCloseConn struct{ net.Conn }

// opaqueProxyDialer 是「能连通、但不支持半关」的 PROXY 出站。
type opaqueProxyDialer struct {
	mu     sync.Mutex
	dialed int
}

func (d *opaqueProxyDialer) Name() string { return string(outbound.PolicyProxy) }

func (d *opaqueProxyDialer) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.dialed++
	d.mu.Unlock()
	return noHalfCloseConn{c}, nil
}

func (d *opaqueProxyDialer) Close() error { return nil }

func (d *opaqueProxyDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dialed
}

// newProxyOnlyRouter 用「兜底走 PROXY」的规则搭路由器，PROXY 出站由调用方观察。
func newProxyOnlyRouter(t *testing.T, dialer outbound.Dialer) *router.Router {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,PROXY"), 0o644); err != nil {
		t.Fatalf("写规则: %v", err)
	}
	eng, err := rules.Load(path, nil, nil)
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	set := outbound.NewSet(outbound.NewDirect(3*time.Second), dialer)
	t.Cleanup(func() { _ = set.Close() })
	return router.New(eng, set, 3*time.Second)
}

// 明文 HTTP 转发经 PROXY 出站时必须拿到完整响应。
//
// 这条路径曾经坏得很安静：请求写完后的收尾用 Close() 代替半关，
// 于是响应还没开始回就被掐掉，客户端只看到一个空响应，日志里一行错误都没有。
// 已有的转发用例走的是 DIRECT 出站（真 TCP 连接支持 CloseWrite），
// 所以只有「出站不支持半关」这个组合没被覆盖到 —— 而那正是 hysteria 的常态。
func TestHTTPForwardThroughProxyWithoutHalfCloseDeliversResponse(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		fmt.Fprint(w, "proxy-answer")
	}))
	defer up.Close()

	dialer := &opaqueProxyDialer{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = NewHTTPProxy(newProxyOnlyRouter(t, dialer)).Serve(ln) }()

	c := dialProxy(t, ln.Addr().String())
	upHost := strings.TrimPrefix(up.URL, "http://")
	if _, err := fmt.Fprintf(c, "GET http://%s/path HTTP/1.1\r\nHost: %s\r\n\r\n", upHost, upHost); err != nil {
		t.Fatalf("写请求: %v", err)
	}
	resp, err := http.ReadResponse(newReader(c), nil)
	if err != nil {
		t.Fatalf("读响应: %v —— 空响应说明转发时把连接提前关掉了", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "proxy-answer" {
		t.Fatalf("响应体 = %q, want \"proxy-answer\"", body)
	}
	if dialer.dialCount() == 0 {
		t.Fatal("请求没走 PROXY 出站，这条用例就白写了")
	}
}

// relay 把 idleConn 与计数包装叠在真连接外面，任何一层漏掉 CloseWrite，
// 半关就会在断言里"成功"、实际上把整条连接关掉。
func TestRelayWrappersPreserveCloseWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	serverCh := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		close(serverCh)
		_, _ = io.Copy(c, c)
		_ = c.Close()
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	var ctr atomic.Uint64
	got := newIdleConn(metrics.Wrap(client, &ctr), time.Second)
	if _, err := got.Write([]byte("echo")); err != nil {
		t.Fatalf("写请求: %v", err)
	}
	cw, ok := interface{}(got).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("包装后的连接必须仍然暴露 CloseWrite")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	// 半关只关写侧：读侧还得能收到对端把已写数据原样回显回来。
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(got, buf); err != nil {
		t.Fatalf("半关后读侧应仍可用: %v", err)
	}
	if string(buf) != "echo" {
		t.Fatalf("读到 %q, want \"echo\"", buf)
	}
	<-serverCh
}

// 绝对 URI 里没有端口时应补成 80。用失败的 PROXY 出站来观测代理拼出的地址，
// 避免依赖真实占用 80 端口的站点。
func TestHTTPForwardDefaultsToPort80(t *testing.T) {
	proxyAddr, proxy := startHTTPProxyWithProxy(t, "DOMAIN,port80.example,PROXY\nFINAL,DIRECT")
	c := dialProxy(t, proxyAddr)

	if _, err := io.WriteString(c, "GET http://port80.example/ HTTP/1.1\r\nHost: port80.example\r\n\r\n"); err != nil {
		t.Fatalf("写请求: %v", err)
	}
	resp, err := http.ReadResponse(newReader(c), nil)
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("状态码 = %d, want 502（缺省端口应拨 80，无监听）", resp.StatusCode)
	}
	if got := proxy.lastAddr(); got != "port80.example:80" {
		t.Fatalf("代理拨号目标 = %q, want \"port80.example:80\"", got)
	}
}

func TestHTTPRejectsNonAbsoluteURI(t *testing.T) {
	proxyAddr := startHTTPProxy(t, rulesDirect)
	c := dialProxy(t, proxyAddr)
	if _, err := io.WriteString(c, "GET /relative/path HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("写请求: %v", err)
	}
	resp, err := http.ReadResponse(newReader(c), nil)
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("状态码 = %d, want 400", resp.StatusCode)
	}
}

func TestHTTPRejectsHTTPSAbsoluteURI(t *testing.T) {
	proxyAddr := startHTTPProxy(t, rulesDirect)
	c := dialProxy(t, proxyAddr)
	if _, err := io.WriteString(c, "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("写请求: %v", err)
	}
	resp, err := http.ReadResponse(newReader(c), nil)
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	_ = resp.Body.Close()
	// 走明文转发会泄露 https 内容，因此必须拒绝。
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("状态码 = %d, want 501", resp.StatusCode)
	}
}

func TestHTTPDialFailureReturnsBadGateway(t *testing.T) {
	cases := []struct {
		name string
		req  string
	}{
		{"CONNECT", "CONNECT proxy.example:443 HTTP/1.1\r\nHost: proxy.example:443\r\n\r\n"},
		{"绝对 URI", "GET http://proxy.example/ HTTP/1.1\r\nHost: proxy.example\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxyAddr := startHTTPProxy(t, "DOMAIN,proxy.example,PROXY\nFINAL,DIRECT")
			c := dialProxy(t, proxyAddr)
			if _, err := io.WriteString(c, tc.req); err != nil {
				t.Fatalf("写请求: %v", err)
			}
			resp, err := http.ReadResponse(newReader(c), nil)
			if err != nil {
				t.Fatalf("读响应: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("状态码 = %d, want 502", resp.StatusCode)
			}
		})
	}
}

func TestHTTPMalformedRequestClosesConnection(t *testing.T) {
	proxyAddr := startHTTPProxy(t, rulesDirect)
	c := dialProxy(t, proxyAddr)
	if _, err := io.WriteString(c, "这不是 HTTP 请求\r\n\r\n"); err != nil {
		t.Fatalf("写: %v", err)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("无法解析的请求应直接关闭连接")
	}
}

// TestHTTPConnectDeliversBytesSentWithRequest 锁住一个曾经的静默丢包：
// 客户端把 CONNECT 请求头与隧道首段数据放在同一次 write 里发出，
// bufio.Reader 会在解析请求头时把它们一起预读走。隧道必须从 br 读，
// 否则这批字节就烂在缓冲区里，客户端表现为「连上了但一直收不到东西」。
func TestHTTPConnectDeliversBytesSentWithRequest(t *testing.T) {
	echo := startEchoServer(t)
	proxyAddr := startHTTPProxy(t, rulesDirect)
	c := dialProxy(t, proxyAddr)

	payload := "EARLY-TUNNEL-BYTES"
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", echo.Addr(), echo.Addr(), payload)
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("写: %v", err)
	}

	status := make([]byte, len("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if _, err := io.ReadFull(c, status); err != nil {
		t.Fatalf("读 CONNECT 应答: %v", err)
	}
	got := make([]byte, len(payload))
	n, err := io.ReadFull(c, got)
	if err != nil {
		t.Fatalf("隧道只回读到 %d/%d 字节（%q）: %v", n, len(payload), string(got[:n]), err)
	}
	if string(got) != payload {
		t.Fatalf("隧道数据不一致: 期望 %q，实际 %q", payload, string(got))
	}
}

// TestHTTPRejectsEmptyAuthorityAbsoluteURI 挡住「借代理打本机」这条路。
// `http://`、`http:/foo`、`http://:80/` 的 Hostname() 都是空串，
// 一路走到拨号就变成 ":80"——那是回环地址，代理会替客户端连上本机端口。
func TestHTTPRejectsEmptyAuthorityAbsoluteURI(t *testing.T) {
	for _, uri := range []string{"http://", "http:/foo", "http://:80/", "http://[::]:80/"} {
		t.Run(uri, func(t *testing.T) {
			proxyAddr := startHTTPProxy(t, rulesDirect)
			c := dialProxy(t, proxyAddr)
			if _, err := io.WriteString(c, "GET "+uri+" HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
				t.Fatalf("写: %v", err)
			}
			line, err := newReader(c).ReadString('\n')
			if err != nil {
				t.Fatalf("读状态行: %v", err)
			}
			if !strings.Contains(line, " 400 ") {
				t.Fatalf("空 authority 的绝对 URI %q 应被 400 拒绝，实际状态行 %q", uri, strings.TrimSpace(line))
			}
		})
	}
}

// TestHTTPForwardStripsHopByHopHeaders 锁住凭据外泄：
// Proxy-Authorization 是发给代理自己的，转发给源站等于泄露代理口令；
// Connection 里点名的头同样是跳级的，必须一并摘掉（RFC 7230 §6.1）。
func TestHTTPForwardStripsHopByHopHeaders(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = up.Close() })
	got := make(chan string, 1)
	go func() {
		c, err := up.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _ := c.Read(buf)
		got <- string(buf[:n])
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
		time.Sleep(200 * time.Millisecond)
	}()

	proxyAddr := startHTTPProxy(t, rulesDirect)
	c := dialProxy(t, proxyAddr)
	raw := "GET http://" + up.Addr().String() + "/ HTTP/1.1\r\nHost: " + up.Addr().String() + "\r\n" +
		"Proxy-Authorization: Basic dXNlcjpzZWNyZXA=\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Keep-Alive: timeout=5\r\n" +
		"Connection: X-Hop\r\n" +
		"X-Hop: named-by-connection\r\n\r\n"
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("写: %v", err)
	}
	select {
	case s := <-got:
		for _, banned := range []string{"Proxy-Authorization", "Proxy-Connection", "Keep-Alive", "X-Hop", "Connection:"} {
			if strings.Contains(s, banned) {
				t.Errorf("跳级头 %q 不应转发给源站，实际收到:\n%s", banned, s)
			}
		}
	case <-time.After(4 * time.Second):
		t.Fatal("源站没有收到请求")
	}
}

// TestStripHopByHop 直接单测摘头逻辑，包含 Connection 点名的动态项。
func TestStripHopByHop(t *testing.T) {
	h := http.Header{}
	h.Set("Host", "example.com")
	h.Set("X-Keep", "1")
	h.Set("Connection", "close, X-Named")
	h.Set("X-Named", "named")
	h.Set("Proxy-Authorization", "Basic x")
	h.Set("Te", "trailers")
	h.Set("Upgrade", "websocket")

	stripHopByHop(h)

	if h.Get("X-Keep") != "1" || h.Get("Host") != "example.com" {
		t.Errorf("普通端到端头不该被动: %v", h)
	}
	for _, name := range []string{"Connection", "X-Named", "Proxy-Authorization", "Te", "Upgrade"} {
		if got := h.Get(name); got != "" {
			t.Errorf("%q 应被摘掉，仍为 %q", name, got)
		}
	}
}

func TestServeStopsWhenListenerClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	rt := newTestRouter(t, rulesDirect)

	done := make(chan error, 2)
	go func() { done <- NewSOCKS5(rt, "", "").Serve(ln) }()
	go func() { done <- NewHTTPProxy(rt).Serve(ln) }()

	time.Sleep(50 * time.Millisecond)
	_ = ln.Close()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Serve 应在监听器关闭后返回 nil，得到 %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Serve 未在监听器关闭后退出")
		}
	}
}
