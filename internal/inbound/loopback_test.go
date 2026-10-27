package inbound

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
	"wps_app/internal/rules"
)

// 这个文件是 trojan 的**全栈本地闭环**：入站分帧 → 路由判定 → 真实 trojan 客户端
// 编解码 → 本地 trojan 服务端 → 本地源站 → 原路返回。
//
// outbound 包自己的 trojan 测试只验编解码与握手，inbound 包的测试只用假 dialer，
// 两者之间的接缝——「入站交出来的字节能不能被真实 trojan 出站原样送到目标」——
// 没有任何测试覆盖过。这里的源站与 trojan 服务端都在回环上，所以不依赖外网、
// 不需要 root、也不受真实节点抖动影响。

const loopbackPassword = "loopback-secret"

// rulesAllProxy 把除 10.0.0.0/8 以外的一切都塞进 PROXY，
// 从而保证下面的往返一定真的穿过了 trojan 出站而不是被直连抄近路。
const rulesAllProxy = "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,PROXY"

// trojanOrigin 是按 trojan 协议真正转发到目标地址的服务端：
// 验口令、拨 req.target、然后双向搬运字节。回显式的假服务端验不到这一段。
type trojanOrigin struct {
	ln  net.Listener
	crt tls.Certificate

	mu    sync.Mutex
	dials []string
}

func newTrojanOrigin(t *testing.T) *trojanOrigin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	o := &trojanOrigin{ln: ln, crt: loopbackCert(t)}
	t.Cleanup(func() { _ = ln.Close() })
	go o.serve()
	return o
}

func (o *trojanOrigin) addr() string { return o.ln.Addr().String() }

func (o *trojanOrigin) dialed() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.dials...)
}

func (o *trojanOrigin) serve() {
	for {
		raw, err := o.ln.Accept()
		if err != nil {
			return
		}
		go o.handle(raw)
	}
}

func (o *trojanOrigin) handle(raw net.Conn) {
	tc := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{o.crt},
		NextProtos:   []string{"Trojan"},
	})
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return
	}
	// 头部之后是裸流，只能按字节读，不能贪心地把整段都当成头部。
	br := bufio.NewReader(tc)
	hash, target, err := readTrojanRequestHeader(br)
	if err != nil {
		_ = tc.Close()
		return
	}
	if hash != trojanPasswordHash() {
		// 规范规定口令不对不报错，直接断连，客户端要等第一次读才发现。
		_ = tc.Close()
		return
	}
	up, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		_ = tc.Close()
		return
	}
	o.mu.Lock()
	o.dials = append(o.dials, target)
	o.mu.Unlock()

	done := make(chan struct{}, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src)
		// 半关：对端看到 FIN 就知道这边发完了，不必等它先断。
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	// 上行必须从 br 读：客户端把头部和首段请求一次 write 出去时，
	// bufio 预读已经把那些字节收进缓冲区了，从 tc 读等于静默丢包。
	go cp(up, br)
	go cp(tc, up)
	<-done
	<-done
	_ = up.Close()
	_ = tc.Close()
}

// trojanPasswordHash 是 trojan 规范要求的口令摘要：SHA1(password) 的十六进制小写。
// 必须是 SHA-1 而不是 SHA-256 —— 客户端用 SHA-1 算，服务端换算法就永远对不上，
// 而症状是「握手成功、第一次读就 EOF」，看上去像网络问题。
func trojanPasswordHash() string {
	sum := sha1.Sum([]byte(loopbackPassword))
	return hex.EncodeToString(sum[:])
}

// readTrojanRequestHeader 解析 `CMD CRLF HASH CRLF ADDR CRLF`。
// 顺序不能反：CMD 在最前面，且它是「一个字节 + CRLF」而不是一行文本。
// 本测试的客户端不带 SNI，ADDR 用 ATYP + 地址 + 端口的形式。
func readTrojanRequestHeader(r *bufio.Reader) (string, string, error) {
	cmd, err := readCRLFByte(r)
	if err != nil {
		return "", "", err
	}
	if cmd != 0x04 {
		return "", "", fmt.Errorf("只接受 CONNECT(0x04)，收到 %#x", cmd)
	}
	hash, err := readCRLFLine(r)
	if err != nil {
		return "", "", err
	}
	atyp, err := r.ReadByte()
	if err != nil {
		return "", "", err
	}
	var host string
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", "", err
		}
		host = net.IP(b).String()
	case 0x03:
		n, err := r.ReadByte()
		if err != nil {
			return "", "", err
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", "", err
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", "", err
		}
		host = net.IP(b).String()
	default:
		return "", "", fmt.Errorf("未知 ATYP %#x", atyp)
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", "", err
	}
	if _, err := readCRLFLine(r); err != nil { // 结尾 CRLF
		return "", "", err
	}
	return hash, net.JoinHostPort(host, fmt.Sprint(int(p[0])<<8|int(p[1]))), nil
}

func readCRLFLine(r *bufio.Reader) (string, error) {
	var out []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\r' {
			lf, err := r.ReadByte()
			if err != nil {
				return "", err
			}
			if lf != '\n' {
				return "", fmt.Errorf("期望 LF，得到 %#x", lf)
			}
			return string(out), nil
		}
		out = append(out, b)
		if len(out) > 512 {
			return "", fmt.Errorf("行过长")
		}
	}
}

func readCRLFByte(r *bufio.Reader) (byte, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if _, err := readCRLFLine(r); err != nil {
		return 0, err
	}
	return b, nil
}

func loopbackCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "loopback-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// loopbackStack 是「源站 + trojan 服务端 + 真实 trojan 出站 + 路由器 + 两个入站」。
type loopbackStack struct {
	origin string // 源站的 host:port
	socks  string
	http   string
	trojan *trojanOrigin
}

func newLoopbackStack(t *testing.T) *loopbackStack {
	t.Helper()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Loopback", "yes")
		fmt.Fprintf(w, "hello from %s", r.URL.Path)
	}))
	t.Cleanup(origin.Close)

	trojan := newTrojanOrigin(t)
	tr, err := outbound.NewTrojan(config.ServerConfig{
		Type: config.ProtocolTrojan,
		Addr: trojan.addr(),
		Auth: loopbackPassword,
		TLS:  config.TLSConfig{SNI: "localhost", Insecure: true},
	}, 3*time.Second, nil, netip.Prefix{})
	if err != nil {
		t.Fatalf("NewTrojan: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	dir := t.TempDir()
	path := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(path, []byte(rulesAllProxy), 0o644); err != nil {
		t.Fatalf("写规则文件: %v", err)
	}
	eng, err := rules.Load(path, nil, nil)
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	set := outbound.NewSet(outbound.NewDirect(3*time.Second), tr)
	t.Cleanup(func() { _ = set.Close() })
	rt := router.New(eng, set, 3*time.Second)

	sl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen socks: %v", err)
	}
	t.Cleanup(func() { _ = sl.Close() })
	go func() { _ = NewSOCKS5(rt, "", "").Serve(sl) }()

	hl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen http: %v", err)
	}
	t.Cleanup(func() { _ = hl.Close() })
	go func() { _ = NewHTTPProxy(rt).Serve(hl) }()

	return &loopbackStack{
		origin: strings.TrimPrefix(origin.URL, "http://"),
		socks:  sl.Addr().String(),
		http:   hl.Addr().String(),
		trojan: trojan,
	}
}

func TestSOCKS5ThroughRealTrojanLoopback(t *testing.T) {
	st := newLoopbackStack(t)
	_, portStr, err := net.SplitHostPort(st.origin)
	if err != nil {
		t.Fatalf("拆目标地址: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("解析端口: %v", err)
	}

	c := dialProxy(t, st.socks)
	socksGreeting(t, c, 0x00)
	if m := readSocksMethod(t, c); m != 0x00 {
		t.Fatalf("协商方法 = %#x, want 0x00", m)
	}
	// 用域名而不是 IP：域名要原样穿过 trojan 头部交给服务端解析，
	// 用 IP 绕过了 ATYP 0x03 这一段最易错的编码。
	socksConnectRequest(t, c, 0x01, 0x03, domainAddr("localhost"), uint16(port))
	if rep := readSocksReply(t, c); rep != 0x00 {
		t.Fatalf("REP = %d, want 0", rep)
	}
	fmt.Fprintf(c, "GET /socks HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读正文: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("状态码 = %d, want 200", resp.StatusCode)
	}
	if got, want := string(body), "hello from /socks"; got != want {
		t.Fatalf("正文 = %q, want %q", got, want)
	}
	if resp.Header.Get("X-Loopback") != "yes" {
		t.Fatalf("源站自定义头没穿过 trojan 回来: %v", resp.Header)
	}
	// 服务端这一侧看到的目标必须是域名而不是 IP：
	// 这条同时证明 ATYP 0x03 的编码与服务端的解析是对齐的。
	dialed := st.trojan.dialed()
	if len(dialed) != 1 || dialed[0] != net.JoinHostPort("localhost", portStr) {
		t.Fatalf("trojan 服务端拨的目标 = %v, want [%s]", dialed,
			net.JoinHostPort("localhost", portStr))
	}
}

func TestHTTPForwardThroughRealTrojanLoopback(t *testing.T) {
	st := newLoopbackStack(t)

	c := dialProxy(t, st.http)
	fmt.Fprintf(c, "GET http://%s/forward HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		st.origin, st.origin)

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读正文: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("状态码 = %d, want 200", resp.StatusCode)
	}
	if got, want := string(body), "hello from /forward"; got != want {
		t.Fatalf("正文 = %q, want %q", got, want)
	}
}

// TestTrojanLoopbackRejectsWrongPassword 钉住「口令不对必须断连」这条：
// 客户端在第一次读之前不会报错，所以断言点放在读上。
func TestTrojanLoopbackRejectsWrongPassword(t *testing.T) {
	trojan := newTrojanOrigin(t)
	tr, err := outbound.NewTrojan(config.ServerConfig{
		Type: config.ProtocolTrojan,
		Addr: trojan.addr(),
		Auth: "not-the-password",
		TLS:  config.TLSConfig{SNI: "localhost", Insecure: true},
	}, 3*time.Second, nil, netip.Prefix{})
	if err != nil {
		t.Fatalf("NewTrojan: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.DialContext(ctx, "example.com:80")
	if err == nil {
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, werr := conn.Write([]byte("ping")); werr != nil {
			t.Fatalf("写: %v", werr)
		}
		buf := make([]byte, 1)
		if _, rerr := conn.Read(buf); rerr == nil {
			t.Fatal("口令不对却读到了数据")
		}
	}
}
