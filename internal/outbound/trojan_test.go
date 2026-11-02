package outbound

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
)

func trojanHash(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
}

func TestTrojanHeaderEncoding(t *testing.T) {
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef01234567"

	tests := []struct {
		name   string
		target string
		want   []byte
	}{
		{
			name:   "ipv4",
			target: "93.184.216.34:443",
			want: concat(
				[]byte(hash), []byte{'\r', '\n'},
				[]byte{0x01}, // CMD CONNECT
				[]byte{0x01, 93, 184, 216, 34},
				[]byte{0x01, 0xbb}, // 443
				[]byte{'\r', '\n'},
			),
		},
		{
			name:   "domain",
			target: "example.com:8443",
			want: concat(
				[]byte(hash), []byte{'\r', '\n'},
				[]byte{0x01}, // CMD CONNECT
				[]byte{0x03, byte(len("example.com"))}, []byte("example.com"),
				[]byte{0x20, 0xfb}, // 8443
				[]byte{'\r', '\n'},
			),
		},
		{
			name:   "ipv6",
			target: "[2001:db8::1]:80",
			want: concat(
				[]byte(hash), []byte{'\r', '\n'},
				[]byte{0x01}, // CMD CONNECT
				[]byte{0x04,
					0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
				[]byte{0x00, 0x50},
				[]byte{'\r', '\n'},
			),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := trojanHeader(tc.target, hash)
			if err != nil {
				t.Fatalf("trojanHeader(%q): %v", tc.target, err)
			}
			if string(got) != string(tc.want) {
				t.Fatalf("头部字节不对:\n got % x\nwant % x", got, tc.want)
			}
		})
	}
}

func TestTrojanHeaderRejects(t *testing.T) {
	hash := trojanHash("x")
	for _, target := range []string{
		"example.com",      // 没有端口
		"example.com:http", // 端口不是数字
		"example.com:70000",
		":443", // 空主机
	} {
		if _, err := trojanHeader(target, hash); err == nil {
			t.Fatalf("trojanHeader(%q) 期望报错", target)
		}
	}
	// 摘要长度不对必须拦住：真实服务端是按 sha224 的 56 个 hex 字符定长读的，
	// 长度错了它会把后面的命令字节当摘要的一部分，整条连接就错位了。
	if _, err := trojanHeader("example.com:443", "deadbeef"); err == nil {
		t.Fatal("短摘要应当被拒绝")
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ---------- 内存里的 trojan 服务端 ----------

type trojanRequest struct {
	cmd    byte
	hash   string
	atyp   byte
	target string
}

// trojanStub 是最小可用的 trojan 服务端：握手 → 收头部 → 校验口令 → 回显。
//
// 回显不是协议的一部分，只是测试要的「能证明字节确实穿过来了」的效果。
type trojanStub struct {
	ln       net.Listener
	password string
	cert     tls.Certificate

	reqs chan trojanRequest
}

func newTrojanStub(t *testing.T, password string) *trojanStub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	st := &trojanStub{
		ln:       ln,
		password: password,
		cert:     selfSignedCert(t),
		reqs:     make(chan trojanRequest, 16),
	}
	go st.serve()
	return st
}

func (st *trojanStub) addr() string { return st.ln.Addr().String() }

func (st *trojanStub) close() { _ = st.ln.Close() }

func (st *trojanStub) serve() {
	for {
		c, err := st.ln.Accept()
		if err != nil {
			return
		}
		go st.handle(c)
	}
}

func (st *trojanStub) handle(raw net.Conn) {
	tc := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{st.cert},
		NextProtos:   []string{"Trojan"},
	})
	if err := tc.Handshake(); err != nil {
		_ = raw.Close()
		return
	}
	// 头部之后是裸流，所以只能按字节读，不能贪心地把整段都当成头部。
	req, err := readTrojanHeader(bufio.NewReader(tc))
	if err != nil {
		_ = tc.Close()
		return
	}
	st.reqs <- req
	if req.hash != trojanHash(st.password) {
		// 规范就是这么规定的：口令不对不报错，直接把连接关掉。
		// 没配兼底的服务端就是这样；配了的那台会改回一张 400 页面，
		// 那才是 wbthinks 这个节点被记成"兼底型节点"的源头。
		_ = tc.Close()
		return
	}
	// 接受头部之后服务端**不发任何应答**，直接等客户端的数据——2026-10-29 在这台
	// trojan 1.16 上实测：把隧道打到它自己的 nginx，请求前 0 字节，
	// 请求后第一个字节已经是 "HTTP/1.1 301"。所以这里不许替它补那 10 个字节。
	_, _ = io.Copy(tc, tc) //nolint:errcheck // 回显，对端关掉就结束
	_ = tc.Close()
}

func readTrojanHeader(r *bufio.Reader) (trojanRequest, error) {
	var req trojanRequest
	// 第一行是口令摘要，第二行才是「命令字节 + 地址族 + 地址 + 端口」的裸字节。
	line, err := readLine(r)
	if err != nil {
		return req, err
	}
	req.hash = line
	cmd, err := r.ReadByte()
	if err != nil {
		return req, err
	}
	req.cmd = cmd
	atyp, err := r.ReadByte()
	if err != nil {
		return req, err
	}
	req.atyp = atyp
	switch atyp {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return req, err
		}
		req.target = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	case 0x03:
		n, err := r.ReadByte()
		if err != nil {
			return req, err
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return req, err
		}
		req.target = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return req, err
		}
		req.target = net.IP(b).String()
	default:
		return req, fmt.Errorf("未知 ATYP %#x", atyp)
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return req, err
	}
	req.target = fmt.Sprintf("%s:%d", req.target, int(p[0])<<8|int(p[1]))
	return req, expectCRLF(r)
}

func readLine(r *bufio.Reader) (string, error) {
	var out []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '\r' {
			if next, err := r.ReadByte(); err != nil {
				return "", err
			} else if next == '\n' {
				return string(out), nil
			}
		}
		out = append(out, b)
		if len(out) > 512 {
			return "", errors.New("行过长")
		}
	}
}

func expectCRLF(r *bufio.Reader) error {
	b := make([]byte, 2)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	if b[0] != '\r' || b[1] != '\n' {
		return fmt.Errorf("期望 CRLF，得到 %q", b)
	}
	return nil
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "trojan-test"},
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

func newTestTrojan(t *testing.T, addr, password string, insecure bool) *Trojan {
	t.Helper()
	tr, err := NewTrojan(config.ServerConfig{
		Type: config.ProtocolTrojan,
		Addr: addr,
		Auth: password,
		TLS:  config.TLSConfig{SNI: "localhost", Insecure: insecure},
	}, 3*time.Second, nil, netip.Prefix{})
	if err != nil {
		t.Fatalf("NewTrojan: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

func TestTrojanEndToEnd(t *testing.T) {
	st := newTrojanStub(t, "sekrit")
	defer st.close()
	tr := newTestTrojan(t, st.addr(), "sekrit", true)

	conn, err := tr.DialContext(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("回显不对: %q", buf)
	}

	select {
	case req := <-st.reqs:
		if req.cmd != 0x01 {
			t.Fatalf("命令字节 = %#x, want 0x01", req.cmd)
		}
		if req.hash != trojanHash("sekrit") {
			t.Fatalf("口令摘要不对: %q", req.hash)
		}
		if req.atyp != 0x03 || req.target != "example.com:443" {
			t.Fatalf("目标编码不对: atyp=%#x target=%q", req.atyp, req.target)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("服务端没收到头部")
	}

	if !tr.Connected() {
		t.Fatal("握手成功后 Connected 应为 true")
	}
	if got := tr.Status(); got == "" {
		t.Fatal("Status 为空")
	} else if !strings.Contains(got, "SNI=localhost") {
		t.Fatalf("Status %q 应当包含 SNI=localhost", got)
	}
}

// TestTrojanWrongPasswordSurfacesOnlyOnRead 钉住口令不对时的形状：TLS 握手在认证之前
// 就完成了，拨号本身不会失败，错误只在第一次读时以 EOF 出现。
//
// 今天在现场被验证了一次反面：那台配了兼底页的服务端连 EOF 都不给，改成回一张 400，
// 于是界面上"电路通了"照旧绿灯、只有应用层探针报红——这就是测速必须再探一次页面
// （pageProbe）的理由，也是这条测试留在这里的意义。
func TestTrojanWrongPasswordSurfacesOnlyOnRead(t *testing.T) {
	st := newTrojanStub(t, "right")
	defer st.close()
	tr := newTestTrojan(t, st.addr(), "wrong", true)

	conn, err := tr.DialContext(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("口令不对时握手仍应完成: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 1)); err == nil {
		t.Fatal("错误口令的连接应当读不出东西")
	} else if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "EOF") {
		t.Fatalf("期望 EOF，得到 %v", err)
	}

	req := <-st.reqs
	if req.hash == trojanHash("right") {
		t.Fatal("服务端不该收到正确摘要")
	}
}

// TestTrojanVerifiesCertificate 保证 insecure 关掉之后是真的在验证书，
// 而不是「配了个校验但其实没生效」。自签证书必然验不过。
func TestTrojanVerifiesCertificate(t *testing.T) {
	st := newTrojanStub(t, "sekrit")
	defer st.close()
	tr := newTestTrojan(t, st.addr(), "sekrit", false)

	_, err := tr.DialContext(context.Background(), "example.com:443")
	if err == nil {
		t.Fatal("自签证书 + 关闭跳过校验，握手应当失败")
	}
	if strings.Contains(err.Error(), "write trojan header") {
		t.Fatalf("失败发生在握手之后，说明证书根本没校验: %v", err)
	}
}

func TestTrojanDialAfterClose(t *testing.T) {
	st := newTrojanStub(t, "sekrit")
	defer st.close()
	tr := newTestTrojan(t, st.addr(), "sekrit", true)
	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := tr.DialContext(context.Background(), "example.com:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("关闭后拨号应报 net.ErrClosed，得到 %v", err)
	}
	if tr.Connected() {
		t.Fatal("关闭后 Connected 应为 false")
	}
}

func TestNewTrojanRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name     string
		sc       config.ServerConfig
		resolver HostResolver
	}{
		{
			name:     "缺口令",
			sc:       config.ServerConfig{Type: config.ProtocolTrojan, Addr: "a.com:443"},
			resolver: &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}},
		},
		{
			name:     "缺端口",
			sc:       config.ServerConfig{Type: config.ProtocolTrojan, Addr: "a.com", Auth: "x"},
			resolver: &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}},
		},
		{
			name:     "协议不对",
			sc:       config.ServerConfig{Type: "ss", Addr: "a.com:443", Auth: "x"},
			resolver: &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}},
		},
		{
			// 端口检查发生在解析之前，所以这条不碰网络。
			// hy2 早就拒绝了 70000，trojan 复用同一个 parsePort，不该再放水。
			name:     "端口超范围",
			sc:       config.ServerConfig{Type: config.ProtocolTrojan, Addr: "127.0.0.1:70000", Auth: "x"},
			resolver: &fakeResolver{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewTrojan(tc.sc, time.Second, tc.resolver, netip.Prefix{}); err == nil {
				t.Fatalf("NewTrojan(%+v) 期望报错", tc.sc)
			}
		})
	}
}

func TestNewTrojanSNIFallback(t *testing.T) {
	// 主机名：SNI 跟随主机名。
	tr := mustTrojan(t, config.ServerConfig{
		Type: config.ProtocolTrojan, Addr: "trojan.example.net:443", Auth: "x",
	})
	if tr.sni != "trojan.example.net" {
		t.Fatalf("SNI 缺省应跟随主机名，得到 %q", tr.sni)
	}
	// 字面量 IP：TLS 库不接受 IP 作 SNI，必须给个占位名。
	ip := mustTrojan(t, config.ServerConfig{
		Type: config.ProtocolTrojan, Addr: "203.0.113.9:8443", Auth: "x",
		TLS: config.TLSConfig{Insecure: true},
	})
	if ip.sni != "localhost" {
		t.Fatalf("IP 节点的 SNI 应退化成 localhost，得到 %q", ip.sni)
	}
	if ip.serverAddr != "203.0.113.9:8443" {
		t.Fatalf("地址不该被改写: %q", ip.serverAddr)
	}
}

// TestNewTrojanUsesSharedResolution 钉住「协议不同但解析规则相同」：
// 多候选优先 IPv4、字面量 IP 不查 DNS——这两条都是 hysteria2 踩过的坑，
// trojan 复用同一段代码，就不该再各自长出一份变体。
func TestNewTrojanUsesSharedResolution(t *testing.T) {
	r := &fakeResolver{addrs: []netip.Addr{
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("203.0.113.9"),
	}}
	tr, err := NewTrojan(config.ServerConfig{
		Type: config.ProtocolTrojan, Addr: "tj.example.com:8443", Auth: "x",
	}, time.Second, r, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	if tr.serverAddr != "203.0.113.9:8443" {
		t.Fatalf("应优先 IPv4，实得 %s", tr.serverAddr)
	}
	if r.calls != 1 || r.got != "tj.example.com" {
		t.Fatalf("没走传入的解析器: calls=%d host=%q", r.calls, r.got)
	}

	literal := &fakeResolver{err: errors.New("不该被调用")}
	tr2, err := NewTrojan(config.ServerConfig{
		Type: config.ProtocolTrojan, Addr: "127.0.0.1:18443", Auth: "x",
	}, time.Second, literal, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer tr2.Close()
	if literal.calls != 0 {
		t.Fatalf("字面量 IP 不该再解析: %d 次", literal.calls)
	}
	if tr2.serverAddr != "127.0.0.1:18443" {
		t.Fatalf("地址被改写了: %s", tr2.serverAddr)
	}
}

func mustTrojan(t *testing.T, sc config.ServerConfig) *Trojan {
	t.Helper()
	tr, err := NewTrojan(sc, time.Second, &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}, netip.Prefix{})
	if err != nil {
		t.Fatalf("NewTrojan: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// TestNewDispatchesByProtocol 是「加协议只改一处」的守卫：
// 工厂必须按 type 给出对应实现，且两种实现都能回答 Conn 的三件事。
func TestNewDispatchesByProtocol(t *testing.T) {
	resolver := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}

	hy, err := New(config.ServerConfig{
		Addr: "hy.example.com:443", Auth: "x", TLS: config.TLSConfig{SNI: "hy.example.com"},
	}, time.Second, resolver, netip.Prefix{}, nil)
	if err != nil {
		t.Fatalf("New(hysteria2): %v", err)
	}
	defer hy.Close()
	if _, ok := hy.(*Hysteria); !ok {
		t.Fatalf("缺省协议应给出 hysteria2，得到 %T", hy)
	}
	if hy.Status() == "" || hy.Connected() {
		t.Fatalf("未握手的 hysteria2 应报地址而不是已连接: %q", hy.Status())
	}

	tr, err := New(config.ServerConfig{
		Type: config.ProtocolTrojan, Addr: "tj.example.com:443", Auth: "x",
	}, time.Second, resolver, netip.Prefix{}, nil)
	if err != nil {
		t.Fatalf("New(trojan): %v", err)
	}
	defer tr.Close()
	if _, ok := tr.(*Trojan); !ok {
		t.Fatalf("type=trojan 应给出 trojan 出站，得到 %T", tr)
	}
	if tr.Status() == "" || tr.Connected() {
		t.Fatalf("未握手的 trojan 应报地址而不是已连接: %q", tr.Status())
	}
}
