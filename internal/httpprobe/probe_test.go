package httpprobe

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in     string
		want   Target
		wantEr bool
	}{
		{in: "http://example.com/generate_204", want: Target{Host: "example.com", Port: "80", Path: "/generate_204"}},
		{in: "https://example.com", want: Target{Host: "example.com", Port: "443", Path: "/", UseTLS: true}},
		{in: "https://example.com:8443/a/b?x=1", want: Target{Host: "example.com", Port: "8443", Path: "/a/b?x=1", UseTLS: true}},
		{in: "http://example.com/a", want: Target{Host: "example.com", Port: "80", Path: "/a"}},
		{in: "ftp://example.com/", wantEr: true}, // 没有"取页面"这层含义
		{in: "http:///no-host", wantEr: true},    // 没主机名
		{in: "not a url at all", wantEr: true},   // scheme 都不是
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantEr {
			if err == nil {
				t.Errorf("%q 应当被拒，却得到 %+v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%q 拆成 %+v，期望 %+v", c.in, got, c.want)
		}
	}
}

func TestJudge(t *testing.T) {
	cases := []struct {
		name    string
		out     Outcome
		wantErr string
	}{
		{name: "204 算通", out: Outcome{Code: 204}},
		{name: "302 算通（站点自己的跳转）", out: Outcome{Code: 302, Location: "https://example.com/login"}},
		{name: "400 是失败", out: Outcome{Code: 400, Server: "nginx/1.28.3"}, wantErr: "nginx/1.28.3"},
		{name: "502 是失败", out: Outcome{Code: 502}, wantErr: "没带 Server 头的服务"},
		{name: "没有状态行", out: Outcome{}, wantErr: "状态行"},
	}
	for _, c := range cases {
		err := c.out.Judge()
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%s: 期望通过，得到 %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: 期望错误里含 %q，得到 %v", c.name, c.wantErr, err)
		}
	}
}

// TestOutcomeString 那一行是给界面和命令行共用的，措辞变了两边一起变，
// 所以把它钉住：状态码、Server、字节数、跳转去向各在该在的位置。
func TestOutcomeString(t *testing.T) {
	got := Outcome{Code: 302, Server: "edge/1.0", Body: 12, ViaTLS: true, Location: "https://login.example/start"}.String()
	for _, want := range []string{"https 302", "server=edge/1.0", "12 字节", "→ https://login.example/start"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q 少了 %q", got, want)
		}
	}
	if plain := (Outcome{Code: 200}).String(); !strings.HasPrefix(plain, "http 200") || strings.Contains(plain, "server=") {
		t.Errorf("没有 Server 与正文时那一行不该出现它们：%q", plain)
	}
}

// serveOnce 起一个只回一次的本地假服务器（只走回环，断网命名空间里也能跑）。
// 它把收到的请求头存进 *got，让测试能断言"我们到底发出去了什么"——
// Host 头写错的话，虚拟主机型站点会回 400，而那看起来像节点的锅。
func serveOnce(t *testing.T, got *string, reply func(req string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		br := bufio.NewReader(conn)
		req, _ := br.ReadString('\n')
		headers := req
		for {
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimRight(line, "\r\n") == "" {
				break
			}
			headers += line
		}
		if got != nil {
			*got = headers
		}
		_, _ = conn.Write([]byte(reply(headers)))
	}()
	a := ln.Addr().(*net.TCPAddr)
	return net.JoinHostPort("127.0.0.1", itoa(a.Port))
}

// dialTestServer 拨到 serveOnce 起的地址。
func dialTestServer(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("拨号 %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestFetchReadsStatusServerAndBody(t *testing.T) {
	body := strings.Repeat("x", 5000)
	var got string
	addr := serveOnce(t, &got, func(string) string {
		return "HTTP/1.1 200 OK\r\nServer: real-edge/2.1\r\nContent-Length: " +
			itoa(len(body)) + "\r\n\r\n" + body
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := Fetch(ctx, dialTestServer(t, addr), Target{Host: "example.test", Path: "/generate_204"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if out.Code != 200 || out.Server != "real-edge/2.1" || out.Body != int64(len(body)) {
		t.Errorf("读数不对：%+v", out)
	}
	if out.ViaTLS {
		t.Error("明文连接不该报成 TLS")
	}
	if err := out.Judge(); err != nil {
		t.Errorf("200 应当判通：%v", err)
	}
	// 请求形状：目标是虚拟主机时，Host 头决定回什么。
	// 少了它，很多站点会回 400，而那条错误会被读成"节点不通"。
	if !strings.Contains(got, "GET /generate_204 HTTP/1.1\r\n") ||
		!strings.Contains(got, "Host: example.test\r\n") {
		t.Errorf("请求行/Host 头不对，实际发出:\n%s", got)
	}
}

// TestFetchRejectsNonHTTP 对端说的不是 HTTP：这句话必须原样报出来。
// 兼底服务器、被劫持的 80、还有一个开着别的服务的端口，都长这样。
func TestFetchRejectsNonHTTP(t *testing.T) {
	addr := serveOnce(t, nil, func(string) string { return "SSH-2.0-OpenSSH_9.6\r\n" })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Fetch(ctx, dialTestServer(t, addr), Target{Host: "127.0.0.1", Path: "/"})
	if err == nil || !strings.Contains(err.Error(), "不是 HTTP") {
		t.Fatalf("期望「第一行不是 HTTP 响应」，得到 %v", err)
	}
}

// TestFetchCountsBodyAcrossBufferBoundary 正文必须接着同一个 reader 数。
// bufio 预读会把头的空行后面那段一起吸进缓冲区，换一个 reader 就读不到那几个字节——
// 症状是"字节数偏少"，而这种错不会让任何一条判断变红，只会让界面上的数看着不对。
func TestFetchCountsBodyAcrossBufferBoundary(t *testing.T) {
	body := strings.Repeat("y", 9000) // 远超 bufio 默认的 4096，确保跨缓冲区
	addr := serveOnce(t, nil, func(string) string {
		return "HTTP/1.1 200 OK\r\nServer: edge/1.0\r\nContent-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := Fetch(ctx, dialTestServer(t, addr), Target{Host: "t.test", Path: "/"})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if out.Body != int64(len(body)) {
		t.Errorf("正文数到 %d 字节，实际发了 %d", out.Body, len(body))
	}
}

// TestFetchStopsAtHeaderLimit 对端一直不给空行时不许无限读下去。
func TestFetchStopsAtHeaderLimit(t *testing.T) {
	addr := serveOnce(t, nil, func(string) string {
		var b strings.Builder
		b.WriteString("HTTP/1.1 200 OK\r\n")
		for i := 0; i < 4000; i++ { // 每条 ~9 字节，合起来超过 32 KiB
			b.WriteString("X-Pad: aaaaaa\r\n")
		}
		return b.String()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := Fetch(ctx, dialTestServer(t, addr), Target{Host: "t.test", Path: "/"})
	if err == nil || !strings.Contains(err.Error(), "响应头超过") {
		t.Fatalf("期望撞上响应头上限，得到 %v", err)
	}
}

// TestFetchTLSChecksCert 用自签证书证明"我们没跳过证书校验"。
//
// 跳过校验的探针会一路绿灯，而真实浏览器会拦下来——
// 那正好是兼底型节点最常见的样子（它给不出目标站点的证书）。
func TestFetchTLSChecksCert(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	defer ln.Close()
	cert := selfSignedCert(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = s.Handshake() // 客户端会拒，这里拿到错误即可
	}()
	a := ln.Addr().(*net.TCPAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", itoa(a.Port)), 3*time.Second)
	if err != nil {
		t.Fatalf("拨号: %v", err)
	}
	defer conn.Close()
	_, err = Fetch(ctx, conn, Target{Host: "127.0.0.1", Path: "/", UseTLS: true})
	if err == nil || !strings.Contains(err.Error(), "TLS 握手失败") {
		t.Fatalf("期望证书校验把这次探针对掉，得到 %v", err)
	}
	// 只断言"是握手阶段的错"，不断言具体文案：Go 的证书错误措辞会变。
	t.Logf("握手错误原文（供参考）：%v", err)
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wps-probe-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
