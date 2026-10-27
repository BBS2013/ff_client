package inbound

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"wps_app/internal/metrics"
)

const blockRuleBook = "DOMAIN-SUFFIX,ads.example.com,REJECT\nDOMAIN-SUFFIX,example.com,PROXY\nFINAL,DIRECT\n"

// startBlockingSOCKS5 起一个能把挂起上限改短的 SOCKS5 入口。
//
// 不复用 startSOCKS5：它只返回地址，用例就没法把 75 秒的上限压成几十毫秒。
// 上限做成服务器上的字段而不是包级变量，并发用例之间才不会互相踩。
func startBlockingSOCKS5(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	s := NewSOCKS5(newTestRouter(t, blockRuleBook), "", "", reg)
	s.blocked.hold = 50 * time.Millisecond
	return serve(t, func(ln net.Listener) { _ = s.Serve(ln) })
}

func startBlockingHTTP(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	h := NewHTTPProxy(newTestRouter(t, blockRuleBook), reg)
	h.blocked.hold = 50 * time.Millisecond
	return serve(t, func(ln net.Listener) { _ = h.Serve(ln) })
}

func serve(t *testing.T, run func(net.Listener)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go run(ln)
	return ln.Addr().String()
}

// TestSOCKS5BlockedWritesNoReply 被拦时一个字节都不许回。
//
// SOCKS5 的失败应答在客户端看来就是"这个域名连不上"，
// 而这里选的是"让它超时"：回任何应答都等于告诉发起方有一个代理在做决定。
func TestSOCKS5BlockedWritesNoReply(t *testing.T) {
	addr := startBlockingSOCKS5(t, nil)
	c := dialProxy(t, addr)
	defer func() { _ = c.Close() }()
	socksGreeting(t, c, authNone)
	readSocksMethod(t, c)
	socksConnectRequest(t, c, cmdConnect, atypDomain, domainAddr("ads.example.com"), 443)

	_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	buf := make([]byte, 32)
	n, err := c.Read(buf)
	if n > 0 {
		t.Fatalf("被拦时不该回任何字节，收到 %d 字节 %#v", n, buf[:n])
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("这段窗口里应当什么都没有（超时候），实际 %v", err)
	}

	// 到挂起上限后必须收掉：不能真的永久挂着，否则一堆广告连接会把 fd 占满。
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf[:1]); err == nil {
		t.Fatal("挂到上限后应被关闭，连接却一直留着")
	}
}

// TestHTTPBlockedWritesNoResponse HTTP 同理——502 是最刺眼的泄漏。
func TestHTTPBlockedWritesNoResponse(t *testing.T) {
	addr := startBlockingHTTP(t, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, err = c.Write([]byte("CONNECT ads.example.com:443 HTTP/1.1\r\nHost: ads.example.com:443\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if n > 0 {
		t.Fatalf("被拦时不该回任何响应，收到 %q", buf[:n])
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("应当什么都没有（超时候），实际 %v", err)
	}

	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(c, buf[:1]); err == nil {
		t.Fatal("挂到上限后应被关闭")
	}
}

// TestHTTPPlainRequestBlockedWritesNoResponse 普通（非 CONNECT）请求也不能回 502。
func TestHTTPPlainRequestBlockedWritesNoResponse(t *testing.T) {
	addr := startBlockingHTTP(t, nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("GET http://ads.example.com/ HTTP/1.1\r\nHost: ads.example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	buf := make([]byte, 64)
	n, rerr := c.Read(buf)
	if n > 0 {
		t.Fatalf("收到响应 %q，客户端因此知道被拦了", buf[:n])
	}
	if !errors.Is(rerr, os.ErrDeadlineExceeded) {
		t.Fatalf("应当什么都没有，实际 %v", rerr)
	}
}

// TestBlockedConnShowsUpInRegistry 客户端什么都收不到，本机就必须看得见。
// 连接表里要有这一条，标成拦截、字节数为 0——
// 否则「查不出为什么这个网站打不开」就成了无解的题。
func TestBlockedConnShowsUpInRegistry(t *testing.T) {
	reg := metrics.NewRegistry(16, 16)
	addr := startBlockingSOCKS5(t, reg)
	c := dialProxy(t, addr)
	defer func() { _ = c.Close() }()
	socksGreeting(t, c, authNone)
	readSocksMethod(t, c)
	socksConnectRequest(t, c, cmdConnect, atypDomain, domainAddr("ads.example.com"), 443)
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = c.Read(make([]byte, 8))

	snap := reg.Snapshot()
	all := append(append([]metrics.ConnView{}, snap.Active...), snap.History...)
	var found *metrics.ConnView
	for i := range all {
		if strings.Contains(all[i].Matched, "ads.example.com") || all[i].Outbound == "REJECT" {
			found = &all[i]
		}
	}
	if found == nil {
		t.Fatalf("拦截在本机连接表里完全没有（active=%d history=%d）——客户端收不到、本机也看不见，就成了查无此事",
			len(snap.Active), len(snap.History))
	}
	if found.Up+found.Down != 0 {
		t.Errorf("拦截不该记进上下行: up=%d down=%d", found.Up, found.Down)
	}
}
