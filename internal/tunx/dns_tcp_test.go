package tunx

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// 这些测试钉的是「一条 TCP 连接上能连续问」这件事。
// hijack_dns 把 tcp:53 也 DNAT 进了协议栈，而 relayTCP 过去没有 53 端口分支，
// 被劫持的 TCP DNS 连接于是被当成普通连接、朝自己的网卡地址拨了出去。

type served struct {
	n   int
	err error
}

// dnsTCPAsk 发一条带 2 字节大端长度前缀的查询，读回一条带前缀的应答。
func dnsTCPAsk(t *testing.T, c net.Conn, query []byte) []byte {
	t.Helper()
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(query)))
	// 前缀与正文一次写出去：net.Pipe 是无缓冲的同步管道，
	// 分开写会让服务端的 bufio 先只看见 2 字节，正文留到下一次读。
	msg := append(append([]byte{}, hdr[:]...), query...)
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("写查询: %v", err)
	}
	return dnsTCPRead(t, c)
}

// dnsTCPRead 按前缀读出一条应答。
func dnsTCPRead(t *testing.T, c net.Conn) []byte {
	t.Helper()
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		t.Fatalf("读应答长度: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("读应答正文: %v", err)
	}
	return resp
}

// serve 起被测循环，返回它的结束结果。
func serveDNS(t *testing.T, server net.Conn, s *dnsServer, idle time.Duration) <-chan served {
	t.Helper()
	ch := make(chan served, 1)
	go func() {
		n, err := serveDNSOverTCP(server, s.Serve, idle)
		ch <- served{n, err}
	}()
	return ch
}

func TestDNSTCPServesOneQuery(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{"a.example.com": true}}
	s := newDNSServer(t, dec, nil)
	client, server := net.Pipe()
	defer server.Close()
	done := serveDNS(t, server, s, dnsTCPIdle)

	resp := dnsTCPAsk(t, client, queryFor(t, "a.example.com", dnsmessage.TypeA))
	ip := answerIP(t, resp)
	if !ip.Is4() || ip.String()[:6] != "198.18" {
		t.Fatalf("应答里的 IP 不对: %s", ip)
	}

	client.Close()
	r := <-done
	if r.err != nil {
		t.Fatalf("客户端关连接后应视为正常收尾, got %v", r.err)
	}
	if r.n != 1 {
		t.Fatalf("应答条数 = %d, want 1", r.n)
	}
}

// TestDNSTCPServesManyQueriesOnOneConnection 是这条修复的全部理由。
//
// glibc 的 resolver 与 systemd-resolved 的上行连接都会留着复用，
// RFC 5936 也要求服务端支持一条连接上连续查询。
// 只答一条就收尾，表现是「解析时好时坏，且只在应答变大时出现」——最难查的一类故障，
// 而且 Go 自己的 dnsclient 一次一问就关连接（dnsclient_unix.go:197-198），
// 拿 Go 程序去验是验不出这个缺陷的。
func TestDNSTCPServesManyQueriesOnOneConnection(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{
		"a.example.com": true, "b.example.com": true, "c.example.com": true,
	}}
	s := newDNSServer(t, dec, nil)
	client, server := net.Pipe()
	defer server.Close()
	done := serveDNS(t, server, s, dnsTCPIdle)

	names := []string{"a.example.com", "b.example.com", "c.example.com", "a.example.com"}
	seen := make([]string, 0, len(names))
	for _, name := range names {
		resp := dnsTCPAsk(t, client, queryFor(t, name, dnsmessage.TypeA))
		seen = append(seen, answerIP(t, resp).String())
	}

	// 三个不同域名必须是三个不同的假 IP；重复问同一个域名必须拿回同一个，
	// 否则同一次会话里的两条连接会落到两个地址上，反查也就会错配。
	if seen[0] == seen[1] || seen[1] == seen[2] || seen[0] == seen[2] {
		t.Fatalf("不同域名发回了同一个假 IP: %v", seen)
	}
	if seen[3] != seen[0] {
		t.Fatalf("同一域名两次答案不一致: %s vs %s", seen[0], seen[3])
	}

	client.Close()
	r := <-done
	if r.err != nil {
		t.Fatalf("%v", r.err)
	}
	if r.n != len(names) {
		t.Fatalf("应答条数 = %d, want %d", r.n, len(names))
	}
}

// TestDNSTCPIdleTimeoutIsCleanExit 空转到点应当正常收、不报错。
// 空闲计时器是这条连接上唯一还会一直挂着的情况，值得单独钉。
func TestDNSTCPIdleTimeoutIsCleanExit(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{"a.example.com": true}}
	s := newDNSServer(t, dec, nil)
	client, server := net.Pipe()
	defer server.Close()
	defer client.Close()
	done := serveDNS(t, server, s, 40*time.Millisecond)

	dnsTCPAsk(t, client, queryFor(t, "a.example.com", dnsmessage.TypeA))
	// 读完应答之后什么都不做，也不关连接——关了就区分不出超时和 EOF。
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("空闲到点不该报错: %v", r.err)
		}
		if r.n != 1 {
			t.Fatalf("应答条数 = %d, want 1", r.n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("空闲计时器没让循环收下去")
	}
}

// TestDNSTCPRejectsOversizedFrame 长度前缀是对方给的，不能拿它直接当分配依据。
func TestDNSTCPRejectsOversizedFrame(t *testing.T) {
	var called bool
	ch := make(chan served, 1)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		n, err := serveDNSOverTCP(server, func(context.Context, []byte) ([]byte, error) {
			called = true
			return nil, nil
		}, dnsTCPIdle)
		ch <- served{n, err}
	}()

	// 声称有 65535 字节，但正文一个都不发。
	if _, err := client.Write([]byte{0xFF, 0xFF}); err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err == nil {
		t.Fatal("超长报文应当报错")
	}
	if called {
		t.Fatal("长度越界时不该把报文交给应答逻辑")
	}
	server.Close()
}

func TestDNSTCPZeroLengthIsError(t *testing.T) {
	ch := make(chan served, 1)
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		n, err := serveDNSOverTCP(server, func(context.Context, []byte) ([]byte, error) {
			t.Error("长度为 0 的报文不该进入应答")
			return nil, nil
		}, dnsTCPIdle)
		ch <- served{n, err}
	}()
	if _, err := client.Write([]byte{0x00, 0x00}); err != nil {
		t.Fatal(err)
	}
	if r := <-ch; r.err == nil {
		t.Fatal("长度为 0 的报文应当报错")
	}
	server.Close()
}

// TestDNSTCPTruncatedFrame 只送到半个长度前缀就断开，属于半截握手：
// 要报错，不能当成正常收尾放过去。
func TestDNSTCPTruncatedFrame(t *testing.T) {
	ch := make(chan served, 1)
	client, server := net.Pipe()
	go func() {
		n, err := serveDNSOverTCP(server, func(context.Context, []byte) ([]byte, error) {
			return nil, nil
		}, dnsTCPIdle)
		ch <- served{n, err}
	}()
	if _, err := client.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if r := <-ch; r.err == nil {
		t.Fatal("半截长度前缀加 EOF 应当报错")
	}
	server.Close()
}

// TestDNSTCPPrefixAndBodyArriveSeparately 分开两次写（先长度再正文）是
// 一个合法客户端可以做的事，也是分帧最容易出错的地方：前缀读走之后
// 若把正文多吞或少吞一个字节，后面整条流就错位，表现是「解析超时」而不是「解析出错」。
// 注意 stdlib 自己不这么写——它把前缀和正文放在同一次 Write 里
// （dnsclient_unix.go:89-92），所以这条测的是健壮性，不是复现某个真实客户端。
func TestDNSTCPPrefixAndBodyArriveSeparately(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{"x.example.com": true}}
	s := newDNSServer(t, dec, nil)
	q := queryFor(t, "x.example.com", dnsmessage.TypeA)

	client, server := net.Pipe()
	defer server.Close()
	go func() { _, _ = serveDNSOverTCP(server, s.Serve, dnsTCPIdle) }()

	for i := 0; i < 3; i++ {
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(q)))
		if _, err := client.Write(hdr[:]); err != nil {
			t.Fatalf("第 %d 次写前缀: %v", i+1, err)
		}
		if _, err := client.Write(q); err != nil {
			t.Fatalf("第 %d 次写正文: %v", i+1, err)
		}
		resp := dnsTCPRead(t, client)
		if ip := answerIP(t, resp); ip.String()[:6] != "198.18" {
			t.Fatalf("第 %d 次应答不对: %s", i+1, ip)
		}
	}
	client.Close()
}
