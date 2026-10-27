package inbound

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// finSensitiveOrigin 模拟 Tengine 这类源站：读完请求后如果发现客户端已经把
// 写侧关了（收到 FIN），它就不再回响应，直接把连接关掉。
//
// 真实抓包确认过 mirrors.aliyun.com:80 就是这个行为——同一个请求，带 FIN
// 得到 0 字节，不带 FIN 正常回 301。代理曾经在这里无条件半关，
// 于是所有这样的源站一律空响应，而日志里一行错误都没有。
func finSensitiveOrigin(t *testing.T, body string) string {
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
				br := bufio.NewReader(c)
				if _, err := http.ReadRequest(br); err != nil {
					return
				}
				// 再读一次：只有立刻拿到 EOF 才说明对端半关了写侧。
				// 超时不算——没收到 FIN 就该正常回响应。
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				var probe [1]byte
				n, perr := c.Read(probe[:])
				if n == 0 && errors.Is(perr, io.EOF) {
					return // 客户端半关了：不回任何响应，静默关连接。
				}
				_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: "+
					itoa(len(body))+"\r\nConnection: keep-alive\r\n\r\n"+body)
				// 故意不回 EOF：源站保持连接，等下一个请求。
				time.Sleep(300 * time.Millisecond)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestHTTPForwardMustNotHalfCloseFramedRequest 锁住明文 HTTP 转发的分帧契约：
// 请求只要有 Content-Length 或压根没正文，源站就已经知道正文到哪儿结束，
// 不需要 FIN。补一个 FIN 不是「更规范」，而是会让一部分源站直接不回响应。
func TestHTTPForwardMustNotHalfCloseFramedRequest(t *testing.T) {
	origin := finSensitiveOrigin(t, "payload-ok")
	proxyAddr := startHTTPProxy(t, rulesDirect)

	c := dialProxy(t, proxyAddr)
	req := "GET http://" + origin + "/ HTTP/1.1\r\nHost: " + origin + "\r\n\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatalf("写请求: %v", err)
	}

	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读响应: %v（源站因收到 FIN 静默关连接）", err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("状态码 = %d, 期望 200", res.StatusCode)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("读正文: %v", err)
	}
	if string(body) != "payload-ok" {
		t.Fatalf("正文 = %q, 期望 %q", body, "payload-ok")
	}
}

// TestHTTPForwardDoesNotHangOnKeepAliveOrigin 另一头的问题：源站回完响应
// 按 keep-alive 把连接留着（真实 CDN 的常态），转发必须自己收尾，
// 不能挂在那条连接上等一个永远不会来的 EOF——那是每请求泄漏一个 goroutine 和 fd。
func TestHTTPForwardDoesNotHangOnKeepAliveOrigin(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	released := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		_, _ = http.ReadRequest(br)
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
		// 响应发完就什么都不做：既不发 FIN 也不关连接。
		// 只有代理主动收尾，这里才会读到 EOF。
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var probe [1]byte
		if n, _ := c.Read(probe[:]); n == 0 {
			released <- struct{}{}
		}
		_ = c.Close()
	}()

	origin := ln.Addr().String()
	proxyAddr := startHTTPProxy(t, rulesDirect)
	c := dialProxy(t, proxyAddr)
	if _, err := io.WriteString(c, "GET http://"+origin+"/ HTTP/1.1\r\nHost: "+origin+"\r\n\r\n"); err != nil {
		t.Fatalf("写请求: %v", err)
	}

	br := bufio.NewReader(c)
	res, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("读响应: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if strings.TrimSpace(string(body)) != "hello" {
		t.Fatalf("正文 = %q, 期望 hello", body)
	}

	select {
	case <-released:
	case <-time.After(4 * time.Second):
		t.Fatal("源站连接没被代理收尾：转发挂在 keep-alive 连接上，goroutine 与 fd 泄漏")
	}
}
