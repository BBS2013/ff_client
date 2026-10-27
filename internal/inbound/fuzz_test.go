// 入站解析的模糊测试。这一层收的是"本机任何进程都能发过来"的字节，
// 所以它的第一条要求不是"聪明"，而是**任何输入都不许 panic、不许越界**。
//
// 跑法：
//
//	make fuzz-smoke      # 每个目标各跑 10 秒（CI 与本机等价，不需要网络）
//	go test ./internal/inbound -run=NONE -fuzz=FuzzSocks5Addr -fuzztime=2m
package inbound

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"testing"

	"wps_app/internal/rules"
)

// FuzzSocks5Addr 打的是 readAddrN：SOCKS5 握手与 UDP 报文头都经它。
//
// 断言的是**帧边界**而不是具体地址：解析器多报或少报一个字节，
// 上层就会把端口当成地址、把正文当成下一个请求——那是比崩溃更难查的坏法。
func FuzzSocks5Addr(f *testing.F) {
	seeds := [][]byte{
		{127, 0, 0, 1},
		{0, 0, 0, 0},
		{1, 1, 1, 1, 0x01, 0xbb}, // 后面还跟着别的字节
		{},                       // 空
		{0x01},                   // 截断的 IPv4
		make([]byte, 16),         // 全零 IPv6
		{0xff, 0xff},             // 不支持的 ATYP
		{0x00, 0x03, 0x00},       // 长度 0 的域名
		{0x03, 'a'},              // 声明有域名却没内容
	}
	for _, s := range seeds {
		for _, atyp := range []byte{atypIPv4, atypDomain, atypIPv6, 0x00, 0x7f, 0xff} {
			f.Add(atyp, s)
		}
	}
	f.Fuzz(func(t *testing.T, atyp byte, body []byte) {
		host, n, err := readAddrN(bytes.NewReader(body), atyp)
		if err != nil {
			if n != 0 {
				t.Fatalf("报错却消耗了 %d 字节（atyp=%d）", n, atyp)
			}
			return
		}
		if n <= 0 || n > len(body) {
			t.Fatalf("消耗 %d 字节越界（输入只有 %d 字节，atyp=%d）", n, len(body), atyp)
		}
		if host == "" {
			t.Fatalf("解析成功却给了空地址（atyp=%d, %x）", atyp, body)
		}
		if len(host) > 255 {
			t.Fatalf("域名长度 %d 超出 ATYP 可编码范围", len(host))
		}
	})
}

// FuzzAssocPacket 打的是 SOCKS5 UDP 中继的报文头拆解：
// 那 4 字节头 + 地址 + 端口全由对端决定，切错一刀就把别人的正文当地址用。
//
// 这里还验一次"解出来的东西能原样封回去"，因为应答方向用的是同一套编码。
func FuzzAssocPacket(f *testing.F) {
	pkt := func(atyp byte, addr []byte, port uint16, payload string) []byte {
		out := []byte{0, 0, 0, atyp}
		out = append(out, addr...)
		out = append(out, byte(port>>8), byte(port))
		return append(out, []byte(payload)...)
	}
	f.Add(pkt(atypIPv4, []byte{8, 8, 8, 8}, 53, "hello"))
	f.Add(pkt(atypDomain, append([]byte{7}, []byte("example")...), 443, ""))
	f.Add(pkt(atypIPv6, make([]byte, 16), 1, "x"))
	f.Add([]byte{})
	f.Add([]byte{0, 0, 1, 1}) // FRAG != 0
	f.Add([]byte{0, 0, 0, 1, 127, 0, 0})
	f.Add([]byte{0, 0, 0, 3, 255, 'a'})
	f.Fuzz(func(t *testing.T, p []byte) {
		addr, payload, ok := parseAssocPacket(p)
		if !ok {
			return
		}
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatalf("解出来的地址连 SplitHostPort 都过不了: %q", addr)
		}
		if portStr == "" || host == "" {
			t.Fatalf("地址不完整: %q", addr)
		}
		if port, err := strconv.Atoi(portStr); err != nil || port < 0 || port > 65535 {
			t.Fatalf("端口不可读: %q", addr)
		}
		if len(payload) > len(p) {
			t.Fatalf("正文比整个报文还长: %d > %d", len(payload), len(p))
		}
		// port 0 是"发往 0 端口"的畸形目标：解析器只管拆帧，所以会放过它，
		// 而编码器从来拒绝它（应答里不该出现 0 端口）。这个不对称是有意的，
		// 写成断言钉住，免得将来有人拿"要能往返"当理由把 0 端口编进应答。
		if port, err := strconv.Atoi(portStr); err == nil && port == 0 {
			if _, err := appendAddr(nil, addr); err == nil {
				t.Fatalf("port 0 应当被编码器拒绝: %q", addr)
			}
			return
		}
		// 封回去再解一次，必须得到同一个地址与同一份正文。
		// appendAddr 已经带上 ATYP 那一字节，报文头只剩 RSV+FRAG 三个零。
		buf, err := appendAddr(nil, addr)
		if err != nil {
			t.Fatalf("解出来的地址封不回去 %q: %v", addr, err)
		}
		again := append([]byte{0, 0, 0}, buf...)
		again = append(again, payload...)
		addr2, payload2, ok2 := parseAssocPacket(again)
		if !ok2 || addr2 != addr || !bytes.Equal(payload2, payload) {
			t.Fatalf("往返不一致:\n 原 %q/%x\n 回 %q/%x (ok=%v)", addr, payload, addr2, payload2, ok2)
		}
	})
}

// FuzzAppendAddr 打的是"给客户端的每个报文头都要用"的编码器。
// 它吃的是从隧道那边回来的地址字符串，同样不是本机可控的东西。
func FuzzAppendAddr(f *testing.F) {
	f.Add("127.0.0.1:7891")
	f.Add("[::1]:443")
	f.Add("example.com:80")
	f.Add("0.0.0.0:0")
	f.Add(":80")
	f.Add("host:notaport")
	f.Add("host:70000")
	f.Add("a.com:")
	f.Fuzz(func(t *testing.T, hostport string) {
		out, err := appendAddr(nil, hostport)
		if err != nil {
			return
		}
		if len(out) < 4 {
			t.Fatalf("编码结果短到没法再解析: %x", out)
		}
		host, n, err := readAddrN(bytes.NewReader(out[1:]), out[0])
		if err != nil {
			t.Fatalf("自己编出来的地址解不回去 %q: %v", hostport, err)
		}
		if len(out) != 1+n+2 {
			t.Fatalf("编码结果长度不对：ATYP(1)+地址(%d)+端口(2) 之后还剩 %d 字节",
				n, len(out)-(1+n+2))
		}
		want, portStr, err := net.SplitHostPort(hostport)
		if err != nil {
			t.Fatalf("编码成功但输入连 SplitHostPort 都过不了: %q", hostport)
		}
		wantPort, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatalf("输入端口不是数字: %q", hostport)
		}
		// 按数值比：appendAddr 会把 "01" 归一成 1，那是应该的，不是漂移。
		if got := int(binary.BigEndian.Uint16(out[1+n:])); got != wantPort {
			t.Fatalf("端口编解码不一致：写 %s，读回 %d", portStr, got)
		}
		if got := normalizeForCompare(host); !sameAddress(got, normalizeForCompare(want)) {
			t.Fatalf("往返地址变了: %q → %q", want, host)
		}
	})
}

// normalizeForCompare / sameAddress：IP 的字面量写法不止一种
// （::ffff:1.2.3.4 与 1.2.3.4 是同一个地址），编码时会归一成紧凑形式，
// 所以比较双方都先过一遍 net.IP 的规范字符串。
func normalizeForCompare(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

func sameAddress(a, b string) bool { return a == b }

// TestUsableHostChars 把 fuzz 找到的那一类输入钉成常驻用例。
//
// testdata/fuzz 里也留了原始最小用例，但那种只在一行上断言；
// 这里要的是"为什么这些字符必须拒"这件事有个地方写着。
func TestUsableHostChars(t *testing.T) {
	good := []string{"example.com", "a", "xn--fiqs8s.cn", "1.2.3.4", "host-with-dash"}
	bad := []string{"ex:ample.com", "a]b", "[::1]", "user@host", "a b", "a\n", "a\x00b", "a\tb"}
	for _, h := range good {
		if !rules.ValidHostName(h) {
			t.Errorf("%q 是合法主机名，不该被拒", h)
		}
	}
	for _, h := range bad {
		if rules.ValidHostName(h) {
			t.Errorf("%q 会把 host:port 的切分带坏，必须拒", h)
		}
	}
	// 端到端一次：域名里带 ':' 的 CONNECT 请求必须被当场拒绝，
	// 而不是把一个"再解析不了"的地址交给路由器。
	host, _, err := readAddrN(bytes.NewReader([]byte{3, 5, 'a', ':', 'b', 'c', 'd'}), atypDomain)
	if err == nil {
		t.Fatalf("带冒号的域名被接受了，host=%q", host)
	}
}
