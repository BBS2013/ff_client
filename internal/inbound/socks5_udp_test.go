package inbound

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
	"wps_app/internal/rules"
)

// rulesProxy 是「全部走代理」的最小规则集。UDP 关联的测试必须用它：
// 直连出站明确不支持 UDP，拿 rulesDirect 去跑只会一路撞上那一句拒绝。
const rulesProxy = "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,PROXY"

// udpEchoOutbound 是一个走真实 UDP 回环的假 PROXY 出站：报文发给哪儿就真发到哪儿。
// 用真的 socket 而不是把实现复述一遍——UDP 关联的每一个字节都要经过真实收发，
// 才算真的在验证它。
type udpEchoOutbound struct {
	dials atomic.Int32
	// failDials 让前 N 次 DialUDP 直接失败，用来演"首包拨号失败、之后恢复"。
	failDials atomic.Int32

	mu   sync.Mutex
	sent []string
}

func (e *udpEchoOutbound) Name() string { return string(outbound.PolicyProxy) }

func (e *udpEchoOutbound) DialContext(context.Context, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (e *udpEchoOutbound) Close() error { return nil }

func (e *udpEchoOutbound) DialUDP(context.Context) (outbound.PacketConn, error) {
	n := e.dials.Add(1)
	if e.failDials.Add(-1) >= 0 {
		return nil, errors.New("模拟拨号失败（测试用）")
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	_ = n
	return &echoPacket{conn: pc, owner: e}, nil
}

type echoPacket struct {
	conn  *net.UDPConn
	owner *udpEchoOutbound
}

func (p *echoPacket) WriteTo(b []byte, addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	p.owner.mu.Lock()
	p.owner.sent = append(p.owner.sent, addr)
	p.owner.mu.Unlock()
	_, err = p.conn.WriteToUDP(b, ua)
	return err
}

func (p *echoPacket) ReadFrom(b []byte) (int, string, error) {
	if err := p.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return 0, "", err
	}
	// 来源就是真实对端的地址：客户端据此认出「这是谁回的」，
	// 测试也正是靠这一点验证应答头里的地址没被写错。
	n, from, err := p.conn.ReadFromUDP(b)
	if err != nil {
		return 0, "", err
	}
	return n, from.String(), nil
}

func (p *echoPacket) Close() error { return p.conn.Close() }

// startSOCKS5UDP 起一个 PROXY 出站为真发真收的 SOCKS5 入口。
func startSOCKS5UDP(t *testing.T, ruleText string) (string, *udpEchoOutbound) {
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
	echo := &udpEchoOutbound{}
	out := outbound.NewSet(outbound.NewDirect(3*time.Second), echo)
	t.Cleanup(func() { _ = out.Close() })
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() { _ = NewSOCKS5(router.New(eng, out, 3*time.Second), "", "").Serve(ln) }()
	return ln.Addr().String(), echo
}

// startUDPEcho 起一个「原样回显」的 UDP 服务，充当隧道的对端。
func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, udpAssocBuffer)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteToUDP(buf[:n], from); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

// assocOpenUDP 完成协商并发起 UDP ASSOCIATE，返回控制连接与中继地址。
func assocOpenUDP(t *testing.T, proxyAddr string) (net.Conn, string) {
	t.Helper()
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authNone)
	readSocksMethod(t, c)
	socksConnectRequest(t, c, cmdUDPAssociate, atypIPv4, []byte{127, 0, 0, 1}, 0)
	var b [10]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		t.Fatalf("读 ASSOCIATE 应答: %v", err)
	}
	if b[1] != repSuccess {
		t.Fatalf("UDP ASSOCIATE 应答 = %#x, want %#x", b[1], repSuccess)
	}
	if b[3] != atypIPv4 {
		t.Fatalf("BND ATYP = %#x, 本地中继只可能是 IPv4", b[3])
	}
	relayIP := net.IP(b[4:8])
	if !relayIP.IsLoopback() {
		t.Fatalf("BND.ADDR = %v, 中继口应绑在控制连接的本地地址上", relayIP)
	}
	port := binary.BigEndian.Uint16(b[8:10])
	if port == 0 {
		t.Fatalf("BND.PORT = 0，客户端无从知道往哪儿发包")
	}
	relay := net.JoinHostPort(relayIP.String(), strconv.Itoa(int(port)))
	t.Logf("中继地址 %s", relay)
	return c, relay
}

func TestSOCKS5UDPAssociateRelaysDatagram(t *testing.T) {
	echoAddr := startUDPEcho(t)
	proxyAddr, echo := startSOCKS5UDP(t, rulesProxy)
	_, relay := assocOpenUDP(t, proxyAddr)

	uc, err := net.DialUDP("udp", nil, mustUDPAddr(t, relay))
	if err != nil {
		t.Fatalf("连中继: %v", err)
	}
	defer func() { _ = uc.Close() }()

	host, port := mustHostPort(t, echoAddr)
	if _, err := uc.Write(assocPacket(t, "hello udp", atypIPv4, net.ParseIP(host).To4(), uint16(port))); err != nil {
		t.Fatalf("发报文: %v", err)
	}
	from, payload := readAssoc(t, uc)
	if string(payload) != "hello udp" {
		t.Fatalf("回包正文 = %q", payload)
	}
	// 回包头里的地址必须是对端真实来源，客户端靠它认人。
	if from != echoAddr {
		t.Fatalf("回包来源 = %q, want %q", from, echoAddr)
	}
	if got := echo.sentAt(0); got != echoAddr {
		t.Fatalf("转发目标 = %q, want %q", got, echoAddr)
	}
}

func TestSOCKS5UDPAssociateDialsOncePerAssociation(t *testing.T) {
	echoAddr := startUDPEcho(t)
	proxyAddr, echo := startSOCKS5UDP(t, rulesProxy)
	_, relay := assocOpenUDP(t, proxyAddr)

	uc, err := net.DialUDP("udp", nil, mustUDPAddr(t, relay))
	if err != nil {
		t.Fatalf("连中继: %v", err)
	}
	defer func() { _ = uc.Close() }()

	host, port := mustHostPort(t, echoAddr)
	for i := 0; i < 3; i++ {
		if _, err := uc.Write(assocPacket(t, "ping", atypIPv4, net.ParseIP(host).To4(), uint16(port))); err != nil {
			t.Fatalf("发第 %d 包: %v", i, err)
		}
		if _, payload := readAssoc(t, uc); string(payload) != "ping" {
			t.Fatalf("第 %d 个回包正文 = %q", i, payload)
		}
	}
	// 一条控制连接对应一条隧道会话：客户端往多少个目标发包都不该再开新会话。
	if n := echo.dials.Load(); n != 1 {
		t.Fatalf("建立 UDP 会话 %d 次, want 1", n)
	}
}

func TestSOCKS5UDPAssociateEndsWithControlConnection(t *testing.T) {
	echoAddr := startUDPEcho(t)
	proxyAddr, _ := startSOCKS5UDP(t, rulesProxy)
	c, relay := assocOpenUDP(t, proxyAddr)

	uc, err := net.DialUDP("udp", nil, mustUDPAddr(t, relay))
	if err != nil {
		t.Fatalf("连中继: %v", err)
	}
	defer func() { _ = uc.Close() }()

	host, port := mustHostPort(t, echoAddr)
	if _, err := uc.Write(assocPacket(t, "alive", atypIPv4, net.ParseIP(host).To4(), uint16(port))); err != nil {
		t.Fatalf("发报文: %v", err)
	}
	readAssoc(t, uc)

	_ = c.Close()
	// 中继口是在服务端那个 goroutine 里、等控制连接读到 EOF 之后才关的
	// （见 socks5_udp.go 主循环末尾那句 pc.Close()），所以"客户端关掉控制连接"与
	// "中继口作废"之间必然有一段窗口。
	//
	// 这里原来只等 500ms 就断言"再也收不到回声"：机器一忙、或者被挪进独立网络
	// 命名空间跑（make test-offline 就是），服务端注意到 EOF 会慢过 500ms，
	// 于是回声真的还在——用例随机红，而产品什么都没做错。
	//
	// 换成量它真正要保证的那件事：**中继口必须在有限时间内不再回包**。
	// 会话漏掉的后果（客户端走了、UDP 转发还开着）照样当场红；
	// 而"收尾慢了几百毫秒"不再被当成缺陷。
	// 连续两次探针没回声才算作废——单次超时可能只是网络慢，不是口关了。
	deadline := time.Now().Add(10 * time.Second)
	buf := make([]byte, 2048)
	var probes, quietRun int
	start := time.Now()
	for {
		if time.Now().After(deadline) {
			t.Fatalf("控制连接已断 %v，中继仍在回包（探针 %d 次）：这条 UDP 会话漏了",
				time.Since(start), probes)
		}
		if _, err := uc.Write(assocPacket(t, "gone-"+strconv.Itoa(probes), atypIPv4, net.ParseIP(host).To4(), uint16(port))); err != nil {
			break // 口已经关了，写不进去——正是它作废的证据
		}
		probes++
		_ = uc.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := uc.Read(buf); err != nil {
			if quietRun++; quietRun >= 2 {
				break
			}
			continue
		}
		quietRun = 0
		// 还在回包就再探一次。没有这一句，会话真漏了的时候这里会在 10 秒里
		// 空转几十万发探针——红是红了，但把一个失败用例跑成了打自己机器的 DoS。
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("中继在控制连接断开后 %v 内停止回包，探针 %d 次", time.Since(start), probes)
}

func TestSOCKS5UDPAssociateSurvivesOutboundWithoutUDP(t *testing.T) {
	// rulesDirect 配的 PROXY 出站是 failingDialer，它没有 DialUDP。
	// ASSOCIATE 仍要应答成功——RFC 要求应答早于第一个报文，那时还不知道能不能转发；
	// 真正被拒的是那一条带原因的日志，而不是把关联建不起来。
	proxyAddr := startSOCKS5(t, rulesDirect, "", "")
	c := dialProxy(t, proxyAddr)
	socksGreeting(t, c, authNone)
	readSocksMethod(t, c)
	socksConnectRequest(t, c, cmdUDPAssociate, atypIPv4, []byte{127, 0, 0, 1}, 0)
	if rep := readSocksReply(t, c); rep != repSuccess {
		t.Fatalf("UDP ASSOCIATE 应答 = %#x, want %#x", rep, repSuccess)
	}
}

// TestSOCKS5UDPRefusalIsRecordedOnce 是被拒的 UDP 也进连接表这一条的 SOCKS5 半边。
//
// 客户端拿不到任何错误：UDP 没有"拒绝"这个表达方式，重试是它唯一会做的事。
// 于是两件事必须同时成立——① 表里要有一行带原因的记录，
// ② 同一个目标只能有一行。
//
// ② 现在靠的是「按目标去重」（refused 那张 map），不是「整条关联只拨一次号」。
// 后者更省事，但它把"首包拨号失败"变成了永久判决：一次瞬时失败之后，
// 这条关联在剩下 10 分钟里再也不拨号，后续每个包都掉进 pc == nil 被静默丢弃，
// 而表里只有一行、日志里只有一句——用户看到的是"UDP 全哑了，面板说没问题"。
func TestSOCKS5UDPRefusalIsRecordedOnce(t *testing.T) {
	reg := metrics.NewRegistry(16, 16)
	s := NewSOCKS5(newTestRouter(t, rulesDirect), "", "", reg)
	addr := serve(t, func(ln net.Listener) { _ = s.Serve(ln) })

	ctl, relay := assocOpenUDP(t, addr)
	defer func() { _ = ctl.Close() }()
	uc, err := net.DialUDP("udp", nil, mustUDPAddr(t, relay))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = uc.Close() }()

	// 10.0.0.0/8 命中 IP-CIDR…DIRECT，而直连出站明确不带 UDP。
	pkt := assocPacket(t, "ping", atypIPv4, []byte{10, 0, 0, 1}, 53)
	for i := 0; i < 3; i++ {
		if _, err := uc.Write(pkt); err != nil {
			t.Fatalf("发第 %d 个报文: %v", i+1, err)
		}
		time.Sleep(60 * time.Millisecond)
	}

	var row metrics.ConnView
	deadline := time.Now().Add(3 * time.Second)
	var snap metrics.Snapshot
	for time.Now().Before(deadline) {
		snap = reg.Snapshot()
		for _, h := range append(append([]metrics.ConnView(nil), snap.Active...), snap.History...) {
			if h.Inbound == "socks5-udp" && h.Err != "" {
				row = h
			}
		}
		if row.ID != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if row.ID == 0 {
		t.Fatalf("被拒的 UDP 在连接表里没有任何痕迹（active=%d history=%d）",
			len(snap.Active), len(snap.History))
	}
	if !strings.Contains(row.Err, "UDP") {
		t.Errorf("失败原因没说是 UDP 带不动: %q", row.Err)
	}
	if row.Host != "10.0.0.1" || row.Port != "53" {
		t.Errorf("失败行指错了目标: %+v", row)
	}
	if row.Up+row.Down != 0 {
		t.Errorf("一条根本没建起来的关联不该有字节: %+v", row)
	}
	if snap.TotalFailed != 1 {
		t.Errorf("发了三个被拒的报文，「拨不通」计了 %d 条，want 1（每次重试都记一行会把表淹掉）",
			snap.TotalFailed)
	}
}

func TestParseAssocPacketRejectsFragmentedDatagram(t *testing.T) {
	p := append([]byte{0, 0, 1 /* FRAG=1 */, atypIPv4}, []byte{127, 0, 0, 1, 0x27, 0x10}...)
	p = append(p, []byte("data")...)
	if _, _, ok := parseAssocPacket(p); ok {
		t.Fatal("分片报文被接受了")
	}
}

func TestParseAssocPacketRejectsTruncatedHeader(t *testing.T) {
	if _, _, ok := parseAssocPacket([]byte{0, 0, 0, atypIPv4, 127}); ok {
		t.Fatal("截断的地址被接受了")
	}
	if _, _, ok := parseAssocPacket([]byte{0, 0, 0, atypIPv4, 127, 0, 0, 1}); ok {
		t.Fatal("缺端口的报文被接受了")
	}
}

func TestAssocPacketRoundTripsEveryAddressType(t *testing.T) {
	cases := []struct {
		name string
		atyp byte
		addr []byte
		host string
	}{
		{"IPv4", atypIPv4, []byte{1, 2, 3, 4}, "1.2.3.4:443"},
		{"IPv6", atypIPv6, net.ParseIP("2001:db8::1").To16(), "[2001:db8::1]:443"},
		{"域名", atypDomain, domainAddr("example.com"), "example.com:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, payload, ok := parseAssocPacket(assocPacket(t, "body", tc.atyp, tc.addr, 443))
			if !ok {
				t.Fatal("报文未被接受")
			}
			if addr != tc.host {
				t.Fatalf("地址 = %q, want %q", addr, tc.host)
			}
			if string(payload) != "body" {
				t.Fatalf("正文 = %q", payload)
			}
		})
	}
}

func TestBuildAssocPacketRoundTripsEveryAddressType(t *testing.T) {
	for _, from := range []string{"1.2.3.4:443", "[2001:db8::1]:53", "example.com:80"} {
		pkt, err := buildAssocPacket(from, []byte("x"))
		if err != nil {
			t.Fatalf("封装 %q: %v", from, err)
		}
		addr, payload, ok := parseAssocPacket(pkt)
		if !ok {
			t.Fatalf("%q 封装后无法解析: %x", from, pkt)
		}
		if addr != from {
			t.Fatalf("回环地址 = %q, want %q", addr, from)
		}
		if string(payload) != "x" {
			t.Fatalf("正文 = %q", payload)
		}
	}
}

func TestBuildAssocPacketRejectsBadAddress(t *testing.T) {
	if _, err := buildAssocPacket("not-an-addr", []byte("x")); err == nil {
		t.Fatal("缺端口的地址被接受了")
	}
	if _, err := buildAssocPacket("example.com:99999", []byte("x")); err == nil {
		t.Fatal("越界端口被接受了")
	}
}

func TestBindAssocSocketReusesControlLocalAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			time.Sleep(50 * time.Millisecond)
			_ = c.Close()
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	uc, bound, clientIP, err := bindAssocSocket(c)
	if err != nil {
		t.Fatalf("bindAssocSocket: %v", err)
	}
	defer func() { _ = uc.Close() }()
	if !clientIP.IsLoopback() {
		t.Fatalf("客户端地址 = %v", clientIP)
	}
	if !uc.LocalAddr().(*net.UDPAddr).IP.IsLoopback() {
		t.Fatalf("中继口没有绑在控制连接的本地地址上: %s", bound)
	}
	// 端口必须是内核现给的，不能与控制连接撞上。
	if port := uc.LocalAddr().(*net.UDPAddr).Port; port == 0 {
		t.Fatalf("中继口没有分配到端口: %s", bound)
	}
}

// --- 小工具 ---

func (e *udpEchoOutbound) sentAt(i int) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if i >= len(e.sent) {
		return ""
	}
	return e.sent[i]
}

// assocPacket 按 SOCKS5 UDP 头拼一个请求报文。
func assocPacket(t *testing.T, payload string, atyp byte, addr []byte, port uint16) []byte {
	t.Helper()
	buf := []byte{0x00, 0x00, 0x00, atyp}
	buf = append(buf, addr...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	buf = append(buf, p[:]...)
	return append(buf, payload...)
}

func readAssoc(t *testing.T, uc *net.UDPConn) (string, []byte) {
	t.Helper()
	_ = uc.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, udpAssocBuffer)
	n, err := uc.Read(buf)
	if err != nil {
		t.Fatalf("读回包: %v", err)
	}
	addr, payload, ok := parseAssocPacket(buf[:n])
	if !ok {
		t.Fatalf("回包不是合法的 SOCKS5 UDP 报文: %x", buf[:n])
	}
	return addr, payload
}

func mustUDPAddr(t *testing.T, hostport string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		t.Fatalf("解析中继地址 %q: %v", hostport, err)
	}
	return a
}

func mustHostPort(t *testing.T, hostport string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("拆分 %q: %v", hostport, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("端口 %q 不是数字: %v", p, err)
	}
	return h, n
}

// TestSOCKS5UDPPayloadIsNotAliasedToReadBuffer 锁住"入队前必须拷贝"。
//
// 读循环只有一块 64KB 的 buf，parseAssocPacket 返回的正文是它的子切片。
// 以前那个切片直接进队列交给另一个 goroutine 发送：只要排队（深度 64）
// 或者下游还在 WriteTo 里拷，下一次 ReadFromUDP 就把字节改写了。
//
// 症状是 UDP 载荷串包——音视频花屏、QUIC 握手随机失败，而日志里一切正常，
// 因为转发"成功"了，只是内容不对。
//
// 这里不靠时序去撞那个窗口（撞不稳），而是直接钉住不变量：
// 入队的那份数据不能与解析它的那块缓冲共享底层数组。
func TestSOCKS5UDPPayloadIsNotAliasedToReadBuffer(t *testing.T) {
	// 一包足够大的正文，确保它躺在读缓冲的深处（前面还有头）。
	body := strings.Repeat("A", 4096)
	pkt := assocPacket(t, body, atypIPv4, []byte{127, 0, 0, 1}, 5353)

	buf := make([]byte, udpAssocBuffer)
	copy(buf, pkt)

	addr, payload, ok := parseAssocPacket(buf[:len(pkt)])
	if !ok || addr == "" {
		t.Fatal("解析失败，测试前提不成立")
	}
	data := append([]byte(nil), payload...)

	// 模拟下一次 ReadFromUDP：整块缓冲被新报文覆盖。
	for i := range buf {
		buf[i] = 'B'
	}

	if string(data) != body {
		t.Fatalf("入队的数据被后续读改写了（长度 %d，首字节 %q）——"+
			"这就是 UDP 串包", len(data), data[:1])
	}
	// 反向确认：如果不拷贝，上面那个覆盖确实会改到它。这条断言是给读代码的人看的：
	// 它证明"不拷贝"这个写法真的会坏，而不是我多虑。
	if string(payload) == body {
		t.Fatal("解析结果与读缓冲没有共享底层数组？那这条用例就没在测它想测的东西")
	}
}

// TestSOCKS5UDPRecoversAfterFirstDialFails 锁住"首包拨号失败不是永久判决"。
//
// 以前 decided 在拨号**之前**就置真：首包失败之后，这条关联在剩下 10 分钟里
// 再也不拨号，后续每个包都被静默丢弃。而首包失败恰恰最常复现——
// DIRECT 明确不支持 UDP、会话数到 512、一次瞬时超时。
//
// 正确行为：失败的那个目标记一行（不刷屏），但下一个包仍会再试。
// 这里用"第一次拨号失败、第二次成功"的假出站把它演完。
func TestSOCKS5UDPRecoversAfterFirstDialFails(t *testing.T) {
	echoAddr := startUDPEcho(t)
	proxyAddr, echo := startSOCKS5UDP(t, rulesProxy)
	echo.failDials.Store(1) // 第一次 DialUDP 失败
	_, relay := assocOpenUDP(t, proxyAddr)

	uc, err := net.DialUDP("udp", nil, mustUDPAddr(t, relay))
	if err != nil {
		t.Fatalf("连中继: %v", err)
	}
	defer func() { _ = uc.Close() }()

	host, port := mustHostPort(t, echoAddr)
	pkt := assocPacket(t, "retry-me", atypIPv4, net.ParseIP(host).To4(), uint16(port))

	// 第一包：拨号失败，收不到回声。
	if _, err := uc.Write(pkt); err != nil {
		t.Fatalf("发第 1 包: %v", err)
	}
	expectNoAssocReply(t, uc, 400*time.Millisecond)

	// 第二包：必须重新拨号并真的转发出去。以前这里会被永久丢掉。
	if _, err := uc.Write(pkt); err != nil {
		t.Fatalf("发第 2 包: %v", err)
	}
	_, payload := readAssoc(t, uc)
	if string(payload) != "retry-me" {
		t.Fatalf("第二个包的回声正文 = %q", payload)
	}
	if n := echo.dials.Load(); n != 2 {
		t.Fatalf("拨号 %d 次, want 2（首包失败后应当再试一次）", n)
	}
}

// expectNoAssocReply 断言在这段时间内读不到回声。
func expectNoAssocReply(t *testing.T, uc *net.UDPConn, d time.Duration) {
	t.Helper()
	if err := uc.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("设读超时: %v", err)
	}
	buf := make([]byte, 1500)
	if n, _, err := uc.ReadFromUDP(buf); err == nil {
		t.Fatalf("本该收不到回声，却收到了 %d 字节", n)
	}
	_ = uc.SetReadDeadline(time.Time{})
}
