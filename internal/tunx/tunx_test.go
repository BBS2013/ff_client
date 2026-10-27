package tunx

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	tunstack "gvisor.dev/gvisor/pkg/tcpip/stack"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
	"wps_app/internal/rules"
)

// ---------------------------------------------------------------- 假 IP 表

func TestFakeStoreAllocatesAndReverseLookups(t *testing.T) {
	s, err := NewFakeStore("198.18.0.0/15", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.Allocate("WWW.Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Contains(a) {
		t.Errorf("%s 应落在假 IP 段内", a)
	}
	// 大小写不敏感：同一个域名的两次查询必须拿到同一个假 IP，
	// 否则应用侧的连接会反查不到域名而被拒。
	again, err := s.Allocate("www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if again != a {
		t.Fatalf("同域名两次分配不同: %s vs %s", a, again)
	}
	b, err := s.Allocate("other.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if b == a {
		t.Fatalf("不同域名撞在同一个假 IP: %s", a)
	}
	if got, ok := s.Lookup(a); !ok || got != "www.example.com" {
		t.Errorf("反查 = %q,%v，期望 www.example.com,true", got, ok)
	}
	if got, ok := s.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Errorf("段外地址不该反查命中: %q", got)
	}
	if s.Len() != 2 {
		t.Errorf("在册数量 = %d, 期望 2", s.Len())
	}
}

func TestFakeStoreExpiresEntries(t *testing.T) {
	s, err := NewFakeStore("198.18.0.0/15", "", 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Allocate("short.example")
	if _, ok := s.Lookup(a); !ok {
		t.Fatal("刚分配的映射应当可查")
	}
	time.Sleep(20 * time.Millisecond)
	if _, ok := s.Lookup(a); ok {
		t.Fatal("过期后不该还能反查")
	}
	// 过期即回收，重新分配可以拿到新的。
	if _, err := s.Allocate("short.example"); err != nil {
		t.Fatal(err)
	}
	if s.Len() != 1 {
		t.Errorf("回收没做对, Len=%d", s.Len())
	}
}

func TestFakeStoreRejectsBadRange(t *testing.T) {
	if _, err := NewFakeStore("nope", "", time.Minute); err == nil {
		t.Fatal("非法 CIDR 应报错")
	}
	// v6 段不能放进 v4 的位置——族别错了必须在建表时就挡住，
	// 否则分配出来的地址压根没人路由。
	if _, err := NewFakeStore("2001:db8::/64", "", time.Minute); err == nil {
		t.Fatal("v6 段放进了 v4 的位置")
	}
}

// ---------------------------------------------------------------- DNS 应答

type stubDecider struct {
	proxy map[string]bool
	// block 是「判定成 REJECT」的域名集合。它和 proxy 分开写，
	// 是为了让漏掉 REJECT 的用例直接红，而不是被顺手当成 PROXY 蒙过去。
	block map[string]bool
	// every 是「不论域名，一律判成这个策略」。给守卫用例遍历策略用——
	// 新增一个 Policy 时，那批用例必须自动把它跑一遍，而不是靠人想起来。
	every rules.Policy
	mode  config.Mode
}

func (d stubDecider) Decide(_ context.Context, host string) (rules.Policy, string) {
	if d.every != "" {
		return d.every, "GUARD," + string(d.every)
	}
	switch d.mode {
	case config.ModeGlobal:
		return rules.PolicyProxy, "MODE,GLOBAL"
	case config.ModeDirect:
		return rules.PolicyDirect, "MODE,DIRECT"
	}
	if d.block[host] {
		return rules.PolicyReject, "DOMAIN-SUFFIX," + host + ",REJECT"
	}
	if d.proxy[host] {
		return rules.PolicyProxy, "DOMAIN-SUFFIX,example.com,PROXY"
	}
	return rules.PolicyDirect, "FINAL"
}

func newDNSServer(t *testing.T, dec stubDecider, lookup Lookup) *dnsServer {
	t.Helper()
	fake, err := NewFakeStore("198.18.0.0/15", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &dnsServer{decide: dec, lookup: lookup, fake: fake}
}

func parseResponse(t *testing.T, raw []byte) (dnsmessage.Header, []dnsmessage.Question, []dnsmessage.Resource) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil {
		t.Fatalf("解析应答头: %v", err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatalf("解析 question: %v", err)
	}
	rr, err := p.AllAnswers()
	if err != nil {
		t.Fatalf("读答案: %v", err)
	}
	for _, r := range rr {
		if r.Header.Type != dnsmessage.TypeA && r.Header.Type != dnsmessage.TypeAAAA {
			t.Fatalf("不该出现其它类型的记录: %v", r.Header.Type)
		}
	}
	return h, qs, rr
}

func answerIP(t *testing.T, raw []byte) netip.Addr {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AllQuestions(); err != nil {
		t.Fatal(err)
	}
	res, err := p.Answer()
	if err != nil {
		t.Fatalf("没有答案: %v", err)
	}
	a, ok := res.Body.(*dnsmessage.AResource)
	if !ok {
		t.Fatalf("答案不是 A 记录: %T", res.Body)
	}
	return netip.AddrFrom4(a.A)
}

func queryFor(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	raw, err := BuildQuery(name, qtype)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestDNSServerGivesFakeIPForProxy 是 TUN 模式成立的前提：
// 走代理的域名只拿假 IP，且这个假 IP 必须能反查回域名。
func TestDNSServerGivesFakeIPForProxy(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{"a.example.com": true}}
	s := newDNSServer(t, dec, func(context.Context, string) ([]netip.Addr, error) {
		t.Error("判成 PROXY 的域名不该触发解析（这正是免疫 DNS 污染的地方）")
		return nil, nil
	})
	resp, err := s.Serve(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	h, qs, rr := parseResponse(t, resp)
	if !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("应答头不对: %+v", h)
	}
	if len(qs) != 1 || len(rr) != 1 {
		t.Fatalf("question/answer 数量不对: %d/%d", len(qs), len(rr))
	}
	ip := answerIP(t, resp)
	if !ip.Is4() || !strings.HasPrefix(ip.String(), "198.18.") {
		t.Fatalf("没发到假 IP 段: %s", ip)
	}
	if got, ok := s.fake.Lookup(ip); !ok || got != "a.example.com" {
		t.Fatalf("假 IP 反查失败: %q %v", got, ok)
	}
}

// TestDNSServerDirectGetsRealIP 直连域名必须回真 IP——
// 回假 IP 会把本可以直连的流量白白拖进 tun。
func TestDNSServerDirectGetsRealIP(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{}}
	s := newDNSServer(t, dec, func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "b.example.net" {
			t.Errorf("解析目标 = %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	resp, err := s.Serve(context.Background(), queryFor(t, "b.example.net", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, resp); ip.String() != "93.184.216.34" {
		t.Fatalf("真 IP 没回出去: %s", ip)
	}
}

// TestDNSServerAAAAIsNodataForProxy 假 IP 只有 v4。AAAA 回 NODATA，
// 应用才会退回 A 记录；回一个假 v6 反而会让连接直接失败。
func TestDNSServerAAAAIsNodataForProxy(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{"a.example.com": true}}
	s := newDNSServer(t, dec, nil)
	resp, err := s.Serve(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	_, _, rr := parseResponse(t, resp)
	if len(rr) != 0 {
		t.Fatalf("AAAA 不该有答案: %d 条", len(rr))
	}
}

func TestDNSServerGlobalModeMakesEverythingFake(t *testing.T) {
	dec := stubDecider{mode: config.ModeGlobal}
	s := newDNSServer(t, dec, func(context.Context, string) ([]netip.Addr, error) {
		t.Error("全局模式下不该再解析真 IP")
		return nil, nil
	})
	resp, err := s.Serve(context.Background(), queryFor(t, "www.baidu.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, resp); !strings.HasPrefix(ip.String(), "198.18.") {
		t.Fatalf("全局模式没发假 IP: %s", ip)
	}
}

func TestDNSServerServFailOnLookupError(t *testing.T) {
	dec := stubDecider{mode: config.ModeDirect}
	s := newDNSServer(t, dec, func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("上游炸了")
	})
	resp, err := s.Serve(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	h, _, _ := parseResponse(t, resp)
	if h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("解析失败应回 SERVFAIL, 实际 %v", h.RCode)
	}
}

func TestDNSServerRejectsGarbage(t *testing.T) {
	s := newDNSServer(t, stubDecider{}, nil)
	if _, err := s.Serve(context.Background(), []byte{1, 2, 3}); err == nil {
		t.Fatal("残缺报文应报错")
	}
}

// ---------------------------------------------------------------- 路由命令

func TestRoutePlanUpAndDown(t *testing.T) {
	p := RoutePlan{
		Device: "wps-tun", Address: "172.19.0.1/30", DNS: "172.19.0.2",
		FakeIPRange: "198.18.0.0/15", MTU: 1500, HijackDNS: true, UID: 1000,
		Upstreams: []string{"223.5.5.5", "119.29.29.29"},
	}
	up, down, err := p.Plan()
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, c := range up {
		joined += c.String() + "\n"
	}
	for _, want := range []string{
		"ip addr add 172.19.0.1/30 dev wps-tun",
		"ip link set dev wps-tun up",
		"ip route add 198.18.0.0/15 dev wps-tun",
		"iptables -t nat -N wps_app_dns",
		// 上游必须被放行，否则我们自己的解析被劫持回来，形成环路。
		"iptables -t nat -A wps_app_dns -d 223.5.5.5/32 -p udp --dport 53 -j RETURN",
		"iptables -t nat -A wps_app_dns -d 119.29.29.29/32 -p tcp --dport 53 -j RETURN",
		// 回环目的地址必须放过：DNAT 之后 127/8 的源地址在 tun 上不合法，包会被内核丢掉。
		"! -d 127.0.0.0/8 -p udp --dport 53 -j DNAT --to-destination 172.19.0.2:53",
		// 回程 SNAT：没有它，源地址是 127.0.0.1 的查询（systemd-resolved stub）
		// 会拿到一个被内核当 martian 丢掉的应答，表现是 curl 说无法解析。
		"iptables -t nat -A POSTROUTING -o wps-tun -p udp --dport 53 -j SNAT --to-source 172.19.0.1",
		"iptables -t nat -A POSTROUTING -o wps-tun -p tcp --dport 53 -j SNAT --to-source 172.19.0.1",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("up 里缺 %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, "route add default") {
		t.Errorf("非 strict_route 不该动默认路由:\n%s", joined)
	}
	// 劫持规则不许再按 uid 豁免。这条是踩过才写下的：面板以桌面用户身份跑时，
	// `-m owner ! --uid-owner 1000` 放过的正是我们要服务的那个人，
	// 结果是他的应用拿回污染地址、TUN 对他本人形同关闭，而且一点报错都没有。
	if strings.Contains(joined, "--uid-owner") {
		t.Errorf("劫持规则里出现了 uid 豁免:\n%s", joined)
	}
	// 卸载必须把劫持摘掉，而且顺序上先恢复 DNS 再拆网卡：
	// 反过来做会留一个「规则还在、地址已没」的解析黑洞。
	downText := ""
	for _, c := range down {
		downText += c.String() + "\n"
	}
	if !strings.Contains(downText, "-D OUTPUT -p udp --dport 53 -j wps_app_dns") ||
		!strings.Contains(downText, "-X wps_app_dns") ||
		!strings.Contains(downText, "-D POSTROUTING -o wps-tun -p udp --dport 53 -j SNAT") {
		t.Errorf("down 没摘干净劫持链:\n%s", downText)
	}
	if strings.Index(downText, "iptables") > strings.Index(downText, "addr del") {
		t.Errorf("应先摘 iptables 再拆地址:\n%s", downText)
	}
	for _, c := range down {
		if !c.Optional {
			t.Errorf("卸载路径必须全部容忍失败: %+v", c)
		}
	}
}

// TestUpstreamCIDRForms 盯住 IPv6 上游：照抄 /32 会把它变成一段很大的网段，
// 放行范围悄悄扩大，我们自己那条 v6 解析又被劫持回去。
func TestUpstreamCIDRForms(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"223.5.5.5", "223.5.5.5/32"},
		{" 223.5.5.5 ", "223.5.5.5/32"},
		{"2400:3200::1", "2400:3200::1/128"},
		{"not-an-ip", "not-an-ip/32"}, // 非 IP 交给上游校验去拒，这里不猜
	} {
		if got := upstreamCIDR(c.in); got != c.want {
			t.Errorf("upstreamCIDR(%q) = %s, 期望 %s", c.in, got, c.want)
		}
	}
	// 开了劫持却没有可放行的上游 = 自己吃自己，必须拒绝出计划。
	p := RoutePlan{Device: "wps-tun", Address: "172.19.0.1/30", DNS: "172.19.0.2", HijackDNS: true}
	if _, _, err := p.Plan(); err == nil {
		t.Fatal("没有上游时不该生成劫持计划")
	}
}

func TestRoutePlanStrictRoute(t *testing.T) {
	p := RoutePlan{
		Device: "wps-tun", Address: "172.19.0.1/30", FakeIPRange: "198.18.0.0/15",
		StrictRoute: true, Gateway: "10.0.0.1", Interface: "eth0",
		Exclude: []string{"10.180.63.2/32", "223.5.5.5/32"},
	}
	up, down, err := p.Plan()
	if err != nil {
		t.Fatal(err)
	}
	text := ""
	for _, c := range up {
		text += c.String() + "\n"
	}
	if !strings.Contains(text, "ip route add default dev wps-tun") {
		t.Errorf("strict_route 没接管默认路由:\n%s", text)
	}
	for _, want := range []string{"ip route add 10.180.63.2/32 via 10.0.0.1 dev eth0", "ip route add 223.5.5.5/32 via 10.0.0.1 dev eth0"} {
		if !strings.Contains(text, want) {
			t.Errorf("防环路路由缺失: %q\n%s", want, text)
		}
	}
	downText := ""
	for _, c := range down {
		downText += c.String() + "\n"
	}
	if !strings.Contains(downText, "ip route del 223.5.5.5/32") || !strings.Contains(downText, "route del default dev wps-tun") {
		t.Errorf("down 没撤销路由:\n%s", downText)
	}

	// 没有已知网关时坚决不进入 strict_route：把默认路由指向一个不存在的出口，
	// 等于把这台机器的网络关掉。
	if _, _, err := (RoutePlan{Device: "t", Address: "10.0.0.1/24", StrictRoute: true}).Plan(); err == nil {
		t.Error("缺网关时应报错")
	}
}

// TestApplyTreatsFileExistsAsSuccess 盯住那次把 TUN 永久卡住的故障：
// 排除路由已经在了，ip route add 回 EEXIST，却被当成致命错误 → 开启路径不可重入。
func TestApplyTreatsFileExistsAsSuccess(t *testing.T) {
	r := &recorderRunner{fail: map[string]error{
		"ip route add 223.5.5.5/32 via 10.180.63.254 dev wlp3s0f0": errors.New("RTNETLINK answers: File exists"),
	}}
	err := Apply(context.Background(), r, []Cmd{
		{Bin: "ip", Args: []string{"route", "add", "223.5.5.5/32", "via", "10.180.63.254", "dev", "wlp3s0f0"}, Desc: "防环路", TolerateExists: true},
		{Bin: "ip", Args: []string{"route", "add", "default", "dev", "wps-tun"}, Desc: "默认路由"},
	})
	if err != nil {
		t.Fatalf("EEXIST 应视为成功: %v", err)
	}
	if len(r.ran) != 2 {
		t.Fatalf("后续步骤应继续执行: %v", r.ran)
	}

	// 但真正的失败不能被吞掉：网关不存在时必须中断，
	// 否则会留下「默认路由已交给 tun、防环路却没装上」的自环状态。
	r2 := &recorderRunner{fail: map[string]error{
		"ip route add 223.5.5.5/32 via 10.180.63.254 dev wlp3s0f0": errors.New("RTNETLINK answers: Network is unreachable"),
	}}
	if err := Apply(context.Background(), r2, []Cmd{
		{Bin: "ip", Args: []string{"route", "add", "223.5.5.5/32", "via", "10.180.63.254", "dev", "wlp3s0f0"}, Desc: "防环路", TolerateExists: true},
		{Bin: "ip", Args: []string{"route", "add", "default", "dev", "wps-tun"}, Desc: "默认路由"},
	}); err == nil {
		t.Fatal("非 EEXIST 的失败应中断")
	} else if len(r2.ran) != 1 {
		t.Fatalf("中断后不该再加默认路由: %v", r2.ran)
	}
}

func TestParseDefaultRoute(t *testing.T) {
	gw, iface, ok := ParseDefaultRoute("default via 10.180.63.254 dev wlp3s0f0 proto dhcp metric 600\n")
	if !ok || gw != "10.180.63.254" || iface != "wlp3s0f0" {
		t.Fatalf("解析失败: %q %q %v", gw, iface, ok)
	}
	if _, _, ok := ParseDefaultRoute("10.0.0.0/24 dev eth0\n"); ok {
		t.Fatal("没有默认路由时不该报成功")
	}
}

// recorderRunner 记录执行过的命令，失败项可按名字注入。
type recorderRunner struct {
	mu   sync.Mutex
	ran  []string
	fail map[string]error
}

func (r *recorderRunner) Run(_ context.Context, c Cmd) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ran = append(r.ran, c.String())
	if err, ok := r.fail[c.String()]; ok {
		// 真实执行器会把命令的 stderr 原样带回来，Apply 判 EEXIST 靠的就是这段文本，
		// 所以替身也得还回同样的文本，不然测的是假人的行为。
		return err.Error(), err
	}
	if c.Bin == "ip" && strings.Join(c.Args, " ") == "-o route show default" {
		return "default via 10.180.63.254 dev wlp3s0f0 proto dhcp metric 600", nil
	}
	return "", nil
}

// snapshot 给并发用例读记录用：helper 是在另一个 goroutine 里跑命令的，
// 直接摸 r.ran 会被 -race 判竞争。
func (r *recorderRunner) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ran...)
}

func TestApplyStopsOnHardFailure(t *testing.T) {
	r := &recorderRunner{fail: map[string]error{"ip link set dev wps-tun up": errors.New("nope")}}
	err := Apply(context.Background(), r, []Cmd{
		{Bin: "ip", Args: []string{"addr", "add", "172.19.0.1/30", "dev", "wps-tun"}, Desc: "加地址"},
		{Bin: "ip", Args: []string{"link", "set", "dev", "wps-tun", "up"}, Desc: "启用网卡"},
		{Bin: "ip", Args: []string{"route", "add", "198.18.0.0/15", "dev", "wps-tun"}, Desc: "路由"},
	})
	if err == nil || !strings.Contains(err.Error(), "启用网卡") {
		t.Fatalf("硬失败应中断并带上下文: %v", err)
	}
	if len(r.ran) != 2 {
		t.Fatalf("失败后不该继续执行: %v", r.ran)
	}
	// Optional 的失败不阻断。
	r2 := &recorderRunner{fail: map[string]error{"ip route del nope": errors.New("不存在")}}
	if err := Apply(context.Background(), r2, []Cmd{
		{Bin: "ip", Args: []string{"route", "del", "nope"}, Desc: "撤销", Optional: true},
		{Bin: "ip", Args: []string{"link", "set", "dev", "x", "down"}, Desc: "关网卡"},
	}); err != nil {
		t.Fatalf("Optional 失败不该中断: %v", err)
	}
}

// ---------------------------------------------------------------- 转发

// pipeConn 实现 adapter.TCPConn：一对 net.Pipe 加上协议栈那份端点 ID。
type pipeConn struct {
	net.Conn
	id tunstack.TransportEndpointID
}

func (c *pipeConn) ID() tunstack.TransportEndpointID { return c.id }

func idFor(dst string, dstPort uint16, src string, srcPort uint16) tunstack.TransportEndpointID {
	d := tcpip.AddrFromSlice(netip.MustParseAddr(dst).AsSlice())
	r := tcpip.AddrFromSlice(netip.MustParseAddr(src).AsSlice())
	return tunstack.TransportEndpointID{
		LocalAddress:  d,
		LocalPort:     dstPort,
		RemoteAddress: r,
		RemotePort:    srcPort,
	}
}

func startEcho(t *testing.T) (int, chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	go func() {
		defer ln.Close()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				got <- string(buf[:n])
				_, _ = c.Write(buf[:n])
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return p, got
}

func newTUNForRelay(t *testing.T, m config.Mode) (*TUN, *stubDialRecorder) {
	t.Helper()
	rec := &stubDialRecorder{}
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(2*time.Second), rec), 2*time.Second)
	rt.SetMode(m)
	fake, err := NewFakeStore("198.18.0.0/15", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &TUN{
		conf: config.TUNConfig{Enable: true, Device: "wps-tun", FakeIPRange: "198.18.0.0/15"},
		rt:   rt,
		fake: fake,
	}, rec
}

func mustEngine(t *testing.T) *rules.Engine {
	t.Helper()
	e, err := rules.Load(writeRules(t), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func writeRules(t *testing.T) string {
	t.Helper()
	p := t.TempDir() + "/rules.txt"
	body := "DOMAIN-SUFFIX,example.com,PROXY\nFINAL,DIRECT\n"
	if err := writeFile(p, body); err != nil {
		t.Fatal(err)
	}
	return p
}

// stubDialRecorder 是「代理出站」的替身：把拨号目标记下来并回一个 pipe。
type stubDialRecorder struct {
	last string
}

func (d *stubDialRecorder) Name() string { return "PROXY" }

func (d *stubDialRecorder) DialContext(_ context.Context, addr string) (net.Conn, error) {
	d.last = addr
	a, b := net.Pipe()
	// 回声一次就关，模拟真实远端在收到 FIN 后收尾；
	// 不关的话 relay 的另一半会永远挂在 Read 上，那是在测替身的 bug 而不是转发的行为。
	go func() {
		defer b.Close()
		buf := make([]byte, 512)
		n, err := b.Read(buf)
		if err != nil {
			return
		}
		_, _ = b.Write(buf[:n])
	}()
	return a, nil
}

func (d *stubDialRecorder) Close() error { return nil }

// TestRelayTCPViaFakeIP 走通 TUN 的主路径：
// 应用连假 IP → 反查域名 → 按域名决策 → 把连接交给代理出站，数据双向搬通。
func TestRelayTCPViaFakeIP(t *testing.T) {
	tr, proxy := newTUNForRelay(t, config.ModeRule)
	fake, err := tr.fake.Allocate("a.example.com")
	if err != nil {
		t.Fatal(err)
	}

	app, peer := net.Pipe()
	conn := &pipeConn{Conn: app, id: idFor(fake.String(), 443, "10.180.56.140", 51000)}
	done := make(chan struct{})
	go func() { tr.relayTCP(conn); close(done) }()

	if _, err := peer.Write([]byte("hello tun")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("回包失败: %v", err)
	}
	if string(buf[:n]) != "hello tun" {
		t.Fatalf("搬错内容: %q", buf[:n])
	}
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relayTCP 没随连接关闭而收尾")
	}
	// 交给隧道的是「域名 + 原端口」，让服务端做解析。
	if proxy.last != "a.example.com:443" {
		t.Fatalf("代理拨号目标 = %q, 期望 a.example.com:443", proxy.last)
	}
	if tr.active.Load() != 0 {
		t.Errorf("结束后计数没归零: %d", tr.active.Load())
	}
}

// TestRelayRefusesUnknownFakeIP 是关键的安全边界：
// 假 IP 段内但反查不到域名的连接必须就地拒绝，
// 否则这个包会被拨出去又被打回同一块 tun，形成环路。
func TestRelayRefusesUnknownFakeIP(t *testing.T) {
	tr, proxy := newTUNForRelay(t, config.ModeGlobal)
	app, peer := net.Pipe()
	conn := &pipeConn{Conn: app, id: idFor("198.18.9.9", 443, "10.0.0.9", 40000)}
	tr.relayTCP(conn) // 不应拨号，应立刻返回并关闭
	_ = peer.Close()
	if proxy.last != "" {
		t.Fatalf("未知假 IP 不该被拨出去: %q", proxy.last)
	}
}

// TestRelayDirectModeBypassesProxy 确认直连模式下 tun 里的连接也不会误入隧道。
func TestRelayDirectModeBypassesProxy(t *testing.T) {
	port, got := startEcho(t)
	tr, proxy := newTUNForRelay(t, config.ModeDirect)
	app, peer := net.Pipe()
	conn := &pipeConn{Conn: app, id: idFor("127.0.0.1", uint16(port), "127.0.0.1", 44000)}
	done := make(chan struct{})
	go func() { tr.relayTCP(conn); close(done) }()
	if _, err := peer.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("内容不对: %q", buf[:n])
	}
	_ = peer.Close()
	<-done
	if proxy.last != "" {
		t.Errorf("直连模式却拨了代理: %q", proxy.last)
	}
	if received := <-got; received != "ping" {
		t.Errorf("回声服务端收到 %q", received)
	}
}

// ---------------------------------------------------------------- 生命周期

func TestNewRejectsDisabledOrBadConfig(t *testing.T) {
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(time.Second), nil), time.Second)
	if _, err := New(Options{Conf: config.TUNConfig{Enable: false}, Router: rt}); err == nil {
		t.Fatal("enable=false 时应拒绝")
	}
	if _, err := New(Options{Conf: config.TUNConfig{Enable: true, FakeIPRange: "198.18.0.0/15"}, Router: nil}); err == nil {
		t.Fatal("缺 router 时应拒绝")
	}
	if _, err := New(Options{Conf: config.TUNConfig{Enable: true, FakeIPRange: "not-a-cidr"}, Router: rt}); err == nil {
		t.Fatal("假 IP 段非法时应拒绝")
	}
}

// TestStartFailureKeepsErrorForUI 是界面能不能自证清白的一条：
// 起不来时句柄必须还在，Status 里带得上真实错误，否则用户只看到一个「没开」。
func TestStartFailureKeepsErrorForUI(t *testing.T) {
	yes := true
	conf := config.TUNConfig{
		Enable: true, Device: "wps-tun", Address: "172.19.0.1/30", DNS: "172.19.0.2",
		FakeIPRange: "198.18.0.0/15", MTU: 1500, HijackDNS: &yes,
	}
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(time.Second), nil), time.Second)
	uid := 1000
	tr, err := New(Options{Conf: conf, Router: rt, Runner: &recorderRunner{}, UID: &uid})
	if err != nil {
		t.Fatal(err)
	}
	// 普通用户跑这条会死在打开 tun 设备那一步，正好验证失败路径。
	err = tr.Start(context.Background())
	if err == nil {
		_ = tr.Stop(context.Background())
		t.Skip("本机有建 tun 的权限，跳过失败路径")
	}
	st := tr.Status()
	if st.Running {
		t.Error("Start 失败后不该是 running")
	}
	if st.LastError == "" {
		t.Errorf("状态里没带上失败原因: %+v", st)
	}
	if !st.Enabled || st.Device != "wps-tun" || !st.HijackDNS {
		t.Errorf("状态里的配置项丢了: %+v", st)
	}
}

func TestSecondHost(t *testing.T) {
	if got := SecondHost("172.19.0.1/30"); got != "172.19.0.2" {
		t.Errorf("172.19.0.1/30 的下一个可用地址 = %q", got)
	}
	if got := SecondHost("10.0.0.1/32"); got != "10.0.0.1" {
		t.Errorf("单地址网段应原样返回: %q", got)
	}
	if got := SecondHost("garbage"); got != "" {
		t.Errorf("非法输入应返回空: %q", got)
	}
}

func TestCIDROf(t *testing.T) {
	if CIDROf("8.8.8.8") != "8.8.8.8/32" {
		t.Errorf("v4 应成 /32: %q", CIDROf("8.8.8.8"))
	}
	if CIDROf("2001:db8::1") != "2001:db8::1/128" {
		t.Error("v6 应成 /128")
	}
	if CIDROf("nope") != "" {
		t.Error("非法 IP 应返回空")
	}
}

func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
