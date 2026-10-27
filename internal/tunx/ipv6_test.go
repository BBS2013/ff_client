package tunx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// 这一组覆盖 IPv6 假 IP。整件事的成败只取决于一条性质：
// **DNS 绝不能发一个到不了的 v6 地址出去。**
// 发出去 = 应用拿着它一路连到超时；发 NODATA = 应用退回 A 记录并正常工作。
// 所以下面每条测试都在盯这个分界。

func newDualDNSServer(t *testing.T, dec stubDecider, allowV6 bool) *dnsServer {
	t.Helper()
	fake, err := NewFakeStore("198.18.0.0/15", "fc00::/18", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &dnsServer{decide: dec, lookup: nil, fake: fake, allowV6: allowV6}
}

func answerV6(t *testing.T, raw []byte) netip.Addr {
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
		t.Fatalf("没有 AAAA 答案: %v", err)
	}
	r, ok := res.Body.(*dnsmessage.AAAAResource)
	if !ok {
		t.Fatalf("答案不是 AAAA 记录: %T", res.Body)
	}
	return netip.AddrFrom16(r.AAAA)
}

// ------------------------------------------------------------------ 假 IP 表

// TestFakeStoreGivesEachDomainBothFamilies 是 v6 假 IP 的地基：
// 同一个域名要能同时拿到一个 A 假 IP 与一个 AAAA 假 IP，且两个都能反查回来。
//
// 只按域名做键的话，AAAA 会把先前 A 用的地址覆盖掉，
// 于是已经建好的 v4 连接会在下一次反查时指向同一个域名——
// 症状是「偶发地连到别的 host」，几乎无从归因。
func TestFakeStoreGivesEachDomainBothFamilies(t *testing.T) {
	s, err := NewFakeStore("198.18.0.0/15", "fc00::/18", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v4, err := s.Allocate("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	v6, err := s.Allocate6("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !v4.Is4() || !v6.Is6() {
		t.Fatalf("族别错了: v4=%s v6=%s", v4, v6)
	}
	if v4.String() == v6.String() {
		t.Fatalf("v4 与 v6 拿到了同一个地址: %s", v4)
	}
	for _, a := range []netip.Addr{v4, v6} {
		if got, ok := s.Lookup(a); !ok || got != "a.example.com" {
			t.Errorf("%s 反查 = %q %v", a, got, ok)
		}
	}
	if s.Len() != 2 {
		t.Errorf("在册数量 = %d, want 2", s.Len())
	}
}

// TestFakeStoreIsIdempotentPerFamily 重复分配要拿回同一个地址并续期，
// 否则应用每次 DNS 查询都会换一个假 IP，已建立的连接全部作废。
func TestFakeStoreIsIdempotentPerFamily(t *testing.T) {
	s, err := NewFakeStore("198.18.0.0/15", "fc00::/18", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := s.Allocate6("a.example.com")
	// 大小写不同也该命中同一个映射。
	again, _ := s.Allocate6("A.Example.COM")
	if first != again {
		t.Fatalf("同一域名拿到了两个 v6 假 IP: %s / %s", first, again)
	}
	if s.Len() != 1 {
		t.Errorf("在册数量 = %d, want 1", s.Len())
	}
}

// TestFakeStoreV6AddressesStayInsideTheirPrefix 挡住一个很容易写错的实现：
// v6 段名义上有 2^64 个地址，递增时一不留神就越出段外，
// 而越出去的地址照样能被反查——于是应用被发到一个我们根本没路由的地址上。
func TestFakeStoreV6AddressesStayInsideTheirPrefix(t *testing.T) {
	prefix := netip.MustParsePrefix("fc00::/18")
	s, err := NewFakeStore("198.18.0.0/15", "fc00::/18", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[netip.Addr]bool{}
	for i := 0; i < 500; i++ {
		a, err := s.Allocate6(fmt.Sprintf("host%d.example.com", i))
		if err != nil {
			t.Fatal(err)
		}
		if !prefix.Contains(a) {
			t.Fatalf("第 %d 个地址 %s 越出了 %s", i, a, prefix)
		}
		if a.Is4In6() || a.Is4() {
			t.Fatalf("第 %d 个地址 %s 不是 v6", i, a)
		}
		if seen[a] {
			t.Fatalf("第 %d 个地址 %s 与之前重复", i, a)
		}
		seen[a] = true
	}
}

// TestFakeStoreContainsIsPerFamily Contains 是「拒绝环路」那道闸门：
// 段内的地址却反查不到域名时必须拒绝，否则包会被打回 tun。
// 所以它必须对两个族都认，且不误伤另一族的段。
func TestFakeStoreContainsIsPerFamily(t *testing.T) {
	s, err := NewFakeStore("198.18.0.0/15", "fc00::/18", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Contains(netip.MustParseAddr("198.19.5.5")) || !s.Contains(netip.MustParseAddr("fc00::99")) {
		t.Error("两个段内的地址都该被认出来")
	}
	// 真地址不能被当成假 IP——否则一条正常的直连 v6 连接会被无理由拒掉。
	if s.Contains(netip.MustParseAddr("2400:3200::1")) || s.Contains(netip.MustParseAddr("93.184.216.34")) {
		t.Error("真地址被误判成假 IP 了")
	}
	// v6 地址不能被 v4 段认走。
	if netip.MustParsePrefix("198.18.0.0/15").Contains(netip.MustParseAddr("fc00::1")) {
		t.Error("v4 段认了 v6 地址")
	}
}

// TestFakeStoreWithoutV6RangeHasNoV6 留空就不该有 v6 段，
// HasV6 是 DNS 那边的开关依据。
func TestFakeStoreWithoutV6RangeHasNoV6(t *testing.T) {
	s, err := NewFakeStore("198.18.0.0/15", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if s.HasV6() {
		t.Error("没配 v6 段却报告有")
	}
	if _, err := s.Allocate6("a.example.com"); err == nil {
		t.Error("没有 v6 段却分配成功了")
	}
	// 没配 v6 段时也不能把任意 v6 地址当成假 IP。
	if s.Contains(netip.MustParseAddr("fc00::1")) {
		t.Error("没配 v6 段却认得 v6 地址")
	}
}

func TestFakeStoreRejectsSwappedFamilies(t *testing.T) {
	if _, err := NewFakeStore("fc00::/18", "", time.Minute); err == nil {
		t.Error("v6 段放进了 v4 的位置")
	}
	if _, err := NewFakeStore("198.18.0.0/15", "10.0.0.0/8", time.Minute); err == nil {
		t.Error("v4 段放进了 v6 的位置")
	}
}

// ------------------------------------------------------------------ DNS 应答

// TestDNSServerGivesFakeV6ForProxy 是这个功能存在的理由：
// v6-only 的应用只查 AAAA，而 AAAA 拿不到可用地址就完全没法用。
func TestDNSServerGivesFakeV6ForProxy(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{"a.example.com": true}}
	s := newDualDNSServer(t, dec, true)
	resp, err := s.Serve(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	h, _, rr := parseResponse(t, resp)
	if h.RCode != dnsmessage.RCodeSuccess || len(rr) != 1 {
		t.Fatalf("应答不对: rcode=%v 条数=%d", h.RCode, len(rr))
	}
	ip := answerV6(t, resp)
	if !netip.MustParsePrefix("fc00::/18").Contains(ip) {
		t.Fatalf("没发到 v6 假 IP 段: %s", ip)
	}
	if got, ok := s.fake.Lookup(ip); !ok || got != "a.example.com" {
		t.Fatalf("v6 假 IP 反查失败: %q %v", got, ok)
	}
}

// TestDNSServerAAAAFallsBackToNodataWhenRouteMissing 是本组最要紧的一条。
//
// v6 段配了、假 IP 也分得出来，但 `ip -6 route` 没装上（多半是内核缺
// ip6table_nat）。此时发假 v6 就是把应用推向一个到不了的地址：
// 它不会退回 A 记录，只会一直重试到超时——比回 NODATA 难查得多。
// allowV6 就是那组路由是否真的就位的标记。
func TestDNSServerAAAAFallsBackToNodataWhenRouteMissing(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{"a.example.com": true}}
	s := newDualDNSServer(t, dec, false)
	if !s.fake.HasV6() {
		t.Fatal("前提错了：v6 段应该是配好的")
	}
	resp, err := s.Serve(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	_, _, rr := parseResponse(t, resp)
	if len(rr) != 0 {
		t.Fatalf("路由没装上却发了 %d 条 AAAA 答案", len(rr))
	}
	// 同一时刻 A 记录照常发假 v4，v4 不该被 v6 的失败牵连。
	aresp, err := s.Serve(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, aresp); !strings.HasPrefix(ip.String(), "198.18.") {
		t.Fatalf("v4 假 IP 也被影响了: %s", ip)
	}
}

// TestDNSServerDirectStillGetsRealV6 DIRECT 的域名必须拿真 v6：
// 回假 v6 会把本可以直连的流量白白拖进 tun 绕一圈。
func TestDNSServerDirectStillGetsRealV6(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{}}
	fake, err := NewFakeStore("198.18.0.0/15", "fc00::/18", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := &dnsServer{
		decide:  dec,
		allowV6: true,
		fake:    fake,
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("2400:3200::1"),
				netip.MustParseAddr("93.184.216.34"),
			}, nil
		},
	}
	resp, err := s.Serve(context.Background(), queryFor(t, "b.example.net", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerV6(t, resp); ip.String() != "2400:3200::1" {
		t.Fatalf("直连域名没拿到真 v6: %s", ip)
	}
}

// TestDNSServerV6AndV4RecordsForSameDomain 同一域名两次查询拿到的地址必须
// 各自都能反查回来——否则 v4 与 v6 连接里必有一个拨错 host。
func TestDNSServerV6AndV4RecordsForSameDomain(t *testing.T) {
	dec := stubDecider{proxy: map[string]bool{"a.example.com": true}}
	s := newDualDNSServer(t, dec, true)
	v4resp, err := s.Serve(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	v6resp, err := s.Serve(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	a4, a6 := answerIP(t, v4resp), answerV6(t, v6resp)
	if a4 == a6 {
		t.Fatalf("两个族拿到了同一个地址: %s", a4)
	}
	for _, a := range []netip.Addr{a4, a6} {
		if got, ok := s.fake.Lookup(a); !ok || got != "a.example.com" {
			t.Errorf("%s 反查 = %q %v", a, got, ok)
		}
	}
}

// ------------------------------------------------------------------ 路由计划

func v6Plan() RoutePlan {
	return RoutePlan{
		Device:       "wps-tun",
		Address:      "172.19.0.1/30",
		DNS:          "172.19.0.2",
		FakeIPRange:  "198.18.0.0/15",
		Address6:     "fd00:1::1/64",
		DNS6:         "fd00:1::2",
		FakeIPRange6: "fc00::/18",
		MTU:          1500,
		HijackDNS:    true,
		Upstreams:    []string{"223.5.5.5", "2400:3200::1"},
	}
}

// TestPlanV6EmitsOnlyV6Commands v6 那组必须自成一体：
// 混进 v4 的列表里，一条 ip6tables 失败就会把整个 TUN 拖下水。
func TestPlanV6EmitsOnlyV6Commands(t *testing.T) {
	up, _, err := v6Plan().PlanV6()
	if err != nil {
		t.Fatal(err)
	}
	if len(up) == 0 {
		t.Fatal("v6 组是空的")
	}
	var sawAddr, sawRoute, sawHijack bool
	for _, c := range up {
		joined := strings.Join(c.Args, " ")
		if c.Bin == "ip" {
			if len(c.Args) < 1 || c.Args[0] != "-6" {
				t.Errorf("非 -6 的 ip 命令混进了 v6 组: %s", c)
			}
			if strings.Contains(joined, "addr") {
				sawAddr = true
			}
			if strings.Contains(joined, "route") && strings.Contains(joined, "fc00::/18") {
				sawRoute = true
			}
		}
		if c.Bin == "iptables" {
			t.Errorf("v4 的 iptables 混进了 v6 组: %s", c)
		}
		if c.Bin == "ip6tables" && strings.Contains(joined, "DNAT") {
			sawHijack = true
		}
	}
	if !sawAddr || !sawRoute || !sawHijack {
		t.Errorf("v6 组缺东西: addr=%v route=%v hijack=%v", sawAddr, sawRoute, sawHijack)
	}
}

// TestPlanV6LetsLoopbackStubThrough 盯的是 v4 那条坑在 v6 上的同一份拷贝：
// systemd-resolved 的 v6 stub 就在 ::1，DNAT 只改目的地址、源仍是 ::1，
// 这个源地址在 tun 上不合法，内核按 martian 丢掉——表现是 dig @tun.dns 正常、
// resolvectl 正常，唯独 curl 报 Could not resolve host。
// 忘了 `! -d ::1/128` 就是把这个故障原样搬到 IPv6 上。
func TestPlanV6LetsLoopbackStubThrough(t *testing.T) {
	up, _, err := v6Plan().PlanV6()
	if err != nil {
		t.Fatal(err)
	}
	var sawUDP, sawTCP bool
	for _, c := range up {
		if c.Bin != "ip6tables" || !strings.Contains(strings.Join(c.Args, " "), "DNAT") {
			continue
		}
		if !strings.Contains(strings.Join(c.Args, " "), "! -d ::1/128") {
			t.Errorf("v6 劫持没有放过回环 stub: %s", c)
		}
		if strings.Contains(strings.Join(c.Args, " "), "-p udp") {
			sawUDP = true
		}
		if strings.Contains(strings.Join(c.Args, " "), "-p tcp") {
			sawTCP = true
		}
	}
	if !sawUDP || !sawTCP {
		t.Fatalf("v6 DNAT 只生成了一条: udp=%v tcp=%v", sawUDP, sawTCP)
	}
}

// TestPlanV6SkipsV4Upstreams ip6tables 里写一个 v4 网段会被内核直接拒绝，
// 那会让整条规则加不上，表现为「DNS 劫持莫名其妙不工作」。
func TestPlanV6SkipsV4Upstreams(t *testing.T) {
	up, _, err := v6Plan().PlanV6()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range up {
		joined := strings.Join(c.Args, " ")
		if c.Bin == "ip6tables" && strings.Contains(joined, "223.5.5.5") {
			t.Errorf("v4 上游被写进了 ip6tables: %s", c)
		}
	}
	// 反向：v4 那组同样不能带 v6 上游。
	plan := v6Plan()
	v4up, _, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v4up {
		joined := strings.Join(c.Args, " ")
		if c.Bin == "iptables" && strings.Contains(joined, "2400:3200::1") {
			t.Errorf("v6 上游被写进了 iptables: %s", c)
		}
	}
}

// TestPlanV6DownIsInverseOfUp 关闭路径必须能把开启路径留下的每一样都撤掉。
func TestPlanV6DownIsInverseOfUp(t *testing.T) {
	plan := v6Plan()
	up, down, err := plan.PlanV6()
	if err != nil {
		t.Fatal(err)
	}
	if len(down) == 0 {
		t.Fatal("v6 的 down 是空的")
	}
	// 每条开启命令都要有一条与之配对的撤销：地址、路由各一条。
	var sawAddrDel, sawRouteDel bool
	for _, c := range down {
		joined := strings.Join(c.Args, " ")
		if strings.HasSuffix(joined, "addr del fd00:1::1/64 dev wps-tun") {
			sawAddrDel = true
		}
		if strings.HasSuffix(joined, "route del fc00::/18 dev wps-tun") {
			sawRouteDel = true
		}
	}
	if !sawAddrDel || !sawRouteDel {
		t.Errorf("down 缺东西: addr=%v route=%v", sawAddrDel, sawRouteDel)
	}
	// down 全部是可选的：v6 本来就没装上时，删它必然失败，那是预期内的。
	for _, c := range down {
		if !c.Optional {
			t.Errorf("down 里的 %s 不是 Optional，v6 没启用时会报错", c)
		}
	}
	_ = up
}

func hasCmd(cmds []Cmd, bin, argsJoined string) bool {
	for _, c := range cmds {
		if c.Bin == bin && strings.Join(c.Args, " ") == argsJoined {
			return true
		}
	}
	return false
}

// TestPlanV6EmptyWhenUnconfigured 没配 address6 或 fake_ip_range6 时整组不生成命令。
func TestPlanV6EmptyWhenUnconfigured(t *testing.T) {
	base := v6Plan()
	for _, mutate := range []func(*RoutePlan){
		func(p *RoutePlan) { p.Address6 = "" },
		func(p *RoutePlan) { p.FakeIPRange6 = "" },
		func(p *RoutePlan) { p.Device = "" },
	} {
		p := base
		mutate(&p)
		up, down, err := p.PlanV6()
		if err != nil {
			t.Fatal(err)
		}
		if len(up) != 0 || len(down) != 0 {
			t.Errorf("未配置却生成了 %d/%d 条命令", len(up), len(down))
		}
	}
}

// TestPlanV6RefusesWithoutUpstreams 没有可放行的上游就不能劫持：
// 我们自己的解析会被这条劫持抓回来，变成「问假 IP 表要一个假 IP」。
func TestPlanV6RefusesWithoutUpstreams(t *testing.T) {
	p := v6Plan()
	p.Upstreams = nil
	if _, _, err := p.PlanV6(); err == nil {
		t.Fatal("没有上游却允许劫持 v6 DNS")
	}
}

// ------------------------------------------------------------------ 失败回滚

// recordingRunner 记下执行过的命令，并对匹配 failOn 的命令报错。
type recordingRunner struct {
	ran    []Cmd
	failOn string
}

func (r *recordingRunner) Run(_ context.Context, c Cmd) (string, error) {
	r.ran = append(r.ran, c)
	if r.failOn != "" && strings.Contains(strings.Join(c.Args, " "), r.failOn) {
		return "", errors.New("模拟失败")
	}
	return "", nil
}

// newTUNForV6 用真构造函数造一个 TUN，并把 plan 备好，
// 这样测的确实是产品会走的那个分支（含默认值填充）。
func newTUNForV6(t *testing.T, failOn string) (*TUN, *recordingRunner) {
	t.Helper()
	conf := config.DefaultTUN()
	conf.Enable = true
	r := &recordingRunner{failOn: failOn}
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(2*time.Second), outbound.NewDirect(2*time.Second)), 2*time.Second)
	tun, err := New(Options{
		Conf:      conf,
		Router:    rt,
		Runner:    r,
		Upstreams: []string{"223.5.5.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tun.plan = plan
	return tun, r
}

// TestApplyV6RollsBackAndLeavesV6Off 是 v6 失败时唯一正确的处置：
// 整组撤干净并如实报告没装上，让 DNS 退回 NODATA。
//
// 留着半套规则比完全没装更糟：下次启动的残留清理会以为有东西要清，
// 而 DNS 这边已经在发假 v6 了——正好是「解析得出地址但连不上」那个最难查的组合。
func TestApplyV6RollsBackAndLeavesV6Off(t *testing.T) {
	tun, r := newTUNForV6(t, "-A wps_app_dns ! -d ::1/128 -p udp")
	tun.setV6Ready(tun.applyV6(context.Background(), tun.plan))
	if tun.dns.allowV6 {
		t.Fatal("有命令失败却让 DNS 开始发假 v6")
	}
	if !hasCmd(r.ran, "ip6tables", "-t nat -X wps_app_dns") {
		t.Error("没有撤销 ip6tables 规则")
	}
	if !hasCmd(r.ran, "ip", "-6 addr del fd00:1::1/64 dev wps-tun") {
		t.Error("没有撤销网卡 v6 地址")
	}
	if !hasCmd(r.ran, "ip", "-6 route del fc00::/18 dev wps-tun") {
		t.Error("没有撤销 v6 假 IP 路由")
	}
}

func TestApplyV6SucceedsWhenAllCommandsWork(t *testing.T) {
	tun, _ := newTUNForV6(t, "")
	tun.setV6Ready(tun.applyV6(context.Background(), tun.plan))
	if !tun.dns.allowV6 {
		t.Fatal("全部命令都成功，DNS 却仍不发假 v6")
	}
}

// TestIPv6OffLeavesEveryV6CommandOut 是给不想被碰 ip6tables 的人准备的：
// tun.ipv6: false 之后，整条链路上一个 v6 命令都不该出现。
func TestIPv6OffLeavesEveryV6CommandOut(t *testing.T) {
	no := false
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.IPv6 = &no
	r := &recordingRunner{}
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(2*time.Second), outbound.NewDirect(2*time.Second)), 2*time.Second)
	tun, err := New(Options{Conf: conf, Router: rt, Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tun.plan = plan
	if tun.fake.HasV6() {
		t.Error("关掉了却仍建了 v6 段")
	}
	tun.setV6Ready(tun.applyV6(context.Background(), plan))
	if tun.dns.allowV6 {
		t.Error("关掉了却让 DNS 开始发假 v6")
	}
	for _, c := range r.ran {
		if c.Bin == "ip6tables" || strings.Contains(strings.Join(c.Args, " "), "-6 ") {
			t.Errorf("关掉后仍执行了 v6 命令: %s", c)
		}
	}
}

// ------------------------------------------------------------------ 状态投影

// TestStatusSeparatesNotWantedFromFailed 面板上要分得清「用户没要 v6」
// 和「要了但没装上」：前者是配置，后者是故障（多半内核没加载 ip6table_nat）。
// 合成一个字段报出去，排查方向就会指错地方。
func TestStatusSeparatesNotWantedFromFailed(t *testing.T) {
	failed, _ := newTUNForV6(t, "-A wps_app_dns ! -d ::1/128 -p udp")
	failed.setV6Ready(failed.applyV6(context.Background(), failed.plan))
	st := failed.Status()
	if !st.IPv6 {
		t.Fatal("配置里 v6 是开的，状态却说没要")
	}
	if st.V6Ready {
		t.Fatal("有一组 v6 命令失败了，状态却说装上了")
	}

	ok, _ := newTUNForV6(t, "")
	ok.setV6Ready(ok.applyV6(context.Background(), ok.plan))
	if st := ok.Status(); !st.IPv6 || !st.V6Ready {
		t.Fatalf("全部成功却报成 ipv6=%v v6Ready=%v", st.IPv6, st.V6Ready)
	}

	no := false
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.IPv6 = &no
	r := &recordingRunner{}
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(2*time.Second), outbound.NewDirect(2*time.Second)), 2*time.Second)
	off, err := New(Options{Conf: conf, Router: rt, Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	if st := off.Status(); st.IPv6 || st.V6Ready {
		t.Fatalf("没要 v6 却报成 ipv6=%v v6Ready=%v", st.IPv6, st.V6Ready)
	}
}

// ------------------------------------------------------------------ 转发路径

// TestRelayTCPViaFakeV6 走通 v6 的主路径：应用连假 v6 → 反查域名 → 按域名拨号。
//
// 这条链路决定了「判定用的是什么」：交给 router 的是域名而不是那个 fc00:: 地址。
// 用域名判定才谈得上 GEOIP/DOMAIN-SUFFIX——拿 fc00:: 去查规则集必然一条都不中。
func TestRelayTCPViaFakeV6(t *testing.T) {
	rec := &stubDialRecorder{}
	rt := router.New(mustEngine(t), outbound.NewSet(rec, rec), 2*time.Second)
	fake, err := NewFakeStore("198.18.0.0/15", "fc00::/18", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tr := &TUN{
		conf: config.TUNConfig{Enable: true, Device: "wps-tun"},
		rt:   rt,
		fake: fake,
	}
	v6, err := fake.Allocate6("a.example.com")
	if err != nil {
		t.Fatal(err)
	}

	app, peer := net.Pipe()
	conn := &pipeConn{Conn: app, id: idFor(v6.String(), 443, "fd00:1::9", 51000)}
	done := make(chan struct{})
	go func() { tr.relayTCP(conn); close(done) }()

	if _, err := peer.Write([]byte("hello v6")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("回包失败: %v", err)
	}
	if string(buf[:n]) != "hello v6" {
		t.Fatalf("搬错内容: %q", buf[:n])
	}
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relayTCP 没随连接关闭而收尾")
	}
	if rec.last != "a.example.com:443" {
		t.Fatalf("拨号目标 = %q，期望域名而不是假 v6 %s", rec.last, v6)
	}
}

// TestRelayRefusesUnknownFakeV6 与 v4 同一个理由，但要单独钉一遍：
// fc00::/18 段内反查不到域名的连接必须就地拒绝，否则包会被打回同一块 tun。
func TestRelayRefusesUnknownFakeV6(t *testing.T) {
	rec := &stubDialRecorder{}
	rt := router.New(mustEngine(t), outbound.NewSet(rec, rec), 2*time.Second)
	fake, err := NewFakeStore("198.18.0.0/15", "fc00::/18", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tr := &TUN{
		conf: config.TUNConfig{Enable: true, Device: "wps-tun"},
		rt:   rt,
		fake: fake,
	}
	app, peer := net.Pipe()
	conn := &pipeConn{Conn: app, id: idFor("fc00::dead:beef", 443, "fd00:1::9", 40000)}
	tr.relayTCP(conn)
	_ = peer.Close()
	if rec.last != "" {
		t.Fatalf("未知假 v6 不该被拨出去: %q", rec.last)
	}
}

// TestRelayRealV6IsNotMistakenForFake 真正的 v6 连接不能被当成假 IP 拒掉：
// strict_route 下裸 IP 流量本来就会进 tun，那条路径上 hint 是空的，
// 判定与拨号都用这个干净的真 v6。
func TestRelayRealV6IsNotMistakenForFake(t *testing.T) {
	rec := &stubDialRecorder{}
	rt := router.New(mustEngine(t), outbound.NewSet(rec, rec), 2*time.Second)
	fake, err := NewFakeStore("198.18.0.0/15", "fc00::/18", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tr := &TUN{
		conf: config.TUNConfig{Enable: true, Device: "wps-tun"},
		rt:   rt,
		fake: fake,
	}
	app, peer := net.Pipe()
	conn := &pipeConn{Conn: app, id: idFor("2400:3200::1", 443, "fd00:1::9", 40001)}
	done := make(chan struct{})
	go func() { tr.relayTCP(conn); close(done) }()
	// 走一个来回让 relay 真正开始搬数据——只等它结束会一直卡在双向搬运里。
	if _, err := peer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := peer.Read(buf); err != nil {
		t.Fatalf("真 v6 连接没被转发: %v", err)
	}
	_ = peer.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relayTCP 没随连接关闭而收尾")
	}
	// 真 v6 不在假 IP 段内，所以按字面地址拨出去（hint 为空）。
	if rec.last != "[2400:3200::1]:443" {
		t.Fatalf("真 v6 的拨号目标 = %q", rec.last)
	}
}
