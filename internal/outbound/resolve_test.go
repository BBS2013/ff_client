package outbound

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
)

type fakeResolver struct {
	addrs []netip.Addr
	err   error
	calls int
	got   string
}

func (f *fakeResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	f.calls++
	f.got = host
	if f.err != nil {
		return nil, f.err
	}
	return f.addrs, nil
}

// TestResolveServerAddrPrefersOwnDNS 是这次修复的正身：
// 节点地址必须由我们自己的直连 DNS 解析，系统 resolver 在 TUN 下不可信、也可能已经坏了。
func TestResolveServerAddrPrefersOwnDNS(t *testing.T) {
	r := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("203.0.113.9")}}
	addr, err := resolveServerAddr(context.Background(), r, "example.com:443", netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if r.calls != 1 || r.got != "example.com" {
		t.Fatalf("没走自带解析: calls=%d host=%q", r.calls, r.got)
	}
	if addr.String() != "203.0.113.9:443" {
		t.Fatalf("应优先挑 IPv4，实得 %s", addr)
	}
}

func TestResolveServerAddrLiteralIPSkipsResolver(t *testing.T) {
	r := &fakeResolver{err: errors.New("不该被调用")}
	addr, err := resolveServerAddr(context.Background(), r, "127.0.0.1:14433", netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if r.calls != 0 {
		t.Fatalf("字面量 IP 不该再解析: %d 次", r.calls)
	}
	if addr.String() != "127.0.0.1:14433" {
		t.Fatalf("地址不对: %s", addr)
	}
}

// TestResolveServerAddrFallsBackToSystem 保证「自带 DNS 坏了」不会变成开不起来：
// 降级到系统解析，实在不行才报错。
func TestResolveServerAddrFallsBackToSystem(t *testing.T) {
	r := &fakeResolver{err: errors.New("上游全挂")}
	addr, err := resolveServerAddr(context.Background(), r, "localhost:443", netip.Prefix{})
	if err != nil {
		t.Fatalf("应能退回系统解析: %v", err)
	}
	if addr.Port != 443 || addr.IP == nil {
		t.Fatalf("降级结果不对: %s", addr)
	}
	if r.calls != 1 {
		t.Errorf("先试了自带解析才降级，calls=%d", r.calls)
	}

	empty := &fakeResolver{addrs: []netip.Addr{}}
	if _, err := resolveServerAddr(context.Background(), empty, "localhost:8443", netip.Prefix{}); err != nil {
		t.Fatalf("解析结果为空时也应降级: %v", err)
	}

	bad := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("2001:db8::1")}}
	got, err := resolveServerAddr(context.Background(), bad, "example.com:443", netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	if got.IP.To4() != nil || got.String() != "[2001:db8::1]:443" {
		t.Fatalf("只有 IPv6 时应回落到 IPv6: %s", got)
	}
}

func TestResolveServerAddrRejectsBadAddr(t *testing.T) {
	for _, bad := range []string{"example.com", ":443", "example.com:notaport"} {
		if _, err := resolveServerAddr(context.Background(), nil, bad, netip.Prefix{}); err == nil {
			t.Errorf("%q 应报错", bad)
		}
	}
	// 端口非数字时不能悄悄变成 0 端口。
	if _, err := resolveServerAddr(context.Background(), &fakeResolver{
		addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")},
	}, "example.com:http", netip.Prefix{}); err == nil {
		t.Error("非法端口应报错")
	}
}

// TestNewHysteriaUsesResolver 串起构造路径：握手参数与解析结果都要落对。
func TestNewHysteriaUsesResolver(t *testing.T) {
	r := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("198.51.100.7")}}
	hy, err := NewHysteria(config.ServerConfig{
		Addr:       "hy.example.com:443",
		Auth:       "x",
		TLS:        config.TLSConfig{SNI: "hy.example.com"},
		Bandwidth:  config.BandwidthConfig{Up: "200 mbps", Down: "1000 mbps"},
		Congestion: "bbr",
		FastOpen:   true,
	}, 5*time.Second, r, netip.Prefix{})
	if err != nil {
		t.Fatal(err)
	}
	defer hy.Close()
	if r.calls != 1 {
		t.Errorf("构造时应先用自带解析, calls=%d", r.calls)
	}
	if got := hy.template.ServerAddr.String(); got != "198.51.100.7:443" {
		t.Fatalf("服务端地址不对: %s", got)
	}
	if tx, _ := config.ParseBandwidth("200 mbps"); hy.template.BandwidthConfig.MaxTx != tx {
		t.Fatalf("带宽参数不对: %+v", hy.template.BandwidthConfig)
	}
	if !hy.template.FastOpen || hy.template.Auth != "x" {
		t.Fatalf("基础参数丢了: %+v", hy.template)
	}
}

// TestResolveServerHostRejectsFakeIPs 是 jp 节点那次故障的复盘。
//
// 现象：trojan 报 `read tcp 172.19.0.1:58046->198.18.0.9:8443: connection reset by peer`。
// 198.18.0.9 是我们自己发出去的假 IP——节点域名不在规则集里、落到 FINAL=PROXY，
// 于是被劫持的系统解析把「节点」答成了自家网卡里的地址。照着连过去，
// 就是「用节点去连节点」的环路，而症状是一句和配置毫无关系的 reset。
// 假 IP 永远不可能是节点的真实地址，所以这里直接拒绝，并把原因写进错误里。
func TestResolveServerHostRejectsFakeIPs(t *testing.T) {
	fake := netip.MustParsePrefix("198.18.0.0/15")

	// 只有假 IP：必须报错，且要说清是假 IP。
	only := &fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("198.18.0.9")}}
	if _, err := resolveServerHost(context.Background(), only, "node.example.com", fake); err == nil {
		t.Fatal("解析结果全在假 IP 段内时应报错")
	} else if !strings.Contains(err.Error(), "假 IP") {
		t.Fatalf("错误应点明假 IP: %v", err)
	}

	// 混着来：跳过假 IP，取真实地址——这是最常见的污染场景（一条真一条假）。
	mixed := &fakeResolver{addrs: []netip.Addr{
		netip.MustParseAddr("198.18.0.9"), netip.MustParseAddr("203.0.113.9"),
	}}
	got, err := resolveServerHost(context.Background(), mixed, "node.example.com", fake)
	if err != nil {
		t.Fatal(err)
	}
	if got != "203.0.113.9" {
		t.Fatalf("应跳过假 IP 取真实地址，实得 %s", got)
	}

	// 字面量 IP 直接写在配置里也照样拦：用户完全可能把假 IP 抄进 config.yaml。
	if _, err := resolveServerHost(context.Background(), nil, "198.18.7.4:443", fake); err == nil {
		t.Fatal("addr 直接写假 IP 时应报错")
	}

	// 没配假 IP 段（零值）时不额外拦，行为与改动前一致。
	if _, err := resolveServerHost(context.Background(), only, "node.example.com", netip.Prefix{}); err != nil {
		t.Fatalf("reject 为空时不该拦真地址: %v", err)
	}
}

// TestResolveServerAddrRejectsFakeInLiteral 串起 UDP 地址这一层：
// hysteria2 的节点同样可能拿到假 IP，护栏必须在两条协议上都生效。
func TestResolveServerAddrRejectsFakeInLiteral(t *testing.T) {
	fake := netip.MustParsePrefix("198.18.0.0/15")
	if _, err := resolveServerAddr(context.Background(), nil, "198.18.2.3:443", fake); err == nil {
		t.Fatal("字面量假 IP 应被拒绝")
	}
	hy, err := NewHysteria(config.ServerConfig{Addr: "198.18.2.3:443", Auth: "x"}, time.Second, nil, fake)
	if err == nil {
		_ = hy.Close()
		t.Fatal("NewHysteria 应拒绝把假 IP 当节点")
	}
	tj, err := NewTrojan(config.ServerConfig{Type: config.ProtocolTrojan, Addr: "198.18.2.3:443", Auth: "x"}, time.Second, nil, fake)
	if err == nil {
		_ = tj.Close()
		t.Fatal("NewTrojan 应拒绝把假 IP 当节点")
	}
}
