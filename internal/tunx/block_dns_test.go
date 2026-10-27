package tunx

import (
	"context"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"wps_app/internal/config"
)

// TestDNSServerGivesFakeIPForBlocked 被拦的域名必须和 PROXY 一样领假 IP。
//
// 这是整个拦截功能最容易踩空的地方：DIRECT 的域名回真 IP，应用拿到真地址
// 根本不进 tun，我们连"看一眼"的机会都没有。漏了这条，TUN 模式下的黑名单
// 会**一条都拦不住**，而 DNS 应答、日志、界面全都看不出任何异常。
func TestDNSServerGivesFakeIPForBlocked(t *testing.T) {
	dec := stubDecider{block: map[string]bool{"ads.example.com": true}}
	s := newDNSServer(t, dec, func(_ context.Context, _ string) ([]netip.Addr, error) {
		t.Error("拦截域名不该去解析真 IP：它必须直接领假 IP")
		return nil, nil
	})
	resp, err := s.Serve(context.Background(), queryFor(t, "ads.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	ip := answerIP(t, resp)
	if !netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
		t.Fatalf("拦截域名没领到假 IP，回了 %s——它会在 tun 外面直接出去", ip)
	}
	if got, ok := s.fake.Lookup(ip); !ok || got != "ads.example.com" {
		t.Fatalf("假 IP 反查失败: %q %v", got, ok)
	}
}

func TestDNSServerGivesFakeV6ForBlocked(t *testing.T) {
	dec := stubDecider{block: map[string]bool{"ads.example.com": true}}
	s := newDualDNSServer(t, dec, true)
	resp, err := s.Serve(context.Background(), queryFor(t, "ads.example.com", dnsmessage.TypeAAAA))
	if err != nil {
		t.Fatal(err)
	}
	ip := answerV6(t, resp)
	if !netip.MustParsePrefix("fc00::/18").Contains(ip) {
		t.Fatalf("v6 上同样要拦住，回了 %s", ip)
	}
}

// TestDNSServerDirectModeDoesNotBlock 用户选的是「模式优先」：
// 切到直连模式，黑名单连同其它规则一起让开——这是刻意留的逃生阀。
// DNS 这一侧必须跟着让，否则应用拿到假 IP 却根本没有拦截逻辑在等它。
func TestDNSServerDirectModeDoesNotBlock(t *testing.T) {
	dec := stubDecider{
		block: map[string]bool{"ads.example.com": true},
		mode:  config.ModeDirect,
	}
	real := netip.MustParseAddr("203.0.113.77")
	s := newDNSServer(t, dec, func(_ context.Context, _ string) ([]netip.Addr, error) {
		return []netip.Addr{real}, nil
	})
	resp, err := s.Serve(context.Background(), queryFor(t, "ads.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if ip := answerIP(t, resp); ip != real {
		t.Errorf("direct 模式下应回真 IP（黑名单整体让开），实际 %s", ip)
	}
}
