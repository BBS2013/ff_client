package tunx

import (
	"context"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"wps_app/internal/rules"
)

// TestOnlyDirectGetsRealIP 每个分流策略都必须被明确决定过「领假 IP 还是领真 IP」。
//
// 这是本项目里后果最不对称的一处判断：判成 DIRECT 会回真 IP，应用拿到真地址
// 就根本不进 tun——于是那条策略在 TUN 模式下**整体失效**，
// 而 DNS 应答、日志、界面、连接表全都显示正常。
// 所以这里用「不是 DIRECT」取反，并要求每个新策略都在下面这张表里被写清楚。
func TestOnlyDirectGetsRealIP(t *testing.T) {
	resolved := netip.MustParseAddr("203.0.113.55")
	for _, p := range rules.Policies() {
		dec := stubDecider{every: p}
		s := newDNSServer(t, dec, func(_ context.Context, _ string) ([]netip.Addr, error) {
			return []netip.Addr{resolved}, nil
		})
		resp, err := s.Serve(context.Background(), queryFor(t, "any.example.com", dnsmessage.TypeA))
		if err != nil {
			t.Fatalf("策略 %q: Serve: %v", p, err)
		}
		ip := answerIP(t, resp)
		if p == rules.PolicyDirect {
			if ip != resolved {
				t.Errorf("DIRECT 该回真 IP（直连不绕路、也不该被引到 tun），实际 %s", ip)
			}
			continue
		}
		if ip == resolved {
			t.Errorf("策略 %q 回了真 IP：它会在 tun 外面直连，这条策略等于没生效", p)
			continue
		}
		if _, ok := s.fake.Lookup(ip); !ok {
			t.Errorf("策略 %q 领了个不是假 IP 的地址 %s，relay 无法反查回来", p, ip)
		}
	}
}
