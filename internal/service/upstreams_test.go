package service

import (
	"testing"

	"wps_app/internal/config"
)

// TestResolverUpstreamHostsIncludeInternal 锁住"两处该一致"这件事。
//
// 同一份上游清单有两个用处：iptables 的放行清单（问上游的 :53 不能被自己劫持）
// 与 strict_route 的绕行路由（接管默认路由后，问上游的包必须钉回物理网关）。
// 以前后一处只用了公网那一半，于是开内网分层 + strict_route 时，
// 问公司 DNS 的查询既被放行、又被 tun 抓回去——内网域名唯一能问的那条路断了，
// 而症状只是"内网服务时好时坏"。
func TestResolverUpstreamHostsIncludeInternal(t *testing.T) {
	cfg := &config.Config{}
	cfg.DNS.Servers = []string{"223.5.5.5", "119.29.29.29:53"}
	cfg.DNS.InternalServers = []string{"10.180.191.11"}
	cfg.DNS.InternalDomains = []string{".corp.example"}

	got := resolverUpstreamHosts(cfg)
	want := map[string]bool{"223.5.5.5": true, "119.29.29.29": true, "10.180.191.11": true}
	if len(got) != len(want) {
		t.Fatalf("上游主机数 = %v，想要 3 个（公网 2 + 内网 1）", got)
	}
	for _, h := range got {
		if !want[h] {
			t.Errorf("多出来的上游主机 %q", h)
		}
		delete(want, h)
	}
	for h := range want {
		t.Errorf("漏掉的上游主机 %q——它不会进 strict_route 的绕行路由", h)
	}
}

// TestResolverUpstreamHostsNilSafe 没配 DNS 段时不能 panic（TUN 可以不开）。
func TestResolverUpstreamHostsNilSafe(t *testing.T) {
	if got := resolverUpstreamHosts(nil); got != nil {
		t.Fatalf("nil 配置应返回 nil，实际 %v", got)
	}
	if got := resolverUpstreamHosts(&config.Config{}); len(got) != 0 {
		t.Fatalf("空配置应返回空清单，实际 %v", got)
	}
}
