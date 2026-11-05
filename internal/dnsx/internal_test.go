package dnsx

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// TestServersForSplitsByDomain 内网后缀走内网上游，其余走公网上游。
func TestServersForSplitsByDomain(t *testing.T) {
	r, err := NewWithInternal(
		[]string{"223.5.5.5"},
		[]string{"10.180.191.11"},
		[]string{"mychery.com"},
		3*time.Second, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want []string
	}{
		{"yfjira.mychery.com", []string{"10.180.191.11:53"}},
		{"mychery.com", []string{"10.180.191.11:53"}},
		{"a.b.mychery.com", []string{"10.180.191.11:53"}},
		{"www.google.com", []string{"223.5.5.5:53"}},
		{"notmychery.com", []string{"223.5.5.5:53"}},
	}
	for _, c := range cases {
		got := r.serversFor(c.host)
		if len(got) != 1 || got[0] != c.want[0] {
			t.Errorf("serversFor(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// TestInternalWithoutSuffixIsError 配了内网上游却没有后缀必须报错：
// 否则用户以为内网分层生效了，实际一次都没用上。
func TestInternalWithoutSuffixIsError(t *testing.T) {
	_, err := NewWithInternal([]string{"223.5.5.5"}, []string{"10.180.191.11"}, nil, time.Second, time.Minute)
	if err == nil {
		t.Fatal("配了内网上游却没有后缀，应当报错")
	}
}

// TestNoInternalKeepsOldBehaviour 没配内网层时行为与从前一致。
func TestNoInternalKeepsOldBehaviour(t *testing.T) {
	r, err := New([]string{"223.5.5.5", "119.29.29.29"}, time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := r.serversFor("yfjira.mychery.com"); len(got) != 2 {
		t.Fatalf("未配内网层时所有域名都该走公网上游，实际 %v", got)
	}
}

// TestIsInternalAddr 私有段判定：RFC1918 / CGNAT / ULA 算内网，
// 回环与链接本地不算（那是环路信号，不是内网服务）。
func TestIsInternalAddr(t *testing.T) {
	internal := []string{"10.0.0.1", "172.25.51.92", "192.168.1.1", "100.64.0.1", "fd00::1"}
	for _, s := range internal {
		a := netip.MustParseAddr(s)
		if !isInternalAddr(a) {
			t.Errorf("%s 应算内网地址", s)
		}
	}
	notInternal := []string{"127.0.0.1", "169.254.1.1", "8.8.8.8", "223.5.5.5", "fe80::1", "::1"}
	for _, s := range notInternal {
		a := netip.MustParseAddr(s)
		if isInternalAddr(a) {
			t.Errorf("%s 不该算内网地址", s)
		}
	}
}

// TestPrioritizeInternalKeepsAll 私有地址排前面，但公网地址不能丢：
// 多地址重试需要完整候选集。
func TestPrioritizeInternalKeepsAll(t *testing.T) {
	in := []netip.Addr{
		netip.MustParseAddr("123.60.194.157"),
		netip.MustParseAddr("172.25.51.92"),
	}
	out := prioritizeInternal(in)
	if len(out) != 2 {
		t.Fatalf("候选集长度变了: %v", out)
	}
	if out[0].String() != "172.25.51.92" {
		t.Fatalf("私有地址应排第一，实际 %v", out)
	}
}

// TestHasInternalAddr 混合候选集里只要有一个内网地址就要认出来。
func TestHasInternalAddr(t *testing.T) {
	if !hasInternalAddr([]netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("10.1.2.3")}) {
		t.Error("应识别出内网地址")
	}
	if hasInternalAddr([]netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("127.0.0.1")}) {
		t.Error("回环地址不算内网地址")
	}
}

// TestRealInternalDomainEndToEnd 用真实上游验证内网域名解析到内网地址。
//
// 必须显式打开（WPS_INTERNAL_DNS=1）才跑，因为它是这一堆用例里唯一真的往外
// 发 DNS 查询的一条：
//
//   - 默认的 `go test ./...` 与 `make gate` 都该是离线可跑的。公司网里跑这一条
//     会打到 10.180.191.11，出了公司网就变成一条要等超时的失败/跳过，
//     而"跑得通"与"跑不通"取决于这台机器此刻在哪个网络——那不是回归信号。
//   - 内网主机名与上游地址也不该写死在源码里：写死等于把公司内网拓扑带进仓库。
//
// 用法：WPS_INTERNAL_DNS=1 WPS_INTERNAL_DNS_HOST=yfjira.mychery.com \
//
//	WPS_INTERNAL_DNS_SERVER=10.180.191.11 go test ./internal/dnsx -run RealInternal
func TestRealInternalDomainEndToEnd(t *testing.T) {
	if os.Getenv("WPS_INTERNAL_DNS") != "1" {
		t.Skip("需要真实内网 DNS：设 WPS_INTERNAL_DNS=1 才跑（见注释）")
	}
	host := strings.TrimSpace(os.Getenv("WPS_INTERNAL_DNS_HOST"))
	if host == "" {
		t.Skip("没给 WPS_INTERNAL_DNS_HOST（要查的内网域名）")
	}
	server := strings.TrimSpace(os.Getenv("WPS_INTERNAL_DNS_SERVER"))
	if server == "" {
		t.Skip("没给 WPS_INTERNAL_DNS_SERVER（内网上游地址）")
	}
	suffix := host
	if i := strings.Index(host, "."); i >= 0 {
		suffix = host[i:] // ".mychery.com"
	}
	r, err := NewWithInternal(
		[]string{"223.5.5.5", "119.29.29.29"},
		[]string{server},
		[]string{suffix},
		3*time.Second, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := r.LookupIP(context.Background(), host)
	if err != nil {
		t.Skipf("内网 DNS 不可达（不在公司网络？）: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("解析结果为空")
	}
	t.Logf("%s -> %v", host, addrs)
	if !isInternalAddr(addrs[0]) {
		t.Fatalf("应解析到内网地址，实际 %v", addrs)
	}
}
