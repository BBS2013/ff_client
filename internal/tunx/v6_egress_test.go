//go:build linux

package tunx

import (
	"context"
	"strings"
	"testing"

	"wps_app/internal/config"
)

// 假 v6 只解决「应用连到哪」，真送出去还得本机有 v6 出口。
// 2026-10-29 的现场：带全局 v6 的 USB 网卡掉线那段时间，AAAA 照样回假 v6，
// 而启动日志在承诺「路由装不上时降级为 NODATA（不声称可用）」——
// 应用拿到一个拨不通的地址，比拿不到地址更难查。
func TestV6FakeIPNeedsAnEgress(t *testing.T) {
	base := RoutePlan{Device: "wps-tun", Address6: "fd00:1::1/64", FakeIPRange6: "fc00::/18"}
	cases := []struct {
		name string
		plan RoutePlan
		want bool
	}{
		{"没有 v6 默认路由", base, false},
		{"有 v6 默认路由", func() RoutePlan { p := base; p.Gateway6 = "fe80::5"; return p }(), true},
		{"有网关但没有假 IP 段", func() RoutePlan { p := base; p.Gateway6 = "fe80::5"; p.FakeIPRange6 = ""; return p }(), false},
		{"有网关但地址是空的", func() RoutePlan { p := base; p.Gateway6 = "fe80::5"; p.Address6 = ""; return p }(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.plan.v6FakeIPUsable(); got != tc.want {
				t.Errorf("v6FakeIPUsable = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestApplyV6StaysOffWithoutEgress 一句话：没有出口时，v6 那一组命令**一条都不该发**。
// 只断言返回值是不够的——真发了命令再「逻辑上返回 false」，路由和假 IP 段还是留在内核里。
func TestApplyV6StaysOffWithoutEgress(t *testing.T) {
	conf := config.DefaultTUN()
	conf.Enable = true
	r := &recorderRunner{}
	tun := newDualTUN(t, r)
	if tun.conf.Device != conf.Device {
		t.Fatalf("harness 变了: %q", tun.conf.Device)
	}

	noEgress := RoutePlan{Device: conf.Device, Address6: conf.Address6, FakeIPRange6: conf.FakeIPRange6}
	if tun.applyV6(context.Background(), noEgress) {
		t.Fatal("没有 v6 出口却把 v6 假 IP 启用了")
	}
	for _, c := range r.snapshot() {
		if strings.HasPrefix(c, "ip -6") || strings.Contains(c, "-6 ") {
			t.Errorf("没有出口却发了 v6 命令: %s", c)
		}
	}

	withEgress := noEgress
	withEgress.Gateway6 = "fe80::5"
	withEgress.Interface6 = "wlp3s0f0"
	if !tun.applyV6(context.Background(), withEgress) {
		t.Fatal("有 v6 出口却没启用 v6 假 IP")
	}
	var sawAddr bool
	for _, c := range r.snapshot() {
		if strings.Contains(c, "-6 addr add") {
			sawAddr = true
		}
	}
	if !sawAddr {
		t.Errorf("有出口时本该真的去装 v6 地址，实际命令: %v", r.snapshot())
	}
}
