package dnsx

import (
	"context"
	"net"
	"testing"
	"time"

	"wps_app/internal/dnstest"
)

// startFakeDNSIP 起一台会答指定地址的假上游。ip 为空串时回一条全零 A（"答了但没地址"）。
func startFakeDNSIP(t *testing.T, delay time.Duration, ip string) *dnstest.Server {
	t.Helper()
	var parsed net.IP
	if ip != "" {
		parsed = net.ParseIP(ip)
		if parsed == nil {
			t.Fatalf("测试写错了：%q 不是合法 IP", ip)
		}
	}
	return dnstest.Start(t, delay, parsed)
}

// TestQueryDoesNotWaitForSlowestUpstream 锁住"未命中延迟 = 最快上游"这条语义。
//
// 以前 query 要收齐 len(servers) 个结果才裁决，只有出现私有地址才提前返回。
// 后果是：一家上游黑洞时，每次缓存未命中都要打满 timeout——哪怕 20ms 时已经
// 拿到了正确答案。单飞会把这个等待摊给所有并发查询，于是"某个站点打不开"
// 变成"整片一起慢"，而且看起来像节点的问题。
func TestQueryDoesNotWaitForSlowestUpstream(t *testing.T) {
	fast := startFakeDNSIP(t, 0, "1.2.3.4")
	slow := startFakeDNSIP(t, 0, "5.6.7.8")
	// 装死是"有一家上游黑洞"在客户端眼里的真实形状：包发出去了，就是不回。
	slow.Mute(true)

	// 预算给到 3 秒，但正确实现应当在几十毫秒内返回。
	r, err := New([]string{fast.Addr, slow.Addr}, 3*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	addrs, err := r.query(context.Background(), "fast.example", PathDirect)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("有一家上游已经答出来了，不该失败: %v", err)
	}
	// 1 秒是很宽的阈值：真的等齐就要 3 秒，而正常路径是个位数毫秒。
	if elapsed > time.Second {
		t.Fatalf("等了 %v 才返回——仍在等最慢的那家上游", elapsed.Round(time.Millisecond))
	}
	if len(addrs) == 0 || addrs[0].String() != "1.2.3.4" {
		t.Fatalf("应拿到快的那家的答案 1.2.3.4，实际 %v", addrs)
	}
}

// TestQueryKeepsAnswerWhenBudgetRunsOut 锁住"超时不能丢掉已经拿到的答案"。
//
// 形状：快的那家给了答案，但慢的那家一直不回，总预算先耗尽。
// 这时交出去的错误会变成"这次解析失败"，而调用方还得为一次已经成功的解析
// 再付一次重试——表现是页面偶发白、日志里却是超时。
func TestQueryKeepsAnswerWhenBudgetRunsOut(t *testing.T) {
	fast := startFakeDNSIP(t, 0, "1.2.3.4")
	slow := startFakeDNSIP(t, 0, "5.6.7.8")
	slow.Mute(true)

	// 预算压到 400ms：慢的那家永远不会回，超时一定会先到。
	r, err := New([]string{fast.Addr, slow.Addr}, 400*time.Millisecond, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	addrs, err := r.query(context.Background(), "budget.example", PathDirect)
	if err != nil {
		t.Fatalf("已经拿到答案，预算耗尽时不该判失败: %v", err)
	}
	if len(addrs) == 0 || addrs[0].String() != "1.2.3.4" {
		t.Fatalf("应保留已经拿到的答案 1.2.3.4，实际 %v", addrs)
	}
}

// TestPublicLayerRejectsPrivateWinner 锁住"公网上游给的私有地址不算赢家"。
//
// 两层分开问之后，公网域名只会问公网上游。此时若某家（被污染的）上游回 10.x，
// 而另一家回真实公网地址，"私有地址直接胜出"就会把污染答案写进缓存，
// 一黏五分钟——正是这次改动要修的那个形状，只是方向反了。
func TestPublicLayerRejectsPrivateWinner(t *testing.T) {
	// 污染的那家先回来（0ms），干净的那家晚 120ms。
	poisoned := startFakeDNSIP(t, 0, "10.1.2.3")
	clean := startFakeDNSIP(t, 120*time.Millisecond, "1.2.3.4")

	r, err := New([]string{poisoned.Addr, clean.Addr}, 2*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	addrs, err := r.query(context.Background(), "public.example", PathDirect)
	if err != nil {
		t.Fatalf("有一家给了公网地址，不该失败: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("解析结果为空")
	}
	if isInternalAddr(addrs[0]) {
		t.Fatalf("采用了公网上游给出的私有地址 %v —— 那更可能是污染，不是答案", addrs)
	}
	if addrs[0].String() != "1.2.3.4" {
		t.Fatalf("应采用公网答案 1.2.3.4，实际 %v", addrs)
	}
}

// TestRouteForPicksLayer 确认"走哪一层"这个判据本身：
// 内网后缀走内网上游，其余走公网；这个布尔值是裁决规则的前提。
func TestRouteForPicksLayer(t *testing.T) {
	r, err := NewWithInternal(
		[]string{"223.5.5.5"},
		[]string{"10.180.191.11"},
		[]string{"corp.example"},
		2*time.Second, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if servers, internal := r.routeFor("a.corp.example"); !internal || len(servers) != 1 {
		t.Fatalf("内网后缀应走内网层，实际 internal=%v servers=%v", internal, servers)
	}
	if _, internal := r.routeFor("www.example.com"); internal {
		t.Fatal("公网域名不该被当成内网层")
	}
}
