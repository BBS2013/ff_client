package dnsx

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"wps_app/internal/dnstest"
)

// fakeDNS 是包内测试用的旧名字，实现搬到了 internal/dnstest：
// 服务层「看解析」那一格（internal/service/dnsprobe.go）也要一个会答 A 记录的上游，
// 而复制一份会漂——改了一边的"按问题名计数"这个判据，另一边会静默地量不到东西。
// 这里只留一层薄壳，本包那批用例的写法因此不用全改。
type fakeDNS = dnstest.Server

func startFakeDNS(t *testing.T, delay time.Duration, ip net.IP) *fakeDNS {
	return dnstest.Start(t, delay, ip)
}

func newTestResolver(t *testing.T, servers []string, ttl time.Duration) *Resolver {
	t.Helper()
	r, err := New(servers, 2*time.Second, ttl)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// TestResolverSharedQuerySurvivesLeaderCancel 锁住一个隐蔽的取消传播：
// 同一域名的并发查询会合并成一次，由首个到达者代跑。
// 以前那次查询直接挂在首个调用者的 ctx 上——而那个 ctx 属于一次具体的拨号
// （通常带 15~30 秒超时）。它一取消，所有共享本次查询的等待者都会拿到
// ctx.Err()，哪怕它们自己的 ctx 还活着。于是「浏览器开了一堆并发连接、
// 第一个刚好慢」会表现成后面全部解析失败。
func TestResolverSharedQuerySurvivesLeaderCancel(t *testing.T) {
	srv := startFakeDNS(t, 300*time.Millisecond, net.ParseIP("93.184.216.34"))
	r := newTestResolver(t, []string{srv.Addr}, time.Minute)

	// 首个调用者：自己的 ctx 短于上游的回答延迟，查询期间必然被取消。
	// 150ms 而不是原来的 50ms——留给「查询真的发出去」这段时间，否则取消发生在拨号之前，
	// 测的就不是共享查询了。
	leaderCtx, cancelLeader := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancelLeader()
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_, _ = r.LookupIP(leaderCtx, "leader.example")
	}()

	// 等首个查询确实到达上游（fakeDNS 会延迟 300ms 才答），此时 leader 还在飞。
	srv.WaitQueries(t, 1, 2*time.Second)

	// 等待者：自己的 ctx 长得多，不该被 leader 的取消连累。
	waiterCtx, cancelWaiter := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelWaiter()
	addrs, err := r.LookupIP(waiterCtx, "leader.example")

	<-leaderDone
	if err != nil {
		t.Fatalf("等待者的 ctx 未过期，却拿到了错误（被 leader 的取消连累了）: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("等待者应拿到解析结果")
	}
	// 共享成功的样子：每个问题只被问一次。
	//
	// 原来这里断的是"上游总共收到 ≤2 个包"，那个数其实是标准库的事：
	// /etc/resolv.conf 里有一行 search 域，它就会多问一个带后缀的变体，
	// 于是这条用例在"今天网络配置不同的同一台机器"上会无故变红（实测：本机加了
	// search chery.local 后稳定报 3 个包，而共享逻辑一行都没变）。
	// 换成看"同一个问题被问了几遍"之后，包数随环境怎么变都不影响判据，
	// 而两个调用者各查各的（每个问题 ×2）照样当场红。
	if dup := srv.Doubled(); len(dup) > 0 {
		t.Fatalf("上游把同一个问题问了不止一遍：%v —— 两个调用者没共享同一次解析（共 %d 个包）",
			dup, srv.Queries())
	}
	if srv.Queries() < 2 {
		t.Fatalf("上游只收到 %d 个查询：这次解析根本没走到上游", srv.Queries())
	}
}

// TestResolverCacheStaysBounded 长跑客户端（TUN 模式尤其明显）
// 会不断查到新域名。缓存只在命中时清理过期项，没有上界就会一直涨。
func TestResolverCacheStaysBounded(t *testing.T) {
	srv := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	// ttl 给足，确保条目不会因为过期被提前清掉——这样上界必须由条数限制来保证。
	r := newTestResolver(t, []string{srv.Addr}, time.Hour)

	const n = maxCacheEntries + 200
	for i := 0; i < n; i++ {
		if _, err := r.LookupIP(context.Background(), "d"+strconv.Itoa(i)+".example"); err != nil {
			t.Fatalf("解析第 %d 个域名失败: %v", i, err)
		}
	}
	r.mu.Lock()
	size := len(r.cache)
	r.mu.Unlock()
	if size > maxCacheEntries {
		t.Fatalf("缓存条目 = %d, 超过上限 %d（长跑会一直涨下去）", size, maxCacheEntries)
	}
	if size == 0 {
		t.Fatal("缓存空了，测试本身失效")
	}
}

// TestResolverCacheHit 确认上限没有把缓存彻底废掉：重复查同一域名不该重复发查询。
func TestResolverCacheHit(t *testing.T) {
	srv := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	r := newTestResolver(t, []string{srv.Addr}, time.Minute)

	if _, err := r.LookupIP(context.Background(), "cached.example"); err != nil {
		t.Fatalf("首次查询失败: %v", err)
	}
	// 不能直接断言总查询数为 1：queryOne 会同时问 A 与 AAAA，
	// 所以首查就会打出不止一条。真正的判据是「后续查询不再增加上游负担」。
	afterFirst := srv.Queries()
	if afterFirst == 0 {
		t.Fatal("fakeDNS 没收到查询，测试本身失效")
	}

	for i := 0; i < 5; i++ {
		if _, err := r.LookupIP(context.Background(), "cached.example"); err != nil {
			t.Fatalf("第 %d 次查询失败: %v", i, err)
		}
	}
	if got := srv.Queries(); got != afterFirst {
		t.Fatalf("重复查询命中了缓存却仍打到上游：查询数 %d -> %d", afterFirst, got)
	}
}

// TestResolverFailoverAcrossUpstreams 确认任一上游成功即可，不必等齐。
func TestResolverFailoverAcrossUpstreams(t *testing.T) {
	dead, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	_ = dead.Close() // 立刻关掉，得到一个无人应答的地址

	good := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	r := newTestResolver(t, []string{dead.LocalAddr().String(), good.Addr}, time.Minute)

	addrs, err := r.LookupIP(context.Background(), "failover.example")
	if err != nil {
		t.Fatalf("有一个可用上游就不该失败: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("应拿到结果")
	}
}
