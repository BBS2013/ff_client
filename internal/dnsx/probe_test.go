package dnsx

// 「看解析」那一格的判据。
//
// Probe 存在的意义是"面板上看到的地址就是引擎下一刻拿去判定的那批"，
// 所以这里盯的不是它能不能问出东西，而是三条容易写歪的性质：
//   1. 与 LookupIP 共用同一份缓存与同一个键（各问一次就该只出门一次）；
//   2. Cached 是后端给的事实，不是从耗时反推的猜测；
//   3. IP 字面量与空输入这两种"根本不该出门问"的输入，一个当场答、一个当场拒。

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbeSharesCacheWithLookup(t *testing.T) {
	srv := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	r := newTestResolver(t, []string{srv.Addr}, time.Minute)
	ctx := context.Background()

	first, err := r.Probe(ctx, "probe.example", PathDirect)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if first.Cached {
		t.Error("第一次探测就报「命中缓存」，那这一格的缓存读数是假的")
	}
	if len(first.Addrs) == 0 {
		t.Fatal("第一次探测没拿到地址，测试前提不成立")
	}
	afterFirst := srv.Queries()
	if afterFirst == 0 {
		t.Fatal("fakeDNS 没收到查询，测试本身失效")
	}

	// 引擎那条路问同一个名字：它必须命中同一份缓存，而不是另开一次出门问。
	// 这一条断的是"面板与判定是同一个真相"——两边各自洗名字的话，
	// 缓存键会差一个尾点或大小写，于是探测显示 A、判定按 B 走。
	via, err := r.LookupIP(ctx, "PROBE.EXAMPLE.")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if srv.Queries() != afterFirst {
		t.Errorf("换个大小写/带尾点就问不出缓存：上游查询数 %d -> %d", afterFirst, srv.Queries())
	}

	second, err := r.Probe(ctx, "probe.example", PathDirect)
	if err != nil {
		t.Fatalf("第二次探测失败: %v", err)
	}
	if !second.Cached {
		t.Error("问过两次之后探测仍报没命中缓存，Cached 这一格就是假的")
	}
	if len(second.Addrs) != len(via) {
		t.Fatalf("探测与引擎拿到的地址数量不同：%v vs %v", second.Addrs, via)
	}
	for i := range second.Addrs {
		if second.Addrs[i] != via[i] {
			t.Fatalf("探测报的地址与引擎要拿去判定的不是同一批：第 %d 个 %v vs %v", i, second.Addrs[i], via[i])
		}
	}
	if second.Host != "probe.example" {
		t.Errorf("回显的查询名没洗： %q", second.Host)
	}
}

func TestProbeDoesNotAskForIPLiterals(t *testing.T) {
	srv := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	r := newTestResolver(t, []string{srv.Addr}, time.Minute)

	got, err := r.Probe(context.Background(), "10.0.0.5", PathDirect)
	if err != nil {
		t.Fatalf("IP 字面量该当场答: %v", err)
	}
	if len(got.Addrs) != 1 || got.Addrs[0].String() != "10.0.0.5" {
		t.Errorf("IP 字面量答错了: %v", got.Addrs)
	}
	if got.Cached {
		t.Error("字面量这条路压根不经过缓存，报命中缓存就是假读数")
	}
	if n := srv.Queries(); n != 0 {
		t.Errorf("一个 IP 字面量不该出门问上游，却打了 %d 条查询", n)
	}
}

func TestProbeRefusesEmptyInput(t *testing.T) {
	r := newTestResolver(t, []string{"127.0.0.1:53"}, time.Minute)
	for _, bad := range []string{"", "   ", "."} {
		if _, err := r.Probe(context.Background(), bad, PathDirect); err == nil {
			t.Errorf("空输入 %q 居然答出来了", bad)
		}
		// 重问那一路也得拒：它跳过的是缓存，不是输入检查。
		if _, err := r.ProbeFresh(context.Background(), bad, PathDirect); err == nil {
			t.Errorf("空输入 %q 走「不用缓存」那一路居然答出来了", bad)
		}
	}
}

// TestProbeFreshIgnoresAndRepairsTheCache 是「重问（不用缓存）」这一按的全部语义，
// 拆成三句缺一不可：
//   - 上游改口之后，普通 Probe 仍然回旧的那批——这就是这一按存在的理由，
//     没有这一句，后面两句都可以靠"缓存本来就会更新"蒙过去；
//   - ProbeFresh 真的出门问了，而且给的是新那批；
//   - 它把新答案**写回了缓存**：紧接着的 Probe 报"命中缓存"且给的是新那批。
//     第三句最容易被写丢（"只问不写"看起来更安全），丢掉了这一按就只是看了一眼，
//     脏的那份还在，引擎下一刻照旧拿它判定。
func TestProbeFreshIgnoresAndRepairsTheCache(t *testing.T) {
	oldIP, newIP := "93.184.216.34", "104.16.1.2"
	srv := startFakeDNS(t, 0, net.ParseIP(oldIP))
	r := newTestResolver(t, []string{srv.Addr}, time.Minute)
	ctx := context.Background()

	if got, err := r.Probe(ctx, "dirty.example", PathDirect); err != nil {
		t.Fatalf("Probe: %v", err)
	} else if got.Addrs[0].String() != oldIP {
		t.Fatalf("测试前提不成立：第一次拿到的不是 %v，是 %v", oldIP, got.Addrs)
	}

	// 上游中途改口——真实世界里这就是 DNS 缓存变脏的方式（换 CDN、被污染、TTL 还没到）。
	srv.SetIP(net.ParseIP(newIP))

	stale, err := r.Probe(ctx, "dirty.example", PathDirect)
	if err != nil {
		t.Fatalf("Probe(缓存): %v", err)
	}
	if !stale.Cached {
		t.Fatal("第二次探测没命中缓存，那" + "\u201c脏缓存还在被端出来\u201d这个前提就不成立")
	}
	if len(stale.Addrs) != 1 || stale.Addrs[0].String() != oldIP {
		t.Fatalf("缓存里那份被跳过了（回的是 %v），这一档要量的就是旧答案还会不会出来", stale.Addrs)
	}

	asked := srv.Queries()
	fresh, err := r.ProbeFresh(ctx, "dirty.example", PathDirect)
	if err != nil {
		t.Fatalf("ProbeFresh: %v", err)
	}
	if fresh.Cached {
		t.Error("「不用缓存」那一路报了命中缓存——它跳过的应该是读，不是整件事")
	}
	if len(fresh.Addrs) != 1 || fresh.Addrs[0].String() != newIP {
		t.Fatalf("重问拿到的还是旧地址：%v（上游已经改成 %v）", fresh.Addrs, newIP)
	}
	if srv.Queries() <= asked {
		t.Errorf("重问没有真的出门问上游：查询数 %d -> %d", asked, srv.Queries())
	}

	repaired, err := r.Probe(ctx, "dirty.example", PathDirect)
	if err != nil {
		t.Fatalf("Probe(修复后): %v", err)
	}
	if !repaired.Cached {
		t.Error("重问之后缓存没被写回：这一按只看了一眼，脏的那份还在，等于没修")
	}
	if len(repaired.Addrs) != 1 || repaired.Addrs[0].String() != newIP {
		t.Fatalf("重问写回的不是新答案：%v", repaired.Addrs)
	}
}

// TestProbeReportsRemainingTtl 盯的是"TtlMs 到底是不是剩余时间"。
// 判据用倍率而不是绝对值：这台机器上 sleep 会漂，但"过掉一半之后剩余必须明显小于整条"
// 这件事不会漂。把整条 TTL 原样抄回来（也就是把"还剩多久"写成"有效期多久"）
// 是最容易犯的错，而这一档要是错了，界面上那句"还剩 N 秒自己变新"就成了假话。
func TestProbeReportsRemainingTtl(t *testing.T) {
	srv := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	const ttl = 3 * time.Second
	r := newTestResolver(t, []string{srv.Addr}, ttl)
	ctx := context.Background()

	full, err := r.Probe(ctx, "ttl.example", PathDirect)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if full.Cached {
		t.Fatal("第一次不该命中缓存")
	}
	if full.TtlMs < ttl.Milliseconds()-300 {
		t.Errorf("刚问到的答案该带整条 TTL，拿到 %dms（配置 %s）", full.TtlMs, ttl)
	}
	if full.TtlMs > ttl.Milliseconds() {
		t.Errorf("剩余时间比配置的 TTL 还长：%dms", full.TtlMs)
	}

	time.Sleep(600 * time.Millisecond)
	left, err := r.Probe(ctx, "ttl.example", PathDirect)
	if err != nil {
		t.Fatalf("Probe(缓存): %v", err)
	}
	if !left.Cached {
		t.Fatal("只过了 600ms 就没能命中缓存，TTL 那一格不用看了")
	}
	if left.TtlMs <= 0 {
		t.Errorf("命中缓存却没报剩余时间（%dms）：界面那句「还剩多久自己变」只能空着", left.TtlMs)
	}
	if left.TtlMs > full.TtlMs-400 {
		t.Errorf("剩余时间没随时间减少：%dms -> %dms，这一格报的是整条 TTL 不是剩余", full.TtlMs, left.TtlMs)
	}
	if left.TtlMs < (ttl-600*time.Millisecond).Milliseconds()/2 {
		t.Errorf("剩余时间掉得太快：%dms（只过了 600ms，配置 %s）", left.TtlMs, ttl)
	}

	// 过期之后必须自己认账：报"没命中"而不是报一条剩余为负的缓存。
	time.Sleep(ttl)
	expired, err := r.Probe(ctx, "ttl.example", PathDirect)
	if err != nil {
		t.Fatalf("Probe(过期后): %v", err)
	}
	if expired.Cached {
		t.Errorf("过了 TTL 还报命中缓存，剩余时间 %dms", expired.TtlMs)
	}
	if expired.TtlMs < ttl.Milliseconds()-500 {
		t.Errorf("过期后重新问到的那份该是整条 TTL，拿到 %dms", expired.TtlMs)
	}
}

// TestProbeFreshOnIPLiteralStillDoesNotAsk：跳过缓存是跳过"读缓存"，
// 不是把字面量这条路也拖去问上游。写歪一行的后果是给 10.0.0.5 发一条 A 查询。
func TestProbeFreshOnIPLiteralStillDoesNotAsk(t *testing.T) {
	srv := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	r := newTestResolver(t, []string{srv.Addr}, time.Minute)
	got, err := r.ProbeFresh(context.Background(), "10.0.0.5", PathDirect)
	if err != nil {
		t.Fatalf("ProbeFresh: %v", err)
	}
	if len(got.Addrs) != 1 || got.Addrs[0].String() != "10.0.0.5" {
		t.Errorf("IP 字面量答错了: %v", got.Addrs)
	}
	if n := srv.Queries(); n != 0 {
		t.Errorf("对 IP 字面量出门问了上游，%d 条", n)
	}
}

// TestProbeEachShowsEveryUpstreamOpinion 是这一格存在的理由：
// 两个上游对同一个名字给出**不同地址**时（污染就是这形状），
// 合并那条路只会留下先回来的一个，而人想知道的是"谁在说谎"。
func TestProbeEachShowsEveryUpstreamOpinion(t *testing.T) {
	good := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	polluted := startFakeDNS(t, 0, net.ParseIP("127.0.0.1")) // 假 IP 段：污染答案常长这样
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.LocalAddr().String()
	_ = dead.Close() // 占过又关掉：这个端口上没人应答

	r := newTestResolver(t, []string{polluted.Addr, good.Addr, deadAddr}, time.Minute)
	got := r.ProbeEach(context.Background(), "split.example", PathDirect)

	if len(got) != 3 {
		t.Fatalf("三个上游该三条答案，拿到 %d 条", len(got))
	}
	// 顺序必须是配置顺序：面板按这个顺序列出来，换一次排序就换一次结论。
	if got[0].Server != polluted.Addr || got[1].Server != good.Addr || got[2].Server != deadAddr {
		t.Errorf("答案顺序被打乱: %s / %s / %s", got[0].Server, got[1].Server, got[2].Server)
	}
	if len(got[0].Addrs) == 0 || got[0].Addrs[0].String() != "127.0.0.1" {
		t.Errorf("第一个上游的答案没拿到: %+v", got[0])
	}
	if len(got[1].Addrs) == 0 || got[1].Addrs[0].String() != "93.184.216.34" {
		t.Errorf("第二个上游的答案没拿到: %+v", got[1])
	}
	if got[0].Addrs[0] == got[1].Addrs[0] {
		t.Error("两个上游给了同一个答案，测试前提不成立（这一档要量的就是分叉）")
	}
	if got[2].Err == "" {
		t.Errorf("没人应答的那个上游该报错误，却给了 %+v", got[2])
	}
	// 各问各的：三个上游各收到过查询，才说明这里没有"抢先返回后把别人掐掉"。
	if good.Queries() == 0 || polluted.Queries() == 0 {
		t.Errorf("有个上游根本没被问到：good=%d polluted=%d", good.Queries(), polluted.Queries())
	}
}

func TestProbeEachOnIPLiteralDoesNotAsk(t *testing.T) {
	fake := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	r := newTestResolver(t, []string{fake.Addr}, time.Minute)
	got := r.ProbeEach(context.Background(), "10.0.0.7", PathDirect)
	if len(got) != 1 || len(got[0].Addrs) != 1 || got[0].Addrs[0].String() != "10.0.0.7" {
		t.Fatalf("IP 字面量该原样答: %+v", got)
	}
	if n := fake.Queries(); n != 0 {
		t.Errorf("IP 字面量不该出门问上游，却打了 %d 条查询", n)
	}
	if r.Servers()[0] != fake.Addr {
		t.Errorf("Servers() 该给出配置里那几个上游: %v", r.Servers())
	}
}

// TestProbeTunnelPathFallsBackLikeLookup 锁住一件事：探测报的 Path 是**这次真的走了哪条**，
// 不是调用方要的那条。没注入隧道拨号器时等价于直连——那种状态如果照原样报 tunnel，
// 面板就会指着一份直连答案说"这是从节点那头问出来的"，
// 而这正是 §10.7 那条"视角不同答案不同"最容易被误读的地方。
func TestProbeTunnelPathFallsBackLikeLookup(t *testing.T) {
	srv := startFakeDNS(t, 0, net.ParseIP("1.1.1.1"))
	r := newTestResolver(t, []string{srv.Addr}, time.Minute)
	if r.tunnel.Load() != nil {
		t.Fatal("这个用例要的是「没注入隧道」的初始状态")
	}
	got, err := r.Probe(context.Background(), "no-tunnel.example", PathTunnel)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	// 没隧道时 lookup 走的就是直连那份实现，所以答案必须拿得出来；
	// 而 Path 这一格由调用方决定语义（service 那侧会照配置一起报），
	// 这里只断言它不会假装出门问了隧道。
	if len(got.Addrs) == 0 {
		t.Error("没注入隧道拨号器时探测应该退回直连结果，不该空手回来")
	}
	if got.Path != PathDirect {
		t.Errorf("实际走的是直连，Path 却报 %q——面板会指着一份本机答案说"+"\u201c这是从节点那头问来的\u201d", got.Path)
	}
}
