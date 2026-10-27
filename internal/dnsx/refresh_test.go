package dnsx

// 「只重问这一个上游」那一按的判据。
//
// 这一组不测"能不能解析"，测的是界面上那句话承诺的三件事，每一件都比"能问"容易写错：
//   1. 按下去**当场**就能看到新值——引擎那条路不许还端旧的那份；
//   2. 只刷点名的那一个：别一个都不许多问（否则"只刷这一个"是句假话）；
//   3. 不许顺手清全局：别的域名的缓存条目必须原样留着。
//
// 第 2、3 条是这一按与"把缓存整个丢掉"的分界。后者三行就能写完、看起来也正确，
// 后果是一按之后所有域名的解析都慢一轮，而屏幕上只写着"已刷新"。
// 还有第四件容易混的：这一按是**换成新的**，不是**删掉条目等下一次重新问**——
// 这两种写法都能让上面第 1 条通过，所以那里单独补了一句"缓存里现在得有东西"。

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// settle 等在途的查询都落进计数里再回来。
//
// 合并那一路是"任一成功即采用"：先回来的那台答了，`LookupIP` 就返回了，
// 另一台的包可能还在半路上。这时候取基线会少算一条，
// 于是"恰好多问一次"那条断言凭空多数一次——实测红过一次的 0 -> 2 就是这么来的
// （基线取到 a=0，实际上 a 那一问只是晚落地）。
// 连续两轮计数不变才算停，最多等 400ms：真停不下来就是解析器在背后自己反复问，
// 那这一档的前提已经不成立，直接红在这里比后面报一笔假账有用。
func settle(t *testing.T, srvs ...*fakeDNS) {
	t.Helper()
	prev := -1
	for i := 0; i < 20; i++ {
		n := 0
		for _, s := range srvs {
			n += s.Queries()
		}
		if n == prev && i > 0 {
			return
		}
		prev = n
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等了 400ms，%d 台上游的查询数还在变，取不到稳定基线", len(srvs))
}

// askedCount 是某个上游收到过几条**针对这个名字的 A 查询**。
// 判据落在这一层而不是"总包数"：总包数会被 search 后缀、EDNS 那些无关因素带偏。
//
// 三个坑都在这函数里，而且都是哑的：
//   - 名字要补尾点——上游记的是线格式里带尾点那一份；
//   - 记录里的类型串是 `TypeA`（dnsmessage.Type 的 String），不是 `A`；
//   - 一次解析会并行问 A 与 AAAA，按前缀数就变成"每轮两问"，"+1"那条断言会当场红得莫名其妙。
//
// 少任何一条，这个函数要么恒返回 0、要么把每一轮数成两轮。前者会让增量断言
// 变成 0 -> 0 直接红（好在红得干脆），后者会把"只多问一次"写成"多问了两次"。
func askedCount(t *testing.T, srv *fakeDNS, name string) int {
	t.Helper()
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return srv.Questions()[name+"/TypeA"]
}

func TestProbeEachRefreshSeenByEngineImmediately(t *testing.T) {
	fake := startFakeDNS(t, 0, net.ParseIP("1.1.1.1"))
	r := newTestResolver(t, []string{fake.Addr}, time.Hour)
	ctx := context.Background()

	if _, err := r.LookupIP(ctx, "refresh.example"); err != nil {
		t.Fatalf("先把缓存灌满: %v", err)
	}
	fake.SetIP(net.ParseIP("2.2.2.2"))

	// 这一句是"为什么需要这个按钮"的证据：引擎那条路还在端旧答案。
	// 它要是当场就自己换了，这一按就没有存在的理由，测试也白写。
	addrs, err := r.LookupIP(ctx, "refresh.example")
	if err != nil {
		t.Fatalf("LookupIP: %v", err)
	}
	if len(addrs) == 0 || addrs[0].String() != "1.1.1.1" {
		t.Fatalf("测试前提不成立：缓存没把旧答案留住（拿到 %v），这一档要量的东西就不存在", addrs)
	}

	got := r.ProbeEachRefresh(ctx, "refresh.example", PathDirect, []string{fake.Addr})
	if len(got) != 1 {
		t.Fatalf("点名一个上游就该回一条，拿到 %d 条", len(got))
	}
	if got[0].Err != "" {
		t.Fatalf("被点名的上游就在配置里，却报了错: %s", got[0].Err)
	}
	if len(got[0].Addrs) == 0 || got[0].Addrs[0].String() != "2.2.2.2" {
		t.Fatalf("重问回来的不是上游现在给的答案: %v", got[0].Addrs)
	}

	// 承诺的那一句：按下去之后引擎立刻用新的。
	now, err := r.LookupIP(ctx, "refresh.example")
	if err != nil {
		t.Fatalf("LookupIP(刷新后): %v", err)
	}
	if len(now) == 0 || now[0].String() != "2.2.2.2" {
		t.Fatalf("刷完了引擎还在拿旧地址判定: %v——那一按只是看了一眼，等于没修", now)
	}
	// 而且它是**缓存里的一份新答案**，不是"把条目删掉等下一次出门"：
	// 上面两行删条目那种写法也能过，但下一眼就得再等一次网络往返，
	// 而这一格要避免的正是"过一会儿才生效"。
	probe, err := r.Probe(ctx, "refresh.example", PathDirect)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !probe.Cached {
		t.Error("这一按该是「换成新的」，结果缓存里没留下条目（下一次还得重新出门问）")
	}
	if probe.TtlMs <= 0 {
		t.Errorf("刚写回去的那份该带一整条 TTL，拿到 %dms", probe.TtlMs)
	}
}

func TestProbeEachRefreshAsksOnlyWhatItIsPointedAt(t *testing.T) {
	a := startFakeDNS(t, 0, net.ParseIP("1.1.1.1"))
	b := startFakeDNS(t, 0, net.ParseIP("1.1.1.1"))
	r := newTestResolver(t, []string{a.Addr, b.Addr}, time.Hour)
	ctx := context.Background()

	// 灌两条进缓存：一条要被刷，另一条是用来验证"不许顺手清全局"的证人。
	if _, err := r.LookupIP(ctx, "keep.example"); err != nil {
		t.Fatalf("LookupIP(keep): %v", err)
	}
	if _, err := r.LookupIP(ctx, "refresh.example"); err != nil {
		t.Fatalf("LookupIP(refresh): %v", err)
	}
	settle(t, a, b)
	a.SetIP(net.ParseIP("2.2.2.2"))
	b.SetIP(net.ParseIP("3.3.3.3"))

	// 灌缓存那两轮由"任一成功即采用"决定谁先答，两台的账都要拿下来当基线。
	// 必须用**增量**而不是绝对值：拿"a 应该被问过 refresh"当前提的话，
	// 这一档会在 b 恰好先回来的那些运行里静默失效（断言全过、量的却是零笔账）。
	aRefresh, aKeep := askedCount(t, a, "refresh.example"), askedCount(t, a, "keep.example")
	bRefresh, bKeep := askedCount(t, b, "refresh.example"), askedCount(t, b, "keep.example")
	bTotal := b.Queries()
	if aRefresh+bRefresh == 0 || aKeep+bKeep == 0 {
		t.Fatalf("测试前提不成立：两条域名一条都没被真的问过（a %d/%d b %d/%d）",
			aRefresh, aKeep, bRefresh, bKeep)
	}

	got := r.ProbeEachRefresh(ctx, "refresh.example", PathDirect, []string{a.Addr})
	if len(got) != 1 || got[0].Server != a.Addr {
		t.Fatalf("只点名 a 就该只回 a 那一条: %+v", got)
	}
	if got[0].Err != "" || len(got[0].Addrs) == 0 || got[0].Addrs[0].String() != "2.2.2.2" {
		t.Fatalf("点名的那台该回它此刻的答案: %+v", got[0])
	}
	// 只多发针对 refresh.example 的那一条查询。
	if n := askedCount(t, a, "refresh.example"); n != aRefresh+1 {
		t.Errorf("点名的那条该被多问恰好一次：%d -> %d", aRefresh, n)
	}
	if n := askedCount(t, a, "keep.example"); n != aKeep {
		t.Errorf("刷 refresh 却把同一台上游的 keep 也拖去重问了：%d -> %d", aKeep, n)
	}
	// 点名 a 之后，"缓存里那份"该换成 a 的答案——这一句是这一按与"只看不写"的分界。
	seen, err := r.LookupIP(ctx, "refresh.example")
	if err != nil {
		t.Fatalf("LookupIP(刷新后): %v", err)
	}
	if len(seen) == 0 || seen[0].String() != "2.2.2.2" {
		t.Errorf("点名 a 刷完，引擎拿到的却不是 a 的答案: %v", seen)
	}
	// 没点名的那台上游一个包都不该多收到。
	if n := b.Queries(); n != bTotal {
		t.Errorf("没点名的上游 %s 被多问了：%d -> %d——「只刷这一个」是句假话", b.Addr, bTotal, n)
	}
	// 证人：keep.example 那份必须还是缓存命中。
	keep, err := r.Probe(ctx, "keep.example", PathDirect)
	if err != nil {
		t.Fatalf("Probe(keep): %v", err)
	}
	if !keep.Cached {
		t.Error("只刷一条域名却把整个缓存清了：这一按的代价被藏起来了")
	}
}

// TestProbeEachRefreshRefusesWhatIsNotConfigured：名单为空、或指名了一个不在配置里的上游时，
// 不许退化成"那就全部问一遍"。那是把人没做的事替他做了。
func TestProbeEachRefreshRefusesWhatIsNotConfigured(t *testing.T) {
	fake := startFakeDNS(t, 0, net.ParseIP("1.1.1.1"))
	r := newTestResolver(t, []string{fake.Addr}, time.Hour)
	ctx := context.Background()
	if _, err := r.LookupIP(ctx, "example"); err != nil {
		t.Fatalf("灌缓存: %v", err)
	}
	base := fake.Queries()

	if got := r.ProbeEachRefresh(ctx, "example", PathDirect, nil); len(got) != 0 {
		t.Errorf("没点名任何上游却回了 %d 条答案", len(got))
	}
	unknown := "127.0.0.1:53999"
	got := r.ProbeEachRefresh(ctx, "example", PathDirect, []string{unknown})
	if len(got) != 1 || got[0].Server != unknown {
		t.Fatalf("指名的那个上游该原样报回来，哪怕结论是「不在配置里」: %+v", got)
	}
	if got[0].Err == "" {
		t.Errorf("一个不在配置里的上游被当成刷成功了: %+v", got[0])
	}
	if fake.Queries() != base {
		t.Errorf("只指名了一个陌生上游，配置里那台却被问了 %d -> %d 次（退化成全刷了）",
			base, fake.Queries())
	}
}

// TestProbeEachRefreshKeepsLiteralAndTunnelRules 把两条与 Probe 共用的规矩再钉一遍：
// IP 字面量不出门、没注入隧道时按直连那份写。写丢任一条都会让这一按
// 在界面上给出一个"看着刷新了、其实动的是另一条路径"的读数。
func TestProbeEachRefreshKeepsLiteralAndTunnelRules(t *testing.T) {
	fake := startFakeDNS(t, 0, net.ParseIP("1.1.1.1"))
	r := newTestResolver(t, []string{fake.Addr}, time.Hour)
	ctx := context.Background()

	got := r.ProbeEachRefresh(ctx, "10.0.0.9", PathDirect, []string{fake.Addr})
	if len(got) != 1 || len(got[0].Addrs) != 1 || got[0].Addrs[0].String() != "10.0.0.9" {
		t.Errorf("IP 字面量该原样答: %+v", got)
	}
	if n := fake.Queries(); n != 0 {
		t.Errorf("对 IP 字面量出门问了上游，%d 条", n)
	}

	// 要隧道但没注入拨号器：得按直连那份写回，否则刷的是 A 键、引擎读的是 B 键。
	if got := r.ProbeEachRefresh(ctx, "tunnel.example", PathTunnel, []string{fake.Addr}); len(got) != 1 ||
		got[0].Err != "" {
		t.Fatalf("没注入隧道时这一按该退回直连并成功: %+v", got)
	}
	probe, err := r.Probe(ctx, "tunnel.example", PathDirect)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !probe.Cached {
		t.Error("这一按写回的键与引擎读的键不是同一个（直连那份里没有条目）")
	}
}
