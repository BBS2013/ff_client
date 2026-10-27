package service

// 「看解析」这一格的判据。
//
// 这一格最容易写歪的地方与「取一个真页面」同一类：**问不出东西不是查询失败**。
// NXDOMAIN、上游被污染丢弃、超时——这些正是这一问的答案，
// 当 error 返回，界面上就只剩"查询失败"四个字，而人要看的是那批 IP 与归属码。
// 另外两条盯的是"面板看到的地址就是引擎拿去判定的那批"这条同源关系。

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wps_app/internal/dnstest"
	"wps_app/internal/logx"
)

// dnsEnv 起一份"上游就在回环上"的配置并启动服务。
//
// 为什么不在这里造解析器：这一格要验的就是**装配之后**那条路
// （服务自己建解析器、自己绑引擎、自己决定走直连还是隧道）。
// 手工塞一个 resolver 进去会让测试与真实装配脱钩。
func dnsEnv(t *testing.T, servers []string, rulesBody string) *Service {
	t.Helper()
	dir := t.TempDir()
	assets := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(assets, "rules.txt")
	if err := os.WriteFile(main, []byte(rulesBody), 0o644); err != nil {
		t.Fatal(err)
	}
	quoted := make([]string, len(servers))
	for i, s := range servers {
		quoted[i] = `"` + s + `"`
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	body := "proxies:\n" +
		"  - name: \"n1\"\n" +
		"    server: { addr: \"127.0.0.1:14499\", auth: \"x\" }\n" +
		"active: n1\nmode: rule\n" +
		"inbounds:\n  - { type: socks5, listen: \"127.0.0.1:0\" }\n" +
		"dns: { servers: [" + strings.Join(quoted, ", ") + "], timeout: 400ms, cache: 1m }\n" +
		"rules_file: \"" + main + "\"\nlog: { level: \"error\" }\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(cfgPath, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	return svc
}

func hasAddr(list []AddrView, want string) bool {
	for _, a := range list {
		if a.Addr == want {
			return true
		}
	}
	return false
}

func TestProbeDNSAnswersWithTheEnginesOwnView(t *testing.T) {
	fake := dnstest.Start(t, 0, net.ParseIP("10.0.0.5"))
	svc := dnsEnv(t, []string{fake.Addr}, "IP-CIDR,10.0.0.0/8,DIRECT\nFINAL,PROXY\n")

	got, err := svc.ProbeDNS(context.Background(), "  Internal.Example.  ", false, "")
	if err != nil {
		t.Fatalf("探测失败: %v (%+v)", err, got)
	}
	if got.Host != "internal.example" {
		t.Errorf("回显的名字没洗: %q", got.Host)
	}
	if !hasAddr(got.Addrs, "10.0.0.5") {
		t.Fatalf("没拿到上游回的那个地址: %+v", got.Addrs)
	}
	if got.Via != "direct" {
		t.Errorf("Via = %q，配置没开隧道解析时该是 direct", got.Via)
	}
	if got.TunnelOn {
		t.Error("TunnelOn 与配置不符")
	}
	if got.Cached {
		t.Error("第一次探测就报命中缓存，这一格是假的")
	}
	if got.IPPolicy != "DIRECT" || got.IPMatched != "IP-CIDR,10.0.0.0/8,DIRECT" {
		t.Errorf("只看这批 IP 的判定不对: %s/%q", got.IPPolicy, got.IPMatched)
	}
	// 域名那一段没有规则命中，所以引擎的完整判定就该等于 IP 那一段。
	// 两者分开报、但必须能互相对上——这一条断的就是"没有第二套判定"。
	if got.Policy != got.IPPolicy || got.Matched != got.IPMatched {
		t.Errorf("完整判定与 IP 段判定该一致（没有域名规则抢先）：%s/%q vs %s/%q",
			got.Policy, got.Matched, got.IPPolicy, got.IPMatched)
	}
	if len(got.Upstreams) != 1 || got.Upstreams[0] != fake.Addr {
		t.Errorf("上游列表没带回来: %v", got.Upstreams)
	}
	before := fake.Queries()

	second, err := svc.ProbeDNS(context.Background(), "internal.example", false, "")
	if err != nil {
		t.Fatalf("第二次探测失败: %v", err)
	}
	if !second.Cached {
		t.Errorf("问过两次之后还不报命中缓存，这一格的缓存读数是假的")
	}
	// 上游查询数**会**再涨：挨个问一遍那部分（perUpstream）是刻意每次都出门的，
	// 它问的就是"每个上游此刻怎么说"，拿缓存里那份合并答案回答就是答非所问。
	// 所以这里断的是合并那一份没再出门（上面 Cached 已断），而不是"总数不变"。
	if fake.Queries() <= before {
		t.Errorf("逐上游那一份看起来没真的去问：%d -> %d", before, fake.Queries())
	}
}

// TestProbeDNSFreshReplacesWhatTheEngineWillUse 量的不是"能不能重问"，
// 而是重问**改掉了什么**——三句都得有：
//   - 不重问时，这一格端出来的是旧地址，而且判定跟着旧地址走
//     （这一句是这一按的存在理由：判定不是错的，它是照着一份过期数据算对的）；
//   - 重问那一下把新地址换了上来，判定**跟着翻**（DIRECT → PROXY）；
//   - 重问之后再看一眼（fresh=false），拿到的还是新地址——缓存被写回了。
//
// 第三句才是这一按与"我只是又看了一眼"的分界。少了它，脏的那份仍在，
// 引擎下一秒照旧判 DIRECT，而屏幕上刚闪过一句"已重问"。
//
// 另外盯一条 `Used`：旧答案那一次它必须是空串（合并结果对不上任何上游此刻的回答，
// 那就是"说不清"，实现里不许硬指一个）；重问之后它该指得出是谁给的。
func TestProbeDNSFreshReplacesWhatTheEngineWillUse(t *testing.T) {
	a := dnstest.Start(t, 0, net.ParseIP("10.0.0.5"))
	b := dnstest.Start(t, 0, net.ParseIP("10.0.0.5"))
	svc := dnsEnv(t, []string{a.Addr, b.Addr},
		"IP-CIDR,10.0.0.0/8,DIRECT\nIP-CIDR,104.16.0.0/16,PROXY\nFINAL,PROXY\n")
	ctx := context.Background()

	if _, err := svc.ProbeDNS(ctx, "stale.example", false, ""); err != nil {
		t.Fatalf("先把缓存灌满: %v", err)
	}
	// 上游改口：真实世界里这就是"换 CDN / 被污染 / TTL 还没到"那一下。
	a.SetIP(net.ParseIP("104.16.1.1"))
	b.SetIP(net.ParseIP("104.16.1.1"))

	cached, err := svc.ProbeDNS(ctx, "stale.example", false, "")
	if err != nil {
		t.Fatalf("ProbeDNS(缓存): %v", err)
	}
	if !cached.Cached || cached.Fresh {
		t.Fatalf("这一眼该是"+"\u201c缓存里那份\u201d，拿到 cached=%v fresh=%v", cached.Cached, cached.Fresh)
	}
	if !hasAddr(cached.Addrs, "10.0.0.5") {
		t.Fatalf("测试前提不成立：缓存没把旧地址端出来（%+v）", cached.Addrs)
	}
	if cached.IPPolicy != "DIRECT" {
		t.Fatalf("判定没跟着旧地址走：%s/%q", cached.IPPolicy, cached.IPMatched)
	}
	if cached.TtlMs <= 0 {
		t.Errorf("报"+"\u201c命中缓存\u201d却没说还剩多久（%dms），界面那一格只能空着", cached.TtlMs)
	}
	if cached.Used != "" {
		t.Errorf("合并那份是缓存里的旧地址，对不上任何上游此刻的回答，Used 却指了 %q——说不清就该空着", cached.Used)
	}

	fresh, err := svc.ProbeDNS(ctx, "stale.example", true, "")
	if err != nil {
		t.Fatalf("ProbeDNS(重问): %v", err)
	}
	if !fresh.Fresh {
		t.Error("重问那一次没把 Fresh 带回来，界面就无法说明这一按改了状态")
	}
	if fresh.Cached {
		t.Error("重问还报命中缓存，那这一按到底跳过了什么")
	}
	if !hasAddr(fresh.Addrs, "104.16.1.1") {
		t.Fatalf("重问拿到的还是旧地址: %+v", fresh.Addrs)
	}
	if fresh.IPPolicy != "PROXY" {
		t.Errorf("换成新地址后判定该翻成 PROXY，拿到 %s/%q", fresh.IPPolicy, fresh.IPMatched)
	}
	if fresh.Used == "" {
		t.Error("重问之后仍然指不出这份答案是谁给的——它明明就是刚问出来的")
	}

	after, err := svc.ProbeDNS(ctx, "stale.example", false, "")
	if err != nil {
		t.Fatalf("ProbeDNS(重问后): %v", err)
	}
	if !after.Cached {
		t.Error("重问的结果没写回缓存：这一按只看了一眼，脏的那份还在")
	}
	if !hasAddr(after.Addrs, "104.16.1.1") || after.IPPolicy != "PROXY" {
		t.Errorf("引擎下一刻拿到的还是旧那批: %+v → %s", after.Addrs, after.IPPolicy)
	}
	if after.Fresh {
		t.Error("这一眼不是重问，Fresh 不该为真")
	}
}

// TestProbeDNSDomainRuleWins 是这一格最有信息量的那一档：
// 域名规则先命中时，DNS 根本没参与这次结论。两半分开报，
// 人才能看出"IP 是海外地址但流量还是走代理"不是矛盾。
func TestProbeDNSDomainRuleWins(t *testing.T) {
	fake := dnstest.Start(t, 0, net.ParseIP("203.0.113.9"))
	svc := dnsEnv(t, []string{fake.Addr}, "DOMAIN-SUFFIX,example,PROXY\nIP-CIDR,10.0.0.0/8,DIRECT\nFINAL,DIRECT\n")

	got, err := svc.ProbeDNS(context.Background(), "a.example", false, "")
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if got.Policy != "PROXY" || got.Matched != "DOMAIN-SUFFIX,example,PROXY" {
		t.Errorf("引擎的完整判定没走域名规则: %s/%q", got.Policy, got.Matched)
	}
	if got.IPPolicy != "DIRECT" || got.IPMatched != "FINAL" {
		t.Errorf("只看这批 IP 应该落到 FINAL/DIRECT（这是海外地址）: %s/%q", got.IPPolicy, got.IPMatched)
	}
	if got.Policy == got.IPPolicy {
		t.Error("这一档要演示的就是两半会不一致；两者相同说明用例前提没成立")
	}
}

// TestProbeDNSNoAnswerIsAnAnswer：问不出东西时不许报 error。
func TestProbeDNSNoAnswerIsAnAnswer(t *testing.T) {
	// 占一个端口再关掉：回环上没人应答，400ms 超时后就是"问不出"。
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := conn.LocalAddr().String()
	_ = conn.Close()

	svc := dnsEnv(t, []string{dead}, "DOMAIN-SUFFIX,keep.example,PROXY\nFINAL,PROXY\n")
	got, err := svc.ProbeDNS(context.Background(), "nothing.example", false, "")
	if err != nil {
		t.Fatalf("解析不出是答案不是失败，却当错误返回了: %v", err)
	}
	if len(got.Addrs) != 0 {
		t.Errorf("上游死了却还报出地址: %+v", got.Addrs)
	}
	if !strings.Contains(got.Note, "没问到地址") {
		t.Errorf("空表必须带一句为什么，否则会被读成\"这个域名没有地址\": %q", got.Note)
	}
}

// TestProbeDNSShowsUpstreamSplit 是这一格存在的理由里最硬的那一档：
// 两个上游对同一个名字给出不同地址（污染就是这个形状）。
// 合并那份答案只会留下先回来的一个，而人想知道的是"谁在说谎、引擎用的是谁"。
func TestProbeDNSShowsUpstreamSplit(t *testing.T) {
	fa := dnstest.Start(t, 0, net.ParseIP("93.184.216.34"))
	fb := dnstest.Start(t, 0, net.ParseIP("127.0.0.1"))
	a, b := fa.Addr, fb.Addr
	svc := dnsEnv(t, []string{a, b}, "IP-CIDR,127.0.0.0/8,DIRECT\nFINAL,PROXY\n")

	got, err := svc.ProbeDNS(context.Background(), "split.example", false, "")
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if len(got.PerUpstream) != 2 {
		t.Fatalf("两个上游该给两条答案: %+v", got.PerUpstream)
	}
	if !got.Divergent {
		t.Errorf("两个上游给了不同地址，却没报分叉: %+v", got.PerUpstream)
	}
	// 引擎那份合并答案必须能与其中一个上游对上——对不上就是这里在猜。
	if got.Used != a && got.Used != b {
		t.Errorf("Used=%q，既不是 %q 也不是 %q", got.Used, a, b)
	}
	// 分叉时两半判定会不一样：127.0.0.1 命中那条 /8 直连，公网地址落到兜底。
	var sawDirect, sawProxy bool
	for _, u := range got.PerUpstream {
		switch u.Policy {
		case "DIRECT":
			sawDirect = true
		case "PROXY":
			sawProxy = true
		}
	}
	if !sawDirect || !sawProxy {
		t.Errorf("两个上游该一个判直连一个判代理，实际 %+v", got.PerUpstream)
	}
}

// TestProbeDNSNoFalseDivergence 断的是反向那一半：一个上游回两条地址
// 不是分叉。把这条写死是因为"出现过的地址数 > 1"那种偷懒判据
// 会把正常的多出口天天报成污染。
func TestProbeDNSNoFalseDivergence(t *testing.T) {
	one := dnstest.Start(t, 0, net.ParseIP("93.184.216.34"))
	svc := dnsEnv(t, []string{one.Addr}, "DOMAIN-SUFFIX,keep.example,PROXY\nFINAL,PROXY\n")
	got, err := svc.ProbeDNS(context.Background(), "single.example", false, "")
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if got.Divergent {
		t.Errorf("只有一个上游也报分叉: %+v", got.PerUpstream)
	}
	if got.Used != "" {
		t.Errorf("只有一个上游时不该指认是谁给的（那是废话）: %q", got.Used)
	}
}

func TestProbeDNSRefusesWhatItCannotAsk(t *testing.T) {
	fake := dnstest.Start(t, 0, net.ParseIP("10.0.0.5"))
	svc := dnsEnv(t, []string{fake.Addr}, "DOMAIN-SUFFIX,keep.example,PROXY\nFINAL,PROXY\n")
	if _, err := svc.ProbeDNS(context.Background(), "   ", false, ""); err == nil ||
		!strings.Contains(err.Error(), "先填一个域名") {
		t.Errorf("空输入该拒: %v", err)
	}
	// IP 字面量是合法输入（引擎也会照 IP 规则判它），不该被当成"不是域名"弹回去。
	got, err := svc.ProbeDNS(context.Background(), "10.0.0.7", false, "")
	if err != nil {
		t.Fatalf("IP 字面量该答出来: %v", err)
	}
	if !hasAddr(got.Addrs, "10.0.0.7") || got.IPPolicy != "PROXY" {
		t.Errorf("IP 字面量答错了: %+v / %s", got.Addrs, got.IPPolicy)
	}

	// 停着的时候不答：那套解析器根本没起来。
	off := New(filepath.Join(t.TempDir(), "config.yaml"), nil)
	if _, err := off.ProbeDNS(context.Background(), "example.com", false, ""); err == nil ||
		!strings.Contains(err.Error(), "没在跑") {
		t.Errorf("停着的时候这一格该拒绝: %v", err)
	}
}

// TestProbeDNSWithSlowUpstream：上游比配置里的超时更慢时，
// 这一格要报"问不出"，而不是挂着或者报成查询失败。
//
// 这里刻意不断言"150ms 就返回"：解析器为了共享同一次查询，
// 故意把出门那一段挂在 context.WithoutCancel 上（见 dnsx.lookup 那段注释），
// 所以真正决定等待时间的是配置里的 timeout（这份配置给的是 400ms）。
// 断 150ms 会红，而红的原因是设计如此——那种断言只会教人去看错地方。
func TestProbeDNSWithSlowUpstream(t *testing.T) {
	fake := dnstest.Start(t, 2*time.Second, net.ParseIP("10.0.0.5"))
	svc := dnsEnv(t, []string{fake.Addr}, "DOMAIN-SUFFIX,keep.example,PROXY\nFINAL,PROXY\n")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	got, err := svc.ProbeDNS(ctx, "slow.example", false, "")
	spent := time.Since(start)
	if err != nil {
		t.Fatalf("探测失败: %v", err)
	}
	if spent > 1200*time.Millisecond {
		t.Errorf("等了 %v——ctx 只给了 150ms（配置里那份超时是 400ms）", spent.Round(10*time.Millisecond))
	}
	if len(got.Addrs) != 0 || !strings.Contains(got.Note, "没问到地址") {
		t.Errorf("上游 2 秒才回，这一格该报问不出: %+v / %q", got.Addrs, got.Note)
	}
}

// TestProbeDNSRefreshedUpstreamWinsTheCache 是「只重问这一家」的语义：
//   - 引擎读到的是**被点名那一家**刚给的答案，不是"任一成功即采用"碰运气碰到的那份；
//   - 刷完再看一眼（三个开关都关）读到的还是这一家的——它已经留在缓存里了。
//
// 第二条最要紧：这一按之后**不能**再走合并那一路，否则另一个上游（往往正是被怀疑的那一个）
// 会把刚写回的又盖掉，那一按就成了"刷了等于没刷"。
// 这里不断言"没被点名的那一家一个包都没收到"——卡片末尾那一列（每个上游此刻怎么说）
// 本来就要挨个问一遍，那是显示用的另一轮，与刷新写回的是两回事。
// "只问被点名的那一家"这条断在 dnsx 那一层（TestProbeEachRefreshAsksOnlyWhatItIsPointedAt）。
func TestProbeDNSRefreshedUpstreamWinsTheCache(t *testing.T) {
	good := dnstest.Start(t, 0, net.ParseIP("93.184.216.34"))
	polluted := dnstest.Start(t, 0, net.ParseIP("127.0.0.1"))
	svc := dnsEnv(t, []string{polluted.Addr, good.Addr},
		"IP-CIDR,127.0.0.0/8,DIRECT\nIP-CIDR,93.184.0.0/16,PROXY\nFINAL,PROXY\n")
	ctx := context.Background()

	if _, err := svc.ProbeDNS(ctx, "split.example", false, ""); err != nil {
		t.Fatalf("先问一眼: %v", err)
	}
	got, err := svc.ProbeDNS(ctx, "split.example", false, good.Addr)
	if err != nil {
		t.Fatalf("点名重问: %v", err)
	}
	if !got.Fresh || got.Refreshed != good.Addr {
		t.Errorf("刷新这件事没带回来: fresh=%v refreshed=%q", got.Fresh, got.Refreshed)
	}
	if !hasAddr(got.Addrs, "93.184.216.34") {
		t.Fatalf("点名了干净那家，读到的却不是它的地址: %+v", got.Addrs)
	}
	if got.IPPolicy != "PROXY" {
		t.Errorf("地址换了判定却没跟着换: %s/%q", got.IPPolicy, got.IPMatched)
	}
	if got.Used != good.Addr {
		t.Errorf("这份答案就来自被点名那家，Used 却写着 %q", got.Used)
	}

	again, err := svc.ProbeDNS(ctx, "split.example", false, "")
	if err != nil {
		t.Fatalf("刷完再看一眼: %v", err)
	}
	if !again.Cached || !hasAddr(again.Addrs, "93.184.216.34") {
		t.Errorf("点名重问的结果没留在缓存里: cached=%v addrs=%+v", again.Cached, again.Addrs)
	}
	if again.Fresh || again.Refreshed != "" {
		t.Errorf("这一眼只是查看，却报 fresh=%v refreshed=%q", again.Fresh, again.Refreshed)
	}
}

// TestProbeDNSRefreshedReportsAnUnknownUpstream：点名的那一家不在配置里时，
// 这一按是**没办成**，要报 error，不能悄悄退回"那就整条重来"。
func TestProbeDNSRefreshedReportsAnUnknownUpstream(t *testing.T) {
	fake := dnstest.Start(t, 0, net.ParseIP("93.184.216.34"))
	svc := dnsEnv(t, []string{fake.Addr}, "IP-CIDR,93.184.0.0/16,PROXY\nFINAL,PROXY\n")
	_, err := svc.ProbeDNS(context.Background(), "a.example", false, "127.0.0.1:53998")
	if err == nil {
		t.Fatal("点名了一个配置里没有的上游，这一按居然算成功")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:53998") {
		t.Errorf("错误里没说是哪一家没刷成: %v", err)
	}
}

// TestProbeDNSRefreshIsWhatGetsLogged 盯的是"改了状态的动作得留痕"这一条，
// 以及它的**反面**：看一眼不许留痕。
//
// 为什么反面更要紧：解析这件事每秒都在发生（连接要建立，引擎自己就会问），
// 把"看一眼"也记进去，日志就被刷成噪音，而这一行的全部用途是
// "事后说得清这批地址是谁在什么时候换进来的"。
func TestProbeDNSRefreshIsWhatGetsLogged(t *testing.T) {
	fake := dnstest.Start(t, 0, net.ParseIP("93.184.216.34"))
	svc := dnsEnv(t, []string{fake.Addr}, "IP-CIDR,93.184.0.0/16,PROXY\nFINAL,PROXY\n")
	ctx := context.Background()

	// 那份测试配置写的是 log.level=error，而"手动重问"是 INFO：不抬级别钩子一条也收不到，
	// 用例会以"记了 0 条"失败——看着像功能坏了，其实是被级别门掉了。
	logx.SetLevel(logx.LevelInfo)
	t.Cleanup(func() { logx.SetLevel(logx.LevelInfo) })

	var mu sync.Mutex
	var lines []string
	remove := logx.AddHook(func(_ logx.Level, msg string, _ time.Time) {
		if strings.Contains(msg, "手动重问") {
			mu.Lock()
			lines = append(lines, msg)
			mu.Unlock()
		}
	})
	defer remove()
	seen := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
	reset := func() {
		mu.Lock()
		lines = nil
		mu.Unlock()
	}

	if _, err := svc.ProbeDNS(ctx, "log.example", false, ""); err != nil {
		t.Fatalf("看一眼: %v", err)
	}
	if got := seen(); len(got) != 0 {
		t.Errorf("普通「看一眼」也记了日志：%v——那一问每秒都在发生，记下来就把日志刷成噪音了", got)
	}

	if _, err := svc.ProbeDNS(ctx, "log.example", true, ""); err != nil {
		t.Fatalf("整条重问: %v", err)
	}
	got := seen()
	if len(got) != 1 {
		t.Fatalf("整条重问该记恰好一条，拿到 %d 条: %v", len(got), got)
	}
	for _, want := range []string{"log.example", "整条路径", "93.184.216.34", "写回"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("那一行里缺 %q：%s", want, got[0])
		}
	}
	reset()

	if _, err := svc.ProbeDNS(ctx, "log.example", false, fake.Addr); err != nil {
		t.Fatalf("只刷一家: %v", err)
	}
	got = seen()
	if len(got) != 1 {
		t.Fatalf("点名重问该记恰好一条，拿到 %d 条: %v", len(got), got)
	}
	if !strings.Contains(got[0], "只问 "+fake.Addr) {
		t.Errorf("那一行没说是哪一家被刷了：%s", got[0])
	}
	reset()

	// 点名了一个配置里没有的上游：这一按**没办成**，也得留一条（而且不能写成成功）。
	if _, err := svc.ProbeDNS(ctx, "log.example", false, "127.0.0.1:53997"); err == nil {
		t.Fatal("点名陌生上游该报错")
	}
	got = seen()
	if len(got) != 1 || !strings.Contains(got[0], "没成功") {
		t.Errorf("失败那一按没留下说得清的一条：%v", got)
	}
}
