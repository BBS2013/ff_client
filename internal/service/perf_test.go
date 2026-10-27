package service

import (
	"sort"
	"testing"
	"time"

	"wps_app/internal/config"
)

// 这个文件把「无卡顿」翻译成两个可回归的数：
//
//	节点选用/切换 P95 < 1s
//	面板 API      P95 < 200ms
//
// 为什么是 P95 而不是均值或单次：面板每秒轮询一次状态，单次耗时再好看也
// 掩盖不了偶尔一次的长尾——而长尾恰恰就是用户看到的「卡了一下」。
// switch_test.go 里那条 500ms 的断言管的是单次，这里管分布。
//
// 全部在回环上跑，不依赖任何真实节点：换节点的代价是「重建出站 + 换指针」，
// 与节点在哪无关（见 TestSetActiveProfileSwapsOutboundOnly）。

// pct 返回采样里第 q 分位。用最近秩而不是插值：我们要的是
// 「从多少开始」，一个真实发生过的观测值比插出来的数字更有意义。
func pct(d []time.Duration, q float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	idx := int(float64(len(s))*q+0.999999) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func p95(d []time.Duration) time.Duration { return pct(d, 0.95) }

// p50 是倍率类断言该用的那一个：中位数对"别人正好在这时抢了 CPU"不敏感，
// 而 p95 会把一次抢占直接读成性能回归。
func p50(d []time.Duration) time.Duration { return pct(d, 0.5) }

func report(t *testing.T, name string, d []time.Duration, budget time.Duration) {
	t.Helper()
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	var sum time.Duration
	for _, v := range s {
		sum += v
	}
	avg := sum / time.Duration(len(s))
	t.Logf("%-28s n=%d  p50=%-10v p95=%-10v max=%-10v avg=%v  预算 %v",
		name, len(s), s[len(s)/2], p95(s), s[len(s)-1], avg, budget)
	if got := p95(s); got > budget {
		t.Errorf("%s 的 P95 是 %v，超过预算 %v", name, got, budget)
	}
}

// TestPanelAPIP95 覆盖面板每秒都会调的那几个只读方法。
//
// 它们全部走 diskConfig 的 mtime+size 缓存，所以这里顺带钉住了缓存没被
// 「优化」成每次都读盘——真那样改的话 P95 会直接跳到毫秒级以上。
func TestPanelAPIP95(t *testing.T) {
	svc := New(twoProfileConfig(t), nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop()

	const n = 300
	// 预热：第一次调用要真读一次盘，不能算进 P95。
	for i := 0; i < 20; i++ {
		_ = svc.Snapshot()
	}

	snapshot := make([]time.Duration, 0, n)
	profiles := make([]time.Duration, 0, n)
	mode := make([]time.Duration, 0, n)
	tun := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		_ = svc.Snapshot()
		snapshot = append(snapshot, time.Since(t0))

		t0 = time.Now()
		if _, _, err := svc.Profiles(); err != nil {
			t.Fatalf("Profiles: %v", err)
		}
		profiles = append(profiles, time.Since(t0))

		t0 = time.Now()
		_ = svc.Mode()
		mode = append(mode, time.Since(t0))

		t0 = time.Now()
		_ = svc.TUNStatus()
		tun = append(tun, time.Since(t0))
	}

	const budget = 200 * time.Millisecond
	report(t, "面板 Snapshot", snapshot, budget)
	report(t, "面板 Profiles", profiles, budget)
	report(t, "面板 Mode", mode, budget)
	report(t, "面板 TUNStatus", tun, budget)
}

// TestProfileSwitchP95 量「点选用」这一下的耗时分布。
//
// 两个节点来回切，每次都真写一次配置文件并重建出站——走的是面板按钮的同一条路径。
func TestProfileSwitchP95(t *testing.T) {
	svc := New(twoProfileConfig(t), nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop()

	const n = 40
	names := []string{"b-trojan", "a-hy2"}
	d := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		want := names[i%2]
		t0 := time.Now()
		if err := svc.SetActiveProfile(want); err != nil {
			t.Fatalf("SetActiveProfile(%s): %v", want, err)
		}
		d = append(d, time.Since(t0))
		if got := svc.Snapshot().ActiveProfile; got != want {
			t.Fatalf("第 %d 次切换后 active = %q, want %q", i, got, want)
		}
	}
	report(t, "节点选用/切换", d, time.Second)
}

// TestRulesPanelReadsP95 规则页那两栏（自动重载 / 订阅）是每 5 秒轮询一次的，
// 它们各自都要碰磁盘：前者 stat 引擎打开过的每个文件，后者在没跑时还要读一份配置。
//
// 单独一条而不是塞进 TestPanelAPIP95：那几个是每秒轮询的只读方法，
// 预算的来由不一样；这里要钉住的是"别把它们做成每次去解析整个规则集"。
func TestRulesPanelReadsP95(t *testing.T) {
	cfgPath := twoProfileConfig(t)
	svc := New(cfgPath, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	const n = 200
	running := make([]time.Duration, 0, n)
	subsLive := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		_ = svc.RulesWatchView()
		running = append(running, time.Since(t0))

		t0 = time.Now()
		_ = svc.Subscriptions()
		subsLive = append(subsLive, time.Since(t0))
	}
	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// 停下来之后那一栏还在被轮询（面板不会因为它没在跑就不问），
	// 这条路径要读配置，所以单独量。
	stopped := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		_ = svc.Subscriptions()
		stopped = append(stopped, time.Since(t0))
	}

	const budget = 200 * time.Millisecond
	report(t, "规则页 RulesWatchView", running, budget)
	report(t, "规则页 Subscriptions(跑)", subsLive, budget)
	report(t, "规则页 Subscriptions(停)", stopped, budget)
}

// TestRulesPanelBlocklistP95 把"停着的时候问一次拦截名单有多贵"变成常驻断言。
//
// 这一格真的退化过一次：拦截名单当年是绕道建一个引擎来拿归一化写法的，
// 于是面板每五秒把整份 GFW 规则集重新解析一遍（实测 0.25ms → 2.3ms 一档白扔）。
// 用仓库自带的真实规则集而不是三行玩具规则是这条用例有意义的前提——
// 规则集只有三行时，"每次都重编译"和"根本不编译"量出来是一样的，
// 预算拦不住任何东西（所以找不到规则集时宁可 Skip，也不假装通过）。
//
// **断的是倍率，不是绝对毫秒数。** 这台机器上随时可能同时跑着另一个
// `go test ./...`（同一个 checkout 有第二个写入者），绝对时延在 contention 下
// 能翻好几倍——那种红是随机的，而随机红的用例活不过第二次。
// 倍率就不怕这个：基准和受测项被同一次抢占一起拖慢，比值不动。
//
// 基准选"光读一遍这份配置"（config.Load）：那是这一栏**不可避免**要付的代价，
// 名单本身只是它读出来的一段。超出它两倍以内 = 除归一化与去重外没干别的。
// 退回"每问一次重编译规则集"那一版，实测比值约 10 倍，这条会当场拦住。
func TestRulesPanelBlocklistP95(t *testing.T) {
	if testing.Short() {
		t.Skip("-short：这一条要量时延，跳过")
	}
	if raceEnabled {
		t.Skip("-race 下时延量的是竞态插桩的开销，不是面板的")
	}
	cfgPath, _ := stoppedPollEnv(t, 200)
	svc := New(cfgPath, nil) // 刻意不 Start：停着的那一路才是要钉住的那一路

	const n = 60
	block := make([]time.Duration, 0, n)
	baseline := make([]time.Duration, 0, n)
	round := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		if _, err := config.Load(cfgPath); err != nil {
			t.Fatal(err)
		}
		baseline = append(baseline, time.Since(t0))

		t0 = time.Now()
		_ = svc.BlockList()
		block = append(block, time.Since(t0))

		// 规则页一轮的真实形状：名单问两次（一次直接、一次经由判语）。
		t0 = time.Now()
		_ = svc.BlockList()
		if _, err := svc.UserRuleWarnings(); err != nil {
			t.Fatal(err)
		}
		round = append(round, time.Since(t0))
	}
	// 绝对值照样打出来给人看，但预算放到不会因抢占而红的宽度：
	// 这一条真正把关的是上面那个倍率。
	report(t, "拦截名单(停)", block, 50*time.Millisecond)
	report(t, "基准 只读配置", baseline, 50*time.Millisecond)
	report(t, "规则页一轮(停)", round, 100*time.Millisecond)

	got, want := p50(block), p50(baseline)
	if got > 2*want {
		t.Errorf("问一次拦截名单用了 %v，而光读一遍配置只要 %v（%.1f 倍）——"+
			"这一栏除了归一化名单不该再干别的，尤其不该去编译整张规则表",
			got, want, float64(got)/float64(want))
	}
	t.Logf("拦截名单 / 只读配置 = %.2f 倍（p50 %v vs %v）", float64(got)/float64(want), got, want)
}
