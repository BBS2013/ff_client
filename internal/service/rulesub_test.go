package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/metrics"
	"wps_app/internal/rules"
)

// writeSubConfig 写一份带订阅的配置。
//
// rules.txt 里除订阅之外**一定还留一条本地规则**，这才是真实配置的样子。
// 顺带说明一个刻意的行为：一份只剩 `#include` 加 `FINAL` 的规则集，
// 在订阅没到位时会被引擎以「no usable rules found」拒绝启动——
// 那不是回归，是既有那道「规则文件写错了却静默全走 FINAL」的护栏在起作用。
// 订阅拉不到时的正常退路是「本地那份仍然生效」，那需要本地还有规则。
func writeSubConfig(t *testing.T, body string) (cfgPath, rulesPath string) {
	t.Helper()
	dir := t.TempDir()
	rulesPath = filepath.Join(dir, "rules.txt")
	local := "#include? providers/cn.txt\nDOMAIN-SUFFIX,local.test,DIRECT\nFINAL,PROXY\n"
	if err := os.WriteFile(rulesPath, []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	geoPath := filepath.Join(dir, "missing.mmdb")
	cfgPath = filepath.Join(dir, "config.yaml")
	full := fmt.Sprintf(`server:
  addr: "127.0.0.1:4433"
  auth: "test-auth"
inbounds:
  - type: socks5
    listen: "127.0.0.1:0"
rules_file: %q
geoip:
  path: %q
dns:
  servers: ["127.0.0.1:53"]
log:
  level: warn
%s
`, rulesPath, geoPath, body)
	if err := os.WriteFile(cfgPath, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, rulesPath
}

// 订阅拉下来的规则应当真的进到运行中的规则引擎里——
// 这是整件事唯一有意义的目标，中间那些落盘、重载都只是手段。
func TestRuleProvidersReachTheRunningEngine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,vendor.example,DIRECT\n"))
	}))
	defer srv.Close()

	cfgPath, rulesPath := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: cn\n    url: %q\n    interval: 1h\n", srv.URL))

	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	cache := filepath.Join(filepath.Dir(rulesPath), "providers", "cn.txt")
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("订阅缓存没落盘: %v", err)
	}

	svc.mu.Lock()
	rt := svc.rt
	svc.mu.Unlock()
	if rt == nil {
		t.Fatal("路由器没起来")
	}
	// 用引擎自己的口径问一次：这条订阅的域名规则必须在册。
	got, _ := rt.Decide(context.Background(), "shop.vendor.example")
	if got != rules.PolicyDirect {
		t.Fatalf("vendor.example 的判定 = %v, want DIRECT（订阅规则没生效）", got)
	}
}

// 订阅拉不到时服务照常起，且规则退回到「只有本地那条」而不是崩掉。
func TestRuleProvidersDoNotBlockStartupWhenUnreachable(t *testing.T) {
	// 指向一个必定连不上的地址：127.0.0.1 上没人监听。
	cfgPath, _ := writeSubConfig(t,
		"rule_providers:\n  - name: cn\n    url: \"http://127.0.0.1:1/cn.txt\"\n    interval: 1h\n")

	svc := newService(t, cfgPath)
	done := make(chan error, 1)
	go func() { done <- svc.Start() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("拉不到订阅不该让启动失败: %v", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("启动被订阅拉取卡住了（首次拉取应当有明确的短预算）")
	}
	// 判定必须在 Stop 之前问：stop 会把路由器句柄置 nil。
	svc.mu.Lock()
	rt := svc.rt
	svc.mu.Unlock()
	if rt == nil {
		t.Fatal("服务起来了却没路由器")
	}
	// 本地那条规则还在，说明「订阅挂了但服务照常」这条性质成立。
	if got, _ := rt.Decide(context.Background(), "a.local.test"); got != rules.PolicyDirect {
		t.Fatalf("本地规则判定 = %v, want DIRECT（订阅挂了不该把本地规则也带走）", got)
	}
	// 订阅那部分退回 FINAL：既没有缓存也没有本地补充。
	if got, _ := rt.Decide(context.Background(), "shop.vendor.example"); got != rules.PolicyProxy {
		t.Fatalf("订阅缺失时判定 = %v, want FINAL 的 PROXY", got)
	}

	if err := svc.Stop(); err != nil {
		t.Fatalf("停止: %v", err)
	}
}

// enabled: false 的订阅不该被拉。
func TestDisabledRuleProviderIsNotFetched(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,vendor.example,DIRECT\n"))
	}))
	defer srv.Close()

	cfgPath, _ := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: cn\n    url: %q\n    enabled: false\n", srv.URL))

	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	if n := hits.Load(); n != 0 {
		t.Fatalf("关掉的订阅被请求了 %d 次", n)
	}
	svc.mu.Lock()
	cancel := svc.rulesubCancel
	svc.mu.Unlock()
	if cancel != nil {
		t.Fatal("没有可用的订阅时不该起后台循环")
	}
}

// 一条订阅拉不动不该把已经跑好的转发一起拖垮。
func TestFailingRuleProviderDoesNotStopTheService(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		// 源站活着，但内容是坏的（限流时常见的 HTML 错误页）。
		_, _ = w.Write([]byte("<html>429 Too Many Requests</html>"))
	}))
	defer srv.Close()

	cfgPath, _ := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: cn\n    url: %q\n    interval: 1h\n", srv.URL))

	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("拉到的内容编译不过就让启动失败: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	if hits.Load() == 0 {
		t.Error("根本没有去拉，说明启动前那次预取没跑")
	}
	svc.mu.Lock()
	rt := svc.rt
	svc.mu.Unlock()
	if got, _ := rt.Decide(context.Background(), "a.local.test"); got != rules.PolicyDirect {
		t.Fatalf("本地规则判定 = %v, want DIRECT", got)
	}
}

// 订阅 URL 写错要在**加载配置**时就报出来，而不是等到跑起来才失败：
// 这与「规则文件路径写错」是同一类错误，静默放过会让所有流量按 FINAL 走。
func TestRuleProviderTypoIsRejectedAtLoad(t *testing.T) {
	cfgPath, _ := writeSubConfig(t,
		"rule_providers:\n  - name: cn\n    url: \"not-a-url\"\n    interval: 1h\n")
	if _, err := config.Load(cfgPath); err == nil {
		t.Fatal("URL 写错竟然通过了配置校验")
	}
}

// Stop 必须把后台循环停掉，否则反复启停会攒下一串还在拉取的 goroutine。
func TestStopEndsTheProviderLoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,vendor.example,DIRECT\n"))
	}))
	defer srv.Close()

	cfgPath, _ := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: cn\n    url: %q\n    interval: 1h\n", srv.URL))

	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	svc.mu.Lock()
	cancel := svc.rulesubCancel
	svc.mu.Unlock()
	if cancel == nil {
		t.Fatal("有订阅却没有起后台循环")
	}
	if err := svc.Stop(); err != nil {
		t.Fatalf("停止: %v", err)
	}
	svc.mu.Lock()
	after := svc.rulesubCancel
	svc.mu.Unlock()
	if after != nil {
		t.Fatal("停止之后 cancel 还留着")
	}
}

// 配置里一条订阅都没有时不许起后台循环：绝大多数用户用不到这个功能，
// 不该为它常驻一个 goroutine 和一个定时器。
func TestNoProvidersMeansNoLoop(t *testing.T) {
	cfgPath, _ := writeSubConfig(t, "")
	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	svc.mu.Lock()
	cancel := svc.rulesubCancel
	svc.mu.Unlock()
	if cancel != nil {
		t.Fatal("没有订阅却起了后台循环")
	}
}

// 反复启停之后订阅段仍在配置里，且缓存不会被重复拉爆。
func TestRestartKeepsProviderCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,vendor.example,DIRECT\n"))
	}))
	defer srv.Close()

	cfgPath, rulesPath := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: cn\n    url: %q\n    interval: 1h\n", srv.URL))

	svc := newService(t, cfgPath)
	for i := 0; i < 3; i++ {
		if err := svc.Start(); err != nil {
			t.Fatalf("第 %d 次启动: %v", i, err)
		}
		if err := svc.Stop(); err != nil {
			t.Fatalf("第 %d 次停止: %v", i, err)
		}
	}
	// 内容没变，后台那次的重新拉取会被摘要挡掉。
	if n := hits.Load(); n > 3 {
		t.Errorf("同一份内容被拉了 %d 次，应当被摘要挡掉多余的", n)
	}
	cache := filepath.Join(filepath.Dir(rulesPath), "providers", "cn.txt")
	if _, err := os.Stat(cache); err != nil {
		t.Fatalf("缓存没保住: %v", err)
	}
}

func newService(t *testing.T, cfgPath string) *Service {
	t.Helper()
	return New(cfgPath, metrics.NewRegistry(64, 64))
}

// ---------- 订阅在界面上的那一栏（见 subscriptions.go）----------

// TestSubscriptionsViewWhileRunning 拉通了的那条必须报出"上次拉于何时、缓存多大、下次何时"。
func TestSubscriptionsViewWhileRunning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,vendor.example,DIRECT\n"))
	}))
	defer srv.Close()
	cfgPath, _ := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: cn\n    url: %q\n    interval: 1h\n", srv.URL))

	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	v := svc.Subscriptions()
	if v.ConfigErr != "" {
		t.Fatalf("配置读不到：%s", v.ConfigErr)
	}
	if !v.Running {
		t.Fatal("Start 之后应当报在跑")
	}
	if v.Configured != 1 || len(v.Items) != 1 {
		t.Fatalf("条数不对：configured=%d items=%+v", v.Configured, v.Items)
	}
	// 后台那一轮是异步的，Start 返回时可能还没拉完。等它，而不是睡一觉再猜。
	it := waitSubOk(t, svc)
	if it.LastOkMs == 0 || it.LastAttemptMs == 0 {
		t.Errorf("已经拉通了，时刻却不为 0：attempt=%d ok=%d", it.LastAttemptMs, it.LastOkMs)
	}
	if it.Fails != 0 || it.LastErr != "" {
		t.Errorf("拉通之后还挂着失败：fails=%d err=%q", it.Fails, it.LastErr)
	}
	if !it.HasCache || it.Size == 0 {
		t.Errorf("缓存应当在场且有大小，得到 hasCache=%v size=%d", it.HasCache, it.Size)
	}
	if it.NextDueMs <= time.Now().UnixMilli() {
		t.Errorf("周期 1 小时，下次时刻应当在未来，得到 %d", it.NextDueMs)
	}
}

// TestSubscriptionsViewReportsFailure 拉不通时必须把原文交给界面。
// 这条存在的全部理由：以前这件事只有日志知道，界面上"订阅很健康只是没新内容"
// 与"这个源早挂了"是同一个样子。
func TestSubscriptionsViewReportsFailure(t *testing.T) {
	cfgPath, _ := writeSubConfig(t,
		"rule_providers:\n  - name: dead\n    url: \"http://127.0.0.1:1/dead.txt\"\n    interval: 1h\n")
	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	var it SubscriptionView
	deadline := time.Now().Add(5 * time.Second)
	for {
		v := svc.Subscriptions()
		if len(v.Items) == 1 {
			it = v.Items[0]
		}
		if it.Fails > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if it.Fails == 0 {
		t.Fatal("拉不通却始终报 0 次失败")
	}
	if it.LastErr == "" {
		t.Error("失败原文没交给界面")
	}
	if it.LastOkMs != 0 {
		t.Errorf("从没成功过，lastOkMs 必须是 0（画成「很久以前」就是编的），得到 %d", it.LastOkMs)
	}
}

// TestSubscriptionsViewStopped 没在跑时条目还在（配置里写了），但一个时刻都没有。
// "配了但没在跑"与"根本没配"必须是两句话。
func TestSubscriptionsViewStopped(t *testing.T) {
	cfgPath, _ := writeSubConfig(t,
		"rule_providers:\n  - name: cn\n    url: \"http://example.invalid/cn.txt\"\n    interval: 1h\n")
	v := New(cfgPath, nil).Subscriptions()
	if v.Running {
		t.Error("没 Start 却报在跑")
	}
	if v.Configured != 1 || len(v.Items) != 1 {
		t.Fatalf("停着也应当报出配置里那条订阅，得到 %+v", v)
	}
	it := v.Items[0]
	if it.LastAttemptMs != 0 || it.LastOkMs != 0 || it.NextDueMs != 0 {
		t.Errorf("没在跑时时刻必须全是 0，界面才会说「不会去拉」，得到 %+v", it)
	}
	if it.Name != "cn" || it.EverySec != 3600 {
		t.Errorf("条目本身没报对：%+v", it)
	}
}

// TestBuildProvidersReportsRejection 两条订阅抢同一个缓存文件时，被拒的那条
// 必须带着原因回来，而不是从清单上凭空消失。
//
// 为什么直接测 buildProviders 而不从 config.yaml 走：配置校验在**加载阶段**
// 就拒绝重复的缓存路径（Start 会失败），所以这个状态在真配置下拿不到。
// 但 Add 与校验是两处代码，将来 Add 多一条判据而校验没跟上，这里就是唯一
// 还能看见"有一条订阅从来没生效过"的地方。
func TestBuildProvidersReportsRejection(t *testing.T) {
	cfgPath, rulesPath := writeSubConfig(t, "rule_providers:\n  - name: a\n    url: \"http://example.invalid/a.txt\"\n")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	same := filepath.Join(filepath.Dir(rulesPath), "providers", "same.txt")
	cfg.RuleProviders = []config.RuleProvider{
		{Name: "a", URL: "http://example.invalid/a.txt", Path: same, Interval: config.Duration{}},
		{Name: "b", URL: "http://example.invalid/b.txt", Path: same, Interval: config.Duration{}},
	}
	up, rejected := buildProviders(cfg, nil, nil)
	if up.Len() != 1 {
		t.Errorf("实际登记的应当只有 1 条，得到 %d", up.Len())
	}
	if len(rejected) != 1 || !strings.Contains(rejected[0], "相同") {
		t.Fatalf("被拒的那条应当带原因，得到 %+v", rejected)
	}
}

// TestSubscriptionsViewSurfacesRejections 那一栏必须把 providerErrs 原样带出来：
// 只记在日志里的话，"配了 2 条、实际在拉 1 条"就又变成只有翻日志才知道了。
func TestSubscriptionsViewSurfacesRejections(t *testing.T) {
	cfgPath, _ := writeSubConfig(t,
		"rule_providers:\n  - name: cn\n    url: \"http://example.invalid/cn.txt\"\n    interval: 1h\n")
	svc := New(cfgPath, nil)
	svc.providerErrs = []string{"规则集订阅 \"b\"：缓存路径与 \"a\" 相同"}
	v := svc.Subscriptions()
	if len(v.Errors) != 1 || v.Errors[0] == "" {
		t.Fatalf("被拒原因没上界面：%+v", v.Errors)
	}
}

// TestSubscriptionsViewCacheDeleted 拉通过、缓存后来被人删了：
// lastOk 仍然有值，但 hasCache 必须翻成假。这一对同时成立才是那个真实现场。
func TestSubscriptionsViewCacheDeleted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,vendor.example,DIRECT\n"))
	}))
	defer srv.Close()
	cfgPath, rulesPath := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: cn\n    url: %q\n    interval: 1h\n", srv.URL))
	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	it := waitSubOk(t, svc)
	if it.LastOkMs == 0 {
		t.Fatal("等不到「拉通」这一步，用例没构造起来")
	}
	cache := filepath.Join(filepath.Dir(rulesPath), "providers", "cn.txt")
	if err := os.Remove(cache); err != nil {
		t.Fatalf("删缓存: %v", err)
	}
	after := svc.Subscriptions().Items[0]
	if after.LastOkMs == 0 {
		t.Error("这条确实拉通过，lastOkMs 不该被删缓存抹掉")
	}
	if after.HasCache {
		t.Error("缓存文件已经没了还报在场")
	}
}

// waitSubOk 轮询到「后台那一轮真的拉通了」为止。
// Start 返回时那个循环可能还在 HTTP 上，拿那一刻当结论就是在测时序而不是测行为。
func waitSubOk(t *testing.T, svc *Service) SubscriptionView {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var last SubscriptionView
	for {
		items := svc.Subscriptions().Items
		if len(items) == 1 {
			last = items[0]
			if last.LastOkMs != 0 {
				return last
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("等不到订阅拉通：%+v", last)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// ---------- 「立即拉取」这个动作 ----------

// TestRefreshProvidersReportsPerItem 按钮回来的必须逐条说清，还要真的换到新规则。
func TestRefreshProvidersReportsPerItem(t *testing.T) {
	var body atomic.Value
	body.Store("DOMAIN-SUFFIX,v1.example,DIRECT\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	cfgPath, rulesPath := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: cn\n    url: %q\n    interval: 1h\n", srv.URL))
	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	if _, err := os.Stat(filepath.Join(filepath.Dir(rulesPath), "providers", "cn.txt")); err != nil {
		t.Fatalf("启动时没补齐缓存: %v", err)
	}
	// 先等后台那一轮**拉通**，再换远端内容。
	// 反过来的话就是拿一次异步拉取和自己的手动拉取赛跑：循环先跑到就把新内容
	// 消化掉了，手动那一次得到"没变"——实测 `go test ./...` 并发跑时约三次红一次，
	// 单包跑又是绿的。等一个可观察的信号，而不是赌时序。
	waitSubOk(t, svc)
	body.Store("DOMAIN-SUFFIX,v1.example,DIRECT\nDOMAIN-SUFFIX,v2.example,REJECT\n")
	rep, err := svc.RefreshProviders(context.Background())
	if err != nil {
		t.Fatalf("RefreshProviders: %v", err)
	}
	if len(rep.Results) != 1 || !rep.Results[0].Changed || rep.Results[0].Err != "" {
		t.Fatalf("逐条结果不对：%+v", rep.Results)
	}
	if !rep.Reloaded || rep.ReloadErr != "" {
		t.Errorf("内容变了就该重载，得到 reloaded=%v err=%q", rep.Reloaded, rep.ReloadErr)
	}
	// 判据落在决策上，不落在计数上：新规则必须真的能改走向。
	res, err := svc.Probe("shop.v2.example")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Policy != "REJECT" {
		t.Errorf("v2.example 的走向 = %s，期望 REJECT（拉到的新内容没进引擎）", res.Policy)
	}
}

// TestRefreshProvidersNothingChanged 远端没新东西时，报告必须说"没有一条变了"，
// 而且不许顺手重载引擎——白重载一次是 3.8ms 加一次整引擎替换。
func TestRefreshProvidersNothingChanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,v1.example,DIRECT\n"))
	}))
	defer srv.Close()
	cfgPath, _ := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: cn\n    url: %q\n    interval: 1h\n", srv.URL))
	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	waitSubOk(t, svc)

	rep, err := svc.RefreshProviders(context.Background())
	if err != nil {
		t.Fatalf("RefreshProviders: %v", err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Changed {
		t.Fatalf("内容没变却报变了：%+v", rep.Results)
	}
	if rep.Reloaded {
		t.Error("没新内容也去重载了引擎")
	}
}

// TestRefreshProvidersRefusedWhenStopped 没在跑时必须是一句错误，
// 不能是一个空报告——空报告在界面上与"拉了，什么都没变"长得一样。
func TestRefreshProvidersRefusedWhenStopped(t *testing.T) {
	cfgPath, _ := writeSubConfig(t,
		"rule_providers:\n  - name: cn\n    url: \"http://example.invalid/cn.txt\"\n    interval: 1h\n")
	_, err := New(cfgPath, nil).RefreshProviders(context.Background())
	if err == nil || !strings.Contains(err.Error(), "没在跑") {
		t.Fatalf("期望一句「没在跑」的错误，得到 %v", err)
	}
}

// TestRefreshProvidersCarriesPerItemFailure 一条失败不能拖垮其余几条，
// 但每条各自的结果都得原样带回去。
func TestRefreshProvidersCarriesPerItemFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("DOMAIN-SUFFIX,good.example,DIRECT\n"))
	}))
	defer srv.Close()
	cfgPath, _ := writeSubConfig(t, fmt.Sprintf(
		"rule_providers:\n  - name: bad\n    url: \"http://127.0.0.1:1/bad.txt\"\n    interval: 1h\n"+
			"  - name: good\n    url: %q\n    interval: 1h\n", srv.URL))
	svc := newService(t, cfgPath)
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })

	rep, err := svc.RefreshProviders(context.Background())
	if err != nil {
		t.Fatalf("RefreshProviders: %v", err)
	}
	byName := map[string]ProviderRefresh{}
	for _, r := range rep.Results {
		byName[r.Name] = r
	}
	if len(byName) != 2 {
		t.Fatalf("两条订阅应当逐条回报，得到 %+v", rep.Results)
	}
	if byName["bad"].Err == "" {
		t.Error("失败那条没带原因")
	}
	if byName["good"].Err != "" {
		t.Errorf("成功那条不该带错误：%+v", byName["good"])
	}
}
