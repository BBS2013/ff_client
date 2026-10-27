package rules

import (
	"context"
	"testing"
	"time"
)

// 性能预算闸。README §9.3 记了实测形状，但记下来不等于守得住——
// 这条测试的作用是让"判定慢了五倍"这种事在一次提交内就响，而不是等谁再手跑一遍 bench。

// 预算故意留得极宽：这条测试会在共享机器、CI、后台编译各种负载下跑，
// 收紧到实测值的 1.5 倍只会得到一个随机红的用例，而随机红的用例活不过第二次
// ——人们会直接给它加 skip。它要拦的是"线性扫被改成扫两遍""每次判定多一次分配"
// 这种量级的变化。
func measureMatch(t *testing.T, e *Engine, host string) time.Duration {
	t.Helper()
	const iters = 2000
	start := time.Now()
	ctx := context.Background()
	for i := 0; i < iters; i++ {
		if _, matched := e.Match(ctx, host); matched == "" {
			t.Fatalf("判定 %q 没给出结果", host)
		}
	}
	return time.Since(start) / iters
}

// TestMatchLatencyBudget 量三种判定的单次耗时：第一条命中、一条都不命中、IP 判定。
func TestMatchLatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("性能预算闸：-short 时跳过")
	}
	e := loadReal(t)
	e.SetBlocklist([]string{"ads.example.com"})
	cases := []struct {
		name string
		host string
		// 实测（i7-13850HX）：first-hit 0.4µs / miss 88µs / ip 0.12µs。
		want time.Duration
	}{
		{"第一条命中", firstDomainRuleHost(t, e), 200 * time.Microsecond},
		{"一条都不命中", "definitely-not-in-any-ruleset.example", 1 * time.Millisecond},
		{"IP 判定", "8.8.8.8", 200 * time.Microsecond},
	}
	for _, c := range cases {
		per := measureMatch(t, e, c.host)
		if per > c.want {
			t.Errorf("%s：单次判定 %v，超预算 %v（README §9.3 的实测形状是几微秒到几十微秒）",
				c.name, per, c.want)
		}
		t.Logf("%s 单次 %v（预算 %v）", c.name, per, c.want)
	}
}

// TestLoadBudget 装配整份规则集的代价：面板每次"重载规则"都要付一遍。
func TestLoadBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("性能预算闸：-short 时跳过")
	}
	rulesFile, geoFile := realRules(t)
	geo, err := OpenGeoIP(geoFile)
	if err != nil {
		t.Fatal(err)
	}
	ref := NewGeoRef(geo)
	start := time.Now()
	e, err := Load(rulesFile, ref, nil)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	dom, ip := e.Stats()
	// 实测 3.8ms。给到 200ms：这条不是微基准，它要拦的是
	// "加载从 O(n) 变成 O(n²)"（4547 条规则下那会是秒级）。
	if elapsed > 200*time.Millisecond {
		t.Errorf("装配规则集用了 %v（域名 %d / IP %d 条），比实测的 3.8ms 慢了两个量级",
			elapsed, dom, ip)
	}
	t.Logf("装配 %d 条规则用了 %v", dom+ip, elapsed)
}
