package ui

// 演示词表守卫：frontend/src/demo.ts 里那些"照抄后端字面量"的位置，
// 必须与 Go 侧真能产出的那一套**双向对上**——每个后端取值演示里都要有，
// 演示写出的每个取值后端也都得能产出。
//
// 为什么要单独有一条跨语言的测试：投影链守卫比的是**字段名**，
// 而演示桥两边都是 TS，所以字面量的取值集合它管不到（`?demo=` 自证不了后端形状）。
// 这一层坏起来的样子不是报错，是"那一格在演示里永远点不出来"：
// 2026-10-19 一天之内为此返工三次——日志缺 DEBUG/ERROR 两档（那排阈值按钮点出空列表）、
// `?demo=down` 只覆写了一半读数（顶栏说停了别处还在说跑着）、探测框把模式优先级答反。
// 三条的共同点是**没有任何测试会红**，人不去点那一下就永远不知道。
//
// 所以这里不测行为，只测"演示有没有覆盖后端的全部取值"。它很笨，但笨得正好：
// 加一个日志级别 / 一种策略 / 一个账本状态而忘了给演示补一档，就该有人当场拦一下。

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/metrics"
	"wps_app/internal/rules"
	"wps_app/internal/service"
)

func demoSource(t *testing.T) string {
	t.Helper()
	return frontendFile(t, "demo.ts")
}

// frontendFile 读 frontend/src 下的一个文件。守卫要跨语言比对，只能读源码。
func frontendFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{repoRoot(t), "frontend", "src"}, parts...)...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读演示桥源码 %v: %v", parts, err)
	}
	return string(b)
}

// goLevels 遍历 logx 的级别常量，而不是在测试里抄一份名单。
//
// 判据是"String() 出来的字面量还能被 ParseLevel 认回同一个值"：
// 越界的那个整数会落到 String() 的 default 分支上，回来的就不是它自己。
// 这样新增一级时不必改这条测试——它会自动多要一档演示数据。
func goLevels(t *testing.T) []string {
	t.Helper()
	var out []string
	for l := logx.LevelDebug; ; l++ {
		s := l.String()
		if logx.ParseLevel(s) != l {
			break
		}
		out = append(out, s)
		if len(out) > 16 {
			t.Fatal("级别枚举没有走到头，遍历方式该改了")
		}
	}
	return out
}

func diffSets(name string, goSet, demoSet []string) string {
	inGo := map[string]bool{}
	for _, v := range goSet {
		inGo[v] = true
	}
	inDemo := map[string]bool{}
	for _, v := range demoSet {
		inDemo[v] = true
	}
	var missing, invented []string
	for _, v := range goSet {
		if !inDemo[v] {
			missing = append(missing, v)
		}
	}
	for _, v := range demoSet {
		if !inGo[v] {
			invented = append(invented, v)
		}
	}
	if len(missing) == 0 && len(invented) == 0 {
		return ""
	}
	sort.Strings(missing)
	sort.Strings(invented)
	var b strings.Builder
	b.WriteString(name + " 对不上：")
	if len(missing) > 0 {
		b.WriteString(" 后端有而演示里一档都没有（那一格在 ?demo= 下永远点不出来）: " + strings.Join(missing, " "))
	}
	if len(invented) > 0 {
		b.WriteString(" 演示写了后端产不出的值: " + strings.Join(invented, " "))
	}
	return b.String()
}

// quotedIn 从一个字面量块里把取值捞出来。
// field 非空时只取那个键的取值（`id: 'rule'`），空时取块里所有单引号串
// （DEMO_LOG_LEVEL 那种键不带引号的，取到的正好只有值）。
func quotedIn(t *testing.T, src, blockMarker, endMarker, field string) []string {
	t.Helper()
	i := strings.Index(src, blockMarker)
	if i < 0 {
		t.Fatalf("演示源码里找不到 %q——它搬家了就把这条守卫一起搬走", blockMarker)
	}
	rest := src[i:]
	end := strings.Index(rest, endMarker)
	if end < 0 {
		t.Fatalf("%s 那个块的结尾 %q 找不到", blockMarker, endMarker)
	}
	body := rest[:end]
	pat := `'([^']+)'`
	if field != "" {
		pat = field + `:\s*'([^']+)'`
	}
	re := regexp.MustCompile(pat)
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestDemoLogLevelsCoverGo 盯的是日志页那排阈值按钮：
// 演示少发一档，按钮点出来就是空列表，看着像功能坏了。
func TestDemoLogLevelsCoverGo(t *testing.T) {
	src := demoSource(t)
	if msg := diffSets("日志级别", goLevels(t), quotedIn(t, src, "const DEMO_LOG_LEVEL", "\n}", "")); msg != "" {
		t.Error(msg)
	}
}

// TestDemoPoliciesCoverGo 盯的是策略名：连接表、规则页、探测框都按它上色与分支。
func TestDemoPoliciesCoverGo(t *testing.T) {
	src := demoSource(t)
	var goSet []string
	for _, p := range rules.Policies() {
		goSet = append(goSet, string(p))
	}
	re := regexp.MustCompile(`policy:\s*'([A-Z-]+)'`)
	var demoSet []string
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		demoSet = append(demoSet, m[1])
	}
	// 探测那几处是函数实参，不是 `policy:` 赋值，单独捞一遍。
	re2 := regexp.MustCompile(`withExtras\('([A-Z-]+)'`)
	for _, m := range re2.FindAllStringSubmatch(src, -1) {
		demoSet = append(demoSet, m[1])
	}
	if msg := diffSets("分流策略", goSet, demoSet); msg != "" {
		t.Error(msg)
	}
}

// TestDemoModesCoverGo 盯两件事：顶栏那排模式按钮是否覆盖后端全部模式，
// 以及探测框那句 `MODE,XXX` 的写法后端产不产得出来。
// 后者是 2026-10-19 刚补的——演示原来压根不看模式，切到「全局」还在报某条域名规则命中。
func TestDemoModesCoverGo(t *testing.T) {
	src := demoSource(t)
	bar := frontendFile(t, "components", "TopBar.vue")

	var goSet []string
	for _, m := range config.Modes() {
		goSet = append(goSet, string(m))
	}
	if msg := diffSets("分流模式（顶栏按钮）", goSet, quotedIn(t, bar, "const MODES = [", "\n]", "id")); msg != "" {
		t.Error(msg)
	}

	// `MODE,<大写>` 这种命中依据只有非 rule 的两档会产出：rule 模式走的是规则本身。
	want := map[string]bool{}
	for _, m := range config.Modes() {
		if m != config.ModeRule {
			want["MODE,"+strings.ToUpper(string(m))] = true
		}
	}
	reM := regexp.MustCompile(`MODE,[A-Z]+`)
	for _, tok := range reM.FindAllString(src, -1) {
		if !want[tok] {
			t.Errorf("演示写了后端产不出的命中依据 %q（可选的只有 %v）", tok, keysOf(want))
		}
	}
	// 演示里必须真能产出每一档：那串是模板字符串（`MODE,${…}`），
	// 所以查的是"每个非 rule 模式的字面量在演示源码里出现过"。
	for _, m := range config.Modes() {
		if m == config.ModeRule {
			continue
		}
		if !strings.Contains(src, "'"+string(m)+"'") {
			t.Errorf("后端会产出 MODE,%s，演示里却连 %q 这个档都没写", strings.ToUpper(string(m)), string(m))
		}
	}
}

// TestDemoUsageStatesCoverGo 盯的是账本被拒那几种状态。
// 界面为「版本太新」与「读不到」各写了一句话，而这两句只有在演示里点得出来时才算被验收过。
func TestDemoUsageStatesCoverGo(t *testing.T) {
	src := demoSource(t)
	goSet := []string{metrics.UsageLoaded, metrics.UsageEmpty, metrics.UsageTooNew, metrics.UsageUnreadable}

	// 不许发明：写进 usageState 的字面量必须是后端会产出的那一个。
	re := regexp.MustCompile(`usageState:\s*(?:'([^']+)'|[^,\n]*\?\s*'([^']+)'\s*:\s*'([^']+)')`)
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		for _, g := range m[1:] {
			if g == "" {
				continue
			}
			if !contains(goSet, g) {
				t.Errorf("演示往 usageState 写了后端产不出的值 %q（可选: %v）", g, goSet)
			}
		}
	}
	// 也不许缺档：每一档都得能在 ?demo= 下被点出来。
	for _, v := range goSet {
		if !strings.Contains(src, "'"+v+"'") {
			t.Errorf("后端会产出账本状态 %q，演示里却一档都没有——界面对它写的那句话没人验过", v)
		}
	}
}

// TestDemoFetchBudgetMatchesGo 盯的是「取一个真页面」超时那一档里的秒数。
//
// 演示里那句"在 15 秒内没回话"是抄 Go 那侧的（`service.plainTimeout` 的句式），
// 而抄来的数字会漂：预算一改，演示就在报一个后端永远不会报的秒数，
// 照着演示验收超时那一档的人会白找一次。
// 这条守卫比的是**句式里的数**，不是行为——行为要等一个真超时，那是没人愿意等的 15 秒。
func TestDemoFetchBudgetMatchesGo(t *testing.T) {
	src := demoSource(t)
	secs := int(service.FetchBudget / time.Second)
	if service.FetchBudget%time.Second != 0 {
		t.Fatalf("service.FetchBudget 不是整秒（%v），这条守卫的比法要一起改", service.FetchBudget)
	}
	pat := regexp.MustCompile(`在 (\d+) 秒内没回话（这一格的预算就是 (\d+) 秒）`)
	found := pat.FindAllStringSubmatch(src, -1)
	if len(found) == 0 {
		t.Fatal("演示里没有超时那一档的句子——?demo= 下这一格演不出「到点没回话」")
	}
	for _, m := range found {
		if m[1] != m[2] {
			t.Errorf("演示那一句自己前后不一致: %q", m[0])
		}
		if n, err := strconv.Atoi(m[1]); err != nil || n != secs {
			t.Errorf("演示说预算是 %s 秒，后端 service.FetchBudget 是 %d 秒——改预算要把演示一起改", m[1], secs)
		}
	}
}

// TestDemoBigScenarioMatchesRealCaps 盯的是 ?demo=big 那一档的**尺寸来源**。
//
// 这一档存在的唯一理由是"按生产稳态量一次"（README §9.3 那张切页表、§10.12 那个窗口），
// 而它灌的是**抄来的常数**：已结束连接抄 historyCap、活跃抄"浏览器开 300 条"、
// 日志抄 LOG_CAP。抄来的数会漂——哪天 historyCap 改成 200，这一档还在灌 500 行，
// 量出来的代价就是真的，但对应的形状是假的，而且没有任何测试会红。
// 所以这里把 TS 里那几个字面量与 Go 侧真正的那份对上。
func TestDemoBigScenarioMatchesRealCaps(t *testing.T) {
	src := demoSource(t)
	caps := map[string]int{}
	for _, want := range []struct{ what, pat string }{
		{"已结束那一份的条数（= historyCap）", `length: (\d+) \}, \(_, i\) => \{\s+const s = snap\.history`},
		{"活跃那一份的条数", `Array\.from\(\{ length: (\d+) \}, \(_, i\) => \{\s+const s = seed`},
	} {
		re := regexp.MustCompile(want.pat)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("在演示源码里找不到 %s 的那个长度——它搬家了就把这条守卫一起搬走", want.what)
			continue
		}
		got, err := strconv.Atoi(m[1])
		if err != nil {
			t.Errorf("%s 的长度读不出来: %q", want.what, m[1])
			continue
		}
		caps[want.what] = got
	}
	if got, ok := caps["已结束那一份的条数（= historyCap）"]; ok && got != historyCap {
		t.Errorf("演示灌 %d 条已结束连接，真实环的上限 historyCap 是 %d——量的形状与生产不是同一件事", got, historyCap)
	}
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func keysOf(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
