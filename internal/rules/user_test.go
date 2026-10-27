package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), UserRuleFileName)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadUserRulesMissingFileIsEmpty(t *testing.T) {
	list, err := LoadUserRules(filepath.Join(t.TempDir(), "nope.txt"))
	if err != nil {
		t.Fatalf("文件不存在应是空列表而非错误: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("应为空: %+v", list)
	}
}

func TestUserRuleNormalizeAndValidate(t *testing.T) {
	r := UserRule{Type: " domain-suffix ", Value: "  WWW.Example.COM. ", Policy: " proxy "}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if r.Type != "DOMAIN-SUFFIX" || r.Value != "www.example.com" || r.Policy != "PROXY" {
		t.Fatalf("规范化结果不对: %+v", r)
	}
	if got := r.Line(); got != "DOMAIN-SUFFIX,www.example.com,PROXY" {
		t.Fatalf("Line = %q", got)
	}
	// HY2/PROXY-HY2 是 PROXY 的别名，界面上不该出现第二种写法
	alias := UserRule{Type: "DOMAIN", Value: "a.com", Policy: "PROXY-HY2"}
	if err := alias.Normalize(); err != nil || alias.Policy != "PROXY" {
		t.Fatalf("别名没归一: %v %+v", err, alias)
	}

	// REJECT 必须被 Normalize 接受。
	// 拒绝它的后果不是"这条加不了"，而是**面板从此存不了这份文件**：
	// 读路径把域名类规则一律标成可编辑（不带 raw），而 SaveUserRules 只对
	// 非 raw 条目跑 Normalize——手改进去的一行 REJECT 会把整表回写顶死。
	rejectRow := UserRule{Type: "DOMAIN", Value: "a.com", Policy: "reject"}
	if err := rejectRow.Normalize(); err != nil {
		t.Errorf("REJECT 应被接受（大小写都认）: %v", err)
	}

	for _, bad := range []UserRule{
		{Type: "GEOIP", Value: "cn", Policy: "DIRECT"},
		{Type: "FINAL", Value: "", Policy: "DIRECT"},
		{Type: "DOMAIN", Value: "", Policy: "PROXY"},
		{Type: "DOMAIN", Value: "a.com", Policy: "BLOCKIT"},
		{Type: "DOMAIN", Value: "a.com, DIRECT", Policy: "PROXY"},
	} {
		item := bad
		if err := item.Normalize(); err == nil {
			t.Errorf("%+v 应被拒绝", bad)
		}
	}
}

// TestHandWrittenRejectSurvivesPanelSave 见上：一行手写的 REJECT 不该卡死保存，
// 也不该在回写时被改写成别的策略。
func TestHandWrittenRejectSurvivesPanelSave(t *testing.T) {
	path := writeTemp(t, "DOMAIN-SUFFIX,ads.example.com,REJECT\nDOMAIN-SUFFIX,notion.so,PROXY\n")
	list, err := LoadUserRules(path)
	if err != nil {
		t.Fatalf("LoadUserRules: %v", err)
	}
	if err := SaveUserRules(path, list); err != nil {
		t.Fatalf("带 REJECT 的名单让保存失败了: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "DOMAIN-SUFFIX,ads.example.com,REJECT") {
		t.Errorf("拦截行被改写或丢了:\n%s", raw)
	}
}

// TestRejectIsNotPanelEditable 策略开关只有走代理/直连两档，
// 拦截规则不能从那里编辑：显示成"走代理"是一半谎言，
// 而那个一键翻转会把拦截悄悄变成放行。
func TestRejectIsNotPanelEditable(t *testing.T) {
	r := UserRule{Type: "DOMAIN-SUFFIX", Value: "ads.example.com", Policy: "REJECT"}
	if err := r.Normalize(); err != nil {
		t.Fatal(err)
	}
	if r.IsDomain() {
		t.Error("REJECT 不该进可编辑的那一档")
	}
	// 对照：同一个类型换个策略就该是可编辑的，别把判断写死成"类型不行"。
	ok := UserRule{Type: "DOMAIN-SUFFIX", Value: "ads.example.com", Policy: "PROXY"}
	if !ok.IsDomain() {
		t.Error("PROXY 的域名规则本该可编辑")
	}
}

func TestSaveAndLoadUserRulesRoundTrip(t *testing.T) {
	path := writeTemp(t, "DOMAIN-SUFFIX,notion.so,PROXY\nDOMAIN,direct.example.cn,DIRECT\n")
	list, err := LoadUserRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Type != "DOMAIN-SUFFIX" || list[0].Value != "notion.so" {
		t.Fatalf("读回不对: %+v", list)
	}
	if err := SaveUserRules(path, list); err != nil {
		t.Fatal(err)
	}
	again, err := LoadUserRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 2 || again[1].Policy != "DIRECT" {
		t.Fatalf("保存后变形: %+v", again)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "自定义域名规则") {
		t.Errorf("表头注释没写出来:\n%s", raw)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Errorf("覆盖前应备份: %v", err)
	}
}

// TestSaveKeepsUnknownLinesVerbatim 盯住一个很容易犯的破坏：
// 用户手写的 IP-CIDR / GEOIP 行不能被面板「加一条域名规则」连带丢掉。
func TestSaveKeepsUnknownLinesVerbatim(t *testing.T) {
	path := writeTemp(t, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nGEOIP,CN,DIRECT\nDOMAIN,keep.me,PROXY\n")
	list, err := LoadUserRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("应读出 3 条: %+v", list)
	}
	if list[0].Type != "IP-CIDR" || list[0].Line() != "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve" {
		t.Fatalf("非域名规则没被原样保留（类型名要照实报）: %+v", list[0])
	}
	if list[1].Type != "GEOIP" {
		t.Fatalf("第二条报成 %q，想要 GEOIP: %+v", list[1].Type, list[1])
	}
	if list[0].IsDomain() {
		t.Error("IP-CIDR 不该在界面上可编辑")
	}
	next := UpsertUserRule(list, UserRule{Type: "DOMAIN-SUFFIX", Value: "added.test", Policy: "DIRECT"})
	if err := SaveUserRules(path, next); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, want := range []string{"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "GEOIP,CN,DIRECT", "DOMAIN,keep.me,PROXY", "DOMAIN-SUFFIX,added.test,DIRECT"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("保存后丢了 %q:\n%s", want, raw)
		}
	}
}

func TestUserRulesRejectIncludeAndFinal(t *testing.T) {
	if _, err := parseUserRules("#include ./other.txt\n"); err == nil {
		t.Error("自定义规则里不该允许 #include（回写整表时会连带毁掉引用关系）")
	}
	if _, err := parseUserRules("FINAL,DIRECT\n"); err == nil {
		t.Error("FINAL 只能有一份，且该由主规则集决定")
	}
	if _, err := parseUserRules("DOMAIN-SUFFIX\n"); err == nil {
		t.Error("残缺行应报错而不是被静默忽略")
	}
}

func TestUpsertAndRemoveUserRule(t *testing.T) {
	base := []UserRule{
		{Type: "DOMAIN-SUFFIX", Value: "a.com", Policy: "PROXY"},
		{Type: "DOMAIN", Value: "b.com", Policy: "DIRECT"},
	}
	// 同类型同域名：改策略而不是攒第二条。
	got := UpsertUserRule(base, UserRule{Type: "DOMAIN-SUFFIX", Value: "a.com", Policy: "DIRECT"})
	if len(got) != 2 || got[0].Policy != "DIRECT" {
		t.Fatalf("Upsert 没覆盖同键规则: %+v", got)
	}
	// 同域名不同类型是两条不同规则（精确 vs 后缀），不该互相吞掉。
	got = UpsertUserRule(base, UserRule{Type: "DOMAIN", Value: "a.com", Policy: "PROXY"})
	if len(got) != 3 {
		t.Fatalf("不同类型应并存: %+v", got)
	}
	left, removed := RemoveUserRule(base, "domain-suffix", "A.COM")
	if !removed || len(left) != 1 {
		t.Fatalf("删除应按类型+域名大小写不敏感: %+v removed=%v", left, removed)
	}
	if _, removed := RemoveUserRule(base, "DOMAIN", "nope.com"); removed {
		t.Error("删不存在的规则应报未命中")
	}
}

// TestUserRulesTakePrecedenceInEngine 是这块功能的落点：
// 主规则集把 user-rules.txt 引在最前面，所以自定义规则能盖住内置的被墙域名表。
func TestUserRulesTakePrecedenceInEngine(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "rules.txt")
	body := "#include? ./user-rules.txt\nDOMAIN-SUFFIX,google.com,PROXY\nFINAL,PROXY\n"
	if err := os.WriteFile(main, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	user := filepath.Join(dir, UserRuleFileName)

	eng, err := Load(main, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p, m := eng.Match(context.Background(), "www.google.com"); p != PolicyProxy || !strings.Contains(m, "DOMAIN-SUFFIX,google.com") {
		t.Fatalf("没有自定义规则时应命中内置表: %s %s", p, m)
	}

	if err := SaveUserRules(user, []UserRule{{Type: "DOMAIN-SUFFIX", Value: "google.com", Policy: "DIRECT"}}); err != nil {
		t.Fatal(err)
	}
	eng2, err := Load(main, nil, nil)
	if err != nil {
		t.Fatalf("带自定义规则的主规则集加载失败: %v", err)
	}
	p, m := eng2.Match(context.Background(), "www.google.com")
	if p != PolicyDirect {
		t.Fatalf("自定义规则没盖住内置表: %s %s", p, m)
	}
	if !strings.Contains(m, "DOMAIN-SUFFIX,google.com,DIRECT") {
		t.Fatalf("命中依据里应能看出是自定义那条: %s", m)
	}
	dom, _ := eng2.Stats()
	if dom < 2 {
		t.Fatalf("自定义规则没被算进域名规则: %d", dom)
	}
}

func TestUserRulePathSitsBesideRulesFile(t *testing.T) {
	if got := UserRulePath("/etc/wps_app/assets/rules.txt"); got != "/etc/wps_app/assets/user-rules.txt" {
		t.Fatalf("路径推导不对: %s", got)
	}
	if got := UserRulePath("rules.txt"); got != "user-rules.txt" {
		t.Fatalf("相对路径不对: %s", got)
	}
}

// TestMoveUserRule 换顺序是这个功能存在的全部理由：引擎命中第一条就停，
// 所以被前面那条压住的规则，改内容改不掉，只有挪位置才救得回来。
func TestMoveUserRule(t *testing.T) {
	list := []UserRule{
		{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"},
		{Type: "IP-CIDR", Value: "10.0.0.0/8", Policy: "DIRECT", raw: "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"},
		{Type: "DOMAIN", Value: "www.example.com", Policy: "DIRECT"},
	}
	// 最后一行挪到最前：精确域名那条要盖住第 0 行那条 SUFFIX。
	got, err := MoveUserRule(list, "DOMAIN", "www.example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Type != "DOMAIN" || got[1].Type != "DOMAIN-SUFFIX" || got[2].Type != "IP-CIDR" {
		t.Fatalf("顺序不对: %+v", got)
	}
	// 手写的行整行跟着走，不能被"能显示的那三个字段"重新拼一遍。
	if got[2].Line() != "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve" {
		t.Fatalf("手写行在移动中被改写了: %q", got[2].Line())
	}
	// 原名单不许被动过：面板会拿它继续渲染。
	if list[2].Type != "DOMAIN" || len(list) != 3 {
		t.Fatalf("入参被就地改了: %+v", list)
	}

	// 往下挪一格。
	got, err = MoveUserRule(list, "DOMAIN-SUFFIX", "example.com", 2)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Type != "IP-CIDR" || got[1].Type != "DOMAIN" || got[2].Type != "DOMAIN-SUFFIX" {
		t.Fatalf("往下挪不对: %+v", got)
	}

	// 原地不动也是合法答案，但必须给出一份新切片。
	same, err := MoveUserRule(list, "DOMAIN", "www.example.com", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(same) != 3 || same[2].Type != "DOMAIN" {
		t.Fatalf("原地移动把名单弄坏了: %+v", same)
	}

	// 找不到与越界都要响：静默写成"挪到某一格"会改出一个没人要求的顺序。
	if _, err := MoveUserRule(list, "DOMAIN", "missing.test", 0); err == nil {
		t.Error("不存在的规则挪成功了")
	}
	for _, to := range []int{-1, 3, 99} {
		if _, err := MoveUserRule(list, "DOMAIN", "www.example.com", to); err == nil {
			t.Errorf("位置 %d 越界却成功了", to)
		}
	}

	// 大小写与空格按 RemoveUserRule 同一套归一，面板传什么写法都认。
	if _, err := MoveUserRule(list, "domain", " WWW.Example.COM ", 0); err != nil {
		t.Errorf("归一化没对上: %v", err)
	}
}

// TestMoveThenSaveKeepsEveryLine 移动完写盘再读回来，名单必须一模一样：
// 这条盯的是"移动顺手把别的行丢了"和"表头/备份把顺序洗掉"两种事故。
func TestMoveThenSaveKeepsEveryLine(t *testing.T) {
	path := writeTemp(t, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nDOMAIN,a.test,PROXY\nDOMAIN-SUFFIX,b.test,DIRECT\n")
	list, err := LoadUserRules(path)
	if err != nil {
		t.Fatal(err)
	}
	moved, err := MoveUserRule(list, "DOMAIN-SUFFIX", "b.test", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveUserRules(path, moved); err != nil {
		t.Fatal(err)
	}
	again, err := LoadUserRules(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range again {
		lines = append(lines, r.Line())
	}
	want := []string{"DOMAIN-SUFFIX,b.test,DIRECT", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "DOMAIN,a.test,PROXY"}
	if strings.Join(lines, "|") != strings.Join(want, "|") {
		t.Fatalf("回写后的名单不对: %v", lines)
	}
}

// TestParseRuleLine 批量粘贴那一栏的入口判据：两种写法都要收，
// 而收不下的一种（REJECT / 非域名类型）必须说清去哪儿手写。
func TestParseRuleLine(t *testing.T) {
	ok := []struct {
		line, defType, defPolicy, typ, value, policy string
	}{
		{"notion.so", "DOMAIN-SUFFIX", "PROXY", "DOMAIN-SUFFIX", "notion.so", "PROXY"},
		{"  Notion.SO  ", "DOMAIN", "DIRECT", "DOMAIN", "notion.so", "DIRECT"},
		{"DOMAIN-SUFFIX,example.cn,DIRECT", "DOMAIN", "PROXY", "DOMAIN-SUFFIX", "example.cn", "DIRECT"},
		{"domain-keyword,zhihu,proxy", "DOMAIN", "DIRECT", "DOMAIN-KEYWORD", "zhihu", "PROXY"},
	}
	for _, c := range ok {
		r, err := ParseRuleLine(c.line, c.defType, c.defPolicy)
		if err != nil {
			t.Errorf("%q 被拒了: %v", c.line, err)
			continue
		}
		if r.Type != c.typ || r.Value != c.value || r.Policy != c.policy {
			t.Errorf("%q 解析成 %+v，想要 %s/%s/%s", c.line, r, c.typ, c.value, c.policy)
		}
	}

	bad := []string{
		"",                    // 空行由调用方跳过，这里也要能自己挡住
		"# 注释",                // 同上
		"a b.com",             // 域名里不许有空格
		"FINAL,PROXY",         // 兜底策略只有一份
		"DOMAIN, a.test,NUKE", // 策略不认识
		"DOMAIN-SUFFIX,ads.test,REJECT",
		"IP-CIDR,10.0.0.0/8,DIRECT",
		"DOMAIN-REGEX,^api\\..*$,PROXY",
		"GEOIP,CN,DIRECT",
	}
	for _, line := range bad {
		if r, err := ParseRuleLine(line, "DOMAIN-SUFFIX", "PROXY"); err == nil {
			t.Errorf("%q 竟然收下了: %+v", line, r)
		}
	}

	// 拒绝理由里不许带出整段垃圾：粘进来的一行长度没有上界，而这句话会显示在面板上。
	long := strings.Repeat("x", 5000) + ",PROXY"
	if _, err := ParseRuleLine(long, "DOMAIN-SUFFIX", "PROXY"); err != nil {
		if len(err.Error()) > 600 {
			t.Errorf("拒绝理由长度 %d，没截住", len(err.Error()))
		}
	}
}

func TestHasUserRule(t *testing.T) {
	list := []UserRule{{Type: "DOMAIN-SUFFIX", Value: "a.test", Policy: "PROXY"}}
	if !HasUserRule(list, UserRule{Type: "DOMAIN-SUFFIX", Value: "A.TEST", Policy: "DIRECT"}) {
		t.Error("归一化之后应当认得出是同一条")
	}
	if HasUserRule(list, UserRule{Type: "DOMAIN", Value: "a.test", Policy: "PROXY"}) {
		t.Error("类型不同的两条是两条规则")
	}
}
