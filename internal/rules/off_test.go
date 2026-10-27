package rules

// 「停用这一条」的验收。
//
// 这个功能存在的理由很具体：想查"是不是这条规则把网站弄坏的"，
// 今天唯一的办法是删掉它，而删掉之后就再也想不起来原来写的是什么
// （尤其是从订阅里抄来的那几条）。停用要能一键来回，且**不改变任何其他字段**。
//
// 最要紧的一条不是"关掉的规则不生效"（那太显然），而是
// **关掉一条盖住别人的规则，会让后面那条活过来**——
// 判语那一栏必须跟着变，否则它会在用户刚刚做完"让这条生效"的动作之后，
// 指着那条说"它永远不会命中"。

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readUserFile 读回一份规则文件的正文。测试里读盘的地方统一走它，少一处 err 处理分支。
func readUserFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestDisabledRuleDoesNotMatch 关掉的那条不参与匹配，落到后面的规则或 FINAL 上。
func TestDisabledRuleDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	p := writeRulesIn(t, dir, ""+
		"DOMAIN-SUFFIX,corp.example,DIRECT,off\n"+
		"DOMAIN-SUFFIX,corp.example,PROXY\n"+
		"FINAL,DIRECT\n")
	e, err := Load(p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 第 1 条停用了，所以第 2 条才是答案——引擎取第一条**生效**的规则。
	if got, matched := e.Match(context.Background(), "a.corp.example"); got != PolicyProxy || !strings.Contains(matched, "DOMAIN-SUFFIX,corp.example,PROXY") {
		t.Fatalf("停用的那条仍然在拦: policy=%q matched=%q", got, matched)
	}
}

// TestDisablingACoveringRuleRevivesTheCoveredOne 是这一整块最要紧的一条。
//
// 名单：第 1 条 SUFFIX example.com 压住第 2 条 DOMAIN a.example.com。
// 把第 1 条停用之后，第 2 条必须**真的开始生效**，
// 而不是"引擎里生效了、判语那一栏还说它是死的"。
func TestDisablingACoveringRuleRevivesTheCoveredOne(t *testing.T) {
	list := []UserRule{
		{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"},
		{Type: "DOMAIN", Value: "a.example.com", Policy: "DIRECT"},
	}
	// 起点：第 2 条被第 1 条盖住，判语要说它是死的。
	if got := DeadRules(list, nil); len(got) != 1 {
		t.Fatalf("第 2 条本该被判成死的: %+v", got)
	}
	// 引擎同一时刻也必须给出 PROXY（第 1 条先命中）。
	if p := engineVerdict(t, list); p != PolicyProxy {
		t.Fatalf("起点判定应为 PROXY，实际 %s", p)
	}

	list[0].Disabled = true
	if got := DeadRules(list, nil); len(got) != 0 {
		t.Fatalf("把盖人的那条停用之后，第 2 条活了，判语却还在报: %+v", got)
	}
	// 判语闭嘴还不够，引擎必须真的改成第 2 条的答案。
	if p := engineVerdict(t, list); p != PolicyDirect {
		t.Fatalf("停用第 1 条之后应该走 DIRECT（第 2 条生效），实际 %s", p)
	}
}

// engineVerdict 按这份名单装一个引擎并判定 a.example.com。
// 判语与引擎必须看同一件事，所以两边都要问一遍。
func engineVerdict(t *testing.T, list []UserRule) Policy {
	t.Helper()
	dir := t.TempDir()
	lines := make([]string, 0, len(list)+1)
	for _, r := range list {
		lines = append(lines, r.Line())
	}
	lines = append(lines, "FINAL,DIRECT")
	p := writeRulesIn(t, dir, strings.Join(lines, "\n")+"\n")
	e, err := Load(p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := e.Match(context.Background(), "a.example.com")
	return pol
}

// TestDisabledRuleRoundTripsThroughTheFile 停用状态必须能原样写回去再读出来。
//
// 两条路径分别验：域名类型那一条是面板重建的（走结构体字段），
// 而 IP-CIDR 那一条走 raw 原文——只测前者的话，
// 手写的行会在下一次整表回写时把 off 弄丢（或者反过来，把 no-resolve 弄丢）。
func TestDisabledRuleRoundTripsThroughTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, UserRuleFileName)
	in := []UserRule{
		{Type: "DOMAIN-SUFFIX", Value: "a.test", Policy: "PROXY", Disabled: true},
		{Type: "DOMAIN", Value: "b.test", Policy: "DIRECT", Disabled: true},
		// 钉了节点又停用：两个可选字段要能同时留住。
		{Type: "DOMAIN-SUFFIX", Value: "c.test", Policy: "PROXY", Node: "美西", Disabled: true},
		// 停用状态由用户手写在文件里的那一条（面板重建不了它，只能改 raw）。
		{Type: "IP-CIDR", Value: "10.0.0.0/8", Policy: "DIRECT", raw: "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve,off", Disabled: true},
	}
	if err := SaveUserRules(path, in); err != nil {
		t.Fatal(err)
	}
	body := readUserFile(t, path)
	out, err := parseUserRules(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("读回 %d 条，想要 %d:\n%s", len(out), len(in), body)
	}
	for i := range in {
		if !out[i].Disabled {
			t.Errorf("第 %d 条的停用状态丢了: %q", i+1, out[i].Line())
		}
		if out[i].Node != in[i].Node {
			t.Errorf("第 %d 条的节点丢了: %q", i+1, out[i].Line())
		}
	}
	// 手写那条的 no-resolve 必须还在：只加减 off，不许整行重建。
	if !strings.Contains(out[3].Line(), "no-resolve") {
		t.Errorf("停用一条手写的规则时把 no-resolve 弄丢了: %q", out[3].Line())
	}
	if !strings.HasSuffix(out[3].Line(), ",off") {
		t.Errorf("off 应该留在行尾: %q", out[3].Line())
	}

	// 再全部打开，写盘读回后一个都不许是停用的。
	for i := range out {
		out[i].Disabled = false
	}
	if err := SaveUserRules(path, out); err != nil {
		t.Fatal(err)
	}
	body = readUserFile(t, path)
	again, err := parseUserRules(body)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range again {
		if r.Disabled {
			t.Errorf("第 %d 条打开之后仍被当成停用: %q", i+1, r.Line())
		}
	}
	if strings.Contains(body, ",off") {
		t.Errorf("全部打开之后文件里还留着 off:\n%s", body)
	}
}

// TestSetOffTokenLeavesARegexValueAlone 挡住一个很容易写出来的实现：
// 扫全部字段找 "off"。DOMAIN-REGEX 的模式是任意文本，
// 恰好就是 "off" 这个字并不稀奇（`off` 会匹配任何含 off 的串），
// 那种写法会把用户的模式当成开关删掉。
func TestSetOffTokenLeavesARegexValueAlone(t *testing.T) {
	line := "DOMAIN-REGEX,off,PROXY"
	if got := setOffToken(line, true); got != "DOMAIN-REGEX,off,PROXY,off" {
		t.Errorf("加 off 不该动中间那个字段: %q", got)
	}
	if got := setOffToken(line, false); got != line {
		t.Errorf("这一行末尾不是 off，不该删任何东西: %q", got)
	}
	// 幂等：已经是停用状态再停一次不加第二个。
	once := setOffToken(line, true)
	if got := setOffToken(once, true); got != once {
		t.Errorf("重复停用写出了两个 off: %q", got)
	}
}

// TestFinalCannotBeDisabled 兜底策略没有"停用"这一档。
// 允许它，等于让整张规则表有一个"谁都不接"的状态。
func TestFinalCannotBeDisabled(t *testing.T) {
	dir := t.TempDir()
	p := writeRulesIn(t, dir, "FINAL,DIRECT,off\n")
	if _, err := Load(p, nil, nil); err == nil {
		t.Fatal("FINAL 被停用了还能加载：那没命中时该走谁？")
	} else if !strings.Contains(err.Error(), "FINAL") {
		t.Errorf("报错没说是 FINAL: %v", err)
	}
}

// TestDisabledRuleStillValidated 停用不是把坏规则留在文件里的通道。
// 今天不报错，用户哪天打开它就当场起不来——那才是最难查的时刻。
func TestDisabledRuleStillValidated(t *testing.T) {
	dir := t.TempDir()
	// 一个不认识的类型，停用的。
	p := writeRulesIn(t, dir, "BOGUS,a.test,PROXY,off\nFINAL,DIRECT\n")
	if _, err := Load(p, nil, nil); err == nil {
		t.Fatal("停用的坏规则被放行了")
	}
	// node= 对 DIRECT 没意义，停用的也一样不许带。
	p2 := writeRulesIn(t, dir, "DOMAIN-SUFFIX,a.test,DIRECT,node=美西,off\nFINAL,DIRECT\n")
	if _, err := Load(p2, nil, nil); err == nil {
		t.Fatal("停用的那条绕过了 node= 的策略检查")
	}
}

// TestDisabledRuleNotReportedAsDead 用户自己关掉的规则不该被这一栏当成"写错了"。
func TestDisabledRuleNotReportedAsDead(t *testing.T) {
	list := []UserRule{
		{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"},
		{Type: "DOMAIN", Value: "a.example.com", Policy: "DIRECT", Disabled: true},
	}
	if got := DeadRules(list, nil); len(got) != 0 {
		t.Fatalf("自己关掉的那条被当成死规则报出来了: %+v", got)
	}
}

// TestUserRuleDescIsWhatTheEngineReports 钉住 UserRule.Desc() 与引擎命中依据的一致性。
//
// 这一条是整个"每条规则命中多少次"那栏的地基：计数按引擎写下的那串文本归并，
// 而面板要把它对回自己列出的某一行，靠的就是 Desc() 现算出**同一串**。
// 两边只要有一天分家（desc 又加了一档后缀、或者某类规则的键拼法不同），
// 表现不是报错，是那一列安静地全是 0——谁也不会想到是格式对不上。
// 所以这里不用字符串比对，而是让引擎真的判一次，拿它说的那句来比。
func TestUserRuleDescIsWhatTheEngineReports(t *testing.T) {
	cases := []UserRule{
		{Type: "DOMAIN-SUFFIX", Value: "a.test", Policy: "PROXY"},
		{Type: "DOMAIN", Value: "b.test", Policy: "DIRECT"},
		{Type: "DOMAIN-KEYWORD", Value: "cdn", Policy: "REJECT"},
		{Type: "DOMAIN-SUFFIX", Value: "c.test", Policy: "PROXY", Node: "美西"},
		{Type: "DOMAIN", Value: "d.test", Policy: "DIRECT"},
	}
	dir := t.TempDir()
	var body []string
	for _, r := range cases {
		body = append(body, r.Line())
	}
	body = append(body, "FINAL,DIRECT")
	path := writeRulesIn(t, dir, strings.Join(body, "\n")+"\n")
	e, err := Load(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 每个用例挑一个只会被它自己命中的主机名，避免"第一条先命中"串了台。
	hosts := []string{"x.a.test", "b.test", "zzcdnyy.d.example", "x.c.test", "d.test"}
	for i, r := range cases {
		_, matched := e.Match(context.Background(), hosts[i])
		if matched != r.Desc() {
			t.Errorf("第 %d 条：引擎说的是 %q，面板会去找 %q —— 这一条的命中计数会永远是 0",
				i+1, matched, r.Desc())
		}
	}
}

// TestUserRuleDescSkipsUnknownType：认不出的类型返回空串，调用方跳过它。
// 编一个对不上的键比不报这个数更糟——它看起来像"这条从没命中过"。
func TestUserRuleDescSkipsUnknownType(t *testing.T) {
	if got := (UserRule{Type: "NOPE", Value: "a.test", Policy: "PROXY"}).Desc(); got != "" {
		t.Errorf("认不出的类型编出了一个键: %q", got)
	}
}
