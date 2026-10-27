// 死规则判据的验收。除了"报得对不对"，这里还拿真引擎对一遍答案：
// 这条判据会让人去删规则，所以它错一次比不报更糟。
package rules

import (
	"context"
	"strconv"
	"strings"
	"testing"
)

func TestDeadUserRules(t *testing.T) {
	cases := []struct {
		name    string
		list    []UserRule
		blocked []string
		want    int // 期望报出几条
		wantHas string
	}{
		{
			name: "后缀压住精确域名",
			list: []UserRule{
				{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"},
				{Type: "DOMAIN", Value: "www.example.com", Policy: "DIRECT"},
			},
			want:    1,
			wantHas: "第 2 条 DOMAIN,www.example.com,DIRECT 永远不会命中",
		},
		{
			name: "换过来就不是死的",
			list: []UserRule{
				{Type: "DOMAIN", Value: "www.example.com", Policy: "DIRECT"},
				{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"},
			},
			want: 0,
		},
		{
			name: "关键字在前面能盖住整段后缀",
			list: []UserRule{
				{Type: "DOMAIN-KEYWORD", Value: "google", Policy: "PROXY"},
				{Type: "DOMAIN-SUFFIX", Value: "google.com", Policy: "DIRECT"},
			},
			want:    1,
			wantHas: "第 2 条 DOMAIN-SUFFIX,google.com,DIRECT 永远不会命中",
		},
		{
			// 反过来的包含关系判不出来，也不该硬猜：正则同理。
			name: "后缀盖不住关键字",
			list: []UserRule{
				{Type: "DOMAIN-SUFFIX", Value: "google.com", Policy: "PROXY"},
				{Type: "DOMAIN-KEYWORD", Value: "google", Policy: "DIRECT"},
			},
			want: 0,
		},
		{
			name: "一模一样的两条",
			list: []UserRule{
				{Type: "DOMAIN", Value: "a.test", Policy: "PROXY"},
				{Type: "DOMAIN", Value: "a.test", Policy: "DIRECT"},
			},
			want: 1,
		},
		{
			name: "点边界不是后缀",
			list: []UserRule{
				{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"},
				{Type: "DOMAIN-SUFFIX", Value: "notexample.com", Policy: "DIRECT"},
				{Type: "DOMAIN", Value: "myexample.com", Policy: "DIRECT"},
			},
			want: 0,
		},
		{
			// 第 2 条其实真被第 1 条那中正则盖住了，但这里刻意报 0：
			// 正则的包含关系判不准，宁可少说一句也不要说错一句——
			// "这条永远不会命中"是一句会让人去删规则的话。
			name: "正则一律不断言",
			list: []UserRule{
				{Type: "DOMAIN-REGEX", Value: `^.*\.example\.com$`, Policy: "PROXY"},
				{Type: "DOMAIN", Value: "www.example.com", Policy: "DIRECT"},
				{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"},
				{Type: "DOMAIN-REGEX", Value: `^api\.`, Policy: "DIRECT"},
			},
			want: 0,
		},
		{
			name:    "被拦截名单盖住",
			list:    []UserRule{{Type: "DOMAIN-SUFFIX", Value: "ads.example.com", Policy: "PROXY"}},
			blocked: []string{"ads.example.com"},
			want:    1,
			wantHas: "拦截名单里的 ads.example.com 先把它拦下了",
		},
		{
			name:    "名单是后缀语义，子域也算盖住",
			list:    []UserRule{{Type: "DOMAIN", Value: "api.ads.example.com", Policy: "PROXY"}},
			blocked: []string{" ads.example.com "},
			want:    1,
		},
		{
			name:    "名单盖不住旁支",
			list:    []UserRule{{Type: "DOMAIN", Value: "notads.example.com", Policy: "PROXY"}},
			blocked: []string{"ads.example.com"},
			want:    0,
		},
	}
	for _, c := range cases {
		got := DeadUserRules(c.list, c.blocked)
		if len(got) != c.want {
			t.Errorf("%s: 报出 %d 条，想要 %d:\n  %s", c.name, len(got), c.want, strings.Join(got, "\n  "))
			continue
		}
		if c.wantHas != "" && (len(got) == 0 || !strings.Contains(got[0], c.wantHas)) {
			t.Errorf("%s: 那句话不对: %q", c.name, got[0])
		}
	}
}

// TestDeadUserRulesAgreeWithEngine 是这条判据的真正验收：
// 说一条规则是死的，就得能拿出引擎自己给出的同一个答案。
//
// 每个样本都同时喂给 DeadUserRules 和真的 Engine，两边必须一致：
// 判据说死的，引擎对那个代表域名必须给出**前面那条**的策略。
func TestDeadUserRulesAgreeWithEngine(t *testing.T) {
	sets := [][]UserRule{
		{
			{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"},
			{Type: "DOMAIN", Value: "www.example.com", Policy: "DIRECT"},
		},
		{
			{Type: "DOMAIN-KEYWORD", Value: "google", Policy: "PROXY"},
			{Type: "DOMAIN-SUFFIX", Value: "google.com", Policy: "DIRECT"},
		},
		{
			{Type: "DOMAIN", Value: "a.test", Policy: "PROXY"},
			{Type: "DOMAIN", Value: "a.test", Policy: "DIRECT"},
		},
		{
			{Type: "DOMAIN-SUFFIX", Value: "ok.test", Policy: "DIRECT"},
			{Type: "DOMAIN", Value: "www.ok.test", Policy: "PROXY"},
			{Type: "DOMAIN-KEYWORD", Value: "keyword", Policy: "PROXY"},
			{Type: "DOMAIN", Value: "has-keyword-here.test", Policy: "DIRECT"},
		},
	}
	for _, list := range sets {
		dead := DeadUserRules(list, nil)
		eng := load(t, renderRuleLines(list)+"\nFINAL,PROXY\n", fakeGeo{}, fakeResolver{})
		for _, line := range dead {
			// 句子开头是"第 N 条 <那一行> 永远不会命中：…"，取那个 N。
			field := strings.TrimPrefix(line, "第 ")
			i := strings.Index(field, " 条 ")
			if i < 0 {
				t.Fatalf("读不懂这句: %q", line)
			}
			n, err := strconv.Atoi(field[:i])
			if err != nil || n < 1 || n > len(list) {
				t.Fatalf("句子里的序号不对: %q (%v)", line, err)
			}
			deadRule := list[n-1]
			p, matched := eng.Match(context.Background(), representativeHost(deadRule.Type, deadRule.Value))
			if matched == deadRule.Line() {
				t.Errorf("判据说 %q 是死的，引擎却真的命中了它（策略 %s）", deadRule.Line(), p)
			}
		}
	}
}

// representativeHost 给出"这条规则一定会命中"的一个域名。
func representativeHost(typ, val string) string {
	switch typ {
	case "DOMAIN":
		return val
	case "DOMAIN-SUFFIX":
		return "zz." + val
	}
	return val + ".example"
}

func renderRuleLines(list []UserRule) string {
	var b strings.Builder
	for _, r := range list {
		b.WriteString(r.Line() + "\n")
	}
	return b.String()
}
