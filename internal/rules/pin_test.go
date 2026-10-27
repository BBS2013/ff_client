// node=<节点名> 这个可选字段的解析与判据。
//
// 这个字段最容易出事的三处都在这里有名字：
//  1. 它必须被认成"可选字段"，否则会被当成第二个值而拒掉整行；
//  2. 它必须进 desc()，否则连接表与日志说不出这批字节走了谁；
//  3. 它必须只在 PROXY 上成立，给 DIRECT/REJECT 配节点等于让用户以为钉上了。
package rules

import (
	"context"
	"strings"
	"testing"
)

func TestNodeTokenParses(t *testing.T) {
	r, _, err := parseLine("DOMAIN-SUFFIX,example.com,PROXY,node=US-LA", 1)
	if err != nil {
		t.Fatalf("合法写法被拒: %v", err)
	}
	if r.node != "US-LA" {
		t.Fatalf("节点名没进来: %+v", r)
	}
	if d := r.desc(); !strings.Contains(d, "node=US-LA") {
		t.Errorf("命中依据里看不出钉了谁: %q", d)
	}
	// 键名大小写不敏感，值里首尾空格抹掉：手写规则时这两样必然会碰到。
	for _, line := range []string{
		"DOMAIN-SUFFIX,a.test,PROXY,NODE=SG",
		"DOMAIN-SUFFIX,a.test,PROXY,node= SG ",
		"DOMAIN-SUFFIX,a.test,node=SG,PROXY",
	} {
		r2, _, err := parseLine(line, 1)
		if err != nil {
			t.Errorf("%q 被拒: %v", line, err)
			continue
		}
		if r2.node != "SG" || r2.policy != PolicyProxy {
			t.Errorf("%q 解析成 %+v", line, r2)
		}
	}

	// 与 no-resolve 同时出现（IP 规则上最常见）也要认。
	r3, _, err := parseLine("IP-CIDR,10.9.0.0/16,PROXY,node=SG,no-resolve", 1)
	if err != nil || r3.node != "SG" || !r3.noResolve {
		t.Errorf("node= 与 no-resolve 挤在一起就解析不动: %+v %v", r3, err)
	}
}

func TestNodeTokenRefusesBadShapes(t *testing.T) {
	bad := map[string]string{
		"DOMAIN-SUFFIX,a.test,PROXY,node=":                                     "空",
		"DOMAIN-SUFFIX,a.test,PROXY,node=US,node=SG":                           "两个",
		"DOMAIN-SUFFIX,a.test,DIRECT,node=US":                                  "直连带节点",
		"DOMAIN-SUFFIX,a.test,REJECT,node=US":                                  "拦截带节点",
		"FINAL,PROXY,node=US":                                                  "兜底带节点",
		"DOMAIN-SUFFIX,a.test,PROXY,node=" + strings.Repeat("n", maxNodeLen+1): "过长",
		"DOMAIN-SUFFIX,a.test,PROXY,node=a\x01b":                               "控制字符",
	}
	for line, what := range bad {
		if _, _, err := parseLine(line, 1); err == nil {
			t.Errorf("%s的那一行竟然装上了: %q", what, line)
		}
	}
	// 报错不能把整段垃圾带出去（值来自远端订阅，错误会进日志与面板）。
	long := "DOMAIN-SUFFIX,a.test,PROXY,node=" + strings.Repeat("q", 4000)
	if _, _, err := parseLine(long, 1); err != nil && len(err.Error()) > 1024 {
		t.Errorf("错误信息长度 %d，没被截住", len(err.Error()))
	}
}

// TestMatchNodeCarriesThePin 判定要能把节点名带出来，而且是**命中那一条**的。
func TestMatchNodeCarriesThePin(t *testing.T) {
	e := load(t, `
DOMAIN-SUFFIX,pinned.test,PROXY,node=US-LA
DOMAIN-SUFFIX,plain.test,PROXY
FINAL,DIRECT
`, fakeGeo{}, fakeResolver{})

	if p, m, n := e.MatchNode(context.Background(), "a.pinned.test"); p != PolicyProxy || n != "US-LA" {
		t.Errorf("钉住的这条: %s %q %q", p, m, n)
	}
	if p, _, n := e.MatchNode(context.Background(), "a.plain.test"); p != PolicyProxy || n != "" {
		t.Errorf("没钉的这条带出了节点名 %q", n)
	}
	if p, _, n := e.MatchNode(context.Background(), "other.test"); p != PolicyDirect || n != "" {
		t.Errorf("兜底那条: %s %q", p, n)
	}

	// Match（旧签名）必须仍然给同样的策略：DNS 那一侧只用它，不能因为新字段而变。
	if p, m := e.Match(context.Background(), "a.pinned.test"); p != PolicyProxy || !strings.Contains(m, "node=US-LA") {
		t.Errorf("Match 的行为变了: %s %q", p, m)
	}
}

// TestBlocklistCannotCarryAPin 配置的 block: 段铺出来的那条不许带节点名：
// 它策略是 REJECT，一个字节都不发，带出去只会让日志说"拦截走了 US-LA"。
func TestBlocklistCannotCarryAPin(t *testing.T) {
	e := load(t, "DOMAIN-SUFFIX,a.test,PROXY\nFINAL,PROXY\n", fakeGeo{}, fakeResolver{})
	e.SetBlocklist([]string{"ads.example.com"})
	if _, m, n := e.MatchNode(context.Background(), "ads.example.com"); n != "" || !strings.Contains(m, "(block)") {
		t.Errorf("拦截那条报出了节点名或丢了来源: %q %q", m, n)
	}
}

// TestSavedNodeRuleRoundTrips 手写的 node= 行必须原样活过面板那一次整表回写。
//
// 这一条是本文件最要紧的用例：UserRule 只有 类型+域名+策略 三格时，
// 加一条域名规则就会把别人手写的 node= 抹掉——而"我的固定节点怎么不生效了"
// 查起来完全没有线索，因为文件里那一行看起来"还在"。
func TestSavedNodeRuleRoundTrips(t *testing.T) {
	body := "DOMAIN-SUFFIX,shop.test,PROXY,node=US-LA\nDOMAIN,keep.test,DIRECT\n"
	list, err := parseUserRules(body)
	if err != nil {
		t.Fatalf("parseUserRules: %v", err)
	}
	if list[0].Type != "DOMAIN-SUFFIX" || list[0].Node != "US-LA" {
		t.Fatalf("节点名没读进 UserRule: %+v", list[0])
	}
	if list[0].Line() != "DOMAIN-SUFFIX,shop.test,PROXY,node=US-LA" {
		t.Fatalf("回写出来的行丢了 node=: %q", list[0].Line())
	}
	path := t.TempDir() + "/user-rules.txt"
	if err := SaveUserRules(path, list); err != nil {
		t.Fatal(err)
	}
	again, err := LoadUserRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if again[0].Line() != list[0].Line() || again[0].Node != "US-LA" {
		t.Fatalf("整表回写把固定节点改坏了: %+v", again[0])
	}
	// 界面能编辑的那一档也要能表达它（否则加了节点就变成只读行，用户没法改）。
	if err := (&UserRule{Type: "DOMAIN-SUFFIX", Value: "shop.test", Policy: "PROXY", Node: "US-LA"}).Normalize(); err != nil {
		t.Errorf("带 node= 的域名规则应当可以新增: %v", err)
	}
	for _, r := range []*UserRule{
		{Type: "DOMAIN", Value: "a.test", Policy: "PROXY", Node: "US,LA"},
		{Type: "DOMAIN", Value: "a.test", Policy: "PROXY", Node: "有 空格"},
		{Type: "DOMAIN", Value: "a.test", Policy: "PROXY", Node: "x=1"},
	} {
		if err := r.Normalize(); err == nil {
			t.Errorf("节点名 %q 应当被拒", r.Node)
		}
	}
	// 同类型同域名只留一条：换节点等于换那条的去处。
	two := UpsertUserRule(list, UserRule{Type: "DOMAIN-SUFFIX", Value: "shop.test", Policy: "PROXY", Node: "SG"})
	if len(two) != 2 || two[0].Node != "SG" {
		t.Fatalf("换节点没落到同一条上: %+v", two)
	}
}
