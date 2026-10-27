// DOMAIN-REGEX 的语义与失败模式。这个类型比旁边那几个多两件事要钉住：
// 模式在加载期编译（编译失败必须响，不能变成"永不命中"），
// 以及模式文本来自远端订阅（长度与错误信息都得截住）。
package rules

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestDomainRegexMatch(t *testing.T) {
	e := load(t, `
DOMAIN-REGEX,\.co\.uk$,REJECT
DOMAIN-REGEX,^Google\.,PROXY
DOMAIN-REGEX,^(api|cdn)\.(foo|bar)\.com$,PROXY
DOMAIN-REGEX,telemetry,PROXY
FINAL,DIRECT
`, fakeGeo{}, fakeResolver{})

	cases := []struct {
		host    string
		want    Policy
		matched string
	}{
		// 不锚定开头：模式里没有 ^，所以任意前缀都能命中结尾那一段。
		{"shop.co.uk", PolicyReject, "DOMAIN-REGEX,\\.co\\.uk$,REJECT"},
		{"www.example.co.uk", PolicyReject, ""},
		// 缺了模式要求的那个点：它不是 DOMAIN-SUFFIX，少一个字符就是不命中。
		{"co.uk", PolicyDirect, ""},
		// (?i) 是自动加的：模式里写大写，归一后的小写域名照样命中。
		{"google.com", PolicyProxy, ""},
		// 写了 ^ 就真的锚在开头——子域名不算命中，这一条是"锚不锚"的分界。
		{"mail.google.com", PolicyDirect, ""},
		{"api.foo.com", PolicyProxy, ""},
		{"cdn.bar.com", PolicyProxy, ""},
		{"api.baz.com", PolicyDirect, ""},
		// 不带元字符的模式退化成子串匹配，和 DOMAIN-KEYWORD 同一行为。
		{"x.telemetry.y.net", PolicyProxy, ""},
	}
	for _, c := range cases {
		got, matched := e.Match(context.Background(), c.host)
		if got != c.want {
			t.Errorf("Match(%q) = %s，想要 %s（命中依据 %q）", c.host, got, c.want, matched)
		}
		if c.matched != "" && matched != c.matched {
			t.Errorf("Match(%q) 的命中依据 = %q，想要 %q", c.host, matched, c.matched)
		}
	}
	// 命中依据要能看出是哪条 regex 拦的：desc 里带的就是文件里那一行模式。
	if _, m := e.Match(context.Background(), "shop.co.uk"); !strings.HasPrefix(m, "DOMAIN-REGEX,") {
		t.Errorf("命中依据里没有类型名：日志与连接表会说不出是谁拦的（%q）", m)
	}
}

// TestDomainRegexIsADomainRule 装表位置是行为问题，不只是统计问题：
// 域名规则在 DNS 之前跑，进错表（ipRules）就会让每个域名都先付一次解析。
func TestDomainRegexIsADomainRule(t *testing.T) {
	rs := &countingResolver{addrs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	e := load(t, "DOMAIN-REGEX,^block\\..*$,REJECT\nFINAL,PROXY\n", fakeGeo{}, rs)
	domain, ip := e.Stats()
	if domain != 1 || ip != 0 {
		t.Fatalf("装表错位：domain=%d ip=%d，想要 1/0", domain, ip)
	}
	if got, _ := e.Match(context.Background(), "block.example.com"); got != PolicyReject {
		t.Errorf("Match = %s，想要 REJECT", got)
	}
	if rs.calls != 0 {
		t.Errorf("域名已被 regex 判掉，却还是解析了 %d 次", rs.calls)
	}
}

type countingResolver struct {
	addrs []netip.Addr
	calls int
}

func (c *countingResolver) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	c.calls++
	return c.addrs, nil
}

// TestDomainRegexBadPatternRefused 语法错的规则必须在加载时炸掉。
//
// 这是整个用例的核：解析放行、加载不报错、然后这条规则一条都不命中，
// 等于在黑名单上静默开个洞——正是 kind_guard_test 给每个新类型守的那扇门。
func TestDomainRegexBadPatternRefused(t *testing.T) {
	for _, pat := range []string{"[unclosed", "^(a|b", "*quant", "(?P<>)", "a**", "[z-a]"} {
		_, err := Load(writeRules(t, "DOMAIN-REGEX,"+pat+",PROXY\nFINAL,PROXY\n"), fakeGeo{}, fakeResolver{})
		if err == nil {
			t.Errorf("模式 %q 装上了：编译失败必须拒绝加载", pat)
			continue
		}
		if !strings.Contains(err.Error(), "模式无法编译") {
			t.Errorf("模式 %q 的拒绝理由不对：%v", pat, err)
		}
	}
}

// TestDomainRegexCommaIsTheSeparator 钉住一个真实存在的表达力边界。
//
// 逗号是这一行的字段分隔符，所以 `{2,3}` 这类量词写不进规则文件——
// 它会被拆成"多个值"而拒绝加载。方向是对的（宁可拒掉也不静默走偏），
// 但这条限制必须有人明说：等用户自己撞上去时，那句 "has more than one value"
// 完全看不出根因是逗号。
func TestDomainRegexCommaIsTheSeparator(t *testing.T) {
	_, err := Load(writeRules(t, "DOMAIN-REGEX,^a{2,3}b$,PROXY\nFINAL,PROXY\n"), fakeGeo{}, fakeResolver{})
	if err == nil {
		t.Fatal("带逗号的量词应当装不上：逗号就是字段分隔符")
	}
	if !strings.Contains(err.Error(), "more than one value") {
		t.Errorf("拒绝理由不对：%v", err)
	}
	// 把逗号换掉（这里少写一个重复次数）就应当正常装上并命中。
	e := load(t, "DOMAIN-REGEX,^a{2}b,PROXY\nFINAL,DIRECT\n", fakeGeo{}, fakeResolver{})
	if got, _ := e.Match(context.Background(), "aabb.example"); got != PolicyProxy {
		t.Errorf("Match = %s，想要 PROXY", got)
	}
}

// TestDomainRegexPatternLengthCap 长度封顶是给远端订阅准备的。
// Scanner 允许一行 1MB，不封顶的话一行垃圾就是一份每次加载都要编译的巨大模式，
// 而那条规则的命中依据还会原样进日志与面板。
func TestDomainRegexPatternLengthCap(t *testing.T) {
	tooLong := "^" + strings.Repeat("a", maxRegexLen) + "$"
	_, err := Load(writeRules(t, "DOMAIN-REGEX,"+tooLong+",PROXY\nFINAL,PROXY\n"), fakeGeo{}, fakeResolver{})
	if err == nil {
		t.Fatalf("超过 %d 字节的模式装上了，封顶没生效", maxRegexLen)
	}
	if !strings.Contains(err.Error(), "过长") {
		t.Errorf("拒绝理由不对：%v", err)
	}
	// 错误信息会进日志与面板，长度必须跟着上限走而不是跟着输入走。
	if len(err.Error()) > 1024 {
		t.Errorf("错误信息长度 %d，没被截住", len(err.Error()))
	}
	// 上限以内的正常模式必须装得上——别把截断写成误伤。
	if _, err := Load(writeRules(t, "DOMAIN-REGEX,"+strings.Repeat("a", maxRegexLen-4)+"$,PROXY\nFINAL,PROXY\n"), fakeGeo{}, fakeResolver{}); err != nil {
		t.Errorf("上限以内的模式被拒了：%v", err)
	}
}

// TestDomainRegexCompileErrorStaysReadable 编译错误里嵌的是模式本身，
// 而模式来自远端订阅：控制字符与非法 UTF-8 都不能原样进日志与面板。
func TestDomainRegexCompileErrorStaysReadable(t *testing.T) {
	for _, pat := range []string{"[\x7fa", "(?i)[\xc3", "[\xff\xfe-" + strings.Repeat("x", 200)} {
		_, err := Load(writeRules(t, "DOMAIN-REGEX,"+pat+",PROXY\nFINAL,PROXY\n"), fakeGeo{}, fakeResolver{})
		if err == nil {
			t.Fatalf("模式 %q 竟然合法，这条样本不再适用", pat)
		}
		msg := err.Error()
		if len(msg) > 1024 {
			t.Fatalf("错误信息长度 %d，没被截住", len(msg))
		}
		for i := 0; i < len(msg); i++ {
			if c := msg[i]; c < 0x20 && c != '\n' || c == 0x7f {
				t.Fatalf("错误信息里带了控制字符 0x%02x: %q", c, msg)
			}
		}
	}
}

// TestUserRulesPreserveRegex 手写在 user-rules.txt 里的 regex 规则不能被面板改坏。
//
// 面板的三格表单（类型+域名+策略）表达不了带逗号的模式，所以它走 raw 原样回写；
// 这里同时验"回写后还能装回来"和"回写时没把别的行丢掉"。
func TestUserRulesPreserveRegex(t *testing.T) {
	path := t.TempDir() + "/user-rules.txt"
	body := "# 注释\nDOMAIN-REGEX,^(api|cdn)\\.foo\\.com$,PROXY\nDOMAIN-SUFFIX,example.com,DIRECT\n"
	list, err := parseUserRules(body)
	if err != nil {
		t.Fatalf("parseUserRules: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("读回 %d 条，想要 2", len(list))
	}
	if list[0].Type != "DOMAIN-REGEX" || list[0].raw == "" {
		t.Errorf("regex 规则应当照实报类型名并按原文只读保存，得到 type=%q raw=%q", list[0].Type, list[0].raw)
	}
	if err := SaveUserRules(path, list); err != nil {
		t.Fatalf("SaveUserRules: %v", err)
	}
	again, err := LoadUserRules(path)
	if err != nil {
		t.Fatalf("LoadUserRules: %v", err)
	}
	if len(again) != 2 || again[0].Line() != list[0].Line() {
		t.Errorf("回写后规则变了：%+v", again)
	}
	// 面板能编辑的那一档必须明确拒绝 regex：否则用户会以为自己加上了，
	// 而 Normalize 会把模式转小写、还会因为里面有逗号而报"多个值"。
	if err := (&UserRule{Type: "DOMAIN-REGEX", Value: `^a|b$`, Policy: "PROXY"}).Normalize(); err == nil {
		t.Error("面板应当不允许新增 DOMAIN-REGEX（只能手写），Normalize 却放行了")
	}
}
