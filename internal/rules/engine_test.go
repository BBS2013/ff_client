package rules

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGeo 用固定表模拟 mmdb，避免单测依赖真实数据库。
type fakeGeo map[string]string

func (f fakeGeo) Country(ip netip.Addr) (string, bool) {
	cc, ok := f[ip.String()]
	return cc, ok
}

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	addrs, ok := f[host]
	if !ok {
		return nil, context.DeadlineExceeded
	}
	return addrs, nil
}

func mustParseAll(t *testing.T, s string) []netip.Addr {
	t.Helper()
	var out []netip.Addr
	for _, f := range strings.Fields(s) {
		a, err := netip.ParseAddr(f)
		if err != nil {
			t.Fatalf("bad addr %q: %v", f, err)
		}
		out = append(out, a)
	}
	return out
}

func writeRules(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func load(t *testing.T, body string, geo GeoLookup, rs Resolver) *Engine {
	t.Helper()
	e, err := Load(writeRules(t, body), geo, rs)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return e
}

func TestDomainRules(t *testing.T) {
	e := load(t, `
DOMAIN,www.example.com,DIRECT
DOMAIN-SUFFIX,google.com,PROXY
DOMAIN-KEYWORD,youtube,PROXY
FINAL,PROXY
`, fakeGeo{}, fakeResolver{})

	cases := []struct {
		host   string
		policy Policy
	}{
		{"www.example.com", PolicyDirect},
		{"WWW.EXAMPLE.COM", PolicyDirect}, // 大小写不敏感
		{"example.com", PolicyProxy},      // DOMAIN 不匹配子域
		{"google.com", PolicyProxy},       // 自身即命中 SUFFIX
		{"mail.google.com", PolicyProxy},  // 子域命中 SUFFIX
		{"notgoogle.com", PolicyProxy},    // KEYWORD? 否，走 FINAL
		{"www.youtube.com", PolicyProxy},  // KEYWORD
		{"a.b.youtube.com", PolicyProxy},  // KEYWORD
		{"example.org", PolicyProxy},      // FINAL
		{"google.com.", PolicyProxy},      // 尾点归一
	}
	for _, c := range cases {
		if got, _ := e.Match(context.Background(), c.host); got != c.policy {
			t.Errorf("Match(%q) = %s, want %s", c.host, got, c.policy)
		}
	}
}

func TestDomainSuffixRequiresDotBoundary(t *testing.T) {
	// DOMAIN-SUFFIX,google.com 不应命中 evilgoogle.com
	e := load(t, "DOMAIN-SUFFIX,google.com,DIRECT\nFINAL,PROXY\n", fakeGeo{}, fakeResolver{})
	if got, _ := e.Match(context.Background(), "evilgoogle.com"); got != PolicyProxy {
		t.Errorf("evilgoogle.com 命中了 DOMAIN-SUFFIX，得到 %s", got)
	}
}

func TestIPCIDRAndGeoIP(t *testing.T) {
	geo := fakeGeo{
		"114.114.114.114": "CN",
		"8.8.8.8":         "US",
	}
	e := load(t, `
IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
GEOIP,CN,DIRECT
FINAL,PROXY
`, geo, fakeResolver{})

	cases := []struct {
		host   string
		policy Policy
		desc   string
	}{
		{"114.114.114.114", PolicyDirect, "GEOIP,CN,DIRECT"},
		{"8.8.8.8", PolicyProxy, "FINAL"},
		{"10.1.2.3", PolicyDirect, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"},
		{"192.168.1.1", PolicyProxy, "FINAL"},
	}
	for _, c := range cases {
		got, desc := e.Match(context.Background(), c.host)
		if got != c.policy || desc != c.desc {
			t.Errorf("Match(%q) = (%s, %q), want (%s, %q)", c.host, got, desc, c.policy, c.desc)
		}
	}
}

func TestGeoIPCaseInsensitiveCountryCode(t *testing.T) {
	geo := fakeGeo{"1.2.3.4": "CN"}
	e := load(t, "GEOIP,cn,DIRECT\nFINAL,PROXY\n", geo, fakeResolver{})
	if got, _ := e.Match(context.Background(), "1.2.3.4"); got != PolicyDirect {
		t.Errorf("小写国家码未命中，得到 %s", got)
	}
}

func TestResolverOnlyInvokedWhenNeeded(t *testing.T) {
	geo := fakeGeo{"114.114.114.114": "CN"}
	rs := fakeResolver{"www.baidu.com": mustParseAll(t, "114.114.114.114")}

	// 全部 IP 规则都 no-resolve 时不应该触发 DNS。
	noResolve := load(t, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,PROXY\n", geo, rs)
	if noResolve.needResolve {
		t.Error("needResolve 应为 false")
	}

	// 有 GEOIP 规则（未标 no-resolve）时应触发 DNS 并按解析结果分流。
	withGeo := load(t, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nGEOIP,CN,DIRECT\nFINAL,PROXY\n", geo, rs)
	if !withGeo.needResolve {
		t.Error("needResolve 应为 true")
	}
	got, desc := withGeo.Match(context.Background(), "www.baidu.com")
	if got != PolicyDirect || desc != "GEOIP,CN,DIRECT" {
		t.Errorf("Match(www.baidu.com) = (%s, %q), want (DIRECT, GEOIP,CN,DIRECT)", got, desc)
	}
}

func TestDomainRuleWinsOverResolve(t *testing.T) {
	// 域名规则先于 DNS 判定，解析结果不应覆盖域名规则的结论。
	rs := fakeResolver{"blocked.example": mustParseAll(t, "114.114.114.114")}
	geo := fakeGeo{"114.114.114.114": "CN"}
	e := load(t, "DOMAIN,blocked.example,PROXY\nGEOIP,CN,DIRECT\nFINAL,PROXY\n", geo, rs)
	if got, desc := e.Match(context.Background(), "blocked.example"); got != PolicyProxy || desc != "DOMAIN,blocked.example,PROXY" {
		t.Errorf("got (%s, %q), want (PROXY, DOMAIN,blocked.example,PROXY)", got, desc)
	}
}

func TestDNSFailureDegradesToFinal(t *testing.T) {
	rs := fakeResolver{} // 任何域名都解析失败
	e := load(t, "GEOIP,CN,DIRECT\nFINAL,PROXY\n", fakeGeo{}, rs)
	got, desc := e.Match(context.Background(), "nonexistent.invalid")
	if got != PolicyProxy || desc != "FINAL(dns-failed)" {
		t.Errorf("got (%s, %q), want (PROXY, FINAL(dns-failed))", got, desc)
	}
}

func TestIPRuleOrderMatters(t *testing.T) {
	geo := fakeGeo{"114.114.114.114": "CN"}
	// 精确 IP 规则排在 GEOIP 之前，应优先命中。
	e := load(t, `
IP-CIDR,114.114.114.114/32,PROXY,no-resolve
GEOIP,CN,DIRECT
FINAL,DIRECT
`, geo, fakeResolver{})
	got, desc := e.Match(context.Background(), "114.114.114.114")
	if got != PolicyProxy || desc != "IP-CIDR,114.114.114.114/32,PROXY,no-resolve" {
		t.Errorf("got (%s, %q), want PROXY 优先命中", got, desc)
	}
}

func TestNoResolveFlagAcceptedInEitherOrder(t *testing.T) {
	// Clash 风格把 no-resolve 放在最后；也应容忍写在 POLICY 之前。
	body := "IP-CIDR,10.0.0.0/8,no-resolve,DIRECT\nFINAL,PROXY\n"
	e := load(t, body, fakeGeo{}, fakeResolver{})
	if e.needResolve {
		t.Error("no-resolve 未被识别，needResolve 不应为 true")
	}
	if got, _ := e.Match(context.Background(), "10.0.0.1"); got != PolicyDirect {
		t.Errorf("got %s, want DIRECT", got)
	}
}

func TestCommentsAndBlankLinesIgnored(t *testing.T) {
	e := load(t, `
# 注释行

   # 缩进注释
DOMAIN-SUFFIX,example.org,DIRECT   # 行尾注释

FINAL,PROXY
`, fakeGeo{}, fakeResolver{})
	dom, ip := e.Stats()
	if dom != 1 || ip != 0 {
		t.Errorf("Stats = (%d, %d), want (1, 0)", dom, ip)
	}
	if got, _ := e.Match(context.Background(), "a.example.org"); got != PolicyDirect {
		t.Errorf("got %s, want DIRECT", got)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"未知类型", "BOGUS,x,DIRECT\n"},
		{"缺少策略", "DOMAIN-SUFFIX,example.com\n"},
		{"CIDR 非法", "IP-CIDR,not-a-cidr,DIRECT\n"},
		{"国家码长度错", "GEOIP,CHN,DIRECT\n"},
		{"多个策略", "DOMAIN,a.com,DIRECT,PROXY\n"},
		{"多个值", "DOMAIN,a.com,b.com,DIRECT\n"},
		{"规则文件为空", "# 只有注释\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Load(writeRules(t, c.body), fakeGeo{}, fakeResolver{}); err == nil {
				t.Fatalf("期望报错，实际通过：%s", strings.TrimSpace(c.body))
			}
		})
	}
}

func TestGeoIPRuleRequiresDatabase(t *testing.T) {
	_, err := Load(writeRules(t, "GEOIP,CN,DIRECT\nFINAL,PROXY\n"), nil, fakeResolver{})
	if err == nil {
		t.Fatal("GEOIP 规则缺少 mmdb 时应报错")
	}
	if !strings.Contains(err.Error(), "geoip") {
		t.Errorf("错误信息应提及 geoip，实际：%v", err)
	}
}

func TestDuplicateFinalRejected(t *testing.T) {
	_, err := Load(writeRules(t, "FINAL,DIRECT\nFINAL,PROXY\n"), fakeGeo{}, fakeResolver{})
	if err == nil {
		t.Fatal("重复 FINAL 应报错")
	}
}

func TestFinalPolicyHonored(t *testing.T) {
	e := load(t, "DOMAIN-SUFFIX,a.com,PROXY\nFINAL,DIRECT\n", fakeGeo{}, fakeResolver{})
	if e.Final() != PolicyDirect {
		t.Errorf("Final() = %s, want DIRECT", e.Final())
	}
	if got, _ := e.Match(context.Background(), "other.com"); got != PolicyDirect {
		t.Errorf("got %s, want DIRECT", got)
	}
}

func TestGeoIPMissingEntryFallsThrough(t *testing.T) {
	// mmdb 里没有该 IP 时不应误判，应继续走到后续规则/FINAL。
	e := load(t, "GEOIP,CN,DIRECT\nFINAL,PROXY\n", fakeGeo{}, fakeResolver{})
	if got, desc := e.Match(context.Background(), "9.9.9.9"); got != PolicyProxy || desc != "FINAL" {
		t.Errorf("got (%s, %q), want (PROXY, FINAL)", got, desc)
	}
}

func TestEmptyHostFallsToFinal(t *testing.T) {
	e := load(t, "DOMAIN,a.com,DIRECT\nFINAL,PROXY\n", fakeGeo{}, fakeResolver{})
	if got, _ := e.Match(context.Background(), "  "); got != PolicyProxy {
		t.Errorf("空 host 应走 FINAL，得到 %s", got)
	}
}

func writeInDir(t *testing.T, dir, name, body string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIncludeResolvesRelativeToIncludingFile(t *testing.T) {
	dir := t.TempDir()
	// 子规则放在子目录里，主文件用相对路径引用，验证基准目录不是进程工作目录。
	writeInDir(t, filepath.Join(dir, "sub"), "list.txt", "DOMAIN-SUFFIX,blocked.example,PROXY\n")
	main := writeInDir(t, dir, "rules.txt", "#include sub/list.txt\nFINAL,DIRECT\n")

	e, err := Load(main, fakeGeo{}, fakeResolver{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got, _ := e.Match(context.Background(), "a.blocked.example"); got != PolicyProxy {
		t.Errorf("被 include 的规则未生效，得到 %s", got)
	}
	if got, _ := e.Match(context.Background(), "ok.example"); got != PolicyDirect {
		t.Errorf("FINAL 应来自主文件，得到 %s", got)
	}
}

// TestIncludeNestingResolvesRelativeToIncludingFile 覆盖 depth ≥ 2 的那层。
//
// TestIncludeResolvesRelativeToIncludingFile 只有一层，而一层的 base
// 恰好等于顶层文件自己的目录——所以它绕开了真正的问题：递归时往下传的是
// **上一层**的 base，于是嵌套的 #include 一律从顶层目录找。
// 下面这个布局里 `../shared.txt` 只有相对 providers/ 才对；
// 按顶层目录解析会落到临时目录的父目录上，必读不到。
func TestIncludeNestingResolvesRelativeToIncludingFile(t *testing.T) {
	dir := t.TempDir()
	writeInDir(t, dir, "shared.txt", "DOMAIN-SUFFIX,shared.example,DIRECT\n")
	writeInDir(t, filepath.Join(dir, "providers"), "a.txt", "#include ../shared.txt\nDOMAIN-SUFFIX,a.example,DIRECT\n")
	main := writeInDir(t, dir, "rules.txt", "#include providers/a.txt\nFINAL,PROXY\n")

	e, err := Load(main, fakeGeo{}, fakeResolver{})
	if err != nil {
		t.Fatalf("嵌套 #include 加载失败: %v", err)
	}
	if got, _ := e.Match(context.Background(), "x.shared.example"); got != PolicyDirect {
		t.Errorf("嵌套引进来的规则未生效，得到 %s", got)
	}
	if got, _ := e.Match(context.Background(), "x.a.example"); got != PolicyDirect {
		t.Errorf("第二层文件自身的规则未生效，得到 %s", got)
	}
}

// TestIncludeNestingWrongBaseFailsLoudlyOptional 是上面那个 bug 更难查的形态。
//
// 写成 #include? 时解析错了也不报错，只是那一段规则凭空消失——
// 用户看到的是「部分域名分流不对」，日志里一行线索都没有。
// 这里用一个**只在顶层目录存在**的同名文件做对照：
// 解析对了必然读不到并被跳过；解析错了（当成相对顶层）反而会读到它。
func TestIncludeNestingWrongBaseFailsLoudlyOptional(t *testing.T) {
	dir := t.TempDir()
	// 只有顶层目录有 sub.txt；providers/ 下面没有。
	writeInDir(t, dir, "sub.txt", "DOMAIN-SUFFIX,top.example,DIRECT\n")
	writeInDir(t, filepath.Join(dir, "providers"), "a.txt", "#include? sub.txt\nDOMAIN-SUFFIX,a.example,DIRECT\n")
	main := writeInDir(t, dir, "rules.txt", "#include providers/a.txt\nFINAL,PROXY\n")

	e, err := Load(main, fakeGeo{}, fakeResolver{})
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if got, _ := e.Match(context.Background(), "x.top.example"); got == PolicyDirect {
		t.Error("sub.txt 明明不在 providers/ 下却被读到了：相对路径仍按顶层目录解析")
	}
	if len(e.Skipped()) != 1 {
		t.Errorf("Skipped() = %v, want 恰好一条（providers/sub.txt）", e.Skipped())
	}
}

func TestIncludeRequiredMissingIsError(t *testing.T) {
	main := writeInDir(t, t.TempDir(), "rules.txt", "#include ./nope.txt\nFINAL,PROXY\n")
	_, err := Load(main, fakeGeo{}, fakeResolver{})
	if err == nil {
		t.Fatal("必需 #include 缺失应报错")
	}
	if !strings.Contains(err.Error(), "nope.txt") || !strings.Contains(err.Error(), ":1:") {
		t.Errorf("错误信息应含文件名与行号: %v", err)
	}
}

func TestIncludeOptionalMissingIsSkipped(t *testing.T) {
	dir := t.TempDir()
	main := writeInDir(t, dir, "rules.txt", "#include? ./nope.txt\nIP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,PROXY\n")

	e, err := Load(main, fakeGeo{}, fakeResolver{})
	if err != nil {
		t.Fatalf("可选 #include 缺失不应报错: %v", err)
	}
	if got, _ := e.Match(context.Background(), "10.1.2.3"); got != PolicyDirect {
		t.Errorf("got %s, want DIRECT", got)
	}
	if len(e.Skipped()) != 1 || !strings.HasSuffix(e.Skipped()[0], "nope.txt") {
		t.Errorf("Skipped() = %v, want 一个以 nope.txt 结尾的条目", e.Skipped())
	}
}

func TestIncludeNestedDepthLimited(t *testing.T) {
	dir := t.TempDir()
	// 自 include 形成环，靠深度上限收敛而不是栈溢出。
	main := writeInDir(t, dir, "rules.txt", "#include ./rules.txt\nFINAL,PROXY\n")
	_, err := Load(main, fakeGeo{}, fakeResolver{})
	if err == nil || !strings.Contains(err.Error(), "nesting too deep") {
		t.Fatalf("应报嵌套过深，得到 %v", err)
	}
}

func TestIncludeFinalIsSharedAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	writeInDir(t, dir, "extra.txt", "DOMAIN,a.com,PROXY\n")
	writeInDir(t, dir, "more.txt", "DOMAIN,b.com,DIRECT\n")
	main := writeInDir(t, dir, "rules.txt", "#include extra.txt\n#include more.txt\nFINAL,PROXY\n")

	e, err := Load(main, fakeGeo{}, fakeResolver{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if e.Final() != PolicyProxy {
		t.Errorf("FINAL = %s, want PROXY", e.Final())
	}
	// 第二个文件再写一次 FINAL 应被判为重复。
	writeInDir(t, dir, "more.txt", "DOMAIN,b.com,DIRECT\nFINAL,DIRECT\n")
	if _, err := Load(main, fakeGeo{}, fakeResolver{}); err == nil ||
		!strings.Contains(err.Error(), "duplicate FINAL") {
		t.Fatalf("跨文件的重复 FINAL 应报错，得到 %v", err)
	}
}

func TestIncludeLineNotConfusedWithComment(t *testing.T) {
	// 这些行都以 # 开头，但关键字后没有空白（或不是 include），应当被当作普通注释。
	e := load(t, `
#included something
#include-me
#includeme
# includee me
DOMAIN,a.com,DIRECT
FINAL,PROXY
`, fakeGeo{}, fakeResolver{})
	if got, _ := e.Match(context.Background(), "something"); got != PolicyProxy {
		t.Errorf("got %s, want PROXY（注释行不得被当成规则）", got)
	}
	if len(e.Skipped()) != 0 {
		t.Errorf("注释行被误判为 include: %v", e.Skipped())
	}
}

func TestIncludeLineWithoutPathIsError(t *testing.T) {
	// 裸的 "#include" 是指令但缺路径，属于配置错误。
	main := writeInDir(t, t.TempDir(), "rules.txt", "#include\nFINAL,PROXY\n")
	_, err := Load(main, fakeGeo{}, fakeResolver{})
	if err == nil || !strings.Contains(err.Error(), "需要一个文件路径") {
		t.Fatalf("应报缺少路径，得到 %v", err)
	}
}

func TestTrimIncludeDirective(t *testing.T) {
	cases := []struct {
		raw      string
		wantPath string
		wantOpt  bool
		wantOK   bool
	}{
		{"#include foo.txt", "foo.txt", false, true},
		{"  #  include   foo.txt  ", "foo.txt", false, true},
		{"#INCLUDE foo.txt", "foo.txt", false, true},
		{"#include? foo.txt", "foo.txt", true, true},
		{"#include", "", false, true},
		{"#include?", "", true, true},
		{"#included foo.txt", "", false, false},
		{"#includefoo.txt", "", false, false},
		{"# 普通注释", "", false, false},
		{"DOMAIN,a.com,DIRECT", "", false, false},
		{"", "", false, false},
	}
	for _, c := range cases {
		p, opt, ok := trimIncludeDirective(c.raw)
		if ok != c.wantOK || opt != c.wantOpt || p != c.wantPath {
			t.Errorf("trimIncludeDirective(%q) = (%q, %v, %v), want (%q, %v, %v)",
				c.raw, p, opt, ok, c.wantPath, c.wantOpt, c.wantOK)
		}
	}
}
