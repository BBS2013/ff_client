package diag

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wps_app/internal/config"
)

const diagCfg = `
proxies:
  - name: "hk-1"
    server:
      type: hysteria2
      addr: "198.51.100.7:443"
      auth: "HY2AUTH-abcdef0123456789"
      tls: { sni: "cdn.example.com" }
      bandwidth: { up: "200 mbps", down: "1000 mbps" }
  - name: "sg-2"
    server:
      type: trojan
      addr: "203.0.113.9:443"
      auth: "TROJANPASS-zzz999"
active: "hk-1"
mode: rule
inbounds:
  - { type: socks5, listen: "127.0.0.1:7891", username: "bobname", password: "Socks-Passw0rd-77" }
  - { type: http, listen: "127.0.0.1:7892" }
geoip: { path: "./assets/geoip.mmdb" }
rules_file: "./assets/rules.txt"
rule_providers:
  - { name: "ad", url: "https://sub.example.com/Socks-Passw0rd-77/list?token=SUBTOKEN-777" }
dns: { servers: ["223.5.5.5", "https://dohuser:dohpass@dns.example.com/dns-query"], timeout: "3s", cache: "300s" }
block:
  domains: ["ads.example.com"]
log: { level: "info" }
`

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// goodRules 是一份能加载成功的小规则集：诊断报告的其它断言不该被"规则文件不存在"干扰。
const goodRules = "DOMAIN-SUFFIX,example.com,PROXY\nDOMAIN,exact.cn,DIRECT\nIP-CIDR,10.0.0.0/8,DIRECT\nFINAL,PROXY\n"

// cfgWith 把 diagCfg 里那两个相对路径换成临时目录里的真文件，
// 让每个用例都从"规则装上了"那个状态出发。
func cfgWith(t *testing.T, geoipPath string) string {
	t.Helper()
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rulesFile, []byte(goodRules), 0o600); err != nil {
		t.Fatal(err)
	}
	return writeCfg(t, strings.Replace(strings.Replace(diagCfg,
		`geoip: { path: "./assets/geoip.mmdb" }`, `geoip: { path: "`+geoipPath+`" }`, 1),
		`rules_file: "./assets/rules.txt"`, `rules_file: "`+rulesFile+`"`, 1))
}

func run(t *testing.T, cfgPath string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Report(context.Background(), cfgPath, &buf); err != nil {
		t.Fatalf("Report 写盘失败: %v", err)
	}
	return buf.String()
}

// TestReportMasksEverySecret 这份报告是要贴给别人看的，所以口令必须进不去。
//
// 掩码是整篇渲染完之后再做一遍，不指望每个 section 自觉——
// 漏一处的后果不是"报告不好看"，是别人的节点密钥发出去了。
func TestReportMasksEverySecret(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	out := run(t, cfgWith(t, filepath.Join(t.TempDir(), "missing.mmdb")))

	// 两层掩码各挡一种，缺一层就有一种真的漏出去：
	// 按值的那层管"口令被复用在别的地方"（订阅 URL 里塞的就是 socks 密码），
	// 按形状的那层管"根本不在配置字段名单里的写法"（URL 的 userinfo 与 ?token=）。
	secrets := []struct {
		what, val string
	}{
		{"hysteria2 节点密钥", "HY2AUTH-abcdef0123456789"},
		{"trojan 节点口令", "TROJANPASS-zzz999"},
		{"socks5 用户名", "bobname"},
		{"socks5 密码", "Socks-Passw0rd-77"},
		{"订阅 URL 里的 ?token=", "SUBTOKEN-777"},
		{"DoH URL 里的口令", "dohpass"},
		{"DoH URL 里的用户名", "dohuser"},
	}
	for _, sec := range secrets {
		if strings.Contains(out, sec.val) {
			t.Errorf("报告里漏出了%s（%q）:\n%s", sec.what, sec.val, out)
		}
	}
	// 反过来也要成立：掩码不能把该说的东西一起抹掉，否则这份报告没有诊断价值。
	// 订阅地址被拉不下来时，"到底在拉哪个主机"就是最有用的那一半。
	for _, want := range []string{
		"198.51.100.7:443", "203.0.113.9:443", "hysteria2", "trojan",
		"cdn.example.com", "hk-1", "sg-2", "已设置", "要求认证",
		"sub.example.com", "dns.example.com", "域名 2 条",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("报告里应当留着 %q:\n%s", want, out)
		}
	}
}

// TestCollectSecretsCoversTheValueBearingFields 按值掩码那层收的就是这些字段。
// 新增一个"值本身就是口令"的配置字段时，这里必须跟着加，
// 否则那层掩码对新字段一无所知——而报告里恰好可能印出复用了它的别的字段。
func TestCollectSecretsCoversTheValueBearingFields(t *testing.T) {
	cfg := &config.Config{
		Proxies: []config.ProxyProfile{{Server: config.ServerConfig{Auth: "A-AAA"}}},
		Inbounds: []config.InboundConfig{
			{Type: "socks5", Username: "user-bbb", Password: "pass-ccc"},
			{Type: "http", Username: "  "}, // 空白不算口令
		},
	}
	got := strings.Join(collectSecrets(cfg), ",")
	for _, want := range []string{"A-AAA", "user-bbb", "pass-ccc"} {
		if !strings.Contains(got, want) {
			t.Errorf("collectSecrets 漏了 %q，实得 [%s]", want, got)
		}
	}
	if strings.Contains(got, "  ") || strings.Count(got, ",") != 2 {
		t.Errorf("collectSecrets 收了不该收的东西: [%s]", got)
	}
}

// TestReportMasksWhenConfigCannotBeLoaded 配置读不懂时，按值的集合是空的，
// 但按形状的那层必须照样跑——而且这恰恰是最需要它的时候：
// 解析错误的原文会把文件里那一行（多半就是 auth/口令）回显进报告。
func TestReportMasksWhenConfigCannotBeLoaded(t *testing.T) {
	// proxies 该是列表却写成字符串：yaml.v3 会把这个标量原样引进错误里（反引号），
	// 而它正是那条口令。
	body := "proxies: \"LEAKED-AUTH-9ff3\"\n" +
		"dns:\n  servers: [\"https://u1:p4ss@dns.example.com/dns-query\"]\n"
	out := run(t, writeCfg(t, body))
	if !strings.Contains(out, "读不到") {
		t.Fatalf("配置读不懂时必须写出来:\n%s", out)
	}
	// 断言挑的是"LEAKED"这个前缀而不是整串：yaml.v3 自己会把过长的标量
	// 截成 `LEAKED-...`，只断言整串的话，"漏了前 7 个字符"这种也能过关。
	if strings.Contains(out, "LEAKED") {
		t.Errorf("解析错误把口令（哪怕只是前缀）带进了报告:\n%s", out)
	}
	if strings.Contains(out, "u1:p4ss@") {
		t.Errorf("错误里的 URL 凭据没被掩掉:\n%s", out)
	}
}

// TestHideURLTailKeepsHostOnly 订阅与 DoH 地址的 key 常常就放在路径第一段
// （NextDNS 那种 https://dns.nextdns.io/<配置ID>），所以整条路径都不该进报告——
// 而"在拉哪台主机"这个诊断信息必须留着。
func TestHideURLTailKeepsHostOnly(t *testing.T) {
	// 只断言"主机留着、key 不见了"，不去核对那句提示里的字节数——
	// 数字是给人看的，钉死它只会让测试先于代码坏掉。
	cases := []struct{ in, keep, drop string }{
		{"https://sub.example.com/8f4e2c1d/list.yaml", "https://sub.example.com", "8f4e2c1d"},
		{"https://dns.nextdns.io/ABC123", "https://dns.nextdns.io", "ABC123"},
		{"https://user:pw@host.example/dns-query", "https://host.example", "user:pw"},
	}
	for _, c := range cases {
		got := hideURLTail(c.in)
		if !strings.Contains(got, c.keep) {
			t.Errorf("hideURLTail(%q) 把主机也藏了: %q", c.in, got)
		}
		if strings.Contains(got, c.drop) {
			t.Errorf("hideURLTail(%q) 漏出了 %q: %q", c.in, c.drop, got)
		}
	}
	// 没有路径的、以及根本不是 URL 的，都不该编造"已隐去"的说明。
	if got := hideURLTail("https://host"); got != "https://host" {
		t.Errorf("无路径的 URL 不该加尾巴: %q", got)
	}
	if got := hideURLTail("223.5.5.5"); got != "223.5.5.5" {
		t.Errorf("纯 IP 的上游不该被改动: %q", got)
	}
	if hideURLTail("") != "" {
		t.Error("空串应当原样返回")
	}
	// 非 URL 的一行垃圾也不能带控制字符进报告。
	if got := hideURLTail("not a\x1b\x7ful"); strings.ContainsAny(got, "\x1b\x7f") {
		t.Errorf("洗过之后还留着控制字符: %q", got)
	}
}

func TestReportCoversEachSection(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	out := run(t, cfgWith(t, filepath.Join(t.TempDir(), "missing.mmdb")))
	for _, sec := range []string{"运行身份", "入站", "出站节点", "规则与拦截", "DNS", "TUN", "网卡分流", "系统代理"} {
		if !strings.Contains(out, "## "+sec) {
			t.Errorf("少了 %q 这一节:\n%s", sec, out)
		}
	}
	// 开关没开时必须说清"没开"，而不是安静地什么都不写：
	// "面板上开着、报告里查无此项"是最难查的一种故障。
	if !strings.Contains(out, "没开 iface_split") {
		t.Errorf("没开时该明说没开:\n%s", out)
	}
}

// TestReportFlagsIfaceSplitWaitingOnMode 开了但模式不对时要说清差在哪一步，
// 而不是笼统地报一句"没生效"。
func TestReportFlagsIfaceSplitWaitingOnMode(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	out := run(t, writeCfg(t, strings.Replace(diagCfg,
		"mode: rule", "mode: global\niface_split: { enable: true }", 1)))
	if !strings.Contains(out, "只有规则模式才分流") {
		t.Errorf("global 模式下该点明差在模式:\n%s", out)
	}
}

// TestReportSurvivesBrokenConfig 配置读不懂时不许抛错、也不许留白。
//
// 一份"少了六节但说清了为什么少"的报告仍然有用；抛错则什么都拿不到。
func TestReportSurvivesBrokenConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	out := run(t, writeCfg(t, "proxies: [ this is not a mapping\n"))
	if !strings.Contains(out, "## 运行身份") {
		t.Errorf("连配置都读不懂时，运行身份那一节仍该给出来:\n%s", out)
	}
	if !strings.Contains(out, "读不到") {
		t.Errorf("必须写清配置读不到，而不是静默少几节:\n%s", out)
	}
}

func TestReportMissingConfigFile(t *testing.T) {
	out := run(t, filepath.Join(t.TempDir(), "nope.yaml"))
	if !strings.Contains(out, "读不到") || strings.Contains(out, "## 入站") {
		t.Errorf("文件不存在时应说明读不到且不编造各节:\n%s", out)
	}
}

// TestReportCountsWhatTheEngineLoaded 数字必须来自引擎，不是"数文件行数"。
//
// 面板上写的是引擎那份（含 #include 展开进来的用户规则），诊断报告若各数一遍，
// 两边就会给出两个不同的"域名条数"——而这类不一致正是让人放弃诊断报告的开始。
func TestReportCountsWhatTheEngineLoaded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.txt")
	body := "# 头\n#include? ./no-such-file.txt\n" +
		"DOMAIN-SUFFIX,example.com,PROXY\nDOMAIN,exact.cn,DIRECT\n" +
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,PROXY\n"
	if err := os.WriteFile(rulesFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeCfg(t, strings.Replace(strings.Replace(diagCfg,
		`geoip: { path: "./assets/geoip.mmdb" }`,
		`geoip: { path: "`+filepath.Join(dir, "missing.mmdb")+`" }`, 1),
		`rules_file: "./assets/rules.txt"`, `rules_file: "`+rulesFile+`"`, 1))

	out := run(t, cfgPath)
	if !strings.Contains(out, "域名 2 条") || !strings.Contains(out, "IP 类 1 条") ||
		!strings.Contains(out, "FINAL=PROXY") {
		t.Errorf("规则计数不对（GeoIP 缺失不该影响这些条数）:\n%s", out)
	}
	if !strings.Contains(out, "GEOIP") || !strings.Contains(out, "读不到") {
		t.Errorf("mmdb 读不到时要说清受影响的只有 GEOIP:\n%s", out)
	}
	if !strings.Contains(out, "no-such-file.txt") {
		t.Errorf("被跳过的可选 include 必须留在纸上:\n%s", out)
	}
	if !strings.Contains(out, "引擎装上 1 条") {
		t.Errorf("拦截名单要说「装上了几条」而不只是配置里写了几条:\n%s", out)
	}
}

// TestReportFlagsRuleLoadFailure 规则装不上是"什么都不通"的头号原因，
// 这一条必须自己站出来；而且站出来之后，同一节里剩下的行（订阅）还得照打——
// "为什么装不上"的答案常常就在那几条订阅里。
func TestReportFlagsRuleLoadFailure(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.txt")
	// 只剩注释与 FINAL：引擎以「no usable rules found」拒绝加载。
	if err := os.WriteFile(rulesFile, []byte("# 被清空了\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeCfg(t, strings.Replace(strings.Replace(diagCfg,
		`geoip: { path: "./assets/geoip.mmdb" }`,
		`geoip: { path: "`+filepath.Join(dir, "missing.mmdb")+`" }`, 1),
		`rules_file: "./assets/rules.txt"`, `rules_file: "`+rulesFile+`"`, 1))

	out := run(t, cfgPath)
	if !strings.Contains(out, "规则加载失败") {
		t.Errorf("规则装不上时必须点名:\n%s", out)
	}
	if !strings.Contains(out, "订阅") || !strings.Contains(out, "sub.example.com") {
		t.Errorf("规则装不上不该把订阅那一行一起吃掉:\n%s", out)
	}
}

func TestProbeAnswersOnlyAboutLocalPorts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("本机起不了监听: %v", err)
	}
	addr := ln.Addr().String()
	if got := probe(addr); got != "在听" {
		t.Errorf("%s 在听，实得 %q", addr, got)
	}
	_ = ln.Close()
	if got := probe(addr); got != "没人听" {
		t.Errorf("关掉的端口应报没人听，实得 %q", got)
	}
	// 非回环地址一律不测：对外连接是这份报告明令禁止的事。
	if got := probe("198.51.100.7:443"); !strings.Contains(got, "未测") {
		t.Errorf("非回环地址不该去连，实得 %q", got)
	}
	if got := probe("not-an-address"); !strings.Contains(got, "写法不对") {
		t.Errorf("地址写法错了要说清楚，实得 %q", got)
	}
}

// TestReportFlagsDNSHijackResidue 这一条是 -diag 存在的理由之一：
// 上一轮崩在 TUN 开着的时候，resolved 里会留着假 IP 段的 nameserver，
// 表现是"什么域名都解析不到"，而看日志什么都正常。
func TestReportFlagsDNSHijackResidue(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolv, []byte("nameserver 198.18.0.1\nnameserver 127.0.0.53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := resolvConfPath
	resolvConfPath = resolv
	t.Cleanup(func() { resolvConfPath = old })

	out := run(t, cfgWith(t, filepath.Join(t.TempDir(), "missing.mmdb")))
	if !strings.Contains(out, "198.18.0.1") || !strings.Contains(out, "残留") {
		t.Errorf("假 IP 段的 nameserver 必须被点名:\n%s", out)
	}
	if !strings.Contains(out, "-tun-reset") {
		t.Errorf("点了名还要给出救回来的命令:\n%s", out)
	}
	// 127.0.0.53 是 resolved 存根，正常，不该跟着一起报。
	if strings.Contains(out, "127.0.0.53 落在假 IP 段") {
		t.Errorf("存根地址不该被报成残留:\n%s", out)
	}
}

func TestReportNormalResolvConfIsQuiet(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	resolv := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolv, []byte("nameserver 127.0.0.53\noptions edns0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := resolvConfPath
	resolvConfPath = resolv
	t.Cleanup(func() { resolvConfPath = old })

	out := run(t, cfgWith(t, filepath.Join(t.TempDir(), "missing.mmdb")))
	// 只看解析这一节的措辞：报告里别的节（比如「默认路由指向 tun」）说的是**这台机器此刻**
	// 有没有人在接管，与这份临时 resolv.conf 无关——拿整份报告里有没有「残留」当判据，
	// 会让一条本来正确的用例在「有人正跑着严格模式面板」时红掉（2026-10-29 实际踩过）。
	if strings.Contains(out, "DNS 劫持的残留") || strings.Contains(out, "没人能解析") {
		t.Errorf("一份正常的 resolv.conf 不该引出任何告警:\n%s", out)
	}
}

func TestMaskPrefersLongerSecrets(t *testing.T) {
	// 短口令正好是长口令的前缀时，先换短的会把长口令切碎、留下半截在外面。
	out := mask("auth=abcdef012345 password=abcdef", []string{"abcdef", "abcdef012345"})
	if strings.Contains(out, "abcdef") {
		t.Errorf("两个口令都没被换干净: %q", out)
	}
	if strings.Count(out, "***") != 2 {
		t.Errorf("应当正好两处被掩: %q", out)
	}
}

func TestMaskUserInfoAndQueryTokens(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://user:pw@example.com/x", "https://***@example.com/x"},
		{"https://sub.example.com/list?token=SUBTOKEN-777&x=1", "https://sub.example.com/list?token=***&x=1"},
		{"http://a.b/c?key=KKK", "http://a.b/c?key=***"},
		// 只吃 URL 里合法的字符：后面的中文括号与逗号必须原样留着。
		{"https://h/l?token=AAA）缓存，间隔 24h", "https://h/l?token=***）缓存，间隔 24h"},
		{"223.5.5.5", "223.5.5.5"}, // 不该动普通内容
	}
	for _, c := range cases {
		if got := maskUserInfo(c.in); got != c.want {
			t.Errorf("maskUserInfo(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// TestReportDoesNotDialOutside 报告里出现的每一个探测都必须是本机回环。
// 这条在 make test-offline（unshare -rn，只留 lo）里会自然成立，
// 但真跑一遍才算证据：网络断着还能出完整报告，是这个工具的前提。
func TestReportDoesNotDialOutside(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	body := strings.Replace(diagCfg, `addr: "198.51.100.7:443"`, `addr: "203.0.113.5:443"`, 1)
	out := run(t, writeCfg(t, body))
	if !strings.Contains(out, "203.0.113.5:443") {
		t.Errorf("节点地址应当原样给出（它不是口令）:\n%s", out)
	}
	if strings.Contains(out, "连接超时") || strings.Contains(out, "no such host") {
		t.Errorf("报告里出现了对外连接的痕迹:\n%s", out)
	}
}

// TestReportShowsSubscriptionCacheAge 配置里写了订阅不等于它在更新。
// 这一节要给出缓存文件的现状：在不在、多大、多久没动——那才是"订阅活着吗"的证据。
func TestReportShowsSubscriptionCacheAge(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	rulesFile := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rulesFile, []byte(goodRules), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(dir, "fresh.txt")
	if err := os.WriteFile(fresh, []byte("DOMAIN-SUFFIX,fresh.example,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adLine := `  - { name: "ad", url: "https://sub.example.com/Socks-Passw0rd-77/list?token=SUBTOKEN-777" }`
	cfgBody := strings.Replace(strings.Replace(diagCfg,
		`geoip: { path: "./assets/geoip.mmdb" }`,
		`geoip: { path: "`+filepath.Join(dir, "missing.mmdb")+`" }`, 1),
		`rules_file: "./assets/rules.txt"`, `rules_file: "`+rulesFile+`"`, 1)
	// 沿用模板里那条 ad（口令掩码那条用例靠它），只在它下面补两条：
	// 一条缓存刚写过、一条缓存根本不存在。
	cfgBody = strings.Replace(cfgBody, adLine, adLine+"\n"+
		`  - { name: "live", url: "https://example.invalid/live.txt", path: "`+fresh+`", interval: 6h }`+"\n"+
		`  - { name: "gone", url: "https://example.invalid/gone.txt", path: "`+filepath.Join(dir, "gone.txt")+`" }`, 1)
	cfgPath := writeCfg(t, cfgBody)

	out := run(t, cfgPath)
	if !strings.Contains(out, "live") || !strings.Contains(out, "fresh.txt") {
		t.Fatalf("两条订阅都没出现在报告里:\n%s", out)
	}
	// 在场的那条：字节数与"多久没动"都要有，光说"存在"等于没答"上次拉到是什么时候"。
	body := "DOMAIN-SUFFIX,fresh.example,PROXY\n"
	if !strings.Contains(out, fmt.Sprintf("fresh.txt：%d 字节", len(body))) ||
		!strings.Contains(out, "不到 1 分钟前") || !strings.Contains(out, "间隔 6 小时 0 分") {
		t.Errorf("缓存现状要说清大小与新鲜度:\n%s", out)
	}
	// 缺席的那条：必须明说"这段规则不在引擎里"，而不是只留一个 ENOENT。
	if !strings.Contains(out, "gone.txt 不存在") || !strings.Contains(out, "这段规则现在不在引擎里") {
		t.Errorf("缓存不在时必须点明这段规则没生效:\n%s", out)
	}
}

// TestReportListsEveryFileTheEngineRead 报告要说清"引擎真的读了哪几份文件"。
// 只看 rules_file 的那一行会漏掉最常见的编辑对象：#include 进来的那一份——
// 用户改了它却"不生效"，而报告上找不到任何线索说明它压根没被读。
func TestReportListsEveryFileTheEngineRead(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(main, []byte("#include ./extra.txt\nFINAL,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.txt")
	if err := os.WriteFile(extra, []byte("DOMAIN-SUFFIX,extra.example,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := writeCfg(t, strings.Replace(strings.Replace(diagCfg,
		`geoip: { path: "./assets/geoip.mmdb" }`,
		`geoip: { path: "`+filepath.Join(dir, "missing.mmdb")+`" }`, 1),
		`rules_file: "./assets/rules.txt"`, `rules_file: "`+main+`"`, 1))

	out := run(t, cfgPath)
	if !strings.Contains(out, "引擎实际读取的规则文件（2 份）") {
		t.Fatalf("被读取的文件清单没报出份数:\n%s", out)
	}
	if !strings.Contains(out, extra) {
		t.Errorf("清单里没有 #include 进来的那份（%s）", extra)
	}
}

// TestSplitBlockedConclusionDistinguishesHelper 守住“报告不许替 helper 那条路下结论”。
// 2026-11-02 的实测里，-diag 说两张卡都退回默认路由，而 ss 显示面板的连接
// 已经钉在 wlx/wlp 上——差别只在面板配了 tun.helper，而报告没把这条算进去。
func TestSplitBlockedConclusionDistinguishesHelper(t *testing.T) {
	with := splitBlockedConclusion(true)
	if !strings.Contains(with, "tun.helper") || !strings.Contains(with, "未验证") {
		t.Fatalf("配了 helper 时应当说明未验证 helper，实际: %q", with)
	}
	if strings.Contains(with, "按系统默认路由走") {
		t.Fatalf("配了 helper 时不能断言退回默认路由，实际: %q", with)
	}
	without := splitBlockedConclusion(false)
	if !strings.Contains(without, "按系统默认路由走") {
		t.Fatalf("没配 helper 时应当说明退回默认路由，实际: %q", without)
	}
	if strings.Contains(without, "tun.helper") {
		t.Fatalf("没配 helper 时不该提 helper，实际: %q", without)
	}
}
