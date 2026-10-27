package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestParseBandwidth(t *testing.T) {
	cases := []struct {
		in   string
		want uint64
	}{
		{"200 mbps", 25_000_000}, // 计划里 config.yaml 的实际取值
		{"1000 mbps", 125_000_000},
		{"200Mbps", 25_000_000},    // 无空格
		{" 200 MBPS ", 25_000_000}, // 大写与空白
		{"1 gbps", 125_000_000},
		{"500 kbps", 62_500},
		{"1 g", 125_000_000}, // 单字母后缀
		{"100 m", 12_500_000},
		{"8 bps", 1},
		{"100", 12_500_000}, // 无后缀按 Mbps
		{"0", 0},
		{"", 0},
		{"0.8 mbps", 100_000},
	}
	for _, c := range cases {
		got, err := ParseBandwidth(c.in)
		if err != nil {
			t.Errorf("ParseBandwidth(%q) 报错: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseBandwidth(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseBandwidthErrors(t *testing.T) {
	for _, in := range []string{"abc", "mbps", "10 xx", "-5 mbps", "12 34 mbps"} {
		if v, err := ParseBandwidth(in); err == nil {
			t.Errorf("ParseBandwidth(%q) 应报错，得到 %d", in, v)
		}
	}
}

func TestBandwidthAccessors(t *testing.T) {
	b := BandwidthConfig{Up: "200 mbps", Down: "1000 mbps"}
	tx, err := b.MaxTx()
	if err != nil || tx != 25_000_000 {
		t.Errorf("MaxTx = (%d, %v), want (25000000, nil)", tx, err)
	}
	rx, err := b.MaxRx()
	if err != nil || rx != 125_000_000 {
		t.Errorf("MaxRx = (%d, %v), want (125000000, nil)", rx, err)
	}
	if _, err := (BandwidthConfig{Up: "oops"}).MaxTx(); err == nil {
		t.Error("非法 up 应报错")
	}
}

func writeYAML(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimalYAML = `
server:
  addr: "example.com:443"
  auth: "secret"
inbounds:
  - { type: socks5, listen: "127.0.0.1:7891" }
`

func TestLoadMinimalAppliesDefaults(t *testing.T) {
	cfg, err := Load(writeYAML(t, minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ActiveServer().TLS.SNI != "example.com" {
		t.Errorf("SNI 未回退为 host，得到 %q", cfg.ActiveServer().TLS.SNI)
	}
	if cfg.DNS.Timeout.Duration != 3*time.Second {
		t.Errorf("DNS 超时默认值 = %v, want 3s", cfg.DNS.Timeout.Duration)
	}
	if cfg.DNS.Cache.Duration != 300*time.Second {
		t.Errorf("DNS 缓存默认值 = %v, want 300s", cfg.DNS.Cache.Duration)
	}
	if len(cfg.DNS.Servers) != 2 {
		t.Errorf("DNS 上游默认值 = %v", cfg.DNS.Servers)
	}
	// 隧道解析默认必须关着：实测它会让国内域名被判成 PROXY（见 TunnelResolve 的注释）。
	// 这条断言是防止有人把默认值"顺手改成一个看起来更聪明的方向"。
	if cfg.DNS.TunnelResolveOn() {
		t.Error("dns.tunnel_resolve 默认必须关闭")
	}
	if cfg.Log.Level != "info" {
		t.Errorf("日志级别默认值 = %q, want info", cfg.Log.Level)
	}
	if cfg.RulesFile == "" || cfg.GeoIP.Path == "" {
		t.Errorf("规则/GeoIP 路径默认值未填充: %q %q", cfg.RulesFile, cfg.GeoIP.Path)
	}
}

func TestLoadDurationFormats(t *testing.T) {
	body := minimalYAML + `
dns:
  timeout: "1.5s"
  cache: 60
`
	cfg, err := Load(writeYAML(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNS.Timeout.Duration != 1500*time.Millisecond {
		t.Errorf("timeout = %v, want 1.5s", cfg.DNS.Timeout.Duration)
	}
	if cfg.DNS.Cache.Duration != 60*time.Second {
		t.Errorf("cache = %v, want 60s（纯数字按秒）", cfg.DNS.Cache.Duration)
	}
}

func TestValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "缺少 addr",
			body: "server:\n  auth: s\ninbounds:\n  - { type: socks5, listen: \"127.0.0.1:7891\" }\n",
			want: "server.addr",
		},
		{
			name: "缺少 auth",
			body: "server:\n  addr: \"a.com:443\"\ninbounds:\n  - { type: socks5, listen: \"127.0.0.1:7891\" }\n",
			want: "server.auth",
		},
		{
			name: "addr 缺端口",
			body: "server:\n  addr: \"a.com\"\n  auth: s\ninbounds:\n  - { type: socks5, listen: \"127.0.0.1:7891\" }\n",
			want: "server.addr",
		},
		{
			name: "带宽非法",
			body: "server:\n  addr: \"a.com:443\"\n  auth: s\n  bandwidth: { up: \"fast\" }\ninbounds:\n  - { type: socks5, listen: \"127.0.0.1:7891\" }\n",
			want: "server.bandwidth.up",
		},
		{
			name: "无入站",
			body: "server:\n  addr: \"a.com:443\"\n  auth: s\n",
			want: "at least one inbound",
		},
		{
			name: "入站类型未知",
			body: "server:\n  addr: \"a.com:443\"\n  auth: s\ninbounds:\n  - { type: trojan, listen: \"127.0.0.1:7891\" }\n",
			want: "unknown inbound type",
		},
		{
			name: "入站缺端口",
			body: "server:\n  addr: \"a.com:443\"\n  auth: s\ninbounds:\n  - { type: http, listen: \"127.0.0.1\" }\n",
			want: "inbound.listen",
		},
		{
			name: "DNS 上游为空项",
			body: minimalYAML + "dns:\n  servers: [\"\", \"1.1.1.1\"]\n",
			want: "dns.servers",
		},
		{
			name: "socks5 只填用户名",
			body: "server:\n  addr: \"a.com:443\"\n  auth: s\ninbounds:\n  - { type: socks5, listen: \"127.0.0.1:7891\", username: alice }\n",
			want: "username 与 password",
		},
		{
			name: "socks5 只填密码",
			body: "server:\n  addr: \"a.com:443\"\n  auth: s\ninbounds:\n  - { type: socks5, listen: \"127.0.0.1:7891\", password: s3cret }\n",
			want: "username 与 password",
		},
		{
			name: "http 入站不支持认证",
			body: "server:\n  addr: \"a.com:443\"\n  auth: s\ninbounds:\n  - { type: http, listen: \"127.0.0.1:7892\", username: alice, password: s3cret }\n",
			want: "http 入站不支持",
		},
		{
			name: "sysproxy 后端名不认识",
			body: minimalYAML + "sysproxy:\n  backend: windows\n",
			want: "sysproxy.backend",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeYAML(t, c.body))
			if err == nil {
				t.Fatal("期望报错")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误信息 %q 未包含 %q", err, c.want)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("读取不存在的配置应报错")
	}
}

func TestLoadMalformedYAML(t *testing.T) {
	if _, err := Load(writeYAML(t, "server: [this is not a map\n")); err == nil {
		t.Fatal("YAML 语法错误应报错")
	}
}

func TestLoadFullConfig(t *testing.T) {
	// 与仓库中的 config.yaml 同构，但用占位凭据，测试不依赖真实服务端。
	body := `
server:
  addr: "example.com:443"
  auth: "placeholder"
  tls:
    sni: "example.com"
    insecure: false
  bandwidth:
    up: "200 mbps"
    down: "1000 mbps"
  congestion: bbr
  fast_open: true
inbounds:
  - { type: socks5, listen: "127.0.0.1:7891" }
  - { type: http,   listen: "127.0.0.1:7892" }
geoip:
  path: "./assets/geoip.mmdb"
rules_file: "./assets/rules.txt"
dns:
  servers: ["223.5.5.5", "119.29.29.29"]
  timeout: "3s"
  cache: "300s"
log: { level: "debug" }
`
	cfg, err := Load(writeYAML(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inbounds) != 2 {
		t.Fatalf("入站数量 = %d, want 2", len(cfg.Inbounds))
	}
	if cfg.Inbounds[1].Type != "http" || cfg.Inbounds[1].Listen != "127.0.0.1:7892" {
		t.Errorf("第二个入站 = %+v", cfg.Inbounds[1])
	}
	if !cfg.ActiveServer().FastOpen || cfg.ActiveServer().Congestion != "bbr" {
		t.Errorf("服务端选项解析错误: %+v", cfg.ActiveServer())
	}
	if cfg.ActiveServer().TLS.Insecure {
		t.Error("insecure 应为 false")
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("log.level = %q", cfg.Log.Level)
	}
}

// 仓库里的 config.yaml 必须能被 Load 通过，防止交付物自身损坏。
func TestRepoConfigIsValid(t *testing.T) {
	p := filepath.Join("..", "..", "config.yaml")
	if _, err := os.Stat(p); err != nil {
		t.Skip("仓库 config.yaml 不存在")
	}
	if _, err := Load(p); err != nil {
		t.Fatalf("仓库 config.yaml 校验失败: %v", err)
	}
}

// TestExampleConfigIsValidAndSecretFree 守的是随包发给别人的那份配置。
//
// 两条都重要：样例必须能被加载（对方照抄就能跑起来，样例写错等于把错误发出去），
// 以及它**不能带任何真实口令**——package.sh 里也有一道同样的扫描，但那要有人跑打包；
// 这条测试每次 go test 都跑，所以"顺手把节点信息填进样例"这种事故进不了主干。
func TestExampleConfigIsValidAndSecretFree(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Skip("仓库里没有 config.example.yaml")
	}
	path := writeYAML(t, string(body))
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("config.example.yaml 加载失败（对方照抄就是坏的）: %v", err)
	}
	if len(cfg.Proxies) < 2 {
		t.Fatalf("样例该给出两种协议各一个节点做对照，实得 %d 个", len(cfg.Proxies))
	}
	if cfg.Proxies[0].Server.Protocol() != ProtocolHysteria2 {
		t.Errorf("第一个样例节点应是 hysteria2，实为 %q", cfg.Proxies[0].Server.Protocol())
	}
	if cfg.Proxies[1].Server.Protocol() != ProtocolTrojan {
		t.Errorf("第二个样例节点应是 trojan，实为 %q", cfg.Proxies[1].Server.Protocol())
	}

	local, err := os.ReadFile(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		return // 没有本地配置就无从比对，不算失败
	}
	seen := map[string]bool{}
	for _, secret := range authValues(string(local)) {
		if len(secret) < 8 || seen[secret] {
			continue // 太短的值没有鉴别力，样例里的占位符本来就可能撞车
		}
		seen[secret] = true
		if strings.Contains(string(body), secret) {
			t.Errorf("config.example.yaml 里出现了本地配置的真实口令（长度 %d）", len(secret))
		}
	}
}

// authValues 抓出配置文本里所有 auth 字段的值，用于口令比对。
func authValues(body string) []string {
	re := regexp.MustCompile(`(?m)^[[:space:]]*auth:[[:space:]]*"?([^"\n]*)"?[[:space:]]*$`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out = append(out, strings.TrimSpace(m[1]))
	}
	return out
}

// TestLoadRejectsUnknownField 锁住「错别字被静默吞掉」。
//
// 解码开了 KnownFields：代理客户端的配置是要手工编辑的，
// 而静默忽略在这里代价特别高——把 rules_file 拼成 rule_file，
// 程序不吭一声地照默认值跑，表现是「规则不生效、全量走 FINAL=PROXY」，
// 日志与界面上一切正常，用户几乎不可能联想到是哪个键拼错了。
func TestLoadRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := `server:
  addr: "127.0.0.1:4433"
  auth: "x"
rule_file: "/tmp/rules.txt"
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	_, err := Load(p)
	if err == nil {
		t.Fatal("未知字段 rule_file 应当报错（正确写法是 rules_file）")
	}
	if !strings.Contains(err.Error(), "rule_file") {
		t.Errorf("报错里应点名那个写错的字段，实际: %v", err)
	}
}

// TestLoadRejectsUnknownNestedField 嵌套层级同样不能漏。
func TestLoadRejectsUnknownNestedField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	body := `server:
  addr: "127.0.0.1:4433"
  auth: "x"
  tls:
    sni: "example.com"
    insecure_sk: true
`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("嵌套的未知字段 insecure_sk 应当报错（正确写法是 insecure）")
	}
}

// TestRealExampleConfigsStillLoad 开 KnownFields 的前提是它不误伤。
// 仓库里的两个真实配置样例必须都能加载，否则等于把所有用户都挡在门外。
func TestRealExampleConfigsStillLoad(t *testing.T) {
	for _, p := range []string{
		filepath.Join("..", "..", "config.example.yaml"),
		filepath.Join("..", "..", "config.yaml"),
	} {
		if _, err := Load(p); err != nil {
			t.Errorf("%s 加载失败（KnownFields 误伤了合法键）: %v", p, err)
		}
	}
}

// TestTunnelResolveOnTriState 区分「没写」「写 false」「写 true」三态。
// 用 *bool 就是为了这个：值语义下"没写"和"显式关掉"会混成同一种状态，
// 而把隧道解析关掉是用户的一个明确决定，不该与"根本不知道有这个开关"等价。
func TestTunnelResolveOnTriState(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name string
		cfg  DNSConfig
		want bool
	}{
		{"没写", DNSConfig{}, false},
		{"显式 false", DNSConfig{TunnelResolve: &no}, false},
		{"显式 true", DNSConfig{TunnelResolve: &yes}, true},
	}
	for _, c := range cases {
		if got := c.cfg.TunnelResolveOn(); got != c.want {
			t.Errorf("%s: TunnelResolveOn = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestSysProxyBackendSurvivesSave 后端名必须活过一次面板保存。
//
// Save 会按 writeConfig 重写整份 YAML：只加在 Unmarshal 侧、忘了加进
// Marshal 侧的话，用户点一次「保存配置」就把 pin 悄悄抹成自动探测，
// 表现是「明明指定了 kde，怎么改回 gnome 了」。
func TestSysProxyBackendSurvivesSave(t *testing.T) {
	p := writeYAML(t, minimalYAML+"sysproxy:\n  backend: kde\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("载入: %v", err)
	}
	if cfg.SysProxy.Backend != "kde" {
		t.Fatalf("backend = %q, want kde", cfg.SysProxy.Backend)
	}
	if err := Save(p, cfg); err != nil {
		t.Fatalf("保存: %v", err)
	}
	again, err := Load(p)
	if err != nil {
		t.Fatalf("重新载入: %v", err)
	}
	if again.SysProxy.Backend != "kde" {
		t.Fatalf("保存后 backend = %q, want kde（Marshal 侧漏了 SysProxy）", again.SysProxy.Backend)
	}
}

// TestSysProxyBackendCaseInsensitive 大小写与空格不该让配置直接不可用。
func TestSysProxyBackendCaseInsensitive(t *testing.T) {
	for _, in := range []string{"KDE", " kde ", "ENV", "auto", "gnome", ""} {
		if _, err := Load(writeYAML(t, minimalYAML+"sysproxy:\n  backend: \""+in+"\"\n")); err != nil {
			t.Errorf("backend=%q 应被接受，实际报错: %v", in, err)
		}
	}
}

func TestBlockSurvivesSave(t *testing.T) {
	p := writeYAML(t, minimalYAML+"block:\n  domains: [\"ads.example.com\", \"track.example.net\"]\n")
	cfg, err := Load(p)
	if err != nil {
		t.Fatalf("载入: %v", err)
	}
	if len(cfg.Block.Domains) != 2 || cfg.Block.Domains[0] != "ads.example.com" {
		t.Fatalf("名单没读进来: %+v", cfg.Block.Domains)
	}
	if err := Save(p, cfg); err != nil {
		t.Fatalf("保存: %v", err)
	}
	again, err := Load(p)
	if err != nil {
		t.Fatalf("重读: %v", err)
	}
	if len(again.Block.Domains) != 2 || again.Block.Domains[1] != "track.example.net" {
		t.Fatalf("保存把名单洗掉了: %+v", again.Block.Domains)
	}
}

func TestBlockValidation(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{"空名单合法", minimalYAML + "block:\n  domains: []\n", ""},
		{"没这段也合法", minimalYAML, ""},
		{"正常域名", minimalYAML + "block:\n  domains: [\"Ads.Example.com\"]\n", ""},
		{"空项会拦下一切", minimalYAML + "block:\n  domains: [\"\"]\n", "空项"},
		{"只有个点", minimalYAML + "block:\n  domains: [\".\"]\n", "空项"},
		{"带协议的 URL", minimalYAML + "block:\n  domains: [\"http://a.com/x\"]\n", "不像域名"},
		{"带端口", minimalYAML + "block:\n  domains: [\"a.com:8080\"]\n", "不像域名"},
		{"IP 段", minimalYAML + "block:\n  domains: [\"10.0.0.0/8\"]\n", "不像域名"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeYAML(t, c.body))
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("应被接受，实际报错: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("错误里应含 %q，实际 %v", c.wantErr, err)
			}
			if !strings.Contains(err.Error(), "block.domains") {
				t.Errorf("错误要指到具体段: %v", err)
			}
		})
	}
}
