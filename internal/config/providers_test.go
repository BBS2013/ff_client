package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func baseWithProviders(provs ...RuleProvider) *Config {
	c := &Config{}
	c.Proxies = []ProxyProfile{{
		Name:   "n1",
		Server: ServerConfig{Addr: "203.0.113.1:443", Auth: "pw"},
	}}
	c.Inbounds = []InboundConfig{{Type: "socks5", Listen: "127.0.0.1:17891"}}
	c.RuleProviders = provs
	return c
}

func TestRuleProviderDefaults(t *testing.T) {
	c := baseWithProviders(RuleProvider{
		Name: "cn",
		URL:  "https://example.com/cn.txt",
	})
	c.RulesFile = "./assets/rules.txt"
	if err := c.applyDefaults(); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	p := c.RuleProviders[0]
	if !p.IsEnabled() {
		t.Error("没写 enabled 应当是启用")
	}
	if p.Every() != DefaultProviderInterval {
		t.Errorf("默认周期 = %v, want %v", p.Every(), DefaultProviderInterval)
	}
	// 默认路径要落在 rules_file 旁边，用户才能直接写 #include providers/cn.txt
	want := "assets/providers/cn.txt"
	if got := c.ProviderPath(p); !strings.HasSuffix(got, want) {
		t.Errorf("默认缓存路径 = %q, 期望以 %q 结尾", got, want)
	}
}

func TestRuleProviderDisabled(t *testing.T) {
	no := false
	c := baseWithProviders(RuleProvider{Name: "cn", URL: "https://e/c", Enabled: &no})
	c.RulesFile = "./assets/rules.txt"
	if err := c.applyDefaults(); err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("关掉的订阅不该让配置不合法: %v", err)
	}
	if c.RuleProviders[0].IsEnabled() {
		t.Error("enabled: false 应当是关掉")
	}
}

func TestRuleProviderExplicitInterval(t *testing.T) {
	p := RuleProvider{Name: "cn", URL: "https://e/c", Interval: Duration{Duration: 6 * time.Hour}}
	if got := p.Every(); got != 6*time.Hour {
		t.Errorf("周期 = %v, want 6h", got)
	}
}

func TestRuleProviderValidation(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		prov RuleProvider
		want string
	}{
		{"空名字", RuleProvider{URL: "https://e/c"}, "name 不能为空"},
		{"名字含斜杠", RuleProvider{Name: "a/b", URL: "https://e/c"}, "路径分隔符"},
		{"名字是 ..", RuleProvider{Name: "..", URL: "https://e/c"}, "路径分隔符"},
		{"空 url", RuleProvider{Name: "cn"}, "url 不能为空"},
		{"file 协议", RuleProvider{Name: "cn", URL: "file:///etc/passwd"}, "只能以 http"},
		{"ftp 协议", RuleProvider{Name: "cn", URL: "ftp://e/c"}, "只能以 http"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := baseWithProviders(c.prov)
			cfg.RulesFile = dir + "/rules.txt"
			if err := cfg.applyDefaults(); err != nil {
				t.Fatal(err)
			}
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("竟然通过了校验")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误 = %q, 期望含 %q", err, c.want)
			}
		})
	}
}

// TestRuleProviderRejectsDuplicateName：名字重名会让两条订阅落到同一个缓存文件，
// 后一条悄悄覆盖前一条。
func TestRuleProviderRejectsDuplicateName(t *testing.T) {
	cfg := baseWithProviders(
		RuleProvider{Name: "cn", URL: "https://e/a"},
		RuleProvider{Name: "cn", URL: "https://e/b"},
	)
	cfg.RulesFile = t.TempDir() + "/rules.txt"
	if err := cfg.applyDefaults(); err != nil {
		t.Fatal(err)
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("重名应当被挡住，实得 %v", err)
	}
}

// TestRuleProviderRejectsDuplicateCachePath 覆盖显式 path 撞车：
// 两条订阅指定了同一个文件，表现是「规则内容随机跳变」。
func TestRuleProviderRejectsDuplicateCachePath(t *testing.T) {
	same := t.TempDir() + "/same.txt"
	cfg := baseWithProviders(
		RuleProvider{Name: "a", URL: "https://e/a", Path: same},
		RuleProvider{Name: "b", URL: "https://e/b", Path: same},
	)
	cfg.RulesFile = t.TempDir() + "/rules.txt"
	if err := cfg.applyDefaults(); err != nil {
		t.Fatal(err)
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("缓存路径撞车竟然通过了")
	}
	if !strings.Contains(err.Error(), "same.txt") {
		t.Errorf("错误里应当点名冲突的路径，实得 %q", err)
	}
}

// TestRuleProviderRejectsCollisionViaDefaultPath：显式 path 与另一条的默认 path 撞上。
// 撞车的是「cn2 的默认路径」，所以显式那条必须写成 cn2 的默认文件名。
func TestRuleProviderRejectsCollisionViaDefaultPath(t *testing.T) {
	dir := t.TempDir()
	cfg := baseWithProviders(
		RuleProvider{Name: "cn", URL: "https://e/a", Path: dir + "/providers/cn2.txt"},
		RuleProvider{Name: "cn2", URL: "https://e/b"},
	)
	cfg.RulesFile = dir + "/rules.txt"
	if err := cfg.applyDefaults(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("显式 path 与默认 path 撞车竟然通过了")
	}
}

// TestRuleProvidersRoundTrip：订阅段要能原样 Save→Load，
// 否则用户在界面上动一次别的配置，订阅就被洗掉了。
func TestRuleProvidersRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/config.yaml"
	body := "proxies:\n" +
		"  - name: n1\n" +
		"    server:\n" +
		"      addr: 203.0.113.1:443\n" +
		"      auth: pw\n" +
		"active: n1\n" +
		"mode: rule\n" +
		"inbounds:\n" +
		"  - type: socks5\n" +
		"    listen: 127.0.0.1:17891\n" +
		"rules_file: " + dir + "/rules.txt\n" +
		"rule_providers:\n" +
		"  - name: cn\n" +
		"    url: https://example.com/cn.txt\n" +
		"    interval: 6h\n" +
		"  - name: off\n" +
		"    url: https://example.com/off.txt\n" +
		"    enabled: false\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("加载: %v", err)
	}
	if len(cfg.RuleProviders) != 2 {
		t.Fatalf("订阅条数 = %d, want 2", len(cfg.RuleProviders))
	}
	if got := cfg.RuleProviders[0].Every(); got != 6*time.Hour {
		t.Errorf("interval = %v, want 6h", got)
	}
	if cfg.RuleProviders[1].IsEnabled() {
		t.Error("enabled: false 没读回来")
	}

	if err := Save(path, cfg); err != nil {
		t.Fatalf("保存: %v", err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatalf("再加载: %v", err)
	}
	if len(again.RuleProviders) != 2 || again.RuleProviders[0].URL != "https://example.com/cn.txt" {
		t.Errorf("Save→Load 之后订阅段变了: %+v", again.RuleProviders)
	}
	if again.RuleProviders[0].Every() != 6*time.Hour || again.RuleProviders[1].IsEnabled() {
		t.Errorf("Save→Load 之后字段丢了: %+v", again.RuleProviders)
	}
}

// TestEmptyRuleProvidersNormalize 保证没有订阅时也写成 []，
// 否则 Save→Load 的等价性对不上（nil 与空切片 reflect 分得出来）。
func TestEmptyRuleProvidersNormalize(t *testing.T) {
	cfg := baseWithProviders()
	cfg.RulesFile = t.TempDir() + "/rules.txt"
	if err := cfg.applyDefaults(); err != nil {
		t.Fatal(err)
	}
	if cfg.RuleProviders == nil {
		t.Fatal("nil 订阅段没有被归一成空切片")
	}
	if len(cfg.RuleProviders) != 0 {
		t.Fatalf("不该凭空多出订阅: %+v", cfg.RuleProviders)
	}
}
