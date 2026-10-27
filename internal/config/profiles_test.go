package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const twoProxies = `
proxies:
  - name: "新加坡"
    server:
      addr: "sg.example.com:443"
      auth: "sg-secret"
      bandwidth: { up: "200 mbps", down: "1000 mbps" }
      congestion: bbr
  - name: "美国"
    server:
      addr: "us.example.com:8443"
      auth: "us-secret"
active: "美国"
mode: global
inbounds:
  - { type: socks5, listen: "127.0.0.1:7891" }
`

// TestLoadMigratesLegacyServer 是兼容性的底线：只有旧 server: 段的配置
// 必须原样可用，并变成一个节点。
func TestLoadMigratesLegacyServer(t *testing.T) {
	cfg, err := Load(writeYAML(t, minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Proxies) != 1 {
		t.Fatalf("旧 server 段没迁成节点: %+v", cfg.Proxies)
	}
	if cfg.Proxies[0].Name != "example.com" {
		t.Errorf("节点默认名 = %q, 期望取 addr 的 host", cfg.Proxies[0].Name)
	}
	if cfg.Active != "example.com" {
		t.Errorf("active = %q, 单节点时应自动落到它", cfg.Active)
	}
	if cfg.LegacyServer != nil {
		t.Errorf("迁移后旧段应清空，实际 %+v", cfg.LegacyServer)
	}
	if got := cfg.ActiveServer().Addr; got != "example.com:443" {
		t.Errorf("ActiveServer().addr = %q", got)
	}
	if cfg.ModeValue() != ModeRule {
		t.Errorf("mode 默认 = %q, 期望 rule", cfg.Mode)
	}
}

func TestLoadProxiesAndActive(t *testing.T) {
	cfg, err := Load(writeYAML(t, twoProxies))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Proxies) != 2 {
		t.Fatalf("节点数 = %d", len(cfg.Proxies))
	}
	if cfg.ActiveServer().Addr != "us.example.com:8443" {
		t.Fatalf("active 没选中第二个节点: %+v", cfg.ActiveServer())
	}
	if cfg.ModeValue() != ModeGlobal {
		t.Fatalf("mode = %q", cfg.Mode)
	}
	// 没写 sni 时用 host 兜底，hysteria 的 TLS 校验依赖它。
	if cfg.Proxies[1].Server.TLS.SNI != "us.example.com" {
		t.Fatalf("sni 默认值没补: %q", cfg.Proxies[1].Server.TLS.SNI)
	}
	if cfg.Proxies[0].Server.Bandwidth.Up != "200 mbps" {
		t.Fatalf("带宽字段丢了: %+v", cfg.Proxies[0].Server)
	}
}

func TestValidateRejectsBadProxyLists(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"active 指向不存在的节点", "proxies:\n  - name: a\n    server: {addr: \"a.com:443\", auth: x}\nactive: b\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\n", "在 proxies 里不存在"},
		{"节点名重复", "proxies:\n  - {name: a, server: {addr: \"a.com:443\", auth: x}}\n  - {name: a, server: {addr: \"b.com:443\", auth: y}}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\n", "重复"},
		{"节点缺 addr", "proxies:\n  - {name: a, server: {auth: x}}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\n", "server.addr"},
		{"节点缺 auth", "proxies:\n  - {name: a, server: {addr: \"a.com:443\"}}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\n", "server.auth"},
		{"非法模式", "proxies:\n  - {name: a, server: {addr: \"a.com:443\", auth: x}}\nmode: turbo\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\n", "unknown mode"},
		{"完全没有节点", "inbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\n", "至少需要一个代理服务"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeYAML(t, c.body))
			if err == nil {
				t.Fatal("期望报错")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误 %q 未包含 %q", err, c.want)
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Mode
	}{
		{"", ModeRule},
		{"rule", ModeRule},
		{"GLOBAL", ModeGlobal},
		{" direct ", ModeDirect},
	} {
		got, err := ParseMode(c.in)
		if err != nil {
			t.Fatalf("ParseMode(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if _, err := ParseMode("proxy"); err == nil {
		t.Error("非法模式应报错")
	}
}

func TestTUNDefaultsAndValidation(t *testing.T) {
	cfg, err := Load(writeYAML(t, minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TUN.Device != "wps-tun" || cfg.TUN.MTU != 1500 || cfg.TUN.FakeIPRange != "198.18.0.0/15" {
		t.Fatalf("TUN 默认值不对: %+v", cfg.TUN)
	}
	// /30 里的第二个可用地址天然就是假 DNS 的落点。
	if cfg.TUN.DNS != "172.19.0.2" {
		t.Errorf("tun.dns 默认 = %q, 期望 172.19.0.2", cfg.TUN.DNS)
	}
	if !cfg.TUN.DNSHijackEnabled() {
		t.Error("hijack_dns 缺省应为开启")
	}
	if cfg.TUN.Enable {
		t.Error("TUN 不该默认开启")
	}

	bad := []struct {
		name string
		body string
		want string
	}{
		{"地址不是 CIDR", "server: {addr: \"a.com:443\", auth: x}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\ntun: {enable: true, device: wps-tun, address: \"172.19.0.1\", mtu: 1500, fake_ip_range: \"198.18.0.0/15\"}\n", "tun.address"},
		{"假 IP 段太小", "server: {addr: \"a.com:443\", auth: x}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\ntun: {enable: true, device: wps-tun, address: \"172.19.0.1/30\", mtu: 1500, fake_ip_range: \"198.18.0.0/31\"}\n", "放不下假 IP"},
		{"MTU 离谱", "server: {addr: \"a.com:443\", auth: x}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\ntun: {enable: true, device: wps-tun, address: \"172.19.0.1/30\", mtu: 68000, fake_ip_range: \"198.18.0.0/15\"}\n", "tun.mtu"},
		{"接口名过长", "server: {addr: \"a.com:443\", auth: x}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\ntun: {enable: true, device: \"this-name-is-way-too-long\", address: \"172.19.0.1/30\", mtu: 1500, fake_ip_range: \"198.18.0.0/15\"}\n", "接口名"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Load(writeYAML(t, c.body)); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("期望包含 %q 的错误，实际 %v", c.want, err)
			}
		})
	}

	// 未启用时轻量放行：不能因为一段闲置配置把整个客户端拒之门外。
	if _, err := Load(writeYAML(t, "server: {addr: \"a.com:443\", auth: x}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\ntun: {enable: false, device: \"\", address: \"nonsense\", mtu: 1}\n")); err != nil {
		t.Fatalf("未启用的 TUN 段不该阻断加载: %v", err)
	}
}

// TestSaveWritesOnlyNewFormat 盯住一个容易复发的坑：
// server: 与 proxies: 同时落盘就有两份事实源，改一份另一份悄悄过期。
func TestSaveWritesOnlyNewFormat(t *testing.T) {
	path := writeYAML(t, minimalYAML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if strings.Contains(text, "\nserver:") && !strings.Contains(text, "  server:") {
		t.Fatalf("旧 server: 段又被写回去了:\n%s", text)
	}
	if !strings.Contains(text, "proxies:") || !strings.Contains(text, "active:") || !strings.Contains(text, "tun:") {
		t.Fatalf("新格式字段没写全:\n%s", text)
	}
	// 写出去的文件必须还能原样读回来。
	again, err := Load(path)
	if err != nil {
		t.Fatalf("回读: %v\n%s", err, text)
	}
	if again.ActiveServer().Auth != "secret" {
		t.Fatalf("口令丢了: %+v", again.Proxies)
	}
}

func TestSaveKeepsAllProfiles(t *testing.T) {
	path := writeYAML(t, twoProxies)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Mode = string(ModeDirect)
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	after, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Proxies) != 2 || after.Proxies[0].Name != "新加坡" {
		t.Fatalf("节点列表保存后变形了: %+v", after.Proxies)
	}
	if after.Active != "美国" || after.ModeValue() != ModeDirect {
		t.Fatalf("active/mode 丢了: %q %q", after.Active, after.Mode)
	}
	// 中文节点名在 YAML 里不该被转义成不可读的样子。
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "新加坡") {
		t.Errorf("节点名被转义了:\n%s", raw)
	}
}

// TestRepoConfigSavesAsNewFormat 仓库里的示例配置必须能原样保存成新格式。
func TestRepoConfigSavesAsNewFormat(t *testing.T) {
	path := filepath.Join("..", "..", "config.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skip("仓库 config.yaml 不存在")
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("仓库 config.yaml 不合法: %v", err)
	}
	if len(cfg.Proxies) == 0 || cfg.ActiveServer().Addr == "" {
		t.Fatalf("示例配置没有可用节点: %+v", cfg.Proxies)
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "\nserver:\n") {
		t.Errorf("示例配置保存时会写出旧 server 段:\n%s", out)
	}
}
