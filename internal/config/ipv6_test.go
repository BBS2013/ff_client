package config

import (
	"strings"
	"testing"
)

func tunWith(mut func(*TUNConfig)) TUNConfig {
	t := DefaultTUN()
	t.Enable = true
	mut(&t)
	return t
}

// minimalCfg 给 Validate 一份能通过其余检查的配置骨架，
// 这样报错就只会来自被测的那一段。
func minimalCfg(tun TUNConfig) *Config {
	return &Config{
		Proxies:  []ProxyProfile{{Name: "n", Server: ServerConfig{Addr: "203.0.113.1:443", Auth: "x"}}},
		Inbounds: []InboundConfig{{Type: "socks5", Listen: "127.0.0.1:1080"}},
		TUN:      tun,
	}
}

func TestTUNv6Defaults(t *testing.T) {
	c := minimalCfg(DefaultTUN())
	c.applyDefaults()
	if c.TUN.Address6 != "fd00:1::1/64" || c.TUN.FakeIPRange6 != "fc00::/18" {
		t.Fatalf("v6 默认值没填上: address6=%q fake_ip_range6=%q", c.TUN.Address6, c.TUN.FakeIPRange6)
	}
	if !c.TUN.IPv6On() {
		t.Error("没写 tun.ipv6 时应当按开启处理")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("默认配置不该报错: %v", err)
	}
}

// TestTUNv6OffLeavesSegmentsEmpty 关掉之后这两个字段不该被默认值填上——
// 留着它们会让人以为「配了但生效了」，而真正生效与否取决于别的地方。
func TestTUNv6OffLeavesSegmentsEmpty(t *testing.T) {
	no := false
	c := minimalCfg(DefaultTUN())
	c.TUN.IPv6 = &no
	c.applyDefaults()
	if c.TUN.IPv6On() {
		t.Error("显式关掉却报告开启")
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("关掉 v6 的配置不该报错: %v", err)
	}
}

func TestTUNv6ValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		mut     func(*TUNConfig)
		wantSub string
	}{
		{"address6 不是 CIDR", func(t *TUNConfig) { t.Address6 = "fd00::1" }, "address6"},
		{"address6 是 v4", func(t *TUNConfig) { t.Address6 = "172.19.0.1/30" }, "IPv6"},
		{"fake_ip_range6 不是 CIDR", func(t *TUNConfig) { t.FakeIPRange6 = "fc00::" }, "fake_ip_range6"},
		{"fake_ip_range6 是 v4", func(t *TUNConfig) { t.FakeIPRange6 = "10.0.0.0/8" }, "IPv6"},
		{"段太小", func(t *TUNConfig) { t.FakeIPRange6 = "fc00::/48" }, "太小"},
		{"与网卡地址重叠", func(t *TUNConfig) { t.Address6 = "fc00::1/64"; t.FakeIPRange6 = "fc00::/18" }, "重叠"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := minimalCfg(tunWith(tc.mut)).Validate()
			if err == nil {
				t.Fatal("该报错却通过了")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("错误信息里没有 %q: %v", tc.wantSub, err)
			}
		})
	}
}

// TestTUNv6ErrorsIgnoredWhenOff 关掉之后字段不参与任何事情，
// 也就没理由为它们的取值报错。
func TestTUNv6ErrorsIgnoredWhenOff(t *testing.T) {
	no := false
	c := minimalCfg(tunWith(func(t *TUNConfig) {
		t.IPv6 = &no
		t.Address6 = "这不是 CIDR"
		t.FakeIPRange6 = "也不是 CIDR"
	}))
	if err := c.Validate(); err != nil {
		t.Fatalf("关掉 v6 时不该校验这两个字段: %v", err)
	}
}

// TestTUNv6SurvivesSaveLoad 新字段必须真的落到磁盘上：
// MarshalYAML 里少列一个，用户点一次「保存」它就没了。
func TestTUNv6SurvivesSaveLoad(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	c := minimalCfg(DefaultTUN())
	c.TUN.Address6 = "fd00:abcd::1/64"
	c.TUN.FakeIPRange6 = "fc00:aaaa::/32"
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.TUN.Address6 != "fd00:abcd::1/64" || got.TUN.FakeIPRange6 != "fc00:aaaa::/32" {
		t.Fatalf("v6 配置没存住: address6=%q fake_ip_range6=%q", got.TUN.Address6, got.TUN.FakeIPRange6)
	}
}
