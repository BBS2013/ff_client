package config

import (
	"os"
	"strings"
	"testing"
)

func TestParseSize(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint64
	}{
		{"", 0},
		{"100", 100},                // 裸数字 = 字节
		{"500b", 500},               //
		{"1kb", 1000},               // 十进制
		{"1kib", 1024},              // 二进制：两套后缀各有含义
		{"1000 GB", 1000 * 1e9},     // 带空格、大写
		{"1.5TB", 1500 * 1e9},       //
		{"2g", 2 * 1e9},             // 单字母等同于带 b 的
		{"1.5TiB", 1.5 * (1 << 40)}, //
		{"1pib", 1 << 50},           //
	} {
		got, err := ParseSize(tc.in)
		if err != nil {
			t.Errorf("ParseSize(%q) 报错: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSize(%q) = %d，想要 %d", tc.in, got, tc.want)
		}
	}
}

// 带宽单位必须被拒，而不是被当成字节数悄悄收下：
// 800Mbit 写成 800MB 差 8 倍，而配额那一格永远不会告诉你它算错了。
func TestParseSizeRejectsBandwidthUnits(t *testing.T) {
	for _, s := range []string{"800mbps", "100 mbit", "10 gb/s"} {
		if _, err := ParseSize(s); err == nil {
			t.Errorf("%q 被收下了：那是带宽写法，配额要的是字节", s)
		}
	}
}

func TestParseSizeRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"abc", "100 xyz", "GB", "-5gb", "1e999gb", "100gbx", "1..5gb", "NaN"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) 竟然通过了", bad)
		} else if !strings.Contains(err.Error(), "size") {
			t.Errorf("ParseSize(%q) 的错误不像在说尺寸: %v", bad, err)
		}
	}
}

// 配额错了要在**加载时**就报，并且错误里要带上节点名与原文：
// 改了三个节点之一，只说"尺寸不合法"得让人逐个翻。
func TestValidateReportsWhichNodeHasBadQuota(t *testing.T) {
	c := &Config{
		Mode:     "rule",
		Inbounds: []InboundConfig{{Type: "socks5", Listen: "127.0.0.1:7891"}},
		Proxies: []ProxyProfile{
			{Name: "good", Server: ServerConfig{Addr: "1.1.1.1:443", Auth: "x"}, Quota: "1000GB"},
			{Name: "typo", Server: ServerConfig{Addr: "2.2.2.2:443", Auth: "x"}, Quota: "1000 gbee"},
		},
	}
	err := c.Validate()
	if err == nil {
		t.Fatal("坏配额被静默接受")
	}
	for _, want := range []string{"typo", "1000 gbee"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误里没提 %q: %v", want, err)
		}
	}
}

// 原文要能活过一次 Save：存成换算后的整数，下次读回来单位就变了，
// 等于面板每保存一次就把用户的配置改成另一种写法。
func TestQuotaSurvivesSaveLoad(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	c := &Config{
		Mode:   "rule",
		Active: "n1",
		Inbounds: []InboundConfig{
			{Type: "socks5", Listen: "127.0.0.1:7891"},
			{Type: "http", Listen: "127.0.0.1:7892"},
		},
		Proxies: []ProxyProfile{
			{Name: "n1", Server: ServerConfig{Addr: "1.1.1.1:443", Auth: "x"}, Quota: "1.5TiB"},
		},
	}
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := back.Proxies[0].Quota; got != "1.5TiB" {
		t.Errorf("配额被改写成 %q 了，原文应当原样留着", got)
	}
	if got := back.Proxies[0].QuotaBytes(); got != uint64(1.5*float64(1<<40)) {
		t.Errorf("换算结果不对: %d", got)
	}

	// 没设配额的那个节点：空串、0 字节，而且文件里不该多出 quota 段。
	plain := &Config{Mode: "rule", Inbounds: c.Inbounds, Proxies: []ProxyProfile{
		{Name: "n1", Server: ServerConfig{Addr: "1.1.1.1:443", Auth: "x"}},
	}}
	p2 := t.TempDir() + "/config.yaml"
	if err := Save(p2, plain); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(p2)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "quota") {
		t.Error("没设配额却往文件里写了 quota")
	}
}

// Validate 会先拦住坏配额，但 QuotaBytes 仍可能拿到没校验过的输入
// （订阅带回来的节点、手工塞进结构体的那份）。那种情况按"没设"处理：
// 配额只是装饰，不能让一个装饰字段把整页用量读数拖下水。
func TestQuotaBytesTreatsUnreadableAsUnset(t *testing.T) {
	if got := (ProxyProfile{Quota: "not-a-size"}).QuotaBytes(); got != 0 {
		t.Errorf("读不出来的配额应当按 0 处理，得到 %d", got)
	}
}
