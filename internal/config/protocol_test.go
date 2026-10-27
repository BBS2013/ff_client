package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestParseProtocol 空串取 hysteria2 是兼容性的关键：
// 现存每一份配置里都没有 type 这一行，升级后它们必须照原样跑。
func TestParseProtocol(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ProtocolHysteria2},
		{"hysteria2", ProtocolHysteria2},
		{"  Trojan  ", ProtocolTrojan},
	} {
		got, err := ParseProtocol(c.in)
		if err != nil {
			t.Errorf("ParseProtocol(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseProtocol(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"ss", "vless", "shadowsocks", "trojan+udp"} {
		_, err := ParseProtocol(bad)
		if err == nil {
			t.Errorf("ParseProtocol(%q) 应当报错", bad)
			continue
		}
		// 报错必须把可选项列出来：这是一眼就能改对的那种错。
		if !strings.Contains(err.Error(), ProtocolHysteria2) || !strings.Contains(err.Error(), ProtocolTrojan) {
			t.Errorf("错误信息没列出可选协议: %v", err)
		}
	}
	if got := (ServerConfig{Type: "ss"}).Protocol(); got != ProtocolHysteria2 {
		t.Errorf("非法 type 的 Protocol() 应当退化成 %q，实得 %q", ProtocolHysteria2, got)
	}
}

const trojanYAML = `
proxies:
  - name: "东京-trojan"
    server:
      type: trojan
      addr: "tj.example.com:8443"
      auth: "pw-with=sign"
      tls:
        sni: bing.com
        insecure: true
inbounds:
  - { type: socks5, listen: "127.0.0.1:7891" }
`

// TestTrojanNodeNeedsNoHysteriaFields 是两种协议共用一段配置的关键：
// trojan 没有带宽整形与拥塞算法，缺了这些字段也必须算合法配置。
func TestTrojanNodeNeedsNoHysteriaFields(t *testing.T) {
	cfg, err := Load(writeYAML(t, trojanYAML))
	if err != nil {
		t.Fatalf("trojan 节点不该被按 hysteria2 的字段要求拦住: %v", err)
	}
	srv := cfg.ActiveServer()
	if srv.Protocol() != ProtocolTrojan {
		t.Fatalf("协议 = %q", srv.Protocol())
	}
	// sni 是显式写的，不能被地址的 host 覆盖掉：这类节点的证书是给 bing.com 签的。
	if srv.TLS.SNI != "bing.com" || !srv.TLS.Insecure {
		t.Fatalf("tls 字段不对: %+v", srv.TLS)
	}
	if srv.Auth != "pw-with=sign" {
		t.Fatalf("auth = %q", srv.Auth)
	}
}

func TestValidateRejectsBadProtocol(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"未知协议", "proxies:\n  - {name: a, server: {type: vless, addr: \"a.com:443\", auth: x}}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\n", "不支持的协议"},
		{"hy2 带宽非法", "proxies:\n  - {name: a, server: {addr: \"a.com:443\", auth: x, bandwidth: {up: \"fast\", down: \"1 mbps\"}}}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\n", "bandwidth"},
		{"trojan 忽略 hy2 字段", "proxies:\n  - {name: a, server: {type: trojan, addr: \"a.com:443\", auth: x, bandwidth: {up: \"fast\"}}}\ninbounds: [{type: socks5, listen: \"127.0.0.1:7891\"}]\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeYAML(t, c.body))
			if c.want == "" {
				if err != nil {
					t.Fatalf("这一条本该合法: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("期望报错")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("错误 %q 未包含 %q", err, c.want)
			}
		})
	}
}

// TestSaveKeepsProtocol 保证 Save→Load 不会把 type 洗掉。
// 一旦洗掉，下次读到的就是 hysteria2 出站，界面显示 trojan 却按 hy2 握手，
// 故障表现会是「莫名其妙连不上」。
func TestSaveKeepsProtocol(t *testing.T) {
	cfg, err := Load(writeYAML(t, trojanYAML))
	if err != nil {
		t.Fatal(err)
	}
	// 输出写到独立目录，与被测的输入文件互不干扰。
	out := filepath.Join(t.TempDir(), "out.yaml")
	if err := Save(out, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, err := Load(out)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if !reflect.DeepEqual(cfg.ActiveServer(), reloaded.ActiveServer()) {
		t.Fatalf("协议字段没原样回来:\n%+v\n%+v", cfg.ActiveServer(), reloaded.ActiveServer())
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "type: trojan") {
		t.Fatalf("写出的 yaml 里没有 type:\n%s", raw)
	}
}
