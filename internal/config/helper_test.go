package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const helperYAML = `
proxies:
  - name: a
    server: { addr: "a.example.com:443", auth: x }
inbounds:
  - { type: socks5, listen: "127.0.0.1:7891" }
tun:
  enable: true
  helper:
    - sudo
    - "-n"
    - "/usr/local/bin/wps_app"
    - "--tun-helper"
`

// TestLoadTUNHelper 认两件事：argv 原样读进来，以及「没配」与「配了空」不产生差异。
// 后者很重要：带 omitempty 的可选列表如果不归一，Save→Load 的等价性会碎在 [] 与 nil 上。
func TestLoadTUNHelper(t *testing.T) {
	cfg, err := Load(writeYAML(t, helperYAML))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sudo", "-n", "/usr/local/bin/wps_app", "--tun-helper"}
	if !reflect.DeepEqual(cfg.TUN.Helper, want) {
		t.Fatalf("helper = %q, 期望 %q", cfg.TUN.Helper, want)
	}

	minimal := `proxies:
  - name: a
    server: { addr: "a.example.com:443", auth: x }
inbounds: [{ type: socks5, listen: "127.0.0.1:7891" }]
tun:
  enable: true
  helper: []
`
	empty, err := Load(writeYAML(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if empty.TUN.Helper != nil {
		t.Fatalf("helper: [] 应归一成 nil，实得 %q", empty.TUN.Helper)
	}
}

func TestValidateRejectsBlankHelperArg(t *testing.T) {
	// argv 里的空项会让 exec 报一句和配置无关的错，必须在这里就拦住。
	body := `proxies:
  - name: a
    server: { addr: "a.example.com:443", auth: x }
inbounds: [{ type: socks5, listen: "127.0.0.1:7891" }]
tun:
  enable: true
  helper: ["sudo", "", "--tun-helper"]
`
	if _, err := Load(writeYAML(t, body)); err == nil {
		t.Fatal("空 argv 项应被拒绝")
	} else if !strings.Contains(err.Error(), "空字符串") {
		t.Fatalf("错误不够具体: %v", err)
	}

	// 没启用 TUN 也照样拦：这是配置写错了，跟开没开无关。
	off := strings.Replace(body, "enable: true", "enable: false", 1)
	if _, err := Load(writeYAML(t, off)); err == nil {
		t.Fatal("未启用时的空 argv 项也应被拒绝")
	}
}

// TestSaveKeepsHelper 是这条配置的存活证明：helper 不进了表单（避免一次
// 「顺手保存」改写 root 命令行），就只能靠 Save 原样带出去。
func TestSaveKeepsHelper(t *testing.T) {
	cfg, err := Load(writeYAML(t, helperYAML))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out.yaml")
	if err := Save(out, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "helper:") || !strings.Contains(string(raw), "--tun-helper") {
		t.Fatalf("写出的 yaml 里没有 helper:\n%s", raw)
	}
	reloaded, err := Load(out)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.TUN, reloaded.TUN) {
		t.Fatalf("TUN 段没原样回来:\n前 %+v\n后 %+v", cfg.TUN, reloaded.TUN)
	}
}
