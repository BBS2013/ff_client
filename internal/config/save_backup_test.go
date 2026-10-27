package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSaveKeepsOriginalAndExplainsRewrite(t *testing.T) {
	p := writeYAML(t, "# 手写注释：别丢\n"+minimalYAML)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := Save(p, cfg); err != nil {
			t.Fatalf("第 %d 次保存: %v", i+1, err)
		}
	}

	orig, err := os.ReadFile(p + OrigSuffix)
	if err != nil {
		t.Fatalf("原始备份不存在: %v", err)
	}
	if !strings.Contains(string(orig), "手写注释：别丢") {
		t.Errorf("连续保存 3 次后原始注释丢了: %q", string(orig))
	}
	cur, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(cur), "# 本文件由 wps_app") {
		t.Errorf("回写文件没有说明头: %q", string(cur[:min(len(cur), 80)]))
	}
	if !strings.Contains(string(cur), filepath.Base(p+OrigSuffix)) {
		t.Error("说明头没有指出原件保存在哪里")
	}
	if _, err := Load(p); err != nil {
		t.Errorf("带说明头的配置应该仍能加载: %v", err)
	}
}

func TestOrigIsNeverOverwritten(t *testing.T) {
	p := writeYAML(t, minimalYAML)
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(p, cfg); err != nil {
		t.Fatal(err)
	}
	orig := p + OrigSuffix
	if err := os.WriteFile(orig, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Save(p, cfg); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(orig)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "sentinel" {
		t.Errorf(".orig 被第二次保存覆盖了: %q", string(body))
	}
}

func TestSaveToNewFileHasNoOrigClaim(t *testing.T) {
	p := filepath.Join(t.TempDir(), "fresh.yaml")
	cfg, err := Load(writeYAML(t, minimalYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(p, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + OrigSuffix); !os.IsNotExist(err) {
		t.Errorf("新文件不该凭空生成 .orig: %v", err)
	}
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "首次回写前的原件") {
		t.Error("新文件没有原件，不该写那份说明头")
	}
}
