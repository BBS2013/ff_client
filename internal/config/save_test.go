package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const sampleYAML = `server:
  addr: "example.com:443"
  auth: "s3cret"
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
  servers: ["223.5.5.5"]
  timeout: "3s"
  cache: "300s"
log: { level: "info" }
`

func writeSample(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(sampleYAML), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	return path
}

// TestSaveRoundTrip 是 Save 最要紧的一条：写出去再读回来必须一模一样。
// Duration 没有 MarshalYAML 时会被写成裸纳秒数，读回来变成天文数字秒。
func TestSaveRoundTrip(t *testing.T) {
	path := writeSample(t)
	before, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Save(path, before); err != nil {
		t.Fatalf("Save: %v", err)
	}
	after, err := Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("Save→Load 不等价:\n前: %+v\n后: %+v", before, after)
	}
	if after.DNS.Timeout.Duration != 3*time.Second {
		t.Fatalf("timeout 回读为 %v, 期望 3s", after.DNS.Timeout.Duration)
	}
	if after.DNS.Cache.Duration != 300*time.Second {
		t.Fatalf("cache 回读为 %v, 期望 300s", after.DNS.Cache.Duration)
	}
}

func TestSaveWritesDurationAsString(t *testing.T) {
	path := writeSample(t)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回: %v", err)
	}
	for _, want := range []string{`timeout: 3s`, `cache: 5m0s`} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("yaml 里应含 %q，实际:\n%s", want, body)
		}
	}
	// 裸纳秒数一旦出现就说明 MarshalYAML 没生效。
	if strings.Contains(string(body), "300000000000") {
		t.Fatalf("duration 被写成了裸纳秒数:\n%s", body)
	}
}

func TestSaveCreatesBackup(t *testing.T) {
	path := writeSample(t)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读原文件: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Proxies[0].Server.Congestion = "cubic"
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}

	bak, err := os.ReadFile(path + BackupSuffix)
	if err != nil {
		t.Fatalf("备份应已生成: %v", err)
	}
	if string(bak) != string(original) {
		t.Fatal("备份内容应与保存前的原文件一致")
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if reloaded.ActiveServer().Congestion != "cubic" {
		t.Fatalf("新值没写进去，congestion = %q", reloaded.ActiveServer().Congestion)
	}
}

func TestSaveWithoutExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	cfg, err := Load(writeSample(t))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// 首次保存时没有可备份的原文件，不该报错。
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("回读: %v", err)
	}
	if _, err := os.Stat(path + BackupSuffix); err == nil {
		t.Fatal("没有原文件时不应凭空造出备份")
	}
}

func TestSaveRejectsInvalidConfig(t *testing.T) {
	path := writeSample(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读原文件: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg.Proxies[0].Server.Auth = "" // Validate 要求 auth 非空

	err = Save(path, cfg)
	if err == nil || !strings.Contains(err.Error(), "server.auth") {
		t.Fatalf("非法配置应在落盘前被拒绝，实际 %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读原文件: %v", err)
	}
	if string(before) != string(after) {
		t.Fatal("校验失败不应动过原文件")
	}
	if _, err := os.Stat(path + BackupSuffix); err == nil {
		t.Fatal("校验失败不该产生备份")
	}
}

func TestSaveNilConfig(t *testing.T) {
	if err := Save(filepath.Join(t.TempDir(), "c.yaml"), nil); err == nil {
		t.Fatal("nil 配置应报错")
	}
}

// TestSaveTightensPermissions 确认含口令的配置文件不会落成 0644。
func TestSaveTightensPermissions(t *testing.T) {
	path := writeSample(t)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("权限 = %v, 期望 0600", fi.Mode().Perm())
	}
}

// TestSaveLeavesNoTempFile 保证临时文件被 rename 或清理干净。
func TestSaveLeavesNoTempFile(t *testing.T) {
	path := writeSample(t)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("读目录: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("残留临时文件 %s", e.Name())
		}
	}
}

func TestSaveInheritsDefaults(t *testing.T) {
	// 最小配置：默认值在 Save 里的 Validate 阶段补齐，回读应当是完整的。
	path := filepath.Join(t.TempDir(), "config.yaml")
	minimal := "server:\n  addr: \"example.com:443\"\n  auth: \"x\"\ninbounds:\n  - { type: socks5, listen: \"127.0.0.1:7891\" }\n"
	if err := os.WriteFile(path, []byte(minimal), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if got.ActiveServer().TLS.SNI != "example.com" {
		t.Fatalf("sni 未被补齐: %q", got.ActiveServer().TLS.SNI)
	}
	if got.Log.Level != "info" || got.RulesFile == "" || got.GeoIP.Path == "" {
		t.Fatalf("默认值未被保留: log=%q rules=%q geoip=%q", got.Log.Level, got.RulesFile, got.GeoIP.Path)
	}
	if len(got.DNS.Servers) == 0 {
		t.Fatal("dns.servers 默认值未保留")
	}
}
