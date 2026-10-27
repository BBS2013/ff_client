package ui

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/logx"
)

// sampleCfg 是测试用的完整配置：含 socks5 认证、http 入站与 DNS 时长，
// 覆盖表单的每一个字段。
const sampleCfg = `server:
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
  - { type: socks5, listen: "127.0.0.1:7891", username: "bob", password: "pw123" }
  - { type: http,   listen: "127.0.0.1:7892" }
geoip: { path: "./assets/geoip.mmdb" }
rules_file: "./assets/rules.txt"
dns:
  servers: ["223.5.5.5", "119.29.29.29"]
  timeout: "3s"
  cache: "300s"
log: { level: "info" }
`

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	return path
}

func TestLogBufferReturnsAll(t *testing.T) {
	b := newLogBuffer(4)
	for i := 1; i <= 3; i++ {
		b.add(logx.LevelInfo, string(rune('a'+i-1)), time.Now())
	}
	p := b.page(0)
	if len(p.Entries) != 3 {
		t.Fatalf("应返回 3 条，实际 %d", len(p.Entries))
	}
	if p.Latest != 3 {
		t.Fatalf("Latest = %d, 期望 3", p.Latest)
	}
	if p.Truncated {
		t.Fatal("首次全量拉取不该报截断")
	}
	for i, e := range p.Entries {
		if e.Seq != int64(i+1) {
			t.Fatalf("第 %d 条 Seq = %d, 期望 %d", i, e.Seq, i+1)
		}
	}
}

func TestLogBufferIncremental(t *testing.T) {
	b := newLogBuffer(8)
	for i := 1; i <= 5; i++ {
		b.add(logx.LevelInfo, "x", time.Now())
	}
	first := b.page(0)
	second := b.page(first.Latest)
	if len(second.Entries) != 0 {
		t.Fatalf("没有新日志时应返回空，实际 %d 条", len(second.Entries))
	}
	b.add(logx.LevelWarn, "新的一条", time.Now())
	third := b.page(second.Latest)
	if len(third.Entries) != 1 || third.Entries[0].Msg != "新的一条" {
		t.Fatalf("增量拉取应只返回新的一条，实际 %+v", third.Entries)
	}
	if third.Entries[0].Level != "WARN" {
		t.Fatalf("级别 = %q, 期望 WARN", third.Entries[0].Level)
	}
	if third.Truncated {
		t.Fatal("没被覆盖过不该报截断")
	}
}

// TestLogBufferRingWraps 确认绕回后老数据确实被丢弃，并且明确告知前端。
func TestLogBufferRingWraps(t *testing.T) {
	b := newLogBuffer(4)
	for i := 1; i <= 6; i++ {
		b.add(logx.LevelInfo, "x", time.Now())
	}
	p := b.page(0)
	if len(p.Entries) != 4 {
		t.Fatalf("容量 4 时最多保留 4 条，实际 %d", len(p.Entries))
	}
	if p.Entries[0].Seq != 3 || p.Latest != 6 {
		t.Fatalf("应保留 Seq 3..6，实际 %d..%d", p.Entries[0].Seq, p.Latest)
	}
	// 前端拿着 1 来要 2~6，中间已被覆盖，必须报截断让它整表替换。
	inc := b.page(1)
	if !inc.Truncated {
		t.Fatal("被覆盖过应报 Truncated")
	}
	if inc.Entries[0].Seq != 3 {
		t.Fatalf("截断后应返回最老可用的一条，实际 Seq=%d", inc.Entries[0].Seq)
	}
	// 拿着仍然保留的 4 来要 5..6，是连续的，不该报截断。
	if tail := b.page(4); tail.Truncated {
		t.Fatal("连续区间不该报 Truncated")
	}
}

func TestLogBufferSkipsUnwrittenSlots(t *testing.T) {
	b := newLogBuffer(8)
	b.add(logx.LevelInfo, "只有一条", time.Now())
	p := b.page(0)
	if len(p.Entries) != 1 {
		t.Fatalf("未写过的槽位不该出现在结果里，实际 %d 条", len(p.Entries))
	}
}

// TestReadFormMasksSecrets 是安全底线：明文口令不得越过 Wails 边界。
func TestReadFormMasksSecrets(t *testing.T) {
	f, err := readForm(writeCfg(t, sampleCfg))
	if err != nil {
		t.Fatalf("readForm: %v", err)
	}
	// 表单里不再携带节点口令：节点走 Profiles/AddProfile 专用通道，
	// 明文口令连表单都不该进。这里守的是「读出来的东西里没有明文」。
	if f.ActiveName != "example.com" {
		t.Fatalf("ActiveName = %q, 期望 example.com", f.ActiveName)
	}
	if f.ActiveAddr != "example.com:443" {
		t.Fatalf("ActiveAddr = %q", f.ActiveAddr)
	}
	if f.Mode != "rule" {
		t.Fatalf("Mode = %q, 默认应为 rule", f.Mode)
	}
	if f.TUN.Device != "wps-tun" || f.TUN.FakeIPRange != "198.18.0.0/15" || !f.TUN.HijackDNS {
		t.Fatalf("TUN 默认值没读出来: %+v", f.TUN)
	}
	if len(f.Inbounds) != 2 {
		t.Fatalf("应有 2 条入站，实际 %d", len(f.Inbounds))
	}
	if f.Inbounds[0].Username != MaskedSecret || f.Inbounds[0].Password != MaskedSecret {
		t.Fatalf("socks5 凭据未掩码: %+v", f.Inbounds[0])
	}
	if f.Inbounds[1].Type != "http" || f.Inbounds[1].Username != "" {
		t.Fatalf("http 入站不该有凭据: %+v", f.Inbounds[1])
	}
	if f.DNSTimeout != "3s" || f.DNSCache != "5m0s" {
		t.Fatalf("时长应转成可读字符串: %q / %q", f.DNSTimeout, f.DNSCache)
	}
	// 整份表单序列化后不得出现明文。
	blob := dumpForm(f)
	if strings.Contains(blob, "s3cret") || strings.Contains(blob, "pw123") {
		t.Fatalf("表单里漏出了明文凭据: %s", blob)
	}
}

func TestReadFormMissingFile(t *testing.T) {
	if _, err := readForm(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("配置文件不存在时应报错")
	}
}

// TestWriteFormKeepsMaskedSecret 确认表单原样回写不会把口令变成掩码串。
func TestWriteFormKeepsMaskedSecret(t *testing.T) {
	path := writeCfg(t, sampleCfg)
	f, err := readForm(path)
	if err != nil {
		t.Fatalf("readForm: %v", err)
	}
	if err := writeForm(path, f); err != nil {
		t.Fatalf("writeForm: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if cfg.ActiveServer().Auth != "s3cret" {
		t.Fatalf("口令被改坏了: %q", cfg.ActiveServer().Auth)
	}
	if cfg.Inbounds[0].Username != "bob" || cfg.Inbounds[0].Password != "pw123" {
		t.Fatalf("入站凭据被改坏了: %+v", cfg.Inbounds[0])
	}
}

func TestWriteFormUpdatesFields(t *testing.T) {
	path := writeCfg(t, sampleCfg)
	f, err := readForm(path)
	if err != nil {
		t.Fatalf("readForm: %v", err)
	}
	f.Mode = "global"
	f.LogLevel = "debug"
	f.DNSServers = []string{"8.8.8.8, 1.1.1.1"}
	f.DNSTimeout = "10s"
	f.Inbounds[1].Listen = "127.0.0.1:7893"
	f.TUN.Enable = true
	f.TUN.Device = "wps0"
	f.TUN.Address = "10.77.0.1/24"
	f.TUN.MTU = 1400
	f.TUN.DNS = "10.77.0.2"
	f.TUN.FakeIPRange = "198.19.0.0/16"
	f.TUN.HijackDNS = false
	f.TUN.StrictRoute = true
	f.TUN.RouteExclude = []string{"10.0.0.0/8"}

	if err := writeForm(path, f); err != nil {
		t.Fatalf("writeForm: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if cfg.ModeValue() != config.ModeGlobal {
		t.Fatalf("模式没写进去: %q", cfg.Mode)
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("日志级别没写进去: %q", cfg.Log.Level)
	}
	if len(cfg.DNS.Servers) != 2 || cfg.DNS.Servers[0] != "8.8.8.8" || cfg.DNS.Servers[1] != "1.1.1.1" {
		t.Fatalf("dns.servers = %v", cfg.DNS.Servers)
	}
	if cfg.DNS.Timeout.Duration != 10*time.Second {
		t.Fatalf("dns.timeout = %v, 期望 10s", cfg.DNS.Timeout.Duration)
	}
	if cfg.Inbounds[1].Listen != "127.0.0.1:7893" {
		t.Fatalf("入站端口没写进去: %q", cfg.Inbounds[1].Listen)
	}
	if !cfg.TUN.Enable || cfg.TUN.Device != "wps0" || cfg.TUN.MTU != 1400 ||
		cfg.TUN.DNS != "10.77.0.2" || cfg.TUN.FakeIPRange != "198.19.0.0/16" ||
		cfg.TUN.DNSHijackEnabled() || !cfg.TUN.StrictRoute {
		t.Fatalf("TUN 段落没写进去: %+v", cfg.TUN)
	}
	if len(cfg.TUN.RouteExclude) != 1 || cfg.TUN.RouteExclude[0] != "10.0.0.0/8" {
		t.Fatalf("route_exclude = %v", cfg.TUN.RouteExclude)
	}
	// 节点信息不在表单里，保存表单绝不能把它顺手改掉。
	if cfg.ActiveServer().Addr != "example.com:443" || cfg.ActiveServer().Congestion != "bbr" {
		t.Fatalf("节点配置被表单保存动过了: %+v", cfg.Proxies[0].Server)
	}
}

// TestWriteFormEmptyKeepsCurrent 确认「留空即不变」：
// 提交一份只改了日志级别的表单，其余字段（含整个 TUN 段）必须原样留在磁盘上。
func TestWriteFormEmptyKeepsCurrent(t *testing.T) {
	path := writeCfg(t, sampleCfg)
	if err := writeForm(path, ConfigForm{LogLevel: "debug"}); err != nil {
		t.Fatalf("writeForm: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("日志级别没写进去: %q", cfg.Log.Level)
	}
	if cfg.ModeValue() != config.ModeRule {
		t.Fatalf("模式被空表单改掉了: %q", cfg.Mode)
	}
	if cfg.ActiveServer().Addr != "example.com:443" || cfg.ActiveServer().Auth != "s3cret" {
		t.Fatalf("节点被空表单改掉了: %+v", cfg.Proxies[0].Server)
	}
	if len(cfg.Inbounds) != 2 {
		t.Fatalf("入站列表被清空了: %d 条", len(cfg.Inbounds))
	}
	if cfg.TUN.Device != "wps-tun" || cfg.TUN.Address == "" || cfg.TUN.FakeIPRange == "" {
		t.Fatalf("TUN 配置被空表单抹平了: %+v", cfg.TUN)
	}
}

func TestWriteFormBadDuration(t *testing.T) {
	path := writeCfg(t, sampleCfg)
	if err := writeForm(path, ConfigForm{DNSTimeout: "五秒"}); err == nil {
		t.Fatal("非法时长应报错")
	}
	// 失败不该动过原文件。
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if cfg.DNS.Timeout.Duration != 3*time.Second {
		t.Fatalf("原文件被改动了: %v", cfg.DNS.Timeout.Duration)
	}
}

func TestWriteFormCreatesBackup(t *testing.T) {
	path := writeCfg(t, sampleCfg)
	if err := writeForm(path, ConfigForm{LogLevel: "warn"}); err != nil {
		t.Fatalf("writeForm: %v", err)
	}
	if _, err := os.Stat(path + config.BackupSuffix); err != nil {
		t.Fatalf("备份未生成: %v", err)
	}
}

func TestParseDuration(t *testing.T) {
	for _, c := range []struct {
		in   string
		want time.Duration
	}{
		{"3s", 3 * time.Second},
		{"300", 300 * time.Second}, // 纯数字按秒，与 UnmarshalYAML 一致
		{"1m30s", 90 * time.Second},
		{"1.5", 1500 * time.Millisecond},
	} {
		got, err := parseDuration(c.in)
		if err != nil {
			t.Fatalf("parseDuration(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("parseDuration(%q) = %v, 期望 %v", c.in, got, c.want)
		}
	}
	if _, err := parseDuration("以后再说"); err == nil {
		t.Fatal("非法输入应报错")
	}
}

// TestAppLifecycle 走一遍绑定层对外暴露的全部控制方法。
func TestAppLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	rules := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rules, []byte("DOMAIN-SUFFIX,example.com,DIRECT\nFINAL,PROXY\n"), 0o600); err != nil {
		t.Fatalf("写规则: %v", err)
	}
	body := strings.Replace(sampleCfg, "127.0.0.1:7891", "127.0.0.1:0", 1)
	body = strings.Replace(body, "127.0.0.1:7892", "127.0.0.1:0", 1)
	body = strings.Replace(body, "./assets/rules.txt", rules, 1)
	body = strings.Replace(body, `log: { level: "info" }`, `log: { level: "warn" }`, 1)
	// 服务端地址换成 IP 字面量：sampleCfg 里那个 example.com 是给纯配置用例断言
	// SNI 回退和表单字段用的，而这条用例真的会 Start()——Start 要先解析服务端地址，
	// 于是整套测试就被绑在「这台机器此刻能出网」上。
	// 本用例测的是生命周期与状态投影，不是 DNS；为它去依赖解析器，
	// 换来的是一条在断网/DNS 故障的机器上必然变红的用例（红了还分不清是代码坏还是网坏）。
	body = strings.Replace(body, `addr: "example.com:443"`, `addr: "127.0.0.1:4433"`, 1)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}

	app := New(path)
	defer func() { _ = app.Close() }()

	if snap := app.Status(); snap.Running {
		t.Fatal("刚创建时不应在运行")
	}
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	snap := app.Status()
	if !snap.Running || len(snap.Inbounds) != 2 {
		t.Fatalf("启动后状态不对: running=%v inbounds=%d", snap.Running, len(snap.Inbounds))
	}
	for _, in := range snap.Inbounds {
		if !in.Active || in.Addr == "" {
			t.Fatalf("入站 %s 未激活: %+v", in.Type, in)
		}
	}
	if !snap.AuthSet {
		t.Fatal("AuthSet 应为 true")
	}

	// 启停一次，日志与流量接口都要还能用。
	//
	// 这里不能断言序列为空：采样器每秒产一个点，与有没有流量无关，
	// 而 -race 下本测试跑得慢，几个零值点会自然攒出来。
	// 「尚无流量」真正该保证的是累计量为 0、序列上的速率全是 0。
	tr := app.Traffic()
	if tr.ActiveCount != 0 || tr.TotalConns != 0 || tr.TotalUp != 0 || tr.TotalDown != 0 {
		t.Fatalf("尚无流量时累计量应全为 0: %+v", tr)
	}
	for i, s := range tr.Series {
		if s.Up != 0 || s.Down != 0 {
			t.Fatalf("尚无流量时第 %d 个采样点速率应全为 0，实际 up=%v down=%v", i, s.Up, s.Down)
		}
	}
	app.ResetStats()

	if err := app.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if !app.Status().Running {
		t.Fatal("重启后应在运行")
	}
	if err := app.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if app.Status().Running {
		t.Fatal("停止后不应在运行")
	}
	if err := app.Stop(); err != nil {
		t.Fatalf("重复 Stop 应无副作用: %v", err)
	}

	page := app.Logs(0)
	if page.Latest == 0 {
		t.Fatal("日志缓冲应已收到启动/停止产生的日志")
	}
}

func TestAppReloadWhenStopped(t *testing.T) {
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()
	if err := app.Reload(); err == nil {
		t.Fatal("未运行时重载应报错")
	}
}

// TestAppLogsCapturesHook 确认 App 真的把日志抄了一份。
func TestAppLogsCapturesHook(t *testing.T) {
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()
	before := app.Logs(0).Latest
	logx.Warnf("来自测试的一条 %d", 7)
	page := app.Logs(before)
	if len(page.Entries) == 0 {
		t.Fatal("钩子没把日志送进缓冲")
	}
	if !strings.Contains(page.Entries[len(page.Entries)-1].Msg, "来自测试的一条 7") {
		t.Fatalf("日志内容不对: %+v", page.Entries)
	}
}

func TestAppConfigRoundTrip(t *testing.T) {
	path := writeCfg(t, sampleCfg)
	app := New(path)
	defer func() { _ = app.Close() }()

	f, err := app.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig: %v", err)
	}
	if f.Path != path {
		t.Fatalf("Path = %q, 期望 %q", f.Path, path)
	}
	f.LogLevel = "debug"
	if err := app.SaveConfig(f); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if cfg.Log.Level != "debug" || cfg.ActiveServer().Auth != "s3cret" {
		t.Fatalf("保存结果不对: log=%q auth=%q", cfg.Log.Level, cfg.ActiveServer().Auth)
	}
}

func TestAppCloseIsIdempotent(t *testing.T) {
	app := New(writeCfg(t, sampleCfg))
	if err := app.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("重复 Close 应无副作用: %v", err)
	}
}

func TestSplitList(t *testing.T) {
	got := splitList([]string{" a , b ", "c", ""})
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("splitList = %v", got)
	}
	if splitList([]string{"", "  "}) != nil {
		t.Fatal("全空应返回 nil 表示「没动这个字段」")
	}
}

// dumpForm 把表单转成 JSON 形态的字符串，专供安全断言使用。
func dumpForm(f ConfigForm) string {
	var b strings.Builder
	for _, v := range []string{f.ActiveName, f.ActiveAddr, f.Mode, f.LogLevel, f.DNSTimeout, f.TUN.Device, f.TUN.DNS} {
		b.WriteString(v)
		b.WriteByte('\n')
	}
	for _, in := range f.Inbounds {
		b.WriteString(in.Type + "|" + in.Listen + "|" + in.Username + "|" + in.Password + "\n")
	}
	return b.String()
}

// TestWriteFormKeepsTUNHelper 守的是一条安全边界：tun.helper 是「用哪条命令提权」，
// 它刻意不是表单字段。表单整块替换 TUN 段，如果顺手把它带没了，
// 用户改个网卡名就会把 root 命令行清空（或者更糟：清空后 TUN 悄悄换成需要 root 的路径）。
func TestWriteFormKeepsTUNHelper(t *testing.T) {
	body := sampleCfg + `
tun:
  enable: true
  device: wps-tun
  address: 172.19.0.1/30
  helper:
    - sudo
    - "-n"
    - "/usr/local/bin/wps_app"
    - "--tun-helper"
`
	path := writeCfg(t, body)
	f, err := readForm(path)
	if err != nil {
		t.Fatalf("readForm: %v", err)
	}
	// 表单里读不到提权命令：它只用于显示状态，不接受界面回写。
	if raw, err := os.ReadFile(path); err == nil && !strings.Contains(string(raw), "--tun-helper") {
		t.Fatal("用例配错了：磁盘上本该有 helper")
	}

	f.TUN.Device = "wps-tun2"
	if err := writeForm(path, f); err != nil {
		t.Fatalf("writeForm: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if cfg.TUN.Device != "wps-tun2" {
		t.Fatalf("网卡名没改过来: %q", cfg.TUN.Device)
	}
	want := []string{"sudo", "-n", "/usr/local/bin/wps_app", "--tun-helper"}
	if !reflect.DeepEqual(cfg.TUN.Helper, want) {
		t.Fatalf("一次表单保存把 tun.helper 改掉了: %q", cfg.TUN.Helper)
	}
}

// TestWriteFormKeepsTUNv6 与 helper 同理：v6 那一组没有表单字段，
// 于是 writeForm 必须原样带回。一次「顺手保存」把用户的 IPv6 选择抹掉，
// 症状是重启后面板不再接管 v6，而界面上没有任何地方能看出发生了什么。
func TestWriteFormKeepsTUNv6(t *testing.T) {
	body := sampleCfg + `
tun:
  enable: true
  device: wps-tun
  address: 172.19.0.1/30
  address6: fd00:abcd::1/64
  fake_ip_range6: fc00:aaaa::/32
  ipv6: false
`
	path := writeCfg(t, body)
	f, err := readForm(path)
	if err != nil {
		t.Fatalf("readForm: %v", err)
	}
	f.TUN.Device = "wps-tun2"
	if err := writeForm(path, f); err != nil {
		t.Fatalf("writeForm: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if cfg.TUN.Device != "wps-tun2" {
		t.Fatalf("用例配错了：表单能改的字段没改上（%q）", cfg.TUN.Device)
	}
	if cfg.TUN.Address6 != "fd00:abcd::1/64" || cfg.TUN.FakeIPRange6 != "fc00:aaaa::/32" {
		t.Fatalf("面板保存把 v6 配置抹了: address6=%q fake_ip_range6=%q",
			cfg.TUN.Address6, cfg.TUN.FakeIPRange6)
	}
	if cfg.TUN.IPv6On() {
		t.Error("面板保存把 tun.ipv6: false 改成了开启")
	}
}

// TestWriteFormKeepsSysProxyBackend sysproxy.backend 同样没有表单字段
// （选后端等于换一条改用户系统设置的路，不该由界面顺手决定）。
// 一次「保存配置」把它抹成自动探测，用户在 KDE 上会突然掉回 gsettings 报错，
// 而界面上没有任何地方能看出发生了什么。
func TestWriteFormKeepsSysProxyBackend(t *testing.T) {
	path := writeCfg(t, sampleCfg+"\nsysproxy:\n  backend: kde\n")
	f, err := readForm(path)
	if err != nil {
		t.Fatalf("readForm: %v", err)
	}
	f.LogLevel = "debug" // 顺手改一个无关字段，走真实的面板保存路径
	if err := writeForm(path, f); err != nil {
		t.Fatalf("writeForm: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("用例配错了：表单能改的字段没改上（%q）", cfg.Log.Level)
	}
	if cfg.SysProxy.Backend != "kde" {
		t.Fatalf("面板保存把 sysproxy.backend 抹了: %q", cfg.SysProxy.Backend)
	}
}

// TestWriteFormKeepsBlock 拦截名单不在表单里，一次面板保存必须原样带回。
//
// 与 sysproxy.backend 同一个理由，而且后果更重：名单被洗成空，
// 表现是"广告又回来了"，用户既看不到报错也看不出是谁动的。
func TestWriteFormKeepsBlock(t *testing.T) {
	path := writeCfg(t, sampleCfg+"\nblock:\n  domains: [\"ads.example.com\", \"track.example.net\"]\n")
	f, err := readForm(path)
	if err != nil {
		t.Fatalf("readForm: %v", err)
	}
	f.LogLevel = "debug"
	if err := writeForm(path, f); err != nil {
		t.Fatalf("writeForm: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if cfg.Log.Level != "debug" {
		t.Fatalf("用例配错了：表单能改的字段没改上（%q）", cfg.Log.Level)
	}
	if len(cfg.Block.Domains) != 2 || cfg.Block.Domains[0] != "ads.example.com" {
		t.Fatalf("面板保存把拦截名单洗了: %+v", cfg.Block.Domains)
	}
}

// TestAppBlockListBinding 规则页那一栏走的是这个绑定：
// 名单要原样送到界面上，且必须带上「是否在生效」和当前模式——
// 少带模式，直连模式下的空拦就会被显示成"这些都被拦着"。
func TestAppBlockListBinding(t *testing.T) {
	app := New(writeCfg(t, sampleCfg+"\nblock:\n  domains: [\"ads.example.com\", \"Track.Example.NET\"]\n"))
	defer func() { _ = app.Close() }()

	v := app.BlockList()
	if len(v.Domains) != 2 || v.Domains[0] != "ads.example.com" || v.Domains[1] != "track.example.net" {
		t.Fatalf("名单不对（应已归一化）: %+v", v)
	}
	if v.Path != app.svc.ConfigPath() {
		t.Errorf("Path = %q, 期望指向配置文件 %q", v.Path, app.svc.ConfigPath())
	}
	if v.Mode == "" {
		t.Error("必须带模式：界面靠它判断要不要提示「黑名单已让开」")
	}

	// 空名单也要能正常交给界面，别让前端去防 null。
	empty := New(writeCfg(t, sampleCfg))
	defer func() { _ = empty.Close() }()
	if got := empty.BlockList(); got.Domains == nil {
		t.Error("Domains 不该是 nil 切片，界面直接 .length 会炸")
	}
}
