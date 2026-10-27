package ui

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"wps_app/internal/sysproxy"
)

// TestSysProxyLedgerNamesEachState 五种情况五种话。
//
// 这一行是"桌面为什么不能信"的唯一出处：混成一类的话，
// 用户要么在该跑 restore 时以为一切正常，要么在没事的时候找不存在的故障。
func TestSysProxyLedgerNamesEachState(t *testing.T) {
	cases := []struct {
		name      string
		led       sysproxy.Ledger
		deskOurs  bool
		wantState string
		wantIn    []string
		deny      []string
	}{
		{
			name:      "没记账、桌面也没指着我们",
			led:       sysproxy.Ledger{},
			wantState: "none",
			wantIn:    []string{"没有记账"},
		},
		{
			name:      "没记账、桌面正指着我们",
			led:       sysproxy.Ledger{},
			deskOurs:  true,
			wantState: "orphan",
			wantIn:    []string{"没有记账", "不会还原"},
		},
		{
			name:      "欠一次自愈",
			led:       sysproxy.Ledger{Exists: true, Holder: "宿主 PID 12 已经不在了"},
			wantState: "stale",
			wantIn:    []string{"已经不在了", "下次启动会自动还一次"},
		},
		{
			name:      "宿主还开着",
			led:       sysproxy.Ledger{Exists: true, Alive: true, Holder: "宿主 PID 12 还开着（/bin/wps_app-gui）"},
			wantState: "live",
			wantIn:    []string{"还开着", "下一个实例", "正常退出"},
		},
		{
			name:      "记账读不懂",
			led:       sysproxy.Ledger{ReadErr: "状态文件损坏"},
			wantState: "unreadable",
			wantIn:    []string{"状态文件损坏", "手工核对"},
			deny:      []string{"没有记账"},
		},
		{
			name:      "还原语义是关掉时要说清",
			led:       sysproxy.Ledger{Exists: true, AlreadyOurs: true, Holder: "宿主 PID 12 已经不在了"},
			wantState: "stale",
			wantIn:    []string{"还原等于关掉"},
		},
	}
	for _, c := range cases {
		v := sysProxyLedgerText(c.led, "/tmp/config.yaml.sysproxy.json", c.deskOurs)
		if v.State != c.wantState {
			t.Errorf("%s: state = %q, 期望 %q（%q）", c.name, v.State, c.wantState, v.Text)
		}
		for _, w := range c.wantIn {
			if !strings.Contains(v.Text, w) {
				t.Errorf("%s: 话里缺 %q，实得 %q", c.name, w, v.Text)
			}
		}
		for _, d := range c.deny {
			if strings.Contains(v.Text, d) {
				t.Errorf("%s: 不该出现 %q:\n%s", c.name, d, v.Text)
			}
		}
		if v.Path != "/tmp/config.yaml.sysproxy.json" {
			t.Errorf("%s: 要告诉用户去哪儿自查, 实得 %q", c.name, v.Path)
		}
	}
}

// TestLedgerLogLineOnlyOnChange 日志只在状态变了的那一次说话。
//
// pollSys 每次显示窗口都会读一遍记账；每次都 WARN 会把日志刷成背景噪音，
// 而"没有记账"和"欠还原"混在一起说，反而看不出来。
func TestLedgerLogLineOnlyOnChange(t *testing.T) {
	none := SysProxyLedger{State: "none", Text: "没有记账", Path: "/x/config.yaml.sysproxy.json"}
	orphan := SysProxyLedger{State: "orphan", Text: "桌面正指着本程序的入站，但没有记账", Path: "/x/a.json"}
	stale := SysProxyLedger{State: "stale", Text: "宿主 PID 1 已经不在了", Path: "/x/b.json"}
	unreadable := SysProxyLedger{State: "unreadable", Text: "记账读不懂：坏了", Path: "/x/c.json"}
	live := SysProxyLedger{State: "live", Text: "宿主还开着", Path: "/x/d.json"}

	cases := []struct {
		prev, next SysProxyLedger
		want       string
		why        string
	}{
		{none, none, "", "同一状态重复轮询不该再写"},
		{SysProxyLedger{}, orphan, "", "第一次读到的那句话就是界面那行本身，日志不该再说第二遍"},
		{none, orphan, "", ""}, // 见下：orphan 只在"从别的状态变过来"时补一句
		{orphan, none, "", "回到正常不必打招呼"},
		{orphan, stale, "", ""},
		{live, stale, "", ""},
		{none, unreadable, "", ""},
		{stale, live, "", "还上了账不用庆祝"},
	}
	// 上面只把"该不该说话"写死成结构；逐条核对内容：
	// 每一种新状态最多一句，且必须带上路径或原因，否则日志里看不出该跑哪条命令。
	for _, c := range cases {
		got := ledgerLogLine(c.prev, c.next)
		if c.prev.State == c.next.State && got != "" {
			t.Errorf("状态没变却写了日志: %q", got)
		}
		if c.next.State == "none" || c.next.State == "live" {
			if got != "" {
				t.Errorf("%v → %v 这种正常状态不该占日志: %q", c.prev.State, c.next.State, got)
			}
			continue
		}
		if got == "" {
			t.Errorf("%s → %s: 这一种该在日志里说一句", c.prev.State, c.next.State)
		}
		if c.next.State == "orphan" && !strings.Contains(got, "/x/a.json") {
			t.Errorf("orphan 那句要带上记账文件路径，用户才知道去哪儿查: %q", got)
		}
	}
	_ = []SysProxyLedger{stale, unreadable}
}

// TestSystemProxyLedgerOnCleanBox 干净机器上（没记账、没有可用后端）应说"没有记账"，
// 而不是因为读不到桌面就编出一个"孤儿"或一片红色。
func TestSystemProxyLedgerOnCleanBox(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()

	v := app.SystemProxyLedger()
	if v.State != "none" {
		t.Errorf("空环境里应是无记账, 实得 state=%q text=%q", v.State, v.Text)
	}
	if !strings.HasSuffix(v.Path, "config.yaml"+".sysproxy.json") {
		t.Errorf("路径应当跟着配置文件走: %q", v.Path)
	}
}

// TestSystemProxyLedgerReportsOrphan 就是本机现在这种：桌面被改成指向我们，
// 而记账文件不在。界面上其它格子全是绿的，只有这一行会说"退出时不会还原"。
func TestSystemProxyLedgerReportsOrphan(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	// KDE 后端（空 PATH 下唯一读得了的那条）写一份"正指向本程序入站"的文件。
	body := "[Proxy Settings]\nProxyType=Manual\nhttpProxy=http://127.0.0.1:7892\n" +
		"httpsProxy=https://127.0.0.1:7892\nsocksProxy=socks5://127.0.0.1:7891\n"
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "kioslaverc"), []byte(body), 0o600); err != nil {
		t.Fatalf("写 kioslaverc: %v", err)
	}
	cfg := strings.Replace(sampleCfg, "log: { level: \"info\" }",
		"log: { level: \"info\" }\nsysproxy:\n  backend: \"kde\"\n", 1)
	app := New(writeCfg(t, cfg))
	defer func() { _ = app.Close() }()

	st := app.SystemProxyStatus()
	if !st.Supported || !st.Enabled {
		t.Fatalf("现场没构造起来: %+v", st)
	}
	v := app.SystemProxyLedger()
	if v.State != "orphan" {
		t.Errorf("桌面指着我们而记账不在时应报 orphan, 实得 state=%q text=%q", v.State, v.Text)
	}
}

// TestSystemProxyLedgerPrefersTheLedger 有记账时不必再读桌面：
// 那句话的答案已经在记账里，多读一次后端只是白花一个子进程。
func TestSystemProxyLedgerPrefersTheLedger(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", t.TempDir())
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()

	sp := sysproxy.StatePath(app.svc.ConfigPath())
	if err := os.WriteFile(sp, []byte(`{"pid":0,"backend":"kde","mode":"None"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	v := app.SystemProxyLedger()
	if v.State != "stale" {
		t.Errorf("pid=0 的记账应判成欠还原, 实得 state=%q text=%q", v.State, v.Text)
	}
	if !strings.Contains(v.Text, "宿主") || strings.Contains(v.Text, "没有记账") {
		t.Errorf("有记账时该把记账里那句原话带出来，而不是报成无记账: %q", v.Text)
	}
}

// TestSystemProxyLedgerIsSafeUnderConcurrentCalls 钉住那条并发前提。
//
// Wails 把绑定方法派到别的 goroutine 上调用，而 Close 在主 goroutine 上读写同一个
// App 状态。这里 lastLedger 曾经是不加锁的裸字段，`go test -race` 一压就是 DATA RACE；
// 本项目的测试全是串行调用，所以只有这条用例真的去撞它。
func TestSystemProxyLedgerIsSafeUnderConcurrentCalls(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	app := New(writeCfg(t, sampleCfg))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if got := app.SystemProxyLedger(); got.State == "" {
					t.Errorf("读数不能是空状态")
					return
				}
			}
		}()
	}
	wg.Wait()
	if err := app.Close(); err != nil {
		t.Logf("Close 报错（不影响本用例）: %v", err)
	}
}

// TestExportDiagnosticsWritesMaskedReport 面板上那个"导出诊断信息"按钮的后端半边。
//
// 要验的是两件事：报告真的落到了配置旁边，以及**口令没进去**。
// sampleCfg 里的 auth 是 "s3cret"，它出现在任何一行里都算泄露。
func TestExportDiagnosticsWritesMaskedReport(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()

	path, err := app.ExportDiagnostics()
	if err != nil {
		t.Fatalf("ExportDiagnostics: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读回报告 %s: %v", path, err)
	}
	body := string(raw)
	for _, want := range []string{"## 运行身份", "## 入站", "## 出站节点", "## 系统代理", "生成于"} {
		if !strings.Contains(body, want) {
			t.Errorf("报告里缺 %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "s3cret") {
		t.Errorf("节点密钥漏进了可导出的报告:\n%s", body)
	}
	if !strings.HasSuffix(path, diagFileName) {
		t.Errorf("路径不对: %q", path)
	}
	// 再点一次：同一个文件被覆盖，不在配置目录里堆历史。
	again, err := app.ExportDiagnostics()
	if err != nil || again != path {
		t.Errorf("第二次导出应当覆盖同一个文件: %q vs %q err=%v", again, path, err)
	}
}
