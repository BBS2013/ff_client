package sysproxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeEnvHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return filepath.Join(dir, ".config", "environment.d", "90-wps_app-proxy.conf")
}

// TestEnvWritesBothCases env 变量大小写两套都要写。
//
// 只写一套等于"一半的程序有效"：curl/git/wget 认小写，一批 Python 与 Java 库
// 只认大写。而那种状态比全不写更难查——因为看起来确实有代理。
func TestEnvWritesBothCases(t *testing.T) {
	path := fakeEnvHome(t)
	if err := (envBackend{}).Apply(context.Background(), &rec{}, Config{
		Enable:    true,
		Backend:   BackendEnv,
		HTTPAddr:  "127.0.0.1:7892",
		SOCKSAddr: "127.0.0.1:7891",
	}); err != nil {
		t.Fatal(err)
	}
	body := readFile(t, path)
	for _, want := range []string{
		"http_proxy=http://127.0.0.1:7892",
		"https_proxy=http://127.0.0.1:7892",
		"all_proxy=socks5://127.0.0.1:7891",
		"no_proxy=localhost,127.0.0.0/8",
		"HTTP_PROXY=http://127.0.0.1:7892",
		"ALL_PROXY=socks5://127.0.0.1:7891",
		"NO_PROXY=localhost,127.0.0.0/8",
		envMarker,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("environment.d 文件里缺 %q:\n%s", want, body)
		}
	}
}

// TestEnvTriesToSetCurrentSession 光写文件的话，当前这一会话里新起的
// systemd 服务要等下次登录才读得到。试一下 systemctl --user。
//
// 这一步失败**不算错**：文件已经写好，重新登录一定生效。所以测试盯的是
// "有没有试"，而不是"试成了没有"。
func TestEnvTriesToSetCurrentSession(t *testing.T) {
	fakeEnvHome(t)
	r := &rec{}
	if err := (envBackend{}).Apply(context.Background(), r, Config{Enable: true, Backend: BackendEnv}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.ran, "\n")
	if !strings.Contains(joined, "systemctl --user set-environment") {
		t.Errorf("没有尝试把变量灌进当前会话:\n%s", joined)
	}
	if !strings.Contains(joined, "http_proxy=http://127.0.0.1:7892") {
		t.Errorf("set-environment 没带上值:\n%s", joined)
	}
}

// TestEnvDisableRemovesFile 关闭就是删掉这一个文件——
// 这正是选 environment.d 而不是 shellrc 的理由。
func TestEnvDisableRemovesFile(t *testing.T) {
	path := fakeEnvHome(t)
	b := envBackend{}
	if err := b.Apply(context.Background(), &rec{}, Config{Enable: true, Backend: BackendEnv}); err != nil {
		t.Fatal(err)
	}
	r := &rec{}
	if err := b.Apply(context.Background(), r, Config{Backend: BackendEnv}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("关闭后文件应当被删掉，实际 err=%v", err)
	}
	if !strings.Contains(strings.Join(r.ran, "\n"), "systemctl --user unset-environment") {
		t.Errorf("没有把当前会话里的变量清掉: %v", r.ran)
	}
	// 再关一次不该报错（文件已经不在了）。
	if err := b.Apply(context.Background(), &rec{}, Config{Backend: BackendEnv}); err != nil {
		t.Errorf("重复关闭应当是无操作，实际 %v", err)
	}
}

// TestEnvRestoreBringsBackExactContent 还原要把用户原来的文件内容写回去。
//
// 别人也可能在 environment.d 里放东西（比如 JAVA_TOOL_OPTIONS），
// 我们只能动自己那一个文件。
func TestEnvRestoreBringsBackExactContent(t *testing.T) {
	path := fakeEnvHome(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := "JAVA_TOOL_OPTIONS=-Dfoo=bar\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	snap, err := CaptureEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Existed || snap.Content != original {
		t.Fatalf("快照不对: %+v", snap)
	}
	if err := (envBackend{}).Apply(context.Background(), &rec{}, Config{Enable: true, Backend: BackendEnv}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got == original {
		t.Fatal("启用后不该还是原内容")
	}
	if err := RestoreEnv(snap); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != original {
		t.Errorf("还原后内容不对:\n得到 %q\n期望 %q", got, original)
	}
}

// TestEnvReadReportsBackendAndLimits 没开过也算"支持"——
// 界面上「不支持」与「没开」必须是两回事。
func TestEnvReadReportsBackendAndLimits(t *testing.T) {
	fakeEnvHome(t)
	b := envBackend{}
	st, err := b.Read(context.Background(), &rec{})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Supported || st.Enabled || st.Mode != "None" {
		t.Fatalf("没开过时的读数不对: %+v", st)
	}
	if st.Backend != BackendEnv {
		t.Errorf("backend = %q", st.Backend)
	}
	// 覆盖不到的地方必须写在状态里。把"只对新进程有效"显示成"已开启"，
	// 用户只会得出"这个代理有 bug"的结论。
	if st.Note == "" {
		t.Error("应当说明覆盖范围，否则界面上「已开启」是误导")
	}

	if err := b.Apply(context.Background(), &rec{}, Config{
		Enable: true, Backend: BackendEnv, HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891",
	}); err != nil {
		t.Fatal(err)
	}
	st, err = b.Read(context.Background(), &rec{})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || st.HTTP != "127.0.0.1:7892" || st.SOCKS != "127.0.0.1:7891" {
		t.Fatalf("开着的读数不对: %+v", st)
	}
	if len(st.Ignored) == 0 || st.Ignored[0] != "localhost" {
		t.Errorf("no_proxy 没解析出来: %v", st.Ignored)
	}
	if st.Path == "" {
		t.Error("没告诉用户文件在哪")
	}
}

// TestEnvReadSeesHandEdits 读数要报文件里**当前的**内容。
//
// 用户手工改过这个文件时，界面上显示的必须是"现在真的生效的是什么"，
// 而不是"我们上次写了什么"。
func TestEnvReadSeesHandEdits(t *testing.T) {
	path := fakeEnvHome(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("http_proxy=http://other.example:3128\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := (envBackend{}).Read(context.Background(), &rec{})
	if err != nil {
		t.Fatal(err)
	}
	if st.HTTP != "other.example:3128" {
		t.Errorf("读到的是 %q，期望文件里当前的 other.example:3128", st.HTTP)
	}
}

// ------------------------------------------------------------------ 记账

// TestLedgerKeepsBackendAcrossRestores 记账里必须记着用的是哪条路。
//
// 还原时若靠"重新探测"来选后端，用户中途卸载了桌面就会还原到另一条路上，
// 原来的设置留在那儿再也回不来——而程序会报告"还原成功"。
func TestLedgerKeepsBackendAcrossRestores(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))

	if err := Enable(context.Background(), &rec{}, sp, Config{
		Enable: true, Backend: BackendEnv, HTTPAddr: "127.0.0.1:7892",
	}); err != nil {
		t.Fatal(err)
	}
	st := loadSaved(t, sp)
	if st.Backend != BackendEnv {
		t.Fatalf("记账里没有后端名: %+v", st)
	}
	if st.Env == nil || st.Env.Existed != false {
		t.Fatalf("env 快照不对: %+v", st.Env)
	}
	// 还原时即便环境完全变了（比如 gsettings 现在能用了），也必须走记账里那条路。
	r := &rec{}
	if err := Restore(context.Background(), r, sp); err != nil {
		t.Fatal(err)
	}
	if len(r.ran) != 0 {
		t.Errorf("env 记账的还原不该碰 gsettings: %v", r.ran)
	}
	if _, err := os.Stat(resolvePath(desktopHome(), envProxyFile)); !os.IsNotExist(err) {
		t.Errorf("还原后 environment.d 文件应当被删掉，实际 err=%v", err)
	}
}

// TestLedgerRestoresKDEGroupBackwards 同一件事在 KDE 上：还原贴回原文。
func TestLedgerRestoresKDEGroupBackwards(t *testing.T) {
	path := fakeEnvHome(t) // 同样只是要一个假家目录
	kiosk := filepath.Join(filepath.Dir(filepath.Dir(path)), "kioslaverc")
	if err := os.MkdirAll(filepath.Dir(kiosk), 0o700); err != nil {
		t.Fatal(err)
	}
	original := "[Proxy Settings]\n\t# 我的\n\tProxyType=Manual\n\thttpProxy=http://mine.example:3128\n"
	if err := os.WriteFile(kiosk, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))

	if err := Enable(context.Background(), &rec{}, sp, Config{
		Enable: true, Backend: BackendKDE, HTTPAddr: "127.0.0.1:7892",
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readFile(t, kiosk), "mine.example") {
		t.Fatal("启用后旧段应当被替换")
	}
	if err := Restore(context.Background(), &rec{}, sp); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, kiosk); got != original {
		t.Errorf("还原后与原文不一致:\n得到 %q\n期望 %q", got, original)
	}
}

// TestLedgerMissingSnapshotIsReported 而不是静默跳过。
//
// 快照丢了却报告"还原成功"，用户会以为桌面恢复了，实际上我们什么都没做。
func TestLedgerMissingSnapshotIsReported(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	if err := writeState(sp, saved{PID: 0, Backend: BackendKDE}); err != nil {
		t.Fatal(err)
	}
	if err := Restore(context.Background(), &rec{}, sp); err == nil {
		t.Fatal("快照缺失时必须报错，不能假装还原成功")
	}
}

// TestLedgerTreatsMissingBackendAsGNOME 老版本的状态文件没有后端名，
// 那时只有 GNOME 一条路，按它还原才不会把用户的桌面设置丢掉。
func TestLedgerTreatsMissingBackendAsGNOME(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	if err := writeState(sp, saved{PID: 0, Mode: "manual", HTTP: "10.0.0.9:8118"}); err != nil {
		t.Fatal(err)
	}
	r := manualRec()
	if err := Restore(context.Background(), r, sp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.ran, "\n"), "mode 'manual'") {
		t.Errorf("老记账没按 GNOME 还原: %v", r.ran)
	}
}

// TestEnableRefusesToStackTwoBackends 记账还在、又要换一条后端启用时必须拒绝。
//
// 否则两条后端同时生效：桌面指向其中一个、环境变量指向另一个，
// 用户看到的是「浏览器走代理、终端不走」这种互相打架的现场；
// 而关掉时只能还原记账里那一条，另一条就永久留在系统里了。
func TestEnableRefusesToStackTwoBackends(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))

	if err := Enable(context.Background(), &rec{}, sp, Config{
		Enable: true, Backend: BackendEnv, HTTPAddr: "127.0.0.1:7892",
	}); err != nil {
		t.Fatalf("第一次 Enable: %v", err)
	}

	r := &rec{}
	err := Enable(context.Background(), r, sp, Config{Enable: true, Backend: BackendGNOME})
	if err == nil {
		t.Fatal("记账还在时换后端启用应当被拒绝")
	}
	if !strings.Contains(err.Error(), BackendEnv) {
		t.Errorf("错误里应说明上一次是哪个后端: %v", err)
	}
	if len(r.ran) != 0 {
		t.Errorf("拒绝时不该下发任何命令: %v", r.ran)
	}
	// 记账不能被这次失败的启用改写，否则真正的还原路径就丢了。
	if st := loadSaved(t, sp); st.Backend != BackendEnv {
		t.Errorf("记账被失败的启用改成了 %q", st.Backend)
	}

	// 同一条后端重复启用是允许的（面板连点两下、切模式后重置都可能走到）。
	if err := Enable(context.Background(), &rec{}, sp, Config{
		Enable: true, Backend: BackendEnv, HTTPAddr: "127.0.0.1:7892",
	}); err != nil {
		t.Errorf("同一条后端重复启用不该被拒: %v", err)
	}
}

// TestEnableRefusesStackUnderAuto auto 不能成为绕过检查的后门：
// 上一次是 env，这次配 auto，而探测落到 gnome，同样是两条后端同时生效。
func TestEnableRefusesStackUnderAuto(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))

	if err := Enable(context.Background(), &rec{}, sp, Config{
		Enable: true, Backend: BackendEnv, HTTPAddr: "127.0.0.1:7892",
	}); err != nil {
		t.Fatalf("第一次 Enable: %v", err)
	}
	r := &rec{} // gsettings 探测通过，于是 auto 落在 gnome 上
	if err := Enable(context.Background(), r, sp, Config{
		Enable: true, Backend: BackendAuto, HTTPAddr: "127.0.0.1:7892",
	}); err == nil {
		t.Fatal("auto 解析到另一条后端时也应当被拒绝")
	}
	if len(r.ran) != 1 || !strings.Contains(r.ran[0], "--version") {
		t.Errorf("只应探测，不该下发设置: %v", r.ran)
	}
	// 关掉之后照旧还原 env 那一条：auto 不该把还原路由带偏。
	if err := Disable(context.Background(), &rec{}, sp, BackendAuto); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if _, err := os.Stat(resolvePath(desktopHome(), envProxyFile)); !os.IsNotExist(err) {
		t.Errorf("还原后 environment.d 文件应当被删掉，实际 err=%v", err)
	}
}

// TestEnvEnableOverOwnValuesRemovesFile env 版本：文件内容本来就等于我们要写的，
// 还原它等于关掉之后还指着我们的端口。
func TestEnvEnableOverOwnValuesRemovesFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := resolvePath(desktopHome(), envProxyFile)
	cfg := Config{
		Enable: true, Backend: BackendEnv,
		HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891",
	}
	if err := (envBackend{}).Apply(context.Background(), &rec{}, cfg); err != nil {
		t.Fatalf("铺垫: %v", err)
	}
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))
	if err := Enable(context.Background(), &rec{}, sp, cfg); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if st := loadSaved(t, sp); !st.AlreadyOurs {
		t.Fatal("文件内容等于要写的那份时应记为 AlreadyOurs")
	}
	if err := Disable(context.Background(), &rec{}, sp, BackendEnv); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("关掉后文件应被删掉，实际 err=%v", err)
	}
}

// TestEnvEnableOverForeignFileKeepsContent 用户自己写的变量文件要原样还回去，
// 哪怕里面也有一对 *_proxy。
func TestEnvEnableOverForeignFileKeepsContent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := resolvePath(desktopHome(), envProxyFile)
	original := "http_proxy=http://proxy.corp.example:3128\nHTTPS_PROXY=http://proxy.corp.example:3128\n"
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))
	if err := Enable(context.Background(), &rec{}, sp, Config{
		Enable: true, Backend: BackendEnv,
		HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891",
	}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if st := loadSaved(t, sp); st.AlreadyOurs {
		t.Fatal("用户自己的代理不是我们的值，不该记成 AlreadyOurs")
	}
	if err := Disable(context.Background(), &rec{}, sp, BackendEnv); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("还原后文件应当还在: %v", err)
	}
	if string(raw) != original {
		t.Errorf("没原样还原:\n得到 %q\n期望 %q", raw, original)
	}
}
