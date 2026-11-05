// 「停止/启动代理」与桌面系统代理的联动。
//
// 这一组用例讲的是同一件事：用户点「停止代理」要的是"流量不走代理了"，
// 而不是"这台机器上不了网"。端口一关，桌面上留在 mode=manual 的那根指针
// 就变成全机应用的死路，而它们只会报一句「代理连接被拒绝」。
//
// 所以这些用例必须能真的调 Stop/Close——为此整个包的系统代理后端在 TestMain
// 里换成假的（见 fakeGsettings）：测试配置的入站端口和线上面板是同一组，
// 不换成假的，一次 go test 就把跑测试这台机器的桌面代理改掉了。
package ui

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"wps_app/internal/sysproxy"
)

// TestMain 给整个包装上一个默认假桌面。
//
// 这条不是可选的装饰，有两层：
//
//  1. Close 现在会动桌面设置，而这个包里一批既有用例用 sampleCfg
//     （入站就是 7891/7892）建 App 又 Close 它。不默认换假的，
//     一句 `go test ./internal/ui` 就把跑测试那个人桌面的代理改成 none。
//  2. HOME 也换一个临时目录：kde 与 env 两条后端**不经 Runner**，
//     直接读写家目录里的文件，而 Detect 是 gnome 探测失败就退到 kde。
//     假桌面哪天答不上来，写掉的就是真人 ~/.config/kioslaverc——
//     这套用例第一版就是这么把那个文件凭空造出来的。
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "wps-ui-home-*")
	if err != nil {
		panic(err)
	}
	oldHome, hadHome := os.Getenv("HOME"), os.Getenv("HOME") != ""
	os.Setenv("HOME", filepath.Join(home, "isolated"))
	prev := sysxRunner
	sysxRunner = newDesktop("none", "127.0.0.1:7892", "127.0.0.1:7891")
	code := m.Run()
	sysxRunner = prev
	if hadHome {
		os.Setenv("HOME", oldHome)
	} else {
		_ = os.Unsetenv("HOME")
	}
	_ = os.RemoveAll(home)
	os.Exit(code)
}

// fakeGsettings 是一个只认 gsettings 的假桌面读数。
//
// 只实现 GNOME 这一条后端就够：Detect 的偏好顺序是 gnome → kde → env，
// `gsettings --version` 一答成功就轮不到后两条。
type fakeGsettings struct {
	mu   sync.Mutex
	vals map[string]string // "schema/key" → gsettings get 的原始输出
	sets []string          // 依次收到过的写入，形如 "schema/key=值"
	// onMode 在每次写 mode 的那一刻回调，用来检查"指针拔掉时端口还在不在"。
	onMode func(mode string)
	// probeFails 用来模拟这台机器根本没有 gsettings（无桌面/CI/总线挂了）。
	probeFails bool
	// writesGoNowhere 模拟「命令返回成功，写却没落到桌面」：
	// gsettings 写进 dconf 影子库时就是这样——退出码 0，读回来的还是原值。
	writesGoNowhere bool
	// readsFail 模拟「读命令本身失败」：D-Bus 卡住、dconf 服务不可达、后端超时。
	// 与"读到了但值是 none"必须分得开：前者什么都不能断定，因此不能撤账。
	readsFail bool
}

func newDesktop(mode, httpAddr, socksAddr string) *fakeGsettings {
	f := &fakeGsettings{vals: map[string]string{}}
	f.put(schema, "mode", quote(mode))
	for _, pair := range [][2]string{
		{schemaHTTP, httpAddr},
		{schemaHTTPS, httpAddr},
		{schemaSOCKS, socksAddr},
	} {
		host, port, _ := strings.Cut(pair[1], ":")
		f.put(pair[0], "host", quote(host))
		f.put(pair[0], "port", port)
	}
	f.put(schema, "ignore-hosts", "['localhost', '127.0.0.0/8']")
	return f
}

func (f *fakeGsettings) put(schema, key, raw string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.vals == nil {
		f.vals = map[string]string{}
	}
	f.vals[schema+"/"+key] = raw
}

// modeNow / httpNow / socksNow 是"桌面上现在写着什么"，测试拿它们断言。
func (f *fakeGsettings) modeNow() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return unq(f.vals[schema+"/mode"])
}

func (f *fakeGsettings) addrNow(s string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return unq(f.vals[s+"/host"]) + ":" + f.vals[s+"/port"]
}

func (f *fakeGsettings) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sets...)
}

const (
	schema      = "org.gnome.system.proxy"
	schemaHTTP  = "org.gnome.system.proxy.http"
	schemaHTTPS = "org.gnome.system.proxy.https"
	schemaSOCKS = "org.gnome.system.proxy.socks"
)

func quote(s string) string { return "'" + s + "'" }

// unq 剥掉读数外面那层引号，与 sysproxy.unquote 同义（那边没导出）。
//
// 两种都要认：`gsettings get` 回话用单引号，而写入时我们递过去的是
// GVariant 的双引号字面量——假桌面把后者原样存下来，比对时就得两种都脱。
func unq(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func (f *fakeGsettings) Run(_ context.Context, args, _ []string) (string, error) {
	i := -1
	for n := range args {
		if args[n] == "gsettings" {
			i = n
			break
		}
	}
	if i < 0 || i+1 >= len(args) {
		return "", fmt.Errorf("假桌面只认 gsettings，收到 %v", args)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch args[i+1] {
	case "--version":
		if f.probeFails {
			return "", fmt.Errorf("gsettings 不可用（假桌面）")
		}
		return "2.74.0", nil
	case "get":
		if i+3 >= len(args) {
			return "", fmt.Errorf("假桌面的 get 参数不全: %v", args)
		}
		if f.readsFail {
			// 模拟 D-Bus 卡住 / 后端超时：命令本身失败，桌面什么都没答。
			// 这一档与"读到了但值是 none"必须分得开——前者什么都不能断定。
			return "", fmt.Errorf("Failed to communicate with dconf service（假桌面）")
		}
		v, ok := f.vals[args[i+2]+"/"+args[i+3]]
		if !ok {
			return "", fmt.Errorf("schema %s 没有键 %s", args[i+2], args[i+3])
		}
		return v, nil
	case "set":
		if i+4 >= len(args) {
			return "", fmt.Errorf("假桌面的 set 参数不全: %v", args)
		}
		key := args[i+2] + "/" + args[i+3]
		val := args[i+4]
		f.sets = append(f.sets, key+"="+val)
		if !f.writesGoNowhere {
			f.vals[key] = val
		}
		if key == schema+"/mode" && f.onMode != nil {
			f.onMode(unq(val))
		}
		return "", nil
	}
	return "", fmt.Errorf("假桌面不认识 %q", args[i+1])
}

// useDesktop 给这个用例换一份全新的假桌面，用例结束自动摘掉。
func useDesktop(t *testing.T, mode, httpAddr, socksAddr string) *fakeGsettings {
	t.Helper()
	f := newDesktop(mode, httpAddr, socksAddr)
	prev := sysxRunner
	sysxRunner = f
	t.Cleanup(func() { sysxRunner = prev })
	return f
}

// requireGnomeFake 确认探测真的落在假桌面上。
//
// 落在 kde / env 上意味着假桌面没接住这条命令，而那两条后端是**直接写家目录文件**的：
// 用例从此就在改跑测试这台真机器，还一句错都不报。
func requireGnomeFake(t *testing.T, app *App) {
	t.Helper()
	if st := app.SystemProxyStatus(); st.Backend != "gnome" {
		t.Fatalf("系统代理后端不是假桌面（gnome），实得 %q：这条用例会写到真机器上", st.Backend)
	}
}

// stopTestCfg 写一份能真的 Start 的配置：入站换成 17891/17892（不撞线上面板那组），
// 服务端用 IP 字面量（免得整套用例被这台机器此刻能不能解析绑住）。
func stopTestCfg(t *testing.T) (path, httpAddr, socksAddr string) {
	t.Helper()
	httpAddr, socksAddr = "127.0.0.1:17892", "127.0.0.1:17891"
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rules, []byte("DOMAIN-SUFFIX,example.com,DIRECT\nFINAL,PROXY\n"), 0o600); err != nil {
		t.Fatalf("写规则: %v", err)
	}
	body := strings.Replace(sampleCfg, "127.0.0.1:7891", socksAddr, 1)
	body = strings.Replace(body, "127.0.0.1:7892", httpAddr, 1)
	body = strings.Replace(body, `addr: "example.com:443"`, `addr: "127.0.0.1:4433"`, 1)
	body = strings.Replace(body, `"./assets/rules.txt"`, `"`+rules+`"`, 1)
	path = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	return path, httpAddr, socksAddr
}

// TestStopClosesPointerThenStartRestoresIt 是用户报的那个现场：
// 停止代理之后桌面还指着刚关掉的端口，于是"停止"看起来等于"断网"。
func TestStopClosesPointerThenStartRestoresIt(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "manual", httpAddr, socksAddr)

	app := New(path)
	defer func() { _ = app.Close() }()
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	requireGnomeFake(t, app)
	if err := app.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got := f.modeNow(); got != "none" {
		t.Fatalf("停止后桌面应切到 none，实际 %q（这就是用户看到的\"断网\"）", got)
	}
	if _, err := os.Stat(sysproxy.StatePath(path)); !os.IsNotExist(err) {
		t.Fatal("本来没有记账，停止也不该凭空造一份")
	}

	// 再启动：用户的手势是"回到走代理"，不该要求他再去点一次开关。
	if err := app.Start(); err != nil {
		t.Fatalf("二次 Start: %v", err)
	}
	if got := f.modeNow(); got != "manual" {
		t.Fatalf("重新启动后桌面应回到 manual，实际 %q", got)
	}
	if got := f.addrNow(schemaHTTP); got != httpAddr {
		t.Fatalf("重新启动后 http 指针应指回 %s，实际 %s", httpAddr, got)
	}
}

// TestStopDropsPointerWhilePortStillAlive 断的是顺序：拔指针必须发生在关端口之前。
// 反过来就留出一个"manual 指着一个正在被关闭的端口"的窗口，
// 而那个窗口里所有应用报的都是「代理连接被拒绝」。
func TestStopDropsPointerWhilePortStillAlive(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "manual", httpAddr, socksAddr)
	var aliveAtNone bool
	f.onMode = func(mode string) {
		if mode != "none" {
			return
		}
		c, err := net.Dial("tcp", httpAddr)
		if err == nil {
			_ = c.Close()
		}
		aliveAtNone = err == nil
	}

	app := New(path)
	defer func() { _ = app.Close() }()
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	requireGnomeFake(t, app)
	if err := app.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !aliveAtNone {
		t.Fatal("写 mode=none 那一刻入站端口已经关了：顺序反了，会有一段时间全机连不上代理")
	}
}

// TestStopLeavesForeignProxyAlone 守住另一头：桌面上那组设置不是我们写的就不该动。
// 用户可能自己配了另一个代理，停止我们的代理没有权利替他把指针改掉。
func TestStopLeavesForeignProxyAlone(t *testing.T) {
	path, _, _ := stopTestCfg(t)
	f := useDesktop(t, "manual", "127.0.0.1:8118", "127.0.0.1:8119")

	app := New(path)
	defer func() { _ = app.Close() }()
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	requireGnomeFake(t, app)
	if err := app.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("别人的代理设置一个字都不该写，实际写了 %v", w)
	}
	if got := f.addrNow(schemaHTTP); got != "127.0.0.1:8118" {
		t.Fatalf("桌面应保持用户自己的 8118，实际 %s", got)
	}
}

// TestCloseRestoresFromLedger 是"有记账"那一路退出：还原成改动前的样子，并销账。
func TestCloseRestoresFromLedger(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "none", httpAddr, socksAddr)

	app := New(path)
	// Close 是幂等的；挂这个 cleanup 是为了断言失败时也别把 17891 占着不放——
	// 漏一次，后面每一条用例会全部以"端口已被占用"红掉，看不出真正红的那一条。
	t.Cleanup(func() { _ = app.Close() })
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	requireGnomeFake(t, app)
	if err := app.SetSystemProxy(true); err != nil {
		t.Fatalf("开启系统代理: %v", err)
	}
	if got := f.modeNow(); got != "manual" {
		t.Fatalf("开关应把桌面写成 manual，实际 %q", got)
	}
	statePath := sysproxy.StatePath(path)
	if _, err := os.Stat(statePath); err != nil {
		t.Fatalf("开关应留下记账: %v", err)
	}
	if err := app.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := f.modeNow(); got != "none" {
		t.Fatalf("退出应按记账还回 none，实际 %q", got)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("退出还原后记账应一起销掉，留着会让下一个实例再还一次")
	}
}

// TestCloseKillsOrphanPointer 是这台机器现在的样子：桌面指着我们，记账却没了。
// 光靠"按记账还原"救不了它——没有账可还原。退出时必须兜底关掉，
// 否则接管重启的那一刻（以及每一次面板消失）就是全机断网。
func TestCloseKillsOrphanPointer(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "manual", httpAddr, socksAddr)

	app := New(path)
	t.Cleanup(func() { _ = app.Close() })
	requireGnomeFake(t, app)
	// 不调 Start：新的 Start 看到桌面指着我们会主动补记账；这条用例要的是
	// 「指针在、账没了」的孤儿现场，Start 会把现场破坏掉。
	if _, err := os.Stat(sysproxy.StatePath(path)); err == nil {
		t.Fatal("这条用例要的就是没有记账")
	}
	if err := app.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := f.modeNow(); got != "none" {
		t.Fatalf("没有记账但桌面指着本程序时，退出必须兜底切到 none，实际 %q", got)
	}
}

// TestStopWithoutDesktopBackend 保证没有桌面手段的机器（无 GUI 会话、CI）
// 不会因为这套联动而停止失败：读不到桌面就当不归我们管。
//
// HOME 也要空掉：kde 与 env 两条后端的探测不看 Runner，只看有没有家目录，
// 留着真 HOME 它们就"成功"了，这条用例于是变成往真家目录写文件。
func TestStopWithoutDesktopBackend(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "manual", httpAddr, socksAddr)
	f.probeFails = true
	t.Setenv("HOME", "")

	app := New(path)
	defer func() { _ = app.Close() }()
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := app.Stop(); err != nil {
		t.Fatalf("没有桌面后端时停止应照常成功: %v", err)
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("探测都失败了还写什么桌面: %v", w)
	}
}

// TestRestartKeepsPointerAndPutsItOnRealPorts 覆盖改配置那条路：
// 重启期间不该把桌面切成 none（那会把"直连"闪出来骗人），
// 起来之后指针要对准实际绑上的端口。
func TestRestartKeepsPointerAndPutsItOnRealPorts(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "manual", httpAddr, socksAddr)

	app := New(path)
	defer func() { _ = app.Close() }()
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	requireGnomeFake(t, app)
	if err := app.Restart(); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	for _, w := range f.writes() {
		if w == schema+"/mode='none'" {
			t.Fatal("重启不该把桌面代理闪成 none")
		}
	}
	if got := f.modeNow(); got != "manual" {
		t.Fatalf("重启后桌面应仍是 manual，实际 %q", got)
	}
	if got := f.addrNow(schemaHTTP); got != httpAddr {
		t.Fatalf("重启后指针应指向实际入站 %s，实际 %s", httpAddr, got)
	}
}

// TestSystemProxySwitchStartsAndStopsService 钉住 2026-11-02 的硬联动：
// 系统代理开关是总开关——开要先把服务拉起来，关要把服务一起停掉。
// 否则用户点「系统代理关闭」后顶栏还写着「运行中」，看起来像开关坏了。
func TestSystemProxySwitchStartsAndStopsService(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "none", httpAddr, socksAddr)

	app := New(path)
	defer func() { _ = app.Close() }()
	requireGnomeFake(t, app)
	if app.Status().Running {
		t.Fatal("刚建的 App 不该已经在跑")
	}

	if err := app.SetSystemProxy(true); err != nil {
		t.Fatalf("打开总开关: %v", err)
	}
	if !app.Status().Running {
		t.Fatal("打开系统代理后代理服务没有启动")
	}
	if got := f.modeNow(); got != "manual" {
		t.Fatalf("打开总开关后桌面应是 manual，实际 %q", got)
	}
	if got := f.addrNow(schemaHTTP); got != httpAddr {
		t.Fatalf("桌面 HTTP 指针 = %s, want %s", got, httpAddr)
	}

	if err := app.SetSystemProxy(false); err != nil {
		t.Fatalf("关闭总开关: %v", err)
	}
	if app.Status().Running {
		t.Fatal("关闭系统代理后代理服务还在跑：这就是用户报的“上面的还没停止”")
	}
	if got := f.modeNow(); got != "none" {
		t.Fatalf("关闭总开关后桌面应恢复 none，实际 %q", got)
	}
}

func writeIntentForTest(t *testing.T, path string, on bool) {
	t.Helper()
	body := "off\n"
	if on {
		body = "on\n"
	}
	if err := os.WriteFile(sysProxyIntentPath(path), []byte(body), 0o600); err != nil {
		t.Fatalf("写总开关状态: %v", err)
	}
}

// TestStartupOffIntentStaysStopped：上次总开关是关的，启动时服务和桌面都不动。
// 这是 2026-11-02 用户看到的「顶栏运行中、系统代理关闭」的另一半：
// 持久化之后，关着启动就应该两个都关，而不是偷偷起服务。
func TestStartupOffIntentStaysStopped(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "none", httpAddr, socksAddr)
	writeIntentForTest(t, path, false)

	app := New(path)
	t.Cleanup(func() { _ = app.Close() })
	if err := app.Startup(); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if app.Status().Running {
		t.Fatal("总开关为关，启动时不该自动起服务")
	}
	if got := f.modeNow(); got != "none" {
		t.Fatalf("总开关为关，桌面应保持 none，实际 %q", got)
	}
}

// TestStartupOnIntentStartsAndEnables：上次是开的，启动后服务和系统代理都应打开。
func TestStartupOnIntentStartsAndEnables(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "none", httpAddr, socksAddr)
	writeIntentForTest(t, path, true)

	app := New(path)
	t.Cleanup(func() { _ = app.Close() })
	requireGnomeFake(t, app)
	if err := app.Startup(); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if !app.Status().Running {
		t.Fatal("总开关为开，启动时服务没起来")
	}
	if got := f.modeNow(); got != "manual" {
		t.Fatalf("总开关为开，桌面应是 manual，实际 %q", got)
	}
	if got := f.addrNow(schemaHTTP); got != httpAddr {
		t.Fatalf("桌面 HTTP 指针 = %s, want %s", got, httpAddr)
	}
	if got := readSysProxyIntent(path); got != sysProxyIntentOn {
		t.Fatalf("启动后状态文件应保持 on，实际 %v", got)
	}
}

// TestStartupWithoutIntentStaysStopped：旧版本没有状态文件时按关处理，
// 不擅自改桌面；桌面已经指着我们的孤儿指针则顺手收掉。
func TestStartupWithoutIntentStaysStopped(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "manual", httpAddr, socksAddr)

	app := New(path)
	t.Cleanup(func() { _ = app.Close() })
	requireGnomeFake(t, app)
	if err := app.Startup(); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if app.Status().Running {
		t.Fatal("没有总开关状态时不该自动起服务")
	}
	if got := f.modeNow(); got != "none" {
		t.Fatalf("孤儿桌面指针应被收掉，实际 %q", got)
	}
}

// TestSetSystemProxyPersistsIntent：总开关的两次操作都要落到状态文件。
func TestSetSystemProxyPersistsIntent(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	_ = useDesktop(t, "none", httpAddr, socksAddr)

	app := New(path)
	t.Cleanup(func() { _ = app.Close() })
	if err := app.SetSystemProxy(true); err != nil {
		t.Fatalf("打开总开关: %v", err)
	}
	if got := readSysProxyIntent(path); got != sysProxyIntentOn {
		t.Fatalf("打开后状态文件 = %v, want on", got)
	}
	if err := app.SetSystemProxy(false); err != nil {
		t.Fatalf("关闭总开关: %v", err)
	}
	if got := readSysProxyIntent(path); got != sysProxyIntentOff {
		t.Fatalf("关闭后状态文件 = %v, want off", got)
	}
}
