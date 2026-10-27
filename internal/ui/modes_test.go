package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wps_app/internal/config"
	"wps_app/internal/service"
)

// TestAppProfileBindings 走的是界面上「节点与模式」页真正会调的那组方法：
// 新增 → 列表 → 选中 → 改名 → 删除。绑定层只该做转发与掩码，不该有自己的逻辑分支。
func TestAppProfileBindings(t *testing.T) {
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()

	list, err := app.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Profiles) != 1 || list.Active != "example.com" || list.Mode != "rule" {
		t.Fatalf("初始列表不对: %+v", list)
	}

	if err := app.AddProfile(service.ProfileSpec{
		Name: "新加坡", Addr: "sg.example.com:443", Auth: "sg-key", BandwidthUp: "100 mbps",
	}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	if err := app.AddProfile(service.ProfileSpec{Name: "新加坡", Addr: "x:443", Auth: "y"}); err == nil {
		t.Error("重名应被拒绝")
	}

	list, err = app.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Profiles) != 2 || list.Profiles[1].Name != "新加坡" || !list.Profiles[1].AuthSet {
		t.Fatalf("新增没进列表: %+v", list.Profiles)
	}
	if list.Active != "example.com" {
		t.Errorf("新增不该改变选中项: %q", list.Active)
	}

	if err := app.SetActiveProfile("新加坡"); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}
	list, _ = app.Profiles()
	if list.Active != "新加坡" {
		t.Fatalf("切换没生效: %q", list.Active)
	}

	if err := app.UpdateProfile("新加坡", service.ProfileSpec{Name: "SG-1", Addr: "sg2.example.com:443"}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	list, _ = app.Profiles()
	if list.Active != "SG-1" || list.Profiles[1].Addr != "sg2.example.com:443" {
		t.Fatalf("改名/改址没生效: %+v", list)
	}

	if err := app.RemoveProfile("SG-1"); err != nil {
		t.Fatalf("RemoveProfile: %v", err)
	}
	list, _ = app.Profiles()
	if len(list.Profiles) != 1 || list.Active != "example.com" {
		t.Fatalf("删除后没回落到剩下的节点: %+v", list)
	}
	if err := app.RemoveProfile("example.com"); err == nil {
		t.Error("最后一个节点不该能删")
	}
}

// TestAppModeBinding 界面切模式必须立刻反映到快照里（不重启进程）。
func TestAppModeBinding(t *testing.T) {
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()

	for _, m := range []string{"global", "direct", "rule"} {
		if err := app.SetMode(m); err != nil {
			t.Fatalf("SetMode(%s): %v", m, err)
		}
		list, err := app.Profiles()
		if err != nil {
			t.Fatal(err)
		}
		if list.Mode != m {
			t.Errorf("Profiles().Mode = %q, 期望 %q", list.Mode, m)
		}
		if snap := app.Status(); snap.Mode != m {
			t.Errorf("Status().Mode = %q, 期望 %q", snap.Mode, m)
		}
	}
	if err := app.SetMode("bogus"); err == nil {
		t.Error("非法模式应报错")
	}
}

// TestAppTUNBindings 未运行时的 TUN 状态也要把配置意图说清楚，
// 界面靠它渲染「将会用哪块网卡」。
func TestAppTUNBindings(t *testing.T) {
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()

	if err := app.SetTUNEnabled(true); err != nil {
		t.Fatalf("SetTUNEnabled: %v", err)
	}
	st := app.TUNStatus()
	if !st.Enabled || st.Device != "wps-tun" || st.FakeIPRange != "198.18.0.0/15" || !st.HijackDNS {
		t.Fatalf("TUN 状态不对: %+v", st)
	}
	if st.Running {
		t.Error("服务没跑，TUN 不该 running")
	}
	if snap := app.Status(); !snap.TUN.Enabled {
		t.Errorf("快照里的 TUN 没跟上: %+v", snap.TUN)
	}
	if err := app.SetTUNEnabled(false); err != nil {
		t.Fatal(err)
	}
	if app.TUNStatus().Enabled {
		t.Error("关闭后仍报启用")
	}
}

// TestAppTestProfile 界面上「测速」按钮：绑定层只该做转发，不该有自己的分支。
//
// 「节点拨不通要给出可读原因」这条真行为测在 service 包
// （TestTestProfileReportsFailure，那里节点地址用 IP 字面量，不碰 DNS）。
// 这里再拨一次既慢（生产语义就是 15s 预算耗尽才放弃）又重复，
// 所以只验两件不依赖网络的事：参数与结果元信息原样透传、未知节点那声「不存在」。
func TestAppTestProfile(t *testing.T) {
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()

	missing := app.TestProfile("不存在", "")
	if missing.OK || !strings.Contains(missing.Error, "不存在") {
		t.Errorf("未知节点应报不存在: %+v", missing)
	}
	if missing.Name != "不存在" {
		t.Errorf("结果元信息没透传回来: %+v", missing)
	}

	// 空 target 会被后端补成默认探测目标；这里只确认绑定没把名字吞掉。
	res := app.TestProfile("不存在的第二个", "")
	if res.Name != "不存在的第二个" {
		t.Errorf("绑定改掉了节点名: %+v", res)
	}
}

// TestAppReadConfigCarriesModeAndTUN 表单里必须带模式与 TUN 段，
// 否则「配置」页会把这两块显示成空。
func TestAppReadConfigCarriesModeAndTUN(t *testing.T) {
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()

	f, err := app.ReadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if f.Mode != string(config.ModeRule) || f.ActiveName != "example.com" || f.ActiveAddr != "example.com:443" {
		t.Fatalf("模式/当前节点没读出来: %+v", f)
	}
	if f.TUN.Device != "wps-tun" || f.TUN.Address != "172.19.0.1/30" || f.TUN.DNS != "172.19.0.2" ||
		f.TUN.FakeIPRange != "198.18.0.0/15" || !f.TUN.HijackDNS {
		t.Fatalf("TUN 段没读出来: %+v", f.TUN)
	}
}

// TestAppSystemProxyStatus 系统代理那一栏要能解释「开关为什么是灰的」，还要说清它读的是哪份。
//
// 这一条以前直接问本机桌面：开发机上 gsettings 通着就一路绿；换到没有会话总线的环境
// （比如只留回环的网络命名空间）就掉到 KDE 后端、读出 Mode 为空——红的不是被测代码，
// 而是它在猜"开发机长什么样"。现在家目录和 PATH 都由测试摆出来，两种结局都自己造。
func TestAppSystemProxyStatus(t *testing.T) {
	app := New(writeCfg(t, sampleCfg))
	defer func() { _ = app.Close() }()

	home := t.TempDir()
	t.Setenv("HOME", home)
	// 一个空目录当 PATH：gsettings 探不到，后端选择就落到"读文件"那一条，
	// 于是这台机器上有没有 GNOME 都影响不到结果。
	t.Setenv("PATH", t.TempDir())
	// 包级的假桌面（TestMain）也会让 GNOME 探测成功，这条用例要的是"没有 GNOME"，
	// 所以这里得把假桌面本身也调成探不到——它比 PATH 更靠前。
	desktop := useDesktop(t, "none", "127.0.0.1:7892", "127.0.0.1:7891")
	desktop.probeFails = true

	// 1) 家目录里什么都没有：支持（有家目录就管得了 kioslaverc），但没开启、也没模式。
	//    界面据此写"未开启"，而不是"读不到"——这两种状态对用户是两回事。
	st := app.SystemProxyStatus()
	if !st.Supported {
		t.Fatalf("有家目录就该支持 KDE 后端: %+v (error=%q)", st, st.Error)
	}
	if st.Enabled || st.Mode != "" {
		t.Fatalf("空家目录应读成「未配置」，实得 %+v", st)
	}
	if st.Backend != "kde" || !strings.Contains(st.Path, "kioslaverc") {
		t.Fatalf("读数没说明它来自哪个后端的哪份文件: %+v", st)
	}

	// 2) 写一份手动代理：每个字段都要照文件里的样子报上来。
	if err := os.MkdirAll(filepath.Join(home, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "[Proxy Settings]\n" +
		"ProxyType=Manual\n" +
		"httpProxy=http://127.0.0.1:7892\n" +
		"httpsProxy=https://127.0.0.1:7892\n" +
		"socksProxy=socks5://127.0.0.1:7891\n" +
		"NoProxyFor=localhost,127.0.0.0/8\n"
	if err := os.WriteFile(filepath.Join(home, ".config", "kioslaverc"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := app.SystemProxyStatus()
	if !got.Supported || !got.Enabled || got.Mode != "Manual" {
		t.Fatalf("手动代理没读出来: %+v", got)
	}
	if got.HTTP != "127.0.0.1:7892" || got.HTTPS != "127.0.0.1:7892" || got.SOCKS != "127.0.0.1:7891" {
		t.Fatalf("地址没被抹掉协议前缀: %+v", got)
	}
	if strings.Join(got.Ignored, ",") != "localhost,127.0.0.0/8" {
		t.Fatalf("绕过列表读错: %v", got.Ignored)
	}
	if got.Error != "" {
		t.Fatalf("读成功却带着错误: %q", got.Error)
	}
}

// TestAppSysProxyTargetUsesConfigPorts 面板那条路必须拿配置里的端口去比桌面读数。
//
// 用写死的默认端口的话，改了端口的配置会让「桌面明明指着我们」被判成「和我们无关」，
// 于是孤儿状态——本进程退出时不还原桌面、整机断网那一种——永远不报。
func TestAppSysProxyTargetUsesConfigPorts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir()) // 空 PATH：不碰真桌面，后端选择落到读文件那条
	body := strings.Replace(strings.Replace(sampleCfg,
		"127.0.0.1:7891", "127.0.0.1:1080", 1),
		"127.0.0.1:7892", "127.0.0.1:8118", 1) + "sysproxy:\n  backend: \"kde\"\n"
	app := New(writeCfg(t, body))
	defer func() { _ = app.Close() }()

	backend, http, socks := app.sysProxyTarget()
	if backend != "kde" {
		t.Errorf("backend = %q, 期望 kde", backend)
	}
	if http != "127.0.0.1:8118" || socks != "127.0.0.1:1080" {
		t.Errorf("端口没跟配置走: http=%q socks=%q", http, socks)
	}
	// sysProxyBackend 与它同源，两条路不该读出两个后端。
	if got := app.sysProxyBackend(); got != backend {
		t.Errorf("sysProxyBackend = %q, 与 sysProxyTarget 的 %q 不一致", got, backend)
	}
	// 空 HOME + 空 PATH 下桌面既没开着也没记账：那一行应是安静的"没有记账"。
	if v := app.SystemProxyLedger(); v.State != "none" {
		t.Errorf("这个环境里的记账读数应为 none, 实得 %q (%q)", v.State, v.Text)
	}
}

// TestAppSysProxyTargetSurvivesBadConfig 配置读不懂时不许 panic 或返回半成品：
// 三个值全空即可，sysproxy 会按本机默认入站兜底。
func TestAppSysProxyTargetSurvivesBadConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	app := New(writeCfg(t, "server:\n  addr: \"\"\n  auth: \"\"\ninbounds: []\n"))
	defer func() { _ = app.Close() }()
	backend, http, socks := app.sysProxyTarget()
	if backend != "" || http != "" || socks != "" {
		t.Errorf("配置没有这些项时应全空, 实得 %q %q %q", backend, http, socks)
	}
}
