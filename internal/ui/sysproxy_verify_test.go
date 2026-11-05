// 「写成功」不等于「桌面真的被改了」。
//
// 2026-11-05 这台机器上的现场：面板以 root 跑，gsettings 是用
// `sudo -n -u <用户> gsettings` 发出去的，而 sudo 默认 env_reset 把
// DBUS_SESSION_BUS_ADDRESS 丢了。gsettings 于是拿不到桌面会话总线，
// 写进了 dconf 的兜底影子库 ~/.cache/dconf/user —— 退出码 0，桌面纹丝不动。
// 面板读回时读的是同一个影子库，读到 none，开关点开就自己弹回关闭，
// 而日志里只留一句"总开关开启"。
//
// 这里钉住面板那一半：桌面没被接管时，面板不许报成功，
// 也不许留下一份描述了"没发生的改动"的记账。
package ui

import (
	"os"
	"testing"

	"wps_app/internal/sysproxy"
)

// TestEnableFailsWhenDesktopDidNotChange 模拟"写成功但桌面没变"。
//
// 期望：开启报错（界面显示失败，而不是显示已开启再自己弹回关闭），
// 桌面读数不变，记账也不留——那份记账描述的是一次没发生的改动，
// 留着会让退出时的还原去动一个并不属于我们的设置。
func TestEnableFailsWhenDesktopDidNotChange(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "none", httpAddr, socksAddr)
	f.writesGoNowhere = true

	app := New(path)
	t.Cleanup(func() { _ = app.Close() })
	requireGnomeFake(t, app)
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := app.SetSystemProxy(true); err == nil {
		t.Fatal("桌面没被接管却报成功：界面上会显示已开启，下一次读回又是关闭")
	}
	if got := f.modeNow(); got != "none" {
		t.Fatalf("桌面没被接管，mode 不该变，实际 %q", got)
	}
	if _, statErr := os.Stat(sysproxy.StatePath(path)); !os.IsNotExist(statErr) {
		t.Fatal("没落到桌面的改动不该留下记账：退出时会去还原一个并不属于我们的设置")
	}
}

// TestEnableKeepsLedgerWhenReadBackFails 锁住「读不到 ≠ 没生效」。
//
// 这一档是上一条的反面，而两者的正确动作完全相反：
//
//	读到了、值是 none  -> 写入确实没生效，撤账（上一条）。
//	**一次都读不到**   -> 什么都不知道，保留记账。
//
// 记账是退出时唯一能还原桌面的依据。因为一次 D-Bus 抖动把它删掉，
// 桌面就永久指着本客户端；进程一退，全机应用只会报「代理连接被拒绝」，
// 而面板日志里连一句"我删了账"都没有。
func TestEnableKeepsLedgerWhenReadBackFails(t *testing.T) {
	path, httpAddr, socksAddr := stopTestCfg(t)
	f := useDesktop(t, "none", httpAddr, socksAddr)

	app := New(path)
	t.Cleanup(func() { _ = app.Close() })
	requireGnomeFake(t, app)
	if err := app.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// 写入生效（假桌面照常存），但**写入之后**所有读命令都失败。
	// 时机必须精确：Enable 动手前会先读一次原值（读不到就放弃改动，
	// 那是正确的安全行为），所以不能在 Start 之后就把读打死。
	f.onMode = func(mode string) {
		if mode == "manual" {
			f.readsFail = true
		}
	}

	if err := app.SetSystemProxy(true); err != nil {
		t.Fatalf("读回失败不该判成开启失败（设置已经写进去了）: %v", err)
	}
	if _, statErr := os.Stat(sysproxy.StatePath(path)); statErr != nil {
		t.Fatalf("读不回来的时候记账被删了：退出时再也认不出桌面正指着我们 (%v)", statErr)
	}
	if got := f.modeNow(); got != "manual" {
		t.Fatalf("写入本身应当已经落到桌面，mode 实际 %q", got)
	}
	// 界面要能说出"已写入、尚未确认"这一档，而不是含糊地说已开启。
	if d := app.sysProxyUnverifiedDetail(); d == "" {
		t.Fatal("没有记下「设置了但读不回」这个状态，界面上只会显示已开启")
	}

	// 读恢复之后，那条提示应当自己消失（不必重启）。
	f.readsFail = false
	st := app.SystemProxyStatus()
	if st.Error != "" {
		t.Fatalf("读恢复后仍报错: %s", st.Error)
	}
	if d := app.sysProxyUnverifiedDetail(); d != "" {
		t.Fatalf("读恢复后仍留着未确认提示: %s", d)
	}
}
