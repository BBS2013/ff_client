//go:build gui

// tray.go 是系统托盘。Wails v2 没有内置托盘（v2.16.0 全库 SystemTray 零命中），
// 所以外接 fyne.io/systray：Linux 上它是纯 D-Bus 实现，不抢 GTK 主循环，
// 可以和 Wails 的窗口同进程共存。
package ui

import (
	"time"

	"fyne.io/systray"

	"wps_app/internal/appicon"
	"wps_app/internal/logx"
)

// RunTray 启动系统托盘并阻塞在事件循环里，onExit 返回后函数才返回。
//
// 调用方应当在自己的 goroutine 里跑它——systray.Run 是阻塞的，
// 而 Wails 的主循环必须留在当前 goroutine。
//
// showWindow 用于把隐藏的主窗口唤回来，shutdown 用于退出整个进程；
// 两者都由 gui.go 注入，托盘本身不关心 Wails 的存在。
func RunTray(app *App, showWindow, shutdown func()) {
	// fyne.io/systray v1.12.2 在「DBus 一开始就没连上」的情况下（root 进程连不上
	// 用户会话总线时就是这种状态），退出路径会拿着一个无效的 *Conn 调 Close()，
	// 直接 nil 解引用 panic。这个 panic 发生在托盘自己的 goroutine 里，会把整个进程
	// 一起带走——连带我们的 TUN 拆网卡与摘 iptables 收尾都不再执行，
	// 后果就是本机 DNS 整片挂掉，只能靠 -tun-reset 救回来。
	//
	// 这里吞掉它的退出 panic：托盘本来就已经不可用，让它安静地死掉，
	// 把收尾交回主 goroutine。
	defer func() {
		if r := recover(); r != nil {
			logx.Warnf("系统托盘退出时异常（已忽略，代理收尾继续走正常路径）: %v", r)
		}
	}()
	systray.Run(func() {
		systray.SetIcon(appicon.Tray())
		systray.SetTitle("wps_app")
		systray.SetTooltip("wps_app — 正在读取状态")

		// 状态行：禁用项，纯展示。托盘是"不开窗口也能看一眼"的那个界面，
		// 之前它连代理有没有在跑都不说，看一眼还得先把窗口调出来。
		mStatus := systray.AddMenuItem("正在读取状态…", "代理当前状态")
		mStatus.Disable()
		systray.AddSeparator()
		mShow := systray.AddMenuItem("显示控制面板", "打开主窗口")
		systray.AddSeparator()
		mStart := systray.AddMenuItem("启动代理", "开始监听 SOCKS5/HTTP 入站")
		mStop := systray.AddMenuItem("停止代理", "关闭全部入站监听")
		mReload := systray.AddMenuItem("重载规则", "重新载入 GeoIP 与规则集")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("退出", "停止代理并退出 wps_app")

		// 状态刷新与事件循环分开跑：文字怎么变都不影响点击通道。
		// 2s 一次是权衡后的值——再快对托盘没意义（它不是图表），
		// 再慢就会出现「刚按下启动，托盘还写着已停止」。
		go func() {
			t := time.NewTicker(2 * time.Second)
			defer t.Stop()
			var push trayPush
			for range t.C {
				now := time.Now()
				st := statusOf(app.Status(), app.svc.Metrics().BlockedTotal())
				// 只在文字真的变了时才推给通知器：状态行是分钟粒度，
				// 无条件推等于每 2 秒发一条内容相同的总线消息。
				dl, dt := push.changed(st.line(now), st.tooltip(now))
				if dl != "" {
					mStatus.SetTitle(dl)
				}
				if dt != "" {
					systray.SetTooltip(dt)
				}
			}
		}()

		go func() {
			for {
				select {
				case <-mShow.ClickedCh:
					showWindow()
				case <-mStart.ClickedCh:
					// 托盘里的启停走的是同一个 App，与窗口按钮共用状态。
					if err := app.Start(); err != nil {
						logx.Errorf("托盘启动失败: %v", err)
					}
				case <-mStop.ClickedCh:
					if err := app.Stop(); err != nil {
						logx.Errorf("托盘停止失败: %v", err)
					}
				case <-mReload.ClickedCh:
					if err := app.Reload(); err != nil {
						logx.Warnf("托盘重载失败: %v", err)
					}
				case <-mQuit.ClickedCh:
					shutdown()
					systray.Quit()
					return
				}
			}
		}()
	}, func() {
		// systray 自身退出时不要顺手停代理：正常退出路径由 shutdown 负责，
		// 这里只做记录，方便分辨「用户退出」与「托盘异常退出」。
		logx.Infof("系统托盘已退出")
	})
}
