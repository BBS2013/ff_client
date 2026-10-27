//go:build gui

// gui.go 把代理服务、系统托盘和 Wails 窗口装配到一起。
//
// 不用 wails build CLI：它只是 npm + go build 的糖衣。直接 go build 配
// assetserver.Options{Assets: fs.FS} 就够了，少一条工具链耦合，CI 里也能
// 用同一条 go build 复现出窗。
package main

import (
	"context"
	"embed"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"fyne.io/systray"
	"github.com/wailsapp/wails/v2"
	wopts "github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/linux"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"wps_app/internal/appicon"
	"wps_app/internal/logx"
	"wps_app/internal/ui"
)

// 前端产物由 vite build 生成到 frontend/dist。all: 前缀不能省：
// 它保证目录下的所有文件（含子目录与隐藏文件）都被打进去。
//
//go:embed all:frontend/dist
var distFS embed.FS

// 把内嵌那份前端交给 ui 包，让设置页能报出"界面是哪一份构建"（internal/ui/buildinfo.go）。
// 在这里赋值而不是让 ui 包自己 embed：界面文件只存在于带 gui 标签的构建里，
// 而 ui 包要在没有那个标签的测试里也能编译。
func init() { ui.DistFS = distFS }

// guiDefault 让这份产物双击即出窗口。
//
// 配合 main.go 的 runCLI：带 gui 标签时不开界面反而是意外行为——用户从文件
// 管理器双击一个桌面控制面板，看到的应该是面板，而不是一个跑起来没反应的服务端。
// 需要反向行为时用 -cli。
const guiDefault = true

// resolveConfigPath 与 chdirToConfigDir 住在 configpath.go（没有构建标签），
// 这样它们才进得了 `go test ./...`——判断没被测过，就等于交给"哪天有人双击一次"。

func runGUI(configPath, logFile string, logOpened bool) error {
	configPath = resolveConfigPath(configPath)
	// 面板的 stdout 是启动器给的 socket，进程一退就没了。默认把日志写到
	// <config>.log（0600，20MB × 3），至少让"昨天为什么断了"有纸可查。
	if !logOpened {
		abs, err := filepath.Abs(configPath)
		if err != nil {
			abs = configPath
		}
		logFile = abs + ".log"
		if closer, err := logx.SetFileOutput(logFile, logx.DefaultMaxBytes, logx.DefaultBackups); err != nil {
			logx.Warnf("日志文件打不开（%s）: %v；继续只用内存日志", logFile, err)
		} else {
			defer func() { _ = closer.Close() }()
			logx.Infof("日志同时写入 %s（%dMB × %d 轮转）", logFile, logx.DefaultMaxBytes>>20, logx.DefaultBackups)
		}
	}
	chdirToConfigDir(configPath)
	app := ui.New(configPath)

	// 主窗口的 ctx 用 atomic 存，而不是「塞进 channel 等人取一次」：
	// showWindow 取走之后，后面 SIGTERM 想 Quit 就取不到了，
	// 结果是进程把代理停干净却一直不退出的孤儿窗口（实测同时挂着两个面板进程）。
	// ctx 本身是长期有效的，谁都能读，读不到只表示「窗口还没就绪」。
	var ctxRef atomic.Pointer[context.Context]
	// quitting 覆盖「用户要求退出」这个状态，被信号处理、托盘退出、
	// OnShutdown 三条路径共用，保证真正的清理只跑一次。
	var quitting atomic.Bool

	showWindow := func() {
		if p := ctxRef.Load(); p != nil {
			// Show 会把隐藏或最小化的窗口拉回可见，比单纯 Unminimise 稳。
			runtime.Show(*p)
			return
		}
		logx.Warnf("主窗口尚未就绪，本次「显示控制面板」已忽略")
	}

	shutdown := func() {
		if !quitting.CompareAndSwap(false, true) {
			// 已经有人在退出了，重复触发直接返回，避免端口被关两遍。
			return
		}
		if p := ctxRef.Load(); p != nil {
			runtime.Quit(*p)
		} else {
			// Wails 还没起来就没有 ctx 可 Quit。OnStartup 里会看到 quitting
			// 已经置位并立刻 Quit，所以这里什么都不用做。
			logx.Infof("收到退出请求，此时窗口尚未就绪")
		}
		systray.Quit()
	}

	go ui.RunTray(app, showWindow, shutdown)

	// Ctrl+C 与 systemd 的 SIGTERM 走和托盘「退出」同一条路径，
	// 这样托盘图标不会在进程死后留下幽灵项，入站端口也能正常释放。
	sigCh := make(chan os.Signal, 1)
	// SIGHUP 也接：README 里「改完规则 kill -HUP 就生效」对命令行成立，
	// 对面板进程同样该成立——不接的话信号会被 GTK 吞掉，
	// 用户以为重载过了，实际还在用旧规则，是最难查的一类不一致。
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		// 循环收信号：SIGHUP 只重载规则，进程要留着继续服务，
		// 收一次就退出的写法会让第二次 kill -HUP 石沉大海。
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				if err := app.Reload(); err != nil {
					logx.Errorf("收到 SIGHUP 但重载失败: %v", err)
				}
				continue
			}
			logx.Infof("收到信号 %s，开始退出", sig)
			shutdown()
			return
		}
	}()

	err := wails.Run(&wopts.App{
		Title:       "wps_app 控制面板",
		Width:       1080,
		Height:      720,
		MinWidth:    900,
		MinHeight:   600,
		AssetServer: &assetserver.Options{Assets: distFS},
		Bind:        []interface{}{app},
		Linux: &linux.Options{
			Icon: appicon.Window(),
			// 这行不是冗余的：Linux options 一旦非 nil，Wails 就不再走
			// 「nil ⇒ GPU 策略强制 Never」的兜底（wails#2977），零值 OnDemand
			// 会让 webview 在部分驱动上直接白屏。为了加图标而顺手打开硬件加速，
			// 是拿整个界面去换一个图标。
			WebviewGpuPolicy: linux.WebviewGpuPolicyNever,
			ProgramName:      "wps_app",
		},
		OnStartup: func(ctx context.Context) {
			ctxRef.Store(&ctx)
			if quitting.Load() {
				// 极窄的竞态：用户在窗口出现前就点了托盘退出。
				// 这里补一次 Quit，否则窗口会一直留着、进程也退不掉。
				runtime.Quit(ctx)
				return
			}
			// GUI 进程就是代理进程：窗口一亮就该在转发。启动失败也不退出，
			// 界面会把 lastError 显示出来，用户改完配置还能在面板里重试。
			if serr := app.Start(); serr != nil {
				logx.Errorf("GUI 启动代理失败: %v", serr)
			}
		},
		// 关窗口只是隐藏，代理与托盘继续跑——这是常驻控制面板的前提。
		HideWindowOnClose: true,
		OnShutdown: func(context.Context) {
			// Close 幂等（摘钩子置 nil、Stop 判空），与下面的兜底调用可共存。
			if err := app.Close(); err != nil {
				logx.Errorf("退出时停止代理出错: %v", err)
			}
			systray.Quit()
		},
	})

	// wails.Run 返回的路径（正常退出、窗口被外部关闭）也走一遍清理。
	systray.Quit()
	if cerr := app.Close(); cerr != nil {
		logx.Errorf("退出时停止代理出错: %v", cerr)
	}
	return err
}
