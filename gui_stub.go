//go:build !gui

package main

import "fmt"

// guiDefault 为 false：默认构建只含命令行模式，双击仍是启动代理服务，
// ./wps_app [config.yaml] 的既有语义不变。gui 产物侧见 gui.go。
const guiDefault = false

// runGUI 是 -gui 在无 GUI 构建下的占位实现。
//
// 默认构建刻意不引入 wails 与 systray，因此不能直接编译默认二进制再「藏」一个窗口：
// 那会把 GTK3/WebKit2GTK 的运行时依赖强加给 systemd 部署路径。
// 用构建标签把两种产物彻底分开，这里只负责给出可操作的错误提示。
// 带 GUI 的实现在 gui.go（//go:build gui）。
func runGUI(configPath string) error {
	return fmt.Errorf("-gui 需要带 gui 标签的构建产物（make build-gui）；当前二进制只含命令行模式，配置文件 %s", configPath)
}
