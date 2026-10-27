// Command genicon 把应用图标渲染成一组 PNG，用于预览、favicon 与文档配图。
//
// 用法: go run ./scripts/genicon [输出目录]      # 默认 ./assets/icon
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"wps_app/internal/appicon"
)

// sizes 是会被渲染的边长：托盘/窗口/文档/商店图各取所需。
var sizes = []int{16, 22, 32, 48, 64, 128, 256, 512}

func main() {
	dir := "assets/icon"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "建目录失败:", err)
		os.Exit(1)
	}
	for _, n := range sizes {
		raw := appicon.PNG(n)
		if raw == nil {
			fmt.Fprintln(os.Stderr, "渲染失败:", n)
			os.Exit(1)
		}
		p := filepath.Join(dir, fmt.Sprintf("icon-%d.png", n))
		if err := os.WriteFile(p, raw, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "写文件失败:", err)
			os.Exit(1)
		}
		fmt.Printf("  %-16s %6d 字节\n", p, len(raw))
	}
	// 托盘用的是简化几何，和同尺寸的 PNG(n) 不是同一张图，单独出一份便于预览。
	if err := os.WriteFile(filepath.Join(dir, "tray-64.png"), appicon.Tray(), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "写文件失败:", err)
		os.Exit(1)
	}
}
