package main

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"image"
	"image/color"
	"image/png"

	"fyne.io/systray"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var distFS embed.FS

// icon 画一个 64x64 测试图标，不引入二进制素材。
func icon() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 64, 64))
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 4), G: uint8(y * 4), B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func main() {
	go func() {
		systray.Run(func() {
			fmt.Println("TRAY_READY")
			systray.SetIcon(icon())
			systray.SetTooltip("wps spike tray")
			systray.SetTitle("wps spike")
			systray.AddMenuItem("显示主窗口", "show")
			systray.AddMenuItem("退出", "quit")
		}, func() { fmt.Println("TRAY_EXIT") })
	}()

	err := wails.Run(&options.App{
		Title:             "wps spike",
		Width:             480,
		Height:            240,
		AssetServer:       &assetserver.Options{Assets: distFS},
		HideWindowOnClose: true,
		OnStartup:         func(ctx context.Context) { fmt.Println("SPAWN_OK") },
	})
	fmt.Println("EXIT:", err)
}
