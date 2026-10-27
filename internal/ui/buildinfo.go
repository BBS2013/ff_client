package ui

import (
	"io/fs"
	"os"
	"regexp"
	"time"
)

// DistFS 是这份产物内嵌的前端文件系统，由带 gui 标签的那份文件在 init 里装上。
// 不带界面标签的构建里它是 nil——那时"内嵌的是哪一份前端"这个问题压根不存在。
var DistFS fs.FS

// BuildInfo 回答排查时最先要问、却最难自己答的那一句：
// 「我现在看到的界面，是不是磁盘上最新的那一份」。
//
// 界面是 go:embed 进二进制的，所以磁盘上重新构建多少次都不关正在跑的那个进程的事——
// 它的画面停在启动那一刻。这个项目里"面板上没有某个界面"的第一嫌疑始终是进程旧，
// 而不是改动没做。与其让人去比 `strings wps_app-gui | grep index-` 与 `ls frontend/dist`，
// 不如把这两个数摆到同一屏上，并且直接把结论说出来。
type BuildInfo struct {
	// ExePath 是本进程的可执行文件路径。
	ExePath string `json:"exePath"`
	// ExeModTime 是磁盘上那份二进制的改动时间（Unix 毫秒）。
	// 取的是**当前**磁盘状态，所以它可能已经不是本进程所用那份的构建时间了——
	// 那正是 NewerOnDisk 要报的事。
	ExeModTime int64 `json:"exeModTime"`
	// StartedAt 是本进程启动时刻（Unix 毫秒）。
	StartedAt int64 `json:"startedAt"`
	// Frontend 是内嵌那份 index.html 引用的 JS 资源名，例如 index-cZ8NrLDR.js。
	// 它是"界面上有没有某个改动"唯一可靠的指纹：文件时间戳会因拷贝而变，这个名字不会。
	Frontend string `json:"frontend"`
	// NewerOnDisk 为真表示磁盘上的二进制比本进程新——你看到的界面是旧的。
	NewerOnDisk bool `json:"newerOnDisk"`
}

var assetRe = regexp.MustCompile(`index-[A-Za-z0-9_-]{8}\.js`)

// embeddedAsset 从内嵌的 index.html 里挑出那个 JS 资源名。
// 读不到就返回空串：这一格的意义是"报出它是什么"，猜一个反而更坏。
func embeddedAsset() string {
	if DistFS == nil {
		return ""
	}
	b, err := fs.ReadFile(DistFS, "frontend/dist/index.html")
	if err != nil {
		return ""
	}
	return assetRe.FindString(string(b))
}

// BuildInfo 是绑定给界面的读数。它不报错：每一条读不到都有对应的空值，
// 而"这份构建是什么"不该成为一个能挡住设置页的失败。
func (a *App) BuildInfo() BuildInfo {
	return buildInfo(a.startedAt, embeddedAsset())
}

// buildInfo 把"取路径 / 取磁盘时间"这两件不可注入的事隔在外面，
// 判断本身交给 fillExe，好让 NewerOnDisk 那条能被正反两头验到。
func buildInfo(started time.Time, asset string) BuildInfo {
	info := BuildInfo{StartedAt: started.UnixMilli(), Frontend: asset}
	exe, err := os.Executable()
	if err != nil {
		return info
	}
	info.ExePath = exe
	st, err := os.Stat(exe)
	if err != nil {
		return info
	}
	info.fillExe(st, started)
	return info
}

// fillExe 是唯一一处判断"磁盘上这份是不是比本进程新"的地方。
func (info *BuildInfo) fillExe(st fs.FileInfo, started time.Time) {
	info.ExeModTime = st.ModTime().UnixMilli()
	// 留 2 秒余量：先 `make build-gui` 再立刻起界面是常态，
	// 那一刻 mtime 与启动时刻的先后只反映毫秒级竞争，不说明界面旧。
	info.NewerOnDisk = st.ModTime().After(started.Add(2 * time.Second))
}
