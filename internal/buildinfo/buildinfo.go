// Package buildinfo 回答「正在跑的是哪一次构建」。
//
// 三个值都由构建脚本通过 -ldflags -X 注入：
//   - Version 来自 VERSION 文件；
//   - Stamp 是源码指纹：有 git 时是短 commit + -dirty，没有 git 时是内容哈希；
//   - BuiltAt 是 UTC 构建时刻。
//
// 默认值 "unknown" 让没走脚本的 go build 仍然能跑，但会诚实地说明自己不知道。
package buildinfo

import (
	"fmt"
	"runtime"
)

var (
	Version = "unknown"
	Stamp   = "unknown"
	BuiltAt = ""
)

// Summary 是给 -version 与诊断报告用的一行。
func Summary() string {
	stamp := Stamp
	if stamp == "" {
		stamp = "unknown"
	}
	s := fmt.Sprintf("wps_app %s (source %s)", Version, stamp)
	if BuiltAt != "" {
		s += " built " + BuiltAt
	}
	return s + " " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
}
