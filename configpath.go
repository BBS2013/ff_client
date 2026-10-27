package main

// configpath.go 管"双击启动时去哪儿找配置文件"。
//
// 这两个函数原先住在 gui.go 里，而 gui.go 带 `//go:build gui`：
// 默认构建不编译它，`go test ./...` 也就永远跑不到它。
// 偏偏这里全是判断——什么时候该回退、什么时候必须如实报错、什么时候不该动 cwd——
// 判断没被测过，就等于交给"哪天有人双击一次"。放在没有标签的文件里，
// CLI 构建多编译两个没人调用的函数而已，代价是零，换来的是它们进得了测试。

import (
	"os"
	"path/filepath"

	"wps_app/internal/logx"
)

// executablePath 是 os.Executable 的一个缝：
// 测试要验"退到程序同目录"那条分支，就得能假装自己在别的目录里跑。
var executablePath = os.Executable

// resolveConfigPath 兜住双击启动时不可控的工作目录。
//
// 从文件管理器双击，进程的工作目录未必是程序所在目录，./config.yaml 常常
// 找不到；此时退到可执行文件旁边的 config.yaml，GUI 用户不该被要求「先 cd 到
// 某个目录再启动」。只有默认路径会回退：用户显式写了 -c 或位置参数却找不到文件，
// 必须如实报错，不能偷偷换个文件读。
func resolveConfigPath(configPath string) string {
	if configPath != defaultConfigPath {
		return configPath
	}
	if _, err := os.Stat(configPath); err == nil {
		return configPath
	}
	exe, err := executablePath()
	if err != nil {
		return configPath
	}
	beside := filepath.Join(filepath.Dir(exe), defaultConfigPath)
	if _, err := os.Stat(beside); err == nil {
		logx.Infof("当前目录下没有 %s，改用程序同目录的 %s", defaultConfigPath, beside)
		return beside
	}
	return configPath
}

// chdirToConfigDir 把工作目录切到配置文件所在目录。
//
// 配置文件里的 rules_file、geoip.path 都是 "./assets/..." 这种相对路径，
// 按进程 cwd 解析。双击启动时 cwd 是文件管理器给的地方（多半是 ~ 或 /tmp），
// 于是配置找到了、assets 却找不到，界面能开但代理起不来，日志里只留一句
// "open ./assets/rules.txt: no such file or directory"——用户看不出是自己启动
// 方式不对。切到配置目录后，相对路径一律以配置为中心，和在项目目录里
// `wps_app config.yaml` 手动启动完全一致。
//
// 切目录失败不阻断启动：面板本身不依赖 cwd，用户可以在界面里看到真实报错并
// 改配置路径，比进程直接退出更好排查。
func chdirToConfigDir(configPath string) {
	dir := filepath.Dir(configPath)
	if dir == "" || dir == "." {
		return
	}
	if wd, err := os.Getwd(); err == nil && wd == dir {
		return
	}
	if err := os.Chdir(dir); err != nil {
		logx.Warnf("切换到配置目录 %s 失败，配置里的相对路径可能找不到: %v", dir, err)
		return
	}
	logx.Infof("工作目录切换到 %s（配置文件所在目录）", dir)
}
