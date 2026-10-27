package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveConfigPathOnlyFallsBackForTheDefault 回退只服务于"没指定路径"那一种情况。
//
// 最要紧的是最后那条：用户显式给了 -c / 位置参数，文件却不存在，
// 这时候偷偷换成程序旁边那份 config.yaml，读的是另一台机器的语义、
// 报的错还指向用户根本没给的路径。宁可失败，也不换文件。
func TestResolveConfigPathOnlyFallsBackForTheDefault(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	// 1) 默认路径且当前目录就有：原样返回，不去碰可执行文件旁边那份。
	here := filepath.Join(cwd, "config.yaml")
	if err := os.WriteFile(here, []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	exeDir := t.TempDir()
	writeBeside(t, exeDir)
	restore := useExecutable(exeDir)
	defer restore()
	if got := resolveConfigPath(defaultConfigPath); got != defaultConfigPath {
		t.Fatalf("当前目录有配置却回退了: %q", got)
	}

	// 2) 默认路径、当前目录没有、程序同目录有：退到同目录那份（双击启动的正解）。
	if err := os.Remove(here); err != nil {
		t.Fatal(err)
	}
	if got := resolveConfigPath(defaultConfigPath); got != filepath.Join(exeDir, "config.yaml") {
		t.Fatalf("没有退到程序同目录: %q", got)
	}

	// 3) 两边都没有：保持原样，让后面那句 open 报出用户看得懂的路径。
	restore2 := useExecutable(t.TempDir())
	defer restore2()
	if got := resolveConfigPath(defaultConfigPath); got != defaultConfigPath {
		t.Fatalf("两处都没有时不该改路径: %q", got)
	}

	// 4) 显式给的路径哪怕不存在也不许被换掉。
	if got := resolveConfigPath("/nowhere/x.yaml"); got != "/nowhere/x.yaml" {
		t.Fatalf("显式路径被偷偷换成了 %q", got)
	}
}

// TestChdirToConfigDir 相对路径必须围着配置文件解析，但只在该切的时候切。
func TestChdirToConfigDir(t *testing.T) {
	dir := t.TempDir()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	// 配置在别的目录：切过去，之后 ./assets/... 才指得对。
	chdirToConfigDir(filepath.Join(resolved, "config.yaml"))
	if wd, _ := os.Getwd(); wd != resolved {
		t.Fatalf("没切到配置目录: %q, 期望 %q", wd, resolved)
	}

	// 已经在同一个目录：不该再动（重复 Chdir 会把错误日志刷成噪音）。
	chdirToConfigDir("config.yaml")
	if wd, _ := os.Getwd(); wd != resolved {
		t.Fatalf("相对路径不该改变工作目录: %q", wd)
	}

	// 切不动就如实放弃：面板还能开、还能看见真实报错，比进程直接退出好排查。
	chdirToConfigDir(filepath.Join(t.TempDir(), "nope", "config.yaml"))
	if wd, _ := os.Getwd(); wd != resolved {
		t.Fatalf("切失败之后 cwd 被动了: %q", wd)
	}
}

// useExecutable 把"我在哪儿跑"这件事交给测试控制。返回恢复函数。
func useExecutable(exeDir string) func() {
	old := executablePath
	executablePath = func() (string, error) { return filepath.Join(exeDir, "wps_app-gui"), nil }
	return func() { executablePath = old }
}

func writeBeside(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("mode: rule\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
