package sudoown

import (
	"os"
	"path/filepath"
	"testing"
)

// ToDesktopUser 的 root 分支要真 root 才能测（chown 别人的文件、
// 伪造 euid=0 都做不到），这里只钉住三条「必须空操作」的路：
// 非 root 进程调它绝不能碰文件，也不能报错——普通面板的每一次落盘都过这里。
func TestNoopWhenNotRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 跑的测试环境里，非 root 的空操作分支覆盖不到")
	}
	path := filepath.Join(t.TempDir(), "ledger.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// SUDO_USER 有没有值都不许有动作：这个函数的唯一入口判据是 euid。
	t.Setenv("SUDO_USER", "root")
	if err := ToDesktopUser(path); err != nil {
		t.Fatalf("非 root 进程调 ToDesktopUser 不该报错: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, after) {
		t.Errorf("非 root 进程的调用改动了文件")
	}
}
