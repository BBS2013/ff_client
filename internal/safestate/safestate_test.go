package safestate

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileRejectsSymlinkTarget 是这一整个包存在的理由。
//
// 攻击形状：面板以 root 跑（或经 helper 提权），状态文件路径由配置文件推导，
// 落在普通用户能改的目录里。用户把那个路径换成一个指向 /etc/sudoers.d/xxx
// 的符号链接——下一次写入就让 root 把内容写到那里去了，而写进去的东西里
// 包含节点口令、代理账本、iptables 决策依据。
func TestWriteFileRejectsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("原始内容"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "state.json")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}

	if err := WriteFile(link, []byte("被写进去的东西"), 0o600); err == nil {
		t.Fatal("符号链接目标被接受了：root 会跟着链接往任意路径写")
	}
	// 链接后面的文件必须原封不动。
	got, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "原始内容" {
		t.Fatalf("链接指向的文件被改写了：%q", got)
	}
}

// TestWriteFileAtomicAndOwnerPreserving 确认正常路径没被上面的拒绝逻辑弄坏。
func TestWriteFileAtomicAndOwnerPreserving(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "state.json")

	if err := WriteFile(path, []byte("第一版"), 0o600); err != nil {
		t.Fatalf("首次写（目录还不存在）失败: %v", err)
	}
	if err := WriteFile(path, []byte("第二版"), 0o600); err != nil {
		t.Fatalf("覆盖写失败: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "第二版" {
		t.Fatalf("内容 = %q, want 第二版", got)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("权限 = %o, want 0600", st.Mode().Perm())
	}
	// 目录里不该留下临时文件。
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "state.json" {
			t.Errorf("目录里留下了垃圾: %s", e.Name())
		}
	}
}

// TestWriteFileDoesNotLeavePartialFile 确认失败路径不留半截文件。
//
// 判据是"要么旧内容、要么新内容"：写一半的账本读不懂，而读不懂的账本会被
// 当成"没有账"，于是退出时不再还原桌面/解析器——那是最难查的一类故障。
func TestWriteFileDoesNotLeavePartialFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := WriteFile(path, []byte("旧内容"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 造一个写入必然失败的调用：目标目录被一个普通文件占住。
	badDir := filepath.Join(dir, "blocked")
	if err := os.WriteFile(badDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(filepath.Join(badDir, "state.json"), []byte("新"), 0o600); err == nil {
		t.Fatal("父路径是普通文件却写成功了")
	}
	// 原来那份必须还在。
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("原有文件被弄丢了: %v", err)
	}
	if string(got) != "旧内容" {
		t.Fatalf("原有内容被改了：%q", got)
	}
}
