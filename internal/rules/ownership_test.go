package rules

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestSaveUserRulesRestoresOwnership 守住“root 面板写规则后要把属主还给桌面用户”。
//
// 真 chown 需要 root，这里只验调用点：规则文件与它的 .bak 都必须经过
// chownToDesktopUser。2026-11-02 本机上 assets/user-rules.txt 就是 root:root，
// 而 README 又允许用户直接编辑它——普通用户打开就是只读。
func TestSaveUserRulesRestoresOwnership(t *testing.T) {
	old := chownToDesktopUser
	t.Cleanup(func() { chownToDesktopUser = old })

	var got []string
	chownToDesktopUser = func(path string) error {
		got = append(got, filepath.Base(path))
		return nil
	}

	dir := t.TempDir()
	path := filepath.Join(dir, UserRuleFileName)
	if err := os.WriteFile(path, []byte("# old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	list := []UserRule{{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"}}
	if err := SaveUserRules(path, list); err != nil {
		t.Fatalf("SaveUserRules: %v", err)
	}
	want := []string{UserRuleFileName + ".bak", UserRuleFileName}
	if !slices.Equal(got, want) {
		t.Fatalf("归还属主的路径 = %v, want %v", got, want)
	}
}
