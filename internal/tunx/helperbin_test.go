//go:build linux

package tunx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckHelperBinaryRejectsUserOwnedInRepo 是这一轮安全整改的核心一条。
//
// sudoers 只认路径，不认内容。README 里那条免密规则指向的就是产物文件，
// 而产物通常躺在仓库目录里——那里属于普通用户、可写。同用户（或同组）的
// 任何进程把它换掉之后，下一次 helper 调用就以 root 执行。
//
// 这里造一个"属主是当前用户、权限 0775"的文件（正是本机仓库里产物的形状），
// 断言它被拒绝；再把它改成 0755 且属主是 root 时应当放行——后者在非 root
// 下造不出来，所以只验证"用户属主 + 组可写"这一档，以及权限那一档。
func TestCheckHelperBinaryRejectsUserOwnedInRepo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 跑时造不出「属主不是 root」的文件（root 建的东西属主就是 root）")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "wps_app-gui")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// 属主是普通用户：即使权限 0755 也必须拒——这正是"仓库里的产物"的形状。
	err := checkHelperBinary(bin)
	if err == nil {
		t.Fatal("属主不是 root 的 helper 被放行了：同用户进程换掉这个文件就能借 sudo 拿 root")
	}
	if !strings.Contains(err.Error(), "root") {
		t.Errorf("错误没说清该装到哪: %v", err)
	}

	// 组可写：任何人都能替换它，必须拒。
	groupWritable := filepath.Join(dir, "group-writable")
	if err := os.WriteFile(groupWritable, []byte("x"), 0o775); err != nil {
		t.Fatal(err)
	}
	if err := checkHelperBinary(groupWritable); err == nil {
		t.Fatal("组可写的 helper 被放行了")
	}

	// 符号链接：sudo 只认路径，链接可以指向别处。
	link := filepath.Join(dir, "link")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	if err := checkHelperBinary(link); err == nil {
		t.Fatal("符号链接形式的 helper 被放行了")
	}

	// 空串表示"没有可校验的二进制"（进程内测试路径），不该报错。
	if err := checkHelperBinary(""); err != nil {
		t.Fatalf("空路径不该报错: %v", err)
	}
}

// TestHelperBinaryFromArgv 认准配置里那几种写法里的可执行文件。
func TestHelperBinaryFromArgv(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"sudo", "-n", "/opt/wps/wps_app-gui", "--tun-helper"}, "/opt/wps/wps_app-gui"},
		{[]string{"/usr/bin/sudo", "--", "/opt/wps/wps_app-gui", "--tun-helper"}, "/opt/wps/wps_app-gui"},
		// sudo 的选项会吃参数，别把它的值当成二进制。
		{[]string{"sudo", "-n", "-u", "alice", "/opt/wps/wps_app-gui"}, "/opt/wps/wps_app-gui"},
		// 没写 sudo（root 面板直接叫自己）。
		{[]string{"/opt/wps/wps_app-gui", "--tun-helper"}, "/opt/wps/wps_app-gui"},
		// 认不出来时返回空串，调用方按"无从校验"处理。
		{[]string{"sudo", "-n"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := helperBinaryFromArgv(c.argv); got != c.want {
			t.Errorf("helperBinaryFromArgv(%v) = %q, want %q", c.argv, got, c.want)
		}
	}
}
