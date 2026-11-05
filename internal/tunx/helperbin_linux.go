//go:build linux

package tunx

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// checkHelperBinary 在真正调 sudo 之前核对「要提权执行的那个文件本身可信」。
//
// 为什么必须有这一步：sudoers 只认**路径**，不认内容。
// README 里那条免密规则指向的是产物文件（单产物之后面板与 helper 是同一个
// 文件），而产物通常就躺在仓库目录里——那里属于普通用户、可写。于是同一个
// 用户（或同组）的任何进程把它换成一个自己的程序，下一次 helper 调用就以
// root 执行了。这不是理论问题：`git checkout`、`go build`、一次误 `mv`
// 都能顺手改掉这个文件，而它平时就长在那里。
//
// 判据三条，缺一不可：
//
//	属主必须是 root（或当前进程就是 root，那时文件本来就该是 root 的）
//	组与其他用户都不可写（否则同组的人能换掉它）
//	路径不能是符号链接（否则"root 拥有的文件"可能是链过去之后的另一个）
//
// 不符合时不强行继续，也不自动"修一下"——静默修正会让真正的问题（装错位置）
// 一直藏着。返回的错误直接给用户看，里面写着该怎么办。
func checkHelperBinary(path string) error {
	if path == "" {
		return nil
	}
	li, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("提权 helper %s 不可用: %w", path, err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("提权 helper %s 是符号链接，拒绝提权执行（sudo 只认路径，链接可以指向别处）", path)
	}
	if !li.Mode().IsRegular() {
		return fmt.Errorf("提权 helper %s 不是普通文件", path)
	}
	// 世界可写或组可写：任何人都能把它换掉，提权执行等于把 root 交出去。
	if li.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("提权 helper %s 权限为 %o（组或其他用户可写），拒绝提权执行。"+
			"请改成 0755 并装到 root 拥有的目录（make install-helper），"+
			"或临时执行 chmod 755 %s",
			path, li.Mode().Perm(), path)
	}
	st, ok := li.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("读不到提权 helper %s 的属主", path)
	}
	if st.Uid != 0 && os.Geteuid() != 0 {
		return fmt.Errorf("提权 helper %s 的属主是 uid %d（不是 root），拒绝提权执行。"+
			"它必须装到 root 拥有的位置（make install-helper），否则同用户进程换掉这个文件"+
			"就能借 sudo 拿到 root", path, st.Uid)
	}
	return nil
}

// helperBinaryFromArgv 从「sudo -n /path/to/bin」这种前缀里取出要提权执行的文件。
//
// 取的是**第一个不以 '-' 开头、且不是已知 sudo 选项参数**的项，再跳过 sudo 自己
// （含它的选项与被选项吃掉的参数）。刻意不追求完整解析 sudo 的命令行：
// 这里只需要认准"将要被 exec 的那个文件"，而配置里写的永远是
// ["sudo","-n","/abs/path","--tun-helper"] 这一种形状。
// 认不出来时返回空串，调用方按"没有可校验的二进制"处理——
// 那不会放松安全性：真正的约束在 sudoers 与文件权限那两处。
func helperBinaryFromArgv(argv []string) string {
	// sudo 自己的选项里，这些后面跟一个独立参数。
	takesValue := map[string]bool{
		"-u": true, "-g": true, "-p": true, "-C": true, "-D": true,
		"-h": true, "-r": true, "-t": true, "-T": true, "-U": true,
	}
	i := 0
	// 跳过 sudo 本体（可能是 /usr/bin/sudo 或 sudo）。
	if i < len(argv) && isSudo(argv[i]) {
		i++
		for i < len(argv) {
			a := argv[i]
			if !strings.HasPrefix(a, "-") || a == "-" {
				break
			}
			if takesValue[a] {
				i += 2
				continue
			}
			i++
			// "--" 之后紧跟命令，循环下一轮会 break。
			if a == "--" {
				break
			}
		}
	}
	// 也可能没写 sudo（root 面板直接叫自己），那时第一项就是二进制。
	for ; i < len(argv); i++ {
		a := argv[i]
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		// 环境变量赋值（FOO=bar）不是命令。
		if !strings.Contains(a, "/") && strings.Contains(a, "=") {
			continue
		}
		if !filepath.IsAbs(a) {
			// 相对路径同样不可信：工作目录是谁的说不清。
			// 但也不能因此判失败——配置里写相对路径本来就不该出现，
			// 这里返回它，交给 checkHelperBinary 去 Lstat（多半查不到）。
			return a
		}
		return a
	}
	return ""
}

func isSudo(s string) bool {
	base := filepath.Base(s)
	return base == "sudo" || base == "doas" || base == "pkexec"
}
