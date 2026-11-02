// Package sudoown 解决「root 进程替桌面用户落盘」的属主问题。
//
// 面板为了开 TUN 常以 root 跑（sudo ./wps_app-gui），而配置目录、
// 系统代理记账、节点用量账本都跟着配置文件走，落在桌面用户的目录里。
// gsettings 那一路有 desktopPrefix 借 sudo 还原成桌面用户，文件却没有
// 对应的另一半：root 写出来的就是 root 属主 0600。后果在 2026-10-30
// 实际发生过两回：
//
//   - 系统代理记账留在 root 手里，普通权限实例读它一律 permission denied
//     ——「读不懂」在系统代理这里等于「不知道上一轮还欠不欠还原」，
//     于是面板反复报「桌面正指着本程序的入站，但没有记账」的孤儿警告，
//     连 -sysproxy on 这个补救命令都被那本读不到的账挡住；
//   - 用量账本同理，普通实例启动时「节点用量账本读不出，从空账开始」，
//     界面上的「累计」凭空清零。
//
// 修复只有一件事：root 落盘后把属主还给 $SUDO_USER。
package sudoown

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ToDesktopUser 把 path 的属主改成发起 sudo 的那个桌面用户。
//
// 三种情况是空操作（返回 nil）：本进程不是 root（文件本来就归用户）、
// 环境里没有 SUDO_USER（sudo -i / su 进来的 root，没有可归还的人）、
// 查不到那个用户。其余情况 chown 失败的错误原样交回——要不要因此报警
// 由调用方定：对记账文件值得说一句，对刚建成的目录不值得推翻写入。
func ToDesktopUser(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	su := os.Getenv("SUDO_USER")
	if su == "" {
		return nil
	}
	uid, gid, err := lookup(su)
	if err != nil {
		return fmt.Errorf("查不到桌面用户 %s 的 uid/gid，属主还不过去: %w", su, err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("把 %s 的属主还给 %s 失败: %w", path, su, err)
	}
	return nil
}

// lookup 从 passwd 查 uid 与主 gid。
//
// 用 getent 而不是 os/user：os/user 的 cgo 版在静态链接下面向 glibc
// 的行为并不一致，而包里已有的 userUID（internal/sysproxy/backend.go）
// 同样走 getent——同一台机器上两处答案必须同源。
func lookup(name string) (int, int, error) {
	out, err := exec.Command("getent", "passwd", name).Output()
	if err != nil {
		return 0, 0, err
	}
	// passwd 格式：name:passwd:uid:gid:gecos:home:shell
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 4 {
		return 0, 0, fmt.Errorf("passwd 里 %q 的记录不完整", name)
	}
	uid, err := strconv.Atoi(fields[2])
	if err != nil {
		return 0, 0, fmt.Errorf("passwd 里 %q 的 uid 不是数字: %w", name, err)
	}
	gid, err := strconv.Atoi(fields[3])
	if err != nil {
		return 0, 0, fmt.Errorf("passwd 里 %q 的 gid 不是数字: %w", name, err)
	}
	return uid, gid, nil
}
