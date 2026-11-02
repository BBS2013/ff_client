//go:build linux

package service

import (
	"net"
	"strings"
	"syscall"

	// 这里两个包各取所需：**RawConn 只有标准库 syscall 有**（x/sys/unix 没给它做一份），
	// 而 GetsockoptString 在 Linux 上只有 x/sys/unix 有（标准库只给了 SetsockoptString）。
	// 仓库里读这一个选项的地方（outbound/split_test.go、tunx/dialbind_test.go）
	// 走的也是这条组合路，这里跟着走，别为同一件事留第三种写法。
	"golang.org/x/sys/unix"
)

// boundDevice 回读这条 socket 实际被 SO_BINDTODEVICE 拴在哪张网卡上。
//
// 为什么非要回内核问一遍：界面那一格要的是**事实**，不是意图。
// 面板说"我把代理钉在 wlx001f0578cdff 上了"是意图；`ss -tnp` 里出现的
// `192.168.0.104%wlx001f0578cdff` 那个后缀才是事实——而它读的恰恰就是这个选项。
// 两边不一致的故事每天都在发生：绑了又退回默认路由、提权 helper 没干成活、
// 以后某个改动把绑定顺序挪了。界面上写的必须是后者，否则用户拿它跟 ss 对不上账，
// 只能再来问一句"这次到底有没有走那张卡"。
//
// 读不到就给空：没绑、或者这一跳本来就不是靠绑定出的网，那叫"没有证据"，
// 不叫"钉在某张卡上"。用意图冒充证据比不说话更糟。
func boundDevice(conn net.Conn) string {
	sc, ok := conn.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return ""
	}
	raw, err := sc.SyscallConn()
	if err != nil || raw == nil {
		return ""
	}
	var dev string
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		dev, gerr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		return ""
	}
	if gerr != nil {
		return ""
	}
	// 内核回的是一段定长缓冲，尾巴补的是 NUL；空串的意思就是"没绑"。
	dev = strings.TrimSpace(strings.Trim(dev, "\x00"))
	if dev == "" {
		return ""
	}
	return dev
}
