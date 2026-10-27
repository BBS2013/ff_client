//go:build linux

package tunx

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// Linux capability 编号与 prctl 选项常量。
// x/sys/unix 没有导出 PR_CAP_AMBIENT_RAISE 与 CAP_NET_*，这里按内核 uapi 补齐。
const (
	prCapAmbient      = 25
	prCapAmbientRaise = 4
	capNetAdmin       = 12
	capNetRaw         = 13
	capDACOverride    = 1
)

// raiseAmbientCaps 把已经在 permitted+inheritable 里的能力补进 ambient 集合。
//
// 为什么必须做这一步：用 `sudo setcap cap_net_admin+eip wps_app-gui` 授权后，
// 本进程确实能直接打开 /dev/net/tun 建网卡，但我们配地址与路由靠的是
// exec 出去的 `ip` 与 `iptables`——execve 默认会把能力丢掉，子进程仍是
// 无特权的 uid 1000。症状就是「建 tun 成功、ip addr add 报 Operation not permitted」。
// ambient 集合是 Linux 4.3 之后专门为此准备的：放进 ambient 的能力会在 execve
// 后补进子进程的 permitted+effective，不需要 setuid，也不用给系统工具重新授权。
func raiseAmbientCaps() []string {
	var raised []string
	for _, c := range []struct {
		bit  int
		name string
	}{{capNetAdmin, "CAP_NET_ADMIN"}, {capNetRaw, "CAP_NET_RAW"}, {capDACOverride, "CAP_DAC_OVERRIDE"}} {
		if _, err := unix.PrctlRetInt(prCapAmbient, prCapAmbientRaise, uintptr(c.bit), 0, 0); err != nil {
			// EPERM 有两种意思：本进程压根没有该能力（没 setcap、也没 sudo），
			// 或者它已在 ambient 里。两者都不该中断流程——真正有没有权限，
			// 由后面第一条 ip/iptables 命令的结果说话，那时报错才准确。
			continue
		}
		raised = append(raised, c.name)
	}
	return raised
}

// capabilitySummary 读 /proc/self/status 里的能力掩码，供日志定位「到底拿到没有」。
// 排障时这一行比猜「是不是该 sudo」有用得多。
func capabilitySummary() string {
	data, err := unix.Open("/proc/self/status", unix.O_RDONLY, 0)
	if err != nil {
		return ""
	}
	defer unix.Close(data)
	buf := make([]byte, 4096)
	n, _ := unix.Read(data, buf)
	if n <= 0 {
		return ""
	}
	var got []string
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		for _, key := range []string{"CapEff", "CapAmb"} {
			if strings.HasPrefix(line, key) {
				got = append(got, strings.TrimSpace(line))
			}
		}
	}
	if len(got) == 0 {
		return ""
	}
	return fmt.Sprintf("%s", strings.Join(got, " "))
}
