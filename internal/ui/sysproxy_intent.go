package ui

import (
	"os"
	"strings"

	"wps_app/internal/logx"
	"wps_app/internal/sudoown"
)

// sysProxyIntentPath 是「系统代理总开关上次是开还是关」的落盘位置。
//
// 为什么不复用 sysproxy.json：那份是「桌面原来是什么、退出时要还原成什么」的账，
// 正常退出会删掉；而总开关状态必须跨正常退出活下来，否则每次启动都会回到
// 「服务起来了、系统代理却关着」的分裂状态（2026-11-02 用户报的就是这个）。
//
// 文件名跟着配置文件走，与用量账本、系统代理账本同一个目录。
func sysProxyIntentPath(configPath string) string {
	return configPath + ".sysproxy.want"
}

type sysProxyIntent int

const (
	sysProxyIntentUnknown sysProxyIntent = iota
	sysProxyIntentOff
	sysProxyIntentOn
)

// readSysProxyIntent 读上次总开关状态。
//
// 文件不存在、读不懂、内容不认识都按 unknown 处理：调用方对 unknown 的处置
// 必须是保守的（不擅自改桌面），不能把损坏的文件猜成 on。
func readSysProxyIntent(configPath string) sysProxyIntent {
	b, err := os.ReadFile(sysProxyIntentPath(configPath))
	if err != nil {
		if !os.IsNotExist(err) {
			logx.Warnf("系统代理总开关状态读不出（%s）: %v", sysProxyIntentPath(configPath), err)
		}
		return sysProxyIntentUnknown
	}
	switch strings.TrimSpace(string(b)) {
	case "on":
		return sysProxyIntentOn
	case "off":
		return sysProxyIntentOff
	default:
		logx.Warnf("系统代理总开关状态文件内容不认识（%s），按未知处理", sysProxyIntentPath(configPath))
		return sysProxyIntentUnknown
	}
}

// writeSysProxyIntent 记下总开关状态。失败只告警：这次操作本身已经成功，
// 不该因为写不下一行状态就把用户刚打开的代理回滚。
func (a *App) writeSysProxyIntent(on bool) {
	path := sysProxyIntentPath(a.svc.ConfigPath())
	body := "off\n"
	if on {
		body = "on\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		logx.Warnf("系统代理总开关状态没写进 %s（下次启动可能按旧状态处理）: %v", path, err)
		return
	}
	// root 面板替桌面用户落盘时，不要把状态文件留成 root 0600。
	if err := sudoown.ToDesktopUser(path); err != nil {
		logx.Warnf("系统代理总开关状态文件属主未能还给桌面用户（%s）: %v", path, err)
	}
}
