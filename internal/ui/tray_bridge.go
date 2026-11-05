//go:build gui

package ui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"fyne.io/systray"

	"wps_app/internal/appicon"
	"wps_app/internal/logx"
)

// root 面板本身连不上桌面用户的会话总线：DBus 的 EXTERNAL 认证看的是连接
// 进程的 uid，root 不是总线属主。托盘因此必须由桌面用户身份的子进程显示，
// 这个文件就是那条桥：
//
//	root 面板 --(unix socket, 命令/状态)--> 桌面用户 --(DBus StatusNotifierItem)--> 托盘
//
// 为什么不让 root 直接跑 systray：fyne.io/systray 的 Linux 实现是纯 DBus，
// root 连不上总线时它既显示不出来，退出路径还可能 nil 解引用（见 tray.go）。
type trayCommand struct {
	Action string `json:"action"`
}

type trayState struct {
	Status  string `json:"status,omitempty"`
	Tooltip string `json:"tooltip,omitempty"`
}

// RunTrayBridge 在 root 面板这一侧跑桥：拉起桌面用户身份的助手、收菜单动作、
// 推状态文字。它阻塞到助手退出或面板要求退出；调用方应放在 goroutine 里。
func RunTrayBridge(app *App, showWindow, shutdown func()) {
	user, home, uid, gid, err := trayDesktopUser()
	if err != nil {
		logx.Warnf("系统托盘桥不可用: %v", err)
		return
	}

	dir, err := os.MkdirTemp("", "wps_app-tray-")
	if err != nil {
		logx.Warnf("系统托盘桥不可用: 建临时目录: %v", err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Chown(dir, uid, gid); err != nil {
		logx.Warnf("系统托盘桥不可用: 临时目录属主: %v", err)
		return
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		logx.Warnf("系统托盘桥不可用: 临时目录权限: %v", err)
		return
	}

	path := filepath.Join(dir, "s")
	ln, err := net.Listen("unix", path)
	if err != nil {
		logx.Warnf("系统托盘桥不可用: 监听: %v", err)
		return
	}
	defer func() { _ = ln.Close() }()
	if err := os.Chown(path, uid, gid); err != nil {
		logx.Warnf("系统托盘桥不可用: 套接字属主: %v", err)
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		logx.Warnf("系统托盘桥不可用: 套接字权限: %v", err)
		return
	}

	exe, err := os.Executable()
	if err != nil {
		logx.Warnf("系统托盘桥不可用: 读不到自身路径: %v", err)
		return
	}
	display := strings.TrimSpace(os.Getenv("DISPLAY"))
	if display == "" {
		display = ":0"
	}
	xauth := strings.TrimSpace(os.Getenv("XAUTHORITY"))
	if xauth == "" {
		xauth = filepath.Join(home, ".Xauthority")
	}
	cmd := exec.Command(exe, "--tray-helper="+path)
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"USER="+user,
		"LOGNAME="+user,
		"DISPLAY="+display,
		"XAUTHORITY="+xauth,
		"XDG_RUNTIME_DIR=/run/user/"+strconv.Itoa(uid),
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/"+strconv.Itoa(uid)+"/bus",
	)
	// root 自己 setuid 到桌面用户，别走 sudo：sudo 在无 tty 的 root 面板里
	// 会卡在 PAM/pipe 上（实测 ppoll 等 30 秒），托盘助手永远连不回来。
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid),
	}}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		logx.Warnf("系统托盘桥不可用: 拉起托盘助手: %v", err)
		return
	}
	logx.Infof("系统托盘助手已拉起: pid=%d", cmd.Process.Pid)
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	_ = ln.(*net.UnixListener).SetDeadline(time.Now().Add(15 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		logx.Warnf("系统托盘桥不可用: 托盘助手没有连回来: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	_ = ln.(*net.UnixListener).SetDeadline(time.Time{})

	cmds := make(chan trayCommand, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		dec := json.NewDecoder(bufio.NewReader(conn))
		for {
			var c trayCommand
			if err := dec.Decode(&c); err != nil {
				return
			}
			select {
			case cmds <- c:
			default:
			}
		}
	}()

	enc := json.NewEncoder(conn)
	var push trayPush
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	sendStatus := func() bool {
		st := statusOf(app.Status(), app.svc.Metrics().BlockedTotal())
		line, tip := push.changed(st.line(time.Now()), st.tooltip(time.Now()))
		if line == "" && tip == "" {
			return true
		}
		if err := enc.Encode(trayState{Status: line, Tooltip: tip}); err != nil {
			return false
		}
		return true
	}
	sendStatus()

	for {
		select {
		case err := <-waitErr:
			logx.Warnf("系统托盘助手退出: %v", err)
			return
		case <-done:
			logx.Infof("系统托盘助手已退出")
			return
		case <-ticker.C:
			if !sendStatus() {
				return
			}
		case c := <-cmds:
			switch c.Action {
			case "show":
				showWindow()
			case "start":
				if err := app.Start(); err != nil {
					logx.Errorf("托盘启动失败: %v", err)
				}
			case "stop":
				if err := app.Stop(); err != nil {
					logx.Errorf("托盘停止失败: %v", err)
				}
			case "reload":
				if err := app.Reload(); err != nil {
					logx.Warnf("托盘重载失败: %v", err)
				}
			case "quit":
				shutdown()
				return
			}
			sendStatus()
		}
	}
}

// RunTrayHelper 是桌面用户身份的托盘助手。它不读配置、不碰代理，
// 只显示菜单并通过 socket 把动作交给 root 面板。
func RunTrayHelper(socketPath string) error {
	if strings.TrimSpace(socketPath) == "" {
		return fmt.Errorf("--tray-helper 需要一个套接字路径")
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("连托盘桥: %w", err)
	}
	defer func() { _ = conn.Close() }()

	enc := json.NewEncoder(conn)
	send := func(action string) {
		if err := enc.Encode(trayCommand{Action: action}); err != nil {
			systray.Quit()
		}
	}
	dec := json.NewDecoder(bufio.NewReader(conn))
	closed := make(chan struct{})

	// 与 tray.go 同一份防御：助手退出时 systray 可能踩到无效 D-Bus 连接。
	defer func() {
		if r := recover(); r != nil {
			logx.Warnf("托盘助手退出时异常（已忽略）: %v", r)
		}
	}()

	systray.Run(func() {
		systray.SetIcon(appicon.Tray())
		systray.SetTitle("wps_app")
		systray.SetTooltip("wps_app — 正在读取状态")

		mStatus := systray.AddMenuItem("正在读取状态…", "代理当前状态")
		mStatus.Disable()
		systray.AddSeparator()
		mShow := systray.AddMenuItem("显示控制面板", "打开主窗口")
		systray.AddSeparator()
		mStart := systray.AddMenuItem("启动代理", "开始监听 SOCKS5/HTTP 入站")
		mStop := systray.AddMenuItem("停止代理", "关闭全部入站监听")
		mReload := systray.AddMenuItem("重载规则", "重新载入 GeoIP 与规则集")
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("退出", "停止代理并退出 wps_app")

		go func() {
			for {
				var st trayState
				if err := dec.Decode(&st); err != nil {
					close(closed)
					systray.Quit()
					return
				}
				if st.Status != "" {
					mStatus.SetTitle(st.Status)
				}
				if st.Tooltip != "" {
					systray.SetTooltip(st.Tooltip)
				}
			}
		}()

		go func() {
			for {
				select {
				case <-mShow.ClickedCh:
					send("show")
				case <-mStart.ClickedCh:
					send("start")
				case <-mStop.ClickedCh:
					send("stop")
				case <-mReload.ClickedCh:
					send("reload")
				case <-mQuit.ClickedCh:
					send("quit")
					systray.Quit()
					return
				case <-closed:
					return
				}
			}
		}()
	}, func() {
		logx.Infof("系统托盘助手已退出")
	})
	return nil
}

// trayDesktopUser 找发起 sudo 的桌面用户，并读它的 home/uid/gid。
func trayDesktopUser() (name, home string, uid, gid int, err error) {
	name = strings.TrimSpace(os.Getenv("SUDO_USER"))
	if name == "" || name == "root" {
		return "", "", 0, 0, fmt.Errorf("没有 SUDO_USER，判断不出桌面用户")
	}
	out, rerr := exec.Command("getent", "passwd", name).Output()
	if rerr != nil {
		return "", "", 0, 0, fmt.Errorf("查 %s 的 passwd 记录: %w", name, rerr)
	}
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 6 {
		return "", "", 0, 0, fmt.Errorf("passwd 里 %s 的记录不完整", name)
	}
	uid, err = strconv.Atoi(fields[2])
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("passwd 里 %s 的 uid 不是数字: %w", name, err)
	}
	gid, err = strconv.Atoi(fields[3])
	if err != nil {
		return "", "", 0, 0, fmt.Errorf("passwd 里 %s 的 gid 不是数字: %w", name, err)
	}
	return name, fields[5], uid, gid, nil
}
