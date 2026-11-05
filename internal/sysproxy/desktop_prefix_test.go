// 「写成功」不等于「桌面真的被改了」。
//
// 2026-11-05 这台机器上的现场：面板以 root 跑，gsettings 是用
// `sudo -n -u <用户> gsettings` 发出去的。sudo 默认 env_reset 把
// DBUS_SESSION_BUS_ADDRESS 丢了，于是 gsettings 拿不到桌面会话总线，
// 写进了 dconf 的兜底影子库 ~/.cache/dconf/user —— 退出码 0，桌面纹丝不动。
// 面板读回时读的是同一个影子库，读到 none，于是开关点开就自己弹回关闭，
// 而日志里只有一句"总开关开启"。
//
// 这里钉住两件事：前缀必须把总线地址带进 sudo 之内；写完读不回桌面时，
// 面板不许报成功。
package sysproxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDesktopPrefixCarriesBusInsideSudo 钉住"总线地址在 sudo 之内"。
//
// 放在 env 里（也就是只交给子进程的环境）是不够的：sudo 的 env_reset
// 会把它丢掉，gsettings 于是落进影子库，写"成功"而桌面没变。
func TestDesktopPrefixCarriesBusInsideSudo(t *testing.T) {
	bus := filepath.Join(t.TempDir(), "bus")
	if err := os.WriteFile(bus, nil, 0o600); err != nil {
		t.Fatalf("造总线文件: %v", err)
	}

	args, env := desktopPrefixAs("chery", 1000, bus)
	if len(args) == 0 {
		t.Fatal("总线在就该给出前缀")
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "env") {
		t.Fatalf("总线地址必须由 env 在 sudo 之内设上：%v", args)
	}
	if !strings.Contains(joined, "DBUS_SESSION_BUS_ADDRESS=unix:path="+bus) {
		t.Fatalf("前缀里没有总线地址：%v", args)
	}
	if !strings.Contains(joined, "XDG_RUNTIME_DIR=/run/user/1000") {
		t.Fatalf("前缀里没有运行目录（systemctl --user 与 dconf 都要它）：%v", args)
	}
	if env != nil {
		t.Fatalf("环境变量不该再交给子进程的环境，sudo 会 reset 掉：%v", env)
	}
}

// TestDesktopPrefixWithoutBus 覆盖没有会话总线的那台机器：没有总线就没有前缀，
// 命令按本进程的身份跑，别去 sudo 到一个连不上总线的用户身上。
func TestDesktopPrefixWithoutBus(t *testing.T) {
	args, env := desktopPrefixAs("chery", 1000, filepath.Join(t.TempDir(), "no-such-bus"))
	if len(args) != 0 || env != nil {
		t.Fatalf("没有总线就不该有前缀，实际 %v %v", args, env)
	}
}
