package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wps_app/internal/procid"
	"wps_app/internal/sysproxy"
)

// TestPrintLedgerNamesEachState 四种状态必须四种话。
//
// 这一行输出是用户在「桌面指着没人听的端口」时唯一能看到的解释，
// 把「读不懂」印成「没有记账」就等于告诉他一切正常。
func TestPrintLedgerNamesEachState(t *testing.T) {
	dir := t.TempDir()
	sp := sysproxy.StatePath(filepath.Join(dir, "config.yaml"))

	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(sp, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	render := func(st sysproxy.Status) string {
		t.Helper()
		var buf bytes.Buffer
		printLedger(&buf, sp, st, sysproxy.Config{HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891"})
		return buf.String()
	}
	// 桌面上正指着本程序的入站——孤儿状态的半个条件。
	ours := sysproxy.Status{Supported: true, Enabled: true, Mode: "manual",
		HTTP: "127.0.0.1:7892", HTTPS: "127.0.0.1:7892", SOCKS: "127.0.0.1:7891"}

	// 1. 没有记账
	if err := os.Remove(sp); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if out := render(sysproxy.Status{}); !strings.Contains(out, "没有记账") {
		t.Errorf("没有记账时应直说，实得:\n%s", out)
	}
	// 1b. 没有记账 + 桌面指着我们 = 孤儿，必须报警并给出路
	out := render(ours)
	if !strings.Contains(out, "没有记账") || !strings.Contains(out, "警告") ||
		!strings.Contains(out, "本进程退出时不会还原桌面") {
		t.Errorf("孤儿状态只说了「没有记账」，没说后果和出路:\n%s", out)
	}
	if !strings.Contains(out, "-sysproxy on") || !strings.Contains(out, sp) {
		t.Errorf("孤儿提示要能给用户照着做的命令和文件名:\n%s", out)
	}

	// 2. 宿主还活着（就是本测试进程，exe 也对得上）
	write(fmt.Sprintf(`{"pid":%d,"exe":%q,"backend":"gnome","mode":"none"}`, os.Getpid(), procid.Self()))
	out = render(ours)
	if !strings.Contains(out, "宿主还在，不会自动还原") {
		t.Errorf("宿主是本进程时应说不许抢，实得:\n%s", out)
	}
	if strings.Contains(out, "没有记账") || strings.Contains(out, "警告") {
		t.Errorf("有记账时不该报孤儿:\n%s", out)
	}

	// 3. 宿主没了 = 欠一次自愈
	write(fmt.Sprintf(`{"pid":%d,"exe":%q,"backend":"gnome","mode":"none","alreadyOurs":true}`, deadPID(t), procid.Self()))
	out = render(sysproxy.Status{})
	if !strings.Contains(out, "下次启动会自动还原") || !strings.Contains(out, "还原时直接关掉") {
		t.Errorf("欠还原时要说清下一步和还原语义，实得:\n%s", out)
	}

	// 4. 读不懂
	write(`{ this is not json`)
	out = render(sysproxy.Status{})
	if !strings.Contains(out, "读不懂") || strings.Contains(out, "没有记账") {
		t.Errorf("读不懂的记账不许被印成「没有记账」:\n%s", out)
	}
}

// deadPID 造一个确实已经不存在的进程号：起一个立刻退出的子进程并收尸。
// 不收尸的话它是僵尸，kill(pid, 0) 仍会成功，判活结果就成了假的。
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("起 sleep 失败: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Logf("sleep 0 退出码非零（不影响用例）: %v", err)
	}
	return pid
}
