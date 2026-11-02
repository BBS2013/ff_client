package diag

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"wps_app/internal/tunx"
)

// 这份文件管的是「点开 TUN 之前，报告能不能替你把话说完」。
//
// 2026-10-29 那次故障里，面板与 `tun.helper` 那个文件说的不是同一版协议，
// 而这件事只有真的点一次开关、被 root 拒一次之后才会出现在日志上。
// 报告可以更早问出来：以普通用户身份跑一次那个文件的 `-version`，
// 它自报几个协议、和本程序对不对得上、对不上该动哪一边。

// helperConfig 写一份带 tun.helper 的配置。helper 指向调用方给的那个可执行文件。
func helperConfig(t *testing.T, helperPath string) string {
	t.Helper()
	body := "mode: rule\n" +
		"inbounds:\n  - type: socks5\n    listen: 127.0.0.1:17891\n" +
		"proxies:\n  - name: a\n    server:\n      type: hysteria2\n      addr: 192.0.2.1:443\n      auth: x\n" +
		"active: a\n" +
		"tun:\n  enable: true\n  device: " + diagDevice + "\n  address: 172.19.0.1/30\n" +
		"  dns: 172.19.0.2\n  fake_ip_range: 198.18.0.0/15\n" +
		"  hijack_dns: false\n  strict_route: false\n" +
		"  helper:\n    - " + helperPath + "\n    - --tun-helper\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// selfReportingHelper 造一个会自报协议号的假 helper。
func selfReportingHelper(t *testing.T, proto string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wps_app")
	script := "#!/bin/sh\necho \"wps_app fixture\"\necho \"提权协议 " + proto + "\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDiagNamesHelperProtoAndRemedy(t *testing.T) {
	// 对面比本程序**新**：这就是故障当天的形状——面板还是提交版构建（协议 1），
	// 而磁盘上那个文件已经被 make build-gui 刷成了新的。处方是重启面板。
	newer := selfReportingHelper(t, strconv.Itoa(tunx.HelperProto()+3))
	report := diagReport(t, helperConfig(t, newer))
	line := mustLineFor(t, report, "它自报提权协议")
	if !strings.Contains(line, "重启面板") {
		t.Errorf("对面更新时该建议重启面板，报告却只说: %q", line)
	}
	if !strings.Contains(line, newer) {
		t.Errorf("报告要指名那个文件，用户才知道要动什么: %q", line)
	}

	// 反方向：装在磁盘上的还是老构建。处方必须是重新构建，不是重启面板。
	older := selfReportingHelper(t, "1")
	report = diagReport(t, helperConfig(t, older))
	line = mustLineFor(t, report, "它自报提权协议")
	if !strings.Contains(line, "make build-gui") || strings.Contains(line, "重启面板") {
		t.Errorf("对面更旧时该建议刷新那个文件: %q", line)
	}

	// 对面和本程序一致：要说「一致」，不能含糊过去。
	same := selfReportingHelper(t, strconv.Itoa(tunx.HelperProto()))
	report = diagReport(t, helperConfig(t, same))
	if !strings.Contains(report, "与本程序一致") {
		t.Errorf("协议一致时报告要说一致:\n%s", report)
	}

	// 问不出来时必须说「读不到」，并且不许顺手宣布版本不对：
	// 把读不到当成版本不对，报告就会劝用户去做一次根本没必要的重装。
	report = diagReport(t, helperConfig(t, "/nonexistent/wps_app-not-here"))
	line = mustLineFor(t, report, "读不到它自报的提权协议")
	if strings.Contains(line, "重启面板") || strings.Contains(line, "make build-gui") {
		t.Errorf("没读到证据却给出了处方: %q", line)
	}
}

func TestDiagHelperWithoutConfigStaysSilentOnProto(t *testing.T) {
	// 没配 helper 的那一份报告不该出现「自报协议」那一行——
	// 它连要问谁都不知道，硬印一行只会让人以为有什么东西坏了。
	report := diagReport(t, diagConfig(t, false))
	if strings.Contains(report, "自报提权协议") {
		t.Errorf("没配 helper 却报了 helper 的协议:\n%s", report)
	}
	mustLineFor(t, report, "没配 tun.helper")
}
