package ui

// 「导出日志」这一格的判据。
//
// 这一份文件天生就是要发给别人的，所以它和诊断报告共用同一套掩码；
// 但它比报告多一层敏感：里面是本机访问过的域名。
// 于是这里盯的三件事分别是——口令不许在里面、"这不是全部历史"必须在里面、权限必须是 0600。
// 少任何一条，这份文件都会被当成一份完整的、可以放心贴出去的记录来用。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wps_app/internal/logx"
)

func TestExportLogsMasksAndHeaders(t *testing.T) {
	cfg := writeCfg(t, sampleCfg)
	app := New(cfg)
	defer app.Close()

	app.logs.add(logx.LevelError,
		"拨号失败时把口令 pw123 原样回显了，订阅 https://sub.example.com/KEY?token=TOPSECRET 拉不下来",
		time.Now())
	app.logs.add(logx.LevelInfo, "普通的一条正文", time.Now())
	want := len(app.logs.page(0).Entries)

	path, err := app.ExportLogs()
	if err != nil {
		t.Fatalf("ExportLogs: %v", err)
	}
	if filepath.Base(path) != logFileName {
		t.Errorf("落点不对: %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, leak := range []string{"s3cret", "pw123", "TOPSECRET"} {
		if strings.Contains(text, leak) {
			t.Errorf("导出里留着口令原文 %q", leak)
		}
	}
	if !strings.Contains(text, "普通的一条正文") {
		t.Error("正文丢了：掩码把整份文件吃掉了")
	}
	if !strings.Contains(text, fmt.Sprintf("共 %d 条", want)) {
		t.Errorf("条数前言不对（这一轮缓冲里有 %d 条）:\n%s", want, firstLines(text, 6))
	}
	for _, need := range []string{"上限 1000 条", "已截断", "token", "浏览记录"} {
		if !strings.Contains(text, need) {
			t.Errorf("前言里少了 %q 这一句——它决定了这份文件会被怎么使用", need)
		}
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("权限是 %o，这份文件里有访问过的域名，该是 0600", perm)
	}
}

// TestExportLogsRespectsRingCap：灌三倍容量，导出的必须正好停在容量上，
// 而且留下的是最新的那一段——否则"共 N 条"这句话就是在骗人。
func TestExportLogsRespectsRingCap(t *testing.T) {
	cfg := writeCfg(t, sampleCfg)
	app := New(cfg)
	defer app.Close()

	for i := 0; i < logCapacity*3; i++ {
		app.logs.add(logx.LevelInfo, fmt.Sprintf("第 %d 条", i), time.Now())
	}
	path, err := app.ExportLogs()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if n := len(app.logs.page(0).Entries); n != logCapacity {
		t.Fatalf("缓冲里剩 %d 条，容量是 %d", n, logCapacity)
	}
	if !strings.Contains(text, fmt.Sprintf("共 %d 条", logCapacity)) {
		t.Errorf("前言里的条数不是容量:\n%s", firstLines(text, 6))
	}
	if strings.Contains(text, "第 0 条\n") {
		t.Error("最老的那一条还在文件里：环形缓冲的覆盖没生效")
	}
	if !strings.Contains(text, fmt.Sprintf("第 %d 条", logCapacity*3-1)) {
		t.Error("最新那一条不在文件里")
	}
}

func firstLines(text string, n int) string {
	parts := strings.Split(text, "\n")
	if len(parts) > n {
		parts = parts[:n]
	}
	return strings.Join(parts, "\n")
}
