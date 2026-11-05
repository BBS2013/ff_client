package ui

import (
	"strings"
	"testing"
	"time"

	"wps_app/internal/logx"
)

// TestLogsAPIMasksRealtime：LogStream 走 Logs()，必须和导出一样掩掉口令与 URL token。
func TestLogsAPIMasksRealtime(t *testing.T) {
	cfg := writeCfg(t, sampleCfg)
	app := New(cfg)
	defer app.Close()

	// 走缓冲写入路径（与 hook 相同），不用全局 logx，避免并行用例把别家的行灌进本缓冲。
	app.logs.add(logx.LevelError,
		"拨号失败时把口令 pw123 原样回显了，订阅 https://sub.example.com/KEY?token=TOPSECRET 拉不下来",
		time.Now())
	app.logs.add(logx.LevelInfo, "普通的一条正文", time.Now())

	page := app.Logs(0)
	if len(page.Entries) < 2 {
		t.Fatalf("缓冲里应有 hook 写入的条目，实得 %d 条", len(page.Entries))
	}
	var body strings.Builder
	for _, e := range page.Entries {
		body.WriteString(e.Msg)
		body.WriteByte('\n')
	}
	text := body.String()
	for _, leak := range []string{"s3cret", "pw123", "TOPSECRET"} {
		if strings.Contains(text, leak) {
			t.Errorf("Logs 实时路径仍含敏感串 %q:\n%s", leak, text)
		}
	}
	if !strings.Contains(text, "普通的一条正文") {
		t.Error("掩码把正常正文吃掉了")
	}
}
