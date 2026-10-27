package ui

// 托盘状态行的判据。这段逻辑活在 tray.go 外面是有原因的：
// tray.go 带 `//go:build gui`，默认构建下不参与编译，写在里面的东西永远进不了
// `go test ./...`——那等于把判断交给"哪天有人手动开一次面板"。

import (
	"strings"
	"testing"
	"time"

	"wps_app/internal/service"
	"wps_app/internal/tunx"
)

func TestTrayStatusLine(t *testing.T) {
	now := time.Date(2026, 10, 17, 2, 0, 0, 0, time.Local)
	sevenMinAgo := now.Add(-7 * time.Minute).UnixMilli()

	cases := []struct {
		name string
		st   trayStatus
		want []string // 必须出现的片段
		not  []string // 绝不能出现的片段
	}{
		{
			name: "运行中",
			st:   trayStatus{Running: true, StartedAt: sevenMinAgo, Mode: "rule", Profile: "新加坡-1", Blocked: 3},
			want: []string{"运行中", "7m", "规则", "新加坡-1", "拦截 3"},
		},
		{
			name: "停止不是出错",
			st:   trayStatus{Running: false, Mode: "rule", Blocked: 0},
			want: []string{"已停止", "累计拦截 0"},
			not:  []string{"出错", "运行中"},
		},
		{
			// 这一条是整个状态行的重点：启动失败时 Running 也是 false。
			// 只写"已停止"就是把一次故障报成一个正常状态，而托盘往往是唯一看得见的那一行。
			name: "启动失败必须报成出错",
			st:   trayStatus{Running: false, Mode: "rule", LastError: "装配节点失败: 认证被拒"},
			want: []string{"出错", "认证被拒"},
			not:  []string{"已停止 ·"},
		},
		{
			name: "TUN 在跑就报网卡",
			st:   trayStatus{Running: true, StartedAt: now.Add(-2 * time.Hour).UnixMilli(), TUNRunning: true, Device: "wps-tun"},
			want: []string{"2h00m", "TUN wps-tun"},
		},
		{
			name: "认不出的模式原样报，不塌成规则",
			st:   trayStatus{Running: true, StartedAt: sevenMinAgo, Mode: "hybrid"},
			want: []string{"hybrid"},
			not:  []string{"规则"},
		},
		{
			name: "没记到启动时刻就承认不知道",
			st:   trayStatus{Running: true, StartedAt: 0},
			want: []string{"运行中 ?"},
		},
	}

	for _, c := range cases {
		got := c.st.line(now)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: 状态行 %q 里没有 %q", c.name, got, w)
			}
		}
		for _, n := range c.not {
			if strings.Contains(got, n) {
				t.Errorf("%s: 状态行 %q 不该出现 %q", c.name, got, n)
			}
		}
	}
}

func TestTrayTooltipSharesTheLine(t *testing.T) {
	now := time.Now()
	st := trayStatus{Running: true, StartedAt: now.Add(-90 * time.Second).UnixMilli(), Mode: "global", Blocked: 12}
	line, tip := st.line(now), st.tooltip(now)
	if !strings.HasPrefix(tip, "wps_app — ") || !strings.HasSuffix(tip, line) {
		t.Fatalf("tooltip 与状态行不同源，两处说法会分家: %q / %q", tip, line)
	}
}

// TestStatusOfReadsTheSnapshot 状态取自快照，不是取自界面以为的样子。
func TestStatusOfReadsTheSnapshot(t *testing.T) {
	snap := service.Snapshot{
		Running:       true,
		StartedAt:     1234,
		Mode:          "direct",
		ActiveProfile: "tokyo",
		LastError:     "上一次启动失败",
		TUN:           tunx.Status{Device: "wps-tun", Running: true},
	}
	st := statusOf(snap, 7)
	if st.Profile != "tokyo" || st.Mode != "direct" || st.Blocked != 7 || st.StartedAt != 1234 {
		t.Fatalf("快照没被照搬: %+v", st)
	}
	if !st.TUNRunning || st.Device != "wps-tun" || st.LastError == "" {
		t.Fatalf("TUN / 错误 这两项没带上: %+v", st)
	}
	// 出错优先：这条断言盯着上面那条判据在真实快照上同样成立。
	if line := st.line(time.Now()); !strings.HasPrefix(line, "出错：") {
		t.Fatalf("有 LastError 时状态行必须从出错开始: %q", line)
	}
}

// TestTrayPushOnlyOnChange 托盘只在文字真的变了时才推给通知器。
func TestTrayPushOnlyOnChange(t *testing.T) {
	var p trayPush
	// 第一次总是有内容：空串与"还没推过"必须是两回事，否则托盘永远不刷新。
	l, tp := p.changed("运行中 1分", "tip-1")
	if l != "运行中 1分" || tp != "tip-1" {
		t.Fatalf("第一次推送被吞了：%q / %q", l, tp)
	}
	// 同一分钟内的重复轮询：一个字都没变，两段都不该推。
	if l, tp := p.changed("运行中 1分", "tip-1"); l != "" || tp != "" {
		t.Errorf("没变化还推：line=%q tooltip=%q", l, tp)
	}
	// 只有菜单行变了（比如模式换了）：tooltip 不该跟着重发。
	if l, tp := p.changed("运行中 1分 · 规则", "tip-1"); l != "运行中 1分 · 规则" || tp != "" {
		t.Errorf("两段没分开判断：line=%q tooltip=%q", l, tp)
	}
	// 只有 tooltip 变了（比如累计拦截动了）：菜单行不该重发。
	if l, tp := p.changed("运行中 1分 · 规则", "tip-2"); l != "" || tp != "tip-2" {
		t.Errorf("两段没分开判断：line=%q tooltip=%q", l, tp)
	}
	// "" 被这条接口保留为"这段不用推"。它安全的前提是 line()/tooltip()
	// 永远不会产出空串——那由下面的 TestTrayLineIsNeverEmpty 钉住，
	// 不是靠人记得。
	var q trayPush
	if l, tp := q.changed("", ""); l != "" || tp != "" {
		t.Errorf("空内容不该被当成一次变化（那是「没东西可推」的意思）：%q / %q", l, tp)
	}
}

// TestTrayLineIsNeverEmpty 状态行在每一种读数下都必须有字。
//
// 这条不是洁癖：trayPush 用空串表达"这轮不用推"，而 tray.go 的调用方是
// `if dl != "" { SetTitle(dl) }`。哪天 line() 在某个分支上返回了空串，
// 那个状态就永远推不上通知器——托盘会停在上一句话上，
// 表现成"面板已经停了但托盘还写着运行中"。
func TestTrayLineIsNeverEmpty(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	cases := []trayStatus{
		{Running: true, StartedAt: now.Add(-time.Minute).UnixMilli(), Mode: "rule", Profile: "JP"},
		{Running: true, Mode: "", Profile: ""},                      // 启动时刻缺失、模式没读到
		{Running: false},                                            // 已停止
		{Running: false, LastError: "bind: address already in use"}, // 启动失败
		{Running: true, StartedAt: 0},                               // 零值时刻
		{Running: true, Mode: "weird-new-mode"},                     // 认不出的模式
		{Running: true, Blocked: 7, TUNRunning: true, Device: "wps-tun"},
	}
	for i, st := range cases {
		if got := st.line(now); got == "" {
			t.Errorf("第 %d 种读数的状态行是空的：%+v", i, st)
		}
		if got := st.tooltip(now); !strings.HasPrefix(got, "wps_app — ") || len(got) <= len("wps_app — ") {
			t.Errorf("第 %d 种读数的 tooltip 没有内容：%q", i, got)
		}
	}
}
