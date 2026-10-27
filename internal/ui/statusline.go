package ui

// statusline.go 生成托盘那一行（和 tooltip）的文字。
//
// 为什么不直接写在 tray.go 里：tray.go 带 `//go:build gui`，默认构建下不参与编译，
// 也就永远不会被 `go test ./...` 跑到。逻辑放进带标签的文件里，等于把判断交给
// "哪天有人手动开一次面板"。这里把它拆出来，判据就能被测——
// 尤其是"没在运行"与"启动失败"必须是两句话这一条。

import (
	"fmt"
	"strings"
	"time"

	"wps_app/internal/service"
)

// trayStatus 是托盘状态行的一次读数。
// 只取需要的那几项，不传整个 Snapshot：托盘要的是"一眼看懂"，字段越多越没人看。
type trayStatus struct {
	Running    bool
	StartedAt  int64 // Unix 毫秒
	Mode       string
	Profile    string
	Blocked    uint64
	LastError  string
	Device     string // TUN 网卡名，空表示没起
	TUNRunning bool
}

func statusOf(snap service.Snapshot, blocked uint64) trayStatus {
	return trayStatus{
		Running:    snap.Running,
		StartedAt:  snap.StartedAt,
		Mode:       snap.Mode,
		Profile:    snap.ActiveProfile,
		Blocked:    blocked,
		LastError:  snap.LastError,
		Device:     snap.TUN.Device,
		TUNRunning: snap.TUN.Running,
	}
}

// line 是菜单里那一行禁用项的文字。now 由调用方给，是为了让"运行多久"可测。
func (s trayStatus) line(now time.Time) string {
	// 启动失败必须排在最前：那时 running=false，只写"已停止"就是把一次故障
	// 报成一个正常状态，而用户唯一的线索就是这一行。
	if s.LastError != "" {
		return "出错：" + truncate(s.LastError, 90)
	}
	if !s.Running {
		return fmt.Sprintf("已停止 · 累计拦截 %d", s.Blocked)
	}
	parts := []string{fmt.Sprintf("运行中 %s", uptime(now, s.StartedAt))}
	if s.Mode != "" {
		parts = append(parts, modeWord(s.Mode))
	}
	if s.Profile != "" {
		parts = append(parts, s.Profile)
	}
	if s.TUNRunning {
		parts = append(parts, "TUN "+s.Device)
	}
	parts = append(parts, fmt.Sprintf("拦截 %d", s.Blocked))
	return strings.Join(parts, " · ")
}

// tooltip 给只悬停一次的人：与那一行同源，不另编一套说法。
func (s trayStatus) tooltip(now time.Time) string {
	return "wps_app — " + s.line(now)
}

func uptime(now time.Time, startedAtMS int64) string {
	if startedAtMS <= 0 {
		return "?"
	}
	d := now.Sub(time.UnixMilli(startedAtMS))
	if d < 0 {
		return "0s"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func modeWord(m string) string {
	switch m {
	case "rule":
		return "规则"
	case "global":
		return "全局"
	case "direct":
		return "直连"
	default:
		// 认不出的模式原样报出来，不塌成"规则"：
		// 托盘说"规则"而实际是别的模式，用户会按规则去理解自己的流量。
		return m
	}
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// trayPush 决定"这一轮的托盘文字要不要真的推给通知器"。
//
// 为什么要单独拿出来：tray.go 带 `//go:build gui`，`go test ./...` 永远不碰它，
// 判断写在里面就等于没写。这里能测，tray.go 只负责"要不要动手"的结果。
//
// 实测（本机、GNOME 的 AppIndicator 宿主、面板正常运行时）：
// 每 2 秒无条件推一次，7 秒内收到 8 条 PropertiesChanged，
// 而连续三次的 ToolTip 内容 md5 完全相同——因为状态行里的"运行多久"是分钟粒度，
// 一分钟里那 30 次推送推的是同一个字符串。
// 一天下来是四万多条没人需要的总线消息，外加通知器跟着重画。
type trayPush struct {
	line    string
	tooltip string
}

// changed 返回这一轮真正需要写的两段文字；空串表示那一段和上次一样，别动。
// 两段分开判断：菜单行与 tooltip 内容不同，可能只有一个变了。
func (p *trayPush) changed(line, tooltip string) (string, string) {
	var dl, dt string
	if p.line != line {
		dl = line
		p.line = line
	}
	if p.tooltip != tooltip {
		dt = tooltip
		p.tooltip = tooltip
	}
	return dl, dt
}
