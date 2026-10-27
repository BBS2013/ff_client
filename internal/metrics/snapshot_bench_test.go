package metrics

// 面板每 1 秒问一次 Traffic()，而它就是 Registry.Snapshot()
// （`internal/ui/app.go` 的 `App.Traffic` 直接返回这个结构，Wails 把它 JSON 化）。
// 这一格值得单独量，理由和规则页那条一样但更硬：规则页 5 秒一次，
// 这一页一秒一次，而且它**持着 r.mu 做全部拷贝与排序**——
// 快照期间 Begin/End 全都排队等着，也就是"面板读得慢"会直接变成"代理记账慢"。
//
// 数字是判"要不要动"的依据，不是待办清单：量出来够用就写清够用。
//
// go test -bench BenchmarkSnapshot -benchtime 200x ./internal/metrics/

import (
	"encoding/json"
	"fmt"
	"testing"

	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// fill 把注册表灌成一台忙机器跑了几分钟之后的样子：
// 活跃连接贴着面板实测那一档，历史与速率序列都装到环形缓冲的上限。
func fill(b testing.TB, active, hist, series int) *Registry {
	b.Helper()
	r := NewRegistry(hist, series)
	// 历史：Begin 完立刻 End，环形缓冲会被填满到 hist。
	for i := 0; i < hist+active; i++ {
		c := r.Begin("socks5", fmt.Sprintf("127.0.0.1:%d", 4000+i), router.Result{
			Host: fmt.Sprintf("site%d.example.com", i), Port: "443",
			Policy: outbound.PolicyProxy, Matched: "FINAL", Node: "JP",
		})
		c.Up.Add(uint64(i * 4096))
		c.Down.Add(uint64(i * 65536))
		if i < hist {
			r.End(c)
		} else {
			// 剩下的留在 active 里，就是"此刻还在跑的那些"。
			r.active[c.ID] = c
		}
	}
	// 速率序列：采样点靠 sample() 自己填，不绕过它造数组，
	// 否则量到的不是真实形状（环形缓冲的搬运路径也在锁内）。
	for i := 0; i < series; i++ {
		r.sample()
	}
	return r
}

func BenchmarkSnapshotBusy(b *testing.B) {
	r := fill(b, 300, 500, 900)
	snap := r.Snapshot()
	b.ReportAllocs()
	b.Logf("形状: active=%d history=%d series=%d", len(snap.Active), len(snap.History), len(snap.Series))
	for b.Loop() {
		_ = r.Snapshot()
	}
}

// BenchmarkSnapshotIdle 是绝大多数时间的真实情况：没在跑什么连接。
// 两条摆一起才看得出"空闲时很便宜"不等于"忙时也很便宜"。
func BenchmarkSnapshotIdle(b *testing.B) {
	r := NewRegistry(500, 900)
	for b.Loop() {
		_ = r.Snapshot()
	}
}

// TestSnapshotPayloadBudget 把"每秒过一遍桥的那坨字节"变成常驻断言。
//
// 时延在这台机器上只能断倍率（旁边随时可能跑着另一个 go test），
// 但字节数是**给定了形状就完全确定**的，所以这一格可以断绝对值，
// 也就能在 -race 下照跑——它不量时间。
//
// 为什么要盯这个数：面板的"每秒刷一次"手感就是
// 后端拷贝 + 桥的 JSON + 浏览器 parse 三段之和，前一段有上面的基准，
// 后一段没有别的办法观测。真出事的那一类改动是往 ConnView/Sample 里
// 加一个长字段（比如每条连接挂一份完整证书链），它不会让上面的 ns/op
// 跳一个量级，但会让每秒的载荷翻倍——然后浏览器先卡。
func TestSnapshotPayloadBudget(t *testing.T) {
	// 形状与 BenchmarkSnapshotBusy 一致：活跃连接贴着 ?demo=big 实测那一档，
	// 历史与速率序列都填满环形缓冲上限（面板默认 histCap=500、seriesCap=900）。
	r := fill(t, 300, 500, 900)
	snap := r.Snapshot()

	total, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("快照 JSON 化失败: %v", err)
	}
	// 分段只为了失败时能一眼指出是哪一段长出来的，不参与断言。
	for _, part := range []struct {
		name  string
		value any
	}{{"history", snap.History}, {"active", snap.Active}, {"series", snap.Series}} {
		raw, err := json.Marshal(part.value)
		if err != nil {
			t.Fatalf("%s 段 JSON 化失败: %v", part.name, err)
		}
		t.Logf("%-8s %7d B (%.1f%%)", part.name, len(raw), 100*float64(len(raw))/float64(len(total)))
	}

	// 实测 ~232KB，预算 1MB（约 4.4 倍）：只拦"长一个量级"的改动，
	// 加一个短字段这种正常演化不该要求改这个数。
	const budget = 1 << 20
	t.Logf("整份载荷 %d B / %d 行活跃 + %d 行历史 + %d 个采样点", len(total), len(snap.Active), len(snap.History), len(snap.Series))
	if len(total) > budget {
		t.Errorf("每秒轮询的载荷长到 %d B，超过 %d B 预算：流量页是一秒问一次，"+
			"这个数是要被浏览器整个 parse 一遍的。要么瘦身，要么改增量快照，"+
			"要么就带着理由把预算一起改掉（见 README §9.3）。", len(total), budget)
	}
}
