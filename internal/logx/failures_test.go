package logx

import (
	"errors"
	"strings"
	"testing"
)

// TestNoteFailureReportsFirstThenAggregates 钉住降噪的核心行为。
//
// 现场形状：浏览器对一个打不开的站会重试几十次，而每次的原因里都带着不同的
// 超时毫秒数。逐条打出来的结果是一天 3.7 万行日志、其中 22139 行是同一条
// 消息（实测），真正有用的那几行被埋在中间。
//
// 期望：同一个键第一次打一条带完整原因的 WARN，之后只计数；
// FlushFailures 把计数汇总成一条。
func TestNoteFailureReportsFirstThenAggregates(t *testing.T) {
	ResetFailures()
	t.Cleanup(ResetFailures)
	buf, restore := capture(t)
	defer restore()
	setLevel(t, LevelWarn)

	key := "http CONNECT api.example:443"
	for i := 0; i < 30; i++ {
		first := NoteFailure(key, "节点不可用", errors.New("还需 28.88s 才重试"))
		if want := i == 0; first != want {
			t.Fatalf("第 %d 次 NoteFailure 返回 %v, want %v（只有第一条该打出来）", i+1, first, want)
		}
	}

	out := buf.String()
	if n := strings.Count(out, key); n != 1 {
		t.Fatalf("同一个键打了 %d 行，want 1（其余应当只计数）\n%s", n, out)
	}
	if !strings.Contains(out, "节点不可用") {
		t.Errorf("第一条没写原因类别: %s", out)
	}

	// 汇总之后应当出现"失败 30 次"这样一行。
	buf.Reset()
	FlushFailures()
	flushed := buf.String()
	if !strings.Contains(flushed, "30 次") {
		t.Fatalf("汇总里没有累计次数: %s", flushed)
	}
	if !strings.Contains(flushed, key) {
		t.Fatalf("汇总里没有那个键: %s", flushed)
	}

	// 再汇总一次不该重复报同一批（计数已经清零）。
	buf.Reset()
	FlushFailures()
	if s := buf.String(); strings.Contains(s, "30 次") {
		t.Fatalf("同一批被汇总了两次: %s", s)
	}
}

// TestFlushFailuresDropsQuietKeys 锁住"已经不失败了就别再报"。
//
// 没有这一条，一次断网会在之后每一分钟都留下一条"失败 N 次"，
// 而那时网络早就好了——那种日志会训练人忽略这张表。
func TestFlushFailuresDropsQuietKeys(t *testing.T) {
	ResetFailures()
	t.Cleanup(ResetFailures)
	setLevel(t, LevelWarn)

	NoteFailure("once.example", "超时", nil)

	failures.mu.Lock()
	e := failures.keys["once.example"]
	// 把它的 last 拨到窗口之外（等价于"这 60 秒里它一次都没再失败"）。
	e.last = e.last.Add(-2 * FlushFailureWindow)
	failures.mu.Unlock()

	FlushFailures()

	failures.mu.Lock()
	_, still := failures.keys["once.example"]
	failures.mu.Unlock()
	if still {
		t.Fatal("安静的键没有被忘掉：之后每一分钟都会为它写一行")
	}
}

// TestNoteFailureSeparatesKeys 确认不同目标不会被合成一条。
//
// 聚合的键必须是"哪个目标"，否则"所有站都在失败"和"某一个站失败 30 次"
// 会显示成同一件事——而它们的处置完全不同。
func TestNoteFailureSeparatesKeys(t *testing.T) {
	ResetFailures()
	t.Cleanup(ResetFailures)
	buf, restore := capture(t)
	defer restore()
	setLevel(t, LevelWarn)

	NoteFailure("a.example", "超时", nil)
	NoteFailure("b.example", "超时", nil)
	// 同键第二条只计数。
	NoteFailure("a.example", "超时", nil)

	out := buf.String()
	if !strings.Contains(out, "a.example") || !strings.Contains(out, "b.example") {
		t.Fatalf("两个不同的目标应当各有一条: %s", out)
	}
	if n := strings.Count(out, "a.example"); n != 1 {
		t.Fatalf("a.example 打了 %d 次，want 1", n)
	}
}
