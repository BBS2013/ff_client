package logx

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// capture 把全局输出换成 buffer，返回取回内容的函数与恢复函数。
func capture(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	mu.Lock()
	old := output
	buf := &bytes.Buffer{}
	output = buf
	mu.Unlock()
	return buf, func() {
		mu.Lock()
		output = old
		mu.Unlock()
	}
}

// setLevel 临时改级别，t.Cleanup 里恢复。
func setLevel(t *testing.T, l Level) {
	t.Helper()
	old := LevelNow()
	SetLevel(l)
	t.Cleanup(func() { SetLevel(old) })
}

func TestHookReceivesFormattedLine(t *testing.T) {
	buf, restore := capture(t)
	defer restore()
	setLevel(t, LevelDebug)

	type rec struct {
		l   Level
		msg string
		t   time.Time
	}
	got := make(chan rec, 4)
	remove := AddHook(func(l Level, msg string, at time.Time) {
		got <- rec{l, msg, at}
	})
	defer remove()

	before := time.Now()
	Infof("hello %s %d", "world", 42)
	after := time.Now()

	r := <-got
	if r.l != LevelInfo {
		t.Fatalf("级别 = %v, 期望 INFO", r.l)
	}
	if r.msg != "hello world 42" {
		t.Fatalf("消息 = %q, 期望 %q", r.msg, "hello world 42")
	}
	if r.t.Before(before) || r.t.After(after) {
		t.Fatalf("时间戳 %v 不在 [%v, %v] 区间内", r.t, before, after)
	}
	// 钩子是旁路订阅：文件/标准输出照旧。
	if !strings.Contains(buf.String(), "hello world 42") {
		t.Fatalf("原有输出应保持不变，实际 %q", buf.String())
	}
}

func TestHookRespectsLevelFilter(t *testing.T) {
	_, restore := capture(t)
	defer restore()
	setLevel(t, LevelWarn)

	got := make(chan string, 4)
	remove := AddHook(func(l Level, msg string, _ time.Time) { got <- msg })
	defer remove()

	Infof("不该被看到")
	Warnf("该被看到")

	select {
	case m := <-got:
		if m != "该被看到" {
			t.Fatalf("低于级别的日志不应触发钩子，却收到 %q", m)
		}
	case <-time.After(time.Second):
		t.Fatal("钩子没有收到 WARN 日志")
	}
	if len(got) != 0 {
		t.Fatalf("多余投递: %d", len(got))
	}
}

func TestAddHookRemove(t *testing.T) {
	_, restore := capture(t)
	defer restore()
	setLevel(t, LevelDebug)

	var mu2 sync.Mutex
	var n int
	remove := AddHook(func(Level, string, time.Time) {
		mu2.Lock()
		n++
		mu2.Unlock()
	})

	Infof("第一条")
	remove()
	Infof("第二条")
	remove() // 重复注销应无副作用
	Infof("第三条")

	mu2.Lock()
	defer mu2.Unlock()
	if n != 1 {
		t.Fatalf("注销后不应再收到钩子，实际收到 %d 条", n)
	}
}

func TestAddHookSameFuncTwice(t *testing.T) {
	_, restore := capture(t)
	defer restore()
	setLevel(t, LevelDebug)

	var mu2 sync.Mutex
	var n int
	h := func(Level, string, time.Time) {
		mu2.Lock()
		n++
		mu2.Unlock()
	}
	removeA := AddHook(h)
	removeB := AddHook(h)
	defer removeB()

	Infof("两次注册都该收到")
	removeA()
	Infof("只应剩一个")

	mu2.Lock()
	defer mu2.Unlock()
	if n != 3 {
		t.Fatalf("按 ID 注销应只摘掉一个，实际收到 %d 条（期望 3）", n)
	}
}

// TestHookCanLog 锁住「钩子在锁外调用」这一约束：钩子自己再打一条日志是 UI 侧的常态，
// 持锁调用会直接自锁死。
func TestHookCanLog(t *testing.T) {
	_, restore := capture(t)
	defer restore()
	setLevel(t, LevelDebug)

	depth := 0
	var mu2 sync.Mutex
	remove := AddHook(func(l Level, _ string, _ time.Time) {
		mu2.Lock()
		if depth > 0 {
			mu2.Unlock()
			return // 第二层不再递归，避免无限打转
		}
		depth++
		mu2.Unlock()
		Infof("钩子里再打一条")
	})
	defer remove()

	done := make(chan struct{})
	go func() {
		defer close(done)
		Infof("触发钩子")
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("钩子内调用 Infof 死锁了")
	}
}

func TestHookPanicIsContained(t *testing.T) {
	buf, restore := capture(t)
	defer restore()
	setLevel(t, LevelDebug)

	remove := AddHook(func(Level, string, time.Time) { panic("boom") })
	defer remove()

	// 不应 panic；日志调用方必须活着把这条写完。
	Infof("钩子炸了也要写完")
	if !strings.Contains(buf.String(), "钩子炸了也要写完") {
		t.Fatalf("日志应照常写出，实际 %q", buf.String())
	}
}

func TestAddHookNilIsNoop(t *testing.T) {
	_, restore := capture(t)
	defer restore()
	setLevel(t, LevelDebug)

	remove := AddHook(nil)
	defer remove()
	Infof("不该有问题")
}

// TestHookConcurrent 验证并发打日志时钩子与输出都不会炸。
func TestHookConcurrent(t *testing.T) {
	_, restore := capture(t)
	defer restore()
	setLevel(t, LevelDebug)

	var wg sync.WaitGroup
	var mu2 sync.Mutex
	got := 0
	remove := AddHook(func(Level, string, time.Time) {
		mu2.Lock()
		got++
		mu2.Unlock()
	})
	defer remove()

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				Infof("并发 %d-%d", i, j)
			}
		}(i)
	}
	wg.Wait()

	mu2.Lock()
	defer mu2.Unlock()
	if got != 400 {
		t.Fatalf("钩子应收到 400 条，实际 %d", got)
	}
}

// TestLogSanitizesControlCharacters 锁住日志注入：
// 消息里混着大量外部可控文本（SOCKS5 客户端自报的域名、节点名、
// HTTP 请求里的任意字节）。不洗控制字符的话，一个恶意客户端就能靠
// 换行伪造日志行、靠 ANSI 转义序列操纵终端与面板。
func TestLogSanitizesControlCharacters(t *testing.T) {
	buf, restore := capture(t)
	defer restore()

	Infof("socks5 1.2.3.4 -> %s", "evil.example\n2026-01-01 00:00:00 [INFO] 已启动\r\n\x1b[2J\x1b[1;1H")
	got := buf.String()

	if strings.Count(got, "\n") != 1 {
		t.Fatalf("一条日志必须严格占一行，实际:\n%q", got)
	}
	for _, banned := range []string{"\r", "\x1b"} {
		if strings.Contains(got, banned) {
			t.Errorf("输出里残留了控制字符 %q:\n%q", banned, got)
		}
	}
	// 原始内容仍要可辨认，不能被抹掉。
	if !strings.Contains(got, "evil.example") {
		t.Errorf("可见内容丢失:\n%q", got)
	}
	if !strings.Contains(got, `\n`) {
		t.Errorf("换行应转成可见的 \\n:\n%q", got)
	}
}

// TestSanitizeKeepsOrdinaryText 确认正常日志（含中文与制表符）不被破坏。
func TestSanitizeKeepsOrdinaryText(t *testing.T) {
	in := "http CONNECT api2.cursor.sh [PROXY | DOMAIN-SUFFIX,cursor.sh]\t耗时 3ms"
	if got := sanitize(in); got != in {
		t.Fatalf("普通文本被改动了:\n得到 %q\n期望 %q", got, in)
	}
}

// TestSanitizeEscapesInvisibleAndDirectional 覆盖零宽与双向控制字符。
func TestSanitizeEscapesInvisibleAndDirectional(t *testing.T) {
	for _, in := range []string{"a\x00b", "a\x7fb", "a\u200bb", "a\u202eb", "a\u009bb"} {
		got := sanitize(in)
		if got == in {
			t.Errorf("%q 应被转义，实际原样返回", in)
		}
		if strings.ContainsAny(got, "\x00\x7b\u200b\u202e\u009b") {
			t.Errorf("%q 未被完全转义，得到 %q", in, got)
		}
	}
}
