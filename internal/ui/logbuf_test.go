// 日志缓冲的"内存有界"判据（README §10 里那句"日志页开一天不会把内存吃掉"靠这里撑着）。
//
// 槽位数封顶不等于内存封顶：一条超长的日志（错误原文、远端应答、
// YAML 类型错误里被原样引出的那个标量）会常驻在缓冲里，
// 而且面板每秒拉一次时它都在那一页里再过一遍桥。
// 所以这里盯两件事：单条的长度上限，以及"拉一次"这个动作本身的分配量。
package ui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"wps_app/internal/logx"
)

func TestLogBufferClipsHugeMessage(t *testing.T) {
	b := newLogBuffer(8)
	huge := strings.Repeat("错误原文", 40000) // 480 KB：四个汉字 12 字节
	b.add(logx.LevelError, huge, time.Now())

	got := b.page(0).Entries[0].Msg
	if len(got) > logMsgLimit+80 {
		t.Errorf("截完之后还有 %d 字节，上限是 %d 再加一句标记", len(got), logMsgLimit)
	}
	if !strings.HasPrefix(got, "错误原文") {
		t.Error("开头被丢了：截断要留的是能认出是什么事的那一段")
	}
	if !strings.Contains(got, "本条原文 480000 字节") {
		t.Errorf("尾巴上没写清原长，读的人会以为这条日志本来就这么短: %s", got[len(got)-60:])
	}
	// 截在 UTF-8 中间会留下残缺字节：前端渲染成一个替换字符，
	// 而这一串是给人排查错误用的。
	if !utf8.ValidString(got) {
		t.Error("截断了 UTF-8 字符，结果不是一个合法字符串")
	}

	// 没超限的一条要原样过去，一个字符都不许多截。
	short := "规则已加载: ./assets/rules.txt"
	b2 := newLogBuffer(4)
	b2.add(logx.LevelInfo, short, time.Now())
	if got2 := b2.page(0).Entries[0].Msg; got2 != short {
		t.Errorf("短消息被动过: %q", got2)
	}
}

// TestLogBufferStaysBounded 把缓冲灌到容量的五十倍，看总字节有没有停在一个界上。
func TestLogBufferStaysBounded(t *testing.T) {
	const capN = 16
	b := newLogBuffer(capN)
	long := strings.Repeat("x", logMsgLimit*3)
	for i := 0; i < capN*50; i++ {
		// 交替喂长短两种：只喂一种的话，"最坏那一档"就没被压到。
		if i%2 == 0 {
			b.add(logx.LevelWarn, long, time.Now())
			continue
		}
		b.add(logx.LevelInfo, "短的一条", time.Now())
	}
	p := b.page(0)
	if len(p.Entries) != capN {
		t.Fatalf("缓冲里剩 %d 条，容量是 %d", len(p.Entries), capN)
	}
	if p.Entries[capN-1].Seq != int64(capN*50) {
		t.Errorf("最新一条是 Seq %d，应该是最后写进去的 %d", p.Entries[capN-1].Seq, capN*50)
	}
	total := 0
	for _, e := range p.Entries {
		total += len(e.Msg) + len(e.Time) + len(e.Level)
	}
	// 上限 = 槽位数 ×（单条上限 + 那句标记 + 时间/级别），留一点余量。
	if lim := capN * (logMsgLimit + 128); total > lim {
		t.Errorf("灌了 %d 条之后缓冲里还有 %d 字节，上限该是 %d", capN*50, total, lim)
	}
}

// TestLogBufferPageAllocations 盯的是"面板每秒拉一次"这个动作本身。
//
// 断的是字节而不是次数：按容量预分配只多一次分配，但那是每轮 64 KB 的垃圾，
// 数分配次数看不出来。稳态（只有几条新日志）下这一轮该花的字节是几百量级。
func TestLogBufferPageAllocations(t *testing.T) {
	b := newLogBuffer(logCapacity)
	for i := 0; i < logCapacity; i++ {
		b.add(logx.LevelInfo, "转发 127.0.0.1:50000 -> demo.example.com:443 (PROXY)", time.Now())
	}
	// 游标停在"只剩 3 条没读"的位置：这就是面板稳态那一秒的样子。
	latest := b.page(0).Latest - 3
	for i := 0; i < 3; i++ {
		b.add(logx.LevelInfo, "新的一条", time.Now())
	}

	res := testing.Benchmark(func(mb *testing.B) {
		mb.ReportAllocs()
		for i := 0; i < mb.N; i++ {
			if p := b.page(latest); len(p.Entries) == 0 {
				mb.Fatal("稳态下应该还能拉到那 3 条")
			}
		}
	})
	if got := res.AllocedBytesPerOp(); got > 4096 {
		t.Errorf("稳态拉一次分配了 %d B：按容量预分配就是每轮白造一个 1000 槽的切片", got)
	}
}
