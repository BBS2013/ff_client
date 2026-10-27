package ui

import (
	"fmt"
	"sync"
	"time"

	"wps_app/internal/logx"
)

// logCapacity 是日志环形缓冲的槽位数。1000 条足够在高频 DEBUG 下覆盖几分钟，
// 又不至于让前端每次轮询都拉一大坨。
const logCapacity = 1000

// logMsgLimit 是**一条**日志的字节上限。
//
// 槽位数封顶不等于内存封顶：消息是从错误原文、远端应答、配置文件内容里来的，
// 长度不由我们决定，而一条超长的日志会常驻在缓冲里、每秒再经桥面发给面板一遍
// （YAML 的类型错误会把出错的那个标量原样引出来，那可能就是几百 KB）。
// 截到 8 KiB 是"够读出是什么事"与"别拿它当文件传输"之间的一档。
// 尾巴上写明原长——静默截断会让一条日志看起来就是那么短，
// 而"这行被截过"本身就是排查时要知道的事。
const logMsgLimit = 8192

func clipMsg(msg string) string {
	if len(msg) <= logMsgLimit {
		return msg
	}
	kept := logx.Clip(msg, logMsgLimit)
	return kept + fmt.Sprintf(" …（本条原文 %d 字节，已截断）", len(msg))
}

// LogEntry 是一条已格式化的日志，字段全为普通值，便于经 Wails 送给前端。
type LogEntry struct {
	Seq   int64  `json:"seq"`
	Time  string `json:"time"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// LogPage 是按序号增量拉取的结果。
type LogPage struct {
	Entries []LogEntry `json:"entries"`
	// Latest 是缓冲里已分配的最大序号，前端下次带着它来拉增量。
	Latest int64 `json:"latest"`
	// Truncated 表示 after 之前的数据已经被环形缓冲覆盖，
	// Entries 是当前还能拿到的最老的一段，前端应当整表替换而不是追加。
	Truncated bool `json:"truncated"`
}

// logBuffer 是固定容量的环形缓冲，接住 logx.AddHook 抄过来的日志。
//
// 前端每秒带上次收到的最大 Seq 来拉一次，因此这里只需要返回更大的序号；
// 绕回覆盖是正常现象，靠 Truncated 明确告知，而不是假装数据连续。
type logBuffer struct {
	mu      sync.Mutex
	entries []LogEntry // 固定长度，按写入顺序循环覆盖
	next    int        // 下一次写入的槽位；entries[next] 同时也是最老的一条
	seq     int64      // 已分配的最大序号
}

func newLogBuffer(capacity int) *logBuffer {
	if capacity <= 0 {
		capacity = logCapacity
	}
	return &logBuffer{entries: make([]LogEntry, capacity)}
}

// add 追加一条日志。序号从 1 开始，前端用 0 表示「从头给我」。
func (b *logBuffer) add(level logx.Level, msg string, at time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	b.entries[b.next] = LogEntry{
		Seq:   b.seq,
		Time:  at.Format("15:04:05"),
		Level: level.String(),
		Msg:   clipMsg(msg),
	}
	b.next = (b.next + 1) % len(b.entries)
}

// page 返回 Seq 大于 after 的条目，按时间正序。after <= 0 表示要全部。
func (b *logBuffer) page(after int64) LogPage {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 先数一遍再分配。按容量预分配会坑在稳态：面板每秒拉一次，
	// 而绝大多数时候只有个位数新行——那样每轮都白造一个 1000 槽的切片
	// （LogEntry 是四个字符串 ≈ 64 B，也就是每轮 64 KB 的垃圾，
	// 一天五百多 MB 的分配全花在"几乎没有新日志"的那几十轮上）。
	// 两遍扫的都是内存里的固定数组，换来的是每次刚好够用的分配。
	n := 0
	for i := 0; i < len(b.entries); i++ {
		if e := b.entries[(b.next+i)%len(b.entries)]; e.Seq > after && e.Seq != 0 {
			n++
		}
	}
	out := make([]LogEntry, 0, n)
	for i := 0; i < len(b.entries); i++ {
		e := b.entries[(b.next+i)%len(b.entries)]
		if e.Seq == 0 { // 这个槽位还没被写过
			continue
		}
		if e.Seq > after {
			out = append(out, e)
		}
	}
	// 请求的序号不在现有区间内且仍有数据，说明中间被覆盖过。
	truncated := after > 0 && len(out) > 0 && out[0].Seq > after+1
	return LogPage{Entries: out, Latest: b.seq, Truncated: truncated}
}
