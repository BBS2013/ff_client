// Package logx 提供带级别的轻量日志。
package logx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type Level int32

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "INFO"
	}
}

// Clip 按字节上限截一段文字，且不会切进一个 UTF-8 字符中间。
//
// 为什么要有这一条：这一类文本是从错误原文、文件内容或远端应答里来的，
// 长度不由我们决定，而它可能要住进常驻内存的缓冲、再每秒经桥面发给面板一遍。
// max <= 0 表示不截。截没截由调用方判断（`len(结果) < len(原文)`），
// 尾巴上要不要写"原长多少"也归调用方——这里只保证"安全地截"，一份实现两份策略。
func Clip(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	// 在 UTF-8 中间切会留下一个残缺字节：前端渲染时是一个替换字符，
	// 而这一串是给人排查错误用的。往回退到上一个字符边界。
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

var (
	mu      sync.Mutex
	level             = LevelInfo
	output  io.Writer = os.Stdout
	hooks   []hookEntry
	hookSeq uint64
)

// hookEntry 带一个自增 ID，注销时按 ID 删而不是按函数值删——
// 同一个函数可能被注册两次，按值删会一次干掉两个。
type hookEntry struct {
	id uint64
	fn Hook
}

// Hook 旁路订阅一条已格式化好的日志。
//
// msg 不含级别前缀与时间戳，也不含末尾换行；需要原始行的话自己拼。
// t 是这条日志的记录时刻，与写文件用的是同一个时间点，不会因为并发而错位。
type Hook func(level Level, msg string, t time.Time)

// AddHook 注册一个日志钩子，返回注销函数，注销可重复调用。
//
// 与 SetOutput 的区别在于「替换」与「订阅」：SetOutput 会把全局输出目标整个换掉，
// 只适合测试用；AddHook 是旁路订阅，标准输出与文件输出保持原样，
// GUI 用它把日志抄一份送到前端的环形缓冲里。
func AddHook(h Hook) (remove func()) {
	noop := func() {}
	if h == nil {
		return noop
	}
	mu.Lock()
	hookSeq++
	e := hookEntry{id: hookSeq, fn: h}
	hooks = append(hooks, e)
	mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			mu.Lock()
			defer mu.Unlock()
			for i, cur := range hooks {
				if cur.id == e.id {
					hooks = append(hooks[:i], hooks[i+1:]...)
					return
				}
			}
		})
	}
}

// SetLevel 设置全局日志级别。
func SetLevel(l Level) {
	mu.Lock()
	defer mu.Unlock()
	level = l
}

// SetOutput 替换日志输出目标，测试用。
func SetOutput(w io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	output = w
}

// fireHook 逐个广播。钩子在调用方的 goroutine 上同步执行：
// 订阅方只是一个环形缓冲拷贝，代价很小，而同步执行能保证日志顺序与文件输出一致。
//
// 单个钩子 panic 不会波及日志调用方——GUI 侧的钩子不应该有能力带崩代理。
func fireHook(active []Hook, l Level, msg string, t time.Time) {
	for _, h := range active {
		callHook(h, l, msg, t)
	}
}

func callHook(h Hook, l Level, msg string, t time.Time) {
	defer func() { _ = recover() }()
	h(l, msg, t)
}

// logf 是唯一的写日志入口。
func logf(l Level, format string, args ...any) {
	mu.Lock()
	if l < level {
		mu.Unlock()
		return
	}
	// 消息里混着大量外部可控文本：SOCKS5 客户端自报的域名、节点名、
	// HTTP 请求里的任意字节。它们会被原样写进终端与面板，
	// 因此落盘前必须洗掉控制字符——否则一个恶意的客户端（或一份
	// 被污染的规则文件）就能靠换行与 ANSI 转义伪造日志行、
	// 重画面板甚至操纵终端。
	msg := sanitize(fmt.Sprintf(format, args...))
	now := time.Now()
	fmt.Fprintf(output, "%s [%s] %s\n", now.Format("2006-01-02 15:04:05"), l, msg)
	// 必须在解锁后再调钩子：钩子自己完全可能再打一条日志（UI 侧就会），
	// 持锁调用会直接自锁。
	active := make([]Hook, len(hooks))
	for i, e := range hooks {
		active[i] = e.fn
	}
	mu.Unlock()

	fireHook(active, l, msg, now)
}

// sanitize 把控制字符换成可见转义，使每条日志严格占一行且不可携带终端指令。
//
// 保留 \t 与普通可见字符（含中文）；其余 C0/C1 控制字符、DEL 与 CSI 等
// 转义序列一律转成 \xNN 或 \uNNNN。
func sanitize(s string) string {
	needs := false
	for _, r := range s {
		if isUnsafe(r) {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteByte('\t')
		case isUnsafe(r):
			b.WriteString(escapeRune(r))
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isUnsafe(r rune) bool {
	if r == '\t' {
		return false
	}
	// C0、DEL、C1（含 0x9b 这个 8 位 CSI 的等价物）。
	if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
		return true
	}
	// 零宽与方向控制类字符：它们不可见却能改变渲染结果。
	if r == 0x200b || r == 0x200c || r == 0x200d || r == 0xfeff ||
		r == 0x2028 || r == 0x2029 || (r >= 0x202a && r <= 0x202e) || r == 0x2066 || r == 0x2067 {
		return true
	}
	return false
}

func escapeRune(r rune) string {
	switch r {
	case '\n':
		return `\n`
	case '\r':
		return `\r`
	case '\t':
		return `\t`
	}
	if r < 0x100 {
		return fmt.Sprintf(`\x%02x`, r)
	}
	return fmt.Sprintf(`\u%04x`, r)
}

func Debugf(format string, args ...any) { logf(LevelDebug, format, args...) }
func Infof(format string, args ...any)  { logf(LevelInfo, format, args...) }
func Warnf(format string, args ...any)  { logf(LevelWarn, format, args...) }
func Errorf(format string, args ...any) { logf(LevelError, format, args...) }
