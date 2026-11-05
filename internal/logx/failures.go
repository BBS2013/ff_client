package logx

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// 失败日志的聚合。设计目标是回答一个问题：
//
//	「这台机器现在有哪些东西在稳定地失败？」
//
// 直接按每次失败打一行回答不了它——现场实测过：一天 3.7 万行日志里，
// 59%（22139 行）是同一条「节点重连退避中」的拨号失败，来自浏览器的几百条
// 重试。真正有用的信息（哪个目标、为什么、持续多久）被埋掉了，
// 而日志文件 20MB 一轮也就够存几天。
//
// 所以失败改成两个层次：
//
//	第一条立刻打（WARN，带完整原因）——"刚刚出事了"要马上看得见
//	之后同一个键的失败只计数，每 FlushFailureWindow 汇总一条
//	沉默超过 FlushFailureWindow 的键自动消失——"已经不失败了"不必再报
//
// 键由调用方给（通常是「目标 + 原因类别」）。用原因类别而不是原因原文：
// 后者的每一份都可能带不同的超时毫秒数，那样聚合就退化成不聚合。
const (
	// FlushFailureWindow 是汇总窗口，也是"这个键安静多久就忘掉它"的判据。
	FlushFailureWindow = 60 * time.Second
)

type failureEntry struct {
	first   time.Time
	last    time.Time
	count   int
	reasons map[string]int
	// reported 记录这期间有没有打过那条"第一条"。打过之后只累计。
	reported bool
}

var failures struct {
	mu      sync.Mutex
	keys    map[string]*failureEntry
	lastRun time.Time
}

// NoteFailure 记一次失败，必要时打一条日志。
//
// key 建议写成"目标或通道"（例如 "http CONNECT api.example.com:443"），
// reason 建议写成原因类别（例如 "节点重连退避中"）。同 key 同窗口内
// 只打第一条，其余计数。
//
// 返回 true 表示这一条被真的打出来了（调用方在测试里可以用它判断聚合生效）。
func NoteFailure(key, reason string, detail error) bool {
	now := time.Now()
	if reason == "" {
		reason = "其它"
	}

	failures.mu.Lock()
	if failures.keys == nil {
		failures.keys = make(map[string]*failureEntry)
	}
	e, ok := failures.keys[key]
	if !ok {
		e = &failureEntry{first: now, reported: true, reasons: make(map[string]int)}
		failures.keys[key] = e
	}
	e.last = now
	e.count++
	e.reasons[reason]++
	failures.mu.Unlock()

	// 打日志放在锁外：logx.logf 自己要拿另一把锁，而 WARN 行可能触发钩子
	// （面板的环形缓冲），持锁调用会把两把锁串起来。
	if ok {
		return false
	}
	// 第一条要把**类别与原文都给出来**：类别是后面汇总时唯一的键，
	// 用户看到"节点不可用×30"时要能对上第一条到底说了什么；
	// 而原文里才有那一次的具体数值（例如还需要等几秒）。
	if detail != nil {
		Warnf("%s 失败[%s]: %v（同类失败会汇总，每 %s 最多一条）", key, reason, detail, FlushFailureWindow)
	} else {
		Warnf("%s 失败[%s]（同类失败会汇总，每 %s 最多一条）", key, reason, FlushFailureWindow)
	}
	return true
}

// FlushFailures 把窗口内累计到的失败汇总成若干行，并清掉已经安静的键。
//
// 由调用方周期驱动（service 的那条 60 秒 ticker），不在每次写入时检查——
// 把"该不该汇总"塞进热路径只会让每次失败都多一次时间比较。
func FlushFailures() {
	now := time.Now()
	type line struct {
		key      string
		count    int
		duration time.Duration
		reasons  string
	}
	var lines []line

	failures.mu.Lock()
	for key, e := range failures.keys {
		// 只有累计超过一条的才值得汇总：只失败过一次的，第一条 WARN 已经把
		// 全部信息写全了，再打一条"共 1 次"是纯噪音。
		if e.count > 1 {
			lines = append(lines, line{
				key:      key,
				count:    e.count,
				duration: e.last.Sub(e.first),
				reasons:  formatReasons(e.reasons),
			})
			e.count = 1
			e.reasons = map[string]int{}
			e.first = e.last
		}
		if now.Sub(e.last) > FlushFailureWindow && e.count <= 1 {
			delete(failures.keys, key)
		}
	}
	failures.lastRun = now
	failures.mu.Unlock()

	// 排序让输出稳定（map 迭代顺序是随机的，而日志要能 diff）。
	sort.Slice(lines, func(i, j int) bool {
		if lines[i].count != lines[j].count {
			return lines[i].count > lines[j].count
		}
		return lines[i].key < lines[j].key
	})
	for _, l := range lines {
		Warnf("最近 %s 内 %s 失败 %d 次（%s）",
			roundDuration(l.duration), l.key, l.count, l.reasons)
	}
}

// formatReasons 把「原因 → 次数」压成一句"原因×N/原因×M"，按次数降序。
func formatReasons(m map[string]int) string {
	if len(m) == 0 {
		return "原因未知"
	}
	type pair struct {
		r string
		n int
	}
	ps := make([]pair, 0, len(m))
	for r, n := range m {
		ps = append(ps, pair{r, n})
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].n != ps[j].n {
			return ps[i].n > ps[j].n
		}
		return ps[i].r < ps[j].r
	})
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, p.r+"×"+itoa(p.n))
	}
	return strings.Join(parts, "；")
}

func roundDuration(d time.Duration) time.Duration {
	if d < time.Second {
		return time.Second
	}
	return d.Round(time.Second)
}

// itoa 是小整数转换，避免为了一个数字去 fmt。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ResetFailures 清空聚合状态，仅供测试。
func ResetFailures() {
	failures.mu.Lock()
	defer failures.mu.Unlock()
	failures.keys = nil
}
