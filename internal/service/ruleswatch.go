// 规则文件的热重载监视器。
//
// 为什么要有它：改规则的人不一定在面板里改。`assets/rules.txt`、
// 面板自己管的 `assets/user-rules.txt`、订阅缓存 `providers/*.txt`，
// 都可能是用户在编辑器里改的、或者被别的工具改写的。以前只能点「重载规则」，
// 于是"改了没生效"变成一次远程排查。
//
// 三条纪律：
//  1. 盯的是**引擎这次真的打开过的那些文件**（Engine.Sources），
//     只看 rules_file 的 mtime 会漏掉最常见的编辑对象；
//  2. 只有"改动落定了"才重载：连续两轮看到同一个新指纹才动手。
//     编辑器写一半（truncate + 逐行写）时那份指纹是临时的，
//     立刻重载等于把半截文件当规则编译，日志里就是一条假的"规则语法错误"；
//  3. 任何一次成功重载都会刷新基线 —— 包括托盘、SIGHUP、面板改名单触发的。
//     不然它们改完，监视器还会再"发现"一次同样的改动，白重载一遍。
package service

import (
	"context"
	"os"
	"sync"
	"time"

	"wps_app/internal/logx"
)

// rulesWatchInterval 是看一次文件的时间。5 秒是"改完抽根烟回来就生效"和
// "不变成常驻磁盘轮询"之间的折中；一次检查就是几个 os.Stat。
const rulesWatchInterval = 5 * time.Second

// fileStamp 是一个文件的最小指纹。ok=false 代表"这次没看到它"
// （被删了、或者编辑器正把它挪走）——那也算一种变化，不能当成"没变"。
type fileStamp struct {
	mod  time.Time
	size int64
	ok   bool
}

func statFile(path string) fileStamp {
	st, err := os.Stat(path)
	if err != nil {
		return fileStamp{}
	}
	return fileStamp{mod: st.ModTime(), size: st.Size(), ok: true}
}

func stampSet(paths []string) map[string]fileStamp {
	out := make(map[string]fileStamp, len(paths))
	for _, p := range paths {
		out[p] = statFile(p)
	}
	return out
}

func sameStampSet(a, b map[string]fileStamp) bool {
	if len(a) != len(b) {
		return false
	}
	for p, sa := range a {
		sb, ok := b[p]
		if !ok || sa != sb {
			return false
		}
	}
	return true
}

// reloadNeeded 是整个监视器里唯一的判断，所以它单独存在、单独测。
//
// 基线为空（还没成功加载过）时不说"要重载"：那时该做的是记住现状。
func reloadNeeded(base, prev, now map[string]fileStamp) bool {
	if len(base) == 0 {
		return false
	}
	if sameStampSet(now, base) {
		return false
	}
	// 与上一轮也不同 = 文件还在动，等它停下来。
	return sameStampSet(now, prev)
}

// rulesWatch 是挂在 Service 上的那一点状态。它没有自己的 goroutine 生命周期，
// 起停都由 Start/Stop 通过 ctx 管，跟订阅循环一个样式。
type rulesWatch struct {
	mu     sync.Mutex
	base   map[string]fileStamp // 最近一次成功重载时的指纹
	prev   map[string]fileStamp // 上一轮看到的指纹
	lastOK time.Time            // 最近一次成功重载的时刻（任何入口触发的都算）
}

// startRulesWatch 起监视循环。已经在跑就不重复起。
func (s *Service) startRulesWatch() {
	s.mu.Lock()
	if s.rulesWatchCancel != nil {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.rulesWatchCancel = cancel
	s.mu.Unlock()

	go s.rulesWatchLoop(ctx)
}

// stopRulesWatch 停掉循环。与 stop() 里停订阅循环同一处调用，顺序也同理：
// 监听器刚关就停，收尾期间再触发一次重载没有意义。
func (s *Service) stopRulesWatch() {
	s.mu.Lock()
	cancel := s.rulesWatchCancel
	s.rulesWatchCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) rulesWatchLoop(ctx context.Context) {
	ticker := time.NewTicker(rulesWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkRulesChanged()
		}
	}
}

// checkRulesChanged 走一轮：取当前引擎的文件清单 → 算指纹 → 问 reloadNeeded。
// 抽成方法是因为测试要能一轮一轮地驱动它，而不是睡 5 秒等定时器。
func (s *Service) checkRulesChanged() {
	rt := s.Router()
	if rt == nil {
		return // 没在跑：不监视，也不清空基线（重载过什么仍然算数）
	}
	now := stampSet(rt.Engine().Sources())
	w := &s.rwatch
	w.mu.Lock()
	need := reloadNeeded(w.base, w.prev, now)
	w.prev = now
	w.mu.Unlock()
	if !need {
		return
	}
	if err := s.Reload(); err != nil {
		// Reload 自己已经说过"继续用旧规则"。这里只补一句是谁触发的，
		// 半截文件被编辑器写坏时，这条会随下一轮改动落定而自愈。
		logx.Warnf("规则文件变了，但按新文件重载没成功")
		return
	}
	logx.Infof("检测到规则文件变化，已自动重载")
}

// noteRulesReloaded 把基线刷成"当前引擎所依赖的文件现状"。
// 每条成功重载的路径（监视器、托盘、SIGHUP、面板改名单）都要调它。
func (s *Service) noteRulesReloaded() {
	rt := s.Router()
	if rt == nil {
		return
	}
	stamped := stampSet(rt.Engine().Sources())
	w := &s.rwatch
	w.mu.Lock()
	w.base = stamped
	w.prev = stamped
	w.lastOK = time.Now()
	w.mu.Unlock()
}

// RulesFileView 是一个规则文件的最小事实，够界面回答"我改这份会不会自动生效"。
//
// 故意只带 size 与 mtime：那是监视器真正在比的东西。多带一个"内容摘要"
// 就会变成"界面显示的是摘要、判断用的是 mtime"，两句话对不上。
type RulesFileView struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	// ModTime 空串 = 这一轮读不到这个文件（被删了、或编辑器正把它挪走）。
	ModTime string `json:"modTime"`
	// Readable 与"ModTime 为空"是同一件事的两种问法，都带上：
	// 界面要分得开"读不到"和"读到的是个空文件"。
	Readable bool `json:"readable"`
}

// RulesWatchView 是热重载监视器的现状投影。
//
// 为什么要把这些摊到界面上：自动重载是"看不见就以为没生效"的那类功能——
// 用户改了文件、面板没反应（还在等第二轮），他没法区分"在等"与"这功能没有"。
// 这一栏让他看到被看着的是哪些文件、上一次生效是什么时候。
//
// 这里不重复报"被跳过的可选 include"：那一栏在「内置规则集」里已经有了，
// 同一个事实在两页各说一遍，就会在两页说法不一致时谁也不可信。
type RulesWatchView struct {
	// Watching 是"监视循环此刻在跑"。假的时候界面必须说"改文件不会自动生效"，
	// 而不是把文件列表画成空的——空列表读起来像"没有文件要看"，不是"没在监视"。
	Watching bool `json:"watching"`
	// IntervalSec 是轮询间隔，用来解释"为什么改了还要等几秒"。
	IntervalSec int             `json:"intervalSec"`
	Files       []RulesFileView `json:"files"`
	// LastReload 是最近一次成功重载的时刻（任何入口触发的都算）；
	// 空串 = 本次运行还没有过重载，界面不许渲染成 0001-01-01 或"刚刚"。
	LastReload string `json:"lastReload"`
}

// RulesWatchView 读监视器现状。一次调用就是几个 os.Stat，
// 比面板每秒那轮状态查询还便宜，所以可以放心地跟着一起轮询。
func (s *Service) RulesWatchView() RulesWatchView {
	s.mu.Lock()
	rt, watching := s.rt, s.rulesWatchCancel != nil
	s.mu.Unlock()

	v := RulesWatchView{
		Watching:    watching,
		IntervalSec: int(rulesWatchInterval / time.Second),
		Files:       []RulesFileView{},
	}
	w := &s.rwatch
	w.mu.Lock()
	last := w.lastOK
	w.mu.Unlock()
	if !last.IsZero() {
		v.LastReload = last.Format("15:04:05")
	}

	// 清单只在引擎真的装配过时才有意义：报的就是它打开过的那一层层文件。
	// 没在跑时留空——主文件路径本来就印在同一页的「内置规则集」里，
	// 这里再抄一遍会变成两页各说一次同一个路径，改天说法不一致就没人可信。
	// 空的文件列表配上 Watching=false，界面那句必须说"没在监视、改了不生效"。
	if rt != nil {
		v.Files = viewFiles(rt.Engine().Sources())
	}
	return v
}

func viewFiles(paths []string) []RulesFileView {
	out := make([]RulesFileView, 0, len(paths))
	for _, p := range paths {
		st := statFile(p)
		f := RulesFileView{Path: p, Readable: st.ok}
		if st.ok {
			f.Size = st.size
			f.ModTime = st.mod.Format("2006-01-02 15:04:05")
		}
		out = append(out, f)
	}
	return out
}
