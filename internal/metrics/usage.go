package metrics

// 跨重启的节点用量账本。
//
// 为什么要有它：很多节点按配额计费或到量降速，而面板原来只有"本次会话"的数——
// 重启一次就从零开始。于是 §9.5.1 立起来的那张分节点表，恰好回答不了它立起来
// 要回答的那个问题（"这个月的量是谁用掉的"），因为"这个月"跨过好几次重启。
//
// 两份账是分开的，不是合成一个数：
//   - 本次会话：内存里那份，重启/清空都会归零；
//   - 累计（跨重启）：落盘的基数 + 本次会话。
//     界面上两个都要摆出来，只摆一个就会要么让人以为没跑过，要么以为跑过的是今天。
//
// 它**可能少算**：落盘是定时的（外加停止时那一次），崩溃会丢掉最后一次落盘之后的量。
// 这一条必须写在界面上，不能只写在这里——"累计"两个字天然让人觉得是账本。
// 它**不会多算**：每份账只由写它的那个进程落一次，读进来当基数，
// 而基数本身不参与 End/Reset 的累加路径。

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/sudoown"
)

// usageFileName 挂在配置文件旁边，与系统代理记账（config.yaml.sysproxy.json）同一个约定：
// 一个实例一套账，复制走目录就带走账本，不会有两个 checkout 互相踩。
const usageFileName = ".usage.json"

// usageFlushEvery 是"多少秒看一眼要不要落盘"。一分钟是两头成本的交点：
// 再密就是让面板一直碰盘，再疏则一次崩溃能吞掉用户更多的量。
const usageFlushEvery = 60

// usageVersion 是这份账本的格式版本。只增不减。
const usageVersion = 1

// ErrUsageTooNew 表示文件里的格式比当前程序认识的还新。
// 这时候**既不套用也不回写**：拿旧格式盖回去会丢掉新字段，
// 而那种丢失要等到用户发现"累计突然变小"才会被看见。
var ErrUsageTooNew = errors.New("用量账本的格式版本比本程序新")

// UsageNode 是一个节点跨重启攒下来的量。
type UsageNode struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// UsageState 是账本落盘的那一份形状。
type UsageState struct {
	V int `json:"v"`
	// SavedAt 是上一次落盘的时刻（Unix 毫秒）。界面拿它说"累计少算了这之后的量"。
	SavedAt int64 `json:"savedAt"`
	// Since 是这份账开始攒的时刻（Unix 毫秒）：0 表示不知道（文件是别处来的）。
	// 「累计也清零」会把它拨到当下，于是这一栏就是"自 X 起累计"——
	// 按月计费的节点要的就是这个数。
	Since int64                `json:"since"`
	Nodes map[string]UsageNode `json:"nodes"`
}

// UsagePath 由配置文件路径推出账本路径。
func UsagePath(cfgPath string) string {
	dir, base := filepath.Split(strings.TrimSpace(cfgPath))
	if base == "" {
		// 传进来的就是个目录（或者空串）：别拼出 "..json" 这种名字。
		return filepath.Join(dir, "wps_app"+usageFileName)
	}
	return filepath.Join(dir, base+usageFileName)
}

// LoadUsage 读账本。文件不存在是正常状态，返回空账本与 nil。
//
// 解析失败时把原文件挪到 <path>.bad 再报错：那是用户唯一的"这个月用了多少"的证据，
// 就地覆盖等于在报错的同时把证据也销毁了。挪不动（权限/目录只读）也要把错误带出去，
// 让调用方知道"接下来别写"。
func LoadUsage(path string) (UsageState, error) {
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return UsageState{}, nil
	}
	if err != nil {
		return UsageState{}, err
	}
	var st UsageState
	if err := json.Unmarshal(body, &st); err != nil {
		bad := path + ".bad"
		if _, statErr := os.Stat(bad); statErr == nil {
			bad = fmt.Sprintf("%s.bad-%d", path, time.Now().Unix())
		}
		if rerr := os.Rename(path, bad); rerr != nil {
			return UsageState{}, fmt.Errorf("用量账本读不出（%v），而它坏掉的那份也挪不走（%v）——先别写它", err, rerr)
		}
		return UsageState{}, fmt.Errorf("用量账本读不出，原文件已挪到 %s 备查: %w", filepath.Base(bad), err)
	}
	if st.V > usageVersion {
		return UsageState{}, fmt.Errorf("%w: 文件是 v%d，本程序只认到 v%d", ErrUsageTooNew, st.V, usageVersion)
	}
	if st.Nodes == nil {
		st.Nodes = map[string]UsageNode{}
	}
	return st, nil
}

// WriteUsage 原子落盘：先写同目录临时文件再改名。
// 直接写目标文件会留下"写了一半被崩溃截断"的窗口，而那份文件是账本——
// 它坏了不会有人怀疑到自己头上，只会以为程序又在瞎记。
func WriteUsage(path string, st UsageState) error {
	st.V = usageVersion
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // 改名成功时这句是空操作，失败时它负责扫尾。
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// root 面板写出的账本若留在 root 手里，普通权限实例下次启动就读不出
	// （permission denied → 从空账开始 → 界面上的「累计」凭空清零）。
	// best-effort 归还属主（见 sudoown 包注释）：失败只提醒，不为它
	// 推翻一次已经成功的落盘——账在，只是换个人读不动。
	if cerr := sudoown.ToDesktopUser(path); cerr != nil {
		logx.Warnf("用量账本属主没能还给桌面用户，普通权限实例可能读不出: %v", cerr)
	}
	return nil
}

// UsageState 把当前这份账（累计基数 + 本次会话）拍成一个可落盘的结构。
//
// 传出去的是**合成之后**的数：基数只读，不因为这次落盘而改变。
func (r *Registry) UsageState() UsageState {
	if r == nil {
		return UsageState{Nodes: map[string]UsageNode{}}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := UsageState{
		SavedAt: time.Now().UnixMilli(),
		Since:   r.priorSince,
		Nodes:   make(map[string]UsageNode, len(r.nodeClosed)+len(r.prior)),
	}
	add := func(n string, up, down uint64) {
		if !nodeCounts(n) || up == 0 && down == 0 {
			return
		}
		c := st.Nodes[n]
		c.Up += up
		c.Down += down
		st.Nodes[n] = c
	}
	for n, a := range r.prior {
		add(n, a.up, a.down)
	}
	for n, a := range r.nodeClosed {
		add(n, a.up, a.down)
	}
	// 还在跑的那几条也算进来：崩溃前最后几分钟的量能不能留住，
	// 取决于这次有没有把它们写进去，只写"已收尾的"会让长连接的量整段消失。
	for _, c := range r.active {
		up, down := c.Up.Load(), c.Down.Load()
		if up <= c.chargedUp && down <= c.chargedDown {
			continue
		}
		if up > c.chargedUp {
			add(c.Node, up-c.chargedUp, 0)
		}
		if down > c.chargedDown {
			add(c.Node, 0, down-c.chargedDown)
		}
	}
	return st
}

// ApplyPrior 把上一次进程留下的账装进来当基数。
//
// 只认非负、且只认有字节的条目：一个空节点名或者 0/0 的行进了基数，
// 界面上就会多出一行"累计 0 B"，而那一行没有任何可解释的来源。
func (r *Registry) ApplyPrior(st UsageState) {
	if r == nil || len(st.Nodes) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.prior == nil {
		r.prior = make(map[string]nodeBytes, len(st.Nodes))
	}
	for n, v := range st.Nodes {
		if !nodeCounts(n) || v.Up == 0 && v.Down == 0 {
			continue
		}
		p := r.prior[n]
		p.up += v.Up
		p.down += v.Down
		r.prior[n] = p
	}
	if st.Since > 0 {
		r.priorSince = st.Since
	}
	if st.SavedAt > r.priorSavedAt {
		r.priorSavedAt = st.SavedAt
	}
}

// ClearUsageCumulative 把"累计（跨重启）"那一栏也抹掉：基数清空、起点拨到当下。
//
// 它与 Reset 是两件事，所以是两个动作而不是一个按钮：
// 「清空统计」清的是本次会话（原来就是这个意思，不能悄悄扩大它的射程），
// 而这个是"这个月过完了，重新起算"。调用方负责紧接着落一次盘，
// 否则下次启动会把旧账本又读回来——那才是真的"清了个寂寞"。
func (r *Registry) ClearUsageCumulative() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prior = nil
	r.priorSince = time.Now().UnixMilli()
	r.priorSavedAt = 0
}

// 账本这一轮是怎么收场的。界面要按这个值决定"累计"那一栏说什么话——
// 尤其是**没有**累计的时候，得说清是没有账，还是有一本它不敢用的账。
// 常量而不是枚举类型：它要过 JSON 边界，字符串在前端好比对，
// 而新增一种取值本来就有守卫用例盯着（见 §14）。
const (
	UsageLoaded     = "loaded"     // 读到了，已经当基数用上
	UsageEmpty      = "empty"      // 没有账本，或账本里一个节点都没有
	UsageTooNew     = "too-new"    // 版本比本程序新：不套用也不回写
	UsageUnreadable = "unreadable" // 解析失败，坏的那份已挪去 .bad
)

// SetUsageOutcome 记下这一轮的收场。认不出的值按"没有账本"处理：
// 界面宁可少说一句，也不许在没设过状态时显示一个来历不明的"累计"。
func (r *Registry) SetUsageOutcome(state string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch state {
	case UsageLoaded, UsageEmpty, UsageTooNew, UsageUnreadable:
		r.usageState = state
	default:
		r.usageState = UsageEmpty
	}
}

// UsageOutcome 读回那个收场。没设过时给 empty，而不是空串。
// （不叫 UsageState：那个名字已经是"可落盘的那份账"的方法名了。）
func (r *Registry) UsageOutcome() string {
	if r == nil {
		return UsageEmpty
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.usageOutcomeLocked()
}

// usageOutcomeLocked 是同一个读法，但要求调用方**已经**持有 r.mu。
//
// 为什么要单独一个：sync.Mutex 不可重入。Snapshot 整段是持锁的，
// 如果它在锁内调 UsageOutcome()（自己再抢一次锁），面板第一次轮询就把
// 整个注册表锁死——而症状是"测试挂到超时"，不是"测试失败"。
// 这条就是那么踩出来的，所以拆成两个入口，锁内只用带 Locked 后缀的那个。
func (r *Registry) usageOutcomeLocked() string {
	if r.usageState == "" {
		return UsageEmpty
	}
	return r.usageState
}

// EnableUsage 让这份账开始跨重启留住：记下往哪写，并让采样那条 goroutine
// 顺带每分钟落一次盘。必须在 StartSampler 之前调用（否则这条 goroutine 已经起来了，
// 它读到的还是空路径）。传空串就是关掉整条链。
func (r *Registry) EnableUsage(path string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.usagePath = strings.TrimSpace(path)
}

// HasUsageFile 报告这份账是否会被留住。
func (r *Registry) HasUsageFile() bool {
	if r == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.usagePath != ""
}

// ensureSince 在第一次真要落盘之前把起点盖上。
//
// 不在 UsageState() 里现编一个"since = 现在"：那个数每次调用都不一样，
// 于是"内容没变就不写盘"那把尺子每次量出的都是新内容，面板会每分钟碰一次盘。
// 起点是账本的一个事实，就该存在账本的状态里，而不是算出来。
func (r *Registry) ensureSince() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.priorSince == 0 {
		r.priorSince = time.Now().UnixMilli()
	}
}

// FlushUsage 立刻落一次盘。停止/退出路径与「累计也清零」之后都要调它——
// 前者留住最后这一段，后者要是不落盘，下次启动就把刚清掉的账又读回来了。
func (r *Registry) FlushUsage() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	path := r.usagePath
	r.mu.Unlock()
	if path == "" {
		return nil
	}
	r.ensureSince()
	return WriteUsage(path, r.UsageState())
}

// maybeFlushUsage 是定时那一次：内容没变就不写盘。
//
// 比"照抄上一次的字节数"更省心的做法是直接比序列化结果——这份账一共几十十字节，
// 每分钟一次 marshal 的成本可以忽略，而它顺带覆盖了"有一条长连接一直在跑、
// 一条都没收尾"那种 End 永远不来的情况。
func (r *Registry) maybeFlushUsage() {
	if r == nil {
		return
	}
	r.mu.Lock()
	path := r.usagePath
	last := r.lastFlushed
	r.mu.Unlock()
	if path == "" {
		return
	}
	r.ensureSince()
	st := r.UsageState()
	probe, err := json.Marshal(UsageState{Since: st.Since, Nodes: st.Nodes})
	if err != nil {
		return
	}
	if len(st.Nodes) == 0 {
		// 一条都还没记过就不碰盘。空账本没有要留住的东西，
		// 而"面板开着、什么都没跑"是这个程序绝大多数时间的状态。
		// 真要清空已有的一份，走的是显式 FlushUsage（「累计也清零」那条路）。
		return
	}
	if string(last) == string(probe) {
		return
	}
	if err := WriteUsage(path, st); err != nil {
		// 写失败只打日志：账本丢了不该把转发链路一起弄停。
		// 不更新 lastFlushed，所以下一分钟还会再试一次。
		logx.Warnf("节点用量账本没写进去（%s），累计这一栏会继续只反映上次落盘之前的量: %v", path, err)
		return
	}
	r.mu.Lock()
	r.lastFlushed = probe
	r.priorSavedAt = st.SavedAt
	r.mu.Unlock()
}
