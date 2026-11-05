// Package metrics 统计代理连接的实时流量与连接信息，供 GUI 面板轮询。
//
// 埋点方式刻意不改入站协议代码：给 net.Conn 套一层计数包装即可拿到上下行字节数，
// 同时把连接元信息登记进 Registry。Registry 自身维护一个每秒采样一次的速率序列，
// 前端直接画序列，不必自己算差分。
package metrics

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// Conn 是一条进行中的连接。Up/Down 由 countConn 写入，读写它必须用 Load。
type Conn struct {
	ID       uint64
	Start    time.Time
	Inbound  string // socks5 / http
	Client   string
	Host     string
	Port     string
	Policy   string
	Matched  string
	Outbound string
	// Node 是这条连接的字节记在谁名下（节点名 / DIRECT / REJECT）。
	Node string
	// Iface 是这条连接被钉在的那张网卡；没分流时为空串。
	Iface string
	// Err 非空 = 这条连接根本没建起来（只有 Refuse 会写它）。
	Err string
	// chargedUp/chargedDown 是"已经算进各节点账本"的水位，只在 mu 下读写。
	// 点「清空统计」时把它推到连接当前的字节数，于是这条连接之后再有写入
	// 才计进节点账本——不然会出现"总数已经归零、A 节点还挂着 3GB"，
	// 而那 3GB 里绝大部分是清零之前跑的。
	chargedUp, chargedDown uint64

	Up   atomic.Uint64
	Down atomic.Uint64
}

// ConnView 是 Conn 的可序列化投影，字段全为普通值，便于经 Wails 送给前端。
type ConnView struct {
	ID       uint64 `json:"id"`
	Start    int64  `json:"start"` // Unix 毫秒
	Duration int64  `json:"duration"`
	Inbound  string `json:"inbound"`
	Client   string `json:"client"`
	Host     string `json:"host"`
	Port     string `json:"port"`
	Target   string `json:"target"`
	Policy   string `json:"policy"`
	Matched  string `json:"matched"`
	Outbound string `json:"outbound"`
	// Node 是这条连接**实际**落在哪个去处名下：节点名、DIRECT，或被拦时的 REJECT。
	// 与 Outbound 不是一回事——Outbound 是策略分组的名字（proxy / direct 那一层），
	// 而节点会自动切换、规则也能钉节点，所以"走了代理"回答不了"走的是哪个代理"。
	// 各节点用量那张表按的就是这个值，两张表必须说同一个字符串。
	Node string `json:"node"`
	// Iface 是这条连接走了哪张网卡（wlp3s0f0 之类）；没开分流时是空串。
	Iface string `json:"iface"`
	// Err 非空表示这条连接**根本没建起来**：拨号失败，一个字节都没走。
	// 空串是"没有失败"，不是"还不知道失败"——所以它只在 Refuse 那条路上被写。
	Err  string `json:"err"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// Sample 是速率序列上的一个点，Up/Down 单位为字节/秒。
type Sample struct {
	T    int64   `json:"t"` // Unix 毫秒
	Up   float64 `json:"up"`
	Down float64 `json:"down"`

	// rawUp/rawDown 是采样瞬间的累计值，用于下一轮算差分，不发给前端。
	rawUp   uint64
	rawDown uint64
}

// BlockedHit 是「最近被拦的是哪个目标」的一条留痕。
//
// 为什么单独留一份，而不是让人去翻连接表：连接表是几百条的环形流水，
// 一个页面就能挤出十几条广告请求，几分钟后"刚才那个到底拦没拦"就查不到了；
// 而拦截对客户端完全静默（不回拒绝、只让它超时），本机要是也答不上来，
// 用户就只剩日志文件可翻。
type BlockedHit struct {
	Host  string `json:"host"`
	Rule  string `json:"rule"` // 命中的规则原文，如 DOMAIN-SUFFIX,ads.example.com,REJECT(block)
	Count uint64 `json:"count"`
	// LastAt 是最近一次撞上的时刻（Unix 毫秒）。同一 host+rule 合并成一条，只动这个数。
	LastAt int64 `json:"lastAt"`
}

// blockedRingCap 是最近拦截留痕的条数上限。
// 它只为"刚才那一批"服务，不是审计日志：上限太小会被广告风暴刷掉，
// 太大就把一个临时问答做成了永久账本——那份账本该由日志负责。
const blockedRingCap = 32

// nodeCounts 决定哪些连接进"各节点用量"这张表。
//
// 判断只留这一处：收尾路径与"还在跑的"路径各写一遍的话，
// 改一处漏一处就会让同一类连接在半边出现、半边消失。
func nodeCounts(n string) bool {
	return n != "" && n != "REJECT"
}

// nodeBytes 是一个去处累计的字节与连接数（内部账，不直接投影）。
// 按规则的那本账形状完全一样，所以共用这一个类型：
// 两张表必须对同一批连接说话，字段少一个都会变成"两份账对不上"。
type nodeBytes struct {
	up, down, conns uint64
}

type ruleBytes = nodeBytes

// chargedDelta 算「水位以上还剩多少字节要记账」。
//
// 这段判断原来在四处各写了一遍（收尾的上下行、在跑的上下行），
// 少写一处的后果是账本半真半假：水位以下的重算会让"清空统计"之后
// 某节点又冒出几个 GB，而漏掉回退那一支时，一次计数器回绕会加成天文数字。
func chargedDelta(now, charged uint64) uint64 {
	if now >= charged {
		return now - charged
	}
	return now
}

// ruleSlotLocked 取出该记账的那一条规则条目。调用方必须持有 r.mu。
//
// 新键在账本已满时并进溢出桶：这张表是"现在谁在搬流量"的排行，
// 不是审计日志——让它的键随规则数无限增长，等于在这里另存一份规则文件。
func (r *Registry) ruleSlotLocked(matched string) (string, ruleBytes) {
	if _, ok := r.ruleClosed[matched]; ok {
		return matched, r.ruleClosed[matched]
	}
	if len(r.ruleClosed) >= ruleKeyCap {
		return ruleOverflowKey, r.ruleClosed[ruleOverflowKey]
	}
	return matched, r.ruleClosed[matched]
}

// NodeTraffic 是一个"去处"在本次运行里用掉的字节。
//
// 直连也占一行：它同样是"这些流量没走节点"的答案。
// REJECT 不占行——被拦的连接一个字节都没有，列出来只会稀释这张表。
type NodeTraffic struct {
	Node  string `json:"node"`
	Up    uint64 `json:"up"`
	Down  uint64 `json:"down"`
	Conns uint64 `json:"conns"`
	// Prior 是上一次进程落盘时这个节点已经跑掉的字节（up+down 合成一个数：
	// 跨重启再拆方向已经没有意义，拆开的两份账对不上一次崩溃）。
	// 界面上"本次 X · 累计 Y"的 Y 就是 Up+Down+Prior。见 usage.go。
	Prior uint64 `json:"prior"`
}

// ruleKeyCap 是「按规则汇总」最多留多少条不同的命中依据。
//
// 必须设上限：规则文件动辄几千条，逐条留账会把一张「现在谁在搬流量」的临时排行
// 做成一份永久账本——那份账本该由日志与落盘用量负责，不是这里。
// 超出上限的新条目并进一个「其余」桶，界面上的总数仍然对得上。
const ruleKeyCap = 256

// ruleHitCap 是命中次数表的上限，与字节账同一量级。
// ruleHitOverflow 收纳超出上限的新键，避免「见过的主机数」无界增长。
const (
	ruleHitCap      = 256
	ruleHitOverflow = "（其余规则）"
)

// ruleRowsShown 是给界面看的行数（含那一条合并行）。
const ruleRowsShown = 12

// ruleOverflowKey 是那个合并桶的名字。它直接当 map 的键用，
// 于是"超出上限的量"从一开始就走的是和正常条目同一条路径，
// 不需要在读的时候再想办法补平。
const ruleOverflowKey = "（汇总上限之外的其余规则）"

// RuleTraffic 是一条命中依据在本次运行里搬了多少字节。
//
// 它回答的是「量记在哪条规则名下」，与规则页那一栏「命中次数」是两个口径：
// 命中次数包含被拦下与拨不通的（那些一个字节都没有），这张表只数真的搬过东西的连接。
// 两者混在一个数里，就会出现"这条规则拦了 800 次，可它一个字节都没走过"那种读不懂的行。
type RuleTraffic struct {
	Rule  string `json:"rule"`
	Up    uint64 `json:"up"`
	Down  uint64 `json:"down"`
	Conns uint64 `json:"conns"`
	// Folded 非零表示这一行合了多少条规则；最后一行才是合并行。
	// 有它才能既把表控制在可读的篇幅里，又让"这些加起来等于总量"这句话成立。
	Folded uint64 `json:"folded,omitempty"`
}

// Snapshot 是 Registry 的一次全量快照。
type Snapshot struct {
	Active      []ConnView `json:"active"`
	History     []ConnView `json:"history"`
	Series      []Sample   `json:"series"`
	ActiveCount int        `json:"activeCount"`
	TotalConns  uint64     `json:"totalConns"`
	// TotalBlocked 是本次运行累计被拦下的连接条数（含还没收尾的）。
	// 拦截对客户端完全静默，这个数与连接表就是本机唯一的凭据。
	TotalBlocked uint64 `json:"totalBlocked"`
	// TotalFailed 是本次运行累计"根本没建起来"的连接条数（见 Refuse）。
	// 它和 TotalBlocked 是两个意思：拦下是**按规则办**，拨不通是**出事了**。
	TotalFailed uint64 `json:"totalFailed"`
	// RecentBlocked 是最近被拦的目标，新→旧。见 BlockedHit。
	RecentBlocked []BlockedHit `json:"recentBlocked"`
	// ByNode 是"字节记在哪个去处名下"的合计，按总量从大到小。
	// 见 NodeTraffic：为什么需要它，是因为节点会自动切换之后，
	// 只看总数已经回答不了"这个月的量是谁用掉的"。
	ByNode []NodeTraffic `json:"byNode"`
	// ByRule 是"字节记在哪条规则名下"的合计，最多 ruleRowsShown 行，
	// 超出部分折进最后一行（Folded 说明折了几条）。见 RuleTraffic：
	// 为什么要单独一张表，是因为节点会切换、规则却不会——
	// "这个站点的量为什么这么大"只能按命中依据回答。
	ByRule    []RuleTraffic `json:"byRule"`
	TotalUp   uint64        `json:"totalUp"`
	TotalDown uint64        `json:"totalDown"`
	// PriorSince / PriorSavedAt 是给"累计（跨重启）"这一栏配的两句说明，单位 Unix 毫秒：
	// 前者是这份账开始攒的时刻（「累计也清零」会把它拨到当下），
	// 后者是上一次落盘的时刻——崩溃会丢掉这之后的量，所以累计**可能少算**。
	// 0 表示没有跨重启的账。见 usage.go。
	PriorSince   int64 `json:"priorSince"`
	PriorSavedAt int64 `json:"priorSavedAt"`
	// UsageState 说清"为什么有/没有累计这一栏"：loaded / empty / too-new / unreadable。
	// 界面拿它决定那一行说什么话——尤其是一本被拒之门外的账本，
	// 不能安静地退化成"从来没有过累计"。
	UsageState string `json:"usageState"`
}

// Registry 保存活动连接、最近结束的连接与速率序列。所有方法都并发安全。
type Registry struct {
	mu     sync.Mutex
	active map[uint64]*Conn
	// history 是环形缓冲，保留最近 histCap 条已结束连接。
	history []ConnView
	histCap int
	// series 是环形缓冲，保留最近 seriesCap 个采样点。
	series    []Sample
	seriesCap int

	seq        atomic.Uint64
	totalUp    atomic.Uint64 // 已结束连接的累计字节
	totalDown  atomic.Uint64
	totalConns atomic.Uint64
	// totalBlocked 是本次运行累计被拦下的连接条数。
	//
	// 与 totalConns 不同，它在 **Begin** 时就加：拦截是静默的（客户端什么都收不到），
	// 而一条被拦的连接可能还挂在 BlockHold 里没结束——用户按下刷新那一刻就该看到计数动过，
	// 而不是等 75 秒后它才"算数"。
	totalBlocked atomic.Uint64
	// totalFailed 是本次运行累计"拨不通"的连接条数。
	// 它必须是独立计数，而不是"数连接表里那些带 err 的行"：那张表是 500 条的环形缓冲，
	// 只数留在表里的话，跑久之后总览上"有没有出事"这一格会被最近的流量洗成 0。
	totalFailed atomic.Uint64
	// blocked 是最近拦截留痕，新的在后面。只在 mu 下读写。
	blocked []BlockedHit
	// nodeClosed 是**已收尾**连接的按节点累计；还在跑的那部分不写在这里，
	// 由 Snapshot 现从 active 加上来。这样每次写数据包都不用抢锁。
	nodeClosed map[string]nodeBytes
	// ruleHits 是"每条规则的命中依据被用过多少次"，键是引擎写下的那串文本（rule.desc()）。
	//
	// 为什么按整串而不是按域名：命中依据本身就是"哪一条规则"的唯一说法，
	// 连接表、日志、这一份计数三处用的必须是同一个字符串，
	// 另起一套键就会有两份"哪条规则"互相说不清。
	// 面板那一栏要把它对回用户写的行，靠的是 rules.UserRule.Desc() 现算同一个串，
	// 不是在这里再拆一遍——见 Desc 的注释。
	ruleHits map[string]int64
	// ruleClosed 是**已收尾**连接的按命中依据累计；还在跑的那部分不写在这里，
	// 由 Snapshot 现从 active 加上来——与 nodeClosed 同一套算法，见那里的注释。
	ruleClosed map[string]ruleBytes

	// prior 是上一次进程落盘时各节点已经跑掉的量，只当基数用（见 usage.go）：
	// End 与 Reset 都不碰它，界面上"累计"那一栏 = prior + 本次。
	prior map[string]nodeBytes
	// priorSince / priorSavedAt 是给界面说清"这份账从哪来、新到什么时候"的两个时刻。
	// 前者是起点（累计也清零会把它拨到当下），后者是上次落盘的时刻——
	// 崩溃会丢掉这之后的量，不报这个时刻就等于假装"累计"是个精确数。
	priorSince   int64
	priorSavedAt int64
	// usagePath 非空表示这份账要跨重启留住。空串就一个字节都不写。
	usagePath string
	// usageState 是这一轮账本的收场，见 usage.go 那组常量。
	usageState string
	// lastFlushed 是上一次真正写进盘里的那份内容（不含落盘时刻）。
	// 只为"没跑流量就别每分钟碰一次盘"而留着，见 maybeFlushUsage。
	lastFlushed []byte

	samplerStop chan struct{}
	samplerDone chan struct{}
}

// NewRegistry 创建一个注册表。histCap <= 0 时不保留历史连接，
// seriesCap <= 0 时不保留速率序列（纯 CLI 场景即可关掉后者）。
func NewRegistry(histCap, seriesCap int) *Registry {
	if histCap < 0 {
		histCap = 0
	}
	if seriesCap < 0 {
		seriesCap = 0
	}
	return &Registry{
		active:     make(map[uint64]*Conn),
		nodeClosed: make(map[string]nodeBytes),
		ruleClosed: make(map[string]ruleBytes),
		histCap:    histCap,
		seriesCap:  seriesCap,
	}
}

// Begin 登记一条新连接。inbound 为 "socks5" 或 "http"，client 一般是 RemoteAddr。
func (r *Registry) Begin(inbound, client string, res router.Result) *Conn {
	if r == nil {
		return nil
	}
	c := &Conn{
		ID:       r.seq.Add(1),
		Start:    time.Now(),
		Inbound:  inbound,
		Client:   client,
		Host:     res.Host,
		Port:     res.Port,
		Policy:   string(res.Policy),
		Matched:  res.Matched,
		Outbound: res.Outbound,
		Node:     res.Node,
		Iface:    res.Iface,
	}
	r.mu.Lock()
	r.active[c.ID] = c
	// 命中计数在 Begin：这一刻已经知道"是哪条规则定的"，
	// 而拦截那条可能压在 BlockHold 里几十秒不收尾——等 End 再记，
	// 用户按下刷新看到的就是"规则明明在拦，计数却是 0"。
	r.countRuleHitLocked(res.Matched)
	if res.Policy == outbound.PolicyReject {
		// 计数与留痕都在 Begin 这一刻：拦截是静默的，被拦的连接还可能压在 BlockHold 里
		// 几十秒不收尾，等 End 再记就成了"拦了但界面没反应"。
		r.totalBlocked.Add(1)
		r.noteBlockedLocked(res.Host, res.Matched, c.Start)
	}
	r.mu.Unlock()
	return c
}

// noteBlockedLocked 把一次拦截合并进最近留痕。调用方必须持有 mu。
//
// 合并键是 host+规则：同一个域名被两条不同规则拦到（名单与规则文件各一条）
// 是两件事，合成一条就等于把"是谁拦的"这个唯一有用的信息抹掉了。
func (r *Registry) noteBlockedLocked(host, rule string, at time.Time) {
	ms := at.UnixMilli()
	for i := range r.blocked {
		if r.blocked[i].Host == host && r.blocked[i].Rule == rule {
			r.blocked[i].Count++
			if ms > r.blocked[i].LastAt {
				r.blocked[i].LastAt = ms
			}
			return
		}
	}
	r.blocked = append(r.blocked, BlockedHit{Host: host, Rule: rule, Count: 1, LastAt: ms})
	if len(r.blocked) > blockedRingCap {
		r.blocked = append(r.blocked[:0], r.blocked[len(r.blocked)-blockedRingCap:]...)
	}
}

// countRuleHitLocked 记一次"这条规则的判定被用过了"。调用方必须持有 r.mu。
//
// 两条路都要记：连接建起来了（Begin）和**没建起来**（Refuse）。
// 漏掉后者的话，一条把流量导向坏节点的规则会出现这种自相矛盾的屏——
// 流量页里它的连接一行行红着，规则页的「命中」列却写 0。
func (r *Registry) countRuleHitLocked(matched string) {
	if matched == "" {
		return
	}
	if r.ruleHits == nil {
		r.ruleHits = make(map[string]int64)
		// 按规则的字节账同属"本次会话的读数"：只清命中不清字节，
		// 界面上就会留下"规则页说没命中过、流量页说它刚搬了 2GB"。
		r.ruleClosed = make(map[string]ruleBytes)
	}
	// 键跟着「规则 + via 主机」走时，不同主机会无限长。字节账有上限，
	// 命中次数以前没有。超过上限的新键并进溢出桶，已经在册的键继续累加。
	if _, ok := r.ruleHits[matched]; !ok && len(r.ruleHits) >= ruleHitCap {
		matched = ruleHitOverflow
	}
	r.ruleHits[matched]++
}

// Refuse 记一条"根本没建起来的连接"。
//
// 为什么要专门记它：拨号失败在原来那套埋点里是**不存在**的——inbound 拿到错误就
// 直接 return，`Begin` 根本没被调用过。于是"这一页是本机唯一的凭据"这句话有个洞：
// 被拦的连接看得见（block.go 记了），拨不通的看不见，
// 而用户点开这一页恰恰是因为"这个网站打不开"。
//
// res 是路由器在失败之前已经定下来的那部分判定（命中哪条、打算走哪个去处）：
// 拿得到就一并记下，那一行于是能回答"它本来要怎么走"；
// 拿不到（错误发生在判定之前）就留空，界面上写「（未记录）」，不猜。
//
// 它走的是同一条收尾路径，所以"累计连接"这个数与表里的行数仍然对得上；
// 零字节，也就不会给任何节点添上用量。
func (r *Registry) Refuse(inbound, client, target string, res router.Result, reason string) {
	if r == nil {
		return
	}
	host, port := res.Host, res.Port
	if host == "" {
		host = target
		port = ""
		if h, p, err := net.SplitHostPort(target); err == nil {
			host, port = h, p
		}
	}
	r.End(&Conn{
		ID: r.seq.Add(1), Start: time.Now(), Inbound: inbound, Client: client,
		Host: host, Port: port, Policy: string(res.Policy), Matched: res.Matched,
		Outbound: res.Outbound, Node: res.Node, Iface: res.Iface,
		Err: clipText(reason),
	})
}

// clipText 把错误原文截住：它要进内存里的历史与面板，而有些实现会把一大段
// 握手细节挂在错误串上。留够认出来是什么错就行。
// 截的动作本身在 logx.Clip（日志缓冲那边也要截，一份实现两种预算）。
func clipText(s string) string {
	s = strings.TrimSpace(s)
	c := logx.Clip(s, 240)
	if len(c) < len(s) {
		return c + "…"
	}
	return s
}

// End 注销连接并把它移入历史。c 为 nil 时直接返回。
func (r *Registry) End(c *Conn) {
	if r == nil || c == nil {
		return
	}
	// 累计与从 active 里摘掉这两步必须在同一个临界区里完成。
	// 分开放会留下一个「同一批字节既在 total 又还在 active」的窗口，
	// 而 sample() 正是靠 total+active 求出一个单调不减的量来做差分的。
	r.mu.Lock()
	up, down := c.Up.Load(), c.Down.Load()
	// 拨不通的那条也要给规则记一次命中：判定确实被用过了，只是没拨通。
	// 放在这里（而不是 Refuse 里另抢一次锁）是为了和"这一行进表"同属一个临界区——
	// 否则会出现某一瞬规则页已经写"命中 1"而流量页里那行还不存在。
	// 认 Err 就够：Begin 那条路永远不写它（见字段上的注释）。
	if c.Err != "" {
		r.countRuleHitLocked(c.Matched)
		r.totalFailed.Add(1)
	}
	r.totalUp.Add(up)
	r.totalDown.Add(down)
	r.totalConns.Add(1)
	// 收尾的字节一次性并进"该节点累计"。留着在跑的不在这里——
	// 它们在 Snapshot 里由 active 现算，所以既不用在每次写包时加锁，
	// 也不会出现"关了之后从 active 消失、总数却掉下去"的那种倒退。
	if n := c.Node; nodeCounts(n) {
		// 收尾的这条只补"上次清零之后"的那部分；水位以下的已经算过了。
		acc := r.nodeClosed[n]
		acc.up += chargedDelta(up, c.chargedUp)
		acc.down += chargedDelta(down, c.chargedDown)
		acc.conns++
		r.nodeClosed[n] = acc
	}
	// 同一批字节再按命中依据记一遍：节点会切换，规则不会，
	// "这个站点的量为什么这么大"只有按规则才答得上来。
	// 被拦的（Node 是 REJECT）在这里占一行——它在节点表里没有行，
	// 因为零字节只会稀释那张表；而"哪条规则在拦"本身就是这条表的用途。
	if m := strings.TrimSpace(c.Matched); m != "" {
		key, acc := r.ruleSlotLocked(m)
		acc.up += chargedDelta(up, c.chargedUp)
		acc.down += chargedDelta(down, c.chargedDown)
		acc.conns++
		r.ruleClosed[key] = acc
	}
	delete(r.active, c.ID)
	if r.histCap > 0 {
		r.history = append(r.history, c.view(time.Now()))
		if len(r.history) > r.histCap {
			r.history = append(r.history[:0], r.history[len(r.history)-r.histCap:]...)
		}
	}
	r.mu.Unlock()
}

// view 投影成可序列化结构。at 为零值时用连接自身的起始时间。
func (c *Conn) view(at time.Time) ConnView {
	if at.IsZero() {
		at = c.Start
	}
	d := at.Sub(c.Start)
	if d < 0 {
		d = 0
	}
	return ConnView{
		ID:       c.ID,
		Start:    c.Start.UnixMilli(),
		Duration: d.Milliseconds(),
		Inbound:  c.Inbound,
		Client:   c.Client,
		Host:     c.Host,
		Port:     c.Port,
		Target:   net.JoinHostPort(c.Host, c.Port),
		Policy:   c.Policy,
		Matched:  c.Matched,
		Outbound: c.Outbound,
		Node:     c.Node,
		Iface:    c.Iface,
		Err:      c.Err,
		Up:       c.Up.Load(),
		Down:     c.Down.Load(),
	}
}

// StartSampler 启动每秒一次的速率采样 goroutine。重复调用无副作用。
// seriesCap 为 0 且不落账本时什么都不做。
//
// 这条 goroutine 顺带负责每分钟一次的用量落盘：另起一条 ticker 就要另写一套
// 起停配对（而"Stop 之后不留 goroutine"这条在这里已经有测试盯着），
// 一分钟一次的粒度也犯不上单独一条。
func (r *Registry) StartSampler() {
	if r == nil {
		return
	}
	// 检查与赋值要一起放进临界区：裸着写这两个字段时，两个并发调用
	// 会各自起一个 ticker goroutine，被覆盖的那条 stop 通道从此没人能关，
	// 于是留下一个每秒钟醒一次、永不退出的 goroutine。
	r.mu.Lock()
	if (r.seriesCap <= 0 && r.usagePath == "") || r.samplerStop != nil {
		r.mu.Unlock()
		return
	}
	stop, done := make(chan struct{}), make(chan struct{})
	r.samplerStop, r.samplerDone = stop, done
	r.mu.Unlock()

	go func() {
		defer close(done)
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for tick := 1; ; tick++ {
			select {
			case <-t.C:
				if r.seriesCap > 0 {
					r.sample()
				}
				if tick%usageFlushEvery == 0 {
					r.maybeFlushUsage()
				}
			case <-stop:
				return
			}
		}
	}()
}

// StopSampler 停止采样 goroutine 并等待其退出。重复调用无副作用。
func (r *Registry) StopSampler() {
	if r == nil {
		return
	}
	// 先摘句柄再等退出：采样 goroutine 自己也要抢 r.mu 去写 series，
	// 攥着锁等它退出就是死锁。句柄在锁内置空，顺带让并发的两次
	// StopSampler 各自只拿到一次 close 的机会（否则第二次 close 已关闭的
	// 通道会 panic）。
	r.mu.Lock()
	stop, done := r.samplerStop, r.samplerDone
	r.samplerStop, r.samplerDone = nil, nil
	r.mu.Unlock()

	if stop == nil {
		return
	}
	close(stop)
	<-done
	// 收尾那一次落盘要等 goroutine 真的退了之后再做：两条路同时在写同一份账，
	// 后写的那一份可能已经是半秒前的数了。
	r.maybeFlushUsage()
}

// sample 采集一个点：拿累计字节与上一个点做差得到速率。
func (r *Registry) sample() {
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	// 差分要建立在单调不减的量上，这里用的是
	// 「已结束连接的累计 + 仍在跑的累计」：每个字节在连接活着时算在 active、
	// 结束时算进 total，两边既不重复也不消失，因此相加只会变大或不变。
	//
	// 以前这里只取 activeTotals，而它会在任意一条连接结束的瞬间变小，
	// uint64 相减直接下溢——5MB 的差值会变成 1.8446744e19 字节/秒的假尖峰。
	// 浏览器每分钟开关上百条短连接，面板流量图于是永远是满格毛刺。
	// 换成 total+active 之后这条不变量应当成立，但成立不等于可以不检查：
	// 真出现回退时 diffRate 会把这一格记成 0 并打出双方的值，
	// 而不是再画一根把整张图 Y 轴顶到 PB 级的假尖峰。
	up := r.totalUp.Load()
	down := r.totalDown.Load()
	for _, c := range r.active {
		up += c.Up.Load()
		down += c.Down.Load()
	}

	s := Sample{T: now.UnixMilli(), rawUp: up, rawDown: down}
	if n := len(r.series); n > 0 {
		prev := r.series[n-1]
		if dt := now.Sub(time.UnixMilli(prev.T)).Seconds(); dt > 0 {
			s.Up = diffRate(prev.rawUp, up, dt, "上行")
			s.Down = diffRate(prev.rawDown, down, dt, "下行")
		}
	}
	r.series = append(r.series, s)
	if len(r.series) > r.seriesCap {
		r.series = append(r.series[:0], r.series[len(r.series)-r.seriesCap:]...)
	}
}

// diffRate 算一个采样格的速率：(cur-prev)/dt，并守住「总量不会倒退」这条前提。
//
// uint64 直接相减在倒退时下溢成 ~1.8e19，摊到 dt 上就是一根几百 PB/s 的假尖峰；
// 速率图是自动取轴的，一根假尖峰能把整条曲线的可读性吃掉——面板上真实速率
// 只有几 MB/s，Y 轴却被顶到 1000 PB。所以倒退时这一格记 0，并把两边的值打出来：
// 这条不变量真被破坏时，日志里要留得下现场，而不是悄悄画个洞。
func diffRate(prev, cur uint64, dt float64, dir string) float64 {
	if cur < prev {
		logx.Warnf("metrics: %s累计值倒退（上一格 %d → 本格 %d），这一格按 0 处理", dir, prev, cur)
		return 0
	}
	return float64(cur-prev) / dt
}

// Snapshot 返回全量快照。所有切片都是新拷贝，调用方可以安全持有。
func (r *Registry) Snapshot() Snapshot {
	if r == nil {
		return Snapshot{Active: []ConnView{}, History: []ConnView{}, Series: []Sample{}, RecentBlocked: []BlockedHit{}}
	}
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	active := make([]ConnView, 0, len(r.active))
	for _, c := range r.active {
		active = append(active, c.view(now))
	}
	// 活动连接按流量从大到小排，最忙的连接永远在表头。
	sortByTraffic(active)

	history := make([]ConnView, len(r.history))
	copy(history, r.history)
	// 历史按结束时间倒序，最新结束的在前。
	reverseViews(history)

	series := make([]Sample, len(r.series))
	copy(series, r.series)

	// 按节点合计 = 已收尾的 + 还在跑的。
	live := map[string]nodeBytes{}
	for _, c := range r.active {
		n := c.Node
		if !nodeCounts(n) {
			continue
		}
		a := live[n]
		// 在跑的这条只算水位以上：清零之后它不该再把历史字节算进来。
		a.up += chargedDelta(c.Up.Load(), c.chargedUp)
		a.down += chargedDelta(c.Down.Load(), c.chargedDown)
		a.conns++
		live[n] = a
	}
	merged := make(map[string]nodeBytes, len(r.nodeClosed)+len(live))
	for n, a := range r.nodeClosed {
		merged[n] = a
	}
	for n, a := range live {
		m := merged[n]
		m.up += a.up
		m.down += a.down
		m.conns += a.conns
		merged[n] = m
	}
	byNode := make([]NodeTraffic, 0, len(merged)+len(r.prior))
	// 上一次进程用过、这次一条都没碰的节点也要有行：配额问题的答案恰恰是
	// "这个月它一共跑了多少"，而重启之后完全可能还没走到它。只摆本次用过的节点，
	// 那个数就会凭空消失，看上去像"没跑过"。
	priorOf := func(n string) uint64 {
		p := r.prior[n]
		return p.up + p.down
	}
	for n := range r.prior {
		if _, ok := merged[n]; !ok && nodeCounts(n) {
			merged[n] = nodeBytes{}
		}
	}
	for n, a := range merged {
		byNode = append(byNode, NodeTraffic{Node: n, Up: a.up, Down: a.down, Conns: a.conns, Prior: priorOf(n)})
	}
	sort.Slice(byNode, func(i, j int) bool {
		// 排的是**累计**（含 prior），因为那才是这一列给人读的量；
		// 只按本次排会把"这个月用了 40GB、今天还没开始"的那个节点排到最后。
		si := byNode[i].Up + byNode[i].Down + byNode[i].Prior
		sj := byNode[j].Up + byNode[j].Down + byNode[j].Prior
		if si != sj {
			return si > sj
		}
		return byNode[i].Node < byNode[j].Node
	})

	// 按规则合计：同一批字节的另一种分法。活的这条也算水位以上。
	liveRule := map[string]ruleBytes{}
	for _, c := range r.active {
		m := strings.TrimSpace(c.Matched)
		if m == "" {
			continue
		}
		a := liveRule[m]
		a.up += chargedDelta(c.Up.Load(), c.chargedUp)
		a.down += chargedDelta(c.Down.Load(), c.chargedDown)
		a.conns++
		liveRule[m] = a
	}
	mergedRule := make(map[string]ruleBytes, len(r.ruleClosed)+len(liveRule))
	for m, a := range r.ruleClosed {
		mergedRule[m] = a
	}
	for m, a := range liveRule {
		x := mergedRule[m]
		x.up += a.up
		x.down += a.down
		x.conns += a.conns
		mergedRule[m] = x
	}
	ruleRows := make([]RuleTraffic, 0, len(mergedRule))
	for m, a := range mergedRule {
		ruleRows = append(ruleRows, RuleTraffic{Rule: m, Up: a.up, Down: a.down, Conns: a.conns})
	}
	sort.Slice(ruleRows, func(i, j int) bool {
		si := ruleRows[i].Up + ruleRows[i].Down
		sj := ruleRows[j].Up + ruleRows[j].Down
		if si != sj {
			return si > sj
		}
		return ruleRows[i].Rule < ruleRows[j].Rule
	})
	// 超出展示行数的那部分折成一行，而不是丢掉：这张表加起来必须仍然等于总量，
	// 否则「按规则看」就成了一个只能看不能对账的东西——
	// 而它唯一的用途恰恰是回答"这些量到底是谁的"。
	if len(ruleRows) > ruleRowsShown {
		rest := ruleRows[ruleRowsShown-1:]
		var folded RuleTraffic
		folded.Rule = "（其余 " + strconv.Itoa(len(rest)) + " 条规则）"
		folded.Folded = uint64(len(rest))
		for _, row := range rest {
			folded.Up += row.Up
			folded.Down += row.Down
			folded.Conns += row.Conns
		}
		ruleRows = append(ruleRows[:ruleRowsShown-1], folded)
	}

	// 留痕按"最近撞上的排最前"交给投影这一层来翻，内部始终是新在后。
	blocked := make([]BlockedHit, len(r.blocked))
	for i, b := range r.blocked {
		blocked[len(r.blocked)-1-i] = b
	}

	up, down := r.totalUp.Load(), r.totalDown.Load()
	for _, c := range r.active {
		up += c.Up.Load()
		down += c.Down.Load()
	}

	return Snapshot{
		Active:        active,
		History:       history,
		Series:        series,
		ActiveCount:   len(active),
		TotalConns:    r.totalConns.Load(),
		TotalBlocked:  r.totalBlocked.Load(),
		TotalFailed:   r.totalFailed.Load(),
		RecentBlocked: blocked,
		ByNode:        byNode,
		ByRule:        ruleRows,
		TotalUp:       up,
		TotalDown:     down,
		PriorSince:    r.priorSince,
		PriorSavedAt:  r.priorSavedAt,
		UsageState:    r.usageOutcomeLocked(),
	}
}

// Reset 清空全部统计，用于「重置统计」按钮。
// BlockedTotal 只读那个原子计数，不拷贝任何切片。
// 托盘每两秒问一次，用 Snapshot() 就等于每两秒复制一遍整张连接表。
func (r *Registry) BlockedTotal() uint64 {
	if r == nil {
		return 0
	}
	return r.totalBlocked.Load()
}

// RuleHits 返回"每条规则的命中依据被用过多少次"的一份快照。
//
// 返回的是副本：调用方（面板每 5 秒问一次）会拿着它慢慢比对，
// 直接把内部 map 交出去等于让一次 Begin 的写入改掉人家正在读的东西。
// 键是引擎写下的那串文本，怎么对回界面上的某一行的见 rules.UserRule.Desc()。
func (r *Registry) RuleHits() map[string]int64 {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.ruleHits) == 0 {
		return nil
	}
	out := make(map[string]int64, len(r.ruleHits))
	for k, v := range r.ruleHits {
		out[k] = v
	}
	return out
}

func (r *Registry) Reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.history = r.history[:0]
	r.series = r.series[:0]
	r.blocked = r.blocked[:0]
	// 「清空统计」清的是本次会话的所有读数，按节点的账本也在其列：
	// 只清总数不清分节点，界面上就会出现"总数 0、JP 还有 3GB"。
	r.nodeClosed = make(map[string]nodeBytes)
	// 命中排行同属"本次会话的读数"：不清它就会出现
	// "总数 0、连接表空了，可规则页还说这条刚刚命中过 800 次"。
	r.ruleHits = make(map[string]int64)
	// 还在跑的连接把水位推到当前值：它们此后的字节才算新账。
	// （active 不清——连接确实还在跑，表里就该看见它。）
	for _, c := range r.active {
		c.chargedUp = c.Up.Load()
		c.chargedDown = c.Down.Load()
	}
	// 清零也要在锁内：End 现在是在同一个临界区里累加的，
	// 放到锁外就会和它抢跑，把刚记上的那一笔覆盖掉。
	r.totalUp.Store(0)
	r.totalDown.Store(0)
	r.totalConns.Store(0)
	r.totalBlocked.Store(0)
	r.totalFailed.Store(0)
	r.mu.Unlock()
}

func sortByTraffic(v []ConnView) {
	// 插入排序：活动连接数量级是十几次，比较次数可忽略，比引入 sort 更好读。
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j].Up+v[j].Down > v[j-1].Up+v[j-1].Down; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func reverseViews(v []ConnView) {
	for i, j := 0, len(v)-1; i < j; i, j = i+1, j-1 {
		v[i], v[j] = v[j], v[i]
	}
}
