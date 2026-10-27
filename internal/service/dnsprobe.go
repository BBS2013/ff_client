package service

// 「看解析」：诊断三连里的第三问。
//
// 「查走向」答"按规则该怎么走"，「取一个真页面」答"那它实际回什么"，
// 两者之间还夹着一件谁都没直接答过的事：**引擎此刻拿到的 IP 是哪一批**。
//
// 为什么这一格值得单独存在，§10.7 那次误判就是理由：一个域名被污染成国内地址，
// `GEOIP,CN,DIRECT` 判不中，流量白绕一圈隧道。只看「查走向」那一格，
// 得到的是结果（DIRECT 还是 PROXY），拿不到"它是照着哪几个 IP 判出来的"，
// 于是"名单缺项"这个假结论看起来比"DNS 被污染"这个真结论更像话。
//
// 判定本体仍然只有一份：这一格调的是 `Engine.MatchIPAddrs` 与 `Engine.CountryOf`，
// 它们都是既有 `matchIP` / geo 查表的公开入口，不是这里另实现一遍。

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"wps_app/internal/dnsx"
	"wps_app/internal/logx"
)

// AddrView 是一个地址"被怎么看"。
type AddrView struct {
	Addr string `json:"addr"`
	// Country 是 GeoIP 归属码。空串本身不够——"库里没有这条"与"这不是 CN"
	// 是两句话，前者不能说成后者（那是把不知道报成一个结论）。
	Country string `json:"country"`
	Known   bool   `json:"known"`
}

// UpstreamView 是**一个上游**的回话，以及"只看它给的那批地址会判成什么"。
type UpstreamView struct {
	Server  string   `json:"server"`
	Addrs   []string `json:"addrs"`
	Policy  string   `json:"policy"`
	Matched string   `json:"matched"`
	Ms      int64    `json:"ms"`
	// Err 非空 = 这个上游没答上来（超时、REFUSED…）。它仍然要摆出来：
	// "三个上游里有一个从来不答"本身就是有用的事实，藏起来等于少报一档。
	Err string `json:"err"`
}

// DNSProbe 是一次"此刻再问一次会拿到什么"。
type DNSProbe struct {
	// Host 是洗过的查询名（小写、去尾点、去空格）。
	Host string `json:"host"`
	// Via 是这次**真的**走了哪条路：direct / tunnel。没注入隧道拨号器时
	// 要隧道也等价于直连，而这里就报直连——不能指着一份本机答案说"这是节点那头问的"。
	Via string `json:"via"`
	// TunnelOn 是配置里让不让经隧道问上游。它与 Via 分开，是因为
	// "配了但隧道还没起来"与"没配"是两句不同的话，混起来就找不到那个缺口。
	TunnelOn bool `json:"tunnelOn"`
	// Cached 为真表示这份答案是缓存里的，没有出门问。
	Cached bool `json:"cached"`
	// Fresh 为真表示**这一次是刷新，不是查看**：没读缓存，问完已写回。
	// 它与 Cached 不是互斥的两个说法——Cached 讲"这份答案从哪儿来"，
	// Fresh 讲"你这一下改了什么"。少了后者，界面就没法说出
	// "引擎下一刻拿的是这批"这句要紧的话（这一按不只是看一眼，它动了状态）。
	Fresh bool `json:"fresh"`
	// Refreshed 非空表示这一次是**只点名重问某一个上游**，值就是那个上游地址。
	// 它必须单独报出来：这一按之后合并那一路刻意没再走（再走一遍会把另一个上游——
	// 往往正是被怀疑的那一个——的答案又盖回来，那一按就成了"刷了等于没刷"）。
	// 界面不说清是哪一家被刷了，人就以为刷的是整条路径。
	Refreshed string `json:"refreshed"`
	// TtlMs 是这份答案**还剩多久**自己变新（命中缓存=剩余，刚问到=整条 TTL）。
	// 有了它，"命中缓存"才不是一句"这是旧的、你要么忍要么重启"。
	TtlMs int64 `json:"ttlMs"`
	// Ms 是这次探测用了多久（缓存命中就在 0 附近，所以"新不新鲜"看 Cached 不看它）。
	Ms int64 `json:"ms"`
	// Upstreams 是配置里那几个上游地址。查污染时第一个要看的就在这个列表里。
	Upstreams []string `json:"upstreams"`
	// Addrs 是引擎此刻拿去判定的那批地址。
	Addrs []AddrView `json:"addrs"`
	// PerUpstream 是**挨个上游各问一遍**的结果（不合并、不抢先返回）。
	// 这一份才是"哪个上游在说谎"那一问的答案：上面 Addrs 走的是"任一成功即采用"，
	// 两个上游分叉时它只留下先回来的那一个。
	PerUpstream []UpstreamView `json:"perUpstream"`
	// Divergent 为真表示至少两个上游给了**不同的地址集合**。
	// 判据不能是"出现过的地址多于一条"——一个上游本来就可以回两条 A，那是正常多出口。
	Divergent bool `json:"divergent"`
	// Used 是上面 Addrs 那份答案对应的是哪个上游（按地址集合对上）。
	// 空串 = 说不清（只有一个上游、或者合并结果与谁都不完全相同）。
	Used string `json:"used"`
	// Policy / Matched 是引擎对这个**域名**的完整判定（域名规则可能先命中）。
	Policy  string `json:"policy"`
	Matched string `json:"matched"`
	// IPPolicy / IPMatched 是"只看这批 IP 会判成什么"。
	// 两半分开给才有意义：两者不一样，就说明域名规则先命中、DNS 根本没参与这次结论。
	IPPolicy  string `json:"ipPolicy"`
	IPMatched string `json:"ipMatched"`
	// Note 是"这一格为什么是空的"：解析不出、没配 GeoIP 库这类。
	// 空表不写一句话，就会被读成"这个域名没有地址"。
	Note string `json:"note"`
}

// ProbeDNS 问一次当前解析器，并把引擎会怎么判这批地址一起带回来。
//
// fresh 为真 = 「重问（不用缓存）」那一下：不读缓存，问完把新答案写回缓存，
// 于是引擎下一刻判定用的就是这批地址。它是个**动作**，不是一次查看，
// 所以调用方（界面上）必须把它说清楚。
//
// upstream 非空 = 「只重问这一家」：只问被点名的那个上游、只把它的回答写回这一条域名的缓存，
// 之后读的就是这份。它**不**再走合并那一路——再走一遍等于让另一个上游（往往正是被怀疑的那一个）
// 把刚写回的盖掉，那一按就成了"刷了等于没刷"。两家同时给（fresh 与 upstream 都非空）时
// 以 upstream 为准：点名比"整条重来"更具体，人想知道的就是这一家。
//
// 解析不出**不是查询失败**：那正是这一问的答案（NXDOMAIN 或被污染丢弃都长这样），
// 所以它走 Note + 空表，不走 error。这与 `Preview` 里"被拦不算失败"、
// `FetchPage` 里"取回 400 不算失败"是同一条规矩。
// 但**点名重问失败**是另一回事：那是人刚下的那个动作没办成，直接报 error。
func (s *Service) ProbeDNS(ctx context.Context, host string, fresh bool, upstream string) (DNSProbe, error) {
	s.mu.Lock()
	rt, res, cfg := s.rt, s.resolve, s.cfg
	geoOK := s.geoOK
	s.mu.Unlock()
	// 停着的时候不答：这套解析器根本没起来，拿系统 resolver 的答案冒充它的，
	// 正是这一格最不该说的话（它要答的就是"引擎会照着哪批 IP 判"）。
	if rt == nil || res == nil {
		return DNSProbe{}, errors.New("代理没在跑：这套解析器还没起来，先点「启动」")
	}
	name := strings.TrimSpace(host)
	if name == "" {
		return DNSProbe{}, errors.New("先填一个域名")
	}
	tunnelOn := cfg != nil && cfg.DNS.TunnelResolveOn()
	path := dnsx.PathDirect
	if tunnelOn {
		path = dnsx.PathTunnel
	}
	var (
		pr        dnsx.ProbeResult
		err       error
		refreshed string
	)
	switch {
	case upstream != "":
		ans := res.ProbeEachRefresh(ctx, name, path, []string{upstream})
		if len(ans) == 1 && ans[0].Err != "" {
			logx.Warnf("dns: 手动重问 %s 没成功：%s（%s）", name, upstream, ans[0].Err)
			return DNSProbe{}, fmt.Errorf("重问 %s 没成功：%s", upstream, ans[0].Err)
		}
		refreshed = upstream
		pr, err = res.Probe(ctx, name, path)
	case fresh:
		pr, err = res.ProbeFresh(ctx, name, path)
	default:
		pr, err = res.Probe(ctx, name, path)
	}
	// 只有**改掉了状态**的那两种才记日志。普通"看一眼"不记：那一问每秒都在发生
	// （连接要建立时引擎自己就会解析），把它记成"有人查过"会把日志刷成噪音，
	// 而这一行的用途恰恰是"事后说得清这批地址是谁换进来的"。
	if refreshed != "" || fresh {
		what := "整条路径"
		if refreshed != "" {
			what = "只问 " + refreshed
		}
		if err != nil {
			logx.Warnf("dns: 手动重问 %s（%s）没问到地址：%v", name, what, err)
		} else {
			logx.Infof("dns: 手动重问 %s（%s）→ %s，已写回缓存：引擎下一刻就按这批地址判定",
				name, what, addrsText(pr.Addrs))
		}
	}
	out := DNSProbe{
		Host: pr.Host, Via: pr.Path.String(), TunnelOn: tunnelOn,
		Cached: pr.Cached, Fresh: fresh || refreshed != "", Refreshed: refreshed,
		TtlMs: pr.TtlMs, Ms: pr.Ms,
		Addrs: []AddrView{},
	}
	if cfg != nil {
		out.Upstreams = append(out.Upstreams, cfg.DNS.Servers...)
	}
	if err != nil {
		out.Note = "没问到地址：" + err.Error()
		return out, nil
	}
	eng := rt.Engine()
	if eng == nil {
		out.Note = "规则引擎还没装载，归属码与判定都答不了"
		return out, nil
	}
	for _, a := range pr.Addrs {
		cc, known := eng.CountryOf(a)
		out.Addrs = append(out.Addrs, AddrView{Addr: a.String(), Country: cc, Known: known})
	}
	ipP, ipD := eng.MatchIPAddrs(pr.Addrs)
	out.IPPolicy, out.IPMatched = string(ipP), ipD
	p, d := eng.Match(ctx, pr.Host)
	out.Policy, out.Matched = string(p), d
	// 再挨个上游问一遍。这一步会**多发一轮 DNS**（每个上游一次），
	// 但它只在人真点了「解析」时发生，不是每秒轮询的一部分——这个代价换的
	// 是"哪个上游在说谎"那一问，值。
	merged := make([]string, 0, len(pr.Addrs))
	for _, a := range pr.Addrs {
		merged = append(merged, a.String())
	}
	for _, u := range res.ProbeEach(ctx, pr.Host, path) {
		view := UpstreamView{Server: u.Server, Ms: u.Ms, Err: u.Err, Addrs: []string{}}
		for _, a := range u.Addrs {
			view.Addrs = append(view.Addrs, a.String())
		}
		if u.Err == "" && len(u.Addrs) > 0 {
			vp, vd := eng.MatchIPAddrs(u.Addrs)
			view.Policy, view.Matched = string(vp), vd
		}
		out.PerUpstream = append(out.PerUpstream, view)
	}
	out.Divergent = upstreamsDiffer(out.PerUpstream)
	out.Used = whichUpstreamAnswered(out.PerUpstream, merged)
	switch {
	case !geoOK:
		out.Note = "没配 GeoIP 库：GEOIP 那类规则一条都不会命中，归属码这一格只能是空的"
	case len(out.Addrs) == 0:
		out.Note = "上游回了成功但一个地址都没有（没有 A 也没有 AAAA）"
	}
	return out, nil
}

// upstreamsDiffer 判断有没有两个上游给了**不同的地址集合**。
//
// 判据不能是"出现过的地址多于一条"：一个上游本来就可以回两条 A 记录，
// 那是正常的多出口，不是分叉。只有两个都答了的上游互相对不上才算。
// 没答上的上游不参与比较——它给不出"不同的答案"，只给得出"没答案"。
func upstreamsDiffer(list []UpstreamView) bool {
	var first []string
	have := false
	for _, u := range list {
		if u.Err != "" || len(u.Addrs) == 0 {
			continue
		}
		got := sortedCopy(u.Addrs)
		if !have {
			first, have = got, true
			continue
		}
		if !sameStrings(first, got) {
			return true
		}
	}
	return false
}

// whichUpstreamAnswered 找出合并那份答案是谁给的（按地址集合对上）。
// 说不清就返回空串，不猜：只有一个上游时"就是它"是废话，
// 而合并结果与谁都不完全相同时（比如先回来的那个上游这会儿换了答案）
// 硬指一个就是假话。
func whichUpstreamAnswered(list []UpstreamView, merged []string) string {
	if len(list) < 2 {
		return ""
	}
	want := sortedCopy(merged)
	for _, u := range list {
		if u.Err != "" || len(u.Addrs) == 0 {
			continue
		}
		if sameStrings(want, sortedCopy(u.Addrs)) {
			return u.Server
		}
	}
	return ""
}

// addrsText 把一批地址写成日志里那一串。空表要留一句人话：
// "手动重问 x → （空）"读起来像日志坏了，而"没问到地址"才是那一按的结果。
func addrsText(list []netip.Addr) string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.String())
	}
	if len(out) == 0 {
		return "没问到地址"
	}
	return strings.Join(out, " ")
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
