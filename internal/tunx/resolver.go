package tunx

// 「DNS 劫持到底有没有生效」这一段。
//
// 劫持只在「系统解析器把查询发往一个没被豁免的地址」时才成立。豁免按目的地址
// 放行（按 uid 放行会豁免掉本来要服务的那个人，理由见 RoutePlan.Upstreams 那段），
// 而放行清单必然包含 dns.internal_servers——service 那边是刻意把它们并进去的，
// 否则解析器问公司 DNS 的查询会被自己劫持回来，变成问自己。
//
// 于是一种配置组合会把整套劫持静默作废：**这台机器的系统解析器只有内网上游**。
// 2026-11-04 现场就是它——systemd-resolved 的上游只有 10.180.191.11，那条 RETURN
// 吞掉全部查询，假 IP 一个都没发出去（`dig @172.19.0.2` 却答得好好的，因为那是
// 直接问我们，不是经系统解析器绕过来）。症状是「面板说 TUN 已启用，而本机流量
// 整条从物理卡裸奔」：认代理环境变量的程序照常，不认的（被 --proxy-server=direct://
// 钉住的那些）直接后端连不通、登录被弹「账户非法」。
//
// 所以装完劫持必须**问系统解析器**，而不是问自己的 DNS：只有自己被问到，
// 说明别人发的查询也在被我们收到。判据用假 IP 段落点，不靠记忆也不看计数器——
// 计数器为 0 可能只是没人查过域名，那既不能证明活着也不能证明死了。
//
// 验出来收不到时，把这条 link 的上游改接成我们的 DNS 落点（并把原值记进配置文件
// 旁边的状态文件，停止或被 kill 之后都要还得回去）。为什么不改成「加一个上游」：
// resolved 会并发问所有上游并采用先到的答案，公司 DNS 回污染地址比隧道里的假 IP
// 快，混在一起就变成同一批域名时好时坏——比全错更难查。

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/sudoown"
)

// hijackProbeName 是自检用的域名。
//
// 不能用 .invalid / .test / .local 这些 RFC 6761 保留后缀：systemd-resolved 对
// 它们直接本地合成答案、根本不往外发，那种名字会让自检永远报「劫持没生效」，
// 于是每一次启用 TUN 都白改一遍系统解析器。
// 也不拿真实业务域名：探针答案会进解析器缓存，名字要让人过一眼就知道是本程序造的。
const hijackProbeName = "wps-tun-check-probe.com"

// resolverProbeBudget 是问一次系统解析器的时间预算。
//
// 必须有上限：这一步是在 Start 的锁里做的。超时不是失败而是「读不到」——
// 解析器不可达时最不该做的就是改它的配置。
const resolverProbeBudget = 2 * time.Second

// resolverFeeds 是三档结论，第三档必须独立存在。
type resolverFeeds int

const (
	// feedsUnknown 是没验出来（解析器没回答、没有 resolvectl、假 IP 段没配）。
	// 它绝不能并进 feedsNo：拿一次「读不到」去做改系统解析器这种动作，
	// 等于用不确定的证据做确定的改动，而改错的代价是整机解析。
	feedsUnknown resolverFeeds = iota
	// feedsYes 是探针答案落在假 IP 段里：别人的查询确实被我们收走了。
	feedsYes
	// feedsNo 是探针答得出、却落在段外：劫持装了，一个包也没拦到。
	feedsNo
)

// label 交出给界面与日志看的那句话。四档必须分得开：
// 「没验过」和「验出没生效」是两句话，而只有后者需要用户改配置或接受接管。
func (f resolverFeeds) label() string {
	switch f {
	case feedsYes:
		return "yes"
	case feedsNo:
		return "no"
	default:
		return "unverified"
	}
}

// reading 交出界面该显示的那一档。
//
// 接管成功时不能再报 "no"：那时劫持确实还是收不到别人的查询，
// 但系统解析器已经被我们改接了，用户看到的「没生效」会变成一句假警报。
func (s resolverState) reading() string {
	if s.tookOver {
		return "taken-over"
	}
	return s.feeds.label()
}

// resolverLedger 是「我们改过系统解析器」的那笔账。
type resolverLedger struct {
	// Link 是改的那张 link（resolvectl 的 per-link DNS，不是全局配置）。
	Link string `json:"link"`
	// Prev 是动手前这条 link 上的上游，可能为空（DHCP 本来就没发）。
	Prev []string `json:"prev"`
	// Applied 是我们写进去的地址。判断「现在这个值是别人设的还是我们设的」
	// 全靠它——被 kill 之后重来一轮，若拿当前值当 Prev 记下来，
	// 回滚就会把解析器永久钉在自己身上，而那块网卡早没了。
	Applied []string  `json:"applied"`
	SavedAt time.Time `json:"savedAt"`
}

// resolverState 是这一段在 TUN 里的活体状态，全部受 t.mu 保护。
type resolverState struct {
	// ledger 非空表示「系统解析器现在是我们改的」，停止时要写回去。
	ledger *resolverLedger
	feeds  resolverFeeds
	// tookOver 区分「本来就收得到」与「收不到、是我们接过来的」——
	// 界面上这两句话不一样，后者意味着这台机器的劫持规则对它无效。
	tookOver bool
	detail   string
}

// resolverStatePath 与 sysproxy 的状态文件同一套路：配置文件旁边，
// 相对配置路径推导，重定向配置文件就一起搬家。
// 配置路径为空时返回空串——这一轮就不落盘（内存里的账仍然够 Stop 回滚）。
func resolverStatePath(configPath string) string {
	if strings.TrimSpace(configPath) == "" {
		return ""
	}
	dir, base := filepath.Split(configPath)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, base+"-resolver.state")
}

func (l *resolverLedger) sameApplied(servers []string) bool {
	return sameAddrSet(l.Applied, servers)
}

// sameAddrSet 判断两组上游是不是同一组，**顺序不参与语义**：
// resolvectl 回读的顺序与我们写入的顺序不保证一致（实测同一条 link
// 两次回读的排列可以不同）。按字符串比会得出"别人的配置"，于是
// 被 kill 之后不再回滚，系统解析器永久指着已经消失的 tun 地址。
//
// 空项与空白先洗掉：resolvectl 会把 "（没有上游）" 之外的空白也印出来。
func sameAddrSet(a, b []string) bool {
	clean := func(in []string) map[string]struct{} {
		out := make(map[string]struct{}, len(in))
		for _, s := range in {
			if s = strings.TrimSpace(s); s != "" {
				out[s] = struct{}{}
			}
		}
		return out
	}
	as, bs := clean(a), clean(b)
	if len(as) != len(bs) {
		return false
	}
	for s := range as {
		if _, ok := bs[s]; !ok {
			return false
		}
	}
	return true
}

// checkResolverFeedsTUN 验一次劫持是否真的收得到查询，收不到就接管系统解析器。
//
// 调用方必须持有 t.mu（Start 全程持锁，与 publishTakeoverLocked 同一纪律）。
// 这一步不推翻启用：验不出结论、接管失败，都只是把状态如实贴出来，
// 因为 TUN 对认代理的程序仍然有用，而「没接管成」已经把话说清了。
func (t *TUN) checkResolverFeedsTUN(ctx context.Context) {
	t.resolver.feeds, t.resolver.detail, t.resolver.tookOver = feedsUnknown, "", false

	verdict, detail := probeHijacked(ctx, t.runner, t.conf.FakeIPRange)
	if verdict == feedsYes {
		logx.Infof("TUN: DNS 劫持确实在收别人的查询（%s）", detail)
		t.resolver.feeds, t.resolver.detail = verdict, detail
		return
	}
	t.resolver.feeds, t.resolver.detail = verdict, detail
	if verdict == feedsUnknown {
		// 读不到就只说读不到。这里最容易犯的错是把它当成「没生效」去改配置，
		// 于是解析器不可达的那一刻，系统里多出一条指向不存在网卡的 DNS。
		logx.Warnf("TUN: 验不出 DNS 劫持有没有生效（%s），不动系统解析器", detail)
		return
	}

	logx.Warnf("TUN: DNS 劫持装了但收不到任何查询（%s）——本机上游全在放行清单里，TUN 对不认代理的程序形同关闭", detail)
	link, prev, ok := t.currentDNSLink(ctx)
	if !ok {
		logx.Warnf("TUN: 没能接管系统解析器：读不到当前 link 的上游。手动做法：resolvectl dns <网卡> %s", t.dnsAddress())
		return
	}
	if err := t.takeoverResolver(ctx, link, prev); err != nil {
		logx.Warnf("TUN: 接管系统解析器失败（%v）。手动做法：resolvectl dns %s %s", err, link, t.dnsAddress())
		return
	}
	t.resolver.tookOver = true
	t.resolver.detail = "已把 " + link + " 的上游从 " + orNone(prev) + " 改接为 " + t.dnsAddress()
	logx.Infof("TUN: 已接管系统解析器（%s → %s）。原值记在 %s，停用或下次启动时会写回去",
		link, t.dnsAddress(), resolverStatePath(t.configPath))
}

// probeHijacked 问系统解析器要一个探针域名，看答案落不落进假 IP 段。
//
// 走 resolvectl 而不是 getent：只有它能把「这条名字不存在」和「问不到解析器」
// 给出不同原文，而这个区分正是要不要动系统配置的依据。getent 两者都只回一个非零退出码。
func probeHijacked(ctx context.Context, r Runner, fakeRange string) (resolverFeeds, string) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(fakeRange))
	if err != nil {
		return feedsUnknown, "假 IP 段没配或读不懂（" + fakeRange + "）"
	}
	pctx, cancel := context.WithTimeout(ctx, resolverProbeBudget)
	defer cancel()
	out, err := r.Run(pctx, Cmd{
		Bin:  "resolvectl",
		Args: []string{"query", "--legend=no", hijackProbeName},
		Desc: "问系统解析器要一个探针域名", Optional: true,
	})
	if pctx.Err() != nil {
		return feedsUnknown, "系统解析器没在 " + resolverProbeBudget.String() + " 内回答"
	}
	if text := strings.TrimSpace(out); text != "" {
		// 必须扫完所有字段再下结论。resolvectl 的输出里可能先后出现多个地址
		// （AAAA 与 A 都列出、或者"Name: xxx"那一行里就带一个），
		// 见到第一个段外地址就判 feedsNo，会把"确实收到了劫持答案"读成
		// "劫持没生效"，进而去改系统解析器——而那次改动是不该发生的。
		var outside []string
		for _, field := range strings.Fields(text) {
			addr, perr := netip.ParseAddr(strings.TrimSuffix(field, ":"))
			if perr != nil {
				continue
			}
			if prefix.Contains(addr.WithZone("")) {
				return feedsYes, hijackProbeName + " → " + addr.String() + "（假 IP 段内）"
			}
			outside = append(outside, addr.String())
		}
		if len(outside) > 0 {
			return feedsNo, hijackProbeName + " → " + strings.Join(outside, ",") + "（段外，查询没被劫持收走）"
		}
		// 有输出但一个地址都没有（"Temporary failure"、权限错、Too many open
		// queries 之类）：这不是"劫持没生效"的证据，只是"没验出来"。
		// 判成 feedsNo 会去改系统解析器，而依据仅仅是一行错误文本。
		return feedsUnknown, hijackProbeName + " 没给出地址：" + firstLine(text, nil)
	}
	if err == nil {
		return feedsUnknown, "系统解析器答了空"
	}
	// 「域名不存在」是解析器真的把查询发出去并拿到了否定答复——也就是绕过了我们。
	if msg := err.Error(); strings.Contains(msg, "not registered") || strings.Contains(msg, "NXDOMAIN") {
		return feedsNo, hijackProbeName + " 被解析成不存在（NXDOMAIN）：查询原路发给了上游，没进 tun"
	}
	return feedsUnknown, firstLine("", err)
}

// currentDNSLink 找出「系统解析器此刻把上游配在哪张 link 上、原值是什么」。
//
// 优先默认路由那张卡；只有一条 link 配了上游时就用它——桌面机器常见 DHCP
// 只给一张卡发 DNS。两条以上又都不是默认出口时宁可不动：改错 link 等于
// 白改一次，还会让人以为已经接管。
func (t *TUN) currentDNSLink(ctx context.Context) (link string, prev []string, ok bool) {
	cands := parseLinkDNS(runOptional(ctx, t.runner, Cmd{
		Bin: "resolvectl", Args: []string{"dns"}, Desc: "读各 link 的 DNS 上游", Optional: true,
	}))
	if len(cands) == 0 {
		return "", nil, false
	}
	prefer := probeRouteState(ctx, t.runner, t.conf.Device).Interface
	if servers, hit := cands[prefer]; prefer != "" && hit && len(servers) > 0 {
		return prefer, servers, true
	}
	var named []string
	for link, servers := range cands {
		if len(servers) > 0 {
			named = append(named, link)
		}
	}
	if len(named) == 1 {
		return named[0], cands[named[0]], true
	}
	return "", nil, false
}

// parseLinkDNS 把 `resolvectl dns` 的输出读成 link → 上游列表。
// 形态：`Link 3 (wlp3s0f0): 172.19.0.2 8.8.8.8`；`Global:` 与没配上游的 link 也在输出里。
func parseLinkDNS(out string) map[string][]string {
	res := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Link ") {
			continue
		}
		open := strings.Index(line, "(")
		closed := strings.Index(line, ")")
		colon := strings.Index(line, ":")
		if open < 0 || closed <= open+1 || colon < closed {
			continue
		}
		name := line[open+1 : closed]
		var servers []string
		for _, f := range strings.Fields(line[colon+1:]) {
			if _, err := netip.ParseAddr(f); err == nil {
				servers = append(servers, f)
			}
		}
		res[name] = servers
	}
	return res
}

// takeoverResolver 把这条 link 的上游换成我们的 DNS 落点，并记下原值。
func (t *TUN) takeoverResolver(ctx context.Context, link string, prev []string) error {
	if l := readResolverLedger(t.configPath); l != nil && l.Link == link && l.sameApplied([]string{t.dnsAddress()}) {
		// 账还在，说明上一轮（多半是被 kill）改过没还原。照旧账接管，
		// 但绝不能把当前值当原值重记一遍——那时原值就永久丢了。
		prev = l.Prev
	}
	ledger := &resolverLedger{
		Link:    link,
		Prev:    append([]string(nil), prev...),
		Applied: []string{t.dnsAddress()},
		SavedAt: time.Now(),
	}
	// 先落账再动手：反过来就有一段「改了系统但没人知道改了什么」的窗口，
	// 而那正是被 kill 之后最难补的一种状态。
	if err := writeResolverLedger(t.configPath, ledger); err != nil {
		logx.Debugf("TUN: 接管系统解析器的账没落盘（%v），仍继续接管——停用时会靠内存里的这份还原", err)
	}
	out, err := t.runner.Run(ctx, Cmd{
		Bin:  "resolvectl",
		Args: []string{"dns", link, t.dnsAddress()},
		Desc: "把系统解析器接 tun 的 DNS",
	})
	if err != nil {
		_ = removeResolverLedger(t.configPath)
		return errors.New(firstLine(out, err))
	}
	t.resolver.ledger = ledger
	t.flushResolverCache(ctx)
	return nil
}

// restoreResolver 把我们改过的系统解析器写回原值。
//
// 调用方必须持有 t.mu。这里刻意不用 `resolvectl revert`：实测（2026-11-04）
// 它会把这条 link 的上游直接清空，而不是退回 DHCP 给的那一组——
// 于是「回滚」变成「整机解析死」，比不改还糟。只有原值本来就为空时，
// revert 才是对的动作（那时我们要的状态本身就是「这条 link 没有上游」）。
func (t *TUN) restoreResolver(ctx context.Context) {
	l := t.resolver.ledger
	if l == nil {
		return
	}
	t.resolver.ledger = nil
	if len(l.Prev) == 0 {
		runOptional(ctx, t.runner, Cmd{
			Bin: "resolvectl", Args: []string{"revert", l.Link},
			Desc: "原值本为空，撤销这条 link 的 DNS", Optional: true,
		})
		logx.Infof("TUN: 已撤销对系统解析器的接管（%s：原来没有上游）", l.Link)
	} else {
		args := append([]string{"dns", l.Link}, l.Prev...)
		runOptional(ctx, t.runner, Cmd{
			Bin: "resolvectl", Args: args, Desc: "写回系统解析器原上游", Optional: true,
		})
		logx.Infof("TUN: 已把系统解析器写回 %s（%s）", l.Link, strings.Join(l.Prev, " "))
	}
	if err := removeResolverLedger(t.configPath); err != nil {
		logx.Debugf("TUN: 状态文件没删掉（%v）——接管已经还原了，留下的只会让下次多读一遍", err)
	}
}

// recoverResolverLedger 收回上一轮被 kill 留下的接管。
//
// 调用方必须持有 t.mu，且要在装任何东西之前跑：那块网卡已经不在了，
// 系统解析器却还指着它的地址，整机解析吊死的形状和「劫持没生效」完全不同，
// 但两者都会让人以为是代理挂了。
func (t *TUN) recoverResolverLedger(ctx context.Context) {
	l := readResolverLedger(t.configPath)
	if l == nil {
		return
	}
	link, prev, ok := ledgerStillOurs(ctx, t.runner, l)
	if !ok {
		// 当前值已经不是我们写的那一组：桌面用户或别的程序改过了，
		// 这时候照账写回只会覆盖别人的决定。账留着也没意义，删掉。
		logx.Infof("TUN: 上次接管系统解析器的账已过时（%s 现在是别人的配置），不再回滚", l.Link)
		_ = removeResolverLedger(t.configPath)
		return
	}
	t.resolver.ledger = &resolverLedger{Link: link, Prev: prev, Applied: l.Applied, SavedAt: l.SavedAt}
	t.restoreResolver(ctx)
}

// ledgerStillOurs 核对「这条 link 现在还是不是我们接管的那副样子」，并交出该写回的原值。
func ledgerStillOurs(ctx context.Context, r Runner, l *resolverLedger) (link string, prev []string, ok bool) {
	cands := parseLinkDNS(runOptional(ctx, r, Cmd{
		Bin: "resolvectl", Args: []string{"dns"}, Desc: "读各 link 的 DNS 上游", Optional: true,
	}))
	servers, hit := cands[l.Link]
	if !hit || !l.sameApplied(servers) {
		return "", nil, false
	}
	return l.Link, append([]string(nil), l.Prev...), true
}

// runOptional 跑一条 best-effort 命令，失败只进 Debug。
// 系统解析器这一族命令在不同发行版上差异很大（没有 resolvectl、link 名对不上、
// polkit 不让普通用户改），没有一条值得让 TUN 启停整体失败。
func runOptional(ctx context.Context, r Runner, c Cmd) string {
	out, err := r.Run(ctx, c)
	if err != nil && !tolerates(c, out) {
		logx.Debugf("TUN: %s 没做成（%v）", c.Desc, firstLine(out, err))
	}
	return out
}

func orNone(servers []string) string {
	if len(servers) == 0 {
		return "（没有上游）"
	}
	return strings.Join(servers, " ")
}

// writeResolverLedger 先落盘再动系统；写失败不推翻这一次——
// 内存里那份够 Stop 回滚，落盘只为兜住 kill -9。
//
// **必须原子写**：这份账是"系统解析器原来是什么"的唯一记录。直接截断重写时，
// kill -9 或断电落在截断之后、写完之前，账就坏了；而 readResolverLedger 读不懂
// 时按"没有账"处理，于是系统解析器停在 tun 的地址上再也不回来——
// 整机解析吊死，而那个地址对应的网卡早随进程消失了。
func writeResolverLedger(configPath string, l *resolverLedger) error {
	path := resolverStatePath(configPath)
	if path == "" {
		return errors.New("没有配置路径，状态文件无处可写")
	}
	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".wps-resolver-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(name) // rename 成功后这条是空操作
	}()
	if _, err := tmp.Write(raw); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	// root 面板替桌面用户落盘时把属主还回去：账留在 root 手里，
	// 普通权限的那一份实例就读不到也删不掉，孤儿检查全废。
	_ = sudoown.ToDesktopUser(path)
	return nil
}

// readResolverLedger 读回并**重新校验**账里的每一个字段。
//
// 这个文件在配置旁边，属主还会被改回桌面用户——也就是说它属于"本机普通用户
// 能改的输入"。而它的内容会原样进 `resolvectl dns <link> <addr...>`：
// 一个以 '-' 开头的值会被 iproute2 当成选项，一个乱写的 link 名会让命令
// 落到别的网络接口上。内存里刚解析出来的地址都是过过 netip.ParseAddr 的，
// 磁盘上这份没有，所以读回时必须按不可信输入再验一次。
func readResolverLedger(configPath string) *resolverLedger {
	path := resolverStatePath(configPath)
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var l resolverLedger
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil
	}
	if !validIfaceName(strings.TrimSpace(l.Link)) {
		return nil
	}
	prev, ok := sanitizeDNSServers(l.Prev)
	if !ok {
		return nil
	}
	applied, ok := sanitizeDNSServers(l.Applied)
	if !ok || len(applied) == 0 {
		// 没有 Applied 就无从判断"现在这个值是不是我们写的"，
		// 而照账写回会覆盖别人的配置。
		return nil
	}
	l.Link = strings.TrimSpace(l.Link)
	l.Prev, l.Applied = prev, applied
	return &l
}

// sanitizeDNSServers 把一组地址洗干净：每一项都必须是 IP 字面量。
//
// 只认 IP，不认"看起来像地址的字符串"：resolvectl 的 dns 子命令接受域名，
// 而账里出现域名意味着要么配置文件被改过、要么有人手工塞了东西。
// 这一族的账只可能由我们写入，所以"只认 IP"不会误伤正常路径。
func sanitizeDNSServers(in []string) ([]string, bool) {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, err := netip.ParseAddr(s); err != nil {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func removeResolverLedger(configPath string) error {
	path := resolverStatePath(configPath)
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
