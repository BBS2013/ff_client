package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

// 自定义域名规则：面板上「哪些域名走代理、哪些不走」的那块。
//
// 文件读写与热重载分开看：写文件是本地事务（先备份再原子替换），
// 而让正在跑的进程用上新规则靠的是 Reload——它失败时保留旧规则继续服务。
// 所以这里的原则是「文件一定先落盘成功，重载失败只告警」：
// 磁盘上的状态才是事实源，重载大不了再点一次。

// policyText 把策略翻成人话。第三档必须单列：
// 把拦截报成"直连"，日志里就看不出这个域名其实是被挡下的。
func policyText(p string) string {
	switch p {
	case "PROXY":
		return "走代理"
	case "REJECT":
		return "已拦截"
	default:
		return "直连"
	}
}

// UserRulePath 返回自定义规则文件路径：与主规则集同目录的 user-rules.txt。
//
// 路径定不下来时必须报错，不能猜一个 "./assets/rules.txt"顶上。猜错的代价
// 不是"这一栏空着"，而是面板把用户刚写的规则存到另一个文件里去，而他已经
// 看着它说"已保存"了：代理一停 s.cfg 就是 nil，此时配置又恰好读不动，
// 正是这条路。宁可这一栏明说"读不到"，也不能替用户挑一个地方落笔。
func (s *Service) UserRulePath() (string, error) {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if cfg == nil {
		loaded, err := config.Load(s.cfgPath)
		if err != nil {
			return "", fmt.Errorf("配置读不到（%s），定不出自定义规则文件的位置：%w", s.cfgPath, err)
		}
		cfg = loaded
	}
	return rules.UserRulePath(cfg.RulesFile), nil
}

// ListUserRules 返回全部自定义规则。文件不存在时是空列表而非错误。
func (s *Service) ListUserRules() ([]rules.UserRule, error) {
	path, err := s.UserRulePath()
	if err != nil {
		return nil, err
	}
	list, err := rules.LoadUserRules(path)
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []rules.UserRule{}
	}
	return list, nil
}

// AddUserRule 新增或改策略：同类型同域名只保留一条，
// 重复条目会让「命中哪条」取决于文件里的先后顺序，等于藏了一个状态。
func (s *Service) AddUserRule(r rules.UserRule) error {
	if err := r.Normalize(); err != nil {
		return err
	}
	path, err := s.UserRulePath()
	if err != nil {
		return err
	}
	list, err := rules.LoadUserRules(path)
	if err != nil {
		return err
	}
	next := rules.UpsertUserRule(list, r)
	if err := rules.SaveUserRules(path, next); err != nil {
		return err
	}
	logx.Infof("自定义规则已保存: %s（%s），共 %d 条", r.Line(), policyText(r.Policy), len(next))
	return s.reloadRulesLive()
}

// RemoveUserRule 删除一条自定义规则。
func (s *Service) RemoveUserRule(typ, value string) error {
	path, err := s.UserRulePath()
	if err != nil {
		return err
	}
	list, err := rules.LoadUserRules(path)
	if err != nil {
		return err
	}
	next, removed := rules.RemoveUserRule(list, typ, value)
	if !removed {
		return fmt.Errorf("没有找到规则 %s,%s", typ, value)
	}
	if err := rules.SaveUserRules(path, next); err != nil {
		return err
	}
	logx.Infof("自定义规则已删除: %s,%s，剩 %d 条", typ, value, len(next))
	return s.reloadRulesLive()
}

// SetUserRuleDisabled 停用/打开一条自定义规则，并立刻按新状态生效。
//
// 单独一个入口而不是让界面把整条规则重发一遍：AddUserRule 那条路会 Normalize，
// 而 Normalize 只收域名类型，手写的 IP-CIDR / GEOIP / DOMAIN-REGEX 关不掉——
// 那些恰恰是最想临时关掉来排查的。这里只翻一个布尔，那一行的其余部分原样留着。
func (s *Service) SetUserRuleDisabled(typ, value string, off bool) error {
	path, err := s.UserRulePath()
	if err != nil {
		return err
	}
	list, err := rules.LoadUserRules(path)
	if err != nil {
		return err
	}
	next, found := rules.SetUserRuleDisabled(list, typ, value, off)
	if !found {
		return fmt.Errorf("没有找到规则 %s,%s", typ, value)
	}
	if err := rules.SaveUserRules(path, next); err != nil {
		return err
	}
	what := "已停用"
	if !off {
		what = "已启用"
	}
	logx.Infof("自定义规则%s: %s,%s，共 %d 条", what, typ, value, len(next))
	return s.reloadRulesLive()
}

// MoveUserRule 把一条规则挪到名单里的第 to 格（0 起），并立刻按新顺序生效。
//
// 这件事值得单独有一条写盘路径：引擎按顺序取第一条命中的规则，
// 所以"这条被上面那条压住了"只能靠换顺序来解，改内容改不掉。
// 名单里那条按 typ+value 找——不按面板上看到的行号找，因为面板那份可能被筛过，
// 也可能在用户点下去和后端读盘之间被文件监视器换掉。
func (s *Service) MoveUserRule(typ, value string, to int) error {
	path, err := s.UserRulePath()
	if err != nil {
		return err
	}
	list, err := rules.LoadUserRules(path)
	if err != nil {
		return err
	}
	next, err := rules.MoveUserRule(list, typ, value, to)
	if err != nil {
		return err
	}
	if err := rules.SaveUserRules(path, next); err != nil {
		return err
	}
	logx.Infof("自定义规则已挪到第 %d 位: %s,%s（共 %d 条）", to+1, typ, value, len(next))
	return s.reloadRulesLive()
}

// UserRuleImport 是一次批量粘贴的结果。
//
// 每个字段都得在界面上露出来，因为它们各自回答一个用户会问的问题：
// 读了几行、新增几条、覆盖了几条（"覆盖"必须单列，不然用户不知道自己改了别人的策略）、
// 哪几行被拒以及为什么、以及有没有几条装上但永远不会命中。
// Written 是"文件到底动了没有"——全被拒时不能顺着提示写"已保存"。
type UserRuleImport struct {
	Total    int      `json:"total"`
	Accepted int      `json:"accepted"`
	Updated  int      `json:"updated"`
	Rejected []string `json:"rejected"`
	Dead     []string `json:"dead"`
	Written  bool     `json:"written"`
}

// AddUserRules 把一整段文本里的规则收进名单：每行可以是裸域名，
// 也可以是完整的 TYPE,VALUE,POLICY 行；空行与 # 开头的注释行跳过。
//
// 一行一次判定、逐条记账，而不是"整段解析失败就全不要"：
// 粘 20 条里有 1 条打错字是常事，全丢等于让用户重粘一遍。
// 落盘只有一次（SaveUserRules 自带备份与临时文件 rename），
// 热重载也只在写成功之后来一次。
func (s *Service) AddUserRules(text, defType, defPolicy string) (UserRuleImport, error) {
	path, err := s.UserRulePath()
	if err != nil {
		return UserRuleImport{}, err
	}
	list, err := rules.LoadUserRules(path)
	if err != nil {
		return UserRuleImport{}, err
	}
	imp := UserRuleImport{Rejected: []string{}, Dead: []string{}}
	next := list
	accepted := make(map[string]bool)
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		imp.Total++
		r, perr := rules.ParseRuleLine(line, defType, defPolicy)
		if perr != nil {
			imp.Rejected = append(imp.Rejected, fmt.Sprintf("第 %d 行 %s：%v", i+1, briefLine(line), perr))
			continue
		}
		if rules.HasUserRule(next, r) {
			imp.Updated++
		} else {
			imp.Accepted++
		}
		next = rules.UpsertUserRule(next, r)
		accepted[r.Line()] = true
	}
	if imp.Total == 0 {
		return imp, errors.New("没有要添加的行：空行与 # 注释不算")
	}
	if imp.Accepted+imp.Updated == 0 {
		// 一条都没收下：文件原样不动，别留一个只改了表头的备份。
		return imp, nil
	}
	if err := rules.SaveUserRules(path, next); err != nil {
		return UserRuleImport{}, err
	}
	imp.Written = true
	// 只报这次新加的那几条会不会命中不到：整份名单的死规则上面那一栏一直在说，
	// 在这里重复一遍等于把"这次粘贴的问题"淹在历史账里。
	blocked := s.BlockList().Domains
	for _, d := range rules.DeadRules(next, blocked) {
		if accepted[d.Line] {
			imp.Dead = append(imp.Dead, d.String())
		}
	}
	logx.Infof("批量添加自定义规则: 读 %d 行，新增 %d，覆盖 %d，拒掉 %d",
		imp.Total, imp.Accepted, imp.Updated, len(imp.Rejected))
	return imp, s.reloadRulesLive()
}

// briefLine 把粘贴进来的一行截成能进结果列表的长度。
// 那一行是用户贴进来的，长度没有上界（编辑器里一行几 KB 很正常），
// 而这句话会原样显示在面板上，还会进日志。
func briefLine(line string) string {
	const keep = 60
	r := []rune(line)
	if len(r) <= keep {
		return line
	}
	return string(r[:keep]) + "…"
}

// reloadRulesLive 让运行中的进程立即按新规则集决策；没在跑就什么都不做
// （下次 Start 会从磁盘读）。返回的错误只代表「重载没成功」，文件已经写好了。
func (s *Service) reloadRulesLive() error {
	s.mu.Lock()
	running := s.running && s.rt != nil
	s.mu.Unlock()
	if !running {
		return nil
	}
	if err := s.Reload(); err != nil {
		return fmt.Errorf("规则已写入文件，但热重载未生效（可点「重载规则」或重启）: %w", err)
	}
	return nil
}

// 判语的两类。分开的原因是它们的"怎么办"完全不同：
// 被盖住的那条只要挪位置或删掉，钉错节点的那条要么把节点改回来、要么去掉 node=。
const (
	// WarnShadow：被前面的规则（或拦截名单）盖住，永远不会命中。
	WarnShadow = "shadow"
	// WarnNodeMissing：规则钉的节点在配置里不存在（改名或删除之后规则不会跟着改）。
	WarnNodeMissing = "node-missing"
)

// RuleWarning 是规则页「这份名单里有问题」那一栏的一条判语。
//
// 拆成 line + why 而不是一整句话：面板上要把用户自己写的那一行用等宽字体单独立出来，
// 而"为什么"和"怎么办"合成后半句。两段分开放，界面才不用去句子中间找位置。
type RuleWarning struct {
	Kind string `json:"kind"`
	Line string `json:"line"`
	Why  string `json:"why"`
}

// UserRuleWarnings 说出这份名单里的问题，一条一则判语。
// 为什么在 Go 侧算而不是界面自己算：判定要用引擎那套归一化写法
// （小写、去尾点、后缀按点边界）与配置的节点名单，而那份写法只有一份权威在 rules 包里。
// 界面上再抄一遍，两边的判据迟早分家，而分家的代价是当着用户的面
// 说一条其实活着的规则是死的。
//
// 拦截名单取的是 BlockList() 那份：引擎里正在生效的名单，不是配置文件里那份——
// 两者在重载失败时会分家，而这条判据说的是"实际会不会命中"。
// RuleHit 是一条自定义规则在本次会话里被用过的次数。
type RuleHit struct {
	// Key 是 TYPE,VALUE —— 也就是面板那一行的身份（UserRule.Key()）。
	// 界面拿它去对行，不需要认识引擎那串文本。
	Key string `json:"key"`
	// Hits 是"这一条定过多少条连接"。0 有两种意思：还没轮到它，或者它其实没用。
	// 这一栏只报观察到的次数，不下结论——下结论那部分是 DeadRules 的活（见 UserRuleWarnings）。
	Hits int64 `json:"hits"`
}

// UserRuleHits 把引擎写下的命中依据对回用户自己写的那几行。
//
// 为什么值得单独有一栏：判语那一栏说的是"这条**结构上**永远不会命中"，
// 而一份 900 条的名单里更多的是另一种——活着、但从没轮到过。
// 那种只能靠观察，不能靠推导；没有它，用户清理名单只能凭记忆。
//
// 计数按**整串命中依据**归并（就是引擎在连接表里写的那一句），
// 所以改过走向或节点的那一条会从头数起：在引擎看来那本来就是一行不一样的规则。
// 这一点必须写在界面上，否则"刚改完走向，这条突然变成 0 次"会被读成功能坏了。
func (s *Service) UserRuleHits() ([]RuleHit, error) {
	list, err := s.ListUserRules()
	if err != nil {
		return nil, err
	}
	counts := s.Metrics().RuleHits()
	out := make([]RuleHit, 0, len(list))
	for _, r := range list {
		// Desc() 认不出的类型返回空串（见它的注释），这种行不参与归并。
		if d := r.Desc(); d != "" {
			out = append(out, RuleHit{Key: r.Key(), Hits: counts[d]})
		}
	}
	return out, nil
}

func (s *Service) UserRuleWarnings() ([]RuleWarning, error) {
	list, err := s.ListUserRules()
	if err != nil {
		return nil, err
	}
	// 两类判语要按名单顺序混排（用户是照着表从上往下找的），
	// 而顺序只在这一段里有用——它不进 RuleWarning，省一个只为了排序而存在的字段。
	type placed struct {
		RuleWarning
		idx int
	}
	var found []placed
	for _, d := range rules.DeadRules(list, s.BlockList().Domains) {
		found = append(found, placed{RuleWarning{
			Kind: WarnShadow,
			Line: d.Line,
			Why:  d.Reason + "。要让它生效就把它挪到前面，否则删掉。",
		}, d.Index})
	}
	// 走到这里时配置一定读得到过：UserRulePath() 刚刚为定位规则文件 load 过一次，
	// 它失败的话这一栏早就返回错误了。所以这里那份节点名单不会是"读不到的空名单"。
	nodes := s.nodeNameSet()
	for i, r := range list {
		if r.Node == "" || nodes[r.Node] {
			continue
		}
		// 停用的那条不参与匹配，永远不会有连接"走到它然后失败"。
		// 这一句和 DeadRules 里对 shadow 的处理是同一个口径：
		// 这一栏说的必须是"此刻真会出的问题"，否则用户刚把一条关掉，
		// 界面就指着它警告它正在造成的那个故障——而他关掉它正是为了消掉这个故障。
		if r.Disabled {
			continue
		}
		found = append(found, placed{RuleWarning{
			Kind: WarnNodeMissing,
			Line: r.Line(),
			Why: fmt.Sprintf("它钉的节点 %q 不在配置的节点列表里（改名或删除之后规则不会跟着改）。"+
				"这类规则不会回落当前节点：走到它的连接会直接失败，日志里会出现这个名字。"+
				"把节点改回这个名字，或者去掉这一行的 node=。", r.Node),
		}, i})
	}
	sort.SliceStable(found, func(a, b int) bool { return found[a].idx < found[b].idx })
	out := make([]RuleWarning, 0, len(found))
	for _, w := range found {
		out = append(out, w.RuleWarning)
	}
	return out, nil
}

// nodeNameSet 是配置里现存的节点名。
//
// 判据读的是磁盘上那份配置（与"这一栏和代理跑不跑无关"一致）：
// 节点刚被改名但还没存盘时，那条规则此刻确实还连得通。
func (s *Service) nodeNameSet() map[string]bool {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if cfg == nil {
		loaded, err := config.Load(s.cfgPath)
		if err != nil {
			return map[string]bool{}
		}
		cfg = loaded
	}
	set := make(map[string]bool, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		set[p.Name] = true
	}
	return set
}

// ProbeResult 是「这个域名现在到底怎么走」的答案。
type ProbeResult struct {
	Host    string `json:"host"`
	Policy  string `json:"policy"`
	Matched string `json:"matched"`
	Mode    string `json:"mode"`
	// Node 是判成 PROXY 时字节会记到谁头上——与连接表那一列同一个来源
	// （Router.decide 那一段，也就是拨号走的同一个函数）。规则钉了节点时它是那条的名字，
	// 没钉时是当前活动节点。直连与拦截不填：那一格的答案已经写在 Policy 里了。
	// 探测**不**会去建那只出站：建出站要解析节点的服务端地址，而那不是这一问的一部分。
	Node string `json:"node"`
	// Iface 是这条流量会被钉在哪张网卡上（按网卡分流，见 §4.2.1），空串 = 没钉。
	// 与连接表那一列同一个来源（`Split.DevForPolicy`）。
	// 代理没在跑时**不填**：分流要真探测到两张卡、且模式是规则才算数，
	// 磁盘上的配置只能说明"选了哪张卡"，答不了"此刻钉上了没有"。
	Iface string `json:"iface"`
	// Live 为 false 表示代理没在跑，答案是按磁盘上的规则集与模式算出来的。
	Live bool `json:"live"`
}

// Probe 用当前生效的模式+规则回答一个域名该怎么走。
// 排障时这是最省事的一步：不用猜「到底哪条规则命中了」。
func (s *Service) Probe(host string) (ProbeResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	s.mu.Lock()
	rt := s.rt
	cfg := s.cfg
	s.mu.Unlock()

	if rt != nil {
		// 走 Preview 而不是 Decide：多出来那一格是"落到哪个节点"。
		// 它同源于拨号那一段 decide（真转发走的就是它），且**不会**去建出站——
		// 探测是在网已经不好的时候被打开的，不能挂在节点地址能不能解析上
		// （那一问的判据见 router.Preview 的注释）。
		res, err := rt.Preview(ctx, host)
		if err != nil {
			return ProbeResult{}, err
		}
		node := res.Node
		if res.Policy != outbound.PolicyProxy {
			// DIRECT / REJECT 那一侧的 Node 是 "DIRECT" / "REJECT" 这样的类名，
			// 把它当节点名报给界面等于多造一个"节点"。
			node = ""
		}
		return ProbeResult{
			Host: host, Policy: string(res.Policy), Matched: res.Matched,
			Node: node, Iface: res.Iface, Mode: string(rt.Mode()), Live: true,
		}, nil
	}

	// 没在跑：临时装一份引擎来回答。解析器传 nil 即可——
	// 域名规则在 DNS 之前就判定完，只有 IP/GEOIP 规则才需要解析。
	if cfg == nil {
		loaded, err := config.Load(s.cfgPath)
		if err != nil {
			return ProbeResult{}, err
		}
		cfg = loaded
	}
	geo, err := rules.OpenGeoIP(cfg.GeoIP.Path)
	if err != nil {
		logx.Debugf("探测时 GeoIP 不可用，GEOIP 规则将不参与: %v", err)
	}
	ref := rules.NewGeoRef(geo)
	defer ref.Swap(nil)
	eng, err := rules.Load(cfg.RulesFile, ref, nil)
	if err != nil {
		return ProbeResult{}, err
	}
	// 探测必须和真转发用同一份名单：不铺的话面板上显示"走代理"，
	// 实际连接却被拦下，用户会以为探测功能坏了。
	eng.SetBlocklist(cfg.Block.Domains)
	mode := cfg.ModeValue()
	// 没在跑时"会落到哪个节点"只能答一半：规则钉住的那个名字是磁盘上的事实，
	// 而"当前活动节点"这件事此刻并不存在——出站注册表还没建起来。
	// 所以钉住就用钉住的，否则用配置里选中的那个，靠 Live=false 那半句
	// 让界面说明"这是起起来之后会是的节点"，不是现在正在跑的。
	fromDisk := func(pinned string) string {
		if pinned != "" {
			return pinned
		}
		return cfg.Active
	}
	switch mode {
	case config.ModeGlobal:
		return ProbeResult{Host: host, Policy: "PROXY", Matched: "MODE,GLOBAL",
			Node: fromDisk(""), Mode: string(mode)}, nil
	case config.ModeDirect:
		return ProbeResult{Host: host, Policy: "DIRECT", Matched: "MODE,DIRECT", Mode: string(mode)}, nil
	}
	policy, matched, node := eng.MatchNode(ctx, host)
	res := ProbeResult{Host: host, Policy: string(policy), Matched: matched, Mode: string(mode)}
	if policy == rules.PolicyProxy {
		res.Node = fromDisk(node)
	}
	return res, nil
}

func boolText(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}

// BlockView 是面板「拦截域名」那一栏的答案。
type BlockView struct {
	// Domains 是**正在生效**的那份名单（已归一化：小写、去尾点、去重）。
	Domains []string `json:"domains"`
	// Live 为 false 表示代理没在跑，这份是照磁盘上的配置算出来的。
	Live bool `json:"live"`
	// Mode 必须一起给：切到「直连」模式时名单整体让开，
	// 只列域名不写这句，就等于骗用户说这些域名此刻拦着。
	Mode string `json:"mode"`
	// Path 是名单住在哪个文件里——它是配置段，界面只读，改要回 config.yaml。
	Path string `json:"path"`
	// Dead 是"装上了却什么也没多拦"的条目，一句一条：名单按后缀拦，
	// 所以里面已经有 example.com 时，再加的 ads.example.com 不会多拦下任何东西。
	// DeadTotal 是它们的真实条数——Dead 最多给 blockDeadCap 条，
	// 抄来的名单能有几千条死条目，每轮轮询全搬过桥面板会卡；
	// 只给截断的列表而不给总数，界面上就会写成"就这些"。
	Dead      []string `json:"dead"`
	DeadTotal int      `json:"deadTotal"`
}

// fillDead 按当前名单算一遍死条目。BlockList 的每一条返回路径都要过它：
// 名单是显示"我到底拦住了什么"的那一栏，冗余条目也在回答同一个问题。
func (v *BlockView) fillDead() {
	v.Dead, v.DeadTotal = blockDeadSentences(v.Domains)
}

// BlockList 回答「现在哪些域名被拦着」。
//
// 优先报运行中引擎里那份，而不是磁盘上的：重载失败时两者会分家，
// 而这一栏的意义恰恰是"我到底拦住了什么"。
func (s *Service) BlockList() BlockView {
	// 判据与 Probe 用同一个：引擎装好了就算「正在生效」。
	// 用 s.running 的话，同一个页面上的「查走向」和「拦截名单」会互相打脸
	// （Prepare 之后 Probe 报 live、BlockList 报未运行）。
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()

	// 模式不能在持有 s.mu 的时候取：Mode() 自己也要这把锁，
	// 在这里调它就是自己锁死自己。
	v := BlockView{Domains: []string{}, Path: s.cfgPath}
	if rt != nil {
		v.Mode = string(rt.Mode())
		if got := rt.Engine().BlockDomains(); got != nil {
			v.Domains = got
		}
		v.Live = true
		v.fillDead()
		return v
	}
	v.Mode = s.Mode()
	// 没在跑：读磁盘那份。名单本身只由 block: 段决定，所以这里**不碰规则集**——
	// 早先为了复用引擎的归一化，把整张 GFW 表重新编译了一遍，纯白扔。
	// BlockDomainView 就是引擎装完之后会给出的那一份，权威仍然只有一处。
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		logx.Debugf("读不到配置，拦截名单按空显示: %v", err)
		v.fillDead()
		return v
	}
	v.Domains = rules.BlockDomainView(cfg.Block.Domains)
	v.fillDead()
	return v
}

// AddBlockDomain 把一个域名加进 block: 段，并让运行中的实例立即生效。
//
// 重复添加是幂等的：引擎里同一条本来也只会生效一次，
// 但文件里堆两份会让"删掉它"变成"删了还在"——下次读到的还是另一条。
//
// 返回值是**归一化之后**的域名。界面上要回显的是名单里真实存着的那一种写法
// （用户手打 "Ads.Example.COM."，存进去是 ads.example.com），
// 顺带让它分得清"这次真加了"和"本来就有"——这两件事对用户的含义完全不同。
func (s *Service) AddBlockDomain(raw string) (string, error) {
	d, err := config.NormalizeBlockDomain(raw)
	if err != nil {
		return "", fmt.Errorf("拦截域名 %w", err)
	}
	var added bool
	if err := s.mutate(func(cfg *config.Config) error {
		for _, have := range cfg.Block.Domains {
			if h, e := config.NormalizeBlockDomain(have); e == nil && h == d {
				return nil
			}
		}
		cfg.Block.Domains = append(cfg.Block.Domains, d)
		// 存进去的一律是归一化后的写法：留着用户手打的 "Ads.Example.COM."
		// 再靠引擎每次去抹平，界面显示的和文件里就会是两种样子。
		cfg.Block.Domains = rules.NormalizeBlocklist(cfg.Block.Domains)
		added = true
		return nil
	}); err != nil {
		return "", err
	}
	if added {
		logx.Infof("拦截名单已加入: %s", d)
	} else {
		logx.Infof("拦截名单里本来就有 %s，本次未改动", d)
	}
	if err := s.applyBlockLive(); err != nil {
		return d, err
	}
	return d, nil
}

// RemoveBlockDomain 从名单里删掉一个域名。删不存在的项报错而不是静默成功：
// 静默"成功"会让用户以为已经放开了，而实际拦着的一直没动。
func (s *Service) RemoveBlockDomain(raw string) error {
	d, err := config.NormalizeBlockDomain(raw)
	if err != nil {
		return fmt.Errorf("拦截域名 %w", err)
	}
	found := false
	if err := s.mutate(func(cfg *config.Config) error {
		kept := cfg.Block.Domains[:0]
		for _, have := range cfg.Block.Domains {
			if h, e := config.NormalizeBlockDomain(have); e == nil && h == d && !found {
				found = true
				continue
			}
			kept = append(kept, have)
		}
		cfg.Block.Domains = kept
		return nil
	}); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("拦截名单里没有 %s", d)
	}
	logx.Infof("拦截名单已删除: %s", d)
	return s.applyBlockLive()
}

// applyBlockLive 把磁盘上的名单铺到正在运行的引擎上。
//
// 不用整份 Reload：名单住在引擎独立的一份切片里，换它不需要重读那几千条规则。
// 没在跑就什么都不做——下次 Start 自然从文件里读。
func (s *Service) applyBlockLive() error {
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		return err
	}
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()
	if rt == nil {
		return nil
	}
	rt.SetBlocklist(cfg.Block.Domains)
	return nil
}
