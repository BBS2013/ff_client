package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/netdev"
	"wps_app/internal/outbound"
	"wps_app/internal/tunx"
)

// IfaceCardView 是下拉框里的一行：本机一张可用的无线卡。
type IfaceCardView struct {
	Name  string   `json:"name"`
	USB   bool     `json:"usb"`
	Addrs []string `json:"addrs"`
}

// IfaceSplitStatus 是「按网卡分流」的状态，供面板显示。
type IfaceSplitStatus struct {
	// Enabled 是配置里的开关。
	Enabled bool `json:"enabled"`
	// Active 是此刻真的生效了：开关开着、模式是规则、且两张卡都在。
	Active bool `json:"active"`
	// DirectDev / ProxyDev 是选中的两张接口名；没选到时为空。
	DirectDev string `json:"directDev"`
	ProxyDev  string `json:"proxyDev"`
	// Note 解释「为什么现在没有分流」，没有这类原因时为空串。
	// 它只讲配置层面的原因（找不到两张卡 / 没有权限 / 点名的卡换了）；
	// 「还没启动」「当前不是规则模式」这类运行期状态由界面自己拼。
	Note string `json:"note"`
	// Cards 是本机当前可用的无线卡，供界面的两个下拉列出可选项。
	// 空数组 = 开关没开（那时不探测，也就没有网卡可列）。
	Cards []IfaceCardView `json:"cards"`
}

// splitPick 是「两张卡钉在哪」这个事实本身。
//
// 只比接口名，不比地址：DHCP 续租会让地址天天不同，而卡还是那张卡。
// 拿整份探测结果去比，一续租就会换来一次没必要的隧道重建。
type splitPick struct {
	direct string
	proxy  string
}

func (p splitPick) same(o splitPick) bool { return p.direct == o.direct && p.proxy == o.proxy }

func pickOf(d, p string) splitPick { return splitPick{direct: d, proxy: p} }

// unpinProxy / unpinDirect 把一份解析结果里「某一侧钉在哪张卡」松开，另一侧与网卡清单留着，
// 换上降级原因。
//
// 为什么要分两侧各一个：这两侧的病可以不一样，而 2026-10-30 之前只有代理侧这一半，
// note 里那句「直连钉在内置卡上是真的在干活」因此是**假的**——普通权限下内置卡的
// 钉卡同样被静默丢包（两台面板 via DIRECT 失败 363/1244 条、成功建连 0 条；
// 转 root 后失败 0、成功 17）。留着另一侧的前提是"它真的在干活"，这个前提必须被问过。
//
// 做成函数而不是就地赋字面量：service.go 里那份 plan 的局部变量名叫 splitPlan，
// 正好挡住同名的类型，`splitPlan{...}` 在那儿写不出来。
func unpinProxy(p splitPlan, why string) splitPlan {
	return splitPlan{pick: pickOf(p.pick.direct, ""), note: joinWhy(p.note, why), cards: p.cards}
}

func unpinDirect(p splitPlan, why string) splitPlan {
	return splitPlan{pick: pickOf("", p.pick.proxy), note: joinWhy(p.note, why), cards: p.cards}
}

// joinWhy 把两句话并成一句：两侧都降级时界面上只有那一格，后一句不能把前一句顶掉。
func joinWhy(old, add string) string {
	switch {
	case old == "":
		return add
	case add == "":
		return old
	default:
		return old + "；" + add
	}
}

// splitPlan 是一次解析的完整结果：两张卡钉在哪、为什么没钉成、界面上有哪些卡可选。
type splitPlan struct {
	pick  splitPick
	note  string
	cards []IfaceCardView
}

// probeBind 探当前进程有没有权限钉网卡。
// 做成变量是为了让单测不必真的去建 socket 绑网卡：那一步是真的系统调用。
var probeBind = outbound.ProbeDeviceBind

// probeEgress 是「钉上这张卡之后包到底出不出得去」那一次真拨号。
// 抽成变量有两个理由：真拨要等两秒，单测不能等；而它分不清的责任
// （钉卡 vs 节点本身不通）要靠一个对照组来拆。
var probeEgress = outbound.ProbeDeviceEgress

// egressProbeBudget 是给这一次探路的预算。两秒是权衡出来的：
// 比一次正常握手慢不了多少，又足够把「静默丢包」和「链路慢」分开。
const egressProbeBudget = 2 * time.Second

// egressBlockedWhy 验一次代理那张卡能不能真的发包，返回一句给人看的原因；
// 能发出去时返回空串。addr 是**这一次要拨的目标**（当前选中节点），由调用方给：
// 命令行那条路上 s.cfg 还没落定，藏在函数里读 s.cfg 会静默跳过这次检查。
//
// 这一步是补上的，不是多余的：这台机器的链路安全软件让普通进程钉网卡之后
// **静默丢包**，而 setsockopt 返回成功——只看系统调用就会在界面上写
// 「已生效」，症状却是所有出海连接一起超时（2026-10-20 那次 612 条拨不通、
// 2026-10-29 复现，都是这一条）。
//
// 失败时还要用不钉网卡的方式再拨一次：两条都拨不通说明是节点或链路的事，
// 不该把「分流未生效」这顶帽子扣上去。
func (s *Service) egressBlockedWhy(dev, addr, what string, cfg *config.Config) (note string, useBind bool) {
	v := s.egressVerdictFor(dev, addr, cfg)
	if !v.blocked {
		if v.fact != "" {
			// 钉着与不钉都拨不通：那是节点或链路的事，别抢走界面里那一格。
			logx.Debugf("分流探针不下结论：%s", v.fact)
		}
		return "", false
	}
	if v.bind {
		// 这句话必须把"谁绑不上"说清楚：钉不上的是**普通权限的那个进程**，
		// 不是这张卡——同一张卡上 helper 造出来的 socket 跑得好好的。
		// 写成"发不出包"会被读成"这张卡坏了"，而实际要处理的是权限那一层。
		proto := ""
		if cfg != nil {
			proto = cfg.ActiveServer().Protocol()
		}
		return bindViaHelperNote(proto, what, dev, v.fact), true
	}
	return fmt.Sprintf("开关已打开，但钉上发不出包（%s）——%s这一侧退回系统默认路由，没有真的换到这张卡", v.fact, what), false
}

// settleEgress 把「钉上这张卡发不发得出包」在**两侧各问一次**，据此决定每一侧是
// 维持点名（有特权通道就交给它）还是退回系统默认路由。
//
// 为什么单独成一层：Start 与运行期的 applyPlan 必须共用同一判据（启动不走 applyPlan，
// 这正是这条判据原来漏掉它的原因），而两侧共用同一问句——只问代理侧，就是
// 2026-10-30 之前那个"直连那一半废了却没人说"的形状。
// 返回落地用的 plan、两侧各自该不该走特权通道、以及**只有走通道时**该说一次的话
// （退回默认路由那一句已经写进 plan.note，由 logSplitPlan 去说，这里再说一遍就是刷屏）。
func (s *Service) settleEgress(plan splitPlan, nodeAddr string, cfg *config.Config) (splitPlan, bool, bool, []string) {
	if strings.TrimSpace(nodeAddr) == "" {
		return plan, false, false, nil // 没有目标就不许编结论
	}
	var (
		notes                 []string
		bindDirect, bindProxy bool
	)
	if plan.pick.proxy != "" {
		if why, useBind := s.egressBlockedWhy(plan.pick.proxy, nodeAddr, "代理", cfg); why != "" {
			if useBind {
				bindProxy, notes = true, append(notes, why)
			} else {
				plan = unpinProxy(plan, why)
			}
		}
	}
	if plan.pick.direct != "" {
		if why, useBind := s.egressBlockedWhy(plan.pick.direct, nodeAddr, "直连", cfg); why != "" {
			if useBind {
				bindDirect, notes = true, append(notes, why)
			} else {
				plan = unpinDirect(plan, why)
			}
		}
	}
	return plan, bindDirect, bindProxy, notes
}

// egressVerdict 是对「钉上这张卡到底发不出包」的一次判定结果。
// 存结构而不是存句子：句子被 egressBlockedWhy 消费，缓存里存句子就会在第二次
// 命中时被再包一层（同一个事实套两遍说法）。
type egressVerdict struct {
	blocked bool
	bind    bool   // blocked 且这条机器上有提权 helper：交给它，而不是退回默认路由
	fact    string // 一句事实（EgressPair 给的），或"分不清"的那句
}

// egressVerdictFor 是"同一个网卡+目标只探一次"那层缓存。
//
// 为什么必须缓存而不是每轮都探：判成降级会重建隧道，而 commitProxy 在 strict_route 下
// 会回头再走一遍装配，装配又探一次、又判降级——2026-10-29 就是这么每 3~5 秒刷一组日志
// （详见 README §10.19 与 ACCEPTANCE A55）。用户拨开关/改点名才是"重新问一次"。
func (s *Service) egressVerdictFor(dev, addr string, cfg *config.Config) egressVerdict {
	addr = strings.TrimSpace(addr)
	if dev == "" || addr == "" {
		return egressVerdict{}
	}
	// 有没有特权通道按**这次装配用的那份配置**判：Start 那条路上 s.cfg 还没落定，
	// 去读它会得到"没有 helper"的错结论，于是把本该走 helper 的机器退回了默认路由
	// （2026-10-30 第一次上线就是这么错的：面板启动时判成"钉不上"）。
	binder := s.bindChannelWith(cfg)
	key := dev + "|" + addr + "|" + fmt.Sprint(binder != nil)
	s.mu.Lock()
	v, seen := s.egressVerdict[key]
	s.mu.Unlock()
	if seen {
		return v
	}
	blocked, fact := outbound.EgressPair(probeEgress, dev, addr, egressProbeBudget)
	v = egressVerdict{blocked: blocked, bind: blocked && binder != nil, fact: fact}
	s.mu.Lock()
	if s.egressVerdict == nil {
		s.egressVerdict = map[string]egressVerdict{}
	}
	s.egressVerdict[key] = v
	s.mu.Unlock()
	return v
}

// bindChannel 造那条「请 helper 替我把 socket 钉到这张卡上」的通道。
//
// 没有配 tun.helper 就没有这条通道（返回 nil），那时分流只能"能绑就绑、绑不上就退回
// 默认路由并说清"——那是 2026-10-29 的形状。配了之后面板仍然不碰 root：
// 它只是拿回一条已经钉好并连上的 socket（与 TUN 的 fd 交接同一条机制）。
func (s *Service) bindChannel() outbound.BindSocketFunc {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	return s.bindChannelWith(cfg)
}

// bindChannelWith 同上，但用调用手头这份配置（Start 那条路上 s.cfg 还没落定）。
func (s *Service) bindChannelWith(cfg *config.Config) outbound.BindSocketFunc {
	h := s.ensureDialHelper(cfg)
	if h == nil {
		return nil
	}
	return func(ctx context.Context, dev, addr string) (net.Conn, error) {
		// 名单就是这一次要连的端点本身。它防的不是这个配置的属主（他想加端点随时加得动），
		// 而是以后某条路径把用户在界面上输入的地址顺手交给 root 去连——那一步必须被拒。
		return h.DialBound(ctx, dev, addr, []string{addr})
	}
}

// ensureDialHelper 按需拉起**常驻**提权 helper：只拉一次，之后一直用。
//
// 为什么要常驻：造一条钉住网卡的 socket 每条流都要做一次，一次性的 helper
// 每请求付一次 sudo + 进程起落（实测 0.08~0.11s），那笔开销直接摊在用户的每一次浏览上。
func (s *Service) ensureDialHelper(cfg *config.Config) *tunx.PersistentHelper {
	prefix := helperArgvPrefix(cfg)
	if prefix == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dialHelper != nil {
		return s.dialHelper
	}
	s.dialHelper = &tunx.PersistentHelper{Argv: prefix, Timeout: dialHelperTimeout}
	return s.dialHelper
}

// helperArgvPrefix 从配置里的提权命令里取出"唤起常驻 helper"要用的前缀：
// 去掉 --tun-helper（那是"跑一次就退出"的模式），剩下的就是 sudo + 二进制。
func helperArgvPrefix(cfg *config.Config) []string {
	if cfg == nil || len(cfg.TUN.Helper) == 0 {
		return nil
	}
	out := make([]string, 0, len(cfg.TUN.Helper))
	for _, a := range cfg.TUN.Helper {
		if strings.HasPrefix(a, "--tun-helper") || strings.HasPrefix(a, "--dial-helper") {
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// dialHelperTimeout 是常驻 helper 一次请求的预算。
const dialHelperTimeout = 25 * time.Second

// clearEgressVerdict 丢掉「网卡|目标」的探针结论，让下一次落地重新探一遍。
// 只有用户拨开关/改点名这条路会调它——自动重扫网卡不该反复问（见 egressPair 那段）。
func (s *Service) clearEgressVerdict() {
	s.mu.Lock()
	s.egressVerdict = nil
	s.mu.Unlock()
}

// currentCfg 取当前这份配置（可能在装配落定之前为空）。
func (s *Service) currentCfg() *config.Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// bindViaHelperNote 是"钉卡这一步换了个人做"那一句的**唯一出处**。
//
// 为什么要有且只有一个：这句话会出现两处（状态 note 与测速那一格），各写一份就会
// 各说各话——而"发不出包"这个说法很容易被读成"那张卡坏了"，实际坏的是普通进程
// 去钉这一层。fact 是探针那句话（可空）：长句放得下的地方就带上。
// what 是"代理"还是"直连"：两侧的病可以不一样（2026-10-30 实测直连那一侧同样被
// 静默丢包，而探针以前只问代理侧），所以这句话必须说清是哪一侧换了人做。
//
// proto 决定"谁代劳"：trojan/直连是 TCP，走提权 helper；hysteria2 的 QUIC
// 由 ProxyConnFactory 在面板进程里自己钉，不能也写成 helper 代劳——那会让
// 用户按 helper 去查一个根本没参与这条隧道的进程。
func bindViaHelperNote(proto, what, dev, fact string) string {
	out := fmt.Sprintf("分流没有退回默认路由：面板自己（普通权限）直接钉 %s 会被静默丢包", dev)
	if fact != "" {
		out += "（" + fact + "）"
	}
	if proto == config.ProtocolHysteria2 && what == "代理" {
		return out + fmt.Sprintf("；hysteria2 的 QUIC socket 由面板自己钉在这张卡上（可用 ss -unpa 核对），"+
			"%s仍然走 %s", what, dev)
	}
	return out + fmt.Sprintf("；已交给提权 helper 代劳，%s仍然钉在这张卡", what)
}

// activeAddrOf 取当前选中节点的地址，作为分流探针的拨号目标。
// 没有配置就没有目标可拨，返回空串让调用方跳过探测——不编一个地址出来。
func activeAddrOf(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return strings.TrimSpace(cfg.ActiveServer().Addr)
}

// resolveSplit 按配置解析一次分流。
//
// 按 config 里的点名挑；点的那张不在了，按它原来的类别顶上同类的那张——
// 于是「拔掉 USB 卡再插一张新的」不用改配置就能接住。
//
// 挑不出两张卡时两边都是空串：空串让出站的 Control 回调什么都不做，
// 于是行为与「没开这个功能」完全一样。空串在这套代码里一路都当「不分流」处理，
// 从解析到绑定到界面，不用在哪一层再判一次。
func resolveSplit(set netdev.Set, cfg config.IfaceSplitConfig) splitPlan {
	if !cfg.Enable {
		return splitPlan{note: "已关闭：直连与代理都按系统默认路由走", cards: []IfaceCardView{}}
	}
	plan := splitPlan{cards: cardsView(set)}
	d, p, why := set.Resolve(choiceOf(cfg.Direct), choiceOf(cfg.Proxy))
	if d.Name == "" || p.Name == "" {
		// 只有一张卡时把全部流量钉到它上面没有任何好处——它本来就是默认路由。
		if why == "" {
			why = "只找到一张无线"
		}
		plan.note = fmt.Sprintf("开关已打开，但%s（%s）：仍按系统默认路由走", why, set.Describe())
		return plan
	}
	// 钉网卡要 SO_BINDTODEVICE，它在 Linux 5.7 之前需要 CAP_NET_RAW，
	// 而面板正是以普通用户跑的。探不到权限还照样去绑的话，
	// 症状是所有连接一起失败，而界面上只显示「已开启」。
	if err := probeBind(p.Name); err != nil {
		plan.note = fmt.Sprintf("开关已打开，但本进程没有钉网卡的权限（%v）：仍按系统默认路由走", err)
		return plan
	}
	plan.note = why
	plan.pick = splitPick{direct: d.Name, proxy: p.Name}
	return plan
}

func choiceOf(c config.IfaceCard) netdev.Choice {
	return netdev.Choice{Dev: c.Dev, USB: c.USB}
}

// planForConfig 按配置解析一次分流，开关关着时不去探测。
//
// 没在分流就没有网卡可盯，也就不该为此去读 sysfs——面板每秒问一次状态，
// 而 Start 与每次点开关都会走这里。
func planForConfig(cfg config.IfaceSplitConfig) splitPlan {
	if !cfg.Enable {
		return splitPlan{note: "已关闭：直连与代理都按系统默认路由走", cards: []IfaceCardView{}}
	}
	return resolveSplit(netdev.Detect(), cfg)
}

func cardsView(set netdev.Set) []IfaceCardView {
	all := set.All()
	out := make([]IfaceCardView, 0, len(all))
	for _, w := range all {
		out = append(out, IfaceCardView{Name: w.Name, USB: w.USB, Addrs: w.Addrs})
	}
	return out
}

// applySplitGate 按当前分流模式开合闸门：只有规则模式才分流。
//
// 放在服务层而不是路由器里，是因为闸门要跟着「模式」而不是跟着某条连接，
// 而模式在这两层都能改；服务层是唯一同时握着两者的那一层。
func (s *Service) applySplitGate(m config.Mode) {
	s.mu.Lock()
	sp := s.split
	s.mu.Unlock()
	if sp == nil {
		return
	}
	want := m == config.ModeRule
	sp.SetActive(want)
	if want {
		logx.Infof("规则模式：%s", sp.Describe())
	} else {
		logx.Infof("分流模式为 %s：网卡分流已收起，直连与代理都按系统默认路由走", m)
	}
}

// IfaceSplitStatus 返回当前状态。
func (s *Service) IfaceSplitStatus() IfaceSplitStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	enabled := false
	if s.cfg != nil {
		enabled = s.cfg.IfaceSplit.Enable
	}
	return s.splitStatusLocked(enabled, s.running)
}

// splitStatusLocked 组装分流状态。调用方必须已持有 s.mu。
//
// 开关位置取配置而不是探测结果：探测每 5 秒才跑一轮（见 ifacewatch.go），
// 而面板每秒轮询一次快照。可选的网卡清单是那一轮顺手存下的，
// 所以刚被拔掉的那张卡还会在下拉里留 5 秒——这一条是划算的，
// 读不出"这张卡刚被拔了"会让界面凭空多出一次闪动。
func (s *Service) splitStatusLocked(enabled, running bool) IfaceSplitStatus {
	st := s.ifaceSplit
	st.Enabled = enabled
	st.Cards = s.ifaceCards
	d, p := s.split.Devices()
	st.Active = running && enabled && d != "" && p != "" && s.split.Active()
	return st
}

// SetIfaceSplitEnabled 开/关按网卡分流，并落盘。
func (s *Service) SetIfaceSplitEnabled(enable bool) error {
	if err := s.mutate(func(cfg *config.Config) error {
		cfg.IfaceSplit.Enable = enable
		return nil
	}); err != nil {
		return err
	}
	if err := s.refreshSplit(); err != nil {
		return err
	}
	// 监视循环跟着开关走：不开就不探测，也就没有网卡可盯。
	s.syncSplitWatch()
	return nil
}

// SetIfaceSplitCards 换掉直连与代理各自钉的网卡，并落盘。空串即那一侧交给系统默认路由。
//
// 已经建好的隧道 socket 换不了设备——那条 socket 已经钉在旧卡上了，
// 因此换到代理那一侧时必须重建出站，也就是换节点那条路（见 applyPlan）。
func (s *Service) SetIfaceSplitCards(direct, proxy string) error {
	direct, proxy = strings.TrimSpace(direct), strings.TrimSpace(proxy)
	if direct != "" && direct == proxy {
		// 两边钉同一张卡与不钉是一回事，却会让"另一张卡还能分流"这件事一起消失。
		// 这是界面上一次误点就能造出来的状态，不该默默执行。
		return fmt.Errorf("直连与代理不能选同一张网卡（%s）：请改选另一张，或让其中一侧留空走系统默认路由", direct)
	}
	// 先探测再落盘：mutate 整段持有配置锁，不该让它顺带去走一遍 sysfs。
	set := netdev.Detect()
	if err := s.mutate(func(cfg *config.Config) error {
		setCardChoice(&cfg.IfaceSplit.Direct, direct, set)
		setCardChoice(&cfg.IfaceSplit.Proxy, proxy, set)
		return nil
	}); err != nil {
		return err
	}
	return s.refreshSplit()
}

// setCardChoice 记下点名，并顺手记住那张卡属于哪一类。
//
// 类别是当场从探测结果里取的，不靠名字猜：卡被拔掉之后名字就说不出它是哪类，
// 而"用户要的是 USB 卡"这件事要跨过这次拔插活下来。
func setCardChoice(dst *config.IfaceCard, dev string, set netdev.Set) {
	dst.Dev, dst.USB = dev, false
	if dev == "" {
		return
	}
	for _, w := range set.All() {
		if w.Name == dev {
			dst.USB = w.USB
			return
		}
	}
}

// refreshSplit 按当前配置重算两张卡并落到运行时。
//
// 拨开关、换网卡、网卡插拔走的是同一条路：配置是唯一的事实来源，
// 每次都重新探测、重新解析、重新落地，不存在"某一路改了另一路忘了跟"的状态。
//
// 刻意不持 opMu。opMu 是 Start/Stop 那一段的，而 commitProxy 在 strict_route 下
// 会回头去调 Start——抱着 opMu 进来就是自死锁（failover.go 里写着同一条理由）。
// 真正的护栏在 commitProxy 自己：它拿到 s.mu 比对，发现期间被启停过就整只作废。
func (s *Service) refreshSplit() error {
	// 用户主动动这个开关（拨一次、换一张卡）就是"重新问一次"的意思：
	// 探针结论只在这时候作废，平时不重复探——重复探会带着重建隧道，
	// 而隧道重建又会回头再走一遍装配里的探针，那是个自激循环。
	s.clearEgressVerdict()
	s.mu.Lock()
	cfg, rt := s.cfg, s.rt
	s.mu.Unlock()

	// 开关关着就不探测：没在分流就没有网卡可盯，也就不该为此去读 sysfs。
	plan := planForConfig(config.IfaceSplitConfig{})
	if cfg != nil {
		plan = planForConfig(cfg.IfaceSplit)
	}
	_, err := s.applyPlan(plan, rt != nil && cfg != nil, activeAddrOf(cfg))
	if rt == nil || cfg == nil {
		logx.Infof("网卡分流开关设为 %v（当前未运行，启动后生效）", cfg != nil && cfg.IfaceSplit.Enable)
	}
	return err
}

// logSplitPlan 把一次解析的结果写进日志。
//
// 单独抽出来是因为启动与运行期是两条路：启动那次不走 applyPlan，
// 而"没生效"这件事又必须在启动那一行就说得清——
// 只印一句"直连走 ，代理走 "的话，排查的人只能回去读代码猜是哪一步没成。
func logSplitPlan(plan splitPlan) {
	switch {
	case plan.pick.direct != "":
		logx.Infof("网卡分流：直连走 %s，代理走 %s", plan.pick.direct, devOr(plan.pick.proxy, "系统默认路由"))
		if plan.note != "" {
			logx.Warnf("网卡分流：%s", plan.note)
		}
	case plan.note != "":
		logx.Warnf("网卡分流未生效：%s", plan.note)
	}
}

// applyPlan 把一份解析结果落到运行时。
//
// 只在**代理那张**真的换了的时候才重建隧道：直连是每条连接现拨的，改个名字就够；
// 而隧道那条 socket 已经钉死在旧卡上，包括"从有卡变成没卡"这一种——
// 那一次重建才真的把它放回系统默认路由，否则拔掉 USB 卡就是全部代理一起断。
//
// 复用同一个 Split 实例而不是换一个：出站集体持有它，换指针的话正在传的隧道
// 还攥着老实例，关开关也只是把新实例的闸门关了——界面说"未开启"，
// 隧道其实还钉在那张 USB 卡上。
func (s *Service) applyPlan(plan splitPlan, running bool, nodeAddr string) (splitPick, error) {
	// 通道要在加锁之前拿到：ensureDialHelper 自己会加锁，在锁里调它就是自死锁。
	// 拿到它并不会起进程——常驻 helper 是第一次真的要用时才拉起来的。
	binder := s.bindChannel()
	// 钉上发不出包就退回不钉：留着这条"已生效"的记录，代价是那一侧全部连接一起超时，
	// 而界面还会指着那张卡说在用它。降级之后 note 会写清是它自己退回默认路由的。
	// 两侧各问一次（settleEgress）：以前只问代理侧，于是直连那一半同样是废的、
	// 而 note 写着"直连真的在干活"——那句假话的账记在 README §10.19。
	before := plan.pick
	var (
		bindDirect, bindProxy bool
		bindNotes             []string
	)
	if running {
		plan, bindDirect, bindProxy, bindNotes = s.settleEgress(plan, nodeAddr, s.currentCfg())
	}
	downgraded := !before.same(plan.pick)
	s.mu.Lock()
	sp := s.split
	curDirect, curProxy := "", ""
	if sp != nil {
		curDirect, curProxy = sp.Devices()
	}
	// 现状已经就是这样就到此为止：网卡监视每 10 秒问一次，以前每次都要写一遍状态、
	// 念一遍同一句「发不出包」（2026-10-29 实测 60 秒刷了 12 条）。真变了才落地、才说。
	// 特权通道那两个开关也在比较里：它们换了就必须重新落地，否则"helper 中途出现"
	// 这一转会因为两张卡名字没变而被这道早退吞掉。
	if curDirect == plan.pick.direct && curProxy == plan.pick.proxy &&
		s.ifaceSplit.Note == plan.note && s.splitBind == [2]bool{bindDirect, bindProxy} {
		s.mu.Unlock()
		return plan.pick, nil
	}
	if sp != nil {
		sp.SetDevices(plan.pick.direct, plan.pick.proxy)
		sp.SetBindSocket(binder)
		sp.SetBindNeeded(bindDirect, bindProxy)
		s.splitBind = [2]bool{bindDirect, bindProxy}
	}
	s.ifaceCards = plan.cards
	s.ifaceSplit = IfaceSplitStatus{
		Note:      plan.note,
		DirectDev: plan.pick.direct,
		ProxyDev:  plan.pick.proxy,
	}
	s.mu.Unlock()

	// 交回**实际落地的**那一份，调用方念这句话时才不会念成点名那份（降级后是空串）。
	if sp == nil || !running {
		return plan.pick, nil
	}
	s.applySplitGate(s.effectiveMode())
	logSplitPlan(plan)
	if len(bindNotes) > 0 {
		// 只在这里说一次：上面那道"现状已经就是这样"的早退保证了它不会每 10 秒刷一遍。
		logx.Infof("网卡分流：%s", strings.Join(bindNotes, "；"))
	}
	// 降级不是"用户换了张卡"，不该触发重建：隧道本来就是按同一份判据装配的，
	// 重建会回头再走一遍装配、装配又带着同一个结论再落一次——那是循环的另一半。
	if downgraded || curProxy == plan.pick.proxy {
		return plan.pick, nil
	}
	if err := s.rebuildProxy(); err != nil {
		return plan.pick, err
	}
	return plan.pick, nil
}

// rebuildProxy 把正在传的那条隧道重造一遍，让它换到（或者离开）另一张卡。
//
// 走的是换节点同一条路：规则里钉死的那些节点要丢掉重来，否则它们还攥着旧卡的出站。
func (s *Service) rebuildProxy() error {
	s.dropPinnedNodes()
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	next, err := s.stageActive(cfg.Active)
	if err != nil {
		return fmt.Errorf("重建隧道以切换代理网卡失败: %w", err)
	}
	if next == nil {
		return nil
	}
	if err := s.commitProxy(next); err != nil {
		return err
	}
	logx.Infof("已重建隧道，代理流量现在走 %s", devOr(s.ProxyDevNow(), "系统默认路由"))
	return nil
}

// ProxyDevNow 报告代理此刻该走哪张卡，没钉住时是空串。
func (s *Service) ProxyDevNow() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, p := s.split.Devices()
	return p
}

// devOr 把空串说成「系统默认路由」——日志里出现一个空的网卡名会被当成读错了。
func devOr(dev, fallback string) string {
	if dev == "" {
		return fallback
	}
	return dev
}

// effectiveMode 返回此刻真正生效的分流模式（命令行覆盖优先）。
func (s *Service) effectiveMode() config.Mode {
	s.mu.Lock()
	override := s.modeOverride
	s.mu.Unlock()
	if override != "" {
		return override
	}
	if m := s.Mode(); m != "" {
		if parsed, err := config.ParseMode(m); err == nil {
			return parsed
		}
	}
	return config.ModeRule
}
