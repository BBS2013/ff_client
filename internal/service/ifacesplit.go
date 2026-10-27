package service

import (
	"fmt"
	"strings"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/netdev"
	"wps_app/internal/outbound"
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

// splitPlan 是一次解析的完整结果：两张卡钉在哪、为什么没钉成、界面上有哪些卡可选。
type splitPlan struct {
	pick  splitPick
	note  string
	cards []IfaceCardView
}

// probeBind 探当前进程有没有权限钉网卡。
// 做成变量是为了让单测不必真的去建 socket 绑网卡：那一步是真的系统调用。
var probeBind = outbound.ProbeDeviceBind

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
	s.mu.Lock()
	cfg, rt := s.cfg, s.rt
	s.mu.Unlock()

	// 开关关着就不探测：没在分流就没有网卡可盯，也就不该为此去读 sysfs。
	plan := planForConfig(config.IfaceSplitConfig{})
	if cfg != nil {
		plan = planForConfig(cfg.IfaceSplit)
	}
	err := s.applyPlan(plan, rt != nil && cfg != nil)
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
func (s *Service) applyPlan(plan splitPlan, running bool) error {
	s.mu.Lock()
	sp := s.split
	_, prevProxy := sp.Devices()
	if sp != nil {
		sp.SetDevices(plan.pick.direct, plan.pick.proxy)
	}
	s.ifaceCards = plan.cards
	s.ifaceSplit = IfaceSplitStatus{
		Note:      plan.note,
		DirectDev: plan.pick.direct,
		ProxyDev:  plan.pick.proxy,
	}
	s.mu.Unlock()

	if sp == nil || !running {
		return nil
	}
	s.applySplitGate(s.effectiveMode())
	logSplitPlan(plan)
	if prevProxy == plan.pick.proxy {
		return nil
	}
	return s.rebuildProxy()
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
