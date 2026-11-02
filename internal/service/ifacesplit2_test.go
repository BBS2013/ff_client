package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/netdev"
	"wps_app/internal/outbound"
)

// twoCards 是这台机器该有的样子：一内置一 USB。
func twoCards() netdev.Set {
	return netdev.Set{
		Builtin: []netdev.Wireless{{Name: "wlp3s0f0", Addrs: []string{"10.0.0.5"}}},
		USB:     []netdev.Wireless{{Name: "wlx001f0578cdff", USB: true, Addrs: []string{"192.168.0.23"}}},
	}
}

// 只探权限那一步换成假的：解析要挑网卡，不能让单测真的去建 socket 绑网卡。
func stubProbe(t *testing.T, err error) {
	t.Helper()
	old := probeBind
	probeBind = func(string) error { return err }
	t.Cleanup(func() { probeBind = old })
}

// 点名的那张还在，就照点名来。
func TestResolveSplitHonoursNamedCards(t *testing.T) {
	stubProbe(t, nil)
	plan := resolveSplit(twoCards(), config.IfaceSplitConfig{
		Enable: true,
		// 与默认相反：内置给代理、USB 给直连。用户点得动才叫选择。
		Direct: config.IfaceCard{Dev: "wlx001f0578cdff", USB: true},
		Proxy:  config.IfaceCard{Dev: "wlp3s0f0"},
	})
	if plan.pick.direct != "wlx001f0578cdff" || plan.pick.proxy != "wlp3s0f0" {
		t.Fatalf("点名没被采纳: %+v", plan.pick)
	}
}

// 只点一边时，另一边照旧按各自的默认类别挑。
// 这条专门盯住"代理侧没点名时默认挑 USB"：默认类别一旦跟着直连侧走，
// 两边就会挑到同一张卡上，而界面看着只是"没分流"，看不出是这个原因。
func TestResolveSplitFillsUnnamedSideAutomatically(t *testing.T) {
	stubProbe(t, nil)
	plan := resolveSplit(twoCards(), config.IfaceSplitConfig{
		Enable: true,
		Direct: config.IfaceCard{Dev: "wlp3s0f0"},
	})
	if plan.pick.direct != "wlp3s0f0" {
		t.Errorf("点名的直连卡没被采纳: %q", plan.pick.direct)
	}
	if plan.pick.proxy != "wlx001f0578cdff" {
		t.Errorf("没点名的代理侧应当默认挑 USB，得到 %q", plan.pick.proxy)
	}
}

// 两边点名同一张卡：钉在同一张上与不钉是一回事。
// 界面已经挡掉了，手改配置的人也会撞上——撞上时该说清，而不是给出一个假象。
func TestResolveSplitRefusesTheSameCardOnBothSides(t *testing.T) {
	stubProbe(t, nil)
	plan := resolveSplit(twoCards(), config.IfaceSplitConfig{
		Enable: true,
		Direct: config.IfaceCard{Dev: "wlp3s0f0"},
		Proxy:  config.IfaceCard{Dev: "wlp3s0f0"},
	})
	if plan.pick != (splitPick{}) {
		t.Fatalf("同一张卡不该算作一次分流: %+v", plan.pick)
	}
	if !strings.Contains(plan.note, "同一张卡") {
		t.Errorf("note 得说清是两边撞了，得到 %q", plan.note)
	}
}

// 换了同类的另一张卡：点名要的那张没了，按它的类别顶上同类那一张。
// 这是「拔掉 USB 卡再插一张新的」能被接住的那一步。
func TestResolveSplitFallsBackToSameClassWhenNamedCardIsGone(t *testing.T) {
	stubProbe(t, nil)
	set := twoCards()
	set.USB = []netdev.Wireless{{Name: "wlx001f0578cdfe", USB: true, Addrs: []string{"192.168.0.9"}}}
	plan := resolveSplit(set, config.IfaceSplitConfig{
		Enable: true,
		Proxy:  config.IfaceCard{Dev: "wlx001f0578cdff", USB: true},
	})
	if plan.pick.proxy != "wlx001f0578cdfe" {
		t.Fatalf("该顶上同类的那张，得到 %q", plan.pick.proxy)
	}
	if !strings.Contains(plan.note, "wlx001f0578cdff") {
		t.Errorf("换了卡这件事必须说出来，note=%q", plan.note)
	}
}

// 只剩一张卡时整份分流都不做，而不是只收掉一侧。
// 只钉一张与一张都不钉完全等价——那张卡本来就是默认路由——
// 留一个"不对称"的状态只会在界面上看着像还有一半在跑。
func TestResolveSplitDropsEverythingWithOnlyOneCard(t *testing.T) {
	stubProbe(t, nil)
	set := twoCards()
	set.USB = nil
	plan := resolveSplit(set, config.IfaceSplitConfig{
		Enable: true,
		Proxy:  config.IfaceCard{Dev: "wlx001f0578cdff", USB: true},
	})
	if plan.pick != (splitPick{}) {
		t.Fatalf("只剩一张卡时不该留下半套分流: %+v", plan.pick)
	}
	if plan.note == "" {
		t.Error("退回默认路由这件事必须说给界面听")
	}
}

// 探不到钉网卡的权限时整份分流都不做，而不是照样去绑。
// 照样去绑的症状是所有连接一起失败，而界面只显示"已开启"。
func TestResolveSplitRefusesWithoutBindPermission(t *testing.T) {
	stubProbe(t, errNoPermission)
	plan := resolveSplit(twoCards(), config.IfaceSplitConfig{Enable: true})
	if plan.pick != (splitPick{}) {
		t.Fatalf("探不到权限时不该给出两张卡: %+v", plan.pick)
	}
	if !strings.Contains(plan.note, "权限") {
		t.Errorf("note 得说清是没权限，得到 %q", plan.note)
	}
}

var errNoPermission = errStr("钉网卡失败: operation not permitted")

type errStr string

func (e errStr) Error() string { return string(e) }

// 开关关着就不该探测、也不该给卡片——没在分流就没有网卡可列。
func TestResolveSplitOffReportsNothingToChoose(t *testing.T) {
	plan := resolveSplit(twoCards(), config.IfaceSplitConfig{})
	if plan.pick != (splitPick{}) {
		t.Fatalf("关着就不该有分流: %+v", plan.pick)
	}
	if len(plan.cards) != 0 {
		t.Fatalf("关着时下拉不该有可选项，得到 %+v", plan.cards)
	}
}

// 可选项要带上面试选得出来的全部网卡，且地址要一并带过去。
func TestResolveSplitListsEveryCard(t *testing.T) {
	stubProbe(t, nil)
	plan := resolveSplit(twoCards(), config.IfaceSplitConfig{Enable: true})
	if len(plan.cards) != 2 {
		t.Fatalf("两张卡都该列出来，得到 %+v", plan.cards)
	}
	if plan.cards[0].Name != "wlp3s0f0" || plan.cards[1].Name != "wlx001f0578cdff" {
		t.Errorf("先内置后 USB 的次序要稳定，得到 %+v", plan.cards)
	}
	if len(plan.cards[1].Addrs) != 1 || plan.cards[1].Addrs[0] != "192.168.0.23" {
		t.Errorf("地址要一并带过去，得到 %+v", plan.cards[1])
	}
}

// applyPlan 必须复用同一个 Split 实例。
// 换指针的话正在传的隧道还攥着老实例，关开关就只是把新实例的闸门关了——
// 界面说"未开启"，隧道其实还钉在那张卡上。
func TestApplyPlanReusesTheSameSplit(t *testing.T) {
	// 起点就是"代理已经钉在这张卡上"：换卡才要重建隧道，而重建会去拨真节点。
	// 这条用例要验的是特权通道的开合，不是重建本身。
	sp := outbound.NewSplit("wlp3s0f0", "wlx001f0578cdff")
	svc := New(writeCfg(t), nil)
	svc.split = sp
	sp.SetActive(true)

	_, _ = svc.applyPlan(splitPlan{pick: splitPick{direct: "wlp3s0f0", proxy: "wlx001f0578cdff"}}, false, "example.com:8443")

	if svc.split != sp {
		t.Fatal("applyPlan 换掉了 Split 实例：出站还攥着老的那份")
	}
	d, p := sp.Devices()
	if d != "wlp3s0f0" || p != "wlx001f0578cdff" {
		t.Fatalf("两张卡没落到同一个实例上: %q / %q", d, p)
	}
	if !sp.Active() {
		t.Error("闸门不该被 applyPlan 收起来，那是模式的事")
	}
}

// 状态投影里的两个关键量：生效与否要同时看"两张都在"和"模式是规则"。
// 读的是 Split 本身而不是另抄一份——抄一份就多一处可能对不上的地方。
func TestSplitStatusActiveNeedsBothCards(t *testing.T) {
	sp := outbound.NewSplit("wlp3s0f0", "wlx001f0578cdff")
	sp.SetActive(true)
	svc := New(writeCfg(t), nil)
	svc.split = sp

	if st := svc.splitStatusLocked(true, true); !st.Active {
		t.Error("两张卡都在、闸门开着、正在跑：应当显示已生效")
	}
	sp.SetDevices("wlp3s0f0", "")
	if st := svc.splitStatusLocked(true, true); st.Active {
		t.Error("只剩一张卡时不该显示已生效")
	}
	sp.SetDevices("wlp3s0f0", "wlx001f0578cdff")
	if st := svc.splitStatusLocked(true, false); st.Active {
		t.Error("没在跑时不该显示已生效")
	}
	if st := svc.splitStatusLocked(false, true); st.Active {
		t.Error("开关关着时不该显示已生效")
	}
}

// 监视器的判断：连着两轮看到同一个新结果才动手，中间的抖动一律不动。
func TestIfaceSettledWaitsForTheChangeToLand(t *testing.T) {
	base := splitPick{direct: "wlp3s0f0", proxy: "wlx001f0578cdff"}
	// 基线为空时不动手：那时的动作该是记住现状。
	if ifaceSettled(splitPick{}, splitPick{}, base) {
		t.Error("基线还没建立时不该动手")
	}
	if ifaceSettled(base, base, base) {
		t.Error("和当前一样时不该动手")
	}
	gone := splitPick{direct: "wlp3s0f0"}
	if ifaceSettled(base, base, gone) {
		t.Error("第一轮看到新结果时不该动手——它可能还在抖")
	}
	if !ifaceSettled(base, gone, gone) {
		t.Error("连着两轮都是同一个新结果就该动手了")
	}
	other := splitPick{direct: "", proxy: "wlx001f0578cdff"}
	if ifaceSettled(base, gone, other) {
		t.Error("这一轮又变了说明还在抖，不该动手")
	}
}

// 只换卡名（DHCP 续租）不该换来一次重建：比较的是接口名，不是地址。
func TestIfaceSettledIgnoresAddressChanges(t *testing.T) {
	base := splitPick{direct: "wlp3s0f0", proxy: "wlx001f0578cdff"}
	if !base.same(splitPick{direct: "wlp3s0f0", proxy: "wlx001f0578cdff"}) {
		t.Fatal("同一对名字就该算没变")
	}
}
func TestSetIfaceSplitCardsRejectsSameCard(t *testing.T) {
	svc := New(writeCfg(t), nil)
	if err := svc.SetIfaceSplitCards("wlp3s0f0", "wlp3s0f0"); err == nil {
		t.Fatal("两边选同一张卡必须报错，而不是默默执行")
	}
}

// 选卡要连"它属于哪一类"一起落盘：卡被拔掉之后名字就说不出它是哪类，
// 而"用户要的是 USB 卡"这件事要跨过这次拔插活下来。
func TestSetIfaceSplitCardsRecordsTheClass(t *testing.T) {
	set := twoCards()

	var direct, proxy config.IfaceCard
	setCardChoice(&direct, "wlx001f0578cdff", set)
	setCardChoice(&proxy, "wlp3s0f0", set)

	if direct.Dev != "wlx001f0578cdff" || !direct.USB {
		t.Errorf("USB 卡要连类别一起记下来，得到 %+v", direct)
	}
	if proxy.Dev != "wlp3s0f0" || proxy.USB {
		t.Errorf("内置卡不该被记成 USB，得到 %+v", proxy)
	}
	setCardChoice(&direct, "", set)
	if direct.Dev != "" || direct.USB {
		t.Errorf("清空之后不该留下上一张卡的类别，得到 %+v", direct)
	}
}

// 换完卡，落盘的那份要能被下一次启动原样读回来。
func TestSetIfaceSplitCardsPersists(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)
	if err := svc.SetIfaceSplitCards("", ""); err != nil {
		t.Fatalf("SetIfaceSplitCards: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IfaceSplit.Direct.Dev != "" || cfg.IfaceSplit.Proxy.Dev != "" {
		t.Fatalf("两边都传空串就该落成不点名，得到 %+v / %+v",
			cfg.IfaceSplit.Direct, cfg.IfaceSplit.Proxy)
	}
}

// ---------- 钉上网卡却发不出包 ----------

// stubEgress 把那一次真拨号换成假的：键是网卡名（空串=不钉的对照组），值是非空表示拨不通。
func stubEgress(t *testing.T, res map[string]string) {
	t.Helper()
	old := probeEgress
	probeEgress = func(dev, _ string, _ time.Duration) error {
		if msg := res[dev]; msg != "" {
			return errors.New(msg)
		}
		return nil
	}
	t.Cleanup(func() { probeEgress = old })
}

func splitSvc() *Service { return &Service{} }

// setsockopt 成功不代表包出得去：这台机器的链路安全软件就是在普通进程钉网卡之后
// 静默丢包。只看系统调用会留下一句「已生效」，症状却是全部代理连接一起超时
// （2026-10-20 的 612 条拨不通、2026-10-29 复现，都是这一条）。
// 所以钉不通而不钉能通时，必须自己退回默认路由并把原因写进 note。
func TestEgressBlockedDowngradesToDefaultRoute(t *testing.T) {
	stubEgress(t, map[string]string{"wlx001f0578cdff": "i/o timeout", "": ""})
	why, useBind := splitSvc().egressBlockedWhy("wlx001f0578cdff", "example.com:8443", "代理", nil)
	if !strings.Contains(why, "发不出包") || !strings.Contains(why, "系统默认路由") {
		t.Fatalf("退回默认路由这件事必须写在 note 里: %q", why)
	}
	if !strings.Contains(why, "example.com:8443") {
		t.Fatalf("note 要给出对照组拨通的是哪个地址: %q", why)
	}
	if useBind {
		t.Fatal("没配 tun.helper 时不该说有特权通道可用")
	}
}

// 没给目标就不许假装验过：命令行那条路上配置还没落定。
func TestEgressBlockedNeedsATarget(t *testing.T) {
	stubEgress(t, map[string]string{"wlx001f0578cdff": "i/o timeout"})
	if why, _ := splitSvc().egressBlockedWhy("wlx001f0578cdff", "", "代理", nil); why != "" {
		t.Fatalf("没有拨号目标时不该给出结论: %q", why)
	}
}

// 不钉也拨不通时不能冤枉分流：那是节点或链路的事，界面上的红要留给真正的原因。
func TestEgressBlockedStaysSilentWhenNodeUnreachable(t *testing.T) {
	stubEgress(t, map[string]string{"wlx001f0578cdff": "i/o timeout", "": "connection refused"})
	if why, _ := splitSvc().egressBlockedWhy("wlx001f0578cdff", "example.com:8443", "代理", nil); why != "" {
		t.Fatalf("两条都拨不通不该报分流问题: %q", why)
	}
}

// 钉上也能发出去时不提这事——否则每次正常分流都要被冤枉一遍。
func TestEgressBlockedQuietWhenBindWorks(t *testing.T) {
	stubEgress(t, nil)
	if why, _ := splitSvc().egressBlockedWhy("wlx001f0578cdff", "example.com:8443", "代理", nil); why != "" {
		t.Fatalf("能发出去就不该有 note: %q", why)
	}
}

// applyPlan 这一层要真的把钉住撤掉，而不只是记一句话。
func TestApplyPlanDropsPinWhenEgressBlocked(t *testing.T) {
	stubEgress(t, map[string]string{"wlx001f0578cdff": "i/o timeout", "": ""})
	s := splitSvc()
	eff, err := s.applyPlan(splitPlan{pick: pickOf("wlp3s0f0", "wlx001f0578cdff")}, true, "example.com:8443")
	if err != nil {
		t.Fatalf("applyPlan: %v", err)
	}
	// 交回的必须是**实际落地的**那一份：网卡扫描拿它当基线，
	// 还拿点名的那份去记，就会每 5 秒以为"没落地"再判一次（刷出 190 条日志的循环）。
	if eff.proxy != "" || eff.direct != "wlp3s0f0" {
		t.Fatalf("降级后交回的应当是实际落地的挑选: %+v", eff)
	}
	s.mu.Lock()
	st := s.ifaceSplit
	s.mu.Unlock()
	if st.ProxyDev != "" {
		t.Fatalf("发不出包就不该还钉着这张卡: %+v", st)
	}
	// 直连那侧是真的在干活，不该陪着一起退。
	if st.DirectDev != "wlp3s0f0" {
		t.Fatalf("只该松开代理那一侧，直连应当还钉着: %+v", st)
	}
	if !strings.Contains(st.Note, "发不出包") {
		t.Fatalf("降级这件事必须在 note 里看得见: %q", st.Note)
	}
}

// 同一个「网卡|目标」只许探一次。判成降级会重建隧道，而 commitProxy 在 strict_route
// 下会回头再走一遍装配、装配又探一次——2026-10-29 实测这样每 3~5 秒刷一组日志、
// 每组两次真拨号（113 行里 36 条）。用户拨开关或换卡才是"重新问一次"的信号。
func TestEgressVerdictIsProbedOncePerPair(t *testing.T) {
	var calls int
	old := probeEgress
	probeEgress = func(dev, _ string, _ time.Duration) error {
		if dev != "" {
			calls++
			return errors.New("i/o timeout")
		}
		return nil
	}
	t.Cleanup(func() { probeEgress = old })

	s := splitSvc()
	for i := 0; i < 5; i++ {
		if why, _ := s.egressBlockedWhy("wlx0", "node.example:8443", "代理", nil); why == "" {
			t.Fatalf("第 %d 次仍应给出降级结论", i)
		}
	}
	if calls != 1 {
		t.Fatalf("同一个组合只该探一次，探了 %d 次", calls)
	}
	s.clearEgressVerdict()
	if why, _ := s.egressBlockedWhy("wlx0", "node.example:8443", "代理", nil); why == "" {
		t.Fatal("清掉结论后应当重新探")
	}
	if calls != 2 {
		t.Fatalf("清掉后该再探一次，探了 %d 次", calls)
	}
}

// 同一句「钉上发不出包」，在有提权 helper 的机器上是另一种处置：不改拓扑，
// 把造 socket 这一步交给 helper。这两条用例盯的就是"别退回默认路由"这个决定。
func TestEgressBlockedPrefersBindChannel(t *testing.T) {
	stubEgress(t, map[string]string{"wlx001f0578cdff": "i/o timeout", "": ""})
	s := &Service{cfg: &config.Config{
		Active:  "n",
		TUN:     config.TUNConfig{Helper: []string{"sudo", "-n", "./wps_app-gui", "--tun-helper"}},
		Proxies: []config.ProxyProfile{{Name: "n", Server: config.ServerConfig{Type: config.ProtocolTrojan, Addr: "example.com:8443"}}},
	}}
	why, useBind := s.egressBlockedWhy("wlx001f0578cdff", "example.com:8443", "代理", s.cfg)
	if !useBind {
		t.Fatalf("配了 helper 就该走特权通道: %q", why)
	}
	if !strings.Contains(why, "提权 helper") || !strings.Contains(why, "仍然钉在") {
		t.Fatalf("这句话要说清拓扑没变: %q", why)
	}
	if strings.Contains(why, "退回系统默认路由") {
		t.Fatalf("走特权通道时不该出现退回默认路由: %q", why)
	}
}

// applyPlan 走特权通道时必须维持点名（不 unpin），并把通道真的打开。
func TestApplyPlanKeepsPinWhenBindAvailable(t *testing.T) {
	stubEgress(t, map[string]string{"wlx001f0578cdff": "i/o timeout", "": ""})
	// 起点就是"代理已钉在这张卡"：换卡才要重建隧道，而重建会去拨真节点。
	sp := outbound.NewSplit("wlp3s0f0", "wlx001f0578cdff")
	sp.SetActive(true) // 特权通道只在分流真的在跑时开（ShouldUseBind 的第一道闸）
	s := &Service{split: sp, ifaceSplit: IfaceSplitStatus{Note: "上一轮的说明"}, cfg: &config.Config{
		Active:  "n",
		TUN:     config.TUNConfig{Helper: []string{"sudo", "-n", "./wps_app-gui", "--tun-helper"}},
		Proxies: []config.ProxyProfile{{Name: "n", Server: config.ServerConfig{Type: config.ProtocolTrojan, Addr: "example.com:8443"}}},
	}}
	eff, err := s.applyPlan(splitPlan{pick: pickOf("wlp3s0f0", "wlx001f0578cdff")}, true, "example.com:8443")
	if err != nil {
		t.Fatalf("applyPlan: %v", err)
	}
	if eff.proxy != "wlx001f0578cdff" {
		t.Fatalf("有特权通道就该维持点名，实际交回 %+v", eff)
	}
	if !sp.ShouldUseBind(outbound.PolicyProxy) {
		t.Fatal("特权通道没打开：ShouldUseBind 应为 true")
	}
}

// 这句话会出现两处（状态 note 与测速那一格）。两处各写一份就会各说各话，
// 而"发不出包"很容易被读成"那张卡坏了"——实际坏的是普通进程去钉这一层。
// 这条用例盯住"同一个事实同一句话"。
func TestBindViaHelperNoteIsTheOnlyWording(t *testing.T) {
	note := bindViaHelperNote(config.ProtocolTrojan, "代理", "wlx001f0578cdff", "钉在 wlx001f0578cdff 上拨 x 不通，不钉时却拨得通")
	for _, want := range []string{"分流没有退回默认路由", "面板自己（普通权限）", "wlx001f0578cdff", "提权 helper 代劳", "代理仍然钉在这张卡"} {
		if !strings.Contains(note, want) {
			t.Fatalf("这句话里少了 %q: %q", want, note)
		}
	}
	if !strings.Contains(note, "不钉时却拨得通") {
		t.Fatalf("带上事实时也要留着它: %q", note)
	}
	// 不带事实时句子仍然完整（测速那格放得下短版）。
	short := bindViaHelperNote(config.ProtocolTrojan, "代理", "wlx001f0578cdff", "")
	if !strings.Contains(short, "提权 helper 代劳") || strings.Contains(short, "不通") {
		t.Fatalf("短版也要说清谁代劳: %q", short)
	}
	// hysteria2 的 QUIC 在面板进程里自己钉，不能写成 helper 代劳。
	hys := bindViaHelperNote(config.ProtocolHysteria2, "代理", "wlx001f0578cdff", "")
	if !strings.Contains(hys, "QUIC socket") || strings.Contains(hys, "提权 helper") {
		t.Fatalf("hysteria2 应当说 QUIC 自钉、不是 helper 代劳: %q", hys)
	}
}

// 探针以前只问代理侧，于是 note 里那句「直连钉在内置卡上是真的在干活」是假的：
// 2026-10-30 实测普通权限下内置卡的钉卡同样被静默丢包（两台面板 via DIRECT 失败
// 363/1244 条、成功建连 0 条；转 root 后失败 0、成功 17）。settleEgress 把同一问句
// 在两侧各问一次——谁钉不上松谁，另一侧不该陪着退，也不该替它说话。
func TestSettleEgressProbesBothSides(t *testing.T) {
	stubEgress(t, map[string]string{"wlp3s0f0": "i/o timeout", "": ""})
	s := splitSvc()
	plan, bindDirect, bindProxy, notes := s.settleEgress(
		splitPlan{pick: pickOf("wlp3s0f0", "wlx001f0578cdff")}, "example.com:8443", nil)
	if plan.pick.direct != "" {
		t.Fatalf("直连侧钉上发不出包，必须退回默认路由，got %q", plan.pick.direct)
	}
	if plan.pick.proxy != "wlx001f0578cdff" {
		t.Fatalf("代理侧钉得住，不该陪着退: %+v", plan.pick)
	}
	if bindDirect || bindProxy || len(notes) != 0 {
		t.Fatalf("这台机器上没有特权通道，不该把它打开: %v %v %v", bindDirect, bindProxy, notes)
	}
	if !strings.Contains(plan.note, "直连") {
		t.Fatalf("note 必须说是哪一侧退的，got %q", plan.note)
	}
}

// 两侧都被判钉不上、而这台机器有 helper：两张卡都照用户点名的钉着，各自走通道。
// 这是"拓扑不许退"那件事在按侧之后的形状。
func TestSettleEgressKeepsBothPinsViaBindChannel(t *testing.T) {
	stubEgress(t, map[string]string{
		"wlp3s0f0": "i/o timeout", "wlx001f0578cdff": "i/o timeout", "": "",
	})
	s := &Service{cfg: &config.Config{
		Active:  "n",
		TUN:     config.TUNConfig{Helper: []string{"sudo", "-n", "./wps_app-gui", "--tun-helper"}},
		Proxies: []config.ProxyProfile{{Name: "n", Server: config.ServerConfig{Type: config.ProtocolTrojan, Addr: "example.com:8443"}}},
	}}
	plan, bindDirect, bindProxy, notes := s.settleEgress(
		splitPlan{pick: pickOf("wlp3s0f0", "wlx001f0578cdff")}, "example.com:8443", s.cfg)
	if plan.pick.direct != "wlp3s0f0" || plan.pick.proxy != "wlx001f0578cdff" {
		t.Fatalf("有特权通道时两张卡都不该被松开: %+v", plan.pick)
	}
	if !bindDirect || !bindProxy {
		t.Fatalf("两侧都该走通道: direct=%v proxy=%v", bindDirect, bindProxy)
	}
	if len(notes) != 2 {
		t.Fatalf("两侧各说一句，got %v", notes)
	}
	if !strings.Contains(notes[0], "代理") || !strings.Contains(notes[1], "直连") {
		t.Fatalf("两句必须各自点名是哪一侧换了人做: %v", notes)
	}
	for _, n := range notes {
		if !strings.Contains(n, "提权 helper 代劳") {
			t.Fatalf("句子要说清谁代劳: %q", n)
		}
	}
}
