package service

import (
	"strings"
	"testing"

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
	sp := outbound.NewSplit("", "")
	svc := New(writeCfg(t), nil)
	svc.split = sp
	sp.SetActive(true)

	svc.applyPlan(splitPlan{pick: splitPick{direct: "wlp3s0f0", proxy: "wlx001f0578cdff"}}, false)

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
