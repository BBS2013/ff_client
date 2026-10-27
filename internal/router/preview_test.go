// 探测（Preview）这一路的判据。
//
// 它存在的唯一理由是让面板上那句"这个域名现在会怎么走"和真转发是同一个答案，
// 所以这里盯的全是"预览与拨号会不会分家"：分家一次，用户就会拿着一句
// "探测说走代理"去查一条实际被拦掉的连接，而拦截在应用侧是静默的，他没有第二条线索。
//
// 另一半盯的是**它不许有副作用**：探测是在网已经不好的时候被打开的，
// 一次查询既不能拨号，也不能把节点的服务端地址解析一遍
// （第一版就是走了 `pick` 的出站那一段，于是"钉了个 DNS 解析不了的节点"
// 会让整个探测框报查询失败——被 gate 的 `make test` 抓到，见 §9.3）。
package router

import (
	"context"
	"strings"
	"testing"

	"wps_app/internal/outbound"
)

func TestPreviewAnswersWithoutTouchingOutbounds(t *testing.T) {
	us := &pinDialer{name: "PROXY-US-LA"}
	known := map[string]*pinDialer{"US-LA": us}
	builds := 0
	rt, active := newPinRouter(t, pinBook, known, &builds)

	res, err := rt.Preview(context.Background(), "a.pinned.test")
	if err != nil {
		t.Fatalf("Preview: %v", err)
	}
	if res.Node != "US-LA" {
		t.Errorf("探测报的节点是 %q，想要钉住的那条 US-LA", res.Node)
	}
	if res.Policy != outbound.PolicyProxy {
		t.Errorf("策略是 %q，想要 PROXY", res.Policy)
	}
	// 一个字节都不拨、一只出站都不建：后者是这条守卫的重点——
	// 建出站会顺带解析节点地址，而那是探测不该做的事。
	if us.last != "" || active.last != "" {
		t.Errorf("拨号了：US-LA 被要求拨 %q，活动节点被要求拨 %q", us.last, active.last)
	}
	if builds != 0 {
		t.Errorf("探测建了 %d 次出站：它只该读规则，不该把隧道架起来", builds)
	}

	plain, err := rt.Preview(context.Background(), "a.plain.test")
	if err != nil {
		t.Fatalf("Preview plain: %v", err)
	}
	// 没钉节点的 PROXY 要答"当前活动节点"，不是空着让用户以为没节点。
	// 这个数取自内存里的出站集合，不需要建任何东西。
	if plain.Node != "JP-MAIN" {
		t.Errorf("没钉节点时报的节点是 %q，想要当前活动的 JP-MAIN", plain.Node)
	}
}

// TestPreviewGhostPinStillAnswers：规则钉着一个配置里没有的名字时，
// 探测照样把规则那一段答完（钉住谁、判成什么），而不是整句失败。
// "这条钉了个不存在的节点"是「这份名单里的问题」那一栏的活，
// 而真拨号会在 GetNode 那里明确失败——两处都不必靠建出站来回答。
func TestPreviewGhostPinStillAnswers(t *testing.T) {
	builds := 0
	rt, _ := newPinRouter(t, pinBook, map[string]*pinDialer{}, &builds)
	res, err := rt.Preview(context.Background(), "a.pinned.test")
	if err != nil {
		t.Fatalf("钉着不存在的节点就把探测打死是错的: %v", err)
	}
	if res.Node != "US-LA" || !strings.Contains(res.Matched, "node=US-LA") {
		t.Errorf("钉住的名字没照规则报出来: %+v", res)
	}
	if builds != 0 {
		t.Errorf("探测试着去建那只不存在的出站（%d 次）", builds)
	}
}

// TestPreviewBlockedIsNotAnError 把"被拦"当答案返回，而不是当失败。
// 界面拼的是错误原文，所以这里一旦退回成 error，探测框就会在用户输入一个
// 真的被拦的域名时报"查询失败"——而那恰恰是他最想看到的一句话。
func TestPreviewBlockedIsNotAnError(t *testing.T) {
	rt, active := newPinRouter(t, pinBook, map[string]*pinDialer{}, nil)
	rt.Engine().SetBlocklist([]string{"blocked.test"})

	res, err := rt.Preview(context.Background(), "x.blocked.test")
	if err != nil {
		t.Fatalf("被拦是这一问的答案，不是失败: %v", err)
	}
	if res.Policy != outbound.PolicyReject {
		t.Errorf("策略是 %q，想要 REJECT", res.Policy)
	}
	if !strings.Contains(res.Matched, "(block)") {
		t.Errorf("命中依据里看不出是名单拦的: %q", res.Matched)
	}
	if active.last != "" {
		t.Errorf("被拦却还是拨了号: %s", active.last)
	}
}

// TestPreviewShapes：探测框里的输入是手打的，形状比规则里的目标野。
func TestPreviewShapes(t *testing.T) {
	rt, _ := newPinRouter(t, pinBook, map[string]*pinDialer{}, nil)
	ctx := context.Background()

	// 带端口的写法要和连接表里复制出来的一模一样能查：先摘端口，
	// 与 pick 第一句 SplitHostPort 同一个读法。
	withPort, err := rt.Preview(ctx, "a.plain.test:8443")
	if err != nil {
		t.Fatalf("带端口的输入: %v", err)
	}
	if !strings.Contains(withPort.Matched, "plain.test") {
		t.Errorf("端口没被摘掉，判定用的是 %q: %+v", withPort.Host, withPort)
	}
	bracketed, err := rt.Preview(ctx, "[2001:db8::1]:443")
	if err != nil {
		t.Fatalf("带方括号的 IPv6: %v", err)
	}
	if bracketed.Host != "2001:db8::1" {
		t.Errorf("host 是 %q，想要剥掉方括号与端口的那个", bracketed.Host)
	}
	// 裸 IPv6（没端口没方括号）照原样交给引擎按 IP 规则处理。
	if _, err := rt.Preview(ctx, "2001:db8::1"); err != nil {
		t.Errorf("裸 IPv6 被当成坏地址: %v", err)
	}
	// 空输入要报错：让它往下走会得到 FINAL 的答案，
	// 屏幕上就是"你什么都没输，但这条走直连"。
	if _, err := rt.Preview(ctx, "   "); err == nil {
		t.Error("空目标居然答出来了")
	}
}

// TestPreviewReportsThePinnedCard：分流开着时"这条走哪张卡"是这一问的一部分，
// 而它必须与真拨号那一步报同一个名字——探测说走内置网卡、实际从 USB 卡出去，
// 是这一页最难自证的那种分家。
func TestPreviewReportsThePinnedCard(t *testing.T) {
	rt, _ := newPinRouter(t, pinBook, map[string]*pinDialer{}, nil)
	resolve := func(p outbound.Policy) string {
		if p == outbound.PolicyDirect {
			return "wlp3s0f0"
		}
		return "wlx001f0578cdff"
	}
	rt.SetIfaceResolver(resolve)
	ctx := context.Background()

	proxy, err := rt.Preview(ctx, "a.plain.test")
	if err != nil {
		t.Fatalf("Preview plain: %v", err)
	}
	if proxy.Iface != "wlx001f0578cdff" {
		t.Errorf("走代理报的网卡是 %q，想要 USB 那张", proxy.Iface)
	}
	direct, err := rt.Preview(ctx, "www.final.example")
	if err != nil {
		t.Fatalf("Preview final: %v", err)
	}
	if direct.Iface != "wlp3s0f0" {
		t.Errorf("直连报的网卡是 %q，想要内置那张", direct.Iface)
	}
	_, dialed, err := rt.DialHost(ctx, "a.plain.test:443", "")
	if err != nil {
		t.Fatalf("DialHost: %v", err)
	}
	if proxy.Iface != dialed.Iface {
		t.Errorf("网卡分家：预览 %q / 拨号 %q", proxy.Iface, dialed.Iface)
	}

	// 分流被收回（查询器卸掉）后要立刻回到空串：界面不该继续挂着一张已经不算数的卡。
	rt.SetIfaceResolver(nil)
	after, err := rt.Preview(ctx, "a.plain.test")
	if err != nil {
		t.Fatalf("Preview after: %v", err)
	}
	if after.Iface != "" {
		t.Errorf("卸掉查询器后探测仍报网卡: %q", after.Iface)
	}

	// 被拦的那条不钉卡：它一个字节都不发出去，报一张卡等于凭空造一条走向。
	rt.Engine().SetBlocklist([]string{"blocked.test"})
	rt.SetIfaceResolver(resolve)
	blocked, err := rt.Preview(ctx, "x.blocked.test")
	if err != nil {
		t.Fatalf("Preview blocked: %v", err)
	}
	if blocked.Iface != "" {
		t.Errorf("被拦的连接报了网卡 %q，它根本不出站", blocked.Iface)
	}
}

// TestPreviewAgreesWithDial 是这一整条设计的那根钉子：
// 同一个目标，预览与真拨号给出的策略、命中依据、节点必须一字不差。
// `Outbound` 不在比较之列：那是出站自己的名字，只有真去 Get 才知道，
// 而探测刻意不碰那一步（见 Preview 的注释）。
func TestPreviewAgreesWithDial(t *testing.T) {
	known := map[string]*pinDialer{"US-LA": {name: "PROXY-US-LA"}, "SG": {name: "PROXY-SG"}}
	rt, _ := newPinRouter(t, pinBook, known, nil)
	ctx := context.Background()

	for _, host := range []string{"a.pinned.test", "a.plain.test", "www.final.example"} {
		p, err := rt.Preview(ctx, host)
		if err != nil {
			t.Fatalf("预览 %s: %v", host, err)
		}
		_, d, err := rt.DialHost(ctx, host+":443", "")
		if err != nil {
			t.Fatalf("拨号 %s: %v", host, err)
		}
		if p.Policy != d.Policy || p.Matched != d.Matched || p.Node != d.Node {
			t.Errorf("%s 分家了：预览 %+v / 拨号 %+v", host, p, d)
		}
	}
}
