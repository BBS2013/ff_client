package router

import (
	"context"
	"testing"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
)

// TestResultCarriesTheInterface 决策要顺带说清"这条连接走了哪张卡"。
//
// 连接表那一列全部来自这里。它错的代价是安静的：网卡一栏会一直显示旧卡名或者空串，
// 而用户恰恰是在"分流到底生效没有"这个问题上才去看这一列——指错了方向比不说更糟。
func TestResultCarriesTheInterface(t *testing.T) {
	rt, _, _ := newTestRouter(t, ruleBook, config.ModeRule)

	// 没装查询器时必须给空串，而不是 panic 或猜一张卡。
	if res := mustResult(t, rt, "shop.cn"); res.Iface != "" {
		t.Errorf("没挂查询器不该报网卡，得到 %q", res.Iface)
	}

	rt.SetIfaceResolver(func(p outbound.Policy) string {
		if p == outbound.PolicyDirect {
			return "wlp3s0f0"
		}
		return "wlx001f0578cdff"
	})

	if got := mustResult(t, rt, "shop.cn").Iface; got != "wlp3s0f0" {
		t.Errorf("直连该报内置无线，得到 %q", got)
	}
	if got := mustResult(t, rt, "a.example.com").Iface; got != "wlx001f0578cdff" {
		t.Errorf("走代理该报 USB 无线，得到 %q", got)
	}

	// 卸掉查询器后要立刻回到空串：分流被收回时，界面不该继续挂着旧卡名。
	rt.SetIfaceResolver(nil)
	if got := mustResult(t, rt, "shop.cn").Iface; got != "" {
		t.Errorf("卸掉查询器后不该还报网卡，得到 %q", got)
	}
}

// TestRejectedConnHasNoInterface 被拦下的连接压根没有出站，也就没有网卡。
func TestRejectedConnHasNoInterface(t *testing.T) {
	rt, _, _ := newTestRouter(t, "DOMAIN-SUFFIX,ads.example.com,REJECT\nFINAL,DIRECT\n", config.ModeRule)
	rt.SetIfaceResolver(func(outbound.Policy) string { return "wlx001f0578cdff" })

	// 拦截那条路必然带着错误回来，所以不能走 mustResult（它把错误当失败）。
	_, res, err := rt.DialHost(context.Background(), "ads.example.com:443", "")
	if err == nil {
		t.Fatal("命中拦截却没报错")
	}
	if res.Iface != "" {
		t.Errorf("拦截不该有网卡，得到 %q", res.Iface)
	}
}

// TestPinnedNodeStillReportsInterface 规则钉了节点的那条路也要带网卡。
//
// 那条路提前 return，走的是另一段代码。漏了它的话，"node= 钉节点"的用户看到的
// 会是空网卡——而那恰好是最需要这一列的人群（他们在排查单节点的问题）。
func TestPinnedNodeStillReportsInterface(t *testing.T) {
	known := map[string]*pinDialer{"US-LA": {name: "PROXY-US-LA"}}
	rt, _ := newPinRouter(t, pinBook, known, nil)
	rt.SetIfaceResolver(func(p outbound.Policy) string {
		if p == outbound.PolicyDirect {
			return "wlp3s0f0"
		}
		return "wlx001f0578cdff"
	})

	res := mustResult(t, rt, "a.pinned.test")
	if res.Node != "US-LA" {
		t.Fatalf("这条用例本该走钉住的节点，得到 %q", res.Node)
	}
	if res.Iface != "wlx001f0578cdff" {
		t.Errorf("钉节点那条路也得报网卡，得到 %q", res.Iface)
	}
}
