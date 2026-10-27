package router

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

// TestNodeFollowsTheProxy 连接记到哪个节点名下，必须跟着"当前 PROXY 出站是谁"走。
//
// 这条是「各节点用量」那张表的根：表里说 JP 用了 3GB，就得保证那 3GB 真的
// 是从 JP 那条隧道走的。所以节点名与出站必须一起换、一起装配——
// 分成两步就存在"字节记到旧节点头上"的窗口。
func TestNodeFollowsTheProxy(t *testing.T) {
	rt, _, _ := newTestRouter(t, ruleBook, config.ModeRule)

	// 没设过节点名：必须给一个显式占位，而不是空串。
	// 空串会让那批字节在表里消失，"记不全"就变成"看不见"。
	if res := mustResult(t, rt, "a.example.com"); res.Node != "（未命名节点）" {
		t.Errorf("未命名时应当报占位，得到 %q", res.Node)
	}
	if res := mustResult(t, rt, "shop.cn"); res.Node != "DIRECT" {
		t.Errorf("直连不该记到节点名下，得到 %q", res.Node)
	}

	eng := mustRuleBook(t)
	set := outbound.NewSet(outbound.NewDirect(time.Second), &spyDialer{name: "PROXY"}).WithNode("JP")
	rt2 := New(eng, set, 2*time.Second)
	rt2.SetMode(config.ModeRule)
	if res := mustResult(t, rt2, "a.example.com"); res.Node != "JP" {
		t.Errorf("初始装配的节点名没生效，得到 %q", res.Node)
	}
	if _, err := rt2.SwapProxy(&spyDialer{name: "PROXY"}, "SG"); err != nil {
		t.Fatalf("SwapProxy: %v", err)
	}
	if res := mustResult(t, rt2, "a.example.com"); res.Node != "SG" {
		t.Errorf("换节点之后的新决策仍记在旧节点上：%q", res.Node)
	}
}

// TestNodeOfMapping 三种策略各自的去处。REJECT 单独一行是有意的：
// 被拦的连接一个字节都没有，混进节点表里只会稀释它。
func TestNodeOfMapping(t *testing.T) {
	if got := nodeOf(outbound.PolicyDirect, "JP"); got != "DIRECT" {
		t.Errorf("直连 = %q", got)
	}
	if got := nodeOf(outbound.PolicyReject, "JP"); got != "REJECT" {
		t.Errorf("拦截 = %q", got)
	}
	if got := nodeOf(outbound.PolicyProxy, "JP"); got != "JP" {
		t.Errorf("走代理 = %q", got)
	}
}

func mustRuleBook(t *testing.T) *rules.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte(ruleBook), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(path, nil, nil)
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	return eng
}

func mustResult(t *testing.T, rt *Router, host string) Result {
	t.Helper()
	_, res, err := rt.DialHost(context.Background(), host+":443", "")
	if err != nil {
		t.Fatalf("DialHost %s: %v", host, err)
	}
	return res
}
