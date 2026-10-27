package router

import (
	"context"
	"errors"
	"strings"
	"testing"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

const rejectBook = "DOMAIN-SUFFIX,ads.example.com,REJECT\nDOMAIN-SUFFIX,example.com,PROXY\nDOMAIN-SUFFIX,cn,DIRECT\nFINAL,DIRECT\n"

// TestDialRejectBlocksWithoutDialing 命中的是拦截时，两个出站都一次都不许被碰。
//
// 这条断言的真正对象不是"报错对不对"，而是**没有拨号**：
// Set.Get 现在对未知策略是 fail-open 到代理的（那是有测试背书的既有选择），
// 一旦 REJECT 漏进去，黑名单就变成"给这些域名专门走代理"，
// 而且症状与正常转发一模一样，没人看得出来。
func TestDialRejectBlocksWithoutDialing(t *testing.T) {
	rt, direct, proxy := newTestRouter(t, rejectBook, config.ModeRule)
	_, res, err := rt.Dial(context.Background(), "x.ads.example.com:443")
	if !errors.Is(err, rules.ErrBlocked) {
		t.Fatalf("应返回 ErrBlocked，实际 %v", err)
	}
	if direct.last != "" || proxy.last != "" {
		t.Errorf("拦截不该碰任何出站: direct=%q proxy=%q", direct.last, proxy.last)
	}
	if res.Policy != outbound.PolicyReject || res.Outbound != "REJECT" {
		t.Errorf("决策结果要能标出是拦截: %+v", res)
	}
	if !strings.Contains(res.Matched, "ads.example.com") {
		t.Errorf("命中依据里要能看出是哪条拦的: %q", res.Matched)
	}
	// 错误里带上命中依据：客户端那边什么都收不到，本机日志是唯一的线索。
	if !strings.Contains(err.Error(), "ads.example.com") {
		t.Errorf("错误信息里应含命中规则: %v", err)
	}
}

// TestDialRejectHintPath TUN 里目标只剩 IP，靠 hint 才知道域名。
// hint 必须参与拦截判定，否则假 IP 阶段拦不到任何东西。
func TestDialRejectHintPath(t *testing.T) {
	rt, direct, proxy := newTestRouter(t, rejectBook, config.ModeRule)
	_, _, err := rt.DialHost(context.Background(), "198.18.0.7:443", "ads.example.com")
	if !errors.Is(err, rules.ErrBlocked) {
		t.Fatalf("hint 是拦截域名时应被拦，实际 %v", err)
	}
	if direct.last != "" || proxy.last != "" {
		t.Errorf("hint 判定后仍拨了号: direct=%q proxy=%q", direct.last, proxy.last)
	}

	// 同一个 IP 属于另一个没被拦的域名时照常放行。
	rt2, _, proxy2 := newTestRouter(t, rejectBook, config.ModeRule)
	conn, _, err := rt2.DialHost(context.Background(), "198.18.0.9:443", "a.example.com")
	if err != nil {
		t.Fatalf("未被拦的域名被误伤: %v", err)
	}
	_ = conn.Close()
	if proxy2.last != "198.18.0.9:443" {
		t.Errorf("该走代理的没走: %q", proxy2.last)
	}
}

// TestRejectOverriddenByMode 用户选的是「拦截跟其它规则一起被模式绕过」：
// mode=direct 就是「本次运行完全不碰规则集」，黑名单也一并让开。
// 这条用例把这个逃生阀固定下来，免得以后有人"顺手"把拦截提到模式之前。
func TestRejectOverriddenByMode(t *testing.T) {
	rt, direct, proxy := newTestRouter(t, rejectBook, config.ModeDirect)
	conn, res, err := rt.Dial(context.Background(), "ads.example.com:443")
	if err != nil {
		t.Fatalf("direct 模式下应放行，实际 %v", err)
	}
	_ = conn.Close()
	if res.Outbound != "DIRECT" || direct.last == "" || proxy.last != "" {
		t.Errorf("direct 模式判定 = %+v direct=%q proxy=%q", res, direct.last, proxy.last)
	}

	// 而 rule 模式必须拦得住——否则上一条用例只是证明了规则没被加载。
	rt2, _, _ := newTestRouter(t, rejectBook, config.ModeRule)
	if _, _, err := rt2.Dial(context.Background(), "ads.example.com:443"); !errors.Is(err, rules.ErrBlocked) {
		t.Errorf("rule 模式下没拦住: %v", err)
	}
}

func TestDecideReportsReject(t *testing.T) {
	rt, _, _ := newTestRouter(t, rejectBook, config.ModeRule)
	policy, matched := rt.Decide(context.Background(), "ads.example.com")
	if policy != rules.PolicyReject {
		t.Errorf("Decide = %q (%s), 期望 REJECT", policy, matched)
	}
}

// TestUDPRejectBlocksWithoutDialing UDP 同理：判定成拦截时不建关联。
// 故障计数也必须为 0——把拦截记成节点故障，黑名单会凑够次数把好节点切掉。
func TestUDPRejectBlocksWithoutDialing(t *testing.T) {
	proxy := &udpSpy{spyDialer: spyDialer{name: "PROXY"}}
	rt, faults := newUDPRouter(t, rejectBook, proxy)
	pc, res, err := rt.DialUDPHost(context.Background(), "ads.example.com:443", "")
	if !errors.Is(err, rules.ErrBlocked) {
		t.Fatalf("应返回 ErrBlocked，实际 %v", err)
	}
	if pc != nil {
		t.Error("拦截时不该开出 UDP 关联")
	}
	if res.Outbound != "REJECT" {
		t.Errorf("决策结果要能标出是拦截: %+v", res)
	}
	if proxy.dials.Load() != 0 {
		t.Errorf("PROXY 会话数 = %d, 期望 0", proxy.dials.Load())
	}
	if faults.Load() != 0 {
		t.Errorf("拦截被记成了节点故障: %d 次", faults.Load())
	}
}

// TestConfigBlocklistReachesRouter 配置段的名单要真的进到判定里。
// 只测 rules 层不够：装配时忘了 SetBlocklist，名单写得再对也不生效。
func TestConfigBlocklistReachesRouter(t *testing.T) {
	rt, direct, proxy := newTestRouter(t, "DOMAIN-SUFFIX,keep.example,DIRECT\nFINAL,PROXY\n", config.ModeRule)
	rt.Engine().SetBlocklist([]string{"ads.example.com"})

	if _, _, err := rt.Dial(context.Background(), "ads.example.com:443"); !errors.Is(err, rules.ErrBlocked) {
		t.Fatalf("配置段名单没生效: %v", err)
	}
	if direct.last != "" || proxy.last != "" {
		t.Errorf("没拦住还拨了号: direct=%q proxy=%q", direct.last, proxy.last)
	}
}

// TestSetGetRefusesReject 单独把 REJECT 挡在出站选择之外。
// 未知策略回落到代理是既有决定，但拦截漏进那里等于黑名单反转，
// 症状又和正常转发一模一样，所以这一条要单独报错。
func TestSetGetRefusesReject(t *testing.T) {
	s := outbound.NewSet(outbound.NewDirect(0), nil)
	if _, err := s.Get(outbound.PolicyReject); err == nil {
		t.Fatal("REJECT 绝不能被解析成任何一个出站")
	}
}
