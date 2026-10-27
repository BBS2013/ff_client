package router

import (
	"testing"

	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

// TestEveryPolicyMapsToIntentionalOutbound 每个分流策略都必须被**明确决定**过方向。
//
// 这条用例的价值全在"新增策略时它会红"：往 rules.Policies() 里加一个值
// 而没在这里补一行，测试就失败——因为 toOutboundPolicy 会把没听过的策略
// 报错拒绝，而不是猜一个方向。猜的方向在界面上和正常工作长得一模一样。
func TestEveryPolicyMapsToIntentionalOutbound(t *testing.T) {
	want := map[rules.Policy]outbound.Policy{
		rules.PolicyDirect: outbound.PolicyDirect,
		rules.PolicyProxy:  outbound.PolicyProxy,
		rules.PolicyReject: outbound.PolicyReject,
	}
	for _, p := range rules.Policies() {
		got, err := toOutboundPolicy(p)
		if err != nil {
			t.Errorf("策略 %q 没有被接入出站选择: %v", p, err)
			continue
		}
		if exp, ok := want[p]; !ok {
			t.Errorf("策略 %q 出现在 rules.Policies() 里却不在本用例的期望表里——"+
				"新增策略时必须先想清楚它走哪个出站", p)
		} else if got != exp {
			t.Errorf("策略 %q 映射成 %q, 期望 %q", p, got, exp)
		}
	}
	// 反过来：期望表里也不能有已经消失的策略。
	for p := range want {
		found := false
		for _, known := range rules.Policies() {
			if known == p {
				found = true
			}
		}
		if !found {
			t.Errorf("期望表里的 %q 已不在 rules.Policies() 中，请一并清理", p)
		}
	}
}

// TestUnknownPolicyIsRefused 没听过的策略一律拒绝，不落到任何一个方向。
func TestUnknownPolicyIsRefused(t *testing.T) {
	for _, p := range []rules.Policy{"", "REJECT-DROP", "BLOCK", "proxy"} {
		got, err := toOutboundPolicy(p)
		if err == nil {
			t.Errorf("策略 %q 竟然被接受并映射成 %q；未接入的策略必须拒绝", p, got)
		}
		if got != "" {
			t.Errorf("策略 %q 报错却返回了方向 %q", p, got)
		}
	}
}
