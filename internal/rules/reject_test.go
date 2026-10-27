package rules

import (
	"context"
	"strings"
	"testing"
)

// TestRejectPolicyAccepted 规则文件里写 REJECT 必须能解析。
//
// 不只是"多个新功能"：不认识的政策名会让整份文件加载失败，
// 而外部黑名单几乎一律用 REJECT，订阅进来就会把整个规则集搞挂。
func TestRejectPolicyAccepted(t *testing.T) {
	e := load(t, "DOMAIN-SUFFIX,ads.example.com,REJECT\nFINAL,PROXY", nil, nil)
	policy, matched := e.Match(context.Background(), "www.ads.example.com")
	if policy != PolicyReject {
		t.Fatalf("policy = %q, 期望 REJECT（命中 %s）", policy, matched)
	}
	if !strings.Contains(matched, "ads.example.com") {
		t.Errorf("命中依据里要能看出是哪条拦的: %s", matched)
	}
}

func TestRejectDropIsTheSameThing(t *testing.T) {
	e := load(t, "DOMAIN,track.example.net,REJECT-DROP\nFINAL,PROXY", nil, nil)
	if policy, _ := e.Match(context.Background(), "track.example.net"); policy != PolicyReject {
		t.Fatalf("REJECT-DROP 应归入同一个策略，实际 %q", policy)
	}
}

// TestUnknownPolicyStillFailsLoud 放开 REJECT 不等于放开一切拼错的策略名：
// 静默降级成直连等于黑名单上开了个后门。
func TestUnknownPolicyStillFailsLoud(t *testing.T) {
	_, err := Load(writeRules(t, "DOMAIN-SUFFIX,a.com,NUKE\nFINAL,PROXY"), nil, nil)
	if err == nil {
		t.Fatal("不认识的策略名必须报错")
	}
	for _, want := range []string{"NUKE", "REJECT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误里应同时出现实收到的名字和可选值，实际 %q", err)
		}
	}
}

// TestBlocklistPrecedesFileRules 配置段里的拦截必须排在规则文件前面。
//
// 匹配是「第一条命中即停」，插在后面就会被 `DOMAIN-SUFFIX,x,DIRECT` 这类
// 放行规则吃掉——用户加了黑名单却什么都没拦下，而且毫无提示。
func TestBlocklistPrecedesFileRules(t *testing.T) {
	e := load(t, "DOMAIN-SUFFIX,example.com,DIRECT\nFINAL,PROXY", nil, nil)
	e.SetBlocklist([]string{"example.com"})
	policy, matched := e.Match(context.Background(), "api.example.com")
	if policy != PolicyReject {
		t.Fatalf("拦截名单没压过文件里的 DIRECT: policy=%q matched=%s", policy, matched)
	}
}

func TestBlocklistCoversApexAndSubdomains(t *testing.T) {
	e := load(t, "DOMAIN-SUFFIX,keep.example,DIRECT\nFINAL,PROXY", nil, nil)
	e.SetBlocklist([]string{"ads.example.com"})
	for _, host := range []string{"ads.example.com", "x.ads.example.com", "ADS.Example.COM."} {
		if policy, matched := e.Match(context.Background(), host); policy != PolicyReject {
			t.Errorf("%s 应被拦下，实际 %q（%s）", host, policy, matched)
		}
	}
	// 点边界：notads.example.com 不是它的子域。
	if policy, _ := e.Match(context.Background(), "notads.example.com"); policy == PolicyReject {
		t.Error("把 notads.example.com 也拦了，后缀匹配没按点边界")
	}
}

// TestBlocklistDescSaysWhereItCameFrom 两处都能拦的时候，
// 日志必须说清是哪一侧拦的，否则用户会去翻那份几千行的规则文件。
func TestBlocklistDescSaysWhereItCameFrom(t *testing.T) {
	e := load(t, "DOMAIN-SUFFIX,keep.example,DIRECT\nFINAL,PROXY", nil, nil)
	e.SetBlocklist([]string{"ads.example.com"})
	_, matched := e.Match(context.Background(), "ads.example.com")
	if !strings.Contains(matched, "block") {
		t.Errorf("命中依据里应标出来自配置段: %s", matched)
	}
}

// TestSetBlocklistReplaces 重载时要整块替换。
// 追加的话，热重载几次名单就翻几倍，删掉的一项也永远删不掉。
func TestSetBlocklistReplaces(t *testing.T) {
	e := load(t, "DOMAIN-SUFFIX,keep.example,DIRECT\nFINAL,PROXY", nil, nil)
	e.SetBlocklist([]string{"a.com"})
	e.SetBlocklist([]string{"b.com"})
	if len(e.blockRules) != 1 {
		t.Fatalf("拦截规则堆成了 %d 条: %+v", len(e.blockRules), e.blockRules)
	}
	if policy, _ := e.Match(context.Background(), "a.com"); policy == PolicyReject {
		t.Error("旧名单还留着")
	}
	if policy, _ := e.Match(context.Background(), "b.com"); policy != PolicyReject {
		t.Errorf("新名单没生效: %q", policy)
	}

	e.SetBlocklist(nil)
	if policy, _ := e.Match(context.Background(), "b.com"); policy == PolicyReject {
		t.Error("清空后不该还在拦")
	}
}

func TestSetBlocklistNormalizesInput(t *testing.T) {
	e := load(t, "DOMAIN-SUFFIX,keep.example,DIRECT\nFINAL,PROXY", nil, nil)
	e.SetBlocklist([]string{"", "  ", "Ads.Example.com", "ads.example.com"})
	if len(e.blockRules) != 1 {
		t.Fatalf("空项与重复项没被去掉: %+v", e.blockRules)
	}
	if got := e.blockRules[0].value; got != "ads.example.com" {
		t.Errorf("域名没归一化成小写: %q", got)
	}
}
