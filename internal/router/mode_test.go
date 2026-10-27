package router

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

// spyDialer 记录自己被要求拨的地址，连接本身用 net.Pipe 造，不碰真实网络。
type spyDialer struct {
	name string
	last string
}

func (d *spyDialer) Name() string { return d.name }

func (d *spyDialer) DialContext(_ context.Context, addr string) (net.Conn, error) {
	d.last = addr
	// 这些用例只验证「选了哪个出站、拨的哪个地址」，不搬运数据，
	// 所以造一对立刻关掉一侧的 pipe 就够了。
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func (d *spyDialer) Close() error { return nil }

func newTestRouter(t *testing.T, body string, m config.Mode) (*Router, *spyDialer, *spyDialer) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(path, nil, nil)
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	direct := &spyDialer{name: "DIRECT"}
	proxy := &spyDialer{name: "PROXY"}
	rt := New(eng, outbound.NewSet(direct, proxy), 2*time.Second)
	rt.SetMode(m)
	return rt, direct, proxy
}

const ruleBook = "DOMAIN-SUFFIX,example.com,PROXY\nDOMAIN-SUFFIX,cn,DIRECT\nFINAL,DIRECT\n"

// TestModeOverridesRules 是整个模式功能的骨架：
// 全局压过规则、直连压过规则、rule 模式回到规则本身。
func TestModeOverridesRules(t *testing.T) {
	for _, c := range []struct {
		mode       config.Mode
		wantPolicy rules.Policy
		wantOut    string
		wantMatch  string
		wantAddr   string
	}{
		{config.ModeRule, rules.PolicyProxy, "PROXY", "DOMAIN-SUFFIX,example.com,PROXY", "www.example.com:443"},
		{config.ModeGlobal, rules.PolicyProxy, "PROXY", "MODE,GLOBAL", "www.example.com:443"},
		{config.ModeDirect, rules.PolicyDirect, "DIRECT", "MODE,DIRECT", "www.example.com:443"},
	} {
		rt, direct, proxy := newTestRouter(t, ruleBook, c.mode)
		conn, res, err := rt.Dial(context.Background(), "www.example.com:443")
		if err != nil {
			t.Fatalf("%s 模式拨号失败: %v", c.mode, err)
		}
		_ = conn.Close()
		if string(res.Policy) != string(c.wantPolicy) || res.Outbound != c.wantOut {
			t.Errorf("%s: policy=%s outbound=%s, 期望 %s/%s", c.mode, res.Policy, res.Outbound, c.wantPolicy, c.wantOut)
		}
		if res.Matched != c.wantMatch {
			t.Errorf("%s: matched=%q, 期望 %q", c.mode, res.Matched, c.wantMatch)
		}
		used := proxy
		if c.wantOut == "DIRECT" {
			used = direct
		}
		if used.last != c.wantAddr {
			t.Errorf("%s: 实际拨了 %q, 期望 %q", c.mode, used.last, c.wantAddr)
		}
		// 另一个出站不该被碰。
		other := direct
		if c.wantOut == "DIRECT" {
			other = proxy
		}
		if other.last != "" {
			t.Errorf("%s: 未被选中的出站 %s 也拨了 %q", c.mode, other.name, other.last)
		}
	}
}

// TestRuleModeDomainNeedsNoDNS 确认规则模式的老性质还在：
// 命中域名规则就直接出结果，不会因为要判 IP 归属而去发起 DNS（这里 resolver 传的就是 nil）。
func TestRuleModeDomainNeedsNoDNS(t *testing.T) {
	rt, direct, proxy := newTestRouter(t, ruleBook, config.ModeRule)
	if _, _, err := rt.Dial(context.Background(), "www.example.com:443"); err != nil {
		t.Fatal(err)
	}
	if proxy.last != "www.example.com:443" || direct.last != "" {
		t.Errorf("域名规则没生效: proxy=%q direct=%q", proxy.last, direct.last)
	}
}

func TestSetModeIgnoresInvalid(t *testing.T) {
	rt, _, _ := newTestRouter(t, ruleBook, config.ModeRule)
	rt.SetMode(config.Mode("bogus"))
	if rt.Mode() != config.ModeRule {
		t.Fatalf("非法模式不该改状态，实际 %q", rt.Mode())
	}
	rt.SetMode(config.ModeGlobal)
	if rt.Mode() != config.ModeGlobal {
		t.Fatalf("SetMode 没生效: %q", rt.Mode())
	}
}

// TestDialHostHint 是 TUN 模式的关键语义：
// 报文里只有 IP，但决策必须按域名来；拨号目标却要保持 IP 原样，
// 由 hint 决定走哪个出站。
func TestDialHostHint(t *testing.T) {
	rt, direct, proxy := newTestRouter(t, ruleBook, config.ModeRule)

	conn, res, err := rt.DialHost(context.Background(), "198.18.0.7:443", "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if res.Outbound != "PROXY" {
		t.Errorf("hint 没参与决策: outbound=%s matched=%s", res.Outbound, res.Matched)
	}
	if !strings.Contains(res.Matched, "via a.example.com") {
		t.Errorf("命中依据里该带上 hint 方便排查: %q", res.Matched)
	}
	if proxy.last != "198.18.0.7:443" {
		t.Errorf("拨号目标被换成域名了: %q", proxy.last)
	}
	if direct.last != "" {
		t.Errorf("不该碰直连: %q", direct.last)
	}

	// 没有 hint 的字面 IP 走 IP 规则，最终落到 FINAL=DIRECT。
	rt2, direct2, proxy2 := newTestRouter(t, ruleBook, config.ModeRule)
	conn2, res2, err := rt2.DialHost(context.Background(), "198.18.0.7:443", "")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn2.Close()
	if res2.Outbound != "DIRECT" || direct2.last != "198.18.0.7:443" || proxy2.last != "" {
		t.Errorf("无 hint 时决策=%+v direct=%q proxy=%q", res2, direct2.last, proxy2.last)
	}
}

// TestDecideMatchesDial 保证 DNS 阶段用的决策与实际拨号是同一套逻辑，
// 否则假 IP 发出去、连接却走了另一条路，是最难复现的错位。
func TestDecideMatchesDial(t *testing.T) {
	rt, _, _ := newTestRouter(t, ruleBook, config.ModeRule)
	for _, host := range []string{"www.example.com", "a.cn", "something.test"} {
		policy, matched := rt.Decide(context.Background(), host)
		conn, res, err := rt.Dial(context.Background(), host+":443")
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		_ = conn.Close()
		if string(policy) != string(res.Policy) || matched != res.Matched {
			t.Errorf("%s: Decide=(%s,%s) 与 Dial=(%s,%s) 不一致", host, policy, matched, res.Policy, res.Matched)
		}
	}
}

// TestRouterSwapProxyGuardsNil 换出站的两条底线：nil 必须被拒（换上去了，
// 之后每条 PROXY 连接都会拿着一只 nil dialer，故障点离原因极远），
// 以及旧的那只要原样交回调用方去关。
func TestRouterSwapProxyGuardsNil(t *testing.T) {
	rt, _, proxy := newTestRouter(t, ruleBook, config.ModeRule)
	if _, err := rt.SwapProxy(nil, "x"); err == nil {
		t.Fatal("nil 出站应被拒绝")
	}
	old, err := rt.SwapProxy(&spyDialer{name: "PROXY-2"}, "node-2")
	if err != nil {
		t.Fatalf("正常替换应成功: %v", err)
	}
	if old != outbound.Dialer(proxy) {
		t.Fatal("没把旧出站交回调用方")
	}
	conn, res, err := rt.Dial(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("拨号应成功（spyDialer 用 pipe 造连接）: %v", err)
	}
	defer conn.Close()
	if res.Outbound != "PROXY-2" {
		t.Fatalf("新连接取到的还是旧出站: %q", res.Outbound)
	}
}
