// 规则把流量钉到某个节点（node=）这一条路的判据。
//
// 这里最要紧的一条不是"钉对了走谁"，而是"钉错了必须失败"：
// 名字找不到时如果回落到当前活动节点，界面上看是"这条域名固定走 US-LA"，
// 实际字节从别的节点出去了——用户钉它正因为不想让它去别处。
// 那种失效与正常工作长得一模一样，所以要用例钉住。
package router

import (
	"context"
	"errors"
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

const pinBook = "DOMAIN-SUFFIX,pinned.test,PROXY,node=US-LA\n" +
	"DOMAIN-SUFFIX,plain.test,PROXY\n" +
	"IP-CIDR,10.9.0.0/16,PROXY,node=SG,no-resolve\n" +
	"FINAL,DIRECT\n"

// pinDialer 记两件事：拨过的地址，以及有没有被关掉。
// 后者是缓存生命周期唯一可见的证据——共享的那只 spyDialer 不报这件事。
type pinDialer struct {
	name    string
	last    string
	dropped bool
}

func (d *pinDialer) Name() string { return d.name }

func (d *pinDialer) DialContext(_ context.Context, addr string) (net.Conn, error) {
	d.last = addr
	a, b := net.Pipe()
	_ = b.Close()
	return a, nil
}

func (d *pinDialer) Close() error {
	d.dropped = true
	return nil
}

// 工厂的返回类型是 outbound.Conn（不是 Dialer）：节点要能自报"隧道建起来没有"。
// 这里只走选路，不测隧道状态，所以两句话固定回答即可。
func (d *pinDialer) Connected() bool { return true }

func (d *pinDialer) Status() string { return d.name }

func loadBook(t *testing.T, body string) *rules.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(path, nil, nil)
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	return eng
}

// newPinRouter 装一台带节点工厂的路由器。builds 数的是工厂被调用几次，
// 那正是"懒建 + 缓存"唯一的观察口。
func newPinRouter(t *testing.T, body string, known map[string]*pinDialer, builds *int) (*Router, *pinDialer) {
	t.Helper()
	active := &pinDialer{name: "PROXY-ACTIVE"}
	set := outbound.NewSet(&pinDialer{name: "DIRECT"}, active).WithNode("JP-MAIN").
		WithNodeFactory(func(name string) (outbound.Conn, error) {
			if builds != nil {
				*builds++
			}
			d, ok := known[name]
			if !ok {
				return nil, errors.New("配置里没有这个节点: " + name)
			}
			return d, nil
		})
	rt := New(loadBook(t, body), set, time.Second)
	rt.SetMode(config.ModeRule)
	return rt, active
}

func TestRulePinsTheNode(t *testing.T) {
	builds := 0
	us := &pinDialer{name: "PROXY-US-LA"}
	sg := &pinDialer{name: "PROXY-SG"}
	known := map[string]*pinDialer{"US-LA": us, "SG": sg}
	rt, active := newPinRouter(t, pinBook, known, &builds)

	res := mustResult(t, rt, "a.pinned.test")
	if res.Node != "US-LA" {
		t.Errorf("字节记到了 %q 名下，想要 US-LA", res.Node)
	}
	if us.last == "" {
		t.Error("钉了 US-LA 却没从那只出站拨")
	}
	if active.last != "" {
		t.Error("活动节点被拿来代劳了：固定节点不许回落")
	}
	// 命中依据里要能看出钉了谁：日志与连接表只有这一处说法。
	if !strings.Contains(res.Matched, "node=US-LA") {
		t.Errorf("命中依据里没有节点名: %q", res.Matched)
	}

	// 没钉的那条照旧走活动节点，且不该顺手造一只新的。
	res = mustResult(t, rt, "a.plain.test")
	if res.Node != "JP-MAIN" || active.last == "" {
		t.Errorf("普通 PROXY 规则被改坏了: %+v", res)
	}
	if builds != 1 {
		t.Errorf("只该为 US-LA 造一只，造了 %d 次", builds)
	}

	// IP 规则同样能钉（这条还带 no-resolve，多了字段也不许去解析）。
	// 工厂在这里被第二次调用是对的：SG 是第二个名字，缓存按名字分格。
	res = mustResult(t, rt, "10.9.1.7")
	if res.Node != "SG" || sg.last == "" {
		t.Errorf("IP 规则没钉上节点: %+v", res)
	}
	if builds != 2 {
		t.Fatalf("US-LA 与 SG 各该造一只，现在工厂被调了 %d 次", builds)
	}

	// 同名的第二条连接必须复用缓存，不再造一只。
	mustResult(t, rt, "b.pinned.test")
	if builds != 2 {
		t.Errorf("同一个节点造了 %d 次，缓存没生效", builds)
	}
}

// TestUnknownPinnedNodeFailsClosed 是这一组里最该常驻的一条。
func TestUnknownPinnedNodeFailsClosed(t *testing.T) {
	rt, active := newPinRouter(t, pinBook, map[string]*pinDialer{"SG": {name: "PROXY-SG"}}, nil)

	_, _, err := rt.Dial(context.Background(), "a.pinned.test:443")
	if err == nil {
		t.Fatal("钉了一个配置里没有的节点，连接却成功了")
	}
	if !strings.Contains(err.Error(), "US-LA") {
		t.Errorf("错误里没说清是哪个节点找不到: %v", err)
	}
	// 更要紧的：一条字节都没从活动节点出去。
	if active.last != "" {
		t.Errorf("失败回落到了活动节点，拨的是 %q", active.last)
	}
}

// TestPinnedNodeReusesTheActiveDialer 钉的正好是当前活动节点时不该另造一只：
// 对同一台服务器开两条隧道，QUIC 那份状态与心跳都是白花的。
func TestPinnedNodeReusesTheActiveDialer(t *testing.T) {
	active := &pinDialer{name: "PROXY-ACTIVE"}
	builds := 0
	set := outbound.NewSet(&pinDialer{name: "DIRECT"}, active).WithNode("JP-MAIN").
		WithNodeFactory(func(string) (outbound.Conn, error) {
			builds++
			return &pinDialer{name: "第二只"}, nil
		})
	rt := New(loadBook(t, "DOMAIN-SUFFIX,home.test,PROXY,node=JP-MAIN\nFINAL,DIRECT\n"), set, time.Second)

	res := mustResult(t, rt, "a.home.test")
	if builds != 0 {
		t.Errorf("钉的就是活动节点，却还是造了 %d 只新的", builds)
	}
	if res.Node != "JP-MAIN" || active.last == "" {
		t.Errorf("没复用活动那只: %+v", res)
	}
}

// TestModesOverrideThePin 全局/直连模式整体压过规则集，钉的节点名也不该带出来：
// 否则界面上会出现"直连模式，但这条走 US-LA"这种自相矛盾的话。
func TestModesOverrideThePin(t *testing.T) {
	known := map[string]*pinDialer{"US-LA": {name: "PROXY-US-LA"}, "SG": {name: "PROXY-SG"}}
	rt, active := newPinRouter(t, pinBook, known, nil)

	rt.SetMode(config.ModeDirect)
	if res := mustResult(t, rt, "a.pinned.test"); res.Node != "DIRECT" {
		t.Errorf("直连模式还报节点 %q", res.Node)
	}
	rt.SetMode(config.ModeGlobal)
	res := mustResult(t, rt, "a.pinned.test")
	if res.Node != "JP-MAIN" || active.last == "" {
		t.Errorf("全局模式该整体走活动节点: %+v", res)
	}
	for _, d := range known {
		if d.last != "" {
			t.Errorf("模式压过规则时还拨了钉住的节点 %s", d.name)
		}
	}
}

// TestDropPinnedNodes 配置一改就要能把临时出站整张丢掉，
// 否则缓存里那只还在用旧的 addr/口令拨号——症状是"改了节点参数却像没生效"。
func TestDropPinnedNodes(t *testing.T) {
	first := &pinDialer{name: "PROXY-US-LA-1"}
	known := map[string]*pinDialer{"US-LA": first}
	builds := 0
	rt, _ := newPinRouter(t, pinBook, known, &builds)

	mustResult(t, rt, "a.pinned.test")
	if first.last == "" || builds != 1 {
		t.Fatalf("第一条没落在第一只上: last=%q builds=%d", first.last, builds)
	}
	// 缓存生效：第二条不再造。
	mustResult(t, rt, "b.pinned.test")
	if builds != 1 {
		t.Fatalf("同一个节点造了 %d 只", builds)
	}

	rt.DropPinnedNodes()
	if !first.dropped {
		t.Fatal("DropPinnedNodes 没把缓存那只关掉")
	}

	// 丢完再来一条必须重新走工厂——这是"改了节点参数之后拿到的是新那只"的唯一保证。
	second := &pinDialer{name: "PROXY-US-LA-2"}
	known["US-LA"] = second
	mustResult(t, rt, "c.pinned.test")
	if builds != 2 {
		t.Errorf("丢了缓存却没重造（工厂被调 %d 次）", builds)
	}
	if second.last == "" {
		t.Error("重造出来的那只没被用上")
	}
	// 再丢一次、丢到空：不能报错，也不能把活动节点那只一起关掉。
	rt.DropPinnedNodes()
	rt.DropPinnedNodes()
	if !second.dropped {
		t.Error("第二次丢没关掉重造的那只")
	}
}

// TestDropPinnedNodesWhenNothingPinned 没钉过任何节点时这条路径必须是空操作：
// 停机与改配置都会调它，第一次调用就 panic 的话，故障只会在用户改节点时现形。
func TestDropPinnedNodesWhenNothingPinned(t *testing.T) {
	rt, _ := newPinRouter(t, "DOMAIN-SUFFIX,plain.test,PROXY\nFINAL,DIRECT\n", nil, nil)
	mustResult(t, rt, "a.plain.test")
	rt.DropPinnedNodes()
}
