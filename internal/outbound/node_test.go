// 固定节点（规则里的 node=）那批临时出站的缓存生命周期。
//
// Set 只有 direct/proxy 两只"公"出站，这一组多出来的都是按需造的：
// 造错一次是多一条隧道，漏关一次是泄漏一条，回落错一次是流量悄悄走了别的节点。
// 三种错都只在真实流量下才看得见，所以全部在这里钉住。
package outbound

import (
	"errors"
	"sync"
	"testing"
)

// stubConn 是带工厂返回值形状的那一类出站：Set 里存的是 Dialer，
// 而工厂必须交出一只 Conn（节点要能自报隧道状态）。
type stubConn struct {
	stubDialer
}

func (s *stubConn) Connected() bool { return true }
func (s *stubConn) Status() string  { return s.name }

func newPinSet(t *testing.T, known map[string]*stubConn, builds *int) (*Set, *stubConn) {
	t.Helper()
	active := &stubConn{stubDialer: stubDialer{name: "proxy-active"}}
	set := NewSet(&stubDialer{name: "direct"}, active).WithNode("MAIN").
		WithNodeFactory(func(name string) (Conn, error) {
			if builds != nil {
				*builds++
			}
			d, ok := known[name]
			if !ok {
				return nil, errors.New("没有这个节点: " + name)
			}
			return d, nil
		})
	return set, active
}

func TestGetNodeBuildsOncePerName(t *testing.T) {
	builds := 0
	us := &stubConn{stubDialer: stubDialer{name: "us"}}
	sg := &stubConn{stubDialer: stubDialer{name: "sg"}}
	set, active := newPinSet(t, map[string]*stubConn{"US-LA": us, "SG": sg}, &builds)

	d, err := set.GetNode("US-LA")
	if err != nil {
		t.Fatal(err)
	}
	if d != us {
		t.Errorf("拿到的不是那一只: %v", d.Name())
	}
	for range 5 {
		if _, err := set.GetNode("US-LA"); err != nil {
			t.Fatal(err)
		}
	}
	if builds != 1 {
		t.Errorf("同一个名字造了 %d 只，缓存没生效", builds)
	}
	if _, err := set.GetNode("SG"); err != nil {
		t.Fatal(err)
	}
	if builds != 2 {
		t.Errorf("第二个名字该另造一只，现在造了 %d 次", builds)
	}
	// 活动节点那只不该被这些临时出站牵动。
	if active.Closed() {
		t.Fatal("活动节点那只被关了")
	}
}

// TestGetNodeNeverFallsBackToTheActiveProxy 是这个文件存在的理由。
//
// 名字找不到时必须报错。回落到当前活动节点在代码里只有一行，
// 但它把"这条域名固定走 US-LA"变成"走此刻随便哪个节点"，
// 而界面上、日志里、字节数上都看不出区别——用户钉它正因为不想让它去别处。
func TestGetNodeNeverFallsBackToTheActiveProxy(t *testing.T) {
	builds := 0
	set, active := newPinSet(t, map[string]*stubConn{"SG": {stubDialer: stubDialer{name: "sg"}}}, &builds)

	d, err := set.GetNode("US-LA")
	if err == nil {
		t.Fatalf("找不到节点却返回了 %v", d.Name())
	}
	if d != nil {
		t.Error("报错的同时还给出了一只出站")
	}
	if active.Closed() {
		t.Error("活动节点不该因为一次失败的查找被关掉")
	}
	// 没有工厂的那只 Set 同样不许猜。
	plain := NewSet(&stubDialer{name: "direct"}, &stubConn{stubDialer: stubDialer{name: "proxy"}})
	if _, err := plain.GetNode("US-LA"); err == nil {
		t.Error("没装工厂的 Set 竟然答出了节点")
	}
	// 空名字是编程错误，不是"用默认"。
	if _, err := set.GetNode("  "); err == nil {
		t.Error("空的节点名被当成合法的默认值")
	}
}

// TestGetNodeReusesTheActiveProxyByName 钉的就是当前活动节点时复用那一只：
// 对同一台服务器开两条隧道，QUIC 的状态与心跳都白花。
func TestGetNodeReusesTheActiveProxyByName(t *testing.T) {
	builds := 0
	set, active := newPinSet(t, nil, &builds)
	d, err := set.GetNode("MAIN")
	if err != nil {
		t.Fatal(err)
	}
	if d != active {
		t.Errorf("没复用活动那只，得到了 %v", d.Name())
	}
	if builds != 0 {
		t.Errorf("复用的路径上工厂被调了 %d 次", builds)
	}
}

// TestSwapProxyDropsTheNewName 换成某个节点之后，同名的临时出站必须作废：
// 缓存里再留一只，就是同时开着两条到同一台服务器的隧道。
func TestSwapProxyDropsTheNewName(t *testing.T) {
	cached := &stubConn{stubDialer: stubDialer{name: "us-cached"}}
	builds := 0
	set, _ := newPinSet(t, map[string]*stubConn{"US-LA": cached}, &builds)
	if _, err := set.GetNode("US-LA"); err != nil {
		t.Fatal(err)
	}

	next := &stubConn{stubDialer: stubDialer{name: "proxy-us"}}
	old := set.SwapProxy(next, "US-LA")
	if old == nil {
		t.Fatal("SwapProxy 没把旧的交回去")
	}
	if !cached.Closed() {
		t.Error("切到 US-LA 之后，缓存里那只还在——同一名节点开了两条隧道")
	}
	// 之后再取同名，拿到的必须是新的活动那只。
	d, err := set.GetNode("US-LA")
	if err != nil {
		t.Fatal(err)
	}
	if d != next {
		t.Errorf("切完之后取到的是 %v", d.Name())
	}
}

func TestDropNodeAndCloseCoverTheCache(t *testing.T) {
	us := &stubConn{stubDialer: stubDialer{name: "us"}}
	sg := &stubConn{stubDialer: stubDialer{name: "sg"}}
	direct := &stubDialer{name: "direct"}
	proxy := &stubConn{stubDialer: stubDialer{name: "proxy"}}
	builds := 0
	set := NewSet(direct, proxy).WithNode("MAIN").
		WithNodeFactory(func(name string) (Conn, error) {
			builds++
			switch name {
			case "US-LA":
				return us, nil
			case "SG":
				return sg, nil
			}
			return nil, errors.New("没有这个节点: " + name)
		})
	for _, n := range []string{"US-LA", "SG"} {
		if _, err := set.GetNode(n); err != nil {
			t.Fatal(err)
		}
	}

	// 只丢一个：另一个还在，且没有被关掉。
	dropped := set.DropNode("US-LA")
	if len(dropped) != 1 || dropped[0] != us {
		t.Fatalf("丢出来的不对: %v", dropped)
	}
	if sg.Closed() {
		t.Error("丢 US-LA 把 SG 也关了")
	}
	if set.DropNode("没有这个名字") != nil {
		t.Error("丢一个不在缓存里的名字应当是空操作")
	}

	// 空名字 = 整张表，交回来的东西由调用方关闭（与 SwapProxy 同一套约定）。
	all := set.DropNode("")
	if len(all) != 1 || all[0] != sg {
		t.Fatalf("整张丢只该剩下 SG: %v", all)
	}
	if set.DropNode("") != nil {
		t.Error("空表再丢一次应当给空")
	}

	// Close 必须把缓存里的也算上：装配方只握着 Set，漏掉这张表就是每次停机留几条僵尸隧道。
	if _, err := set.GetNode("US-LA"); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	if !us.Closed() {
		t.Error("Close 没关缓存里的固定节点出站")
	}
	if !direct.Closed() || !proxy.Closed() {
		t.Error("Close 把 direct/proxy 漏了")
	}
}

// TestGetNodeConcurrentSingleFlight 两条连接同时钉到同一个还没造出来的节点时，
// 只允许一只活下来：另一只必须当场关掉，否则每来一批并发就漏一条隧道。
func TestGetNodeConcurrentSingleFlight(t *testing.T) {
	built := &stubConn{stubDialer: stubDialer{name: "us"}}
	loser := &stubConn{stubDialer: stubDialer{name: "us-loser"}}
	var mu sync.Mutex
	calls := 0
	set := NewSet(&stubDialer{name: "direct"}, &stubConn{stubDialer: stubDialer{name: "proxy"}}).
		WithNode("MAIN").
		WithNodeFactory(func(string) (Conn, error) {
			mu.Lock()
			calls++
			n := calls
			mu.Unlock()
			if n == 1 {
				return built, nil
			}
			return loser, nil
		})

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := set.GetNode("US-LA"); err != nil {
				t.Errorf("并发取节点失败: %v", err)
			}
		}()
	}
	wg.Wait()

	// 输掉那一轮必须被关掉（这是唯一会泄漏的路径）。
	// 不要求工厂只被调一次：两条同时进来时各自造一只，是允许的一次重复；
	// 不允许的是把重复的那只留在世上。
	if !loser.Closed() && calls > 1 {
		t.Errorf("工厂被调 %d 次，多造的那只没关掉", calls)
	}
}
