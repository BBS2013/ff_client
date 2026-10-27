package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

// 这组测试盯的是直连出站改用自有解析器之后的几条底线。

// stubResolver 返回预设地址，并可记录自己有没有被调用。
type stubResolver struct {
	addrs   []netip.Addr
	err     error
	calls   int
	gotHost string
}

func (s *stubResolver) LookupIP(_ context.Context, host string) ([]netip.Addr, error) {
	s.calls++
	s.gotHost = host
	return s.addrs, s.err
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestDirectDialsResolvedAddress 判定与拨号必须看同一批地址。
func TestDirectDialsResolvedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())
	res := &stubResolver{addrs: []netip.Addr{mustAddr(t, "127.0.0.1")}}
	d := NewDirect(2 * time.Second).WithResolver(res)

	conn, err := d.DialContext(context.Background(), net.JoinHostPort("chosen.example", port))
	if err != nil {
		t.Fatalf("拨不通: %v", err)
	}
	defer conn.Close()
	if res.calls == 0 {
		t.Fatal("配了解析器却没用它，判定与拨号还是两套解析")
	}
	if res.gotHost != "chosen.example" {
		t.Fatalf("解析的域名不对: %q", res.gotHost)
	}
}

// TestDirectLiteralIPSkipsResolver 已经是 IP 就不该再问解析器。
func TestDirectLiteralIPSkipsResolver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	res := &stubResolver{err: errors.New("解析器坏了也不该影响字面 IP")}
	d := NewDirect(2 * time.Second).WithResolver(res)

	conn, err := d.DialContext(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("字面 IP 直连失败: %v", err)
	}
	_ = conn.Close()
	if res.calls != 0 {
		t.Fatalf("字面 IP 不该触发解析: calls=%d", res.calls)
	}
}

// TestDirectResolverFailureDegrades 自己的解析器坏了，不能把连接也判死。
// 退回系统解析器即可——这与 resolveServerHost 的降级方向一致。
func TestDirectResolverFailureDegrades(t *testing.T) {
	// localhost 由系统解析器一定能解出来。
	d := NewDirect(2 * time.Second).WithResolver(&stubResolver{err: errors.New("上游挂了")})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	conn, err := d.DialContext(context.Background(), net.JoinHostPort("localhost", portOf(ln.Addr().String())))
	if err != nil {
		t.Fatalf("解析器失败时应退回系统解析并连上: %v", err)
	}
	_ = conn.Close()
}

// TestDirectLoopGuardAppliesToResolvedIP 是这次改动新开的洞会不会被堵住的关键。
//
// checkLoop 原本只看字面 host，所以 evil.com 解析成 127.0.0.1 时按 host 判会整个漏掉，
// 于是「代理连了它自己」那条保护正好在新路径上失效。
func TestDirectLoopGuardAppliesToResolvedIP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	d := NewDirect(2*time.Second, ln.Addr().String()).
		WithResolver(&stubResolver{addrs: []netip.Addr{mustAddr(t, "127.0.0.1")}})

	// 目标 host 是个无辜的域名，端口却是自己的监听端口，且解析结果是回环地址。
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_, err = d.DialContext(context.Background(), net.JoinHostPort("evil.example", port))
	if !errors.Is(err, loopErr) {
		t.Fatalf("解析出回环地址后应当仍然拒绝，got: %v", err)
	}
}

// TestDirectTriesEveryAddress net.Dialer 拿到域名时本来会把多个候选都试一遍，
// 自己预解析就必须把这个能力补回来，否则多宿主域名会从"有一个通就通"
// 退化成"第一个不通就全不通"。
//
// 解析器只返回地址、不返回端口，所以两个候选必须共用一个端口：
// 监听在 127.0.0.1，而 127.0.0.2 上是同一个端口位、没人应答，必然先失败。
func TestDirectTriesEveryAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	d := NewDirect(1500 * time.Millisecond).WithResolver(&stubResolver{addrs: []netip.Addr{
		mustAddr(t, "127.0.0.2"), // 先试这个：同端口位上没有监听
		mustAddr(t, "127.0.0.1"), // 再试这个：真监听
	}})
	conn, err := d.DialContext(context.Background(), net.JoinHostPort("multi.example", portOf(ln.Addr().String())))
	if err != nil {
		t.Fatalf("第一个地址失败后应当继续试下一个，got: %v", err)
	}
	_ = conn.Close()
}

// cancelOnAnswer 在交出解析答案的那一刻取消 ctx。
// 这样"取消发生在什么时候"完全由代码决定，不再依赖网络状况。
type cancelOnAnswer struct {
	addrs  []netip.Addr
	cancel context.CancelFunc
}

func (c *cancelOnAnswer) LookupIP(_ context.Context, _ string) ([]netip.Addr, error) {
	c.cancel()
	return c.addrs, nil
}

// TestDirectCancelWinsOverRetryExhaustion 钉住 DialContext 里「取消之后不再试下一个地址」那一段。
//
// 这条以前是靠拨一个"假定不可路由"的地址（203.0.113.1）制造挂起，断网环境里当场就废了：
// 内核立刻回 network unreachable，err 非空、耗时极短，测试照绿，可取消逻辑一次都没走到
// （把它放到只有回环的网络命名空间里跑，红的就是它）。
//
// 换成回环上的两个地址（.2 没人听、.1 真监听）之后，两种实现唯一区分得开的观察量是**错误是谁**：
// 有那段检查时返回的就是 ctx 的取消错误本身；没有它，循环会把两个地址都试完，
// 交出的是「N 个地址都没拨通: …」那个包装。用错误文本断言不漂亮，但这里它才是真的能区分的一端——
// `errors.Is(err, context.Canceled)` 区分不了：两种写法的错误链里都裹着同一个 sentinel，
// 这条最初就是那样假绿的（把那段检查删掉跑一遍，它照样过）。
func TestDirectCancelWinsOverRetryExhaustion(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := NewDirect(10 * time.Second).WithResolver(&cancelOnAnswer{
		// 第一个地址没人听（同端口的 .2 上没绑），第二个才是真监听。
		addrs:  []netip.Addr{mustAddr(t, "127.0.0.2"), mustAddr(t, "127.0.0.1")},
		cancel: cancel,
	})

	conn, err := d.DialContext(ctx, net.JoinHostPort("cancel.example", portOf(ln.Addr().String())))
	if conn != nil {
		t.Fatal("ctx 都取消了还连上了")
	}
	if err == nil {
		t.Fatal("期望失败")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("应回 ctx 的取消错误，实得 %v (%T)", err, err)
	}
	if msg := err.Error(); strings.Contains(msg, "都没拨通") {
		t.Fatalf("取消被报成「所有地址都不通」，说明重试没在取消时收手: %s", msg)
	}
}

// portOf 从 "127.0.0.1:8080" 取端口串。
func portOf(addr string) string {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "0"
	}
	return p
}

// freePort 占一个端口再立刻放开，作为「这个端口位上没人应答」的确定性来源。
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := portOf(ln.Addr().String())
	_ = ln.Close()
	return p
}

// TestDirectNamesFirstAddressError 多地址全失败时，错误里必须留着**第一个**地址的错误。
//
// 以前只带 lastErr，而 preferV4 把 v6 排在最后，于是线上那 55 条「直连拨不通」
// 能看见的永远是最后一个地址；两个实现唯一区分得开的观察量就是首因在不在文本里。
func TestDirectNamesFirstAddressError(t *testing.T) {
	d := NewDirect(2 * time.Second).WithResolver(&stubResolver{addrs: []netip.Addr{
		mustAddr(t, "127.0.0.2"),
		mustAddr(t, "127.0.0.3"),
	}})
	_, err := d.DialContext(context.Background(), net.JoinHostPort("alldead.example", freePort(t)))
	if err == nil {
		t.Fatal("两个都没有监听的位置竟然拨通了")
	}
	msg := err.Error()
	if !strings.Contains(msg, "127.0.0.2") {
		t.Fatalf("错误里没留首因，只报了最后一个地址: %s", msg)
	}
	if !strings.Contains(msg, "127.0.0.3") {
		t.Fatalf("错误里连最后一个地址都没有: %s", msg)
	}
	if !strings.Contains(msg, "2 个地址都没拨通") {
		t.Fatalf("没交代一共试了几个地址: %s", msg)
	}
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("聚合之后 errors.Is 仍要能判出连接被拒: %v", err)
	}
}

// TestDirectCancelKeepsHostAndFirstCause 预算在重试中途用尽时，交出去的不该是一句裸的
// context deadline exceeded——线上正是这一句让 55 条直连失败查无原因。
//
// 与 TestDirectCancelWinsOverRetryExhaustion 共用同一个"由代码决定取消时机"的机关，
// 但那边断的是「别把取消报成全都不通」，这边断的是「取消也要把域名、进度、首因带上」。
func TestDirectCancelKeepsHostAndFirstCause(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := NewDirect(10 * time.Second).WithResolver(&cancelOnAnswer{
		// .2 没人听（先失败），.1 是真监听——走到取消检查时只可能拨过 .2。
		addrs:  []netip.Addr{mustAddr(t, "127.0.0.2"), mustAddr(t, "127.0.0.1")},
		cancel: cancel,
	})

	_, err = d.DialContext(ctx, net.JoinHostPort("cancel.example", portOf(ln.Addr().String())))
	if err == nil {
		t.Fatal("期望失败")
	}
	msg := err.Error()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("错误链里必须还能判出取消: %v", err)
	}
	for _, want := range []string{"cancel.example", "127.0.0.2", "只拨到第 1 个"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("取消时把 %q 丢了: %s", want, msg)
		}
	}
}
