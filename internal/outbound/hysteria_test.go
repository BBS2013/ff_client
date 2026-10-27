package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/quic-go"

	"wps_app/internal/config"
)

// fakeClient 是 client.Client 的最小实现，用来观察共享连接是否被 invalidate。
type fakeClient struct {
	closed  atomic.Int32
	calls   atomic.Int32
	dialErr error
}

func (f *fakeClient) TCP(addr string) (net.Conn, error) {
	f.calls.Add(1)
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	return &scriptedConn{}, nil
}

func (f *fakeClient) UDP() (client.HyUDPConn, error) {
	return nil, errors.New("udp not supported in test")
}

func (f *fakeClient) Close() error { f.closed.Add(1); return nil }

// scriptedConn 按预设脚本返回错误的 net.Conn。
type scriptedConn struct {
	readErr  error
	writeErr error

	mu     sync.Mutex
	closed int
}

func (c *scriptedConn) Read(b []byte) (int, error) { return 0, c.readErr }
func (c *scriptedConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(b), nil
}

func (c *scriptedConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	return nil
}

func (c *scriptedConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *scriptedConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero, Port: 1} }
func (c *scriptedConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4zero, Port: 2} }
func (c *scriptedConn) SetDeadline(t time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(t time.Time) error { return nil }

// attached 出站已挂上一个共享客户端，cli 为当前连接（nil 表示尚未连接）。
func attached(cli client.Client) *Hysteria {
	h := &Hysteria{handshakeTO: time.Second}
	h.cli = cli
	return h
}

// newTestServerConfig 造一份除地址外都合法的服务端配置，便于单测只改一个变量。
func newTestServerConfig(addr string) config.ServerConfig {
	return config.ServerConfig{
		Addr:       addr,
		Auth:       "unit-test",
		TLS:        config.TLSConfig{SNI: "example.com"},
		Bandwidth:  config.BandwidthConfig{Up: "1 mbps", Down: "1 mbps"},
		Congestion: "bbr",
	}
}

func mustUDPAddr(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("ResolveUDPAddr(%q): %v", addr, err)
	}
	return a
}

// 分级只看真实错误类型：只有连接级错误才值得换隧道，流级与目标级错误留在产生它的那条连接上。
// 这里把 quic-go 与 hysteria 会报的每一类错误逐个钉住，因为「要不要拆共享连接」
// 是全进程吞吐量的开关：判错方向的代价要等到用户的下载被掐断才看得见，
// 而那时候日志里只剩一句已经查不回去的 debug。
func TestIsConnectionFatalClassification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"对端正常关流", io.EOF, false},
		{"包装过的 EOF", fmt.Errorf("read: %w", io.EOF), false},
		{"本地已关闭", net.ErrClosed, false},
		{"本地管道关闭", io.ErrClosedPipe, false},
		{"对端重置这条流", &quic.StreamError{StreamID: 4, ErrorCode: 1, Remote: true}, false},
		{"本地取消这条流", &quic.StreamError{StreamID: 4, Remote: false}, false},
		{"服务端拨不通目标", coreErrs.DialError{Message: "connection refused"}, false},
		{"自己设的读超时", os.ErrDeadlineExceeded, false},
		{"调用方取消", context.DeadlineExceeded, false},
		{"流数达到上限", quic.StreamLimitReachedError{}, false},
		{"看不出名目的错误", errors.New("boom"), false},
		{"空闲超时", &quic.IdleTimeoutError{}, true},
		{"握手超时", &quic.HandshakeTimeoutError{}, true},
		{"无状态重置", &quic.StatelessResetError{}, true},
		{"传输错误", &quic.TransportError{ErrorCode: quic.InternalError, Remote: true}, true},
		{"应用错误", &quic.ApplicationError{ErrorCode: 0x101, Remote: true}, true},
		{"版本协商失败", &quic.VersionNegotiationError{}, true},
		{"隧道被关闭", coreErrs.ClosedError{Err: errors.New("connection closed")}, true},
		{"连不上服务端", coreErrs.ConnectError{Err: errors.New("handshake failed")}, true},
		{"协议不对", coreErrs.ProtocolError{Message: "bad frame"}, true},
		{"包装过的空闲超时", fmt.Errorf("read stream: %w", &quic.IdleTimeoutError{}), true},
		{"包装过的隧道关闭", fmt.Errorf("write: %w", coreErrs.ClosedError{}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isConnectionFatal(tc.err); got != tc.want {
				t.Fatalf("isConnectionFatal(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// DialError 单独有一个判据：它既不该拆隧道，也不该重试三轮（换隧道不会让目标变通）。
func TestIsTargetRefusedCoversOnlyDialError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"服务端拒绝拨号", coreErrs.DialError{Message: "no route to host"}, true},
		{"包装过的拒绝", fmt.Errorf("tcp stream to x: %w", coreErrs.DialError{Message: "refused"}), true},
		{"空闲超时不是拒绝", &quic.IdleTimeoutError{}, false},
		{"流被重置不是拒绝", &quic.StreamError{StreamID: 9, Remote: true}, false},
		{"EOF 不是拒绝", io.EOF, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTargetRefused(tc.err); got != tc.want {
				t.Fatalf("isTargetRefused(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// 对端把这一条流重置了（浏览器自己关掉的连接、被墙的目标都会走到这里），
// 隧道上别人的连接必须照常活着。
func TestTrackedConnStreamLevelErrorKeepsTunnel(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"对端重置流", &quic.StreamError{StreamID: 4, ErrorCode: 1, Remote: true}},
		{"fast_open 下目标连不通", coreErrs.DialError{Message: "connection refused"}},
		{"本地设的读超时", os.ErrDeadlineExceeded},
		{"本地取消流", &quic.StreamError{StreamID: 4, Remote: false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli := &fakeClient{}
			h := attached(cli)
			tc2 := &trackedConn{Conn: &scriptedConn{readErr: tc.err, writeErr: tc.err}, h: h, gen: cli}

			if _, err := tc2.Read(make([]byte, 8)); !errors.Is(err, tc.err) {
				t.Fatalf("Read err = %v, want %v", err, tc.err)
			}
			if _, err := tc2.Write([]byte("x")); !errors.Is(err, tc.err) {
				t.Fatalf("Write err = %v, want %v", err, tc.err)
			}
			if h.cli != cli {
				t.Fatalf("流级错误 %v 不该让共享连接失效", tc.err)
			}
			if n := cli.closed.Load(); n != 0 {
				t.Fatalf("共享客户端被关闭 %d 次，流级错误应 0 次", n)
			}
		})
	}
}

// 连接级错误必须如实反映为隧道故障：漏判会让一条死隧道一直挂着，
// 之后每个请求都失败却永远不重连。
func TestTrackedConnConnectionErrorInvalidates(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"空闲超时", &quic.IdleTimeoutError{}},
		{"无状态重置", &quic.StatelessResetError{}},
		{"传输错误", &quic.TransportError{ErrorCode: quic.InternalError, Remote: true}},
		{"隧道已关闭", coreErrs.ClosedError{Err: errors.New("connection closed")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cli := &fakeClient{}
			h := attached(cli)
			tc2 := &trackedConn{Conn: &scriptedConn{readErr: tc.err}, h: h, gen: cli}

			if _, err := tc2.Read(make([]byte, 8)); err == nil {
				t.Fatal("Read 应返回底层错误")
			}
			if h.cli != nil {
				t.Fatal("连接级错误应丢弃共享连接")
			}
			if n := cli.closed.Load(); n != 1 {
				t.Fatalf("共享客户端被关闭 %d 次, want 1", n)
			}
		})
	}
}

func TestTrackedConnWriteConnectionErrorInvalidates(t *testing.T) {
	cli := &fakeClient{}
	h := attached(cli)
	tc2 := &trackedConn{
		Conn: &scriptedConn{writeErr: &quic.TransportError{ErrorCode: quic.InternalError}},
		h:    h,
		gen:  cli,
	}

	if _, err := tc2.Write([]byte("x")); err == nil {
		t.Fatal("Write 应返回底层错误")
	}
	if h.cli != nil {
		t.Fatal("连接级写错误应调用 invalidateCurrent 丢弃共享连接")
	}
}

func TestTrackedConnReportsFatalOnlyOnce(t *testing.T) {
	cli := &fakeClient{}
	h := attached(cli)
	tc2 := &trackedConn{Conn: &scriptedConn{readErr: &quic.IdleTimeoutError{}}, h: h, gen: cli}

	for i := 0; i < 3; i++ {
		_, _ = tc2.Read(make([]byte, 8))
	}
	if n := cli.closed.Load(); n != 1 {
		t.Fatalf("共享客户端被关闭 %d 次, want 1（一条流只报告一次）", n)
	}
}

// 隧道被换掉之后，挂在旧隧道上的流仍可能迟到地报出连接级错误。
// 这时绝不能动当前这条新连接，否则一次故障就滚成持续重连：
// 每次重连又打断一批正在传的连接。这正是浏览器下载被反复掐断的成因。
func TestLateFatalErrorFromOldGenerationKeepsNewTunnel(t *testing.T) {
	old := &fakeClient{}
	h := attached(old)
	fresh := &fakeClient{}
	// 模拟另一次拨号已经握手出新隧道。
	h.cli = fresh

	late := &trackedConn{Conn: &scriptedConn{readErr: &quic.IdleTimeoutError{}}, h: h, gen: old}
	if _, err := late.Read(make([]byte, 8)); err == nil {
		t.Fatal("Read 应返回底层错误")
	}
	if h.cli != fresh {
		t.Fatal("旧隧道上迟到的错误不应让当前连接失效")
	}
	if n := fresh.closed.Load(); n != 0 {
		t.Fatalf("当前连接被关闭 %d 次, want 0", n)
	}
}

// 本地关闭这条流（浏览器放弃请求）之后 quic-go 报的取消错误不是隧道故障。
func TestTrackedConnLocalCloseDoesNotInvalidate(t *testing.T) {
	cli := &fakeClient{}
	h := attached(cli)
	raw := &scriptedConn{readErr: &quic.StreamError{StreamID: 4, Remote: false}}
	tc2 := &trackedConn{Conn: raw, h: h, gen: cli}

	if err := tc2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if raw.closeCount() != 1 {
		t.Fatalf("底层流 Close 次数 = %d, want 1", raw.closeCount())
	}
	if _, err := tc2.Read(make([]byte, 8)); err == nil {
		t.Fatal("Read 应返回底层错误")
	}
	if h.cli != cli {
		t.Fatal("本地关闭后的读错误不应让共享连接失效")
	}
	if n := cli.closed.Load(); n != 0 {
		t.Fatalf("共享客户端被关闭 %d 次, want 0", n)
	}
}

func TestTrackedConnEOFDoesNotInvalidate(t *testing.T) {
	cli := &fakeClient{}
	h := attached(cli)
	tc2 := &trackedConn{Conn: &scriptedConn{readErr: io.EOF}, h: h, gen: cli}

	if _, err := tc2.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	if h.cli != cli {
		t.Fatal("对端正常关流不应让共享连接失效")
	}
}

func TestTrackedConnCloseTwiceStillUnderlyingOnce(t *testing.T) {
	cli := &fakeClient{}
	h := attached(cli)
	raw := &scriptedConn{readErr: io.EOF}
	tc2 := &trackedConn{Conn: raw, h: h, gen: cli}

	if err := tc2.Close(); err != nil {
		t.Fatalf("第一次 Close: %v", err)
	}
	// 幂等性由底层流保证，这里只要求不触发 invalidate。
	if _, err := tc2.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read err = %v, want io.EOF", err)
	}
	if h.cli != cli {
		t.Fatal("关闭后不应让共享连接失效")
	}
}

// cancelOnCloseConn 忠实模拟 quic-go：流的读错误只能由本地取消引起，
// 因此 Read 会阻塞到 Close 被调用之后才返回 quic 风格的错误。
type cancelOnCloseConn struct {
	closeOnce sync.Once
	closed    chan struct{}
	readErr   error
}

func newCancelOnCloseConn(readErr error) *cancelOnCloseConn {
	return &cancelOnCloseConn{closed: make(chan struct{}), readErr: readErr}
}

func (c *cancelOnCloseConn) Read(b []byte) (int, error) {
	<-c.closed
	return 0, c.readErr
}

func (c *cancelOnCloseConn) Write(b []byte) (int, error) {
	<-c.closed
	return 0, c.readErr
}

func (c *cancelOnCloseConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *cancelOnCloseConn) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.IPv4zero, Port: 1} }
func (c *cancelOnCloseConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.IPv4zero, Port: 2} }
func (c *cancelOnCloseConn) SetDeadline(t time.Time) error      { return nil }
func (c *cancelOnCloseConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *cancelOnCloseConn) SetWriteDeadline(t time.Time) error { return nil }

// 关闭与挂起的读并发时不能出现数据竞争；本地取消引起的错误不是隧道故障，
// 所以两边都不该让共享连接失效。
func TestTrackedConnConcurrentCloseAndRead(t *testing.T) {
	cli := &fakeClient{}
	h := attached(cli)
	tc := &trackedConn{
		Conn: newCancelOnCloseConn(&quic.StreamError{StreamID: 4, Remote: false}),
		h:    h,
		gen:  cli,
	}

	var wg sync.WaitGroup
	readDone := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := tc.Read(make([]byte, 8))
			readDone <- err
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = tc.Close() }()
	wg.Wait()
	close(readDone)

	for err := range readDone {
		if err == nil {
			t.Fatal("Read 应返回 quic 取消错误")
		}
	}
	if n := cli.closed.Load(); n != 0 {
		t.Fatalf("本地取消引起的读错误不应失效共享连接，实际关闭 %d 次", n)
	}
	if h.cli != cli {
		t.Fatal("本地取消后共享连接应仍然可用")
	}
}

// 真实的隧道故障与 Close 同时到达时：失效与否取决于谁先拿到锁，
// 但代次校验保证最多失效一次（幂等）。
func TestTrackedConnFatalErrorRacingCloseIsIdempotent(t *testing.T) {
	for i := 0; i < 200; i++ {
		cli := &fakeClient{}
		h := attached(cli)
		tc := &trackedConn{Conn: &scriptedConn{readErr: &quic.IdleTimeoutError{}}, h: h, gen: cli}

		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _ = tc.Close() }()
		go func() { defer wg.Done(); close(start); _, _ = tc.Read(make([]byte, 8)) }()
		wg.Wait()

		if n := cli.closed.Load(); n > 1 {
			t.Fatalf("第 %d 轮：共享客户端被关闭 %d 次，最多应 1 次", i, n)
		}
	}
}

func TestBackoffForBoundsAndCap(t *testing.T) {
	// 失败次数 → 基准间隔（指数翻倍，30s 封顶后不再增长）。
	base := map[int]time.Duration{
		0: time.Second,
		1: time.Second,
		2: 2 * time.Second,
		3: 4 * time.Second,
		4: 8 * time.Second,
		5: 16 * time.Second,
	}
	for failures, want := range base {
		for i := 0; i < 20; i++ {
			d := backoffFor(failures)
			// ±20% 抖动。
			lo := time.Duration(float64(want) * 0.8)
			hi := time.Duration(float64(want) * 1.2)
			if d < lo || d > hi {
				t.Fatalf("backoffFor(%d) = %v, 期望落在 [%v, %v]", failures, d, lo, hi)
			}
		}
	}
	// 6 次及以上都封顶到 30s（抖动后上界仍不超过 1.2 倍基准，封顶值不再放大）。
	for _, failures := range []int{6, 7, 20, 1000} {
		for i := 0; i < 20; i++ {
			d := backoffFor(failures)
			if d > 30*time.Second || d < 24*time.Second {
				t.Fatalf("backoffFor(%d) = %v, 期望落在 [24s, 30s]", failures, d)
			}
		}
	}
}

func TestHysteriaCloseRejectsDial(t *testing.T) {
	cli := &fakeClient{}
	h := attached(cli)
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := cli.closed.Load(); n != 1 {
		t.Fatalf("共享客户端被关闭 %d 次, want 1", n)
	}
	// 幂等：第二次 Close 不再关一次。
	if err := h.Close(); err != nil {
		t.Fatalf("第二次 Close: %v", err)
	}
	if n := cli.closed.Load(); n != 1 {
		t.Fatalf("重复 Close 导致关闭 %d 次, want 1", n)
	}
	if _, err := h.client(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("关闭后 client() err = %v, want ErrClosed", err)
	}
	if _, err := h.DialContext(context.Background(), "example.com:443"); !errors.Is(err, ErrClosed) {
		t.Fatalf("关闭后 DialContext err = %v, want ErrClosed", err)
	}
}

// Connected 报的是「到服务端的隧道是否真的建起来了」，GUI 用它区分
// 「代理在跑」和「能出海」。几个关键状态都必须如实报，尤其不能图省事
// 一律返回 cli != nil——出站关闭后即使句柄还在也该报未连接。
func TestHysteriaConnected(t *testing.T) {
	t.Run("从未握手", func(t *testing.T) {
		h := attached(nil)
		if h.Connected() {
			t.Fatal("握手是懒触发的，还没拨号过时应为 false")
		}
	})

	t.Run("共享连接在位", func(t *testing.T) {
		h := attached(&fakeClient{})
		if !h.Connected() {
			t.Fatal("共享连接已建立，应为 true")
		}
		conn, err := h.DialContext(context.Background(), "example.com:443")
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		_ = conn.Close()
		if !h.Connected() {
			t.Fatal("拨号成功后连接态仍应为 true")
		}
	})

	t.Run("连接失效后", func(t *testing.T) {
		cli := &fakeClient{}
		h := attached(cli)
		h.invalidateCurrent(cli)
		if h.Connected() {
			t.Fatal("共享连接被丢弃后应为 false")
		}
	})

	t.Run("出站关闭后", func(t *testing.T) {
		h := attached(&fakeClient{})
		if err := h.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if h.Connected() {
			t.Fatal("出站已关闭，应为 false")
		}
	})
}

// 拨号策略分三档：隧道好好的就复用；目标连不通就如实返回、一次都不重试；
// 只有隧道确实坏了（或反复开不了流却说不出连接级原因）才换一条隧道。
func TestDialContextKeepsOrDropsSharedConnByErrorClass(t *testing.T) {
	t.Run("复用", func(t *testing.T) {
		cli := &fakeClient{}
		h := attached(cli)
		conn, err := h.DialContext(context.Background(), "example.com:443")
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		_ = conn.Close()
		if h.cli != cli {
			t.Fatal("拨号成功后应继续复用同一条 QUIC 连接")
		}
		if n := cli.closed.Load(); n != 0 {
			t.Fatalf("复用路径不应关闭共享客户端，实际 %d 次", n)
		}
	})

	// 浏览器每个页面都带着几个已经死掉的目标。为它们拆隧道，
	// 等于让一个失效的短链接打断同一隧道上正在传的大文件。
	t.Run("目标连不通时不拆隧道也不重试", func(t *testing.T) {
		cli := &fakeClient{dialErr: coreErrs.DialError{Message: "connection refused"}}
		h := attached(cli)
		start := time.Now()
		if _, err := h.DialContext(context.Background(), "dead.example:443"); err == nil {
			t.Fatal("期望拨号失败")
		}
		if el := time.Since(start); el > time.Second {
			t.Fatalf("目标连不通时应立刻返回，实际耗时 %v（不该排队退避重试）", el)
		}
		if n := cli.calls.Load(); n != 1 {
			t.Fatalf("开流调用 %d 次, want 1", n)
		}
		if h.cli != cli {
			t.Fatal("目标连不通不该让共享连接失效")
		}
		if n := cli.closed.Load(); n != 0 {
			t.Fatalf("共享客户端被关闭 %d 次, want 0", n)
		}
		if h.failures != 0 {
			t.Fatalf("失败计数 = %d, want 0（目标问题不该升级退避）", h.failures)
		}
	})

	t.Run("连接级开流失败后换隧道", func(t *testing.T) {
		cli := &fakeClient{dialErr: coreErrs.ClosedError{Err: errors.New("connection closed")}}
		h := attached(cli)
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		if _, err := h.DialContext(ctx, "example.com:443"); err == nil {
			t.Fatal("期望拨号失败")
		}
		if n := cli.closed.Load(); n != 1 {
			t.Fatalf("连接级开流失败应关闭共享客户端，实际 %d 次", n)
		}
		if h.failures == 0 {
			t.Fatal("连接级开流失败应计入失败次数，使退避升级")
		}
	})

	// 反复开不了流、却报不出连接级原因（服务端的流数上限就是这种）。
	// 不换隧道就会永久卡在这条连接上，所以最后一轮兜底重连。
	// 这一条要走完 maxDialAttempt 轮退避，是全套用例里最慢的（约 3s）。
	t.Run("反复开不了流时兜底换隧道", func(t *testing.T) {
		cli := &fakeClient{dialErr: quic.StreamLimitReachedError{}}
		h := attached(cli)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := h.DialContext(ctx, "example.com:443"); err == nil {
			t.Fatal("期望拨号失败")
		}
		if n := cli.calls.Load(); n != maxDialAttempt {
			t.Fatalf("开流调用 %d 次, want %d", n, maxDialAttempt)
		}
		if n := cli.closed.Load(); n != 1 {
			t.Fatalf("前 %d 轮不应拆隧道、最后一轮要兜底重建，实际关闭 %d 次", maxDialAttempt-1, n)
		}
	})

	// 出站已关闭时立刻返回，不做无意义的退避重试。
	t.Run("已关闭时不重试", func(t *testing.T) {
		cli := &fakeClient{}
		h := attached(cli)
		if err := h.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		start := time.Now()
		if _, err := h.DialContext(context.Background(), "example.com:443"); !errors.Is(err, ErrClosed) {
			t.Fatalf("DialContext err = %v, want ErrClosed", err)
		}
		if el := time.Since(start); el > 500*time.Millisecond {
			t.Fatalf("出站已关闭时应立即返回，实际耗时 %v", el)
		}
	})

	// 拨号拿到的流要记住自己属于哪一代隧道，否则它的错误无法判断该不该动当前连接。
	t.Run("流带上了所属代次", func(t *testing.T) {
		cli := &fakeClient{}
		h := attached(cli)
		conn, err := h.DialContext(context.Background(), "example.com:443")
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		tc, ok := conn.(*trackedConn)
		if !ok {
			t.Fatalf("返回类型 %T，期望 *trackedConn", conn)
		}
		if tc.gen != client.Client(cli) {
			t.Fatal("trackedConn 没有记下它所属的客户端代次")
		}
		_ = conn.Close()
	})
}

func TestNewHysteriaRejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		{"非法地址", "not-an-address"},
		{"缺少端口", "127.0.0.1"},
		{"端口超范围", "127.0.0.1:99999"},
		{"端口为负", "127.0.0.1:-1"},
		{"IP 字面量非法", "300.1.1.1:443"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := newTestServerConfig(tc.addr)
			if _, err := NewHysteria(sc, time.Second, nil, netip.Prefix{}); err == nil {
				t.Fatalf("NewHysteria(%q) 期望报错", tc.addr)
			}
		})
	}
}

func TestDirectOutboundRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("pong"))
		_ = c.Close()
	}()

	d := NewDirect(2 * time.Second)
	if d.Name() != string(PolicyDirect) {
		t.Fatalf("Name() = %q, want DIRECT", d.Name())
	}
	conn, err := d.DialContext(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("读到 %q, want \"pong\"", buf)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestSetGetPolicy(t *testing.T) {
	direct := NewDirect(time.Second)
	proxy := attached(&fakeClient{})
	proxy.template.ServerAddr = mustUDPAddr(t, "127.0.0.1:443")
	s := NewSet(direct, proxy)

	got, err := s.Get(PolicyDirect)
	if err != nil || got != Dialer(direct) {
		t.Fatalf("Get(DIRECT) = %v, %v", got, err)
	}
	got, err = s.Get(PolicyProxy)
	if err != nil || got != Dialer(proxy) {
		t.Fatalf("Get(PROXY) = %v, %v", got, err)
	}
	// 未知策略 fail-open 到代理。
	got, err = s.Get(Policy("nonsense"))
	if err != nil || got != Dialer(proxy) {
		t.Fatalf("Get(未知) = %v, %v, 期望回落到 PROXY", got, err)
	}
}

func TestSetGetMissingOutbound(t *testing.T) {
	if _, err := NewSet(NewDirect(time.Second), nil).Get(PolicyProxy); err == nil {
		t.Fatal("缺少代理出站时应报错")
	}
	if _, err := NewSet(nil, attached(&fakeClient{})).Get(PolicyDirect); err == nil {
		t.Fatal("缺少直连出站时应报错")
	}
}

func TestSetCloseClosesAll(t *testing.T) {
	cli := &fakeClient{}
	proxy := attached(cli)
	s := NewSet(NewDirect(time.Second), proxy)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n := cli.closed.Load(); n != 1 {
		t.Fatalf("Set.Close 应关闭代理出站，实际 %d 次", n)
	}
	// 再关一次不应重复关闭已释放的连接。
	if err := s.Close(); err != nil {
		t.Fatalf("第二次 Close: %v", err)
	}
	if n := cli.closed.Load(); n != 1 {
		t.Fatalf("重复 Set.Close 导致关闭 %d 次, want 1", n)
	}
}

// TestBackoffBeyondBudgetFailsFast 等不到的退避不能替调用方把预算睡光。
//
// 钉的是线上 232 条「拨不通」的形状：隧道掉线的那两分钟里，每条新连接先干等退避、
// 再被自己的时限掐掉，日志只剩一句 context deadline exceeded——
// 「节点在重连退避中」这个真实原因一个字都没留，而故障切换的判据还把这种错误
// 判成「调用方等不下去了，与节点无关」，于是那一类挂法永远触发不了切换。
func TestBackoffBeyondBudgetFailsFast(t *testing.T) {
	h := &Hysteria{handshakeTO: time.Second, failures: 3, retryAt: time.Now().Add(10 * time.Second)}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	_, err := h.DialContext(ctx, "busy.example:443")
	if !errors.Is(err, ErrInBackoff) {
		t.Fatalf("应当如实报「节点在重连退避中」，实得 %v", err)
	}
	// 这一句同时证明了「没有干等」：等到点的话 ctx 必然先到期，错误里就带着它。
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("退避被等成了调用方超时，原因又被盖回去了")
	}
	if !h.NodeFailure(err) {
		t.Fatal("退避中的失败被判成与节点无关，故障切换对这种挂法会瞎")
	}
}

// TestWaitBackoffOnlySleepsWithinBudget 两个方向都钉住：等得到的照等，等不到的收手。
// 只断后半句的话，把比较符整个反过来（或干脆永远跳过等待）都会绿。
func TestWaitBackoffOnlySleepsWithinBudget(t *testing.T) {
	h := &Hysteria{failures: 1} // backoffFor(1) = 1s ± 20%

	wide, cancelWide := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelWide()
	if !h.waitBackoff(wide, 1) {
		t.Fatal("预算够却跳过了退避：等于白白放弃一次本可以成功的重试")
	}

	deep, cancelDeep := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelDeep()
	if h.waitBackoff(deep, 6) { // backoffFor(6) 封顶 30s，远长于这 500ms 预算
		t.Fatal("30s 的退避在 500ms 的预算里还要睡，应立刻收手")
	}
	// 真正要紧的一端：收手必须发生在 ctx 到期**之前**。等到点才返回的话，
	// 这条改动等于没有——调用方仍然被烧光预算，交出去的原因仍然会被盖掉。
	if deep.Err() != nil {
		t.Fatal("等到 ctx 自己到期才返回，说明这段睡还是替调用方把预算烧光了")
	}
}
