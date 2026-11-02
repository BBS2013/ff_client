package metrics

import (
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// zeroCounter 是一个没人读写的计数器，只用来验证 Wrap 在 nilsafe 路径上的行为。
var zeroCounter atomic.Uint64

// closeWriteConn 是一个最小可用连接：实现了 net.Conn 全部方法，
// 外加 CloseWrite 以便验证 closeWrite() 的类型断言路径不会被 Wrap 打断。
type closeWriteConn struct {
	in  chan []byte
	out chan []byte
	mu  sync.Mutex
	// writes 记录所有写往对端的数据，用于断言透传行为没被包装改变。
	writes []byte
}

func newCloseWriteConn() *closeWriteConn {
	return &closeWriteConn{in: make(chan []byte, 4), out: make(chan []byte, 4)}
}

func (c *closeWriteConn) Read(p []byte) (int, error) {
	b, ok := <-c.in
	if !ok {
		return 0, io.EOF
	}
	return copy(p, b), nil
}

func (c *closeWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes = append(c.writes, p...)
	c.mu.Unlock()
	return len(p), nil
}

func (c *closeWriteConn) Close() error                     { return nil }
func (c *closeWriteConn) CloseWrite() error                { return nil }
func (c *closeWriteConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *closeWriteConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *closeWriteConn) SetDeadline(time.Time) error      { return nil }
func (c *closeWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (c *closeWriteConn) SetWriteDeadline(time.Time) error { return nil }

func (c *closeWriteConn) sent() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.writes...)
}

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

// TestWrapCountsReadOnly 锁住「只计 Read」这一语义：relay 两个方向各有一个 io.Copy，
// 都靠读出量区分上下行。若同时计 Write，同一份流量会被算两遍。
func TestWrapCountsReadOnly(t *testing.T) {
	base := newCloseWriteConn()
	var up, down atomic.Uint64

	c := Wrap(base, &up)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if up.Load() != 0 {
		t.Fatalf("Write 不应计入读出量，实际 %d", up.Load())
	}

	base.in <- []byte("world")
	buf := make([]byte, 5)
	if _, err := c.Read(buf); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := string(buf); got != "world" {
		t.Fatalf("Read 返回 %q, 期望 %q", got, "world")
	}
	if up.Load() != 5 {
		t.Fatalf("读出计数 = %d, 期望 5", up.Load())
	}
	if down.Load() != 0 {
		t.Fatalf("下行计数器不应被另一个连接写入，实际 %d", down.Load())
	}
	if got := string(base.sent()); got != "hello" {
		t.Fatalf("透传到对端的数据 = %q, 期望 %q", got, "hello")
	}
}

// TestWrapDirectionsWithRelay 模拟 inbound.relay 的真实结构，断言上下行不会被互相污染。
func TestWrapDirectionsWithRelay(t *testing.T) {
	var up, down atomic.Uint64
	cw := Wrap(newStreamConn('C'), &up)
	rw := Wrap(newStreamConn('S'), &down)

	// 上行 100 字节：io.Copy(remote, client) 从 client 读。
	if n, _ := io.Copy(io.Discard, io.LimitReader(cw, 100)); n != 100 {
		t.Fatalf("上行拷贝 %d 字节, 期望 100", n)
	}
	// 下行 40 字节：io.Copy(client, remote) 从 remote 读。
	if n, _ := io.Copy(io.Discard, io.LimitReader(rw, 40)); n != 40 {
		t.Fatalf("下行拷贝 %d 字节, 期望 40", n)
	}

	if up.Load() != 100 {
		t.Fatalf("上行 = %d, 期望 100", up.Load())
	}
	if down.Load() != 40 {
		t.Fatalf("下行 = %d, 期望 40（上下行不得互相污染）", down.Load())
	}
}

// streamConn 是一个无限吐固定字节的连接，用来验证计数方向。
type streamConn struct {
	b byte
}

func newStreamConn(b byte) *streamConn { return &streamConn{b: b} }

func (c *streamConn) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = c.b
	}
	return len(p), nil
}

func (c *streamConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *streamConn) Close() error                { return nil }
func (c *streamConn) CloseWrite() error           { return nil }
func (c *streamConn) LocalAddr() net.Addr         { return dummyAddr("local") }
func (c *streamConn) RemoteAddr() net.Addr        { return dummyAddr("remote") }
func (c *streamConn) SetDeadline(time.Time) error { return nil }
func (c *streamConn) SetReadDeadline(t time.Time) error {
	return nil
}
func (c *streamConn) SetWriteDeadline(t time.Time) error { return nil }

func TestCountReader(t *testing.T) {
	var up atomic.Uint64
	src := strings.NewReader("0123456789")
	n, err := io.Copy(io.Discard, CountReader(src, &up))
	if err != nil || n != 10 {
		t.Fatalf("Copy = %d, %v, 期望 10, nil", n, err)
	}
	if up.Load() != 10 {
		t.Fatalf("请求体计数 = %d, 期望 10", up.Load())
	}

	var zero atomic.Uint64
	if got := CountReader(src, nil); got != io.Reader(src) {
		t.Fatal("ctr 为 nil 时 CountReader 应原样返回 reader")
	}
	if got := CountReader(nil, &zero); got != nil {
		t.Fatal("reader 为 nil 时 CountReader 应返回 nil")
	}
}

// TestWrapPreservesCloseWrite 是本包最重要的一条：入站的 closeWrite() 靠类型断言
// `interface{ CloseWrite() error }` 决定半关闭。若 Wrap 吞掉了该方法，
// 断言失败会退化成 Close()，连接被提前整体关闭。
func TestWrapPreservesCloseWrite(t *testing.T) {
	base := newCloseWriteConn()
	c := Wrap(base, &zeroCounter)

	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("Wrap 后的连接没有 CloseWrite 方法，会让 inbound.closeWrite 退化成整体关闭")
	}
	if err := cw.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
}

func TestWrapNilCounterReturnsSameConn(t *testing.T) {
	base := newCloseWriteConn()
	if got := Wrap(base, nil); got != net.Conn(base) {
		t.Fatal("ctr 为 nil 时 Wrap 应原样返回连接")
	}
	if got := Wrap(nil, &zeroCounter); got != nil {
		t.Fatal("连接为 nil 时 Wrap 应返回 nil")
	}
}

// 底层没有 CloseWrite（hysteria 的 QUIC 流、TLS、UDP 都是）时，包装层必须如实报
// 「做不到」，而不是替调用方把整条连接关掉：入站靠这个判断决定要不要继续等响应。
func TestWrapWithoutCloseWriteReportsUnsupported(t *testing.T) {
	base := newPlainConn()
	c := Wrap(base, &zeroCounter)
	cw, ok := c.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("包装后仍应暴露 CloseWrite")
	}
	if err := cw.CloseWrite(); !errors.Is(err, ErrNoHalfClose) {
		t.Fatalf("CloseWrite err = %v, want ErrNoHalfClose", err)
	}
	if base.closed {
		t.Fatal("不支持半关时绝不能退化成 Close —— 那会把还没回完的响应一起掐掉")
	}
}

// 速率差分不能依赖「总量一定不减」这个前提：uint64 一旦倒退就下溢成 ~1.8e19，
// 除以 dt 就是一根几百 PB/s 的假尖峰，而速率图自动取轴，一整条曲线都会被判死。
func TestDiffRateHandlesRegressionWithoutSpike(t *testing.T) {
	cases := []struct {
		name      string
		prev, cur uint64
		dt        float64
		want      float64
	}{
		{"正常增速", 1000, 3000, 2, 1000},
		{"没有增长", 1000, 1000, 1, 0},
		{"倒退一格", 3000, 2990, 1, 0},
		{"倒退到零（清空统计）", 5 << 20, 0, 1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := diffRate(tc.prev, tc.cur, tc.dt, "上行"); got != tc.want {
				t.Fatalf("diffRate(%d,%d,%v) = %v, want %v", tc.prev, tc.cur, tc.dt, got, tc.want)
			}
		})
	}
}

// 连接结束的那一刻是历史上最容易造出假尖峰的时机：字节从 active 挪进 total，
// 只要差分写法不对，5MB 的正常流量就会画成 1.8e19 的满格毛刺。
func TestSamplerStaysSaneAcrossConnLifecycle(t *testing.T) {
	r := NewRegistry(0, 8)
	res := router.Result{Host: "example.com", Port: "443", Policy: "proxy", Matched: "FINAL", Outbound: "proxy"}

	sampleWith := func(bytesUp, bytesDown uint64) {
		c := r.Begin("http", "127.0.0.1:1", res)
		c.Up.Add(bytesUp)
		c.Down.Add(bytesDown)
		r.sample()
		r.End(c)
		r.sample()
	}
	sampleWith(5<<20, 1<<10) // 一条 5MB 的连接开合
	sampleWith(1<<10, 1<<10)

	snap := r.Snapshot()
	if len(snap.Series) < 3 {
		t.Fatalf("采样点 %d 个，期望至少 3 个", len(snap.Series))
	}
	for _, s := range snap.Series {
		// 采样点之间只差几微秒，速率算出来本来就偏大；
		// 但下溢的假尖峰是 1e19 量级，两者隔着四个数量级，这条线不会误报。
		if s.Up > 1e15 || s.Down > 1e15 {
			t.Fatalf("采样点出现不可能的速率: up=%.0f down=%.0f（点 %+v）", s.Up, s.Down, s)
		}
	}
}

type plainConn struct {
	net.Conn
	closed bool
}

func newPlainConn() *plainConn { return &plainConn{} }

func (c *plainConn) Close() error { c.closed = true; return nil }

func TestRegistryBeginEnd(t *testing.T) {
	r := NewRegistry(10, 0)
	res := router.Result{Host: "example.com", Port: "443", Policy: "proxy", Matched: "FINAL", Outbound: "proxy"}

	c := r.Begin("socks5", "127.0.0.1:1234", res)
	if c == nil {
		t.Fatal("Begin 返回 nil")
	}
	c.Up.Add(100)
	c.Down.Add(200)

	snap := r.Snapshot()
	if snap.ActiveCount != 1 || len(snap.Active) != 1 {
		t.Fatalf("活动连接数 = %d, 期望 1", snap.ActiveCount)
	}
	if snap.TotalUp != 100 || snap.TotalDown != 200 {
		t.Fatalf("累计 = %d/%d, 期望 100/200", snap.TotalUp, snap.TotalDown)
	}
	a := snap.Active[0]
	if a.Target != "example.com:443" || a.Inbound != "socks5" || a.Matched != "FINAL" {
		t.Fatalf("连接元信息不对: %+v", a)
	}

	r.End(c)
	snap = r.Snapshot()
	if snap.ActiveCount != 0 || len(snap.History) != 1 {
		t.Fatalf("End 之后 active=%d history=%d, 期望 0/1", snap.ActiveCount, len(snap.History))
	}
	if snap.TotalUp != 100 || snap.TotalDown != 200 || snap.TotalConns != 1 {
		t.Fatalf("End 之后累计应保留: %+v", snap)
	}
	if snap.History[0].Up != 100 || snap.History[0].Down != 200 {
		t.Fatalf("历史记录字节数不对: %+v", snap.History[0])
	}
}

func TestRegistryNilSafe(t *testing.T) {
	var r *Registry
	if c := r.Begin("socks5", "x", router.Result{}); c != nil {
		t.Fatal("nil Registry 的 Begin 应返回 nil")
	}
	r.End(nil) // 不能 panic
	r.StartSampler()
	r.StopSampler()
	r.Reset()
	if s := r.Snapshot(); s.ActiveCount != 0 {
		t.Fatal("nil Registry 的快照应为空")
	}
}

func TestRegistryHistoryRingCap(t *testing.T) {
	r := NewRegistry(3, 0)
	for i := 0; i < 10; i++ {
		c := r.Begin("socks5", "c", router.Result{Host: "h", Port: "80"})
		c.Down.Add(uint64(i))
		r.End(c)
	}
	snap := r.Snapshot()
	if len(snap.History) != 3 {
		t.Fatalf("历史条数 = %d, 期望被环形缓冲截断为 3", len(snap.History))
	}
	// End 顺序为 0..9，保留最近三条即 7/8/9，倒序后最新在前。
	if snap.History[0].Down != 9 || snap.History[2].Down != 7 {
		t.Fatalf("历史倒序不对: %d %d %d", snap.History[0].Down, snap.History[1].Down, snap.History[2].Down)
	}
	if snap.TotalConns != 10 {
		t.Fatalf("总连接数 = %d, 期望 10", snap.TotalConns)
	}
}

func TestRegistrySeriesRingAndRate(t *testing.T) {
	r := NewRegistry(0, 3)
	c := r.Begin("socks5", "c", router.Result{Host: "h", Port: "80"})
	c.Down.Add(1_000_000)

	// 直接驱动采样点，避免依赖真实 ticker。
	r.sample()
	c.Down.Add(1_000_000)
	r.sample()
	c.Down.Add(1_000_000)
	r.sample()
	c.Down.Add(1_000_000)
	r.sample()

	snap := r.Snapshot()
	if len(snap.Series) != 3 {
		t.Fatalf("序列长度 = %d, 期望环形缓冲截断为 3", len(snap.Series))
	}
	for i, s := range snap.Series {
		if s.Down <= 0 {
			t.Fatalf("第 %d 个采样点下行速率为 %f, 期望 > 0", i, s.Down)
		}
	}
	// 活动连接仍计入累计。
	if snap.TotalDown != 4_000_000 {
		t.Fatalf("累计下行 = %d, 期望 4000000", snap.TotalDown)
	}
}

func TestRegistryRateDoesNotUnderflowWhenConnectionEnds(t *testing.T) {
	// 速率差分必须建立在单调不减的累计量上。
	// 只拿「活动连接」求和的话，任何一条连接结束都会让总数变小，
	// uint64 相减下溢成 ~1.8e19 字节/秒——浏览器每分钟开关上百条短连接，
	// 面板流量图于是永远是满格毛刺。
	r := NewRegistry(0, 8)
	c := r.Begin("socks5", "c", router.Result{Host: "h", Port: "80"})
	c.Down.Add(5_000_000)

	// 采样之间留出真实间隔，让速率是「字节/秒」而不是「字节/微秒」，
	// 否则断言会被除数过小带偏，测不出下溢。
	time.Sleep(20 * time.Millisecond)
	r.sample()
	c.Down.Add(5_000_000)
	time.Sleep(20 * time.Millisecond)
	r.sample()

	// 连接在这里结束：它的 10MB 从「活动」搬进「已结束累计」。
	// 累计总量本身不该变，这正是 rawDown 必须保持单调不减的原因。
	r.End(c)
	time.Sleep(20 * time.Millisecond)
	r.sample()
	time.Sleep(20 * time.Millisecond)
	r.sample()

	series := r.Snapshot().Series
	if len(series) != 4 {
		t.Fatalf("采样点 = %d, 期望 4", len(series))
	}
	// 不变量：差分的底数单调不减。
	for i := 1; i < len(series); i++ {
		if series[i].rawDown < series[i-1].rawDown {
			t.Fatalf("rawDown 在第 %d 个点回落: %d -> %d，差分必然下溢",
				i, series[i-1].rawDown, series[i].rawDown)
		}
	}
	for i, s := range series {
		if math.IsNaN(s.Down) || s.Down < 0 {
			t.Fatalf("第 %d 个采样点下行速率 = %f, 期望非负", i, s.Down)
		}
	}
	// 最后一个采样点之后既没有新流量也没有连接结束，速率必须归零。
	// 修复前这一步会冒出 ~1.8e19 的假尖峰。
	if last := series[len(series)-1].Down; last != 0 {
		t.Fatalf("无流量时下行速率 = %f, 期望 0（下溢会产生 1.8e19 量级的假尖峰）", last)
	}
	// 累计量必须守恒：连接结束前后 TotalDown 都应是 10MB。
	if got := r.Snapshot().TotalDown; got != 10_000_000 {
		t.Fatalf("累计下行 = %d, 期望 10000000", got)
	}
}

func TestRegistryStopSamplerIsIdempotentUnderConcurrency(t *testing.T) {
	// 两个 goroutine 同时 StopSampler：句柄在锁内置空，
	// 因此只有一方拿到 close 的机会（否则会 close 一个已关闭的通道而 panic）。
	r := NewRegistry(0, 4)
	r.StartSampler()

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.StopSampler()
		}()
	}
	wg.Wait()

	// 并发 Start/Stop 也不该留下关不掉的采样 goroutine 或 panic。
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.StartSampler()
			r.StopSampler()
		}()
	}
	wg.Wait()
	r.StopSampler()
}

func TestRegistrySnapshotActiveSortedByTraffic(t *testing.T) {
	r := NewRegistry(0, 0)
	small := r.Begin("socks5", "small", router.Result{Host: "a", Port: "80"})
	small.Down.Add(10)
	big := r.Begin("socks5", "big", router.Result{Host: "b", Port: "80"})
	big.Down.Add(999)

	snap := r.Snapshot()
	if snap.Active[0].ID != big.ID {
		t.Fatalf("活动连接未按流量排序，首位 ID = %d, 期望 %d", snap.Active[0].ID, big.ID)
	}
}

func TestRegistryReset(t *testing.T) {
	r := NewRegistry(5, 5)
	c := r.Begin("socks5", "c", router.Result{Host: "h", Port: "80"})
	c.Up.Add(50)
	r.End(c)
	r.sample()
	r.Reset()

	snap := r.Snapshot()
	if snap.TotalConns != 0 || snap.TotalUp != 0 || snap.TotalDown != 0 {
		t.Fatalf("Reset 后累计未清零: %+v", snap)
	}
	if len(snap.History) != 0 || len(snap.Series) != 0 {
		t.Fatalf("Reset 后历史与序列未清空: %d/%d", len(snap.History), len(snap.Series))
	}
}

func TestRegistrySamplerStartStop(t *testing.T) {
	r := NewRegistry(0, 10)
	r.StartSampler()
	r.StartSampler() // 幂等

	// 等到真的出现一个点，而不是睡 1.2 秒再去数：ticker 是 1s 一次，
	// 那 200ms 余量只说明"机器当时不忙"，机器忙时它就变成偶发红灯，
	// 而这个断言本来的含义是"采样器会产出点"，跟多久产出无关。
	if n := waitSeries(t, r, 1, 5*time.Second); n < 1 {
		t.Fatalf("采样器在 5s 内一个点都没产出（实得 %d）", n)
	}
	r.StopSampler()
	r.StopSampler() // 幂等

	stopped := len(r.Snapshot().Series)
	// 另一半是"证明没有"，只能等够一个周期以上：这里必须是真实等待。
	time.Sleep(1200 * time.Millisecond)
	if got := len(r.Snapshot().Series); got != stopped {
		t.Fatalf("停止后仍在采样: %d -> %d", stopped, got)
	}
}

// waitSeries 轮询到速率序列里至少出现 want 个点，返回当时的点数。
func waitSeries(t *testing.T, r *Registry, want int, within time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		n := len(r.Snapshot().Series)
		if n >= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNewRegistryNegativeCaps(t *testing.T) {
	r := NewRegistry(-1, -1)
	c := r.Begin("socks5", "c", router.Result{Host: "h", Port: "80"})
	r.End(c)
	r.StartSampler()
	r.StopSampler()
	if n := len(r.Snapshot().History); n != 0 {
		t.Fatalf("histCap<=0 时不应保留历史，实际 %d", n)
	}
}

// TestBlockedCounterUnderLoad 并发拦截：计数一条不许丢，留痕一条不许被拆成两份。
//
// 留痕的合并与上限都在 mu 里做，计数是原子量——这两件事在真实面板上会同时被
// 一个页面的十几条广告请求压到，所以不能只测单线程那一遍。
func TestBlockedCounterUnderLoad(t *testing.T) {
	const n = 500
	r := NewRegistry(0, 0)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("a%d.example", i%40)
			c := r.Begin("socks5", "127.0.0.1:5000", router.Result{
				Host: host, Port: "443", Policy: outbound.PolicyReject, Matched: "RULE-" + host,
			})
			r.End(c)
		}(i)
	}
	wg.Wait()

	snap := r.Snapshot()
	if snap.TotalBlocked != n {
		t.Fatalf("累计拦截丢了计数：%d, 期望 %d", snap.TotalBlocked, n)
	}
	if len(snap.RecentBlocked) != blockedRingCap {
		t.Fatalf("留痕应停在上限 %d，实得 %d", blockedRingCap, len(snap.RecentBlocked))
	}
	seen := map[string]int{}
	for _, h := range snap.RecentBlocked {
		key := h.Host + "|" + h.Rule
		seen[key]++
		if h.Count == 0 {
			t.Fatalf("留痕里有零记录的条目：%+v", h)
		}
	}
	if len(seen) != len(snap.RecentBlocked) {
		t.Fatalf("同一 host+规则被拆成了多条（合并没在同一个临界区里做）：%+v", snap.RecentBlocked)
	}
}

// TestBlockedRing 最近拦截留痕的三条规矩：合并、上限、顺序。
func TestBlockedRing(t *testing.T) {
	r := NewRegistry(0, 0)
	add := func(host, rule string) {
		r.End(r.Begin("socks5", "127.0.0.1:5001", router.Result{
			Host: host, Port: "443", Policy: outbound.PolicyReject, Matched: rule,
		}))
	}

	empty := r.Snapshot().RecentBlocked
	if empty == nil {
		t.Fatal("RecentBlocked 为 nil：JSON 会发 null，前端 .length 直接炸")
	}
	if len(empty) != 0 {
		t.Fatalf("初始应为空，实得 %d", len(empty))
	}

	add("a.example", "RULE-A")
	add("a.example", "RULE-A") // 同 host 同规则：合并成一条
	add("a.example", "RULE-B") // 同 host 不同规则：两条都要在，"是谁拦的"是唯一有用的信息
	add("b.example", "RULE-A")

	got := r.Snapshot().RecentBlocked
	if len(got) != 3 {
		t.Fatalf("应为 3 条，实得 %d: %+v", len(got), got)
	}
	if got[0].Host != "b.example" {
		t.Fatalf("投影应按新→旧，第一条实得 %q", got[0].Host)
	}
	var merged *BlockedHit
	for i := range got {
		if got[i].Host == "a.example" && got[i].Rule == "RULE-A" {
			merged = &got[i]
		}
	}
	if merged == nil {
		t.Fatalf("没找到 a.example/RULE-A 那条: %+v", got)
	}
	if merged.Count != 2 {
		t.Fatalf("同 host 同规则应合并计数，实得 %d", merged.Count)
	}
	if merged.LastAt == 0 {
		t.Fatal("最近时刻没记上")
	}

	// 上限：超过就丢最老的，内存不许随拦截次数一直长。
	for i := 0; i < 3*blockedRingCap; i++ {
		add(fmt.Sprintf("x%d.example", i), "RULE-A")
	}
	if n := len(r.Snapshot().RecentBlocked); n != blockedRingCap {
		t.Fatalf("留痕上限 %d，实得 %d", blockedRingCap, n)
	}

	r.Reset()
	if n := len(r.Snapshot().RecentBlocked); n != 0 {
		t.Fatalf("Reset 后留痕未清空，实得 %d", n)
	}
}

// 为什么要在 Begin 计而不是 End：一条被拦的连接可能还压在 BlockHold 里（上限 75s），
// 用户按下刷新那一刻就想看到计数动了——等它收尾才数，界面上就是"拦了但没反应"。
func TestBlockedCounter(t *testing.T) {
	r := NewRegistry(10, 0)
	if got := r.Snapshot().TotalBlocked; got != 0 {
		t.Fatalf("初始应为 0，实得 %d", got)
	}

	blocked := r.Begin("socks5", "127.0.0.1:5001", router.Result{
		Host: "ads.example.com", Port: "443",
		Policy: outbound.PolicyReject, Outbound: string(outbound.PolicyReject),
	})
	if got := r.Snapshot().TotalBlocked; got != 1 {
		t.Fatalf("还没收尾的拦截也该计数，实得 %d", got)
	}
	r.End(blocked)
	if got := r.Snapshot().TotalBlocked; got != 1 {
		t.Fatalf("收尾后不该重复计，实得 %d", got)
	}

	// 放行与直连都不进这个数。
	for _, p := range []outbound.Policy{outbound.PolicyDirect, outbound.PolicyProxy} {
		r.End(r.Begin("socks5", "127.0.0.1:5002", router.Result{Host: "ok.example", Port: "443", Policy: p}))
	}
	if got := r.Snapshot().TotalBlocked; got != 1 {
		t.Fatalf("非拦截的连接被计进来了，实得 %d", got)
	}

	r.Reset()
	if got := r.Snapshot().TotalBlocked; got != 0 {
		t.Fatalf("Reset 后累计拦截未清零，实得 %d", got)
	}
}

// TestByNodeTotals 按节点的用量必须算得准：已收尾的加进来、还在跑的也算进来，
// 而且不能靠"每次写数据包抢一次锁"来实现。
func TestByNodeTotals(t *testing.T) {
	r := NewRegistry(10, 4)

	// 节点 A：一条已经收尾（1000/2000）+ 一条还在跑（7/11）。
	a := r.Begin("socks5", "127.0.0.1:1", router.Result{Host: "a.example", Policy: outbound.PolicyProxy, Node: "A"})
	a.Up.Add(1000)
	a.Down.Add(2000)
	r.End(a)
	live := r.Begin("socks5", "127.0.0.1:2", router.Result{Host: "b.example", Policy: outbound.PolicyProxy, Node: "A"})
	live.Up.Add(7)
	live.Down.Add(11)

	// 直连自成一行：它回答的是"这些流量没走节点"。
	d := r.Begin("http", "127.0.0.1:3", router.Result{Host: "c.example", Policy: outbound.PolicyDirect, Node: "DIRECT"})
	d.Down.Add(500)
	r.End(d)

	// 被拦的不占行：零字节的行只会稀释这张表。
	b := r.Begin("socks5", "127.0.0.1:4", router.Result{Host: "ads.example", Policy: outbound.PolicyReject, Node: "REJECT"})
	r.End(b)

	snap := r.Snapshot()
	got := map[string]NodeTraffic{}
	for _, n := range snap.ByNode {
		got[n.Node] = n
	}
	if len(snap.ByNode) != 2 {
		t.Fatalf("应当只有 A 与 DIRECT 两行（REJECT 不占行），得到 %+v", snap.ByNode)
	}
	if a := got["A"]; a.Up != 1007 || a.Down != 2011 || a.Conns != 2 {
		t.Errorf("A 的账算错了（收尾的 + 在跑的）：%+v", a)
	}
	if d := got["DIRECT"]; d.Down != 500 || d.Conns != 1 {
		t.Errorf("直连那行不对：%+v", d)
	}
	// 大在前。
	if snap.ByNode[0].Node != "A" {
		t.Errorf("应当按总量从大到小排，得到 %s 在前", snap.ByNode[0].Node)
	}

	// 「清空统计」清的是字节账。那条还在跑的连接仍然占一行（它确实存在，
	// 连接表里也看得见），但它清零之前跑过的字节不能再算进新账——
	// 否则会出现"总数已经归零、A 还挂着 3GB"。
	r.Reset()
	after := map[string]NodeTraffic{}
	for _, n := range r.Snapshot().ByNode {
		after[n.Node] = n
	}
	if a := after["A"]; a.Up != 0 || a.Down != 0 {
		t.Errorf("Reset 之后在跑的那条不该再带清零前的字节：%+v", a)
	}
	if _, ok := after["DIRECT"]; ok {
		t.Errorf("已收尾的直连账应当清空，得到 %+v", after["DIRECT"])
	}
	// 清零之后再写的字节算新账。
	live.Down.Add(5)
	if got := r.Snapshot().ByNode; len(got) == 0 || got[0].Down != 5 {
		t.Errorf("清零之后的新字节没记上：%+v", got)
	}
}

// TestNodeFieldAndByNodeSayTheSameString 守的是"同一个事实被算两遍"这一处。
//
// 各节点用量那张表按 Conn.Node 分组，连接表每一行也报同一个值。
// 只要投影漏了 Node、或者 view() 忘了带上它，屏幕上会出现一张自相矛盾的表：
// 「tokyo 用掉 3GB、5 条」，而下面那 5 条连接一个都没写明自己走的是 tokyo。
// 这种断法不会报错，只会让人怀疑自己看错了——所以把它写成断言。
func TestNodeFieldAndByNodeSayTheSameString(t *testing.T) {
	r := NewRegistry(10, 4)

	type seed struct {
		node string
		// live 为 false 的会在登记之后立刻收尾，覆盖 active 与 history 两条拷贝路径。
		live bool
	}
	seeds := []seed{
		{"tokyo", true}, {"tokyo", false}, {"tokyo", false},
		{"berlin", true}, {"berlin", false},
		{"DIRECT", false},
		{"REJECT", false}, // 零字节、不占行，也不该出现在连接表的分组里
	}
	for i, s := range seeds {
		c := r.Begin("socks5", fmt.Sprintf("127.0.0.1:%d", 4000+i), router.Result{
			Host: fmt.Sprintf("h%d.example", i), Policy: outbound.PolicyProxy, Node: s.node,
		})
		c.Down.Add(10)
		if !s.live {
			r.End(c)
		}
	}

	snap := r.Snapshot()
	rows := append(append([]ConnView{}, snap.Active...), snap.History...)
	if len(rows) != len(seeds) {
		t.Fatalf("连接表应当有 %d 行，得到 %d", len(seeds), len(rows))
	}
	// 每一条都在自己的行上写明了去处：空串意味着"这一行没告诉用户它走了哪里"。
	for _, row := range rows {
		if row.Node == "" {
			t.Errorf("连接 id=%d 没投影出 node（outbound=%q），两张表会对不上", row.ID, row.Outbound)
		}
	}

	// 表上的行数与那张用量表里的 conns 必须是同一个数——这正是点那一行去筛连接时
	// 用户会自己核对的东西。数的是**投影出来的那些行**，不是构造用例时的那份清单：
	// 后者只能证明用例自己跟自己对上了。
	wantRows := map[string]int{}
	for _, row := range rows {
		if row.Node == "REJECT" {
			continue
		}
		wantRows[row.Node]++
	}
	for _, n := range snap.ByNode {
		if got := wantRows[n.Node]; got != int(n.Conns) {
			t.Errorf("%s 在用量表上写着 %d 条，连接表里却筛出 %d 行", n.Node, n.Conns, got)
		}
		delete(wantRows, n.Node)
	}
	if len(wantRows) != 0 {
		t.Errorf("连接表里有 %d 个去处没出现在用量表上: %v", len(wantRows), wantRows)
	}
}

// TestByNodeFollowsTheNodeSwitch 换节点之后的新连接记到新节点名下，
// 换之前那条还在跑的仍然记在旧节点名下——这正是"这个月的量是谁用掉的"要的答案。
func TestByNodeFollowsTheNodeSwitch(t *testing.T) {
	r := NewRegistry(0, 0)
	old := r.Begin("socks5", "c1", router.Result{Policy: outbound.PolicyProxy, Node: "old"})
	old.Down.Add(100)
	// 模拟换节点：路由器给出的 Node 变了，但已登记的那条不改口。
	neo := r.Begin("socks5", "c2", router.Result{Policy: outbound.PolicyProxy, Node: "new"})
	neo.Down.Add(30)
	r.End(neo)

	got := map[string]uint64{}
	for _, n := range r.Snapshot().ByNode {
		got[n.Node] = n.Down
	}
	if got["old"] != 100 || got["new"] != 30 {
		t.Errorf("换节点后两家的账应当各记各的，得到 %+v", got)
	}
}

// 网卡那一列必须从 Result 一路活到活跃连接与历史连接两处。
//
// 只在活跃表里显示是"看起来能用、实际漏一半"：连接一结束就查不到了，
// 而排查分流问题的时刻恰恰常常发生在连接结束之后。
func TestConnViewCarriesInterface(t *testing.T) {
	r := NewRegistry(10, 0)
	res := router.Result{
		Host: "example.com", Port: "443", Policy: "proxy",
		Matched: "FINAL", Outbound: "proxy", Iface: "wlx001f0578cdff",
	}

	c := r.Begin("socks5", "127.0.0.1:1234", res)
	if c.Iface != "wlx001f0578cdff" {
		t.Fatalf("Conn 上没带上网卡: %q", c.Iface)
	}
	r.End(c)

	snap := r.Snapshot()
	if len(snap.History) != 1 {
		t.Fatalf("历史里该有 1 条，得到 %d", len(snap.History))
	}
	if got := snap.History[0].Iface; got != "wlx001f0578cdff" {
		t.Errorf("历史连接丢了网卡: %q", got)
	}
}

// TestRegistryRuleHits 命中计数按"引擎写下的那句命中依据"归并。
func TestRegistryRuleHits(t *testing.T) {
	r := NewRegistry(0, 0)
	begin := func(matched string, policy outbound.Policy) {
		r.Begin("socks5", "c", router.Result{Host: "h", Port: "80", Matched: matched, Policy: policy})
	}
	begin("DOMAIN-SUFFIX,a.test,PROXY", outbound.PolicyProxy)
	begin("DOMAIN-SUFFIX,a.test,PROXY", outbound.PolicyProxy)
	// 拦截的那条也要算：计数在 Begin 这一刻加，不等连接收尾。
	// 被拦的连接可能还压在 BlockHold 里几十秒，等 End 就成了"明明在拦、计数不动"。
	begin("DOMAIN-SUFFIX,ads.test,REJECT(block)", outbound.PolicyReject)
	// FINAL 不是一个"用户写的规则"，但它是引擎给出的命中依据，照记。
	// 面板那一栏只会去对应用户写的行，所以它安静地待在 map 里不影响界面。
	begin("FINAL", outbound.PolicyDirect)

	hits := r.RuleHits()
	if hits["DOMAIN-SUFFIX,a.test,PROXY"] != 2 {
		t.Errorf("同一条命中依据没归并到一起: %+v", hits)
	}
	if hits["DOMAIN-SUFFIX,ads.test,REJECT(block)"] != 1 {
		t.Errorf("拦截的那条没算: %+v", hits)
	}
	if hits["FINAL"] != 1 {
		t.Errorf("FINAL 没算: %+v", hits)
	}

	// 交出去的必须是副本：调用方（面板每 5 秒拿一份）慢慢改也不该动到内部。
	hits["DOMAIN-SUFFIX,a.test,PROXY"] = 999
	if got := r.RuleHits()["DOMAIN-SUFFIX,a.test,PROXY"]; got != 2 {
		t.Errorf("RuleHits 交的是内部 map，被调用方改掉了: %d", got)
	}

	// 「清空统计」必须连它一起清：只清总数不清这一份，
	// 界面上就会出现"连接表空了、可这条规则刚刚命中过 2 次"。
	r.Reset()
	if got := r.RuleHits(); len(got) != 0 {
		t.Errorf("Reset 之后命中计数还在: %+v", got)
	}
}

// TestRegistryRuleHitsSkipsEmptyMatched 没有命中依据就不记。
// 记成一个空串的键，等于在排行里造一条永远对不上任何规则的幽灵。
func TestRegistryRuleHitsSkipsEmptyMatched(t *testing.T) {
	r := NewRegistry(0, 0)
	r.Begin("socks5", "c", router.Result{Host: "h", Port: "80"})
	if got := r.RuleHits(); len(got) != 0 {
		t.Errorf("空命中依据被记了一笔: %+v", got)
	}
}

// ---------- 按规则的字节汇总 ----------

// TestByRuleTotals 已收尾的加进来、还在跑的也算进来，与按节点那张表同一条算法。
func TestByRuleTotals(t *testing.T) {
	r := NewRegistry(10, 4)

	a := r.Begin("socks5", "127.0.0.1:1", router.Result{Host: "a.example", Policy: outbound.PolicyProxy,
		Matched: "DOMAIN-SUFFIX,a.example,PROXY", Node: "A"})
	a.Up.Add(1000)
	a.Down.Add(2000)
	r.End(a)
	// 同一条规则上还在跑的那条也要算：只看 End 的话，长连接永远不出现在排行里，
	// 而"谁在搬流量"恰恰多半是长连接。
	live := r.Begin("socks5", "127.0.0.1:2", router.Result{Host: "a2.example", Policy: outbound.PolicyProxy,
		Matched: "DOMAIN-SUFFIX,a.example,PROXY", Node: "A"})
	live.Up.Add(7)
	live.Down.Add(11)

	d := r.Begin("http", "127.0.0.1:3", router.Result{Host: "c.example", Policy: outbound.PolicyDirect,
		Matched: "FINAL", Node: "DIRECT"})
	d.Down.Add(500)
	r.End(d)

	// 没有命中依据的连接不配占一行：那会造出一条对不上任何规则的幽灵。
	ghost := r.Begin("socks5", "127.0.0.1:4", router.Result{Host: "x.example", Policy: outbound.PolicyProxy})
	ghost.Up.Add(9999)
	r.End(ghost)

	snap := r.Snapshot()
	got := map[string]RuleTraffic{}
	for _, row := range snap.ByRule {
		got[row.Rule] = row
	}
	if len(snap.ByRule) != 2 {
		t.Fatalf("应当只有两条规则，得到 %+v", snap.ByRule)
	}
	if a := got["DOMAIN-SUFFIX,a.example,PROXY"]; a.Up != 1007 || a.Down != 2011 || a.Conns != 2 {
		t.Errorf("这条规则的账算错了（收尾的 + 在跑的）：%+v", a)
	}
	if f := got["FINAL"]; f.Down != 500 || f.Conns != 1 {
		t.Errorf("FINAL 那行不对：%+v", f)
	}
}

// TestByRuleReconcilesWithTotal 是这张表唯一要守住的算式：
// 各行加起来必须等于总量，否则"按规则看"就成一个只能看、不能对账的东西。
func TestByRuleReconcilesWithTotal(t *testing.T) {
	r := NewRegistry(0, 0)
	ruleOf := func(i int) string {
		return "DOMAIN-SUFFIX,r" + string(rune('A'+i%7)) + ".test,PROXY"
	}
	for i := 0; i < 40; i++ {
		c := r.Begin("socks5", "c", router.Result{Host: "h", Policy: outbound.PolicyProxy,
			Matched: ruleOf(i), Node: "A"})
		c.Up.Add(uint64(100 + i))
		c.Down.Add(uint64(7))
		r.End(c)
	}
	snap := r.Snapshot()
	var sum uint64
	for _, row := range snap.ByRule {
		sum += row.Up + row.Down
	}
	if want := snap.TotalUp + snap.TotalDown; sum != want {
		t.Errorf("按规则加起来不等于总量：%d ≠ %d", sum, want)
	}
}

// TestByRuleFoldsTheRest 行数有上限，但被折掉的那些必须仍然算在表里。
func TestByRuleFoldsTheRest(t *testing.T) {
	r := NewRegistry(0, 0)
	// 20 条各不相同的规则，比展示上限多。
	for i := 0; i < 20; i++ {
		c := r.Begin("socks5", "c", router.Result{Host: "h", Policy: outbound.PolicyProxy,
			Matched: "RULE-" + string(rune('a'+i)), Node: "A"})
		c.Up.Add(uint64(1000 - i*10))
		r.End(c)
	}
	snap := r.Snapshot()
	if len(snap.ByRule) != ruleRowsShown {
		t.Fatalf("行数该收在展示上限：%+v", snap.ByRule)
	}
	last := snap.ByRule[len(snap.ByRule)-1]
	if last.Folded == 0 {
		t.Fatalf("最后一行该是合并行，却写着 %+v", last)
	}
	var sum uint64
	for _, row := range snap.ByRule {
		sum += row.Up + row.Down
	}
	if want := snap.TotalUp + snap.TotalDown; sum != want {
		t.Errorf("合并之后总数对不上了：%d ≠ %d", sum, want)
	}
	if got := snap.ByRule[0].Up; got != 1000 {
		t.Errorf("排行没按字节从大到小：%+v", snap.ByRule)
	}
}

// TestByRuleKeysAreBounded 规则文件的条数是几千这个量级，账本的键不能跟着无限长。
// 超上限的部分并进一个桶，表里加总仍然等于总量——这才是"有上限"的正确形状：
// 限制内存，而不是限制被记住的字节。
func TestByRuleKeysAreBounded(t *testing.T) {
	r := NewRegistry(0, 0)
	for i := 0; i < ruleKeyCap+300; i++ {
		c := r.Begin("socks5", "c", router.Result{Host: "h", Policy: outbound.PolicyProxy,
			Matched: fmt.Sprintf("RULE-%d", i), Node: "A"})
		c.Up.Add(10)
		r.End(c)
	}
	snap := r.Snapshot()
	if len(snap.ByRule) > ruleRowsShown {
		t.Fatalf("表该被收成有限行：%d 行", len(snap.ByRule))
	}
	var sum uint64
	for _, row := range snap.ByRule {
		sum += row.Up + row.Down
	}
	if want := snap.TotalUp + snap.TotalDown; sum != want {
		t.Errorf("键数封顶却把量弄丢了：%d ≠ %d", sum, want)
	}
	var hasOverflow bool
	for _, row := range snap.ByRule {
		if row.Rule == ruleOverflowKey || row.Folded > 0 {
			hasOverflow = true
		}
	}
	if !hasOverflow {
		t.Error("超上限的量没有落在任何一个可见的桶里")
	}
}

// TestByRuleReset 清零要连这张表一起清：只清命中不清字节，
// 界面上就是"规则页说没命中过、流量页说它刚搬了 2GB"。
// 而且在跑的那条不能把清零之前的字节再算一遍（水位与按节点那张表共用）。
func TestByRuleReset(t *testing.T) {
	r := NewRegistry(0, 0)
	const rule = "DOMAIN-SUFFIX,big.test,PROXY"
	c := r.Begin("socks5", "c", router.Result{Host: "h", Policy: outbound.PolicyProxy, Matched: rule, Node: "A"})
	c.Up.Add(5 << 20)
	live := r.Begin("socks5", "c2", router.Result{Host: "h2", Policy: outbound.PolicyProxy, Matched: rule, Node: "A"})
	live.Up.Add(3 << 20)

	r.Reset()
	live.Up.Add(1 << 20) // 清零之后才跑的，这一笔才算新账
	r.End(c)
	r.End(live)

	snap := r.Snapshot()
	row, ok := func() (RuleTraffic, bool) {
		for _, x := range snap.ByRule {
			if x.Rule == rule {
				return x, true
			}
		}
		return RuleTraffic{}, false
	}()
	if !ok {
		t.Fatalf("清零之后这条规则整行都没了：%+v", snap.ByRule)
	}
	if row.Up != 1<<20 {
		t.Errorf("清零之前的字节被算进来了：%d，期望只有清零后的 1MB", row.Up)
	}
}

// TestByRuleRefusedCarriesNoBytesButStillRows 拨不通的那条：零字节。
// 它进这张表是好事（哪条规则在产出失败，一眼看得见），
// 但也仅此而已——别把"命中次数"混进来，那张口径在规则页。
func TestByRuleRefusedCarriesNoBytes(t *testing.T) {
	r := NewRegistry(0, 0)
	r.Refuse("socks5", "c", "h:443", router.Result{Host: "h", Matched: "GEOIP,CN,DIRECT", Node: "DIRECT"}, "拨不通")
	snap := r.Snapshot()
	for _, row := range snap.ByRule {
		if row.Rule == "GEOIP,CN,DIRECT" && (row.Up != 0 || row.Down != 0) {
			t.Errorf("拨不通的连接不该有字节：%+v", row)
		}
	}
}
