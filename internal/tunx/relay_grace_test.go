package tunx

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// blockingConn 是"永远读不到东西"的连接：
// Read 阻塞到 Close 为止，Write 正常丢弃，且**不实现** CloseWrite。
//
// 后者是关键：hysteria2 的流就是这个形状（vendor 里 client.tcpConn 只有 Close）。
// 于是 closeWrite 那次类型断言会静默落空，对端收不到 FIN。
type blockingConn struct {
	closed chan struct{}
	once   sync.Once
}

func newBlockingConn() *blockingConn {
	return &blockingConn{closed: make(chan struct{})}
}

func (c *blockingConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, io.EOF
}

func (c *blockingConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *blockingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingConn) LocalAddr() net.Addr              { return tunnelAddr("local") }
func (c *blockingConn) RemoteAddr() net.Addr             { return tunnelAddr("remote") }
func (c *blockingConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingConn) SetWriteDeadline(time.Time) error { return nil }

type tunnelAddr string

func (a tunnelAddr) Network() string { return "test" }
func (a tunnelAddr) String() string  { return string(a) }

// eofConn 立刻回 EOF，模拟"应用发了 FIN"。
type eofConn struct {
	*blockingConn
}

func newEOFConn() *eofConn { return &eofConn{blockingConn: newBlockingConn()} }

func (c *eofConn) Read([]byte) (int, error) { return 0, io.EOF }

// TestRelayGivesUpAfterOneSideHalfCloses 锁住"对端不支持半关闭时不能永久挂着"。
//
// 现场形状：应用发了 FIN，服务端却要看到写侧关闭才回完数据。hysteria2 的流
// 没有 CloseWrite，closeWrite 落空 → 对端不收 FIN → 反方向那条 io.Copy
// 永远堵在 Read 上。它占着两个 goroutine、一条 QUIC 流、一条 gVisor 连接；
// 一条这样的连接就是一处泄漏，而且面板上看不出任何异常。
//
// 这条用例把 relay 的宽限压到很短来验：正常实现会在宽限后整条关掉。
func TestRelayGivesUpAfterOneSideHalfCloses(t *testing.T) {
	prev := tunRelayGrace
	tunRelayGrace = 80 * time.Millisecond
	t.Cleanup(func() { tunRelayGrace = prev })

	// 一侧立刻 EOF，另一侧永不返回、也不认半关闭。
	a := newEOFConn()
	// 用普通 net.Pipe 不行：它认 CloseWrite。这里要的就是"没有 CloseWrite"的形状。
	b := newBlockingConn()

	done := make(chan struct{})
	go func() {
		defer close(done)
		relay(a, b)
	}()

	select {
	case <-done:
		// 正常：宽限之后整条关掉。
	case <-time.After(3 * time.Second):
		t.Fatal("一侧已经 EOF，中继却一直没退出——对端不认半关闭时会泄漏整条连接")
	}
}

// TestRelayPropagatesCloseWriteThroughIdleConn 锁住 idleConn 的半关闭透传。
//
// idleConn 是 relay 里包在连接外面的那层。它不透传 CloseWrite 的话，
// closeWrite 的类型断言会**对所有连接**落空——包括底层本来支持半关闭的
// *tls.Conn（trojan 走的就是它）。后果是 trojan 那条正常通路也退化成
// "等宽限再硬关"，下载被截断。
func TestRelayPropagatesCloseWriteThroughIdleConn(t *testing.T) {
	// 一个真正支持半关闭的假连接。
	cw := &closeWriteProbe{blockingConn: newBlockingConn()}
	wrapped := newIdleConn(cw, time.Minute)

	closeWrite(wrapped)
	if !cw.closed {
		t.Fatal("idleConn 没有把 CloseWrite 透传给底层——trojan(tls.Conn) 的半关闭会失效")
	}
}

type closeWriteProbe struct {
	*blockingConn
	closed bool
}

func (c *closeWriteProbe) CloseWrite() error {
	c.closed = true
	return nil
}
