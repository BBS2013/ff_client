package outbound

import (
	"context"
	"errors"
	"io"
	"net"

	"sync"
	"testing"
	"time"
	"wps_app/internal/config"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
)

// scriptedUDP 是 HyUDPConn 的可编程实现，用来驱动 hysteriaUDPConn 的各条分支。
type scriptedUDP struct {
	in     chan udpMsg
	sendMu sync.Mutex
	sent   []string

	sendErr error
	closed  bool
	closeCh chan struct{}
}

type udpMsg struct {
	data []byte
	addr string
}

func newScriptedUDP() *scriptedUDP {
	return &scriptedUDP{in: make(chan udpMsg, 8), closeCh: make(chan struct{})}
}

func (s *scriptedUDP) Receive() ([]byte, string, error) {
	select {
	case m, ok := <-s.in:
		if !ok {
			return nil, "", io.EOF
		}
		return m.data, m.addr, nil
	case <-s.closeCh:
		return nil, "", io.EOF
	}
}

// Send 复刻库里的真实约束：共用一块发送缓冲区，并发调用会互相踩。
// 这里用同一把锁把调用串起来，好让并发用例能真的验出我们加了这把锁。
func (s *scriptedUDP) Send(b []byte, addr string) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, addr)
	return nil
}

func (s *scriptedUDP) Close() error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if !s.closed {
		s.closed = true
		close(s.closeCh)
	}
	return nil
}

func (s *scriptedUDP) feed(data, addr string) { s.in <- udpMsg{data: []byte(data), addr: addr} }

// udpCapableClient 是一个「服务端开了 UDP」的假客户端。
type udpCapableClient struct {
	fakeClient
	conn *scriptedUDP
}

func (c *udpCapableClient) UDP() (client.HyUDPConn, error) { return c.conn, nil }

// refusingUDPClient 模拟服务端拒绝建立会话，库同样报 DialError。
type refusingUDPClient struct{ fakeClient }

func (c *refusingUDPClient) UDP() (client.HyUDPConn, error) {
	return nil, coreErrs.DialError{Message: "connection refused"}
}

// udpDisabledClient 复刻库里 UDP() 的第一个分支：服务端没开 UDP。
type udpDisabledClient struct{ fakeClient }

func (c *udpDisabledClient) UDP() (client.HyUDPConn, error) {
	return nil, coreErrs.DialError{Message: udpNotEnabledMsg}
}

func TestHysteriaDialUDPRefusesWhenServerHasNoUDP(t *testing.T) {
	h := attached(&udpDisabledClient{})
	before := UDPSessions()
	_, err := h.DialUDP(context.Background())
	if !errors.Is(err, ErrNoUDP) {
		t.Fatalf("err = %v, want ErrNoUDP", err)
	}
	if after := UDPSessions(); after != before {
		t.Fatalf("会话计数没有归还: %d -> %d", before, after)
	}
}

func TestHysteriaDialUDPDoesNotSwallowUnrelatedError(t *testing.T) {
	// fakeClient.UDP() 报的是一个与「不支持 UDP」无关的普通错误。
	// 把它也归到 ErrNoUDP 就会对着一个真故障说「这条路本来就不通」，
	// 于是故障切换连它都不记，用户只看到一句去哪儿都对不上的拒绝。
	h := attached(&fakeClient{})
	_, err := h.DialUDP(context.Background())
	if errors.Is(err, ErrNoUDP) {
		t.Fatalf("无关错误被误报成协议不支持: %v", err)
	}
}

func TestHysteriaDialUDPRejectsTargetRefusalAsNoUDP(t *testing.T) {
	h := attached(&refusingUDPClient{})
	before := UDPSessions()
	_, err := h.DialUDP(context.Background())
	if !errors.Is(err, ErrNoUDP) {
		t.Fatalf("err = %v, want ErrNoUDP", err)
	}
	if after := UDPSessions(); after != before {
		t.Fatalf("会话计数没有归还: %d -> %d", before, after)
	}
}

func TestHysteriaDialUDPDoesNotLeakSessionWhenTunnelFails(t *testing.T) {
	h := &Hysteria{handshakeTO: 10 * time.Millisecond}
	before := UDPSessions()
	_, err := h.DialUDP(context.Background())
	if err == nil {
		t.Fatal("隧道拨不通却开出了 UDP 会话")
	}
	if errors.Is(err, ErrNoUDP) {
		t.Fatalf("握手失败被误报成协议不支持: %v", err)
	}
	if after := UDPSessions(); after != before {
		t.Fatalf("会话计数泄漏: %d -> %d", before, after)
	}
}

func TestHysteriaUDPConnCarriesAddrBothWays(t *testing.T) {
	su := newScriptedUDP()
	cli := &fakeClient{}
	h := attached(cli)
	u := &hysteriaUDPConn{conn: su, h: h, gen: cli}

	if err := u.WriteTo([]byte("ping"), "1.2.3.4:443"); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	su.feed("pong", "1.2.3.4:443")
	buf := make([]byte, 64)
	n, from, err := u.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "pong" {
		t.Fatalf("读到 %q", buf[:n])
	}
	if from != "1.2.3.4:443" {
		t.Fatalf("来源 = %q", from)
	}
	if su.sent[0] != "1.2.3.4:443" {
		t.Fatalf("发出目标 = %q", su.sent[0])
	}
}

func TestHysteriaUDPConnOwnCloseDoesNotInvalidateTunnel(t *testing.T) {
	su := newScriptedUDP()
	cli := &fakeClient{}
	h := attached(cli)
	u := &hysteriaUDPConn{conn: su, h: h, gen: cli}

	if err := u.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, err := u.ReadFrom(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Close 后 ReadFrom err = %v, want EOF", err)
	}
	// 自己收的尾不是隧道故障：共享连接必须留着。
	if h.cli != cli {
		t.Fatal("自己关掉会话却让共享隧道失效了")
	}
	if n := cli.closed.Load(); n != 0 {
		t.Fatalf("共享客户端被关闭 %d 次", n)
	}
}

func TestHysteriaUDPConnTunnelDeathInvalidates(t *testing.T) {
	su := newScriptedUDP()
	cli := &fakeClient{}
	h := attached(cli)
	u := &hysteriaUDPConn{conn: su, h: h, gen: cli}

	// 隧道断了：库会挨个关掉每条会话，于是 Receive 返回 EOF 而我们并未关过它。
	close(su.closeCh)
	if _, _, err := u.ReadFrom(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want EOF", err)
	}
	if h.cli != nil {
		t.Fatal("隧道已死却没有丢弃共享连接，后续流量会一直挂在死连接上")
	}
	if n := cli.closed.Load(); n != 1 {
		t.Fatalf("共享客户端被关闭 %d 次, want 1", n)
	}
}

func TestHysteriaUDPConnReportsTunnelDeathOnce(t *testing.T) {
	su := newScriptedUDP()
	cli := &fakeClient{}
	h := attached(cli)
	u := &hysteriaUDPConn{conn: su, h: h, gen: cli}

	close(su.closeCh)
	for i := 0; i < 3; i++ {
		_, _, _ = u.ReadFrom(make([]byte, 8))
	}
	if n := cli.closed.Load(); n != 1 {
		t.Fatalf("共享客户端被关闭 %d 次, want 1", n)
	}

	// 紧接着重连上了新的隧道。旧会话迟到的 EOF 若不加代次判断，
	// 会把刚建好的新隧道再拆一次——一次关联故障就此滚成持续重连。
	fresh := &fakeClient{}
	h.cli = fresh
	for i := 0; i < 3; i++ {
		_, _, _ = u.ReadFrom(make([]byte, 8))
	}
	if h.cli != fresh {
		t.Fatal("旧会话的迟到 EOF 拆掉了新一代隧道")
	}
}

func TestHysteriaUDPConnRejectsWriteAfterClose(t *testing.T) {
	su := newScriptedUDP()
	cli := &fakeClient{}
	h := attached(cli)
	u := &hysteriaUDPConn{conn: su, h: h, gen: cli}

	_ = u.Close()
	if err := u.WriteTo([]byte("x"), "1.2.3.4:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close 后 WriteTo err = %v, want net.ErrClosed", err)
	}
}

func TestHysteriaUDPConnSerializesConcurrentSends(t *testing.T) {
	su := newScriptedUDP()
	cli := &fakeClient{}
	h := attached(cli)
	u := &hysteriaUDPConn{conn: su, h: h, gen: cli}

	const n = 64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := u.WriteTo([]byte("x"), "1.2.3.4:443"); err != nil {
				t.Errorf("WriteTo: %v", err)
			}
		}()
	}
	wg.Wait()
	// 少一个就说明并发把共享发送缓冲区踩了：库那边只会安静地少发一包。
	su.sendMu.Lock()
	got := len(su.sent)
	su.sendMu.Unlock()
	if got != n {
		t.Fatalf("发出 %d/%d 包", got, n)
	}
}

func TestHysteriaUDPConnCountsSessionOnlyWhileOpen(t *testing.T) {
	before := UDPSessions()
	h := attached(&udpCapableClient{conn: newScriptedUDP()})
	pc, err := h.DialUDP(context.Background())
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	if got := UDPSessions(); got != before+1 {
		t.Fatalf("会话数 = %d, want %d", got, before+1)
	}
	if err := pc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := UDPSessions(); got != before {
		t.Fatalf("关闭后会话数 = %d, want %d", got, before)
	}
	// Close 必须幂等：重复关闭会把全局计数减到负数去，把上限提前吃光。
	if err := pc.Close(); err != nil {
		t.Fatalf("重复 Close: %v", err)
	}
	if got := UDPSessions(); got != before {
		t.Fatalf("重复关闭后会话数 = %d, want %d", got, before)
	}
}

func TestDialUDPFallsBackWhenDialerHasNoPacketDialer(t *testing.T) {
	_, err := DialUDP(context.Background(), plainDialer{})
	if !errors.Is(err, ErrNoUDP) {
		t.Fatalf("err = %v, want ErrNoUDP", err)
	}
}

func TestErrUDPRefusedIsClassifiable(t *testing.T) {
	// 故障切换靠 errors.Is 把它摘出去，不能只靠文本。
	if !errors.Is(errUDPRefused("trojan 节点"), ErrNoUDP) {
		t.Fatal("协议级拒绝没有被归到 ErrNoUDP")
	}
}

func TestTrojanAndDirectRefuseUDPWithReason(t *testing.T) {
	tr := mustTrojan(t, config.ServerConfig{
		Type: config.ProtocolTrojan, Addr: "127.0.0.1:443", Auth: "x",
		TLS: config.TLSConfig{SNI: "example.com"},
	})
	if _, err := tr.DialUDP(context.Background()); !errors.Is(err, ErrNoUDP) {
		t.Fatalf("trojan: err = %v, want ErrNoUDP", err)
	}
	if _, err := NewDirect(time.Second).DialUDP(context.Background()); !errors.Is(err, ErrNoUDP) {
		t.Fatalf("direct: err = %v, want ErrNoUDP", err)
	}
}
