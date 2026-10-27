package tunx

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/router"

	tunstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// tunUDPFlow 是一条 tun 侧 UDP 关联的替身。
//
// 数据面走真实的 socket，但用一对普通 UDP socket 顶替内核协议栈：
// 应用把包交给 tun 那一侧，tun 再写回应用那侧。方向与真实链路一致，
// 于是这条用例验的是真的收发，而不是把实现复述一遍。
type tunUDPFlow struct {
	*net.UDPConn
	id     tunstack.TransportEndpointID
	closed atomic.Bool
}

func (f *tunUDPFlow) ID() tunstack.TransportEndpointID { return f.id }

func (f *tunUDPFlow) Close() error {
	if f.closed.CompareAndSwap(false, true) {
		_ = f.UDPConn.Close()
	}
	return nil
}

// newTUNUDPFlow 造一条 tun 侧关联。返回的第一个是「应用」，它发包给 flow、
// 也从 flow 收包——真实链路里这两端就是同一个 socket。
//
// 源地址必须取应用 socket 真实的那个：pumpUDP 是按 endpoint ID 里的源口
// 写回的，用一个假源口的话回包会寄到一个没人 listen 的地址上。
func newTUNUDPFlow(t *testing.T, dst string, dstPort uint16) (*tunUDPFlow, *net.UDPConn) {
	t.Helper()
	app, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	ep, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = app.Close(); _ = ep.Close() })
	srcPort := uint16(app.LocalAddr().(*net.UDPAddr).Port)
	id := idFor(dst, dstPort, "127.0.0.1", srcPort)
	return &tunUDPFlow{UDPConn: ep, id: id}, app
}

// echoPacketOutbound 扮演「隧道那头的真实服务端」：它替客户端把域名解析掉，
// 于是「客户端只给域名、服务端去做解析」这个语义在测试里也成立。
type echoPacketOutbound struct {
	name     string
	upstream string
	dials    atomic.Int32

	mu   sync.Mutex
	sent []string
}

func (e *echoPacketOutbound) Name() string { return e.name }

func (e *echoPacketOutbound) DialContext(context.Context, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (e *echoPacketOutbound) Close() error { return nil }

func (e *echoPacketOutbound) DialUDP(context.Context) (outbound.PacketConn, error) {
	e.dials.Add(1)
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return nil, err
	}
	return &echoPacket{conn: pc, owner: e}, nil
}

func (e *echoPacketOutbound) sentAt(i int) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if i >= len(e.sent) {
		return ""
	}
	return e.sent[i]
}

type echoPacket struct {
	conn  *net.UDPConn
	owner *echoPacketOutbound
}

func (p *echoPacket) WriteTo(b []byte, addr string) error {
	p.owner.mu.Lock()
	p.owner.sent = append(p.owner.sent, addr)
	p.owner.mu.Unlock()
	ua, err := net.ResolveUDPAddr("udp", p.owner.upstream)
	if err != nil {
		return err
	}
	_, err = p.conn.WriteToUDP(b, ua)
	return err
}

func (p *echoPacket) ReadFrom(b []byte) (int, string, error) {
	if err := p.conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return 0, "", err
	}
	n, from, err := p.conn.ReadFromUDP(b)
	if err != nil {
		return 0, "", err
	}
	return n, from.String(), nil
}

func (p *echoPacket) Close() error { return p.conn.Close() }

// refusingUDPOutbound 明确拒绝 UDP，理由与 trojan 节点一模一样。
type refusingUDPOutbound struct{ name string }

func (r *refusingUDPOutbound) Name() string { return r.name }
func (r *refusingUDPOutbound) DialContext(context.Context, string) (net.Conn, error) {
	return nil, net.ErrClosed
}
func (r *refusingUDPOutbound) Close() error { return nil }
func (r *refusingUDPOutbound) DialUDP(ctx context.Context) (outbound.PacketConn, error) {
	return outbound.DialUDP(ctx, outbound.NewDirect(time.Second))
}

func newTUNForUDP(t *testing.T, proxy outbound.Dialer) *TUN {
	t.Helper()
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(2*time.Second), proxy), 2*time.Second)
	rt.SetMode(config.ModeRule)
	fake, err := NewFakeStore("198.18.0.0/15", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &TUN{
		conf: config.TUNConfig{Enable: true, Device: "wps-tun", FakeIPRange: "198.18.0.0/15"},
		rt:   rt,
		fake: fake,
	}
}

// startUDPEchoForTUN 起一个回显 UDP 服务，充当隧道对端。
func startUDPEchoForTUN(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := pc.WriteToUDP(buf[:n], from); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

// TestRelayUDPViaFakeIP 走通 TUN 的 UDP 主路径：应用发往假 IP → 反查域名 →
// 按域名决策 → 报文进隧道 → 回包写回应用的源口。
func TestRelayUDPViaFakeIP(t *testing.T) {
	upstream := startUDPEchoForTUN(t)
	proxy := &echoPacketOutbound{name: "PROXY", upstream: upstream}
	tr := newTUNForUDP(t, proxy)

	fake, err := tr.fake.Allocate("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	flow, app := newTUNUDPFlow(t, fake.String(), 443)

	dst, srcAddr := endpointFull(flow.id)
	done := make(chan struct{})
	go func() {
		tr.relayUDP(flow, dst, srcAddr, srcAddr.String())
		close(done)
	}()

	if _, err := app.WriteToUDP([]byte("hello quic"), flow.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("应用发包: %v", err)
	}
	_ = app.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := app.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("应用收包: %v", err)
	}
	if string(buf[:n]) != "hello quic" {
		t.Fatalf("搬错内容: %q", buf[:n])
	}
	// 交给隧道的是「域名 + 原端口」，语义与 TCP 路径一致：服务端自己做解析。
	if got := proxy.sentAt(0); got != "a.example.com:443" {
		t.Fatalf("转发目标 = %q, want a.example.com:443", got)
	}
	_ = flow.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("relayUDP 没随关联关闭而收尾")
	}
	if tr.active.Load() != 0 {
		t.Errorf("结束后计数没归零: %d", tr.active.Load())
	}
}

// TestRelayUDPFeedsTrafficTable 保证 UDP 关联也进流量表并统计两个方向的字节。
// 不统计的话面板上的速率图会在跑 QUIC 的机器上莫名其妙地平着，
// 而连接列表里也永远看不到那些「正在传数据」的关联。
func TestRelayUDPFeedsTrafficTable(t *testing.T) {
	upstream := startUDPEchoForTUN(t)
	proxy := &echoPacketOutbound{name: "PROXY", upstream: upstream}
	tr := newTUNForUDP(t, proxy)
	reg := metrics.NewRegistry(10, 0)
	tr.reg = reg

	fake, err := tr.fake.Allocate("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	flow, app := newTUNUDPFlow(t, fake.String(), 443)
	dst, srcAddr := endpointFull(flow.id)
	go tr.relayUDP(flow, dst, srcAddr, srcAddr.String())

	payload := []byte("0123456789")
	if _, err := app.WriteToUDP(payload, flow.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("应用发包: %v", err)
	}
	_ = app.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 2048)
	if _, _, err := app.ReadFromUDP(buf); err != nil {
		t.Fatalf("应用收包: %v", err)
	}

	active := reg.Snapshot().Active
	if len(active) != 1 {
		t.Fatalf("活跃连接 = %d 条, want 1", len(active))
	}
	// Host 记的是反查出来的域名而不是假 IP：面板上看到 198.18.x.x 对用户没有任何意义。
	if active[0].Inbound != "tun" || active[0].Host != "a.example.com" || active[0].Port != "443" {
		t.Fatalf("连接记录不对: %+v", active[0])
	}
	// 回包先到，所以两个方向此时都已经计过账。
	if active[0].Up != uint64(len(payload)) || active[0].Down != uint64(len(payload)) {
		t.Fatalf("上下行 = %d/%d, want %d/%d", active[0].Up, active[0].Down, len(payload), len(payload))
	}

	_ = flow.Close()
}

// TestRelayUDPRefusesUnknownFakeIP 是关键的安全边界：
// 假 IP 段内但反查不到域名的 UDP 必须就地拒绝，否则包会被拨出去又打回同一块 tun。
func TestRelayUDPRefusesUnknownFakeIP(t *testing.T) {
	proxy := &echoPacketOutbound{name: "PROXY", upstream: "127.0.0.1:1"}
	tr := newTUNForUDP(t, proxy)

	flow, _ := newTUNUDPFlow(t, "198.18.9.9", 443)
	dst, srcAddr := endpointFull(flow.id)
	tr.relayUDP(flow, dst, srcAddr, srcAddr.String())

	if proxy.dials.Load() != 0 {
		t.Fatalf("未知假 IP 被拨出去了，建立会话 %d 次", proxy.dials.Load())
	}
	if tr.active.Load() != 0 {
		t.Errorf("被拒的关联不该计入活跃: %d", tr.active.Load())
	}
}

// TestRelayUDPWhenOutboundRefusesEndsCleanly 是「明确拒绝」的守卫：
// 带不动的 UDP 必须立刻收尾并留下带原因的日志，而不是把应用挂在超时里。
func TestRelayUDPWhenOutboundRefusesEndsCleanly(t *testing.T) {
	tr := newTUNForUDP(t, &refusingUDPOutbound{name: "PROXY"})

	fake, err := tr.fake.Allocate("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	flow, _ := newTUNUDPFlow(t, fake.String(), 443)
	dst, srcAddr := endpointFull(flow.id)

	done := make(chan struct{})
	go func() {
		tr.relayUDP(flow, dst, srcAddr, srcAddr.String())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("被明确拒绝的 UDP 关联没有收尾")
	}
	if tr.active.Load() != 0 {
		t.Errorf("被拒的关联不该计入活跃: %d", tr.active.Load())
	}
}
