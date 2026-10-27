package router

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

// udpSpy 是带 UDP 能力的出站替身：记录自己被要求转发过什么。
type udpSpy struct {
	spyDialer
	dials    atomic.Int32
	noUDP    bool
	udpErr   error
	sessions int
}

func (d *udpSpy) DialUDP(context.Context) (outbound.PacketConn, error) {
	d.dials.Add(1)
	if d.noUDP {
		return nil, errors.New("dial udp: boom")
	}
	if d.udpErr != nil {
		return nil, d.udpErr
	}
	return &noopPacket{}, nil
}

type noopPacket struct{}

func (noopPacket) ReadFrom([]byte) (int, string, error) { return 0, "", nil }
func (noopPacket) WriteTo([]byte, string) error         { return nil }
func (noopPacket) Close() error                         { return nil }

// refuseUDP 是一个只肯拒绝的出站：它的 DialUDP 永远返回 ErrNoUDP。
type refuseUDP struct{ spyDialer }

func (d *refuseUDP) DialUDP(context.Context) (outbound.PacketConn, error) {
	return nil, fmt.Errorf("trojan 节点 承载不了 UDP: %w", outbound.ErrNoUDP)
}

func newUDPRouter(t *testing.T, body string, proxy outbound.Dialer) (*Router, *atomic.Int32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(path, nil, nil)
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	var faults atomic.Int32
	rt := New(eng, outbound.NewSet(&spyDialer{name: "DIRECT"}, proxy), 2*time.Second)
	rt.SetFaultObserver(func(string, outbound.Dialer, error) { faults.Add(1) })
	return rt, &faults
}

const udpRuleBook = "DOMAIN-SUFFIX,example.com,PROXY\nDOMAIN-SUFFIX,cn,DIRECT\nFINAL,DIRECT\n"

// TestDialUDPHostUsesSameDecisionAsDialHost 是 UDP 与 TCP 必须共用同一套判定的守卫。
// 两边一旦走偏，就会出现「同一个域名，TCP 走代理而 QUIC 直连」这种最难解释的现象。
func TestDialUDPHostUsesSameDecisionAsDialHost(t *testing.T) {
	proxy := &udpSpy{spyDialer: spyDialer{name: "PROXY"}}
	rt, _ := newUDPRouter(t, udpRuleBook, proxy)

	pc, res, err := rt.DialUDPHost(context.Background(), "198.18.0.7:443", "a.example.com")
	if err != nil {
		t.Fatalf("DialUDPHost: %v", err)
	}
	defer func() { _ = pc.Close() }()
	if res.Outbound != "PROXY" || res.Policy != outbound.PolicyProxy {
		t.Fatalf("决策 = %+v, want PROXY", res)
	}
	if proxy.dials.Load() != 1 {
		t.Fatalf("PROXY 会话数 = %d, want 1", proxy.dials.Load())
	}
	if proxy.last != "" {
		t.Fatalf("UDP 关联不该携带目标（报文自带地址），却拨了 %q", proxy.last)
	}

	// 直连判定的那一类必须真的落到 DIRECT 出站，而它会拒绝 UDP。
	if _, _, err := rt.DialUDPHost(context.Background(), "a.cn:443", ""); err == nil {
		t.Fatal("DIRECT 出站居然开出了 UDP 会话")
	}
}

func TestDialUDPHostRefusalIsNotANodeFault(t *testing.T) {
	proxy := &refuseUDP{spyDialer{name: "PROXY"}}
	rt, faults := newUDPRouter(t, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,PROXY\n", proxy)

	_, _, err := rt.DialUDPHost(context.Background(), "www.example.com:443", "")
	if err == nil {
		t.Fatal("不支持 UDP 的出站却开出了会话")
	}
	if !errors.Is(err, outbound.ErrNoUDP) {
		t.Fatalf("err = %v, 未保留 ErrNoUDP 判据", err)
	}
	// 「这条路本来就不通」被算成节点故障的话，一次正常的拒绝就能凑够
	// 故障切换的次数，把好好的节点切掉。
	if n := faults.Load(); n != 0 {
		t.Fatalf("协议不支持被记成 %d 次节点故障", n)
	}
}

func TestDialUDPHostReportsRealFailures(t *testing.T) {
	proxy := &udpSpy{spyDialer: spyDialer{name: "PROXY"}, udpErr: errors.New("handshake failed")}
	rt, faults := newUDPRouter(t, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,PROXY\n", proxy)

	if _, _, err := rt.DialUDPHost(context.Background(), "www.example.com:443", ""); err == nil {
		t.Fatal("隧道故障却开出了会话")
	}
	if n := faults.Load(); n != 1 {
		t.Fatalf("节点故障被记了 %d 次, want 1", n)
	}
}

func TestDialUDPHostRejectsBadAddress(t *testing.T) {
	rt, faults := newUDPRouter(t, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,PROXY\n", &udpSpy{spyDialer: spyDialer{name: "PROXY"}})
	if _, _, err := rt.DialUDPHost(context.Background(), "no-port", ""); err == nil {
		t.Fatal("地址形状不对却开出了会话")
	}
	if n := faults.Load(); n != 0 {
		t.Fatalf("请求本身就错，却记了 %d 次节点故障", n)
	}
}
