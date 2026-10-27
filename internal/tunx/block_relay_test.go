package tunx

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/metrics"
)

// TestRelayTCPBlockedHoldsSilently 被拦的连接要"挂着不回话"，而不是立刻关掉。
//
// 直接 return 会发 FIN：应用看到的是"连上就断了"，那是明确的重置信号，
// 和选定的"让它超时"语义正好相反。所以这里必须读到底或到上限才收。
func TestRelayTCPBlockedHoldsSilently(t *testing.T) {
	tr, proxy := newTUNForRelay(t, config.ModeRule)
	tr.blockedHold = 60 * time.Millisecond
	tr.rt.Engine().SetBlocklist([]string{"ads.example.com"})

	fake, err := tr.fake.Allocate("ads.example.com")
	if err != nil {
		t.Fatal(err)
	}
	app, peer := net.Pipe()
	conn := &pipeConn{Conn: app, id: idFor(fake.String(), 443, "10.180.56.140", 51000)}
	done := make(chan struct{})
	go func() { tr.relayTCP(conn); close(done) }()

	// 窗口内什么都没发生：没回数据，也没把连接关掉。
	_ = peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 32)
	n, rerr := peer.Read(buf)
	if n > 0 {
		t.Fatalf("被拦时不该回任何数据，收到 %q", buf[:n])
	}
	if !errors.Is(rerr, os.ErrDeadlineExceeded) {
		t.Fatalf("应当挂着（超时候），实际 %v", rerr)
	}

	// 到上限后必须收尾，否则一批广告连接会把 fd 占满。
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(peer, buf[:1]); err == nil {
		t.Fatal("到挂起上限后应被关闭")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relayTCP 没随连接收尾")
	}
	if proxy.last != "" {
		t.Errorf("拦截时不该拨号，却拨了 %q", proxy.last)
	}
}

// TestRelayTCPBlockedShowsUpInRegistry 应用侧收不到原因，本机连接表就得有这一条。
func TestRelayTCPBlockedShowsUpInRegistry(t *testing.T) {
	reg := metrics.NewRegistry(16, 16)
	tr, _ := newTUNForRelay(t, config.ModeRule)
	tr.reg = reg
	tr.blockedHold = 20 * time.Millisecond
	tr.rt.Engine().SetBlocklist([]string{"ads.example.com"})

	fake, err := tr.fake.Allocate("ads.example.com")
	if err != nil {
		t.Fatal(err)
	}
	app, peer := net.Pipe()
	conn := &pipeConn{Conn: app, id: idFor(fake.String(), 443, "10.180.56.140", 51000)}
	tr.relayTCP(conn)
	_ = peer.Close()

	snap := reg.Snapshot()
	all := append(append([]metrics.ConnView{}, snap.Active...), snap.History...)
	var found bool
	for _, c := range all {
		if c.Outbound == "REJECT" {
			found = true
			if c.Up+c.Down != 0 {
				t.Errorf("拦截不该有流量: up=%d down=%d", c.Up, c.Down)
			}
		}
	}
	if !found {
		t.Fatalf("tun 的拦截在本机连接表里看不见: %+v", all)
	}
}

// TestRelayTCPUnblockedStillProxies 反向对照：没被拦的照旧正常转发，
// 免得"静默丢弃"其实是把所有连接都丢掉了。
func TestRelayTCPUnblockedStillProxies(t *testing.T) {
	tr, proxy := newTUNForRelay(t, config.ModeRule)
	tr.blockedHold = 20 * time.Millisecond
	tr.rt.Engine().SetBlocklist([]string{"ads.example.com"})

	fake, err := tr.fake.Allocate("a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	app, peer := net.Pipe()
	conn := &pipeConn{Conn: app, id: idFor(fake.String(), 443, "10.180.56.140", 51000)}
	go tr.relayTCP(conn)

	if _, err := peer.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = peer.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := peer.Read(buf)
	if err != nil {
		t.Fatalf("未被拦的连接没通: %v", err)
	}
	if string(buf[:n]) != "hello" || proxy.last == "" {
		t.Fatalf("转发了错的东西: %q dial=%q", buf[:n], proxy.last)
	}
}
