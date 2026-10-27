package service

// 一条被拦的连接，从入站到面板读数得一路都在。
//
// registry 那边的单测是自己调 Begin/End，等于假设了「入站真的会为一次拦截去登记一笔」。
// 这一条走真实 SOCKS5 请求，把 入站 → 判定 → 静默丢弃 → 登记 → 投影 串起来验一次：
// 缺任何一环都会红，而每一环单独看都可能是好的。

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// TestBlockedTrafficReachesPanel 撞一次名单，要求三处同时看得到：
// 累计计数、最近留痕、连接表里那一行——外加客户端确实什么应答都没收到。
func TestBlockedTrafficReachesPanel(t *testing.T) {
	cfgPath := newTestConfigWithBlock(t, []string{"ads.example.com"})
	svc := New(cfgPath, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop()

	conn := socksConnect(t, svc, "ads.example.com", 443)
	defer conn.Close()

	// 静默丢弃的语义：不回失败应答、不回 502、也不主动 FIN。
	// 客户端这里必须只能等到超时——读到任何字节（连 EOF 都算）都说明语义变了。
	_ = conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	b := make([]byte, 32)
	n, err := conn.Read(b)
	if err == nil {
		t.Fatalf("被拦的连接竟然收到 %d 字节应答：%v", n, b[:n])
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("期望超时（客户端什么都收不到），实得 %v (%T)", err, err)
	}

	// 计数在登记那一刻就该动，不等这条连接收尾（它还压在 BlockHold 里）。
	snap := svc.Metrics().Snapshot()
	if snap.TotalBlocked != 1 {
		t.Fatalf("累计拦截 = %d, 期望 1", snap.TotalBlocked)
	}

	idx := -1
	for i, c := range snap.Active {
		if strings.Contains(c.Host, "ads.example.com") {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatalf("连接表里没有这一条：%+v", snap.Active)
	}
	row := snap.Active[idx]
	if row.Outbound != "REJECT" || row.Policy != "REJECT" {
		t.Fatalf("被拦的连接被记成别的走向：policy=%q outbound=%q", row.Policy, row.Outbound)
	}
	if row.Up != 0 || row.Down != 0 {
		t.Fatalf("拦截应当一个字节都不搬，实得 up=%d down=%d", row.Up, row.Down)
	}
	if !strings.Contains(row.Matched, "REJECT") {
		t.Fatalf("命中规则没记上：%q", row.Matched)
	}

	if len(snap.RecentBlocked) != 1 {
		t.Fatalf("最近留痕 = %d 条, 期望 1: %+v", len(snap.RecentBlocked), snap.RecentBlocked)
	}
	hit := snap.RecentBlocked[0]
	if !strings.Contains(hit.Host, "ads.example.com") || hit.Count != 1 || hit.LastAt == 0 {
		t.Fatalf("留痕内容不对：%+v", hit)
	}
	if !strings.Contains(hit.Rule, "REJECT") {
		t.Fatalf("留痕没写是哪条规则拦的：%q", hit.Rule)
	}
	// 连接表与留痕必须指向同一条规则：两处说法不一，用户就不知道该信哪个。
	if hit.Rule != row.Matched {
		t.Fatalf("留痕与连接表的命中规则不一致：留痕 %q / 表里 %q", hit.Rule, row.Matched)
	}
}

// socksConnect 发一条真实的 SOCKS5 CONNECT（无认证），返回刚发出请求的连接。
// 只走到"发出请求"为止：有没有应答、什么时候有，由调用方按各自的断言去读。
func socksConnect(t *testing.T, svc *Service, host string, port int) net.Conn {
	t.Helper()
	p := portOf(t, svc.Snapshot(), "socks5")
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 3*time.Second)
	if err != nil {
		t.Fatalf("连 SOCKS5 入站: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("读方法协商: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	return conn
}
