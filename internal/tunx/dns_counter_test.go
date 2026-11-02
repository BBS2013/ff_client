//go:build linux

package tunx

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// 这一组盯 DNS 的两个计数。
//
// 起因是一个会说反话的数字：面板上「已应答 DNS N 次」原来把回 SERVFAIL 的查询
// 也一起计进去了。上游全挂的时候那个数照样涨，而它唯一的用途是证明劫持在工作——
// 于是最需要看见「解析在失败」的那一刻，界面报的是「解析很健康」。
// 现在答上的与回失败的分开计，两条用例各守一半：
// Reply 必须把 SERVFAIL 说出来（以前只有一段报文字节，调用方无从分辨），
// 而计数必须落在正确的格子里，并且**上游回来之后能立刻恢复**。

// TestDNSReplyFlagsServfail 是"调用方能不能分辨"这一半。
func TestDNSReplyFlagsServfail(t *testing.T) {
	dec := stubDecider{mode: config.ModeDirect}
	broken := newDNSServer(t, dec, func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("上游炸了")
	})
	rep, err := broken.Reply(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatalf("回 SERVFAIL 是一条合法的应答，不该当成处理失败: %v", err)
	}
	if !rep.ServFail {
		t.Error("解析失败的那一条没标 ServFail——计数就还是瞎的")
	}
	if len(rep.Packet) == 0 {
		t.Fatal("没有报文")
	}
	// Serve 是同一个东西的"不关心 RCODE"版本：报文必须一模一样。
	// 这条等式是 wrapper 的全部职责，写歪了就是"两个入口答得不一样"。
	raw, err := broken.Serve(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != len(rep.Packet) {
		t.Errorf("Serve 与 Reply 答得不一样: %d vs %d 字节", len(raw), len(rep.Packet))
	}

	working := newDNSServer(t, dec, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	})
	rep, err = working.Reply(context.Background(), queryFor(t, "a.example.com", dnsmessage.TypeA))
	if err != nil {
		t.Fatal(err)
	}
	if rep.ServFail {
		t.Errorf("答上了却标成 ServFail: %v", rep)
	}
}

// dialBackFlow 造一条 tun 侧的 UDP 关联，它的 Write 就是"把应答送回应用"。
//
// 用 connected socket 而不是又一个 ListenUDP：serveUDPDNS 走的是 c.Write(b)，
// 没连对端的那种 socket 上这句会直接报错——那正是"接口形状对不上"的另一种写法，
// 而真实那条（gVisor 的端点）本来就是"知道对端是谁"的。
func dialBackFlow(t *testing.T, app *net.UDPConn, dst string, dstPort uint16) *tunUDPFlow {
	t.Helper()
	flow, err := net.DialUDP("udp", nil, app.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	t.Cleanup(func() { _ = flow.Close() })
	id := idFor(dst, dstPort, "127.0.0.1", uint16(app.LocalAddr().(*net.UDPAddr).Port))
	return &tunUDPFlow{UDPConn: flow, id: id}
}

// TestServeUDPDNSCountsFailureThenRecovers 是要的那句「可重复的恢复验证」：
// 上游一个都答不上时，本机必须看得见（计数进 dnsFailed，应用收到 SERVFAIL），
// 而**上游回来之后，同一个进程、同一个域名要立刻答得上**，
// 不需要重启、不留下被污染的缓存。
func TestServeUDPDNSCountsFailureThenRecovers(t *testing.T) {
	// 上游先是不通的：返回错误就是"所有上游都没答上"在这条路径上的形状。
	var up atomic.Bool
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.StrictRoute = false
	off := false
	conf.HijackDNS = &off
	conf.IPv6 = &off
	rt := router.New(mustEngine(t),
		outbound.NewSet(outbound.NewDirect(2*time.Second), outbound.NewDirect(2*time.Second)),
		2*time.Second)
	rt.SetMode(config.ModeRule)
	// baidu 不在 example.com 那条规则里，落到 FINAL,DIRECT → 走真解析这条路。
	// （判成 PROXY 的域名我们根本不做解析，那一档验不了上游。）
	tun, err := New(Options{
		Conf:   conf,
		Router: rt,
		Runner: &recordingRunner{},
		Lookup: func(context.Context, string) ([]netip.Addr, error) {
			if !up.Load() {
				return nil, errors.New("模拟上游无响应")
			}
			return []netip.Addr{netip.MustParseAddr("119.10.10.10")}, nil
		},
		Upstreams: []string{"223.5.5.5"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	app, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	flow := dialBackFlow(t, app, "172.19.0.2", 53)

	done := make(chan struct{})
	go func() {
		tun.serveUDPDNS(flow, "127.0.0.1:"+portOf(app))
		close(done)
	}()

	query := queryFor(t, "www.baidu.com", dnsmessage.TypeA)
	// 两次各带一个不同的 ID（头两字节就是 DNS 报文的事务 ID）：
	// 同一个 ID 的两次问答会让"收到的这条是哪一次"变成猜的。
	first := append([]byte(nil), query...)
	first[0], first[1] = 0x00, 0x11
	second := append([]byte(nil), query...)
	second[0], second[1] = 0x00, 0x22

	// ① 上游不通：应用收到 SERVFAIL，计数进"失败"那一格，
	// 并且"最近一次失败的时刻"落在刚才这一下上——界面上那句告警靠它判断
	// "现在还在失败"还是"这辈子失败过一次"。
	sent := time.Now()
	h := askDNS(t, app, flow, first, "第 1 次（上游不通）")
	if h.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("上游不通时应回 SERVFAIL，实际 RCode=%v", h.RCode)
	}
	if got := tun.Status(); got.DNSFailed != 1 || got.DNSServed != 0 {
		t.Fatalf("计数 = 已应答 %d / 失败 %d，want 0/1（把失败计成应答正是这次的病根）",
			got.DNSServed, got.DNSFailed)
	} else if got.DNSFailedAt < sent.UnixMilli() || got.DNSFailedAt > time.Now().UnixMilli() {
		t.Fatalf("最近失败时刻 = %d，不在刚才那一下的窗口里 [%d, %d]",
			got.DNSFailedAt, sent.UnixMilli(), time.Now().UnixMilli())
	}

	// ② 上游回来：同一个域名立刻答得出真 IP，失败那一格不再涨。
	up.Store(true)
	h = askDNS(t, app, flow, second, "第 2 次（上游恢复）")
	if h.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("上游恢复后仍回 RCode=%v —— 说明失败被缓存住了，只能重启才好", h.RCode)
	}
	if got := tun.Status(); got.DNSServed != 1 || got.DNSFailed != 1 {
		t.Fatalf("恢复后的计数 = 已应答 %d / 失败 %d，want 1/1", got.DNSServed, got.DNSFailed)
	}

	_ = flow.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveUDPDNS 没随关联关闭而收尾")
	}
}

// askDNS 发一条查询并读回应答头。
func askDNS(t *testing.T, app *net.UDPConn, flow *tunUDPFlow, query []byte, label string) dnsmessage.Header {
	t.Helper()
	if _, err := app.WriteToUDP(query, flow.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("%s 发包: %v", label, err)
	}
	_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 2048)
	n, _, err := app.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("%s 收包: %v", label, err)
	}
	h, _, _ := parseResponse(t, buf[:n])
	return h
}

func portOf(c net.Conn) string {
	_, p, err := net.SplitHostPort(c.LocalAddr().String())
	if err != nil {
		return "0"
	}
	return p
}
