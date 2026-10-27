package inbound

// 拨不通的连接也要在本机留一行。
//
// 这一格原来是个洞：被拦的连接由 block.go 记进注册表，而**拨号失败**的那条路
// 在 `Begin` 之前就 return 了，于是连接表里干干净净——用户点开这一页的原因
// 恰恰是"这个网站打不开"，结果这一页对"打不开"这件事一个字都不说。
// 日志里有（WARN 那一行），但没人会为了看一个网站去翻日志。

import (
	"net"
	"strings"
	"testing"
	"time"

	"wps_app/internal/metrics"
)

const proxyAllRules = "DOMAIN-SUFFIX,example.com,PROXY\nFINAL,DIRECT\n"

func TestFailedDialShowsUpInRegistry(t *testing.T) {
	reg := metrics.NewRegistry(16, 16)
	s := NewSOCKS5(newTestRouter(t, proxyAllRules), "", "", reg)
	addr := serve(t, func(ln net.Listener) { _ = s.Serve(ln) })

	c := dialProxy(t, addr)
	defer func() { _ = c.Close() }()
	socksGreeting(t, c, authNone)
	readSocksMethod(t, c)
	socksConnectRequest(t, c, cmdConnect, atypDomain, domainAddr("nowhere.example.com"), 443)
	// 这个测试里对端是坏的，SOCKS5 该回一个失败应答（与"被拦"那条刻意不回东西相反）：
	// 回不回是两件事，但**记不记**必须是同一件。
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _ = c.Read(make([]byte, 8))

	snap := reg.Snapshot()
	var found *metrics.ConnView
	for i := range snap.History {
		if snap.History[i].Err != "" {
			found = &snap.History[i]
		}
	}
	if found == nil {
		t.Fatalf("拨不通的连接在本机完全没有（active=%d history=%d）——"+
			"客户端只拿到一个失败应答，本机这一页却像什么都没发生", len(snap.Active), len(snap.History))
	}
	if !strings.Contains(found.Host, "nowhere.example.com") {
		t.Errorf("目标记错了: %+v", found)
	}
	if !strings.Contains(found.Err, "proxy unavailable") {
		t.Errorf("错误原文没带上，用户看不出是哪种失败: %q", found.Err)
	}
	if found.Up+found.Down != 0 {
		t.Errorf("一条没建起来的连接不该有字节: %+v", found)
	}
	if found.Matched == "" {
		t.Errorf("没记下它本来按哪条规则走: %+v", found)
	}
	if int(snap.TotalConns) != len(snap.History)+len(snap.Active) {
		t.Errorf("「累计连接」%d 与表里 %d 行对不上", snap.TotalConns, len(snap.History)+len(snap.Active))
	}
}
