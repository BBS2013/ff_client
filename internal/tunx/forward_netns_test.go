//go:build linux

package tunx

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// 这一组验的是那句验收清单里的「TCP/UDP 转发」：
// 一个真的包从内核里的一台 socket 出发，落进真的 tun 网卡，被真的 gVisor 协议栈
// 收下来、按规则判定、再从物理侧发出去，回程同理。
//
// 为什么前面那些测试还不算数：数据面那几组（block_relay_test.go / udp_test.go）
// 用普通 socket 顶替了协议栈那一端——它们验的是转发逻辑与收发方向，
// 「包真能穿过网卡与栈的接缝」这一条从来没被跑过。
// 而这个接缝恰恰是最容易坏又最难看见的一段：fd 交接、IFF_NO_PI 与
// EthernetHeader=false 是否相配、假 IP 路由有没有真装进内核，
// 任何一个错了表现都一样——面板显示已启用，浏览器却什么都打不开。
//
// 开关同其它 netns 用例（WPS_FW=1，见 make test-netns-fw）。
//
// TCP 与 UDP 各验两个方向：搬得动的（回声原样回来）与搬不动的
// （直连出站明确拒绝 UDP）。后者同样重要——UDP 没有能力把「拒绝」告诉应用，
// 如果本机连接表里也不留一行，用户手上就什么都没有。

// echoTCP 起一个"收一行回一行"的服务端，返回它的地址与关闭函数。
func echoTCP(t *testing.T, addr string) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("起 TCP 回声服务失败: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				for {
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					n, err := c.Read(buf)
					if n > 0 {
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// echoUDP 是同一件事的 UDP 版：一个包进、一个包出。
func echoUDP(t *testing.T, addr string) (string, func()) {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("起 UDP 回声服务失败: %v", err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, peer, rerr := c.ReadFromUDP(buf)
			if n > 0 && rerr == nil {
				_, _ = c.WriteTo(buf[:n], peer)
			}
			if rerr != nil {
				return
			}
		}
	}()
	return c.LocalAddr().String(), func() { _ = c.Close() }
}

// startNetnsTUN 在 netns 里把整套真东西立起来：网卡、协议栈、路由。
//
// 刻意关掉 DNS 劫持与 strict_route：这一组要量的是「包穿过网卡与栈的接缝」，
// 那两个开关各自有自己的用例，混进来只会让失败说不清是谁。
//
// 规则模式是显式设的，不是默认的——这三条用例的结论都挂在"命中了哪条规则、
// 落进哪个出站"上（直连拒 UDP / 代理位带得动 UDP），用默认模式的话
// 失败原因会被模式盖住。
func startNetnsTUN(t *testing.T, ctx context.Context, proxy outbound.Dialer) *TUN {
	t.Helper()
	off := false
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.StrictRoute = false
	conf.HijackDNS = &off
	conf.IPv6 = &off

	direct := outbound.NewDirect(5 * time.Second)
	if proxy == nil {
		// 代理位也放一只直连：走 FINAL,DIRECT 的用例永远不该碰代理位，
		// 但 NewSet 要两个出站——给个能用的，别留 nil 让"万一命错了规则"变成空指针。
		proxy = direct
	}
	rt := router.New(mustEngine(t), outbound.NewSet(direct, proxy), 5*time.Second)
	rt.SetMode(config.ModeRule)
	// Runner 必须是 ExecRunner：这条用例要的就是"路由真的装进内核、
	// 包真的从网卡过一遍"。换成记录型替身，测的就只是命令的字符串了。
	tun, err := New(Options{
		Conf:      conf,
		Router:    rt,
		Runner:    ExecRunner{},
		Reg:       metrics.NewRegistry(50, 0),
		Upstreams: []string{"223.5.5.5"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tun.Start(ctx); err != nil {
		t.Fatalf("在 netns 里启用 TUN 失败: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer scancel()
		_ = tun.Stop(sctx)
	})
	return tun
}

func TestNetnsForwardsTCPThroughRealTUN(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := ExecRunner{}
	fwEnsureNIC(t, ctx, r)

	srvAddr, closeSrv := echoTCP(t, "10.60.0.1:0")
	defer closeSrv()
	host, portStr, err := net.SplitHostPort(srvAddr)
	if err != nil {
		t.Fatal(err)
	}

	tun := startNetnsTUN(t, ctx, nil)
	// 假 IP 的反查值直接写成真地址：这条路径要验的是转发，
	// 域名解析在 DNS 那组用例里已经单独验过了，中间少一环就少一处歧义。
	fake, err := tun.fake.Allocate(host)
	if err != nil {
		t.Fatalf("分配假 IP: %v", err)
	}

	c, err := net.DialTimeout("tcp", net.JoinHostPort(fake.String(), portStr), 10*time.Second)
	if err != nil {
		t.Fatalf("连假 IP 失败（包没能穿过内核→网卡→协议栈→直连出站这条链）: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("through-the-tun")); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "through-the-tun" {
		t.Fatalf("回声没原样回来: n=%d err=%v got=%q", n, err, string(buf[:n]))
	}

	// 连接表与字节必须也看见这一条：面板上"有哪些连接"与"搬了多少字节"
	// 说的必须是同一批真实存在的流量。
	// 先关连接再对账——TotalConns 是收尾时才累加的，连接还开着的时候它是 0，
	// 那条断言会红得莫名其妙。
	_ = c.Close()
	var snap metrics.Snapshot
	if !waitSome(5*time.Second, func() bool {
		snap = tun.reg.Snapshot()
		return snap.TotalConns > 0
	}) {
		t.Fatalf("转发成功了，连接账上却一条都没有：%+v", snap)
	}
	var seen bool
	for _, row := range snap.ByRule {
		if row.Conns > 0 && row.Up+row.Down > 0 {
			seen = true
		}
	}
	if !seen {
		t.Errorf("转发的字节没进按规则的账：%+v", snap.ByRule)
	}
}

// TestNetnsForwardsUDPThroughRealTUN 验 UDP 真的穿过网卡与栈的接缝：
// 报文从内核 socket 出发 → 落进真的 tun → gVisor 收下 → 按域名命中 PROXY →
// 交给一只带得动 UDP 的出站 → 回包原路送回应用 socket。
//
// 出站用的是替身（echoPacketOutbound）而不是真的 hysteria2 节点：
// 这一条要量的是网卡与栈那一段，隧道协议自己那一段在 outbound 包里另有对应用例。
// 真节点的隧道实测是 make acceptance-tun 的活，网络命名空间里没有节点可连。
func TestNetnsForwardsUDPThroughRealTUN(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := ExecRunner{}
	fwEnsureNIC(t, ctx, r)

	srvAddr, closeSrv := echoUDP(t, "127.0.0.1:0")
	defer closeSrv()
	_, portStr, err := net.SplitHostPort(srvAddr)
	if err != nil {
		t.Fatal(err)
	}

	tun := startNetnsTUN(t, ctx, &echoPacketOutbound{name: "NODE", upstream: srvAddr})
	// 这里必须给**域名**分配假 IP：规则集认的是域名，
	// 换成真 IP 就命中不了 DOMAIN-SUFFIX，也就永远走不到代理位。
	fake, err := tun.fake.Allocate("a.example.com")
	if err != nil {
		t.Fatalf("分配假 IP: %v", err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(fake.String(), portStr))
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("udp-through-the-tun")); err != nil {
		t.Fatalf("写失败: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "udp-through-the-tun" {
		t.Fatalf("UDP 回声没原样回来: n=%d err=%v got=%q", n, err, string(buf[:n]))
	}
	// 记账同样要看见这一条：QUIC 这类纯 UDP 应用如果不在表里，
	// 面板上的量就会在一台跑得满是 QUIC 的机器上莫名其妙地平着。
	//
	// 预算给到 15 秒而不是 5 秒，这不是随手放宽：这一条的收尾时刻是**算得出来的**——
	// 替身的 ReadFrom 有 3 秒读截止，先结束的那一路把 pump 叫醒，
	// pump 再按 2 秒等另一方向收尾（QUIC 关掉时本地可能还有包在路上），
	// 于是这一条大约在 5 秒整才进 TotalConns。原来给 5 秒等于把断言压在边界上：
	// 单跑恰好赶上，全套一起跑就翻车（真翻过一次，Active 里那条停在 Duration:5000）。
	var snap metrics.Snapshot
	if !waitSome(15*time.Second, func() bool {
		snap = tun.reg.Snapshot()
		return snap.TotalConns > 0
	}) {
		t.Fatalf("UDP 转发成功了，连接账上却一条都没有：%+v", snap)
	}
	var host string
	for _, row := range append(append([]metrics.ConnView(nil), snap.Active...), snap.History...) {
		if row.Up+row.Down > 0 {
			host = row.Host
		}
	}
	if host != "a.example.com" {
		t.Errorf("连接行记的目标 = %q，应当是反查出来的域名（假 IP 对使用者没有意义）", host)
	}
}

// TestNetnsUDPOnDirectEgressReportsWhy 是另一半：判成直连的 UDP 谁都带不动
// （DIRECT 出站明确拒绝 UDP，见 internal/outbound/direct.go），
// 这时候必须**立刻**在连接表留下带原因的一行，而不是让应用干等到超时、
// 而本机这一侧一句都不说。
//
// 为什么单独写一条 netns 用例：拒绝本身在 udp_test.go 里有守卫，
// 但"应用侧什么都收不到 + 表里有原因"这个组合只有在真的包进 tun 之后才成立——
// 之前这里只有日志，界面上是空白的，而这恰恰是最需要那一行的时候。
func TestNetnsUDPOnDirectEgressReportsWhy(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := ExecRunner{}
	fwEnsureNIC(t, ctx, r)

	srvAddr, closeSrv := echoUDP(t, "10.60.0.1:0")
	defer closeSrv()
	host, portStr, err := net.SplitHostPort(srvAddr)
	if err != nil {
		t.Fatal(err)
	}

	// 代理位留空 → 换成直连：这条用例要的就是"判成直连"，
	// 而规则集里没写过的域名正是落到 FINAL,DIRECT 的那个形状。
	tun := startNetnsTUN(t, ctx, nil)
	fake, err := tun.fake.Allocate(host)
	if err != nil {
		t.Fatalf("分配假 IP: %v", err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(fake.String(), portStr))
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()
	sent := time.Now()
	if _, err := c.Write([]byte("udp-egress")); err != nil {
		t.Fatalf("写失败: %v", err)
	}

	// 应用侧：什么都收不到。UDP 没有"拒绝"这个表达方式，超时是它唯一的答复。
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	if n, _, rerr := c.ReadFrom(buf); rerr == nil {
		t.Fatalf("直连本该拒掉这条 UDP，却搬回来了 %d 字节：%q", n, string(buf[:n]))
	}

	// 本机侧：表里必须有原因，而且是"很快就到"——
	// 等到 30s 拨号超时才出现的那一行，与根本没有这一行没有区别。
	var row metrics.ConnView
	deadline := sent.Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snap := tun.reg.Snapshot()
		for _, h := range append(append([]metrics.ConnView(nil), snap.Active...), snap.History...) {
			if h.Err != "" {
				row = h
			}
		}
		if row.ID != 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if row.ID == 0 {
		t.Fatal("直连拒掉的 UDP 在连接表里没有留下任何痕迹（用户手上就什么都没有）")
	}
	if !strings.Contains(row.Err, "UDP") {
		t.Errorf("失败原因没说是 UDP 带不动: %q", row.Err)
	}
	if row.Host != host {
		t.Errorf("失败行指错了目标: %+v", row)
	}
	if row.Up+row.Down != 0 {
		t.Errorf("一条根本没建起来的关联不该有字节: %+v", row)
	}
	if snap := tun.reg.Snapshot(); snap.TotalFailed != 1 {
		t.Errorf("「拨不通」的计数 = %d, want 1", snap.TotalFailed)
	}
}

// TestNetnsStoppedTUNLeavesNoRouteIntoIt 停止之后，那条「假 IP 网段进 tun」的路由
// 必须跟着没了：留着它，之后所有发往假 IP 段的包会被送进一块已经不存在的网卡，
// 症状是某些站点突然全打不开，而面板上 TUN 明明显示已停止。
func TestNetnsStoppedTUNLeavesNoRouteIntoIt(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := ExecRunner{}
	fwEnsureNIC(t, ctx, r)

	tun := startNetnsTUN(t, ctx, nil)
	out, err := r.Run(ctx, Cmd{Bin: "ip", Args: []string{"-o", "route", "show", "198.18.0.0/15"}})
	if err != nil || !strings.Contains(out, "wps-tun") {
		t.Fatalf("前置：假 IP 网段该路由进 tun（out=%q err=%v）", out, err)
	}
	before, berr := r.Run(ctx, Cmd{Bin: "ip", Args: []string{"-o", "link", "show", "wps-tun"}})
	t.Logf("Stop 之前网卡状态: out=%q err=%v", before, berr)
	t.Logf("Stop 之前 running=%v", tun.Status().Running)
	if err := tun.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// 网卡没了，挂在它上面的路由会被内核一起收走；这里要的是"确实没有了"，
	// 而不是"我们发过删除命令"。
	out, _ = r.Run(ctx, Cmd{Bin: "ip", Args: []string{"-o", "route", "show", "table", "main", "198.18.0.0/15"}})
	if strings.Contains(out, "wps-tun") {
		t.Errorf("停止之后假 IP 网段还路由向一块已经不存在的网卡:\n%s", out)
	}
}

// TestNetnsICMPIsAnsweredLocallyAndNeverCarried 把能力边界那句「ICMP 不走隧道、也不计入」
// 从一句声明改成实测——而实测的结果把这句声明修正了一半。
//
// 为什么这条值得跑：全局接管之后，本机 ping 的 echo request 会顺着我们装的默认路由
// 落进 tun。协议栈注册了 ICMP（tun2socks 的 core 带上 gVisor 的默认 ICMP forwarder），
// 于是它对**任何**目的地址都直接回一个应答——ttl 64、亚毫秒。
// 实测的结论不是「ping 不通」，而是「ping 谁都能通，那个通是本地编出来的」：
// 它比不通更误导人，因为这是用户和脚本最常用来判断「网络好了没有」的信号。
// 同一件事在界面上不留任何痕迹：连接表空、字节不涨、也没有失败行。
// 这行边界必须照实写，所以这里用 A/B 把它钉住：接管前发不出去，接管后必回。
func TestNetnsICMPIsAnsweredLocallyAndNeverCarried(t *testing.T) {
	if !fwReady() || !netnsReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1 + 私有 netns）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if _, err := r.Run(ctx, Cmd{Bin: "ping", Args: []string{"-c", "1", "-W", "1", "127.0.0.1"}}); err != nil {
		t.Fatal("WPS_FW 开了却跑不了 ping：这条用例的证据全靠它，缺 iputils-ping 请装上，不能跳过")
	}
	fwEnsureNIC(t, ctx, r)
	fwMust(t, ctx, r, "ip", "route", "replace", "default", "via", restartGW, "dev", "fwphys0", "metric", "20600")

	// 两个目标：一个像真公网地址，一个是不该存在的 TEST-NET 地址。
	// 两个都回，就排除了「这张网里恰好有那么一台可达」的解释。
	const realTarget = "8.8.8.8"
	const bogusTarget = "203.0.113.9"
	pings := func(addr string) error {
		_, err := r.Run(ctx, Cmd{Bin: "ping", Args: []string{"-c", "1", "-W", "2", addr}})
		return err
	}

	// A 组（接管前）：默认路由在 dummy 网卡上，没有任何真实的出口，
	// 所以 ping 必须失败。这是 B 组那句「回了」的解释力的来源。
	for _, addr := range []string{realTarget, bogusTarget} {
		if pings(addr) == nil {
			t.Fatalf("接管之前 ping %s 就通了：这张网里根本不该有出口，A/B 的对照不成立", addr)
		}
	}

	tun := startHijackTUN(t, ctx, true, false)
	// 前提：此刻内核确实把 ICMP 交给了 tun（不是「大概会」，是路由查询的答案）。
	route := fwMust(t, ctx, r, "ip", "route", "get", realTarget)
	if !strings.Contains(route, " dev "+config.DefaultTUN().Device) {
		t.Fatalf("echo request 压根不会进 tun（%s），后面的对照无从谈起：\n%s", realTarget, route)
	}

	before := tun.reg.Snapshot()
	stBefore := tun.Status()
	for _, addr := range []string{realTarget, bogusTarget} {
		if err := pings(addr); err != nil {
			// 这条不是「失败」而是「行为变了」：如果哪天 ICMP 真的被丢弃了，
			// 上面那句关于面板与文案的结论要一起改，所以这里必须报出来。
			t.Errorf("ping %s 没回（%v）：协议栈不再本地应答 ICMP 了，README §0.3/§12 与设置页那行都得改", addr, err)
		}
	}
	after := tun.reg.Snapshot()
	stAfter := tun.Status()

	// 不计入：连接数与字节一动不动。这是「口径」的负面证据——
	// 面板上看不见 ICMP 不是统计漏了，而是它从来没进过转发逻辑。
	if after.TotalConns != before.TotalConns || after.TotalUp+after.TotalDown != before.TotalUp+before.TotalDown {
		t.Errorf("一条没被承载的 ICMP 却动了连接账：连接 %d→%d，字节 %d→%d",
			before.TotalConns, after.TotalConns, before.TotalUp+before.TotalDown, after.TotalUp+after.TotalDown)
	}
	// 也不该记成「拨不通」：那不是拨了没通，是我们压根没搬。
	if after.TotalFailed != before.TotalFailed {
		t.Errorf("ICMP 被记成了「拨不通的连接」（%d→%d），而它从没进过转发逻辑", before.TotalFailed, after.TotalFailed)
	}
	// 更不能被当成 DNS 查询吃掉：劫持只改 53 端口。
	if stAfter.DNSServed != stBefore.DNSServed || stAfter.DNSFailed != stBefore.DNSFailed {
		t.Errorf("一个 echo request 被当成 DNS 查询处理了：served %d→%d，failed %d→%d",
			stBefore.DNSServed, stAfter.DNSServed, stBefore.DNSFailed, stAfter.DNSFailed)
	}
}

// TestNetnsICMPv6IsAnsweredLocallyAndNeverCarried v6 那一族的同一件事。
//
// 边界声明写的是「ICMP 等非 TCP/UDP 流量」，两族都算数，所以 v4 那条的结论必须在 v6 上
// 再证一遍——而不是假定协议栈的行为跟着地址族一起继承。v6 还多一层风险：
// 邻居发现、路由通告同样是 ICMPv6，接管把它们吸进 tun 的后果与 v4 完全不同。
// 实测：与 v4 一致——echo request 进 tun，协议栈就地应答，一个字节都不计。
func TestNetnsICMPv6IsAnsweredLocallyAndNeverCarried(t *testing.T) {
	if !fwReady() || !netnsReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1 + 私有 netns）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := ExecRunner{}
	if out, err := r.Run(ctx, Cmd{Bin: "ping", Args: []string{"-6", "-c", "1", "-W", "1", "::1"}}); err != nil {
		t.Fatalf("这台机器的 ping 不认 -6（%v / %s）：v6 这半句证据没法跑", err, out)
	}
	fwEnsureNIC(t, ctx, r)
	fwMust(t, ctx, r, "ip", "route", "replace", "default", "via", restartGW, "dev", "fwphys0", "metric", "20600")
	fwMust(t, ctx, r, "ip", "-6", "route", "replace", "default", "via", "fe80::5", "dev", "fwphys0", "metric", "20600")

	ping6 := func(addr string) (string, error) {
		return r.Run(ctx, Cmd{Bin: "ping", Args: []string{"-6", "-c", "1", "-W", "2", addr}})
	}
	// 一个像真公网（Google DNS v6），一个是文档保留地址：两个都回，
	// 就排除了「这张网里恰好有那么一台可达」的解释。
	targets := []string{"2001:4860:4860::8888", "2001:db8::1"}
	for _, addr := range targets {
		if out, err := ping6(addr); err == nil {
			t.Fatalf("接管之前 ping6 %s 就通了，A/B 对照不成立：\n%s", addr, out)
		}
	}

	tun := startHijackTUN(t, ctx, true, true)
	st := tun.Status()
	// 前提一：面板说 v6 接管了，而且这说法来自内核，不是进程记忆。
	if !st.TakeoverV6 || st.TakeoverFrom != "kernel" {
		t.Fatalf("前置：v6 没被实测确认接管（v6=%v 来源=%s），后面的对照无从谈起", st.TakeoverV6, st.TakeoverFrom)
	}
	// 前提二：此刻内核确实把 v6 的 ICMP 交给了 tun（路由查询的答案，不是「大概会」）。
	route := fwMust(t, ctx, r, "ip", "-6", "route", "get", targets[0])
	if !strings.Contains(route, " dev "+config.DefaultTUN().Device) {
		t.Fatalf("echo request 压根不会进 tun（%s）：\n%s", targets[0], route)
	}

	before := tun.reg.Snapshot()
	stBefore := tun.Status()

	// 邻居发现吸不吸进去？这是 v6 才有的那一半问题：接管装的是**默认路由**，
	// 而 ND 用的是链路本地地址，命中的是物理网卡那条 metric 256 的直连路由。
	// 内核的答案必须是「还在 fwphys0 上」——否则接管会把本机自己的链路问断掉，
	// 症状是整个 v6 网络瘫，而面板只会显示"已接管"。
	// 组播同理（它走 local 表），顺带把 tun 自己那段也算清楚。
	for _, probe := range []struct{ addr, wantDev, why string }{
		{"fe80::5", "fwphys0", "v6 网关的邻居发现目标"},
		{"ff02::1", "fwphys0", "全节点组播"},
		{"fd00:1::2", config.DefaultTUN().Device, "隧道自己那段"},
	} {
		out := fwMust(t, ctx, r, "ip", "-6", "-o", "route", "get", probe.addr)
		if !strings.Contains(out, " dev "+probe.wantDev+" ") {
			t.Errorf("%s（%s）的路由查询落错了网卡，want %q:\n%s", probe.addr, probe.why, probe.wantDev, out)
		}
	}

	for _, addr := range targets {
		if out, err := ping6(addr); err != nil {
			// 与 v4 那条同构：这不是「测试失败」而是「行为变了」——
			// 如果哪天 v6 的 ICMP 真被丢弃了，README §0.3/§12 和设置页那句边界要一起改。
			t.Errorf("ping6 %s 没回（%v / %s）：协议栈不再本地应答 ICMPv6 了，README §0.3/§12 与设置页那行都得改",
				addr, err, strings.TrimSpace(out))
		}
	}
	after := tun.reg.Snapshot()
	stAfter := tun.Status()

	if after.TotalConns != before.TotalConns || after.TotalUp+after.TotalDown != before.TotalUp+before.TotalDown {
		t.Errorf("一条没被承载的 ICMPv6 却动了连接账：连接 %d→%d，字节 %d→%d",
			before.TotalConns, after.TotalConns, before.TotalUp+before.TotalDown, after.TotalUp+after.TotalDown)
	}
	if after.TotalFailed != before.TotalFailed {
		t.Errorf("ICMPv6 被记成了「拨不通的连接」（%d→%d），而它从没进过转发逻辑", before.TotalFailed, after.TotalFailed)
	}
	if stAfter.DNSServed != stBefore.DNSServed || stAfter.DNSFailed != stBefore.DNSFailed {
		t.Errorf("一个 v6 echo request 被当成 DNS 查询处理了：served %d→%d，failed %d→%d",
			stBefore.DNSServed, stAfter.DNSServed, stBefore.DNSFailed, stAfter.DNSFailed)
	}
}

// waitSome 给一个异步落账的动作一点时间再判定：连接的收尾是在协议栈销毁端点的
// 回调里做的，不是 Write 返回那一刻。
func waitSome(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}
