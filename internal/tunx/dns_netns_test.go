//go:build linux

package tunx

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// 这一组把「DNS 劫持真的装上了、真的拆干净了」验到内核里。
//
// 为什么值得单独立一个文件：这条路径是本项目最狠的一类故障——
// 劫持规则残留是把本机**所有** :53 指向一个已经不存在的地址，
// 症状是「整机解析超时、看着像断网」，而网卡早就没了，没人能从界面上看出关联。
// 之前 teardown_test.go 只能验到「Down 列表里有那几条命令」，
// 命令写了但内核没删干净（比如 spec 与真实规则差一个 -m udp）是验不出来的。
//
// 开关同 killswitch_netns_test.go：WPS_FW=1（需要私有 netns 里把 /run 换成 tmpfs）。

// dnsNetnsPlan 是一份开着劫持、两族齐全的计划。网卡由测试自己造。
func dnsNetnsPlan(device string) RoutePlan {
	return RoutePlan{
		Device:       device,
		Address:      "172.19.0.1/30",
		DNS:          "172.19.0.2",
		FakeIPRange:  "198.18.0.0/15",
		Address6:     "fd00:1::1/64",
		DNS6:         "fd00:1::2",
		FakeIPRange6: "fc00::/18",
		MTU:          1500,
		HijackDNS:    true,
		Upstreams:    []string{"223.5.5.5", "2400:3200::1"},
	}
}

// dnsNetnsTUN 造一块真 tun 网卡，测试结束删掉。
func dnsNetnsTUN(t *testing.T, ctx context.Context, r Runner, device string) {
	t.Helper()
	out, err := r.Run(ctx, Cmd{Bin: "ip", Args: []string{"tuntap", "add", "dev", device, "mode", "tun"}})
	if err != nil && !strings.Contains(out, "File exists") {
		t.Skipf("建不了 tun 网卡（多半没有 /dev/net/tun）: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_, _ = r.Run(context.Background(), Cmd{Bin: "ip", Args: []string{"link", "del", device}})
	})
	// 网卡必须 up：`ip -6 route add <段> dev <网卡>` 在未 up 的网卡上会被内核直接拒
	// （Nexthop device is not up）。生产里 Plan() 的第一组命令就把它 up 了，
	// 而这里单独跑 PlanV6 时必须自己补上这一步——否则失败的是脚手架，不是产品。
	fwMust(t, ctx, r, "ip", "link", "set", device, "up")
}

// dnsNatDump 打印某个后端的 nat 表。
func dnsNatDump(t *testing.T, ctx context.Context, r Runner, bin string) string {
	t.Helper()
	return fwMust(t, ctx, r, bin, "-t", "nat", "-S")
}

// TestNetnsDNSHijackReallyRemoved 装上 → 逐项确认在位 → 按 Down 列表拆 → 逐项确认没了。
func TestNetnsDNSHijackReallyRemoved(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if !fwChainUp(t, ctx, r, "iptables") {
		t.Fatal("WPS_FW 开了却建不了链：脚手架不对")
	}
	const device = "wps-tun"
	dnsNetnsTUN(t, ctx, r, device)

	plan := dnsNetnsPlan(device)
	up, down, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, up); err != nil {
		t.Fatalf("装 v4 劫持失败: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		for _, c := range down {
			_, _ = r.Run(dctx, c)
		}
	})

	dump := dnsNatDump(t, ctx, r, "iptables")
	for _, want := range []string{
		"-N " + DNSChain,
		"-A OUTPUT -p udp -m udp --dport 53 -j " + DNSChain,
		"DNAT --to-destination 172.19.0.2:53",
		// 上游放行与回环排除都要真在位：少一条就是我们自己吃自己的解析。
		"-A " + DNSChain + " -d 223.5.5.5/32 -p udp -m udp --dport 53 -j RETURN",
		"! -d 127.0.0.0/8 -p udp -m udp --dport 53 -j DNAT",
		"-A POSTROUTING -o " + device + " -p udp -m udp --dport 53 -j SNAT --to-source 172.19.0.1",
	} {
		if !strings.Contains(dump, want) {
			t.Errorf("内核里没有这条已装好的规则 %q，实际:\n%s", want, dump)
		}
	}

	if err := Apply(ctx, r, down); err != nil {
		t.Fatalf("拆 v4 劫持失败: %v", err)
	}
	// 判据是「nat 表里再也找不到我们的痕迹」，而不是「删除命令都返回了成功」：
	// spec 与真实规则差一个字段时删除会成功匹配不到，而表里那条还在继续劫持。
	dump = dnsNatDump(t, ctx, r, "iptables")
	for _, banned := range []string{DNSChain, "DNAT", "172.19.0.2:53", "--to-source 172.19.0.1"} {
		if strings.Contains(dump, banned) {
			t.Errorf("拆完还留着 %q:\n%s", banned, dump)
		}
	}
}

// TestNetnsStaleCleanupRemovesRealResidue 是进程被杀那条路径的实核版：
// 异常退出时 defer 不会跑，规则原样留在表里；下一次启动的清理必须真的把它们删掉。
func TestNetnsStaleCleanupRemovesRealResidue(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if !fwChainUp(t, ctx, r, "iptables") {
		t.Fatal("WPS_FW 开了却建不了链：脚手架不对")
	}
	const device = "wps-tun"
	dnsNetnsTUN(t, ctx, r, device)

	plan := dnsNetnsPlan(device)
	up, _, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, up); err != nil {
		t.Fatal(err)
	}
	// 不复用 down——这就是「进程被杀，什么都没来得及做」留下的那张表。

	done := CleanupStale(ctx, r, os.Geteuid(), device, plan.Address)
	if len(done) == 0 {
		t.Fatal("清残留一项都没做成，后面的断言无从谈起")
	}
	dump := dnsNatDump(t, ctx, r, "iptables")
	for _, banned := range []string{DNSChain, "DNAT", "--to-source 172.19.0.1"} {
		if strings.Contains(dump, banned) {
			t.Errorf("清残留之后还留着 %q（清掉了 %d 项）:\n%s", banned, len(done), dump)
		}
	}
	// 清残留必须能反复跑：没残留时它不该报错，也不该动别人的规则。
	_ = CleanupStale(ctx, r, os.Geteuid(), device, plan.Address)
}

// TestNetnsIPv6DNSHijackIfKernelSupportsIt v6 那一组单独确认。
//
// 内核没加载 ip6table_nat 是常见情况（生产里就按降级处理，AAAA 回 NODATA），
// 所以这一族允许「环境不支持」但不允许「装上了拆不掉」。
func TestNetnsIPv6DNSHijackIfKernelSupportsIt(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if _, err := r.Run(ctx, Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-N", "wps_fw_probe"}}); err != nil {
		t.Skip("这台内核没有 ip6table_nat：v6 劫持在生产里按降级处理，这里不算失败")
	}
	_, _ = r.Run(ctx, Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-X", "wps_fw_probe"}})

	const device = "wps-tun"
	dnsNetnsTUN(t, ctx, r, device)
	plan := dnsNetnsPlan(device)
	up6, down6, err := plan.PlanV6()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, up6); err != nil {
		t.Fatalf("装 v6 劫持失败: %v", err)
	}
	dump := dnsNatDump(t, ctx, r, "ip6tables")
	if !strings.Contains(dump, "DNAT --to-destination [fd00:1::2]:53") {
		t.Errorf("v6 的 DNAT 没装上，实际:\n%s", dump)
	}
	// v4 上游绝不能出现在 ip6tables 里：那条会被内核整条拒掉，
	// 而它的失败会把整个 v6 那一组一起拖 down。
	if strings.Contains(dump, "223.5.5.5") {
		t.Errorf("v4 上游被写进了 ip6tables:\n%s", dump)
	}
	if err := Apply(ctx, r, down6); err != nil {
		t.Fatalf("拆 v6 劫持失败: %v", err)
	}
	dump = dnsNatDump(t, ctx, r, "ip6tables")
	for _, banned := range []string{DNSChain, "DNAT", "fd00:1::2"} {
		if strings.Contains(dump, banned) {
			t.Errorf("v6 拆完还留着 %q:\n%s", banned, dump)
		}
	}
}

// TestNetnsDNSHijackDeliversQueriesToOurResolver 是真的发一次 DNS 查询，看它落到谁手上。
//
// 为什么这条值得写：劫持规则的意义是「本机所有解析都经过我们」，
// 而它的两个失败方向都静默——
//   - 规则装歪了，查询照旧发往 8.8.8.8，我们发出的解析被自己劫持回去，
//     变成「问假 IP 表要一个假 IP」；
//   - 豁免名单漏了上游，同一件事也以另一种方式发生。
//
// 只看 -S 里的规则文本，这两种都看不出来。
//
// 判据用的是 netns 里没有到公网的路由这件事：DNAT 生效时路由按改写后的目的地址
// （172.19.0.2，本机地址）查，写包会成功并被我们的监听收到；
// 没被改写时目标是 8.8.8.8，这台「机器」根本没有那条路，直接 ENETUNREACH。
// 于是不需要抓包工具，成功/失败各自都有明确信号。
func TestNetnsDNSHijackDeliversQueriesToOurResolver(t *testing.T) {
	if !fwReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := ExecRunner{}
	if !fwChainUp(t, ctx, r, "iptables") {
		t.Fatal("WPS_FW 开了却建不了链：脚手架不对")
	}
	const device = "wps-tun"
	dnsNetnsTUN(t, ctx, r, device)
	// 一条默认路由指向 dummy：这是这套用例的前提条件，不是被测行为。
	// 少了它，connect()/首包的路由查询会在 netfilter 之前就 ENETUNREACH——
	// DNAT 发生在 LOCAL_OUT，而 connect() 的路由查询发生在有包之前，
	// 于是「劫持生效」和「根本发不出去」在断言上分不开。
	fwEnsureNIC(t, ctx, r)
	fwMust(t, ctx, r, "ip", "route", "replace", "default", "dev", "fwphys0")

	plan := dnsNetnsPlan(device)
	up, down, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := Apply(ctx, r, up); err != nil {
		t.Fatalf("装劫持失败: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		for _, c := range down {
			_, _ = r.Run(dctx, c)
		}
	})
	// 让 DNS 落点成为本机地址：DNAT 之后的包要靠这一步才投递得到我们的监听。
	// 生产里这个地址属于 tun，由我们的用户态协议栈应答；这里用一个监听套接字替身。
	fwMust(t, ctx, r, "ip", "addr", "add", plan.DNS+"/32", "dev", "lo")
	t.Cleanup(func() {
		_, _ = r.Run(context.Background(), Cmd{Bin: "ip", Args: []string{"addr", "del", plan.DNS + "/32", "dev", "lo"}})
	})

	laddr := &net.UDPAddr{IP: net.ParseIP(plan.DNS), Port: 53}
	udp, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatalf("绑不上 %s:53（需要 root 与 netns 内的 CAP_NET_BIND_SERVICE）: %v", plan.DNS, err)
	}
	defer udp.Close()

	// 收一次：给足时间，读不到就返回 false。
	receivedUDP := func(budget time.Duration) bool {
		deadline := time.Now().Add(budget)
		_ = udp.SetReadDeadline(deadline)
		buf := make([]byte, 512)
		for time.Now().Before(deadline) {
			n, _, err := udp.ReadFrom(buf)
			if err == nil && n > 12 {
				return true
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return false
			}
		}
		return false
	}
	// 不连出去的 UDP 套接字：connect() 会在 netfilter 之前做路由查询，
	// 而我们要的是「一个发往 8.8.8.8:53 的包经过 LOCAL_OUT 被改写」这条路。
	sendUDP := func(dst string) error {
		c, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		// 一个最像样的查询头：ID + RD=1，问题部分留空。
		_, err = c.WriteTo([]byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0},
			&net.UDPAddr{IP: net.ParseIP(dst), Port: 53})
		return err
	}

	// 1) 白名单外的目标必须被劫持到我们这里。
	if err := sendUDP("8.8.8.8"); err != nil {
		t.Fatalf("发往 8.8.8.8:53 的查询没写出去（劫持应当改写目的地址，让路由落到本机）: %v", err)
	}
	if !receivedUDP(2 * time.Second) {
		t.Fatal("UDP 查询被发出去了，却没有到达 DNS 落点：劫持规则没在工作")
	}

	// 2) 我们自己的上游绝不能被劫持——那等于问假 IP 表要一个假 IP。
	if err := sendUDP("223.5.5.5"); err == nil {
		// 没有路由时写包会直接失败，那也是「没被劫持」的证据；只有真的
		// 投递到了我们的监听才算劫持错了。
		if receivedUDP(500 * time.Millisecond) {
			t.Error("发往上游 223.5.5.5 的查询被我们自己劫持了：我们的解析会落进假 IP 表")
		}
	}
	// 3) 发给 systemd-resolved stub 的查询同理要原样交给 resolved。
	if err := sendUDP("127.0.0.53"); err == nil && receivedUDP(500*time.Millisecond) {
		t.Error("发给 127.0.0.53 的查询被 DNAT 了：127/8 的源地址在 tun 上不合法，应答会被当 martian 丢掉")
	}

	// 4) TCP 那一族也要劫持得到（DoT 之外的 zone 传输与大包走 TCP）。
	ln, err := net.Listen("tcp", net.JoinHostPort(plan.DNS, "53"))
	if err != nil {
		t.Fatalf("绑不上 TCP %s:53: %v", plan.DNS, err)
	}
	defer ln.Close()
	accepted := make(chan bool, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_ = c.Close()
			accepted <- true
			return
		}
		accepted <- false
	}()
	dconn, err := net.DialTimeout("tcp", net.JoinHostPort("8.8.8.8", "53"), 2*time.Second)
	if err != nil {
		t.Errorf("TCP 查询连不出去（劫持生效时它应落到本机的 DNS 落点）: %v", err)
	} else {
		_ = dconn.Close()
	}
	select {
	case ok := <-accepted:
		if !ok {
			t.Error("TCP 的 :53 没有被劫持到 DNS 落点")
		}
	case <-time.After(3 * time.Second):
		t.Error("TCP 查询没有被投递到我们的监听上")
	}
}
