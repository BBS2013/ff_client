package service

import (
	"net"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
)

// TestTrojanProfileLifecycle 覆盖「加一个 trojan 节点」的整条配置链路：
// 协议落盘、hysteria2 专属字段被清掉、列表与快照都报得出协议名、再改回 hysteria2。
func TestTrojanProfileLifecycle(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	if err := svc.AddProfile(ProfileSpec{
		Name: "东京-trojan", Type: config.ProtocolTrojan,
		Addr: "tj.example.com:443", Auth: "pw", SNI: "bing.com", Insecure: true,
		BandwidthUp: "200 mbps", Congestion: "bbr",
	}); err != nil {
		t.Fatalf("AddProfile(trojan): %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := cfg.Proxies[1].Server
	if srv.Protocol() != config.ProtocolTrojan {
		t.Fatalf("协议没落盘: type=%q", srv.Type)
	}
	// trojan 用不到拥塞算法与带宽整形。留着它们，面板就会对一个 trojan 节点
	// 显示「BBR / 200 mbps」这种看起来像配置其实全是废话的东西。
	if srv.Bandwidth.Up != "" || srv.Bandwidth.Down != "" || srv.Congestion != "" || srv.FastOpen {
		t.Fatalf("trojan 节点上残留了 hysteria2 专属参数: %+v", srv)
	}
	if srv.TLS.SNI != "bing.com" || !srv.TLS.Insecure || srv.Auth != "pw" {
		t.Fatalf("trojan 节点的基础字段不对: %+v", srv)
	}

	list, _, err := svc.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	if list[0].Type != config.ProtocolHysteria2 {
		t.Errorf("旧节点没写 type，应当报 hysteria2，实得 %q", list[0].Type)
	}
	if list[1].Type != config.ProtocolTrojan {
		t.Errorf("新节点应报 trojan，实得 %q", list[1].Type)
	}

	if err := svc.SetActiveProfile("东京-trojan"); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}
	snap := svc.Snapshot()
	if snap.ProxyType != config.ProtocolTrojan || snap.Server != "tj.example.com:443" {
		t.Fatalf("快照里的协议/地址不对: %+v", snap)
	}
	// 界面按这两个字段是否为空来决定显不显示带宽行。
	if snap.BandwidthUp != "" || snap.Congestion != "" {
		t.Fatalf("trojan 节点的快照里不该有带宽/拥塞: %+v", snap)
	}

	// 改回 hysteria2：只换协议，口令与 SNI 都不该被顺手改掉。
	if err := svc.UpdateProfile("东京-trojan", ProfileSpec{
		Name: "东京-trojan", Type: config.ProtocolHysteria2,
		Addr: "tj.example.com:443", BandwidthUp: "150 mbps", Congestion: "bbr",
	}); err != nil {
		t.Fatalf("UpdateProfile 回 hysteria2: %v", err)
	}
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	back := cfg.Proxies[1].Server
	if back.Protocol() != config.ProtocolHysteria2 || back.Bandwidth.Up != "150 mbps" {
		t.Fatalf("换协议没生效: %+v", back)
	}
	if back.Auth != "pw" || back.TLS.SNI != "bing.com" {
		t.Fatalf("换协议把口令/SNI 弄丢了: %+v", back)
	}

	if err := svc.UpdateProfile("东京-trojan", ProfileSpec{Type: "ss"}); err == nil {
		t.Error("未知协议应被拒绝")
	}
	if err := svc.AddProfile(ProfileSpec{Name: "非法", Type: "vless", Addr: "a.com:443", Auth: "x"}); err == nil {
		t.Error("新增时的未知协议也应被拒绝")
	}
}

// TestTestProfileDispatchesTrojan 证明测速用的是配置里的协议而不是写死的 hysteria2：
// 指向本机没在监听的端口，报错里必须带 trojan 字样，并且必须马上返回——
// 如果工厂分派错了，这里会变成 hysteria2 的 QUIC 握手，等到超时才失败。
func TestTestProfileDispatchesTrojan(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)
	if err := svc.AddProfile(ProfileSpec{
		Name: "tj", Type: config.ProtocolTrojan, Addr: "127.0.0.1:1", Auth: "pw", Insecure: true,
	}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}

	start := time.Now()
	res := svc.TestProfile("tj", "example.com:443")
	if res.OK {
		t.Fatalf("连不上的节点不该报成功: %+v", res)
	}
	if !strings.Contains(res.Error, "trojan") {
		t.Fatalf("报错里没体现协议，可能压根没分派: %q", res.Error)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("trojan 拨号失败应当立刻返回，实际等了 %v（%s）", elapsed, res.Error)
	}
}

// TestProbeAccept 钉住测速探测的三种读结果。
//
// trojan 的口令校验在 TLS 握手之后，服务端拒绝时只会关连接、不回错误码，
// 所以「握手成功」并不等于「配置能用」——这一段读探测就是补这个缺口的。
func TestProbeAccept(t *testing.T) {
	t.Run("对端关闭", func(t *testing.T) {
		// 用真 TCP 而不是 net.Pipe：Pipe 的任一端 Close 会把两端一起关掉，
		// 于是 SetReadDeadline 自己就先失败了，测不到想测的那条分支。
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		closed := make(chan struct{})
		go func() {
			defer close(closed)
			if c, err := ln.Accept(); err == nil {
				_ = c.Close() // 连上就断，模拟口令不对的服务端
			}
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		<-closed // 一定要等对端真的关掉再探，否则这次读只会等到超时
		if err := probeAccept(conn); err == nil {
			t.Fatal("对端已关闭却报正常")
		} else if !strings.Contains(err.Error(), "口令不对") {
			t.Fatalf("报错应当告诉用户可能是口令问题: %v", err)
		}
	})

	t.Run("静默即正常", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c2.Close()
		defer c1.Close()
		start := time.Now()
		if err := probeAccept(c1); err != nil {
			t.Fatalf("没数据可读只是超时，不该判失败: %v", err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("探测没有按超时收口，等了 %v", elapsed)
		}
	})

	t.Run("有数据也算通", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		go func() { _, _ = c2.Write([]byte{0x16}) }()
		if err := probeAccept(c1); err != nil {
			t.Fatalf("对端在发数据却报失败: %v", err)
		}
	})
}
