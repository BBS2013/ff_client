package tunx

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// dialTestEndpoint 找一个"这台机器自己的、非环回的 IPv4 + 它的接口名"。
// 为什么不能用 127.0.0.1：checkBindTarget 故意拒绝环回——这条通道是给"出网的节点
// 连接"开的，不是给本机服务当 root 跳板的。所以成功路径只能在真网卡的地址上验。
func dialTestEndpoint(t *testing.T) (dev, addr string) {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("读不到本机地址: %v", err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, err := netip.ParseAddr(ipn.IP.String())
		if err != nil || !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		ifaces, err := net.Interfaces()
		if err != nil {
			t.Skipf("读不到接口: %v", err)
		}
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagUp == 0 {
				continue
			}
			na, _ := ifi.Addrs()
			for _, x := range na {
				if xn, ok := x.(*net.IPNet); ok && xn.IP.String() == ip.String() {
					return ifi.Name, ip.String()
				}
			}
		}
	}
	t.Skip("这台机器上没有非环回的 IPv4 地址，dialbind 的成功路径验不了")
	return "", ""
}

// 名单校验必须拒绝的四种，和接受的那一种。
func TestCheckBindTarget(t *testing.T) {
	cases := []struct {
		name, addr string
		allow      []string
		wantErr    string
	}{
		{"域名不收（helper 里不许解析）", "node.example:8443", []string{"1.2.3.4:8443"}, "已解析的 IP"},
		{"环回不收（不当 root 的本地跳板）", "127.0.0.1:8443", []string{"127.0.0.1:8443"}, "拒绝连到"},
		{"不在名单里不收", "9.9.9.9:443", []string{"1.2.3.4:443"}, "名单"},
		{"组播不收", "239.1.1.1:443", []string{"239.1.1.1:443"}, "拒绝连到"},
		{"在名单里就收", "1.2.3.4:8443", []string{"5.6.7.8:443", "1.2.3.4:8443"}, ""},
	}
	for _, c := range cases {
		_, _, err := checkBindTarget(c.addr, c.allow)
		if c.wantErr == "" {
			if err != nil {
				t.Errorf("%s: 不该报错: %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: 期望错误里有 %q，得到 %v", c.name, c.wantErr, err)
		}
	}
}

// 请求形状的校验：dialbind 不带 RoutePlan，那套按计划的检查一条都不许套上来。
func TestDialBindRequestValidate(t *testing.T) {
	good := DialBindRequest(os.Geteuid(), "wlan0", "1.2.3.4:8443", []string{"1.2.3.4:8443"})
	if err := good.validate(); err != nil {
		t.Fatalf("合用的请求被拒: %v", err)
	}
	noAllow := good
	noAllow.BindAllow = nil
	if err := noAllow.validate(); err == nil {
		t.Fatal("没有名单就该拒绝")
	}
	badDev := good
	badDev.BindDev = ""
	if err := badDev.validate(); err == nil {
		t.Fatal("没有接口名就该拒绝")
	}
	// 空 Plan.Device 不能被"网卡名不合法"那条拦住——那是 up/reroute 的要求。
	if err := good.validate(); err != nil && strings.Contains(err.Error(), "网卡名不合法") {
		t.Fatalf("dialbind 不该被 RoutePlan 的网卡校验拦住: %v", err)
	}
}

// 关键的一条：进程内起一个 helper，走真 unix socket + 真 SCM_RIGHTS，
// 面板（无特权）拿回 fd 之后必须能收发，而且那条 socket 确实钉在点名的卡上。
func TestDialBoundHandshakesRealSocket(t *testing.T) {
	dev, addr := dialTestEndpoint(t)

	ln, err := net.Listen("tcp", addr+":0")
	if err != nil {
		t.Skipf("在本机地址 %s 上起不了监听: %v", addr, err)
	}
	defer ln.Close()
	endpoint := ln.Addr().String()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("pong"))
	}()

	srv := &HelperServer{
		Runner:  &recorderRunner{},
		Timeout: 5 * time.Second,
	}
	client := helperTestServer(srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.DialBound(ctx, dev, endpoint, []string{endpoint})
	if err != nil {
		// 普通用户在这类机器上绑不上网卡是**内核策略**，不是这条通道的逻辑坏：
		// 真机验证由 root 跑一次端到端补上（见 ACCEPTANCE 那条），这里先 Skip 而不是假绿。
		if strings.Contains(err.Error(), "operation not permitted") ||
			strings.Contains(err.Error(), "invalid argument") {
			t.Skipf("这个环境不让普通进程钉网卡（%v）——逻辑路径改由 root 的真机跑验证", err)
		}
		t.Fatalf("DialBound 失败: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("拿回的 fd 读不到数据: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("回包不对: %q", buf)
	}
	// 钉住没有？直接问内核，不看我们自己的字段。
	bound := boundDeviceOf(t, conn)
	if bound != dev {
		t.Fatalf("这条 socket 应该钉在 %s，实际是 %q", dev, bound)
	}
}

// 名单之外的目标必须在 helper 那侧就被拒掉，而且不要把一个没人认领的 fd 漏出去。
func TestDialBoundRefusesEndpointNotInAllow(t *testing.T) {
	dev, _ := dialTestEndpoint(t)
	srv := &HelperServer{Runner: &recorderRunner{}, Timeout: 5 * time.Second}
	client := helperTestServer(srv)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.DialBound(ctx, dev, "1.2.3.4:443", []string{"5.6.7.8:443"})
	if err == nil || !strings.Contains(err.Error(), "名单") {
		t.Fatalf("期望被名单拒掉，得到 %v", err)
	}
}

// boundDeviceOf 读回 socket 实际绑定的接口名（与 split_test 里同一办法）。
func boundDeviceOf(t *testing.T, conn net.Conn) string {
	t.Helper()
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("拿回的不是 *net.TCPConn，而是 %T", conn)
	}
	sc, err := tc.SyscallConn()
	if err != nil {
		t.Fatalf("拿不到底层 socket: %v", err)
	}
	var (
		name string
		gerr error
	)
	err = sc.Control(func(fd uintptr) {
		name, gerr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	})
	if err != nil || gerr != nil {
		t.Fatalf("读 SO_BINDTODEVICE 失败: %v %v", err, gerr)
	}
	return name
}
