package dnsx

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// 这组测试证明的是「同一个上游、两个视角」这件事。
// 污染发生在本机到上游的那条路上，所以从节点那一侧问同一个上游才拿得到真答案；
// 而两条路径的答案必须各存各的，谁也不许覆盖谁。

var polluted = net.ParseIP("185.45.5.35").To4()
var clean = net.ParseIP("39.156.66.10").To4()

// tcpDNSServer 是一个只会答 A 记录的 DNS-over-TCP 假上游（RFC 5936 的 2 字节长度前缀）。
// 隧道路径拿到的是 stream，stdlib 因此自动改用 TCP 分帧，所以假的这一侧必须照做。
func tcpDNSServer(t *testing.T, ip net.IP) (addr string, fail func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveOne(t, c, ip)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		<-done
	})
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func serveOne(t *testing.T, c net.Conn, ip net.IP) {
	t.Helper()
	defer c.Close()
	for {
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		var size uint16
		if err := binary.Read(c, binary.BigEndian, &size); err != nil {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(c, query); err != nil {
			return
		}
		var p dnsmessage.Parser
		hdr, err := p.Start(query)
		if err != nil {
			return
		}
		q, err := p.Question()
		if err != nil {
			return
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: hdr.ID, Response: true, Authoritative: true})
		if err := b.StartQuestions(); err != nil {
			return
		}
		_ = b.Question(q)
		if err := b.StartAnswers(); err != nil {
			return
		}
		v4 := ip.To4()
		if v4 == nil {
			return
		}
		if err := b.AResource(dnsmessage.ResourceHeader{
			Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
		}, dnsmessage.AResource{A: [4]byte(v4)}); err != nil {
			return
		}
		msg, err := b.Finish()
		if err != nil {
			return
		}
		var hdrBuf [2]byte
		binary.BigEndian.PutUint16(hdrBuf[:], uint16(len(msg)))
		if _, err := c.Write(append(hdrBuf[:], msg...)); err != nil {
			return
		}
	}
}

// newTwoVantage 造一个「直连答污染 IP、隧道答干净 IP」的解析器。
func newTwoVantage(t *testing.T) (*Resolver, net.IP, net.IP) {
	t.Helper()
	directFake := startFakeDNS(t, 0, polluted) // 既有的 UDP 假上游，代表本机视角
	r, err := New([]string{directFake.Addr}, 2*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return r, polluted, clean
}

func TestTunnelPathUsesInjectedDialer(t *testing.T) {
	r, _, _ := newTwoVantage(t)
	tunAddr, _ := tcpDNSServer(t, clean)

	// 拨号回调会被并发调用（A 与 AAAA 是并行问的），所以计数必须原子。
	var used atomic.Int32
	r.SetTunnel(func(ctx context.Context, addr string) (net.Conn, error) {
		used.Add(1)
		// 刻意无视调用方给的 addr：真实隧道也是把包送到节点、由节点去联系上游。
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "tcp", tunAddr)
	})

	got, err := r.LookupIPVia(context.Background(), "example.cn", PathTunnel)
	if err != nil {
		t.Fatalf("隧道解析失败: %v", err)
	}
	if used.Load() == 0 {
		t.Fatal("说是走隧道，实际一次都没经过注入的拨号器")
	}
	if len(got) != 1 || got[0].String() != clean.String() {
		t.Fatalf("隧道路径拿到的不是干净答案: %v", got)
	}

	// 同一次调用里直连入口必须还是那个被污染的答案——两个视角不能串。
	direct, err := r.LookupIP(context.Background(), "example.cn")
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != 1 || direct[0].String() != polluted.String() {
		t.Fatalf("直连答案被隧道路径改写了: %v", direct)
	}
}

// TestPathsCacheSeparately 是这次改动最关键的一条：
// 缓存原本只按域名分键，干净答案和被污染的答案会互相覆盖。
// 谁覆盖谁取决于谁先到，于是判定结果变成一个看运气的东西——最难复现的那类 bug。
func TestPathsCacheSeparately(t *testing.T) {
	r, _, _ := newTwoVantage(t)
	tunAddr, _ := tcpDNSServer(t, clean)
	r.SetTunnel(func(ctx context.Context, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "tcp", tunAddr)
	})

	// 先问隧道，再问直连。
	if got, err := r.LookupIPVia(context.Background(), "foo.cn", PathTunnel); err != nil || got[0].String() != clean.String() {
		t.Fatalf("隧道首问: %v %v", got, err)
	}
	if got, err := r.LookupIP(context.Background(), "foo.cn"); err != nil || got[0].String() != polluted.String() {
		t.Fatalf("直连首问: %v %v", got, err)
	}
	// 两个都已经进缓存。之后无论谁先命中，都不该被另一个污染。
	for i := 0; i < 5; i++ {
		if got, _ := r.LookupIPVia(context.Background(), "foo.cn", PathTunnel); got[0].String() != clean.String() {
			t.Fatalf("第 %d 次隧道问到了污染答案: %v", i+1, got)
		}
		if got, _ := r.LookupIP(context.Background(), "foo.cn"); got[0].String() != polluted.String() {
			t.Fatalf("第 %d 次直连问到了隧道答案: %v", i+1, got)
		}
	}
}

// TestNodeAddressAlwaysDirect 拨节点之前先要解析节点地址，那时隧道还不存在。
// 这条是启动死锁的防线（见 hysteria.go:55-68），一旦隧道路径变成默认路径就会复发。
func TestNodeAddressAlwaysDirect(t *testing.T) {
	r, _, _ := newTwoVantage(t)
	r.SetTunnel(func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("隧道此时不该被使用")
	})
	// LookupIP 是 outbound.HostResolver 用的那个入口。
	if got, err := r.LookupIP(context.Background(), "node.example.com"); err != nil {
		t.Fatalf("节点地址解析应当走直连、不受隧道影响: %v", err)
	} else if got[0].String() != polluted.String() {
		t.Fatalf("节点地址解析走错了路: %v", got)
	}
	// 字面量 IP 连解析都不该触发。
	if got, err := r.LookupIP(context.Background(), "203.0.113.9"); err != nil || got[0].String() != "203.0.113.9" {
		t.Fatalf("字面量 IP 本该直接返回: %v %v", got, err)
	}
}

// TestTunnelFailureFallsBackToDirect 隧道不通时规则判定不能瞎。
// 退回直连结果（哪怕可能被污染）比"解析失败→全部走兜底策略"更可解释。
func TestTunnelFailureFallsBackToDirect(t *testing.T) {
	r, _, _ := newTwoVantage(t)
	r.SetTunnel(func(context.Context, string) (net.Conn, error) {
		return nil, errors.New("节点没在应答")
	})
	got, err := r.LookupIPVia(context.Background(), "bar.cn", PathTunnel)
	if err != nil {
		t.Fatalf("隧道失败时应当退回直连，而不是整条解析失败: %v", err)
	}
	if got[0].String() != polluted.String() {
		t.Fatalf("退回的应当是直连答案: %v", got)
	}
}

// TestNoTunnelBoundIsPlainDirect 没注入拨号器时，PathTunnel 等价于直连，
// 不报错、也不制造「配了但没接上」的第三种状态。
func TestNoTunnelBoundIsPlainDirect(t *testing.T) {
	r, _, _ := newTwoVantage(t)
	got, err := r.LookupIPVia(context.Background(), "baz.cn", PathTunnel)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].String() != polluted.String() {
		t.Fatalf("未绑定隧道时应等价于直连: %v", got)
	}
}

// TestSetTunnelInvalidatesOldNode 换节点必须作废隧道缓存。
// 不同地区的节点问同一个上游会得到不同归属，抱着上一个节点的答案做 GEOIP 判定，
// 等于用别人的视角决定自己该不该翻墙。
func TestSetTunnelInvalidatesOldNode(t *testing.T) {
	r, _, _ := newTwoVantage(t)
	nodeA, _ := tcpDNSServer(t, net.ParseIP("8.8.8.8").To4())
	nodeB, _ := tcpDNSServer(t, clean)

	to := func(addr string) TunnelDial {
		return func(ctx context.Context, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "tcp", addr)
		}
	}
	r.SetTunnel(to(nodeA))
	first, err := r.LookupIPVia(context.Background(), "qux.cn", PathTunnel)
	if err != nil || first[0].String() != "8.8.8.8" {
		t.Fatalf("节点 A 视角: %v %v", first, err)
	}

	r.SetTunnel(to(nodeB))
	second, err := r.LookupIPVia(context.Background(), "qux.cn", PathTunnel)
	if err != nil {
		t.Fatal(err)
	}
	if second[0].String() != clean.String() {
		t.Fatalf("切到节点 B 之后仍拿到节点 A 的缓存答案: %v", second)
	}
}

// TestKeyCarriesPath 直接盯住键本身，免得将来有人"顺手"把维度合回去。
func TestKeyCarriesPath(t *testing.T) {
	r, _, _ := newTwoVantage(t)
	if r.key(PathDirect, "a.cn") != "a.cn" {
		t.Fatalf("直连键应保持原样（兼容既有缓存与调用方）: %q", r.key(PathDirect, "a.cn"))
	}
	k1 := r.key(PathTunnel, "a.cn")
	if k1 == "a.cn" {
		t.Fatalf("隧道键必须与直连键不同: %q", k1)
	}
	r.SetTunnel(func(context.Context, string) (net.Conn, error) { return nil, errors.New("x") })
	k2 := r.key(PathTunnel, "a.cn")
	if k2 == k1 {
		t.Fatal("换隧道之后隧道路径的键没变，旧节点的答案会留下来")
	}
}
