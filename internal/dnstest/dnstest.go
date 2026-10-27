// Package dnstest 是一个最小 DNS 上游，给这个仓库里所有需要"有人回答 DNS"的测试用。
//
// 为什么单独一个包：这份实现在 internal/dnsx 里长了一年，直到「看解析」那一格
// （internal/service/dnsprobe.go）也要一个能答 A 记录的上游——
// 服务层的测试拿不到 dnsx 的包内测试类型，要么复制一百行，要么把它搬出来。
// 复制的那份会漂：改了一边的"查询计数判据"，另一边会静默地量不到东西。
package dnstest

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Server 收到查询后先等 delay，再回一条 A 记录。
// ip 为 nil 时回一条全零的 A（"答了但没地址"那一档）。
type Server struct {
	// Addr 是监听地址（"127.0.0.1:53123"），直接塞进 dns.servers 用。
	Addr string

	conn  *net.UDPConn
	delay time.Duration
	ip    net.IP

	mu     sync.Mutex
	count  int
	qnames map[string]int
}

func Start(t *testing.T, delay time.Duration, ip net.IP) *Server {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	f := &Server{Addr: conn.LocalAddr().String(), conn: conn, delay: delay, ip: ip}
	go f.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return f
}

func (f *Server) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.count++
		f.mu.Unlock()

		query := buf[:n]
		var p dnsmessage.Parser
		hdr, err := p.Start(query)
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		f.mu.Lock()
		if f.qnames == nil {
			f.qnames = make(map[string]int)
		}
		f.qnames[q.Name.String()+"/"+q.Type.String()]++
		f.mu.Unlock()
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID:            hdr.ID,
			Response:      true,
			OpCode:        hdr.OpCode,
			Authoritative: true,
		})
		if err := b.StartQuestions(); err != nil {
			continue
		}
		_ = b.Question(q)
		if err := b.StartAnswers(); err != nil {
			continue
		}
		rr := dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   60,
		}
		ip := f.answer()
		if ip == nil {
			_ = b.AResource(rr, dnsmessage.AResource{})
		} else if v4 := ip.To4(); v4 == nil {
			continue
		} else if err := b.AResource(rr, dnsmessage.AResource{A: [4]byte(v4)}); err != nil {
			continue
		}
		msg, err := b.Finish()
		if err != nil {
			continue
		}
		_, _ = f.conn.WriteToUDP(msg, from)
	}
}

func (f *Server) Queries() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}

// SetIP 换掉这个上游接下来给的答案。
//
// 上游要是一开始就把答案定死，能测的只有"有没有命中缓存"，测不出
// "命中的那份还该不该信"——而缓存这东西真正要防的正是后者。
// 有了它，"先答 A、中途改口成 B"这种 DNS 最日常的动作才进得了测试。
func (f *Server) SetIP(ip net.IP) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ip = ip
}

func (f *Server) answer() net.IP {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ip
}

// Questions 返回上游收到过的每个「问题名+类型」各被问过几次。
//
// 为什么判据要落在这一层而不是"总共几个包"：标准库发多少包是它自己的事——
// /etc/resolv.conf 里有一行 `search xxx.local` 就会多问一个带后缀的变体，
// edns0、trust-ad 那些开关也都会改变包数。这些和"两个调用者有没有共享同一次解析"
// 毫无关系，却会让断言随这台机器当天的网络配置变红。
// 真正的判据只有一条：**同一个问题被问了两遍**，才说明两个调用者各查各的。
func (f *Server) Questions() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.qnames))
	for k, n := range f.qnames {
		out[k] = n
	}
	return out
}

// Doubled 列出被问过两次以上的问题（共享失败时非空）。
func (f *Server) Doubled() []string {
	var out []string
	for k, n := range f.Questions() {
		if n > 1 {
			out = append(out, fmt.Sprintf("%s×%d", k, n))
		}
	}
	return out
}

// WaitQueries 等上游真的收到 want 条查询再往下走。
//
// 拿固定 sleep 当同步点是"静默空跑"的主要来源：等待者要是抢在首个查询到达之前进场，
// 它自己就成了 leader，于是断言全过、但被测的那条路径一次都没走。
// 宁可在这里失败，也不让结论交给调度。
func (f *Server) WaitQueries(t *testing.T, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if f.Queries() >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("等了 %s，上游只收到 %d 条查询（想要 %d 条）——查询根本没发出去，测试前提不成立",
		within, f.Queries(), want)
}
