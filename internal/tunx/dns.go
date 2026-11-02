package tunx

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"wps_app/internal/logx"
	"wps_app/internal/rules"
)

// Decider 是路由层的决策入口（*router.Router 实现它）。
// DNS 应答必须先问一次「这个域名该走哪」，才知道该发假 IP 还是真 IP。
type Decider interface {
	Decide(ctx context.Context, host string) (rules.Policy, string)
}

// Lookup 解析出域名的真实地址。
type Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

const (
	// fakeTTL 刻意压得短：模式或规则一改，同一个域名的归属就可能变，
	// TTL 太长会让应用抱着旧答案不放。
	fakeTTL = 60 * time.Second
	// realTTL 是直连域名回真 IP 时的兜底 TTL。
	realTTL = 300 * time.Second
)

// dnsServer 是 tun 上的 DNS 应答器：不转发报文，而是按判定现编答案。
//
// 这是「假 IP」方案的关键一环，也是唯一能免疫 DNS 污染的一环——
// 对判成 PROXY 的域名我们根本不做解析，直接发假 IP，
// 被污染的伪造 IP 永远没有机会进入应用的连接目标。
type dnsServer struct {
	decide Decider
	lookup Lookup
	fake   *FakeStore
	// allowV6 记「v6 假 IP 那一组路由确实装上了」。没装上却发假 v6，
	// 应用会拿着一个到不了的地址一路连到超时，而 NODATA 至少能让它退回 A 记录。
	allowV6 bool
}

// record 是一条已决定的答案。用中间结构而不是直接写 Builder，
// 是为了能在出错时整包回退成 SERVFAIL——半截答案加错误码是最难排查的报文。
type record struct {
	q   dnsmessage.Question
	ttl uint32
	v4  netip.Addr
	v6  netip.Addr
}

// DNSReply 是一次应答的结果：报文，外加「这一条是不是 SERVFAIL」。
//
// 分开是有原因的：SERVFAIL 也算"应答过了"，而那个计数（面板上「已应答 DNS N 次」）
// 唯一的用途是证明劫持确实在工作。上游全挂的时候把一百次失败报成一百次成功，
// 那个数字说的是反话。
type DNSReply struct {
	Packet   []byte
	ServFail bool
}

// Serve 处理一条 DNS 查询报文，返回应答报文。
// 不关心 RCODE 的调用方用它；要分开计数的用 Reply。
func (s *dnsServer) Serve(ctx context.Context, query []byte) ([]byte, error) {
	rep, err := s.Reply(ctx, query)
	return rep.Packet, err
}

// Reply 是 Serve 的完整版：报文 + 这一条到底答上了没有。
func (s *dnsServer) Reply(ctx context.Context, query []byte) (DNSReply, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return DNSReply{}, fmt.Errorf("parse dns header: %w", err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return DNSReply{}, fmt.Errorf("parse dns questions: %w", err)
	}
	if len(qs) == 0 {
		return DNSReply{}, fmt.Errorf("dns query without question")
	}

	var (
		records []record
		failed  error
	)
	for _, q := range qs {
		rrs, err := s.answer(ctx, q)
		if err != nil {
			failed = err
			break
		}
		records = append(records, rrs...)
	}
	head := dnsmessage.Header{
		ID:                 h.ID,
		Response:           true,
		RecursionDesired:   h.RecursionDesired,
		RecursionAvailable: true,
	}
	if failed != nil {
		// 上游解析不动这条查询：回 SERVFAIL，让应用自己去试别的（或者退回 hosts）。
		// 这里必须同时把"失败了"告诉调用方，见 DNSReply.ServFail。
		head.RCode = dnsmessage.RCodeServerFailure
		pkt, err := encode(head, qs, nil)
		return DNSReply{Packet: pkt, ServFail: true}, err
	}
	pkt, err := encode(head, qs, records)
	return DNSReply{Packet: pkt}, err
}

// answer 为单个 question 生成答案。返回空切片表示 NODATA（合法但无记录）。
//
// AAAA 与 A 走同一条假 IP 路径，只是从 IPv6 段里取。没配 v6 段（或者那一组
// 路由没装上）时回 NODATA —— 让应用老实退回 A 记录。
// 回一个「有地址但到不了」的假 v6 只会让它一路连到超时。
func (s *dnsServer) answer(ctx context.Context, q dnsmessage.Question) ([]record, error) {
	name := strings.TrimSuffix(q.Name.String(), ".")
	// 空名（查根）与"结构上不是主机名"的名字（NUL、控制字符、带 ':' 的那种）一律 NODATA。
	// 这个名字要当规则判定的键、要进假 IP 池：喂垃圾进去只会得到一条永远匹配不上的假 IP，
	// 应用抱着它连到超时。判据与 SOCKS5 入站共用 rules.ValidHostName，两边不许各写一份。
	if !rules.ValidHostName(name) {
		return nil, nil
	}
	switch q.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
	case dnsmessage.TypeSVCB, dnsmessage.TypeHTTPS:
		// 不代答 DoH/SVCB 记录，应用会退回普通 A/AAAA 流程。
		return nil, nil
	default:
		return nil, nil
	}

	policy, matched := s.decide.Decide(ctx, name)
	// 拦截和走代理在 DNS 这一侧必须同一个待遇：都领假 IP。
	//
	// 判成 DIRECT 的域名回真 IP，应用拿到真地址就绕开了 tun——
	// 于是"拦截名单"一条都拦不住，而 DNS 应答、日志、界面全都看不出异常。
	// 领了假 IP，连接才会回到 relay，在那里被挡下。
	// 判据用「不是 DIRECT」而不是枚举「是 Proxy 或 Reject」：
	// 枚举在新增策略时会漏，而漏掉的后果是那条策略**在 TUN 模式下整体失效**
	// （回真 IP → 应用根本不进 tun），日志、界面、DNS 应答还全都正常。
	if policy != rules.PolicyDirect {
		rec, err := s.fakeRecord(q, name, matched)
		if err != nil || len(rec) == 0 {
			return rec, err
		}
		return rec, nil
	}

	// 直连：回真 IP。这类连接根本不进 tun，应用拿到真地址直接发。
	if s.lookup == nil {
		return nil, nil
	}
	addrs, err := s.lookup(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("直连解析 %s: %w", name, err)
	}
	want6 := q.Type == dnsmessage.TypeAAAA
	var out []record
	for _, a := range addrs {
		if a.Is6() != want6 {
			continue
		}
		rec := record{q: q, ttl: uint32(realTTL / time.Second)}
		if want6 {
			rec.v6 = a
		} else {
			rec.v4 = a
		}
		out = append(out, rec)
	}
	logx.Debugf("tun dns: %s 直连回 %d 条真 IP [DIRECT | %s]", name, len(out), matched)
	return out, nil
}

// fakeRecord 给判成 PROXY 的域名发一个假 IP。q 是 AAAA 而没配 v6 段时返回空切片。
func (s *dnsServer) fakeRecord(q dnsmessage.Question, name, matched string) ([]record, error) {
	want6 := q.Type == dnsmessage.TypeAAAA
	if want6 && !(s.allowV6 && s.fake.HasV6()) {
		return nil, nil
	}
	addr, err := allocateFake(s.fake, name, want6)
	if err != nil {
		return nil, err
	}
	logx.Debugf("tun dns: %s -> %s [PROXY | %s]（假 IP）", name, addr, matched)
	rec := record{q: q, ttl: uint32(fakeTTL / time.Second)}
	if want6 {
		rec.v6 = addr
	} else {
		rec.v4 = addr
	}
	return []record{rec}, nil
}

func allocateFake(s *FakeStore, name string, want6 bool) (netip.Addr, error) {
	if want6 {
		return s.Allocate6(name)
	}
	return s.Allocate(name)
}

// encode 组报文。响应必须原样回显 question 段，否则多数解析器会直接丢掉这条答案。
func encode(head dnsmessage.Header, qs []dnsmessage.Question, records []record) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, head)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, fmt.Errorf("start questions: %w", err)
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			return nil, fmt.Errorf("echo question: %w", err)
		}
	}
	if err := b.StartAnswers(); err != nil {
		return nil, fmt.Errorf("start answers: %w", err)
	}
	for _, r := range records {
		hdr := dnsmessage.ResourceHeader{
			Name:  r.q.Name,
			Class: r.q.Class,
			TTL:   r.ttl,
		}
		switch {
		case r.v4.IsValid():
			hdr.Type = dnsmessage.TypeA
			if err := b.AResource(hdr, dnsmessage.AResource{A: r.v4.As4()}); err != nil {
				return nil, fmt.Errorf("write A: %w", err)
			}
		case r.v6.IsValid():
			hdr.Type = dnsmessage.TypeAAAA
			if err := b.AAAAResource(hdr, dnsmessage.AAAAResource{AAAA: r.v6.As16()}); err != nil {
				return nil, fmt.Errorf("write AAAA: %w", err)
			}
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil, fmt.Errorf("finish dns response: %w", err)
	}
	return append([]byte(nil), out...), nil
}

// BuildQuery 造一条 A 记录查询，供测试与自检使用。
func BuildQuery(name string, qtype dnsmessage.Type) ([]byte, error) {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(strings.TrimSuffix(name, ".") + "."),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	out, err := b.Finish()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), out...), nil
}

// dnsTCPMaxQuery 是单条 TCP DNS 查询允许的最大正文字节数。
// 长度字段本身容得下 65535，但真实查询不会超过 UDP 那一档；
// 卡在这里，对端就不能拿一个假长度前缀让我们先去分配 64KB。
const dnsTCPMaxQuery = 4096

// dnsTCPIdle 是一条 TCP DNS 连接安静多久就收。与 UDP 侧同值：
// 解析器会把连接留着复用，太短等于逼它反复重连。
const dnsTCPIdle = 60 * time.Second

// serveDNSOverTCP 在一条流上按 RFC 5936 连续应答 DNS 查询——
// 每条报文前置 2 字节大端长度，一条连接可以问很多次。
//
// 为什么要支持「很多次」：glibc 的 resolver 与 systemd-resolved 的上行连接都会
// 留着复用，而 RFC 5936 要求服务端本来就支持连续查询。
// 一问一答就收尾的话，表现是「解析时好时坏，且只在应答变大时出现」——最难查的一类故障。
// （Go 自己的 dnsclient 反倒是一次一问然后关连接，dnsclient_unix.go:197-198，
// 所以只支持一条也能骗过它——那正是这类缺陷藏得住的原因。）
//
// idle 为空转收连的等待；生产传 dnsTCPIdle，测试传短值以便真的走到那条分支上。
// 返回两个计数：答上的条数与回 SERVFAIL 的条数（为什么要分开，见 DNSReply）。
// 读到 EOF、连接被关或空闲到点都算正常收尾，不报错。
func serveDNSOverTCP(c net.Conn, serve func(context.Context, []byte) (DNSReply, error), idle time.Duration) (served, failed int, err error) {
	// 读写各配一个缓冲：stdlib 把长度前缀和正文放在同一次 Write 里
	// （dnsclient_unix.go:89-92 先把前缀写进 tcpReq 头两字节），
	// 但也有客户端先写长度再写正文；有缓冲两种都接得住，不会逐字节打散成系统调用。
	br := bufio.NewReader(c)
	bw := bufio.NewWriter(c)
	for {
		_ = c.SetReadDeadline(time.Now().Add(idle))
		var size uint16
		if err := binary.Read(br, binary.BigEndian, &size); err != nil {
			switch {
			case errors.Is(err, io.EOF), errors.Is(err, net.ErrClosed):
				return served, failed, nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return served, failed, nil
			}
			return served, failed, fmt.Errorf("读 dns 长度前缀: %w", err)
		}
		if size == 0 {
			return served, failed, errors.New("dns over tcp 收到长度为 0 的报文")
		}
		if size > dnsTCPMaxQuery {
			return served, failed, fmt.Errorf("dns over tcp 报文过长: %d 字节", size)
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(br, query); err != nil {
			return served, failed, fmt.Errorf("读 dns 报文正文: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		rep, err := serve(ctx, query)
		cancel()
		if err != nil {
			return served, failed, fmt.Errorf("应答 dns 查询: %w", err)
		}
		// 应答也必须带长度前缀：否则对端把报文头的前两字节当长度读，
		// 后面整条流就错位了，表现是「解析超时」而不是「解析出错」。
		if len(rep.Packet) > dnsTCPOneMessageMax {
			return served, failed, fmt.Errorf("dns 应答 %d 字节，超出 tcp 长度字段", len(rep.Packet))
		}
		if err := binary.Write(bw, binary.BigEndian, uint16(len(rep.Packet))); err != nil {
			return served, failed, fmt.Errorf("写应答长度: %w", err)
		}
		if _, err := bw.Write(rep.Packet); err != nil {
			return served, failed, fmt.Errorf("写应答: %w", err)
		}
		if err := bw.Flush(); err != nil {
			return served, failed, fmt.Errorf("刷应答: %w", err)
		}
		// 计在 Flush 之后：没送到对端的答案不算"应答过"。
		if rep.ServFail {
			failed++
		} else {
			served++
		}
	}
}

// dnsTCPOneMessageMax 是 DNS-over-TCP 单条报文的上限，也是长度字段的上限。
const dnsTCPOneMessageMax = 1<<16 - 1
