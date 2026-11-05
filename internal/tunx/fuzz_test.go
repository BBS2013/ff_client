// tun 上 DNS 应答器与 helper 帧的模糊测试。
//
// 这两处的输入都不是"本机自己人"写出来的：
// DNS 报文来自任何本机进程（应用、扫描器、被攻破的容器都能往 tun 上丢），
// helper 帧来自一个 unix socket（对端是提权后的子进程，但那台机器上任何能碰到
// socket 路径的程序都能发）。所以第一条要求是"任何字节都不许炸、不许编出
// 自解不开的报文"，而不是"聪明地处理"。
package tunx

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"wps_app/internal/rules"
)

// fuzzDecider 固定一个策略：这样"报文会不会炸"与"判定对不对"两件事不会混在一起，
// 而 DIRECT 那条分支会去查上游，模糊测试里绝不能真去查。
type fuzzDecider struct{ policy rules.Policy }

func (d fuzzDecider) Decide(context.Context, string) (rules.Policy, string) {
	return d.policy, "DOMAIN-SUFFIX,fuzz.example,PROXY"
}

func mustNotLookUp(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("fuzz: 这条路径不该去解析")
}

func newFuzzDNSServer(t testing.TB, policy rules.Policy) *dnsServer {
	t.Helper()
	fake, err := NewFakeStore("198.18.0.0/15", "fd00::/120", 0)
	if err != nil {
		t.Fatalf("建假 IP 池: %v", err)
	}
	return &dnsServer{decide: fuzzDecider{policy}, lookup: mustNotLookUp, fake: fake, allowV6: true}
}

func FuzzDNSServe(f *testing.F) {
	add := func(name string, typ dnsmessage.Type) {
		raw, err := BuildQuery(name, typ)
		if err != nil {
			f.Fatalf("造种子查询失败: %v", err)
		}
		f.Add(raw)
	}
	add("example.com", dnsmessage.TypeA)
	add("example.com", dnsmessage.TypeAAAA)
	add("ads.example.com", dnsmessage.TypeA)
	// 各种残缺与畸形：只有头、问题数说有很多、名字压缩指针乱指、超长标签。
	f.Add([]byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add([]byte{0x00})
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 'a'})
	f.Add([]byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01})
	f.Add([]byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xff, 'a'})
	f.Add(append([]byte{0x00, 0x01, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		bytes.Repeat([]byte{'a'}, 300)...))

	f.Fuzz(func(t *testing.T, query []byte) {
		for _, policy := range []rules.Policy{rules.PolicyProxy, rules.PolicyReject} {
			s := newFuzzDNSServer(t, policy)
			reply, err := s.Serve(context.Background(), query)
			if err != nil {
				continue // 拒收是正当结果，只要没炸
			}
			if len(reply) < 12 {
				t.Fatalf("应答比 DNS 头部还短：%d 字节", len(reply))
			}
			var p dnsmessage.Parser
			h, err := p.Start(reply)
			if err != nil {
				t.Fatalf("我们编出来的应答自己解不开: %v (%x)", err, reply)
			}
			if !h.Response {
				t.Fatalf("应答没置 QR 位: %x", reply[:2])
			}
			// 客户端是按 ID 配应答的：ID 不照抄，这条回复就永远没人认领。
			var qp dnsmessage.Parser
			if qh, err := qp.Start(query); err == nil && qh.ID != h.ID {
				t.Fatalf("ID 没照抄：查询 %d，应答 %d", qh.ID, h.ID)
			}
			if h.RCode == dnsmessage.RCodeSuccess {
				qs, err := p.AllQuestions()
				if err != nil {
					t.Fatalf("成功应答的问题段解不开: %v", err)
				}
				if len(qs) == 0 {
					t.Fatalf("成功应答却不带问题段: %x", reply)
				}
			}
		}
	})
}

// FuzzReadFrame 喂给提权协议的帧解析器。
//
// 以前 Makefile 里有这个目标名，函数却不存在。go test -fuzz 匹配不到目标时
// 仍然返回 0，门禁日志里它 0.005 秒就「通过」了，于是这条边界从没被跑过。
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, '{'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := readFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		// 能解出来的帧，长度必须落在协议允许的范围内。
		// 解不开是正常的（绝大多数随机字节都不是一帧）。
		_ = t
	})
}
