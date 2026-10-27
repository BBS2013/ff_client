package tunx

import (
	"context"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"wps_app/internal/rules"
)

// queryWithRawName 手工拼一条查询报文：名字段原样塞进去（含 NUL 这种非法形状），
// 因为 dnsmessage.Builder 会拒绝写非法名字。
func queryWithRawName(t *testing.T, rawName []byte, typ dnsmessage.Type) []byte {
	t.Helper()
	head := []byte{0x0a, 0x0b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// 一个标签 = 长度字节 + 原文，再跟根标签的 0x00 终止符，然后才是 qtype/qclass。
	body := append([]byte{byte(len(rawName))}, rawName...)
	body = append(body, 0x00, 0x00, byte(typ), 0x00, 0x01)
	return append(head, body...)
}

// TestDNSServerRefusesGarbageNames 名字要当规则判定的键与假 IP 池的索引，
// 所以 NUL、控制字符、带 ':' 的名字必须在边界上就被挡成 NODATA。
//
// 这条是被 FuzzDNSServe 教出来的：修之前 `\\x00` 会被当成一个正常域名发假 IP。
func TestDNSServerRefusesGarbageNames(t *testing.T) {
	garbage := [][]byte{{0x00}, []byte("a\x00b"), []byte("a b"), []byte("a:b"), []byte{0x7f}}
	for _, g := range garbage {
		s := newFuzzDNSServer(t, rules.PolicyProxy)
		reply, err := s.Serve(context.Background(), queryWithRawName(t, g, dnsmessage.TypeA))
		if err != nil {
			t.Fatalf("名字 %q 不该让应答器报错: %v", g, err)
		}
		var p dnsmessage.Parser
		h, err := p.Start(reply)
		if err != nil {
			t.Fatalf("应答解不开: %v", err)
		}
		if h.RCode != dnsmessage.RCodeSuccess {
			t.Errorf("名字 %q 应回 NODATA（成功但没有答案），实得 rcode=%d", g, h.RCode)
		}
		// dnsmessage 的解析器是单向游标：问题段没读完就读应答段，会得到
		// "parsing/packing of this type isn't available yet"。
		if _, err := p.AllQuestions(); err != nil {
			t.Fatalf("读问题段: %v", err)
		}
		answers, err := p.AllAnswers()
		if err != nil {
			t.Fatalf("读应答段: %v", err)
		}
		if len(answers) != 0 {
			t.Errorf("名字 %q 竟然拿到了 %d 条假 IP", g, len(answers))
		}
	}
	// 正常名字必须照旧拿假 IP——否则这条守卫就成了"什么都不答"。
	// 真名字要按标签切开编码（"ok"、"example"），所以这里用 BuildQuery；
	// 上面那个手工拼的函数只负责往名字段里塞非法字节。
	good, err := BuildQuery("ok.example.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	s := newFuzzDNSServer(t, rules.PolicyProxy)
	reply, err := s.Serve(context.Background(), good)
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(reply); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	if len(answers) != 1 {
		t.Fatalf("正常域名该拿到 1 条假 IP，实得 %d", len(answers))
	}
}
