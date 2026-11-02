package service

import (
	"strings"
	"testing"
)

// 这两句都被读成"节点不行"，而 2026-10-29 现场里它们是同一件事的两种形状：
// 出口链路上的设备在替我们终止 TLS。不补这一句，下一轮又会照着"节点坏了"去查。
func TestAnnotateNodeFaultCoversBothTLSShapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"trojan tls handshake: tls: failed to verify certificate: x509: certificate signed by unknown authority", "链路上有设备"},
		{"TLS 握手失败: tls: first record does not look like a TLS handshake", "兼底页"},
	}
	for _, c := range cases {
		got := annotateNodeFault(c.in, "")
		if !strings.Contains(got, c.want) {
			t.Errorf("%q 的补充里没提到 %q: %q", c.in, c.want, got)
		}
		if !strings.HasPrefix(got, c.in) {
			t.Errorf("失败原文必须原样留着（那是可核对的证据），得到 %q", got)
		}
	}
}

// 分流没真的生效时，同一句红要先看自己这台机器——这一条必须出现在句子里，
// 而不是只在另一页的分流卡片上。
func TestAnnotateNodeFaultMentionsSplit(t *testing.T) {
	msg := "x509: certificate signed by unknown authority"
	got := annotateNodeFault(msg, "开关已打开，但钉在 wlx001f0578cdff 上发不出包")
	if !strings.Contains(got, "没有真的钉在点名的网卡上") {
		t.Fatalf("分流没生效这件事必须一起写上: %q", got)
	}
}

// 其余失败一律不加注：拨不通、超时、DNS 各自有原因，硬塞一句"可能是链路设备"
// 会把人往错的方向带。
func TestAnnotateNodeFaultLeavesOthersAlone(t *testing.T) {
	for _, in := range []string{
		"",
		"dial trojan server 1.2.3.4:8443: dial tcp: i/o timeout",
		"服务端在读完请求头后断开了连接（口令不对或目标不可达）",
	} {
		if got := annotateNodeFault(in, ""); got != in {
			t.Errorf("不该被改写: %q → %q", in, got)
		}
	}
	if got := annotateNodeFault("x509: certificate signed by unknown authority", ""); strings.Contains(got, "钉在") {
		t.Errorf("分流正常时不该提网卡: %q", got)
	}
}

// 分流没开 + 证书不受信：这两件事要一起说。出口上有人替换证书是最常见的成因，
// 而"分流没开"正是我们能立刻改的那一件——不说它就等于让人去查节点。
func TestAnnotateNodeFaultSaysSplitIsOff(t *testing.T) {
	msg := "trojan tls handshake: tls: failed to verify certificate: x509: certificate signed by unknown authority"
	got := annotateNodeFault(msg, "网卡分流没开，代理流量走的是系统默认路由")
	if !strings.Contains(got, "网卡分流没开") {
		t.Fatalf("分流没开这件事必须出现在句子里: %q", got)
	}
	if !strings.Contains(got, "链路上有设备") {
		t.Fatalf("证书这一句要保留另一种成因: %q", got)
	}
}
