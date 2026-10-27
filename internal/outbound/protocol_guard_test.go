package outbound

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
)

// TestEveryProtocolGetsItsOwnImplementation 每个登记的协议都必须拿到**它自己**的实现。
//
// 这条用例守的是 `outbound.New` 的 default 分支：新协议只要进了 config.Protocols
// 却没在这里加 case，就会被当 hysteria2 去拨（auth 当 QUIC key、TLS 参数整个忽略），
// 症状是"连接超时"而不是"不支持这个协议"——照着超时去查网络，永远查不到根因。
func TestEveryProtocolGetsItsOwnImplementation(t *testing.T) {
	for _, proto := range config.Protocols {
		var sc config.ServerConfig
		sc.Type = proto
		sc.Addr = "127.0.0.1:443"
		sc.Auth = "placeholder"
		sc.TLS.SNI = "example.invalid"
		switch proto {
		case config.ProtocolHysteria2:
			sc.Bandwidth = config.BandwidthConfig{Up: "100 mbps", Down: "100 mbps"}
		case config.ProtocolTrojan:
			// trojan 不该被要求填 hysteria 专属字段；这里刻意留空。
		default:
			t.Errorf("协议 %q 已登记但本用例没 expectations：新增协议时要在这里说明它该拿到什么实现", proto)
		}
		c, err := New(sc, time.Second, nil, netip.Prefix{}, nil)
		if err != nil {
			t.Errorf("协议 %q 装配失败（要么没接入实现，要么字段要求变了）: %v", proto, err)
			continue
		}
		_ = c.Close()
	}
}

// TestUnknownProtocolIsRefused 未接入的协议必须报错，不能落到任何一个实现上。
func TestUnknownProtocolIsRefused(t *testing.T) {
	for _, proto := range []string{"ss", "vmess", "trojan-grpc", "HY2"} {
		var sc config.ServerConfig
		sc.Type = proto
		sc.Addr = "127.0.0.1:443"
		sc.Auth = "x"
		c, err := New(sc, time.Second, nil, netip.Prefix{}, nil)
		if err == nil {
			_ = c.Close()
			t.Errorf("协议 %q 竟然被接受并装配了：未接入的协议必须拒绝", proto)
			continue
		}
		msg := err.Error()
		// 断言语义而不是措辞：要点名是哪个协议、并告诉用户可选什么。
		// 装配被拒（"还没接入实现"）和解析被拒（"不支持的协议"）都算对——
		// 要紧的是绝不能悄悄按 hysteria2 拨出去。
		if !strings.Contains(msg, proto) || !strings.Contains(msg, "hysteria2") {
			t.Errorf("错误要点名 %q 并给出可选项，实际 %q", proto, err)
		}
	}
}
