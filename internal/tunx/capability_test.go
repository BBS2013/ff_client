package tunx

import (
	"strings"
	"testing"

	"wps_app/internal/config"
)

func capabilityConfig(proto string, enabled bool) *config.Config {
	return &config.Config{
		Proxies: []config.ProxyProfile{{
			Name: "a",
			Server: config.ServerConfig{
				Type: proto,
				Addr: "example.com:443",
				Auth: "secret",
			},
		}},
		Active: "a",
		TUN:    config.TUNConfig{Enable: enabled},
	}
}

func TestCapabilityNotes(t *testing.T) {
	if got := CapabilityNotes(nil); got != nil {
		t.Errorf("nil 配置不该有告警: %v", got)
	}
	if got := CapabilityNotes(capabilityConfig("hysteria2", false)); got != nil {
		t.Errorf("TUN 没开不该有告警: %v", got)
	}

	hy2 := CapabilityNotes(capabilityConfig("hysteria2", true))
	if len(hy2) != 2 {
		t.Fatalf("hy2 该有两条: %v", hy2)
	}
	// 两条都要说清「按族分开」与「v6 没有端到端证据」。
	joined := strings.Join(hy2, "\n")
	if !strings.Contains(joined, "地址族") || !strings.Contains(joined, "IPv6") {
		t.Errorf("v6 那条没说清接管范围与证据边界: %s", joined)
	}

	trojan := CapabilityNotes(capabilityConfig("trojan", true))
	if len(trojan) != 3 {
		t.Fatalf("trojan 该有三条: %v", trojan)
	}
	joined = strings.Join(trojan, "\n")
	if !strings.Contains(joined, "trojan") || !strings.Contains(joined, "hysteria2") {
		t.Errorf("trojan 那条没说清替代路径: %s", joined)
	}
}

// TestCapabilityNotesKillSwitch：「开了保护但装不上」必须现在就说。
//
// 这道保护只在故障那天才说话，所以它的配置错误绝不能留到那天才发现——
// 而它生效时拦的范围也要写在前面，否则用户会以为它是「断掉一切」。
func TestCapabilityNotesKillSwitch(t *testing.T) {
	cfg := capabilityConfig("hysteria2", true)
	cfg.TUN.KillSwitch = true
	joined := strings.Join(CapabilityNotes(cfg), "\n")
	if !strings.Contains(joined, "不会挂上") {
		t.Errorf("没开 strict_route 时没报出保护不生效: %s", joined)
	}

	cfg.TUN.StrictRoute = true
	joined = strings.Join(CapabilityNotes(cfg), "\n")
	if strings.Contains(joined, "不会挂上") {
		t.Error("已经开了全局接管，却还在报保护装不上")
	}
	if !strings.Contains(joined, "本机生成的出站") {
		t.Errorf("保护生效时也要说清它拦的范围: %s", joined)
	}

	base := strings.Join(CapabilityNotes(capabilityConfig("hysteria2", true)), "\n")
	if strings.Contains(base, "断网保护") {
		t.Errorf("没开保护却报了保护相关的话: %s", base)
	}
}

// TestCapabilityNotesICMPScope 全局接管必须把「ping 是个假信号」说出来。
//
// 这条不是修辞：实测（forward_netns_test.go::TestNetnsICMPIsAnsweredLocallyAndNeverCarried）
// 是「接管前 ping 谁都不通，接管后连不存在的地址都通」。而面板的连接表里一行都没有——
// 用户与脚本默认拿 ping 判断隧道状态，所以这句必须出现在能力边界里，
// 而不是等人踩过才发现。
func TestCapabilityNotesICMPScope(t *testing.T) {
	strict := capabilityConfig("hysteria2", true)
	strict.TUN.StrictRoute = true
	joined := strings.Join(CapabilityNotes(strict), "\n")
	if !strings.Contains(joined, "就地应答") || !strings.Contains(joined, "不代表对端可达") {
		t.Errorf("全局接管却没说清 ICMP 的去处与 ping 的假信号: %s", joined)
	}

	// 选择性接管不吸收公网 ICMP，这句就不该出现——说了反而让人以为自己的 ping 是假的。
	selective := strings.Join(CapabilityNotes(capabilityConfig("hysteria2", true)), "\n")
	if strings.Contains(selective, "就地应答") {
		t.Errorf("没开全局接管却报了 ICMP 被本地应答: %s", selective)
	}
	// TUN 没开时更不该有这句。
	if strings.Contains(strings.Join(CapabilityNotes(capabilityConfig("hysteria2", false)), "\n"), "就地应答") {
		t.Error("TUN 没开，不该有 ICMP 应答的告警")
	}
}
