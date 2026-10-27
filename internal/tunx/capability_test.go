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
	if len(hy2) != 1 || !strings.Contains(hy2[0], "IPv6") {
		t.Errorf("hy2 只该有 v6 那条: %v", hy2)
	}

	trojan := CapabilityNotes(capabilityConfig("trojan", true))
	if len(trojan) != 2 {
		t.Fatalf("trojan 该有两条: %v", trojan)
	}
	joined := strings.Join(trojan, "\n")
	if !strings.Contains(joined, "trojan") || !strings.Contains(joined, "hysteria2") {
		t.Errorf("trojan 那条没说清替代路径: %s", joined)
	}
}
