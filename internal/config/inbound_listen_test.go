package config

import (
	"strings"
	"testing"
)

func TestListenHostLoopback(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		ok   bool
	}{
		{"127.0.0.1:7891", true, true},
		{"localhost:7891", true, true},
		{"[::1]:7892", true, true},
		{"0.0.0.0:7893", false, true},
		{"[::]:7893", false, true},
		{":7893", false, true},
		{"192.168.1.2:7891", false, true},
		{"127.0.0.1", false, false},
	}
	for _, c := range cases {
		got, err := listenHostLoopback(c.in)
		if c.ok {
			if err != nil || got != c.want {
				t.Errorf("%q: got loopback=%v err=%v; want %v", c.in, got, err, c.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q: 应解析失败，却得到 loopback=%v", c.in, got)
		}
	}
}

func TestValidateInboundListenLoopback(t *testing.T) {
	base := "proxies:\n  - name: a\n    server: {addr: \"a.com:443\", auth: x}\n"
	loopOK := base + "inbounds:\n  - { type: socks5, listen: \"127.0.0.1:7891\" }\n"
	if _, err := Load(writeYAML(t, loopOK)); err != nil {
		t.Fatalf("回环无认证应通过: %v", err)
	}

	nonLoopNoAuth := base + "inbounds:\n  - { type: socks5, listen: \"0.0.0.0:7893\" }\n"
	if _, err := Load(writeYAML(t, nonLoopNoAuth)); err == nil {
		t.Fatal("非回环无认证应失败")
	} else if !strings.Contains(err.Error(), "0.0.0.0:7893") || !strings.Contains(err.Error(), "allow_lan") {
		t.Fatalf("错误信息不可读: %v", err)
	}

	nonLoopAuth := base + "inbounds:\n  - { type: socks5, listen: \"0.0.0.0:7893\", username: u, password: p }\n"
	if _, err := Load(writeYAML(t, nonLoopAuth)); err != nil {
		t.Fatalf("非回环+认证应通过: %v", err)
	}

	nonLoopAllow := base + "inbounds:\n  - { type: socks5, listen: \"0.0.0.0:7893\", allow_lan: true }\n"
	if _, err := Load(writeYAML(t, nonLoopAllow)); err != nil {
		t.Fatalf("非回环+allow_lan 应通过: %v", err)
	}

	httpLAN := base + "inbounds:\n  - { type: http, listen: \"0.0.0.0:7892\", allow_lan: true }\n"
	if _, err := Load(writeYAML(t, httpLAN)); err != nil {
		t.Fatalf("http 非回环+allow_lan 应通过: %v", err)
	}

	httpNoAllow := base + "inbounds:\n  - { type: http, listen: \"0.0.0.0:7892\" }\n"
	if _, err := Load(writeYAML(t, httpNoAllow)); err == nil {
		t.Fatal("http 非回环无 allow_lan 应失败")
	} else if !strings.Contains(err.Error(), "http") || !strings.Contains(err.Error(), "allow_lan") {
		t.Fatalf("http 错误信息: %v", err)
	}
}
