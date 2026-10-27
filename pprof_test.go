package main

import "testing"

func TestPprofListenAddrOnlyLoopback(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"127.0.0.1:6060", "127.0.0.1:6060", true},
		{"localhost:6060", "127.0.0.1:6060", true},
		{"[::1]:6060", "[::1]:6060", true},
		{":6060", "", false},
		{"0.0.0.0:6060", "", false},
		{"192.168.1.2:6060", "", false},
		{"127.0.0.1", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, err := pprofListenAddr(c.in)
		if c.ok {
			if err != nil || got != c.want {
				t.Errorf("%q: got %q, %v; want %q", c.in, got, err, c.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("%q: 应被拒绝，却得到 %q", c.in, got)
		}
	}
}
