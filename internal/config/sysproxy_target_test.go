package config

import "testing"

// TestSystemProxyTargetFollowsConfig 系统代理该指到哪儿，答案只有一个出处。
//
// -sysproxy on、面板的开关、启动时的孤儿检查都用它。写死 127.0.0.1:7892 的话，
// 换了端口的配置会让桌面指向一个没人听的端口，用户只看到「代理连接被拒绝」，
// 而孤儿检查会因为端口对不上而闭嘴——最该报警的那一种反而不报。
func TestSystemProxyTargetFollowsConfig(t *testing.T) {
	cases := []struct {
		name        string
		cfg         Config
		wantBackend string
		wantHTTP    string
		wantSOCKS   string
	}{
		{
			name: "本机默认端口",
			cfg: Config{Inbounds: []InboundConfig{
				{Type: "socks5", Listen: "127.0.0.1:7891"},
				{Type: "http", Listen: "127.0.0.1:7892"},
			}},
			wantHTTP: "127.0.0.1:7892", wantSOCKS: "127.0.0.1:7891",
		},
		{
			name: "改过端口",
			cfg: Config{Inbounds: []InboundConfig{
				{Type: "socks5", Listen: "127.0.0.1:1080"},
				{Type: "http", Listen: "127.0.0.1:8118"},
			}},
			wantHTTP: "127.0.0.1:8118", wantSOCKS: "127.0.0.1:1080",
		},
		{
			name:        "指定后端",
			cfg:         Config{SysProxy: SysProxyConfig{Backend: " env "}, Inbounds: []InboundConfig{{Type: "socks5", Listen: "127.0.0.1:1080"}}},
			wantBackend: "env", wantSOCKS: "127.0.0.1:1080",
		},
		{
			name:     "只开 socks 时 http 留空给默认",
			cfg:      Config{Inbounds: []InboundConfig{{Type: "socks5", Listen: "127.0.0.1:1080"}}},
			wantHTTP: "", wantSOCKS: "127.0.0.1:1080",
		},
		{
			name:     "一个入站都没有",
			cfg:      Config{},
			wantHTTP: "", wantSOCKS: "",
		},
		{
			name: "同类重复取第一条",
			cfg: Config{Inbounds: []InboundConfig{
				{Type: "http", Listen: "127.0.0.1:8118"},
				{Type: "http", Listen: "127.0.0.1:9999"},
			}},
			wantHTTP: "127.0.0.1:8118",
		},
		{
			name: "listen 留空白交给默认值",
			cfg:  Config{Inbounds: []InboundConfig{{Type: "http", Listen: "   "}}},
		},
	}
	for _, c := range cases {
		backend, http, socks := c.cfg.SystemProxyTarget()
		if backend != c.wantBackend || http != c.wantHTTP || socks != c.wantSOCKS {
			t.Errorf("%s: 得到 backend=%q http=%q socks=%q, 期望 backend=%q http=%q socks=%q",
				c.name, backend, http, socks, c.wantBackend, c.wantHTTP, c.wantSOCKS)
		}
	}
}
