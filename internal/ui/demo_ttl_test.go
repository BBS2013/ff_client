package ui

// 演示里那句"缓存挂多久"与后端默认值必须对得上，而那一格倒计时的压缩必须是有意的。
//
// 两处抄来的数：
//   - 状态卡上那句 `dnsCache: "5m0s"` 抄的是 `dns.cache` 的默认值（config.applyDefaults 填出来的）；
//   - 「看解析」那一格"还剩多久自己换成新的"倒的是 **60 秒**，那是刻意压短的——
//     挂 5 分钟的话，"到点自己过期"这一档在演示里永远点不出来（§10.6 那批缺档返工的同一个形状）。
//
// 所以这条守卫两头都管：抄错默认值要红，而压缩要是被压没了（演示倒计时 ≥ 真 TTL）也要红——
// 后者意味着有人把演示改成"演得出过期"以外的东西，那这一档就again点不出来了。

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"wps_app/internal/config"
)

func TestDemoDNSCacheNumbersMatchGo(t *testing.T) {
	src := demoSource(t)

	want := defaultDNSCache(t)

	// 1) 状态卡里那句 dns.cache。
	tag := regexp.MustCompile(`dnsCache:\s*'([^']+)'`).FindStringSubmatch(src)
	if tag == nil {
		t.Fatal("演示里没有 dnsCache 那一句——状态卡上'缓存挂多久'这一格没数据可演")
	}
	d, err := time.ParseDuration(tag[1])
	if err != nil {
		t.Fatalf("演示里的 dnsCache %q 不是个时长", tag[1])
	}
	if d != want {
		t.Errorf("演示状态卡说缓存挂 %v，后端 dns.cache 默认是 %v——改默认值要把演示一起改", d, want)
	}

	// 2) 那一格的倒计时是被刻意压短的，压过真 TTL 就等于把这一档又点不出来了。
	m := regexp.MustCompile(`DEMO_DNS_TTL_MS\s*=\s*([\d_]+)`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("演示源码里没有 DEMO_DNS_TTL_MS——「还剩多久自己换成新的」那一行又没有数可以对照了")
	}
	n, err := strconv.ParseInt(regexp.MustCompile(`_`).ReplaceAllString(m[1], ""), 10, 64)
	if err != nil {
		t.Fatalf("读不出 DEMO_DNS_TTL_MS: %q", m[1])
	}
	if n <= 0 || time.Duration(n)*time.Millisecond >= want {
		t.Errorf("演示的倒计时 %dms 没有比真 TTL（%v）短：这一格在演示里点不出「到点自己过期」", n, want)
	}
	// 也不能压到没人能看清：短于 10 秒的话，那一行小字在两次点击之间就跳没了。
	if n < 10_000 {
		t.Errorf("演示的倒计时 %dms 压得太狠，界面上那一行跳得太快，读不出它在说什么", n)
	}
}

// defaultDNSCache 走一遍真配置：读一份只填必填项的 YAML，让 applyDefaults 填出 dns.cache。
// 不直接把 300 写在这里——那样这条守卫就只是在和一份自己抄的常数比。
func defaultDNSCache(t *testing.T) time.Duration {
	t.Helper()
	f := filepath.Join(t.TempDir(), "c.yaml")
	body := "server:\n  addr: \"example.com:443\"\n  auth: \"secret\"\n" +
		"inbounds:\n  - { type: socks5, listen: \"127.0.0.1:0\" }\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(f)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DNS.Cache.Duration <= 0 {
		t.Fatalf("dns.cache 默认值没填出来（%v），这条守卫无从比起", cfg.DNS.Cache.Duration)
	}
	return cfg.DNS.Cache.Duration
}
