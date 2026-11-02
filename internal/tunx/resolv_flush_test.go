//go:build linux

package tunx

import (
	"context"
	"strings"
	"testing"

	"wps_app/internal/config"
)

// 2026-10-29 实测到的那一脚：面板停掉之后 `getent hosts www.google.com`
// 还在回 198.18.0.9——systemd-resolved 把假 IP 缓存住了，指向一块已经不存在的网卡。
// 用户看到的症状是「代理关了，浏览器反而几分钟上不了网」，而这段窗口里
// 面板已经退出、日志里什么都没有。
//
// 所以两头都要刷：装好劫持之后刷（把之前问到的真 IP 清掉，去向下落才完整），
// 拆掉劫持之后再刷（把假 IP 清掉，别把人送进不存在的网卡）。
func TestTeardownFlushesResolverCacheAfterRemovingHijack(t *testing.T) {
	conf := config.DefaultTUN()
	conf.Enable = true
	r := &recorderRunner{}
	tun := newDualTUN(t, r)
	tun.plan = RoutePlan{
		Device: conf.Device, Address: conf.Address, MTU: conf.MTU,
		HijackDNS: true, DNS: conf.DNS, UID: 1000, Upstreams: []string{"223.5.5.5"},
	}

	if err := tun.teardownLocked(context.Background()); err != nil {
		t.Fatalf("拆除报错: %v", err)
	}
	cmds := r.snapshot()
	flushAt, lastIptables := -1, -1
	for i, c := range cmds {
		if c == "resolvectl flush-caches" {
			flushAt = i
		}
		if strings.HasPrefix(c, "iptables") {
			lastIptables = i
		}
	}
	if flushAt < 0 {
		t.Fatalf("拆除之后没有刷系统解析器缓存，缓存里的假 IP 会一直用到过期: %v", cmds)
	}
	if lastIptables >= 0 && flushAt < lastIptables {
		t.Errorf("刷缓存排在了拆劫持规则之前（顺序反了：那时假 IP 还会被写回缓存）: %v", cmds)
	}
}

// TestFlushResolverCacheToleratesFailure 刷不动不是错误：
// 没有 systemd-resolved 的机器上这条命令本来就不存在，接管与拆除都不该因此失败。
func TestFlushResolverCacheToleratesFailure(t *testing.T) {
	conf := config.DefaultTUN()
	r := &recorderRunner{fail: map[string]error{"resolvectl flush-caches": context.DeadlineExceeded}}
	tun := newDualTUN(t, r)
	tun.flushResolverCache(context.Background()) // 不 panic、不返回错误就是通过
	if tun.conf.Device != conf.Device {
		t.Fatalf("harness 变了: %q", tun.conf.Device)
	}
}
