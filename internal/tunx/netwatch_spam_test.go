//go:build linux

package tunx

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"wps_app/internal/logx"
)

// 2026-10-29 的现场：一张 USB 网卡消失之后，面板每 5 秒往日志里写一条
// 「TUN: 网络断了（…），绕行路由保持原样」，直到网络回来。
// 这条话本身是对的（那时确实没有网关，绕行路由也确实该保持原样），
// 但它同一句话重复几十遍，会把同一时间段里真正要看的东西——
// 「拨不通」「隧道故障」——全埋掉。
//
// 所以判据是**条数**：一次中断一条，恢复一条，之后不再重复。
func TestNetworkDownWarningSpeaksOncePerEpisode(t *testing.T) {
	r := &netRunner{v4out: "", v6out: ""}
	tun := newWatchTUN(t, r)
	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	tun.plan = plan
	tun.initNetWatch(plan)

	var mu sync.Mutex
	var down, back int
	remove := logx.AddHook(func(level logx.Level, msg string, _ time.Time) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.Contains(msg, "网络断了"):
			down++
		case strings.Contains(msg, "网络回来了"):
			back++
		}
	})
	defer remove()

	ctx := context.Background()
	// 前四轮：第一轮只是「看到变化，先看着」，后面三轮才是「确实没网关」。
	for i := 0; i < 4; i++ {
		tun.checkNetworkChanged(ctx)
	}
	if down != 1 {
		t.Fatalf("一次中断里「网络断了」打了 %d 条，want 1（每 5 秒一条会把日志刷满）", down)
	}
	if back != 0 {
		t.Fatalf("网络还没回来就报了恢复: %d", back)
	}

	// 网关回来了：先把默认路由放回去，等它落定。
	r.v4out = "default via 192.168.5.1 dev wlp3s0f0 proto dhcp metric 20600"
	for i := 0; i < 2; i++ {
		tun.checkNetworkChanged(ctx)
	}
	if back != 1 {
		t.Fatalf("网络回来这件事说了 %d 次，want 1", back)
	}
	// 再跑几轮：恢复了就不该再提。
	for i := 0; i < 3; i++ {
		tun.checkNetworkChanged(ctx)
	}
	if back != 1 || down != 1 {
		t.Fatalf("稳定之后还在刷：down=%d back=%d（want 1/1）", down, back)
	}

	// 第二次中断要重新说一次：它不是同一件事，读日志的人需要知道又断过。
	r.v4out = ""
	for i := 0; i < 4; i++ {
		tun.checkNetworkChanged(ctx)
	}
	if down != 2 {
		t.Errorf("第二次中断只说了 %d 条，want 2（每次中断都该有一条）", down)
	}
}
