//go:build linux

package tunx

import (
	"context"
	"testing"
	"time"
)

// 这一条盯的是面板上那两格「IPv4/IPv6 是否已接管」到底是谁在说话。
//
// 之前它读的是本进程的记忆：装上的那一刻之后，只要默认路由被别人改回去
// （DHCP 续约、NetworkManager 重启、另一个 VPN 起来），
// 界面会继续显示「已接管」，而机器的公网流量其实已经从物理卡出去了——
// 这正是「面板说接管、其实没接管」那种最贵的错。
// 现在这一格去问内核，所以这里演的是**接管被抢回去**的现场：
// 进程什么都不知道、也没重启，界面必须自己改口。

// TestNetnsPanelTakeoverFollowsKernel 内核改主意，面板就得改口。
func TestNetnsPanelTakeoverFollowsKernel(t *testing.T) {
	if !fwReady() || !netnsReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1 + 私有 netns）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	r := ExecRunner{}
	fwEnsureNIC(t, ctx, r)
	fwMust(t, ctx, r, "ip", "route", "replace", "default", "via", restartGW, "dev", "fwphys0", "metric", "20600")

	tun := startHijackTUN(t, ctx, true, false)
	const dev = "wps-tun"

	st := tun.Status()
	if !st.TakeoverV4 {
		t.Fatalf("接管刚装上，面板却说没接管（来源标的是 %q）", st.TakeoverFrom)
	}
	if st.TakeoverFrom != "kernel" {
		t.Fatalf("这一格没问到内核，来源应当是 kernel，实际 %q", st.TakeoverFrom)
	}

	// 把默认路由抢回物理卡：不碰 TUN 本身，它还在跑、栈还活着。
	fwMust(t, ctx, r, "ip", "route", "del", "default", "dev", dev)
	fwMust(t, ctx, r, "ip", "route", "replace", "default", "via", restartGW, "dev", "fwphys0", "metric", "20600")
	// 本进程这边什么都没变——这正是老写法会说谎的那个前提。
	if !tun.running || !tun.conf.StrictRoute || tun.plan.Gateway == "" {
		t.Fatal("现场条件变了：进程已经不「相信」自己在接管，这条用例证明不了什么")
	}

	// 界面必须在一个探测周期内自己改口（缓存 TTL 是 2 秒，给足到 10 秒）。
	if !waitSome(10*time.Second, func() bool { return !tun.Status().TakeoverV4 }) {
		t.Error("默认路由都被抢回去了，面板还在报 IPv4 已接管")
	}
	// 反向也要成立：把接管装回去，那一格得跟着变回来。
	fwMust(t, ctx, r, "ip", "route", "add", "default", "dev", dev)
	tun.checkNetworkChanged(ctx)
	if st := tun.Status(); !st.TakeoverV4 {
		t.Errorf("默认路由重新交给 tun 了，面板还在报未接管（来源 %q）", st.TakeoverFrom)
	}
}
