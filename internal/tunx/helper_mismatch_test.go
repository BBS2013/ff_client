//go:build linux

package tunx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// 这一组管的是 2026-10-29 09:16 真实响过一次的那条失败路径。
//
// 现场：跑着的面板是提交版构建（helper 协议 1），而 `make build-gui` 刚把
// tun.helper 指向的那个文件刷成了工作树版本（协议 3）。从那一刻起这个进程
// 再也开不了 TUN——每一次特权请求都被同一句话拒掉。
// 日志里只有那句「helper 协议版本 1 不被支持（本程序是 3）」：
// 两个数字都摆出来了，却没有一句说该重启面板还是该重装 helper，
// 而每按一次开关都会再多两趟注定白跑的 root 调用。
//
// 所以这里要钉住两件事：错误必须自己说清「动哪一边」，
// 以及已知对不上之后不许再白跑（但用户显式的启用仍然实打实试一次，
// 因为把文件刷新的那一刻就该立刻恢复）。

// mismatchHelper 造一个「对面是另一个构建」的 helper：它不干我们的活，
// 只原样回一句别的构建会说的那句话。用真套接字回，是为了让解析走真实形状——
// 那句话由对面生成，我们只能读，不能假装它一定长成本包的格式。
func mismatchHelper(t *testing.T, text string, calls *atomic.Int32) HelperClient {
	t.Helper()
	payload, err := encodeReply(HelperReply{OK: false, Err: text})
	if err != nil {
		t.Fatal(err)
	}
	return HelperClient{
		Timeout: 3 * time.Second,
		Spawn: func(_ context.Context, socketPath string) error {
			calls.Add(1)
			go func() {
				conn, derr := net.Dial("unix", socketPath)
				if derr != nil {
					return
				}
				uc, ok := conn.(*net.UnixConn)
				if !ok {
					_ = conn.Close()
					return
				}
				// 先把请求读完再答：真 helper 就是这么干的。
				// 抢在对面写完之前把套接字关掉，面板拿到的会是 broken pipe，
				// 测的就不是「对面说了什么」而是「对面没听完」。
				if _, rerr := readFrame(uc); rerr != nil {
					_ = uc.Close()
					return
				}
				_ = writeFrame(uc, payload)
				_ = uc.Close()
			}()
			return nil
		},
	}
}

// rejectionText 按对面那句话的格式现拼：数字由参数给，别让测试把常量写死，
// 否则哪天抬版本时这条会一起变绿——那正是它最该变红的时候。
func rejectionText(mine, theirs int) string {
	return fmt.Sprintf("helper 协议版本 %d 不被支持（本程序是 %d）", mine, theirs)
}

func TestHelperRejectionNamesTheStaleSide(t *testing.T) {
	argv := []string{"sudo", "-n", "/home/dev/wps_app", "--tun-helper"}

	cases := []struct {
		name      string
		text      string
		wantParts []string
	}{
		{
			// 生产里真响的那一支：helper 文件比跑着的面板新。
			name:      "helper 比面板新",
			text:      rejectionText(helperProtoVersion, helperProtoVersion+5),
			wantParts: []string{"比面板新", "重启面板", "/home/dev/wps_app"},
		},
		{
			// 反方向：装在那里的还是老构建（升级了面板、忘了刷 helper）。
			name:      "helper 比面板旧",
			text:      rejectionText(helperProtoVersion+5, helperProtoVersion),
			wantParts: []string{"比跑着的面板", "旧", "make build-gui", "/home/dev/wps_app"},
		},
		{
			// 认得出是版本问题却读不出数字（更老的措辞）：不许猜一个版本糊过去。
			name:      "读不出对面版本",
			text:      "helper 协议版本对不上，不被支持",
			wantParts: []string{"读不出对方的版本", "/home/dev/wps_app"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mine, theirs, ok := helperVersionRejection(tc.text)
			if !ok {
				t.Fatalf("这句明明就是版本拒绝，却没认出来: %q", tc.text)
			}
			advice := helperMismatchAdvice(mine, theirs, argv)
			for _, part := range tc.wantParts {
				if !strings.Contains(advice, part) {
					t.Errorf("建议里缺了 %q，用户照着做不了: %s", part, advice)
				}
			}
		})
	}

	// 反向也要守：其它 helper 失败不能被当成版本问题。
	// 把「sudo 要密码」报成「请重启面板」，用户重启完还是失败，只会多绕一圈。
	for _, text := range []string{
		"sudo: 需要密码",
		"helper 没有连回来: signal: killed",
		"经 tun.helper 开网卡失败: 启用网卡失败: Operation not permitted",
	} {
		if _, _, ok := helperVersionRejection(text); ok {
			t.Errorf("把不是版本问题的失败认成了版本问题: %q", text)
		}
	}
}

// TestHelperMismatchSilencesTheDoomedRoundTrip 已知两边对不上之后，
// 清残留那趟注定白跑的 root 调用必须省掉；但用户显式启用要照旧实打实试一次，
// 否则文件刷新之后这个进程再也恢复不了。
func TestHelperMismatchSilencesTheDoomedRoundTrip(t *testing.T) {
	var calls atomic.Int32
	tun := helperTUNT(t)
	tun.helper = mismatchHelper(t, rejectionText(helperProtoVersion, helperProtoVersion+1), &calls)

	// 第一次：清残留与开网卡各问一次（这时还不可能知道对面版本不对）。
	if err := tun.Start(context.Background()); err == nil {
		t.Fatal("对面拒收，Start 却成功了")
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("第一次启用起了 %d 趟 helper 调用, want 2（清残留 + 开网卡）", got)
	}
	if !tun.helperMismatchKnown() {
		t.Fatal("被版本拒绝过一次却没记住")
	}

	// 第二次：清残留必须跳过，只留开网卡那一次真实尝试。
	if err := tun.Start(context.Background()); err == nil {
		t.Fatal("对面还是拒收，Start 却成功了")
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("已知版本对不上之后仍然起了 %d 趟调用（want 3：跳过清残留、保留开网卡）", got)
	}

	// 过期之后必须重新去问：那条「对不上」是会被外部修好的（刷文件、重启面板），
	// 本进程不该把它当成永久事实。
	tun.helperMismatchAt.Store(time.Now().Add(-2 * helperMismatchSilence).UnixMilli())
	if tun.helperMismatchKnown() {
		t.Fatal("过了保质期还说「已知对不上」，等于永久拉黑 helper")
	}
	_ = tun.Start(context.Background())
	if got := calls.Load(); got != 5 {
		t.Errorf("过期后没重新问（%d 趟调用, want 5：清残留 + 开网卡 又各一次）", got)
	}
}

// TestHelperMismatchTextReachesThePanel 界面上那行错误必须自带处方。
// 只有两个版本号的原文进了面板，和用户自己去看日志是一回事——什么都没多说。
func TestHelperMismatchTextReachesThePanel(t *testing.T) {
	var calls atomic.Int32
	tun := helperTUNT(t)
	text := rejectionText(helperProtoVersion, helperProtoVersion-2)
	tun.helper = mismatchHelper(t, text, &calls)

	err := tun.Start(context.Background())
	if err == nil {
		t.Fatal("对面拒收，Start 却成功了")
	}
	st := tun.Status()
	if st.LastError == "" {
		t.Fatal("面板拿不到任何错误")
	}
	if !strings.Contains(st.LastError, text) {
		t.Errorf("把原文丢了，界面读不到对面到底说了什么: %s", st.LastError)
	}
	for _, part := range []string{"比跑着的面板", "旧", "make build-gui", "/home/dev/wps_app"} {
		if !strings.Contains(st.LastError, part) {
			t.Errorf("面板上那行缺 %q，用户还是不知道该动哪一边: %s", part, st.LastError)
		}
	}
	// 指名道姓这件事必须来自配置：这个 harness 里的客户端结构体根本没有 Argv
	// （只有 Spawn），拿得到路径只可能是因为读的是 conf.Helper。
	if len(tun.helper.Argv) != 0 {
		t.Fatalf("这个用例的前提是客户端没有 Argv，want 0, got %v", tun.helper.Argv)
	}
}

// TestHelperMismatchForgottenOnSuccess 一次成功的往返就是「两边其实对得上」的实测证据：
// 缓存必须当场作废，不然刚刷完文件的那次启用会被自己上一轮的结论挡在门外。
func TestHelperMismatchForgottenOnSuccess(t *testing.T) {
	var calls atomic.Int32
	tun := helperTUNT(t)
	tun.helper = mismatchHelper(t, rejectionText(helperProtoVersion, helperProtoVersion+1), &calls)
	if err := tun.Start(context.Background()); err == nil {
		t.Fatal("对面拒收，Start 却成功了")
	}
	if !tun.helperMismatchKnown() {
		t.Fatal("没记住这次不匹配")
	}

	devFD, _ := socketPair(t)
	tun.helper = helperTestServer(&HelperServer{
		Runner:  &recorderRunner{},
		Open:    func(string) (int, error) { return devFD, nil },
		MTU:     func(string) (uint32, error) { return uint32(tun.conf.MTU), nil },
		Timeout: 5 * time.Second,
		PeerUID: func(*net.UnixConn) (int, error) { return 1000, nil },
	})
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tun.provision(context.Background(), plan); err != nil {
		t.Fatalf("对面换成同一个构建之后 provision 仍失败: %v", err)
	}
	if tun.helperMismatchKnown() {
		t.Error("helper 已经答成功了，还留着「版本对不上」的结论")
	}
}

// TestRerouteSkipsWhileMismatchKnown 跑着的 TUN 也会遇上版本错位：
// 面板起来之后有人 `make build-gui`，把 tun.helper 指着的那个文件换成了另一个构建。
// 从那一刻起监视器每 5 秒一轮都会去请求重钉，每一轮都被同一句话拒、每一轮一条 WARN——
// 日志被同一件事刷满，而绕行路由其实早就没跟着新网关走了。
func TestRerouteSkipsWhileMismatchKnown(t *testing.T) {
	var calls atomic.Int32
	r := &netRunner{
		v4out: "default via 192.168.1.1 dev wlp3s0f1 proto dhcp metric 20600",
		v6out: "default via fe80::5 dev wlp3s0f1 proto ra metric 20600 pref medium",
	}
	tun := newWatchTUN(t, r)
	tun.conf.Helper = []string{"sudo", "-n", "/home/dev/wps_app", "--tun-helper"}
	tun.helper = mismatchHelper(t, rejectionText(helperProtoVersion, helperProtoVersion+1), &calls)

	plan := dualPlan()
	plan.Exclude = []string{"192.168.5.1/32", "2001:db8::1/128"}
	tun.plan = plan
	tun.initNetWatch(plan)
	ctx := context.Background()

	// 网关换了：两轮落定之后该重钉 → 第一次真的去问（那时还不知道对面版本不对）。
	tun.checkNetworkChanged(ctx)
	tun.checkNetworkChanged(ctx)
	if got := calls.Load(); got != 1 {
		t.Fatalf("重钉起了 %d 趟 helper 调用, want 1", got)
	}
	if tun.routeFixes.Load() != 0 {
		t.Fatalf("重钉明明失败了，routeFixes 却涨了: %d", tun.routeFixes.Load())
	}
	if tun.plan.Gateway != "192.168.5.1" {
		t.Errorf("重钉失败却把计划改了，进程从此以为绕行路由钉在新网关上: %+v", tun.plan)
	}

	// 后面几轮：已知对不上，就一轮都不该再去问（而监视器并不会停下来）。
	for i := 0; i < 4; i++ {
		tun.checkNetworkChanged(ctx)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("已知版本对不上之后监视器又起了 %d 趟调用（want 仍然 1）——每 5 秒一趟白跑，"+
			"还会每趟留一条 WARN", got-1)
	}

	// 过期之后重新去问：文件被刷新的那一刻，这一路要能自己恢复。
	tun.helperMismatchAt.Store(time.Now().Add(-2 * helperMismatchSilence).UnixMilli())
	tun.checkNetworkChanged(ctx)
	if got := calls.Load(); got != 2 {
		t.Errorf("过期后没有重新尝试重钉: %d 趟调用, want 2", got)
	}
}

// TestTeardownNeverSkipsHelperMismatch 这条是上面那条的反面，而且更重要：
// 拆除（拆路由/网卡与摘保护）**永远照发**，哪怕已知版本对不上。
// 跳过不会让失败变小，只会让它改名——机器上留下的是一条还在拦出站的链、
// 一块还在吸流量的网卡，而面板写着「已停止」。
func TestTeardownNeverSkipsHelperMismatch(t *testing.T) {
	var calls atomic.Int32
	tun := helperTUNT(t)
	tun.helper = mismatchHelper(t, rejectionText(helperProtoVersion, helperProtoVersion+1), &calls)
	// 先把「已知对不上」这个结论摆上（跳过分支的依据就是它）。
	if advice := tun.noteHelperMismatch(rejectionText(helperProtoVersion, helperProtoVersion+1)); advice == "" {
		t.Fatal("前置：这条错误没被认成版本问题")
	}
	if !tun.helperMismatchKnown() {
		t.Fatal("前置：已知结论没生效")
	}

	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = tun.releaseSystem(context.Background(), plan)
	if err == nil {
		t.Fatal("对面拒收，拆除却报告成功")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("拆除这一路只该实打实发一次，want 1, got %d（0 就是被跳过了）", got)
	}
	if !strings.Contains(err.Error(), "不能跳") {
		t.Errorf("拆除失败要当场说清「这一步没有跳过」，否则读日志的人会以为是我们偷懒: %v", err)
	}
	if !strings.Contains(err.Error(), "/home/dev/wps_app") {
		t.Errorf("拆除失败也得给出该动哪一边的处方: %v", err)
	}
}

// helperTUNT 造一个「配了 tun.helper」的 TUN：helper 客户端由调用方换成进程内的，
// argv 留着一个像真的路径，好让建议里那句「要动哪个文件」可断言。
// Runner 用替身：探测默认路由这一步必须离线也能跑，不能依赖宿主机上恰好有什么。
func helperTUNT(t *testing.T) *TUN {
	t.Helper()
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.Helper = []string{"sudo", "-n", "/home/dev/wps_app", "--tun-helper"}
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(time.Second), nil), time.Second)
	// 显式钉住非 root：helper 路径只对普通用户存在，root 面板会直接开网卡
	// （见 helperArgvFor）。测试若跟着跑测试的 uid 走，在 root 下会静默
	// 改测另一条分支，正好漏掉这一组要守的东西。
	uid := 1000
	tun, err := New(Options{
		Conf:      conf,
		Router:    rt,
		Runner:    &dualRunner{},
		UID:       &uid,
		Upstreams: []string{"223.5.5.5"},
		Bypass:    []string{"223.5.5.5"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !tun.usesHelper() {
		t.Fatal("配了 tun.helper 却走的是直接开的路径")
	}
	return tun
}
