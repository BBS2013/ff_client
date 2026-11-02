package tunx

import (
	"context"
	"testing"
)

// TestStatusNeverForksForTakeover 面板轮询状态时一个进程都不许起。
//
// 把接管那两格改成读内核之后，最顺手写成也更贵的样子是「每次问状态都跑一次 ip」：
// 面板每 1–2 秒就问一次，那就是一条每秒两次的常驻 fork——而网络监视器本来
// 每 5 秒就要把这两张路由表读一遍。这个测试盯的就是那份冗余：
// 读数由监视器贴出来，Status() 只拿现成的。
//
// 它同时钉住另一半：贴出来的读数在用例里是新鲜可用的，
// 不许为了过这个测试把探测干脆去掉、让两格永远退回推断。
func TestStatusNeverForksForTakeover(t *testing.T) {
	r := &dualRunner{
		v4Default: "default dev wps-tun metric 0",
		v6Default: "default via fe80::5 dev wlp3s0f0 proto ra metric 20600",
	}
	tun := newDualTUN(t, r)
	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	tun.plan = plan
	tun.running = true
	tun.setV6RouteReady(true)
	tun.publishTakeoverLocked(context.Background()) // 监视器每一轮顺手做的事

	ran := len(r.ran)
	for i := 0; i < 20; i++ {
		st := tun.Status()
		if st.TakeoverFrom != "kernel" {
			t.Fatalf("第 %d 次状态查询的接管来源是 %q，应当是 kernel（探测被省掉了的话两格就永远是猜的）", i+1, st.TakeoverFrom)
		}
		if !st.TakeoverV4 {
			t.Fatalf("第 %d 次：内核说 v4 默认路由在 tun 上，面板却说没接管", i+1)
		}
		if st.TakeoverV6 {
			t.Fatalf("第 %d 次：内核说 v6 走物理卡，面板却说接管了", i+1)
		}
	}
	if got := len(r.ran) - ran; got != 0 {
		t.Errorf("20 次状态查询起了 %d 条命令，应为 0", got)
	}
}
