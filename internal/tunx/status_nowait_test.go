package tunx

import (
	"context"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// TestStatusDoesNotBlockDuringStartStop 锁住"启停 TUN 时面板还能读到状态"。
//
// 现场形状（改之前）：面板每秒轮一次状态，调用链是
// service.Snapshot →（持 s.mu）→ tun.Status →（持 t.mu）。
// 而 TUN 的 Start/Stop 全程持有 t.mu，里面要跑 helper、ip、iptables、
// resolvectl，最长二十秒。于是「正在启停 TUN」那十几秒里，面板的每一次轮询
// 都攥着 s.mu 干等，连带拨号失败记账、切节点、关监听一起卡住——
// 用户看到的是整个面板卡死，而此刻恰恰最需要它说明"正在启动"。
//
// 判据：在 Start/Stop 占着 t.mu 的那段时间里，Status() 必须在毫秒级返回。
func TestStatusDoesNotBlockDuringStartStop(t *testing.T) {
	tun := newResolverTUN(t, &resolverRunner{outputs: map[string]string{}, failOn: map[string]error{}})

	// 先发布一份快照（生产里由 Start/Stop 的 defer 做）。
	tun.PublishStatus()

	// 模拟"启停正在跑"：直接把 t.mu 拿走，然后读 Status()。
	// 这正是 Start 持锁期间面板在做的事。
	tun.mu.Lock()

	done := make(chan Status, 1)
	go func() { done <- tun.Status() }()

	select {
	case st := <-done:
		if st.Device == "" {
			tun.mu.Unlock()
			t.Fatalf("拿到了快照但内容不对: %+v", st)
		}
	case <-time.After(2 * time.Second):
		tun.mu.Unlock()
		t.Fatal("启停持锁期间 Status() 被阻塞了——面板轮询会被它拖住十几秒")
	}
	tun.mu.Unlock()

	// 反过来：解锁之后应当仍然读得到（已发布的快照不该因为解锁就失效）。
	if st := tun.Status(); st.Device == "" {
		t.Fatalf("解锁后状态丢了: %+v", st)
	}
}

// TestStatusReflectsPublishedFields 确认发布出去的是**当前**字段，
// 而不是 New 时的第一份。
//
// 没有这一条，"不阻塞"可以用"永远返回一份新建的零值"骗过去——
// 界面会显示一切正常，而实际 TUN 起没起来、接管没接管全看不见。
func TestStatusReflectsPublishedFields(t *testing.T) {
	tun := newResolverTUN(t, &resolverRunner{outputs: map[string]string{}, failOn: map[string]error{}})

	tun.mu.Lock()
	tun.running = true
	tun.startedAt = time.Now()
	tun.lastErr = errTestStatus
	tun.mu.Unlock()
	tun.PublishStatus()

	st := tun.Status()
	if !st.Running {
		t.Error("已发布的 Running 没反映出来")
	}
	if st.StartedAt == 0 {
		t.Error("StartedAt 没反映出来")
	}
	if st.LastError != errTestStatus.Error() {
		t.Errorf("LastError = %q, want %q", st.LastError, errTestStatus.Error())
	}
}

var errTestStatus = &statusErr{}

type statusErr struct{}

func (e *statusErr) Error() string { return "假错误（测试用）" }

// 让这个文件不依赖具体实现细节：只要能被 newResolverTUN 造出来即可。
var _ = config.DefaultTUN
var _ = metrics.NewRegistry
var _ = outbound.NewDirect
var _ = router.New
var _ = context.Background
