//go:build linux

package tunx

import (
	"context"
	"testing"
	"time"
)

func TestOpenRouteEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := openRouteEvents(ctx)
	if ch == nil {
		t.Fatal("netlink 路由订阅失败")
	}
}

func TestWaitRouteSettleQuiet(t *testing.T) {
	ctx := context.Background()
	more := make(chan struct{})
	start := time.Now()
	if !waitRouteSettle(ctx, more, 20*time.Millisecond) {
		t.Fatal("没有新事件时应当在安静窗口结束")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("安静窗口等得太久")
	}
}
