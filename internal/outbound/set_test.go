package outbound

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
)

// stubDialer 是一只可控的出站，只用来验证集合层面的行为。
type stubDialer struct {
	name   string
	closed int32
	mu     sync.Mutex
}

func (s *stubDialer) Name() string { return s.name }
func (s *stubDialer) DialContext(context.Context, string) (net.Conn, error) {
	return nil, errors.New("stub")
}
func (s *stubDialer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return nil
}
func (s *stubDialer) Closed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed > 0
}

func TestSetSwapProxyReturnsOld(t *testing.T) {
	first := &stubDialer{name: "first"}
	second := &stubDialer{name: "second"}
	set := NewSet(&stubDialer{name: "direct"}, first)

	if old := set.SwapProxy(second, "node-2"); old != first {
		t.Fatal("SwapProxy 应把旧出站交回调用方去关")
	}
	got, err := set.Get(PolicyProxy)
	if err != nil || got.Name() != "second" {
		t.Fatalf("换完之后取到的还是旧的: %v %v", got, err)
	}
	// Set 只管"当前在用"的那一只：旧的必须由调用方关，
	// 否则切一次节点就漏一条 QUIC 连接在外面。
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	if !first.Closed() || !second.Closed() {
		t.Fatal("新旧出站都该被关掉")
	}
	// 集合关完之后不能再提供出站，否则入站会拿着一只已关闭的 dialer 继续拨。
	if _, err := set.Get(PolicyProxy); err == nil {
		t.Error("Close 之后仍返回可用出站")
	}
}

// TestSetConcurrentSwapAndGet 是给 -race 准备的形状：
// 一边切节点，一边有新连接取用出站。取到的必须是"某一只完整的"，
// 不能是半新半旧的撕裂状态，也不能取到 nil。
func TestSetConcurrentSwapAndGet(t *testing.T) {
	set := NewSet(&stubDialer{name: "direct"}, &stubDialer{name: "v0"})
	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				d, err := set.Get(PolicyProxy)
				if err != nil || d == nil {
					t.Errorf("取用出站失败: %v", err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= 50; i++ {
			old := set.SwapProxy(&stubDialer{name: "v" + string(rune('A'+i%26))}, "swapped")
			if old != nil {
				_ = old.Close()
			}
		}
		close(stop)
	}()
	wg.Wait()
}
