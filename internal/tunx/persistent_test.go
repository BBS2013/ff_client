package tunx

import (
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 常驻 helper 存在的全部理由就在这一句上：**进程只拉起一次，请求可以来很多次**。
// 每条流都重新起一次 sudo + 进程起落（实测 0.08~0.11s）那条路，每分钟要付几十次。
// 这条用例盯的是"多次拨号只拉起一次 helper"；连接可以一次一开，见下面那条并发用例。
func TestPersistentHelperServesManyRequestsWithOneSpawn(t *testing.T) {
	dev, addr := dialTestEndpoint(t)
	ln, err := net.Listen("tcp", addr+":0")
	if err != nil {
		t.Skipf("在本机地址 %s 上起不了监听: %v", addr, err)
	}
	defer ln.Close()
	endpoint := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("pong"))
			}(c)
		}
	}()

	var spawns int32
	h := &PersistentHelper{Timeout: 5 * time.Second}
	h.Spawn = func(ctx context.Context, path string) error {
		atomic.AddInt32(&spawns, 1)
		go func() { _ = RunDialHelper(ctx, path, os.Getuid()) }()
		return nil
	}
	defer h.Close()

	for i := 0; i < 3; i++ {
		conn, err := h.DialBound(context.Background(), dev, endpoint, []string{endpoint})
		if err != nil {
			t.Fatalf("第 %d 次拨号失败: %v", i+1, err)
		}
		_ = conn.Close()
	}
	if got := atomic.LoadInt32(&spawns); got != 1 {
		t.Fatalf("三次请求只该拉起一次常驻 helper，实际 %d 次", got)
	}
}

// TestPersistentHelperOwnerZeroMeansRootPanel 是 2026-10-30 那个现场退化的回归：
// 面板整个由 sudo 拉起时 uid=0，helper 侧若把 0 当成"没传 owner"，
// 每条隧道出境都要等满 25s 才失败，且报的是"需要 --dial-helper-owner"。
func TestPersistentHelperOwnerZeroMeansRootPanel(t *testing.T) {
	dev, addr := dialTestEndpoint(t)
	ln, err := net.Listen("tcp", addr+":0")
	if err != nil {
		t.Skipf("在本机地址 %s 上起不了监听: %v", addr, err)
	}
	defer ln.Close()
	endpoint := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("pong"))
			}(c)
		}
	}()

	h := &PersistentHelper{Timeout: 3 * time.Second}
	h.Spawn = func(ctx context.Context, path string) error {
		go func() { _ = RunDialHelper(ctx, path, 0) }()
		return nil
	}
	defer h.Close()
	conn, err := h.DialBound(context.Background(), dev, endpoint, []string{endpoint})
	if err != nil {
		t.Fatalf("owner=0（root 面板）时拉不起常驻 helper: %v", err)
	}
	_ = conn.Close()
}

// 名单之外的目标仍然必须被拒——常驻 helper 一直开着，这条防线不能因为"常驻"而松。
func TestPersistentHelperRefusesEndpointNotInAllow(t *testing.T) {
	dev, _ := dialTestEndpoint(t)
	h := &PersistentHelper{Timeout: 5 * time.Second}
	h.Spawn = func(ctx context.Context, path string) error {
		go func() { _ = RunDialHelper(ctx, path, os.Getuid()) }()
		return nil
	}
	defer h.Close()
	if _, err := h.DialBound(context.Background(), dev, "1.2.3.4:443", []string{"5.6.7.8:443"}); err == nil {
		t.Fatal("名单之外的目标必须被拒")
	}
}

// stallHelper 起一个只会收请求、从不作答的假 helper，用来观察客户端自己的并发行为。
// 它不碰网络、不碰 root，返回的 got 每收到一条请求就发一个信号。
func stallHelper(t *testing.T) (*PersistentHelper, <-chan struct{}) {
	t.Helper()
	got := make(chan struct{}, 8)
	h := &PersistentHelper{Timeout: 2 * time.Second}
	h.Spawn = func(_ context.Context, path string) error {
		ln, err := net.Listen("unix", path)
		if err != nil {
			return err
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					uc, ok := c.(*net.UnixConn)
					if !ok {
						return
					}
					if _, err := readFrame(uc); err != nil {
						return
					}
					got <- struct{}{}
					// 不作答，让客户端停在读应答这一步；连接由客户端关闭。
					_, _ = readFrame(uc)
				}(c)
			}
		}()
		return nil
	}
	t.Cleanup(h.Close)
	return h, got
}

// TestPersistentHelperDoesNotSerializeDials 是 2026-11-03 那个现场退化的回归：
// 常驻 helper 的客户端把整次往返抱在一把互斥锁里，一条走不通的直连会把它后面的
// 所有代理拨号一起堵住，直到 25s 超时。修好之后两条请求必须能同时在飞。
func TestPersistentHelperDoesNotSerializeDials(t *testing.T) {
	h, got := stallHelper(t)
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	first := make(chan error, 1)
	go func() {
		_, err := h.DialBound(ctx1, "lo", "127.0.0.1:1", []string{"127.0.0.1:1"})
		first <- err
	}()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("第一条请求没有到 helper")
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	second := make(chan error, 1)
	go func() {
		_, err := h.DialBound(ctx2, "lo", "127.0.0.1:2", []string{"127.0.0.1:2"})
		second <- err
	}()
	select {
	case <-got:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("第二条请求被第一条堵住了：常驻 helper 客户端仍在串行化拨号")
	}
}

// TestPersistentHelperHonorsCallerDeadline 盯住"调用方只给 120ms"这件事：
// 客户端必须按 ctx 收手，不能自己等满 Timeout。现场那些 trojan 握手超时，
// 很多其实是排在 helper 队列里等掉了调用方的预算。
func TestPersistentHelperHonorsCallerDeadline(t *testing.T) {
	h, _ := stallHelper(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := h.DialBound(ctx, "lo", "127.0.0.1:3", []string{"127.0.0.1:3"}); err == nil {
		t.Fatal("假 helper 不应答，DialBound 不该成功")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("DialBound 等了 %v，没按调用方的 120ms 收手", elapsed)
	}
}

// TestPersistentHelperConcurrentStartKeepsOneSpawn 锁住启动期的并发安全。
//
// 以前的形状：start() 在套接字还没 bind 时就把 p.path 设好了，而 ensure()
// 看到 path 非空就当"已在线"直接返回。于是并发的第二条拨号拿着一条
// 注定 Dial 失败的路径出发，失败后又 drop() 把正在启动的这个 helper 杀掉——
// 一次并发就把整条提权通道拆了，日志里只有"连不上"。
//
// 正确形状：几条同时进来的拨号共用同一次启动，全部成功，且只 spawn 一次。
func TestPersistentHelperConcurrentStartKeepsOneSpawn(t *testing.T) {
	dev, addr := dialTestEndpoint(t)
	ln, err := net.Listen("tcp", addr+":0")
	if err != nil {
		t.Skipf("在本机地址 %s 上起不了监听: %v", addr, err)
	}
	defer ln.Close()
	endpoint := ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("pong"))
			}(c)
		}
	}()

	var spawns int32
	h := &PersistentHelper{Timeout: 5 * time.Second}
	h.Spawn = func(ctx context.Context, path string) error {
		atomic.AddInt32(&spawns, 1)
		go func() {
			// 故意晚一点起监听：让并发的拨号真的撞上"启动中"这个窗口。
			time.Sleep(30 * time.Millisecond)
			_ = RunDialHelper(ctx, path, os.Getuid())
		}()
		return nil
	}
	defer h.Close()

	const n = 4
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := h.DialBound(context.Background(), dev, endpoint, []string{endpoint})
			if err == nil {
				_ = conn.Close()
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("并发启动时有一条拨号失败: %v", err)
		}
	}
	if got := atomic.LoadInt32(&spawns); got != 1 {
		t.Fatalf("%d 条并发拨号只该拉起一次常驻 helper，实际 %d 次", n, got)
	}
}
