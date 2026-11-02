package tunx

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// 常驻 helper 存在的全部理由就在这一句上：**一条连接扛多次请求**。
// 每条流都重新起一次 sudo + 进程起落（实测 0.08~0.11s）那条路，每分钟要付几十次。
// 这条用例盯的是"连一次、多次用"，并且顺手盯住"只拉起一次"。
func TestPersistentHelperServesManyRequestsOnOneConnection(t *testing.T) {
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
