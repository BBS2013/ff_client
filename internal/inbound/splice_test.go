package inbound

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"wps_app/internal/metrics"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		got <- c
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv := <-got
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
	})
	return cli, srv
}

func TestWrappedTCPCopySkipsUserspaceRead(t *testing.T) {
	payload := bytes.Repeat([]byte("a"), 256*1024)
	srcPeer, src := tcpPair(t)
	dst, dstPeer := tcpPair(t)

	go func() {
		_, _ = srcPeer.Write(payload)
		_ = srcPeer.Close()
	}()
	done := make(chan struct{})
	got := make([]byte, len(payload))
	var readErr error
	go func() {
		defer close(done)
		_, readErr = io.ReadFull(dstPeer, got)
	}()

	var up atomic.Uint64
	wrappedSrc := newIdleConn(metrics.Wrap(src, &up), time.Minute)
	wrappedDst := newIdleConn(dst, time.Minute)
	n, err := io.Copy(wrappedDst, wrappedSrc)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("拷贝 %d 字节, want %d", n, len(payload))
	}
	if wrappedSrc.reads.Load() != 0 {
		t.Fatalf("走了用户态 Read %d 次，没有交到 *TCPConn.ReadFrom", wrappedSrc.reads.Load())
	}
	if up.Load() != uint64(len(payload)) {
		t.Fatalf("上行计数 %d, want %d", up.Load(), len(payload))
	}
	<-done
	if readErr != nil {
		t.Fatalf("对端没读全: %v", readErr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("对端读到的内容和发出去的不一样")
	}
}

func TestWrappedPipeCopyStillCounts(t *testing.T) {
	a, b := net.Pipe()
	c, d := net.Pipe()
	t.Cleanup(func() {
		_ = a.Close()
		_ = b.Close()
		_ = c.Close()
		_ = d.Close()
	})
	payload := []byte("hello-pipe")
	go func() {
		_, _ = b.Write(payload)
		_ = b.Close()
	}()
	go func() { _, _ = io.Copy(io.Discard, d) }()

	var nread atomic.Uint64
	src := newIdleConn(metrics.Wrap(a, &nread), time.Minute)
	dst := newIdleConn(c, time.Minute)
	n, err := io.Copy(dst, src)
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("拷贝 %d, want %d", n, len(payload))
	}
	if src.reads.Load() == 0 {
		t.Fatal("pipe 不是 TCP，不该走 splice")
	}
	if nread.Load() != uint64(len(payload)) {
		t.Fatalf("计数 %d, want %d", nread.Load(), len(payload))
	}
}
