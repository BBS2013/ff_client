package metrics

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type peel struct {
	net.Conn
}

func (p peel) Unwrap() net.Conn { return p.Conn }

func TestTCPOfPeelsWrappers(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		got <- c.(*net.TCPConn)
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srv := <-got
	defer srv.Close()

	tcp := cli.(*net.TCPConn)
	wrapped := peel{Conn: peel{Conn: tcp}}
	if TCPOf(wrapped) != tcp {
		t.Fatal("TCPOf 没有剥到最里面的 *TCPConn")
	}
	if TCPOf(srv) == nil {
		t.Fatal("裸 *TCPConn 也该认出来")
	}
}

type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	return n, err
}

func (c *countingReader) CountRead(n int64) { c.n.Add(n) }

func TestCountReadHitsOuter(t *testing.T) {
	var inner countingReader
	CountRead(&inner, 12)
	if inner.n.Load() != 12 {
		t.Fatalf("计数 = %d, want 12", inner.n.Load())
	}
	CountRead(&inner, 0)
	if inner.n.Load() != 12 {
		t.Fatal("0 字节不该改计数")
	}
}

func TestBumpDeadlineCoalesces(t *testing.T) {
	var last atomic.Int64
	var calls atomic.Int32
	set := func(time.Time) error {
		calls.Add(1)
		return nil
	}
	BumpDeadline(&last, time.Hour, time.Hour, 8, set)
	BumpDeadline(&last, time.Hour, time.Hour, 8, set)
	if calls.Load() != 1 {
		t.Fatalf("间隔内推了 %d 次截止时间，want 1", calls.Load())
	}
	BumpDeadline(&last, time.Hour, time.Hour, 0, set)
	if calls.Load() != 1 {
		t.Fatal("没有字节却又推了一次")
	}
}

func TestCopyPooledDoesNotRecurse(t *testing.T) {
	var dst bytes.Buffer
	n, err := CopyPooled(&dst, bytes.NewReader([]byte("abc")))
	if err != nil || n != 3 || dst.String() != "abc" {
		t.Fatalf("n=%d err=%v got %q", n, err, dst.String())
	}
}
