package metrics

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Go 的 splice 不看 syscall.Conn。net.(*TCPConn).ReadFrom 只对源是
// *TCPConn（或 unix 流）时走 splice，包装过一层就退回用户态拷贝。
// 所以这里把 idle/count 包装剥开，直接把两头的 *TCPConn 交给 ReadFrom。
// 字节数在剥开之后补记一次：splice 不会经过 countConn.Read。

type unwrapper interface {
	Unwrap() net.Conn
}

// TCPOf 顺着 Unwrap 找到最里面的 *TCPConn。不是 TCP 就返回 nil。
func TCPOf(c net.Conn) *net.TCPConn {
	for i := 0; i < 8 && c != nil; i++ {
		if t, ok := c.(*net.TCPConn); ok {
			return t
		}
		u, ok := c.(unwrapper)
		if !ok {
			return nil
		}
		c = u.Unwrap()
	}
	return nil
}

// CountRead 把 n 记到 r 这条读侧包装上。r 自己没有计数器就什么都不做。
func CountRead(r io.Reader, n int64) {
	if n <= 0 || r == nil {
		return
	}
	if a, ok := r.(interface{ CountRead(int64) }); ok {
		a.CountRead(n)
	}
}

// CopySplice 在两端都是 TCP 时走 *TCPConn.ReadFrom（Linux 上即 splice）。
// 返回的 ok 为 false 表示没动过任何字节，调用方应改走普通拷贝。
func CopySplice(dst net.Conn, src io.Reader) (n int64, ok bool, err error) {
	d := TCPOf(dst)
	s, isConn := src.(net.Conn)
	if d == nil || !isConn {
		return 0, false, nil
	}
	srcTCP := TCPOf(s)
	if srcTCP == nil {
		return 0, false, nil
	}
	n, err = d.ReadFrom(srcTCP)
	CountRead(src, n)
	return n, true, err
}

// RawConn 把包装下面的 syscall.RawConn 取出来。
// 先剥 Unwrap：包装层自己的 SyscallConn 会再调回来，不剥就会递归。
func RawConn(c net.Conn) (syscall.RawConn, error) {
	for i := 0; i < 8 && c != nil; i++ {
		if u, ok := c.(unwrapper); ok {
			c = u.Unwrap()
			continue
		}
		sc, ok := c.(syscall.Conn)
		if !ok {
			break
		}
		return sc.SyscallConn()
	}
	return nil, errNotSyscall
}

var errNotSyscall = errString("连接没有可交给内核的文件描述符")

type errString string

func (e errString) Error() string { return string(e) }

// BumpDeadline 在有字节流动时把截止时间往后推，但两次之间至少隔 gap。
// 这样一条忙碌的连接不会每个 32KB 都做一次 setsockopt。
// 完全没有字节时不推：空闲超时仍然按最初设下的截止时间生效。
func BumpDeadline(last *atomic.Int64, gap, idle time.Duration, n int, set func(time.Time) error) {
	if n <= 0 || set == nil || last == nil {
		return
	}
	if gap <= 0 {
		gap = idle
	}
	now := time.Now()
	prev := last.Load()
	if prev != 0 && now.UnixNano()-prev < int64(gap) {
		return
	}
	if !last.CompareAndSwap(prev, now.UnixNano()) {
		return
	}
	_ = set(now.Add(idle))
}

var copyBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

type onlyWriter struct{ io.Writer }

// CopyPooled 用一块复用的 32KB 缓冲做用户态拷贝。
// 目标被包成只有 Write 的一面，避免再进 ReadFrom 把自己递归进去。
func CopyPooled(dst io.Writer, src io.Reader) (int64, error) {
	bp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bp)
	return io.CopyBuffer(onlyWriter{dst}, src, *bp)
}
