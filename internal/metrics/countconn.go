package metrics

import (
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"
)

// countConn 给 net.Conn 套一层「读出字节数」计数，其余行为完全透传。
type countConn struct {
	net.Conn
	ctr *atomic.Uint64
}

// Wrap 返回一个统计「从该连接读出字节数」的连接包装。
//
// 为什么只计 Read 不计 Write：relay 的两个方向各自是一个 io.Copy，
// `io.Copy(remote, client)` 只从 client 读、`io.Copy(client, remote)` 只从 remote 读，
// 因此「从 client 读出的总量」正好是上行、「从 remote 读出的总量」正好是下行。
// 若 Read/Write 都计，同一份流量会经两条方向各算一遍，两个计数器都退化成总量。
//
// ctr 为 nil 时原样返回 c，不产生任何包装开销。
func Wrap(c net.Conn, ctr *atomic.Uint64) net.Conn {
	if ctr == nil || c == nil {
		return c
	}
	return &countConn{Conn: c, ctr: ctr}
}

func (cc *countConn) Read(p []byte) (int, error) {
	n, err := cc.Conn.Read(p)
	if n > 0 {
		cc.ctr.Add(uint64(n))
	}
	return n, err
}

// Unwrap 让 splice 能剥到里面的 *TCPConn。
func (cc *countConn) Unwrap() net.Conn { return cc.Conn }

// CountRead 补记 splice 搬过、但没有经过 Read 的那些字节。
func (cc *countConn) CountRead(n int64) {
	if n > 0 {
		cc.ctr.Add(uint64(n))
	}
}

// ReadFrom 在对端也是 TCP 时把字节一次性交给内核 splice，并记在源那一侧。
// 这里自己的计数器统计的是「从这条连接读出」，而 ReadFrom 是在往这条连接写，
// 所以不要加到自己头上。
func (cc *countConn) ReadFrom(r io.Reader) (int64, error) {
	if n, ok, err := CopySplice(cc.Conn, r); ok {
		return n, err
	}
	return CopyPooled(cc.Conn, r)
}

// SyscallConn 把底层的原始连接交出去。不转发的话，外面再套一层就拿不到 fd。
func (cc *countConn) SyscallConn() (syscall.RawConn, error) {
	return RawConn(cc.Conn)
}

// ErrNoHalfClose 表示这条连接做不到「只关掉写侧」。
//
// 判不出来就别替调用方关：包装层一旦把 CloseWrite 悄悄实现成 Close()，
// 上层看类型断言以为半关成功，实际把整条连接掐了——
// 明文 HTTP 转发就是这么在请求刚发完时把还没回来的响应一起杀掉的。
var ErrNoHalfClose = errors.New("不支持半关闭写侧")

// CloseWrite 必须显式转发：入站的 halfClose() 用类型断言
// `c.(interface{ CloseWrite() error })` 决定走半关闭还是什么都不做。
// 不转发的话断言会失败，一个方向的收尾会连带掐掉另一个还在传的方向。
func (cc *countConn) CloseWrite() error {
	if cw, ok := cc.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return ErrNoHalfClose
}

// countReader 给任意 io.Reader 套一层读出字节数计数，用于不是 net.Conn 的数据源
// （HTTP 明文转发的请求体就是这种）。
type countReader struct {
	r   io.Reader
	ctr *atomic.Uint64
}

// CountReader 返回一个统计读出字节数的 io.Reader 包装。ctr 为 nil 时原样返回 r。
func CountReader(r io.Reader, ctr *atomic.Uint64) io.Reader {
	if ctr == nil || r == nil {
		return r
	}
	return &countReader{r: r, ctr: ctr}
}

func (cr *countReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.ctr.Add(uint64(n))
	}
	return n, err
}
