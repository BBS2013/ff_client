package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"

	"wps_app/internal/logx"
)

// maxUDPSessions 限制本进程同时存在的 hysteria2 UDP 会话数。
//
// 库里给每个会话配了 1024 条消息的队列（塞满就丢包），却完全不管会话数，
// 而我们这侧的会话是按「转发关联」开的：TUN 模式下每个不同的 UDP 四元组
// 都是一条，一台机器上跑着几十个走 QUIC 的应用就是几百条，没有上限就是
// 无界的内存与内核态 QUIC 会话。这个上限只能在我们这层加。
const maxUDPSessions = 512

// ErrTooManyUDP 是会话数打满时的说法，单独一个判据好让调用方给出一句人话。
var ErrTooManyUDP = errors.New("UDP 会话数已达上限")

// udpNotEnabledMsg 是库在服务端没开 UDP 时给出的原话，
// 见 vendor/.../core/v2/client/client.go 里 UDP() 的第一个分支。
// 库没给它单独的错误类型，只能按带类型的结构体比 Message 字段；
// 匹配 DialError 而不是拿错误文本比，是因为那才是这段代码里唯一可靠的部分。
const udpNotEnabledMsg = "UDP not enabled"

// udpSessions 是当前进程里活着的 UDP 会话数。跨出站实例累计是对的：
// 只有 hysteria2 会加减它，而它约束的恰恰是「库那边同时开着的会话数」。
var udpSessions atomic.Int64

// UDPSessions 报告当前活着的 UDP 会话数，供面板与测试观察。
func UDPSessions() int64 { return udpSessions.Load() }

// DialUDP 开一条新的 UDP 关联。
//
// 复用 DialContext 那条 client() 路径是有意的：握手是懒触发的且带退避，
// 走同一条路才拿得到同样的「连不上就重试 + 记账」行为，
// 否则 UDP 会变成一条与 TCP 各走各的、完全没有故障记账的旁路。
func (h *Hysteria) DialUDP(ctx context.Context) (PacketConn, error) {
	if n := udpSessions.Add(1); n > maxUDPSessions {
		udpSessions.Add(-1)
		return nil, fmt.Errorf("%d 条：%w", maxUDPSessions, ErrTooManyUDP)
	}
	cli, err := h.client(ctx)
	if err != nil {
		udpSessions.Add(-1)
		return nil, fmt.Errorf("开 UDP 会话前隧道未能建立: %w", err)
	}
	conn, err := cli.UDP()
	if err != nil {
		udpSessions.Add(-1)
		// 「服务端没开 UDP」也报成 DialError，与「服务端拨不通某个目标」同一形态，
		// 可这两件事的处置完全不同：后者如实报给调用方，前者是节点侧配置问题、
		// 只有换节点才有救。混在一起只会让人看不懂日志里那句 dial error。
		var de coreErrs.DialError
		if errors.As(err, &de) && de.Message == udpNotEnabledMsg {
			return nil, errUDPRefused("服务端未开启 UDP 转发的 hysteria2 节点")
		}
		if isTargetRefused(err) {
			return nil, errUDPRefused("节点拒绝建立 UDP 会话")
		}
		return nil, fmt.Errorf("开 UDP 会话: %w", err)
	}
	logx.Debugf("hysteria: 已开 UDP 会话（当前 %d 条）", udpSessions.Load())
	return &hysteriaUDPConn{conn: conn, h: h, gen: cli}, nil
}

// hysteriaUDPConn 把 hysteria2 的 HyUDPConn 适配成 PacketConn。
type hysteriaUDPConn struct {
	conn client.HyUDPConn
	h    *Hysteria
	// gen 是这条会话所属的那一代客户端。连接级失效要按代次比对，理由同 invalidateCurrent。
	gen client.Client

	// sendMu 是必需的不是保险：HyUDPConn.Send 把数据拷进一块**所有调用共享**的
	// 发送缓冲区，并发调用会互相踩。UDP 转发恰好天然并发（应答一到就回一包）。
	sendMu sync.Mutex

	// closed 用来区分「我们自己关的」与「隧道死了连带关的」：
	// 两种情况下 Receive 都返回 io.EOF，而后者该上报、前者不该。
	closed atomic.Bool
	// gone 保证一条会话只上报一次隧道故障。
	gone atomic.Bool
}

func (u *hysteriaUDPConn) ReadFrom(p []byte) (int, string, error) {
	msg, addr, err := u.conn.Receive()
	if err != nil {
		if errors.Is(err, io.EOF) && !u.closed.Load() {
			// 隧道没了：udpSessionManager 在连接断开时挨个关会话，
			// 于是每个还挂着的关联都收到一个 io.EOF。照原样交出去没有头没有尾，
			// 得让它有机会丢弃共享连接，好让后续流量走一次干净的重连。
			u.noteGone()
		}
		return 0, "", err
	}
	return copy(p, msg), addr, nil
}

func (u *hysteriaUDPConn) WriteTo(p []byte, addr string) error {
	if u.closed.Load() {
		return net.ErrClosed
	}
	u.sendMu.Lock()
	defer u.sendMu.Unlock()
	return u.conn.Send(p, addr)
}

func (u *hysteriaUDPConn) Close() error {
	// 先置位再关会话：Receive 只有在被关之后才会返回 io.EOF，
	// 顺序反了就会把「自己收的尾」误报成「隧道挂了」。
	if !u.closed.CompareAndSwap(false, true) {
		return nil
	}
	udpSessions.Add(-1)
	return u.conn.Close()
}

func (u *hysteriaUDPConn) noteGone() {
	if !u.gone.CompareAndSwap(false, true) {
		return
	}
	logx.Warnf("hysteria: UDP 会话因隧道断开而结束，丢弃共享连接以便重连")
	u.h.invalidateCurrent(u.gen)
}
