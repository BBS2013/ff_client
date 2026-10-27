package outbound

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoUDP 是「这只出站带不动 UDP」的判据，供调用方区分「节点坏了」与「这条路本来就不通」。
var ErrNoUDP = errors.New("该出站不支持 UDP 转发")

// PacketConn 是一条已建立的 UDP 关联：报文自带目标地址，
// 因此它不是 net.Conn——UDP 没有连接可言，「连上」只是本进程里的一份状态。
type PacketConn interface {
	// ReadFrom 取下一个应答，addr 是它的来源。
	// Close 必须让并发的 ReadFrom 返回错误，否则关联永远收不了尾。
	ReadFrom(p []byte) (n int, addr string, err error)
	// WriteTo 把 p 发往 addr（形如 "host:port"）。
	WriteTo(p []byte, addr string) error
	// Close 结束关联，之后的收发一律报错。
	Close() error
}

// PacketDialer 是「这只出站带得动 UDP」的能力接口。
//
// 刻意不并进 Dialer：UDP 只有 hysteria2 一种协议能带，而 Dialer 是每条转发路径
// 都必须过的窄接口，为一种协议把它撑大，代价是另外两种实现每天都要返回一句
// 「不支持」。挂在旁边、用类型断言取，只有真要转 UDP 的路径才会碰到它。
type PacketDialer interface {
	Dialer
	DialUDP(ctx context.Context) (PacketConn, error)
}

// DialUDP 是取 UDP 能力的唯一入口。
//
// 没有实现 PacketDialer 的出站走这里的兜底：三只出站都实现了它，
// 这条分支只留给测试替身与将来新增的协议——那时宁可明确报「不支持」，
// 也不要静默把 UDP 丢掉让应用干等到超时。
func DialUDP(ctx context.Context, d Dialer) (PacketConn, error) {
	pd, ok := d.(PacketDialer)
	if !ok {
		return nil, fmt.Errorf("%s: %w", d.Name(), ErrNoUDP)
	}
	return pd.DialUDP(ctx)
}

// errUDPRefused 是「这条出站明确不支持 UDP」时统一给出的说法。
//
// 措辞给的是「这条路本来就不通」而不是「出站坏了」：调用方（故障切换、
// 面板统计）都靠 errors.Is(err, ErrNoUDP) 把它摘出去，
// 混进节点故障里去会导致一次正常的拒绝触发切节点。
func errUDPRefused(what string) error {
	return fmt.Errorf("%s 承载不了 UDP：%w", what, ErrNoUDP)
}
