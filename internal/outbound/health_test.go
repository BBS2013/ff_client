package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"
)

// 这组测试钉住的是故障切换的判据：什么算节点坏了，什么不算。
// 切错的代价很实在——换节点会掐掉旧隧道上所有正在传的连接。

// plainDialer 是一个故意不实现 NodeFault 的出站，用来验不可判定时的默认值。
type plainDialer struct{}

func (plainDialer) Name() string { return "plain" }
func (plainDialer) DialContext(context.Context, string) (net.Conn, error) {
	return nil, errors.New("boom")
}
func (plainDialer) Close() error { return nil }

func TestHysteriaNodeFailureExcludesTargetRefusal(t *testing.T) {
	h := &Hysteria{}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		// 目标被拒是这一组里最要紧的 false：
		// 浏览器每个页面都带着几个已经死掉的目标，为它们切节点等于无事生非。
		{"服务端拨不通这个目标", coreErrs.DialError{Message: "connection refused"}, false},
		{"包装过的目标拒绝", fmt.Errorf("tcp stream to x: %w", coreErrs.DialError{Message: "refused"}), false},
		// 本进程自己关掉的，不是节点的错。
		{"出站已被自己关闭", ErrClosed, false},
		{"包装过的自关闭", fmt.Errorf("dial: %w", ErrClosed), false},
		// 调用方放弃，与节点无关。
		{"调用方取消", context.Canceled, false},
		{"调用方超时", context.DeadlineExceeded, false},
		{"包装过的调用方超时", fmt.Errorf("wait: %w", context.DeadlineExceeded), false},
		// 以下都该算节点故障。
		{"连不上服务端", coreErrs.ConnectError{Err: errors.New("handshake failed")}, true},
		{"隧道被关闭", coreErrs.ClosedError{Err: errors.New("connection closed")}, true},
		{"协议不对", coreErrs.ProtocolError{Message: "bad frame"}, true},
		{"叫不出名字的错（例如服务端不再给新流）", errors.New("stream limit reached"), true},
		{"节点地址解析失败", errors.New("no such host"), true},
	}
	for _, c := range cases {
		if got := h.NodeFailure(c.err); got != c.want {
			t.Errorf("%s: NodeFailure = %v, want %v (err=%v)", c.name, got, c.want, c.err)
		}
	}
}

func TestTrojanNodeFailureIsDeliberatelyCoarse(t *testing.T) {
	tr := &Trojan{}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"出站已被自己关闭", ErrClosed, false},
		{"调用方取消", context.Canceled, false},
		{"调用方超时", context.DeadlineExceeded, false},
		// trojan 服务端拨不通目标时直接挂断，与「它自己不行」在客户端侧同形，
		// 所以这里只能一律算节点故障——误报由故障切换的迟滞去消化。
		{"TLS 握手失败", errors.New("tls: bad record MAC"), true},
		{"连接被重置", fmt.Errorf("dial tcp: %w", syscall.ECONNRESET), true},
		{"口令不对时服务端直接挂断（读到 EOF）", io.EOF, true},
	}
	for _, c := range cases {
		if got := tr.NodeFailure(c.err); got != c.want {
			t.Errorf("%s: NodeFailure = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestTrojanConnectedIsNotHealth 钉住那个陷阱本身：
// 握手成功一次之后，即便之后的拨号全部失败，Connected 依旧为 true。
// 拿它当健康信号会让死节点永远显示正常。
func TestTrojanConnectedIsNotHealth(t *testing.T) {
	tr := &Trojan{}
	if tr.Connected() {
		t.Fatal("还没握手过就该是 false")
	}
	tr.mu.Lock()
	tr.connected = true
	tr.mu.Unlock()

	// 模拟之后所有拨号都失败。
	for i := 0; i < 5; i++ {
		if !tr.NodeFailure(errors.New("connection refused")) {
			t.Fatal("拨号失败必须算节点故障")
		}
	}
	if !tr.Connected() {
		t.Fatal("Connected 语义变了，本测试的前提不成立")
	}
	t.Log("Connected 仍为 true —— 这正是不能用它做故障判据的原因")
}

// TestHandshakeTimeoutIsNodeFailure 钉住那个最容易搞混的分界。
//
// ErrHandshakeTimeout 是「我们自己的握手预算用完了」——节点不应答，
// 这是节点挂掉最常见的形态，必须算节点级故障。
// 裸的 context.DeadlineExceeded 则是调用方放弃，不算。
// 早先这两者是同一条错误（握手超时的包装里带着 ctx.Err()），
// 于是故障切换对沉默死掉的节点一次都不会触发。
func TestHandshakeTimeoutIsNodeFailure(t *testing.T) {
	h := &Hysteria{}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"自己的握手预算用完", fmt.Errorf("dial x: %w", ErrHandshakeTimeout), true},
		{"裸的握手超时", ErrHandshakeTimeout, true},
		{"调用方自己超时", context.DeadlineExceeded, false},
		{"调用方取消", context.Canceled, false},
		{"包装过的调用方取消", fmt.Errorf("握手被调用方取消: %w", context.Canceled), false},
	}
	for _, c := range cases {
		if got := h.NodeFailure(c.err); got != c.want {
			t.Errorf("%s: NodeFailure = %v, want %v", c.name, got, c.want)
		}
	}
	// ErrHandshakeTimeout 不能顺带匹配上 context.DeadlineExceeded，
	// 否则上面那条分界就白画了。
	if errors.Is(ErrHandshakeTimeout, context.DeadlineExceeded) {
		t.Error("ErrHandshakeTimeout 包装了 context.DeadlineExceeded，两类错误又混回去了")
	}
}

func TestReportNodeFailureFallsBackToUndecidable(t *testing.T) {
	// 认不出来的出站一律 false：宁可不动，也不要在判不出是谁的错时切节点。
	if ReportNodeFailure(plainDialer{}, errors.New("boom")) {
		t.Fatal("没实现 NodeFault 的出站应当算不可判定")
	}
	if !ReportNodeFailure(&Hysteria{}, coreErrs.ConnectError{Err: errors.New("x")}) {
		t.Fatal("实现应当被走到")
	}
	if ReportNodeFailure(nil, errors.New("boom")) {
		t.Fatal("nil 出站不该报错")
	}
}
