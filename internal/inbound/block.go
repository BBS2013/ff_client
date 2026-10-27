package inbound

import (
	"errors"
	"io"
	"net"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/metrics"
	"wps_app/internal/router"
	"wps_app/internal/rules"
)

// blocker 负责「命中拦截名单」时入站这一侧的动作。
//
// 语义是**静默丢弃**：不回 SOCKS 的失败应答、也不回 HTTP 的 502——
// 那两种应答都等于告诉发起方"这里有一个代理在替你做决定"。
// 客户端看到的就只是"连上了，然后什么都没有发生"，最后自己超时。
type blocker struct {
	reg  *metrics.Registry
	kind string
	// hold 是最长挂起时间。做成字段而不是常量：
	// 用例不该为了验证"到点会收"真等 75 秒。
	hold time.Duration
}

func newBlocker(kind string, reg *metrics.Registry) blocker {
	return blocker{reg: reg, kind: kind, hold: rules.BlockHold}
}

// isBlocked 区分「被拦」与「拨不通」。
// 后者的既有行为（回失败应答 / 502）必须原样保留，不然排障时会把两件事混成一件。
func isBlocked(err error) bool { return errors.Is(err, rules.ErrBlocked) }

// drop 挂着不回话，到上限再收。
//
// 不能真的永久挂：浏览器对一批广告域会同时发十几条，全留着就是 fd 堆积。
// 所以这里是"读到对端先走、否则到点就走"——客户端超时断开时我们立刻跟着释放，
// 上限只是没人先放手时的兜底。
//
// 埋点照常记一条，字节数为 0：客户端收不到任何信息，本机连接表就是唯一线索。
func (b blocker) drop(c net.Conn, client, target string, res router.Result) {
	defer func() { _ = c.Close() }()

	hold := b.hold
	if hold <= 0 {
		hold = rules.BlockHold
	}
	logx.Warnf("%s 拦截 %s [%s]（按拦截名单，客户端不会收到原因）", b.kind, target, res.Matched)

	if b.reg != nil {
		rec := b.reg.Begin(b.kind, client, res)
		defer b.reg.End(rec)
	}
	_ = c.SetReadDeadline(time.Now().Add(hold))
	_, _ = io.Copy(io.Discard, c)
}
