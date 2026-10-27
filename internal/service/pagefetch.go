package service

// 贴一个网址进来，看它到底回什么。
//
// 这一格与「查走向」是一对：那边答"按规则这条会怎么走"，这边答"那它实际回什么"。
// 分开是因为它们会不一致——节点把流量交给一个兼底 web 服务器时，
// 规则判定完全正常、电路也建得起来，而任何站点回来的都是同一个 400。
// 只看判定那一格看不出来，取一次页面就说漏嘴了（状态码与 `Server:` 头）。
//
// 判"通不通"的那套式子只有一份：`-check-fetch`、节点测速、这一格走的都是
// internal/httpprobe。三条路各写一遍"什么算通"是迟早会漂移的那种写法。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"wps_app/internal/httpprobe"
	"wps_app/internal/router"
)

// FetchBudget 是面板那一格等一次取页面的预算。
//
// 写在 service 这边而不是 `internal/ui/app.go` 那边，只为一件事：
// 演示桥里那句"在 15 秒内没回话"要有一条跨语言的守卫可比
// （`internal/ui/demo_words_test.go` 拿它核对秒数）。抄在 app.go 里的话，
// 那个数字对 TS 侧就是一个无主字面量，改了预算没人会想起演示还在说 15 秒。
const FetchBudget = 15 * time.Second

// PageFetch 是一次取页面的结果。
//
// 注意 OK/Reason 这一对：**取回一个 400 不是"查询失败"**，那正是这一问的答案。
// 把它当错误返回，界面就只剩一句"查询失败"，而用户要看的偏偏是那个状态码
// 与是谁在回话（`Server:`）。这与 `Router.Preview` 里"被拦不算失败"是同一条规矩。
type PageFetch struct {
	// URL 是回显给用户的那一份：查询串与 userinfo 去掉。
	// 用户贴进来的可能是带 token 的订阅地址，而这一格的内容会被截图发出去。
	URL string `json:"url"`
	// Addr 是真正拨出去的 host:port（补上默认端口之后）。
	Addr string `json:"addr"`
	// Code 是 HTTP 状态码，0 表示连上了但没回状态行。
	Code int `json:"code"`
	// Server 是 `Server:` 头——兼底 web 服务器就是在这里露馅的。
	Server string `json:"server"`
	// Body 是数到的正文字节（探针有上限，不是整页大小）。
	Body int64 `json:"body"`
	// ViaTLS 说明这一条走的是 https（TLS 在本地做，交给节点的是明文 CONNECT）。
	ViaTLS bool `json:"viaTLS"`
	// Location 是 3xx 的去向：跳到一个登录页也是一种"没通"。
	Location string `json:"location"`
	// OK 是 httpprobe 那一份判据的结论。
	OK bool `json:"ok"`
	// Reason 是给人看的那一句话：不通时是"为什么不算通"，通时是状态行那一句。
	Reason string `json:"reason"`
	// 下面四格是这一条**实际**走的判定（来自拨号那一刻的路由结果），
	// 与「查走向」是同一批字段名、同一个来源，界面上说的话也就对得上。
	Policy  string `json:"policy"`
	Matched string `json:"matched"`
	Node    string `json:"node"`
	Iface   string `json:"iface"`
}

// FetchViaRouter 按规则拨出去、真取一个页面回来。
//
// 导出来是给命令行那条路（`-check-fetch`）复用的：那条与这一格必须同源于
// "怎么拨、怎么读、怎么判"，所以这里放的是唯一一份实现。
func FetchViaRouter(ctx context.Context, rt *router.Router, raw string) (httpprobe.Outcome, router.Result, error) {
	t, err := httpprobe.Parse(raw)
	if err != nil {
		return httpprobe.Outcome{}, router.Result{}, err
	}
	conn, res, err := rt.Dial(ctx, t.Addr())
	if err != nil {
		return httpprobe.Outcome{}, res, fmt.Errorf("拨 %s 失败: %w", t.Addr(), err)
	}
	defer conn.Close()
	out, err := httpprobe.Fetch(ctx, conn, t)
	if err != nil {
		return out, res, err
	}
	return out, res, out.Judge()
}

// FetchPage 是面板那一步：没在跑就直说，其余交给 FetchViaRouter。
func (s *Service) FetchPage(ctx context.Context, raw string) (PageFetch, error) {
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()
	if rt == nil {
		return PageFetch{}, errors.New("代理没在跑：先点「启动」再取页面")
	}
	target := strings.TrimSpace(raw)
	if target == "" {
		return PageFetch{}, errors.New("先填一个网址")
	}
	budget, hasBudget := budgetText(ctx)
	out, res, err := FetchViaRouter(ctx, rt, target)
	pf := PageFetch{
		URL: displayURL(target), Code: out.Code, Server: out.Server, Body: out.Body,
		ViaTLS: out.ViaTLS, Location: out.Location,
		Policy: string(res.Policy), Matched: res.Matched, Node: res.Node, Iface: res.Iface,
	}
	if res.Host != "" {
		pf.Addr = net.JoinHostPort(res.Host, res.Port)
	}
	// err 非空有两种：一种是"取回来了但不算通"（Judge 给的），
	// 一种是压根没走到那一步（解析、拨号、读状态行）。两种都要摆出来，
	// 但前者是答案、后者才是失败——界面对它们的颜色不一样。
	if err != nil {
		err = plainTimeout(pf.Addr, budget, hasBudget, err)
	}
	pf.Reason = errText(err, out)
	if err != nil {
		if out.Code != 0 {
			pf.OK = false
			return pf, nil // 有状态码就说明取到了东西，这是答案
		}
		return pf, err
	}
	pf.OK = true
	return pf, nil
}

// errText 决定这一格"给人看的那一句"写什么：出错时就是那句错，
// 没错时是探针那一份摘要（`https 200 server=x 1256 字节`）。
func errText(err error, out httpprobe.Outcome) string {
	if err != nil {
		return err.Error()
	}
	return out.String()
}

// plainTimeout 把 Go 那句 socket 噪音换成一句能读的话。
//
// 真取一次超时，界面上摆出来的是
// `读状态行失败: read tcp 127.0.0.1:37292->127.0.0.1:39649: i/o timeout`。
// 那两串数字是本机的临时端口，既不是用户填的地址、也不告诉他"等了多久"，
// 而这一格最容易被误读成"面板坏了"的时刻恰恰是超时。
// 换掉之后说的是：<真正拨出去的那个 host:port> 在 <这一格的预算> 内没回话。
//
// 只换超时。拨不通、证书对不上、TLS 握手失败那些原文都保留——
// 那些错误里的地址与算法名是有用的，不是噪音。
func plainTimeout(addr, budget string, hasBudget bool, err error) error {
	if !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if addr == "" {
		addr = "对端"
	}
	if !hasBudget {
		// 调用方没给截止，就不报"多少秒"这种具体数字——那是编出来的。
		return fmt.Errorf("%s 到点没回话（调用方没给预算，按探针兜底的 30 秒等的）", addr)
	}
	return fmt.Errorf("%s 在 %s 内没回话（这一格的预算就是 %s）", addr, budget, budget)
}

// budgetText 读出 ctx 里那份截止，化成人话的时长。
func budgetText(ctx context.Context) (string, bool) {
	d, ok := ctx.Deadline()
	if !ok {
		return "", false
	}
	left := time.Until(d)
	if left < 0 {
		left = 0
	}
	if left < time.Second {
		return fmt.Sprintf("%.1f 秒", left.Round(100*time.Millisecond).Seconds()), true
	}
	return fmt.Sprintf("%d 秒", int(left.Round(time.Second).Seconds())), true
}

// displayURL 把要回显的网址洗成"scheme://host[:port]/path"：
// 查询串与 userinfo 一律丢掉。订阅地址的 key 常挂在查询串上，
// 而这一格的存在意义就是让人把结果截图发给别人。
func displayURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	out := u.Scheme + "://" + u.Host + u.Path
	if u.Path == "" {
		out += "/"
	}
	return out
}
