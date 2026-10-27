package router

import (
	"context"
	"errors"
	"net"
	"strings"

	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

// Preview 回答「这个目标现在会怎么走」：一个字节都不拨，也不解析任何节点地址。
//
// 判定那一段复用 decide——那正是 `pick` 的第一步，真拨号走的也是它，
// 所以"探测说走代理、连接却被拦下"这种当场打脸在规则这一段是分不了家的。
//
// 刻意**不**往下走 pick 的出站解析那一段。那一步会懒建节点的出站，
// 于是顺手把节点的服务端地址解析一次（一次对外 DNS 查询），
// 而探测恰恰是在"网已经不好"的时候被人打开的：
// 让它的成败挂在一个节点的 DNS 上，等于把这一问最要紧的答案
// （哪条规则命中、判成什么、钉了谁）交给了一件它本来不必知道的事。
// "钉住的节点在配置里根本没有"那一问另有出处：面板上「这份名单里的问题」那一栏，
// 以及真拨号时 `GetNode` 的失败——两处都不必靠解析地址来回答。
//
// 命中拦截名单**不算失败**：被拦就是这一问的答案。把它当错误返回，
// 调用方就只能去比对错误文本，而那正是界面不该拼起来的东西。
func (r *Router) Preview(ctx context.Context, host string) (Result, error) {
	h := decisionHost(host)
	if h == "" {
		return Result{}, errors.New("router: 探测目标为空")
	}
	policy, matched, node := r.decide(ctx, h)
	// 与 pick 同一个顺序：拦截在选择出站之前就挡下，且两个出站一个都不碰。
	if policy == rules.PolicyReject {
		return Result{
			Host: h, Policy: outbound.PolicyReject, Matched: matched,
			Outbound: "REJECT", Node: "REJECT",
		}, nil
	}
	op, err := toOutboundPolicy(policy)
	if err != nil {
		return Result{Host: h, Matched: matched}, err
	}
	res := Result{
		Host: h, Policy: op, Matched: matched,
		// 去处这一段只能报到策略名：出站的名字要 Get 才知道，而 Get 就是上面
		// 刻意不去做的那一步。界面用的是 Node 那一格，不是这里。
		Outbound: string(op),
		Node:     nodeOf(op, r.out.Node()),
		// 网卡那一段是一次纯查表（SetIfaceResolver 装进去的那个函数），
		// 不建任何东西，所以探测可以照实报"这条会被钉在哪张卡上"。
		Iface: r.ifaceOf(op),
	}
	if node != "" {
		// 规则钉住的名字优先，且它来自规则行本身，不必建出站。
		res.Node = node
	}
	return res, nil
}

// decisionHost 把探测框里的写法收成判定用的 host。
//
// "域名:端口" 与 "[::1]:443" 都先摘掉端口——与 pick 第一句 SplitHostPort 同一个读法，
// 否则用户从连接表里复制一个带端口的目标过来，会得到一句"没命中任何规则"。
// 裸 IPv6（没有端口也没有方括号）SplitHostPort 会报 too many colons，
// 那种输入照原样交给引擎，它会按 IP 规则处理。
func decisionHost(in string) string {
	h := strings.TrimSpace(in)
	if hh, _, err := net.SplitHostPort(h); err == nil {
		return hh
	}
	if len(h) > 2 && strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1]
	}
	return h
}
