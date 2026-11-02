package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// loopErr 是拨回自己入站端口时给出的错误。它必须是一眼可辨的错误而不是
// 一个普通的拨号失败：症状（连接数指数增长、CPU 打满）离原因太远，
// 用户很难自己想到「我让代理连了它自己」。
var loopErr = fmt.Errorf("outbound: 目标是本进程自己的入站监听地址，会形成环路，已拒绝")

// Direct 是直连出站。
type Direct struct {
	dialer *net.Dialer
	// resolve 非空时先自己解析再拨字面 IP，见 WithResolver。
	resolve HostResolver
	// selfPorts 是本进程入站监听的端口集合。
	// Dialer 接口要求「出站流量不得经过本进程的入站监听端口」，
	// 直连出站不做任何加工，是唯一会去照拨目标的地方，因此由它兜底。
	selfPorts map[int]struct{}
	// split 非空时把直连钉在那张卡上，见 WithSplit。
	split *Split
}

// NewDirect 创建直连出站。timeout 用于限制建立连接的时间。
//
// reject 传入本进程自己的入站监听地址（如 "127.0.0.1:7891"）。
// 留空则不做环路防护，仅适合测试与单一用途的嵌入式调用。
func NewDirect(timeout time.Duration, reject ...string) *Direct {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	d := &Direct{dialer: &net.Dialer{Timeout: timeout}}
	for _, a := range reject {
		_, port, err := net.SplitHostPort(strings.TrimSpace(a))
		if err != nil {
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			continue
		}
		if d.selfPorts == nil {
			d.selfPorts = make(map[int]struct{})
		}
		d.selfPorts[p] = struct{}{}
	}
	return d
}

func (d *Direct) Name() string { return string(PolicyDirect) }

// WithResolver 让直连出站用自己的解析器先把域名换成 IP 再拨。
//
// 要修的是「判定与拨号用了两套解析器」：规则引擎拿一份 IP 判成 DIRECT，
// Direct 转头用系统解析器（glibc / systemd-resolved）连到**另一个**地址上——
// 于是日志里那条「命中 GEOIP,CN,DIRECT」描述的连接，和真正建立的连接不是同一回事。
// 统一到一个解析器之后，判定看到的和拨号连上的才是同一批地址。
//
// 注意这里用的是**直连视角**，不是隧道视角：CDN 会按问的人所在的位置给答案，
// 从节点那边问回来的地址对本地直连往往是更糟的选择，不是"更干净"的答案。
func (d *Direct) WithResolver(r HostResolver) *Direct {
	d.resolve = r
	return d
}

// WithSplit 让直连出站把 socket 钉到指定网卡上，链式写法。
//
// 绑在拨号器而不是每条连接上：直连是每条连接现拨的，而钉网卡的判据
// （这张分流此刻生效没有）会在运行中变；Control 回调在建 socket 的那一刻
// 才去看，因此一次装配就够，切模式不必重建出站。
func (d *Direct) WithSplit(s *Split) *Direct {
	d.split = s
	if s != nil {
		d.dialer.Control = s.DirectControl()
	}
	return d
}

// dial 是直连唯一的落点：能自己绑就自己绑，绑了发不出包而这台机器上有特权通道时，
// 请 root 造一条钉在**直连那张卡**上、已经连通的 socket 交回来。
//
// 为什么直连也要问这件事：2026-10-30 之前特权通道只接代理侧，探针也只问代理侧，
// 于是普通权限的界面写着「直连钉在内置卡上是真的在干活」——那句话是假的：
// 内置卡上的钉卡同样被静默丢包（两台面板 via DIRECT 失败 363/1244 条、成功 0 条；
// 转 root 后失败 0、成功 17）。
//
// 只接**已解析的 ip:port**：helper 里不许解析域名（故障现场重解析会拿到假 IP，
// 这条硬规矩在 tunx 的 checkBindTarget），所以那两条"解析器坏了退回系统解析"的
// 降级路径仍然自己拨——宁可少钉一次，也不把域名交给 root。
func (d *Direct) dial(ctx context.Context, addr string) (net.Conn, error) {
	if d.split != nil && d.split.ShouldUseBind(PolicyDirect) {
		if host, _, err := net.SplitHostPort(addr); err == nil && net.ParseIP(host) != nil {
			conn, berr := d.split.BoundDialFor(ctx, PolicyDirect, addr)
			if berr != nil {
				return nil, fmt.Errorf("走提权通道钉卡失败: %w", berr)
			}
			return conn, nil
		}
	}
	return d.dialer.DialContext(ctx, "tcp", addr)
}

func (d *Direct) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	if err := d.checkLoop(addr); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// 形状不对就别自己解释，交给拨号器报它那份标准错误。
		return d.dial(ctx, addr)
	}
	if d.resolve == nil || net.ParseIP(host) != nil {
		return d.dial(ctx, addr)
	}
	addrs, rerr := d.resolve.LookupIP(ctx, host)
	if rerr != nil || len(addrs) == 0 {
		// 自己的解析器坏了不能顺手把连接也判死：退回原样交给系统解析器。
		// 这与 resolveServerHost 的降级方向一致——宁可多一次降级，不制造新的失败。
		return d.dial(ctx, addr)
	}
	// 自己预解析就得把 net.Dialer 原本免费提供的多地址重试补回来：
	// 只连第一个地址的话，多宿主的域名会从"有一个能通就通"变成"第一个不通就全不通"。
	//
	// 报错误必要带上**第一个**地址的错误：只留 lastErr 时，日志上看到的
	// 永远是最后一个候选（常常是排在 v4 后面的 v6），而 v4 那份才是首因。
	// 更要紧的是下面那条提前退出——预算没了的时候以前直接交一句裸的 ctx.Err()，
	// 于是「直连拨不通」在线上只剩「context deadline exceeded」这一种形状，
	// 哪个域名、几个地址、拨到第几个、为什么不通，全都在那一步丢了。
	var (
		firstErr error
		lastErr  error
		tried    int
	)
	for _, a := range preferV4(addrs) {
		candidate := net.JoinHostPort(a.String(), port)
		// 环路防护必须逐个 IP 再做一遍：checkLoop 看的是字面 host，
		// 而 evil.com 完全可能解析成 127.0.0.1——按 host 判会整个漏掉。
		if err := d.checkLoop(candidate); err != nil {
			return nil, err
		}
		conn, derr := d.dial(ctx, candidate)
		if derr == nil {
			return conn, nil
		}
		tried++
		if firstErr == nil {
			firstErr = derr
		}
		lastErr = derr
		if ctx.Err() != nil {
			return nil, fmt.Errorf("直连 %s 的 %d 个地址只拨到第 %d 个就没预算了（首个错误 %v）: %w",
				host, len(addrs), tried, firstErr, ctx.Err())
		}
	}
	if firstErr == lastErr {
		// 只有一个候选地址，不必把同一条错误写两遍。
		return nil, fmt.Errorf("直连 %s 的 %d 个地址都没拨通: %w", host, tried, lastErr)
	}
	return nil, fmt.Errorf("直连 %s 的 %d 个地址都没拨通（首个 %v，末个 %v）: %w",
		host, tried, firstErr, lastErr, errors.Join(firstErr, lastErr))
}

// DialUDP 明确拒绝。
//
// 直连出站要真的支持 UDP，就得为每个目标自己解析、自己挑 IP、自己重试，
// 而直连 UDP 的默认用法（游戏、语音）恰恰是那些直连判定最不关心的目标——
// 规则集里根本没有它们的信息。于是这条路径的收益远小于它带来的复杂度，
// 不做比做一个半吊子诚实。UDP 走不通的目标由调用方按协议明确告知。
func (d *Direct) DialUDP(context.Context) (PacketConn, error) {
	return nil, errUDPRefused("直连（DIRECT）出站")
}

// preferV4 把 IPv4 排到前面，与 resolveServerHost 的多候选取向保持一致。
func preferV4(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !a.Is6() {
			out = append(out, a)
		}
	}
	for _, a := range addrs {
		if a.Is6() {
			out = append(out, a)
		}
	}
	return out
}

// checkLoop 判断目标是不是本进程自己的入站端口。
//
// 只比端口，不比 IP：配置里常写 "0.0.0.0:7891"，而客户端拨的是
// "127.0.0.1:7891" 或 "[::1]:7891"，三者落到同一个 socket 上。
// 因此命中端口且目标是回环/未指定地址时一律拒绝。
func (d *Direct) checkLoop(addr string) error {
	if len(d.selfPorts) == 0 {
		return nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil // 交给拨号器去报错，这里不越权解释
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil
	}
	if _, self := d.selfPorts[p]; !self {
		return nil
	}
	// 目标必须是本机回环才构成环路：拨自己的通配监听地址只有回到本机才成立。
	ip, perr := netip.ParseAddr(host)
	if perr == nil && !ip.IsLoopback() && !ip.IsUnspecified() {
		return nil
	}
	if perr != nil {
		// 主机名形式（如 "localhost:7891"）：交给回环判定，保守拒绝。
		if !isLocalHostName(host) {
			return nil
		}
	}
	return loopErr
}

// isLocalHostName 判断主机名是否一定指向本机。
func isLocalHostName(host string) bool {
	switch strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), ".")) {
	case "localhost", "localhost.localdomain":
		return true
	}
	return false
}

func (d *Direct) Close() error { return nil }
