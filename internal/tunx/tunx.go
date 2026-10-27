package tunx

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	tunstack "gvisor.dev/gvisor/pkg/tcpip/stack"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
	"wps_app/internal/rules"
)

// ErrUnsupported 由非 Linux 平台的设备层返回。
var ErrUnsupported = errors.New("tun: 当前平台不支持 TUN 模式（仅 Linux）")

// Options 装配一个 TUN 入站。
type Options struct {
	Conf   config.TUNConfig
	Router *router.Router
	// Lookup 是真实解析（dnsx.Resolver.LookupIP），直连域名要用它回真 IP。
	Lookup Lookup
	// Reg 可为 nil，此时连接不进流量表。
	Reg *metrics.Registry
	// Runner 为 nil 时用 ExecRunner；测试里换成记录型实现。
	Runner Runner
	// UID 为本进程有效 uid，nil 时取 os.Geteuid()。
	UID *int
	// Bypass 是 strict_route 下要钉回物理网关的目标（代理服务端 IP、DNS 上游 IP）。
	// 由调用方给出：只有 service 知道自己往哪儿发包。
	Bypass []string
	// Upstreams 是本进程用来解析的上游 DNS（IP 字面量列表）。
	// 开劫持时必须放行它们，理由见 RoutePlan.Upstreams。
	Upstreams []string
}

// Status 是 TUN 的只读状态投影，直接交给 GUI。
type Status struct {
	Enabled     bool   `json:"enabled"`
	Running     bool   `json:"running"`
	Device      string `json:"device"`
	Address     string `json:"address"`
	DNS         string `json:"dns"`
	FakeIPRange string `json:"fakeIpRange"`
	HijackDNS   bool   `json:"hijackDns"`
	StrictRoute bool   `json:"strictRoute"`
	// FakeIPs 是当前在册的假 IP 数量，能一眼看出 DNS 劫持有没有在工作。
	FakeIPs int `json:"fakeIps"`
	// Active 是正在 tun 里转发的 TCP 连接数。
	Active int64 `json:"active"`
	// DNSServed 是累计应答过的 DNS 查询数。
	DNSServed int64    `json:"dnsServed"`
	StartedAt int64    `json:"startedAt"`
	LastError string   `json:"lastError"`
	Applied   []string `json:"applied"`
	// IPv6 是用户要不要 v6 假 IP（tun.ipv6）。
	IPv6 bool `json:"ipv6"`
	// V6Ready 是 v6 那一组命令是否真的全装上了。
	// 它和 IPv6 分开报，因为「没要」和「要了没成」是两回事：前者是配置，
	// 后者多半是内核没加载 ip6table_nat，只报一个 false 会把原因指错方向。
	// V6Ready 为 false 而 IPv6 为 true 时 AAAA 回 NODATA，应用退回 A 记录——
	// 这是能工作的降级，比发一个路由不到的假 v6 好。
	V6Ready bool `json:"v6Ready"`
	// Privilege 说清「刚才那些 ip/iptables 是谁干的」：self 是本进程直接开，
	// helper 是提权命令代开。排障时这一眼就能区分权限问题的成因。
	Privilege string `json:"privilege"`
	// HelperCmd 是配置里的提权命令，出错时用户要能看见自己配的是什么。
	HelperCmd []string `json:"helperCmd,omitempty"`
}

// TUN 是一块虚拟网卡加挂在它上面的用户态协议栈。
type TUN struct {
	conf   config.TUNConfig
	rt     *router.Router
	lookup Lookup
	reg    *metrics.Registry
	runner Runner
	uid    int
	bypass []string
	// upstreams 是劫持规则要放行的 DNS 上游（New 里已过滤成 IP 字面量）。
	upstreams []string
	helper    HelperClient
	// blockedHold 是被拦连接的最长挂起时间，0 表示用 rules.BlockHold。
	// 留成字段是为了让用例不必真等 75 秒。
	blockedHold time.Duration

	mu        sync.Mutex
	dev       linkDevice
	stack     *tunstack.Stack
	fake      *FakeStore
	dns       *dnsServer
	running   bool
	startedAt time.Time
	lastErr   error
	applied   []Cmd
	plan      RoutePlan
	// v6Ready 记「v6 那一组命令全装上了」。DNS 只在它为真时才发假 v6 地址：
	// 发出去却路由不到，应用只会一路连到超时，而 NODATA 至少能退回 A 记录。
	v6Ready bool

	active    atomic.Int64
	dnsServed atomic.Int64
}

// New 只做参数校验与假 IP 表初始化，不碰系统。
func New(opt Options) (*TUN, error) {
	if opt.Router == nil {
		return nil, errors.New("tun: router 必填")
	}
	if !opt.Conf.Enable {
		return nil, errors.New("tun: 配置里 tun.enable 为 false")
	}
	uid := os.Geteuid()
	if opt.UID != nil {
		uid = *opt.UID
	}
	runner := opt.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	upstreams := make([]string, 0, len(opt.Upstreams))
	for _, s := range opt.Upstreams {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			upstreams = append(upstreams, ip.String())
		}
	}
	// tun.ipv6 关掉时连 v6 段都不建：那之后 AAAA 走 NODATA 分支，
	// 全程没有任何地方会碰 ip6tables。
	range6 := ""
	if opt.Conf.IPv6On() {
		range6 = opt.Conf.FakeIPRange6
	}
	fake, err := NewFakeStore(opt.Conf.FakeIPRange, range6, defaultFakeTTL)
	if err != nil {
		return nil, err
	}
	return &TUN{
		conf:   opt.Conf,
		rt:     opt.Router,
		lookup: opt.Lookup,
		reg:    opt.Reg,
		runner: runner,
		uid:    uid,
		bypass: opt.Bypass,
		// 提权命令来自配置，不在 Options 上再开一个口子：
		// 两条来源迟早会不一致，而「到底走哪条特权路径」是排障时最不能含糊的一件事。
		helper:    HelperClient{Argv: opt.Conf.Helper},
		upstreams: upstreams,
		fake:      fake,
		dns:       &dnsServer{decide: opt.Router, lookup: opt.Lookup, fake: fake},
	}, nil
}

// Start 建网卡、配路由、起协议栈。任一步失败都会把已做的部分回滚，
// 不会留下「网卡起来了但栈没起来」这种半活状态。
func (t *TUN) Start(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return nil
	}

	// 先把要现场探测的字段补齐：strict_route 需要知道当前的默认路由与网卡。
	plan, err := t.buildPlan(ctx)
	if err != nil {
		t.lastErr = err
		return err
	}
	t.plan = plan

	// 无条件先清残留：上一次被 kill -9 的话，劫持规则还挂在 nat 表上，
	// 而它指向的地址已经随网卡一起没了，整机解析会挂。
	if t.conf.DNSHijackEnabled() {
		if cleaned := t.cleanupStale(ctx); len(cleaned) > 0 {
			logx.Infof("TUN: 清掉了上次遗留的 %d 项（%s）", len(cleaned), strings.Join(uniqueStrings(cleaned), "、"))
		}
	}

	dev, applied, err := t.provision(ctx, plan)
	if err != nil {
		t.lastErr = err
		return err
	}
	t.dev = dev
	t.applied = applied

	st, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: handler{t},
	})
	if err != nil {
		t.teardownLocked(ctx)
		t.dev = nil
		t.lastErr = err
		return fmt.Errorf("创建协议栈失败: %w", err)
	}
	t.stack = st
	t.running = true
	t.startedAt = time.Now()
	t.lastErr = nil
	logx.Infof("TUN 已启用: %s 地址 %s，假 IP %s，DNS 劫持点 %s:53",
		t.conf.Device, t.conf.Address, t.conf.FakeIPRange, t.dnsAddress())
	return nil
}

// usesHelper 报告这次的特权路径：配了 tun.helper 就把建网卡与改网络交给提权命令。
//
// Spawn 非空也算：单测把 helper 放在进程内跑（没有 argv，但走的是同一条
// 代码路径），判据必须认这第二种来源，否则测的就不是产品真正会走的那条分支。
func (t *TUN) usesHelper() bool { return len(t.helper.Argv) > 0 || t.helper.Spawn != nil }

// provision 拿到一块「地址、路由、劫持规则都已就位」的设备，并返回执行过的步骤。
//
// 两条路径的差别只在「谁去执行 ip/iptables」：
//   - 本进程足够有权（root 面板 / setcap）就直接干，保持老行为不变；
//   - 否则交给 helper，面板以普通用户身份跑，网卡 fd 用 SCM_RIGHTS 传回来。
//     桌面要托盘就只能走这条：root 进程连不上用户会话总线，托盘注册不了。
func (t *TUN) provision(ctx context.Context, plan RoutePlan) (linkDevice, []Cmd, error) {
	if !t.usesHelper() {
		// 先提升 ambient 能力：setcap 只给本进程，exec 出去的 ip/iptables 需要它
		// 才能在 execve 之后仍然有权限改路由与 netfilter。
		if raised := raiseAmbientCaps(); len(raised) > 0 {
			logx.Infof("TUN: 已把 %s 提升进 ambient 集合，供 ip/iptables 子进程继承", strings.Join(raised, "、"))
		} else if sum := capabilitySummary(); sum != "" {
			logx.Debugf("TUN: 未能提升 ambient 能力（%s），若接下来报 Operation not permitted，请用 sudo 启动或先 setcap", sum)
		}
		dev, err := openLinkDevice(plan.Device, uint32(plan.MTU))
		if err != nil {
			return nil, nil, permissionHint(err)
		}
		up, _, _ := plan.Plan()
		if err := Apply(ctx, t.runner, up); err != nil {
			dev.Close()
			return nil, nil, fmt.Errorf("配置 tun 网络失败: %w（常见原因是缺少 CAP_NET_ADMIN，请用 sudo 或 setcap 启动）", err)
		}
		t.setV6Ready(t.applyV6(ctx, plan))
		return dev, up, nil
	}

	reply, fd, err := t.helper.Run(ctx, HelperRequest{V: helperProtoVersion, Action: ActionUp, Plan: plan})
	if err != nil {
		return nil, nil, fmt.Errorf("经 tun.helper 开网卡失败: %w", err)
	}
	dev, err := deviceFromFD(fd, reply.Device, reply.MTU)
	if err != nil {
		// 系统配置已经由 helper 落下去了，端点建不起来就得原路拆掉：
		// 留着一块没人读的网卡，表现为「TUN 显示没开但流量全黑洞」。
		dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if derr := t.releaseSystem(dctx, plan); derr != nil {
			logx.Warnf("TUN: 端点创建失败后的回滚也没干净: %v", derr)
		}
		return nil, nil, err
	}
	// Applied 来自 root 侧，只剩描述；面板日志与界面展示的那串步骤不能因为换了执行者就丢。
	applied := make([]Cmd, 0, len(reply.Applied))
	for _, desc := range reply.Applied {
		applied = append(applied, Cmd{Desc: desc})
	}
	t.setV6Ready(reply.V6OK)
	logx.Infof("TUN: 网卡 %s 由 tun.helper 创建，fd 已交给本进程（uid=%d）", reply.Device, t.uid)
	return dev, applied, nil
}

// releaseSystem 拆掉 plan 在系统里留下的配置。设备 fd 由调用方负责关。
func (t *TUN) releaseSystem(ctx context.Context, plan RoutePlan) error {
	if !t.usesHelper() {
		_, down, err := plan.Plan()
		if err == nil {
			if _, v6down, verr := plan.PlanV6(); verr == nil {
				down = append(v6down, down...)
			}
		}
		if err != nil {
			return err
		}
		var errs []error
		for _, c := range down {
			if _, err := t.runner.Run(ctx, c); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", c.Desc, err))
			}
		}
		return errors.Join(errs...)
	}
	reply, _, err := t.helper.Run(ctx, HelperRequest{V: helperProtoVersion, Action: ActionDown, Plan: plan})
	if err != nil {
		return err
	}
	if !reply.OK {
		if reply.Err == "" {
			return errors.New("helper 拆 TUN 时报告失败")
		}
		return errors.New(reply.Err)
	}
	return nil
}

// cleanupStale 清历史残留。配了 helper 就必须让它去跑 iptables——
// 在本进程跑只会在普通用户下全军覆没，而「残留没清」正是整机 DNS 挂掉那个坑。
func (t *TUN) cleanupStale(ctx context.Context) []string {
	if !t.usesHelper() {
		return CleanupStale(ctx, t.runner, t.uid, t.conf.Device, t.conf.Address)
	}
	reply, _, err := t.helper.Run(ctx, CleanupRequest(t.uid, t.conf.Device, t.conf.Address))
	if err != nil {
		// 清残留失败不阻断启用：下面的 up 本身是可重入的。
		logx.Warnf("TUN: 经 helper 清残留失败，继续尝试启用: %v", err)
		return nil
	}
	return reply.Removed
}

// Stop 关栈、拆路由、销网卡。可重复调用。
func (t *TUN) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.running && t.dev == nil {
		return nil
	}
	err := t.teardownLocked(ctx)
	t.running = false
	logx.Infof("TUN 已停用: %s", t.conf.Device)
	return err
}

// teardownLocked 是唯一的清理路径，调用方必须持有 mu。
func (t *TUN) teardownLocked(ctx context.Context) error {
	var errs []error
	if t.stack != nil {
		t.stack.Close()
		// Wait 不设上限就等于把退出交给客户端的脸色：浏览器/IDE 的长连接不会自己断，
		// 而 stack.Close 只是"不再接受新连接"。给它一个固定预算，超了就继续往下走——
		// 后面关掉设备 fd 时，内核会连着路由与这些连接一起收掉，不会留下悬挂状态。
		if !waitStack(t.stack, stackWaitBudget) {
			logx.Warnf("TUN: %s 还有连接没走完，等满 %s 后强制继续（关网卡会一并收掉它们）",
				t.conf.Device, stackWaitBudget)
		}
		t.stack = nil
	}
	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
	}
	// 网卡一消失，内核会自动收掉挂在它上面的路由；iptables 却不会自己干净，
	// 所以这里按 best-effort 跑一遍 Down 列表，重点保证劫持规则被摘掉。
	if t.plan.Device != "" {
		if err := t.releaseSystem(ctx, t.plan); err != nil {
			errs = append(errs, err)
		}
		t.applied = nil
		t.plan = RoutePlan{}
	}
	return errors.Join(errs...)
}

// Status 返回当前状态快照。
func (t *TUN) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := Status{
		Enabled:     t.conf.Enable,
		Running:     t.running,
		Device:      t.conf.Device,
		Address:     t.conf.Address,
		DNS:         t.dnsAddress(),
		FakeIPRange: t.conf.FakeIPRange,
		HijackDNS:   t.conf.DNSHijackEnabled(),
		StrictRoute: t.conf.StrictRoute,
		FakeIPs:     t.fake.Len(),
		IPv6:        t.conf.IPv6On(),
		V6Ready:     t.v6Ready,
		Active:      t.active.Load(),
		DNSServed:   t.dnsServed.Load(),
		Privilege:   "self",
		HelperCmd:   t.helper.Argv,
	}
	if t.usesHelper() {
		st.Privilege = "helper"
	}
	if t.running && !t.startedAt.IsZero() {
		st.StartedAt = t.startedAt.UnixMilli()
	}
	if t.lastErr != nil {
		st.LastError = t.lastErr.Error()
	}
	for _, c := range t.applied {
		st.Applied = append(st.Applied, c.Desc)
	}
	if st.Applied == nil {
		st.Applied = []string{}
	}
	return st
}

// setV6Ready 记录 v6 假 IP 是否真的可用，并同步给 DNS 应答器。
// Start 已经持有 t.mu，这里不再加锁。
func (t *TUN) setV6Ready(ok bool) {
	t.v6Ready = ok
	t.dns.allowV6 = ok
}

func (t *TUN) dnsAddress() string {
	if t.conf.DNS != "" {
		return t.conf.DNS
	}
	return SecondHost(t.conf.Address)
}

// address6OrEmpty 在 tun.ipv6 关掉时返回空串，PlanV6 于是整组不生成命令。
func (t *TUN) address6OrEmpty() string {
	if !t.conf.IPv6On() {
		return ""
	}
	return t.conf.Address6
}

// dns6Address 是 v6 的劫持落点。没配 address6 就返回空串，
// 那时 PlanV6 整组不生成命令，v6 假 IP 自然不发。
func (t *TUN) dns6Address() string {
	a := t.address6OrEmpty()
	if a == "" {
		return ""
	}
	return SecondHost(a)
}

// applyV6 单独应用 v6 那一组命令，成败用返回值表达。
//
// 整组要么全成、要么全撤：DNS 发了假 v6 而路由没建起来，
// 表现是「AAAA 解析得出地址但连不上」——比回 NODATA 难查得多，
// 因为应用不会退回 A 记录，它只会一直重试到超时。
func (t *TUN) applyV6(ctx context.Context, plan RoutePlan) bool {
	up, down, err := plan.PlanV6()
	if err != nil {
		logx.Warnf("TUN: IPv6 那一组配置有问题，v6 假 IP 不启用（AAAA 仍回 NODATA）: %v", err)
		return false
	}
	if len(up) == 0 {
		return false
	}
	if err := Apply(ctx, t.runner, up); err != nil {
		logx.Warnf("TUN: IPv6 假 IP 未启用，已撤回这一组（AAAA 仍回 NODATA，应用会退回 A 记录）: %v", err)
		// 撤干净：留半套规则比完全没装更糟，下次启动的残留清理会误判。
		if derr := Apply(ctx, t.runner, down); derr != nil {
			logx.Warnf("TUN: 撤回 IPv6 配置时也没干净: %v", derr)
		}
		return false
	}
	return true
}

// buildPlan 补齐需要现场探测的字段：当前默认路由（strict_route 的排除路由要用）。
func (t *TUN) buildPlan(ctx context.Context) (RoutePlan, error) {
	plan := RoutePlan{
		Device:       t.conf.Device,
		Address:      t.conf.Address,
		DNS:          t.dnsAddress(),
		FakeIPRange:  t.conf.FakeIPRange,
		Address6:     t.address6OrEmpty(),
		DNS6:         t.dns6Address(),
		FakeIPRange6: t.conf.FakeIPRange6,
		MTU:          t.conf.MTU,
		HijackDNS:    t.conf.DNSHijackEnabled(),
		StrictRoute:  t.conf.StrictRoute,
		UID:          t.uid,
		Upstreams:    append([]string(nil), t.upstreams...),
	}
	exclude := append([]string(nil), t.conf.RouteExclude...)
	if plan.StrictRoute {
		out, err := t.runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"-o", "route", "show", "default"}, Desc: "查默认路由"})
		if err != nil {
			return plan, fmt.Errorf("查默认路由失败，无法安全开启 strict_route: %w", err)
		}
		gw, iface, ok := ParseDefaultRoute(out)
		if !ok {
			return plan, errors.New("tun: 没找到默认路由，strict_route 会把默认路由指向一个不存在的出口")
		}
		plan.Gateway, plan.Interface = gw, iface
		// 自己的出站必须先绕开 tun：DNS 上游与被代理服务端一旦落进 tun，
		// 我们发出的包会被自己再抓一遍，形成环路。
		for _, ip := range t.bypass {
			exclude = append(exclude, CIDROf(ip))
		}
	}
	plan.Exclude = dedupeCIDR(exclude)
	return plan, nil
}

// CIDROf 把一个 IP 变成 /32 或 /128。
func CIDROf(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	if addr.Is4() {
		return ip + "/32"
	}
	return ip + "/128"
}

func dedupeCIDR(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// handler 把协议栈的 TCP/UDP 事件接到 TUN 上。
type handler struct{ t *TUN }

var _ adapter.TransportHandler = handler{}

func (h handler) HandleTCP(c adapter.TCPConn) { go h.t.relayTCP(c) }
func (h handler) HandleUDP(c adapter.UDPConn) { go h.t.serveUDP(c) }

// relayTCP 把 tun 里进来的一条 TCP 转给 router 选定的出站。
//
// 目标地址是从报文里来的，只会是 IP；FakeStore 反查到的域名才是规则集认的那种 key，
// 所以命中时把域名同时用作「决策依据」和「拨号目标」——
// 交给隧道去拨域名，正好也让服务端做一次解析，语义与 SOCKS5 入站保持一致。
func (t *TUN) relayTCP(c adapter.TCPConn) {
	defer c.Close()
	dst, src := endpointAddrs(c.ID())
	if !dst.IsValid() {
		logx.Warnf("tun: 收到目标地址不合法的 TCP 连接，已丢弃")
		return
	}
	// DNS-over-TCP 必须先于普通转发判掉。hijack_dns 把 tcp:53 也 DNAT 进了协议栈
	// （route.go 的「劫持 TCP DNS」），而这里过去没有 53 端口分支——
	// 结果一条被劫持的 TCP DNS 连接被当成普通连接，朝自己的网卡地址 172.19.0.2:53
	// 拨了出去。发 TCP DNS 的（Go 程序在 UDP 应答被截断时、以及开了 TC 的 glibc）
	// 拿不到任何应答，只能等到超时。
	if dst.Port() == 53 {
		n, err := serveDNSOverTCP(c, t.dns.Serve, dnsTCPIdle)
		t.dnsServed.Add(int64(n))
		if err != nil {
			logx.Debugf("tun dns(tcp) %s 处理中断（已应答 %d 条）: %v", src, n, err)
		}
		return
	}
	target := net.JoinHostPort(dst.Addr().String(), strconv.Itoa(int(dst.Port())))
	hint, _ := t.fake.Lookup(dst.Addr())
	if hint == "" && t.fake.Contains(dst.Addr()) {
		// 假 IP 段里的地址却反查不到域名：要么映射过期了，要么是应用硬编了
		// 198.18.x.x。这种连接拨出去会打回 tun，必须就地拒绝。
		logx.Warnf("tun: %s 落在假 IP 段但反查不到域名，拒绝以免环路", target)
		return
	}
	dialTarget := target
	if hint != "" {
		dialTarget = net.JoinHostPort(hint, strconv.Itoa(int(dst.Port())))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	conn, res, err := t.rt.DialHost(ctx, dialTarget, hint)
	cancel()
	if err != nil {
		if errors.Is(err, rules.ErrBlocked) {
			t.dropBlocked(c, src, dialTarget, res)
			return
		}
		logx.Warnf("tun tcp %s -> %s 失败: %v", src, dialTarget, err)
		// 拨不通也要在这一页留一行：用户点开流量页的原因往往就是"这个站打不开"，
		// 而"被拦的看得见、拨不通的看不见"会让人以为代理没在工作。
		t.reg.Refuse("tun", src, dialTarget, res, err.Error())
		return
	}
	defer conn.Close()

	t.active.Add(1)
	defer t.active.Add(-1)
	rec := t.reg.Begin("tun", src, res)
	defer t.reg.End(rec)
	logx.Infof("tun tcp %s -> %s [%s | %s]", src, dialTarget, res.Outbound, res.Matched)
	relay(metrics.Wrap(c, upOf(rec)), metrics.Wrap(conn, downOf(rec)))
}

// dropBlocked 是被拦 TCP 的落法：挂着不回话，到上限再收。
//
// 直接 return 会发 FIN——应用看到"连上就断"，那是明确的 reset 信号，
// 和选定的"让它超时"正好相反。gVisor 已经替这条连接握过手，
// 所以这里必须读到底或到上限才收尾。
// 上限是必要的而不是奢侈的：一批广告域名同时进来，全挂着就是 fd 堆积。
func (t *TUN) dropBlocked(c adapter.TCPConn, client, target string, res router.Result) {
	hold := t.blockedHold
	if hold <= 0 {
		hold = rules.BlockHold
	}
	t.recordBlocked("tun tcp", client, target, res)
	_ = c.SetReadDeadline(time.Now().Add(hold))
	_, _ = io.Copy(io.Discard, c)
}

// recordBlocked 单独记一笔拦截：客户端收不到原因，本机连接表就是唯一线索。
// 字节数天然是 0——我们一个字节也没搬。
func (t *TUN) recordBlocked(kind, client, target string, res router.Result) {
	logx.Warnf("%s 拦截 %s [%s]（按拦截名单，应用不会收到原因）", kind, target, res.Matched)
	if t.reg == nil {
		return
	}
	rec := t.reg.Begin(kind, client, res)
	t.reg.End(rec)
}

// serveUDP 处理 tun 里进来的一条 UDP 关联：53 端口是 DNS，其余走隧道。
func (t *TUN) serveUDP(c adapter.UDPConn) {
	defer c.Close()
	dst, srcAddr := endpointFull(c.ID())
	if !dst.IsValid() {
		return
	}
	if dst.Port() == 53 {
		t.serveUDPDNS(c, srcAddr.String())
		return
	}
	t.relayUDP(c, dst, srcAddr, srcAddr.String())
}

// serveUDPDNS 原地应答 DNS 查询，不惊动出站。
func (t *TUN) serveUDPDNS(c adapter.UDPConn, src string) {
	buf := make([]byte, 4096)
	for {
		_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				logx.Debugf("tun dns 读失败: %v", err)
			}
			return
		}
		query := append([]byte(nil), buf[:n]...)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		resp, err := t.dns.Serve(ctx, query)
		cancel()
		if err != nil {
			logx.Warnf("tun dns %s 应答失败: %v", src, err)
			return
		}
		t.dnsServed.Add(1)
		if _, err := c.Write(resp); err != nil {
			logx.Debugf("tun dns 写回失败: %v", err)
			return
		}
	}
}

// udpIdle 是 UDP 关联的空闲回收窗口。
//
// UDP 没有 FIN，协议栈那边的端点会一直活着：应用关掉了程序也不会有人来收尾，
// 于是「机器上曾经开过的每一条 UDP 关联」都会变成一条永久挂着的关联。
// 两分钟对齐 QUIC 自己的习惯——客户端一般十几秒一次 keepalive，
// 真在传数据的关联每次收发都会把窗口往后推，所以活着的关联碰不到它。
const udpIdle = 2 * time.Minute

// udpBufferSize 是收发缓冲。取满 64K 是因为 IP 层的最大报文就是这么多，
// 比它小的那一截会在 ReadFrom 里被直接截断（没有 MSG_TRUNC 可言），
// 而 QUIC 的路径 MTU 探测包、DTLS 握手包都在这个量级上。
const udpBufferSize = 65535

// udpFlow 是 tun 侧一条 UDP 关联真正用到的那些能力。
// 从 adapter.UDPConn 收窄出来，是为了能在没有协议栈的单元测试里驱动它。
type udpFlow interface {
	net.PacketConn
	ID() tunstack.TransportEndpointID
}

// relayUDP 把一条 tun 里的 UDP 关联接到出站上。
//
// 与 relayTCP 同构：报文里只有 IP，FakeStore 反查到的域名才是规则集认的 key，
// 于是域名既用于判定也用于拨号，交给服务端解析，语义与 SOCKS5 入站一致。
func (t *TUN) relayUDP(c udpFlow, dst netip.AddrPort, srcAddr netip.AddrPort, src string) {
	target := net.JoinHostPort(dst.Addr().String(), strconv.Itoa(int(dst.Port())))
	hint, _ := t.fake.Lookup(dst.Addr())
	if hint == "" && t.fake.Contains(dst.Addr()) {
		// 与 relayTCP 同一个理由：假 IP 段里的地址反查不到域名，拨出去只会打回 tun。
		logx.Warnf("tun udp: %s 落在假 IP 段但反查不到域名，拒绝以免环路", target)
		return
	}
	dialTarget := target
	if hint != "" {
		dialTarget = net.JoinHostPort(hint, strconv.Itoa(int(dst.Port())))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pc, res, err := t.rt.DialUDPHost(ctx, dialTarget, hint)
	cancel()
	if err != nil {
		if errors.Is(err, rules.ErrBlocked) {
			// UDP 本来就是丢包不回话，这里只是把它单独记一笔：
			// 应用侧看不到任何原因，本机得看得见。
			t.recordBlocked("tun udp", src, dialTarget, res)
			return
		}
		// 「这条路本来就不通」（节点协议不带 UDP、会话数打满）不是节点故障，
		// 但也不能静默丢掉——应用的表现会是干等到超时，而超时从不说为什么。
		logx.Warnf("tun udp %s -> %s 未转发: %v", src, dialTarget, err)
		return
	}
	defer pc.Close()

	t.active.Add(1)
	defer t.active.Add(-1)
	rec := t.reg.Begin("tun", src, res)
	defer t.reg.End(rec)
	logx.Infof("tun udp %s -> %s [%s | %s]", src, dialTarget, res.Outbound, res.Matched)

	back := &net.UDPAddr{IP: srcAddr.Addr().AsSlice(), Port: int(srcAddr.Port())}
	t.pumpUDP(c, pc, dialTarget, back, rec)
}

// pumpUDP 双向搬运一条 UDP 关联。任一方向结束就整体收尾。
func (t *TUN) pumpUDP(c udpFlow, pc outbound.PacketConn, target string, back *net.UDPAddr, rec *metrics.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			_ = c.SetReadDeadline(time.Now().Add(udpIdle))
			n, _, err := c.ReadFrom(buf)
			if err != nil || n == 0 {
				done <- struct{}{}
				return
			}
			countUp(rec, n)
			if err := pc.WriteTo(buf[:n], target); err != nil {
				logx.Debugf("tun udp 发往 %s 失败: %v", target, err)
				done <- struct{}{}
				return
			}
		}
	}()
	go func() {
		buf := make([]byte, udpBufferSize)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil || n == 0 {
				done <- struct{}{}
				return
			}
			countDown(rec, n)
			if _, err := c.WriteTo(buf[:n], back); err != nil {
				logx.Debugf("tun udp 回写 %s 失败: %v", back, err)
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
	// 等另一方向收尾再退：一条 QUIC 关联关掉时，本地这一侧可能还有几个包在路上。
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func countUp(rec *metrics.Conn, n int) {
	if rec != nil {
		rec.Up.Add(uint64(n))
	}
}

func countDown(rec *metrics.Conn, n int) {
	if rec != nil {
		rec.Down.Add(uint64(n))
	}
}

// relay 双向搬运，与 SOCKS5/HTTP 入站同一套半关闭语义：
// 一个方向读到 EOF 后只做 CloseWrite，另一方向还能把剩下的数据发完，
// 两侧都收尾才整体结束。不做半关闭的话，一端先关会让另一端永远挂在 Read 上。
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		closeWrite(b)
	}()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func upOf(c *metrics.Conn) *atomic.Uint64 {
	if c == nil {
		return nil
	}
	return &c.Up
}

func downOf(c *metrics.Conn) *atomic.Uint64 {
	if c == nil {
		return nil
	}
	return &c.Down
}

// stackWaitBudget 是退出时等协议栈把在传连接走完的上限。
const stackWaitBudget = 3 * time.Second

// waitStack 在后台等 stack.Wait()，最多等 budget，返回是否在预算内结束。
//
// stack.Wait 本身没有超时能力，而它等的是「应用什么时候肯关连接」——
// 浏览器的 keep-alive 与 IDE 的长轮询可以一直不关。
func waitStack(st *tunstack.Stack, budget time.Duration) bool {
	done := make(chan struct{})
	go func() {
		st.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(budget):
		return false
	}
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func permissionHint(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrPermission) || errors.Is(err, ErrUnsupported) {
		return err
	}
	return fmt.Errorf("%w（TUN 需要 root：面板靠 exec ip/iptables 改网络与 netfilter，"+
		"子进程不会继承文件能力，所以单给二进制 setcap 不够，请用 sudo 启动面板）", err)
}
