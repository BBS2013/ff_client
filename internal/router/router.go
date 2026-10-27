// Package router 把入站请求按规则映射到具体出站。
package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

// Result 描述一次路由决策，便于日志与排障。
type Result struct {
	Host     string
	Port     string
	Policy   outbound.Policy
	Matched  string
	Outbound string
	// Node 是这条连接的字节实际记到谁头上：走代理=当前节点名，DIRECT/REJECT 各自成类。
	Node string
	// Iface 是这条连接被钉在的那张网卡（wlp3s0f0 之类）；没钉时是空串。
	Iface string
}

// Router 持有可热替换的规则引擎与出站集合。
type Router struct {
	engine atomic.Pointer[rules.Engine]
	// mode 用 atomic.Pointer 存 *config.Mode：config.Mode 是字符串类型，
	// 没有原子版本，指针换起来不会撕裂读。
	mode   atomic.Pointer[config.Mode]
	out    *outbound.Set
	dialTO time.Duration
	// onFault 是拨号失败的观察者，见 SetFaultObserver。
	onFault atomic.Pointer[FaultObserver]
	// iface 回答某个策略的出站被钉在哪张网卡上，见 SetIfaceResolver。
	iface atomic.Pointer[IfaceResolver]
}

// IfaceResolver 回答「这个策略的出站会被钉在哪张网卡上」，返回空串表示没钉。
//
// 做成函数而不是直接持有 outbound.Split：路由器不该知道网卡分流怎么实现，
// 而服务层装配时那个 Split 还没进任何出站，构造期传不进来——与 SetFaultObserver 同理。
type IfaceResolver func(policy outbound.Policy) string

// SetIfaceResolver 装上（或传 nil 清掉）网卡走向的查询器。
func (r *Router) SetIfaceResolver(fn IfaceResolver) {
	if fn == nil {
		r.iface.Store(nil)
		return
	}
	r.iface.Store(&fn)
}

// ifaceOf 问一次网卡走向，没装查询器时返回空串。
func (r *Router) ifaceOf(p outbound.Policy) string {
	fn := r.iface.Load()
	if fn == nil {
		return ""
	}
	return (*fn)(p)
}

// FaultObserver 收到一次「拨号失败」。
//
// 每条转发路径本来就会把自己的错误写进日志，但没有一个地方把它们攒起来看趋势——
// 「这个节点是不是已经不行了」需要跨请求统计，只能在这里挂钩子取。
// 传入的是未包装的原始错误与当初选中的那只出站，
// 由调用方自己判断是不是节点的锅、以及要不要动手。
type FaultObserver func(target string, d outbound.Dialer, err error)

// SetFaultObserver 设置（或传 nil 清掉）拨号失败的观察者。
// 用 atomic 而不是构造参数：观察者要在出站建好之后才装得上，
// 而它读的是服务层的状态，构造期互相依赖会绕成环。
func (r *Router) SetFaultObserver(obs FaultObserver) {
	if obs == nil {
		r.onFault.Store(nil)
		return
	}
	r.onFault.Store(&obs)
}

// New 创建路由器并加载首份规则。
func New(engine *rules.Engine, out *outbound.Set, dialTimeout time.Duration) *Router {
	r := &Router{out: out, dialTO: dialTimeout}
	r.engine.Store(engine)
	m := config.ModeRule
	r.mode.Store(&m)
	return r
}

// Engine 返回当前规则引擎。
func (r *Router) Engine() *rules.Engine { return r.engine.Load() }

// SetBlocklist 装上配置里的拦截名单。
//
// 必须在每一次规则加载之后调用：Reload 换的是整个引擎，
// 名单不跟着补一次就会在下一次热重载后**悄悄不再拦**——
// 而那正好是最难发现的一种失效（没人会去盯一个本来就没反应的域名）。
func (r *Router) SetBlocklist(domains []string) {
	if r == nil {
		return
	}
	r.Engine().SetBlocklist(domains)
}

// DropPinnedNodes 丢掉「规则钉到具体节点」那批临时出站并关掉它们。
//
// 配置里的节点一改就必须调，否则缓存里那只还在用旧参数拨号（详见 outbound.Set.DropNode
// 与 service.mutate 那一段）。正在跑的连接不受影响：它们握着的是当初选好的那只 dialer。
func (r *Router) DropPinnedNodes() {
	for _, d := range r.out.DropNode("") {
		_ = d.Close()
	}
}

// SwapProxy 换掉 PROXY 出站，返回旧的那只（可能为 nil），由调用方关闭。
//
// 这是「切节点」的正解：节点只决定出口是谁，规则、模式、假 IP、监听端口、
// 网卡与路由都跟它无关。整块重启服务把这些也一起拆了重来，
// 用户点一下「选用」要等两三秒，看起来就像界面卡死。
func (r *Router) SwapProxy(next outbound.Dialer, node string) (outbound.Dialer, error) {
	if next == nil {
		return nil, errors.New("router: 新的 PROXY 出站为空")
	}
	old := r.out.SwapProxy(next, node)
	logx.Infof("PROXY 出站已换成 %s（节点 %s）", next.Name(), r.out.Node())
	return old, nil
}

// Mode 返回当前分流模式。
func (r *Router) Mode() config.Mode {
	if p := r.mode.Load(); p != nil {
		return *p
	}
	return config.ModeRule
}

// SetMode 切换分流模式，对随后的新连接立即生效。
// 已建立的连接不受影响——它们走的是当初选定的那条出站，
// 强行中途改道会让正在传的数据失去语义。
func (r *Router) SetMode(m config.Mode) {
	if _, err := config.ParseMode(string(m)); err != nil {
		return
	}
	r.mode.Store(&m)
	logx.Infof("分流模式切换为 %s", m)
}

// decide 是「这条连接该走哪个出站」的唯一决策入口：模式优先于规则。
// 返回值第二个是给人看的命中依据，会进日志与连接表；第三个是这条规则钉住的节点名
// （没钉就是空串）。
//
// 全局模式与直连模式一律不带节点：它们整体压过规则集，此刻"这条域名钉了谁"
// 根本不参与决策。让模式那一栏也能返回节点名，界面上就会出现
// 「现在是直连模式，但这条流量固定走 US-LA」这种自相矛盾的话。
func (r *Router) decide(ctx context.Context, host string) (rules.Policy, string, string) {
	switch r.Mode() {
	case config.ModeGlobal:
		return rules.PolicyProxy, "MODE,GLOBAL", ""
	case config.ModeDirect:
		return rules.PolicyDirect, "MODE,DIRECT", ""
	default:
		return r.Engine().MatchNode(ctx, host)
	}
}

// Decide 只出策略、不建连接。TUN 的 DNS 应答需要它：
// 同一个域名，判成 PROXY 就回假 IP（把流量引进 tun），判成 DIRECT 就回真 IP
// （流量根本不进 tun）。没有这个入口的话 DNS 就只能瞎猜。
//
// 它刻意**不**带节点名出去：DNS 只决定"这个 IP 是假的还是真的"，
// 走哪条隧道是转发那一刻的事。固定节点那条在拨号时会按同一份规则再算一次，
// 两次算的是同一个引擎、同一个域名，所以方向不会分家
// （判据见 mode_test.go 里"DNS 与拨号必须给同一个答案"那条）。
func (r *Router) Decide(ctx context.Context, host string) (rules.Policy, string) {
	p, m, _ := r.decide(ctx, host)
	return p, m
}

// Dial 按规则选择出站并建立连接。addr 形如 "host:port"。
func (r *Router) Dial(ctx context.Context, addr string) (net.Conn, Result, error) {
	return r.DialHost(ctx, addr, "")
}

// DialHost 与 Dial 相同，但多给一个「这个 IP 其实属于哪个域名」的提示。
// TUN 入站拿到的目标往往只是 IP（应用已经把域名解析掉了），
// 而规则集里最有价值的正是域名规则，所以解析阶段记下来的域名要能带进来。
// hint 为空时完全按 addr 里的 host 决策。
func (r *Router) DialHost(ctx context.Context, addr, hint string) (net.Conn, Result, error) {
	host, port, d, res, err := r.pick(ctx, addr, hint)
	if err != nil {
		return nil, res, err
	}
	target := net.JoinHostPort(host, port)
	conn, err := dialWithTimeout(ctx, r.dialTO, d, target)
	if err != nil {
		r.reportFault(target, d, err)
		return nil, res, fmt.Errorf("dial %s via %s: %w", target, d.Name(), err)
	}
	return conn, res, nil
}

// DialUDPHost 与 DialHost 同一套决策，只是开出来的不是一条流而是一整条 UDP 关联。
//
// 关联本身不含目标（报文自带地址），所以这里也只需要一个「先判一次」的地址：
// 调用方用它来定这条关联归谁管，之后每包再按各自的地址转发。
func (r *Router) DialUDPHost(ctx context.Context, addr, hint string) (outbound.PacketConn, Result, error) {
	host, port, d, res, err := r.pick(ctx, addr, hint)
	if err != nil {
		return nil, res, err
	}
	target := net.JoinHostPort(host, port)
	pc, err := dialUDPWithTimeout(ctx, r.dialTO, d)
	if err != nil {
		// 「这条路本来就不通」（协议不带 UDP）不算节点的故障，
		// 不然一次正常的拒绝会在故障切换那里凑够次数，把好好的节点切掉。
		if !errors.Is(err, outbound.ErrNoUDP) && !errors.Is(err, outbound.ErrTooManyUDP) {
			r.reportFault(target, d, err)
		}
		return nil, res, fmt.Errorf("udp %s via %s: %w", target, d.Name(), err)
	}
	return pc, res, nil
}

// pick 是「这条连接该走哪个出站」里与传输无关的那半：拆地址、定策略、取 Dialer。
// TCP 与 UDP 两条路径共用，否则同一个 hint 的处理迟早会在两边走偏。
func (r *Router) pick(ctx context.Context, addr, hint string) (host, port string, d outbound.Dialer, res Result, err error) {
	host, port, err = net.SplitHostPort(addr)
	if err != nil {
		return "", "", nil, Result{}, fmt.Errorf("bad address %q: %w", addr, err)
	}
	// 决策用的 host：优先用 hint（域名），否则用字面量。
	// 字面量 IP 会直接进 IP 规则，这条边界由 rules.Engine 保证。
	decisionHost := host
	if h := strings.TrimSpace(hint); h != "" && net.ParseIP(host) != nil {
		decisionHost = h
	}
	policy, matched, node := r.decide(ctx, decisionHost)
	if decisionHost != host {
		matched = fmt.Sprintf("%s(via %s)", matched, decisionHost)
	}
	// 拦截在选择出站之前挡下：一个都不拨、也不进故障统计。
	// 放在后面哪怕有 Get 里的兜底分支，也已经把「拦下」变成了「走代理」。
	if policy == rules.PolicyReject {
		return host, port, nil, Result{
			Host: host, Port: port,
			Policy: outbound.PolicyReject, Matched: matched, Outbound: "REJECT", Node: "REJECT",
		}, fmt.Errorf("%w: %s", rules.ErrBlocked, matched)
	}
	op, err := toOutboundPolicy(policy)
	if err != nil {
		// 未接入的策略一律拒绝转发。宁可让这一条连接报错，也不能猜方向：
		// 猜成 PROXY 会把"拦下"变成"放行"，猜成 DIRECT 会把"该走代理"变成裸奔，
		// 而两种猜法在界面上都长得跟正常工作一模一样。
		return "", "", nil, Result{}, err
	}
	if node != "" {
		// 规则钉了节点：这条流量只认那一个。取不到就报错，**不许**回落到当前活动节点
		// （理由见 outbound.Set.GetNode）。
		d, err = r.out.GetNode(node)
		if err != nil {
			return "", "", nil, Result{}, err
		}
		return host, port, d, Result{
			Host: host, Port: port, Policy: op, Matched: matched, Outbound: d.Name(), Node: node,
			Iface: r.ifaceOf(op),
		}, nil
	}
	d, err = r.out.Get(op)
	if err != nil {
		return "", "", nil, Result{}, err
	}
	return host, port, d, Result{
		Host: host, Port: port, Policy: op, Matched: matched, Outbound: d.Name(),
		// 直连没有"节点"可言，就写 DIRECT；走代理才报当前那个节点的名字。
		Node:  nodeOf(op, r.out.Node()),
		Iface: r.ifaceOf(op),
	}, nil
}

func dialWithTimeout(ctx context.Context, to time.Duration, d outbound.Dialer, addr string) (net.Conn, error) {
	if to <= 0 {
		return d.DialContext(ctx, addr)
	}
	dctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	return d.DialContext(dctx, addr)
}

func dialUDPWithTimeout(ctx context.Context, to time.Duration, d outbound.Dialer) (outbound.PacketConn, error) {
	if to <= 0 {
		return outbound.DialUDP(ctx, d)
	}
	dctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	return outbound.DialUDP(dctx, d)
}

// reportFault 把一次拨号失败转交给故障观察者。
//
// 如实转交但不替它下结论：「算不算节点的错」只有协议自己知道
// （见 outbound.NodeFault）。观察者拿到的是未包装的原始错误——
// 交出去给调用方的那条是包装过的，两处用同一个 err 反而容易让人以为判据一致。
func (r *Router) reportFault(target string, d outbound.Dialer, err error) {
	if obs := r.onFault.Load(); obs != nil {
		(*obs)(target, d, err)
	}
}

// toOutboundPolicy 把规则层的策略翻译成出站层的策略。
//
// default 不能塌成 PROXY：那是"没听说过这个策略，就当作全部走代理"。
// 拦截刚加进来时踩的就是同一类坑（黑名单静默反转成代理名单，症状与正常转发一模一样），
// 所以未接入的策略一律报错、并且让调用方**拒绝**这条连接而不是猜一个方向。
// 编译器抓不到漏 case，只有把错误当返回值传出去才拦得住下一个人。
func toOutboundPolicy(p rules.Policy) (outbound.Policy, error) {
	switch p {
	case rules.PolicyDirect:
		return outbound.PolicyDirect, nil
	case rules.PolicyProxy:
		return outbound.PolicyProxy, nil
	case rules.PolicyReject:
		return outbound.PolicyReject, nil
	default:
		return "", fmt.Errorf("分流策略 %q 还没接入出站选择，拒绝转发而不是猜一个方向", p)
	}
}

// Reload 重新加载规则集；失败时保留旧规则继续服务。
//
// 这里故意不打那条"重载完成"的汇总日志：日志要报的是**装完之后**的状态，
// 而拦截名单是调用方在 Reload 之后才铺上来的（Service.Reload）。在这里打，
// 拦截数永远是 0，等于把"名单没装上"这个最该看出来的事报成正常。
func (r *Router) Reload(rulesPath string, geo rules.GeoLookup, resolver rules.Resolver) error {
	eng, err := rules.Load(rulesPath, geo, resolver)
	if err != nil {
		return fmt.Errorf("reload rules: %w", err)
	}
	r.engine.Store(eng)
	return nil
}

// Close 关闭出站集合。
func (r *Router) Close() error { return r.out.Close() }

// nodeOf 决定一条连接该记到哪个"去处"名下。
//
// REJECT 与 DIRECT 不是节点：拦截根本不产生字节，直连的字节是走本机网卡的，
// 把它们混进"各节点用量"里，那个表就再也不能拿来对账单了。
func nodeOf(p outbound.Policy, proxyNode string) string {
	switch p {
	case outbound.PolicyDirect:
		return string(outbound.PolicyDirect)
	case outbound.PolicyReject:
		return string(outbound.PolicyReject)
	default:
		return proxyNode
	}
}
