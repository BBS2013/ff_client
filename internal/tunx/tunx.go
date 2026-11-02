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
	// DNSServed 是**答上了**的 DNS 查询数（不含回 SERVFAIL 的那些）。
	DNSServed int64 `json:"dnsServed"`
	// DNSFailed 是回了 SERVFAIL 的查询数——上游一个都没答上。
	// 它必须单独报：只有"应答数"的话，上游全挂时那个数照样涨，
	// 面板就会在最需要说"解析在失败"的时刻说"解析很健康"。
	DNSFailed int64 `json:"dnsFailed"`
	// DNSFailedAt 是最近一次解析失败的时刻（Unix 毫秒），0 表示还没发生过。
	// 有了它，界面上那句告警才可以说"现在还在失败"而不是"这辈子失败过"
	// ——只给累计数的话，一次抖动留下的告警会一直亮到重启。
	DNSFailedAt int64    `json:"dnsFailedAt"`
	StartedAt   int64    `json:"startedAt"`
	LastError   string   `json:"lastError"`
	Applied     []string `json:"applied"`
	// IPv6 是用户要不要 v6 假 IP（tun.ipv6）。
	IPv6 bool `json:"ipv6"`
	// V6Ready 是 v6 那一组命令是否真的全装上了。
	// 它和 IPv6 分开报，因为「没要」和「要了没成」是两回事：前者是配置，
	// 后者多半是内核没加载 ip6table_nat，只报一个 false 会把原因指错方向。
	// V6Ready 为 false 而 IPv6 为 true 时 AAAA 回 NODATA，应用退回 A 记录——
	// 这是能工作的降级，比发一个路由不到的假 v6 好。
	V6Ready bool `json:"v6Ready"`
	// TakeoverV4 / TakeoverV6 说清两族的默认路由到底有没有被接管。
	//
	// 这两个字段必须分开、且只反映「默认路由装上了没有」：
	// 「开了 strict_route」「开了而且装上了」「开了但 v6 装不上」
	// 是三种完全不同的状态，合成一个布尔值只会让人以为全局接管已经生效。
	// v6 为 true 而 v4 为 false 的组合是可能的（只有 v6 的网络）。
	TakeoverV4 bool `json:"takeoverV4"`
	TakeoverV6 bool `json:"takeoverV6"`
	// TakeoverFrom 说清上面两格的来源：kernel 是刚才真去读了路由表，
	// memory 是读不到（只能按本进程装过什么来说），not-running 是根本没在跑。
	// 这三档必须分得开：接管被 DHCP 抢回去的那一刻，"我们相信还在接管"
	// 与"内核说已经接管"是两句话，界面前者该显出来但不该冒充后者。
	TakeoverFrom string `json:"takeoverFrom"`
	// RouteFixes 是网络变化后重钉绕行路由的次数。
	// 它不为零说明「换网之后自己恢复了」——这正是用户看不出来、
	// 却最想知道的一件事。
	RouteFixes int64 `json:"routeFixes"`
	// LastRouteFix 是上一次重钉的时刻（Unix 毫秒），0 表示还没发生过。
	LastRouteFix int64 `json:"lastRouteFix"`
	// Privilege 说清「刚才那些 ip/iptables 是谁干的」：self 是本进程直接开，
	// helper 是提权命令代开。排障时这一眼就能区分权限问题的成因。
	Privilege string `json:"privilege"`
	// HelperCmd 是配置里的提权命令，出错时用户要能看见自己配的是什么。
	HelperCmd []string `json:"helperCmd,omitempty"`
	// KillArmed / KillV4 / KillV6 / KillReason 说清故障断网保护此刻到底在不在。
	// 四个都要：只报「用户开了」会让一次没装成功的保护看起来像保护到位了，
	// 而这道闸门失灵的后果是本机所有出站照旧裸奔，界面上一切正常。
	KillArmed bool `json:"killArmed"`
	KillV4    bool `json:"killV4"`
	KillV6    bool `json:"killV6"`
	// KillEnabled 是用户有没有开这道保护。它和 KillArmed 必须分开：
	// 「没开」是配置，「开了但没触发」是正常状态，「触发了没挂上」才是故障。
	KillEnabled bool `json:"killEnabled"`
	// KillReason 是「为什么没挂上 / 只挂上了一族」，挂全了为空。
	KillReason string `json:"killReason,omitempty"`
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
	// helperMismatchAt 是上一次「helper 因为协议版本对不上而拒收」的时刻（Unix 毫秒，0=没有）。
	// 记着它只为一件事：这种失败不会自己好，除非有人刷新那个文件或重启面板，
	// 所以在那之前每轮启用都再叫一次 root，只是把同一句拒绝多打几遍。
	// 用原子而不是 mu：登记它的地方有持锁的（Start 那一路），也有不持锁的
	// （监视器的重钉、断网保护的挂摘）——一份字段配两套锁纪律，迟早会写错一处。
	helperMismatchAt atomic.Int64
	applied          []Cmd
	plan             RoutePlan
	// v6Ready 记「v6 那一组命令全装上了」。DNS 只在它为真时才发假 v6 地址：
	// 发出去却路由不到，应用只会一路连到超时，而 NODATA 至少能退回 A 记录。
	v6Ready bool
	// v6RouteReady 记「v6 默认路由真的交给 tun 了」。
	// 它和 v6Ready 分开：v6Ready 说的是假 IP 与 DNS 劫持能不能用，
	// v6RouteReady 说的是 v6 全局流量有没有被接管。
	// 两者可以一个成一个不成（v6 网卡有地址但默认路由装不上），
	// 合成一个字段就只剩一个说不清的布尔值。
	v6RouteReady bool
	// 内核眼里的接管现状（带 2 秒缓存）。与上面两个「我们装没装上」的字段分开存：
	// 前者是事实，后者是意图，二者不一致的那一刻正是最需要界面说实话的时候。
	takeoverV4 bool
	takeoverV6 bool
	takeoverAt time.Time

	// watchCancel 是网络监视循环的取消函数；nil 表示没在监视。
	watchCancel context.CancelFunc
	// watchWG 等监视循环真正退出：拆除与重钉同时动路由会互相打架，
	// 所以拆之前要确认没有一轮重钉正在进行。
	watchWG sync.WaitGroup
	// netSeen 是上一轮看到的网络状态，去抖时用来判断「稳没稳」。
	netSeen routeState
	// netPinnedDNS 是上一次重钉时看到的系统解析器。
	// 拿它和当前比，是为了知道「DNS 是不是换人了」——
	// 系统解析器一换，通常意味着 DHCP 换了一整套配置。
	netPinnedDNS string
	// netDownDesc 是上一次「网络断了」那句话的内容。
	// 同一次中断里每 5 秒重打一遍，只会把日志里真出事的那几行埋掉；
	// 形态变了（v4 回来 v6 没回来、DNS 换人）才算新消息，值得再说一次。
	netDownDesc string

	routeFixes atomic.Int64
	// lastFixAt 是上一次重钉绕行路由的时刻（Unix 毫秒）。
	lastFixAt atomic.Int64

	// kill 是故障断网保护的实际落地状态（见 KillState）。
	// 界面上「用户要不要这道保护」来自配置，「它到底在不在」只能从这里来。
	kill KillState

	active      atomic.Int64
	dnsServed   atomic.Int64
	dnsFailed   atomic.Int64
	dnsFailedAt atomic.Int64
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
	// 监视器的起点就是「当前装的是哪一份」：
	// 第一轮探测拿它和现状比，差得多就说明网络真的动了。
	t.initNetWatch(plan)

	// 动 root 之前先问一句对面是谁：版本对不上是「此后再试多少次都一样」的失败，
	// 而这一问只要一次无特权的 fork（见 helper_probe.go 里那段故障记录）。
	if t.usesHelper() {
		if err := t.preflightHelper(ctx); err != nil {
			t.lastErr = err
			return err
		}
	}

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
	// 监视网络变化：换了网关之后绕行路由要重新钉，
	// 否则发往节点的包会一直送到那个已经不存在的出口。
	t.startNetWatchLocked()
	// 监视器第一轮最快也要 5 秒之后；用户启用之后第一件事就是看那两格，
	// 所以这里立刻问一次内核，别让面板在最该准的这一刻退回去猜。
	t.publishTakeoverLocked(ctx)
	if t.conf.DNSHijackEnabled() {
		t.flushResolverCache(ctx)
	}
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
		t.applyV6Route(ctx, plan)
		return dev, up, nil
	}

	reply, fd, err := t.helper.Run(ctx, HelperRequest{V: helperProtoVersion, Action: ActionUp, Plan: plan})
	if err != nil {
		// 版本对不上要单独说：它是「此后再试多少次都一样」的那种失败，
		// 而界面上拿到的原文只有两个版本号。
		if advice := t.noteHelperMismatch(err.Error()); advice != "" {
			return nil, nil, fmt.Errorf("经 tun.helper 开网卡失败: %v。%s", err, advice)
		}
		return nil, nil, fmt.Errorf("经 tun.helper 开网卡失败: %w", err)
	}
	t.clearHelperMismatch()
	if !reply.V6OK && plan.Gateway6 == "" {
		// helper 只报「成没成」，不解释为什么。这一句是给面板日志的：
		// 否则用户只看到 v6 没启用，不知道是因为这台机器根本没有 v6 出口。
		logx.Warnf("TUN: 本机没有 v6 默认路由，v6 假 IP 不发（AAAA 回 NODATA，应用退回 A 记录）")
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
	t.setV6RouteReady(reply.V6RouteOK)
	logx.Infof("TUN: 网卡 %s 由 tun.helper 创建，fd 已交给本进程（uid=%d）", reply.Device, t.uid)
	return dev, applied, nil
}

// releaseSystem 拆掉 plan 在系统里留下的配置。设备 fd 由调用方负责关。
func (t *TUN) releaseSystem(ctx context.Context, plan RoutePlan) error {
	if !t.usesHelper() {
		_, down, err := plan.Plan()
		if err == nil {
			// v6 接管那一组要一起撤：它装了 v6 默认路由与 v6 绕行路由，
			// 留着的话下次启动的绕行路由会指向可能已经失效的网关。
			if _, v6down, verr := plan.PlanV6Route(); verr == nil {
				down = append(v6down, down...)
			}
			if _, v6down, verr := plan.PlanV6(); verr == nil {
				down = append(v6down, down...)
			}
		}
		if err != nil {
			return err
		}
		var errs []error
		for _, c := range down {
			out, err := t.runner.Run(ctx, c)
			// 判据与 helper 那一路同一份（tolerates）：以前这里只看"有没有报错"，
			// 于是网卡先消失时那三条必然的 Cannot find device 被当成拆除失败，
			// 面板显示"TUN 已停止但撤销出错"，而实际上系统里干干净净。
			if err != nil && !tolerates(c, out) {
				errs = append(errs, fmt.Errorf("%s: %w", c.Desc, err))
			}
		}
		return errors.Join(errs...)
	}
	// 拆除这一路**永远不跳过**，哪怕已知版本对不上：跳过不会让失败变小，只会让它改名——
	// 网卡、路由与劫持规则就留在机器上了，而那正是「面板显示已停、整机 DNS 挂死」的形态。
	// 这里能做的只有把该动哪一边说清楚。
	reply, _, err := t.helper.Run(ctx, HelperRequest{V: helperProtoVersion, Action: ActionDown, Plan: plan})
	if err != nil {
		if advice := t.noteHelperMismatch(err.Error()); advice != "" {
			return fmt.Errorf("%w。%s（拆除这一步不能跳：跳了那些东西就留在机器上）", err, advice)
		}
		return err
	}
	if !reply.OK {
		if reply.Err == "" {
			return errors.New("helper 拆 TUN 时报告失败")
		}
		return errors.New(reply.Err)
	}
	t.clearHelperMismatch()
	return nil
}

// flushResolverCache 清掉系统解析器里的缓存。
//
// 为什么两头都要刷：装好劫持之后，缓存里可能还压着几十秒前问到的**真 IP**，
// 那些地址不进 tun，全局模式下的去向下落就少了一截；而拆掉劫持之后，
// 缓存里压着的却是**假 IP**——它们指向一块已经不存在的网卡，
// 症状是「代理关了，浏览器反而几分钟上不了网」，且只有这一个解释。
// 失败只记 Debug：resolvectl 不在（非 systemd 解析器）时这一步本来就没有意义。
func (t *TUN) flushResolverCache(ctx context.Context) {
	out, err := t.runner.Run(ctx, Cmd{Bin: "resolvectl", Args: []string{"flush-caches"}, Desc: "清系统解析器缓存", Optional: true})
	if err != nil && !tolerates(Cmd{Optional: true}, out) {
		logx.Debugf("TUN: 刷系统解析器缓存失败（不影响接管本身）: %v", err)
	}
}

// helperMismatchSilence 是「已知两边版本对不上」这句话的保质期。
// 之所以要有保质期而不是永久拉黑：修法就是把那一侧换成同一个构建，
// 而刷新文件这件事不需要本进程配合——下一次调用自然会成功，
// 成功的那一刻缓存就被清掉（见 clearHelperMismatch）。
const helperMismatchSilence = 60 * time.Second

// errHelperMismatchSkip 标出「这一趟压根没发出去，因为已知会被拒」。
// 调用方靠它把日志降到 Debug：监视器每 5 秒一轮，
// 每轮一条 WARN 会把日志刷满，把真正有用的那几行埋掉。
var errHelperMismatchSkip = errors.New("已知 helper 的协议版本与本程序对不上")

// noteHelperMismatch 认一次 helper 失败是不是协议版本对不上；是的话记一笔，
// 并把「该动哪一边」这句话回给调用方拼进错误里（不是版本问题就返回空串）。
func (t *TUN) noteHelperMismatch(errText string) string {
	mine, theirs, ok := helperVersionRejection(errText)
	if !ok {
		return ""
	}
	t.helperMismatchAt.Store(time.Now().UnixMilli())
	// 路径取自 conf.Helper 而不是 helper.Argv：要告诉用户「动哪个文件」，
	// 而那个文件由配置决定；客户端结构体是可以在测试里整个换掉的。
	return helperMismatchAdvice(mine, theirs, t.conf.Helper)
}

// clearHelperMismatch 一次成功的 helper 往返就是「两边其实是同一个协议」的实测证据，
// 缓存必须当场作废：文件被刷新的那一刻起，跳过理由就不存在了。
func (t *TUN) clearHelperMismatch() { t.helperMismatchAt.Store(0) }

// helperMismatchKnown 报告现在再叫 helper 是否注定还是那句拒绝。
func (t *TUN) helperMismatchKnown() bool {
	ms := t.helperMismatchAt.Load()
	return ms != 0 && time.Since(time.UnixMilli(ms)) < helperMismatchSilence
}

// cleanupStale 清历史残留。配了 helper 就必须让它去跑 iptables——
// 在本进程跑只会在普通用户下全军覆没，而「残留没清」正是整机 DNS 挂掉那个坑。
func (t *TUN) cleanupStale(ctx context.Context) []string {
	if !t.usesHelper() {
		done := CleanupStale(ctx, t.runner, t.uid, t.conf.Device, t.conf.Address)
		// 残链同样要清：那条链拦的是本机所有出站，而挂上它的那个进程可能根本没走到摘的那步。
		return append(done, CleanupKill(ctx, t.runner)...)
	}
	if t.helperMismatchKnown() {
		// 已知对面会因为版本拒收：这一趟注定白跑，而且它留下的日志与「第一次失败」
		// 长得一模一样，看日志的人分不清是在重试还是在恶化。
		logx.Debugf("TUN: 跳过经 helper 清残留（已知协议版本对不上，刷新二进制或重启面板之前不会再变）")
		return nil
	}
	reply, _, err := t.helper.Run(ctx, CleanupRequest(t.uid, t.conf.Device, t.conf.Address))
	if err != nil {
		// 清残留失败不阻断启用：下面的 up 本身是可重入的。
		if advice := t.noteHelperMismatch(err.Error()); advice != "" {
			logx.Warnf("TUN: 经 helper 清残留失败，继续尝试启用: %v。%s", err, advice)
		} else {
			logx.Warnf("TUN: 经 helper 清残留失败，继续尝试启用: %v", err)
		}
		return nil
	}
	t.clearHelperMismatch()
	return reply.Removed
}

// Stop 关栈、拆路由、销网卡。可重复调用。
func (t *TUN) Stop(ctx context.Context) error {
	// 先停监视并等它真正退出，再拆：监视循环可能正在重钉路由，
	// 拆与钉同时动路由会互相打架（拆完又被钉回来，界面显示已停而路由还在）。
	// 这一步不能持有 t.mu：监视循环正等着这把锁。
	t.mu.Lock()
	t.stopNetWatchLocked()
	t.mu.Unlock()
	t.watchWG.Wait()

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
	// 网卡的 fd 归协议栈所有：上面那句 stack.Close() 销毁链路时已经调过一次 Close()
	// 了（非 persistent 的 tun 就是在那一刻消失的，挂在它上面的路由被内核一并收走）。
	// 这里这一次是兜底——比如栈没建起来那条路径——fdDevice.Close() 里有 once，
	// 重复调用不会再关一遍同一个描述符。
	if t.dev != nil {
		t.dev.Close()
		t.dev = nil
	}
	// 出站保护必须先摘，而且要在自己的时间预算里摘：那条链拦的是本机所有出站，
	// TUN 拆干净了却把 DROP 留在机器上，用户看到的症状是「关了代理反而上不了网」。
	if t.kill.Armed {
		kctx, kcancel := context.WithTimeout(context.Background(), disarmTimeout)
		defer kcancel()
		if err := t.disarm(kctx); err != nil {
			errs = append(errs, fmt.Errorf("摘除出站保护失败（本机出站可能仍被限制）: %w", err))
		} else {
			t.kill = KillState{}
		}
	}
	// 按 best-effort 跑一遍 Down 列表。点名网卡的那几条容忍"设备已经没了"
	// （见 tolerateGone）：网卡先消失的话内核已经把路由收走了，那条命令要的效果已经达成；
	// 而 iptables 那些不会随网卡消失的规则，这里删不掉就是真残留，必须报错。
	if t.plan.Device != "" {
		if err := t.releaseSystem(ctx, t.plan); err != nil {
			errs = append(errs, err)
		}
		t.applied = nil
		t.plan = RoutePlan{}
	}
	// 劫持规则已经拆了，缓存里那些假 IP 现在只会把人送进一块不存在的网卡。
	t.flushResolverCache(ctx)
	return errors.Join(errs...)
}

// Status 返回当前状态快照。
func (t *TUN) Status() Status {
	t.mu.Lock()
	defer t.mu.Unlock()

	// 接管那两格读的是监视器贴出来的内核读数；读不到或过期了就走记忆那一档。
	// 这里一次进程都不 fork：面板每 1–2 秒问一次，而路由表每 5 秒已经被读过一次。
	takeoverV4, takeoverV6, takeoverFrom := t.takeoverReading()

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
		DNSFailed:   t.dnsFailed.Load(),
		DNSFailedAt: t.dnsFailedAt.Load(),
		Privilege:   "self",
		HelperCmd:   t.helper.Argv,
		// 接管以内核为准：装上的那一刻之后路由随时可能被别人改回去，
		// 而"我们装过"不是"现在还在"。读不到内核时退回进程记忆并如实标注来源。
		TakeoverV4:   takeoverV4,
		TakeoverV6:   takeoverV6,
		TakeoverFrom: takeoverFrom,
		RouteFixes:   t.routeFixes.Load(),
		LastRouteFix: t.lastFixAt.Load(),
		// 直接读 t.kill：这里已经持有 mu，而 Kill() 也要拿它（Go 的 Mutex 不可重入）。
		KillArmed:   t.kill.Armed,
		KillV4:      t.kill.V4,
		KillV6:      t.kill.V6,
		KillEnabled: t.conf.KillSwitch,
		KillReason:  t.kill.Reason,
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
	if !plan.v6FakeIPUsable() {
		// 没有 v6 出口就不发假 v6：应用拿到一个拨不通的地址，比拿不到地址更糟。
		logx.Warnf("TUN: 本机没有 v6 出口（没有 v6 默认路由），v6 假 IP 不发——AAAA 回 NODATA，应用退回 A 记录")
		return false
	}
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

// applyV6Route 单独应用 v6 全局接管那一组命令，成败用返回值表达。
//
// 失败只降级 v6 接管，不掀 v4：v4 的默认路由已经装好了，v6 装不上时
// 整机照样能用 v4 出网，只是 v6 流量绕过 tun 而已。
// 撤干净是必须的：留半套绕行路由比完全没装更糟——
// 下次启动时它们会指向可能已经失效的网关，表现为「节点时好时坏」。
//
// 状态由本函数自己写：返回值与状态分成两处写，就迟早会出现
// 「返回成功但状态是 false」这种自相矛盾。
func (t *TUN) applyV6Route(ctx context.Context, plan RoutePlan) bool {
	up, down, err := plan.PlanV6Route()
	if err != nil {
		logx.Warnf("TUN: IPv6 接管这一组配置有问题，v6 默认路由不交给 tun（v6 流量走系统默认出口）: %v", err)
		t.setV6RouteReady(false)
		return false
	}
	if len(up) == 0 {
		if plan.StrictRoute && plan.Address6 != "" {
			logx.Infof("TUN: 没有可用的 IPv6 网关或网卡，v6 默认路由不交给 tun（v6 流量走系统默认出口）")
		}
		t.setV6RouteReady(false)
		return false
	}
	if err := Apply(ctx, t.runner, up); err != nil {
		logx.Warnf("TUN: IPv6 全局接管未生效，已撤回这一组（v6 流量走系统默认出口）: %v", err)
		if derr := Apply(ctx, t.runner, down); derr != nil {
			logx.Warnf("TUN: 撤回 IPv6 接管配置时也没干净: %v", derr)
		}
		t.setV6RouteReady(false)
		return false
	}
	logx.Infof("TUN: IPv6 默认路由已交给 %s，v6 全局流量进入隧道", plan.Device)
	t.setV6RouteReady(true)
	return true
}

// setV6RouteReady 记录 v6 默认路由是否真的接管了。
// Start 已经持有 t.mu，这里不再加锁。
func (t *TUN) setV6RouteReady(ok bool) {
	t.v6RouteReady = ok
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
		dr, ok := ParseDefaultRouteExcept(out, plan.Device)
		if ok && dr.Gateway != "" {
			plan.Gateway, plan.Interface = dr.Gateway, dr.Iface
		} else {
			// 没有 v4 默认路由（或它没有网关）：这一族不接管。
			// 只有 v6 的网络照样要能用 v6 接管，所以这里不是致命错误。
			logx.Infof("TUN: 本机没有可用的 IPv4 默认路由，IPv4 全局接管不成，v4 流量走系统默认出口")
		}
		// v6 那一族单独探测。没有 v6 默认路由是常态（很多网络只有 v4），
		// 所以查不到不算失败——只是 v6 接管不成，界面会如实说没接管。
		out6, err6 := t.runner.Run(ctx, Cmd{Bin: "ip", Args: []string{"-6", "-o", "route", "show", "default"}, Desc: "查 IPv6 默认路由"})
		if err6 != nil {
			logx.Debugf("TUN: 查不到 IPv6 默认路由（%v），IPv6 全局接管不成，v6 流量走系统默认出口", err6)
		} else if dr6, ok6 := ParseDefaultRouteExcept(out6, plan.Device); ok6 {
			if dr6.Gateway != "" {
				plan.Gateway6, plan.Interface6 = dr6.Gateway, dr6.Iface
			} else {
				logx.Warnf("TUN: IPv6 默认路由没有网关（dev %s），不做 v6 全局接管：钉不回绕行路由，装了默认路由我们的出站会被自己抓回去", dr6.Iface)
			}
		} else {
			logx.Infof("TUN: 本机没有 IPv6 默认路由，IPv6 全局接管不成，v6 流量走系统默认出口")
		}
		// 两族都没有可用的网关：无处可去，strict_route 装不了。
		if plan.Gateway == "" && plan.Gateway6 == "" {
			return plan, errors.New("tun: 没有可用的默认路由网关，strict_route 会把默认路由指向一个不存在的出口")
		}
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
		n, bad, err := serveDNSOverTCP(c, t.dns.Reply, dnsTCPIdle)
		t.dnsServed.Add(int64(n))
		t.countDNSFailures(bad)
		if err != nil {
			logx.Debugf("tun dns(tcp) %s 处理中断（已应答 %d 条，其中失败 %d 条）: %v", src, n, bad, err)
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
		rep, err := t.dns.Reply(ctx, query)
		cancel()
		if err != nil {
			logx.Warnf("tun dns %s 应答失败: %v", src, err)
			return
		}
		// 分开计是这一轮补上的：SERVFAIL 也"应答过"，但把上游全挂时的一百次失败
		// 报成「已应答 DNS 一百次」说的是反话——这个数字的用途就是证明劫持在工作。
		if rep.ServFail {
			t.countDNSFailures(1)
		} else {
			t.dnsServed.Add(1)
		}
		if _, err := c.Write(rep.Packet); err != nil {
			logx.Debugf("tun dns 写回失败: %v", err)
			return
		}
	}
}

// countDNSFailures 记几笔「上游没答上」：累计数与最近时刻一起写。
//
// 两个都要，因为它们回答的是两个问题：告警那句要的是"现在还在失败吗"，
// 统计那一栏要的是"这一共失败过多少次"。只给累计数的话，
// 一次网络抖动留下的告警会一直亮到重启——那种告警教给用户的不是排查，是忽略它。
func (t *TUN) countDNSFailures(n int) {
	if n <= 0 {
		return
	}
	t.dnsFailed.Add(int64(n))
	t.dnsFailedAt.Store(time.Now().UnixMilli())
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
		// 与 relayTCP 同一句话的理由：拨不通要在流量页留一行。
		// UDP 这一侧尤其需要，因为它连个错误都传不回应用（丢包是唯一能表达的）——
		// 界面上不出现，用户手上就什么都没有：QUIC 站点打不开，而连接表一片干净。
		t.reg.Refuse("tun", src, dialTarget, res, err.Error())
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
