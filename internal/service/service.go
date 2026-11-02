// Package service 把代理的装配与启停收敛成一个可重复调用的容器。
//
// CLI 与 GUI 共用同一份逻辑：main.go 的 run() 与 GUI 托盘面板都只调用
// Start/Stop/Reload/Snapshot，不再各自复制一遍 resolver/规则/出站的搭建流程。
package service

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/dnsx"
	"wps_app/internal/inbound"
	"wps_app/internal/logx"
	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
	"wps_app/internal/rules"
	"wps_app/internal/rulesub"
	"wps_app/internal/tunx"
)

// dialTimeout 与 main.go 保持一致：所有出站拨号的默认超时。
const dialTimeout = 15 * time.Second

// handshakeTimeout 是与服务端握手（hysteria2 的 QUIC、trojan 的 TLS）的超时。
const handshakeTimeout = 10 * time.Second

// Service 持有代理的全部运行时状态。所有方法并发安全，
// GUI 可以从任意 goroutine 调用 Start/Stop/Reload。
type Service struct {
	// opMu 串行化「启停」这类长操作：同一时刻只允许一次装配或拆除在跑。
	// 它与 mu 的分工是刻意的——opMu 保证流程不互相穿插，
	// mu 只保护状态字段，且每段临界区都必须短到能立刻返回。
	//
	// 以前 Prepare/Start 抱着 mu 做 DNS 解析、编译整套规则、建网卡、
	// 执行 ip/iptables 与最长 35 秒的实例接管轮询，面板每次状态轮询
	// 都排在锁后面，于是「启动中」表现为整个界面假死，连「停止」都点不动。
	opMu sync.Mutex

	// cfgMu 串行化「读配置—改—写回」这条龙。
	// mutate 全程不碰 mu：两个并发的界面操作会各自读到同一份基线、
	// 各自 Save，后写的把前一个的改动连同 .bak 一起抹掉。
	cfgMu sync.Mutex

	// killMu 串行化故障断网保护的挂与摘。
	// 一轮故障里每一次拨号失败都会想挂一次（成因见 roundCooldown），而每次挂载
	// 都要付一趟 helper 往返；挂到一半被另一次挂载插进来，留下的就是半条链。
	killMu sync.Mutex
	// killOp 是故障断网保护的执行面。生产时它就是那块 TUN；测试里换成记账的假人：
	// 服务层要验的是「什么时候该动闸门」，而 iptables 该长成什么样在 tunx 那层已经测过了。
	// 与 s.tun 同生同灭（见 tun.go 的三处赋值），不留两份真相。
	killOp killSwitch
	// killAllowKey 是上一次真正挂上去的那份白名单。只在 killMu 下读写。
	// 留着它是为了「名单变了才重挂」：白名单没变时重挂只是闪断一次放行，
	// 而名单变了（多半是某个节点的域名终于解析出来了）就必须重挂——
	// 否则那个节点会一直被自己的保护拦在外面，恢复无路。
	killAllowKey string

	// diskMu 只保护下面这三个磁盘配置缓存字段，与 mu 无关：
	// Snapshot/Mode/TUNStatus 是面板每秒轮询的热点，它们读文件时不能占着 mu。
	diskMu      sync.Mutex
	diskCfg     *config.Config
	diskCfgMod  time.Time
	diskCfgSize int64

	mu sync.Mutex

	cfgPath string
	cfg     *config.Config
	rt      *router.Router
	// proxy 留住当前出站句柄。路由器只暴露 Dialer 接口，没有连接态查询，
	// 而 GUI 需要区分「代理在跑」与「到服务端的隧道真的建起来了」——前者只说明
	// 入站在监听，后者才说明能出海。
	//
	// 类型是 outbound.Conn 而不是具体的 *Hysteria：协议由配置里的 type 决定，
	// 服务层不该知道自己的出站跑的是 hysteria2 还是 trojan。
	proxy   outbound.Conn
	resolve *dnsx.Resolver
	geoRef  *rules.GeoRef
	// geoOK 记录 GeoIP mmdb 是否真的打开了。GeoRef 本身在 mmdb 缺失时也会被创建
	// （规则里的 GEOIP 条目只是被跳过），因此可用性要单独跟踪，不能靠反查某个 IP 推断。
	geoOK bool
	reg   *metrics.Registry

	listeners []net.Listener
	inbounds  []InboundStatus
	// tun 为 nil 表示这次装配里 TUN 没启用（或启用失败）。
	// 它是可选入站：起不来不该拖累 SOCKS5/HTTP 已经跑好的转发。
	tun *tunx.TUN

	// rulesubCancel 停掉规则集订阅的后台循环。nil 表示没起过。
	// 用 cancel 而不是等一个 WaitGroup：拉取可能正卡在一个两分钟超时的 HTTP 上，
	// 而停服务必须立刻返回。
	rulesubCancel context.CancelFunc
	// providers 是正在跑的那个订阅更新器，面板拿它读"每条订阅现在好不好"。
	// nil = 没在跑（没启动，或配置里一条可用订阅都没有）。
	providers *rulesub.Updater
	// providerErrs 是启动时被拒的订阅条目（重名、缓存路径撞车…）。
	// 只记不拦：一条配错的订阅不该让其余几条一起消失，更不该拖垮整个启动。
	providerErrs []string
	// 规则文件热重载：监视器状态 + 它的退出句柄（见 ruleswatch.go）。
	rwatch           rulesWatch
	rulesWatchCancel context.CancelFunc

	running   bool
	startedAt time.Time
	lastErr   error
	// lock 是「同一份配置只跑一个实例」的守卫，Start 拿、Stop 放。
	lock *instanceLock
	// modeOverride 非空时压过配置里的 mode，且只在本次运行有效（-mode 用）。
	modeOverride config.Mode
	// failoverOverride 非空时压过配置里的 active，同样只在本次运行有效。
	// 见 internal/service/failover.go：故障切换不该把一次应急决定写进用户的配置文件。
	failoverOverride string
	// faults 记录每个节点近期的「节点级」拨号失败，是 failoverOverride 的唯一依据。
	// 只在 mu 下访问；停止服务时清空。
	faults map[string]*nodeFault
	// switchedAt 是上一次自动切节点的时间，用于迟滞：
	// 每次切换都会掐掉旧隧道上正在传的连接，绝不能来回切。
	switchedAt time.Time
	// switchReason 是切换当时就定稿的理由，写在 commitFailover 里。
	//
	// 不能等出快照时再数：失败流水只留 faultWindow（2 分钟），而界面读数的
	// 典型时刻是切换之后好几分钟——那时窗口早滑过去了，再数必然是
	// 「0 次节点级失败（涉及 0 个不同目标）」。这句话是界面上唯一能回答
	// 「它为什么自己动了」的东西，填个 0 等于没答。
	switchReason string
	// cooling 里的节点在到期前不会被自动切上去（含刚被放弃的那一个）。
	cooling map[string]time.Time
	// failoverBusy 是「这一轮自动切换正在跑」的标记，理由见 tryFailover 头上的单飞说明。
	failoverBusy bool
	// failoverRoundAt 是上一轮自动切换开始的时间，用来做轮次冷却：
	// 见 roundCooldown。只记开始时间，不记结束时间——一轮里耗掉的那 8s×候选数
	// 本身就是代价，再等它结束才起算等于给坏节点多几秒钟。
	failoverRoundAt time.Time
	// probeCandidate 是选替代品时做一次试拨的方式，默认 probeOutbound。
	// 测试里换成不打网络的实现：真实握手要靠节点地址背后真有个服务端，
	// 而单元测试的 127.0.0.1:4434 后面什么都没有。
	probeCandidate func(outbound.Dialer) error
	// handshakeTO 是与服务端握手的超时，0 表示用上面的默认值。
	//
	// 放在实例上而不是让测试去动全局常量：唯一那条"让真实流量去撞一个死端点"的用例，
	// 按 10s 一轮要跑满十五秒；慢到没人愿意跑的用例等于没有用例，
	// 而它恰好是「观察者真的接在真实链路上」这件事的唯一证据。
	handshakeTO time.Duration
	// split 是本次装配出来的网卡分流。它在本次运行里始终是同一个实例：
	// 出站集体持有它，闸门与两张卡都在它内部，换卡只改内容不换指针。
	// nil 只出现在还没装配（没跑）的时候。
	split *outbound.Split
	// ifaceSplit 记着「这台机器上两张无线各叫什么」，即使探测不到两张也要留着理由，
	// 面板得能说清「开关是开的，但没生效，因为只有一张无线」。
	ifaceSplit IfaceSplitStatus
	// splitBind 记着上一次落地时**两侧各自**有没有走特权通道。它在幂等比较里：
	// 少了它，"helper 中途才出现"这一转会因为两张卡名字没变而被早退吞掉，
	// 于是界面说走了通道、实际还在自己绑（也就是还在被静默丢包）。
	splitBind [2]bool
	// ifaceSeen 是监视循环上一轮看到的解析结果，用来判断网卡的变化是否已经落定。
	ifaceSeen splitPick
	// dialHelper 是常驻提权 helper（造钉住网卡的 socket）；面板退出时要把它收掉。
	dialHelper *tunx.PersistentHelper
	// egressVerdict 记着每个「网卡|拨号目标」组合探出来的结论（空串=发得出包，
	// 非空=降级理由）。同一个组合只探一次：判成降级会重建隧道，而 commitProxy 在
	// strict_route 下会回头再走一遍装配，装配又探一次、又判降级——那是个循环。
	// 想重新探：拨一次开关或改一次点名（见 clearEgressVerdict）。
	egressVerdict map[string]egressVerdict
	// ifaceCards 是最近一次探测到的全部无线卡，供界面的下拉列可选项。
	ifaceCards []IfaceCardView
	// ifaceWatchCancel 停掉网卡监视循环。见 ifacewatch.go。
	ifaceWatchCancel context.CancelFunc
}

// InboundStatus 描述一条入站监听的当前状态，供 GUI 展示。
type InboundStatus struct {
	Type   string `json:"type"`
	Listen string `json:"listen"`
	Addr   string `json:"addr"`
	Auth   bool   `json:"auth"`
	// Active 表示这条入站当前是否真的在监听（停止后为 false）。
	Active bool `json:"active"`
}

// Snapshot 是服务状态的只读投影，字段全为普通值，便于经 Wails 送到前端。
type Snapshot struct {
	Running    bool            `json:"running"`
	StartedAt  int64           `json:"startedAt"` // Unix 毫秒，未运行时为 0
	UptimeMS   int64           `json:"uptimeMs"`
	Server     string          `json:"server"`
	ConfigPath string          `json:"configPath"`
	Inbounds   []InboundStatus `json:"inbounds"`

	// Mode 是当前分流模式：rule / global / direct。
	Mode string `json:"mode"`
	// Profiles 是全部代理服务，ActiveProfile 是其中生效的那个名字。
	Profiles []ProfileView `json:"profiles"`
	// ActiveProfile 是当前选中的节点名。
	ActiveProfile string `json:"activeProfile"`
	// AutoSwitched 为真表示当前生效的节点是故障自动切换选出来的，
	// 并不等于配置文件里写的那个。界面上必须区分这两件事。
	AutoSwitched bool `json:"autoSwitched"`
	// AutoSwitchedAt 是上一次自动切换发生的时刻（Unix 毫秒），0 = 本次运行没切过。
	// 光有「切了」这一个布尔值不够：用户要判断的是"刚才那下是不是它干的"，
	// 而那需要一个时间戳去和现象对齐。
	AutoSwitchedAt int64 `json:"autoSwitchedAt"`
	// SwitchReason 是给人看的自动切换理由，未自动切换时为空。
	SwitchReason string `json:"switchReason,omitempty"`
	// TUN 是 TUN 入站的完整状态；未启用时 Enabled/Running 都是 false。
	TUN tunx.Status `json:"tun"`
	// IfaceSplit 是「按网卡分流」的状态，见 IfaceSplitStatus。
	IfaceSplit IfaceSplitStatus `json:"ifaceSplit"`

	GeoIPPath   string `json:"geoipPath"`
	GeoIPOK     bool   `json:"geoipOk"`
	RulesFile   string `json:"rulesFile"`
	DomainRules int    `json:"domainRules"`
	IPRules     int    `json:"ipRules"`
	// BlockedRules 是配置 block: 段装进去的拦截条数。
	BlockedRules int      `json:"blockedRules"`
	FinalPolicy  string   `json:"finalPolicy"`
	RulesSkipped []string `json:"rulesSkipped"`

	AuthSet     bool   `json:"authSet"`
	SNI         string `json:"sni"`
	BandwidthUp string `json:"bandwidthUp"`
	BandwidthDn string `json:"bandwidthDown"`
	Congestion  string `json:"congestion"`

	// Connected 反映最近一次到服务端的握手是否成功（QUIC 连接或 TLS 会话）。
	Connected bool `json:"connected"`
	// ProxyType 是当前出站的协议名。地址只有一个来源：Server（两者曾重复投影）。
	ProxyType string `json:"proxyType"`
	// ProxyStatus 是出站给出的一句话摘要（已解析地址、SNI、隧道是否已建）。
	ProxyStatus string `json:"proxyStatus"`

	LastError string `json:"lastError"`
}

// New 创建服务。reg 为 nil 时自动建一个只做累计、不保留历史的注册表；
// GUI 传入带历史与速率序列的注册表以便绘图。
func New(cfgPath string, reg *metrics.Registry) *Service {
	if reg == nil {
		reg = metrics.NewRegistry(0, 0)
	}
	return &Service{cfgPath: cfgPath, reg: reg, handshakeTO: handshakeTimeout}
}

// Metrics 返回连接注册表，供 GUI 直接读取流量统计。
func (s *Service) Metrics() *metrics.Registry { return s.reg }

// ConfigPath 返回配置文件路径。
func (s *Service) ConfigPath() string { return s.cfgPath }

// Router 返回当前路由器；未装配时为 nil。
func (s *Service) Router() *router.Router {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rt
}

// Prepare 装配配置、解析器、规则与出站，但不监听任何端口。
// -check 自检与 Start 共用它；重复调用是幂等的。
func (s *Service) Prepare() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.prepare()
}

// prepare 先在锁外把所有会阻塞的活干完——读配置、打开 mmdb、编译整套规则、
// 解析节点域名（最长 5s + 5s 系统解析回退）——最后只用一段极短的临界区
// 把结果发布出去。调用方必须持有 opMu。
//
// 这些阻塞调用以前全都发生在 s.mu 里面，于是面板的每一次状态轮询、
// 每一个「停止」请求都得排在 DNS 解析后面排队。
func (s *Service) prepare() error {
	s.mu.Lock()
	ready := s.rt != nil
	s.mu.Unlock()
	if ready {
		return nil
	}

	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		return err
	}
	logx.SetLevel(logx.ParseLevel(cfg.Log.Level))

	resolver, err := dnsx.New(cfg.DNS.Servers, cfg.DNS.Timeout.Duration, cfg.DNS.Cache.Duration)
	if err != nil {
		return err
	}

	geo, err := rules.OpenGeoIP(cfg.GeoIP.Path)
	if err != nil {
		// mmdb 缺失不该阻断启动：规则集中的 GEOIP 会被跳过，但域名/IP-CIDR 仍可用。
		logx.Warnf("GeoIP 不可用，GEOIP 规则将无法使用: %v", err)
	}
	geoRef := rules.NewGeoRef(geo)

	// 规则集的缓存缺失时先补一次，**在 rules.Load 之前**。
	//
	// 顺序不能反：用户完全可能把规则全部放进订阅里（本地只留 FINAL）。
	// 缓存还没到就 Load，主规则集里的 #include 全被跳过，引擎会以
	// 「no usable rules found」直接拒绝启动——于是一次远端拉取失败
	// 变成了「代理彻底起不来」。补齐之后再 Load，两种情形都成立。
	//
	// 拉不到就往下走：本地那份规则仍然能用，让服务因为一条订阅起不来不划算。
	prefetchProviders(cfg, geoRef, ruleResolverFor(cfg, resolver))

	// 规则判定用的解析入口与「拨节点前解析节点地址」用的入口刻意不是同一个：
	// 后者必须走直连（隧道那时还不存在），前者可以选从节点的视角问上游。
	// 见 tunnelResolver 的说明。
	ruleResolver := ruleResolverFor(cfg, resolver)
	engine, err := rules.Load(cfg.RulesFile, geoRef, ruleResolver)
	if err != nil {
		geoRef.Swap(nil)
		return err
	}
	engine.SetBlocklist(cfg.Block.Domains)
	dom, ip := engine.Stats()
	// 拦截条数一起报：这一行是 headless 用户唯一的入口，而「名单写了但没装上」
	// 正是这里最需要一眼看出的事。0 也照样报——「什么都没拦」和「没装名单」是两回事。
	// 取的是引擎里那份（不是 cfg.Block.Domains）：装没装上看它才算数。
	logx.Infof("规则已加载: %s（域名 %d 条，IP %d 条，拦截 %d 条，FINAL=%s）",
		cfg.RulesFile, dom, ip, len(engine.BlockDomains()), engine.Final())
	for _, sk := range engine.Skipped() {
		logx.Warnf("可选规则文件不存在，已跳过: %s（运行 scripts/fetch-assets.sh --seed 可拉取）", sk)
	}

	s.mu.Lock()
	stagedActive := s.failoverOverride
	s.mu.Unlock()
	srv, activeName := activeServerFor(cfg, stagedActive)
	if stagedActive != "" && activeName == stagedActive {
		logx.Infof("本次运行仍使用自动切换后的节点 %s（不写回配置文件）", activeName)
	}
	// 网卡分流必须在出站装配之前定下来：直连与代理要拿到同一个 Split，
	// 而 hysteria2 在构造时就可能已经把 QUIC 那条 socket 建出来了——
	// 那条 socket 一旦建成就钉死在卡上，两张卡必须先进去。
	splitPlan := planForConfig(cfg.IfaceSplit)
	// 钉上这张卡却发不出包，装配一次就要验一次：Start 这条路和运行期的 applyPlan
	// 必须共用同一判据（启动不走 applyPlan，见 logSplitPlan 那段），而且**两侧各问一次**
	// （settleEgress 里那层只有一处问句）。有提权 helper 就不必退——把 socket 交给
	// helper 造，拓扑照用户点名的两张卡走；没有 helper 才退回系统默认路由，
	// 因为留着那条"已生效"的记录会让那一侧全部连接一起超时。
	splitPlan, bindDirect, bindProxy, bindNotes := s.settleEgress(splitPlan, srv.Addr, cfg)
	for _, why := range bindNotes {
		logx.Infof("网卡分流：%s", why)
	}
	if splitPlan.note != "" {
		logx.Warnf("网卡分流未生效：%s", splitPlan.note)
	}
	split := outbound.NewSplit(splitPlan.pick.direct, splitPlan.pick.proxy)
	split.SetBindSocket(s.bindChannelWith(cfg))
	split.SetBindNeeded(bindDirect, bindProxy)
	proxy, err := outbound.New(srv, s.handshakeTO, resolver, fakeRange(cfg), split)
	if err != nil {
		geoRef.Swap(nil)
		return err
	}
	rt := router.New(engine, outbound.NewSet(
		// 直连也交给同一个解析器，判定与拨号才看的是同一批地址（见 WithResolver）。
		outbound.NewDirect(dialTimeout, inboundAddrs(cfg)...).WithResolver(resolver).WithSplit(split),
		proxy).
		// 节点名跟着出站一起装配：连接表与「各节点用量」要能说出这批字节走了谁。
		WithNode(activeName).
		// 规则里的 node= 靠这只工厂兑现。传的是方法值，所以它读的是**当时**的配置：
		// 改过节点之后再来一条连接，拿到的就是新参数（缓存由 mutate 整张丢掉）。
		WithNodeFactory(s.nodeDialer), dialTimeout)
	// 把隧道交给解析器：规则判定那次「从节点的视角问上游」走的就是这条。
	// 绑定发生在节点装配之后——反过来的话就成了「要解析节点先得有隧道」的死锁。
	if cfg.DNS.TunnelResolveOn() {
		resolver.SetTunnel(proxy.DialContext)
		logx.Debugf("IP/GEOIP 规则的解析将经节点 %s 发起", cfg.Active)
	}
	// 挂上拨号失败的观察者：它是「节点是不是已经不行了」的唯一数据来源。
	// 装配期就挂，第一条流量的失败才不会丢。
	rt.SetFaultObserver(s.observeDialFault)
	// 成功的那一侧也要挂：它是「节点又通了」唯一的信号，而故障断网保护
	// 只有挂上的动作就会永远关着——闸门没人开，症状是「网络一直断着」。
	rt.SetRecoverObserver(s.observeDialOK)
	// 挂上网卡走向的查询器，连接表才说得出每条连接走了哪张卡。
	// 捕获的是 split 本身而不是它的快照：开关在运行期还能拨，
	// 快照会把后来的改动挡在门外。
	rt.SetIfaceResolver(split.DevForPolicy)
	// 模式在装配时就定下来：global/direct 会整体压过规则集，
	// 但规则引擎照样加载着——切回 rule 不需要重新读文件。
	mode := cfg.ModeValue()
	s.mu.Lock()
	override := s.modeOverride
	s.mu.Unlock()
	if override != "" {
		mode = override
		logx.Infof("命令行指定分流模式 %s（不写回配置文件）", mode)
	}
	rt.SetMode(mode)

	// 发布：临界区里只做指针赋值。
	s.mu.Lock()
	if s.rt != nil {
		s.mu.Unlock()
		// 期间已经被别的路径装好了（-check 与 Start 抢跑）：丢掉自己这份，
		// 别把对方刚装配好的运行时顶掉。
		_ = rt.Close()
		geoRef.Swap(nil)
		return nil
	}
	s.split = split
	s.ifaceCards = splitPlan.cards
	s.ifaceSplit = IfaceSplitStatus{
		Note:      splitPlan.note,
		DirectDev: splitPlan.pick.direct,
		ProxyDev:  splitPlan.pick.proxy,
	}
	s.cfg = cfg
	s.proxy = proxy
	s.resolve = resolver
	s.geoRef = geoRef
	s.geoOK = geo != nil
	s.rt = rt
	s.mu.Unlock()
	// 闸门在临界区外开：它自己要读 s.mu，在这里开就是自锁。
	s.applySplitGate(mode)
	// 启动这一趟不走 applyPlan，可"没生效"的理由得在这一行就说清：
	// 只印一句空网卡名的话，排查的人只能回去读代码猜是哪一步没成。
	if cfg.IfaceSplit.Enable {
		logSplitPlan(splitPlan)
	}
	return nil
}

// discardPrepared 丢掉「已装配但没跑起来」的运行时状态。
//
// Start 在监听失败时必须调它。prepare 装好之后 s.rt 一路留着，
// 而 prepare 见到 s.rt != nil 就直接返回——于是「端口被占用 → 在面板里
// 换个端口 → 再启动」会永远拿着那份旧配置去绑同一个依旧被占用的端口，
// 用户看到的还是同一句报错，且没有任何自救手段（托盘里也没有「重启」入口）。
func (s *Service) discardPrepared() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt != nil {
		_ = s.rt.Close()
		s.rt = nil
	}
	// rt.Close 已经连带关掉了出站，这里只丢句柄。
	s.proxy = nil
	if s.geoRef != nil {
		// Swap(nil) 会关闭底层 mmdb，避免反复启停泄漏文件句柄。
		s.geoRef.Swap(nil)
		s.geoRef = nil
	}
	s.geoOK = false
	s.resolve = nil
	s.cfg = nil
}

// acquireInstance 拿单实例锁。已经有就直接复用。
//
// 接管式轮询最长 35 秒，因此它必须在锁外完成：攥着 s.mu 睡意味着面板
// 在这段时间里彻底没有响应，连「停止代理」都发不出去。
func (s *Service) acquireInstance() error {
	s.mu.Lock()
	held := s.lock != nil
	s.mu.Unlock()
	if held {
		return nil
	}

	lk, err := acquireOrTakeover(s.cfgPath, takeoverWait)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		s.lock = lk
		return nil
	}
	lk.release()
	return nil
}

func (s *Service) releaseInstance() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock != nil {
		s.lock.release()
		s.lock = nil
	}
}

// Start 装配并监听全部入站。已在运行时先 Stop 再重启，语义上等价于重启。
func (s *Service) Start() error {
	// 整段流程由 opMu 独占。以前的写法在 Prepare 前后各取一次锁、
	// 中间放掉一次，于是托盘 goroutine 与 Wails 的 OnStartup 撞在一起时，
	// 第二个 Start 会跳过锁获取直接去 bind 第一个正占着的端口，
	// 给用户报一句「端口已被占用，先 pgrep 查查有没有另一个实例」。
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	wasRunning := s.running
	s.mu.Unlock()
	if wasRunning {
		if err := s.stop(); err != nil {
			logx.Warnf("重启前拆除旧运行时失败: %v", err)
		}
	}

	if err := s.prepare(); err != nil {
		s.recordErr(err)
		return err
	}
	if err := s.acquireInstance(); err != nil {
		// 与监听失败同理：把刚装配好的状态丢掉，
		// 否则下一次 Start 会命中 prepare 的短路，继续用那份旧配置。
		s.discardPrepared()
		s.recordErr(err)
		return err
	}

	listeners, _, err := s.startListeners()
	if err != nil {
		for _, l := range listeners {
			_ = l.Close()
		}
		s.releaseInstance()
		s.discardPrepared()
		s.recordErr(err)
		return err
	}

	s.mu.Lock()
	tunWant := s.cfg != nil && s.cfg.TUN.Enable
	cfg := s.cfg
	s.mu.Unlock()

	// TUN 是可选入站：它起不来（缺权限是最常见的一种）不该把已经监听的
	// SOCKS5/HTTP 一起拖垮，所以这里只记警告，错误原样留在 TUN 状态里给界面看。
	// 它也要在锁外起：要解析域名并执行 ip/iptables，最长 20 秒。
	if tunWant {
		if err := s.startTUN(cfg); err != nil {
			logx.Warnf("TUN 入站启动失败（SOCKS5/HTTP 不受影响）: %v", err)
		}
	}
	s.startRuleProviders(cfg)
	// 规则集订阅可能刚刚重载过，基线以引擎当前打开的文件为准。
	s.noteRulesReloaded()
	s.startRulesWatch()
	// 网卡变化要有人盯：USB 卡被拔掉的那一刻起，钉在它上面的隧道就不再是加分项。
	s.syncSplitWatch()
	return nil
}

// startListeners 绑定全部入站并起转发。临界区里只有 bind/listen 与字段发布，
// 没有 DNS 解析也没有子进程调用，因此可以短到立刻返回。
func (s *Service) startListeners() ([]net.Listener, []InboundStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rt == nil || s.cfg == nil {
		return nil, nil, fmt.Errorf("服务未装配，无法监听")
	}
	var listeners []net.Listener
	statuses := make([]InboundStatus, 0, len(s.cfg.Inbounds))
	// rt 与 reg 先存到局部变量再启 goroutine：goroutine 闭包直接读 s.rt/s.reg
	// 会与 stop() 里的 `s.rt = nil` 构成数据竞争（-race 可稳定复现）。
	rt, reg := s.rt, s.reg
	for _, in := range s.cfg.Inbounds {
		ln, err := net.Listen("tcp", in.Listen)
		if err != nil {
			return listeners, nil, listenError(in.Listen, in.Type, err)
		}
		listeners = append(listeners, ln)
		auth := in.Type == "socks5" && in.Username != ""
		statuses = append(statuses, InboundStatus{
			Type:   in.Type,
			Listen: in.Listen,
			Addr:   ln.Addr().String(),
			Auth:   auth,
			Active: true,
		})

		switch in.Type {
		case "socks5":
			go func(l net.Listener, user, pass string) {
				if err := inbound.NewSOCKS5(rt, user, pass, reg).Serve(l); err != nil {
					logx.Warnf("socks5 退出: %v", err)
				}
			}(ln, in.Username, in.Password)
		case "http":
			go func(l net.Listener) {
				if err := inbound.NewHTTPProxy(rt, reg).Serve(l); err != nil {
					logx.Warnf("http 退出: %v", err)
				}
			}(ln)
		}

		authNote := ""
		if auth {
			authNote = "，需用户名密码认证"
		}
		logx.Infof("入站已监听: %s (%s%s)", ln.Addr(), in.Type, authNote)
	}

	s.listeners = listeners
	s.inbounds = statuses
	s.running = true
	s.startedAt = time.Now()
	s.lastErr = nil
	logx.Infof("wps_app 已启动，服务端 %s，模式 %s", s.cfg.ActiveServer().Addr, s.rt.Mode())
	return listeners, statuses, nil
}

// Stop 关闭全部监听器并释放出站。幂等，未运行时直接返回。
func (s *Service) Stop() error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	return s.stop()
}

// stop 拆除全部运行时。分三段：锁内关监听器（快）、锁外拆 TUN（慢）、
// 锁内释放出站与配置句柄（快）。调用方必须持有 opMu。
func (s *Service) stop() error {
	// 先关监听器：不关的话，收尾期间客户端的重连还在不断灌进新连接，
	// 而 TUN 的 `stack.Wait()` 要等所有连接走完——于是"退出"永远退不完。
	// 实测旧实例从收到 SIGTERM 到 TUN 停用花了 20 秒，日志里全是这段时间的
	// `http CONNECT api2.cursor.sh`；接管式重启因此超时，留下
	// 「旧实例已退、新实例不起」的断网空档，比卡顿更糟。
	s.mu.Lock()
	if !s.running && s.rt == nil && s.tun == nil {
		s.mu.Unlock()
		return nil
	}
	for _, ln := range s.listeners {
		_ = ln.Close()
	}
	s.listeners = nil
	for i := range s.inbounds {
		s.inbounds[i].Active = false
	}
	s.running = false
	s.startedAt = time.Time{}
	cancelRulesub := s.rulesubCancel
	s.rulesubCancel = nil
	// 停下来就把订阅状态一起清掉：界面上"上次拉于 3 分钟前"说的是那个还在跑的
	// 循环，循环没了还留着读数，就是在报一个此刻不存在的东西。
	s.providers, s.providerErrs = nil, nil
	cancelWatch := s.rulesWatchCancel
	s.rulesWatchCancel = nil
	cancelIface := s.ifaceWatchCancel
	s.ifaceWatchCancel = nil
	s.mu.Unlock()
	// 常驻提权 helper 是 root 进程，面板没了它就该收工。helper 自己也盯着父进程，
	// 但主动收更干净——不必等到它下一次心跳才发现主人没了。
	s.mu.Lock()
	dialHelper := s.dialHelper
	s.dialHelper = nil
	s.mu.Unlock()
	if dialHelper != nil {
		dialHelper.Close()
	}
	if cancelWatch != nil {
		cancelWatch()
	}
	if cancelIface != nil {
		cancelIface()
	}

	// 订阅循环要趁监听器刚关就停：它可能在拉一份新规则集，
	// 收尾期间再触发一次重载没有意义。
	if cancelRulesub != nil {
		cancelRulesub()
	}

	// 再拆 TUN：它抓着协议栈与网卡，路由和 iptables 也必须在我们这边收尾。
	tunErr := s.stopTUN()
	if tunErr != nil {
		logx.Warnf("TUN 停用时有未清理干净的项: %v", tunErr)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt != nil {
		_ = s.rt.Close()
		s.rt = nil
	}
	// rt.Close 已经连带关掉了出站，这里只丢句柄。
	// 必须置 nil：快照靠它判断连接态，留着已关闭的出站会一直显示「未连接」，
	// 而停止后本来就应该显示未连接。
	s.proxy = nil
	if s.geoRef != nil {
		// Swap(nil) 会关闭底层 mmdb，避免反复启停泄漏文件句柄。
		s.geoRef.Swap(nil)
		s.geoRef = nil
	}
	s.geoOK = false
	s.resolve = nil
	s.cfg = nil
	// 注意 s.tun 不在这里无条件置 nil：stopTUN 已经按拆除结果决定去留。
	// 拆不干净就留着句柄，界面才有机会重试，也才看得见 TUN 仍在运行。
	//
	// 端口一释放就该允许别的实例接手，所以锁跟着 Stop 走而不是等进程退出。
	if s.lock != nil {
		s.lock.release()
		s.lock = nil
	}
	logx.Infof("wps_app 已停止")
	return nil
}

// Reload 热重载 GeoIP 与规则，沿用 SIGHUP 的既有语义：
// 失败时保留旧库/旧规则继续服务。
//
// 读规则集与打开 mmdb 都是磁盘 I/O，因此不放在 s.mu 里：
// 这条路径正是 `kill -HUP` 会走的，攥着锁做全套磁盘读会让面板同时失去响应。
func (s *Service) Reload() error {
	s.mu.Lock()
	rt, cfg, geoRef, resolve := s.rt, s.cfg, s.geoRef, s.resolve
	s.mu.Unlock()
	if rt == nil || geoRef == nil || cfg == nil {
		return fmt.Errorf("服务未运行，无法重载")
	}
	logx.Infof("重载 GeoIP 与规则")
	if next, err := rules.OpenGeoIP(cfg.GeoIP.Path); err != nil {
		logx.Warnf("重载 GeoIP 失败，继续使用旧库: %v", err)
	} else {
		// Swap 内部会换指针并关闭旧库；它自带锁，
		// 因此与并发查询（每条入站连接都会走 geoRef.Country）是安全的。
		geoRef.Swap(next)
		s.mu.Lock()
		s.geoOK = true
		s.mu.Unlock()
	}
	if err := rt.Reload(cfg.RulesFile, geoRef, resolve); err != nil {
		logx.Errorf("重载规则失败，继续使用旧规则: %v", err)
		return err
	}
	// Reload 换了整个引擎，名单要重新铺一次，否则热重载之后就不拦了。
	rt.SetBlocklist(cfg.Block.Domains)
	// 汇总日志与启动那行同格式（含拦截条数）：两处报的是同一个"装完之后"的状态，
	// 才看得出重载把数字改成了什么。取引擎里那份而不是 cfg.Block.Domains——
	// 名单装没装上，只有问引擎才算数。
	eng := rt.Engine()
	dom, ip := eng.Stats()
	logx.Infof("规则已重载: %s（域名 %d 条，IP %d 条，拦截 %d 条，FINAL=%s）",
		cfg.RulesFile, dom, ip, len(eng.BlockDomains()), eng.Final())
	// 基线要在这里刷新，而不是只在监视器自己重载时刷：
	// 托盘、SIGHUP、面板改名单走的都是这一个出口，不刷就会让监视器
	// 再过 5~10 秒"发现"一次同样的改动，白重载一遍还多两条日志。
	s.noteRulesReloaded()
	return nil
}

// diskConfig 读磁盘上的配置，并按「文件变没变过」做缓存。
//
// 关键点是它**不持有 s.mu**：Snapshot/Mode/TUNStatus 是面板每秒轮询一次的热点，
// 把文件读放进状态锁意味着「配置放在慢盘/NFS/fuse 上时，整个服务被一次
// 文件读拖住」——而它们本身只是读，不该有任何阻塞。
//
// 判据用 mtime + size 而不是「缓存几秒」：一次 os.Stat 是一个 syscall，
// 不读数据也不解析，因此既便宜又不会让界面被 I/O 拖住；
// 同时任何外部改动（用户手工编辑、别的工具改写、config.Save 的原子替换）
// 都会立刻被看见——用 TTL 做不到这点，改了配置却要等两秒才生效。
// 代价只是极端情况下同一纳秒内的两次等长改写会被合并，那不是问题。
func (s *Service) diskConfig() *config.Config {
	st, err := os.Stat(s.cfgPath)
	if err != nil {
		// 读不到就沿用上一次那份：文件暂时不可读不该让状态投影整块塌掉。
		s.diskMu.Lock()
		defer s.diskMu.Unlock()
		return s.diskCfg
	}

	s.diskMu.Lock()
	fresh := s.diskCfg != nil &&
		s.diskCfgMod.Equal(st.ModTime()) &&
		s.diskCfgSize == st.Size()
	if fresh {
		cfg := s.diskCfg
		s.diskMu.Unlock()
		return cfg
	}
	s.diskMu.Unlock()

	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		s.diskMu.Lock()
		defer s.diskMu.Unlock()
		return s.diskCfg
	}
	s.diskMu.Lock()
	s.diskCfg, s.diskCfgMod, s.diskCfgSize = cfg, st.ModTime(), st.Size()
	s.diskMu.Unlock()
	return cfg
}

// invalidateDiskConfig 在本进程改写配置后作废缓存。调用方持有 cfgMu。
// 不作废也能靠 mtime 兜住，但那样要等下一次 stat，而这里的调用方
// 手上已经有确定的新值了，直接换掉最省事。
func (s *Service) invalidateDiskConfig(cfg *config.Config) {
	var mt time.Time
	var size int64
	if st, err := os.Stat(s.cfgPath); err == nil {
		mt, size = st.ModTime(), st.Size()
	}
	s.diskMu.Lock()
	s.diskCfg, s.diskCfgMod, s.diskCfgSize = cfg, mt, size
	s.diskMu.Unlock()
}

// Snapshot 返回当前状态。停止状态下除配置字段外大部分为零值。
func (s *Service) Snapshot() Snapshot {
	// 先在锁外把「磁盘配置」准备好，再进临界区拼快照：
	// 临界区里只剩内存字段的拷贝，绝不掺任何 I/O。
	cfg := s.diskConfig()

	s.mu.Lock()
	defer s.mu.Unlock()

	snap := Snapshot{
		ConfigPath:   s.cfgPath,
		Inbounds:     append([]InboundStatus(nil), s.inbounds...),
		RulesSkipped: []string{},
	}
	if snap.Inbounds == nil {
		snap.Inbounds = []InboundStatus{}
	}
	if s.cfg == nil {
		// 未运行时补上配置里的静态信息，方便 GUI 展示「将以什么配置启动」。
		if cfg != nil {
			srv, activeName := activeServerFor(cfg, s.failoverOverride)
			snap.Server = srv.Addr
			snap.GeoIPPath = cfg.GeoIP.Path
			snap.RulesFile = cfg.RulesFile
			snap.AuthSet = srv.Auth != ""
			snap.SNI = srv.TLS.SNI
			snap.BandwidthUp = srv.Bandwidth.Up
			snap.BandwidthDn = srv.Bandwidth.Down
			snap.Congestion = srv.Congestion
			snap.ProxyType = srv.Protocol()
			snap.Mode = string(cfg.ModeValue())
			snap.Profiles = profileViews(cfg, activeName, s.cooling)
			snap.ActiveProfile = activeName
			snap.TUN = tunStatusFromConfig(cfg.TUN)
			snap.IfaceSplit = s.splitStatusLocked(cfg.IfaceSplit.Enable, false)
		}
		if s.lastErr != nil {
			snap.LastError = s.lastErr.Error()
		}
		if snap.Profiles == nil {
			snap.Profiles = []ProfileView{}
		}
		return snap
	}

	// 运行中：一切以内存里那份为准（它可能已经被 mutate 换掉了）。
	rcfg := s.cfg
	// 本次运行真正生效的节点：自动切换之后它压过配置里的 active。
	// 这里必须统一取同一个值——曾经有过一版，Server/ProxyType 读的是盘上的节点，
	// 而实际承载流量的是 override 那个，面板于是显示一个根本没在用的地址。
	srv, activeName := activeServerFor(rcfg, s.failoverOverride)
	snap.Running = s.running
	snap.Server = srv.Addr
	snap.ProxyType = srv.Protocol()
	snap.GeoIPPath = rcfg.GeoIP.Path
	snap.GeoIPOK = s.geoOK
	snap.RulesFile = rcfg.RulesFile
	snap.AuthSet = srv.Auth != ""
	snap.SNI = srv.TLS.SNI
	snap.BandwidthUp = srv.Bandwidth.Up
	snap.BandwidthDn = srv.Bandwidth.Down
	snap.Congestion = srv.Congestion
	snap.Profiles = profileViews(rcfg, activeName, s.cooling)
	snap.ActiveProfile = activeName
	snap.AutoSwitched = s.failoverOverride != "" && activeName == s.failoverOverride
	if !s.switchedAt.IsZero() {
		snap.AutoSwitchedAt = s.switchedAt.UnixMilli()
	}
	if snap.AutoSwitched {
		// 界面上要能问出「它为什么自己动了」：这是自动切换唯一可解释的入口。
		//
		// 理由在 commitFailover 那一刻就定稿了。这里绝不能重新数一遍流水：
		// 窗口只有 faultWindow，切换过几分钟再数必然是空账，
		// 面板于是打出「有 0 次节点级失败（涉及 0 个不同目标）」——一句自相矛盾的
		// 告警，比不给他理由更让人怀疑这软件在乱动。
		snap.SwitchReason = s.switchReason
		if snap.SwitchReason == "" {
			// 非正常路径（override 被别处直接置上，没走过 commitFailover）：
			// 不编造失败次数，只说清楚发生了什么。
			snap.SwitchReason = fmt.Sprintf("本次运行已自动切到 %s，切换时的失败明细没有留下", activeName)
		}
	}
	if s.rt != nil {
		snap.Mode = string(s.rt.Mode())
	} else {
		snap.Mode = string(rcfg.ModeValue())
	}
	if s.tun != nil {
		snap.TUN = s.tun.Status()
	} else {
		snap.TUN = tunStatusFromConfig(rcfg.TUN)
	}
	snap.IfaceSplit = s.splitStatusLocked(rcfg.IfaceSplit.Enable, snap.Running)
	if snap.Profiles == nil {
		snap.Profiles = []ProfileView{}
	}
	// 连接态必须实打实问出站，不能从 Running 推。两者会长期不一致：
	// 代理已启动但还没跑过任何流量时，握手还没发生（hysteria2 是懒触发），
	// 此时如实报未连接比报已连接有用。
	if s.proxy != nil {
		snap.Connected = s.proxy.Connected()
		snap.ProxyStatus = s.proxy.Status()
	}
	if s.running && !s.startedAt.IsZero() {
		snap.StartedAt = s.startedAt.UnixMilli()
		snap.UptimeMS = time.Since(s.startedAt).Milliseconds()
	}
	if s.rt != nil {
		eng := s.rt.Engine()
		if eng != nil {
			snap.DomainRules, snap.IPRules = eng.Stats()
			snap.BlockedRules = eng.BlockCount()
			snap.FinalPolicy = string(eng.Final())
			snap.RulesSkipped = eng.Skipped()
			// Skipped 无跳过项时是 nil slice，会序列化成 JSON null。
			// 快照是要交给前端遍历的，契约上列表字段必须是数组而不是 null，
			// 否则前端一读 .length 就抛错、整块组件渲染不出来。
			if snap.RulesSkipped == nil {
				snap.RulesSkipped = []string{}
			}
		}
	}
	if s.lastErr != nil {
		snap.LastError = s.lastErr.Error()
	}
	return snap
}

func (s *Service) recordErr(err error) {
	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()
}

// mutate 读—改—存一条龙。保存失败时磁盘上还是原文件
// （config.Save 自己会先备份成 .bak）。
//
// cfgMu 必须覆盖 load—modify—save 三步：这三步全程不碰 s.mu（那是运行时状态，
// 与配置文件无关），因此没有别的锁挡着两次并发修改。少了它，「切换到全局」
// 与「新增节点」几乎同时点到就会各自读到同一份基线，后写的把前一个连同 .bak
// 一起抹掉，而 s.cfg 还可能停在另一个指针上，直到重启才与界面一致。
func (s *Service) mutate(fn func(*config.Config) error) error {
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	if err := config.Save(s.cfgPath, cfg); err != nil {
		return err
	}
	// 手上的 cfg 就是刚落盘的那份，连同 stat 一起换进缓存，省掉下一轮轮询的重新加载。
	s.invalidateDiskConfig(cfg)
	// 节点的参数一改，「规则钉到某个节点」那批临时出站就全部过期了：
	// 缓存里那只还拿着旧的 addr/auth/口令，而界面已经显示成新配置——
	// 继续用它，症状是"改了节点参数却像没生效"。
	// 这里整张丢而不是只丢改名的那一个，因为改名/改地址/改口令都算过期，
	// 而判"哪一个还没过期"要在这里判准的成本比重建一条隧道高得多。
	s.dropPinnedNodes()
	s.mu.Lock()
	if s.cfg != nil {
		s.cfg = cfg
	}
	s.mu.Unlock()
	return nil
}

// inboundAddrs 列出配置里的入站监听地址。
//
// 直连出站靠它做防环路：客户端让代理去连代理自己的端口时，
// 那个包会重新落回本进程的监听 socket，进入下一轮转发——
// 症状是连接数指数增长与 CPU 打满，而不是任何一条明确的错误。
func inboundAddrs(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Inbounds))
	for _, in := range cfg.Inbounds {
		if a := strings.TrimSpace(in.Listen); a != "" {
			out = append(out, a)
		}
	}
	return out
}
