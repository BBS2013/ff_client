// Package service 把代理的装配与启停收敛成一个可重复调用的容器。
//
// CLI 与 GUI 共用同一份逻辑：main.go 的 run() 与 GUI 托盘面板都只调用
// Start/Stop/Reload/Snapshot，不再各自复制一遍 resolver/规则/出站的搭建流程。
package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/dnsx"
	"wps_app/internal/httpprobe"
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
	// ifaceSeen 是监视循环上一轮看到的解析结果，用来判断网卡的变化是否已经落定。
	ifaceSeen splitPick
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

// ProfileView 是一个代理服务在界面上的样子。
// 口令不过 Wails 边界，这里只报「有没有填」。
type ProfileView struct {
	Name string `json:"name"`
	// Type 是协议名（hysteria2 / trojan），界面靠它告诉用户这个节点走的是什么。
	Type    string `json:"type"`
	Addr    string `json:"addr"`
	SNI     string `json:"sni"`
	AuthSet bool   `json:"authSet"`
	// UDP 说清这个节点能不能转发 UDP。UDP 现在只有 hysteria2 节点支持，
	// 界面上必须把这件事讲在前面——否则 QUIC 应用会「看着通了却一直超时」。
	UDP    bool `json:"udp"`
	Active bool `json:"active"`
	// QuotaBytes 是这个节点的配额（字节），0 = 没设。见 config.ProxyProfile.Quota。
	QuotaBytes uint64 `json:"quotaBytes"`
	// QuotaText 是人写下来的那一句原文（"1.5TiB"）。界面用它说话，
	// 用 QuotaBytes 算百分比——两份各有分工，不是同一个值的两份拷贝。
	QuotaText string `json:"quotaText"`
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
	split := outbound.NewSplit(splitPlan.pick.direct, splitPlan.pick.proxy)
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

// ruleResolverFor 挑规则判定用的解析入口。
func ruleResolverFor(cfg *config.Config, base *dnsx.Resolver) rules.Resolver {
	if cfg.DNS.TunnelResolveOn() {
		return tunnelResolver{r: base}
	}
	return base
}

// buildProviders 按配置组装订阅列表。一条配错的订阅只记警告，
// 它不该让已经配好的那几条也一起消失，更不该拖垮整个启动。
func buildProviders(cfg *config.Config, geo rules.GeoLookup, resolver rules.Resolver) (*rulesub.Updater, []string) {
	up := rulesub.New(geo, resolver, rulesub.WithRulesDir(filepath.Dir(cfg.RulesFile)))
	var rejected []string
	for _, p := range cfg.RuleProviders {
		if !p.IsEnabled() {
			continue
		}
		name := strings.TrimSpace(p.Name)
		if err := up.Add(name, strings.TrimSpace(p.URL), cfg.ProviderPath(p), p.Every()); err != nil {
			rejected = append(rejected, err.Error())
			logx.Warnf("规则集订阅未启用: %v", err)
		}
	}
	return up, rejected
}

// prefetchProviders 在加载规则之前把「本地还没有」的缓存补齐。
//
// 给一个明确的短预算：远端不可达时等再久也拉不到，而这期间面板一直是「启动中」。
// 拉不到就返回，让服务按现有（本地那部分）规则继续跑。
func prefetchProviders(cfg *config.Config, geo rules.GeoLookup, resolver rules.Resolver) {
	up, _ := buildProviders(cfg, geo, resolver)
	if up.Len() == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if n := up.RefreshMissing(ctx); n > 0 {
		logx.Infof("规则集订阅：启动前补齐了 %d 份缓存", n)
	}
}

// startRuleProviders 起规则集订阅的后台循环。
//
// 配置里一条可用的订阅都没有就什么都不做——绝大多数用户不需要这个功能，
// 不该为它常驻一个 goroutine 和一个定时器。
func (s *Service) startRuleProviders(cfg *config.Config) {
	if cfg == nil || len(cfg.RuleProviders) == 0 {
		return
	}
	s.mu.Lock()
	geoRef, resolve := s.geoRef, s.resolve
	s.mu.Unlock()

	up, rejected := buildProviders(cfg, geoRef, resolve)
	if up.Len() == 0 {
		s.mu.Lock()
		s.providerErrs = rejected
		s.mu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.rulesubCancel = cancel
	// 存下来是给面板看的：不存的话，"订阅配了几条、上次拉到什么时候、
	// 为什么少了一条"这些问题只有日志答得出，而日志是最后手段。
	s.providers, s.providerErrs = up, rejected
	s.mu.Unlock()

	logx.Infof("规则集订阅已启用：%d 条", up.Len())
	go up.Run(ctx, func() {
		// 重载路径与 SIGHUP 一样：失败时保留旧规则继续服务。
		if err := s.Reload(); err != nil {
			logx.Warnf("订阅更新后重载规则失败，继续用旧规则: %v", err)
		}
	})
}

// stopRuleProviders 停掉订阅循环。已经停过就什么都不做。
func (s *Service) stopRuleProviders() {
	s.mu.Lock()
	cancel := s.rulesubCancel
	s.rulesubCancel = nil
	s.providers, s.providerErrs = nil, nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
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

// startTUN 建起 TUN 入站。刻意不持有 s.mu：tunx.Start 会解析域名并执行
// ip/iptables 与提权 helper，最长 20 秒。
func (s *Service) startTUN(cfg *config.Config) error {
	s.mu.Lock()
	if s.tun != nil && s.tun.Status().Running {
		s.mu.Unlock()
		return nil
	}
	if s.rt == nil || s.resolve == nil {
		s.mu.Unlock()
		return fmt.Errorf("服务未装配，无法启动 TUN")
	}
	rt, resolve, reg := s.rt, s.resolve, s.reg
	s.mu.Unlock()

	t, err := tunx.New(tunx.Options{
		Conf:      cfg.TUN,
		Router:    rt,
		Lookup:    resolve.LookupIP,
		Reg:       reg,
		Bypass:    s.selfEgressIPs(cfg, resolve),
		Upstreams: append([]string(nil), cfg.DNS.Servers...),
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := t.Start(ctx); err != nil {
		// 句柄留着：Status 里的 LastError 是界面唯一的错误来源，
		// 丢了句柄就只剩日志里一行字。
		s.mu.Lock()
		s.tun = t
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.tun = t
	s.mu.Unlock()
	return nil
}

// stopTUN 拆掉 TUN。不持有 s.mu：拆除要等协议栈把连接走完并执行
// iptables 清理，实测最长 14 秒。
func (s *Service) stopTUN() error {
	s.mu.Lock()
	t := s.tun
	s.mu.Unlock()
	if t == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := t.Stop(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tun != t {
		return err
	}
	if err != nil {
		// 拆不干净就留着句柄，不要置 nil。
		// 残留的 nat 表劫持规则是一次机器级的 DNS 改写（全部 :53 被指向
		// 一块已经不在的网卡地址），句柄还在才有下一次重试拆除的机会；
		// 一旦丢掉句柄，界面上再没有任何入口能清理它，只能手敲 -tun-reset。
		return err
	}
	s.tun = nil
	return nil
}

// selfEgressIPs 列出「我们自己要拨出去」的地址：当前节点的服务端与 DNS 上游。
// strict_route 下这些必须钉在物理路由上，否则我们发出的包会被自己的 tun 抓回去。
// 会做 DNS 解析，调用方不应持有 s.mu。
func (s *Service) selfEgressIPs(cfg *config.Config, resolve *dnsx.Resolver) []string {
	if cfg == nil {
		return nil
	}
	addr := cfg.ActiveServer().Addr
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	out := make([]string, 0, 4)
	if ip := net.ParseIP(host); ip != nil {
		out = append(out, ip.String())
	} else if resolve != nil {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addrs, rerr := resolve.LookupIP(dctx, host)
		cancel()
		if rerr == nil {
			for _, a := range addrs {
				out = append(out, a.String())
			}
		} else {
			logx.Warnf("TUN: 解析代理服务端 %s 失败，strict_route 的防环路路由不完整: %v", host, rerr)
		}
	}
	for _, srv := range cfg.DNS.Servers {
		h, _, serr := net.SplitHostPort(srv)
		if serr != nil {
			h = srv
		}
		if ip := net.ParseIP(h); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
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
			snap.Profiles = profileViews(cfg, activeName)
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
	snap.Profiles = profileViews(rcfg, activeName)
	snap.ActiveProfile = activeName
	snap.AutoSwitched = s.failoverOverride != "" && activeName == s.failoverOverride
	if snap.AutoSwitched {
		// 界面上要能问出「它为什么自己动了」：这是自动切换唯一可解释的入口。
		n, hosts := s.faultSummaryLocked(rcfg.Active)
		snap.SwitchReason = fmt.Sprintf("配置里的节点 %s 在 %v 内有 %d 次节点级失败（涉及 %d 个不同目标）",
			rcfg.Active, faultWindow, n, len(hosts))
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

// ProfileSpec 是新增/修改一个节点时要填的字段。
// Auth 可以是掩码占位符，表示「沿用磁盘上的原值」。
//
// Type 是协议名，留空表示沿用（新增时继承现有节点、修改时保持原样）：
// 界面把它做成下拉，两个协议的字段差异由 config 那层统一处理。
type ProfileSpec struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Addr          string `json:"addr"`
	Auth          string `json:"auth"`
	SNI           string `json:"sni"`
	Insecure      bool   `json:"insecure"`
	BandwidthUp   string `json:"bandwidthUp"`
	BandwidthDown string `json:"bandwidthDown"`
	Congestion    string `json:"congestion"`
	FastOpen      bool   `json:"fastOpen"`
	// Quota 是"1000GB"这种原文。留空 = 不改这个节点的配额
	// （与上面每一个字段同一套约定：空串是"没填"，不是"清空"，
	//  所以面板上没有把配额抹掉的入口——那要在配置文件里删那一行）。
	Quota string `json:"quota"`
}

// ---------- 分流模式 ----------

// Mode 返回当前生效的分流模式。
func (s *Service) Mode() string {
	// 与 Snapshot 同一个理由：读文件不能占用状态锁。
	cfg := s.diskConfig()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt != nil {
		return string(s.rt.Mode())
	}
	if s.cfg != nil {
		return string(s.cfg.ModeValue())
	}
	if cfg != nil {
		return string(cfg.ModeValue())
	}
	return string(config.ModeRule)
}

// SetMode 切换分流模式并落盘。
//
// 不重启进程：模式只影响「新连接怎么决策」，路由器里换一个原子值就够，
// 已经在传的连接按原路走完。这也是全局/规则之间来回切几乎零成本的原因。
func (s *Service) SetMode(mode string) error {
	m, err := config.ParseMode(mode)
	if err != nil {
		return err
	}
	if err := s.mutate(func(cfg *config.Config) error {
		cfg.Mode = string(m)
		return nil
	}); err != nil {
		return err
	}
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()
	// 闸门跟着模式走：只有规则模式才分流。
	// 切完之后新连接立刻改走另一条路，正在传的那些按原路走完——与切模式本身的语义一致。
	s.applySplitGate(m)
	if rt != nil {
		rt.SetMode(m)
		return nil
	}
	// 没在跑就只改文件，下次 Start 会读新模式。
	s.mu.Lock()
	if s.cfg != nil {
		s.cfg.Mode = string(m)
	}
	s.mu.Unlock()
	logx.Infof("分流模式已设为 %s（当前未运行，启动后生效）", m)
	return nil
}

// OverrideMode 让命令行临时覆盖配置里的分流模式，不落盘。
//
// 与 SetMode 的区别就在这一个字：SetMode 是给界面用的，用户点了就要长期生效；
// OverrideMode 是给「这次先按全局跑一下看看」用的，改文件反而会造成困扰。
func (s *Service) OverrideMode(m config.Mode) error {
	if _, err := config.ParseMode(string(m)); err != nil {
		return err
	}
	s.mu.Lock()
	s.modeOverride = m
	rt := s.rt
	s.mu.Unlock()
	s.applySplitGate(m)
	if rt != nil {
		rt.SetMode(m)
	}
	return nil
}

// ---------- 代理服务（节点） ----------

// Profiles 返回全部节点与当前选中的名字。
func (s *Service) Profiles() ([]ProfileView, string, error) {
	// 走缓存：面板每次渲染设置页都会调它，而它只是一次纯读。
	cfg := s.diskConfig()
	if cfg == nil {
		// 缓存是空的说明真读过一次且失败了，把原因如实带回去，
		// 而不是返回一个空的节点列表让界面显示「没有节点」。
		if _, err := config.Load(s.cfgPath); err != nil {
			return nil, "", err
		}
		return nil, "", fmt.Errorf("配置不可用")
	}
	_, activeName := activeServerFor(cfg, s.activeOverride())
	return profileViews(cfg, activeName), activeName, nil
}

// activeOverride 读出本次运行的自动切换结果。
func (s *Service) activeOverride() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failoverOverride
}

// SetActiveProfile 切到某个节点。
//
// 顺序是「先装配、再落盘、最后提交」，理由见 stageActive：装配会失败，
// 而配置一旦写下去就收不回来了。
func (s *Service) SetActiveProfile(name string) error {
	proxy, err := s.stageActive(name)
	if err != nil {
		return err
	}
	if err := s.mutate(func(cfg *config.Config) error {
		found := false
		for _, p := range cfg.Proxies {
			if p.Name == name {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("节点 %q 不存在", name)
		}
		cfg.Active = name
		return nil
	}); err != nil {
		if proxy != nil {
			_ = proxy.Close()
		}
		return err
	}
	// 用户明确点名了要哪个节点，自动切换的那个结论就此作废：
	// 留着它，界面上看到的永远不是用户选的那个，而且没人能解释为什么。
	s.clearFailoverOverride()
	return s.commitProxy(proxy)
}

// clearFailoverOverride 丢掉本次运行的自动切换结果，并清空失败流水。
func (s *Service) clearFailoverOverride() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failoverOverride = ""
	s.switchedAt = time.Time{}
	s.cooling = nil
	s.faults = nil
	// 轮次冷却也要一起清：用户刚亲手点过节点，下一次自动切换不该被上一轮的账卡住。
	s.failoverRoundAt = time.Time{}
}

// AddProfile 新增一个节点。名字重复直接拒绝，
// 因为 active 是按名字寻址的，两个同名节点会让「切到哪个」变成玄学。
func (s *Service) AddProfile(p ProfileSpec) error {
	name := sanitizeName(p.Name, p.Addr)
	if name == "" {
		return fmt.Errorf("节点名不能为空")
	}
	return s.mutate(func(cfg *config.Config) error {
		for _, old := range cfg.Proxies {
			if old.Name == name {
				return fmt.Errorf("节点名 %q 已存在", name)
			}
		}
		srv := cfg.Proxies[0].Server // 缺省项沿用现有节点，界面只需填协议、地址与密钥
		srv.Type = pick(strings.TrimSpace(p.Type), srv.Type)
		if _, err := config.ParseProtocol(srv.Type); err != nil {
			return err
		}
		srv.Addr = strings.TrimSpace(p.Addr)
		srv.Congestion = pick(p.Congestion, srv.Congestion)
		if bw := strings.TrimSpace(p.BandwidthUp); bw != "" {
			srv.Bandwidth.Up = bw
		}
		if bw := strings.TrimSpace(p.BandwidthDown); bw != "" {
			srv.Bandwidth.Down = bw
		}
		srv.TLS.SNI = strings.TrimSpace(p.SNI)
		srv.TLS.Insecure = p.Insecure
		srv.FastOpen = p.FastOpen
		// trojan 没有拥塞算法、带宽和 TCP fastopen 的概念，从 hysteria2 节点
		// 继承这些字段只会让面板显示一句与实际无关的「本节点跑 BBR 200mbps」。
		if srv.Protocol() == config.ProtocolTrojan {
			srv.Bandwidth = config.BandwidthConfig{}
			srv.Congestion = ""
			srv.FastOpen = false
		}
		if auth := strings.TrimSpace(p.Auth); auth != "" && auth != maskedSecret {
			srv.Auth = auth
		}
		if srv.Auth == "" {
			return fmt.Errorf("节点 %q 缺少 auth", name)
		}
		quota, err := parseQuotaField(p.Quota)
		if err != nil {
			return err
		}
		cfg.Proxies = append(cfg.Proxies, config.ProxyProfile{Name: name, Server: srv, Quota: quota})
		return nil
	})
}

// UpdateProfile 就地改写某个节点的连接参数；auth 留空或仍是掩码就保持原值。
func (s *Service) UpdateProfile(name string, p ProfileSpec) error {
	return s.mutate(func(cfg *config.Config) error {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name != name {
				continue
			}
			srv := cfg.Proxies[i].Server
			if t := strings.TrimSpace(p.Type); t != "" {
				if _, err := config.ParseProtocol(t); err != nil {
					return err
				}
				srv.Type = t
			}
			if addr := strings.TrimSpace(p.Addr); addr != "" {
				srv.Addr = addr
			}
			if auth := strings.TrimSpace(p.Auth); auth != "" && auth != maskedSecret {
				srv.Auth = auth
			}
			if sni := strings.TrimSpace(p.SNI); sni != "" {
				srv.TLS.SNI = sni
			}
			if bw := strings.TrimSpace(p.BandwidthUp); bw != "" {
				srv.Bandwidth.Up = bw
			}
			if bw := strings.TrimSpace(p.BandwidthDown); bw != "" {
				srv.Bandwidth.Down = bw
			}
			if c := strings.TrimSpace(p.Congestion); c != "" {
				srv.Congestion = c
			}
			srv.TLS.Insecure = p.Insecure
			srv.FastOpen = p.FastOpen
			if srv.Protocol() == config.ProtocolTrojan {
				// 协议被改成 trojan：hysteria2 专属字段清掉，理由见 AddProfile。
				srv.Bandwidth = config.BandwidthConfig{}
				srv.Congestion = ""
				srv.FastOpen = false
			}
			quota, err := parseQuotaField(p.Quota)
			if err != nil {
				return err
			}
			if quota != "" {
				cfg.Proxies[i].Quota = quota
			}
			cfg.Proxies[i].Server = srv
			if next := sanitizeName(p.Name, name); next != "" && next != name {
				for j := range cfg.Proxies {
					if cfg.Proxies[j].Name == next {
						return fmt.Errorf("节点名 %q 已存在", next)
					}
				}
				cfg.Proxies[i].Name = next
				if cfg.Active == name {
					cfg.Active = next
				}
			}
			return nil
		}
		return fmt.Errorf("节点 %q 不存在", name)
	})
}

// RemoveProfile 删掉一个节点。最后一个不许删：没有节点的客户端起不来，
// 而「界面点了一下结果软件打不开」是最难解释的故障。
func (s *Service) RemoveProfile(name string) error {
	// 删的若是当前选中的节点，active 会落到剩下的第一个上。
	// 先按那个节点把出站装配成功再动配置：装配会解析节点域名，失败时配置还来得及不改。
	var staged outbound.Conn
	if cfg := s.diskConfig(); cfg != nil && cfg.Active == name {
		for _, p := range cfg.Proxies {
			if p.Name != name {
				proxy, err := s.stageActive(p.Name)
				if err != nil {
					return err
				}
				staged = proxy
				break
			}
		}
	}

	activated := false
	newActive := ""
	if err := s.mutate(func(cfg *config.Config) error {
		kept := make([]config.ProxyProfile, 0, len(cfg.Proxies))
		for _, p := range cfg.Proxies {
			if p.Name != name {
				kept = append(kept, p)
			}
		}
		if len(kept) == len(cfg.Proxies) {
			return fmt.Errorf("节点 %q 不存在", name)
		}
		if len(kept) == 0 {
			return fmt.Errorf("至少保留一个代理服务")
		}
		cfg.Proxies = kept
		if cfg.Active == name {
			cfg.Active = kept[0].Name
			newActive = cfg.Active
			activated = true
		}
		return nil
	}); err != nil {
		if staged != nil {
			_ = staged.Close()
		}
		return err
	}
	if !activated {
		// 删的是没在用的节点：运行中的服务与它没有任何关系，
		// 不该为了"配置少了一条记录"把监听、网卡和正在传的连接全拆一遍。
		if staged != nil {
			_ = staged.Close()
		}
		return nil
	}
	if staged == nil {
		// 预演阶段读不到配置（第一次读盘就失败过），只能事后装配。
		// 仍比旧写法自洽：配置此刻已经是新节点了，最坏是"没换出站"而不是"两个节点各说一半"。
		proxy, err := s.stageActive(newActive)
		if err != nil {
			return err
		}
		staged = proxy
	}
	return s.commitProxy(staged)
}

// ProfileTest 是一次节点连通性自检结果。
type ProfileTest struct {
	Name      string `json:"name"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latencyMs"`
	Remote    string `json:"remote"`
	Error     string `json:"error"`
	// 下面三个是应用层那一步（取一个真页面）的读数，与上面的电路分开：
	// 电路通了不等于页面取回来。PageChecked 说探没探过，
	// 探过之后 PageErr 非空就是失败原文，为空就是 Page 那行读数。
	PageChecked bool   `json:"pageChecked"`
	Page        string `json:"page"`
	PageErr     string `json:"pageErr"`
}

// TestProfile 用指定节点单独握手并拨一次目标，量出建链耗时。
//
// 它与当前选中的节点无关：单独建一条临时出站，测完就关，
// 因此在界面上点「测速」不会打断正在跑的隧道。
func (s *Service) TestProfile(name, target string) ProfileTest {
	res := ProfileTest{Name: name}
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var profile *config.ProxyProfile
	for i := range cfg.Proxies {
		if cfg.Proxies[i].Name == name {
			profile = &cfg.Proxies[i]
			break
		}
	}
	if profile == nil {
		res.Error = fmt.Sprintf("节点 %q 不存在", name)
		return res
	}
	if strings.TrimSpace(target) == "" {
		target = "www.gstatic.com:443"
	}
	res.Remote = target
	// 解析节点地址必须和真实出站用同一套直连 DNS。以前这里传的是 nil，
	// 于是退回系统解析——而 TUN 开着时系统解析正被我们自己的劫持改写过：
	// 节点域名通常不在规则集里、落到 FINAL=PROXY，会被答成一个假 IP，
	// 测速因此去连自家网卡，报回来的是 "connection reset by peer"
	// 这种和配置毫无关系、根本照着没法修的话（jp 节点实测踩过）。
	s.mu.Lock()
	resolve := s.resolve
	split := s.split
	s.mu.Unlock()
	if resolve == nil {
		r, rerr := dnsx.New(cfg.DNS.Servers, cfg.DNS.Timeout.Duration, cfg.DNS.Cache.Duration)
		if rerr != nil {
			res.Error = rerr.Error()
			return res
		}
		resolve = r
	}
	proxy, err := outbound.New(profile.Server, 8*time.Second, resolve, fakeRange(cfg), split)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() { _ = proxy.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := proxy.DialContext(ctx, target)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.LatencyMS = time.Since(start).Milliseconds()
	probeErr := probeAccept(conn)
	_ = conn.Close()
	if probeErr != nil {
		res.Error = probeErr.Error()
		return res
	}
	res.OK = true
	// 应用层再验一次：电路通了不等于页面取回来。
	pageProbe(ctx, proxy, profilePageProbe, &res)
	return res
}

// profilePageProbe 是节点测速顺带取页面的那个地址。
// 永远是同一个：它回答的是"这个节点能不能把一个境外页面取回来"，
// 那是节点级的问题，与这次拨的是哪个目标无关。
const profilePageProbe = "https://www.gstatic.com/generate_204"

// pageProbe 在电路已通的前提下单独再拨一次，取一个真页面回来判定。
//
// 为什么要多这一下：`probeAccept` 只看得出一个把连接直接关掉的节点。
// 另有一类节点是隧道正常建立、服务端把流量交给一个兼底的 web 服务器，
// 任何站点回来的都是同一张 400 页面——握手、探测、延迟全都好看，
// 而用户的浏览器一个页面都打不开。状态码与 `Server:` 头会当场把它说漏。
// 判据与命令行 `-check-fetch` 共用 internal/httpprobe，两条路不会各自漂移。
//
// 不复用上面那条连接：`probeAccept` 已经在它上面读过一次，
// 拿去做 TLS 握手会失败，而那看起来像节点的锅。
// 预算沿用测速那个 ctx 的剩余时间——一次点击不该比今天更慢。
func pageProbe(ctx context.Context, dialer outbound.Dialer, raw string, res *ProfileTest) {
	res.PageChecked = true
	t, err := httpprobe.Parse(raw)
	if err != nil {
		// 常量拆不开属于代码写错，但这里仍然要给一句原文：
		// 留一个空读数会被界面读成"没探"，而实际是"探了、连探针本身都没发出去"。
		res.PageErr = "探针地址用不了: " + err.Error()
		return
	}
	conn, derr := dialer.DialContext(ctx, t.Addr())
	if derr != nil {
		res.PageErr = fmt.Sprintf("拨 %s 失败: %v", t.Addr(), derr)
		return
	}
	defer func() { _ = conn.Close() }()
	out, ferr := httpprobe.Fetch(ctx, conn, t)
	if ferr == nil {
		ferr = out.Judge()
	}
	if ferr != nil {
		res.PageErr = ferr.Error()
		return
	}
	res.Page = out.String()
}

// authProbeTimeout 是测速探测读的等待时间。
const authProbeTimeout = 400 * time.Millisecond

// probeAccept 探一次「服务端是否还活着」。
//
// trojan 的口令校验发生在 TLS 握手之后：头部发完，DialContext 就成功了，
// 而口令不对的服务端是直接把连接关掉——不返回任何错误码。
// 只看握手结果的测速会把一条配错口令的节点显示成「87 ms 正常」。
//
// 所以握手后再读一字节：读到东西或读超时都算正常（正常服务端发完头部就沉默，
// 在等我们的第一个字节），只有读回一个真正的错误才算失败。
// hysteria2 走同一条路径也成立：它的认证在 QUIC 握手里，到这一步连接必然是好的。
func probeAccept(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(authProbeTimeout)); err != nil {
		// 设不上超时就不探了：探针是用来发现坏配置的，不该自己变成测速卡住的原因。
		return nil
	}
	n, err := conn.Read(make([]byte, 1))
	if n > 0 || err == nil {
		return nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return nil
	}
	return fmt.Errorf("服务端在读完请求头后断开了连接（口令不对或目标不可达）: %w", err)
}

// ---------- TUN ----------

// SetTUNEnabled 打开或关闭 TUN 模式，并落盘。
// 运行中会即时起/拆网卡，不需要重启整个代理。
func (s *Service) SetTUNEnabled(enable bool) error {
	if err := s.mutate(func(cfg *config.Config) error {
		cfg.TUN.Enable = enable
		return nil
	}); err != nil {
		return err
	}
	// 与 Start/Stop 串行：起/拆网卡也是长操作，不该与一次重启穿插。
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	if s.cfg != nil {
		s.cfg.TUN.Enable = enable
	}
	running := s.running && s.rt != nil
	cfg := s.cfg
	s.mu.Unlock()

	if !running || cfg == nil {
		logx.Infof("TUN 开关设为 %v（当前未运行，启动后生效）", enable)
		return nil
	}
	if !enable {
		return s.stopTUN()
	}
	return s.startTUN(cfg)
}

// tunStatusFromConfig 用配置文件回答 TUN 的状态：还没开启、或整个服务没起来时，
// 界面照样要能看见网卡名、地址，以及「点开启之后由谁去建网卡」。
//
// 这份构造被三处共用（未运行时的快照、运行中但 TUN 未开启、TUNStatus）。
// 以前每处各写一遍字面量，Privilege 漏在两处里，面板于是把「配了 tun.helper」
// 显示成「本进程直接开（要求面板以 root 运行）」——看到这句的用户只会以为开不起来。
func tunStatusFromConfig(tc config.TUNConfig) tunx.Status {
	st := tunx.Status{
		Enabled:     tc.Enable,
		Device:      tc.Device,
		Address:     tc.Address,
		DNS:         tc.DNS,
		FakeIPRange: tc.FakeIPRange,
		HijackDNS:   tc.DNSHijackEnabled(),
		StrictRoute: tc.StrictRoute,
		// TUN 没在跑，V6Ready 只能是 false。但「用户要不要 v6」仍然要报出来——
		// 面板上这一栏是「开着的」还是「没要的」，两者的排查方向完全不同。
		IPv6:      tc.IPv6On(),
		V6Ready:   false,
		HelperCmd: tc.Helper,
		Privilege: "self",
		Applied:   []string{},
	}
	if len(tc.Helper) > 0 {
		st.Privilege = "helper"
	}
	return st
}

// TUNStatus 返回 TUN 当前状态（未启用时也是一个可用的零值结构）。
func (s *Service) TUNStatus() tunx.Status {
	// 同 Snapshot：磁盘读在锁外做。
	cfg := s.diskConfig()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tun != nil {
		return s.tun.Status()
	}
	if cfg != nil {
		return tunStatusFromConfig(cfg.TUN)
	}
	return tunx.Status{Applied: []string{}}
}

// ---------- 内部小工具 ----------

// maskedSecret 与 ui 层保持一致：表单里回显的占位符不是真口令。
const maskedSecret = "********"

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

// nodeDialer 按节点名造一只出站，是规则里 node= 那条路的唯一实现入口。
//
// 懒建：没被任何规则钉住的节点不该白占一条隧道（每只 hysteria2 客户端都带着
// 自己的 QUIC 状态与心跳）。造出来的一只由 outbound.Set 缓存，
// 停机、换配置时由 Set.Close / DropNode 收尾。
func (s *Service) nodeDialer(name string) (outbound.Conn, error) {
	s.mu.Lock()
	cfg, resolve, to := s.cfg, s.resolve, s.handshakeTO
	split := s.split
	s.mu.Unlock()
	if cfg == nil {
		return nil, fmt.Errorf("规则把流量钉到节点 %s，但配置还没装配好", name)
	}
	var srv *config.ServerConfig
	for i := range cfg.Proxies {
		if cfg.Proxies[i].Name == name {
			srv = &cfg.Proxies[i].Server
			break
		}
	}
	if srv == nil {
		// 报错而不是改用当前活动节点：用户钉它正因为不想让它去别处，
		// 悄悄换个节点走出去是拿别人的出口干这件事（见 GetNode 同一条理由）。
		return nil, fmt.Errorf("规则把流量钉到节点 %s，而配置里没有这个名字", name)
	}
	if resolve == nil {
		// 兜底与测速那条路一致：解析节点域名必须走直连 DNS，
		// 否则 TUN 开着时会把自家网卡的假 IP 当节点地址去拨。
		r, err := dnsx.New(cfg.DNS.Servers, cfg.DNS.Timeout.Duration, cfg.DNS.Cache.Duration)
		if err != nil {
			return nil, err
		}
		resolve = r
	}
	return outbound.New(*srv, to, resolve, fakeRange(cfg), split)
}

// dropPinnedNodes 丢掉固定节点那批临时出站并关掉它们。没在跑就什么都不做。
func (s *Service) dropPinnedNodes() {
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()
	if rt == nil {
		return
	}
	rt.DropPinnedNodes()
}

// stageActive 按「active 改成 name 之后」的当前配置装配一只候选出站，不改任何东西。
// 服务没在跑时返回 (nil, nil)：没有正在使用的出站需要换，下一次 Start 自然读新配置。
//
// 分成「先装配、再落盘」两步是为了堵住一个自相矛盾的状态：装配要解析节点域名，
// 是会失败的，而 active 一旦写进配置就收不回来。先落盘再装配的话，
// 失败那一刻快照里的 ActiveProfile/Server 说的是新节点，
// Connected/ProxyStatus 却还挂在旧节点上，流量也真的还在走旧节点——
// 界面显示"已切换"，实际什么都没切。
func (s *Service) stageActive(name string) (outbound.Conn, error) {
	s.mu.Lock()
	rt, cfg, resolve, split := s.rt, s.cfg, s.resolve, s.split
	s.mu.Unlock()
	if rt == nil || cfg == nil {
		return nil, nil
	}
	cand := *cfg // 浅拷贝够用：只改 Active，节点列表照原样读
	cand.Active = name
	proxy, err := outbound.New(cand.ActiveServer(), s.handshakeTO, resolve, fakeRange(&cand), split)
	if err != nil {
		return nil, fmt.Errorf("装配节点 %q 失败: %w", name, err)
	}
	return proxy, nil
}

// commitProxy 把 stageActive 装配好的那只换成正在使用的 PROXY 出站，
// 不动监听、规则、协议栈、网卡与路由——换节点改变的只有「出口是谁」。
//
// 以前这里走的是整块重启：TUN 在跑时要拆了重建（含多次 sudo 与二十来条
// ip/iptables），点一下「选用」要等两三秒，界面上看就是卡死，
// 还顺手把正在传的、与新节点毫无关系的连接全打断。
//
// 出站的构造在这两个方法里都落在第一个临界区之外：它要解析节点域名（最长 5s），
// 抱着 s.mu 做网络解析，面板每次状态轮询都会排在这条锁后面——那等于把卡顿
// 从"重启网卡"换成"等 DNS"，问题没走。
func (s *Service) commitProxy(proxy outbound.Conn) error {
	s.mu.Lock()
	rt, cfg := s.rt, s.cfg
	strictRunning := s.tun != nil && s.tun.Status().Running && cfg != nil && cfg.TUN.StrictRoute
	s.mu.Unlock()
	if rt == nil || cfg == nil || proxy == nil {
		// 没在跑，或者压根不需要换：新 active 已经在磁盘上，下次 Start 自然用它。
		if proxy != nil {
			_ = proxy.Close()
		}
		return nil
	}
	if strictRunning {
		// strict_route 的防环路路由钉的是「当前节点的 IP」，换节点必须重算，
		// 这一条只能整块重启。慢，但 strict_route 是默认关闭的实验特性。
		_ = proxy.Close()
		logx.Infof("strict_route 已启用：换节点要重算绕过路由，走整块重启")
		return s.Start()
	}

	srv := cfg.ActiveServer()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt != rt {
		// 期间被 Stop/Start 过一轮：新路由器已经按新配置装配好了，这次作废。
		_ = proxy.Close()
		return nil
	}
	// 节点名与出站一起交出去：按节点算用量靠的就是这一刻对上号。
	old, err := s.rt.SwapProxy(proxy, cfg.Active)
	if err != nil {
		_ = proxy.Close()
		return err
	}
	s.proxy = proxy
	if old != nil {
		_ = old.Close()
	}
	// 解析器的隧道入口要跟着换：旧隧道已经关了，而且换节点就是换问 DNS 的位置。
	s.bindTunnelResolver(cfg, proxy)
	logx.Infof("已切到节点 %s（%s · %s），监听与网卡未受影响", cfg.Active, srv.Protocol(), srv.Addr)
	return nil
}

func profileViews(cfg *config.Config, activeName string) []ProfileView {
	out := make([]ProfileView, 0, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		out = append(out, ProfileView{
			Name:    p.Name,
			Type:    p.Server.Protocol(),
			Addr:    p.Server.Addr,
			SNI:     p.Server.TLS.SNI,
			AuthSet: strings.TrimSpace(p.Server.Auth) != "",
			UDP:     p.Server.Protocol() == config.ProtocolHysteria2,
			// 打「使用中」标要看本次运行真正生效的那个名字，
			// 而不是配置文件里写的那个：自动切换之后两者会不一样。
			Active: p.Name == activeName,
			// 配额给两份：换算后的字节用来算百分比，
			// 原文用来说话。只给字节的话，写 "1.5TiB" 的人会在界面上
			// 看到 "1.6 TB"——同一个数换了单位，人就以为程序把配置改了。
			QuotaBytes: p.QuotaBytes(),
			QuotaText:  strings.TrimSpace(p.Quota),
		})
	}
	return out
}

// parseQuotaField 把界面上填的配额先过一遍尺寸解析。
// 不留到 Save 里的 Validate 去报：那时错误会从"写盘失败"那条路绕回来，
// 指不清是哪一格填错了。
func parseQuotaField(q string) (string, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", nil
	}
	if _, err := config.ParseSize(q); err != nil {
		return "", err
	}
	return q, nil
}

func sanitizeName(name, fallback string) string {
	if n := strings.TrimSpace(name); n != "" {
		return n
	}
	return strings.TrimSpace(fallback)
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

// fakeRange 把配置里的假 IP 段变成「节点地址不许落在这里」的判据。
// 解析不出来时返回零值（不额外拦）：假 IP 段没配或写错，自有配置校验去报，
// 这里不该再制造第二种错误。
func fakeRange(cfg *config.Config) netip.Prefix {
	if cfg == nil {
		return netip.Prefix{}
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(cfg.TUN.FakeIPRange))
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

func pick(a, b string) string {
	if s := strings.TrimSpace(a); s != "" {
		return s
	}
	return b
}
