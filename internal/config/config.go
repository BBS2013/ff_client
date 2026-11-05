// Package config 负责 YAML 配置的加载、默认值填充与校验。
package config

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"wps_app/internal/logx"
	"wps_app/internal/sudoown"
)

// Mode 是分流模式。它属于路由决策，但字面量来自配置文件，因此定义放在
// 最底层的 config 里，router 反向引用它——避免两边各写一份字符串常量。
type Mode string

const (
	// ModeRule 按规则集分流：命中 PROXY 走隧道，命中 DIRECT 直连。
	ModeRule Mode = "rule"
	// ModeGlobal 全局模式：所有流量都走当前节点，规则集不参与决策。
	ModeGlobal Mode = "global"
	// ModeDirect 直连模式：全部直连，隧道不参与。
	ModeDirect Mode = "direct"
)

// Modes 返回全部可用的分流模式。
//
// 导出来是为了让下游能**遍历**它做守卫测试（同 rules.Policies() 的理由）：
// Go 不会在新增一个 Mode 时提醒任何一处 switch 漏了分支，
// 而界面与演示数据都是照字面量匹配的——遍历这张表能把"你没决定"变成测试失败。
func Modes() []Mode {
	return []Mode{ModeRule, ModeGlobal, ModeDirect}
}

// ParseMode 校验模式字面量；空串取默认值 ModeRule。
func ParseMode(s string) (Mode, error) {
	switch m := Mode(strings.TrimSpace(strings.ToLower(s))); m {
	case "":
		return ModeRule, nil
	case ModeRule, ModeGlobal, ModeDirect:
		return m, nil
	default:
		return "", fmt.Errorf("unknown mode %q (want rule, global or direct)", s)
	}
}

type Config struct {
	// LegacyServer 只对应旧配置里的顶层 `server:` 段。它不是第二份事实源：
	// 加载时内容会被迁进 Proxies 然后置 nil，写回磁盘时这个段也不再出现（见 MarshalYAML）。
	// 留成字段只是为了让旧文件原样可读。
	LegacyServer *ServerConfig   `yaml:"server"`
	Proxies      []ProxyProfile  `yaml:"proxies"`
	Active       string          `yaml:"active"`
	Mode         string          `yaml:"mode"`
	Inbounds     []InboundConfig `yaml:"inbounds"`
	GeoIP        GeoIPConfig     `yaml:"geoip"`
	RulesFile    string          `yaml:"rules_file"`
	// RuleProviders 是远程规则集订阅，见 RuleProvider。
	RuleProviders []RuleProvider `yaml:"rule_providers"`
	TUN           TUNConfig      `yaml:"tun"`
	DNS           DNSConfig      `yaml:"dns"`
	SysProxy      SysProxyConfig `yaml:"sysproxy"`
	// IfaceSplit 是「两张无线都在时按网卡分流」的开关，见 IfaceSplitConfig。
	IfaceSplit IfaceSplitConfig `yaml:"iface_split"`
	// Block 是拦截名单，见 BlockConfig。
	Block BlockConfig `yaml:"block"`
	Log   LogConfig   `yaml:"log"`
}

// ProxyProfile 是一个可命名、可增删的代理服务（一个 hysteria2 节点）。
type ProxyProfile struct {
	Name   string       `yaml:"name"`
	Server ServerConfig `yaml:"server"`
	// Quota 是这个节点的配额，写成人能抄的样子："1000GB"、"1.5TiB"、"500G"。
	// 空 = 没设。0 字节不是"配额是 0"，而是"没设"——见 QuotaBytes。
	//
	// 为什么挂在 profile 上而不是 server 段里：它不参与拨号，
	// 是"这个节点该被怎么记账"的属性。放进 server: 会让 -check 那类
	// 只关心连通性的路径以为它影响连接，也会让"复制一份 server 段"顺手带走配额。
	Quota string `yaml:"quota,omitempty"`
}

// QuotaBytes 解析这个节点的配额。0 表示没设。
// 错误由 Validate 在加载时统一报，这里只给调用方一个"能不能用"的读法：
// 读不出来的配额按"没设"处理，而不是让面板上每一个用量读数都跟着罢工——
// 配额只是装饰，流量本身才是这一页要回答的问题。
func (p ProxyProfile) QuotaBytes() uint64 {
	n, err := ParseSize(p.Quota)
	if err != nil {
		return 0
	}
	return n
}

// TUNConfig 描述 TUN 模式：建一块虚拟网卡，用用户态协议栈接管系统流量。
//
// 开 TUN 需要 CAP_NET_ADMIN（root 或 setcap），普通用户起不来会在状态里
// 如实报错误，而不是静默降级成「看起来开着」。
//
// 接管方式与 Clash 一致，靠「假 IP + DNS 劫持」而不是抢默认路由：
//   - 被判定走代理的域名，DNS 直接回一个假 IP（落在 FakeIPRange 里）；
//     应用连这个假 IP 时才被路由进 tun，再由假 IP 反查域名、走隧道。
//   - 判定为直连的域名回传真 IP，流量根本不进 tun，既不绕路也没有环路风险。
type TUNConfig struct {
	Enable  bool   `yaml:"enable"`
	Device  string `yaml:"device"`  // 接口名，长度受 IFNAMSIZ 限制
	Address string `yaml:"address"` // 网卡的 IP/前缀，如 172.19.0.1/30
	MTU     int    `yaml:"mtu"`
	// DNS 是劫持目标地址（tun 上接管 :53 的那个 IP），留空取 Address 所在网段的下一个可用地址。
	DNS string `yaml:"dns"`
	// FakeIPRange 是给「走代理的域名」分配假 IP 的网段，必须整段路由进 tun。
	FakeIPRange string `yaml:"fake_ip_range"`
	// Address6 是网卡上的 IPv6 地址。ipv6 关掉时这一项不参与任何事情。
	Address6 string `yaml:"address6"`
	// FakeIPRange6 是 IPv6 假 IP 段。
	FakeIPRange6 string `yaml:"fake_ip_range6"`
	// IPv6 决定要不要接管 IPv6 的假 IP 与 DNS 劫持。留空即启用。
	//
	// **默认启用是有代价的**：开启会在系统里装上 ip6tables 规则，
	// 所以显式关掉的语义必须清楚，而不是「留空就等于某一边」。
	// 关掉后 AAAA 回 NODATA，应用退回 A 记录——那正是本程序一直以来的行为。
	IPv6 *bool `yaml:"ipv6"`
	// HijackDNS 用 iptables 把本机的 :53 出向查询重定向到 DNS 地址（本进程自身除外，
	// 否则我们的上游解析会自己吃自己）。关掉它就得自己让应用改用 tun.dns。
	HijackDNS *bool `yaml:"hijack_dns"`
	// StrictRoute 把默认路由也交给 tun，让所有裸 IP 流量都进来。
	// 需要配合 route_exclude 使用，否则直连出站会形成环路，属于进阶用法。
	StrictRoute bool `yaml:"strict_route"`
	// Helper 是提权命令（argv，不经 shell），用于「面板以普通用户跑、TUN 交给 helper 开」：
	// 典型写法 ["sudo", "-n", "/usr/local/bin/wps_app", "--tun-helper"]。
	// 面板是 GUI 进程时这是唯一能保住托盘的方式——root 进程连不上用户会话总线，
	// 托盘注册不了。留空表示本进程自己直接开网卡（需要 root 或 setcap）。
	Helper []string `yaml:"helper,omitempty"`
	// RouteExclude 在 StrictRoute 下钉回物理网关的网段（CIDR 列表）。
	RouteExclude []string `yaml:"route_exclude"`
	// KillSwitch 打开「故障断网保护」：自动切换放弃时把本机出站收窄到白名单
	// （所有节点、DNS 上游、回环与 DHCP），其余一律丢弃，堵住换节点重启那几百毫秒
	// 里的裸奔窗口。
	//
	// 默认关闭，且只在 strict_route（全局接管）下有意义：选择性 TUN 里直连本来就该
	// 从物理网卡出去，挂上它等于把这个模式要的功能关掉。开了但装不上时，
	// 面板会明确报「未生效」，不会显示成一道开着的保护。
	KillSwitch bool `yaml:"kill_switch"`
}

// DefaultTUN 返回 TUN 段的默认值，供 applyDefaults 与 GUI 表单共用。
func DefaultTUN() TUNConfig {
	yes := true
	return TUNConfig{
		Device:       "wps-tun",
		Address:      "172.19.0.1/30",
		MTU:          1500,
		DNS:          "172.19.0.2",
		FakeIPRange:  "198.18.0.0/15",
		Address6:     "fd00:1::1/64",
		FakeIPRange6: "fc00::/18",
		HijackDNS:    &yes,
	}
}

// DNSHijackEnabled 报告是否要做 DNS 劫持；字段为 nil 时按开启处理。
func (t TUNConfig) DNSHijackEnabled() bool {
	return t.HijackDNS == nil || *t.HijackDNS
}

// IPv6On 报告要不要接管 IPv6 的假 IP 与 DNS 劫持；字段为 nil 时按开启处理。
func (t TUNConfig) IPv6On() bool {
	return t.IPv6 == nil || *t.IPv6
}

// 支持的出站协议。缺省是 hysteria2，这样只写过 addr/auth 的老配置不用改一个字。
const (
	ProtocolHysteria2 = "hysteria2"
	ProtocolTrojan    = "trojan"
)

// Protocols 是面板下拉里能选的协议。
var Protocols = []string{ProtocolHysteria2, ProtocolTrojan}

// ParseProtocol 归一化协议名；空串取 hysteria2。
func ParseProtocol(v string) (string, error) {
	switch p := strings.ToLower(strings.TrimSpace(v)); p {
	case "":
		return ProtocolHysteria2, nil
	case ProtocolHysteria2, ProtocolTrojan:
		return p, nil
	default:
		return "", fmt.Errorf("不支持的协议 %q（可选 %s）", v, strings.Join(Protocols, " / "))
	}
}

type ServerConfig struct {
	// Type 是协议名：hysteria2（默认）或 trojan。
	// 其余字段是「平铺的并集」：Addr/Auth 对两种协议都必需，
	// Bandwidth/Congestion/FastOpen 只有 hysteria2 用得到——
	// 分成子块会更"整齐"，但会让每个读写路径都要先判类型，
	// 而这两类字段本来就高度重叠（addr/auth/sni/insecure）。
	Type       string          `yaml:"type"`
	Addr       string          `yaml:"addr"`
	Auth       string          `yaml:"auth"`
	TLS        TLSConfig       `yaml:"tls"`
	Bandwidth  BandwidthConfig `yaml:"bandwidth"`
	Congestion string          `yaml:"congestion"`
	FastOpen   bool            `yaml:"fast_open"`
}

// Protocol 返回归一化后的协议名，非法值按 hysteria2 处理（校验会另报）。
func (s ServerConfig) Protocol() string {
	p, err := ParseProtocol(s.Type)
	if err != nil {
		return ProtocolHysteria2
	}
	return p
}

type TLSConfig struct {
	SNI      string `yaml:"sni"`
	Insecure bool   `yaml:"insecure"`
}

// BandwidthConfig 中 Up/Down 是面向用户的字符串（如 "200 mbps"），
// 解析后得到字节/秒。上传速率填 MaxTx，下载速率填 MaxRx。
type BandwidthConfig struct {
	Up   string `yaml:"up"`
	Down string `yaml:"down"`
}

type InboundConfig struct {
	Type   string `yaml:"type"`
	Listen string `yaml:"listen"`
	// Username/Password 仅对 socks5 生效：两者都为空时不要求认证，
	// 都非空时启用 RFC 1929 用户名密码认证。
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type GeoIPConfig struct {
	Path string `yaml:"path"`
}

// RuleProvider 是一条远程规则集的订阅。
//
// 它只负责把文件拉到本地缓存上，**不参与判定**：真正生效的仍然只是
// rules_file 那一份，靠 `#include` 把缓存引进去。所以订阅挂了、断了、
// 拉到一份坏文件，最坏结果是「规则还是上次那份」，不会凭空改变分流。
type RuleProvider struct {
	// Name 是这条订阅的名字，用于日志与默认缓存路径，必须非空且唯一。
	Name string `yaml:"name"`
	// URL 是拉取地址，只支持 http/https。
	URL string `yaml:"url"`
	// Path 是缓存落盘位置。留空则取 rules_file 同目录下的 providers/<name>.txt。
	Path string `yaml:"path"`
	// Interval 是多久拉一次，留空或 <=0 取默认 24h。
	Interval Duration `yaml:"interval"`
	// Enabled 关掉这条订阅。留空即启用。
	Enabled *bool `yaml:"enabled"`
}

// DefaultProviderInterval 是没写 interval 时的默认拉取周期。
const DefaultProviderInterval = 24 * time.Hour

// IsEnabled 报告这条订阅是否启用。
func (p RuleProvider) IsEnabled() bool { return p.Enabled == nil || *p.Enabled }

// Every 返回实际使用的拉取周期。
func (p RuleProvider) Every() time.Duration {
	if p.Interval.Duration <= 0 {
		return DefaultProviderInterval
	}
	return p.Interval.Duration
}

type DNSConfig struct {
	Servers []string `yaml:"servers"`
	Timeout Duration `yaml:"timeout"`
	Cache   Duration `yaml:"cache"`
	// InternalServers 是「内网专用」的 DNS 上游，与 Servers 分开。
	//
	// 为什么必须分开：两边各错一半，混在一个列表里就是拼延迟。
	// 实测（公司内网 + 公网双栈，目标 yfjira.mychery.com）：
	//
	//	127.0.0.53（公司 DNS） -> 172.25.51.92   （内网真实地址）
	//	223.5.5.5（公网）      -> 123.60.194.157 （华为云 WAF 入口，回 418 拦截页）
	//
	// 而两边对**外网**域名同样是各错一半：公司 DNS 把 www.google.com 答成
	// 157.240.7.20（Facebook 段），公网 DNS 对内网域名也答不对。
	// 混在一起时"任一成功即采用"等于谁先回来谁说了算，30 次实测内网地址只赢 20 次，
	// 剩下 1/3 的失败还会被 TTL 缓存黏住 5 分钟。
	//
	// 分层之后：内网域名只问内网上游，公网域名只问公网上游，不存在竞速。
	InternalServers []string `yaml:"internal_servers"`
	// InternalDomains 是走内网上游的域名后缀（如 ".mychery.com"）。
	//
	// 必须显式给：解析器不猜"这个域名算不算内网"。若配了 internal_servers
	// 却没有这一项，内网分层不会生效（解析器会报错，避免"以为配好了其实没生效"）。
	InternalDomains []string `yaml:"internal_domains"`
	// TunnelResolve 决定「IP/GEOIP 规则触发的那次解析」是否经当前节点去问上游。
	// **默认关闭**，而且建议保持关闭——见下面那条实测。
	//
	// 直觉上「从节点那一侧问上游能避开污染」是对的，但它搞错了 GEOIP 规则要的是什么：
	// geo-CDN 按提问者的位置给答案，两个答案都合法，只是属于不同的观察者。
	// 2026-10-16 本机实测（规则集 GEOIP,CN,DIRECT + FINAL,PROXY，目标 www.qq.com）：
	//
	//	开：节点视角给出 43.159.109.55（腾讯云**海外**段）→ GEOIP,CN 判不中 → 落 FINAL=PROXY
	//	关：本机视角给出 101.91.22.57 / 101.91.42.232（腾讯深圳段）→ GEOIP,CN 命中 → DIRECT
	//
	// 开启它等于把国内流量白白塞进隧道，比不改更糟。
	// 真正需要防污染的域名走的是域名规则，而判成 PROXY 的连接根本不解析——
	// 域名原样交给节点远端解析（见 README §5），污染压根进不了那条判定。
	TunnelResolve *bool `yaml:"tunnel_resolve"`
}

// InternalEnabled 是内网分层是否启用的读法。
func (d DNSConfig) InternalEnabled() bool {
	return len(d.InternalServers) > 0 && len(d.InternalDomains) > 0
}

// TunnelResolveOn 是显式开启的读法：没写或写 false 都不走隧道。
func (d DNSConfig) TunnelResolveOn() bool {
	return d.TunnelResolve != nil && *d.TunnelResolve
}

// LogConfig 控制日志级别。
type LogConfig struct {
	Level string `yaml:"level"`
}

// SysProxyConfig 控制「系统代理」走哪条路。
type SysProxyConfig struct {
	// Backend 是 auto | gnome | kde | env。留空即 auto（按覆盖面依次探测）。
	//
	// 写死它的意义在于"探测本身会错"：D-Bus 卡住、桌面会话刚起来、
	// 精简装的 KDE 缺 gsettings——这时候用户比程序更清楚该走哪条。
	Backend string `yaml:"backend"`
}

// IfaceSplitConfig 是「两张无线都在时按网卡分流」的开关。
//
// 打开后在**规则模式**下：直连走内置无线，代理（到节点的隧道）走 USB 无线。
// 两张卡能同时连着的时候，这条分流让两张链路各带一部分流量，
// 而不是全部挤在默认路由那一路上。
//
// 直连与代理各由哪张卡承担可以点名（Direct/Proxy），默认是内置给直连、USB 给代理。
// 点了名也不写死：那张卡被拔掉或被换掉时会按它的类别顶上同类的那一张，
// 面板上会把这件事说出来。
//
// **只在两张卡都在时才有意义**：只有一张的时候，把全部流量钉到它上面
// 与交给系统路由表完全等价——那张卡本来就是默认路由。
// 因此探测不到两张卡时开关不会报错，只是照常分发。
//
// **只在规则模式生效**：全局模式下全部流量都走隧道，直连那张卡压根不参与；
// 直连模式下反过来。把分流跟模式绑在一起，切模式时会自动跟着收放。
type IfaceSplitConfig struct {
	Enable bool `yaml:"enable"`
	// Direct 与 Proxy 是用户在面板上点名的两张卡。
	// 两边都留空 = 不点名，走默认的「内置直连、USB 代理」；
	// 只点一边时，另一边照旧按默认挑。
	Direct IfaceCard `yaml:"direct"`
	Proxy  IfaceCard `yaml:"proxy"`
}

// IfaceCard 是点名的那张无线网卡。
type IfaceCard struct {
	// Dev 是接口名（wlp3s0f0 之类）。留空表示这一侧交给程序自动挑。
	Dev string `yaml:"dev"`
	// USB 记下 Dev 那张卡当时是不是插在 USB 口上。
	//
	// 单独存它的理由只有一个：卡被拔掉之后，名字本身就说不出它属于哪一类了，
	// 而「用户要的是这张 USB 卡」这件事必须跨过一次拔插活下来——
	// 换个同类的卡顶上去，而不是被判成没得选、再自动挑到反面那张去。
	USB bool `yaml:"usb"`
}

// SystemProxyTarget 给出「系统代理该指到哪儿」：走哪条后端，以及 http 与 socks5 的监听地址。
//
// -sysproxy on、面板的开关、启动时的孤儿检查三条路必须共用这一份：各自去配置里凑的话，
// 一边用配置里的端口、一边用写死的默认端口，
// 于是「桌面明明指着我们」会被读成「和我们无关」——恰恰漏掉最该报警的那一种。
// 配置里没有某一种入站时留空，由 sysproxy 按本机默认入站补齐。
func (c Config) SystemProxyTarget() (backend, http, socks string) {
	backend = strings.TrimSpace(c.SysProxy.Backend)
	for _, in := range c.Inbounds {
		listen := strings.TrimSpace(in.Listen)
		switch in.Type {
		case "http":
			if http == "" {
				http = listen
			}
		case "socks5":
			if socks == "" {
				socks = listen
			}
		}
	}
	return backend, http, socks
}

// BlockConfig 是拦截名单：命中的域名不许出网。
type BlockConfig struct {
	// Domains 按**后缀**拦（含子域）：写 ads.example.com 会连
	// api.ads.example.com 一起拦掉。方向是刻意选的——黑名单漏拦比误拦更难被发现。
	// 要精确匹配单个域名，请用规则文件写 `DOMAIN,xxx,REJECT`。
	Domains []string `yaml:"domains,omitempty"`
}

// validate 挡住那些"看起来像域名、实际会拦下一切"的写法。
//
// 每一项都只在填了名单时才校验；空名单是合法配置（默认不拦任何东西）。
func (b BlockConfig) validate() error {
	for i, raw := range b.Domains {
		if _, err := NormalizeBlockDomain(raw); err != nil {
			return fmt.Errorf("block.domains[%d]: %w", i, err)
		}
	}
	return nil
}

// NormalizeBlockDomain 抹平一个拦截域名并挡掉危险的写法，返回归一化后的形式。
//
// 导出来是为了让「加载配置时的校验」和「面板里点添加」走同一套规则：
// 两处各写一份，迟早会出现文件里能写、界面里不让点（或反过来）的域名。
func NormalizeBlockDomain(raw string) (string, error) {
	d := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
	if d == "" {
		return "", errors.New("是空项；空域名归一化后是空后缀，等于拦下所有域名")
	}
	if strings.ContainsAny(d, "@/ :#,") {
		return "", fmt.Errorf("%q 不像域名：这里只收裸域名（含子域自动生效），不要带协议、路径、端口或 IP 段", raw)
	}
	// 单标签不是错（localhost 就合法），但粘进 "example" 这种会拦下一整片同名主机。
	// 报错太吵，交给使用方自己决定，这里只挡真正危险的写法。
	return d, nil
}

// Duration 接受 "3s" 这类字符串，也接受纯数字（按秒）。
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	s := strings.TrimSpace(value.Value)
	if s == "" {
		d.Duration = 0
		return nil
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		d.Duration = time.Duration(n * float64(time.Second))
		return nil
	}
	pd, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = pd
	return nil
}

// MaxTx 返回上传速率（字节/秒），空或 "0" 表示交给服务端/拥塞控制自动决定。
func (b BandwidthConfig) MaxTx() (uint64, error) { return ParseBandwidth(b.Up) }

// MaxRx 返回下载速率（字节/秒）。
func (b BandwidthConfig) MaxRx() (uint64, error) { return ParseBandwidth(b.Down) }

var bandwidthUnits = []struct {
	suffix string
	scale  float64
}{
	{"tbps", 1e12 / 8},
	{"gbps", 1e9 / 8},
	{"mbps", 1e6 / 8},
	{"kbps", 1e3 / 8},
	{"bps", 1.0 / 8}, // 注意：写 1/8 会被 Go 当成整数除法而得到 0
	{"t", 1e12 / 8},
	{"g", 1e9 / 8},
	{"m", 1e6 / 8},
	{"k", 1e3 / 8},
}

// ParseBandwidth 把带宽描述转成字节/秒（core/v2 的 BandwidthConfig 单位）。
// 支持 "200 mbps"、"100Mbps"、"1 gbps"、"500 kbps" 等写法；
// 无单位的纯数字沿用 hysteria 的习惯，视为 Mbps（"1000" = 1000 mbps）。
// 空串或 "0" 返回 0，表示不限制。
func ParseBandwidth(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	for _, u := range bandwidthUnits {
		if strings.HasSuffix(s, u.suffix) {
			num := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			return scaleToBytes(num, u.scale)
		}
	}
	// 无后缀：纯数字按 hysteria 惯例视为 Mbps。
	return scaleToBytes(s, 1e6/8)
}

func scaleToBytes(num string, scale float64) (uint64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid bandwidth %q: %w", num, err)
	}
	if v < 0 || math.IsNaN(v) {
		return 0, fmt.Errorf("invalid bandwidth value %v", v)
	}
	b := v * scale
	if b > math.MaxUint64 {
		return 0, fmt.Errorf("bandwidth overflow: %v", b)
	}
	return uint64(b), nil
}

// sizeUnits 从最长后缀开始匹配：HasSuffix("1gib", "b") 也是真，
// 先试 "b" 会把数字切成 "1gi" 而后报一个看不懂的错。
//
// 这里刻意不收 "mbits" 这类比特单位：配额是字节数，收进来只会让人把
// 800Mbit 写成 800MB 而差 8 倍。带宽那一头有 ParseBandwidth 管。
var sizeUnits = []struct {
	suffix string
	scale  uint64
}{
	{"kib", 1 << 10}, {"mib", 1 << 20}, {"gib", 1 << 30}, {"tib", 1 << 40}, {"pib", 1 << 50},
	{"kb", 1e3}, {"mb", 1e6}, {"gb", 1e9}, {"tb", 1e12}, {"pb", 1e15},
	{"k", 1e3}, {"m", 1e6}, {"g", 1e9}, {"t", 1e12}, {"p", 1e15},
	{"b", 1},
}

// ParseSize 把"100 GB"、"1.5TiB"、"500m"这类写法转成字节数。
//
// 为什么收的是字符串而不是整数：配额是人从服务商页面上抄下来的，
// 那一页写的是 "1000 GB"。要人自己换算成 1000000000000 并数对零，
// 错的那一位不会报错，只会让百分比悄悄差一千倍。
//
// 十进制与二进制是分开的两件事，所以两套后缀都给且各有含义：
// GB = 10^9、GiB = 2^30。服务商两种都在用，猜哪一种都是错的。
// 无单位的纯数字按字节算（"100" = 100 字节）——它是唯一不需要约定的读法。
// 空串返回 0，表示"没设配额"。
func ParseSize(s string) (uint64, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "" {
		return 0, nil
	}
	for _, u := range sizeUnits {
		if !strings.HasSuffix(t, u.suffix) {
			continue
		}
		num := strings.TrimSpace(strings.TrimSuffix(t, u.suffix))
		if num == "" {
			return 0, fmt.Errorf("invalid size %q: 只有单位没有数字", s)
		}
		return scaleSize(s, num, u.scale)
	}
	// 无后缀：按字节。
	return scaleSize(s, t, 1)
}

func scaleSize(orig, num string, scale uint64) (uint64, error) {
	v, err := strconv.ParseFloat(num, 64)
	if err != nil {
		return 0, fmt.Errorf(`invalid size %q: %w（认得的写法是 100GB / 1.5TiB / 500m / 裸字节数）`, orig, err)
	}
	if v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("invalid size value %q", orig)
	}
	b := v * float64(scale)
	if b > math.MaxUint64 {
		return 0, fmt.Errorf("size overflow: %q", orig)
	}
	return uint64(b), nil
}

// MarshalYAML 让 Duration 以 "3s" 的字符串形式写出。
//
// 没有它的话 yaml 会把内嵌的 time.Duration（int64 纳秒）当成裸数字输出，
// 而 UnmarshalYAML 会把纯数字按「秒」解释——300000000000 读回来变成 300000000000 秒，
// 配置直接跑偏。这是 Save 能安全回写的前提。
func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

// BackupSuffix 是 Save 备份旧配置时追加的文件名后缀。
const BackupSuffix = ".bak"

// OrigSuffix 保存"第一次被面板回写之前"的那份文件，且之后永不覆盖。
// .bak 每次保存都会被上一版盖掉；连续点几次面板，手写注释就只剩 .orig 一份。
const OrigSuffix = ".orig"

// Save 校验配置后写回磁盘。
//
// GUI 允许在线改配置，写坏一次就够停机了，因此这里做三件事：
//  1. 先 Validate，非法配置根本落不了盘；
//  2. 原文件先备份成 <path>.bak，写坏了还能从备份里救回来；
//  3. 先写同目录临时文件再 rename，避免写到一半崩溃留下半个 yaml。
//
// 权限固定为 0600：配置里存着 server.auth 与入站口令，比原文件常见的 0644 紧。
func Save(path string, c *Config) error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	// Validate 会顺手补上 sni 等默认值，因此对已加载的配置是安全的。
	if err := c.Validate(); err != nil {
		return err
	}
	body, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	existed := false
	if _, statErr := os.Stat(path); statErr == nil {
		existed = true
	}
	if err := backup(path); err != nil {
		return err
	}
	if existed {
		// 整表 marshal 不保留注释；至少把"为什么注释没了、原件在哪"写在文件头上，
		// 而不是让人对着一个变干净的文件猜。
		body = append(rewriteHeader(path), body...)
	}

	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp next to %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer func() {
		// rename 成功后这里是 no-op；失败则清掉半成品，避免堆垃圾。
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(body); err != nil {
		return fmt.Errorf("write %s: %w", tmpName, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpName, err)
	}
	// 保住原文件的属主。以 root 运行的面板如果直接留下 root:root 0600，
	// 用户自己就打不开也改不了这份配置了——rename 会换 inode，
	// 所以必须在换名字之前把 uid/gid 显式设回去。
	if st, statErr := os.Stat(path); statErr == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			if chErr := os.Chown(tmpName, int(sys.Uid), int(sys.Gid)); chErr != nil && os.Geteuid() == 0 {
				return fmt.Errorf("还原 %s 属主失败: %w", tmpName, chErr)
			}
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", tmpName, path, err)
	}
	return nil
}

// restoreBackupOwner 把 root 面板新建的备份文件还给桌面用户。
//
// 配置本体在 Save 里已经保住原属主，但 .orig / .bak 是新建 inode：
// root 跑一次面板就会留下 root:root 0600 的备份，普通用户既读不到也覆盖不了，
// 下次保存会在“备份”这一步失败。失败只告警，不推翻已经写好的配置。
func restoreBackupOwner(path string) {
	if err := sudoown.ToDesktopUser(path); err != nil {
		logx.Warnf("把配置备份 %s 的属主还给桌面用户失败: %v", path, err)
	}
}

// backup 把当前文件另存为 <path>.bak，并在第一次保存时留下 <path>.orig。
// 文件不存在时不算错误（首次保存）。
func backup(path string) error {
	old, err := os.ReadFile(path)
	switch {
	case err == nil:
		// .orig 用 O_EXCL 只建一次：并发保存或连续点击都不会把第一份原件盖掉。
		orig := path + OrigSuffix
		f, oerr := os.OpenFile(orig, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		switch {
		case oerr == nil:
			if _, werr := f.Write(old); werr != nil {
				_ = f.Close()
				_ = os.Remove(orig)
				return fmt.Errorf("写原始备份 %s: %w", orig, werr)
			}
			if cerr := f.Close(); cerr != nil {
				_ = os.Remove(orig)
				return fmt.Errorf("关闭原始备份 %s: %w", orig, cerr)
			}
			restoreBackupOwner(orig)
		case errors.Is(oerr, os.ErrExist):
			// 已经有一份原件了，按约定不再覆盖；顺手把历史 root 属主收回来。
			restoreBackupOwner(orig)
		default:
			return fmt.Errorf("创建原始备份 %s: %w", orig, oerr)
		}
		if err := os.WriteFile(path+BackupSuffix, old, 0o600); err != nil {
			return fmt.Errorf("backup %s: %w", path+BackupSuffix, err)
		}
		restoreBackupOwner(path + BackupSuffix)
		return nil
	case errors.Is(err, os.ErrNotExist):
		return nil
	default:
		return fmt.Errorf("read %s: %w", path, err)
	}
}

// rewriteHeader 是面板整表回写后加在文件头的两行说明。
func rewriteHeader(path string) []byte {
	return []byte(fmt.Sprintf(
		"# 本文件由 wps_app 于 %s 回写；面板不保留 YAML 注释。\n"+
			"# 首次回写前的原件保留在 %s（之后不再覆盖）。\n",
		time.Now().Format("2006-01-02 15:04:05"), filepath.Base(path+OrigSuffix)))
}

// Load 读取并校验配置文件。
//
// 解码刻意开了 KnownFields：未知字段直接报错，而不是被静默忽略。
//
// 代理客户端的配置是要手工编辑的，而「静默忽略」在这里的代价特别高：
// 把 rules_file 拼成 rule_file、把 fake_ip_range 拼成 fakeip_range，
// 程序不吭一声地照默认值跑——表现是「规则不生效、全量走 FINAL=PROXY」，
// 而日志与界面上一切正常。用户几乎不可能自己联想到是哪个键拼错了。
// 报错里带行号，直接就能定位。
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() error {
	if c.DNS.Timeout.Duration == 0 {
		c.DNS.Timeout.Duration = 3 * time.Second
	}
	if c.DNS.Cache.Duration == 0 {
		c.DNS.Cache.Duration = 300 * time.Second
	}
	if len(c.DNS.Servers) == 0 {
		c.DNS.Servers = []string{"223.5.5.5", "119.29.29.29"}
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.RulesFile == "" {
		c.RulesFile = "./assets/rules.txt"
	}
	if c.GeoIP.Path == "" {
		c.GeoIP.Path = "./assets/geoip.mmdb"
	}
	if c.Mode == "" {
		c.Mode = string(ModeRule)
	}
	def := DefaultTUN()
	if c.TUN.Device == "" {
		c.TUN.Device = def.Device
	}
	if c.TUN.Address == "" {
		c.TUN.Address = def.Address
	}
	if c.TUN.MTU == 0 {
		c.TUN.MTU = def.MTU
	}
	if c.TUN.FakeIPRange == "" {
		c.TUN.FakeIPRange = def.FakeIPRange
	}
	if c.TUN.IPv6On() {
		if c.TUN.Address6 == "" {
			c.TUN.Address6 = def.Address6
		}
		if c.TUN.FakeIPRange6 == "" {
			c.TUN.FakeIPRange6 = def.FakeIPRange6
		}
	}
	if c.TUN.HijackDNS == nil {
		c.TUN.HijackDNS = def.HijackDNS
	}
	if c.TUN.DNS == "" {
		c.TUN.DNS = secondHost(c.TUN.Address)
	}
	// nil 与空切片在 yaml 里都会写成 []，但 reflect.DeepEqual 分得出来。
	// 归一成空切片，Save→Load 的等价性才有保证。
	if c.TUN.RouteExclude == nil {
		c.TUN.RouteExclude = []string{}
	}
	if c.RuleProviders == nil {
		c.RuleProviders = []RuleProvider{}
	}
	// helper 是可选段：没配、配成 []、配成空都归一成 nil。
	// 它带 omitempty，不归一的话 Save→Load 会把 [] 变成缺失键，等价性就破了。
	if len(c.TUN.Helper) == 0 {
		c.TUN.Helper = nil
	}
	// 内网分层同理：两个字段都带 omitempty，且**成对**参与判定
	// （InternalEnabled 要求两个都非空）。归一成 nil 而不是空切片，
	// 否则 Save→Load 之后 nil 变 []，reflect.DeepEqual 立刻失败——
	// 而那份"前/后不等价"的报错会把真正的问题（空切片与 nil 的区别）
	// 埋在一大坨结构体打印里。
	if len(c.DNS.InternalServers) == 0 {
		c.DNS.InternalServers = nil
	}
	if len(c.DNS.InternalDomains) == 0 {
		c.DNS.InternalDomains = nil
	}
	for i := range c.Inbounds {
		if c.Inbounds[i].Type == "socks5" && c.Inbounds[i].Listen == "" {
			c.Inbounds[i].Listen = "127.0.0.1:7891"
		}
	}
	return c.normalizeProxies()
}

// DefaultProfileName 给没有名字的节点兜一个可读的名字。
func DefaultProfileName(s ServerConfig, index int) string {
	if host, _, err := net.SplitHostPort(strings.TrimSpace(s.Addr)); err == nil && host != "" {
		return host
	}
	if h := strings.TrimSpace(s.Addr); h != "" {
		return h
	}
	return fmt.Sprintf("node-%d", index+1)
}

// normalizeProxies 把节点列表收敛成「一定有一个可用节点」的形态：
// 旧格式的顶层 server: 迁成第一个节点，Active 指不到节点时回落到第一个，
// Active 指不到具体节点时回落到第一个。
func (c *Config) normalizeProxies() error {
	if len(c.Proxies) == 0 && c.LegacyServer != nil && *c.LegacyServer != (ServerConfig{}) {
		// 旧格式：整个 server: 段变成第一个节点。哪怕 addr 是空的也照样迁过来，
		// 否则报错会退化成「一个节点都没有」，用户看不出自己少写了哪一行。
		c.Proxies = []ProxyProfile{{Server: *c.LegacyServer}}
	}
	c.LegacyServer = nil
	if len(c.Proxies) == 0 {
		return fmt.Errorf("至少需要一个代理服务（proxies 或旧的 server 段）")
	}
	for i := range c.Proxies {
		p := &c.Proxies[i]
		if strings.TrimSpace(p.Name) == "" {
			p.Name = DefaultProfileName(p.Server, i)
		}
		// sni 缺省值必须补在节点本身。以前它补在「指向当前节点的派生指针」上，
		// 副本和原值就成了两份数据，Validate 之后读到的那份还是空的。
		if p.Server.TLS.SNI == "" {
			if host, _, err := net.SplitHostPort(strings.TrimSpace(p.Server.Addr)); err == nil && host != "" {
				p.Server.TLS.SNI = host
			}
		}
	}
	idx := 0
	if want := strings.TrimSpace(c.Active); want != "" {
		found := -1
		for i := range c.Proxies {
			if c.Proxies[i].Name == want {
				found = i
				break
			}
		}
		if found < 0 {
			return fmt.Errorf("active %q 在 proxies 里不存在", want)
		}
		idx = found
	}
	c.Active = c.Proxies[idx].Name
	return nil
}

// ActiveServer 返回当前选中节点的连接参数，这是读取「该拨哪个服务端」的唯一入口。
// 不给字段而给方法：节点列表才是事实源，缓存下来的副本在下一次切节点时就是过期信息。
func (c *Config) ActiveServer() ServerConfig {
	for _, p := range c.Proxies {
		if p.Name == c.Active {
			return p.Server
		}
	}
	if len(c.Proxies) > 0 {
		return c.Proxies[0].Server
	}
	return ServerConfig{}
}

// ModeValue 返回解析后的分流模式，非法值回落成 rule。
func (c *Config) ModeValue() Mode {
	m, err := ParseMode(c.Mode)
	if err != nil {
		return ModeRule
	}
	return m
}

// MarshalYAML 只写新格式。
//
// Config.Server 是派生值（当前节点），把它再写一遍就成了第二个事实源：
// 旧二进制读 server: 段，新配置读 proxies，两边改一个另一个不变。
// 落盘时统一只留 proxies + active。
func (c *Config) MarshalYAML() (any, error) {
	// 这份手写的字段清单就是配置在磁盘上的**全部**内容。
	// 少列一个字段，用户下一次在界面上点「保存」它就没了——
	// 而且症状极难归因（订阅、参数都像凭空消失）。
	// 加字段时记得同时加进这里。
	type plain struct {
		Proxies       []ProxyProfile   `yaml:"proxies"`
		Active        string           `yaml:"active"`
		Mode          string           `yaml:"mode"`
		Inbounds      []InboundConfig  `yaml:"inbounds"`
		GeoIP         GeoIPConfig      `yaml:"geoip"`
		RulesFile     string           `yaml:"rules_file"`
		RuleProviders []RuleProvider   `yaml:"rule_providers"`
		TUN           TUNConfig        `yaml:"tun"`
		DNS           DNSConfig        `yaml:"dns"`
		SysProxy      SysProxyConfig   `yaml:"sysproxy"`
		IfaceSplit    IfaceSplitConfig `yaml:"iface_split"`
		Block         BlockConfig      `yaml:"block"`
		Log           LogConfig        `yaml:"log"`
	}
	return &plain{
		Proxies:       c.Proxies,
		Active:        c.Active,
		Mode:          c.Mode,
		Inbounds:      c.Inbounds,
		GeoIP:         c.GeoIP,
		RulesFile:     c.RulesFile,
		RuleProviders: c.RuleProviders,
		TUN:           c.TUN,
		DNS:           c.DNS,
		SysProxy:      c.SysProxy,
		IfaceSplit:    c.IfaceSplit,
		Block:         c.Block,
		Log:           c.Log,
	}, nil
}

func (c *Config) Validate() error {
	if err := c.normalizeProxies(); err != nil {
		return err
	}
	if _, err := ParseMode(c.Mode); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(c.Proxies))
	for i := range c.Proxies {
		name := c.Proxies[i].Name
		if _, dup := seen[name]; dup {
			return fmt.Errorf("proxies[%d]: 节点名 %q 重复", i, name)
		}
		seen[name] = struct{}{}
		if err := validateServer(c.Proxies[i].Server); err != nil {
			return fmt.Errorf("proxies %q: %w", name, err)
		}
		// 配额在加载时就判，不留到面板上算百分比时才发现读不出来。
		// 报的是原文不是换算结果：人要改的是自己写的那一行。
		if _, err := ParseSize(c.Proxies[i].Quota); err != nil {
			return fmt.Errorf("proxies %q 的 quota: %w", name, err)
		}
	}
	if err := c.validateTUN(); err != nil {
		return err
	}
	if err := c.validateRuleProviders(); err != nil {
		return err
	}
	if len(c.Inbounds) == 0 {
		return fmt.Errorf("at least one inbound is required")
	}
	for _, in := range c.Inbounds {
		switch in.Type {
		case "socks5", "http":
		default:
			return fmt.Errorf("unknown inbound type %q (want socks5 or http)", in.Type)
		}
		if _, _, err := net.SplitHostPort(in.Listen); err != nil {
			return fmt.Errorf("inbound.listen %q: %w", in.Listen, err)
		}
		if (in.Username == "") != (in.Password == "") {
			return fmt.Errorf("inbound %s (%s): username 与 password 必须同时填写", in.Type, in.Listen)
		}
		if in.Type == "http" && (in.Username != "" || in.Password != "") {
			return fmt.Errorf("inbound %s (%s): http 入站不支持用户名密码认证", in.Type, in.Listen)
		}
	}
	for _, s := range c.DNS.Servers {
		if s == "" {
			return fmt.Errorf("dns.servers contains empty entry")
		}
	}
	// 内网分层只配了一半必须当场报错，而不是被装配层悄悄降级。
	//
	// 这条判据在 dnsx.NewWithInternal 里也有，但 newResolver 是"没启用就
	// 直接走 dnsx.New"的写法：只配 internal_servers 时 InternalEnabled() 为假，
	// 于是永远不会走到那句报错，内网分层按纯公网跑——用户以为配好了，
	// 实际一次都没生效，而症状只是"某些内网服务时好时坏"。
	// 放在 Validate 里，Load 的那一刻就挡住。
	if len(c.DNS.InternalServers) > 0 && len(c.DNS.InternalDomains) == 0 {
		return fmt.Errorf("dns: 配了 internal_servers 却没有 internal_domains，内网分层不会生效——补齐后缀，或把两边都删掉")
	}
	if len(c.DNS.InternalDomains) > 0 && len(c.DNS.InternalServers) == 0 {
		return fmt.Errorf("dns: 配了 internal_domains 却没有 internal_servers，这些域名会照常问公网上游——补齐上游，或把两边都删掉")
	}
	for _, s := range c.DNS.InternalServers {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("dns.internal_servers contains empty entry")
		}
	}
	for _, s := range c.DNS.InternalDomains {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("dns.internal_domains contains empty entry")
		}
	}
	if err := c.validateSysProxy(); err != nil {
		return err
	}
	return c.Block.validate()
}

// validateSysProxy 校验系统代理后端名。
//
// 这里**不**顺带探测那台机器上有没有 gsettings/kioslaverc：探测是运行时的事，
// 配置文件该在「换一台机器也能读」这一点上保持自洽。写错名字必须在启动时挡住，
// 因为拼错的后端名会被当成 auto，界面显示成「自动选的」——
// 而它其实是用户明确指定了、我们没执行的那个。
func (c *Config) validateSysProxy() error {
	b := strings.ToLower(strings.TrimSpace(c.SysProxy.Backend))
	if b == "" {
		return nil
	}
	for _, k := range []string{"auto", "gnome", "kde", "env"} {
		if b == k {
			return nil
		}
	}
	return fmt.Errorf("sysproxy.backend %q 不认识，可选 auto | gnome | kde | env", c.SysProxy.Backend)
}

// validateServer 纯检查，不改配置（按值收）。sni 的缺省补齐在 normalizeProxies 里做——
// 校验函数顺手改数据，最容易造出「校验前后读到不同值」这类 bug。
func validateServer(s ServerConfig) error {
	if strings.TrimSpace(s.Addr) == "" {
		return fmt.Errorf("server.addr is required")
	}
	if strings.TrimSpace(s.Auth) == "" {
		return fmt.Errorf("server.auth is required")
	}
	if _, _, err := net.SplitHostPort(s.Addr); err != nil {
		return fmt.Errorf("server.addr %q: %w", s.Addr, err)
	}
	if _, err := ParseProtocol(s.Type); err != nil {
		return err
	}
	// 带宽与拥塞控制是 hysteria2 独有的参数。trojan 节点里留着它们不报错，
	// 但也不校验：用户从 hy2 节点复制一份改协议时，不该被一堆无关报错挡住。
	if s.Protocol() == ProtocolTrojan {
		return nil
	}
	if _, err := s.Bandwidth.MaxTx(); err != nil {
		return fmt.Errorf("server.bandwidth.up: %w", err)
	}
	if _, err := s.Bandwidth.MaxRx(); err != nil {
		return fmt.Errorf("server.bandwidth.down: %w", err)
	}
	return nil
}

// validateRuleProviders 校验订阅段。名字重复必须在这里挡住：
// 两条订阅默认会落到同一个缓存路径上，后一条会把前一条悄悄覆盖掉。
func (c *Config) validateRuleProviders() error {
	seen := make(map[string]struct{}, len(c.RuleProviders))
	paths := make(map[string]string, len(c.RuleProviders))
	for i, p := range c.RuleProviders {
		name := strings.TrimSpace(p.Name)
		if name == "" {
			return fmt.Errorf("rule_providers[%d]: name 不能为空", i)
		}
		if strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
			return fmt.Errorf("rule_providers %q: name 不能含路径分隔符", name)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("rule_providers[%d]: name %q 重复", i, name)
		}
		seen[name] = struct{}{}

		u := strings.TrimSpace(p.URL)
		switch {
		case u == "":
			return fmt.Errorf("rule_providers %q: url 不能为空", name)
		case !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://"):
			// 放行 file:// 会让「远程」这个前提消失，而用户多半是写错了 scheme；
			// 真要读本地文件，rules_file 的 #include 已经能做。
			return fmt.Errorf("rule_providers %q: url %q 只能以 http:// 或 https:// 开头", name, u)
		}

		// 缓存路径重名同理：两条订阅写同一个文件等于互相覆盖，
		// 而表现是「规则内容随机跳变」，几乎无从排查。
		cp := c.providerPath(p)
		if prev, dup := paths[cp]; dup {
			return fmt.Errorf("rule_providers %q: 缓存路径 %s 与 %q 相同", name, cp, prev)
		}
		paths[cp] = name
	}
	return nil
}

// ProviderPath 返回一条订阅的缓存路径（未指定时按名字推导）。
func (c *Config) ProviderPath(p RuleProvider) string { return c.providerPath(p) }

func (c *Config) providerPath(p RuleProvider) string {
	if v := strings.TrimSpace(p.Path); v != "" {
		return v
	}
	return filepath.Join(filepath.Dir(c.RulesFile), "providers", strings.TrimSpace(p.Name)+".txt")
}

func (c *Config) validateTUN() error {
	t := c.TUN
	// helper 的检查在 enable 之前：空项会让 exec 报一句和配置无关的错，
	// 与其等用户开了 TUN 才发现，不如现在就说清是哪一项。
	for i, arg := range t.Helper {
		if strings.TrimSpace(arg) == "" {
			return fmt.Errorf("tun.helper 第 %d 项是空字符串：argv 里不能有空项", i)
		}
	}
	if !t.Enable {
		// 未启用时只做轻量检查：不因为一段闲置配置把整个客户端拒之门外。
		for _, cidr := range t.RouteExclude {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("tun.route_exclude %q: %w", cidr, err)
			}
		}
		return nil
	}
	if t.Device == "" {
		return fmt.Errorf("tun.device is required")
	}
	if len(t.Device) >= 15 {
		return fmt.Errorf("tun.device %q: 接口名不能超过 %d 字符", t.Device, 15)
	}
	prefix, err := netip.ParsePrefix(t.Address)
	if err != nil {
		return fmt.Errorf("tun.address %q: 需要 CIDR 形式（如 172.19.0.1/30）", t.Address)
	}
	if !prefix.Addr().IsValid() {
		return fmt.Errorf("tun.address %q: 不是合法 IP", t.Address)
	}
	if t.MTU < 576 || t.MTU > 9000 {
		return fmt.Errorf("tun.mtu %d: 合理区间 576~9000", t.MTU)
	}
	if net.ParseIP(t.DNS) == nil {
		return fmt.Errorf("tun.dns %q: 需要 IP 地址", t.DNS)
	}
	fake, err := netip.ParsePrefix(t.FakeIPRange)
	if err != nil {
		return fmt.Errorf("tun.fake_ip_range %q: 需要 CIDR 形式（如 198.18.0.0/15）", t.FakeIPRange)
	}
	if fake.Addr().Is6() != prefix.Addr().Is6() {
		return fmt.Errorf("tun.fake_ip_range %q: 与 tun.address %q 不是同一协议族", t.FakeIPRange, t.Address)
	}
	if fake.Bits() >= 31 {
		return fmt.Errorf("tun.fake_ip_range %q: 网段太小，放不下假 IP", t.FakeIPRange)
	}
	if err := validateTUNv6(t); err != nil {
		return err
	}
	for _, cidr := range t.RouteExclude {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("tun.route_exclude %q: %w", cidr, err)
		}
	}
	return nil
}

// validateTUNv6 校验 v6 那一组。三个段必须两两不相交：
// 网卡地址与假 IP 段重叠的话，假 IP 会被发到网卡的链路层地址上，
// 而反查回来的域名又指回同一个地址——内环，成因极难定位。
func validateTUNv6(t TUNConfig) error {
	if !t.IPv6On() {
		// 关掉时这两个字段根本不参与任何事情，写成什么都不会生效——
		// 那就干脆不校验，免得留下一段「配了但没用」的字段等着骗人。
		return nil
	}
	addr6, err := netip.ParsePrefix(t.Address6)
	if err != nil {
		return fmt.Errorf("tun.address6 %q: 需要 CIDR 形式（如 fd00:1::1/64）", t.Address6)
	}
	if !addr6.Addr().Is6() {
		return fmt.Errorf("tun.address6 %q: 必须是 IPv6 地址", t.Address6)
	}
	fake6, err := netip.ParsePrefix(t.FakeIPRange6)
	if err != nil {
		return fmt.Errorf("tun.fake_ip_range6 %q: 需要 CIDR 形式（如 fc00::/18）", t.FakeIPRange6)
	}
	if !fake6.Addr().Is6() {
		return fmt.Errorf("tun.fake_ip_range6 %q: 必须是 IPv6 网段", t.FakeIPRange6)
	}
	// /33 及更长只剩可数得过来的地址，扣掉网络地址就分不出假 IP 了。
	// 上界取得很宽（2^32 个地址）是因为 v6 段天然就这么大——
	// 别照抄 v4 那个「必须 /30 以内」的直觉，那会把 fc00::/18 这类正常写法判死。
	if fake6.Bits() > 32 {
		return fmt.Errorf("tun.fake_ip_range6 %q: 网段太小，放不下假 IP（需 /32 或更短）", t.FakeIPRange6)
	}
	if fake6.Overlaps(addr6) {
		return fmt.Errorf("tun.fake_ip_range6 %q 与 tun.address6 %q 重叠", t.FakeIPRange6, t.Address6)
	}
	return nil
}

// secondHost 返回某个前缀里「网卡的下一个可用地址」，用作假 DNS 的监听地址。
// 172.19.0.1/30 → 172.19.0.2；网段只有一个可用地址时原样返回。
func secondHost(address string) string {
	prefix, err := netip.ParsePrefix(address)
	if err != nil {
		return ""
	}
	addr := prefix.Addr().Next()
	if !prefix.Contains(addr) {
		return prefix.Addr().String()
	}
	return addr.String()
}
