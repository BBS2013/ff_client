package tunx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"wps_app/internal/logx"
)

// DNSChain 是我们在 nat 表里自建链的名字。
//
// 用自建链而不是往 OUTPUT 里塞两条规则，是为了「一键拆干净」：
// 卸载时只要 -F/-X 这条链，就不会有我们不知道的规则残留在系统里。
const DNSChain = "wps_app_dns"

// Cmd 是一条要执行的系统命令（ip / iptables）。
type Cmd struct {
	Bin  string
	Args []string
	// Desc 用人话说明这一步在干什么，日志与错误里都靠它定位。
	Desc string
	// Optional 为 true 时失败只记警告，不阻断整体流程
	// （典型是卸载路径：规则可能早就不在了）。
	Optional bool
	// TolerateMissingDevice 非空时，"Cannot find device <这个名字>" 视为成功。
	//
	// 它专治拆除路径上那类"看起来失败、其实已经达成"的错：网卡 fd 被协议栈关掉时
	// 非 persistent 的 tun 就消失了，挂在它上面的路由被内核一并收走；
	// 这时再 `ip route del ... dev wps-tun` 必然报设备不存在，
	// 而它说的恰恰就是我们要的结果。照原样返回错误，每次正常停止都会
	// 带着一串"停用失败"，界面上就再也分不出"没停干净"和"本来就干净"。
	// 只认这一个设备名，别的报错一律照旧算失败。
	TolerateMissingDevice string
	// TolerateExists 为 true 时，"File exists" 视为成功。
	// 开启路径必须可重入：想要的东西已经在位，就是我们要的状态本身，
	// 把它当致命错误会让 TUN 永远起不来（上次就是卡在这条上）。
	TolerateExists bool
}

func (c Cmd) String() string {
	return c.Bin + " " + strings.Join(c.Args, " ")
}

// RoutePlan 是给 planner 的输入：把「TUN 要怎么接管系统」描述成纯数据。
type RoutePlan struct {
	Device      string
	Address     string // CIDR，如 172.19.0.1/30
	DNS         string // 劫持落点 IP
	FakeIPRange string
	// Address6/FakeIPRange6/DNS6 是 v6 那一组，留空则整组不生成命令（见 PlanV6）。
	Address6     string
	FakeIPRange6 string
	DNS6         string
	MTU          int
	HijackDNS    bool
	StrictRoute  bool
	// Exclude 是 StrictRoute 下要钉回物理网关的网段（含代理服务端与 DNS 上游，
	// 避免我们自己的出站被 tun 抓回去形成环路）。
	//
	// 里面同时可能有 v4 与 v6 网段：两族必须分开装。v4 的绕行命令是
	// `ip route add <cidr> via <v4 网关> dev <网卡>`，把一个 v6 网段丢进去，
	// 内核会报 invalid gateway；而这条命令失败会直接掀翻整个 TUN 启动——
	// 一个双栈节点就能把整机代理拖下水。
	Exclude []string
	// Gateway/Interface 来自当前 v4 默认路由，StrictRoute 的排除路由要用。
	Gateway   string
	Interface string
	// Gateway6/Interface6 来自当前 v6 默认路由。
	// v6 的网关常常是 fe80:: 开头的链路本地地址（RA 下发），所以要单独记一份：
	// 拿 v4 的网关去钉 v6 的绕行路由，命令直接是非法的。
	Gateway6   string
	Interface6 string
	// UID 是 DNS 劫持要放行的发起者。已不再写进规则（按 uid 豁免会让桌面用户本人
	// 一起被豁免，见 Plan 里的说明），保留是为了日志与残留清理时认得出是谁留下的。
	UID int
	// Upstreams 是本进程真正用来解析的 DNS 上游（IP 字面量）。劫持必须放行发往
	// 它们的查询，否则自己的解析被自己劫持，形成环路。
	Upstreams []string
}

// Plan 生成开启与关闭两组命令。
//
// Down 与 Up 严格互为逆操作，并且按相反顺序执行：先恢复 DNS 再拆网卡，
// 这样中途失败时不会出现「网卡没了但 iptables 还把 53 往黑洞里指」这种
// 让整机解析瘫痪的状态。
func (p RoutePlan) Plan() (up, down []Cmd, err error) {
	if p.Device == "" || p.Address == "" {
		return nil, nil, errors.New("tun: device 与 address 必填")
	}
	// 这一组只管 v4：v6 网段交给 PlanV6Route。混在一起会让 v6 网段生成
	// 一条非法的 v4 命令，而它的失败会掀翻整个 TUN 启动。
	up = append(up,
		Cmd{Bin: "ip", Args: []string{"addr", "add", p.Address, "dev", p.Device}, Desc: "配置网卡地址", TolerateExists: true},
		Cmd{Bin: "ip", Args: []string{"link", "set", "dev", p.Device, "up"}, Desc: "启用网卡"},
	)
	if p.MTU > 0 {
		// 顺序很重要：MTU 要在 link up 之后设置才会生效到链路上。
		up = append(up, Cmd{
			Bin:  "ip",
			Args: []string{"link", "set", "dev", p.Device, "mtu", fmt.Sprint(p.MTU)},
			Desc: "设置 MTU",
		})
	}
	// 非 strict_route 不该有默认路由指向 tun；但上一次 strict_route 的进程
	// 如果没退干净（崩溃、改配置、网卡先消失），`default dev wps-tun` 会留着。
	// 它不会只影响“全局接管”这一件事：所有 IPv4 都会进 tun，连本进程发往
	// dns.servers 的查询也走 tun，于是 DNS 一个上游都答不上。
	// 这里先删一次；Optional 保证正常机器上没有这条路由时静默通过。
	// 2026-11-02 现场：-diag 明确报出“没撤销干净的残留”，而 DNS 失败
	// 147 次、直连域名全部 FINAL(dns-failed)。
	if !p.StrictRoute {
		up = append(up,
			Cmd{Bin: "ip", Args: []string{"route", "del", "default", "dev", p.Device}, Desc: "清理上次严格路由残留（IPv4）", Optional: true},
			Cmd{Bin: "ip", Args: []string{"-6", "route", "del", "default", "dev", p.Device}, Desc: "清理上次严格路由残留（IPv6）", Optional: true},
		)
	}

	if p.FakeIPRange != "" {
		up = append(up, Cmd{
			Bin:            "ip",
			Args:           []string{"route", "add", p.FakeIPRange, "dev", p.Device},
			Desc:           "把假 IP 网段路由进 tun",
			TolerateExists: true,
		})
	}

	if p.HijackDNS {
		if p.DNS == "" {
			return nil, nil, errors.New("tun: 开启 DNS 劫持必须给出 dns 地址")
		}
		srcIP, _, err := net.ParseCIDR(p.Address)
		if err != nil {
			return nil, nil, fmt.Errorf("tun: address %q 不是合法 CIDR: %w", p.Address, err)
		}
		if len(p.Upstreams) == 0 {
			// 没有可放行的上游就绝不能劫持：我们自己的解析会被这条劫持抓回来，
			// 变成「问假 IP 表要一个假 IP」。
			return nil, nil, errors.New("tun: 开启 DNS 劫持要求 dns.servers 至少有一个 IP 字面量作为上游")
		}
		target := fmt.Sprintf("%s:53", p.DNS)
		up = append(up, Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-N", DNSChain}, Desc: "建 DNS 劫持链", Optional: true, TolerateExists: true})
		// 先放行「发往我们自己上游」的查询（RETURN 跳过后面的 DNAT），再劫持其余的。
		//
		// 这里过去写的是 `-m owner ! --uid-owner <本进程 uid>`。面板以 root 跑时它成立：
		// 被豁免的是 root，桌面用户照常分流。换成 tun.helper、面板变成桌面用户本人之后，
		// 被豁免的恰好是我们想服务的那个人——www.google.com 又拿回污染地址 2001::1，
		// TUN 对本人形同关闭。按目的地址豁免才与运行身份无关，而且范围更小：
		// 只放行真正发往上游的那几个地址。
		for _, up0 := range p.Upstreams {
			dst := upstreamCIDR(up0)
			// 同理只放行 v4 上游：配了一个 IPv6 上游（如 2400:3200::1）之后，
			// 原来的写法会把这行原样丢给 iptables，内核直接拒绝整条规则。
			if isV6CIDR(dst) {
				continue
			}
			for _, proto := range []string{"udp", "tcp"} {
				up = append(up, Cmd{
					Bin:  "iptables",
					Args: []string{"-t", "nat", "-A", DNSChain, "-d", dst, "-p", proto, "--dport", "53", "-j", "RETURN"},
					Desc: "放行发往上游 " + dst + " 的 " + strings.ToUpper(proto) + " 查询",
				})
			}
		}
		// 排除 127.0.0.0/8：发给 systemd-resolved stub（127.0.0.53）的查询
		// 源地址也是 127.0.0.1，DNAT 之后要重新选路，而 127/8 的源地址在
		// tun 上不合法，内核直接把这包丢掉——表现是 dig @tun.dns 正常、
		// resolvectl 正常，唯独 glibc/curl 报 Could not resolve host。
		// 让 stub 查询照常交给 resolved，改劫持 resolved 的上游查询：
		// 它的源地址是真实网卡地址，应答回得来，缓存里也就有了假 IP。
		up = append(up,
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-A", DNSChain, "!", "-d", "127.0.0.0/8", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", target}, Desc: "劫持 UDP DNS"},
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-A", DNSChain, "!", "-d", "127.0.0.0/8", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", target}, Desc: "劫持 TCP DNS"},
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-I", "OUTPUT", "1", "-p", "udp", "--dport", "53", "-j", DNSChain}, Desc: "挂载 UDP DNS 劫持"},
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "--dport", "53", "-j", DNSChain}, Desc: "挂载 TCP DNS 劫持"},
			// SNAT 不是可选项：DNAT 只改目的地址，源地址还是发起方的。
			// 应用问的是 127.0.0.53（systemd-resolved 的 stub），源地址就是 127.0.0.1，
			// 我们的应答从 tun 回来时目的是 127.0.0.1——内核按 martian 包直接丢掉，
			// 表现是 dig @tun.dns 正常、resolved 也正常，唯独 glibc/curl 说
			// "Could not resolve host"。把源改成网卡自己的地址，应答就能正常回投，
			// conntrack 再把它还原成 127.0.0.53 交还给应用。
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-A", "POSTROUTING", "-o", p.Device, "-p", "udp", "--dport", "53", "-j", "SNAT", "--to-source", srcIP.String()}, Desc: "回程 SNAT（UDP DNS）"},
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-A", "POSTROUTING", "-o", p.Device, "-p", "tcp", "--dport", "53", "-j", "SNAT", "--to-source", srcIP.String()}, Desc: "回程 SNAT（TCP DNS）"},
		)
	}

	// 这一族没有网关就整组不装，而不是让整个 TUN 起不来：
	// 只有 v6 的网络（没有 v4 默认路由）照样要能用 v6 接管。
	// 「两族都没有」由 buildPlan 拦——那时确实无处可去。
	routeUp, routeDown := p.PlanRoutes()
	up = append(up, routeUp...)

	down = append(down, routeDown...)
	if p.HijackDNS {
		down = append(down,
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", DNSChain}, Desc: "摘掉 UDP 劫持", Optional: true},
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", DNSChain}, Desc: "摘掉 TCP 劫持", Optional: true},
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-F", DNSChain}, Desc: "清空劫持链", Optional: true},
			Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-X", DNSChain}, Desc: "删除劫持链", Optional: true},
		)
		// SNAT 挂在 POSTROUTING 上，不随自建链一起被 -F/-X 清掉，必须逐条删。
		// 漏删的后果是这块网卡名以后被别的程序复用时，DNS 会被莫名改写源地址。
		if srcIP, _, err := net.ParseCIDR(p.Address); err == nil {
			for _, proto := range []string{"udp", "tcp"} {
				down = append(down, Cmd{
					Bin: "iptables",
					Args: []string{"-t", "nat", "-D", "POSTROUTING", "-o", p.Device,
						"-p", proto, "--dport", "53", "-j", "SNAT", "--to-source", srcIP.String()},
					Desc:     "撤销回程 SNAT（" + proto + "）",
					Optional: true,
				})
			}
		}
	}
	if p.FakeIPRange != "" {
		down = append(down, Cmd{Bin: "ip", Args: []string{"route", "del", p.FakeIPRange, "dev", p.Device}, Desc: "撤销假 IP 路由", Optional: true})
	}
	down = append(down,
		Cmd{Bin: "ip", Args: []string{"addr", "del", p.Address, "dev", p.Device}, Desc: "摘掉网卡地址", Optional: true},
		Cmd{Bin: "ip", Args: []string{"link", "set", "dev", p.Device, "down"}, Desc: "关闭网卡", Optional: true},
	)
	// 这三条（撤销假 IP 路由 / 摘地址 / 关网卡）全点名我们的网卡，而拆的顺序是
	// 先销毁协议栈——那一步就把网卡 fd 关掉、设备从内核摘除了，于是它们必然报
	// "Cannot find device"。要的效果其实已经达成（路由随设备一起没了），
	// 不该让它把 Stop 报成失败：面板会说"TUN 已停止但撤销时出错"，
	// 而那句错误既不可恢复也没有任何可补救的东西。
	return up, tolerateGone(down, p.Device), nil
}

// PlanRoutes 只生成「路由」这一部分：绕行路由、组播、默认路由。
//
// 单独拆出来是因为「网络变了要重钉路由」时只能碰这一部分：
// DNS 劫持那条链是用 -A 追加的，重装一遍就会多出一份重复规则，
// 而重复的劫持规则会把 :53 打到不存在的地址上。
//
// 没开 strict_route 时整组为空：绕行路由与组播只有在默认路由被接管时才有意义。
func (p RoutePlan) PlanRoutes() (up, down []Cmd) {
	if !p.StrictRoute {
		return nil, nil
	}
	if p.Gateway == "" || p.Interface == "" {
		return nil, nil
	}
	exclude4, _ := splitExclude(p.Exclude)
	for _, cidr := range exclude4 {
		up = append(up, Cmd{
			Bin:            "ip",
			Args:           []string{"route", "add", cidr, "via", p.Gateway, "dev", p.Interface},
			Desc:           "把 " + cidr + " 钉回物理网关（防环路）",
			TolerateExists: true,
		})
	}
	// 组播不能跟着默认路由进 tun。本机内核默认并不给物理网卡建组播路由，
	// 于是 224.0.0.0/4 会落到默认路由上，被 tun 收走再转发出去——
	// 组播是链路本地流量，出了这张网卡就没有意义，只会让组播应用卡住。
	// 带上 metric 是为了不和内核自己可能存在的组播路由抢同一条：
	// 真有内核路由时它的 metric 更小、优先生效，我们这条形同虚设；
	// 没有时 ours 就是唯一的那条，组播留在物理网卡上。
	up = append(up, Cmd{
		Bin:            "ip",
		Args:           []string{"route", "add", multicastV4, "dev", p.Interface, "metric", multicastMetric},
		Desc:           "把 IPv4 组播留在物理网卡",
		TolerateExists: true,
	})
	up = append(up, Cmd{Bin: "ip", Args: []string{"route", "add", "default", "dev", p.Device}, Desc: "默认路由交给 tun", TolerateExists: true})

	down = append(down, Cmd{
		Bin:  "ip",
		Args: []string{"route", "del", "default", "dev", p.Device},
		Desc: "撤销默认路由",
		// 非 StrictRoute 模式下这条路由本来就不存在，失败是预期内的。
		Optional: !p.StrictRoute,
	})
	down = append(down, Cmd{
		Bin:      "ip",
		Args:     []string{"route", "del", multicastV4, "dev", p.Interface, "metric", multicastMetric},
		Desc:     "撤销 IPv4 组播路由",
		Optional: true,
	})
	for i := len(exclude4) - 1; i >= 0; i-- {
		down = append(down, Cmd{
			Bin:      "ip",
			Args:     []string{"route", "del", exclude4[i], "via", p.Gateway, "dev", p.Interface},
			Desc:     "撤销排除路由 " + exclude4[i],
			Optional: true,
		})
	}
	return up, tolerateGone(down, p.Device)
}

// PlanV6 生成 IPv6 那一组命令，与 Plan 的 v4 组完全分开。
//
// 分开是因为两组的失败后果不对等：v4 配不上，TUN 本来就起不来，早失败是好事；
// 而 v6 配不上（多半是内核没有 ip6table_nat）完全可以只放弃 v6，
// 让 AAAA 退回 NODATA、应用改走 A 记录。把两者混在一张列表里，
// 一条 ip6tables 失败就会把整个 TUN 拖下水。
// v6FakeIPUsable 报告这台机器的假 v6 该不该发出去。
//
// 假地址只解决「应用连到哪」，真把包送出去还得本机有 v6 出口（Gateway6 来自
// 本机当前那条 v6 默认路由）。没有出口时发假 v6 等于给应用一个拨不通的地址：
// 应用不会退回 A 记录，只会一直重试到超时——比回 NODATA 难查得多。
// 2026-10-29 在这台机器上撞到过：USB 网卡（带全局 v6）掉线的那段时间，
// 假 v6 照发，而启动日志却在承诺「路由装不上时降级为 NODATA（不声称可用）」。
func (p RoutePlan) v6FakeIPUsable() bool {
	return p.Device != "" && p.Address6 != "" && p.FakeIPRange6 != "" && p.Gateway6 != ""
}

func (p RoutePlan) PlanV6() (up, down []Cmd, err error) {
	if p.Device == "" || p.Address6 == "" || p.FakeIPRange6 == "" {
		return nil, nil, nil
	}
	if _, _, err := net.ParseCIDR(p.Address6); err != nil {
		return nil, nil, fmt.Errorf("tun: address6 %q 不是合法 CIDR: %w", p.Address6, err)
	}
	up = append(up,
		Cmd{Bin: "ip", Args: []string{"-6", "addr", "add", p.Address6, "dev", p.Device}, Desc: "配置网卡 IPv6 地址", TolerateExists: true},
		Cmd{Bin: "ip", Args: []string{"-6", "route", "add", p.FakeIPRange6, "dev", p.Device}, Desc: "把 IPv6 假 IP 网段路由进 tun", TolerateExists: true},
	)

	if p.HijackDNS && p.DNS6 != "" {
		if len(p.Upstreams) == 0 {
			// 与 v4 同理：没有可放行的上游就不能劫持，否则我们自己的解析会被自己抓回来。
			return nil, nil, errors.New("tun: 开启 DNS 劫持要求 dns.servers 至少有一个 IP 字面量作为上游")
		}
		srcIP, _, err := net.ParseCIDR(p.Address6)
		if err != nil {
			return nil, nil, fmt.Errorf("tun: address6 %q 不是合法 CIDR: %w", p.Address6, err)
		}
		target := fmt.Sprintf("[%s]:53", p.DNS6)
		up = append(up, Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-N", DNSChain}, Desc: "建 IPv6 DNS 劫持链", Optional: true, TolerateExists: true})
		for _, up0 := range p.Upstreams {
			dst := upstreamCIDR(up0)
			// 只放行 v6 上游：v4 上游在 ip6tables 里没有对应路由，
			// 照抄过去会让整条规则加不上（内核实战后立即拒绝）。
			if !isV6CIDR(dst) {
				continue
			}
			for _, proto := range []string{"udp", "tcp"} {
				up = append(up, Cmd{
					Bin:  "ip6tables",
					Args: []string{"-t", "nat", "-A", DNSChain, "-d", dst, "-p", proto, "--dport", "53", "-j", "RETURN"},
					Desc: "放行发往上游 " + dst + " 的 " + strings.ToUpper(proto) + " 查询",
				})
			}
		}
		up = append(up,
			// 与 v4 同理排除 ::1/128：systemd-resolved 的 v6 stub 就在 ::1。
			// DNAT 只改目的地址，源仍是 ::1，这个包在 tun 上属于非法源，
			// 会被内核按 martian 丢掉——表现和 v4 那次一模一样：
			// dig @tun.dns 正常，唯独 curl 报 Could not resolve host。
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-A", DNSChain, "!", "-d", "::1/128", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", target}, Desc: "劫持 UDP DNS（IPv6）"},
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-A", DNSChain, "!", "-d", "::1/128", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", target}, Desc: "劫持 TCP DNS（IPv6）"},
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-I", "OUTPUT", "1", "-p", "udp", "--dport", "53", "-j", DNSChain}, Desc: "挂载 UDP DNS 劫持（IPv6）"},
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-I", "OUTPUT", "1", "-p", "tcp", "--dport", "53", "-j", DNSChain}, Desc: "挂载 TCP DNS 劫持（IPv6）"},
			// 回程 SNAT 与 v4 同理且不可省：DNAT 只改目的地址，
			// 应答从 tun 回来时源仍是发起方的全局地址，内核按 martian 丢掉。
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-A", "POSTROUTING", "-o", p.Device, "-p", "udp", "--dport", "53", "-j", "SNAT", "--to-source", srcIP.String()}, Desc: "回程 SNAT（UDP DNS / IPv6）"},
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-A", "POSTROUTING", "-o", p.Device, "-p", "tcp", "--dport", "53", "-j", "SNAT", "--to-source", srcIP.String()}, Desc: "回程 SNAT（TCP DNS / IPv6）"},
		)
	}

	down = append(down, Cmd{Bin: "ip", Args: []string{"-6", "route", "del", p.FakeIPRange6, "dev", p.Device}, Desc: "撤销 IPv6 假 IP 路由", Optional: true})
	if p.HijackDNS && p.DNS6 != "" {
		down = append(down,
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", DNSChain}, Desc: "摘掉 UDP 劫持（IPv6）", Optional: true},
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", DNSChain}, Desc: "摘掉 TCP 劫持（IPv6）", Optional: true},
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-F", DNSChain}, Desc: "清空 IPv6 劫持链", Optional: true},
			Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-X", DNSChain}, Desc: "删除 IPv6 劫持链", Optional: true},
		)
		if srcIP, _, err := net.ParseCIDR(p.Address6); err == nil {
			for _, proto := range []string{"udp", "tcp"} {
				down = append(down, Cmd{
					Bin:      "ip6tables",
					Args:     []string{"-t", "nat", "-D", "POSTROUTING", "-o", p.Device, "-p", proto, "--dport", "53", "-j", "SNAT", "--to-source", srcIP.String()},
					Desc:     "撤销回程 SNAT（" + proto + " / IPv6）",
					Optional: true,
				})
			}
		}
	}
	down = append(down, Cmd{Bin: "ip", Args: []string{"-6", "addr", "del", p.Address6, "dev", p.Device}, Desc: "摘掉网卡 IPv6 地址", Optional: true})
	return up, tolerateGone(down, p.Device), nil
}

func isV6CIDR(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	return err == nil && p.Addr().Is6()
}

// 组播网段与它们被钉住时用的 metric。
//
// metric 不取 0 是为了不和内核自己可能存在的组播路由撞成同一条：
// 内核那条 metric 更小、优先生效，我们这条形同虚设；内核没有时，
// 我们这条就是唯一的那条，组播因此留在物理网卡上而不会跟着默认路由进 tun。
const (
	multicastV4     = "224.0.0.0/4"
	multicastV6     = "ff00::/8"
	multicastMetric = "1000"
)

// splitExclude 把排除网段按地址族拆开。
//
// 必须拆的原因：v4 的绕行命令是 `ip route add <cidr> via <v4 网关> dev <网卡>`，
// v6 的是 `ip -6 route add <cidr> via <v6 网关> dev <网卡>`。
// 一个双栈节点解析出来的 v6 地址混进 v4 那组，内核会报 invalid gateway，
// 而这条命令失败会直接掀翻整个 TUN 启动——整机代理为一个节点的地址陪葬。
//
// 解析不了的条目直接丢掉：它们既装不进 v4 也装不进 v6，
// 留着只会让某条命令带着垃圾参数去见内核。
func splitExclude(in []string) (v4, v6 []string) {
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			addr := p.Addr()
			switch {
			case addr.Is4():
				v4 = append(v4, p.String())
			case addr.Is4In6():
				// 4in6（::ffff:a.b.c.d）要转回 v4 形式，
				// 原样交给 ip 会被当成 v6 网段，落到另一组里去。
				v4 = append(v4, addr.Unmap().String()+"/32")
			default:
				v6 = append(v6, p.String())
			}
			continue
		}
		// 配置里也允许写裸 IP。
		if addr, err := netip.ParseAddr(raw); err == nil {
			if addr.Is4() || addr.Is4In6() {
				v4 = append(v4, addr.Unmap().String()+"/32")
			} else {
				v6 = append(v6, addr.String()+"/128")
			}
		}
	}
	return v4, v6
}

// v6Gateway 规整 v6 网关的写法。
//
// 曾经给它加过 %网卡 的 zone 后缀（fe80::5%wlp3s0f0），那是错的：
// iproute2 的 `via` 参数只认纯地址，带 zone 会报
// "inet6 address is expected rather than fe80::5%wlp3s0f0"，整条规则加不上。
// 出口网卡由命令里的 dev 指明，zone 本来就是多余的。
func v6Gateway(gateway, iface string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(gateway))
	if err != nil {
		return gateway
	}
	return addr.String()
}

// PlanV6Route 生成 IPv6 全局接管的命令：把 v6 绕行路由钉回物理网关，
// 再把 v6 默认路由交给 tun。
//
// 单独成组而不是并进 PlanV6，是因为两者的失败后果必须分开说：
//   - v6 假 IP / DNS 劫持失败 → AAAA 回 NODATA，应用退回 A 记录，照样能用；
//   - v6 默认路由接管失败 → v6 流量根本没进 tun，界面必须如实说「v6 没被接管」。
//
// 混成一组就只剩一个真假值，用户分不清是哪一半没成。
//
// 没有 v6 网关时整组不生成命令：此时钉不回绕行路由，
// 装上 v6 默认路由就会把我们自己发往 v6 节点的包也抓回来，形成环路。
func (p RoutePlan) PlanV6Route() (up, down []Cmd, err error) {
	if !p.StrictRoute || p.Address6 == "" {
		return nil, nil, nil
	}
	if p.Gateway6 == "" || p.Interface6 == "" {
		return nil, nil, nil
	}
	_, exclude6 := splitExclude(p.Exclude)
	gateway := v6Gateway(p.Gateway6, p.Interface6)
	for _, cidr := range exclude6 {
		up = append(up, Cmd{
			Bin:            "ip",
			Args:           []string{"-6", "route", "add", cidr, "via", gateway, "dev", p.Interface6},
			Desc:           "把 " + cidr + " 钉回物理网关（IPv6 防环路）",
			TolerateExists: true,
		})
	}
	up = append(up, Cmd{
		Bin:            "ip",
		Args:           []string{"-6", "route", "add", multicastV6, "dev", p.Interface6, "metric", multicastMetric},
		Desc:           "把 IPv6 组播留在物理网卡",
		TolerateExists: true,
	})
	up = append(up, Cmd{
		Bin:            "ip",
		Args:           []string{"-6", "route", "add", "default", "dev", p.Device},
		Desc:           "IPv6 默认路由交给 tun",
		TolerateExists: true,
	})

	down = append(down, Cmd{
		Bin:      "ip",
		Args:     []string{"-6", "route", "del", "default", "dev", p.Device},
		Desc:     "撤销 IPv6 默认路由",
		Optional: true,
	})
	down = append(down, Cmd{
		Bin:      "ip",
		Args:     []string{"-6", "route", "del", multicastV6, "dev", p.Interface6, "metric", multicastMetric},
		Desc:     "撤销 IPv6 组播路由",
		Optional: true,
	})
	for i := len(exclude6) - 1; i >= 0; i-- {
		down = append(down, Cmd{
			Bin:      "ip",
			Args:     []string{"-6", "route", "del", exclude6[i], "via", gateway, "dev", p.Interface6},
			Desc:     "撤销 IPv6 排除路由 " + exclude6[i],
			Optional: true,
		})
	}
	return up, tolerateGone(down, p.Device), nil
}

// StaleCleanup 生成清理历史残留的命令。device/address 用来删掉可能遗留的 SNAT。
//
// 进程被 kill -9 时我们的 defer 不会跑，iptables 劫持规则会留在系统里，
// 而它指向的假 DNS 地址随网卡一起消失了——后果是本机解析全部超时。
// 所以每次启动都先无条件清一遍，把「上次没关干净」这个前提消掉。
func StaleCleanup(uid int, device, address string) []Cmd {
	_ = uid
	cmds := []Cmd{
		Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", DNSChain}, Desc: "清理残留 UDP 劫持", Optional: true},
		Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", DNSChain}, Desc: "清理残留 TCP 劫持", Optional: true},
		Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-F", DNSChain}, Desc: "清理残留劫持链", Optional: true},
		Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-X", DNSChain}, Desc: "删除残留劫持链", Optional: true},
	}
	// SNAT 不在自建链里，-F/-X 清不掉，只能按内容逐条删。
	if srcIP, _, err := net.ParseCIDR(address); err == nil && device != "" {
		for _, proto := range []string{"udp", "tcp"} {
			cmds = append(cmds, Cmd{
				Bin: "iptables",
				Args: []string{"-t", "nat", "-D", "POSTROUTING", "-o", device,
					"-p", proto, "--dport", "53", "-j", "SNAT", "--to-source", srcIP.String()},
				Desc:     "清理残留 SNAT（" + proto + "）",
				Optional: true,
			})
		}
	}
	return cmds
}

// StaleCleanup6 是 StaleCleanup 的 IPv6 版本。两条链同名（DNSChain），
// 但分别住在 iptables 与 ip6tables 里，互不影响。
func StaleCleanup6(uid int, device, address6 string) []Cmd {
	_ = uid
	cmds := []Cmd{
		Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", DNSChain}, Desc: "清理残留 UDP 劫持（IPv6）", Optional: true},
		Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", DNSChain}, Desc: "清理残留 TCP 劫持（IPv6）", Optional: true},
		Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-F", DNSChain}, Desc: "清理残留劫持链（IPv6）", Optional: true},
		Cmd{Bin: "ip6tables", Args: []string{"-t", "nat", "-X", DNSChain}, Desc: "删除残留劫持链（IPv6）", Optional: true},
	}
	if srcIP, _, err := net.ParseCIDR(address6); err == nil && device != "" {
		for _, proto := range []string{"udp", "tcp"} {
			cmds = append(cmds, Cmd{
				Bin: "ip6tables",
				Args: []string{"-t", "nat", "-D", "POSTROUTING", "-o", device,
					"-p", proto, "--dport", "53", "-j", "SNAT", "--to-source", srcIP.String()},
				Desc:     "清理残留 SNAT（" + proto + " / IPv6）",
				Optional: true,
			})
		}
	}
	return cmds
}

// sweepOutputJump 按内容扫一遍某张表的 OUTPUT，把挂着 chain 的跳转**逐条**摘掉，返回摘掉的描述。
//
// 为什么 -D 一次不够：重复装载（上一个进程没清残留、或者装到一半崩了、
// 又或者每次重挂都往前插一条）会在 OUTPUT 上留下好几份一模一样的跳转，
// 而 `-D` 一次只删一份。剩下的那一份让 `-X` 永远失败
// ——链还有引用就删不掉——于是那条链永久挂在用户的防火墙里，
// 而界面上写的是「已拆除」。
// 这条路径的意义是收敛回零；收敛回「还剩一份」等于没清。
// 只认 `-A` 开头的行：`-S` 回的就是这个形式，装载命令当初用 -I 也一样。
func sweepOutputJump(ctx context.Context, r Runner, table, bin, chain string) []string {
	out, err := r.Run(ctx, Cmd{Bin: bin, Args: []string{"-t", table, "-S", "OUTPUT"}, Desc: "列出 OUTPUT"})
	if err != nil {
		return nil
	}
	var done []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A OUTPUT") || !strings.Contains(line, "-j "+chain) {
			continue
		}
		spec := strings.Fields(strings.TrimPrefix(line, "-A OUTPUT"))
		del := Cmd{
			Bin:      bin,
			Args:     append([]string{"-t", table, "-D", "OUTPUT"}, spec...),
			Desc:     "按内容撤销残留挂载跳转",
			Optional: true,
		}
		if _, err := r.Run(ctx, del); err == nil {
			done = append(done, del.Desc)
		}
	}
	return done
}

// sweepDNSJumps 摘掉 nat 表里挂着劫持链的每一份跳转。
func sweepDNSJumps(ctx context.Context, r Runner, bin string) []string {
	return sweepOutputJump(ctx, r, "nat", bin, DNSChain)
}

// applyStale6 跑 v6 的残留清理，返回真正清掉的动作。
func applyStale6(ctx context.Context, r Runner, plan RoutePlan) []string {
	// 先扫跳转：StaleCleanup6 里的 -X 只有在链不再被引用时才删得掉，
	// 而重复装载留下的正是「删不胜删」的那几份引用。
	done := sweepDNSJumps(ctx, r, "ip6tables")
	for _, c := range StaleCleanup6(plan.UID, plan.Device, plan.Address6) {
		if _, err := r.Run(ctx, c); err == nil {
			done = append(done, c.Desc)
		}
	}
	return done
}

// 默认网卡名：-tun-reset 在拿不到配置时也要能认出「这是我们留下的」SNAT 规则。
const defaultDeviceName = "wps-tun"

// CleanupStale 清掉上一次没关干净的 TUN 网络残留，返回实际清掉的动作描述。
//
// 除了按已知参数逐条删除，还要按内容扫一遍 POSTROUTING：改过 device 或 address
// 之后，精确删除会打不中，残留的 SNAT 就一直挂在 nat 表里（我们真遇到过——
// 复位后仍剩 2 条 `-o wps-tun ... --to-source 172.19.0.1`）。
// 匹配条件刻意收紧到「出接口是我们认识的网卡名 + 改写 53 端口源地址」，
// 免得把用户自己的 NAT 规则一起删了。
func CleanupStale(ctx context.Context, r Runner, uid int, device, address string) []string {
	if r == nil {
		r = ExecRunner{}
	}
	var done []string
	// 先扫跳转，再跑那份逐条删除的清单：清单里的 -X 只有在链不再被引用时才删得掉，
	// 而重复装载留下的正是「-D 一次删一份、永远删不完」的那几份引用。
	done = append(done, sweepDNSJumps(ctx, r, "iptables")...)
	for _, c := range StaleCleanup(uid, device, address) {
		if _, err := r.Run(ctx, c); err == nil {
			done = append(done, c.Desc)
		}
	}
	out, err := r.Run(ctx, Cmd{Bin: "iptables", Args: []string{"-t", "nat", "-S", "POSTROUTING"}, Desc: "列出 POSTROUTING"})
	if err != nil {
		return done
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A POSTROUTING") || !strings.Contains(line, "-j SNAT") || !strings.Contains(line, "--dport 53") {
			continue
		}
		if !mentionsOurDevice(line, device) {
			continue
		}
		// 删除规则要给出与原规则完全一致的 spec，所以直接拿列出来的字段（去掉 -A CHAIN）。
		spec := strings.Fields(strings.TrimPrefix(line, "-A POSTROUTING"))
		del := Cmd{
			Bin:      "iptables",
			Args:     append([]string{"-t", "nat", "-D", "POSTROUTING"}, spec...),
			Desc:     "按内容撤销残留 SNAT",
			Optional: true,
		}
		if _, err := r.Run(ctx, del); err == nil {
			done = append(done, del.Desc)
		}
	}
	return done
}

func mentionsOurDevice(line, device string) bool {
	for _, name := range []string{device, defaultDeviceName} {
		if name != "" && strings.Contains(line, "-o "+name+" ") {
			return true
		}
	}
	return false
}

// tolerateGone 给所有点名我们那块网卡的拆除命令标上"设备已经没了也算成功"。
//
// 判据是参数里出现这个设备名，而不是命令列表的硬编码位置：
// 新增一条挂在网卡上的拆除命令时不必记得回来改表，
// 而挂在**物理网卡**上的绕行路由（参数里是物理网卡名）自然也不会被误标。
func tolerateGone(cmds []Cmd, device string) []Cmd {
	if device == "" {
		return cmds
	}
	for i := range cmds {
		if cmds[i].Bin != "ip" {
			continue
		}
		for _, a := range cmds[i].Args {
			if a == device {
				cmds[i].TolerateMissingDevice = device
				break
			}
		}
	}
	return cmds
}

// Runner 执行 Cmd。生产用 ExecRunner，测试换成记录型假实现。
type Runner interface {
	Run(ctx context.Context, c Cmd) (string, error)
}

// ExecRunner 是真正的进程执行器。
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, c Cmd) (string, error) {
	bin, err := resolveBin(c.Bin)
	if err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, bin, c.Args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%s: %w", text, err)
		}
		return text, err
	}
	return text, nil
}

// resolveBin 把命令名解析成绝对路径。
//
// 桌面程序从文件管理器启动时继承的 PATH 往往很短（不含 /usr/sbin），
// 而 iptables 在 Ubuntu 上正好装在 /usr/sbin。找不到就按常见目录兜一遍，
// 报错时也把找过哪些地方说出来，比 "executable file not found" 好定位。
func resolveBin(name string) (string, error) {
	if strings.ContainsRune(name, os.PathSeparator) {
		return name, nil
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("找不到可执行文件 %s（已在 PATH 与 /usr/sbin、/sbin、/usr/bin、/bin 中查找）", name)
}

// tolerates 判断一条命令的失败是否可以当作成功放过。
//
// 三个调用点（Apply、本地 best-effort 拆除、helper 拆除）共用这一份判据：
// 各写一遍的话，"拆除"那两路会把本来该忽略的失败报成错误。
// 真实踩过的那次是 Stop 时报三连 Cannot find device——网卡先被协议栈收走了，
// 那三条要的效果已经达成，而本地循环连 Optional 都没看。
func tolerates(c Cmd, out string) bool {
	if c.TolerateMissingDevice != "" &&
		strings.Contains(out, `Cannot find device "`+c.TolerateMissingDevice+`"`) {
		return true
	}
	if c.TolerateExists {
		// 「已经存在」这三套措辞来自两套工具与两类对象，缺一个就少一种重入：
		//   iproute2 的路由 → RTNETLINK answers: File exists
		//   iproute2 的地址 → Error: ipv4: Address already assigned.
		//   iptables 的链   → iptables: Chain already exists.
		// 只认前者的代价是真发生过的：挂断网保护时 -N 报的是第三种，于是第二次重挂
		// 被判成失败并走回滚——保护每改一次白名单就自己摘自己一次。
		// 地址这一种同样不是假设：Plan 的两条 addr add 都写着 TolerateExists，
		// 而内核给的就是 "already assigned"，网卡上已经挂着地址的那一次重装本应成功。
		// 这三句由 netns 用例拿真工具盯着（tolerance_netns_test.go），不靠我记得准不准。
		for _, phrase := range []string{"File exists", "already exists", "already assigned"} {
			if strings.Contains(out, phrase) {
				return true
			}
		}
	}
	return c.Optional
}

// Apply 依次执行命令。Optional 的失败只记进返回值里供调用方打日志，
// 其余失败立即中断——网卡配不上还继续往下走只会把系统留成半成品状态。
func Apply(ctx context.Context, r Runner, cmds []Cmd) error {
	for _, c := range cmds {
		out, err := r.Run(ctx, c)
		if err != nil {
			if tolerates(c, out) {
				logx.Debugf("tun: %s 没做成，但不算失败（%v）", c.Desc, firstLine(out, err))
				continue
			}
			return fmt.Errorf("%s 失败 (%s): %s", c.Desc, c, firstLine(out, err))
		}
	}
	return nil
}

func firstLine(out string, err error) string {
	if out != "" {
		if i := strings.IndexByte(out, '\n'); i > 0 {
			return out[:i]
		}
		return out
	}
	return err.Error()
}

// DefaultRoute 是一次默认路由探测的结果。
type DefaultRoute struct {
	// Gateway 是网关。v4 一般是 192.168.x.1 这样的普通地址；
	// v6 常常是 fe80:: 开头的链路本地地址（RA 下发），点对点链路则可能没有网关。
	Gateway string
	// Iface 是出口网卡。
	Iface string
}

// ParseDefaultRoute 从 `ip [-6] -o route show default` 的输出里取网关与网卡。
//
// 典型行：default via 10.180.63.254 dev wlp3s0f0 proto dhcp metric 600
// 判据是网卡名而不是网关：v6 的默认路由可以没有网关，
// 而「认出默认路由」与「能不能拿它钉绕行路由」是两个问题，
// 该由调用方分两处决定，不该在这里混成一个布尔值。
func ParseDefaultRoute(out string) (DefaultRoute, bool) {
	return ParseDefaultRouteExcept(out, "")
}

// ParseDefaultRouteExcept 同 ParseDefaultRoute，但跳过 dev 为 skip 的行。
//
// skip 是我们的 tun 网卡名。接管默认路由之后，路由表里同时有两条默认路由：
// 我们那条（metric 0，dev 是 tun）与物理那条（DHCP 来的，metric 20600）。
// 不跳过 tun 那条的话，探测会把 tun 自己当成「出口网卡」，
// 于是网关读成空、网卡读成 tun——监视器从此认为网络一直断着。
func ParseDefaultRouteExcept(out, skip string) (DefaultRoute, bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "default" {
			continue
		}
		var dr DefaultRoute
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					dr.Gateway = fields[i+1]
				}
			case "dev":
				if i+1 < len(fields) {
					dr.Iface = fields[i+1]
				}
			}
		}
		if dr.Iface == "" || dr.Iface == skip {
			continue
		}
		return dr, true
	}
	return DefaultRoute{}, false
}
