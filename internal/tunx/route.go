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
	Exclude []string
	// Gateway/Interface 来自当前默认路由，StrictRoute 的排除路由要用。
	Gateway   string
	Interface string
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

	if p.StrictRoute {
		if p.Gateway == "" || p.Interface == "" {
			return nil, nil, errors.New("tun: strict_route 需要已知默认网关与网卡")
		}
		for _, cidr := range p.Exclude {
			up = append(up, Cmd{
				Bin:            "ip",
				Args:           []string{"route", "add", cidr, "via", p.Gateway, "dev", p.Interface},
				Desc:           "把 " + cidr + " 钉回物理网关（防环路）",
				TolerateExists: true,
			})
		}
		up = append(up, Cmd{Bin: "ip", Args: []string{"route", "add", "default", "dev", p.Device}, Desc: "默认路由交给 tun", TolerateExists: true})
	}

	down = append(down, Cmd{
		Bin:  "ip",
		Args: []string{"route", "del", "default", "dev", p.Device},
		Desc: "撤销默认路由",
		// 非 StrictRoute 模式下这条路由本来就不存在，失败是预期内的。
		Optional: !p.StrictRoute,
	})
	if p.StrictRoute && p.Gateway != "" && p.Interface != "" {
		for i := len(p.Exclude) - 1; i >= 0; i-- {
			down = append(down, Cmd{
				Bin:      "ip",
				Args:     []string{"route", "del", p.Exclude[i], "via", p.Gateway, "dev", p.Interface},
				Desc:     "撤销排除路由 " + p.Exclude[i],
				Optional: true,
			})
		}
	}
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
	return up, down, nil
}

// PlanV6 生成 IPv6 那一组命令，与 Plan 的 v4 组完全分开。
//
// 分开是因为两组的失败后果不对等：v4 配不上，TUN 本来就起不来，早失败是好事；
// 而 v6 配不上（多半是内核没有 ip6table_nat）完全可以只放弃 v6，
// 让 AAAA 退回 NODATA、应用改走 A 记录。把两者混在一张列表里，
// 一条 ip6tables 失败就会把整个 TUN 拖下水。
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
	return up, down, nil
}

func isV6CIDR(cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	return err == nil && p.Addr().Is6()
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

// applyStale6 跑 v6 的残留清理，返回真正清掉的动作。
func applyStale6(ctx context.Context, r Runner, plan RoutePlan) []string {
	var done []string
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

// Apply 依次执行命令。Optional 的失败只记进返回值里供调用方打日志，
// 其余失败立即中断——网卡配不上还继续往下走只会把系统留成半成品状态。
func Apply(ctx context.Context, r Runner, cmds []Cmd) error {
	for _, c := range cmds {
		out, err := r.Run(ctx, c)
		if err != nil {
			if c.TolerateExists && strings.Contains(out, "File exists") {
				logx.Debugf("tun: %s 已在位，按成功处理（%s）", c.Desc, c)
				continue
			}
			if c.Optional {
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

// ParseDefaultRoute 从 `ip -o route show default` 的输出里取网关与网卡。
// 典型行：default via 10.180.63.254 dev wlp3s0f0 proto dhcp metric 600
func ParseDefaultRoute(out string) (gateway, iface string, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "default" {
			continue
		}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					gateway = fields[i+1]
				}
			case "dev":
				if i+1 < len(fields) {
					iface = fields[i+1]
				}
			}
		}
		if gateway != "" && iface != "" {
			return gateway, iface, true
		}
	}
	return "", "", false
}
