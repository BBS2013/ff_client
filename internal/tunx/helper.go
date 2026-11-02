package tunx

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// helper 协议版本：面板与 helper 来自同一个二进制，版本对不上只可能是
// 「用新的面板配了老的 sudoers 路径」这种部署错位，必须当场说清而不是行为漂移。
//
// 2026-10-28 提到 2：应答里多了 V6RouteOK（面板要靠它如实说 v6 有没有被接管），
// 请求里多了 Prev（重钉路由时要知道旧的那份计划）。老 helper 不回 V6RouteOK，
// 面板会把它读成「v6 没接管」——那是静默说错话，所以宁可当场报版本不匹配。
//
// 同一天提到 3：多了 kill 动作（请求带 Allow 白名单，应答带每族挂没挂上）。
// 老 helper 收到 kill 会报「未知的动作」，面板把它读成「保护没生效」——
// 这一条方向上是安全的，但界面上「保护开着」和「保护装不上」必须分开说，
// 而老 helper 给不出这个区分，所以还是抬版本。
//
// 2026-10-30 提到 4：多了 dialbind——helper 以 root 造一条**钉在某张网卡上、已连通**的
// TCP socket，用 SCM_RIGHTS 把 fd 交给面板（网卡 fd 早就这么传了，同一条内核机制）。
// 抬版本的理由和上面两条一样：老 helper 收到 dialbind 只会回「未知的动作」，
// 而面板会把那句读成「这张网卡钉不上」——那恰恰是这条通道要替用户分开的两种失败，
// 方向上是说反话，不能让它静默往下走。
const helperProtoVersion = 4

// HelperProto 是给命令行与诊断用的对外读数：`wps_app -version` 用它打印
// 「这个构建说的是第几版提权协议」，面板再拿它比一比 `tun.helper` 那个文件
// 是不是同一份协议（见 helper_probe.go）。
// 为什么要把版本号打印出来：版本对不上是「此后再试多少次都一样」的失败，
// 而它的两个当事人——跑着的进程与磁盘上的文件——本来没有任何一处说得出自己是谁。
func HelperProto() int { return helperProtoVersion }

// helperRejection 抓 helper 那句版本拒绝里的两个数字。
// 前一个是「我们发过去的版本」，后一个是「对面自己的版本」——
// 谁新谁旧决定该动哪一边，所以这两个数必须解析出来，不能整句当字符串往下传。
// 括号是全角的：那句错误原文由本包生成，改它的人同时也得改这里，
// 读不出来时有兜底分支（见 helperVersionRejection），不会静默变成「不是版本问题」。
var helperRejection = regexp.MustCompile(`协议版本 (\d+) 不被支持（本程序是 (\d+)）`)

// helperVersionRejection 认一条错误是不是「helper 因为协议版本对不上而拒收」。
//
// 为什么这条值得单独立一个判据：2026-10-29 09:16 的真实日志里，
// 跑着的面板是提交版构建（协议 1），而 `make build-gui` 刚把 tun.helper 指向的那个
// 文件刷成了工作树版本（协议 3）。从那一刻起这个进程再也开不了 TUN——
// 每次尝试都被同一句话拒掉，而那句话里只有两个版本号，
// 没说该重启面板还是该重装 helper，用户手上只剩「反复点开关」。
// 本包早就在注释里预见过这种「部署错位」，但没有把它说成一句能照着做的话。
func helperVersionRejection(errText string) (mine, theirs int, ok bool) {
	if !strings.Contains(errText, "协议版本") || !strings.Contains(errText, "不被支持") {
		return 0, 0, false
	}
	m := helperRejection.FindStringSubmatch(errText)
	if m == nil {
		// 认得出是版本问题却读不出对面的版本（措辞是更老的那一版）：
		// 对面版本记成 -1，让建议走「两边都要刷新」那一条，而不是猜一个数字。
		return helperProtoVersion, -1, true
	}
	mine, _ = strconv.Atoi(m[1])
	theirs, _ = strconv.Atoi(m[2])
	return mine, theirs, true
}

// helperPath 从 argv 里挑出那个文件路径，好让建议指名「要刷新/要重启的是哪个二进制」。
// argv 形如 sudo -n /home/.../wps_app --tun-helper，所以第一个带 "/" 的项就是它。
func helperPath(argv []string) string {
	for _, a := range argv {
		if strings.Contains(a, "/") {
			return a
		}
	}
	return ""
}

// HelperPath 是给包外（`-diag`）用的同一个判据：要指名「该动哪个文件」，
// 两处必须挑出同一个路径，不能各写一遍「哪个参数像路径」。
func HelperPath(argv []string) string { return helperPath(argv) }

// HelperMismatchAdvice 把「两边协议版本对不上」的两个数字翻成一句能照着做的话。
// 导出给 `-diag`：诊断报告也要能说「该重启面板还是该重装 helper」，
// 而不是只印两个数字——那句原文对用户来说和没有一样。
func HelperMismatchAdvice(mine, theirs int, argv []string) string {
	return helperMismatchAdvice(mine, theirs, argv)
}

// helperMismatchAdvice 把「两边协议版本对不上」翻成一句照着做就能恢复的话。
// 它只负责说清该动哪一边；原文（那两个版本号）由调用方一并留着，方便对日志。
func helperMismatchAdvice(mine, theirs int, argv []string) string {
	path := helperPath(argv)
	if path == "" {
		path = "tun.helper 配的那条命令"
	}
	switch {
	case theirs < 0:
		return fmt.Sprintf("面板与 %s 的 helper 协议对不上，而且读不出对方的版本："+
			"请用当前构建刷新 %s，并用它重启面板", path, path)
	case theirs > mine:
		// helper 文件比跑着的面板新——「刚 make build-gui 完，老面板还在台上」的那一种。
		return fmt.Sprintf("跑着的面板是协议 %d，%s 已经是协议 %d（比面板新）："+
			"helper 会拒收每一次特权请求，TUN 因此开不了——请用 %s 重启面板", mine, path, theirs, path)
	case theirs < mine:
		return fmt.Sprintf("%s 是协议 %d，比跑着的面板（协议 %d）旧："+
			"helper 会拒收每一次特权请求，TUN 因此开不了——请用当前构建刷新 %s（make build-gui）",
			path, theirs, mine, path)
	default:
		return fmt.Sprintf("面板与 %s 都自称协议 %d 却仍然互斥，先重启面板再试", path, mine)
	}
}

// helper 只做这几件事。任何一件都不接受调用方给的命令行，
// 全部动作由本包按 RoutePlan 现算——这是把 root 权限收窄成「只能按我们的规矩开网卡」的关键。
const (
	ActionUp      = "up"
	ActionDown    = "down"
	ActionCleanup = "cleanup"
	// ActionReroute 在网络变化后重新钉一遍绕行路由。
	// 它需要知道「上一份装的是哪一份」：helper 是短命进程，不记得上次，
	// 而旧网关只能由调用方告诉它（见 HelperRequest.Prev）。
	ActionReroute = "reroute"
	// ActionKill 挂上或摘下故障断网保护。规则同样由本包按 RoutePlan 现算
	// （见 PlanKill）；请求里的 Allow 只是白名单里的地址，会被规范成 CIDR 再用。
	ActionKill = "kill"
	// ActionDialBind 让 helper 造一条钉在指定网卡上、并且已经连通的 TCP socket，
	// 成功时随应答附回一个 fd（与 up 附回 tun fd 同一条通道）。
	//
	// 为什么要有这一件事：`SO_BINDTODEVICE` 在这类机器上对普通进程是**返回成功、
	// 包却一个都上不了线**（2026-10-29 实测：uid 1000 绑任何卡都超时，加 ambient
	// CAP_NET_RAW 仍然超时，只有 uid 0 出得去）。于是「按网卡分流」这个功能对
	// 以普通用户跑的面板等于没开，而症状是全部代理连接一起超时。
	// 把「造 socket」这一步交给同一个 helper，面板仍然不碰 root。
	ActionDialBind = "dialbind"
)

// HelperRequest 是面板发给 helper 的请求。
type HelperRequest struct {
	V      int       `json:"v"`
	Action string    `json:"action"`
	Plan   RoutePlan `json:"plan"`
	// Prev 是「上一份生效的计划」，只有 reroute 用得到。
	// 没有它就没法拆旧路由：新旧两条绕行路由指向同一个目标地址，
	// 而内核只认一条。
	Prev *RoutePlan `json:"prev,omitempty"`
	// Allow 是故障保护白名单里由调用方补充的出站地址（其余节点的端点），只有 kill 用。
	// 为什么必须由调用方给：helper 与面板都不该在故障现场重新解析域名，
	// 而「哪些地址是我们的出口」只有拿着节点配置才知道。
	Allow []string `json:"allow,omitempty"`
	// KillArm 为 true 时挂上保护，false 时摘下。
	KillArm bool `json:"killarm,omitempty"`
	// 下面三个只有 dialbind 用。
	// BindDev 是要钉住的接口名；BindAddr 是**已解析好的** ip:port——
	// 名单与解析都留在面板那侧（它有自己的直连 DNS），helper 不许在现场再解析域名，
	// 那和 kill 的 Allow 是同一条理由：故障现场重解析会拿到假 IP，把出口拨到自己家。
	// BindAllow 是「这些端点是我们的节点」的名单，helper 拿它核对 BindAddr。
	// 为什么要核对：这条通道让 root 替一个无特权进程往外连，
	// 不收窄成"只准连配置里已有的节点端点"就多说了一步它本不必给的能力。
	BindDev   string   `json:"binddev,omitempty"`
	BindAddr  string   `json:"bindaddr,omitempty"`
	BindAllow []string `json:"bindallow,omitempty"`
}

// HelperReply 是 helper 的应答。up 成功时另附一个 tun 设备 fd（见 SendReply）。
type HelperReply struct {
	OK      bool     `json:"ok"`
	Err     string   `json:"err,omitempty"`
	Applied []string `json:"applied,omitempty"` // 实际执行过的步骤描述，直接进面板日志
	// V6OK 报告 v6 那一组命令是否全装上了。false 时面板据此让 AAAA 回 NODATA。
	V6OK bool `json:"v6ok,omitempty"`
	// V6RouteOK 报告 v6 默认路由是否真的交给了 tun。
	// 它和 V6OK 是两件事：v6 假 IP 能不能用，与 v6 全局流量有没有被接管。
	// 两者分开报，面板才能说清「v6 有地址可用但流量没进隧道」。
	V6RouteOK bool `json:"v6routeok,omitempty"`
	// KillV4 / KillV6 报告两族各自的保护挂上了没有，KillReason 说明没挂上的那一族为什么。
	// 用户开的是一道「故障时别裸奔」的保护，界面必须能说它到底在不在——
	// 一道没装成功的保护，在界面上和最危险的状态长得一模一样。
	KillV4     bool     `json:"killv4,omitempty"`
	KillV6     bool     `json:"killv6,omitempty"`
	KillReason string   `json:"killreason,omitempty"`
	Device     string   `json:"device,omitempty"`
	MTU        uint32   `json:"mtu,omitempty"` // 网卡上的真实 MTU，建端点要以它为准
	Removed    []string `json:"removed,omitempty"`
}

// nameChar 判断网卡名里的单个字符。网卡名会进 argv，虽然 exec 不经 shell、
// 注入不成立，但把它收紧到肉眼可辨的范围，出错时也更像人写的东西。
func validIfaceName(s string) bool {
	if s == "" || len(s) > 15 { // IFNAMSIZ-1，超了内核直接报错
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	// "." 与 ".." 不是网卡名，却能让后续拼路径/比前缀的逻辑出怪事。
	return s != "." && s != ".."
}

// validate 把请求里所有会被 root 用掉的参数过一遍。
//
// 这里的每一条都是在防「普通用户借 helper 把手伸进别的接口或别的路由」：
// helper 的父进程是 sudo 起来的 root，能做的事远比面板多，所以校验必须按
// 「输入不可信」来写，而不是按「反正配置是我们自己填的」。
func (r HelperRequest) validate() error {
	if r.V != helperProtoVersion {
		return fmt.Errorf("helper 协议版本 %d 不被支持（本程序是 %d）", r.V, helperProtoVersion)
	}
	switch r.Action {
	case ActionUp, ActionDown, ActionCleanup, ActionReroute, ActionKill, ActionDialBind:
	default:
		return fmt.Errorf("未知的 helper 动作 %q", r.Action)
	}
	if r.Action == ActionDialBind {
		// dialbind 不碰任何网卡/路由配置，Plan 是空的：下面那几项按 RoutePlan 的检查
		// 一条都不该套到它头上，否则这个动作永远进不来。
		// 名单条数上限与 kill 的 Allow 同一个理由——别让一次请求带一张无限长的表。
		if !validIfaceName(r.BindDev) {
			return fmt.Errorf("dialbind 的接口名不合法: %q", r.BindDev)
		}
		if strings.TrimSpace(r.BindAddr) == "" {
			return errors.New("dialbind 缺少目标地址")
		}
		if len(r.BindAllow) == 0 || len(r.BindAllow) > 64 {
			return fmt.Errorf("dialbind 的节点端点名单不合用（%d 条，期望 1~64）", len(r.BindAllow))
		}
		return nil
	}
	p := r.Plan
	if !validIfaceName(p.Device) {
		return fmt.Errorf("网卡名不合法: %q", p.Device)
	}
	if r.Action == ActionReroute {
		// 重钉要拆旧路由，所以必须知道旧的那份计划。
		if r.Prev == nil {
			return errors.New("reroute 缺少 prev 计划（无法知道该拆哪条旧路由）")
		}
		if !validIfaceName(r.Prev.Device) {
			return fmt.Errorf("prev 的网卡名不合法: %q", r.Prev.Device)
		}
	}
	if r.Action == ActionKill {
		// Allow 里的每一项最后都会变成 root 执行的 `iptables ... -d <地址>`。
		// 虽然 exec 不经 shell、注入不成立，但一个以 "-" 开头的值会被 iptables 当成
		// 选项解析——那等于让调用方往 root 的命令里塞参数。所以只收 IP 字面量与 CIDR，
		// 其余一律当场拒绝（PlanKill 里那套 splitExclude 也会把它们丢掉，
		// 但「静默少了一条白名单」会把节点锁在门外，必须报错而不是丢）。
		if len(r.Allow) > 64 {
			return fmt.Errorf("白名单条目 %d 过多", len(r.Allow))
		}
		for _, a := range r.Allow {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if _, err := netip.ParsePrefix(a); err == nil {
				continue
			}
			if _, err := netip.ParseAddr(a); err != nil {
				return fmt.Errorf("白名单地址 %q 既不是 IP 也不是 CIDR", a)
			}
		}
	}
	if p.Address == "" {
		return errors.New("address 必填")
	}
	prefix, err := netip.ParsePrefix(p.Address)
	if err != nil {
		return fmt.Errorf("address %q 不是合法 CIDR: %w", p.Address, err)
	}
	// 网卡地址是 /0 意味着「把整个地址空间让给 tun」，那不是这台机器想要的配置。
	if prefix.Bits() == 0 {
		return fmt.Errorf("address %q 的掩过短，拒绝执行", p.Address)
	}
	if p.MTU < 0 || p.MTU > 65535 {
		return fmt.Errorf("mtu %d 超出范围", p.MTU)
	}
	if p.UID < 0 {
		return fmt.Errorf("uid 不能为负")
	}
	if p.HijackDNS {
		if p.DNS == "" {
			return errors.New("开启 DNS 劫持必须给出 dns 地址")
		}
		if net.ParseIP(p.DNS) == nil {
			return fmt.Errorf("dns %q 不是合法 IP", p.DNS)
		}
		// 上游地址会变成劫持链里的 `-d <ip>/32`，所以必须是字面量 IP，
		// 而且要给出至少一个——没有可放行的上游就不许劫持（自己吃自己）。
		if len(p.Upstreams) == 0 {
			return errors.New("开启 DNS 劫持必须给出要放行的上游地址")
		}
		if len(p.Upstreams) > 16 {
			// 每个上游两条规则。给个上限，免得一次写入几百条规则把 nat 表变成迷宫。
			return fmt.Errorf("上游数量 %d 过多", len(p.Upstreams))
		}
		for _, up := range p.Upstreams {
			if net.ParseIP(strings.TrimSpace(up)) == nil {
				return fmt.Errorf("上游 DNS %q 不是 IP 字面量", up)
			}
		}
	}
	if p.FakeIPRange != "" {
		fp, err := netip.ParsePrefix(p.FakeIPRange)
		if err != nil {
			return fmt.Errorf("fake_ip_range %q 不是合法 CIDR: %w", p.FakeIPRange, err)
		}
		if fp.Bits() < 8 {
			return fmt.Errorf("fake_ip_range %q 段过大，拒绝写入路由", p.FakeIPRange)
		}
	}
	// v6 那一组同样会被 root 用掉（ip -6 route / ip6tables），逐个校验。
	if p.Address6 != "" {
		ap, err := netip.ParsePrefix(p.Address6)
		if err != nil {
			return fmt.Errorf("address6 %q 不是合法 CIDR: %w", p.Address6, err)
		}
		if !ap.Addr().Is6() {
			return fmt.Errorf("address6 %q 必须是 IPv6 地址", p.Address6)
		}
		if ap.Bits() == 0 {
			return fmt.Errorf("address6 %q 的掩过短，拒绝执行", p.Address6)
		}
	}
	if p.FakeIPRange6 != "" {
		fp, err := netip.ParsePrefix(p.FakeIPRange6)
		if err != nil {
			return fmt.Errorf("fake_ip_range6 %q 不是合法 CIDR: %w", p.FakeIPRange6, err)
		}
		if !fp.Addr().Is6() {
			return fmt.Errorf("fake_ip_range6 %q 必须是 IPv6 网段", p.FakeIPRange6)
		}
		// /8 及更短会把整块 v6 地址空间路由进 tun；/33 及更长又放不下假 IP。
		if fp.Bits() < 8 || fp.Bits() > 32 {
			return fmt.Errorf("fake_ip_range6 %q 的段大小不合适（需 /8~/32）", p.FakeIPRange6)
		}
	}
	if p.DNS6 != "" && net.ParseIP(p.DNS6) == nil {
		return fmt.Errorf("dns6 %q 不是合法 IP", p.DNS6)
	}
	if p.StrictRoute {
		// 改默认路由是最容易把机器搞挂的一步，网关与网卡信息必须齐全且合法。
		// 两族是各自独立的：只有 v6 的机器 v4 那一族是空的，那不是错。
		// 但至少得有一族，否则无处可去。
		if p.Gateway == "" && p.Gateway6 == "" {
			return errors.New("strict_route 需要至少一族的网关信息")
		}
		if p.Gateway != "" {
			if !validIfaceName(p.Interface) {
				return fmt.Errorf("strict_route 的网卡名不合法: %q", p.Interface)
			}
			if net.ParseIP(p.Gateway) == nil {
				return fmt.Errorf("strict_route 的网关 %q 不是合法 IP", p.Gateway)
			}
			if p.Gateway == "0.0.0.0" || p.Gateway == "::" {
				return fmt.Errorf("strict_route 的网关 %q 无效", p.Gateway)
			}
		}
	}
	// v6 那一族的绕行路由同样会被 root 用到，逐个校验。
	// 只在两样都给了的时候才要求合法：面板查不到 v6 默认路由时会留空，
	// 那表示「不做 v6 接管」，不是「配置坏了」。
	if p.Gateway6 != "" || p.Interface6 != "" {
		if !validIfaceName(p.Interface6) {
			return fmt.Errorf("strict_route 的 IPv6 网卡名不合法: %q", p.Interface6)
		}
		if net.ParseIP(p.Gateway6) == nil {
			return fmt.Errorf("strict_route 的 IPv6 网关 %q 不是合法 IP", p.Gateway6)
		}
		if p.Gateway6 == "::" {
			return fmt.Errorf("strict_route 的 IPv6 网关 %q 无效", p.Gateway6)
		}
	}
	for _, cidr := range p.Exclude {
		if _, err := netip.ParsePrefix(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("排除网段 %q 不是合法 CIDR", cidr)
		}
	}
	// up 之外，down/cleanup 只需要网卡与地址；提前把 up 会用到的字段验齐，
	// 免得 helper 在 down 路径上因为一个无关的空值罢工。
	return nil
}

// truncate 把一段外部文本压进错误信息里；按 rune 切，免得把中文截成半个字。
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

// CleanupRequest 生成「清残留」请求：只需要网卡名与地址。
func CleanupRequest(uid int, device, address string) HelperRequest {
	return HelperRequest{
		V:      helperProtoVersion,
		Action: ActionCleanup,
		Plan:   RoutePlan{Device: device, Address: address, UID: uid},
	}
}

// DialBindRequest 组一个「替我钉住这张卡、连上这个端点」的请求。
//
// 没有 Plan：这个动作不碰网卡也不碰路由，所以那两个按 RoutePlan 的校验对它不适用
// （见 validate 里那条早退）。addr 必须是**已经解析好的** ip:port，
// allow 是面板从节点配置里数出来的端点名单——为什么要带着它，见 dialbind_linux.go。
func DialBindRequest(uid int, dev, addr string, allow []string) HelperRequest {
	return HelperRequest{
		V: helperProtoVersion, Action: ActionDialBind,
		// UID 仍然要带：ServeConn 用 SO_PEERCRED 核对"发起请求的人就是这个 uid"，
		// 空 Plan 会让它以为请求来自 root 而直接拒收。
		Plan:    RoutePlan{UID: uid},
		BindDev: dev, BindAddr: addr, BindAllow: allow,
	}
}

// KillRequest 组一个挂/摘故障保护的请求。
//
// 挂载时 plan 必须是完整的那一份（白名单和两族的网关都从它来）；摘链不需要它，
// 但 helper 的校验要求一个合法的网卡名与地址——所以照样把 conf 里的那一份带上。
// 摘链不能因为「计划已经变了」就失败：strict_route 刚被关掉的那一刻正是最该摘的时候。
func KillRequest(plan RoutePlan, uid int, allow []string, arm bool) HelperRequest {
	plan.UID = uid
	return HelperRequest{
		V: helperProtoVersion, Action: ActionKill, Plan: plan, Allow: allow, KillArm: arm,
	}
}

// 帧格式：4 字节大端长度 + JSON。长度上限是为了让一个畸形请求撑不爆内存，
// 而不是为了性能——请求体里最宽的字段就是 Exclude 列表。
const (
	maxHelperFrame = 1 << 16
	headerLen      = 4
)

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxHelperFrame {
		return fmt.Errorf("helper 报文过大: %d 字节", len(payload))
	}
	var head [headerLen]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var head [headerLen]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > maxHelperFrame {
		return nil, fmt.Errorf("helper 报文长度非法: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// encodeRequest/decodeRequest 把请求在 JSON 与字节之间来回搬。
// 单独拆出来是为了能让校验逻辑在没有 unix socket、没有 root 的情况下被完整测试。
func encodeRequest(req HelperRequest) ([]byte, error) { return json.Marshal(req) }

func decodeRequest(buf []byte) (HelperRequest, error) {
	var req HelperRequest
	if err := json.Unmarshal(buf, &req); err != nil {
		return req, fmt.Errorf("helper 请求解析失败: %w", err)
	}
	return req, nil
}

func encodeReply(reply HelperReply) ([]byte, error) { return json.Marshal(reply) }

func decodeReply(buf []byte) (HelperReply, error) {
	var reply HelperReply
	if err := json.Unmarshal(buf, &reply); err != nil {
		return reply, fmt.Errorf("helper 应答解析失败: %w", err)
	}
	return reply, nil
}
