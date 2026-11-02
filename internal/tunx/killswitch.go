// 故障断网保护（Kill Switch）。
//
// 它堵的是一个很具体的窗口：strict_route 下换节点要整块重启，那几百毫秒里默认路由
// 回到了物理网卡，浏览器里每一条连接就此裸奔，而界面看上去「只是切了个节点」。
// 路由回滚之后、helper 装失败之后也是同一个形状。做法是把本机出站收窄到一份白名单，
// 其余一律 DROP。
//
// 三条纪律，每条都对应一种「保护把自己锁死」的失败：
//
//  1. 白名单必须装着**所有**节点的地址，不只是当前活动的那个。只放行活动节点的话，
//     自动切换去试拨备用节点会被我们自己的规则拒掉，而报错信息和节点真死了一模一样
//     ——「故障保护」就此变成「永远恢复不了」。备用节点的地址由调用方经 allow 传进来
//     （见 service 侧的 killAllowList）。
//  2. 隧道自己要往里送的那几条必须放行：网卡网段、假 IP 网段、DNS 劫持落点。
//     它们不是泄漏，反而是唯一被允许的路；一起 DROP 掉的表现是
//     「开了保护之后连隧道都不通了」。
//  3. 装不上要如实报「未生效」。一道没装成功的保护，在界面上和最危险的状态无法区分。
package tunx

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// KillChain 是本机出站过滤链的名字。与 DNS 劫持链分开是刻意的：
// 两者生命周期不同——劫持规则跟着 TUN 的启停走，保护只在故障期间挂上。
const KillChain = "wps_app_kill"

// killAllow 是一条可以放进白名单的地址（已带掩码，能直接交给 iptables）。
type killAllow struct {
	cidr string
	desc string
}

// KillPlan 是一次「挂上 / 摘下保护」的命令组，外加两族各自有没有真的挂上。
//
// V4/V6 必须分开报：一台机器可能只有 v4 的节点地址，也可能 ip6tables 压根没加载。
// 合成一个布尔值的话，「v6 没有保护」和「保护整体没生效」在界面上就长得一样。
type KillPlan struct {
	Arm    []Cmd
	Disarm []Cmd
	V4     bool
	V6     bool
	// V4Reason / V6Reason 说明这一族为什么没挂上保护，挂上了则为空。
	// 它们要一路带到界面上：用户开的是一道保护，看到的必须是它到底在不在。
	V4Reason string
	V6Reason string
}

// Empty 报告这份计划什么保护都没挂上。
func (k KillPlan) Empty() bool { return !k.V4 && !k.V6 }

// Error 把两族的原因拼成一句可直接进日志与界面的人话。
func (k KillPlan) Error() string {
	reasons := k.Reasons()
	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, "；")
}

// Reasons 列出没挂上的族与原因，顺序固定为 v4 在前。
func (k KillPlan) Reasons() []string {
	var out []string
	if k.V4Reason != "" {
		out = append(out, k.V4Reason)
	}
	if k.V6Reason != "" {
		out = append(out, k.V6Reason)
	}
	return out
}

// PlanKill 生成挂上与摘下故障保护的命令。
//
// allow 是调用方补进来的出站地址（其余节点的端点）。它与 p.Exclude 里的
// 节点/DNS 上游合并成白名单——后者本来就是为了「我们的出站别掉进 tun」而钉回
// 物理网关的，正是同一批地址，不必重新发明一份。
//
// 选择性 TUN（strict_route 关）下直接拒绝：那时候直连本来就该出去，
// 挂上保护等于把用户开这个模式想要的功能关掉。
func (p RoutePlan) PlanKill(allow []string) (KillPlan, error) {
	if !p.StrictRoute {
		return KillPlan{}, errors.New("故障断网保护只在 strict_route（全局接管）下有意义：" +
			"选择性 TUN 里直连本来就该出去，挂上它等于关掉这个模式要的功能")
	}
	v4, v6 := splitExclude(append(append([]string(nil), p.Exclude...), allow...))

	// 隧道内侧的允许项按族归好：网卡地址、假 IP 网段、DNS 劫持落点。
	var tun4, tun6 []killAllow
	if p.Address != "" {
		tun4 = append(tun4, killAllow{p.Address, "tun 网卡网段"})
	}
	if p.FakeIPRange != "" {
		tun4 = append(tun4, killAllow{p.FakeIPRange, "IPv4 假 IP 网段"})
	}
	if p.DNS != "" {
		tun4 = append(tun4, killAllow{upstreamCIDR(p.DNS), "DNS 劫持落点"})
	}
	if p.Address6 != "" {
		tun6 = append(tun6, killAllow{p.Address6, "tun 网卡 IPv6 网段"})
	}
	if p.FakeIPRange6 != "" {
		tun6 = append(tun6, killAllow{p.FakeIPRange6, "IPv6 假 IP 网段"})
	}
	if p.DNS6 != "" {
		tun6 = append(tun6, killAllow{upstreamCIDR(p.DNS6), "IPv6 DNS 劫持落点"})
	}

	var out KillPlan
	// 每一族单独决定装不装，两个条件缺一不可：这一族要真的在接管
	// （不然被 DROP 的是用户本来该直连的流量），而且白名单里得有**出得来**的地址
	// （只有隧道内侧那几条不算——节点自己锁在门外的话，恢复就无路可走了）。
	// 判据看 v4/v6 这两个「对外出口」列表，不看合并后的总数：隧道网段永远非空，
	// 用总数判断的话这条保护检查永远不会触发，等于没写。
	if p.usable4() {
		if len(v4) == 0 {
			out.V4Reason = "IPv4 断网保护没挂上：白名单里没有任何可对外出去的地址，" +
				"挂上去会把节点自己锁死（检查 tun.route_exclude 与节点地址）"
		} else {
			out.Arm = append(out.Arm, killArm("iptables", "IPv4", dedupeKill(append(tun4, toAllows(v4)...)), false)...)
			out.Disarm = append(out.Disarm, killDisarm("iptables", "IPv4")...)
			out.V4 = true
		}
	} else {
		out.V4Reason = "IPv4 断网保护没挂上：这台机器没有可用的 IPv4 默认出口"
	}
	if p.usable6() {
		if len(v6) == 0 {
			// 这一族的取舍和 v4 不对称，值得说清：节点只有 v6 地址时，
			// 宁可 v6 不保护，也不能把「以后切到一个 v4 节点」的路锁掉。
			out.V6Reason = "IPv6 断网保护没挂上：白名单里没有可对外出去的 IPv6 地址，" +
				"挂上去会把 v6 的节点出口与将来的切换一起锁死"
		} else {
			out.Arm = append(out.Arm, killArm("ip6tables", "IPv6", dedupeKill(append(tun6, toAllows(v6)...)), true)...)
			out.Disarm = append(out.Disarm, killDisarm("ip6tables", "IPv6")...)
			out.V6 = true
		}
	} else {
		out.V6Reason = "IPv6 断网保护没挂上：本机没有 IPv6 默认路由，v6 流量本来就不经隧道"
	}
	if out.Empty() {
		return out, errors.New("故障断网保护挂不上（" + out.Error() + "）")
	}
	return out, nil
}

// killArm 生成一族的白名单规则。顺序就是语义：建链、清空（重挂不能把旧的
// ACCEPT 越叠越多）、放行回环与链路必需的那几种、逐条放行白名单、最后 DROP，
// 最末才把它挂到 OUTPUT 上。
//
// 挂在 OUTPUT 的第 1 条而不是末尾：OUTPUT 默认策略是 ACCEPT，而本机可能已经有
// 别人写的放行规则。排在它们后面，我们的 DROP 永远轮不到——形同虚设的保护比没有
// 保护更糟，因为它让人以为流量已经收住了。
func killArm(bin, family string, allow []killAllow, v6 bool) []Cmd {
	rule := func(desc string, args ...string) Cmd {
		return Cmd{Bin: bin, Args: append([]string{"-t", "filter"}, args...), Desc: family + " 断网保护：" + desc}
	}
	// 残链（上一次异常退出留下的）会在这里报 File exists，而那正是我们要的状态。
	create := Cmd{Bin: bin, Args: []string{"-t", "filter", "-N", KillChain},
		Desc: family + " 断网保护：建链", TolerateExists: true}
	// 新建的链本来就没有规则；-F 只为残链准备，它失败说明链不在——
	// 那同样是可接受的状态，不值得让整次挂保护失败。
	flush := Cmd{Bin: bin, Args: []string{"-t", "filter", "-F", KillChain},
		Desc: family + " 断网保护：清空旧规则（重挂不能把放行叠成两遍）", Optional: true}
	// 挂载点同理，而且它比链里的规则更要紧：-I 是无条件往前插，
	// 重挂 N 次就有 N 份跳转，而拆除一次只摘一份——剩下那些让链永远被引用着、
	// -X 删不掉，于是「已关闭」的保护其实一直挂在用户的 OUTPUT 上。
	// 所以每次挂之前先把上一次的摘掉，让挂载点恒等于一份。
	unmount := rule("先摘掉上一次的挂载点（重挂不许叠加）", "-D", "OUTPUT", "-j", KillChain)
	unmount.Optional = true
	out := []Cmd{
		unmount,
		create,
		flush,
		rule("放行本机回环（面板与本地代理端口都在这上面）", "-A", KillChain, "-o", "lo", "-j", "ACCEPT"),
	}
	if v6 {
		// ICMPv6 不能跟着一起 DROP：邻居发现、路由通告与 PTMU 全在它上面，
		// 拦了这张网卡的 v6 直接瘫掉，连「网络回来」都等不到。
		// 它不承载应用数据，放行不构成泄漏。
		out = append(out, rule("放行 ICMPv6（邻居发现与 PTMU，拦了 v6 整族瘫掉）",
			"-A", KillChain, "-p", "ipv6-icmp", "-j", "ACCEPT"))
	} else {
		// DHCP 客户端要发 discover/request（dport 67），单播回包落到 dport 68。
		// 拦掉它等于换不到地址，网络回来时这台机器也回不来。
		out = append(out, rule("放行 DHCP（拦了就拿不到地址，网络回来了也回不来）",
			"-A", KillChain, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT"))
	}
	for _, a := range allow {
		out = append(out, rule("放行 "+a.cidr+"（"+a.desc+"）", "-A", KillChain, "-d", a.cidr, "-j", "ACCEPT"))
	}
	out = append(out,
		rule("其余本机出站一律丢弃", "-A", KillChain, "-j", "DROP"),
		rule("挂到 OUTPUT 第 1 条", "-I", "OUTPUT", "1", "-j", KillChain),
	)
	return out
}

// killDisarm 是摘链。每一步都 Optional：保护可能只挂上了一族，也可能早被清理过，
// 而这些都不该让一次「解除保护」失败——失败会留下一串 DROP，
// 而用户此刻最需要的正是流量恢复正常。
func killDisarm(bin, family string) []Cmd {
	return []Cmd{
		{Bin: bin, Args: []string{"-t", "filter", "-D", "OUTPUT", "-j", KillChain},
			Desc: family + " 断网保护：从 OUTPUT 摘掉", Optional: true},
		{Bin: bin, Args: []string{"-t", "filter", "-F", KillChain},
			Desc: family + " 断网保护：清空链", Optional: true},
		{Bin: bin, Args: []string{"-t", "filter", "-X", KillChain},
			Desc: family + " 断网保护：删除链", Optional: true},
	}
}

func toAllows(cidrs []string) []killAllow {
	out := make([]killAllow, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, killAllow{c, "节点与 DNS 上游出口"})
	}
	return out
}

// dedupeKill 按地址去重，保留第一次出现时的说明。
//
// 必须去重：同一个节点地址会同时出现在 route_exclude、bypass 和 allow 里，
// 重复的 ACCEPT 规则会一路挂到摘链为止，而日志里全是看不出区别的行。
func dedupeKill(in []killAllow) []killAllow {
	seen := make(map[string]bool, len(in))
	out := make([]killAllow, 0, len(in))
	for _, a := range in {
		if a.cidr == "" || seen[a.cidr] {
			continue
		}
		seen[a.cidr] = true
		out = append(out, a)
	}
	return out
}

// KillDisarmCmds 是两族的摘链命令，不需要计划。
//
// 残链清理要的正是这个：面板被杀在故障期间时，下一个读到的东西只剩链名，
// 而当初那份计划早就不在了。
func KillDisarmCmds() []Cmd {
	return append(killDisarm("iptables", "IPv4"), killDisarm("ip6tables", "IPv6")...)
}

// CleanupKill 是「摘下断网保护」的唯一实现：本进程摘链、helper 摘链、启动时的
// 残留清理三条路都走它。判据也只写这一份——DNS 那边曾经因为「三条执行路各有各的
// 容忍判据」踩过一次（见 §9.1b），这里不再复制第二份。
//
// 这一步不能省：那条链拦的是本机所有出站。面板异常退出后如果它还在，
// 用户的机器看起来就是「断了网」，而罪魁祸首是一个已经没有主人去摘的规则。
func CleanupKill(ctx context.Context, r Runner) []string {
	if r == nil {
		r = ExecRunner{}
	}
	// 先把每一份挂载点扫掉：-D 一次只摘一份，链被引用着的时候 -X 删不掉它，
	// 于是「已关闭」的保护其实一直挂在用户的 OUTPUT 上。
	var done []string
	for _, bin := range []string{"iptables", "ip6tables"} {
		done = append(done, sweepOutputJump(ctx, r, "filter", bin, KillChain)...)
	}
	for _, c := range KillDisarmCmds() {
		if _, err := r.Run(ctx, c); err == nil {
			done = append(done, c.Desc)
		}
	}
	return done
}

// disarmTimeout 是摘链的时间预算。它独立于调用方那个可能已经花完的 ctx：
// 「解除封锁」失败留下的是仍在 DROP 的出站，比慢一点严重得多。
const disarmTimeout = 10 * time.Second

// KillState 是故障保护此刻的真实落地情况。
//
// 三个方向要分开说清，它们在界面上长得像但含义完全不同：
// Armed=false 且 Reason 为空是「还没触发」（保护本身好好的，只是没必要）；
// Armed=false 且 Reason 非空是「触发过但没装上」，也就是用户以为有、实际没有；
// Armed=true 但 V4/V6 只有一族是「只护住了一半」。
type KillState struct {
	Armed  bool   `json:"armed"`
	V4     bool   `json:"v4"`
	V6     bool   `json:"v6"`
	Reason string `json:"reason,omitempty"`
}

// InEffect 报告这一族有没有真的被保护住，供界面与能力边界判断用。
func (k KillState) InEffect() bool { return k.Armed && (k.V4 || k.V6) }

// ArmKill 挂上故障断网保护，allow 是除当前 bypass 之外必须放行的出站地址（其余节点）。
//
// 无论成功还是失败都会把结果写进 t.kill：失败也必须留痕，界面上「保护没触发」和
// 「保护触发了但没装上」是两种完全不同的状态，前者是配置，后者是故障。
func (t *TUN) ArmKill(ctx context.Context, allow []string) error {
	t.mu.Lock()
	plan, running := t.plan, t.running
	t.mu.Unlock()
	if !running {
		return t.failKill(errors.New("TUN 没在运行，挂不上断网保护（先启用全局接管）"))
	}
	if t.usesHelper() {
		reply, _, err := t.helper.Run(ctx, KillRequest(plan, t.uid, allow, true))
		if err != nil {
			// 「未生效」后面必须跟着「为什么、该动哪一边」：界面上这一格就是
			// failKill 写进去的原因，只有版本号的原文用户读不出处方。
			// 这一路不跳过——挂不上保护是真的要如实报未生效。
			advice := t.noteHelperMismatch(err.Error())
			if advice != "" {
				return t.failKill(fmt.Errorf("经 helper 挂断网保护失败: %w。%s", err, advice))
			}
			return t.failKill(fmt.Errorf("经 helper 挂断网保护失败: %w", err))
		}
		if !reply.OK {
			msg := reply.Err
			if msg == "" {
				msg = "helper 挂断网保护时报告失败"
			}
			return t.failKill(errors.New(msg))
		}
		t.clearHelperMismatch()
		t.setKill(KillState{Armed: true, V4: reply.KillV4, V6: reply.KillV6, Reason: reply.KillReason})
		return nil
	}
	kp, err := plan.PlanKill(allow)
	if err != nil {
		return t.failKill(err)
	}
	if err := Apply(ctx, t.runner, kp.Arm); err != nil {
		dctx, cancel := context.WithTimeout(context.Background(), disarmTimeout)
		defer cancel()
		for _, c := range kp.Disarm {
			_, _ = t.runner.Run(dctx, c)
		}
		return t.failKill(fmt.Errorf("断网保护挂到一半失败，已回滚，当前未生效: %w", err))
	}
	t.setKill(KillState{Armed: true, V4: kp.V4, V6: kp.V6, Reason: kp.Error()})
	return nil
}

// DisarmKill 摘下故障断网保护。没挂过时它也应当成功——语义是「出站不再受我们限制」。
//
// 用独立的时间预算而不是调用方的 ctx：这一步失败留下的是仍在 DROP 的出站流量。
func (t *TUN) DisarmKill() error {
	dctx, cancel := context.WithTimeout(context.Background(), disarmTimeout)
	defer cancel()
	if err := t.disarm(dctx); err != nil {
		return err
	}
	t.setKill(KillState{})
	return nil
}

// disarm 是摘链的本体：不加锁、不改状态。
//
// 拆 TUN 的那条路径已经持有 mu，而它同样必须把保护摘掉，所以两边共用这一段。
// 两处刻意：
//   - 不经过 PlanKill。摘链只用到链名，而那份计划可能早已不成立（strict_route 刚被关掉、
//     白名单已经变了）——那些恰恰是最需要把闸门打开的时刻。
//   - 两族一起摘，不看当初挂上了哪一族：每一步都容错，多摘一次没有代价，
//     少摘一次会留下一条仍在 DROP 的链。
func (t *TUN) disarm(ctx context.Context) error {
	if t.usesHelper() {
		minimal := RoutePlan{Device: t.conf.Device, Address: t.conf.Address}
		reply, _, err := t.helper.Run(ctx, KillRequest(minimal, t.uid, nil, false))
		if err != nil {
			// 摘这一路同样**绝不跳过**：跳过等于把一条仍在 DROP 本机所有出站的链留在机器上。
			if advice := t.noteHelperMismatch(err.Error()); advice != "" {
				return fmt.Errorf("%w。%s（摘保护这一步不能跳：那条链还在拦本机出站）", err, advice)
			}
			return err
		}
		if !reply.OK {
			msg := reply.Err
			if msg == "" {
				msg = "helper 摘断网保护时报告失败"
			}
			return errors.New(msg)
		}
		return nil
	}
	// 与本进程摘链走同一个实现：判据只有一份，重复挂载的跳转才扫得干净。
	CleanupKill(ctx, t.runner)
	return nil
}

func (t *TUN) setKill(st KillState) {
	t.mu.Lock()
	t.kill = st
	t.mu.Unlock()
}

// failKill 记下失败并把它原样返回，让调用方既能收到错误、界面也能读出原因。
func (t *TUN) failKill(err error) error {
	t.setKill(KillState{Reason: err.Error()})
	return err
}

// Kill 返回故障保护当前的落地状态。
func (t *TUN) Kill() KillState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.kill
}
