// Package diag 把"这台机器现在为什么不通"需要翻的十几处地方，收成一份可以贴走的文本。
//
// 三条硬约束，都是这块能有用之前必须先立的规矩：
//
//  1. **不发起任何对外连接。** 网络正坏的时候才是它被需要的时候；
//     一个要先把 DNS 问一遍才能出报告的工具，在最需要它的现场必然出不了报告。
//     唯一允许的探测是连自己配置的监听端口（本机回环），那是在回答"有没有人在听"。
//  2. **口令不许进输出。** 这份东西是要贴给别人看的，所以整篇渲染完之后
//     再拿配置里所有"值本身就是口令"的字段做一遍替换，而不是指望每个 section 自觉。
//     漏一处的后果是别人的节点密钥就发出去了。
//  3. **读不到就写读不到。** 配置解析失败、resolv.conf 打不开、网卡不存在——
//     每一条都要留在纸上。诊断报告里最没用的就是空白，
//     一行"读不到 + 为什么"恰恰是最有信息量的答案。
package diag

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"wps_app/internal/buildinfo"
	"wps_app/internal/config"
	"wps_app/internal/metrics"
	"wps_app/internal/netdev"
	"wps_app/internal/outbound"
	"wps_app/internal/procid"
	rulesPkg "wps_app/internal/rules"
	"wps_app/internal/sysproxy"
	"wps_app/internal/tunx"
)

// probeTimeout 是本机端口探测的预算。回环上的 connect 正常是微秒级，
// 给到几百毫秒只是为了"端口在听但 backlog 满"这种边角情况不拖住整份报告。
const probeTimeout = 400 * time.Millisecond

// resolvConfPath 是系统解析配置的位置。留成变量是因为这一节最要紧的那条判断
// ——「nameserver 落在假 IP 段里」=上一轮的 DNS 劫持没摘干净——
// 在真机上永远只在"崩过一次"之后才出现，测试里必须能把它造出来。
var resolvConfPath = "/etc/resolv.conf"

// Report 渲染诊断文本。cfgPath 指向用户那份配置；w 是输出去向（测试里是 buffer）。
//
// 它永远返回 nil error：一份"少了两节"的诊断报告比抛错有用得多，
// 每一节的失败都以一行文字的形式留在原位。
func Report(ctx context.Context, cfgPath string, w io.Writer) error {
	cfg, cfgErr := config.Load(cfgPath)
	b := &builder{}
	secrets := []string{}

	identity(b, cfgPath)
	if cfgErr != nil {
		b.section("配置")
		b.line("读不到 %s：%s", cfgPath, safeErrText(cfgErr))
		b.line("下面各节只能跳过——所有判据都来自这份配置。")
	} else {
		secrets = append(secrets, collectSecrets(cfg)...)
		inbounds(b, cfg)
		outbounds(b, cfg)
		usage(b, cfg, cfgPath)
		rules(b, cfg)
		dns(b, cfg)
		tun(b, cfg)
		ifaceSplit(b, cfg)
		sys(b, ctx, cfg, cfgPath)
	}

	text := maskAll(b.String(), secrets)
	_, err := io.WriteString(w, text)
	return err
}

// maskAll 是"一份要贴给别人看的文本"要过的两道掩码：先按形状换
// （URL 里的 user:pass@ 与 ?token=），再按值换（配置里所有"值本身就是口令"的字段）。
// Report 与 MaskText 共用它——两条路各写一遍，迟早有一边漏掉一层。
//
// 两层都要**无条件**跑。按值那层在"配置读不懂"时集合是空的，
// 而恰恰是那种情况下，配置错误的原文可能正把某行口令回显在文本里——
// 早退等于在最需要它的时候关掉它。
func maskAll(text string, secrets []string) string {
	text = maskUserInfo(text)
	if len(secrets) > 0 {
		text = mask(text, secrets)
	}
	return text
}

// MaskText 给报告之外、同样要从这台机器上出去的一份文本用（面板上的「导出日志」）。
// 判据与报告完全一致；配置读不懂时形状那层照跑，理由同上。
func MaskText(cfgPath string, text string) string {
	secrets := []string{}
	if cfg, err := config.Load(cfgPath); err == nil {
		secrets = collectSecrets(cfg)
	}
	return maskAll(text, secrets)
}

// hideURLTails / hideURLTail 只留 scheme://host，路径与查询整个隐去。
func hideURLTails(items []string) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, hideURLTail(it))
	}
	return out
}

func hideURLTail(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return safeErrText(errors.New(raw)) // 连 URL 都不是：按不可信文本洗一遍
	}
	hidden := len(u.Path) + len(u.RawQuery)
	if hidden == 0 {
		return u.Scheme + "://" + u.Host
	}
	return fmt.Sprintf("%s://%s/***（路径与参数 %d 字节已隐去）", u.Scheme, u.Host, hidden)
}

// safeErrText 把一份外部错误文本洗成可以进报告的样子。
//
// 为什么必须洗：yaml.v3 的类型错误会把**出错的那个标量原样**引出来
// （实测 `cannot unmarshal !!str \`LEAKED-AUTH\` into []config.ProxyProfile`），
// 而配置里写错类型的字段很可能正好是 auth / 口令。
// 所以引号与反引号里的内容一律换成 ***，控制字符换成点，长度截住。
func safeErrText(err error) string {
	msg := err.Error()
	msg = quotedRE.ReplaceAllString(msg, `"***"`)
	msg = backtickRE.ReplaceAllString(msg, "`***`")
	// 按字符截，不按字节：切在多字节字符中间会让报告本身带上非法 UTF-8，
	// 而这份东西是要贴给别人看的。
	if utf8.RuneCountInString(msg) > 240 {
		cut := msg
		for i := 0; i < 240; i++ {
			_, size := utf8.DecodeRuneInString(cut)
			cut = cut[size:]
		}
		msg = msg[:len(msg)-len(cut)] + "…（已截断）"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '.'
		}
		return r
	}, msg)
}

// quotedRE / backtickRE 只吃成对的短引号内容，够盖住 yaml 错误里那种 "value" 回显。
var (
	quotedRE   = regexp.MustCompile(`"[^"\n]{1,240}"`)
	backtickRE = regexp.MustCompile("`[^`\n]{1,240}`")
)

// builder 攒一节一节的行；section 只负责标题，缺什么由调用方自己写清。
type builder struct{ sb strings.Builder }

func (b *builder) section(name string) {
	b.sb.WriteString("\n## " + name + "\n")
}

func (b *builder) line(format string, args ...any) {
	b.sb.WriteString(fmt.Sprintf(format, args...) + "\n")
}

func (b *builder) String() string { return b.sb.String() }

func identity(b *builder, cfgPath string) {
	b.section("运行身份")
	// 这份东西是被贴出去看的，所以时刻要写在里面：
	// "入站没人听"到底是现在的状态，还是三小时前那次崩溃之后没重启，差一个时间戳就是两回事。
	b.line("生成于 %s", time.Now().Format("2006-01-02 15:04:05 -0700"))
	b.line("构建 %s", buildinfo.Summary())
	exe := procid.Self()
	if exe == "" {
		exe = "读不到（os.Executable 失败）"
	}
	b.line("可执行文件 %s", exe)
	b.line("进程 PID %d，uid %d", os.Getpid(), os.Getuid())
	abs := cfgPath
	if a, err := filepath.Abs(cfgPath); err == nil {
		abs = a
	}
	b.line("配置文件 %s", abs)
}

func inbounds(b *builder, cfg *config.Config) {
	b.section("入站（本机回环探测，不碰外网）")
	if len(cfg.Inbounds) == 0 {
		b.line("配置里一个入站都没有：没有端口在听，客户端无处可连。")
		return
	}
	for _, in := range cfg.Inbounds {
		listen := strings.TrimSpace(in.Listen)
		if listen == "" {
			listen = "（未填）"
		}
		state := probe(listen)
		auth := "无认证"
		if strings.TrimSpace(in.Username) != "" || strings.TrimSpace(in.Password) != "" {
			auth = "要求认证" // 只说要不要，不说是什么
		}
		b.line("%-7s %-22s %s（%s）", in.Type, listen, state, auth)
	}
}

// probe 连一下本机这个端口。它回答的是"有没有进程在听"，
// 而不是"这个代理好不好用"——后者需要外网，而外网正是可能坏掉的那一环。
func probe(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "地址写法不对（" + err.Error() + "）"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || strings.HasPrefix(host, "127.") {
		host = "127.0.0.1"
	} else {
		// 非回环地址：不真去连，只说明没测。
		// 对外连接是这份报告明令禁止的事，哪怕目标其实是本机另一块网卡。
		return "未测（监听地址不是回环）"
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), probeTimeout)
	if err != nil {
		return "没人听"
	}
	_ = c.Close()
	return "在听"
}

func outbounds(b *builder, cfg *config.Config) {
	b.section("出站节点（口令已掩码）")
	if len(cfg.Proxies) == 0 {
		b.line("配置里没有任何节点。")
		return
	}
	for _, p := range cfg.Proxies {
		mark := " "
		if p.Name == cfg.Active {
			mark = "*"
		}
		sni := strings.TrimSpace(p.Server.TLS.SNI)
		if sni == "" {
			sni = "（无 SNI）"
		}
		b.line("%s %-14s %-8s %-28s sni=%s auth=%s",
			mark, p.Name, p.Server.Type, p.Server.Addr, sni, setOrUnset(p.Server.Auth))
	}
	b.line("当前选中 %s；分流模式 %s", orNoneStr(cfg.Active, "（没选）"), orNoneStr(cfg.Mode, "rule"))
}

// usage 把"这个月哪个节点跑了多少"这件事单独列一节。
//
// 它值得单独一节，是因为这一格的读数**故意是不全的**：账本每分钟落一次盘，
// 崩溃会丢掉最后一次之后的量。别人拿着报告问"为什么面板写 68% 而我记得跑满了"，
// 答案就在这节的最后那行 caveat 里——没有它，这份报告只会把疑问换个地方再问一遍。
//
// 读的是盘上那份，不碰内存里的注册表：诊断报告要能在面板没跑的时候出。
func usage(b *builder, cfg *config.Config, cfgPath string) {
	b.section("节点用量账本（跨重启累计）")
	path := metrics.UsagePath(cfgPath)
	st, err := metrics.LoadUsage(path)
	switch {
	case errors.Is(err, metrics.ErrUsageTooNew):
		b.line("账本 %s 是本程序不认识的新版本，既不套用也不回写：%s", filepath.Base(path), safeErrText(err))
		b.line("所以面板上「累计」这一栏现在只显示本次会话。用更新的版本跑一次就会恢复。")
		return
	case err != nil:
		// 坏掉的那份已经被 LoadUsage 挪去 .bad 了——这句话要写出来，
		// 不然"账本读不出"看起来像"从来没跑过流量"。
		b.line("账本读不出（%s）：%s", filepath.Base(path), safeErrText(err))
		return
	case len(st.Nodes) == 0:
		b.line("还没有账本：要么第一次运行，要么本次还没跑过任何流量。")
		return
	}
	b.line("文件 %s，起点 %s，上次落盘 %s",
		filepath.Base(path), clockOf(st.Since), agoOf(st.SavedAt))
	known := make(map[string]struct{}, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		used := st.Nodes[p.Name]
		total := used.Up + used.Down
		q, qerr := config.ParseSize(p.Quota)
		line := fmt.Sprintf("  %-14s %s", p.Name, humanBytes(total))
		switch {
		case qerr != nil:
			// Validate 会拦住坏配额，但报告要能在"配置根本读不动"之外单独说这一格坏了。
			line += fmt.Sprintf("  配额写法有问题: %s", safeErrText(qerr))
		case q > 0:
			line += fmt.Sprintf("  配额 %s · 已用 %.1f%%", p.Quota, float64(total)/float64(q)*100)
		default:
			line += "  （没设配额）"
		}
		b.line("%s", line)
		known[p.Name] = struct{}{}
	}
	// 直连那一桶单独说：它不是节点，但那些字节确实经过了这台机器。
	// 把它悄悄丢掉的话，报告里各节点之和会比真实用量少一截，
	// 而"少一截"正是这份报告最不该有的性质。
	if v, ok := st.Nodes[string(outbound.PolicyDirect)]; ok {
		b.line("  %-14s %s  （直连：这些字节没走任何节点）", string(outbound.PolicyDirect), humanBytes(v.Up+v.Down))
	}
	// 账本里有、配置里已经没有的节点：改名或删除之后旧账还挂在盘上。
	// 不说出来，人会觉得"这个节点我早删了怎么还有量"。
	for name, v := range st.Nodes {
		// DIRECT 不是节点，是"这些字节没走任何节点"那个桶（见 metrics.nodeCounts）：
		// 它永远不会出现在配置的节点列表里，所以把它报成"已删除的节点"是在说假话。
		// 这条是拿真账本跑出来的——第一次跑就撞上 12MB 的 DIRECT 被指成了幽灵节点。
		if _, ok := known[name]; ok || !nodeCounts(name) || name == string(outbound.PolicyDirect) {
			continue
		}
		b.line("  %-14s %s  （配置里已经没有这个节点，旧账还留在账本上）", name, humanBytes(v.Up+v.Down))
	}
	b.line("落盘是每分钟一次外加停止时那一次：崩溃或强杀会丢掉最后一次之后的量，")
	b.line("所以这一节的数字只会比真实用量少，不会多。")
}

// nodeCounts 与 metrics 里那条判据同义：空串与 REJECT 不占账。
func nodeCounts(n string) bool { return n != "" && n != "REJECT" }

// humanBytes 是报告用的读数：给一个能读的档位，同时把精确字节带上。
// 诊断里"约 6.9 GB"不够用——差一个数量级的时候需要能看出到底是多少。
func humanBytes(n uint64) string {
	const unit = 1e9
	if n < 1e6 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1e9 {
		return fmt.Sprintf("%.1f MB (%d B)", float64(n)/1e6, n)
	}
	return fmt.Sprintf("%.2f GB (%d B)", float64(n)/unit, n)
}

// clockOf / agoOf 把 Unix 毫秒翻成人话；0 是"没有这个时刻"，不能印成 1970。
func clockOf(ms int64) string {
	if ms <= 0 {
		return "（未知）"
	}
	return time.UnixMilli(ms).Format("2006-01-02 15:04")
}

func agoOf(ms int64) string {
	if ms <= 0 {
		return "（从未）"
	}
	return humanAge(time.Since(time.UnixMilli(ms)))
}

func rules(b *builder, cfg *config.Config) {
	b.section("规则与拦截")
	geo, geoErr := rulesPkg.OpenGeoIP(cfg.GeoIP.Path)
	if geoErr != nil {
		b.line("GeoIP %s 读不到：%v —— 只有 GEOIP 类规则会受影响", cfg.GeoIP.Path, geoErr)
	} else if st, err := os.Stat(cfg.GeoIP.Path); err == nil {
		b.line("GeoIP %s：%d 字节，改动于 %s",
			cfg.GeoIP.Path, st.Size(), st.ModTime().Format("2006-01-02 15:04:05"))
	}
	// 装的是引擎那份，不是配置那份：数字对不上才说明"写了但没装上"，
	// 而面板上看到的从来就是引擎那份。两边各说一遍就是两份会互相矛盾的真相。
	// 规则装不上不提前 return：订阅那一叠还在同一节里，
	// 而"为什么装不上"的答案常常正是某条订阅没拉到——少说一行就等于把线索一起扔了。
	if engine, err := rulesPkg.Load(cfg.RulesFile, rulesPkg.NewGeoRef(geo), nil); err != nil {
		b.line("规则加载失败：%s", safeErrText(err))
		b.line("（这一条足以解释「所有流量都直连/都不通」，先修它再看别的。）")
	} else {
		engine.SetBlocklist(cfg.Block.Domains)
		dom, ip := engine.Stats()
		b.line("规则 %s：域名 %d 条，IP 类 %d 条，FINAL=%s", cfg.RulesFile, dom, ip, engine.Final())
		for _, sk := range engine.Skipped() {
			b.line("  可选 #include 被跳过：%v", sk)
		}
		b.line("拦截名单：配置写了 %d 条，引擎装上 %d 条（命中即静默丢弃）",
			len(cfg.Block.Domains), len(engine.BlockDomains()))
		// 引擎真的打开过哪些文件——这份清单回答的是"我改哪份才会生效"。
		// 只看 rules_file 会漏掉最常见的那种编辑：改的是 #include 进来的那一份。
		// 带上大小与改动时间，是因为"改了没生效"的下一步永远是"它到底读了没"。
		srcs := engine.Sources()
		b.line("引擎实际读取的规则文件（%d 份）：", len(srcs))
		for _, f := range srcs {
			if st, err := os.Stat(f); err == nil {
				b.line("  %s（%d 字节，改动于 %s）", f, st.Size(),
					st.ModTime().Format("2006-01-02 15:04:05"))
			} else {
				b.line("  %s（读不到：%v）", f, safeErrText(err))
			}
		}
	}
	for _, rp := range cfg.RuleProviders {
		on := "开"
		if rp.Enabled != nil && !*rp.Enabled {
			on = "关"
		}
		// URL 原样打出来：口令段由掩码统一抹掉，
		// 而"这个订阅其实指向内网"恰恰是拉不下来的常见原因。
		// 别把 Go 的 6h0m0s 印进一份给人看的报告里。
		interval := "默认 24 小时"
		if rp.Interval.Duration > 0 {
			interval = humanAge(rp.Interval.Duration)
		}
		b.line("订阅 %-12s %s（%s）缓存 %s，间隔 %s",
			rp.Name, on, orNoneStr(hideURLTail(rp.URL), "（没有 url）"),
			orNoneStr(rp.Path, "（默认路径）"), interval)
		// 配置写了不等于在更新：这一行才是证据。缓存文件的 mtime 就是
		// "上一次真的拉到内容"的时刻（拉失败不动文件），所以它能回答
		// "订阅配了三天，规则到底是新的还是启动那一次的"。
		// 只报文件现状，不假装知道运行中那个循环上次几点拉的——那是另一个进程的事。
		cache := cfg.ProviderPath(rp)
		if st, err := os.Stat(cache); err != nil {
			why := safeErrText(err)
			if errors.Is(err, os.ErrNotExist) {
				why = "不存在"
			}
			b.line("  缓存 %s %s —— 这段规则现在不在引擎里", cache, why)
		} else {
			b.line("  缓存 %s：%d 字节，改动于 %s（%s前）",
				cache, st.Size(), st.ModTime().Format("2006-01-02 15:04:05"),
				humanAge(time.Since(st.ModTime())))
		}
	}
}

func dns(b *builder, cfg *config.Config) {
	b.section("DNS")
	if len(cfg.DNS.Servers) == 0 {
		b.line("配置里没写上游 DNS。")
	} else {
		b.line("配置的上游：%s", strings.Join(hideURLTails(cfg.DNS.Servers), ", "))
	}
	raw, err := os.ReadFile(resolvConfPath)
	if err != nil {
		b.line("%s 读不到：%v", resolvConfPath, err)
		return
	}
	var names []string
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "nameserver"); ok {
			if v := strings.TrimSpace(rest); v != "" {
				names = append(names, v)
			}
		}
	}
	if len(names) == 0 {
		b.line("%s 里一条 nameserver 都没有：这台机器上没人能解析域名。", resolvConfPath)
		return
	}
	b.line("系统当前在问：%s", strings.Join(names, ", "))
	for _, n := range names {
		// 127.0.0.53 是 resolved 的存根，正常；指向假 IP 段才是"上一轮劫持没摘干净"。
		if ip := net.ParseIP(n); ip != nil && inFakeRange(ip, cfg) {
			b.line("  %s 落在假 IP 段里：DNS 劫持的残留，本机解析会拿到 198.18.x 这种地址。", n)
			b.line("  救回来：sudo %s -tun-reset（拆网卡与摘 iptables），或让面板正常退出一次。", procid.Self())
		}
	}
}

func inFakeRange(ip net.IP, cfg *config.Config) bool {
	for _, cidr := range []string{cfg.TUN.FakeIPRange, cfg.TUN.FakeIPRange6} {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, netBlock, err := net.ParseCIDR(cidr)
		if err == nil && netBlock.Contains(ip) {
			return true
		}
	}
	return false
}

func tun(b *builder, cfg *config.Config) {
	b.section("TUN")
	if !cfg.TUN.Enable {
		b.line("配置里没开 TUN：不建网卡、不装 iptables 劫持，这是默认。")
		return
	}
	dev := orNoneStr(cfg.TUN.Device, "wps-tun")
	iface, err := net.InterfaceByName(dev)
	switch {
	case err != nil:
		b.line("网卡 %s 不存在（%v）", dev, err)
	default:
		b.line("网卡 %s 在：index %d，状态 %s", dev, iface.Index, iface.Flags.String())
	}
	if len(cfg.TUN.Helper) == 0 {
		b.line("没配 tun.helper：以当前 uid %d 直接建网卡，非 root 会失败。", os.Getuid())
	} else {
		b.line("提权 helper：%s", strings.Join(cfg.TUN.Helper, " "))
	}
	b.line("假 IP 段 %s；DNS 劫持 %s；严格路由 %s",
		orNoneStr(cfg.TUN.FakeIPRange, "（未配）"),
		yesNo(cfg.TUN.HijackDNS), onOff(cfg.TUN.StrictRoute))
	for _, note := range tunx.CapabilityNotes(cfg) {
		b.line("注意：%s", note)
	}
}

// ifaceSplit 讲清"分流到底有没有在跑"。这节是为那种"开关开了却没反应"的报障写的：
// 不生效的原因只有几种（没开、模式不对、只找到一张卡、内核不给绑），全写在这里，
// 免得每次都得回去读代码猜。
func ifaceSplit(b *builder, cfg *config.Config) {
	b.section("网卡分流（内置直连 / USB 代理，可点名改）")
	set := netdev.Detect()
	b.line("探测到的无线网卡：%s", set.Describe())
	if !cfg.IfaceSplit.Enable {
		b.line("配置里没开 iface_split：直连与代理都按系统默认路由走，这是默认。")
		return
	}
	if cfg.IfaceSplit.Direct.Dev != "" || cfg.IfaceSplit.Proxy.Dev != "" {
		b.line("点名：直连 %s，代理 %s（空串即交给系统默认路由）",
			nameOrAuto(cfg.IfaceSplit.Direct.Dev), nameOrAuto(cfg.IfaceSplit.Proxy.Dev))
	}
	if cfg.Mode != string(config.ModeRule) {
		b.line("已开，但当前是 %s 模式：只有规则模式才分流，现在按默认路由走。", cfg.Mode)
		return
	}
	d, p, why := set.Resolve(choiceOf(cfg.IfaceSplit.Direct), choiceOf(cfg.IfaceSplit.Proxy))
	if d.Name == "" || p.Name == "" {
		if why == "" {
			why = "只凑齐一张卡"
		}
		b.line("已开，规则模式，但%s：不分流，按默认路由走。", why)
		return
	}
	if why != "" {
		b.line("注意：%s", why)
	}
	b.line("已开，规则模式：直连钉在 %s（%s），代理钉在 %s（%s）",
		d.Name, strings.Join(d.Addrs, "、"), p.Name, strings.Join(p.Addrs, "、"))
	// 权限探测只建一个空 UDP 套接字再设一次选项，一个字节都不往外发。
	for _, dev := range []string{d.Name, p.Name} {
		if err := outbound.ProbeDeviceBind(dev); err != nil {
			b.line("钉不到 %s：%v（内核拒绝时表现为分流看着开着、流量其实仍走默认路由）", dev, err)
		}
	}
}

// choiceOf 把配置里的点名转成 netdev 的说法。
func choiceOf(c config.IfaceCard) netdev.Choice {
	return netdev.Choice{Dev: c.Dev, USB: c.USB}
}

func nameOrAuto(dev string) string {
	if dev == "" {
		return "（自动挑）"
	}
	return dev
}

func onOff(v bool) string {
	if v {
		return "开"
	}
	return "关"
}

func yesNo(p *bool) string {
	if p == nil {
		return "默认（开）"
	}
	if *p {
		return "开"
	}
	return "关"
}

func sys(b *builder, ctx context.Context, cfg *config.Config, cfgPath string) {
	b.section("系统代理")
	_, httpAddr, socksAddr := cfg.SystemProxyTarget()
	st, err := sysproxy.ReadWith(ctx, nil, cfg.SysProxy.Backend)
	switch {
	case err != nil && !st.Supported:
		b.line("这台机器上没有可用的后端（gsettings / kioslaverc / environment.d 都不在）")
	case err != nil:
		b.line("读不到桌面设置：%v", err)
	default:
		b.line("后端 %s，mode=%s，http=%s，socks=%s", st.Backend, orNoneStr(st.Mode, "（空）"), st.HTTP, st.SOCKS)
		if st.Path != "" {
			b.line("  改动落在 %s", st.Path)
		}
		if st.Note != "" {
			b.line("  注意：%s", st.Note)
		}
	}
	led, lerr := sysproxy.ReadLedger(sysproxy.StatePath(cfgPath))
	switch {
	case lerr != nil:
		b.line("记账读不懂：%s", led.ReadErr)
	case !led.Exists:
		if err == nil && sysproxy.LikesOurs(st, sysproxy.Config{
			Enable: true, HTTPAddr: httpAddr, SOCKSAddr: socksAddr,
		}) {
			b.line("没有记账，而桌面正指着本程序的入站：%s", sysproxy.OrphanHint(sysproxy.StatePath(cfgPath)))
			return
		}
		b.line("没有记账：桌面那组设置不是本程序改的，退出不欠还原")
	case led.Alive:
		b.line("记账在（%s 由 %s 后端记下）：%s", led.SavedAt.Format("2006-01-02 15:04:05"), led.Backend, led.Holder)
	default:
		b.line("记账在，但%s：下次启动会自动还一次", led.Holder)
	}
}

// collectSecrets 把所有"值本身就是口令"的配置字段收出来。
//
// 名单是按字段语义挑的，不是按字符串长相猜的：漏一个就把别人的密钥贴到公聊里，
// 多一个（比如把节点地址也掩了）则让这份报告失去意义。
func collectSecrets(cfg *config.Config) []string {
	out := []string{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		// 单个字符也算口令的话，掩码会把整篇正文啃穿（"a" 到处都是）。
		if len(s) >= 3 {
			out = append(out, s)
		}
	}
	for _, p := range cfg.Proxies {
		add(p.Server.Auth)
	}
	for _, in := range cfg.Inbounds {
		add(in.Username)
		add(in.Password)
	}
	// 订阅 URL 不带 token 字段（内网部署的约定），所以这里没有要收的口令。
	return out
}

// userInfoRE 匹配 scheme://user:pass@host 里的凭据段。
// 配置之外的地方（订阅 URL、DNS 服务器写法）也可能带口令，所以补这一刀。
var userInfoRE = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@`)

// querySecretRE 兜住订阅地址里那种把口令挂在查询串上的写法
// （?token=、?key=、?auth=…）。这类 URL 会被原样打进报告里，
// 而"订阅拉不下来"恰恰需要把 URL 贴给别人看。
// 取值部分只吃 URL 里合法的那批字符：早先用 [^&#\s]* 会把紧跟其后的
// 中文括号、逗号一并吞掉，报告里就出现"半个括号"这种没人能读的排版。
var querySecretRE = regexp.MustCompile(`(?i)([?&](?:key|token|auth|password|passwd|secret|sig|signature)=)[A-Za-z0-9._~+/%$-]*`)

func maskUserInfo(text string) string {
	text = userInfoRE.ReplaceAllString(text, "${1}***@")
	return querySecretRE.ReplaceAllString(text, "${1}***")
}

// mask 把文本里出现过的每个口令换成 ***。
// 先按长度降序替换：短口令是长口令的子串时，先换短的会把长口令切碎、留下半截。
func mask(text string, secrets []string) string {
	sorted := append([]string(nil), secrets...)
	sortByLengthDesc(sorted)
	for _, s := range sorted {
		if strings.Contains(text, s) {
			text = strings.ReplaceAll(text, s, "***")
		}
	}
	return text
}

func sortByLengthDesc(items []string) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && len(items[j]) > len(items[j-1]); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

func setOrUnset(v string) string {
	if strings.TrimSpace(v) == "" {
		return "未设置"
	}
	return "已设置"
}

func orNoneStr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// humanAge 把"多久没动过"说成人话。诊断报告要的是量级：
// "2 小时 13 分"和"7813 秒"是同一个数，但只有前者能一眼看出订阅是不是停了。
func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "不到 1 分钟"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时 %d 分", int(d.Hours()), int(d.Minutes())%60)
	default:
		days := int(d.Hours()) / 24
		hours := int(d.Hours()) % 24
		return fmt.Sprintf("%d 天 %d 小时", days, hours)
	}
}
