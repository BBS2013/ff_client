// Package rules 实现文本规则集的解析与匹配。
package rules

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// Policy 是规则可指定的出站策略。
type Policy string

const (
	PolicyDirect Policy = "DIRECT"
	PolicyProxy  Policy = "PROXY"
	// PolicyReject 是「不许出网」。本实现里它是**静默丢弃**：
	// 不回拒绝信息、连接由发起方自己等到超时，REJECT 与 REJECT-DROP 都归到这里。
	// 注意这与 Clash 的 REJECT（发 RST）不同——照着 Clash 的预期排查会找不到现象。
	PolicyReject Policy = "REJECT"
)

// Policies 返回全部可用的分流策略。
//
// 导出来是为了让下游能**遍历**它做守卫测试：Go 没法反射常量，
// 新增一个 Policy 时编译器不会提醒任何一处 switch 漏了分支，
// 而漏掉的那里全都写成"落到 default"。遍历这张表就能把"你没决定"变成测试失败。
func Policies() []Policy {
	return []Policy{PolicyDirect, PolicyProxy, PolicyReject}
}

// ErrBlocked 表示目标被拦截名单拦下，不是"拨不通"也不是节点故障。
// 三个入站靠它区分「静默丢弃」与「报错」。
var ErrBlocked = errors.New("命中拦截名单")

// BlockHold 是被拦连接继续挂着的时长，到点才关。
//
// 客户端侧既然什么都收不到，就不能真的永久挂着：浏览器对一批广告域会同时
// 发十几条，挂满就是 fd 堆积。这个值由所有入站共用，改一处即可。
const BlockHold = 75 * time.Second

func parsePolicy(s string) (Policy, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DIRECT":
		return PolicyDirect, true
	case "PROXY", "PROXY-HY2", "HY2":
		return PolicyProxy, true
	case "REJECT", "REJECT-DROP":
		return PolicyReject, true
	}
	return "", false
}

type kind int

const (
	kindDomain kind = iota
	kindDomainSuffix
	kindDomainKeyword
	kindDomainRegex
	kindIPCIDR
	kindGeoIP
	// kindCount 是"一共有几种 kind"的哨兵，只给遍历用（守卫用例要能
	// 自动覆盖到以后新增的类型，而不是靠人记得来补一行）。
	kindCount
)

var kindNames = map[kind]string{
	kindDomain:        "DOMAIN",
	kindDomainSuffix:  "DOMAIN-SUFFIX",
	kindDomainKeyword: "DOMAIN-KEYWORD",
	kindDomainRegex:   "DOMAIN-REGEX",
	kindIPCIDR:        "IP-CIDR",
	kindGeoIP:         "GEOIP",
}

var kindByName = map[string]kind{
	"DOMAIN":         kindDomain,
	"DOMAIN-SUFFIX":  kindDomainSuffix,
	"DOMAIN-KEYWORD": kindDomainKeyword,
	"DOMAIN-REGEX":   kindDomainRegex,
	"IP-CIDR":        kindIPCIDR,
	"GEOIP":          kindGeoIP,
}

// maxRegexLen 给 DOMAIN-REGEX 的模式长度封顶（字节）。
//
// 规则文件的来源之一是远端订阅，模式文本不归本机用户管。正则要编译，
// 不封顶的话一行就能塞进 1MB 的模式（Scanner 的单行上限）让每次加载去编译它，
// 而那条规则的 desc() 还会原样进日志与连接表。
// 正常域名模式远到不了这个长度——够写 `^.*\.(co|com)\.(uk|jp)$` 这种，
// 装不下一条用来撑爆日志的垃圾。
const maxRegexLen = 128

// maxNodeLen 给 node= 里那个节点名封顶。它会原样进日志、连接表和面板，
// 而规则文件的来源之一是远端订阅；正常节点名（sanitizeName 出来的）远到不了这个长度。
const maxNodeLen = 64

// splitNodeToken 认出 "node=<节点名>" 这一档可选字段（键名大小写不敏感）。
//
// 第二个返回值说的是"这是不是 node= 写法"，不是"名字合不合法"：
// 空名字、超长、带控制字符都要继续走下去当场报错，
// 悄悄把它当成普通值收下等于凭空多出一个"规则值"，那一行就再也对不上任何节点了。
func splitNodeToken(f string) (string, bool) {
	const kw = "node="
	if len(f) < len(kw) || !strings.EqualFold(f[:len(kw)], kw) {
		return "", false
	}
	return strings.TrimSpace(f[len(kw):]), true
}

// Resolver 由 dnsx 实现，供需要 IP 的规则触发解析。
type Resolver interface {
	LookupIP(ctx context.Context, host string) ([]netip.Addr, error)
}

// GeoLookup 抽象 mmdb 查询，便于测试替换。
type GeoLookup interface {
	Country(ip netip.Addr) (string, bool)
}

type rule struct {
	kind      kind
	value     string
	policy    Policy
	noResolve bool
	prefix    netip.Prefix
	// off = 这一条被**停用**了：还写在文件里、还在面板上，但不参与匹配。
	// 用 `,off` 这个可选字段而不是把整行注释掉，是因为注释掉的行在
	// parseUserRules 那一层就被跳过了——面板就再也看不见它，
	// 而下一次整表回写会把它连同用户想保留的东西一起抹掉。
	// "暂时不生效但还在、还能一键打开"这件事，必须是一个能round-trip的字段。
	off bool
	// node 非空 = 这条规则把 PROXY 流量钉到配置里那个名字的节点，
	// 而不是"当前选中的那个"。只有 PolicyProxy 允许带它（理由见 parseLine）。
	node string
	// re 是 kindDomainRegex 在**加载时**编译好的模式。
	// 编译放在解析期而不是匹配期：匹配每条连接都要跑，而规则集一天才换一次；
	// 语法错误更必须在加载时就响，而不是等某条连接走到那条规则时才"不命中"。
	re   *regexp.Regexp
	line int
	// fromConfig 标记这条来自 block: 段。两处都能拦时，
	// 日志要说清是哪一侧拦的，否则用户会去翻那份几千行的规则文件。
	fromConfig bool
}

func (r rule) desc() string {
	s := fmt.Sprintf("%s,%s,%s", kindNames[r.kind], r.value, r.policy)
	if r.node != "" {
		// 钉了哪个节点必须进命中依据：连接表、日志与面板上"这条走了谁"只有这一处说法。
		// 不写出来的话，固定节点的连接和普通 PROXY 在界面上就长得一模一样。
		s += "(node=" + r.node + ")"
	}
	if r.noResolve {
		s += ",no-resolve"
	}
	if r.fromConfig {
		s += "(block)"
	}
	return s
}

// matchDomain 判断域名是否命中（host 已小写去尾点）。
//
// DOMAIN-REGEX 走的是**不锚定**的正则（和 Clash 一致）：`^` 与 `$` 要自己写。
// 这一条是刻意选的失败方向——写漏锚点的模式会**多拦**而不是少拦，
// 而"漏拦"在这套语义里是完全静默的（黑名单上凭空开个洞，没人看得出来），
// "多拦"至少表现为"这个网站打不开"，用户当场就能发现。
func (r rule) matchDomain(host string) bool {
	switch r.kind {
	case kindDomain:
		return host == r.value
	case kindDomainSuffix:
		return host == r.value || strings.HasSuffix(host, "."+r.value)
	case kindDomainKeyword:
		return strings.Contains(host, r.value)
	case kindDomainRegex:
		// re 为 nil 只可能是有人绕过 parseLine 直接构造了这条规则。
		// 这里不判就会 panic，而 panic 发生在转发路径上=整条连接带崩进程。
		return r.re != nil && r.re.MatchString(host)
	}
	return false
}

// Engine 是编译后的规则集，不可变，可被多个连接并发使用。
type Engine struct {
	// blockRules 来自配置的 block: 段，永远先于规则文件匹配。
	// 单独存一个切片而不是拼进 domainRules：热重载时整块替换即可，
	// 不必在几千条规则里找回上一次插进去的那几条。
	blockRules  []rule
	domainRules []rule
	ipRules     []rule
	finalPolicy Policy
	// skipped 记录因缺失而被跳过的可选 #include，仅用于启动日志提示。
	skipped []string
	// sources 是这次编译**真的打开过**的文件（含顶层规则文件与每个命中的 include）。
	// 热重载的监视器盯的就是这一份清单：只看 rules_file 的 mtime，会漏掉
	// 用户直接编辑 `assets/user-rules.txt` 或订阅缓存那种改动——那才是最常见的。
	sources []string

	geo         GeoLookup
	resolver    Resolver
	needResolve bool
}

// maxIncludeDepth 限制 #include 嵌套层数，防止 include 自环导致无限递归。
const maxIncludeDepth = 8

// maxIncludePathLen 给订阅里一行垃圾留出上限：正常路径不会超过几十个字符，
// 而 Scanner 允许一行 1MB，不 clamp 的话整段垃圾会跟着错误信息进日志。
const maxIncludePathLen = 512

// Load 读取规则文件并编译。geo 可为 nil，但规则集中出现 GEOIP 时会报错。
//
// 规则文件中可写 "#include <路径>" 把另一份规则文件原地展开，路径相对于
// 当前文件所在目录。加问号写成 "#include? <路径>" 则为可选：文件不存在时
// 静默跳过并记入 Skipped()，便于用户按需开关大规则集而不影响启动。
//
// include 被钉在**顶层规则文件所在的那个目录**里，出不去（见 resolveInclude）：
// 其中一份内容可能来自远端订阅，让它读走任意文件是实打实的泄露。
func Load(path string, geo GeoLookup, resolver Resolver) (*Engine, error) {
	return LoadFrom(path, "", geo, resolver)
}

// LoadFrom 与 Load 相同，只是把 include 的允许目录钉在 root 而不是这份文件自己的目录。
//
// 订阅校验需要它：被验的那份文件写在 providers/ 里，而真正加载它的是上一层目录里的
// rules.txt。用文件自己的目录当根，`#include ../sub.txt` 这种正常写法就会被判成越界。
// root 传空串即"就用这份文件的目录"，与 Load 一致。
func LoadFrom(path, root string, geo GeoLookup, resolver Resolver) (*Engine, error) {
	e := &Engine{geo: geo, resolver: resolver, finalPolicy: PolicyProxy}
	seenFinal := false
	if root == "" {
		root = includeRoot(path)
	} else {
		root = absClean(root)
	}
	if err := loadFile(path, 0, root, e, &seenFinal); err != nil {
		return nil, err
	}
	if len(e.domainRules) == 0 && len(e.ipRules) == 0 {
		return nil, fmt.Errorf("%s: no usable rules found", path)
	}
	return e, nil
}

// includeRoot 是 include 允许触及的目录：顶层规则文件所在目录。
//
// 刻意**不**解软链：比较的另一边（filepath.Dir(被 include 的路径)）也没解，
// 两边必须同一基准才比得出东西。早先这里解了一次，于是
// 规则文件只要放在任何带软链的路径上（/tmp 被链走、home 是链接、Nix 那类布局），
// root 变成解析后的绝对路径而 joined 还是原样的相对/未解析形态，
// Rel 算不出来 → 每一条 #include 都被判"越界"，代理直接起不来。
// 软链逃逸另有专门的检查（见 resolveInclude）。
func includeRoot(path string) string {
	return absClean(filepath.Dir(path))
}

// absClean 转成绝对形式并清掉 . 与 ..，但**不解软链**。
//
// 两边必须同一基准：一边解析、一边没解析时，Rel 算不出来，
// 于是合法路径会被判成"越界"——这条是被真实事故教出来的
// （规则目录带软链时，原本能用的 #include 全部被拒，代理起不来）。
func absClean(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	return filepath.Clean(abs)
}

// resolveInclude 把 #include 后面的路径算成实际要打开的文件，并拒绝越界。
//
// 为什么要管到这一步：规则文件里有一条来源是远端订阅的缓存（providers/*.txt），
// 那份内容不归本机用户管。原来允许绝对路径，实测在订阅里写
//
//	#include /home/<user>/.ssh/id_rsa
//
// 就会把那文件的第一行原样拼进错误信息里（rule "…" needs at least TYPE and POLICY），
// 而错误会进日志、会显示在面板上——一条"读走任意文件的一行"就此成立。
// 相对路径同理：../ 也出得去，软链更不用。
func resolveInclude(base, root, raw string) (string, error) {
	if len(raw) > maxIncludePathLen {
		// 不回显路径本身：它可能是订阅里塞的一整段垃圾。
		return "", fmt.Errorf("#include 的路径过长（%d 字节，上限 %d）", len(raw), maxIncludePathLen)
	}
	if filepath.IsAbs(raw) {
		return "", fmt.Errorf("#include 只接受规则目录内的相对路径，收到绝对路径 %q", clip(raw))
	}
	joined := absClean(filepath.Join(base, raw))
	if escaped(joined, root) {
		return "", fmt.Errorf("#include %q 指到了规则目录 %s 之外", clip(raw), clip(root))
	}
	// 目录里放一个指向 /etc 的软链，Clean 查不出来。这一层要两边都解析过才比得出，
	// 任何一边解析不了（文件还不存在、链断了）就放过——上面那道 Clean 比较仍然生效，
	// 而"文件不存在"该由 open 去说，不是在这里编一个越界的理由。
	if target, err := filepath.EvalSymlinks(joined); err == nil {
		if resolvedRoot, rerr := filepath.EvalSymlinks(root); rerr == nil && escaped(target, resolvedRoot) {
			return "", fmt.Errorf("#include %q 经软链指到了规则目录之外", clip(raw))
		}
	}
	return joined, nil
}

// safeText 把"要进错误信息的文本"里非法 UTF-8 与控制字符转成 %q 的可打印形式。
//
// 错误信息会进日志、也会原样显示在面板上，而文本的另一头可能是远端订阅里的一行。
// 直接带出去等于把 ESC/BS/NUL 塞进终端与界面。
//
// 用在 Skipped() 上时**不截长度**：那份列表是给人看"到底哪个文件没到"的，
// 截断就没意义了；只有混进非法字节时才换成 %q。
func safeText(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return s
	}
	return strconv.Quote(s)
}

// briefPath 是 safeText 的路径版本：合法可打印的原样保留，其余先截短再转义。
//
// 为什么不能直接套 brief：真实路径上百字节是常态（临时目录、深层 assets、
// 用户自己起的中文目录名），截到 48 个字符等于让用户看不出到底是哪个文件坏了。
// 真正会顶穿错误信息长度上限的只有非法那一类——转义把每个字节展开成四个字符，
// 订阅里一行 512 字节的垃圾路径因此能撑出 2KB，再乘上 include 的嵌套层数。
// 所以只对这一类动手，而且是在转义**之前**先截，展开才有界。
func briefPath(p string) string {
	if utf8.ValidString(p) && !strings.ContainsFunc(p, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return p
	}
	return strconv.Quote(clip(p))
}

// unreadableAsMissing 判断"这个文件打不开"是不是等同于"它不在那儿"。
//
// 可选 #include 的语义是"没有就算了"，所以除了 ENOENT，还得认 ENOTDIR
// （`#include? file/x`：把某个文件当目录用）、ENAMETOOLONG、ELOOP——
// 这些都可能是远端订阅里的一行造成的。只认 ENOENT 的话，
// 一条这样的垃圾行就能让整个引擎拒绝启动，等于让订阅把代理打死。
func unreadableAsMissing(err error) bool {
	for _, target := range []error{fs.ErrNotExist, syscall.ENOTDIR, syscall.ENAMETOOLONG, syscall.ELOOP} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// escaped 判断一个已规范化的路径是否落在 root 之外（等于 root 本身也算在内）。
func escaped(p, root string) bool {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return true // 一个绝对一个相对之类，算不出来就当场拦下
	}
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// loadFile 解析单个规则文件并把规则追加到 e。
func loadFile(path string, depth int, root string, e *Engine, seenFinal *bool) error {
	// where 是这个路径"给人看"的那一份，错误信息一律用它，不用 path。
	// path 可能来自远端订阅里的一行：include 的原始路径上限是 512 字节，
	// 而 PathError 会把非 ASCII 字节按 \xNN 展开（一个字符变四个），
	// 512 字节的中文路径因此能撑出 2KB 的错误信息，再乘上 include 嵌套层数。
	// 打开文件用的仍然是完整的 path——截断只发生在要给人看的那一份上。
	where := briefPath(path)
	if depth > maxIncludeDepth {
		return fmt.Errorf("%s: #include nesting too deep", where)
	}
	f, err := os.Open(path)
	if err != nil {
		// 路径可能来自远端订阅里的一行，两件事都不能让它原样进日志与面板：
		// 非法 UTF-8 字节，以及 briefPath 说的那个"转义把长度顶穿"。
		// 只换 PathError 里那份路径文本，错误本身照旧向上冒——
		// 可选 #include 靠 errors.Is(err, fs.ErrNotExist) 判"不存在"，换掉就失灵了。
		var pe *fs.PathError
		if errors.As(err, &pe) {
			pe.Path = briefPath(pe.Path)
		}
		return err
	}
	defer f.Close()

	// 相对路径按**当前这个文件**所在目录解析。
	// 早先这里传的是上一层的 base，也就是顶层规则文件的目录，于是嵌套的
	// #include 会从顶层目录去找：providers/cn.txt 里的 `../extra.txt`
	// 被解析成 <顶层目录>/../extra.txt。写成 #include? 时不报错，
	// 只是那一段规则凭空消失——分流开始出错却没有任何线索。
	base := filepath.Dir(path)
	e.sources = append(e.sources, path)

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())

		if inc, optional, ok := trimIncludeDirective(raw); ok {
			inc = strings.TrimSpace(inc)
			if inc == "" {
				return fmt.Errorf("%s:%d: #include 需要一个文件路径", where, lineNo)
			}
			if len(inc) > maxIncludePathLen {
				// 可选的那一条只记一个占位：整段垃圾既没意义也会撑大日志与面板。
				if optional {
					e.skipped = append(e.skipped, fmt.Sprintf("<路径过长：%d 字节，已跳过>", len(inc)))
					continue
				}
				return fmt.Errorf("%s:%d: #include 的路径过长（%d 字节，上限 %d）", where, lineNo, len(inc), maxIncludePathLen)
			}
			// 路径里的控制字符当场拒，并且**不回显**那个路径：
			// 它来自远端订阅，原样进错误信息就是往日志与面板里塞 ESC/BS 这类字节。
			if strings.ContainsFunc(inc, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
				return fmt.Errorf("%s:%d: #include 的路径里有控制字符", where, lineNo)
			}
			target, rerr := resolveInclude(base, root, inc)
			if rerr != nil {
				// 越界不是"文件不存在"：写成 #include? 也不许咽下去——
				// 否则远端订阅可以安静地试探边界，本机一点痕迹都不留。
				return fmt.Errorf("%s:%d: %w", where, lineNo, rerr)
			}
			if err := loadFile(target, depth+1, root, e, seenFinal); err != nil {
				if optional && unreadableAsMissing(err) {
					e.skipped = append(e.skipped, safeText(target))
					continue
				}
				return fmt.Errorf("%s:%d: %w", where, lineNo, err)
			}
			continue
		}

		if i := strings.IndexByte(raw, '#'); i >= 0 {
			raw = raw[:i]
		}
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if strings.EqualFold(raw, "FINAL") {
			continue // 缺策略的占位行，忽略
		}
		r, isFinal, err := parseLine(raw, lineNo)
		if err != nil {
			return fmt.Errorf("%s:%d: %w", where, lineNo, err)
		}
		if isFinal {
			if *seenFinal {
				return fmt.Errorf("%s:%d: duplicate FINAL rule", where, lineNo)
			}
			*seenFinal = true
			e.finalPolicy = r.policy
			continue
		}
		// 先按类型校验、再决定要不要进匹配表：停用的那条仍然要过同一套检查
		// （包括"GEOIP 需要数据库"和"这个 kind 还没接入匹配"）。
		// 否则 off 就成了一个把坏规则悄悄留在文件里的通道——
		// 而且用户哪天把它重新打开时，引擎会当场拒绝加载那份文件。
		switch r.kind {
		case kindDomain, kindDomainSuffix, kindDomainKeyword, kindDomainRegex:
		case kindIPCIDR:
		case kindGeoIP:
			if e.geo == nil {
				return fmt.Errorf("%s:%d: GEOIP rule requires a geoip database", where, lineNo)
			}
		default:
			// 解析成功却没进任何一张表 = 这条规则永远不命中。
			// 新增 kind 时只补 kindByName 不补这里，就会静默开个洞：
			// 写在黑名单里的域名照常放行，而日志一行都不提。
			return fmt.Errorf("%s:%d: 规则类型 %q 还没接入匹配，拒绝加载而不是静默丢弃", where, lineNo, kindNames[r.kind])
		}
		if r.off {
			// 停用：留在文件里、留在面板上，但不参与匹配，
			// 也不该因为它而付出 DNS 解析的代价（needResolve 见下面）。
			continue
		}
		switch r.kind {
		case kindDomain, kindDomainSuffix, kindDomainKeyword, kindDomainRegex:
			e.domainRules = append(e.domainRules, r)
		case kindIPCIDR, kindGeoIP:
			e.ipRules = append(e.ipRules, r)
		}
		if !r.noResolve {
			e.needResolve = true
		}
	}
	return sc.Err()
}

// trimIncludeDirective 识别 "#include path" 与 "#include? path"，
// 返回 (目标路径, 是否可选, 这一行是不是 include)——顺序就是签名里那个顺序。
// 只接受完整单词 include，避免把 "#included" 之类的普通注释误判为指令。
// 两侧空白由本函数自行处理，调用方不必预清理。
func trimIncludeDirective(raw string) (inc string, optional, ok bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "#") {
		return "", false, false
	}
	body := strings.TrimSpace(strings.TrimPrefix(raw, "#"))
	const kw = "include"
	if len(body) < len(kw) || !strings.EqualFold(body[:len(kw)], kw) {
		return "", false, false
	}
	rest := body[len(kw):]
	if rest != "" && rest[0] == '?' {
		optional = true
		rest = rest[1:]
	}
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", false, false
	}
	return strings.TrimSpace(rest), optional, true
}

// parseLine 解析一行规则。字段顺序同时兼容
// "TYPE,VALUE,POLICY" 与 "TYPE,VALUE,POLICY,no-resolve"（Clash 风格）。
func parseLine(line string, lineNo int) (rule, bool, error) {
	fields := strings.Split(line, ",")
	if len(fields) < 2 {
		return rule{}, false, fmt.Errorf("rule %q needs at least TYPE and POLICY", brief(line))
	}
	typ := strings.ToUpper(strings.TrimSpace(fields[0]))

	var (
		value     string
		policy    Policy
		unknown   []string
		noResolve bool
		off       bool
		node      string
	)
	for _, raw := range fields[1:] {
		f := strings.TrimSpace(raw)
		if f == "" {
			continue
		}
		if p, ok := parsePolicy(f); ok {
			if policy != "" {
				return rule{}, false, fmt.Errorf("rule %q has more than one policy", brief(line))
			}
			policy = p
			continue
		}
		if strings.EqualFold(f, "no-resolve") {
			noResolve = true
			continue
		}
		// off = 停用这一条。和 no-resolve 一样必须在这个循环里吃掉：
		// 落到 unknown 里会被当成"第二个值"而拒掉整行，报错说的是"规则写错了"。
		if strings.EqualFold(f, "off") {
			if off {
				return rule{}, false, fmt.Errorf("rule %q 写了两个 off", brief(line))
			}
			off = true
			continue
		}
		// node=<节点名> 是第四个可选字段，必须在这个循环里吃掉：
		// 落到 unknown 里就会被当成"多个值"而拒掉整行，用户看到的报错
		// 说的是"这条规则写错了"，而它其实只是把流量钉到了某个节点上。
		if n, isNode := splitNodeToken(f); isNode {
			if node != "" {
				return rule{}, false, fmt.Errorf("rule %q 写了两个 node=，只能钉一个节点", brief(line))
			}
			if n == "" {
				return rule{}, false, fmt.Errorf("rule %q 的 node= 后面是空的", brief(line))
			}
			if len(n) > maxNodeLen {
				return rule{}, false, fmt.Errorf("rule %q 的节点名过长（%d 字节，上限 %d）", brief(line), len(n), maxNodeLen)
			}
			// 节点名会进日志、进连接表、进面板：控制字符不能原样带出去。
			// 这条与"值里不许有控制字符"是同一判据，各字段各查一次。
			if strings.ContainsFunc(n, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
				return rule{}, false, fmt.Errorf("rule %q 的节点名里有控制字符", brief(line))
			}
			node = n
			continue
		}
		unknown = append(unknown, f)
	}
	// 先报「没有策略」再报「多个值」：`DOMAIN-SUFFIX,a.com,NUKE` 这种拼错的策略名，
	// 真实毛病是策略不认识。把它归成"多个值"，用户会去删那个多余的域名，
	// 而规则照样不会被拦——黑名单上静默开个后门。
	if policy == "" {
		return rule{}, false, fmt.Errorf("rule %q has no usable policy (got %q, want DIRECT | PROXY | REJECT)", brief(line), brief(strings.Join(unknown, "|")))
	}
	switch len(unknown) {
	case 0:
	case 1:
		value = unknown[0]
	default:
		return rule{}, false, fmt.Errorf("rule %q has more than one value", brief(line))
	}

	if typ == "FINAL" {
		if node != "" {
			// 不是"还没做到"，是刻意不接：兜底策略一旦能钉节点，
			// 整份配置的默认出口就由一行规则决定了，而面板上「当前节点」那一栏说的
			// 会是另一个名字。两处说法不一致的默认出口是最难查的一类事故。
			return rule{}, false, fmt.Errorf("FINAL 不支持 node=：兜底走哪个节点请由 active/选节点决定，只有一处说法")
		}
		if off {
			// 停用的是"一条规则"，而 FINAL 是"没有规则命中时怎么办"。
			// 允许停用它就等于让整张规则表失去兜底，而引擎必须始终有一个答案。
			return rule{}, false, fmt.Errorf("FINAL 不能被停用：兜底策略必须一直有效")
		}
		return rule{policy: policy, line: lineNo}, true, nil
	}

	k, ok := kindByName[typ]
	if !ok {
		return rule{}, false, fmt.Errorf("unknown rule type %q", brief(typ))
	}
	if value == "" {
		return rule{}, false, fmt.Errorf("rule %q has no value", brief(line))
	}
	r := rule{kind: k, value: value, policy: policy, noResolve: noResolve, off: off, node: node, line: lineNo}
	if r.node != "" && r.policy != PolicyProxy {
		// DIRECT 自己就是出口、REJECT 一个字节都不发：给它们配节点，
		// 那个节点名永远不会被读到。静默收下等于让用户以为钉上了。
		return rule{}, false, fmt.Errorf("node= 只对 PROXY 有意义，这条规则的策略是 %s", r.policy)
	}
	// 值里不许有控制字符（NUL、换行、退格那一类）。
	//
	// 不是洁癖：fuzz 找到的是 `DOMAIN,\x00,PROXY` 能解析成功，于是那条规则
	// 的 desc() 带着 NUL 进日志、进连接表的"命中规则"字段、进面板的 JSON。
	// 规则值来自远端订阅，而"一个永远不会被匹配上的垃圾规则"没有任何用处——
	// 当场拒掉才是对的，报错信息里那一行仍按 brief 截断。
	if strings.ContainsFunc(r.value, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return rule{}, false, fmt.Errorf("rule %q 的值里有控制字符", brief(line))
	}
	switch k {
	case kindIPCIDR:
		// CIDR 按小写规范化。
		r.value = strings.ToLower(r.value)
		p, err := netip.ParsePrefix(r.value)
		if err != nil {
			// 这里刻意不用 %w：netip 的原话会把整个输入嵌进错误里
			// （netip.ParsePrefix("aaaa…"): …），于是一行超长垃圾就能撑大日志与面板。
			// 判据本身（不是合法 CIDR）已经说完了，原因按 clip 截住。
			return rule{}, false, fmt.Errorf("invalid CIDR %q: %s", brief(r.value), clip(err.Error()))
		}
		r.prefix = p
	case kindGeoIP:
		// 国家码统一大写，便于日志里与 mmdb 输出对照。
		r.value = strings.ToUpper(r.value)
		if len(r.value) != 2 {
			return rule{}, false, fmt.Errorf("GEOIP value %q must be a 2-letter country code", brief(r.value))
		}
	case kindDomainRegex:
		// 模式**不**做小写归一：字符类 `[A-Z]`、`\d`、`\w` 的方向是有语义的，
		// 整条转小写会静默改掉它匹配的东西。大小写不分靠下面那个 (?i)。
		if len(r.value) > maxRegexLen {
			return rule{}, false, fmt.Errorf("DOMAIN-REGEX 模式过长（%d 字节，上限 %d）", len(r.value), maxRegexLen)
		}
		// 编译一次，存进规则里：匹配发生在每条连接上，而规则集一天换一次。
		// Go 的正则是 RE2，没有回溯爆炸（ReDoS），所以一条远端发来的模式
		// 最多是"慢一点"，不可能把进程拖死。
		re, cerr := regexp.Compile("(?i)" + r.value)
		if cerr != nil {
			// 和 invalid CIDR 同一个理由：不用 %w，regexp 的原话会把模式片段
			// 原样嵌进错误里，而那段可能带非法 UTF-8 字节（值来自远端订阅）。
			return rule{}, false, fmt.Errorf("DOMAIN-REGEX 模式无法编译：%s", safeText(clip(cerr.Error())))
		}
		r.re = re
	case kindDomainKeyword, kindDomain, kindDomainSuffix:
		// 域名类统一小写，避免规则文件里大小写混用导致漏匹配。
		r.value = strings.ToLower(r.value)
		if r.value == "" {
			return rule{}, false, fmt.Errorf("rule %q has an empty value", brief(line))
		}
	}
	return r, false, nil
}

// SetBlocklist 用配置里 block: 段的域名整块替换现有拦截名单。
//
// 语义是按后缀拦（含子域）：写 ads.example.com 会连 api.ads.example.com 一起拦掉，
// 这是黑名单想要的方向——漏拦比误拦更难被发现。
// 大小写、首尾空格与结尾那个点都会被抹平，重复项只留一条。
func (e *Engine) SetBlocklist(domains []string) {
	list := make([]rule, 0, len(domains))
	for _, h := range BlockDomainView(domains) {
		list = append(list, rule{kind: kindDomainSuffix, value: h, policy: PolicyReject, fromConfig: true})
	}
	e.blockRules = list
}

// BlockDomainView 是 SetBlocklist 装完之后 BlockDomains() 会给出的那份名单，
// 但**不必先编译整张规则表**。
//
// 面板停着的时候每五秒要问一次拦截名单，而这份名单只由配置的 block: 段决定，
// 与规则集里有几千条无关——早先这里是绕道建一个引擎来拿它，
// 于是每五秒把仓库自带那 ~200KB 的 GFW 名单重新解析一遍（实测 2.3ms 白扔）。
// 走这里还顺带修掉一处不一致：规则集读不到时旧代码退回 NormalizeBlocklist，
// 那一档**不去重**，于是同一份名单在"规则集能读"与"读不到"两种情况下条数不一样。
func BlockDomainView(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	out := make([]string, 0, len(domains))
	for _, h := range NormalizeBlocklist(domains) {
		if seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// NormalizeBlocklist 把配置里的名单抹平成"引擎实际会用来匹配"的形式：
// 小写、去空格、去尾点、丢掉归一后为空的项（一个 "." 会归一成空后缀，
// 那等于拦下所有域名——能把整机网络关掉的一行配置，不能当合法输入）。
//
// 它是导出的，因为界面在规则集读不到时也要显示同一份写法：
// 归一化不该依赖"能不能加载那几千条规则"。
func NormalizeBlocklist(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if h := normalizeHost(d); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// Match 返回目标 host 应使用的策略，以及命中的规则描述（供日志）。
// host 可以是域名，也可以是字面量 IP。
func (e *Engine) Match(ctx context.Context, host string) (Policy, string) {
	p, m, _ := e.MatchNode(ctx, host)
	return p, m
}

// MatchNode 与 Match 同一套判定，另外带出这条规则钉住的节点名（没钉就是空串）。
//
// 拆成两个入口而不是改 Match 的签名：DNS 应答那一侧只关心策略
// （假 IP 还是真 IP），而转发那一侧需要节点名。让不需要它的调用方
// 也去接第三个返回值，等于给它一个可以忽略掉的理由。
func (e *Engine) MatchNode(ctx context.Context, host string) (Policy, string, string) {
	h := normalizeHost(host)
	if addr, err := netip.ParseAddr(h); err == nil {
		return e.matchIP([]netip.Addr{addr.Unmap()})
	}
	if h == "" {
		return e.finalPolicy, "FINAL", ""
	}

	// 0. 拦截名单最先：命中即断，且不依赖规则文件里恰好没有一条放行规则在前面。
	for _, r := range e.blockRules {
		if r.matchDomain(h) {
			return r.policy, r.desc(), r.node
		}
	}

	// 1. 先跑域名规则，避免为已能判定的域名付出 DNS 代价。
	for _, r := range e.domainRules {
		if r.matchDomain(h) {
			return r.policy, r.desc(), r.node
		}
	}

	// 2. 仍有需要解析的规则时才解析域名。
	if e.needResolve && e.resolver != nil {
		addrs, err := e.resolver.LookupIP(ctx, h)
		if err != nil || len(addrs) == 0 {
			// 解析失败不中断连接，退化为 FINAL。
			return e.finalPolicy, "FINAL(dns-failed)", ""
		}
		return e.matchIP(addrs)
	}
	return e.finalPolicy, "FINAL", ""
}

// matchIP 按规则顺序遍历，任一 IP 命中即返回。
func (e *Engine) matchIP(addrs []netip.Addr) (Policy, string, string) {
	for _, r := range e.ipRules {
		for _, a := range addrs {
			switch r.kind {
			case kindIPCIDR:
				if r.prefix.Contains(a.Unmap()) {
					return r.policy, r.desc(), r.node
				}
			case kindGeoIP:
				if cc, ok := e.geo.Country(a.Unmap()); ok && strings.EqualFold(cc, r.value) {
					return r.policy, r.desc(), r.node
				}
			}
		}
	}
	return e.finalPolicy, "FINAL", ""
}

// MatchIPAddrs 答"这批地址合起来会命中哪条 IP 类规则、判成什么策略"。
//
// 它就是上面 `matchIP` 那份结论的公开入口，不是第二套判定：
// 面板上「看解析」那一格要显示"这些 IP 会被判成什么"，
// 而它一旦自己实现一遍"哪个 IP 命中哪条规则"，判定就有了两份，
// 而两份迟早不一样（§14.5 那条同源规矩在 Go 内部同样成立）。
func (e *Engine) MatchIPAddrs(addrs []netip.Addr) (Policy, string) {
	p, desc, _ := e.matchIP(addrs)
	return p, desc
}

// CountryOf 查一个地址在 GeoIP 库里的归属码。
//
// 第二个返回值为假有两种意思：没配库，或库里没有这条。
// 两者都**不能**被说成"这不是中国 IP"——那是把"不知道"报成一个结论，
// 而这一格存在的意义恰恰是让人看清判定建立在什么之上，所以调用方要把两者分开显示。
func (e *Engine) CountryOf(addr netip.Addr) (string, bool) {
	if e.geo == nil {
		return "", false
	}
	return e.geo.Country(addr.Unmap())
}

// Final 返回兜底策略。
func (e *Engine) Final() Policy { return e.finalPolicy }

// Stats 返回规则条数，用于启动日志。
func (e *Engine) Stats() (domain, ip int) { return len(e.domainRules), len(e.ipRules) }

// BlockCount 是配置段名单铺进来的拦截条数。
// 界面单独报它：拦截对客户端是完全安静的，用户需要一个地方能确认"名单真的装上了"。
func (e *Engine) BlockCount() int { return len(e.blockRules) }

// BlockDomains 按加载时的顺序返回名单里的域名。
// 展示栏要的是"现在真正生效的那份"，不是配置文件里那份——两者在重载失败时会分家。
func (e *Engine) BlockDomains() []string {
	out := make([]string, 0, len(e.blockRules))
	for _, r := range e.blockRules {
		out = append(out, r.value)
	}
	return out
}

// Skipped 返回因文件不存在而被跳过的可选 #include 列表。
func (e *Engine) Skipped() []string { return e.skipped }

// Sources 返回这次编译打开过的文件路径，按打开顺序。
//
// 返回副本：调用方（热重载监视器）会把它存起来慢慢比，
// 而引擎随时可能被下一次 Reload 换掉。
func (e *Engine) Sources() []string {
	return append([]string(nil), e.sources...)
}

// brief 把一行规则截成能进错误信息的长度。
//
// 远端订阅可以在一行里塞进 1MB（Scanner 的上限就是 1MB），而错误信息会进日志、
// 会被面板原样显示出来：整行带出去等于让一条坏规则塞满日志与界面。
// clip 把字符串截到 briefKeep 个字符以内，不加说明。
const briefKeep = 48 // 按字符算，不按字节：见 brief 的说明

func clip(s string) string {
	if utf8.RuneCountInString(s) <= briefKeep {
		return s
	}
	rest := s
	for i := 0; i < briefKeep; i++ {
		_, size := utf8.DecodeRuneInString(rest)
		rest = rest[size:]
	}
	return s[:len(s)-len(rest)] + "…"
}

// brief 是"给人看的那一行"的版本：除了截断，还报出原长，
// 免得用户照着半截规则去改，却不知道后面还有多少内容被吃掉了。
func brief(s string) string {
	if utf8.RuneCountInString(s) <= briefKeep {
		return s
	}
	return clip(s) + fmt.Sprintf("（本行共 %d 字节）", len(s))
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	return strings.TrimSuffix(h, ".")
}
