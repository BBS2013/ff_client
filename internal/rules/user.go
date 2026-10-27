package rules

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// UserRuleFileName 是用户自定义规则的文件名，与主规则集放在同一目录。
//
// 单独一个文件而不是往 rules.txt 里追加，理由有两个：
//  1. 主规则集可能被脚本重新生成（fetch-assets.sh），追加进去的东西会被冲掉；
//  2. 界面只该改用户自己写的那几条，读写范围越小越不容易出事故。
const UserRuleFileName = "user-rules.txt"

// userRulesHeader 每次保存都会重写：这份文件是程序生成的，注释也一起维护。
const userRulesHeader = `# wps_app 自定义域名规则（由控制面板维护，也可以手改）
#
# 语法与主规则集一致：TYPE,VALUE,POLICY
#   TYPE    DOMAIN（精确） / DOMAIN-SUFFIX（含子域） / DOMAIN-KEYWORD（含关键字）
#           手写的还有 IP-CIDR / GEOIP / DOMAIN-REGEX（面板里只读，不能增改）
#   POLICY  PROXY（走代理） / DIRECT（直连） / REJECT（拦截，不许出网）
#   可选    第四个字段 node=<节点名>：这条 PROXY 只走那个节点，不跟"当前选中"走。
#           名字对不上时连接直接失败，不会改用别的节点；DIRECT/REJECT 不许带它。
#   可选    再一个字段 off：停用这一条而不删掉它。它还在名单里、还在面板上，
#           但不参与匹配——排查"是不是这条把网站弄坏的"时用，别用删除。
#           注意关掉一条盖住别人的规则会让后面那条开始生效。FINAL 不能被停用。
#
# REJECT 只能手写在下面这一份文件里，面板的策略开关只有走代理/直连两档
# （一键把黑名单放开比拦不住更糟）。成批的拦截名单请用配置的 block: 段。
#
# DOMAIN-REGEX 也属于"只能手写"那一类：模式里合法地会出现逗号与空格，
# 而逗号正是这一行的字段分隔符，面板那个"类型+域名+策略"三格表单表达不了它。
# 模式不锚定（^ 与 $ 自己写）、按 RE2 编译、长度上限 128 字节。
#
# 本文件在主规则集里被 #include? 引在**最前面**，所以这里的规则优先于
# 内置的被墙域名表：想让某个被墙域名直连、或让某个国内域名走代理，写在这里就行。
# 改完在面板里点「重载规则」或给进程发 SIGHUP 生效。
`

// UserRule 是一条用户规则。
type UserRule struct {
	Type   string `json:"type"`
	Value  string `json:"value"`
	Policy string `json:"policy"`
	// Node 非空 = 这条规则把 PROXY 流量钉到配置里那个名字的节点。
	// 它是规则行上第四个可选字段（node=名字），不是界面独有的概念：
	// 少了这个字段，面板一次整表回写就会把手写的固定节点抹掉，
	// 而那一行看起来"还在"——最难查的那种失效。
	Node string `json:"node"`

	// Disabled = 这一条被停用了：规则行上带 `,off`。
	// 它必须是一个能 round-trip 的字段，而不是"把那一行注释掉"：
	// 注释掉的行在 parseUserRules 那一层就被跳过，面板再也看不见它，
	// 而下一次整表回写会把它抹掉——用户只是想临时关掉一条试试，回来发现没了。
	Disabled bool `json:"disabled"`

	// raw 是界面表达不出来的整行原文（例如手写的 IP-CIDR、GEOIP 规则）。
	// 保存时原样写回：否则用户在面板里加一条域名规则，
	// 就会把自己手写的 IP 规则连带丢掉。
	raw string
}

// DomainRuleTypes 是面板上可选的匹配方式。
var DomainRuleTypes = []string{"DOMAIN-SUFFIX", "DOMAIN", "DOMAIN-KEYWORD"}

// Line 返回这条规则在文件里的那一行。
func (r UserRule) Line() string {
	if r.raw != "" {
		// 手写的行（IP-CIDR / GEOIP / DOMAIN-REGEX）原文留着，只在末尾加减 off 那一个字段。
		// 不能整行重建：重建会把 no-resolve、GEOIP 的代码这些结构体装不下的东西丢掉。
		return setOffToken(r.raw, r.Disabled)
	}
	line := r.Type + "," + r.Value + "," + r.Policy
	if r.Node != "" {
		line += ",node=" + r.Node
	}
	if r.Disabled {
		line += ",off"
	}
	return line
}

// setOffToken 在这行末尾加上或去掉那个可选的 off 字段。
//
// 只认**最后一个**字段，不扫全部：规则值里合法地可能出现 "off" 这个字
// （DOMAIN-REGEX 的模式是任意文本，`DOMAIN-REGEX,x,off,PROXY` 里那个 off 是模式的一部分）。
// 而这一行的策略是必填的，所以真正表示停用的那个 off 永远排在最后——
// 手写在前、策略在后的写法（`DOMAIN-SUFFIX,x,off,PROXY`）会被 parseLine
// 当成"没有可用策略"当场拒掉，不会走到这里被误读。
func setOffToken(line string, off bool) string {
	fields := strings.Split(line, ",")
	has := strings.EqualFold(strings.TrimSpace(fields[len(fields)-1]), "off")
	switch {
	case off && !has:
		return line + ",off"
	case !off && has:
		return strings.Join(fields[:len(fields)-1], ",")
	default:
		return line
	}
}

// IsDomain 报告这条规则是否能用「类型+域名+策略」在界面上编辑。
//
// REJECT 故意留在这里为 false：面板的策略控件是 PROXY/DIRECT 二选一的开关，
// 把拦截规则接进去要么显示成"走代理"，要么被那个开关一键改成直连——
// 后者等于在面板里手滑就把黑名单放开。让它走 raw 原样保留，
// 拦截名单由配置的 block: 段管（见 README §4）。
func (r UserRule) IsDomain() bool {
	switch r.Type {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		return r.Policy == "PROXY" || r.Policy == "DIRECT"
	default:
		return false
	}
}

// Normalize 就地整理并校验：类型大写、域名小写去空格去前导点，
// 并挡掉界面上不该出现的类型（GEOIP/FINAL/IP-CIDR 有自己的入口）。
func (r *UserRule) Normalize() error {
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Value = strings.ToLower(strings.Trim(strings.TrimSpace(r.Value), "."))
	r.Policy = strings.ToUpper(strings.TrimSpace(r.Policy))
	if r.Policy == "HY2" || r.Policy == "PROXY-HY2" {
		r.Policy = "PROXY"
	}
	switch r.Type {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
	default:
		return fmt.Errorf("自定义规则只支持域名类型（DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD），收到 %q", r.Type)
	}
	if r.Value == "" {
		return errors.New("域名不能为空")
	}
	if strings.ContainsAny(r.Value, ",# \t") {
		return fmt.Errorf("域名 %q 含有非法字符", r.Value)
	}
	if r.Policy != "PROXY" && r.Policy != "DIRECT" && r.Policy != "REJECT" {
		return fmt.Errorf("策略只能是 PROXY、DIRECT 或 REJECT，收到 %q", r.Policy)
	}
	// 节点名是自由文本，但它会拼成规则行的第四个字段：
	// 逗号会把这一行拆成两个值，等号会让 splitNodeToken 分不清键与值，
	// 空格与 # 则是这一行里别的东西的写法。当场拒掉，别写出一份读不回来的文件。
	r.Node = strings.TrimSpace(r.Node)
	if r.Node != "" {
		if strings.ContainsAny(r.Node, ",#=\t \n") {
			return fmt.Errorf("节点名 %q 里有非法字符（逗号、等号、空格、# 都不行）", r.Node)
		}
		if r.Policy != "PROXY" {
			return fmt.Errorf("node= 只对 PROXY 有意义，这条规则的策略是 %s", r.Policy)
		}
	}
	if _, _, err := parseLine(r.Line(), 0); err != nil {
		return err
	}
	return nil
}

// HasUserRule 报告名单里是否已有同类型同域名的那一条。
//
// 批量添加要靠它分清「新增」与「覆盖已有的那条」：两者数量混在一起报成
// "已保存 N 条"，用户就看不出自己是不是把某条原有规则的策略改掉了。
func HasUserRule(list []UserRule, r UserRule) bool {
	return indexOfKey(list, r.Type, r.Value) >= 0
}

// ParseRuleLine 把面板上抄来的一行变成一条可保存的规则。
//
// 允许两种写法：裸域名（按界面给的默认类型与策略补全），或完整的
// TYPE,VALUE,POLICY 行。裸域名这一档是为"从别处粘一串域名过来"这个真实动作准备的——
// 每条都要先补三个字段才能加，等于没有批量。
//
// 只收面板能表达的那三种域名类型：IP-CIDR / GEOIP 有它们自己的入口，
// 而 DOMAIN-REGEX 的模式里合法地会出现逗号，逗号正是这一行的字段分隔符，
// 让批量入口接受它只会产出一句"多个值"的错。
func ParseRuleLine(line, defType, defPolicy string) (UserRule, error) {
	body := strings.TrimSpace(line)
	if body == "" {
		return UserRule{}, errors.New("这一行是空的")
	}
	var r UserRule
	if !strings.Contains(body, ",") {
		r = UserRule{Type: defType, Value: body, Policy: defPolicy}
	} else {
		parsed, isFinal, err := parseLine(body, 0)
		if err != nil {
			return UserRule{}, err
		}
		if isFinal {
			return UserRule{}, errors.New("FINAL 只能写在主规则集里")
		}
		name := kindNames[parsed.kind]
		switch name {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		default:
			return UserRule{}, fmt.Errorf("%q 这一类只能在文件里手写，批量添加不收", name)
		}
		// 值与策略取 parseLine 归一过的那一份：大小写、尾点它已经抹平了。
		r = UserRule{Type: name, Value: parsed.value, Policy: string(parsed.policy)}
	}
	if err := r.Normalize(); err != nil {
		return UserRule{}, err
	}
	if r.Policy == "REJECT" {
		return UserRule{}, errors.New("批量添加只接受 PROXY / DIRECT：要拦截请用配置的 block: 段，或直接把那一行写进文件")
	}
	return r, nil
}

// Key 用于去重与删除定位：同一类型+同一域名只该有一条。
func (r UserRule) Key() string { return r.Type + "," + r.Value }

// Desc 返回引擎在"命中依据"里为这条规则写出的那串文本。
//
// 存在的理由只有一个：面板要把"每条规则命中了多少次"对回它自己列出的那一行。
// 那串文本的权威是 rule.desc()，所以这里**必须**走同一个函数，而不是在调用方
// 拼一遍 fmt.Sprintf("%s,%s,%s")——desc 后来加过 (node=…)、,no-resolve、(block)
// 三档后缀，任何一处自己拼一份，两边就会在某天分家，
// 而分家的表现是界面上好几条规则的计数永远是 0，谁也想不出为什么。
//
// 也不许反过来让调用方去 split 那串文本：DOMAIN-REGEX 的值里合法地会出现逗号，
// 按逗号切会把一条正则切成两半。
func (r UserRule) Desc() string {
	k, ok := kindByName[strings.ToUpper(r.Type)]
	if !ok {
		// 类型认不出来就没有"引擎会怎么写它"这回事。返回空串让调用方跳过它，
		// 而不是编一个对不上的键——编出来的键永远查不到计数，和拼错格式同一种错。
		return ""
	}
	one := rule{kind: k, value: r.Value, policy: Policy(r.Policy), node: r.Node}
	return one.desc()
}

// UserRulePath 返回与主规则集同目录的自定义规则文件路径。
func UserRulePath(rulesFile string) string {
	return filepath.Join(filepath.Dir(rulesFile), UserRuleFileName)
}

// LoadUserRules 读出自定义规则。文件不存在时返回空列表——
// 这是正常初始状态，不该让面板报错。
func LoadUserRules(path string) ([]UserRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []UserRule{}, nil
		}
		return nil, err
	}
	return parseUserRules(string(raw))
}

func parseUserRules(body string) ([]UserRule, error) {
	var out []UserRule
	for i, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		// 顺序很重要：#include 也是以 # 开头，若先按注释跳过，
		// 这条引用会在下一次整表回写时被静默丢掉。
		if _, _, ok := trimIncludeDirective(trimmed); ok {
			// 自定义文件里再 include 别的文件，会让「这条规则是谁写的」说不清，
			// 面板也就无法安全地整表回写。直接拒绝而不是静默丢掉。
			return nil, fmt.Errorf("%s 第 %d 行：自定义规则文件里不支持 #include", UserRuleFileName, i+1)
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		r, isFinal, err := parseLine(trimmed, i+1)
		if err != nil {
			return nil, fmt.Errorf("第 %d 行: %w", i+1, err)
		}
		if isFinal {
			return nil, fmt.Errorf("第 %d 行: FINAL 只能写在主规则集里", i+1)
		}
		item := UserRule{}
		switch r.kind {
		case kindDomain:
			item = UserRule{Type: "DOMAIN", Value: r.value, Policy: string(r.policy), Node: r.node, Disabled: r.off}
		case kindDomainSuffix:
			item = UserRule{Type: "DOMAIN-SUFFIX", Value: r.value, Policy: string(r.policy), Node: r.node, Disabled: r.off}
		case kindDomainKeyword:
			item = UserRule{Type: "DOMAIN-KEYWORD", Value: r.value, Policy: string(r.policy), Node: r.node, Disabled: r.off}
		default:
			// 非域名类型（IP-CIDR / GEOIP / DOMAIN-REGEX…）：类型名照实报，
			// 原文整行留着回写。
			//
			// 这里原来统一写成 "OTHER"，于是面板那一列显示的是 "OTHER"
			// 而不是用户自己写的 "IP-CIDR"——界面把用户的规则读错了给他看。
			// "能不能在面板上编辑"由 IsDomain() 那份白名单判，不靠这个字符串，
			// 所以以后新增规则类型时这一行自动就对（守卫见 TestEveryKindRoundTripsByName）。
			item = UserRule{Type: kindNames[r.kind], Value: r.value, Policy: string(r.policy), Node: r.node, Disabled: r.off, raw: trimmed}
		}
		out = append(out, item)
	}
	return out, nil
}

// SaveUserRules 原子写回：先备份旧文件，再写临时文件 rename。
// 权限 0644——这份文件不含凭据，且要保证主进程之外的脚本也能读。
func SaveUserRules(path string, list []UserRule) error {
	var b strings.Builder
	b.WriteString(userRulesHeader)
	for _, r := range list {
		if r.raw != "" {
			// 走 Line() 而不是直接写 raw：手写的行也要能被停用/打开。
			// Line() 对 raw 只加减末尾那个 off 字段，其余原样保留，
			// 所以没动过开关时它返回的就是 raw 本身——这一行换掉是零行为差异。
			b.WriteString(r.Line() + "\n")
			continue
		}
		item := r
		if err := item.Normalize(); err != nil {
			return err
		}
		b.WriteString(item.Line() + "\n")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", old, 0o644); err != nil {
			return fmt.Errorf("备份 %s.bak: %w", path, err)
		}
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}()
	if _, err := tmp.WriteString(b.String()); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// UpsertUserRule 加入或替换一条规则：同类型同域名的旧条目被新的策略覆盖，
// 而不是攒出两条互相矛盾的规则（引擎按顺序取第一条命中，重复条目等于隐藏状态）。
func UpsertUserRule(list []UserRule, r UserRule) []UserRule {
	key := r.Key()
	out := make([]UserRule, 0, len(list)+1)
	replaced := false
	for _, old := range list {
		if old.Key() == key {
			// 停用是**这一行**的开关，不是这一行写的内容。
			// 改走向、换节点、批量粘贴覆盖同一条，都只换内容，开关留在原地——
			// 否则用户会遇到"我明明把这条关了，粘了一份名单之后它又开始了"，
			// 而粘贴框里没有任何一个字提到过开关。
			// 唯一会动这个开关的入口是 SetUserRuleDisabled（界面上那枚「停用/启用」）。
			r.Disabled = old.Disabled
			out = append(out, r)
			replaced = true
			continue
		}
		out = append(out, old)
	}
	if !replaced {
		out = append(out, r)
	}
	return out
}

// indexOfKey 找出 typ,value 那条规则在名单里的位置，找不到返回 -1。
// 归一化与 RemoveUserRule 共用同一套写法，否则"面板上看得见的"和"后端找不到的"会分家。
func indexOfKey(list []UserRule, typ, value string) int {
	want := strings.ToUpper(strings.TrimSpace(typ)) + "," + strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	for i, r := range list {
		if r.Key() == want {
			return i
		}
	}
	return -1
}

// MoveUserRule 把 typ,value 那条规则挪到 to 这个下标上（0 起，按"挪完之后"的名单算）。
//
// 为什么面板要有这件事：引擎按顺序取**第一条**命中的规则，而面板加规则一律追加在末尾。
// 于是"我已经加了 DOMAIN,www.example.com,DIRECT，为什么不生效"是必然会出现的一幕——
// 前面那条 DOMAIN-SUFFIX,example.com,PROXY 把它压住了。只能去手改文件的话，
// 大多数人会先怀疑功能坏了。
//
// 摘掉自己再把 to 当插入点是成立的：to 在 i 之后时那一条本来就朝前挪了一格，
// to 在 i 之前时后面的都不动，两种情况都正好落在 to。
func MoveUserRule(list []UserRule, typ, value string, to int) ([]UserRule, error) {
	i := indexOfKey(list, typ, value)
	if i < 0 {
		return nil, fmt.Errorf("没有找到规则 %s,%s", briefKey(typ), briefKey(value))
	}
	if to < 0 || to >= len(list) {
		return nil, fmt.Errorf("位置 %d 超出这份名单的范围（共 %d 条）", to, len(list))
	}
	if to == i {
		return append([]UserRule(nil), list...), nil
	}
	moved := list[i]
	out := make([]UserRule, 0, len(list)-1)
	for j, r := range list {
		if j != i {
			out = append(out, r)
		}
	}
	res := make([]UserRule, 0, len(list))
	res = append(res, out[:to]...)
	res = append(res, moved)
	res = append(res, out[to:]...)
	return res, nil
}

// briefKey 把界面传进来的类型/域名截成能进错误信息的长度。
func briefKey(s string) string {
	return clip(strings.TrimSpace(s))
}

// RemoveUserRule 按 类型+域名 删除。
func RemoveUserRule(list []UserRule, typ, value string) ([]UserRule, bool) {
	want := strings.ToUpper(strings.TrimSpace(typ)) + "," + strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	out := make([]UserRule, 0, len(list))
	removed := false
	for _, r := range list {
		if r.Key() == want {
			removed = true
			continue
		}
		out = append(out, r)
	}
	return out, removed
}

// SetUserRuleDisabled 按 类型+域名 翻那一条的停用标志，返回改过的新名单与"有没有改到"。
//
// 为什么单独有一条，而不是让界面走 AddUserRule：那条要先过 Normalize，
// 而 Normalize 只收域名类型——手写的 IP-CIDR / GEOIP / DOMAIN-REGEX 会被拒。
// 偏偏"临时关掉一条 IP 段看看是不是它碍事"是最想用的场景之一。
// 这里只动一个布尔，别的字段（raw 原文、no-resolve、节点名）一概不重建，
// 所以也就没有"改个开关把别的东西弄丢了"这一类事故。
func SetUserRuleDisabled(list []UserRule, typ, value string, off bool) ([]UserRule, bool) {
	want := strings.ToUpper(strings.TrimSpace(typ)) + "," + strings.ToLower(strings.Trim(strings.TrimSpace(value), "."))
	out := make([]UserRule, len(list))
	changed := false
	for i, r := range list {
		if r.Key() == want {
			// 已经是目标状态也算"改到了"：调用方要能区分"名单里没这条"和"不用改"。
			r.Disabled = off
			changed = true
		}
		out[i] = r
	}
	return out, changed
}
