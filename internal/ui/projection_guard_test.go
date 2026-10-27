package ui

// 投影链守卫：Go 结构体的 json tag 与 frontend/src/types.ts 的 interface 必须逐字段相等。
//
// 为什么必须有这一条：这条链上没有任何编译期检查。Wails 把结构体序列化成 JSON，
// 前端按 interface 读字段——两边名字对不上时，Go 侧照发、前端读到 undefined，
// 于是界面显示空值而不是报错。用户看到的是"没有数据"，实际是投影断了。
// 本项目已经栽过一次（面板显示"已停止 / 活跃连接 0"，其实是状态没读上来）。
//
// 只比字段名集合，不比类型：类型由 Go 侧决定，TS 那边写错类型 vue-tsc 会管，
// 而**名字**是两边唯一会静默错开的东西。

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"wps_app/internal/metrics"
	"wps_app/internal/rules"
	"wps_app/internal/service"
	"wps_app/internal/sysproxy"
	"wps_app/internal/tunx"
)

// typePairs 是完整的对应表。新增一个跨边界结构体就必须在这里登记一行，
// 否则它落进"没被守卫"的集合，等于把静默错开的风险重新引进来。
var typePairs = []struct {
	goName string
	goVal  any
	tsName string
}{
	{"service.Snapshot", service.Snapshot{}, "Status"},
	{"service.IfaceSplitStatus", service.IfaceSplitStatus{}, "IfaceSplitStatus"},
	{"service.IfaceCardView", service.IfaceCardView{}, "IfaceCardView"},
	{"service.InboundStatus", service.InboundStatus{}, "InboundStatus"},
	{"service.ProfileView", service.ProfileView{}, "ProfileView"},
	{"service.ProfileSpec", service.ProfileSpec{}, "ProfileSpec"},
	{"service.ProfileTest", service.ProfileTest{}, "ProfileTest"},
	{"service.ProbeResult", service.ProbeResult{}, "ProbeResult"},
	{"service.PageFetch", service.PageFetch{}, "PageFetch"},
	{"service.DNSProbe", service.DNSProbe{}, "DNSProbe"},
	{"service.UpstreamView", service.UpstreamView{}, "UpstreamView"},
	{"service.AddrView", service.AddrView{}, "AddrView"},
	{"service.BlockView", service.BlockView{}, "BlockView"},
	{"service.RulesWatchView", service.RulesWatchView{}, "RulesWatchView"},
	{"service.RulesFileView", service.RulesFileView{}, "RulesFileView"},
	{"service.SubscriptionsView", service.SubscriptionsView{}, "SubscriptionsView"},
	{"service.SubscriptionView", service.SubscriptionView{}, "SubscriptionView"},
	{"service.ProviderRefreshReport", service.ProviderRefreshReport{}, "ProviderRefreshReport"},
	{"service.ProviderRefresh", service.ProviderRefresh{}, "ProviderRefresh"},
	{"service.UserRuleImport", service.UserRuleImport{}, "UserRuleImport"},
	{"service.BlockImport", service.BlockImport{}, "BlockImport"},
	{"service.RuleHit", service.RuleHit{}, "RuleHit"},
	{"service.RuleWarning", service.RuleWarning{}, "RuleWarning"},
	{"rules.UserRule", rules.UserRule{}, "UserRule"},
	{"tunx.Status", tunx.Status{}, "TUNStatus"},
	{"metrics.ConnView", metrics.ConnView{}, "ConnView"},
	{"metrics.Sample", metrics.Sample{}, "Sample"},
	{"metrics.BlockedHit", metrics.BlockedHit{}, "BlockedHit"},
	{"metrics.NodeTraffic", metrics.NodeTraffic{}, "NodeTraffic"},
	{"metrics.Snapshot", metrics.Snapshot{}, "TrafficSnapshot"},
	{"sysproxy.Status", sysproxy.Status{}, "SystemProxyStatus"},
	{"ui.ProfileList", ProfileList{}, "ProfileList"},
	{"ui.ConfigForm", ConfigForm{}, "ConfigForm"},
	{"ui.InboundForm", InboundForm{}, "InboundForm"},
	{"ui.TUNForm", TUNForm{}, "TUNForm"},
	{"ui.SysProxyLedger", SysProxyLedger{}, "SysProxyLedger"},
	{"ui.BuildInfo", BuildInfo{}, "BuildInfo"},
	{"ui.LogEntry", LogEntry{}, "LogEntry"},
	{"ui.LogPage", LogPage{}, "LogPage"},
}

func TestProjectionMatchesFrontendTypes(t *testing.T) {
	src := readFrontendTypes(t)
	for _, p := range typePairs {
		goFields, err := jsonFields(p.goVal)
		if err != nil {
			t.Errorf("%s: %v", p.goName, err)
			continue
		}
		tsFields, ok := tsInterfaceFields(src, p.tsName)
		if !ok {
			t.Errorf("%s 声称对应 types.ts 的 %s，但那个 interface 不存在", p.goName, p.tsName)
			continue
		}
		if msg := diffFields(p.goName, p.tsName, goFields, tsFields); msg != "" {
			t.Errorf("%s ↔ %s 对不上：\n%s", p.goName, p.tsName, msg)
		}
	}
}

// TestProjectionPairsCoverEveryExportedBinding 防止"新结构体没进守卫表"。
//
// 表里漏一行的后果和字段名写错一模一样：界面默默显示空值。
// 这里扫 App 上暴露给前端的方法返回值，凡是返回结构体（或结构体切片）的，
// 都要求它在对应表里，或者在 types.ts 里根本没有同名 interface（说明确实不跨边界）。
func TestProjectionPairsCoverEveryExportedBinding(t *testing.T) {
	src := readFrontendTypes(t)
	registered := map[string]bool{}
	for _, p := range typePairs {
		registered[p.tsName] = true
		// Go 侧名字也登记：service.Snapshot ↔ types.ts 的 Status 就是两套名字，
		// 只按 interface 名对撞的话，这类"改了名但确实登记过"的会被误报成漏登记。
		short := p.goName
		if i := strings.LastIndex(short, "."); i >= 0 {
			short = short[i+1:]
		}
		registered[short] = true
	}
	missing := []string{}
	// 前端源码：用来认"这个方法真的被调了吗"。
	feSrc := readFrontendSources(t)
	// 必须是 &App{}：App 的方法全是指针接收者，用值类型 reflect.TypeOf(App{})
	// 拿到的方法集是空的，这个守卫会静默地什么都不检查（第一版就是这么漏掉的）。
	typ := reflect.TypeOf(&App{})
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		for j := 0; j < m.Type.NumOut(); j++ {
			for _, name := range structNamesOf(m.Type.Out(j)) {
				if registered[name] {
					continue
				}
				// 前端没有同名 interface、也没调这个方法：那它还没跨过边界，不算漏登记
				// （嵌套结构体由外层字段间接覆盖，或者压根没被界面读）。
				// 两种"没对齐"都要抓：同名 interface 已经写好但表里漏一行；
				// 以及 api.ts 已经在 bridge.Xxx() 调它了——后者是 Go 加了投影类型、
				// 前端给起了另一个名字，靠名字对撞是撞不出来的。
				if hasInterface(src, name) || frontendCalls(feSrc, "bridge."+m.Name+"(") {
					missing = append(missing, fmt.Sprintf("App.%s 返回 %s", m.Name, name))
				}
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("这些被返回给前端的结构体没进 typePairs，字段名对错没人管：\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// frontendCalls 看前端有没有真的调某个绑定方法（api.ts 里是 bridge.Xxx() 这一句）。
func frontendCalls(src map[string]string, needle string) bool {
	for _, body := range src {
		if strings.Contains(body, needle) {
			return true
		}
	}
	return false
}

// TestEveryProjectedFieldIsRead 不许有"投影出去但没人读"的字段。
//
// 这条不是洁癖：Snapshot 上曾经同时挂着 Server 和 ProxyAddr（同一个值的两份拷贝），
// 还挂着 logLevel——界面从来没读过它。多一个字段就多一条"改了 Go 忘了改前端"的路，
// 而它坏起来的样子是界面某格永远是空的，没人怀疑到一个没人读的字段上。
//
// 判据是"前端源码里出现过 .字段名"（模板里 status.foo / props.status.foo / 解构后的 .foo）。
// 这不是完美检测：用别的写法读就会漏。所以宁可报得让人加例外，也不要静默放过。
//
// 还有一个更具体的盲区记在 readInFrontend 上面：**同名字段互相打掩护**，
// 以及为什么没有把它收紧掉（两版收紧各自会造出 56 / 30 条假红）。
func TestEveryProjectedFieldIsRead(t *testing.T) {
	src := readFrontendSources(t)
	unused := []string{}
	for _, p := range typePairs {
		fields, err := jsonFields(p.goVal)
		if err != nil {
			t.Errorf("%s: %v", p.goName, err)
			continue
		}
		for _, f := range fields {
			if _, ok := unusedOK[p.goName+"."+f]; ok {
				continue
			}
			if readInFrontend(src, f) != "" {
				continue
			}
			unused = append(unused, fmt.Sprintf("%s 的 JSON 键 %q", p.goName, f))
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		t.Errorf("这些字段投影给了前端却没人读：\n  %s\n要么在界面上把它显示出来，要么从结构体里删掉；\n"+
			"确实要暂时留着，就加进 unusedOK 并在那里写清为什么。", strings.Join(unused, "\n  "))
	}
}

// unusedOK 是显式登记的例外：键是 "Go 类型名.JSON 键"。
// 空表是常态——加一行就等于欠一条理由。
var unusedOK = map[string]string{}

func readInFrontend(files map[string]string, field string) string {
	// 已知盲区（2026-10-19 实测确认，不是猜想）：**同名字段互相打掩护**。
	// 把连接表里读 ConnView.node 的那三处全删掉，这一条照样报 ok——
	// 因为 Traffic.vue 里 `n.node` 读的是 NodeTraffic.node，同名。
	//
	// 收紧过一次，两版都试了，都不划算（数字是各跑一遍数出来的）：
	//   a) 要求"读它的文件里同时提到这个 interface 名"——**56** 条新红；
	//   b) 只对撞名的字段这么要求——仍然 **30** 条新红。
	// 根因是结构性的：组件拿到的是**已经带好类型的 props**，读的是 `tun.running`，
	// 那个 interface 名（TUNStatus）在前端只出现在 api.ts 与 types.ts 里，
	// 组件文件一个都没提。所以"同文件提到 interface"这个条件本身就不成立。
	// 两种都会把正常的读法判成死字段，而一堆假红只会让人开始往
	// unusedOK 里随手加例外——那比盲区更糟。
	//
	// 所以这一条的准确读法是：**它只保证"这个字段名在前端某处出现过"**。
	// 新加字段时"界面真的读了它"仍然要靠人（以及 §14.5 那份清单第 6 步）。
	for path, body := range files {
		if strings.Contains(body, "."+field) || strings.Contains(body, "["+field+"]") {
			return path
		}
	}
	return ""
}

// readFrontendSources 把前端源码整个读进来（只有十几个文件，够用且比走一遍 AST 便宜）。
func readFrontendSources(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join(repoRoot(t), "frontend", "src")
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".vue") && !strings.HasSuffix(path, ".ts") {
			return nil
		}
		// 演示数据不算"读"：它只是给字段赋一个假值，不证明界面会显示它。
		if strings.HasSuffix(path, "types.ts") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("遍历 %s: %v", root, err)
	}
	if len(out) == 0 {
		t.Fatalf("%s 下一个源文件都没读到，这个守卫等于没跑", root)
	}
	return out
}

func readFrontendTypes(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "frontend", "src", "types.ts")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到 %s：%v。这个守卫就是靠它成立的，不要用 skip 把它关掉。", path, err)
	}
	return string(b)
}

// repoRoot 从测试目录往上找 go.mod，避免把绝对路径写死。
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("往上找不到 go.mod，测试目录不在仓库里？")
	return ""
}

// jsonFields 取一个结构体所有会出现在 JSON 里的键名。
func jsonFields(v any) ([]string, error) {
	typ := reflect.TypeOf(v)
	if typ == nil || typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%T 不是结构体", v)
	}
	out := []string{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Anonymous {
			return nil, fmt.Errorf("%s.%s 是内嵌结构体，这个守卫还没覆盖内嵌字段", typ.Name(), f.Name)
		}
		if !f.IsExported() {
			continue // 非导出字段不过 JSON 边界
		}
		tag, ok := f.Tag.Lookup("json")
		if !ok {
			return nil, fmt.Errorf("%s.%s 没有 json tag：前端拿到的键名会是字段名本身，两边极易错开",
				typ.Name(), f.Name)
		}
		name := strings.Split(tag, ",")[0]
		if name == "-" {
			continue
		}
		if name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

var (
	reInterface = regexp.MustCompile(`^export\s+interface\s+([A-Za-z0-9_]+)\s*\{`)
	reField     = regexp.MustCompile(`^\s*([A-Za-z0-9_]+)\s*\??\s*:`)
)

// tsInterfaceFields 按大括号配对切出 interface 体，逐行取字段名。
func tsInterfaceFields(src, name string) ([]string, bool) {
	body, ok := tsInterfaceBody(src, name)
	if !ok {
		return nil, false
	}
	out := []string{}
	for _, line := range strings.Split(stripTSComments(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if m := reField.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	return out, true
}

func hasInterface(src, name string) bool {
	_, ok := tsInterfaceBody(src, name)
	return ok
}

func tsInterfaceBody(src, name string) (string, bool) {
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		m := reInterface.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil || m[1] != name {
			continue
		}
		depth := strings.Count(line, "{") - strings.Count(line, "}")
		j := i + 1
		for ; j < len(lines) && depth > 0; j++ {
			depth += strings.Count(lines[j], "{") - strings.Count(lines[j], "}")
		}
		if depth > 0 {
			return "", false // interface 没闭合，宁可认成"不存在"也不猜字段
		}
		// 开头那一行 `{` 之后的内容也要算进 body。把字段写在 `interface X { a: string`
		// 这种同一行里的写法并不罕见（编辑器自动格式化、手写都常见），漏掉它等于
		// 悄悄给出一个"字段都对得上"的假结论——那比没有这个守卫更糟。
		body := []string{line[strings.Index(line, "{")+1:]}
		return strings.Join(append(body, lines[i+1:j]...), "\n"), true
	}
	return "", false
}

// stripTSComments 去掉 // 行注释与 /* */ 块注释。
// 必须先剥：字段上方的 /** Unix 毫秒 */ 里有冒号，不剥会被 reField 当成一个字段。
// 这里不处理字符串字面量里的注释符——interface 体里只有类型，没有字符串值。
func stripTSComments(body string) string {
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); {
		switch {
		case body[i] == '/' && i+1 < len(body) && body[i+1] == '/':
			for i < len(body) && body[i] != '\n' {
				i++
			}
		case body[i] == '/' && i+1 < len(body) && body[i+1] == '*':
			i += 2
			for i+1 < len(body) && !(body[i] == '*' && body[i+1] == '/') {
				i++
			}
			if i+1 < len(body) {
				i += 2
			}
		default:
			out = append(out, body[i])
			i++
		}
	}
	return string(out)
}

// structNamesOf 递归取出类型里所有结构体类型的 Go 名字（去掉包前缀）。
// 只关心跨边界的层，所以字段类型也一起看：ConfigForm 里的 TUNForm 就是这么被发现的。
func structNamesOf(t reflect.Type) []string {
	seen := map[string]bool{}
	var walk func(reflect.Type, int)
	walk = func(t reflect.Type, depth int) {
		if depth > 3 {
			return
		}
		switch t.Kind() {
		case reflect.Pointer, reflect.Slice, reflect.Array:
			walk(t.Elem(), depth+1)
		case reflect.Map:
			walk(t.Elem(), depth+1)
		case reflect.Struct:
			name := t.Name()
			if name != "" && !seen[name] && !isStdlib(t) {
				seen[name] = true
			}
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if !f.IsExported() {
					continue
				}
				walk(f.Type, depth+1)
			}
		}
	}
	walk(t, 0)
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	return out
}

// isStdlib 排掉 time.Time 这类：它们有自己的 JSON 形态，不是我们手写的投影。
func isStdlib(t reflect.Type) bool {
	path := t.PkgPath()
	return !strings.HasPrefix(path, "wps_app/")
}

func diffFields(goName, tsName string, goFields, tsFields []string) string {
	inGo := toSet(goFields)
	inTS := toSet(tsFields)
	onlyGo := missing(inTS, inGo)
	onlyTS := missing(inGo, inTS)
	if len(onlyGo) == 0 && len(onlyTS) == 0 {
		return ""
	}
	msg := ""
	if len(onlyGo) > 0 {
		msg += fmt.Sprintf("    Go 侧有、types.ts 没有（前端只会读到 undefined）：%s\n", strings.Join(onlyGo, ", "))
	}
	if len(onlyTS) > 0 {
		msg += fmt.Sprintf("    types.ts 有、Go 侧没有（界面读到的是空值）：%s\n", strings.Join(onlyTS, ", "))
	}
	return fmt.Sprintf("  %s → %s\n%s", goName, tsName, msg)
}

func toSet(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

func missing(skip, src map[string]bool) []string {
	out := []string{}
	for k := range src {
		if !skip[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestTsInterfaceFieldsSeesOpeningLine 守卫自己不许有盲区。
//
// 字段写在 `interface X { a: string` 同一行里时，解析器必须照样看得见：
// 看不见就会报"两边对得上"，而实际上有一侧多了一个字段没人比对——
// 这种"假通过"比守卫缺席更费时间，因为人会因此不再怀疑它。
func TestTsInterfaceFieldsSeesOpeningLine(t *testing.T) {
	src := `export interface Same { type: string
  listen: string
}
`
	fields, ok := tsInterfaceFields(src, "Same")
	if !ok {
		t.Fatal("没找到 Same")
	}
	if len(fields) != 2 || fields[0] != "type" || fields[1] != "listen" {
		t.Fatalf("同一行里写的字段被漏掉了，得到 %v", fields)
	}
}
