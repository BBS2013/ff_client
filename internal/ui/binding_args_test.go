package ui

// 参数个数守卫：api.ts 里 `AppBridge` 声明的每个方法，参数个数必须与 Go 那侧一致。
//
// 这条守的是**最致命那一类跨语言漂移**。字段名对不上时界面某一格变空，看得见；
// 参数对不上时整次调用直接失败，而且它坏的方式和构建方式有关：
// `?demo=` 那套假后端是 TS 自己实现的一个分支，它和 `AppBridge` 受同一份 TS 类型约束，
// 少传一个参数只会让演示页照样给出漂亮读数——守卫在 Go 侧，演示在 TS 侧，两边都发现不了。
// 只有真面板走到 Wails 反射那一步才炸，而那一步恰恰是"不敢重启线面板所以一直没验"的地方。
//
// 所以这里断的是 Go 反射拿到的真实签名对 TS 声明表：改 Go 方法参数不改 api.ts，构建期就红。

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestBridgeArgsMatchGo(t *testing.T) {
	src := readAppBridge(t)
	decls := parseInterfaceParams(src, "AppBridge")
	if len(decls) == 0 {
		t.Fatalf("在 api.ts 里没解析出 AppBridge 的任何方法，这个守卫等于没跑")
	}
	typ := reflect.TypeOf(&App{})
	goMethod := map[string]reflect.Type{}
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		goMethod[m.Name] = m.Type
	}
	// 接口比方法多也要说：TS 声明了一个 Go 上没有的方法，点它必炸，
	// 而炸的样子是"这个按钮在演示里好用、在面板里没反应"。
	for _, name := range sortedKeys(decls) {
		mt, ok := goMethod[name]
		if !ok {
			t.Errorf("api.ts 的 AppBridge 声明了 %s，Go 的 App 上没有这个方法——真面板上点它必失败", name)
			continue
		}
		want := mt.NumIn() - 1 // 去掉接收者
		got := decls[name]
		if want != got {
			t.Errorf("App.%s 收 %d 个参数，api.ts 只声明/传了 %d 个 —— Wails 反射会在这一刻失败，"+
				"而 ?demo= 验不出来", name, want, got)
		}
	}
	// 反向只查"被前端调过、却没在接口里声明"的：那种调用走的是别的路（或者压根是笔误），
	// 而"Go 有、界面没接"是常态（一堆方法给 CLI 用），不能算红。
	fe := readFrontendSources(t)
	for m := range goMethod {
		if _, ok := decls[m]; ok {
			continue
		}
		if frontendCalls(fe, "bridge."+m+"(") {
			t.Errorf("前端调了 bridge.%s，但 AppBridge 接口里没有这一行——参数个数没人管", m)
		}
	}
}

// readAppBridge 读 api.ts。读不到就 Fatalf：这个守卫的全部价值在于它真的跑了。
func readAppBridge(t *testing.T) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), "frontend", "src", "api.ts")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到 %s：%v。这个守卫就是靠它成立的，不要用 skip 把它关掉。", path, err)
	}
	return string(b)
}

// parseInterfaceParams 从 TS 源码里取出某个 interface 的方法声明，数每个方法的参数个数。
//
// 只认 interface 体里 `name(args): Ret` 这一种形状（顶层花括号内、圆括号配对后紧跟冒号）。
// 数参数按**顶层逗号**数：`cb: (a: T, b: U) => void` 这种嵌在类型里的逗号不能算一个参数，
// 所以这里带深度扫描，而不是 split(",")。空圆括号算 0，`a?: T` 这种可选参数算 1——
// 桥是位置传参，可选与否不影响"Go 那边要几个"。
func parseInterfaceParams(src, iface string) map[string]int {
	out := map[string]int{}
	head := "interface " + iface + " {"
	i := strings.Index(src, head)
	if i < 0 {
		return out
	}
	body := src[i+len(head):]
	depth := 1 // 已经在 interface 的那对花括号里
	for j := 0; j < len(body); j++ {
		switch body[j] {
		case '{':
			depth++
			continue
		case '}':
			depth--
			if depth == 0 {
				return out
			}
			continue
		}
		if depth != 1 || body[j] == ' ' || body[j] == '\n' || body[j] == '\t' {
			continue
		}
		// 方法名：行首（跳过分隔符后）的第一个标识符。
		if !isIdentStart(body[j]) {
			continue
		}
		k := j
		for k < len(body) && (isIdentChar(body[k]) || body[k] == '?') {
			k++
		}
		name := body[j:k]
		p := k
		for p < len(body) && (body[p] == ' ' || body[p] == '\t') {
			p++
		}
		if p >= len(body) || body[p] != '(' {
			j = k - 1
			continue
		}
		end, ok := matchParen(body, p)
		if !ok {
			return out
		}
		// 声明表里 `name(args): Ret` 后面必须紧跟冒号；不是冒号的是别的东西（注释里的例子）。
		q := end + 1
		for q < len(body) && (body[q] == ' ' || body[q] == '\n' || body[q] == '\t') {
			q++
		}
		if q < len(body) && body[q] == ':' {
			out[name] = countParams(body[p+1 : end])
			j = end
			continue
		}
		j = k - 1
	}
	return out
}

// countParams 数顶层逗号 + 1；空（或只有空白）为 0。
func countParams(args string) int {
	s := strings.TrimSpace(args)
	if s == "" {
		return 0
	}
	depth, n := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(', '[', '{', '<':
			depth++
		case ')', ']', '}', '>':
			depth--
		case ',':
			if depth == 0 {
				n++
			}
		}
	}
	return n + 1
}

func matchParen(s string, open int) (int, bool) {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestBridgeArgsGuardIsNotAnEmptyRun 是这条守卫自己的负对照。
//
// 上面那个测试最容易的失效方式是"解析出一个方法都没有"或者"Go 侧方法集是空的"
// （用值类型 reflect.TypeOf(App{}) 拿指针接收者的方法集会拿到 0 个，
// 这条守卫在本仓库的前一版就漏过一次，从此再没检查过任何东西）。
// 这里把两个下限写死：解析到的方法数、以及它与 App 方法集的交集都必须够大。
func TestBridgeArgsGuardIsNotAnEmptyRun(t *testing.T) {
	decls := parseInterfaceParams(readAppBridge(t), "AppBridge")
	typ := reflect.TypeOf(&App{})
	if len(decls) < 40 {
		t.Errorf("只从 AppBridge 解析出 %d 个方法，多半是解析器没跟上写法（这仓库的桥有 %d 个方法）",
			len(decls), typ.NumMethod())
	}
	both := 0
	for name := range decls {
		if _, ok := goMethodsOf(typ)[name]; ok {
			both++
		}
	}
	if both < 40 {
		t.Errorf("AppBridge 与 App 的方法只对上 %d 个，这个守卫基本没比任何东西", both)
	}
	// 探针：这条守卫真的能认出参数个数。写死三个已知的方法名，
	// 它们一旦改名或换签名，这里会先红——而不是等某次跨语言事故。
	for name, want := range map[string]int{"ProbeDNS": 3, "FetchPage": 1, "Status": 0} {
		if got, ok := decls[name]; !ok {
			t.Errorf("解析结果里没有 %s，解析器或接口写法变了", name)
		} else if got != want {
			t.Errorf("%s 在 api.ts 里数出 %d 个参数，期望 %d 个", name, got, want)
		}
	}
}

func goMethodsOf(typ reflect.Type) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < typ.NumMethod(); i++ {
		out[typ.Method(i).Name] = true
	}
	return out
}
