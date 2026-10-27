// KDE 后端：改 ~/.config/kioslaverc 里的 [Proxy Settings]。
//
// 为什么直接改文件而不是调 kwriteconfig5：
//
//  1. kwriteconfig5/6 未必在 PATH 上（它们属于 kf5-config / kf6-config，
//     精简装的 KDE 常常没装），而 kioslaverc 本身一定是存在的。
//  2. 直接改文件能按**原样**把旧的 [Proxy Settings] 段抄回快照里做还原；
//     kwriteconfig 会重排整个文件，快照就只剩一个「重写后的样子」，
//     还原等于把用户原来那一段（包括顺序与注释）换掉。
//
// 只动 [Proxy Settings] 这一段，文件里其余的组与键按字节原样保留。
//
// **活性的诚实边界**：Plasma 在登录时读 kioslaverc。写完文件后我们尽力发一次
// D-Bus 通知让它重读，但那条通知在 Plasma 的不同版本上并不统一，
// 发不出去是常态。发不出去时新开的应用仍会读到新值，而已经跑着的不会——
// 所以界面上照实写「可能要重新登录」，不假装它一定立刻生效。
package sysproxy

import (
	"context"
	"fmt"
	"os"
	"strings"
)

const (
	// kdeProxyFile 是相对家目录的路径，与状态文件一样允许配置写绝对路径。
	kdeProxyFile = ".config/kioslaverc"
	// kdeProxyGroup 是我们唯一会改的段。
	kdeProxyGroup = "Proxy Settings"
)

type kdeBackend struct{}

func (kdeBackend) Name() string { return BackendKDE }

// Probe 只看家目录在不在。有家目录就能写 kioslaverc，
// 与 KDE 本身在不在无关——kioslaverc 是 KDE 与 Chromium 系共用的格式，
// 而且「文件在」远比「桌面在」可靠（无头会话里照样能用）。
func (kdeBackend) Probe(context.Context, Runner) error {
	if desktopHome() == "" {
		return fmt.Errorf("找不到家目录，没法写 %s", kdeProxyFile)
	}
	return nil
}

func (b kdeBackend) Apply(ctx context.Context, r Runner, c Config) error {
	if r == nil {
		r = ExecRunner{}
	}
	path := resolvePath(desktopHome(), kdeProxyFile)

	// 关闭时把整段收成 ProxyType=None。与 GNOME 那边「只翻 mode」的差别是刻意的：
	// kioslaverc 里的 ProxyType=None 只表示"不用代理"，而一个指向
	// 127.0.0.1:7892 的 httpProxy 留在文件里，会在用户几个月后手工打开这个文件时
	// 变成一个看起来有效、实际早就没人监听的地址。删文件比留一个假端点好。
	// 真正的"还原成改动前的样子"由记账负责（见 state.go），不是这里。
	if !c.Enable {
		return setKDEGroup(ctx, r, path, []string{"ProxyType=None"})
	}
	// 值先摆好，ProxyType 最后写——理由同 gsettings 那条：
	// 中间失败不会留下「已经生效但指向旧端口」的半配置状态。
	return setKDEGroup(ctx, r, path, kdeEnableKeys(c))
}

// kdeEnableKeys 是启用时写进 [Proxy Settings] 的那几行。
// 记账时的比对也用它：两处各拼一份，默认端口一改就会静默判错。
func kdeEnableKeys(c Config) []string {
	e := c.endpoints()
	return []string{
		"httpProxy=http://" + e.HTTP(),
		"httpsProxy=http://" + e.HTTPS(),
		"socksProxy=socks5://" + e.SOCKS(),
		"ProxyOnlyForLocal=false",
		"NoProxyFor=" + strings.Join(mergeBypass(c.Bypass), ","),
		"ProxyType=Manual",
	}
}

// KDELikesOurs 报告快照里那段是不是已经等于我们要写的内容。
//
// 命中时说明桌面上那套指向本来就是本程序（或等价配置）留下的，
// 把它当"原状"记下来会让关掉之后仍然指向我们的端口。
func KDELikesOurs(snap kdeSnapshot, c Config) bool {
	if !snap.Existed {
		return false
	}
	kv := parseKDEGroup(snap.Group, kdeProxyGroup)
	want := map[string]string{}
	for _, line := range kdeEnableKeys(c) {
		if i := strings.Index(line, "="); i > 0 {
			want[line[:i]] = line[i+1:]
		}
	}
	for k, v := range want {
		if strings.TrimSpace(kv[k]) != v {
			return false
		}
	}
	return true
}

func (b kdeBackend) Read(ctx context.Context, r Runner) (Status, error) {
	st := Status{Ignored: []string{}, Backend: BackendKDE}
	if err := b.Probe(ctx, r); err != nil {
		st.Error = ErrUnsupported.Error()
		return st, ErrUnsupported
	}
	if r == nil {
		r = ExecRunner{}
	}
	path := resolvePath(desktopHome(), kdeProxyFile)
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		st.Error = err.Error()
		return st, err
	}
	st.Supported = true
	st.Path = path
	st.Note = "Plasma 在登录时读这个文件。我们会尽力通知它重读，但这一步在" +
		"不同版本上并不统一；已经在跑的应用不会立刻跟着变，必要时重新登录一次。"
	kv := parseKDEGroup(string(raw), kdeProxyGroup)
	st.Mode = kv["ProxyType"]
	st.Enabled = strings.EqualFold(st.Mode, "Manual")
	if !st.Enabled {
		return st, nil
	}
	st.HTTP = trimScheme(kv["httpProxy"])
	st.HTTPS = trimScheme(kv["httpsProxy"])
	st.SOCKS = trimScheme(kv["socksProxy"])
	if raw := strings.TrimSpace(kv["NoProxyFor"]); raw != "" {
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				st.Ignored = append(st.Ignored, p)
			}
		}
	}
	return st, nil
}

// Snapshot 是 KDE 后端的还原材料：[Proxy Settings] 整段的原文。
//
// 存原文而不是「解析出来的键值」：解析再拼回去会丢掉组内的注释与顺序，
// 而用户对「我原来的设置长什么样」的预期是那一份文件，不是我们对它的理解。
type kdeSnapshot struct {
	Existed bool   `json:"existed"`
	Group   string `json:"group,omitempty"`
}

// CaptureKDE 取出当前的 [Proxy Settings] 段，供记账。
func CaptureKDE() (kdeSnapshot, error) {
	path := resolvePath(desktopHome(), kdeProxyFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return kdeSnapshot{Existed: false}, nil
	}
	if err != nil {
		return kdeSnapshot{}, err
	}
	return kdeSnapshot{Existed: true, Group: extractKDEGroup(string(raw), kdeProxyGroup)}, nil
}

// RestoreKDE 按快照把 kioslaverc 还原回去。
// Existed 为 false 表示「我们动手前这个文件本来不存在」，那就整个删掉。
func RestoreKDE(snap kdeSnapshot) error {
	path := resolvePath(desktopHome(), kdeProxyFile)
	if !snap.Existed {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	out := replaceKDEGroup(string(raw), kdeProxyGroup, snap.Group)
	return writeFileAtomic(path, []byte(out))
}

// setKDEGroup 改写 [Proxy Settings] 并尽力通知 Plasma 重读。
func setKDEGroup(ctx context.Context, r Runner, path string, keys []string) error {
	raw, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	body := make([]string, 0, len(keys))
	for _, k := range keys {
		body = append(body, k)
	}
	// 末尾多一个空元素：段后留一行空行。少了它，写完的段会直接贴上下一个段头，
	// 而还原走的是记账里那段原文（原文带空行）——于是「开→关→再开」的文件
	// 形状跟「开」之前不一样，看着像凭空动过。
	out := replaceKDEGroup(string(raw), kdeProxyGroup, "["+kdeProxyGroup+"]\n"+strings.Join(body, "\n")+"\n")
	if err := writeFileAtomic(path, []byte(out)); err != nil {
		return err
	}
	notifyPlasma(ctx, r)
	return nil
}

// notifyPlasma 尽力让 Plasma 重读 kioslaverc。
//
// 这一步失败不影响正确性：文件已经写好了，下次登录一定生效。
// 所以它刻意吞掉错误——为一条「下次登录就好了」的通知去报错，
// 只会让用户以为代理没设置上。
func notifyPlasma(ctx context.Context, r Runner) {
	if r == nil {
		return
	}
	args, env := desktopPrefix()
	// plasma-nm 在不同版本上的服务名不一样，逐个试，全失败就算了。
	for _, svc := range []string{"org.kde.plasma.networkmanagement", "org.kde.plasma.networkmanagement.plasma"} {
		_, _ = r.Run(ctx, append(args, "dbus-send", "--session", "--dest="+svc,
			"/", svc+".reparseConfiguration"), env)
	}
}

// extractKDEGroup 取出一整段（含段头与其中的注释/空行），段不存在时返回空串。
func extractKDEGroup(body, group string) string {
	lines := strings.Split(body, "\n")
	var out []string
	in := false
	for _, ln := range lines {
		name, isHeader := kdeHeader(ln)
		if isHeader {
			if in {
				break
			}
			in = name == group
		}
		if in {
			out = append(out, ln)
		}
	}
	// 不做 TrimRight：段尾的空行是它与下一个段之间的分隔，
	// 抹掉它，还原出来的文件就不再和原文逐字节一致——而"原样还原"正是这个快照的全部意义。
	return strings.Join(out, "\n")
}

// replaceKDEGroup 用 newGroup 替换 [group] 段。newGroup 为空串等于删掉这一段。
//
// 两个容易写错的地方都在这儿踩过：补上新段之后**必须**把紧随其后的段头
// 原样输出（少输出一行，后面的段连同它的键一起没了），
// 以及段本来就不存在时要追加到末尾（文件为空时一个字符都不会写进去）。
func replaceKDEGroup(body, group, newGroup string) string {
	lines := strings.Split(body, "\n")
	if strings.TrimSpace(body) == "" {
		lines = nil
	}
	out := make([]string, 0, len(lines)+8)
	in := false
	written := false
	flush := func() {
		if !written && strings.TrimSpace(newGroup) != "" {
			out = append(out, splitLines(newGroup)...)
			written = true
		}
	}
	for _, ln := range lines {
		name, isHeader := kdeHeader(ln)
		if isHeader {
			if in {
				// 旧段到此为止：补上新段，然后**这一行本身要照常输出**。
				flush()
				in = false
				out = append(out, ln)
				continue
			}
			if name == group {
				in = true
				continue // 旧段的内容由 flush 整段丢弃
			}
		}
		if in {
			continue
		}
		out = append(out, ln)
	}
	// 走到这里要么段在文件末尾（in 仍为真），要么段压根不存在。
	// 两种情况都要把新段补上。
	flush()
	return strings.Join(out, "\n")
}

// splitLines 按行切开，不吃掉末尾的空元素——那正是段尾的分隔行。
func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

// kdeHeader 判断一行是不是段头，是则返回段名。
func kdeHeader(line string) (name string, ok bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "[") || !strings.HasSuffix(t, "]") {
		return "", false
	}
	inner := strings.TrimSpace(t[1 : len(t)-1])
	// KConfig 允许段名后面带类型限定（[Foo][Bar]），只取第一段。
	if i := strings.Index(inner, "]"); i >= 0 {
		inner = strings.TrimSpace(inner[:i])
	}
	return inner, true
}

// parseKDEGroup 把一段里的 key=value 读成 map。
func parseKDEGroup(body, group string) map[string]string {
	out := map[string]string{}
	in := false
	for _, ln := range strings.Split(body, "\n") {
		if name, isHeader := kdeHeader(ln); isHeader {
			if in {
				break
			}
			in = name == group
			continue
		}
		if !in {
			continue
		}
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		k, v, found := strings.Cut(t, "=")
		if !found {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}

func trimScheme(v string) string {
	v = strings.TrimSpace(v)
	for _, p := range []string{"socks5h://", "socks5://", "socks4a://", "socks4://", "http://", "https://"} {
		if rest, ok := strings.CutPrefix(v, p); ok {
			return rest
		}
	}
	return v
}
