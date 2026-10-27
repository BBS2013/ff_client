// GNOME 后端：用 gsettings 写 org.gnome.system.proxy。
//
// 这是覆盖面最大也最可逆的一条路：桌面自己管着这份设置，`mode none` 就完全还原，
// 不在用户家目录里留下我们自己的任何痕迹。浏览器、apt、curl(libcurl)
// 与一大批遵循 GSettings 的应用会自动生效。
//
// 以 root 运行（TUN 模式需要特权）时，gsettings 必须落到桌面用户身上：
// root 的那份 dconf 里没有桌面会话，写了也没人读。desktopPrefix 按 $SUDO_USER
// 还原调用者身份，并显式给出它的 D-Bus 地址。
package sysproxy

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Schema 键名前缀。
const (
	schema      = "org.gnome.system.proxy"
	schemaHTTP  = "org.gnome.system.proxy.http"
	schemaHTTPS = "org.gnome.system.proxy.https"
	schemaSOCKS = "org.gnome.system.proxy.socks"
)

type gnomeBackend struct{}

func (gnomeBackend) Name() string { return BackendGNOME }

// ProbeTimeout 是探测「这台机器支不支持 gsettings」的时间上限。
//
// 没有它的话，一个卡住的 gsettings（D-Bus 死锁、总线地址指向一个不响应的
// 套接字）会把 Wails 的绑定调用永久挂住：界面上那个开关点下去再也不动，
// 而且因为绑定调用是同步的，整个界面的事件循环都被拖住。
const ProbeTimeout = 5 * time.Second

func (gnomeBackend) Probe(ctx context.Context, r Runner) error {
	pctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	args, env := desktopPrefix()
	if out, err := r.Run(pctx, append(args, "gsettings", "--version"), env); err != nil {
		return fmt.Errorf("gsettings 不可用: %w (%s)", err, out)
	}
	return nil
}

func (gnomeBackend) Apply(ctx context.Context, r Runner, c Config) error {
	if r == nil {
		r = ExecRunner{}
	}
	args, env := desktopPrefix()
	if c.Enable {
		e := c.endpoints()

		// 写入顺序是有讲究的：先把 host/port/ignore-hosts 都摆好，
		// 最后一步才把 mode 切到 manual。
		//
		// 反过来（先切 manual 再填地址）的话，中间任何一步失败都会留下
		// 「mode=manual 但 host 还是上一个值甚至空」的状态：
		// 桌面立刻按新模式取流量，而流量被送往一个错的端口，
		// 表现是整机断网，且系统代理面板里看不出任何异常。
		for _, s := range [][]string{
			{"gsettings", "set", schemaHTTP, "host", gvariantString(e.HTTPHost)},
			{"gsettings", "set", schemaHTTP, "port", e.HTTPPort},
			{"gsettings", "set", schemaHTTPS, "host", gvariantString(e.HTTPSHost)},
			{"gsettings", "set", schemaHTTPS, "port", e.HTTPSPort},
			{"gsettings", "set", schemaSOCKS, "host", gvariantString(e.SOCKSHost)},
			{"gsettings", "set", schemaSOCKS, "port", e.SOCKSPort},
			{"gsettings", "set", schema, "ignore-hosts", gvariantList(mergeBypass(c.Bypass))},
			// mode 最后写：上面全都落盘了，切换模式才是「提交」。
			{"gsettings", "set", schema, "mode", "'manual'"},
		} {
			if out, err := r.Run(ctx, append(args, s...), env); err != nil {
				return fmt.Errorf("gsettings set %s %s: %w (%s)", s[2], s[3], err, out)
			}
		}
		return nil
	}
	// 关闭同样先切 mode：一旦 mode=none，后面即使还有残留值也不会再被使用。
	out, err := r.Run(ctx, append(args, "gsettings", "set", schema, "mode", "'none'"), env)
	if err != nil {
		return fmt.Errorf("关闭系统代理失败: %w (%s)", err, out)
	}
	return nil
}

func (gnomeBackend) Read(ctx context.Context, r Runner) (Status, error) {
	st := Status{Ignored: []string{}, Backend: BackendGNOME}
	if r == nil {
		r = ExecRunner{}
	}
	if err := (gnomeBackend{}).Probe(ctx, r); err != nil {
		st.Error = ErrUnsupported.Error()
		return st, ErrUnsupported
	}
	args, env := desktopPrefix()
	mode, err := r.Run(ctx, append(args, "gsettings", "get", schema, "mode"), env)
	if err != nil {
		st.Error = err.Error()
		return st, err
	}
	st.Supported = true
	st.Mode = unquote(mode)
	st.Enabled = st.Mode == "manual"
	if !st.Enabled {
		return st, nil
	}
	for _, q := range []struct {
		schema string
		key    string
		dst    *string
	}{
		{schemaHTTP, "host", &st.HTTP},
		{schemaHTTPS, "host", &st.HTTPS},
		{schemaSOCKS, "host", &st.SOCKS},
	} {
		v, _ := r.Run(ctx, append(args, "gsettings", "get", q.schema, q.key), env)
		*q.dst = unquote(v)
	}
	for _, q := range []struct {
		schema string
		dst    *string
	}{
		{schemaHTTP, &st.HTTP},
		{schemaHTTPS, &st.HTTPS},
		{schemaSOCKS, &st.SOCKS},
	} {
		v, _ := r.Run(ctx, append(args, "gsettings", "get", q.schema, "port"), env)
		port := strings.Trim(unquote(v), `"`)
		if port != "" && port != "0" {
			*q.dst = (*q.dst + ":" + port)
		}
	}
	ignored, _ := r.Run(ctx, append(args, "gsettings", "get", schema, "ignore-hosts"), env)
	st.Ignored = parseList(ignored)
	return st, nil
}

// gvariantList 把字符串列表编成 gsettings 认的 GVariant 数组字面量。
//
// 两个容易踩的坑：
//
//  1. 不要在最外面再包一层单引号。命令是 exec 直接传参（不经 shell），
//     多包一层会让 gsettings 收到一个「字符串」而不是 as 数组，
//     报 can not parse as value of type 'as'，并且 ignore-hosts 悄悄保持原值。
//
//  2. 用双引号而不是单引号。单引号里 GVariant 只认 `\'` 一种转义，
//     所以一项以奇数个反斜杠结尾时（`\\nas\share\` 这种共享路径），
//     末尾的 `\` 会和收尾的引号合成 `\'`——一个转义引号，
//     解析器于是认为字符串还没结束，整条 ignore-hosts 直接解析失败。
//     双引号下转义规则是完备的（`\\` 与 `\"`），没有这种歧义。
func gvariantList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, s := range items {
		parts = append(parts, gvariantString(s))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// gvariantString 编一个 GVariant 双引号字符串。
func gvariantString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				// 其余控制字符在 GVariant 里没有对应转义，只能整个丢掉。
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func parseList(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if raw == "" {
		return []string{}
	}
	fields := strings.Split(raw, ",")
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, unquote(strings.TrimSpace(f)))
	}
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
