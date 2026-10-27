package sysproxy

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// rec 记录命令，按预设值回答 get 请求。
type rec struct {
	ran  []string
	gets map[string]string
	fail bool
	// failOn 非空时，包含该子串的命令按失败处理（用来验证中途失败的顺序纪律）。
	failOn string
}

func (r *rec) Run(_ context.Context, args []string, _ []string) (string, error) {
	joined := strings.Join(args, " ")
	r.ran = append(r.ran, joined)
	if r.fail && strings.Contains(joined, "--version") {
		return "", errNotFound
	}
	if r.failOn != "" && strings.Contains(joined, r.failOn) {
		return "boom", errors.New("injected failure")
	}
	if len(args) > 2 && args[len(args)-3] == "get" {
		return r.gets[strings.Join(args[len(args)-3:], " ")], nil
	}
	return "", nil
}

var errNotFound = &notFoundErr{}

type notFoundErr struct{}

func (*notFoundErr) Error() string { return "exec: gsettings: not found" }

func TestApplyEnablesSystemProxy(t *testing.T) {
	r := &rec{}
	err := Apply(context.Background(), r, Config{
		Enable:    true,
		Backend:   BackendGNOME,
		HTTPAddr:  "127.0.0.1:7892",
		SOCKSAddr: "127.0.0.1:7891",
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.ran, "\n")
	for _, want := range []string{
		"gsettings set org.gnome.system.proxy mode 'manual'",
		`gsettings set org.gnome.system.proxy.http host "127.0.0.1"`,
		"gsettings set org.gnome.system.proxy.http port 7892",
		`gsettings set org.gnome.system.proxy.socks host "127.0.0.1"`,
		"gsettings set org.gnome.system.proxy.socks port 7891",
		`gsettings set org.gnome.system.proxy ignore-hosts ["localhost", `,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少 %q\n实际:\n%s", want, joined)
		}
	}
	// localhost 漏掉的话，本机自己访问自己会绕一大圈甚至卡在代理端口上。
	if !strings.Contains(joined, `"127.0.0.0/8"`) {
		t.Errorf("绕过列表里没有 127.0.0.0/8:\n%s", joined)
	}
}

// TestApplyWritesModeLast 守住写入顺序。
//
// 先把 mode 切成 manual 再填 host/port，中间任何一步失败都会留下
// 「mode=manual 但 host 还是旧值」：桌面立刻按新模式取流量，
// 却把流量送往一个错的端口——整机断网，且系统代理面板里看不出异常。
func TestApplyWritesModeLast(t *testing.T) {
	r := &rec{}
	if err := Apply(context.Background(), r, Config{Enable: true, Backend: BackendGNOME}); err != nil {
		t.Fatal(err)
	}
	last := r.ran[len(r.ran)-1]
	if !strings.Contains(last, "mode 'manual'") {
		t.Fatalf("最后一步必须是切换 mode，实际最后一步是: %s", last)
	}
	for i, cmd := range r.ran[:len(r.ran)-1] {
		if strings.Contains(cmd, " org.gnome.system.proxy mode ") {
			t.Fatalf("第 %d 步 %q 不该出现在 mode 切换之前", i, cmd)
		}
	}
}

// TestApplyDisableSetsModeFirst 关闭时反过来：先把 mode 摘掉，
// 剩下的残留值就不会再被任何程序使用。
func TestApplyDisableSetsModeFirst(t *testing.T) {
	r := &rec{failOn: "manual"}
	if err := Apply(context.Background(), r, Config{Enable: true, Backend: BackendGNOME}); err == nil {
		t.Fatal("预设在 mode 一步失败时，Apply 应报错")
	}
	if len(r.ran) == 0 {
		t.Fatal("应先写过 host/port 再碰 mode")
	}
	// 从零开始的关闭路径：mode=none 必须是唯一一步。
	r2 := &rec{}
	if err := Apply(context.Background(), r2, Config{Enable: false}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r2.ran[len(r2.ran)-1], "mode 'none'") {
		t.Fatalf("关闭时应把 mode 设为 none: %v", r2.ran)
	}
}

func TestApplyDisablesSystemProxy(t *testing.T) {
	r := &rec{}
	if err := Apply(context.Background(), r, Config{Enable: false}); err != nil {
		t.Fatal(err)
	}
	if len(r.ran) != 2 { // --version + set mode none
		t.Fatalf("关闭时不该做多余的事: %v", r.ran)
	}
	if !strings.Contains(r.ran[len(r.ran)-1], "mode 'none'") {
		t.Fatalf("没把 mode 设回 none: %v", r.ran)
	}
}

func TestApplyUsesFallbackAddrs(t *testing.T) {
	r := &rec{}
	if err := Apply(context.Background(), r, Config{Enable: true, Backend: BackendGNOME}); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(r.ran, "\n")
	if !strings.Contains(joined, "port 7892") || !strings.Contains(joined, "port 7891") {
		t.Fatalf("没落到默认入站端口:\n%s", joined)
	}
}

// TestApplyUnsupported 当用户明确点名了一个后端而它不可用时，必须**硬失败**，
// 不能悄悄换一条路：那等于"我说要 GNOME，你替我改了 KDE 的桌面设置"。
func TestApplyUnsupported(t *testing.T) {
	r := &rec{fail: true}
	err := Apply(context.Background(), r, Config{Enable: true, Backend: BackendGNOME})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("应返回 ErrUnsupported，实际 %v", err)
	}
	if len(r.ran) != 1 {
		t.Fatalf("探测失败后不该继续下发设置: %v", r.ran)
	}
}

// TestApplyUnknownBackendIsRefused 后端名不认识时直接拒绝，不当成 auto。
//
// 拼错的名字若被静默当成 auto，界面会显示"自动选的"——
// 而它其实是用户明确指定了、我们根本没执行的那个。
func TestApplyUnknownBackendIsRefused(t *testing.T) {
	r := &rec{}
	err := Apply(context.Background(), r, Config{Enable: true, Backend: "windos"})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("不认识的后端应报不支持，实际 %v", err)
	}
	if len(r.ran) != 0 {
		t.Fatalf("不认识的后端不该跑任何命令: %v", r.ran)
	}
}

func TestReadParsesGSettings(t *testing.T) {
	r := &rec{gets: map[string]string{
		"get org.gnome.system.proxy mode":         "'manual'",
		"get org.gnome.system.proxy.http host":    "'127.0.0.1'",
		"get org.gnome.system.proxy.http port":    "7892",
		"get org.gnome.system.proxy.https host":   "'127.0.0.1'",
		"get org.gnome.system.proxy.https port":   "7892",
		"get org.gnome.system.proxy.socks host":   "'127.0.0.1'",
		"get org.gnome.system.proxy.socks port":   "7891",
		"get org.gnome.system.proxy ignore-hosts": "['localhost', '127.0.0.0/8']",
	}}
	st, err := Read(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Supported || !st.Enabled || st.Mode != "manual" {
		t.Fatalf("读数不对: %+v", st)
	}
	if st.HTTP != "127.0.0.1:7892" || st.SOCKS != "127.0.0.1:7891" {
		t.Fatalf("地址拼接不对: %+v", st)
	}
	if len(st.Ignored) != 2 || st.Ignored[0] != "localhost" {
		t.Fatalf("ignore-hosts 解析不对: %v", st.Ignored)
	}

	off := &rec{gets: map[string]string{"get org.gnome.system.proxy mode": "'none'"}}
	st, err = Read(context.Background(), off)
	if err != nil {
		t.Fatal(err)
	}
	if st.Enabled || !st.Supported {
		t.Fatalf("关闭态读数不对: %+v", st)
	}
}

// TestReadUnsupportedOnPinnedBackend 明确点名 gnome 而它不可用时报不支持。
func TestReadUnsupportedOnPinnedBackend(t *testing.T) {
	st, err := ReadWith(context.Background(), &rec{fail: true}, BackendGNOME)
	if !errors.Is(err, ErrUnsupported) || st.Supported {
		t.Fatalf("应报不支持: %+v %v", st, err)
	}
	if st.Error == "" {
		t.Error("状态里应带上原因，界面才能解释为什么这个开关是灰的")
	}
}

// TestReadFallsBackWhenGNOMEAbsent 自动探测在 GNOME 不可用时会退到别的后端，
// 而不是一句"不支持"。这条是这个功能存在的理由：KDE 用户不该被告知
// "你的桌面不是 GNOME"。
//
// 注意 ReadWith 传空字符串才是自动探测；显式传名字时不做回退（见上面的用例）。
func TestReadFallsBackWhenGNOMEAbsent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	b, err := Detect(context.Background(), &rec{fail: true}, BackendAuto)
	if err != nil {
		t.Fatalf("gsettings 不可用时应当退到别的后端: %v", err)
	}
	if b.Name() == BackendGNOME {
		t.Fatal("探测到了不可用的 GNOME 后端")
	}
	st, err := b.Read(context.Background(), &rec{fail: true})
	if err != nil {
		t.Fatalf("读数: %v", err)
	}
	if !st.Supported {
		t.Fatalf("回退到的后端应当是可用的: %+v", st)
	}
	if st.Backend == "" {
		t.Error("状态里必须报出用的是哪条路，否则界面上无从解释")
	}
}

func TestGvariantListEscapes(t *testing.T) {
	// 不能带外层引号：gsettings 收到的是参数数组而不是 shell 字符串，
	// 多包一层会被当成字符串值，as 类型解析直接失败。
	if got := gvariantList([]string{"a", "it's"}); got != `["a", "it's"]` {
		t.Fatalf("编码不对: %s", got)
	}
	if got := gvariantList(nil); got != "[]" {
		t.Fatalf("空列表应编成 []: %s", got)
	}
}

// TestGvariantListHandlesTrailingBackslash 锁住一个真实的解析失败。
//
// 单引号里 GVariant 只认 `\'` 一种转义，所以一项以反斜杠结尾时
// （`\\nas\share\` 这种共享路径），末尾的 `\` 会和收尾引号合成 `\'`
// ——一个转义引号。解析器于是认为字符串还没结束，整条 ignore-hosts 解析失败，
// 而代理的其余设置已经写下去了。
//
// 现在的编码用双引号 + 完整转义，`\` 统一写成 `\\`，没有这种歧义。
func TestGvariantListHandlesTrailingBackslash(t *testing.T) {
	// 输入的字面内容是 \\nas\share\（以单个反斜杠结尾）。
	got := gvariantList([]string{`\\nas\share\`})
	// 每个反斜杠都翻倍，末尾那个也不例外：编码后收尾必须是 `\\"]`，
	// 而不是 `\"]`——后者里 `\'…"` 会被解析成一个转义引号，
	// 解析器认为字符串没结束，整条 ignore-hosts 直接失败。
	if want := `["\\\\nas\\share\\"]`; got != want {
		t.Fatalf("编码不对:\n得到 %s\n期望 %s", got, want)
	}
}

// TestGvariantListEscapesControlCharacters 控制字符必须丢掉，
// 否则会把一条 GVariant 数组切成语法错误。
func TestGvariantListEscapesControlCharacters(t *testing.T) {
	got := gvariantList([]string{"a\x00b\nc\td"})
	if strings.ContainsAny(got, "\x00") {
		t.Fatalf("NUL 应被丢掉: %q", got)
	}
	if !strings.Contains(got, `\n`) || !strings.Contains(got, `\t`) {
		t.Fatalf("换行与制表符应转义成可见形式: %s", got)
	}
}

func TestMergeBypassDedupes(t *testing.T) {
	got := mergeBypass([]string{"localhost", " example.org "})
	if len(got) != len(defaultBypass)+1 {
		t.Fatalf("去重没做: %v", got)
	}
	if got[len(got)-1] != "example.org" {
		t.Fatalf("自定义项没保留: %v", got)
	}
}
