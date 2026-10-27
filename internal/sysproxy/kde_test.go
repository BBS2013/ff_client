package sysproxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHome 把家目录指到临时目录，并返回里面 kioslaverc 的路径。
//
// 用 t.Setenv 而不是给后端加一个"可注入家目录"的参数：后者是为了测试
// 才存在的生产代码路径，迟早会有人忘了它是干什么的。$HOME 本来就是
// os.UserHomeDir() 读的东西，改它等于在用真实机制测。
func fakeHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return filepath.Join(dir, ".config", "kioslaverc")
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 %s: %v", path, err)
	}
	return string(raw)
}

// TestKDEWritesProxySettings 写入的内容必须是 Plasma 认得的形状。
func TestKDEWritesProxySettings(t *testing.T) {
	path := fakeHome(t)
	if err := (kdeBackend{}).Apply(context.Background(), &rec{}, Config{
		Enable:    true,
		Backend:   BackendKDE,
		HTTPAddr:  "127.0.0.1:7892",
		SOCKSAddr: "127.0.0.1:7891",
	}); err != nil {
		t.Fatal(err)
	}
	body := readFile(t, path)
	for _, want := range []string{
		"[Proxy Settings]",
		"ProxyType=Manual",
		"httpProxy=http://127.0.0.1:7892",
		"httpsProxy=http://127.0.0.1:7892",
		"socksProxy=socks5://127.0.0.1:7891",
		"ProxyOnlyForLocal=false",
		"NoProxyFor=localhost,127.0.0.0/8",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("kioslaverc 里缺 %q:\n%s", want, body)
		}
	}
	// 值先摆好、ProxyType 最后提交：中间失败留下的半配置状态最麻烦。
	if strings.Index(body, "httpProxy=") > strings.Index(body, "ProxyType=Manual") {
		t.Errorf("ProxyType 必须写在值之后:\n%s", body)
	}
	// 不缩进：KConfig 认，但用户打开文件 diff 一眼看到满屏 tab 会以为被重排了。
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(ln, "\t") {
			t.Errorf("不该给 key 加 tab 缩进: %q", ln)
		}
	}
}

// TestKDELeavesOtherGroupsAlone 只动 [Proxy Settings]。
//
// kioslaverc 里还有用户的其它段（自定义 DNS、路径…），我们没资格替他们重排。
func TestKDELeavesOtherGroupsAlone(t *testing.T) {
	path := fakeHome(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := "[Environment]\nhttpProxy=http://old.example:3128\n\n[Proxy Settings]\nProxyType=Manual\nhttpProxy=http://keep.example:9\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (kdeBackend{}).Apply(context.Background(), &rec{}, Config{
		Enable:   true,
		Backend:  BackendKDE,
		HTTPAddr: "127.0.0.1:7892",
	}); err != nil {
		t.Fatal(err)
	}
	body := readFile(t, path)
	if !strings.Contains(body, "[Environment]") || !strings.Contains(body, "httpProxy=http://old.example:3128") {
		t.Errorf("把用户自己的段弄丢了:\n%s", body)
	}
	if strings.Contains(body, "keep.example") {
		t.Errorf("[Proxy Settings] 的旧内容没有被替换:\n%s", body)
	}
	if strings.Count(body, "[Proxy Settings]") != 1 {
		t.Errorf("[Proxy Settings] 出现了多次:\n%s", body)
	}
}

// TestKDEDisableLeavesNoStaleEndpoint 关闭后文件里不许再留着指向本客户端的地址。
//
// 一个 "ProxyType=None 但 httpProxy=127.0.0.1:7892" 的 kioslaverc 看着无害，
// 可用户几个月后手工打开这个文件，会看到一个"有效"的端点而那时早已没人监听。
// 真正"还原成改动前的样子"由记账负责。
func TestKDEDisableLeavesNoStaleEndpoint(t *testing.T) {
	path := fakeHome(t)
	if err := (kdeBackend{}).Apply(context.Background(), &rec{}, Config{
		Enable: true, Backend: BackendKDE, HTTPAddr: "127.0.0.1:7892",
	}); err != nil {
		t.Fatal(err)
	}
	if err := (kdeBackend{}).Apply(context.Background(), &rec{}, Config{Backend: BackendKDE}); err != nil {
		t.Fatal(err)
	}
	body := readFile(t, path)
	if !strings.Contains(body, "ProxyType=None") {
		t.Errorf("没有关掉:\n%s", body)
	}
	if strings.Contains(body, "127.0.0.1:7892") {
		t.Errorf("关闭后仍留着指向本客户端的地址:\n%s", body)
	}
	if strings.Contains(body, "ProxyType=Manual") {
		t.Errorf("ProxyType 没能从 Manual 翻过来:\n%s", body)
	}
}

// TestKDERestoreBringsBackExactOriginalText 还原要贴回**原文**。
//
// 解析再拼回去会丢掉段里的注释与顺序，而用户对"我原来的设置长什么样"
// 的预期是那一份文件，不是我们对它的理解。
func TestKDERestoreBringsBackExactOriginalText(t *testing.T) {
	path := fakeHome(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := "[Environment]\nhttpProxy=http://old.example:3128\n\n[Proxy Settings]\n# 我自己加的注释\nProxyType=Manual\nhttpProxy=http://keep.example:9\n\n[Other]\nfoo=bar\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}

	b := kdeBackend{}
	snap, err := CaptureKDE()
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Existed {
		t.Fatal("快照说文件不存在")
	}
	if !strings.Contains(snap.Group, "我自己加的注释") {
		t.Errorf("快照没带上段里的注释: %q", snap.Group)
	}
	if err := b.Apply(context.Background(), &rec{}, Config{Enable: true, Backend: BackendKDE, HTTPAddr: "127.0.0.1:7892"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(readFile(t, path), "我自己加的注释") {
		t.Fatal("启用后旧段应当被替换掉")
	}
	if err := RestoreKDE(snap); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != original {
		t.Errorf("还原后与原文不一致:\n得到:\n%q\n期望:\n%q", got, original)
	}
}

// TestKDERestoreRemovesFileThatDidNotExist 动手前文件不存在的话，
// 还原就是删掉它，而不是留一个空壳。
func TestKDERestoreRemovesFileThatDidNotExist(t *testing.T) {
	path := fakeHome(t)
	snap, err := CaptureKDE()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Existed {
		t.Fatal("还不该有文件")
	}
	if err := (kdeBackend{}).Apply(context.Background(), &rec{}, Config{Enable: true, Backend: BackendKDE, HTTPAddr: "127.0.0.1:7892"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("启用后应当有文件: %v", err)
	}
	if err := RestoreKDE(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("还原后文件应当被删掉，实际 err=%v", err)
	}
}

func TestKDEReadReportsBackendAndLimits(t *testing.T) {
	path := fakeHome(t)
	if err := (kdeBackend{}).Apply(context.Background(), &rec{}, Config{
		Enable: true, Backend: BackendKDE, HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891",
	}); err != nil {
		t.Fatal(err)
	}
	st, err := (kdeBackend{}).Read(context.Background(), &rec{})
	if err != nil {
		t.Fatal(err)
	}
	if !st.Supported || !st.Enabled || st.Mode != "Manual" {
		t.Fatalf("读数不对: %+v", st)
	}
	if st.Backend != BackendKDE {
		t.Errorf("backend = %q", st.Backend)
	}
	if st.HTTP != "127.0.0.1:7892" || st.SOCKS != "127.0.0.1:7891" {
		t.Errorf("地址没去掉 scheme 或拼错: %+v", st)
	}
	if st.Path != path {
		t.Errorf("没告诉用户文件在哪: %q 期望 %q", st.Path, path)
	}
	// 覆盖不到的地方必须写在状态里，界面上照实显示而不是显示成"已开启"。
	if st.Note == "" {
		t.Error("应当说明 Plasma 的生效时机，否则界面上的「已开启」是误导")
	}
}

// TestKDEParseGroupIgnoresCommentsAndNestedNames 段名解析要认得
// KConfig 的 [Foo][Bar] 写法与注释行，否则会改错段。
func TestKDEParseGroupIgnoresCommentsAndNestedNames(t *testing.T) {
	body := "[Environment]\n\t# 注释里的 [Proxy Settings] 不算数\n\tfoo=bar\n\n[Proxy Settings][Extra]\n\tProxyType=Manual\n"
	kv := parseKDEGroup(body, "Proxy Settings")
	if kv["ProxyType"] != "Manual" {
		t.Errorf("认不出嵌套段名: %v", kv)
	}
	if _, ok := kv["foo"]; ok {
		t.Errorf("把别的段读进来了: %v", kv)
	}
}

// TestKDENewGroupKeepsBlankSeparator 我们写进去的段要和记账里那段原文形状一致。
//
// 段后少一行空行的话，段会直接贴上下一个段头；而还原走的是记账里带空行的原文。
// 于是「开 → 关 → 再开」之后文件跟第一次开之前长得不一样，
// 用户 diff 一看像是凭空动过别的地方——实际上只动了代理那几行。
func TestKDENewGroupKeepsBlankSeparator(t *testing.T) {
	path := fakeHome(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := "[Proxy Settings]\nProxyType=Manual\nhttpProxy=http://keep.example:9\n\n[KDE General]\nSystemTray=false\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Enable: true, Backend: BackendKDE, HTTPAddr: "127.0.0.1:7892"}
	sp := filepath.Join(t.TempDir(), "config.yaml")

	// 一律走 Enable/Disable：直调 Apply 不记账，后面的「还原」就没有原状可依。
	if err := Enable(context.Background(), &rec{}, sp, cfg); err != nil {
		t.Fatal(err)
	}
	body := readFile(t, path)
	if !strings.Contains(body, "\n\n[KDE General]") {
		t.Errorf("段与下一个段头之间应有空行:\n%q", body)
	}
	if err := Disable(context.Background(), &rec{}, sp, BackendKDE); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != original {
		t.Errorf("还原后与原文不一致:\n得到 %q\n期望 %q", got, original)
	}
	// 再开一次，应当回到同一个形状：写进去的段和记账里那段原文形状一致。
	if err := Enable(context.Background(), &rec{}, sp, cfg); err != nil {
		t.Fatal(err)
	}
	again := readFile(t, path)
	if again != body {
		t.Errorf("再开一次的形状与第一次不一致:\n得到 %q\n期望 %q", again, body)
	}
}

// TestKDEEnableOverOwnValuesDisables 同一条 bug 的 KDE 版本：
// kioslaverc 里那段本来就等于我们要写的内容时，还原快照等于没关。
func TestKDEEnableOverOwnValuesDisables(t *testing.T) {
	path := fakeHome(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Enable: true, Backend: BackendKDE,
		HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891",
	}
	// 先按我们要写的形状铺一份文件，模拟「桌面上已经是我们的了但记账丢了」。
	if err := (kdeBackend{}).Apply(context.Background(), &rec{}, cfg); err != nil {
		t.Fatalf("铺垫: %v", err)
	}
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))
	if err := Enable(context.Background(), &rec{}, sp, cfg); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if st := loadSaved(t, sp); !st.AlreadyOurs {
		t.Fatal("kioslaverc 里那段与要写的完全一致时应记为 AlreadyOurs")
	}
	if err := Disable(context.Background(), &rec{}, sp, BackendKDE); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	got := readFile(t, path)
	if strings.Contains(got, "127.0.0.1:7892") {
		t.Errorf("关掉后文件里不该还留着指向我们的端点:\n%s", got)
	}
	if !strings.Contains(got, "ProxyType=None") {
		t.Errorf("关掉应收成 ProxyType=None:\n%s", got)
	}
}

// TestKDEEnableOverForeignProxyKeepsSnapshot 用户自己的代理必须照原样保住。
func TestKDEEnableOverForeignProxyKeepsSnapshot(t *testing.T) {
	path := fakeHome(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	original := "[Proxy Settings]\nProxyType=Manual\nhttpProxy=http://10.0.0.9:8118\n\n[KDE General]\nSystemTray=false\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))
	if err := Enable(context.Background(), &rec{}, sp, Config{
		Enable: true, Backend: BackendKDE,
		HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891",
	}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if st := loadSaved(t, sp); st.AlreadyOurs {
		t.Fatal("指向 10.0.0.9:8118 不是我们的值，不该记成 AlreadyOurs")
	}
	if err := Disable(context.Background(), &rec{}, sp, BackendKDE); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if got := readFile(t, path); got != original {
		t.Errorf("没原样还原:\n得到 %q\n期望 %q", got, original)
	}
}
