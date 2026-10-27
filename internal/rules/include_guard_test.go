package rules

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// writeRules 在 dir 里写一份规则文件并返回路径。
// writeRulesFileIn 在指定目录里写一份任意名字的规则文件。
func writeRulesFileIn(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "rules-"+strconv.Itoa(len(dir)+len(body))+".txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRulesIn(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestIncludeRejectsAbsolutePath 绝对路径一律不许。
//
// 触发条件不是假设：规则文件里有一条来源是远端订阅的缓存，内容不归本机用户管。
// 修之前实测 `#include /home/<user>/.ssh/id_rsa` 会把那文件的第一行
// 原样拼进错误信息（rule "…" needs at least TYPE and POLICY），
// 而错误会进日志、会显示在面板上——"读走任意文件的一行"就此成立。
func TestIncludeRejectsAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "id_rsa")
	if err := os.WriteFile(secret, []byte("-----BEGIN OPENSSH PRIVATE KEY-bbbb33xxQQ\nrest\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	top := writeRulesIn(t, dir, "#include "+secret+"\nFINAL,PROXY\n")

	_, err := Load(top, nil, nil)
	if err == nil {
		t.Fatal("绝对路径的 #include 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "绝对路径") {
		t.Errorf("错误要说清是绝对路径的问题: %v", err)
	}
	if strings.Contains(err.Error(), "PRIVATE KEY") || strings.Contains(err.Error(), "bbbb33xxQQ") {
		t.Errorf("被 include 的文件内容一个字都不许带进错误信息: %v", err)
	}
}

// TestIncludeRejectsParentEscape 相对路径也一样要管：../ 出得去同一个目录。
func TestIncludeRejectsParentEscape(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "..-outside-secret.txt")
	if err := os.WriteFile(secret, []byte("SECRET-LINE-9ff2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 从子目录里的文件出发，../../ 才够出去；先造一个合法的子目录文件。
	sub := filepath.Join(root, "providers")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(sub, "cn.txt")
	if err := os.WriteFile(nested, []byte("#include ../../SECRET-NOT-HERE-8ff3\nFINAL,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	top := writeRulesIn(t, root, "#include ./providers/cn.txt\nFINAL,PROXY\n")

	_, err := Load(top, nil, nil)
	if err == nil {
		t.Fatal("../ 逃逸的 #include 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "之外") {
		t.Errorf("错误要说清是指到目录外: %v", err)
	}
	// 越界指令本身是订阅自己写的内容，回显它无害；要盯住的是被读的那个文件的内容。
	if strings.Contains(err.Error(), "SECRET-LINE-9ff2") {
		t.Errorf("目录外文件的内容被带进了错误: %v", err)
	}
}

// TestOptionalIncludeStillRejectsEscape 问号版只豁免"文件不存在"，不豁免越界。
// 否则远端订阅可以安静地试探边界，本机一点痕迹都不留。
func TestOptionalIncludeStillRejectsEscape(t *testing.T) {
	dir := t.TempDir()
	top := writeRulesIn(t, dir, "#include? /etc/passwd\nFINAL,PROXY\n")
	_, err := Load(top, nil, nil)
	if err == nil {
		t.Fatal("#include? 不许把越界咽下去")
	}
	if !strings.Contains(err.Error(), "绝对路径") {
		t.Errorf("越界与不存在是两回事，错误必须说是越界: %v", err)
	}
	// 反过来：真的不存在时仍然只是跳过。
	top2 := writeRulesIn(t, dir, "#include? ./nope.txt\nFINAL,PROXY\nDOMAIN-SUFFIX,a.com,PROXY\n")
	e2, err := Load(top2, nil, nil)
	if err != nil {
		t.Fatalf("可选 include 缺失时不该失败: %v", err)
	}
	if len(e2.Skipped()) != 1 {
		t.Errorf("缺失的可选 include 要留痕，实得 %v", e2.Skipped())
	}
}

// TestIncludeStaysUsableInsideRoot 收紧之后，正常写法必须照旧好用：
// 同目录、子目录、以及"绕一下又回到目录内"的相对路径。
func TestIncludeStaysUsableInsideRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "providers"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"providers/cn.txt":        "DOMAIN-SUFFIX,cn.example,PROXY\n",
		"providers/gfw.txt":       "DOMAIN-SUFFIX,gfw.example,PROXY\n",
		"providers/self/../a.txt": "DOMAIN-SUFFIX,a.example,PROXY\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	top := writeRulesIn(t, dir, strings.Join([]string{
		"#include ./user-rules.txt",
		"#include providers/cn.txt",
		"#include ./providers/gfw.txt",
		"#include ./providers/self/../a.txt",
		"FINAL,PROXY",
	}, "\n")+"\n")
	if err := os.WriteFile(filepath.Join(dir, "user-rules.txt"), []byte("DOMAIN-SUFFIX,me.example,DIRECT\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := Load(top, nil, nil)
	if err != nil {
		t.Fatalf("目录内的正常 include 全被挡了: %v", err)
	}
	dom, _ := e.Stats()
	if dom != 4 {
		t.Errorf("四条域名规则都该进来，实得 %d", dom)
	}
	if len(e.Skipped()) != 0 {
		t.Errorf("没有该跳过的项，实得 %v", e.Skipped())
	}
}

func TestIncludeRejectsSymlinkEscape(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secrets.txt"), []byte("TOP-SECRET-77aa\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("这台机器建不了软链: %v", err)
	}
	top := writeRulesIn(t, dir, "#include ./link/secrets.txt\nFINAL,PROXY\n")

	_, err := Load(top, nil, nil)
	if err == nil {
		t.Fatal("经软链逃出规则目录必须被拒绝")
	}
	if !strings.Contains(err.Error(), "软链") {
		t.Errorf("错误要说清是软链带出去的: %v", err)
	}
	if strings.Contains(err.Error(), "TOP-SECRET") {
		t.Errorf("内容还是漏了: %v", err)
	}
}

// TestBriefCapsLongLine 一条坏规则不该把日志与界面塞满。
func TestBriefCapsLongLine(t *testing.T) {
	// 只有一个字段的那一行会走 "rule %q needs at least TYPE and POLICY"，
	// 整行原样进错误信息——这正是要截断的那条路。
	long := strings.Repeat("x", 5000)
	_, _, err := parseLine(long, 1)
	if err == nil {
		t.Fatal("未知类型应当报错")
	}
	if len(err.Error()) > 400 {
		t.Errorf("错误信息没被截住，长度 %d:\n%.200s", len(err.Error()), err.Error())
	}
	if !strings.Contains(err.Error(), "本行共") {
		t.Errorf("截断要说明原长，免得用户照着半截去改: %v", err)
	}
}

func TestBriefKeepsMultibyteIntact(t *testing.T) {
	// 截断点落在一个多字节字符中间，会在错误信息里再制造一次乱码。
	line := strings.Repeat("拦截", 300)
	_, _, err := parseLine(line, 1)
	if err == nil {
		t.Fatal("应当报错")
	}
	if !utf8.ValidString(err.Error()) {
		t.Errorf("错误信息被切在字符中间: %q", err.Error())
	}
}

func TestBriefShortPassesThrough(t *testing.T) {
	if got := brief("DOMAIN,a.com,PROXY"); got != "DOMAIN,a.com,PROXY" {
		t.Errorf("短行不该被改动: %q", got)
	}
	// 边界按"字符数"算（%q 会把非 ASCII 展开成 6 字节，按字节截会让中文规则
	// 的错误比英文长十倍）。正好 48 个字符的不加尾巴，多一个才截。
	exact := strings.Repeat("a", 48)
	if brief(exact) != exact {
		t.Errorf("48 个字符不该被截: %q", brief(exact))
	}
	if got := brief(exact + "b"); !strings.Contains(got, "本行共 49 字节") {
		t.Errorf("49 字节应当被截并标注原长: %q", got)
	}
	cjk := strings.Repeat("拦", 48)
	if brief(cjk) != cjk {
		t.Errorf("48 个中文字符（144 字节）不该被截: %q", brief(cjk))
	}
	if got := brief(cjk + "截"); !strings.Contains(got, "本行共 147 字节") {
		t.Errorf("按字符截断后仍要报出真实字节数: %q", got)
	}
}

// TestIncludeDepthStillBounded 自环的 #include 靠层数上限挡住；
// 越界检查不能替它干活（同目录里的自环是完全"合法"的路径）。
func TestIncludeDepthStillBounded(t *testing.T) {
	dir := t.TempDir()
	top := writeRulesIn(t, dir, "#include ./rules.txt\nFINAL,PROXY\n")
	_, err := Load(top, nil, nil)
	if err == nil {
		t.Fatal("自环应当被层数上限拦下")
	}
	if !strings.Contains(err.Error(), "nesting too deep") {
		t.Errorf("没看到层数上限起作用: %v", err)
	}
}

// TestIncludeWorksThroughSymlinkedRulesDir 规则目录带软链时，include 必须照旧好用。
//
// 这是一次真实回归的守门用例：root 那一边解了软链、joined 这一边没解，
// 两边比不出东西，于是**每一条** #include 都被判"越界"，代理直接起不来。
// 修法是比较双方都用绝对但未解析的形式；这条用例锁住它。
func TestIncludeWorksThroughSymlinkedRulesDir(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "user-rules.txt"),
		[]byte("DOMAIN-SUFFIX,me.example,DIRECT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	top := "#include ./user-rules.txt\nFINAL,PROXY\n"
	if err := os.WriteFile(filepath.Join(real, "rules.txt"), []byte(top), 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, linkDir); err != nil {
		t.Skipf("这台机器建不了软链: %v", err)
	}
	eng, err := Load(filepath.Join(linkDir, "rules.txt"), nil, nil)
	if err != nil {
		t.Fatalf("经过软链的规则目录加载失败: %v", err)
	}
	if dom, _ := eng.Stats(); dom != 1 {
		t.Errorf("被 include 的那条没进来: 域名 %d 条", dom)
	}
	// 同一个目录里，越界仍然要被拒——修误伤不能把门一起拆了。
	bad := filepath.Join(linkDir, "rules-bad.txt")
	if err := os.WriteFile(bad, []byte("#include /etc/passwd\nFINAL,PROXY\nDOMAIN-SUFFIX,x.example,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad, nil, nil); err == nil || !strings.Contains(err.Error(), "绝对路径") {
		t.Errorf("软链目录里的绝对路径 include 仍应被拒: %v", err)
	}
}

// TestOptionalIncludeSurvivesUnreadablePaths 可选 include 遇到"打不开但不在"的各种
// errno（ENOTDIR / ENAMETOOLONG / 超长垃圾行）必须只是跳过。
// 只认 ENOENT 的话，远端订阅里一行 `#include? file/x` 就能让整个引擎拒绝启动。
func TestOptionalIncludeSurvivesUnreadablePaths(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "afile"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, include string }{
		{"把文件当目录", "#include? afile/x.txt"},
		{"名字过长", "#include? " + strings.Repeat("y", 5000)},
		{"路径段过长", "#include? " + strings.Repeat("z", 300) + "/" + strings.Repeat("w", 300)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			top := writeRulesFileIn(t, dir, c.include+"\nFINAL,PROXY\nDOMAIN-SUFFIX,a.example,PROXY\n")
			eng, err := Load(top, nil, nil)
			if err != nil {
				t.Fatalf("可选 include 的一行垃圾不该打死引擎: %v", err)
			}
			if dom, _ := eng.Stats(); dom != 1 {
				t.Errorf("其余规则该照常生效, 实得 %d", dom)
			}
			if len(eng.Skipped()) != 1 {
				t.Errorf("要留下被跳过的痕迹: %v", eng.Skipped())
			}
		})
	}
}

// TestIncludePathTooLongIsRejectedQuietly 超长路径要拒，但不能把那段垃圾原样带进错误。
func TestIncludePathTooLongIsRejectedQuietly(t *testing.T) {
	dir := t.TempDir()
	junk := strings.Repeat("q", 2000)
	top := writeRulesFileIn(t, dir, "#include "+junk+"\nFINAL,PROXY\n")
	_, err := Load(top, nil, nil)
	if err == nil {
		t.Fatal("超长路径应当被拒")
	}
	if strings.Contains(err.Error(), junk) {
		t.Errorf("错误里带了那 2000 字节垃圾:\n%.200v", err)
	}
	if len(err.Error()) > 400 {
		t.Errorf("错误信息本身被撑大了: %d 字节", len(err.Error()))
	}
}

// TestSourcesListsEveryOpenedFile 热重载的监视器只能盯这份清单：
// 只看 rules_file 的 mtime，会漏掉用户直接编辑 user-rules.txt 或订阅缓存那种改动。
func TestSourcesListsEveryOpenedFile(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"user-rules.txt":    "DOMAIN-SUFFIX,me.example,DIRECT\n",
		"providers/cn.txt":  "DOMAIN-SUFFIX,cn.example,PROXY\n",
		"providers/gfw.txt": "DOMAIN-SUFFIX,gfw.example,PROXY\n",
	} {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	top := writeRulesIn(t, dir, "#include ./user-rules.txt\n#include providers/cn.txt\n#include? ./gone.txt\nFINAL,PROXY\n")
	e, err := Load(top, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(e.Sources(), "\n")
	for _, want := range []string{top, "user-rules.txt", filepath.Join(dir, "providers", "cn.txt")} {
		if !strings.Contains(got, want) {
			t.Errorf("Sources 里缺 %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "gone.txt") {
		t.Errorf("没打开的文件不该出现在清单里:\n%s", got)
	}
	// 返回的必须是副本：调用方存着慢慢比，不能跟着下一次 Reload 一起变。
	e.Sources()[0] = "改了也不该影响引擎"
	if e.Sources()[0] == "改了也不该影响引擎" {
		t.Error("Sources 返回了内部切片")
	}
}

// TestBriefPathKeepsRealPathsWhole 挡住"为了截断把有用的路径截没"这一侧。
//
// 真实路径上百字节是常态（临时目录、深层 assets、中文目录名）。
// 错误信息里那句"是哪个文件打不开"就是靠路径本身说清楚的，
// 截到 48 个字符等于把诊断价值一起截掉了——所以合法可打印的一律原样过。
func TestBriefPathKeepsRealPathsWhole(t *testing.T) {
	for _, p := range []string{
		"/tmp/TestIncludeRequiredMissingIsError3097986747/001/rules.txt",
		strings.Repeat("深", 100) + "/rules.txt", // 合法中文长路径：不是要防的那一类
		filepath.Join(os.TempDir(), "a", "b", "c.txt"),
	} {
		if got := briefPath(p); got != p {
			t.Errorf("合法路径被改了:\n in %q\nout %q", p, got)
		}
	}
}

// TestBriefPathCapsEscapedPaths 是这一条真正防的事故：
// 订阅里一行 512 字节的非法 UTF-8 路径，转义后每个字节摊成四个字符，
// 一条 #include 就能顶出 2KB 的错误信息，而它会进日志、也会原样显示在面板上。
func TestBriefPathCapsEscapedPaths(t *testing.T) {
	dir := t.TempDir()
	junk := strings.Repeat("\xa3", 500) // 单看是非法 UTF-8，正是订阅能塞进来的东西
	top := writeRulesIn(t, dir, "#include "+junk+"\nFINAL,PROXY\n")
	_, err := Load(top, nil, nil)
	if err == nil {
		t.Fatal("坏路径应当报错")
	}
	msg := err.Error()
	if len(msg) > 1024 {
		t.Errorf("错误信息长度 %d，没被截住", len(msg))
	}
	if !utf8.ValidString(msg) {
		t.Errorf("错误信息不是合法 UTF-8: %q", msg)
	}
	for i := 0; i < len(msg); i++ {
		if c := msg[i]; c < 0x20 && c != '\n' || c == 0x7f {
			t.Fatalf("错误信息里带了控制字符 0x%02x", c)
		}
	}
	// 截断不等于把话说没：还得看得出是 #include 这一行出的事。
	if !strings.Contains(msg, "#include") && !strings.Contains(msg, filepath.Base(top)) {
		t.Errorf("错误信息没交代现场: %.200s", msg)
	}
}
