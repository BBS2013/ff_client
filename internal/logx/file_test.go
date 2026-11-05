package logx

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRotatingFileRotatesAndKeepsBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w, err := newRotatingFile(path, 32, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()

	for _, s := range []string{strings.Repeat("a", 20), strings.Repeat("b", 20), strings.Repeat("c", 20)} {
		if _, err := w.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}

	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(filepath.Dir(path), name))
		if err != nil {
			t.Fatalf("读 %s: %v", name, err)
		}
		return string(b)
	}
	if got := read("app.log"); got != strings.Repeat("c", 20) {
		t.Errorf("当前文件 = %q", got)
	}
	if got := read("app.log.1"); got != strings.Repeat("b", 20) {
		t.Errorf("第一份备份 = %q", got)
	}
	if got := read("app.log.2"); got != strings.Repeat("a", 20) {
		t.Errorf("第二份备份 = %q", got)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("只该保留 2 份备份，却出现了 .3")
	}
}

func TestRotatingFileIs0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	w, err := newRotatingFile(path, 1024, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("secret domain\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != 0o600 {
		t.Errorf("日志权限 = %o，期望 600", got)
	}
}

func TestSetFileOutputKeepsOldWriterAndRestores(t *testing.T) {
	buf, restore := capture(t)
	defer restore()
	setLevel(t, LevelDebug)

	// capture() 换掉的是一个 bytes.Buffer——**不是终端**。按现在的语义，
	// 那时日志只写文件，不再抄一份到"非终端的原输出"（理由见 SetFileOutput
	// 的注释：那个副本没有轮转、没有 0600，内容是访问过哪些域名）。
	// 所以这条用例先用一个假终端把它要守的"人在终端里能看到"演出来。
	fakeTTY := &ttyProbe{}
	prevTTY := isTerminalFn
	isTerminalFn = func(w io.Writer) bool {
		f, ok := w.(*ttyProbe)
		return ok && f == fakeTTY
	}
	t.Cleanup(func() { isTerminalFn = prevTTY })
	mu.Lock()
	output = fakeTTY
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		output = buf
		mu.Unlock()
	})

	path := filepath.Join(t.TempDir(), "app.log")
	closer, err := SetFileOutput(path, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	Infof("写到文件也写到原输出")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(fakeTTY.String(), "写到文件也写到原输出") {
		t.Errorf("终端里没看到日志: %q", fakeTTY.String())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "写到文件也写到原输出") {
		t.Errorf("文件没收到日志: %q", string(body))
	}

	// Close 之后必须恢复原输出，否则后续测试会继续往临时文件里写。
	// 这里的"原输出"是上面装进去的假终端（capture 的 buf 被它替掉了）。
	Infof("Close 之后应回到原输出")
	if !strings.Contains(fakeTTY.String(), "Close 之后应回到原输出") {
		t.Errorf("Close 后输出没有恢复: %q", fakeTTY.String())
	}
}

// ttyProbe 是一个"看起来像终端"的 writer。
//
// isTerminal 的判据是 *os.File 且是字符设备，而 bytes.Buffer 两条都不满足。
// 要在单测里演"人在终端里看"，就得有一个满足判据、又能在内存里检查的东西。
// 这里用 /dev/ptmx 那种真设备太重；改成让 isTerminal 可注入——
// 见下面那行的 seam。
type ttyProbe struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (p *ttyProbe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.Write(b)
}

func (p *ttyProbe) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}
