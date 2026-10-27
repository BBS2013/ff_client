package logx

import (
	"os"
	"path/filepath"
	"strings"
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

	path := filepath.Join(t.TempDir(), "app.log")
	closer, err := SetFileOutput(path, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	Infof("写到文件也写到原输出")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(buf.String(), "写到文件也写到原输出") {
		t.Errorf("原输出没收到日志: %q", buf.String())
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "写到文件也写到原输出") {
		t.Errorf("文件没收到日志: %q", string(body))
	}

	// Close 之后必须恢复原输出，否则后续测试会继续往临时文件里写。
	Infof("Close 之后应回到原输出")
	if !strings.Contains(buf.String(), "Close 之后应回到原输出") {
		t.Errorf("Close 后输出没有恢复: %q", buf.String())
	}
}
