package procid

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestExePathOnSelfRealProcess 用真进程验一次读法：
// 自己 /proc/self/exe 去掉尾巴后必须等于 Self()，否则整条身份判定都建在错的地基上。
func TestExePathOnSelfRealProcess(t *testing.T) {
	got, err := ExePath(os.Getpid(), os.Readlink)
	if err != nil {
		t.Fatalf("读 /proc/%d/exe: %v", os.Getpid(), err)
	}
	if !Same(got, Self()) {
		t.Errorf("exe 链接与本程序路径不一致:\n exe  = %q\n self = %q", got, Self())
	}
	if Self() == "" || !filepath.IsAbs(Self()) {
		t.Errorf("Self() 应当是绝对路径, 实得 %q", Self())
	}
}

// TestExePathIgnoresAnotherBinary 真起一个别的程序：它的 exe 路径绝不该被判成同身份。
// 这就是 PID 被回收后的现场。
func TestExePathIgnoresAnotherBinary(t *testing.T) {
	cmd := exec.Command("sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("起不了 sleep，这台机器上没法验身份判定: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		// 必须收尸：留着僵尸的话它的 PID 仍算「存在」，会污染后面的判定。
		_ = cmd.Wait()
	})
	link, err := ExePath(pid, os.Readlink)
	if err != nil {
		t.Fatalf("读不到 sleep 的 exe，身份判定这条路在这台机器上根本走不通: %v", err)
	}
	if Same(link, Self()) {
		t.Errorf("%q 和 %q 被算成了同一个程序", link, Self())
	}
	if !strings.Contains(link, "sleep") {
		t.Errorf("读到的 exe 不像 sleep: %q", link)
	}
}

func TestExePathStripsDeletedSuffix(t *testing.T) {
	// 重编译把磁盘上的二进制换掉了，内核就在旧链接后面加 " (deleted)"。
	stub := func(name string) (string, error) {
		if strings.HasSuffix(name, "/exe") {
			return "/home/chery/wps_app/wps_app-gui (deleted)", nil
		}
		return "", errors.New("unexpected read")
	}
	got, err := ExePath(4242, stub)
	if err != nil {
		t.Fatalf("ExePath: %v", err)
	}
	if !Same(got, "/home/chery/wps_app/wps_app-gui") {
		t.Errorf("没去掉尾巴: %q", got)
	}
}

func TestExePathPropagatesReadError(t *testing.T) {
	// 权限不足（进程不归我们）必须原样报出来，调用方要靠它决定「判不出身份」。
	want := errors.New("permission denied")
	if _, err := ExePath(1, func(string) (string, error) { return "", want }); !errors.Is(err, want) {
		t.Errorf("ExePath 吞掉了 readlink 的错误: %v", err)
	}
}

func TestCommTrimmed(t *testing.T) {
	raw := func(string) ([]byte, error) { return []byte("wps_app-gui\n"), nil }
	got, err := Comm(7, raw)
	if err != nil || got != "wps_app-gui" {
		t.Errorf("Comm = %q, err=%v; 期望去掉结尾换行", got, err)
	}
	if _, err := Comm(7, func(string) ([]byte, error) { return nil, os.ErrNotExist }); err == nil {
		t.Error("读不到 comm 时应报错")
	}
}

func TestSameTreatsEmptyAsUnknown(t *testing.T) {
	if Same("", "") {
		t.Error("两边都读不到时不能算「相同」——那会被当成确认了身份")
	}
	if Same("/a/b", "") {
		t.Error("一边为空不能算相同")
	}
	if !Same("/a/./b", "/a/b") {
		t.Error("同一路径的两种写法应当算相同")
	}
}

func TestNameMatches(t *testing.T) {
	cases := []struct {
		comm, exe string
		want      bool
		why       string
	}{
		{"wps_app-gui", "/x/wps_app-gui", true, "同名"},
		{"firefox", "/x/wps_app-gui", false, "PID 被回收给了别的程序"},
		{"", "/x/wps_app-gui", false, "comm 读不到时不许凭 basename 猜"},
		{"wps_app-gui", "", false, "本程序路径读不到时不许猜"},
		// comm 被内核截到 15 字节，只有截断才放宽成前缀。
		{"wps_app-panel-l", "/x/wps_app-panel-linux", true, "截断后的 comm 要按前缀认"},
		{"w", "/x/wps_app-gui", false, "没截断的短名字不许按前缀乱认"},
	}
	for _, c := range cases {
		if got := NameMatches(c.comm, c.exe); got != c.want {
			t.Errorf("NameMatches(%q, %q) = %v, 期望 %v（%s）", c.comm, c.exe, got, c.want, c.why)
		}
	}
}

// TestCommMaxIsKernelTruncationLength 前缀放宽只靠「长度等于 15」这一个事实。
// 内核常量若变了，这里必须响，而不是让 NameMatches 悄悄放宽成任意前缀。
func TestCommMaxIsKernelTruncationLength(t *testing.T) {
	if commMax != 15 {
		t.Fatalf("commMax = %d, 期望 15（TASK_COMM_LEN-1）", commMax)
	}
	// 15 字节本身必须能命中；更长（内核不会给出）或更短（没截断）都不许走前缀分支。
	if !NameMatches(strings.Repeat("a", 15), "/x/"+strings.Repeat("a", 16)) {
		t.Error("长度为 15 的截断 comm 应能按前缀命中")
	}
	if NameMatches(strings.Repeat("a", 16), "/x/"+strings.Repeat("a", 15)+"b") {
		t.Error("比 15 长的 comm 不该走前缀分支（内核不会给这么长）")
	}
}

// TestStateReadsZombie 僵尸这条判断依赖 stat 第二个字段可以含空格与括号，
// 所以解析必须从最后一个 ')' 之后取，而不是按第几"列"数。
func TestStateReadsZombie(t *testing.T) {
	cases := []struct {
		body string
		want byte
	}{
		{"829217 (wps_app-gui) S 1 829217 0 0 -1 4194304 100 0\n", 'S'},
		{"12 (sleep) Z 1 12 0 0 -1 4202496 100 0\n", 'Z'},
		{"42 (weird (name)) R 1 42\n", 'R'}, // comm 里带括号
		{"42 (x) T 1\n", 'T'},
	}
	for _, c := range cases {
		got, err := State(42, func(string) ([]byte, error) { return []byte(c.body), nil })
		if err != nil || got != c.want {
			t.Errorf("State(%q) = %q, %v; 期望 %q", c.body, got, err, c.want)
		}
	}
	if _, err := State(1, func(string) ([]byte, error) { return []byte("garbage"), nil }); err == nil {
		t.Error("读不懂的 stat 必须报错，不能猜一个状态")
	}
}
