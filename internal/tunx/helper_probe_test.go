package tunx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 这一组验的是「动 root 之前先问一句对面是谁」（A43）。
//
// 用真的 fork/exec：预检的全部意义在于它**不起 sudo**，
// 所以替身必须是一个真的可执行文件，而不是一个接口——
// 拿假 Runner 测不出「有没有多叫一次 root」这件事。

// fakeHelper 在临时目录里落一个「像 wps_app 那样自报版本号」的可执行文件。
// 它同时把每次被调用的参数写进 log：读那份 log 才能断言
// 「预检只问了一次，真正的请求压根没发出去」。
func fakeHelper(t *testing.T, proto string) (path, logPath string) {
	t.Helper()
	dir := t.TempDir()
	// 权限位刻意不给 group/other 写：这是本进程自己造的测试夹具，
	// 但保留「谁能改这个文件」的形状，免得将来有人拿它当 root 侧夹具用。
	path = filepath.Join(dir, "wps_app")
	logPath = filepath.Join(dir, "calls.log")
	script := fmt.Sprintf(`#!/bin/sh
echo "$@" >> %s
echo "wps_app test-fixture (source deadbeef-dirty)"
echo "提权协议 %s"
`, logPath, proto)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path, logPath
}

func callsOf(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestParseHelperProto(t *testing.T) {
	n, err := parseHelperProto("wps_app 0.1.0 (source abc1234)\ngo1.26 linux/amd64\n提权协议 7\n")
	if err != nil || n != 7 {
		t.Fatalf("读不出来: n=%d err=%v", n, err)
	}
	// 老构建没有这一行：必须报「读不到」，而不是回一个 0 让上层以为是协议 0。
	if _, err := parseHelperProto("wps_app 0.1.0 (source abc1234)"); err == nil {
		t.Error("没有自报行却当成功读到了")
	} else if !strings.Contains(err.Error(), "比本程序老") {
		t.Errorf("读不到时的原因要说清是「老」: %v", err)
	}
}

func TestProbeHelperProtoForksTheFileItself(t *testing.T) {
	path, _ := fakeHelper(t, "9")
	n, err := ProbeHelperProto(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 9 {
		t.Errorf("读到 %d, want 9", n)
	}
	// 空路径不能当成「对面是协议 0」：那是没配 helper，不是版本不对。
	if _, err := ProbeHelperProto(context.Background(), ""); err == nil {
		t.Error("没配 helper 却返回了一个可用的版本号")
	}
}

// TestStartRefusesRootWhenHelperIsADifferentBuild 这条是 A43 的全部理由：
// 已知对面说的是另一版协议，就**一次 root 都不该叫**。
// 故障当天每一次点开关都会起一个 sudo、生一个 root 进程、发一份注定被拒的请求，
// 而这件事在动 root 之前就能问出来。
func TestStartRefusesRootWhenHelperIsADifferentBuild(t *testing.T) {
	other := fmt.Sprint(helperProtoVersion + 4)
	path, logPath := fakeHelper(t, other)
	tun := helperTUNT(t)
	// 走真实的 argv 分支：argv[0] 就是那个自报号的脚本（不是 sudo），
	// 所以「有没有多叫一次」可以直接从脚本自己记下的调用次数里读出来。
	tun.conf.Helper = []string{path, "--tun-helper"}
	tun.helper = HelperClient{Argv: []string{path}, Timeout: 3 * time.Second}
	if !tun.usesHelper() {
		t.Fatal("前置：这不该走直接开网卡的那条路")
	}

	err := tun.Start(context.Background())
	if err == nil {
		t.Fatalf("对面自报协议 %s，Start 却成功了", other)
	}
	if !strings.Contains(err.Error(), "没有去叫 root") {
		t.Errorf("错误要说清这一次根本没动 root: %v", err)
	}
	if !strings.Contains(err.Error(), "比面板新") {
		t.Errorf("错误要指出该动哪一边: %v", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("错误要指名那个文件: %v", err)
	}
	calls := callsOf(t, logPath)
	if len(calls) != 1 || calls[0] != "-version" {
		t.Errorf("那个文件被以 %v 调起 %d 次，want 1 次且只问 -version"+
			"（多出来的每一次都是一趟注定被拒的提权请求）", calls, len(calls))
	}
	if !tun.helperMismatchKnown() {
		t.Error("预检发现了错位却没把结论记下来，后续每一轮还会照叫 root")
	}
	if st := tun.Status(); !strings.Contains(st.LastError, "没有去叫 root") {
		t.Errorf("面板上那行必须带着处方: %q", st.LastError)
	}
}

// TestPreflightNeverBlocksOnItsOwnFailure 预检问不出来时必须放行：
// 把「读不到」当成「版本不对」，就等于用一次预检的失败取消掉一次本来能成功的启用。
func TestPreflightNeverBlocksOnItsOwnFailure(t *testing.T) {
	tun := helperTUNT(t)
	tun.conf.Helper = []string{"/nonexistent/wps_app-that-is-not-here", "--tun-helper"}
	tun.helper = HelperClient{Timeout: 2 * time.Second}
	if err := tun.preflightHelper(context.Background()); err != nil {
		t.Errorf("问不出对面是谁却拦下了启用: %v", err)
	}
	if tun.helperMismatchKnown() {
		t.Error("问不出版本不等于版本不对，不该记下这个结论")
	}

	// 进程内的 helper（单测那条路）压根没有「那个文件」这回事：
	// 即使配置里摆着一个能跑的路径，预检也不许去 exec 它。
	path, logPath := fakeHelper(t, fmt.Sprint(helperProtoVersion+1))
	tun2 := helperTUNT(t)
	tun2.conf.Helper = []string{path, "--tun-helper"}
	tun2.helper = HelperClient{
		Timeout: 2 * time.Second,
		Spawn:   func(context.Context, string) error { return nil },
	}
	if err := tun2.preflightHelper(context.Background()); err != nil {
		t.Errorf("进程内 helper 被预检拦了: %v", err)
	}
	if n := len(callsOf(t, logPath)); n != 0 {
		t.Errorf("进程内 helper 那条路不该 exec 配置文件里的路径，却起了 %d 次", n)
	}
}

// TestPreflightClearsTheSkewOnceTheFileMatches 文件被刷新的那一刻，
// 结论要当场作废——否则「已经知道对不上」会变成永久拉黑。
func TestPreflightClearsTheSkewOnceTheFileMatches(t *testing.T) {
	path, _ := fakeHelper(t, fmt.Sprint(helperProtoVersion))
	tun := helperTUNT(t)
	tun.conf.Helper = []string{path, "--tun-helper"}
	tun.helper = HelperClient{Timeout: 3 * time.Second}
	tun.helperMismatchAt.Store(time.Now().UnixMilli())
	if !tun.helperMismatchKnown() {
		t.Fatal("前置：没摆上不匹配结论")
	}
	if err := tun.preflightHelper(context.Background()); err != nil {
		t.Fatalf("对面明明和本次构建一致: %v", err)
	}
	if tun.helperMismatchKnown() {
		t.Error("对面自报了同一个协议，还留着「版本对不上」的结论")
	}
}
