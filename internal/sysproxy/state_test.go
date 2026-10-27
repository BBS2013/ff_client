package sysproxy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"wps_app/internal/procid"
)

// manualRec 是一台「原本就开着 manual 代理」的桌面的读数。
func manualRec() *rec {
	return &rec{gets: map[string]string{
		"get org.gnome.system.proxy mode":         "'manual'",
		"get org.gnome.system.proxy.http host":    "'10.0.0.9'",
		"get org.gnome.system.proxy.http port":    "8118",
		"get org.gnome.system.proxy.https host":   "'10.0.0.9'",
		"get org.gnome.system.proxy.https port":   "8118",
		"get org.gnome.system.proxy.socks host":   "'10.0.0.9'",
		"get org.gnome.system.proxy.socks port":   "1080",
		"get org.gnome.system.proxy ignore-hosts": "['corp.example', 'localhost']",
	}}
}

// TestEnableRecordsPreviousState 启用前必须先记账。
//
// 不记账的话，一旦进程异常消失，桌面会永远停在 mode=manual 指向一个
// 已经不存在的端口：整机断网，且只报一句「代理连接被拒绝」。
func TestEnableRecordsPreviousState(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	r := manualRec()

	if err := Enable(context.Background(), r, sp, Config{
		Enable:    true,
		Backend:   BackendGNOME,
		HTTPAddr:  "127.0.0.1:7892",
		SOCKSAddr: "127.0.0.1:7891",
	}); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	if _, err := os.Stat(sp); err != nil {
		t.Fatalf("启用系统代理后应当留下记账文件: %v", err)
	}
	st := loadSaved(t, sp)
	if st.Mode != "manual" {
		t.Errorf("记账里的 mode = %q, 期望 manual（改动前的真实读数）", st.Mode)
	}
	if st.HTTP != "10.0.0.9:8118" || st.SOCKS != "10.0.0.9:1080" {
		t.Errorf("记账里的地址不对: http=%q socks=%q", st.HTTP, st.SOCKS)
	}
	if len(st.Ignore) != 2 || st.Ignore[0] != "corp.example" {
		t.Errorf("记账里的 bypass 列表不对: %v", st.Ignore)
	}
	// 账记下的是本进程，便于崩溃后判断宿主是否还活着。
	if st.PID != os.Getpid() {
		t.Errorf("记账 pid = %d, 期望 %d", st.PID, os.Getpid())
	}
	// 只有 PID 会被回收号码骗过去，所以路径必须一起记下来。
	if st.Exe != procid.Self() {
		t.Errorf("记账 exe = %q, 期望 %q", st.Exe, procid.Self())
	}
}

// TestDisableRestoresRatherThanBlanking 关闭时必须还原成改动前的样子，
// 而不是无脑置 none——用户原来可能就开着 manual 指向另一个代理。
func TestDisableRestoresRatherThanBlanking(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))

	if err := Enable(context.Background(), manualRec(), sp, Config{Enable: true, Backend: BackendGNOME}); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	r := manualRec()
	if err := Disable(context.Background(), r, sp, BackendGNOME); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	joined := strings.Join(r.ran, "\n")
	if !strings.Contains(joined, `http host "10.0.0.9"`) {
		t.Errorf("没有还原原来的 http host:\n%s", joined)
	}
	if !strings.Contains(joined, "http port 8118") {
		t.Errorf("没有还原原来的 http port:\n%s", joined)
	}
	if !strings.Contains(joined, `ignore-hosts ["corp.example", "localhost"]`) {
		t.Errorf("没有还原原来的 bypass 列表:\n%s", joined)
	}
	if !strings.Contains(joined, "mode 'manual'") {
		t.Errorf("没有把 mode 还原成 manual:\n%s", joined)
	}
	// 还原成功才算账清了，否则下次启动会再还原一次，把用户期间自己的改动冲掉。
	if _, err := os.Stat(sp); !os.IsNotExist(err) {
		t.Errorf("还原后记账文件应当删除，实际 err=%v", err)
	}
}

// TestDisableWithoutRecordFallsBackToNone 从来没开过系统代理时，
// 关闭就是老老实实置 none。
func TestDisableWithoutRecordFallsBackToNone(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	r := &rec{}
	if err := Disable(context.Background(), r, sp, BackendGNOME); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if !strings.Contains(r.ran[len(r.ran)-1], "mode 'none'") {
		t.Fatalf("没有记账时应置 mode none: %v", r.ran)
	}
}

// TestEnableDoesNotTouchDesktopWhenReadFails 读不到原状态就不许动手。
// 还原不了等于改了就回不来，宁可什么都不做。
func TestEnableDoesNotTouchDesktopWhenReadFails(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	r := &rec{fail: true} // gsettings 探测直接失败

	if err := Enable(context.Background(), r, sp, Config{Enable: true, Backend: BackendGNOME}); err == nil {
		t.Fatal("读不到当前设置时应当放弃改动")
	}
	if _, err := os.Stat(sp); !os.IsNotExist(err) {
		t.Error("放弃改动时不该留下记账文件")
	}
}

// TestEnableRemovesRecordWhenApplyFails 改失败就撤账，
// 别留一条会让下次启动乱还原的假记录。
func TestEnableRemovesRecordWhenApplyFails(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	r := &rec{failOn: "ignore-hosts"}

	if err := Enable(context.Background(), r, sp, Config{Enable: true, Backend: BackendGNOME}); err == nil {
		t.Fatal("写入失败时应当报错")
	}
	if _, err := os.Stat(sp); !os.IsNotExist(err) {
		t.Error("写入失败后应当把记账撤掉")
	}
}

// TestRecoverIfStaleRestoresAfterCrash 崩溃场景下唯一的自愈机会：
// 崩掉的进程没机会执行任何清理代码，所以由下一个实例来还原。
func TestRecoverIfStaleRestoresAfterCrash(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))

	// 造一条「宿主进程已经不在了」的记账（pid=0 永远不会被判为活着）。
	if err := writeState(sp, saved{
		PID:    0,
		Mode:   "none",
		Ignore: []string{"corp.example"},
	}); err != nil {
		t.Fatalf("写记账: %v", err)
	}

	r := &rec{}
	done, err := RecoverIfStale(context.Background(), r, sp)
	if err != nil {
		t.Fatalf("RecoverIfStale: %v", err)
	}
	if !done {
		t.Fatal("宿主已消失，应当做一次还原")
	}
	if !strings.Contains(strings.Join(r.ran, "\n"), "mode 'none'") {
		t.Errorf("没有把桌面还原成原样: %v", r.ran)
	}
	if _, err := os.Stat(sp); !os.IsNotExist(err) {
		t.Error("还原后应当清掉记账")
	}
}

// TestRecoverIfStaleLeavesLiveInstanceAlone 另一个实例还活着时不能抢。
// 抢了会把正在转发的那份代理的桌面设置搅乱。
func TestRecoverIfStaleLeavesLiveInstanceAlone(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	if err := writeState(sp, saved{PID: os.Getpid(), Mode: "none"}); err != nil {
		t.Fatalf("写记账: %v", err)
	}
	r := &rec{}
	done, err := RecoverIfStale(context.Background(), r, sp)
	if err != nil {
		t.Fatalf("RecoverIfStale: %v", err)
	}
	if done {
		t.Fatal("宿主还活着时不该动桌面")
	}
	if _, err := os.Stat(sp); err != nil {
		t.Error("宿主还活着时记账应当保留")
	}
}

// TestRecoverIfStaleNoRecordIsNotAnError 干净启动是最常见的情况，
// 不该报错也不该有任何副作用。
func TestRecoverIfStaleNoRecordIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	done, err := RecoverIfStale(context.Background(), &rec{}, sp)
	if err != nil || done {
		t.Fatalf("没有记账时应安静返回 (done=%v, err=%v)", done, err)
	}
}

// TestRestoreIsIdempotent 手工跑两次 restore 不该报错，
// 否则用户照着提示操作会以为还有问题。
func TestRestoreIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	if err := writeState(sp, saved{PID: 0, Mode: "none"}); err != nil {
		t.Fatalf("写记账: %v", err)
	}
	if err := Restore(context.Background(), &rec{}, sp); err != nil {
		t.Fatalf("第一次还原: %v", err)
	}
	if err := Restore(context.Background(), &rec{}, sp); err != nil {
		t.Fatalf("第二次还原（应为空操作）: %v", err)
	}
}

// TestStatePathFollowsConfig 让状态文件跟着配置文件走：
// 用户把配置重定向到别处时，记账不能落在老地方。
func TestStatePathFollowsConfig(t *testing.T) {
	got := StatePath("/etc/wps_app/config.yaml")
	want := filepath.Join("/etc/wps_app", "config.yaml"+stateSuffix)
	if got != want {
		t.Fatalf("StatePath = %q, 期望 %q", got, want)
	}
	// 相对路径（README 与 make check 里的常见写法）不能被拼坏。
	if rel := StatePath("config.yaml"); filepath.Dir(rel) != "." {
		t.Fatalf("相对路径的目录部分应保持为 '.': %q", rel)
	}
}

func loadSaved(t *testing.T, path string) saved {
	t.Helper()
	st, err := peekSaved(path)
	if err != nil {
		t.Fatalf("解析记账: %v", err)
	}
	if st == nil {
		t.Fatalf("记账文件不存在: %s", path)
	}
	return *st
}

// TestEnableOverOwnValuesRestoresToNone 桌面上已经指着我们自己的入站时，
// 那份读数不能当成"原状"记下来。
//
// 触发条件不是假设：记账文件被连带删掉（临时目录里的配置跑过一次 on）、
// 或者桌面本来就配了同一个端口，都会走到这里。
// 照原样记账的话，关掉时"还原"的目标就是还指向我们的端口——
// 面板开关看起来是坏的，而进程一退出，桌面就指向一个没人听的端口，
// 全机断网且只报一句「代理连接被拒绝」。
func TestEnableOverOwnValuesRestoresToNone(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))
	r := &rec{gets: map[string]string{
		"get org.gnome.system.proxy mode":         "'manual'",
		"get org.gnome.system.proxy.http host":    "'127.0.0.1'",
		"get org.gnome.system.proxy.http port":    "7892",
		"get org.gnome.system.proxy.https host":   "'127.0.0.1'",
		"get org.gnome.system.proxy.https port":   "7892",
		"get org.gnome.system.proxy.socks host":   "'127.0.0.1'",
		"get org.gnome.system.proxy.socks port":   "7891",
		"get org.gnome.system.proxy ignore-hosts": "['localhost']",
	}}
	if err := Enable(context.Background(), r, sp, Config{
		Enable: true, Backend: BackendGNOME,
		HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891",
	}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if st := loadSaved(t, sp); !st.AlreadyOurs {
		t.Fatal("读数与要写的值一致时应记成「本来就是我们的」")
	}

	r2 := &rec{}
	if err := Disable(context.Background(), r2, sp, BackendGNOME); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	last := r2.ran[len(r2.ran)-1]
	if !strings.Contains(last, "mode 'none'") {
		t.Errorf("关掉应把 mode 置 none，而不是还原成指向我们自己的那套: %v", r2.ran)
	}
	for _, c := range r2.ran {
		if strings.Contains(c, "proxy.http host") || strings.Contains(c, "proxy.socks host") {
			t.Errorf("不该把我们的地址再写回桌面一遍: %s", c)
		}
	}
}

// TestEnableRecordsForeignManualAsPrevious 指向别的代理时是真正要保住的原状，
// 不能因为"也是 manual"就一并置 none。
func TestEnableRecordsForeignManualAsPrevious(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	if err := Enable(context.Background(), manualRec(), sp, Config{
		Enable: true, Backend: BackendGNOME,
		HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891",
	}); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if st := loadSaved(t, sp); st.AlreadyOurs {
		t.Fatal("桌面指向 10.0.0.9:8118，不是我们的值，必须当成原状保住")
	}
	r := &rec{}
	if err := Disable(context.Background(), r, sp, BackendGNOME); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	joined := strings.Join(r.ran, "\n")
	if !strings.Contains(joined, `http host "10.0.0.9"`) || !strings.Contains(joined, "mode 'manual'") {
		t.Errorf("没还原成原来那个代理:\n%s", joined)
	}
}

// TestCorruptLedgerBlocksEveryPath 记账读不懂时，三条路都不许动桌面。
//
// 读不懂 = 不知道改动前是什么样子。这时 Enable 会覆盖掉唯一一个线索，
// Restore/RecoverIfStale 会按一个猜出来的"原状"去写系统设置。
// 两种都比原地不动糟糕，所以宁可报错交回给用户。
func TestCorruptLedgerBlocksEveryPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))
	if err := os.WriteFile(sp, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	r := &rec{}
	if _, err := RecoverIfStale(context.Background(), r, sp); err == nil {
		t.Error("RecoverIfStale 读不懂记账时应报错")
	}
	if err := Restore(context.Background(), r, sp); err == nil {
		t.Error("Restore 读不懂记账时应报错")
	}
	if err := Enable(context.Background(), r, sp, Config{Enable: true, Backend: BackendGNOME}); err == nil {
		t.Error("Enable 不该覆盖一份读不懂的记账")
	}
	if len(r.ran) != 0 {
		t.Errorf("三条路都不该下发任何命令: %v", r.ran)
	}
	// 记账文件保持原样：用户还能自己看一眼它原来记了什么。
	raw, err := os.ReadFile(sp)
	if err != nil || string(raw) != "{ this is not json" {
		t.Errorf("报错不该顺手改写或删除记账: %q %v", raw, err)
	}
}

// ---------- 宿主身份判定（PID 会被回收，所以不能只认号码） ----------

// fakeProc 造一份 /proc 读数：exeErr/commErr 非 nil 就代表那一项读不到；
// self 传空串表示「连本程序的可执行路径都读不出来」。
func fakeProc(exe string, exeErr error, comm string, commErr error, self string) procFS {
	return procFS{
		readlink: func(string) (string, error) { return exe, exeErr },
		readFile: func(string) ([]byte, error) {
			if commErr != nil {
				return nil, commErr
			}
			return []byte(comm + "\n"), nil
		},
		self: func() string { return self },
	}
}

// isAlive 只要结论；原因单独有用例守着（它是给 `-sysproxy status` 印出来的那句话）。
func isAlive(pid int, exe string, fs procFS) bool {
	alive, _ := holderCheck(pid, exe, fs)
	return alive
}

// deadPID 返回一个确定已经不存在的进程号。
// 必须 Wait 收尸：已退出但没回收的子进程还是僵尸，kill(pid, 0) 照样成功。
func deadPID(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("起 sleep 失败: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Logf("sleep 0 退出码非零（不影响用例）: %v", err)
	}
	if err := syscall.Kill(pid, 0); err == nil {
		t.Fatalf("PID %d 收尸后还在，这台机器上判不了「进程不存在」", pid)
	}
	return pid
}

func TestHolderAliveRejectsRecycledPID(t *testing.T) {
	// 记账写的是我们的路径，可这个 PID 现在是 /usr/bin/sleep —— 号码被回收了。
	// 判成「还活着」就等于永远不自愈，桌面一直停在已经不存在的端口上。
	if isAlive(os.Getpid(), "/bin/wps_app-gui",
		fakeProc("/usr/bin/sleep", nil, "sleep", nil, "")) {
		t.Fatal("PID 被回收给别的程序时应判定宿主已消失，允许自愈")
	}
}

func TestHolderAliveAcceptsOurOwnLiveInstance(t *testing.T) {
	if !isAlive(os.Getpid(), "/usr/bin/sleep",
		fakeProc("/usr/bin/sleep", nil, "sleep", nil, "")) {
		t.Fatal("同一个程序还开着时必须判成「活着」，不然会把正在转发的桌面设置抢走")
	}
}

func TestHolderAliveTreatsDeletedBinaryAsSame(t *testing.T) {
	// 重编译换掉了磁盘上的二进制，内核给旧进程的链接加上 " (deleted)"。
	// 那还是同一个程序的上一版：判成「不是我们」会让崩溃自愈在改完代码后失灵。
	if !isAlive(os.Getpid(), "/bin/wps_app-gui",
		fakeProc("/bin/wps_app-gui (deleted)", nil, "wps_app-gui", nil, "")) {
		t.Fatal(`带 " (deleted)" 尾巴的旧实例应算同身份`)
	}
}

func TestHolderAliveDegradesToCommWhenExeUnreadable(t *testing.T) {
	// exe 读不到 = 那个进程不归这个 uid（旧实例用 sudo 起过，真发生过）。
	// comm 是 world-readable 的，够用来把「号码被回收给一个不相干的程序」筛出去。
	noExe := errors.New("permission denied")
	if !isAlive(os.Getpid(), "/bin/wps_app-gui", fakeProc("", noExe, "wps_app-gui", nil, "")) {
		t.Error("exe 读不到但 comm 同名，应按「还活着」处理")
	}
	if isAlive(os.Getpid(), "/bin/wps_app-gui", fakeProc("", noExe, "systemd-resolved", nil, "")) {
		t.Error("exe 读不到但 comm 明显是别的程序，应判定宿主已消失")
	}
	// 两条线索都断了就判不出身份：这时候不动桌面。
	if !isAlive(os.Getpid(), "/bin/wps_app-gui", fakeProc("", noExe, "", noExe, "")) {
		t.Fatal("exe 与 comm 都读不到时应当判成「活着」")
	}
	// 同理，连自己是谁都读不出来时也不许猜成「不是我们」。
	if !isAlive(os.Getpid(), "", fakeProc("", noExe, "", noExe, "")) {
		t.Fatal("老记账没有 exe、当前二进制路径又读不到时，不许判成宿主已消失")
	}
	if !isAlive(os.Getpid(), "", fakeProc("/bin/wps_app-gui", nil, "wps_app-gui", nil, "/bin/wps_app-gui")) {
		t.Fatal("老记账没有 exe 时应退化到用当前二进制路径比对")
	}
}

func TestHolderAliveDeadProcess(t *testing.T) {
	if isAlive(deadPID(t), "/bin/wps_app-gui", realProc) {
		t.Fatal("进程已经不在，不该拦着自愈")
	}
	if isAlive(0, "/bin/wps_app-gui", realProc) || isAlive(-1, "", realProc) {
		t.Fatal("非法 PID 不该被当成活的宿主")
	}
}

func TestHolderAliveOtherUsersProcess(t *testing.T) {
	// PID 1 在真机上必然存在，而且通常不归当前用户：走的是 kill 报 EPERM 那一支。
	// 把它判成「不存在」等于对着别人的进程抢桌面；判成「是我们」则永远不自愈。
	// 只有当 1 号就是本程序时（容器里把我们的二进制当 init）这条判断才没有意义。
	if name, err := procid.Comm(1, os.ReadFile); err == nil &&
		procid.NameMatches(name, procid.Self()) {
		t.Skip("PID 1 就是本程序（容器 init），这台机器上验不了跨 uid 分支")
	}
	// 期望是 false：1 号进程不是我们的旧实例，号码判得出来就该允许自愈。
	if isAlive(1, "/bin/wps_app-gui", realProc) {
		t.Fatal("PID 1 不是记账里那个实例，不该被认成还活着的旧实例")
	}
}

// TestRecoverIfStaleHealsSpoofedHolder 用一个真进程把最阴的一种情况钉住：
// 进程的 argv[0] 被改成和我们的二进制同名（exec -a / 包装脚本都会这样），
// 而它其实不是本程序。只读 cmdline 的判定会一直拦着自愈——
// 于是桌面停在 mode=manual 指向一个已经不存在的端口，整机断网，
// 且日志里一句错都没有，因为「看起来还有一个实例活着」。
func TestRecoverIfStaleHealsSpoofedHolder(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))

	cmd := exec.Command("sleep", "60")
	base := filepath.Base(procid.Self())
	cmd.Args[0] = base // argv[0] 换成我们的名字，Path 仍是真的 sleep
	if err := cmd.Start(); err != nil {
		t.Fatalf("起 decoy 进程失败: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	// 等 fork→exec 走完。刚 fork 出来的那一瞬间 cmdline 还是空的，
	// 那时候读到的是「还没 exec」的中间态，断言就成了空跑。
	var argv0 string
	deadline := time.Now().Add(5 * time.Second)
	for argv0 == "" && time.Now().Before(deadline) {
		if raw, err := os.ReadFile(procid.ProcPath(pid, "cmdline")); err == nil {
			argv0 = strings.SplitN(string(raw), "\x00", 2)[0]
		}
		if argv0 == "" {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if argv0 == "" {
		t.Fatal("decoy 进程没起来（exec 没走完，或一 exec 就退了）")
	}
	// 现场必须真的是「argv[0] 同名、但 exe 是别的程序」，否则这个用例什么也没证明。
	if got := filepath.Base(argv0); got != base {
		t.Fatalf("decoy 的 argv[0] = %q, 期望与我们的文件名 %q 同名（否则本用例是空跑）", got, base)
	}
	if exe, err := procid.ExePath(pid, os.Readlink); err != nil {
		t.Fatalf("读 decoy 的 exe: %v", err)
	} else if procid.Same(exe, procid.Self()) {
		t.Fatalf("decoy 的 exe = %q, 竟然和本程序相同", exe)
	}

	if err := writeState(sp, saved{PID: pid, Exe: procid.Self(), Mode: "none"}); err != nil {
		t.Fatalf("写记账: %v", err)
	}
	r := &rec{}
	done, err := RecoverIfStale(context.Background(), r, sp)
	if err != nil {
		t.Fatalf("RecoverIfStale: %v", err)
	}
	if !done {
		t.Fatal("argv[0] 同名不是同身份，应当照常自愈")
	}
	if !strings.Contains(strings.Join(r.ran, "\n"), "mode 'none'") {
		t.Errorf("没有还原桌面: %v", r.ran)
	}
}

// TestRecoverIfStaleLeavesOurLiveInstanceAlone 另一个真实例（同一个二进制）还开着时不许抢。
// 这条和上面那条是一对：只收紧不放松会把正在转发的代理的桌面设置搅掉。
func TestRecoverIfStaleLeavesOurLiveInstanceAlone(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperLiveInstance", "-test.timeout=120s")
	cmd.Env = append(os.Environ(), "WPS_HELPER_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("起第二个实例失败: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	// 等它真的跑起来（exe 链接可读），而不是贴一个 sleep 时序。
	deadline := time.Now().Add(10 * time.Second)
	for {
		if exe, err := procid.ExePath(pid, os.Readlink); err == nil && procid.Same(exe, procid.Self()) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("子实例一直没起来")
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := writeState(sp, saved{PID: pid, Exe: procid.Self(), Mode: "none"}); err != nil {
		t.Fatalf("写记账: %v", err)
	}
	r := &rec{}
	done, err := RecoverIfStale(context.Background(), r, sp)
	if err != nil {
		t.Fatalf("RecoverIfStale: %v", err)
	}
	if done {
		t.Fatal("同一个二进制的实例还活着，不该动它的桌面")
	}
	if len(r.ran) != 0 {
		t.Errorf("不该下发任何还原命令: %v", r.ran)
	}
	if _, err := os.Stat(sp); err != nil {
		t.Errorf("记账应当留着: %v", err)
	}
}

// TestHelperLiveInstance 是上面那个用例给子进程用的入口，本身不是断言。
// 环境变量挡住时直接 skip，正常跑批不会真的睡在这儿。
func TestHelperLiveInstance(t *testing.T) {
	if os.Getenv("WPS_HELPER_SLEEP") != "1" {
		t.Skip("仅作为子进程入口")
	}
	time.Sleep(90 * time.Second)
}

// TestHolderCheckExplainsEachBranch 「为什么不还原」是这个故障里最难自己看出来的一件事，
// 所以每一支都要说一句不一样的话——空话或重复的话都比不上桌面的状态有用。
func TestHolderCheckExplainsEachBranch(t *testing.T) {
	noExe := errors.New("permission denied")
	cases := []struct {
		name      string
		pid       int
		exe       string
		fs        procFS
		wantAlive bool
		wantIn    []string
	}{
		{"进程没了", deadPID(t), "/bin/wps_app-gui", realProc, false, []string{"已经不在了"}},
		{"没有进程号", 0, "/bin/wps_app-gui", realProc, false, []string{"有效的宿主进程号"}},
		{"同身份还开着", os.Getpid(), "/bin/wps_app-gui",
			fakeProc("/bin/wps_app-gui", nil, "wps_app-gui", nil, ""), true, []string{"还开着", "/bin/wps_app-gui"}},
		{"号码被回收", os.Getpid(), "/bin/wps_app-gui",
			fakeProc("/usr/bin/sleep", nil, "sleep", nil, ""), false, []string{"/usr/bin/sleep", "被回收"}},
		{"退化到进程名", os.Getpid(), "/bin/wps_app-gui",
			fakeProc("", noExe, "wps_app-gui", nil, ""), true, []string{"还开着", "按进程名"}},
		{"退化后名字不对", os.Getpid(), "/bin/wps_app-gui",
			fakeProc("", noExe, "nginx", nil, ""), false, []string{"nginx", "被回收"}},
		{"身份认不出", os.Getpid(), "/bin/wps_app-gui",
			fakeProc("", noExe, "", noExe, ""), true, []string{"读不到"},
		},
		{"自己是谁都不知道", os.Getpid(), "",
			fakeProc("", noExe, "", noExe, ""), true, []string{"认不出"},
		},
	}
	for _, c := range cases {
		alive, why := holderCheck(c.pid, c.exe, c.fs)
		if alive != c.wantAlive {
			t.Errorf("%s: alive = %v, 期望 %v（%q）", c.name, alive, c.wantAlive, why)
		}
		for _, w := range c.wantIn {
			if !strings.Contains(why, w) {
				t.Errorf("%s: 原因里没有 %q，实得 %q", c.name, w, why)
			}
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s: 判活必须带一句能印出来的原因", c.name)
		}
	}
}

// TestReadLedgerDistinguishesFourStates 「没有记账」「欠着还原」「宿主还活着」「读不懂」
// 是四件不同的事，必须给出四种读数。把它们混成一类，
// 用户就没法知道桌面到底是被别人占着，还是等一次自动自愈。
func TestReadLedgerDistinguishesFourStates(t *testing.T) {
	dir := t.TempDir()
	sp := StatePath(filepath.Join(dir, "config.yaml"))

	// 1. 没有记账
	l, err := ReadLedger(sp)
	if err != nil {
		t.Fatalf("没有记账不该报错: %v", err)
	}
	if l.Exists || l.Stale || l.Alive || l.ReadErr != "" {
		t.Errorf("没有记账时读数应当全空: %+v", l)
	}

	// 2. 宿主还活着（用本测试进程当宿主）
	if err := writeState(sp, saved{PID: os.Getpid(), Exe: procid.Self(), Backend: BackendGNOME, Mode: "none"}); err != nil {
		t.Fatalf("写记账: %v", err)
	}
	l, err = ReadLedger(sp)
	if err != nil || !l.Exists {
		t.Fatalf("读记账: exists=%v err=%v", l.Exists, err)
	}
	if !l.Alive || l.Stale {
		t.Errorf("宿主是本进程时应判成还活着: %+v", l)
	}
	if l.Backend != BackendGNOME || l.PID != os.Getpid() || l.Exe != procid.Self() {
		t.Errorf("记账字段没照实读出来: %+v", l)
	}
	if !strings.Contains(l.Holder, "还开着") {
		t.Errorf("Holder = %q, 期望说明宿主还开着", l.Holder)
	}

	// 3. 宿主不在了 = 欠着一次自愈
	dead := deadPID(t)
	if err := writeState(sp, saved{PID: dead, Exe: procid.Self(), Backend: BackendEnv, Mode: "none"}); err != nil {
		t.Fatalf("写记账: %v", err)
	}
	l, err = ReadLedger(sp)
	if err != nil {
		t.Fatalf("ReadLedger: %v", err)
	}
	if !l.Stale || l.Alive {
		t.Errorf("宿主已经不在了，应判成欠还原: %+v", l)
	}
	// 只读不写：ReadLedger 不许动桌面、也不许把记账吃掉。
	if _, err := os.Stat(sp); err != nil {
		t.Errorf("读记账不该删文件: %v", err)
	}

	// 4. 读不懂
	if err := os.WriteFile(sp, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err = ReadLedger(sp)
	if err == nil {
		t.Fatal("读不懂记账时应报错")
	}
	if l.Exists || l.ReadErr == "" {
		t.Errorf("读不懂时要说清楚是读不懂，而不是报成「没有记账」: %+v", l)
	}
}

// TestHolderCheckZombieIsNotAlive 僵尸进程杀不掉也活不好：
// kill(pid,0) 成功、exe 链接没了，如果按"还活着"处理，
// 这份该自愈的记账就永远不敢动桌面，用户整机没网。
func TestHolderCheckZombieIsNotAlive(t *testing.T) {
	cmd := exec.Command("sleep", "0")
	if err := cmd.Start(); err != nil {
		t.Fatalf("起 sleep 失败: %v", err)
	}
	pid := cmd.Process.Pid
	// 故意不 Wait：让它停在僵尸态。收尸前 poll 到状态变成 Z。
	deadline := time.Now().Add(5 * time.Second)
	for {
		if st, err := procid.State(pid, os.ReadFile); err == nil && st == 'Z' {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			t.Fatal("等不到子进程变成僵尸态，这台机器上验不了这一项")
		}
		time.Sleep(10 * time.Millisecond)
	}
	alive, why := holderCheck(pid, procid.Self(), realProc)
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait() // 收尸，别把僵尸留给后面的用例
	if alive {
		t.Errorf("僵尸不该被算成活的宿主: %q", why)
	}
	if !strings.Contains(why, "僵尸") {
		t.Errorf("要说清是僵尸, 实得 %q", why)
	}
}

// TestSameProgramRecognizesBothBuilds 老记账（没写 exe）只比 basename 会出事：
// 命令行版 wps_app 与面板版 wps_app-gui 是同一个程序的两个构建，
// 认成两个程序，就等于让普通用户跑一次 CLI 抢走面板的桌面设置。
func TestSameProgramRecognizesBothBuilds(t *testing.T) {
	cases := []struct {
		holder, self string
		want         bool
	}{
		{"wps_app", "wps_app-gui", true},
		{"wps_app-gui", "wps_app-gui", true},
		{"sysproxy.test", "sysproxy.test", true},
		{"wps_app.app", "wps_app", true},
		{"sleep", "wps_app-gui", false},
		{"nginx", "wps_app-gui", false},
		{"", "wps_app-gui", false},
		{"wps_app", "", false},
	}
	for _, c := range cases {
		if got := sameProgram(c.holder, c.self); got != c.want {
			t.Errorf("sameProgram(%q, %q) = %v, 期望 %v", c.holder, c.self, got, c.want)
		}
	}
}

// TestHolderCheckLegacyRecordKeepsSameNameInstance 老记账 + 另一个构建还活着 → 不许抢。
func TestHolderCheckLegacyRecordKeepsSameNameInstance(t *testing.T) {
	self := procid.Self()
	// 造一个"exe 在别处、但进程名和我们同一族"的现场。
	other := filepath.Dir(filepath.Dir(self)) + "/old-build/wps_app"
	if procid.Same(other, self) {
		t.Fatalf("构造失败：%q 与 %q 相同", other, self)
	}
	fs := procFS{
		readlink: func(string) (string, error) { return other, nil },
		readFile: func(string) ([]byte, error) { return []byte(filepath.Base(self) + "\n"), nil },
		self:     func() string { return self },
	}
	alive, why := holderCheck(os.Getpid(), "", fs)
	if !alive {
		t.Errorf("老记账遇到同族命名的活实例不该判成回收: %q", why)
	}
	// 名字也对不上时，才允许自愈。
	fs.readFile = func(string) ([]byte, error) { return []byte("nginx\n"), nil }
	if alive, _ := holderCheck(os.Getpid(), "", fs); alive {
		t.Error("名字对不上又不在同一路径，应当判成进程号被回收")
	}
}
