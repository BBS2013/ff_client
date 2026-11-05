package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/procid"
)

// lockSuffix 是锁文件的后缀：与配置文件同目录、同名加 .lock。
const lockSuffix = ".lock"

// takeoverWait 是给旧实例收尾的时间上限。它可能还要拆 TUN（删路由、摘 iptables），
// 而 TUN 的停用预算本身就有 15s（见 Service.stopLocked），走 helper 时还要加上
// 几次 sudo 唤起与二十来条 iptables 子进程——真机上见过 14s。
// 这个值必须大于「旧实例最慢的收尾」，否则接管会自己制造一段
// 「旧的已经死了、新的不肯起」的代理空档（实测就断过一次），比卡顿更糟。
const takeoverWait = 35 * time.Second

// instanceLock 是「同一份配置文件只允许一个实例在跑」的守卫。
//
// 为什么需要它：面板进程本身就是代理进程，两个实例会抢同一组入站端口，
// 后启动的那个只会拿到一句 `bind: address already in use`——既看不出是被谁占的，
// 也看不出该关掉谁。桌面程序双击就能再起一个，这个坑踩起来非常容易。
//
// 用 flock 而不是 pid 文件：进程被 kill -9 时内核会自动释放锁，
// 不会留下一个「锁文件说有人在，其实早没了」的死锁状态。
type instanceLock struct {
	f    *os.File
	path string
}

// acquireInstanceLock 尝试独占 cfgPath 对应的锁，抢不到就报错（不动旧实例）。
func acquireInstanceLock(cfgPath string) (*instanceLock, error) {
	path := cfgPath + lockSuffix
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		// 目录不可写（例如配置在 /etc 下而进程非 root）不该阻断启动：
		// 端口冲突仍然会在 Listen 时如实报错，只是少了「是谁占的」这条线索。
		return nil, nil //nolint:nilerr // 有意降级：拿不到锁文件就当没有守卫
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder := readLockHolder(f)
		_ = f.Close()
		if holder > 0 {
			return nil, fmt.Errorf("已有另一个实例正在使用 %s（PID %d），请先退出它再启动", filepath.Base(cfgPath), holder)
		}
		return nil, fmt.Errorf("已有另一个实例正在使用 %s，请先退出它再启动", filepath.Base(cfgPath))
	}
	// 把 PID 写进去：后来者才能报出「被 1301134 占着」而不是只说「被占了」。
	if err := f.Truncate(0); err == nil {
		if _, werr := f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0); werr == nil {
			_ = f.Sync()
		}
	}
	return &instanceLock{f: f, path: path}, nil
}

// acquireOrTakeover 先试独占；拿不到就接管旧实例。
//
// 接管是「启动新的就把旧的关掉」，但只在对身份判断得出手时才动 SIGTERM：
//  1. 锁文件里必须写着 PID；
//  2. 身份要能确认。首选 /proc/<pid>/exe（权威），读不到就退化到 comm/cmdline 同名判断
//     ——读不到 exe 只有一种情况：那进程不归我们（旧实例用 sudo 起、新的普通用户起），
//     而这恰恰是最常见的「想重起却重起不了」；
//  3. 重编译后内核把链接标成 " (deleted)"，同样算同身份，否则每次改完代码重启
//     都会拒绝接管，恰好是最需要它的时候。
//
// 挡掉的始终是同一件事：PID 被复用之后误杀一个无关进程。
func acquireOrTakeover(cfgPath string, wait time.Duration) (*instanceLock, error) {
	lock, err := acquireInstanceLock(cfgPath)
	if err == nil {
		return lock, nil
	}
	pid := lockHolderPID(cfgPath)
	if pid <= 0 || pid == os.Getpid() {
		return nil, err
	}
	id, ierr := identifyProcess(pid)
	if ierr != nil {
		return nil, fmt.Errorf("锁被 PID %d 占着，但确认不了它是谁（%v）；为安全起见不去动它，请手动退出后重试", pid, ierr)
	}
	if !id.same {
		return nil, fmt.Errorf("锁被 PID %d 占着，而它跑的是 %s（不是本程序），不做接管", pid, id.desc)
	}
	if kerr := syscall.Kill(pid, syscall.SIGTERM); kerr != nil {
		if errors.Is(kerr, syscall.EPERM) {
			// 动不了的唯一现实原因：旧实例是 root 起的（为了 TUN）。
			// 这里绝不退化成「绕过旧实例硬起」——那只会换来一句 address already in use。
			return nil, fmt.Errorf("旧实例 PID %d 跑在 %s 下，当前用户结束不了它（它多半是用 sudo 起的）："+
				"要么用 sudo 启动本程序，要么先 sudo kill %d 再启动", pid, uidLabel(id.uid), pid)
		}
		return nil, fmt.Errorf("旧实例 PID %d（%s）无法结束：%v", pid, id.desc, kerr)
	}
	logx.Infof("检测到旧实例 PID %d（%s），已发 SIGTERM 并等待它释放端口与锁", pid, id.desc)

	deadline := time.Now().Add(wait)
	nextNote := time.Now().Add(3 * time.Second)
	for {
		// 轮询而不是等 SIGCHLD：旧进程可能不是我们的子进程。
		// 锁一释放就说明它已经关掉监听器与网卡，可以接手了。
		if lk2, err2 := acquireInstanceLock(cfgPath); err2 == nil {
			logx.Infof("已接管 %s（旧实例 PID %d 已退出）", filepath.Base(cfgPath), pid)
			return lk2, nil
		}
		now := time.Now()
		if now.After(deadline) {
			break
		}
		if now.After(nextNote) {
			// 等得起也要说在等什么：没有这行，界面就是"点了没反应"十几秒。
			logx.Infof("仍在等旧实例 PID %d 收尾（拆 TUN 网卡与摘 iptables 劫持可能要十几秒）…", pid)
			nextNote = now.Add(3 * time.Second)
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("旧实例 PID %d 在 %s 内没有释放锁（多半还卡在 TUN 收尾）。"+
		"确认它已经不退了就 kill -9 %d 再启动；仍不行用 ss -tlnp 看看端口是不是被别的程序占了",
		pid, wait, pid)
}

// lockHolderPID 从锁文件里读持有者 PID。
func lockHolderPID(cfgPath string) int {
	raw, err := os.ReadFile(cfgPath + lockSuffix)
	if err != nil {
		return -1
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.Split(string(raw), "\n")[0]))
	if err != nil || n <= 0 {
		return -1
	}
	return n
}

func readLockHolder(f *os.File) int {
	buf := make([]byte, 32)
	n, _ := f.ReadAt(buf, 0)
	pid, err := strconv.Atoi(strings.TrimSpace(string(buf[:n])))
	if err != nil || pid <= 0 {
		return -1
	}
	return pid
}

// procID 是「锁里那个 PID 到底是谁」的判断结果。
type procID struct {
	desc    string // 给人看的一句话：可执行路径，或退化后的进程名
	same    bool   // 是否认定为本程序
	precise bool   // 是否走成了 /proc/<pid>/exe 这条权威路径
	uid     int    // 归属 uid，-1 表示读不出来
}

// identifyProcess 判断某个 PID 是不是本程序的另一个实例。
//
// exe 读不到时退化到 comm/cmdline 同名判断。会走到这条退化路径的只有一种情况：
// 那个进程不归我们（最典型就是旧实例用 sudo 起的）。此时「同名 + 锁文件里写着它的 PID」
// 已经把认错概率压到可以动手，换来的是用户真正想要的行为：旧的还开着，起新的就把它关掉。
func identifyProcess(pid int) (procID, error) {
	id := procID{uid: processUID(pid)}
	if exe, err := procid.ExePath(pid, os.Readlink); err == nil {
		id.desc, id.precise = exe, true
		id.same = procid.Same(exe, procid.Self())
		return id, nil
	}
	// exe 读不到只可能是权限问题；权限之外的情况（进程刚退出）在下面一并报出来。
	base := filepath.Base(procid.Self())
	comm, commErr := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	cmd, cmdErr := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if commErr != nil && cmdErr != nil {
		return id, fmt.Errorf("readlink /proc/%d/exe 与 comm/cmdline 都读不到（进程已退出？%v）", pid, commErr)
	}
	name := strings.TrimSpace(string(comm))
	// comm 是内核截断过的名字（最多 15 字节），长文件名必须按前缀比。
	if name == "" && cmdErr == nil {
		if argv0 := strings.SplitN(string(cmd), "\x00", 2)[0]; argv0 != "" {
			name = filepath.Base(argv0)
		}
	}
	id.desc = name
	id.same = procid.NameMatches(name, procid.Self())
	if !id.same && cmdErr == nil {
		if argv0 := strings.SplitN(string(cmd), "\x00", 2)[0]; argv0 != "" {
			id.same = filepath.Base(argv0) == base
		}
	}
	return id, nil
}

// processUID 读 /proc/<pid>/status 里的 real uid；读不出来给 -1。
func processUID(pid int) int {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if uid, cerr := strconv.Atoi(fields[1]); cerr == nil {
				return uid
			}
		}
		break
	}
	return -1
}

// uidLabel 把 uid 翻成能看懂的话——报错是要让人照着做的。
func uidLabel(uid int) string {
	switch uid {
	case 0:
		return "root（uid=0）"
	case -1:
		return "另一个用户"
	default:
		return fmt.Sprintf("uid=%d", uid)
	}
}

// processAlive 只回答「这个 PID 还在不在」。
// 它是不是本程序的另一个实例，是 identifyProcess 用 /proc 判的事。
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	// EPERM 说明进程在、只是不归我们动；这正是不能接管的情形，交给上面的 kill 报错。
	return err == nil || errors.Is(err, syscall.EPERM)
}

// release 释放锁。Close 本身就会解锁，这里只是把语义写明白。
func (l *instanceLock) release() {
	if l == nil || l.f == nil {
		return
	}
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	_ = l.f.Close()
	l.f = nil
}

// listenError 把 bind 失败翻译得能照着做。
//
// EADDRINUSE 九成是重复启动的实例（见 acquireOrTakeover），但也不全是——
// 所以话术是「先确认有没有」，而不是断言。
func listenError(listen, kind string, err error) error {
	if errors.Is(err, syscall.EADDRINUSE) {
		return fmt.Errorf("listen %s (%s): 端口已被占用。先确认有没有另一个实例在跑：pgrep -x wps_app-gui；"+
			"没有的话用 ss -tlnp | grep %s 看占用方", listen, kind, listenPort(listen))
	}
	return fmt.Errorf("listen %s (%s): %w", listen, kind, err)
}

func listenPort(listen string) string {
	if i := strings.LastIndexByte(listen, ':'); i >= 0 {
		return listen[i+1:]
	}
	return listen
}

// LiveInstance 返回这份配置当前正在运行的面板（PID 与可执行路径）。
//
// 只认锁文件里那个 PID，并再次确认它确实是本程序；没有就返回 ok=false。
// CLI 的 `-sysproxy on` 用它把系统代理记账交给真正的宿主，而不是交给
// 一个写完就退出的命令行进程（见 sysproxy.AdoptLedger）。
func LiveInstance(configPath string) (pid int, exe string, ok bool) {
	pid = lockHolderPID(configPath)
	if pid <= 0 || pid == os.Getpid() || !processAlive(pid) {
		return 0, "", false
	}
	id, err := identifyProcess(pid)
	if err != nil || !id.same {
		return 0, "", false
	}
	if id.precise {
		exe = id.desc
	}
	return pid, exe, true
}
