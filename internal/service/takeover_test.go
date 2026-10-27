package service

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestTakeoverKillsSameBinaryHolder 就是用户要的行为：
// 启动新实例时如果旧实例还在，先把它关掉，再起新的。
func TestTakeoverKillsSameBinaryHolder(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)

	// 子进程用同一个测试二进制来占锁，模拟「上一次启动的面板还开着」。
	child := exec.Command(os.Args[0], "-test.run=TestHelperHoldLock", "-test.timeout=90s")
	child.Env = append(os.Environ(), "WPS_HOLD_LOCK="+cfgPath+lockSuffix)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	// 必须真的 Wait 回收：已退出但没被回收的子进程仍是僵尸，
	// kill(pid, 0) 会成功，用它判活会把「已经关掉」误判成「还活着」。
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()
	t.Cleanup(func() {
		_ = child.Process.Kill()
		_, _ = child.Process.Wait()
	})

	holder := 0
	for i := 0; i < 60; i++ {
		if holder = lockHolderPID(cfgPath); holder > 0 && processAlive(holder) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if holder <= 0 {
		t.Fatal("子进程没能占住锁")
	}

	lock, err := acquireOrTakeover(cfgPath, 15*time.Second)
	if err != nil {
		t.Fatalf("应能接管旧实例: %v", err)
	}
	defer lock.release()

	if holder == os.Getpid() {
		t.Fatal("自己不该被当成旧实例")
	}
	for i := 0; i < 50 && processAlive(holder); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case err := <-childDone:
		if err != nil {
			t.Logf("旧实例退出码非零（被信号终止属正常）: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("旧实例 PID %d 没被关掉", holder)
	}
}

// TestTakeoverRefusesForeignHolder 守的是最坏的一种事故：
// PID 复用之后误杀一个无关进程。身份对不上就报错，绝不 SIGTERM。
func TestTakeoverRefusesForeignHolder(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/config.yaml"
	lockPath := cfgPath + lockSuffix

	// 起一个「不是本程序」的进程（sleep）当作被误写的持有者。
	foreign := exec.Command("sleep", "60")
	if err := foreign.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = foreign.Process.Kill()
		_, _ = foreign.Process.Wait()
	})

	// 由测试进程自己占住 flock（不同的打开文件描述 → 新实例抢不到锁），
	// 再把外部进程的 PID 写进锁文件，模拟「PID 已被复用」。
	held, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("加锁失败: %v", err)
	}
	if err := os.WriteFile(lockPath, []byte(strconv.Itoa(foreign.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = acquireOrTakeover(cfgPath, 2*time.Second)
	if err == nil {
		t.Fatal("身份对不上时不该接管")
	}
	if !strings.Contains(err.Error(), "不做接管") {
		t.Fatalf("错误应说明是身份问题: %v", err)
	}
	if err := foreign.Process.Kill(); err != nil {
		t.Fatalf("外部进程 PID %d 被动过了（不该被接管逻辑杀掉）: %v", foreign.Process.Pid, err)
	}
}

// TestTakeoverReportsUnkillableHolder 覆盖「旧实例以 root 跑、我们是普通用户」：
// 关不动就要说清楚该怎么做，而不是让新实例卡在端口冲突上。
func TestTakeoverReportsUnkillableHolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("以 root 跑时无法构造 EPERM")
	}
	cfgPath, _ := userRulesEnv(t)
	lock, err := acquireInstanceLock(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()

	// 伪造一个不存在的 PID：走的是「无法确认身份」这条分支，
	// 与「kill 不动」同样属于不能接管，必须报错而不是硬启。
	if err := os.WriteFile(cfgPath+lockSuffix, []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireOrTakeover(cfgPath, time.Second); err == nil {
		t.Fatal("锁真被占着时应报错")
	} else if !strings.Contains(err.Error(), "PID") {
		t.Fatalf("错误里应带上 PID 方便处理: %v", err)
	}
}

// TestHelperHoldLock 不是给测试框架用的，而是被上面的用例重新 exec 起来的子进程：
// 它占住锁文件后挂住，模拟一个仍在运行的旧实例。
func TestHelperHoldLock(t *testing.T) {
	path := os.Getenv("WPS_HOLD_LOCK")
	if path == "" {
		t.Skip("只在被作为子进程调用时运行")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("加锁失败: %v", err)
	}
	if err := f.Truncate(0); err == nil {
		_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	time.Sleep(60 * time.Second)
}
