package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInstanceLockRejectsSecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	first, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("首次加锁应成功: %v", err)
	}
	if first == nil {
		t.Fatal("应拿到锁对象（目录可写）")
	}

	_, err = acquireInstanceLock(path)
	if err == nil {
		t.Fatal("第二个实例应被拒绝")
	}
	if want := fmt.Sprintf("PID %d", os.Getpid()); !containsAll(err.Error(), "已有另一个实例", want) {
		t.Fatalf("错误里应带上持有者 PID: %v", err)
	}

	first.release()
	again, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("释放后应能重新加锁: %v", err)
	}
	again.release()
	// 重复释放不该 panic。
	again.release()
}

// TestInstanceLockSurvivesKilledHolder 是选 flock 而不是 pid 文件的理由：
// 持有者被 kill -9 时内核自动解锁，不会留下「锁说有人在、其实人没了」。
func TestInstanceLockSurvivesKilledHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	f, err := os.OpenFile(path+lockSuffix, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	// 模拟进程被强杀：直接关闭 fd，内核会释放 flock。
	_ = f.Close()
	lock, err := acquireInstanceLock(path)
	if err != nil {
		t.Fatalf("前一个持有者消失后应能拿到锁: %v", err)
	}
	lock.release()
}

// TestStartBlocksSecondInstanceOnSameConfig 走真实入口：
// 两个 Service 用同一份配置文件，第二个必须拿到一句能照着做的话。
func TestStartBlocksSecondInstanceOnSameConfig(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	a := New(cfgPath, nil)
	if err := a.Start(); err != nil {
		t.Fatalf("第一个实例启动失败: %v", err)
	}
	defer func() { _ = a.Stop() }()

	b := New(cfgPath, nil)
	err := b.Start()
	if err == nil {
		_ = b.Stop()
		t.Fatal("第二个实例应被拒绝")
	}
	if !containsAll(err.Error(), "已有另一个实例", fmt.Sprintf("PID %d", os.Getpid())) {
		t.Fatalf("错误不够具体: %v", err)
	}
	if snap := b.Snapshot(); snap.LastError == "" {
		t.Error("快照里也该看得到这次失败的原因")
	}

	// 第一个退出后，第二个应该能正常接手。
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("锁释放后仍启动不了: %v", err)
	}
	_ = b.Stop()
}

// TestCheckDoesNotTakeTheLock 保证 -check（只 Prepare 不 Listen）不会抢锁：
// 面板在跑的时候还要能自检，这是日常排障的基本姿势。
func TestCheckDoesNotTakeTheLock(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	a := New(cfgPath, nil)
	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Stop() }()

	b := New(cfgPath, nil)
	if err := b.Prepare(); err != nil {
		t.Fatalf("Prepare 不该被锁挡住: %v", err)
	}
	_ = b.Stop()
}

func TestListenErrorIsActionable(t *testing.T) {
	err := listenError("127.0.0.1:7891", "socks5", fmt.Errorf("bind: %w", syscall.EADDRINUSE))
	msg := err.Error()
	if !containsAll(msg, "端口已被占用", "pgrep -x wps_app-gui", "7891") {
		t.Fatalf("错误信息不够可操作: %s", msg)
	}
	if !errors.Is(err, syscall.EADDRINUSE) && containsAll(msg, "bind") {
		t.Log("注意：翻译后的错误不再包裹原始 err，调用方只能读文本")
	}
	other := listenError("[::1]:80", "http", errors.New("permission denied"))
	if !containsAll(other.Error(), "permission denied") {
		t.Fatalf("非端口占用类错误应原样带出: %s", other)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		found := false
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
