package service

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// 没有锁文件、锁里是自己、锁里是死 PID，都不是「另一个正在跑的面板」。
func TestLiveInstanceRejectsNonLiveHolders(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if _, _, ok := LiveInstance(cfg); ok {
		t.Fatal("没有锁文件时不该报有活实例")
	}
	if err := os.WriteFile(cfg+".lock", []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := LiveInstance(cfg); ok {
		t.Fatal("锁里是自己时不该报有另一个活实例")
	}
	if err := os.WriteFile(cfg+".lock", []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := LiveInstance(cfg); ok {
		t.Fatal("锁里是死 PID 时不该报有活实例")
	}
}
