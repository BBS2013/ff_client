package service

import (
	"os"
	"sync"
	"testing"
	"time"

	"wps_app/internal/config"
)

// TestDiskConfigCacheHitDoesNotReread 缓存命中时必须直接返回同一份指针：
// 面板每秒轮询 Snapshot/Mode/TUNStatus/Profiles，命中一次就意味着省掉一次解析。
func TestDiskConfigCacheHitDoesNotReread(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	first := svc.diskConfig()
	if first == nil {
		t.Fatal("首次 diskConfig 应读到配置")
	}
	second := svc.diskConfig()
	if first != second {
		t.Fatal("文件未变时 diskConfig 应命中缓存，不该重新 Load")
	}
}

// TestDiskConfigSeesExternalEdit 缓存靠 mtime+size 判新鲜度，别的工具或用户
// 手工改了 config.yaml，下一次轮询就必须看到新值——这是它不用 TTL 的全部理由。
func TestDiskConfigSeesExternalEdit(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	if got := svc.diskConfig().Mode; got != string(config.ModeRule) {
		t.Fatalf("初始 mode = %q, 期望 %q", got, config.ModeRule)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Mode = string(config.ModeGlobal)
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}

	if got := svc.diskConfig().Mode; got != string(config.ModeGlobal) {
		t.Fatalf("外部改写后 mode = %q, 期望 %q", got, config.ModeGlobal)
	}
}

// TestDiskConfigMutateSeesOwnWrite 是上面那条在自己写盘时的版本：
// mutate 末尾会 invalidateDiskConfig，若那条失效路径断了，
// 界面就会在保存后仍旧显示旧值。
func TestDiskConfigMutateSeesOwnWrite(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	if got := svc.diskConfig().Mode; got != string(config.ModeRule) {
		t.Fatalf("预热后的 mode = %q, 期望 %q", got, config.ModeRule)
	}
	if err := svc.SetMode("direct"); err != nil {
		t.Fatal(err)
	}
	if got := svc.diskConfig().Mode; got != string(config.ModeDirect) {
		t.Fatalf("本进程改写后 mode = %q, 期望 %q", got, config.ModeDirect)
	}
}

// TestDiskConfigSurvivesDeletedFile 配置文件被删掉时不该把状态投影整块塌成 nil：
// 界面会直接显示「没有节点」，而文件只是暂时不可读。
func TestDiskConfigSurvivesDeletedFile(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)
	svc.diskConfig()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if cfg := svc.diskConfig(); cfg == nil {
		t.Fatal("文件消失后 diskConfig 应回退到上一份缓存，而不是返回 nil")
	}
}

// TestDiskConfigConcurrentReaders 面板是单写多读：Snapshot/Mode/TUNStatus/Profiles
// 在各自的轮询里并发调它。这里交给 -race 去抓锁外拿指针的问题。
func TestDiskConfigConcurrentReaders(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)
	svc.diskConfig()

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if cfg := svc.diskConfig(); cfg == nil {
					t.Error("并发读拿到了 nil 配置")
					return
				}
			}
		}()
	}

	// 同时从外部改写磁盘，逼出 stat 与 Load 之间的竞态。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 10; j++ {
			cfg, err := config.Load(path)
			if err != nil {
				return
			}
			if j%2 == 0 {
				cfg.Mode = string(config.ModeGlobal)
			} else {
				cfg.Mode = string(config.ModeRule)
			}
			if err := config.Save(path, cfg); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	wg.Wait()

	if got := svc.diskConfig().Mode; got != string(config.ModeRule) {
		t.Fatalf("最终 mode = %q, 期望 %q", got, config.ModeRule)
	}
}
