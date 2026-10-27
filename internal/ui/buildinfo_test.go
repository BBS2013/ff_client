// 「这份界面是不是磁盘上最新的那一份」那一格的判据（见 buildinfo.go 为什么存在）。
package ui

import (
	"io/fs"
	"testing"
	"testing/fstest"
	"time"
)

type fakeStat struct {
	name string
	mod  time.Time
}

func (f fakeStat) Name() string       { return f.name }
func (f fakeStat) Size() int64        { return 0 }
func (f fakeStat) Mode() fs.FileMode  { return 0o755 }
func (f fakeStat) ModTime() time.Time { return f.mod }
func (f fakeStat) IsDir() bool        { return false }
func (f fakeStat) Sys() any           { return nil }

func TestEmbeddedAsset(t *testing.T) {
	// 没装内嵌文件系统（不带 gui 标签的构建、以及绝大多数测试）时必须给空串，
	// 而不是 panic，也不是编一个看起来像的名字。
	DistFS = nil
	if got := embeddedAsset(); got != "" {
		t.Errorf("没有内嵌界面却报出 %q", got)
	}

	DistFS = fstest.MapFS{
		"frontend/dist/index.html": &fstest.MapFile{Data: []byte(
			`<script type="module" crossorigin src="/assets/index-Ab12Cd34.js"></script>`)},
	}
	defer func() { DistFS = nil }()
	if got := embeddedAsset(); got != "index-Ab12Cd34.js" {
		t.Errorf("内嵌资源名没读出来: %q", got)
	}

	// 读不到文件也只会是空串：这一格的意义是"报出它是什么"，猜一个反而更坏。
	DistFS = fstest.MapFS{}
	if got := embeddedAsset(); got != "" {
		t.Errorf("index.html 不在时不该有读数: %q", got)
	}
}

// TestNewerOnDiskOnlyWhenClearlyNewer 盯的是那个提醒的触发条件：
// 误报"界面是旧的"会让人去重启一个本来就最新的面板。
func TestNewerOnDiskOnlyWhenClearlyNewer(t *testing.T) {
	started := time.Now()
	for _, c := range []struct {
		name string
		mod  time.Time
		want bool
	}{
		{"磁盘比进程旧一个小时前", started.Add(-time.Hour), false},
		{"启动前一秒刚编完（正常流程）", started.Add(-time.Second), false},
		{"启动后一秒被重新构建过", started.Add(time.Second), false}, // 2 秒余量之内不算
		{"启动之后确实又编了一次", started.Add(30 * time.Second), true},
	} {
		var info BuildInfo
		info.fillExe(fakeStat{mod: c.mod}, started)
		if info.NewerOnDisk != c.want {
			t.Errorf("%s: 判成 %v，想要 %v", c.name, info.NewerOnDisk, c.want)
		}
		if info.ExeModTime != c.mod.UnixMilli() {
			t.Errorf("%s: 磁盘时间没带上", c.name)
		}
	}
}

// TestBuildInfoNeverFails 这一格不许成为设置页的一个失败源。
func TestBuildInfoNeverFails(t *testing.T) {
	a := &App{startedAt: time.Now()}
	info := a.BuildInfo()
	if info.StartedAt == 0 {
		t.Error("启动时刻没填：界面会写成一个不可能的时间")
	}
	if info.ExePath == "" {
		t.Error("连本进程的路径都没报出来，这一格就没意义了")
	}
}
