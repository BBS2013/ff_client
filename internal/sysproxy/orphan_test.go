package sysproxy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// oursRec 造一台「桌面正指着本客户端的入站」的机器。
func oursRec() *rec {
	return &rec{gets: map[string]string{
		"get org.gnome.system.proxy mode":         "'manual'",
		"get org.gnome.system.proxy.http host":    "'127.0.0.1'",
		"get org.gnome.system.proxy.http port":    "7892",
		"get org.gnome.system.proxy.https host":   "'127.0.0.1'",
		"get org.gnome.system.proxy.https port":   "7892",
		"get org.gnome.system.proxy.socks host":   "'127.0.0.1'",
		"get org.gnome.system.proxy.socks port":   "7891",
		"get org.gnome.system.proxy ignore-hosts": "['localhost']",
	}}
}

func ourConfig() Config {
	return Config{Enable: true, Backend: BackendGNOME,
		HTTPAddr: "127.0.0.1:7892", SOCKSAddr: "127.0.0.1:7891"}
}

func TestOrphanStatusFlagsUnbookedDesktop(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))
	orphan, err := orphanStatus(context.Background(), oursRec(), sp, ourConfig())
	if err != nil {
		t.Fatalf("OrphanStatus: %v", err)
	}
	if !orphan {
		t.Fatal("桌面指着我们、又没有记账，必须报孤儿")
	}
	// 查询不许有任何副作用：它只回答，不替用户决定。
	if _, err := os.Stat(sp); !os.IsNotExist(err) {
		t.Errorf("OrphanStatus 不该创建记账: err=%v", err)
	}
}

// TestOrphanStatusStaysQuiet 三种「不该报警」的情况必须一起覆盖：
// 有记账、桌面指着别人、桌面根本没开代理。
// 误报的代价是用户在好好的桌面上找一个不存在的故障。
func TestOrphanStatusStaysQuiet(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	foreign := &rec{gets: map[string]string{
		"get org.gnome.system.proxy mode":       "'manual'",
		"get org.gnome.system.proxy.http host":  "'10.0.0.9'",
		"get org.gnome.system.proxy.http port":  "8118",
		"get org.gnome.system.proxy.socks host": "'10.0.0.9'",
		"get org.gnome.system.proxy.socks port": "1080",
	}}
	off := &rec{gets: map[string]string{"get org.gnome.system.proxy mode": "'none'"}}

	cases := []struct {
		name   string
		r      *rec
		ledger bool
	}{
		{"有记账就不欠解释", oursRec(), true},
		{"桌面指着别人的代理", foreign, false},
		{"代理本来就是关的", off, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))
			if c.ledger {
				if err := writeState(sp, saved{PID: os.Getpid(), Mode: "none"}); err != nil {
					t.Fatalf("写记账: %v", err)
				}
			}
			orphan, err := orphanStatus(context.Background(), c.r, sp, ourConfig())
			if err != nil {
				t.Fatalf("OrphanStatus: %v", err)
			}
			if orphan {
				t.Error("这一种不该报孤儿")
			}
		})
	}
}

func TestOrphanStatusPropagatesReadFailure(t *testing.T) {
	// 读不到桌面就是读不到，不许退化成"没有孤儿"这种安慰人的答案。
	t.Setenv("HOME", t.TempDir())
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))
	orphan, err := orphanStatus(context.Background(), &rec{fail: true}, sp, ourConfig())
	if err == nil {
		t.Fatal("读不到桌面设置时应把错误交回调用方")
	}
	if orphan {
		t.Error("读不到的情况下不该断言有孤儿")
	}
}

func TestLikesOursRequiresAllThreeEndpoints(t *testing.T) {
	c := ourConfig()
	base := Status{Supported: true, Enabled: true, Mode: "manual",
		HTTP: "127.0.0.1:7892", HTTPS: "127.0.0.1:7892", SOCKS: "127.0.0.1:7891"}
	if !LikesOurs(base, c) {
		t.Fatal("三组地址都对上时应认成我们自己的")
	}
	for _, mut := range []struct {
		name  string
		patch func(*Status)
	}{
		{"https 指向别处", func(s *Status) { s.HTTPS = "127.0.0.1:8443" }},
		{"socks 指向别处", func(s *Status) { s.SOCKS = "127.0.0.1:1080" }},
		{"没开代理", func(s *Status) { s.Enabled = false }},
		{"这台机器不支持", func(s *Status) { s.Supported = false }},
	} {
		st := base
		mut.patch(&st)
		if LikesOurs(st, c) {
			t.Errorf("%s: 不该认成我们自己的", mut.name)
		}
	}
}

func TestOrphanWarningSpeaksOnlyWhenItMeansIt(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	sp := StatePath(filepath.Join(t.TempDir(), "config.yaml"))

	// 桌面没开代理：一句都不该说。
	if w := OrphanWarning(context.Background(), &rec{}, sp, ourConfig()); w != "" {
		t.Errorf("代理关着时不该有警告:\n%s", w)
	}
	// 指着我们、没记账：说后果与出路。
	w := OrphanWarning(context.Background(), oursRec(), sp, ourConfig())
	if !strings.Contains(w, "不会还原") || !strings.Contains(w, "-sysproxy on") {
		t.Errorf("孤儿状态的警告要能照着做，实得:\n%s", w)
	}
	// 这台机器没有桌面手段（gsettings 都起不来）：不是故障，别报警。
	if w := OrphanWarning(context.Background(), &rec{fail: true}, sp, ourConfig()); w != "" {
		t.Errorf("无桌面时不该有话，实得:\n%s", w)
	}
	// 记账读不懂是另一件事，必须说成"查不成"，不能套用孤儿那句话。
	if err := os.WriteFile(sp, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if w := OrphanWarning(context.Background(), oursRec(), sp, ourConfig()); !strings.Contains(w, "查不成") {
		t.Errorf("读不懂记账时应说查不成，实得:\n%s", w)
	}
}

// TestOrphanHintIsActionable 这句话得同时给出后果和两条能照着做的路，
// 否则用户只知道"有问题"，还是得去翻代码。
func TestOrphanHintIsActionable(t *testing.T) {
	h := OrphanHint("/home/chery/wps_app/config.yaml.sysproxy.json")
	for _, w := range []string{"config.yaml.sysproxy.json", "不会还原", "-sysproxy on", "-sysproxy off"} {
		if !strings.Contains(h, w) {
			t.Errorf("提示里缺 %q:\n%s", w, h)
		}
	}
}
