package ui

// 跨重启的节点用量在绑定层这一头的接线。
//
// internal/metrics 那边测的是账本本身（读写、坏文件、基数不翻倍），
// 这一头要证的是"面板真的会用它"：New 会不会去读、读不到会不会瞎猜、
// 「累计也清零」会不会把清完的账落下去。这三条里任何一条断掉，
// 用户看到的都是同一个症状——重启之后累计又回来了，或者干脆永远是 0。

import (
	"os"
	"testing"

	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

func TestNewLoadsPriorUsage(t *testing.T) {
	cfg := writeCfg(t, sampleCfg)
	app := New(cfg)
	defer app.Close()

	// 先跑出一条已经收尾的连接，让"本次"这一档有数。
	reg := app.svc.Metrics()
	c := reg.Begin("socks5", "127.0.0.1:5000", router.Result{Host: "x.example", Policy: outbound.PolicyProxy, Node: "n1"})
	c.Down.Add(1 << 20)
	reg.End(c)

	if err := reg.FlushUsage(); err != nil {
		t.Fatalf("FlushUsage: %v", err)
	}
	st, err := metrics.LoadUsage(metrics.UsagePath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if n := st.Nodes["n1"]; n.Down != 1<<20 {
		t.Fatalf("面板这条路没把账落下去: %+v", st)
	}

	// 换一个新实例：那份账必须以"累计"回来，而不是变成"本次"。
	app2 := New(cfg)
	defer app2.Close()
	snap := app2.Traffic()
	var row metrics.NodeTraffic
	found := false
	for _, n := range snap.ByNode {
		if n.Node == "n1" {
			row, found = n, true
		}
	}
	if !found {
		t.Fatalf("重启后那个节点整行都没了（累计应当留住它）: %+v", snap.ByNode)
	}
	if row.Prior != 1<<20 || row.Up != 0 || row.Down != 0 {
		t.Errorf("累计串成本次了: %+v", row)
	}
	if snap.PriorSince == 0 || snap.PriorSavedAt == 0 {
		t.Errorf("累计的两个时刻没投影出去: %+v", snap)
	}
}

// 账本格式比程序新：不套用，也**不回写**。
// 回写一次就等于把新版本记的字段抹掉，而症状是"累计突然变小"，最难查。
func TestNewKeepsFutureUsageFileUntouched(t *testing.T) {
	cfg := writeCfg(t, sampleCfg)
	path := metrics.UsagePath(cfg)
	future := `{"v":999,"savedAt":1700000000000,"since":1690000000000,"nodes":{"n1":{"up":7,"down":7}}}`
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	app := New(cfg)
	snap := app.Traffic()
	for _, n := range snap.ByNode {
		if n.Node == "n1" {
			t.Fatalf("不认识的新格式被当成账本用了: %+v", snap.ByNode)
		}
	}
	// 跑出一条连接再停掉：Close 里那一次落盘不该发生。
	reg := app.svc.Metrics()
	c := reg.Begin("socks5", "127.0.0.1:5001", router.Result{Host: "y.example", Policy: outbound.PolicyProxy, Node: "n1"})
	c.Down.Add(5)
	reg.End(c)
	app.Close()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("文件不见了: %v", err)
	}
	if string(body) != future {
		t.Errorf("新格式的文件被旧程序改写了，里面的字段已经丢了:\n%s", body)
	}
}

func TestClearUsageStatsWipesAndPersists(t *testing.T) {
	cfg := writeCfg(t, sampleCfg)
	app := New(cfg)
	defer app.Close()
	reg := app.svc.Metrics()

	c := reg.Begin("socks5", "127.0.0.1:5002", router.Result{Host: "z.example", Policy: outbound.PolicyProxy, Node: "n1"})
	c.Down.Add(100)
	reg.End(c)
	if err := reg.FlushUsage(); err != nil {
		t.Fatal(err)
	}
	app2 := New(cfg)
	defer app2.Close()
	if got := app2.Traffic(); len(got.ByNode) == 0 {
		t.Fatal("前置条件没立起来：第二个实例该带着累计")
	}

	if err := app2.ClearUsageStats(); err != nil {
		t.Fatalf("ClearUsageStats: %v", err)
	}
	snap := app2.Traffic()
	for _, n := range snap.ByNode {
		if n.Prior != 0 {
			t.Errorf("清了之后还留着累计: %+v", n)
		}
	}
	if snap.PriorSince == 0 {
		t.Error("清零要把起点拨到当下，否则「自何时起」这句没法说")
	}
	// 关键的一条：清完必须已经落盘，否则下次启动又读回来，等于白清。
	st, err := metrics.LoadUsage(metrics.UsagePath(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Nodes) != 0 {
		t.Errorf("清零没落盘，下次启动会读回 %+v", st.Nodes)
	}
}

// 没配 GUI 的那条路（CLI）不该在配置旁边留下任何文件——
// 那一条由 internal/metrics 的 TestNoUsagePathMeansNoWrites 守着：
// 那里能直接构造"没有路径"的注册表，在这一层反而要绕开真服务的停止路径。

// 账本被拒之门外时，界面要能知道**为什么**没有累计。
//
// 只把这件事写进日志是不够的：日志会滚走，而"这一栏是空的"与"有一本账但
// 这个版本不敢用"在屏幕上长得一样，处置方式却完全不同。
// 所以收场以 usageState 的形式跟着每次快照走。
func TestUsageOutcomeRidesEverySnapshot(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"新格式", `{"v":99,"savedAt":1,"since":1,"nodes":{"n1":{"up":1,"down":1}}}`, "too-new"},
		{"坏文件", `{这不是 JSON`, "unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := writeCfg(t, sampleCfg)
			path := metrics.UsagePath(cfg)
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			app := New(cfg)
			defer app.Close()
			if got := app.Traffic().UsageState; got != tc.want {
				t.Errorf("%s 的账本，快照里的 usageState 是 %q，想要 %q", tc.name, got, tc.want)
			}
		})
	}

	// 什么账本都没有：empty，界面不该弹任何警告。
	cfg := writeCfg(t, sampleCfg)
	app := New(cfg)
	defer app.Close()
	if got := app.Traffic().UsageState; got != metrics.UsageEmpty {
		t.Errorf("没有账本时应当报 empty，得到 %q", got)
	}
	// 「累计也清零」之后也是 empty：起点变了，但没有从盘上带进来的基数了。
	if err := app.ClearUsageStats(); err != nil {
		t.Fatal(err)
	}
	if got := app.Traffic().UsageState; got != metrics.UsageEmpty {
		t.Errorf("清零之后 usageState 还停在 %q", got)
	}
}
