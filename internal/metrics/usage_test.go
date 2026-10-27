package metrics

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

func usageConn(r *Registry, node string, up, down uint64, closeIt bool) {
	c := r.Begin("socks5", "127.0.0.1:4000", router.Result{
		Host: "x.example", Policy: outbound.PolicyProxy, Node: node,
	})
	c.Up.Add(up)
	c.Down.Add(down)
	if closeIt {
		r.End(c)
	}
}

func TestUsagePath(t *testing.T) {
	for _, tc := range []struct{ cfg, want string }{
		{"/etc/wps/config.yaml", "/etc/wps/config.yaml.usage.json"},
		{"config.yaml", "config.yaml.usage.json"},
		// 空串（配置路径没给）不能拼出一个只有后缀的隐藏文件名：
		// 那会写成当前目录下的 ".usage.json"，谁都不知道它是谁留下的。
		{"", "wps_app.usage.json"},
		{"/etc/wps/", "/etc/wps/wps_app.usage.json"},
	} {
		if got := UsagePath(tc.cfg); got != filepath.Clean(tc.want) {
			t.Errorf("UsagePath(%q) = %q，想要 %q", tc.cfg, got, tc.want)
		}
	}
}

func TestUsageRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml.usage.json")
	st := UsageState{Since: 1700000000000, Nodes: map[string]UsageNode{
		"tokyo": {Up: 11, Down: 22},
	}}
	if err := WriteUsage(path, st); err != nil {
		t.Fatal(err)
	}
	got, err := LoadUsage(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.V != usageVersion || got.Since != st.Since {
		t.Errorf("版本或起点丢了: %+v", got)
	}
	if n := got.Nodes["tokyo"]; n.Up != 11 || n.Down != 22 {
		t.Errorf("tokyo 的账读回来不对: %+v", n)
	}
	// 落盘的文件不该带 0644 这种别人能读的权限：它记的是"这台机器什么时间跑了多少流量"。
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("账本权限 %v 太松", fi.Mode().Perm())
	}
}

func TestLoadUsageMissingFileIsNotAnError(t *testing.T) {
	st, err := LoadUsage(filepath.Join(t.TempDir(), "nope.usage.json"))
	if err != nil {
		t.Fatalf("文件不存在应当是正常状态，得到 %v", err)
	}
	if len(st.Nodes) != 0 {
		t.Errorf("没有账本时不该凭空有数: %+v", st)
	}
}

func TestLoadUsageKeepsCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml.usage.json")
	if err := os.WriteFile(path, []byte("{这不是 JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUsage(path); err == nil {
		t.Fatal("坏掉的账本必须报错——静默当没有，等于把用户的累计悄悄清零")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("坏文件还留在原位：下一次落盘会把它直接盖掉")
	}
	// 原位没了，但挪出去的那份必须在，且内容一字不差。
	kept, err := filepath.Glob(path + ".bad*")
	if err != nil || len(kept) != 1 {
		t.Fatalf("没找到被挪走的坏文件（%v）", kept)
	}
	body, _ := os.ReadFile(kept[0])
	if !strings.Contains(string(body), "这不是 JSON") {
		t.Errorf("挪走的时候改了内容: %q", body)
	}
}

func TestLoadUsageRefusesNewerFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml.usage.json")
	future := fmt.Sprintf(`{"v":%d,"savedAt":1,"since":1,"nodes":{"tokyo":{"up":1,"down":1}}}`, usageVersion+1)
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUsage(path); !errors.Is(err, ErrUsageTooNew) {
		t.Fatalf("比本程序新的账本要认出来，得到 %v", err)
	}
	// 这条的意义在于"别写回去"：拿旧格式盖一次，新字段就没了，
	// 而用户看到的症状是累计突然变小。
	if _, err := os.Stat(path); err != nil {
		t.Errorf("太新不是坏，不该被挪走: %v", err)
	}
}

func TestPriorShowsUpAsItsOwnRow(t *testing.T) {
	r := NewRegistry(10, 0)
	r.ApplyPrior(UsageState{
		Since: 1700000000000, SavedAt: 1700000009000,
		Nodes: map[string]UsageNode{
			"tokyo":  {Up: 1000, Down: 2000},
			"berlin": {Up: 50, Down: 50},
			"":       {Up: 9, Down: 9}, // 脏数据：空节点名不该进表
		},
	})
	usageConn(r, "tokyo", 7, 11, true)

	snap := r.Snapshot()
	by := map[string]NodeTraffic{}
	for _, n := range snap.ByNode {
		by[n.Node] = n
	}
	if _, ok := by[""]; ok {
		t.Errorf("空节点名进了表: %+v", snap.ByNode)
	}
	// berlin 这次一条都没跑，但它上次的量必须还在——配额问的正是这个。
	if b := by["berlin"]; b.Up != 0 || b.Down != 0 || b.Conns != 0 || b.Prior != 100 {
		t.Errorf("上次用过、这次没碰的节点应当带着一行累计: %+v", b)
	}
	if tk := by["tokyo"]; tk.Up != 7 || tk.Down != 11 || tk.Prior != 3000 {
		t.Errorf("tokyo 本次与累计混了: %+v", tk)
	}
	// 排的是累计：berlin 只有 100，tokyo 是 3018，大的在前。
	if snap.ByNode[0].Node != "tokyo" {
		t.Errorf("没按累计排: %+v", snap.ByNode)
	}
	if snap.PriorSince != 1700000000000 || snap.PriorSavedAt != 1700000009000 {
		t.Errorf("累计的两个时刻没投影出去: %+v", snap)
	}
}

func TestResetKeepsCumulativeAndClearWipesIt(t *testing.T) {
	r := NewRegistry(10, 0)
	r.ApplyPrior(UsageState{Since: 1, Nodes: map[string]UsageNode{"tokyo": {Up: 40, Down: 60}}})
	usageConn(r, "tokyo", 5, 5, true)

	r.Reset()
	snap := r.Snapshot()
	if len(snap.ByNode) != 1 {
		t.Fatalf("清零之后 tokyo 那行该留着（累计还在），得到 %+v", snap.ByNode)
	}
	if n := snap.ByNode[0]; n.Up != 0 || n.Down != 0 || n.Conns != 0 || n.Prior != 100 {
		t.Errorf("「清空统计」把累计也清了，那是另一个按钮的射程: %+v", n)
	}

	r.ClearUsageCumulative()
	snap = r.Snapshot()
	if len(snap.ByNode) != 0 {
		t.Errorf("累计也清零之后不该再有行: %+v", snap.ByNode)
	}
	if snap.PriorSince == 0 || snap.PriorSince > time.Now().UnixMilli() {
		t.Errorf("清零要把起点拨到当下，否则「自何时起」这句没法说: %d", snap.PriorSince)
	}
	if snap.PriorSavedAt != 0 {
		t.Errorf("没有账了就不该还有「上次落盘」: %d", snap.PriorSavedAt)
	}
}

func TestUsageFlushWritesOncePerChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml.usage.json")
	r := NewRegistry(10, 0)
	r.EnableUsage(path)
	if !r.HasUsageFile() {
		t.Fatal("EnableUsage 之后该知道这份账要留住")
	}

	usageConn(r, "tokyo", 100, 200, true)
	r.maybeFlushUsage()
	first, err := LoadUsage(path)
	if err != nil || first.Nodes["tokyo"].Up != 100 {
		t.Fatalf("第一次落盘没写对: %+v err=%v", first, err)
	}

	// 内容没变就不该再碰盘——这一条是"面板开着但什么都没跑"时的成本上限。
	fi, _ := os.Stat(path)
	time.Sleep(15 * time.Millisecond)
	r.maybeFlushUsage()
	if fi2, _ := os.Stat(path); !fi2.ModTime().Equal(fi.ModTime()) {
		t.Error("账没变却重写了一次文件")
	}

	usageConn(r, "tokyo", 1, 1, true)
	r.maybeFlushUsage()
	second, _ := LoadUsage(path)
	if second.Nodes["tokyo"].Up != 101 {
		t.Errorf("变了之后没落新账: %+v", second)
	}
	// 累计是**合成**的：基数不该因为落盘而翻倍。
	if got := second.Nodes["tokyo"].Down; got != 201 {
		t.Errorf("下行对不上（翻倍说明基数被自己吃进去了）: %d", got)
	}
}

// 一条从没收尾的长连接，落盘时也要带上它已经跑掉的量。
// 只写"已收尾的"那份账，后果是挂了一整天的那条隧道在崩溃后凭空归零。
func TestUsageIncludesLiveConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "u.json")
	r := NewRegistry(10, 0)
	r.EnableUsage(path)
	usageConn(r, "tokyo", 4000, 5000, false) // 不 End，就让它一直跑着
	r.maybeFlushUsage()

	st, err := LoadUsage(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := st.Nodes["tokyo"]; n.Up != 4000 || n.Down != 5000 {
		t.Errorf("在跑的连接没进账本: %+v", n)
	}
}

// 关掉采样 goroutine 时补一次落盘：用户是"用完就 kill -TERM"的，
// 最后那一段流量最容易正好落在两次定时落盘之间。
func TestStopSamplerFlushes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "u.json")
	r := NewRegistry(10, 8)
	r.EnableUsage(path)
	r.StartSampler()
	usageConn(r, "berlin", 10, 20, true)
	r.StopSampler()

	st, err := LoadUsage(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := st.Nodes["berlin"]; n.Up != 10 || n.Down != 20 {
		t.Errorf("StopSampler 没补那一次落盘: %+v", st)
	}
}

// 没开账本（CLI 那条路）时一个字节都不该写。
func TestNoUsagePathMeansNoWrites(t *testing.T) {
	dir := t.TempDir()
	r := NewRegistry(10, 0)
	usageConn(r, "tokyo", 1, 1, true)
	if err := r.FlushUsage(); err != nil {
		t.Fatal(err)
	}
	r.maybeFlushUsage()
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("没配路径却往目录里写了东西: %v", entries)
	}
}

// Refuse 记的是"根本没建起来的连接"。它必须出现在表里（用户点开这一页
// 就是因为打不开），但一个字节都不该进账，也不该进各节点用量那张表。
func TestRefuseShowsUpWithoutBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "u.json")
	r := NewRegistry(10, 0)
	r.EnableUsage(path)
	usageConn(r, "tokyo", 10, 20, true)
	r.Refuse("socks5", "127.0.0.1:5001", "example.com:443",
		router.Result{Host: "example.com", Port: "443", Policy: outbound.PolicyProxy, Matched: "FINAL", Outbound: "PROXY", Node: "tokyo"},
		"dial tcp: connection refused")

	snap := r.Snapshot()
	if len(snap.Active) != 0 {
		t.Errorf("失败的那条不该出现在活跃表里: %+v", snap.Active)
	}
	var bad *ConnView
	for i := range snap.History {
		if snap.History[i].Err != "" {
			bad = &snap.History[i]
		}
	}
	if bad == nil {
		t.Fatalf("失败没被记进历史: %+v", snap.History)
	}
	if bad.Host != "example.com" || bad.Port != "443" {
		t.Errorf("目标没拆开: %+v", bad)
	}
	if bad.Up != 0 || bad.Down != 0 {
		t.Errorf("失败的那条带了字节: %+v", bad)
	}
	// 判定要留住：那一行得说得出"它本来打算怎么走、按哪条规则"，
	// 否则用户看到的仍然只是一个没有来由的失败。
	if bad.Matched != "FINAL" || bad.Outbound != "PROXY" || bad.Node != "tokyo" {
		t.Errorf("失败的那条丢了路由判定: %+v", bad)
	}
	// 表里有几行，"累计连接"就得是几——不然这两个数会当着用户的面互相打脸。
	if snap.TotalConns != uint64(len(snap.History)) {
		t.Errorf("累计连接 %d 与表里 %d 行对不上", snap.TotalConns, len(snap.History))
	}
	// 零字节的失败不新增用量行，但它把"这条本来要走去 tokyo"这件事记在了 tokyo 名下：
	// 那张表的"条数"是**尝试数**，与下面那张表的行数必须一致（上面已经对过）。
	for _, n := range snap.ByNode {
		if n.Node == "" {
			t.Errorf("出现了一个没有去处的用量行: %+v", snap.ByNode)
		}
	}
	r.maybeFlushUsage()
	if st, err := LoadUsage(path); err != nil || st.Nodes["tokyo"].Down != 20 || len(st.Nodes) != 1 {
		t.Errorf("账本里混进了失败的量: %+v err=%v", st, err)
	}
}

// 目标写法五花八门（IPv6、光秃秃的主机名），拆不开也得记，不能把这条丢掉。
func TestRefuseKeepsUnparsableTargets(t *testing.T) {
	r := NewRegistry(10, 0)
	r.Refuse("http", "127.0.0.1:1", "not-a-host-port", router.Result{}, "boom")
	h := r.Snapshot().History
	if len(h) != 1 || h[0].Host != "not-a-host-port" || h[0].Port != "" || h[0].Err != "boom" {
		t.Errorf("拆不开的目标被改写了: %+v", h)
	}
}

// 拨不通也要算一次命中。规则页那一列说的是"这条规则的判定被用过几次"，
// 而"按它走之后连接全失败"恰恰是最需要被数到的一次——漏了它，
// 屏幕上会是：流量页里这条规则的连接一行行红着，规则页写「命中 0」。
func TestRefuseCountsRuleHit(t *testing.T) {
	const rule = "DOMAIN-SUFFIX,example.org,PROXY"
	r := NewRegistry(10, 0)
	r.Refuse("socks5", "127.0.0.1:1", "a.example.org:443", router.Result{Host: "a.example.org", Matched: rule}, "refused")

	if got := r.RuleHits()[rule]; got != 1 {
		t.Fatalf("失败的那条没算命中: %d", got)
	}
	// 建起来的那条在 Begin 已经记过一次，收尾不能再记一遍。
	usageConn(r, "tokyo", 1, 1, true)
	r2 := NewRegistry(10, 0)
	c := r2.Begin("socks5", "127.0.0.1:2", router.Result{Host: "b.example.org", Matched: rule})
	r2.End(c)
	if got := r2.RuleHits()[rule]; got != 1 {
		t.Errorf("一条正常连接被数了两次: %d", got)
	}
}

// 「拨不通」的总数必须撑得过环形缓冲。
//
// 这一格是总览上"有没有出事"的读数，而连接表只留最近 500 条：
// 如果那个数是从表里数出来的，跑久之后它会被最近的正常流量洗成 0，
// 于是"面板说一切正常"与"这一小时一直在失败"能同时成立。
func TestFailedTotalSurvivesHistoryRing(t *testing.T) {
	r := NewRegistry(2, 0) // 历史只留两条
	for i := 0; i < 5; i++ {
		r.Refuse("socks5", "127.0.0.1:1", fmt.Sprintf("dead%d.example:443", i), router.Result{Matched: "FINAL"}, "refused")
	}
	snap := r.Snapshot()
	if len(snap.History) != 2 {
		t.Fatalf("前置条件：环形缓冲该只留两条，得到 %d", len(snap.History))
	}
	if snap.TotalFailed != 5 {
		t.Errorf("总数被环形缓冲洗掉了：表里剩 %d 条，实际失败 5 次，读数 %d", len(snap.History), snap.TotalFailed)
	}
	usageConn(r, "tokyo", 5, 5, true)
	if got := r.Snapshot().TotalFailed; got != 5 {
		t.Errorf("正常连接被算进失败数了: %d", got)
	}
	r.Reset()
	if got := r.Snapshot().TotalFailed; got != 0 {
		t.Errorf("「清空统计」没清掉失败数: %d", got)
	}
}
