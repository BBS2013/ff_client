package service

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"wps_app/internal/logx"
)

// stamps 把 "路径, 版本, 路径, 版本…" 摆成一份指纹。版本号进 mod，
// 所以 stamps("a","1") 与 stamps("a","2") 是真的两个不同指纹。
func stamps(pairs ...string) map[string]fileStamp {
	out := map[string]fileStamp{}
	for i := 0; i+1 < len(pairs); i += 2 {
		v, err := strconv.Atoi(pairs[i+1])
		if err != nil {
			panic(pairs[i+1])
		}
		out[pairs[i]] = fileStamp{mod: time.Unix(int64(v), 0), size: 10, ok: true}
	}
	return out
}

// TestReloadNeededIsStabilityGated 判断只有一句话，但它决定监视器会不会把
// 编辑器写到一半的文件当成"新规则"去编译。
func TestReloadNeededIsStabilityGated(t *testing.T) {
	base := stamps("a", "1")
	changed := stamps("a", "2")
	cases := []struct {
		name      string
		base      map[string]fileStamp
		prev, now map[string]fileStamp
		want      bool
	}{
		{"还没基线，先记住现状", nil, base, changed, false},
		{"没变化", base, base, base, false},
		{"变了，但上一轮就是这个值 → 落定了", base, changed, changed, true},
		{"正在变（上一轮还不是这个值）→ 等一等", base, base, changed, false},
		// 新文件刚出现的那一轮也不动：订阅缓存正在写、编辑器刚把临时文件换名进来，
		// 都属于"还在变"。要连续两轮看到同一个新状态才算落定。
		{"新增文件，这一轮才刚看到", base, base, stamps("a", "1", "b", "1"), false},
		{"新增文件，上一轮就看到了", base, stamps("a", "1", "b", "1"), stamps("a", "1", "b", "1"), true},
		{"少了一个文件（已落定）", stamps("a", "1", "b", "1"), stamps("a", "1"), stamps("a", "1"), true},
	}
	for _, c := range cases {
		if got := reloadNeeded(c.base, c.prev, c.now); got != c.want {
			t.Errorf("%s: reloadNeeded = %v, 期望 %v", c.name, got, c.want)
		}
	}
}

func TestSameStampSetCountsMissingAsDifference(t *testing.T) {
	here := map[string]fileStamp{"a": statFile(t.Name() + "/does-not-exist")}
	also := map[string]fileStamp{"a": {}}
	if !sameStampSet(here, also) {
		t.Error("两个都读不到的条目应当算相同，否则每轮都会判成『在变』")
	}
	if sameStampSet(here, map[string]fileStamp{"a": {mod: time.Now(), size: 1, ok: true}}) {
		t.Error("一个读得到、一个读不到不该算相同")
	}
	if sameStampSet(map[string]fileStamp{"a": {}}, map[string]fileStamp{"a": {}, "b": {}}) {
		t.Error("文件数不同不该算相同")
	}
}

// TestRulesWatchReloadsOnlyAfterEditsSettle 端到端走一遍：
// 改 include 进来的那个文件 → 第一轮不该重载（可能还在写）→ 第二轮才重载。
//
// 盯的是 user-rules.txt 而不是主规则文件：主文件的 mtime 谁都会想到去看，
// 而用户真正在编辑的往往是 #include 进来的那一份。
func TestRulesWatchReloadsOnlyAfterEditsSettle(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	if err := os.WriteFile(userFile, []byte("DOMAIN-SUFFIX,one.example,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(cfgPath, nil)
	if err := svc.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer svc.discardPrepared()

	svc.noteRulesReloaded()
	dom0 := domainCount(t, svc)
	if dom0 == 0 {
		t.Fatal("Prepare 之后规则集是空的，用例没构造起来")
	}

	// 追加一条（size 一定变，mtime 粒度再粗也拦不住这次判定）。
	if err := os.WriteFile(userFile,
		[]byte("DOMAIN-SUFFIX,one.example,PROXY\nDOMAIN-SUFFIX,two.example,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	svc.checkRulesChanged()
	if got := domainCount(t, svc); got != dom0 {
		t.Fatalf("第一轮就重载了（%d → %d）：编辑器写一半的文件会被当成新规则", dom0, got)
	}
	// 第二轮：同一个新指纹，说明改动已经落定。
	svc.checkRulesChanged()
	if got := domainCount(t, svc); got <= dom0 {
		t.Fatalf("改动落定后仍没重载：域名条数 %d → %d", dom0, got)
	}
	// 之后不该再来一次：基线已经随成功重载刷新。
	before := domainCount(t, svc)
	svc.checkRulesChanged()
	svc.checkRulesChanged()
	if got := domainCount(t, svc); got != before {
		t.Errorf("重载之后又被触发了：%d → %d（基线没刷新）", before, got)
	}
}

func domainCount(t *testing.T, svc *Service) int {
	t.Helper()
	dom, _ := svc.Router().Engine().Stats()
	return dom
}

// TestAutoReloadHappensExactlyOnce 盯的是"重载了几次"，不是"条数变没变"。
//
// 为什么单开一条：上面那条用例用条数断言"之后不该再来一次"，那是空断言——
// 把 Reload 里的基线刷新删掉，监视器会连着再重载两遍，但每次读的都是同一个文件，
// 条数一模一样，用例照样绿。这条靠数日志行数，删掉基线刷新就会红。
// 判据要挑两种实现真的区分得开的那一端。
func TestAutoReloadHappensExactlyOnce(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	if err := os.WriteFile(userFile, []byte("DOMAIN-SUFFIX,one.example,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(cfgPath, nil)
	if err := svc.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer svc.discardPrepared()
	svc.noteRulesReloaded()

	// 必须显式抬级别：那份配置写的是 log.level=error，Prepare 会把它应用到全局，
	// 而"已自动重载"是条 INFO——不抬起来钩子一条也收不到，用例就会以
	// "触发了 0 次"失败，看着像功能坏了，其实是日志被门掉了。
	logx.SetLevel(logx.LevelInfo)
	t.Cleanup(func() { logx.SetLevel(logx.LevelInfo) })

	var mu sync.Mutex
	var hits int
	remove := logx.AddHook(func(_ logx.Level, msg string, _ time.Time) {
		if strings.Contains(msg, "检测到规则文件变化") {
			mu.Lock()
			hits++
			mu.Unlock()
		}
	})
	defer remove()

	if err := os.WriteFile(userFile,
		[]byte("DOMAIN-SUFFIX,one.example,PROXY\nDOMAIN-SUFFIX,two.example,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// 第一轮看到新指纹但还没落定；第二轮落定 → 重载；后两轮应当彻底安静。
	for i := 0; i < 4; i++ {
		svc.checkRulesChanged()
	}
	mu.Lock()
	got := hits
	mu.Unlock()
	if got != 1 {
		t.Errorf("自动重载触发了 %d 次，期望恰好 1 次（成功重载后基线没刷新？）", got)
	}
}

// TestRulesWatchStopsWithService 起停要成对：Stop 之后还留着 goroutine，
// 就是在一个没有监听端口的进程里继续每 5 秒 Stat 一轮。
func TestRulesWatchStopsWithService(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)
	svc.startRulesWatch()
	svc.mu.Lock()
	running := svc.rulesWatchCancel != nil
	svc.mu.Unlock()
	if !running {
		t.Fatal("startRulesWatch 之后没有退出句柄")
	}
	svc.stopRulesWatch()
	svc.mu.Lock()
	after := svc.rulesWatchCancel
	svc.mu.Unlock()
	if after != nil {
		t.Error("stopRulesWatch 没清掉句柄，Stop 之后循环还活着")
	}
	// 重复停要安全：Stop 与 Close 都可能走到这里。
	svc.stopRulesWatch()
	// 重复起也只应有一个循环。
	svc.startRulesWatch()
	svc.startRulesWatch()
	svc.mu.Lock()
	again := svc.rulesWatchCancel
	svc.mu.Unlock()
	if again == nil {
		t.Error("重启监视失败")
	}
	svc.stopRulesWatch()
}

// TestRulesWatchViewNotRunning 服务没在跑时那一栏必须说"没在监视"。
// 画成空列表会被读成"没有文件要看"，而真实情况是"看了也不生效"。
func TestRulesWatchViewNotRunning(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)
	v := svc.RulesWatchView()
	if v.Watching {
		t.Error("还没 Start 就报『在监视』")
	}
	if v.LastReload != "" {
		t.Errorf("本次运行还没过重载，lastReload 应当是空串，得到 %q", v.LastReload)
	}
	// 空列表本身没错，错的是"只报空列表"：界面必须靠 Watching=false 说清
	// 是"没在监视"，而不是"没有文件要看"。主文件路径由「内置规则集」那一栏负责印。
	if len(v.Files) != 0 {
		t.Errorf("引擎还没装配，不该报任何被监视的文件，得到 %+v", v.Files)
	}
}

// TestRulesWatchViewListsIncludedFiles 清单必须来自引擎真的打开过的文件，
// 而不是配置文件里那条 rules_file——用户编辑的往往是 #include 进来的那一份，
// 只报主文件就等于指着"这个会被监视"，实际改它却不动。
func TestRulesWatchViewListsIncludedFiles(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	if err := os.WriteFile(userFile, []byte("DOMAIN-SUFFIX,one.example,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(cfgPath, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	v := svc.RulesWatchView()
	if !v.Watching {
		t.Error("Start 之后应当报『在监视』")
	}
	var sawUser bool
	for _, f := range v.Files {
		if f.Path == userFile {
			sawUser = true
			if !f.Readable || f.ModTime == "" || f.Size == 0 {
				t.Errorf("读得到的文件应当带大小与时间，得到 %+v", f)
			}
		}
	}
	if !sawUser {
		t.Errorf("被监视的清单里没有 #include 进来的 %s，实际清单 %+v", userFile, v.Files)
	}
	if v.LastReload == "" {
		t.Error("Start 里已经成功加载过一轮，lastReload 不该是空")
	}
	if v.IntervalSec <= 0 {
		t.Errorf("间隔应当是个正数，得到 %d", v.IntervalSec)
	}
}

// TestRulesWatchViewReportsUnreadableFile 文件被删掉时那一行必须变成"读不到"。
// 报 size=0 + 空时间戳和"这是个空文件"在同一种画法里——那正是最容易看错的一格。
func TestRulesWatchViewReportsUnreadableFile(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	if err := os.WriteFile(userFile, []byte("DOMAIN-SUFFIX,one.example,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(cfgPath, nil)
	if err := svc.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer svc.discardPrepared()
	svc.noteRulesReloaded()

	if err := os.Remove(userFile); err != nil {
		t.Fatal(err)
	}
	v := svc.RulesWatchView()
	var found bool
	for _, f := range v.Files {
		if f.Path == userFile {
			found = true
			if f.Readable || f.ModTime != "" {
				t.Errorf("文件已删除，这一行应当报「读不到」，得到 %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("清单里没有那个被删掉的文件（引擎的 Sources 没记它？）")
	}
}
