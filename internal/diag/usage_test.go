package diag

// 诊断报告里"节点用量账本"那一节。
//
// 这一节存在的理由是：那一栏读数**故意是不全的**（每分钟落一次盘，崩溃会丢掉最后一段）。
// 报告如果只印一串字节，别人拿着它问"为什么面板说 68% 而我记得跑满了"，
// 还得再解释一遍——所以 caveat 与账本同处一节，读的人一次看全。

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"wps_app/internal/metrics"
)

func writeLedger(t *testing.T, cfgPath string, st metrics.UsageState) string {
	t.Helper()
	path := metrics.UsagePath(cfgPath)
	body, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// writeCfgWithQuota 在 fixture 的 hk-1 上加一行配额。
// 用替换而不是整份重写：那两行口令是掩码用例要的东西，别在别的用例里改动它。
func writeCfgWithQuota(t *testing.T, cfgPath, quota string) {
	t.Helper()
	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	patched := strings.Replace(string(body),
		`  - name: "hk-1"`+"\n",
		`  - name: "hk-1"`+"\n"+`    quota: "`+quota+`"`+"\n", 1)
	if patched == string(body) {
		t.Fatal("fixture 里找不到 hk-1 那一行，配额加不上")
	}
	if err := os.WriteFile(cfgPath, []byte(patched), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReportShowsQuotaUsagePerNode(t *testing.T) {
	cfg := cfgWith(t, "./assets/geoip.mmdb")
	now := time.Now().UnixMilli()
	writeLedger(t, cfg, metrics.UsageState{
		SavedAt: now - 90_000,
		Since:   now - 48*3600*1000,
		Nodes:   map[string]metrics.UsageNode{"hk-1": {Up: 1e9, Down: 3e9}},
	})
	body := run(t, cfg)
	section := sectionOf(body, "节点用量账本")
	if section == "" {
		t.Fatalf("报告里没有账本那一节:\n%s", body)
	}
	if !strings.Contains(section, "hk-1") {
		t.Errorf("账本那一节没列出节点:\n%s", section)
	}
	if !strings.Contains(section, "4.00 GB") {
		t.Errorf("累计量没换算成能读的档位:\n%s", section)
	}
	// 没设配额的节点要明说"没设"，而不是留一个空位让人以为漏印了。
	if !strings.Contains(section, "没设配额") {
		t.Errorf("没配 quota 的节点应当写明没设:\n%s", section)
	}
	if !strings.Contains(section, "只会比真实用量少") {
		t.Errorf("少了那句 caveat，这一节的数字就会被当成精确值:\n%s", section)
	}
}

func TestReportShowsQuotaPercent(t *testing.T) {
	cfg := cfgWith(t, "./assets/geoip.mmdb")
	writeCfgWithQuota(t, cfg, "10GB")
	writeLedger(t, cfg, metrics.UsageState{
		SavedAt: time.Now().UnixMilli(),
		Since:   time.Now().Add(-24 * time.Hour).UnixMilli(),
		Nodes:   map[string]metrics.UsageNode{"hk-1": {Up: 3e9, Down: 3.7e9}},
	})
	section := sectionOf(run(t, cfg), "节点用量账本")
	if !strings.Contains(section, `配额 10GB`) {
		t.Errorf("配额原文没出来（要的是人写的那句，不是换算后的 GB 数）:\n%s", section)
	}
	// 6.7 / 10 = 67%
	if !strings.Contains(section, "已用 67.0%") {
		t.Errorf("百分比不对:\n%s", section)
	}
}

// 账本里有、配置里已经没有的节点：改名或删除之后旧账还挂在盘上。
// 不写出来，人会觉得"这个节点我早删了怎么还有量"，然后怀疑程序在瞎记。
func TestReportNamesGhostNodes(t *testing.T) {
	cfg := cfgWith(t, "./assets/geoip.mmdb")
	writeLedger(t, cfg, metrics.UsageState{
		SavedAt: time.Now().UnixMilli(),
		Since:   1,
		Nodes: map[string]metrics.UsageNode{
			"hk-1":     {Up: 1, Down: 1},
			"old-name": {Up: 5e9, Down: 5e9},
			"REJECT":   {Up: 7, Down: 7}, // 被拦的不占账，也不该出现在这里
			"DIRECT":   {Up: 4e6, Down: 4e6},
		},
	})
	section := sectionOf(run(t, cfg), "节点用量账本")
	if !strings.Contains(section, "old-name") || !strings.Contains(section, "配置里已经没有这个节点") {
		t.Errorf("旧名字的账没单独说出来:\n%s", section)
	}
	if strings.Contains(section, "REJECT") {
		t.Errorf("REJECT 占了一行，而它一个字节都没有:\n%s", section)
	}
	// DIRECT 是"这些字节没走任何节点"那个桶，从来不是配置里的节点：
	// 把它报成"已删除的节点留下的旧账"是在说假话。这条是拿真账本跑出来的。
	// 但也不能干脆不印——那 12MB 是真经过这台机器的。
	if !strings.Contains(section, "DIRECT") {
		t.Errorf("直连那一桶的量从报告里消失了:\n%s", section)
	}
	if strings.Contains(section, "DIRECT") && !strings.Contains(section, "直连：这些字节没走任何节点") {
		t.Errorf("DIRECT 出现了却没说清它是什么:\n%s", section)
	}
	if strings.Contains(section, "DIRECT  （配置里已经没有这个节点") {
		t.Errorf("DIRECT 被当成幽灵节点了:\n%s", section)
	}
}

// 新格式的账本：要说清"面板这一栏只显示本次会话"，而不是安静地什么都不印。
func TestReportHandlesNewerLedger(t *testing.T) {
	cfg := cfgWith(t, "./assets/geoip.mmdb")
	path := metrics.UsagePath(cfg)
	newer := `{"v":99,"savedAt":1,"since":1,"nodes":{"hk-1":{"up":1,"down":1}}}`
	if err := os.WriteFile(path, []byte(newer), 0o600); err != nil {
		t.Fatal(err)
	}
	section := sectionOf(run(t, cfg), "节点用量账本")
	for _, want := range []string{"新版本", "只显示本次会话", "用更新的版本"} {
		if !strings.Contains(section, want) {
			t.Errorf("那一节里没提 %q:\n%s", want, section)
		}
	}
	// 文件不能被报告改掉：它只是版本新，不是坏。
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("报告把新格式账本挪走了: %v", err)
	}
	if string(body) != newer {
		t.Error("报告改写了它不认识的那份账本")
	}
}

func TestReportSaysNoLedgerRatherThanNothing(t *testing.T) {
	cfg := cfgWith(t, "./assets/geoip.mmdb")
	section := sectionOf(run(t, cfg), "节点用量账本")
	if !strings.Contains(section, "还没有账本") {
		t.Errorf("没有账本时这一节该说一句，而不是整节消失:\n%s", section)
	}
}

// 账本坏掉时不能写成"没有账"：那是两件事，而看报告的人分不出来。
func TestReportDistinguishesCorruptLedger(t *testing.T) {
	cfg := cfgWith(t, "./assets/geoip.mmdb")
	writeLedger(t, cfg, metrics.UsageState{Nodes: map[string]metrics.UsageNode{"hk-1": {Up: 1, Down: 1}}})
	if err := os.WriteFile(metrics.UsagePath(cfg), []byte("{坏掉的 JSON"), 0o600); err != nil {
		t.Fatal(err)
	}
	section := sectionOf(run(t, cfg), "节点用量账本")
	if !strings.Contains(section, "读不出") {
		t.Errorf("坏账本没被说成坏:\n%s", section)
	}
	if strings.Contains(section, "还没有账本") {
		t.Errorf("坏掉被说成了\"没有\"，那是把人往错方向引:\n%s", section)
	}
}

// sectionOf 从报告里切出某一节（到下一个空行为止）。
// 不整篇匹配：其它节的内容会变，断言钉在自己那一节上才不会互相牵连。
func sectionOf(body, title string) string {
	i := strings.Index(body, title)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	if j := strings.Index(rest, "\n\n"); j >= 0 {
		return rest[:j]
	}
	return rest
}
