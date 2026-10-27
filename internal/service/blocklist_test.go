// 拦截名单批量维护的验收：粘贴一大段、以及把冗余条目清掉。
//
// 这里动的是真实的配置读写路径（写盘 + 备份 + 热生效），所以断言落在三处：
// 逐行记账的数字、磁盘上真正写进去的东西、以及运行中引擎的实际判定。
package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wps_app/internal/config"
)

func blockEnv(t *testing.T, block ...string) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	assets := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(assets, "rules.txt")
	if err := os.WriteFile(main, []byte("DOMAIN-SUFFIX,keep.test,PROXY\nFINAL,DIRECT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	// 用原始字符串写 YAML：里面满是双引号，转义一层比读一遍更难核对。
	cfgBody := fmt.Sprintf(`proxies:
  - name: "n1"
    server: { addr: "127.0.0.1:14499", auth: "x" }
active: n1
mode: rule
inbounds:
  - { type: socks5, listen: "127.0.0.1:0" }
geoip: { path: %q }
rules_file: %q
log: { level: "error" }
`, filepath.Join(assets, "missing.mmdb"), main)
	if len(block) > 0 {
		cfgBody += "block:\n  domains:\n"
		for _, d := range block {
			cfgBody += fmt.Sprintf("    - %q\n", d)
		}
	}
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(cfgPath, nil), cfgPath
}

func blockDomainsOnDisk(t *testing.T, cfgPath string) []string {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("读回配置失败: %v", err)
	}
	return cfg.Block.Domains
}

func TestParseBlockLine(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "裸域名", in: "ads.example.com", want: "ads.example.com"},
		{name: "大小写与空格抹平", in: "  Ads.Example.COM.  ", want: "ads.example.com"},
		{name: "AdGuard 写法", in: "||ads.example.com^", want: "ads.example.com"},
		{name: "带修饰符", in: "||ads.example.com^$third-party", want: "ads.example.com"},
		{name: "例外规则", in: "@@||ads.example.com^", wantErr: "例外规则"},
		{name: "清单头部", in: "[Adblock Plus 2.0]", wantErr: "头部标记"},
		{name: "hosts 一行多域名", in: "0.0.0.0 a.test b.test", wantErr: "一行里有多个域名"},
		{name: "带协议", in: "http://ads.example.com/x", wantErr: "不像域名"},
		{name: "空项", in: "  .  ", wantErr: "空项"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseBlockLine(c.in)
			if c.wantErr != "" {
				if err == nil {
					t.Fatalf("期望报错，得到 %q", got)
				}
				if !strings.Contains(err.Error(), c.wantErr) {
					t.Errorf("报错里没有 %q: %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不该报错: %v", err)
			}
			if got != c.want {
				t.Errorf("得到 %q，期望 %q", got, c.want)
			}
		})
	}
}

func TestAddBlockDomainsAccounting(t *testing.T) {
	svc, cfgPath := blockEnv(t, "existing.test")
	imp, err := svc.AddBlockDomains(strings.Join([]string{
		"# 这是注释",
		"! 这也是注释",
		"",
		"plain.test",
		"||adguard.test^",
		"||mod.test^$script",
		"plain.test",     // 同一次粘贴里重复
		"EXISTING.test",  // 文件里本来就有（大小写不同）
		"@@||safe.test^", // 例外规则：收进来就变成了拦
		"0.0.0.0 a.test b.test",
	}, "\n"))
	if err != nil {
		t.Fatalf("AddBlockDomains: %v", err)
	}
	if imp.Written != true {
		t.Error("Written 应为 true")
	}
	if imp.Total != 7 {
		t.Errorf("Total = %d，期望 7（注释与空行不计）", imp.Total)
	}
	if imp.Accepted != 3 {
		t.Errorf("Accepted = %d，期望 3（plain/adguard/mod）", imp.Accepted)
	}
	if imp.Existing != 2 {
		t.Errorf("Existing = %d，期望 2（文件里已有的 + 粘贴里重复的）", imp.Existing)
	}
	if len(imp.Rejected) != 2 {
		t.Fatalf("Rejected = %v，期望 2 条", imp.Rejected)
	}
	for _, r := range imp.Rejected {
		if !strings.Contains(r, "第 ") || !strings.Contains(r, "行") {
			t.Errorf("拒绝原因要指得出是第几行: %q", r)
		}
	}
	got := blockDomainsOnDisk(t, cfgPath)
	want := []string{"existing.test", "plain.test", "adguard.test", "mod.test"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("磁盘上的名单 = %v，期望 %v", got, want)
	}
}

// TestAddBlockDomainsAllRejectedLeavesFileAlone 覆盖"什么都没收下"这条路：
// 界面提示的是"没加上"，磁盘上也不该出现一次只改了排版的写入与备份。
func TestAddBlockDomainsAllRejectedLeavesFileAlone(t *testing.T) {
	svc, cfgPath := blockEnv(t, "keep.test")
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	imp, err := svc.AddBlockDomains("@@||a.test^\nhttp://b.test\n0.0.0.0 c.test d.test")
	if err != nil {
		t.Fatalf("AddBlockDomains: %v", err)
	}
	if imp.Written {
		t.Error("一条都没收下，Written 不该为 true")
	}
	if imp.Accepted != 0 || len(imp.Rejected) != 3 {
		t.Errorf("记账不对: %+v", imp)
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("配置被改动了")
	}
	if _, err := os.Stat(cfgPath + config.BackupSuffix); !os.IsNotExist(err) {
		t.Error("不该为一次什么都没变的操作留下备份文件")
	}
}

// TestAddBlockDomainsAlreadyThere 名单里有的再粘一遍：不写盘，但要把"本来就有"说出来。
func TestAddBlockDomainsAlreadyThere(t *testing.T) {
	svc, cfgPath := blockEnv(t, "a.test")
	imp, err := svc.AddBlockDomains("a.test\nb.test\nb.test")
	if err != nil {
		t.Fatalf("AddBlockDomains: %v", err)
	}
	if imp.Accepted != 1 || imp.Existing != 2 {
		t.Errorf("记账不对: %+v", imp)
	}
	if !imp.Written {
		t.Error("b.test 是新加的，Written 应为 true")
	}
	if got := blockDomainsOnDisk(t, cfgPath); len(got) != 2 {
		t.Errorf("磁盘上的名单 = %v", got)
	}
}

func TestAddBlockDomainsEmptyPaste(t *testing.T) {
	svc, _ := blockEnv(t)
	if _, err := svc.AddBlockDomains("# 只有注释\n\n   \n"); err == nil {
		t.Error("全是注释与空行时应报错")
	}
	if _, err := svc.AddBlockDomains(""); err == nil {
		t.Error("空文本应报错")
	}
}

// TestAddBlockDomainsReportsWhatItAddedButCovered 粘进来一条被更宽条目盖住的域名时，
// 必须当场说清楚"这一条什么也没多拦"——否则用户会以为加成功了。
func TestAddBlockDomainsReportsWhatItAddedButCovered(t *testing.T) {
	svc, _ := blockEnv(t, "example.test")
	imp, err := svc.AddBlockDomains("ads.example.test")
	if err != nil {
		t.Fatalf("AddBlockDomains: %v", err)
	}
	if len(imp.Dead) != 1 || !strings.Contains(imp.Dead[0], "example.test") {
		t.Errorf("Dead = %v，期望指出被 example.test 盖住", imp.Dead)
	}
	if v := svc.BlockList(); v.DeadTotal != 1 {
		t.Errorf("BlockList().DeadTotal = %d，期望 1", v.DeadTotal)
	}
}

// TestAddBlockDomainsAppliesLive 是这块功能的真正验收：
// 粘贴 → 写盘 → 运行中的引擎立刻拦下，一圈都不绕。
func TestAddBlockDomainsAppliesLive(t *testing.T) {
	svc, _ := blockEnv(t)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	if r, _ := svc.Probe("ads.test"); r.Policy != "DIRECT" {
		t.Fatalf("起点不该被拦: %+v", r)
	}
	if _, err := svc.AddBlockDomains("ads.test\n||cdn.test^"); err != nil {
		t.Fatalf("AddBlockDomains: %v", err)
	}
	res, err := svc.Probe("www.ads.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy != "REJECT" || !res.Live {
		t.Fatalf("粘贴后应立刻拦下（子域也算）: %+v", res)
	}
	if r, _ := svc.Probe("other.test"); r.Policy != "DIRECT" {
		t.Errorf("名单外的域名不该被拦: %+v", r)
	}
	if r, _ := svc.Probe("a.cdn.test"); r.Policy != "REJECT" {
		t.Errorf("AdGuard 写法那条也要生效: %+v", r)
	}
}

func TestPruneBlockDomainsKeepsBlocking(t *testing.T) {
	svc, cfgPath := blockEnv(t)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	if _, err := svc.AddBlockDomains("example.test\nads.example.test\ncdn.other.test"); err != nil {
		t.Fatalf("AddBlockDomains: %v", err)
	}
	removed, err := svc.PruneBlockDomains()
	if err != nil {
		t.Fatalf("PruneBlockDomains: %v", err)
	}
	if removed != 1 {
		t.Errorf("删掉 %d 条，期望 1（ads.example.test 被 example.test 盖住）", removed)
	}
	// 清理不许改判定：被删掉的那条本来就被留下的那条同样盖住。
	for _, h := range []string{"ads.example.test", "www.ads.example.test", "example.test", "zz.example.test", "cdn.other.test"} {
		r, _ := svc.Probe(h)
		if r.Policy != "REJECT" {
			t.Errorf("%s 清理后不再被拦（%s）——清理必须是纯粹的", h, r.Policy)
		}
	}
	if got := blockDomainsOnDisk(t, cfgPath); len(got) != 2 {
		t.Errorf("磁盘上的名单 = %v，期望只剩两条", got)
	}
	if v := svc.BlockList(); v.DeadTotal != 0 {
		t.Errorf("清理后还有 %d 条死条目: %v", v.DeadTotal, v.Dead)
	}
	if _, err := svc.PruneBlockDomains(); err != nil {
		t.Fatalf("第二次清理: %v", err)
	}
}

// TestPruneBlockDomainsNoopDoesNotTouchDisk 一条都删不掉时不写盘。
func TestPruneBlockDomainsNoopDoesNotTouchDisk(t *testing.T) {
	svc, cfgPath := blockEnv(t, "a.test", "b.test", "notb.test")
	removed, err := svc.PruneBlockDomains()
	if err != nil {
		t.Fatalf("PruneBlockDomains: %v", err)
	}
	if removed != 0 {
		t.Errorf("没有冗余却报删了 %d 条", removed)
	}
	if _, err := os.Stat(cfgPath + config.BackupSuffix); !os.IsNotExist(err) {
		t.Error("什么都没删却留下了备份文件")
	}
}

// TestBlockDeadSentencesIsCapped 抄来的名单能有几千条死条目，
// 面板每轮轮询都把它们搬过桥会卡——所以列表截断，总数照实给。
func TestBlockDeadSentencesIsCapped(t *testing.T) {
	list := []string{"test"}
	for i := 0; i < 250; i++ {
		list = append(list, fmt.Sprintf("d%d.test", i))
	}
	msgs, total := blockDeadSentences(list)
	if total != 250 {
		t.Errorf("总数 = %d，期望 250", total)
	}
	if len(msgs) != blockDeadCap {
		t.Errorf("列表给了 %d 条，期望截到 %d", len(msgs), blockDeadCap)
	}
	if msgs[0] == "" {
		t.Error("第一条不该是空句")
	}
}

// TestBlockListSameWhetherRulesetReadable 拦截名单那一栏不许因为"规则集读不读得到"而变样。
//
// 早先停着的时候这里绕道建一个引擎来拿归一化后的名单，于是规则集读得到走
// SetBlocklist（去重），读不到退回 NormalizeBlocklist（**不去重**）：
// 同一份配置，面板上的条数会因为另一个文件坏没坏而不一样，
// 而那一栏顶上写的还是同一句话。现在两条路合成一条，这一条钉住它别再分家。
func TestBlockListSameWhetherRulesetReadable(t *testing.T) {
	svc, _ := blockEnv(t,
		"Ads.Example.com",       // 大写
		"ads.example.com",       // 与上一条归一后同一条：只该留一份
		"track.example.net.",    // 结尾带点
		"  track.example.net  ", // 前后带空格：同上
	)
	good := svc.BlockList()
	if len(good.Domains) != 2 {
		t.Fatalf("去重后该剩 2 条，实际 %d: %v", len(good.Domains), good.Domains)
	}

	// 把规则集弄坏：读得到配置，读不到那几千条规则。
	// 这一栏说的是 block: 段的事，与那几千条无关，所以答案必须一个字都不变。
	cfgPath := good.Path
	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(body), `rules_file: "`, `rules_file: "/nope/`, 1)
	if broken == string(body) {
		t.Fatal("没能把 rules_file 改坏，这一条就没测到东西")
	}
	if err := os.WriteFile(cfgPath, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := svc.BlockList()
	if len(bad.Domains) != len(good.Domains) || strings.Join(bad.Domains, ",") != strings.Join(good.Domains, ",") {
		t.Fatalf("规则集读不到时名单变了样:\n 能读 %v\n 不能读 %v", good.Domains, bad.Domains)
	}
}
