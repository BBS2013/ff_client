package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
	"wps_app/internal/rules"
)

// routerResultFor 造一条"引擎判定成某条规则"的结果，用来喂统计。
// 命中依据一律由 rules.UserRule.Desc() 现算，测试不自己拼那个格式（理由见它的注释）。
func routerResultFor(matched, policy string) router.Result {
	return router.Result{
		Host: "probe.test", Port: "443", Matched: matched, Policy: outbound.Policy(policy),
	}
}

// userRulesEnv 造一份「主规则集 + 自定义规则文件」的最小可运行环境。
// 不依赖仓库里的 4429 条被墙表，也不依赖 GeoIP：判定结果必须完全由测试自己写下的规则决定。
func userRulesEnv(t *testing.T) (cfgPath, userFile string) {
	t.Helper()
	dir := t.TempDir()
	assets := filepath.Join(dir, "assets")
	if err := os.MkdirAll(assets, 0o755); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(assets, "rules.txt")
	body := "#include? ./user-rules.txt\nDOMAIN-SUFFIX,blocked.test,PROXY\nFINAL,DIRECT\n"
	if err := os.WriteFile(main, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "config.yaml")
	cfgBody := "proxies:\n" +
		"  - name: \"n1\"\n" +
		"    server: { addr: \"127.0.0.1:14499\", auth: \"x\" }\n" +
		"active: n1\n" +
		"mode: rule\n" +
		"inbounds:\n" +
		"  - { type: socks5, listen: \"127.0.0.1:0\" }\n" +
		"geoip: { path: \"" + filepath.Join(assets, "missing.mmdb") + "\" }\n" +
		"rules_file: \"" + main + "\"\n" +
		"log: { level: \"error\" }\n"
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, filepath.Join(assets, rules.UserRuleFileName)
}

// TestUserRulesApplyLive 是这块功能的真正验收：
// 面板加一条规则 → 文件落盘 → 运行中的进程热重载 → 决策立即变。
func TestUserRulesApplyLive(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	svc := New(cfgPath, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	// 起点：blocked.test 命中内置规则走代理，其它域名落到 FINAL=DIRECT。
	res, err := svc.Probe("a.blocked.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy != "PROXY" || !res.Live {
		t.Fatalf("初始判定不对: %+v", res)
	}
	if r, _ := svc.Probe("www.example.org"); r.Policy != "DIRECT" {
		t.Fatalf("兜底应是直连: %+v", r)
	}

	// 自定义规则把它改成直连——这条能盖住内置表，是「优先引在最前面」的意义所在。
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-SUFFIX", Value: "blocked.test", Policy: "DIRECT"}); err != nil {
		t.Fatalf("AddUserRule: %v", err)
	}
	res, err = svc.Probe("a.blocked.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy != "DIRECT" || !strings.Contains(res.Matched, "DOMAIN-SUFFIX,blocked.test,DIRECT") {
		t.Fatalf("自定义规则没生效: %+v", res)
	}

	// 文件里确实是这条，且旧版本被备份过。
	raw, err := os.ReadFile(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "DOMAIN-SUFFIX,blocked.test,DIRECT") {
		t.Fatalf("文件内容不对:\n%s", raw)
	}
	// 首次创建没有旧文件可备份。
	if _, err := os.Stat(userFile + ".bak"); err == nil {
		t.Error("第一次写入不该产生 .bak")
	}

	// 改策略（面板上点「改为走代理」）：同一条规则被覆盖，不是攒出第二条。
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-SUFFIX", Value: "blocked.test", Policy: "PROXY"}); err != nil {
		t.Fatal(err)
	}
	list, err := svc.ListUserRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Policy != "PROXY" {
		t.Fatalf("同键规则应被覆盖: %+v", list)
	}
	if r, _ := svc.Probe("a.blocked.test"); r.Policy != "PROXY" {
		t.Fatalf("改回走代理没生效: %+v", r)
	}
	// 第二次写入是覆盖，必须先留 .bak。
	if _, err := os.Stat(userFile + ".bak"); err != nil {
		t.Errorf("覆盖前应备份: %v", err)
	}

	// 删掉之后回到内置表的判定。
	if err := svc.RemoveUserRule("DOMAIN-SUFFIX", "blocked.test"); err != nil {
		t.Fatalf("RemoveUserRule: %v", err)
	}
	r, _ := svc.Probe("a.blocked.test")
	if r.Policy != "PROXY" || !strings.Contains(r.Matched, "DOMAIN-SUFFIX,blocked.test,PROXY") {
		t.Fatalf("删除后应回落到内置规则: %+v", r)
	}
	if err := svc.RemoveUserRule("DOMAIN", "没有这条"); err == nil {
		t.Error("删不存在的规则应报错")
	}
}

func TestUserRulesValidationAndPath(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	svc := New(cfgPath, nil)
	defer func() { _ = svc.Stop() }()

	got, err := svc.UserRulePath()
	if err != nil {
		t.Fatal(err)
	}
	if got != userFile {
		t.Fatalf("路径应跟着 rules_file 走: %s vs %s", got, userFile)
	}
	// 文件还不存在时列表是空的，不是错误——面板首次打开不该报错。
	list, err := svc.ListUserRules()
	if err != nil || len(list) != 0 {
		t.Fatalf("初始应为空: %v %+v", err, list)
	}
	if err := svc.AddUserRule(rules.UserRule{Type: "GEOIP", Value: "cn", Policy: "DIRECT"}); err == nil {
		t.Error("面板不该能往自定义文件里写 GEOIP")
	}
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN", Value: "  ", Policy: "PROXY"}); err == nil {
		t.Error("空域名应被拒绝")
	}
	// 非法输入不该留下文件。
	if _, err := os.Stat(userFile); err == nil {
		t.Error("校验失败时不该创建文件")
	}
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-KEYWORD", Value: "GitHub", Policy: "PROXY"}); err != nil {
		t.Fatal(err)
	}
	list, _ = svc.ListUserRules()
	if len(list) != 1 || list[0].Value != "github" || list[0].Type != "DOMAIN-KEYWORD" {
		t.Fatalf("规范化没做: %+v", list)
	}
}

// TestProbeWithoutRunningProcess 代理没跑时也要能查——
// 用户改完规则想先确认「这条会不会生效」，不该被「服务未运行」挡住。
func TestProbeWithoutRunningProcess(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)

	r, err := svc.Probe("x.blocked.test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Live {
		t.Error("没在跑，Live 应为 false")
	}
	if r.Policy != "PROXY" || r.Mode != "rule" {
		t.Fatalf("按磁盘规则算的结果不对: %+v", r)
	}
	// 模式为全局时，规则集不参与判定。
	if err := svc.SetMode("global"); err != nil {
		t.Fatal(err)
	}
	r, _ = svc.Probe("anything.test")
	if r.Policy != "PROXY" || r.Matched != "MODE,GLOBAL" {
		t.Fatalf("全局模式判定不对: %+v", r)
	}
}

// TestBlockListReflectsLiveEngine 名单那一栏必须报**正在生效**的那份。
//
// 报磁盘那份会在重载失败时骗人：文件里写着三个域名，引擎里还是旧的那套
// （甚至一个都没装），界面却说"这些都被拦着"。
// 模式也必须一起报：直连模式下名单整体让开，只列域名就是撒谎。
func TestBlockListReflectsLiveEngine(t *testing.T) {
	cfgPath := newTestConfigWithBlock(t, []string{"ads.example.com", "Track.Example.NET", "ads.example.com"})
	svc := New(cfgPath, nil)
	if err := svc.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	v := svc.BlockList()
	// 归一化后：小写、去重，两条变一条。
	if len(v.Domains) != 2 || v.Domains[0] != "ads.example.com" || v.Domains[1] != "track.example.net" {
		t.Fatalf("名单不对（应已归一化去重）: %+v", v)
	}
	if !v.Live {
		t.Error("Prepare 装配好引擎后就该算「正在生效」——判据要和 Probe 用同一个（引擎存在），" +
			"否则同一页会出现「查走向说在生效、拦截名单说没跑」")
	}
	if v.Mode != "rule" {
		t.Errorf("模式 = %q, 期望 rule", v.Mode)
	}
	if v.Path != cfgPath {
		t.Errorf("路径该指回配置文件好让用户去改: %q", v.Path)
	}

	// 引擎被换成一份没有名单的，界面就得跟着变——这正是"重载之后名单没补上"
	// 那个失效在界面上的表现。
	svc.Router().SetBlocklist(nil)
	if got := svc.BlockList(); len(got.Domains) != 0 {
		t.Errorf("引擎里没名单却仍显示有: %+v", got.Domains)
	}
}

// TestBlockListWhenNotRunning 没在跑时按磁盘配置显示，并明确标出未生效。
func TestBlockListWhenNotRunning(t *testing.T) {
	cfgPath := newTestConfigWithBlock(t, []string{"ads.example.com"})
	svc := New(cfgPath, nil)
	v := svc.BlockList()
	if v.Live {
		t.Error("没 Start 过不该报 live")
	}
	if len(v.Domains) != 1 || v.Domains[0] != "ads.example.com" {
		t.Errorf("未运行时应按磁盘名单显示: %+v", v.Domains)
	}
}

// TestAddRemoveBlockDomainLive 面板加/删拦截域名：文件与正在生效的引擎必须一起变。
//
// 只写文件不铺引擎的话，用户点完「添加」要再点一次「重载规则」才生效，
// 而界面上那条已经显示在名单里——显示的是"打算拦"，实际还没拦，最容易骗人。
func TestAddRemoveBlockDomainLive(t *testing.T) {
	cfgPath := newTestConfigWithBlock(t, []string{"ads.example.com"})
	svc := New(cfgPath, nil)
	if err := svc.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// 大小写、尾点、空格都该被抹平成同一条。
	saved, err := svc.AddBlockDomain("  Track.Example.NET. ")
	if err != nil {
		t.Fatalf("AddBlockDomain: %v", err)
	}
	// 回给界面的必须是抹平后的那一条：提示里显示的和文件里存的不一样，
	// 用户就会以为自己加了两条。
	if saved != "track.example.net" {
		t.Fatalf("AddBlockDomain 返回 %q, want track.example.net", saved)
	}
	v := svc.BlockList()
	if !v.Live {
		t.Error("加完应算正在生效")
	}
	if len(v.Domains) != 2 || v.Domains[1] != "track.example.net" {
		t.Fatalf("名单不对: %+v", v.Domains)
	}
	// 判定必须立刻跟着变——不重载也拦得住。
	if p, _ := svc.Router().Decide(context.Background(), "x.track.example.net"); p != "REJECT" {
		t.Errorf("加完没立即生效，判定 = %q", p)
	}

	// 幂等：同一条再来一次不该在文件里堆两份。
	if _, err := svc.AddBlockDomain("track.example.net"); err != nil {
		t.Fatalf("重复添加: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("回读: %v", err)
	}
	if len(cfg.Block.Domains) != 2 {
		t.Fatalf("重复项被追加成了 %d 条: %v", len(cfg.Block.Domains), cfg.Block.Domains)
	}

	if err := svc.RemoveBlockDomain("track.example.net"); err != nil {
		t.Fatalf("RemoveBlockDomain: %v", err)
	}
	if p, _ := svc.Router().Decide(context.Background(), "x.track.example.net"); p == "REJECT" {
		t.Error("删掉之后引擎还在拦")
	}
	if got := svc.BlockList(); len(got.Domains) != 1 {
		t.Errorf("删完名单 = %v, 期望只剩 1 条", got.Domains)
	}
}

// TestAddBlockDomainRejectsDangerousInput 危险写法必须在写盘之前就挡住。
// 单独一个 "." 归一化后是空后缀，等于拦下**所有**域名——
// 那是一键把整机网络关掉，绝不能让它进文件。
func TestAddBlockDomainRejectsDangerousInput(t *testing.T) {
	cfgPath := newTestConfigWithBlock(t, []string{"ads.example.com"})
	svc := New(cfgPath, nil)
	if err := svc.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "   ", ".", "..", "http://a.com/x", "a.com:8080", "10.0.0.0/8"} {
		if got, err := svc.AddBlockDomain(bad); err == nil {
			t.Errorf("危险输入 %q 竟然被接受（返回 %q）", bad, got)
		}
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("报错的那几次不该动过配置文件")
	}
	if got := svc.BlockList(); len(got.Domains) != 1 {
		t.Errorf("引擎名单被危险输入改动了: %+v", got.Domains)
	}
}

// TestRemoveBlockDomainUnknownIsError 删一条不在名单里的必须报错。
// 静默"成功"会让用户以为已经放开了，而实际拦着的那条一直没动。
func TestRemoveBlockDomainUnknownIsError(t *testing.T) {
	cfgPath := newTestConfigWithBlock(t, []string{"ads.example.com"})
	svc := New(cfgPath, nil)
	if err := svc.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := svc.RemoveBlockDomain("never-added.example"); err == nil {
		t.Fatal("删不存在的项应报错")
	}
	if got := svc.BlockList(); len(got.Domains) != 1 {
		t.Errorf("报错的那次删改动了名单: %+v", got.Domains)
	}
}

// TestMoveUserRuleChangesTheWinner 是这个功能真正的验收：
// 换顺序换出来的不是"排列不同"，而是"决策不同"。
//
// 面板加规则一律追加在末尾，所以后加的那条精确域名会被前面那条
// DOMAIN-SUFFIX 压住——它一条都生效不了，而界面上两条都明明在列。
// 能把精确那条挪到最前，才算给了用户一个解法，而不只是给了一份看不懂的名单。
func TestMoveUserRuleChangesTheWinner(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	svc := New(cfgPath, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-SUFFIX", Value: "shop.test", Policy: "PROXY"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN", Value: "www.shop.test", Policy: "DIRECT"}); err != nil {
		t.Fatal(err)
	}

	res, err := svc.Probe("www.shop.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy != "PROXY" || !strings.Contains(res.Matched, "DOMAIN-SUFFIX,shop.test") {
		t.Fatalf("起点应当是被 SUFFIX 那条压住: %+v", res)
	}

	if err := svc.MoveUserRule("DOMAIN", "www.shop.test", 0); err != nil {
		t.Fatalf("MoveUserRule: %v", err)
	}
	res, err = svc.Probe("www.shop.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy != "DIRECT" || !strings.Contains(res.Matched, "DOMAIN,www.shop.test,DIRECT") {
		t.Fatalf("挪到最前后判定没跟着变: %+v", res)
	}
	// 别的域名不受影响：这条钉子防止"移动"洗掉了名单里其他行的内容。
	res, err = svc.Probe("other.shop.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy != "PROXY" {
		t.Fatalf("SUFFIX 那条被移动改坏了: %+v", res)
	}

	raw, err := os.ReadFile(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(string(raw), "DOMAIN,www.shop.test") > strings.Index(string(raw), "DOMAIN-SUFFIX,shop.test") {
		t.Fatalf("文件里的顺序没换: %s", raw)
	}

	// 越界与找不到都要响——静默成功会写出一份没人要求过的名单。
	if err := svc.MoveUserRule("DOMAIN", "www.shop.test", 99); err == nil {
		t.Error("位置越界却成功了")
	}
	if err := svc.MoveUserRule("DOMAIN", "nope.test", 0); err == nil {
		t.Error("不存在的规则挪成功了")
	}
	// 名单读回来仍是两条，顺序改动没顺手删掉谁。
	list, err := svc.ListUserRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("移动后剩 %d 条: %+v", len(list), list)
	}
}

// TestUserRuleWarningsNamesTheShading 面板那一栏拿的是这句话，所以它必须由服务层给：
// 界面上自己算一份，两边对"归一化写法"的理解就会分家，
// 而分家的那一侧会当面说一条其实活着的规则是死的。
func TestUserRuleWarningsNamesTheShading(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)

	// 没启动也要能答：这一栏说的是磁盘上那份名单的问题，与代理跑不跑无关。
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-SUFFIX", Value: "example.com", Policy: "PROXY"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN", Value: "www.example.com", Policy: "DIRECT"}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.UserRuleWarnings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("报出 %d 条，想要 1: %+v", len(got), got)
	}
	if got[0].Kind != WarnShadow || got[0].Line != "DOMAIN,www.example.com,DIRECT" {
		t.Errorf("判语的形状不对: %+v", got[0])
	}
	if !strings.Contains(got[0].Why, "第 1 条 DOMAIN-SUFFIX,example.com,PROXY") ||
		!strings.Contains(got[0].Why, "挪到前面") {
		t.Errorf("那句话没说要紧的部分: %q", got[0].Why)
	}

	// 挪到前面之后同样的判据必须闭嘴——这句话是给"点顶"这个动作用的。
	if err := svc.MoveUserRule("DOMAIN", "www.example.com", 0); err != nil {
		t.Fatal(err)
	}
	got, err = svc.UserRuleWarnings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("换过顺序仍报死规则: %+v", got)
	}

	// 拦截名单排在整张规则表之前，所以被它盖住的那条同样是死的。
	if _, err := svc.AddBlockDomain("www.example.com"); err != nil {
		t.Fatal(err)
	}
	got, err = svc.UserRuleWarnings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0].Why, "拦截名单") {
		t.Fatalf("被拦截名单盖住的那条没报出来: %+v", got)
	}
}

// TestUserRuleWarningsNamesAMissingPinNode 覆盖 node= 那一类问题：
// 节点改名或删除之后，规则不会跟着改，而这类规则是**直接失败**、不回落当前节点的。
// 面板上只列一句"永远不会命中"会把这类完全不同的故障混进去，用户照着去点"顶"是白忙。
func TestUserRuleWarningsNamesAMissingPinNode(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)

	// 配置里只有一个节点 n1。
	if err := svc.AddUserRule(rules.UserRule{
		Type: "DOMAIN-SUFFIX", Value: "corp.test", Policy: "PROXY", Node: "美西",
	}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.UserRuleWarnings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("报出 %d 条，想要 1: %+v", len(got), got)
	}
	w := got[0]
	if w.Kind != WarnNodeMissing {
		t.Errorf("Kind = %q，期望 %q", w.Kind, WarnNodeMissing)
	}
	if !strings.Contains(w.Line, "node=美西") {
		t.Errorf("判语里的那一行没带上 node=: %q", w.Line)
	}
	for _, want := range []string{"美西", "不会回落", "日志"} {
		if !strings.Contains(w.Why, want) {
			t.Errorf("判语里没有 %q: %q", want, w.Why)
		}
	}

	// 把节点加回去（同一个名字）之后这条判语必须闭嘴——它说的是"现在连不通"。
	if err := svc.AddProfile(ProfileSpec{
		Name: "美西", Type: "hysteria2", Addr: "127.0.0.1:14501", Auth: "x",
	}); err != nil {
		t.Fatal(err)
	}
	got, err = svc.UserRuleWarnings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("节点已存在却仍报缺失: %+v", got)
	}
}

// TestUserRulePathRefusesToGuessWhenConfigIsUnreadable
// 配置读不到时唯一诚实的说法是"读不到"。
//
// 之前这里会把 UserRulePath 的兜底路径（相对当前目录的 ./assets/rules.txt）
// 当成真路径，于是代理一停（s.cfg 归 nil）+ 配置恰好坏掉这一刻，面板读到的是
// 另一个文件：改规则会存到用户根本不知道的地方。这一条盯住两件事——
// 路径定不出来时要报错，且那句报错要说清是哪个配置文件读不到；
// 整栏跟着报这个错，而不是凭空给出一份"看起来没问题"的名单。
func TestUserRulePathRefusesToGuessWhenConfigIsUnreadable(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)
	if err := svc.AddUserRule(rules.UserRule{
		Type: "DOMAIN-SUFFIX", Value: "corp.test", Policy: "PROXY", Node: "n1",
	}); err != nil {
		t.Fatal(err)
	}
	// 先确认这个前提：节点 n1 明明在配置里，此刻整栏是干净的。
	if got, err := svc.UserRuleWarnings(); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Fatalf("节点存在却报了判语: %+v", got)
	}

	// 把配置改成读不动（YAML 坏掉），并让服务手上的那份也丢掉，
	// 逼它真的走 config.Load 那条路——这正是"代理停了 + 配置坏掉"的现场。
	if err := os.WriteFile(cfgPath, []byte("proxies: [ 坏掉的\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc.mu.Lock()
	svc.cfg = nil
	svc.mu.Unlock()

	if _, err := svc.UserRulePath(); err == nil {
		t.Fatal("配置读不到，却还定得出自定义规则文件的位置")
	} else if !strings.Contains(err.Error(), cfgPath) {
		t.Errorf("报错里没说是哪个配置文件读不到: %v", err)
	}
	if _, err := svc.ListUserRules(); err == nil {
		t.Fatal("配置读不到，却凭空报出一份名单")
	}
	if err := svc.AddUserRule(rules.UserRule{
		Type: "DOMAIN-SUFFIX", Value: "x.test", Policy: "PROXY",
	}); err == nil {
		t.Error("配置读不到，却还把规则写进了某个文件")
	}
}

// TestAddUserRulesReportsEveryLine 批量粘贴要逐行给答案。
//
// 这里盯住三件最容易糊在一起的事：新增与覆盖必须分开数（不然用户不知道自己
// 改了谁的策略）、一行都没收下时文件必须原样不动（Written=false，提示也不许写"已保存"）、
// 这次粘进来的行如果装上但永远不会命中，要当场说出来。
func TestAddUserRulesReportsEveryLine(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	svc := New(cfgPath, nil)

	// 空文本：直接拒，别开一次没有意义的写盘。
	if _, err := svc.AddUserRules("\n# 全是注释\n", "DOMAIN-SUFFIX", "PROXY"); err == nil {
		t.Error("一行规则都没有，却成功了")
	}
	if _, err := os.Stat(userFile); !os.IsNotExist(err) {
		t.Errorf("什么都没添加却把文件建出来了: %v", err)
	}

	imp, err := svc.AddUserRules("notion.so\nDOMAIN-SUFFIX,example.cn,DIRECT\nbogus,line,NUKE\n", "DOMAIN-SUFFIX", "PROXY")
	if err != nil {
		t.Fatalf("AddUserRules: %v", err)
	}
	if imp.Total != 3 || imp.Accepted != 2 || imp.Updated != 0 || len(imp.Rejected) != 1 || !imp.Written {
		t.Fatalf("结果不对: %+v", imp)
	}
	if !strings.Contains(imp.Rejected[0], "第 3 行") {
		t.Errorf("被拒的那行没说清是第几行: %q", imp.Rejected[0])
	}

	list, err := svc.ListUserRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Type != "DOMAIN-SUFFIX" || list[0].Value != "notion.so" {
		t.Fatalf("名单不对: %+v", list)
	}

	// 再粘一次同样的：应该全部计成"覆盖"，一条新增都没有。
	imp, err = svc.AddUserRules("notion.so\n", "DOMAIN-SUFFIX", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	if imp.Accepted != 0 || imp.Updated != 1 {
		t.Fatalf("覆盖没和新增分开数: %+v", imp)
	}

	// 粘一条会被前面那条压住的：装上，但当场说是死的。
	imp, err = svc.AddUserRules("www.notion.so\n", "DOMAIN", "DIRECT")
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Dead) != 1 || !strings.Contains(imp.Dead[0], "永远不会命中") {
		t.Fatalf("这次粘进来的死规则没报出来: %+v", imp)
	}
	// 而死的那条属于这次粘贴——上一轮的东西不该跟着再报一遍。
	if strings.Contains(imp.Dead[0], "example.cn") {
		t.Errorf("报到了别人头上: %q", imp.Dead[0])
	}

	// 全部被拒：文件一个字都不许动，Written 必须是 false。
	before, err := os.ReadFile(userFile)
	if err != nil {
		t.Fatal(err)
	}
	imp, err = svc.AddUserRules("IP-CIDR,10.0.0.0/8,DIRECT\n最终,中文,PROXY\n", "DOMAIN-SUFFIX", "PROXY")
	if err != nil {
		t.Fatalf("全拒也该正常返回: %v", err)
	}
	if imp.Written || imp.Accepted+imp.Updated != 0 || len(imp.Rejected) != 2 {
		t.Fatalf("全被拒的结果不对: %+v", imp)
	}
	after, err := os.ReadFile(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("一条都没收下却改了文件:\n%s\n---\n%s", before, after)
	}
}

// TestPinnedNodeDecisionReachesTheProxy 钉节点这件事在"真配置 + 真路由"上要走通两段：
// 判定段（Probe 的命中依据里看得见 node=）和失败段（名字找不到时报的是"没这个节点"，
// 不是拿当前活动节点白等一次握手超时）。
//
// 失败段是这条用例的重点：回落到活动节点在界面上与正常工作一模一样，
// 只有把错误文案拿出来对一遍，才知道它真的没去代劳。
func TestPinnedNodeDecisionReachesTheProxy(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)
	if err := svc.AddProfile(ProfileSpec{
		Name: "美西", Type: config.ProtocolHysteria2, Addr: "us.example.invalid:443", Auth: "x",
	}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-SUFFIX", Value: "pinned.test", Policy: "PROXY", Node: "美西"}); err != nil {
		t.Fatalf("AddUserRule: %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	res, err := svc.Probe("a.pinned.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Policy != "PROXY" || !strings.Contains(res.Matched, "node=美西") {
		t.Fatalf("命中依据里看不出钉了哪个节点: %+v", res)
	}

	// 改名之后，原来那个名字必须查不到——而且报错要说的是"没这个节点"，
	// 不能是拿旧的隧道再拨一次，也不能悄悄改用当前活动节点。
	if err := svc.UpdateProfile("美西", ProfileSpec{Name: "美东"}); err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	if err := svc.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	srv, _, err := svc.rt.DialHost(context.Background(), "a.pinned.test:443", "")
	if err == nil {
		t.Fatal("钉着一个已经不存在的节点，连接却成功了")
	}
	if srv != nil {
		_ = srv.Close()
	}
	if !strings.Contains(err.Error(), "美西") {
		t.Errorf("错误里没说清是哪个节点找不到: %v", err)
	}
	// 名字对上之后就应当能重新装上（缓存被 mutate 整张丢掉之后必须能重建）。
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-SUFFIX", Value: "pinned.test", Policy: "PROXY", Node: "美东"}); err != nil {
		t.Fatalf("换到新名字失败: %v", err)
	}
	res, err = svc.Probe("a.pinned.test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Matched, "node=美东") {
		t.Errorf("换名后判定没跟上: %+v", res)
	}
}

// TestSetUserRuleDisabledAppliesLive 是"停用"这一档的真正验收：
// 点一下 → 落盘 → 运行中的引擎按新状态判定，全程不用重启也不用改文件。
//
// 起点借内置表那条 blocked.test→PROXY：自定义规则把它改成 DIRECT 才看得出"生效"，
// 停用之后必须**退回 PROXY**（不是退回 FINAL、也不是原地不动）。
// 最后再打开，回到 DIRECT——这一趟来回证明的是开关可逆，
// 而可逆依赖停用那一行没被整表回写弄丢别的东西。
func TestSetUserRuleDisabledAppliesLive(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	svc := New(cfgPath, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-SUFFIX", Value: "blocked.test", Policy: "DIRECT"}); err != nil {
		t.Fatal(err)
	}
	if r, _ := svc.Probe("a.blocked.test"); r.Policy != "DIRECT" {
		t.Fatalf("起点应是自定义规则的 DIRECT: %+v", r)
	}

	if err := svc.SetUserRuleDisabled("DOMAIN-SUFFIX", "blocked.test", true); err != nil {
		t.Fatal(err)
	}
	r, err := svc.Probe("a.blocked.test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Policy != "PROXY" {
		t.Fatalf("停用之后应退回内置表那条 PROXY，实际 %s（%s）", r.Policy, r.Matched)
	}
	// 文件里那一行必须还在，只是带着 off：停用不是删除。
	body, err := os.ReadFile(userFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "DOMAIN-SUFFIX,blocked.test,DIRECT,off") {
		t.Errorf("停用没写进文件（或把那一行删了）:\n%s", body)
	}

	if err := svc.SetUserRuleDisabled("DOMAIN-SUFFIX", "blocked.test", false); err != nil {
		t.Fatal(err)
	}
	if r, _ := svc.Probe("a.blocked.test"); r.Policy != "DIRECT" {
		t.Fatalf("重新启用后应回到 DIRECT，实际 %s（%s）", r.Policy, r.Matched)
	}
	body, _ = os.ReadFile(userFile)
	if strings.Contains(string(body), ",off") {
		t.Errorf("打开之后文件里还留着 off:\n%s", body)
	}

	// 名单里没有的那一条要报错，而不是安静地"改好了"。
	if err := svc.SetUserRuleDisabled("DOMAIN-SUFFIX", "never.added.test", true); err == nil {
		t.Error("停用了一条名单里根本没有的规则，却成功了")
	}
}

// TestSetUserRuleDisabledKeepsPinnedNode 开关不能顺手把钉住的节点弄丢。
// 后端是整条替换的思路，所以这一格专门钉一次。
func TestSetUserRuleDisabledKeepsPinnedNode(t *testing.T) {
	cfgPath, userFile := userRulesEnv(t)
	svc := New(cfgPath, nil)
	if err := svc.AddUserRule(rules.UserRule{
		Type: "DOMAIN-SUFFIX", Value: "corp.test", Policy: "PROXY", Node: "n1",
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetUserRuleDisabled("DOMAIN-SUFFIX", "corp.test", true); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(userFile)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(body))
	// 头部是固定文本，看最后一行即可。
	if i := strings.LastIndex(line, "\n"); i >= 0 {
		line = line[i+1:]
	}
	if !strings.Contains(line, "node=n1") {
		t.Errorf("停用把钉住的节点弄丢了: %q", line)
	}
	if !strings.HasSuffix(line, ",off") {
		t.Errorf("off 没在行尾: %q", line)
	}
	// 读回来还得同时是"钉着 n1"和"停用"。
	got, err := svc.ListUserRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Node != "n1" || !got[0].Disabled {
		t.Fatalf("两个字段没能同时留住: %+v", got)
	}
}

// TestUserRuleWarningsStaySilentOnADisabledRule 停用的那一条不该被报任何判语。
//
// 这一条是被「停用」那个功能新开出来的口子：判语说的是"走到它的连接会直接失败"，
// 可停用的那条**根本不参与匹配**，永远不会有连接走到它。
// 于是界面会指着一条用户刚刚亲手关掉的规则，警告它正在造成的那个失败——
// 而人关掉它恰恰是为了消掉这个失败。
// shadow 那一类在 DeadRules 里已经处理了（关掉盖人的那条会让被盖的活过来），
// node-missing 这一类必须在同一处口径上。
func TestUserRuleWarningsStaySilentOnADisabledRule(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)

	// 配置里只有一个节点 n1：钉到"美西"就是钉了个不存在的名字。
	if err := svc.AddUserRule(rules.UserRule{
		Type: "DOMAIN-SUFFIX", Value: "corp.test", Policy: "PROXY", Node: "美西",
	}); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.UserRuleWarnings(); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 || got[0].Kind != WarnNodeMissing {
		t.Fatalf("起点应报一条 node-missing: %+v", got)
	}

	// 关掉它：判语必须跟着消失，而不是继续警告一条已经不生效的规则。
	if err := svc.SetUserRuleDisabled("DOMAIN-SUFFIX", "corp.test", true); err != nil {
		t.Fatal(err)
	}
	got, err := svc.UserRuleWarnings()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("规则已停用，判语却还在报: %+v", got)
	}

	// 再打开，判语必须回来——这一来一回证明的是"消失"是因为停用，
	// 不是因为那条判语在某个分支里被顺手丢掉了。
	if err := svc.SetUserRuleDisabled("DOMAIN-SUFFIX", "corp.test", false); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.UserRuleWarnings(); err != nil {
		t.Fatal(err)
	} else if len(got) != 1 || got[0].Kind != WarnNodeMissing {
		t.Fatalf("重新启用后判语没有回来: %+v", got)
	}
}

// TestEditingARuleKeepsItsDisabledSwitch 改一条规则的内容不该顺手把它打开。
//
// 判据是"停用属于这一行，不属于这一行写的内容"：改走向、换钉住的节点、
// 批量粘贴覆盖同一条，都只是换内容，那个开关得留在原地。
// 否则用户会遇到"我明明把这条关了，粘了一份名单之后它又开始了"——
// 而粘贴框里没有任何一个字提到过开关。
func TestEditingARuleKeepsItsDisabledSwitch(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)

	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-SUFFIX", Value: "corp.test", Policy: "PROXY"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetUserRuleDisabled("DOMAIN-SUFFIX", "corp.test", true); err != nil {
		t.Fatal(err)
	}

	// 1) 批量粘贴覆盖同一条：内容可以变，开关不许被顺手打开。
	imp, err := svc.AddUserRules("DOMAIN-SUFFIX,corp.test,DIRECT", "DOMAIN-SUFFIX", "PROXY")
	if err != nil {
		t.Fatal(err)
	}
	if imp.Updated == 0 {
		t.Fatalf("这一条本该被认成覆盖: %+v", imp)
	}
	got, err := svc.ListUserRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("粘贴把一条变成了两条: %+v", got)
	}
	if got[0].Policy != "DIRECT" {
		t.Errorf("内容没按粘贴更新: %+v", got[0])
	}
	if !got[0].Disabled {
		t.Errorf("粘贴覆盖一条停用的规则时顺手把它打开了: %+v", got[0])
	}

	// 2) 从添加表单再提交一次同一条（走向不同），开关同样要留住。
	if err := svc.AddUserRule(rules.UserRule{Type: "DOMAIN-SUFFIX", Value: "corp.test", Policy: "PROXY"}); err != nil {
		t.Fatal(err)
	}
	got, err = svc.ListUserRules()
	if err != nil {
		t.Fatal(err)
	}
	if !got[0].Disabled {
		t.Errorf("重新提交同一条把停用状态冲掉了: %+v", got[0])
	}
	// 内容确实按新的走了——留住的是开关，不是旧内容。
	if got[0].Policy != "PROXY" {
		t.Errorf("内容没更新: %+v", got[0])
	}
}

// TestUserRuleHitsJoinsCountsToRows 命中计数要能对回面板列出的那一行。
//
// 这里刻意用 r.Desc() 去喂统计，而不是手写一串 "DOMAIN-SUFFIX,..."：
// 键的格式只有一份权威（见 rules.UserRule.Desc 的注释），
// 测试里再抄一份就成了"两处一起写错还是绿"。
func TestUserRuleHitsJoinsCountsToRows(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)
	list := []rules.UserRule{
		{Type: "DOMAIN-SUFFIX", Value: "a.test", Policy: "PROXY"},
		{Type: "DOMAIN", Value: "b.test", Policy: "DIRECT"},
		{Type: "DOMAIN-SUFFIX", Value: "c.test", Policy: "PROXY", Node: "n1"},
	}
	for _, r := range list {
		if err := svc.AddUserRule(r); err != nil {
			t.Fatal(err)
		}
	}
	// 三条各命中不同次数，外加一条不属于任何用户规则的命中依据。
	reg := svc.Metrics()
	n := map[int]int{0: 5, 1: 1, 2: 12}
	for i, r := range list {
		for k := 0; k < n[i]; k++ {
			reg.Begin("socks5", "c", routerResultFor(r.Desc(), "PROXY"))
		}
	}
	reg.Begin("socks5", "c", routerResultFor("DOMAIN-SUFFIX,other.test,PROXY", "PROXY"))

	got, err := svc.UserRuleHits()
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]int64{}
	for _, h := range got {
		byKey[h.Key] = h.Hits
	}
	if len(got) != 3 {
		t.Fatalf("报了 %d 条，想要 3（每条用户规则一行，对不上的命中依据不该造出新行）: %+v", len(got), got)
	}
	for i, r := range list {
		if byKey[r.Key()] != int64(n[i]) {
			t.Errorf("%s 的命中数 = %d，想要 %d", r.Key(), byKey[r.Key()], n[i])
		}
	}
	// 钉了节点的那一条：引擎的命中依据带 (node=n1)，归并必须也对上。
	if byKey["DOMAIN-SUFFIX,c.test"] != 12 {
		t.Errorf("钉节点的那一条没对上（desc 后缀两边不一致）: %+v", byKey)
	}
}
