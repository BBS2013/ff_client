// 探测答案里「会落到哪个节点」那一格的判据（见 service.Probe 的 Node 字段）。
//
// 单独测它是因为这一个值有三个来源：规则钉住的名字、运行中的当前活动节点、
// 以及代理没在跑时配置里选中的那个。界面对这三句话说的是三种话，
// 混在一处就会变成"探测框偶尔说不上走谁"——而那恰恰是它唯一该说上的事。
package service

import (
	"strings"
	"testing"

	"wps_app/internal/rules"
)

func TestProbeNamesTheNodeWhenLive(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	res, err := svc.Probe("a.blocked.test")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Live || res.Node != "n1" {
		t.Errorf("走代理却没报节点: %+v", res)
	}
	// 这份配置没开按网卡分流：网卡那一格必须是空串，而不是"看起来像默认值"的什么。
	if res.Iface != "" {
		t.Errorf("没开分流却报了网卡 %q", res.Iface)
	}

	// 直连那一侧不许造一个"节点"出来：DIRECT 是去处名，不是节点名，
	// 把它报进节点那一栏，屏幕上就出现「直连 · 落到 DIRECT」这种自相矛盾的话。
	d, err := svc.Probe("www.example.org")
	if err != nil {
		t.Fatal(err)
	}
	if d.Node != "" {
		t.Errorf("直连被报成节点 %q", d.Node)
	}

	// 钉住的那条：节点名与命中依据必须同源于 pick，两处都看得见。
	if err := svc.AddUserRule(rules.UserRule{
		Type: "DOMAIN-SUFFIX", Value: "pinned.test", Policy: "PROXY", Node: "n1",
	}); err != nil {
		t.Fatalf("AddUserRule: %v", err)
	}
	p, err := svc.Probe("x.pinned.test")
	if err != nil {
		t.Fatalf("探测钉住的那条: %v", err)
	}
	if p.Node != "n1" || !strings.Contains(p.Matched, "node=n1") {
		t.Errorf("钉住节点后探测: %+v", p)
	}

	// 钉在配置里根本没有的名字上：探测**照样要把规则那一段答完**，不许因为
	// "这个节点建不出来"就整句查询失败——探测恰恰是在网已经不好的时候被打开的。
	// "这条钉了个不存在的节点"那句话由「这份名单里的问题」那一栏说，
	// 真拨号那侧另有 GetNode 的明确失败（见 TestPinnedNodeDecisionReachesTheProxy）。
	if err := svc.AddUserRule(rules.UserRule{
		Type: "DOMAIN-SUFFIX", Value: "ghost.test", Policy: "PROXY", Node: "no-such",
	}); err != nil {
		t.Fatalf("AddUserRule ghost: %v", err)
	}
	g, err := svc.Probe("x.ghost.test")
	if err != nil {
		t.Fatalf("钉到不存在的节点时探测失败了（它不该去建那个出站）: %v", err)
	}
	if g.Node != "no-such" || !strings.Contains(g.Matched, "node=no-such") {
		t.Errorf("钉住的名字没照规则报出来: %+v", g)
	}

	// 停用（`,off`）的那一条必须从判定里退场：探测框答的是"现在会怎么走"，
	// 而界面上那条还看得见（灰着、写着已停用）。
	// 让它继续参与判定，探测就成了面板上唯一一句假话——人会照着它去理解一条根本不生效的规则。
	if err := svc.AddUserRule(rules.UserRule{
		Type: "DOMAIN-SUFFIX", Value: "quiet.test", Policy: "PROXY",
	}); err != nil {
		t.Fatalf("AddUserRule quiet: %v", err)
	}
	if _, err := svc.Probe("a.quiet.test"); err != nil {
		t.Fatalf("停用之前探测: %v", err)
	}
	if err := svc.SetUserRuleDisabled("DOMAIN-SUFFIX", "quiet.test", true); err != nil {
		t.Fatalf("SetUserRuleDisabled: %v", err)
	}
	off, err := svc.Probe("a.quiet.test")
	if err != nil {
		t.Fatalf("停用之后探测: %v", err)
	}
	// 命中依据写的是 "FINAL" 或 "FINAL(dns-failed)"（这份测试配置没有 GeoIP 也没有解析器，
	// 需要解析的规则会带后一种尾巴），断前缀就够——这里要盯的是那条已停用的规则别再出现。
	if off.Policy != "DIRECT" || !strings.HasPrefix(off.Matched, "FINAL") {
		t.Errorf("停用的那条仍在参与判定: %+v", off)
	}
}

// TestProbeNodeFromDiskWhenNotRunning：代理停着的时候这一格还得有答案，
// 但它只能来自磁盘——用户排障常常就是趁"还没起来"的时候问的。
func TestProbeNodeFromDiskWhenNotRunning(t *testing.T) {
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)

	res, err := svc.Probe("a.blocked.test")
	if err != nil {
		t.Fatal(err)
	}
	if res.Live {
		t.Fatal("没 Start 却报了 Live")
	}
	if res.Node != "n1" {
		t.Errorf("停着时节点应取配置里选中的那个，实际 %q", res.Node)
	}
	if d, _ := svc.Probe("www.example.org"); d.Node != "" {
		t.Errorf("停着时直连也被塞了节点: %q", d.Node)
	}
}
