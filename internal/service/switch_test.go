package service

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
)

// twoProfileConfig 写一份「两个节点 + :0 入站」的配置。
// 节点地址全是字面量 127.0.0.1：装配出站不做解析，测试因此不碰任何网络。
func twoProfileConfig(t *testing.T) string {
	t.Helper()
	return profileConfig(t)
}

// profileConfig 在两个默认节点之上追加额外的 proxies 段落（YAML 原文，缩进两级）。
func profileConfig(t *testing.T, extraProxies ...string) string {
	t.Helper()
	return profileConfigAt(t, "127.0.0.1:4433", "127.0.0.1:4434", extraProxies...)
}

// profileConfigAt 同上，但两个节点地址由调用方给。
//
// 绝大多数用例只要求「这个地址后面没人听着」，4433/4434 这个约定就够了，
// 而且它们让断言读起来更直白（`after.Server == "127.0.0.1:4434"`）。
// 只有结论要看拨号失败结果的那条用例，才需要找内核要一个保证空着的端口。
func profileConfigAt(t *testing.T, addrA, addrB string, extraProxies ...string) string {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rulesPath, []byte("DOMAIN-SUFFIX,example.com,DIRECT\nFINAL,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var extra strings.Builder
	for _, p := range extraProxies {
		extra.WriteString(p)
		extra.WriteString("\n")
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf(`proxies:
  - name: a-hy2
    server: { addr: %q, auth: "x", bandwidth: { up: "50 mbps", down: "50 mbps" } }
  - name: b-trojan
    server: { type: trojan, addr: %q, auth: "y", tls: { sni: localhost, insecure: true } }
%sactive: a-hy2
mode: rule
inbounds:
  - { type: socks5, listen: "127.0.0.1:0" }
  - { type: http, listen: "127.0.0.1:0" }
rules_file: %q
geoip:
  path: %q
dns:
  servers: ["127.0.0.1:53"]
log:
  level: warn
`, addrA, addrB, extra.String(), rulesPath, filepath.Join(dir, "missing.mmdb"))
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// deadUDPPort 让内核分配一个 UDP 端口然后立刻还回去，用来当「后面确实没人听着」的地址。
//
// 为什么不沿用写死的 4433：结论依赖拨号失败的用例一旦端口上真有人听着，能做的只有跳过，
// 而一个静默不跑的守卫比没有守卫更糟——它让后面的人以为这条链已经验过了。
// 刚还给内核的端口在微秒内被抢走的可能性，比 4433 上正好跑着一个 hysteria2 服务端小得多。
func deadUDPPort(t *testing.T) int {
	t.Helper()
	p, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("分配临时端口: %v", err)
	}
	_, port, err := net.SplitHostPort(p.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	n, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("端口号 %q: %v", port, err)
	}
	return n
}

// TestSetActiveProfileSwapsOutboundOnly 钉住「选用」的代价。
//
// 换节点改变的只有出口是谁：监听、规则、假 IP、协议栈、TUN 网卡与路由都与它无关。
// 以前这里走的是整块重启，实测一次点击要花两三秒（TUN 在跑时还要多跑几趟 sudo
// 和二十来条 iptables/ip），界面表现就是"点选用卡住"，
// 而且顺手把其它正在传、与新节点毫无关系的连接全打断了。
func TestSetActiveProfileSwapsOutboundOnly(t *testing.T) {
	svc := New(twoProfileConfig(t), nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop()

	before := svc.Snapshot()
	if before.StartedAt == 0 || !before.Running {
		t.Fatalf("启动后快照不对: %+v", before)
	}
	// :0 入站由内核分配端口，一旦重启就会换一个——用它当"有没有重启"的探针。
	probe := before.Inbounds[0].Addr

	start := time.Now()
	if err := svc.SetActiveProfile("b-trojan"); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}
	elapsed := time.Since(start)

	after := svc.Snapshot()
	if after.StartedAt != before.StartedAt {
		t.Fatalf("换节点竟把服务重启了（StartedAt %d → %d）", before.StartedAt, after.StartedAt)
	}
	if after.Inbounds[0].Addr != probe {
		t.Fatalf("入站端口变了，说明监听过：重启过了（%s → %s）", probe, after.Inbounds[0].Addr)
	}
	if after.ActiveProfile != "b-trojan" || after.Server != "127.0.0.1:4434" {
		t.Fatalf("active 没跟上: %+v", after)
	}
	// 协议要真的换成 trojan 出站：这是「换节点」与「换协议」共用一条路径的证明。
	// 地址上面已经用 after.Server 查过了——Server 就是界面上那一行，不再有第二个副本。
	if after.ProxyType != config.ProtocolTrojan {
		t.Fatalf("快照里的协议不对: %+v", after)
	}
	if after.Connected {
		t.Fatal("刚换上的出站还没握手，Connected 不该为 true")
	}
	// 实测这条是 0.00~0.02s。预算给到 1s 而不是 500ms：
	// 它要拦的是"退化成整块重启"（实测两三秒起，TUN 在跑时还要多跑几趟 sudo），
	// 量级差一百倍，预算宽一点并不会放过任何回归，却不再被机器一时的忙绿绊倒。
	if elapsed > time.Second {
		t.Fatalf("换节点用了 %v——这就是界面上那一下卡顿", elapsed)
	}
}

// TestRemoveInactiveProfileDoesNotTouchService 删一个没在用的节点，
// 运行中的服务不该有任何变化：配置里少了一条记录而已。
func TestRemoveInactiveProfileDoesNotTouchService(t *testing.T) {
	svc := New(twoProfileConfig(t), nil)
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()

	before := svc.Snapshot()
	if err := svc.RemoveProfile("b-trojan"); err != nil {
		t.Fatalf("RemoveProfile: %v", err)
	}
	after := svc.Snapshot()
	if after.StartedAt != before.StartedAt || after.Inbounds[0].Addr != before.Inbounds[0].Addr {
		t.Fatal("删掉闲置节点竟重启了服务")
	}
	if after.ActiveProfile != "a-hy2" || len(after.Profiles) != 1 {
		t.Fatalf("节点列表没跟上: %+v", after)
	}
}

// TestRemoveActiveProfileSwapsOutbound 删掉当前选中的节点时，
// active 会落到剩下的那一个上，运行态同样只需要换一只出站。
func TestRemoveActiveProfileSwapsOutbound(t *testing.T) {
	svc := New(twoProfileConfig(t), nil)
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()

	before := svc.Snapshot()
	if err := svc.RemoveProfile("a-hy2"); err != nil {
		t.Fatalf("RemoveProfile(active): %v", err)
	}
	after := svc.Snapshot()
	if after.StartedAt != before.StartedAt {
		t.Fatal("删当前节点不该重启整个服务")
	}
	if after.ActiveProfile != "b-trojan" || after.ProxyType != config.ProtocolTrojan {
		t.Fatalf("换到的节点没生效: %+v", after)
	}
}

// TestSetActiveProfileWhileStoppedOnlyWritesConfig 没在跑时切节点只写配置：
// 「点了选用就把代理启动起来」这种副作用会让人意外。
func TestSetActiveProfileWhileStoppedOnlyWritesConfig(t *testing.T) {
	path := twoProfileConfig(t)
	svc := New(path, nil)
	if err := svc.SetActiveProfile("b-trojan"); err != nil {
		t.Fatalf("未运行时也应能切节点: %v", err)
	}
	if snap := svc.Snapshot(); snap.Running {
		t.Fatal("切节点不该把服务启动起来")
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Active != "b-trojan" {
		t.Fatalf("没落盘: %q", cfg.Active)
	}
}

// brokenNode 是一个必然装配失败的节点：.invalid 顶级域按 RFC 6761 永远不可能被解析，
// 所以不管有没有可用的 DNS，outbound.New 都会在这里返回错误。
// fakeDNSActive 报告这台机器此刻的解析器是不是在**给任意名字编造答案**：
// 全局 TUN 接管时，本机解析器对任何域名都回 198.18.x 假 IP（那是它的设计），
// 而下面两条用例靠「.invalid 解析不了」来造出「装配必然失败」。
// 那种环境下前提不成立——这不是被测逻辑坏了，是场景换了，所以要**带原因地跳过**，
// 而不是让它们红得莫名其妙（2026-10-29：面板开着 global + TUN 时实际红过）。
func fakeDNSActive() bool {
	addrs, err := lookupHostFn("no-such-host.invalid")
	return err == nil && len(addrs) > 0
}

// lookupHostFn 只为让上面那条判据能被测到：不能只写一句「会跳过」就了事，
// 得证明它在「解析器编答案」时真的返回 true。
var lookupHostFn = net.LookupHost

const brokenNode = `  - name: bad-dns
    server: { addr: "no-such-host.invalid:443", auth: "x", bandwidth: { up: "50 mbps", down: "50 mbps" } }`

// TestFailedSwitchLeavesNoTornState 切到一个装不起来的节点时，
// 整个操作必须当作没发生过：配置不改、运行态不动。
//
// 这一条钉的是「先写盘、后装配」的顺序。旧写法先 mutate 把 active 落盘，
// 再在 switchProxy 里装配出站——装配失败时返回了错误，
// 但配置已经收不回来了。那一刻快照里的 ActiveProfile/Server 说的是新节点，
// Connected/ProxyStatus 却还挂在旧节点上，流量也真的还在走旧节点：
// 界面显示"已切换"，实际什么都没切，而且没有任何错误信息能解释这个矛盾。
func TestFailedSwitchLeavesNoTornState(t *testing.T) {
	if fakeDNSActive() {
		t.Skip("系统解析器正对任意名字回假 IP（有 TUN 在接管）：`.invalid 解析不了` 这个前提不成立")
	}
	path := profileConfig(t, brokenNode)
	svc := New(path, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop()

	before := svc.Snapshot()
	probe := before.Inbounds[0].Addr

	err := svc.SetActiveProfile("bad-dns")
	if err == nil {
		t.Fatal("切到一个装配必然失败的节点，应当报错")
	}

	after := svc.Snapshot()
	// 核心断言：快照说的节点、盘上的节点、正在跑的那只，必须是同一个。
	if after.ActiveProfile != "a-hy2" {
		t.Fatalf("失败的切换改了 active: %q", after.ActiveProfile)
	}
	disk, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Active != "a-hy2" {
		t.Fatalf("失败的切换竟落盘了: active=%q（报的错是 %v）", disk.Active, err)
	}
	if after.Server != before.Server {
		t.Fatalf("快照里的服务端换了，但切换是失败的: %q → %q", before.Server, after.Server)
	}
	if after.Inbounds[0].Addr != probe {
		t.Fatalf("入站端口变了（%s → %s）", probe, after.Inbounds[0].Addr)
	}
	if after.StartedAt != before.StartedAt {
		t.Fatal("失败的切换把服务重启了")
	}

	// 失败之后仍应能切到一个好节点——不能被一次失败卡成"配置指向一个没在跑的节点"。
	if err := svc.SetActiveProfile("b-trojan"); err != nil {
		t.Fatalf("失败之后切到好节点应当成功: %v", err)
	}
	got := svc.Snapshot()
	if got.ActiveProfile != "b-trojan" || got.ProxyType != config.ProtocolTrojan {
		t.Fatalf("失败之后的切换没生效: %+v", got)
	}
}

// TestRemoveActiveProfileWithUnusableReplacementAborts 删掉当前节点、
// 而顶上来的替代品又装不起来时，删除必须整个失败。
//
// 不失败的话结果是「活动节点从配置里消失了，运行时却还在用它」——
// 配置里再没有任何一条记录描述正在承载流量的那个出口。
func TestRemoveActiveProfileWithUnusableReplacementAborts(t *testing.T) {
	if fakeDNSActive() {
		t.Skip("系统解析器正对任意名字回假 IP（有 TUN 在接管）：`.invalid 解析不了` 这个前提不成立")
	}
	path := profileConfig(t, brokenNode)
	svc := New(path, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop()

	// 先删掉没在用的 b-trojan，让 bad-dns 成为 a-hy2 之后顶上来的那一个。
	if err := svc.RemoveProfile("b-trojan"); err != nil {
		t.Fatalf("删闲置节点应当成功: %v", err)
	}
	if snap := svc.Snapshot(); snap.ActiveProfile != "a-hy2" || len(snap.Profiles) != 2 {
		t.Fatalf("前置状态不对: %+v", snap)
	}

	before := svc.Snapshot()
	probe := before.Inbounds[0].Addr

	err := svc.RemoveProfile("a-hy2")
	if err == nil {
		t.Fatal("替代品装不起来时，删除活动节点应当整个失败")
	}

	after := svc.Snapshot()
	// 盘上必须还是那两个节点（b-trojan 已被上一步删掉）、active 还是 a-hy2。
	disk, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(disk.Proxies) != 2 || disk.Active != "a-hy2" {
		t.Fatalf("失败的删除改动了配置: 节点数=%d active=%q", len(disk.Proxies), disk.Active)
	}
	if after.ActiveProfile != "a-hy2" {
		t.Fatalf("失败的删除改了 active: %q", after.ActiveProfile)
	}
	if after.Inbounds[0].Addr != probe || after.StartedAt != before.StartedAt {
		t.Fatal("失败的删除动了运行中的服务")
	}
}

// TestFakeDNSDetectsFabricatedAnswers 判据本身要有用例：
// 「会跳过」这三个字没有测试保护时，最可能的结局是它永远返回 false（那两条用例照旧红），
// 或者永远返回 true（那两条从此再也不跑）。
func TestFakeDNSDetectsFabricatedAnswers(t *testing.T) {
	old := lookupHostFn
	t.Cleanup(func() { lookupHostFn = old })

	lookupHostFn = func(string) ([]string, error) { return []string{"198.18.0.2"}, nil }
	if !fakeDNSActive() {
		t.Error("解析器编了一个假 IP，却没被认成「假 DNS 正在生效」")
	}
	lookupHostFn = func(string) ([]string, error) { return nil, &net.DNSError{Err: "no such host", IsNotFound: true} }
	if fakeDNSActive() {
		t.Error("正常的 NXDOMAIN 被判成了「假 DNS 在生效」——那两条用例会被永久跳过")
	}
}
