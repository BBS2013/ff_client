package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
)

// singleProfileConfig 只写一个节点的配置：用来验「无处可切时什么都不做」。
func singleProfileConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rulesPath, []byte("DOMAIN-SUFFIX,example.com,DIRECT\nFINAL,PROXY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf(`proxies:
  - name: a-hy2
    server: { addr: "127.0.0.1:4433", auth: "x", bandwidth: { up: "50 mbps", down: "50 mbps" } }
active: a-hy2
mode: rule
inbounds:
  - { type: socks5, listen: "127.0.0.1:0" }
rules_file: %q
geoip:
  path: %q
dns:
  servers: ["127.0.0.1:53"]
log:
  level: warn
`, rulesPath, filepath.Join(dir, "missing.mmdb"))
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// 这组测试钉的是「什么时候才敢自动切节点」。
// 切错的代价很实在：换节点会掐掉旧隧道上所有正在传的连接。

// nodeErr 是一个必然被判定为节点级故障的错误。
var nodeErr = coreErrs.ConnectError{Err: errors.New("handshake failed")}

// targetErr 是「节点好好的，只是它拨不通这个目标」。
var targetErr = coreErrs.DialError{Message: "connection refused"}

func startTwoNodes(t *testing.T) (*Service, string) {
	t.Helper()
	path := twoProfileConfig(t)
	svc := New(path, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	return svc, path
}

// TestRecordFaultIgnoresTargetRefusal 单个目标连不通绝不能攒成一次节点故障。
// 浏览器每个页面都带着几个已经死掉的站点，为它们切节点等于无事生非。
func TestRecordFaultIgnoresTargetRefusal(t *testing.T) {
	svc, _ := startTwoNodes(t)
	for i := 0; i < 20; i++ {
		svc.observeDialFault("dead.example.com:443", outbound.Dialer(svc.proxy), targetErr)
	}
	if n, hosts := svc.faultSummary("a-hy2"); n != 0 || len(hosts) != 0 {
		t.Fatalf("目标被拒竟被记账: count=%d hosts=%v", n, hosts)
	}
}

// TestRecordFaultIgnoresDirectDialFailures 直连出站失败是用户自己的网络。
func TestRecordFaultIgnoresDirectDialFailures(t *testing.T) {
	svc, _ := startTwoNodes(t)
	var direct outbound.Dialer = nopDialer{}
	for i := 0; i < 20; i++ {
		svc.observeDialFault("anything:443", direct, nodeErr)
	}
	if n, _ := svc.faultSummary("a-hy2"); n != 0 {
		t.Fatalf("直连的失败记到节点头上了: count=%d", n)
	}
}

// nopDialer 不是 svc.proxy，观察者也应当不理它。
type nopDialer struct{}

func (nopDialer) Name() string { return "DIRECT" }
func (nopDialer) DialContext(context.Context, string) (net.Conn, error) {
	return nil, errors.New("nope")
}
func (nopDialer) Close() error { return nil }

// TestSingleHostDoesNotTrigger 同一个目标失败再多次也不算节点坏了。
// 这一条与上一条合起来才是「跨多个不同目标」这个门槛的全部意义。
func TestSingleHostDoesNotTrigger(t *testing.T) {
	svc, _ := startTwoNodes(t)
	svc.mu.Lock()
	defer svc.mu.Unlock()
	var ready bool
	for i := 0; i < 30; i++ {
		ready = svc.recordFaultLocked("a-hy2", "one.example.com:443")
	}
	if ready {
		t.Fatal("只有一个目标在失败就判定节点故障——这正是误报的典型形状")
	}
	if n, hosts := svc.faultSummaryLocked("a-hy2"); n < 30 || len(hosts) != 1 {
		t.Fatalf("记账不对: count=%d hosts=%d", n, len(hosts))
	}
}

// TestMultipleHostsTrigger 多个不同目标一起失败，才是节点级的结论。
func TestMultipleHostsTrigger(t *testing.T) {
	svc, _ := startTwoNodes(t)
	svc.mu.Lock()
	defer svc.mu.Unlock()
	var ready bool
	for _, h := range []string{"a.example.com:443", "b.example.com:443"} {
		if ready = svc.recordFaultLocked("a-hy2", h); ready {
			break
		}
	}
	if !ready {
		// 门槛是「次数 ≥3 且 不同目标 ≥2」，两个目标各一次只有 2 次，还不该触发。
		if r := svc.recordFaultLocked("a-hy2", "c.example.com:443"); !r {
			t.Fatal("三次失败跨三个目标仍不触发")
		}
		return
	}
}

// TestFailoverSwitchesWithoutTouchingConfig 自动切换改内存、不改配置文件。
//
// 不改盘有两条理由：一次应急决定不该悄悄改掉用户选的节点；
// 以及 config.Save 每次都会覆盖 config.yaml.bak，
// 抖动几轮之后用户原来的配置备份就没了。
func TestFailoverSwitchesWithoutTouchingConfig(t *testing.T) {
	svc, path := startTwoNodes(t)
	svc.probeCandidate = func(outbound.Dialer) error { return nil }

	before := svc.Snapshot()
	if before.ActiveProfile != "a-hy2" {
		t.Fatalf("前置不对: %+v", before)
	}

	svc.tryFailover("a-hy2")

	after := svc.Snapshot()
	if after.ActiveProfile != "b-trojan" {
		t.Fatalf("没有自动切换: activeProfile=%q reason=%q", after.ActiveProfile, after.SwitchReason)
	}
	if !after.AutoSwitched {
		t.Fatal("AutoSwitched 应当为真，界面才有办法解释这次切换")
	}
	if after.SwitchReason == "" {
		t.Fatal("切换理由为空")
	}
	// 快照内部必须自洽：地址、协议、「使用中」的标记都指向同一个节点。
	if after.Server != "127.0.0.1:4434" || after.ProxyType != config.ProtocolTrojan {
		t.Fatalf("快照还在说旧节点: server=%q type=%q", after.Server, after.ProxyType)
	}
	for _, p := range after.Profiles {
		if p.Active != (p.Name == "b-trojan") {
			t.Fatalf("「使用中」标记没跟着自动切换走: %+v", after.Profiles)
		}
	}

	disk, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if disk.Active != "a-hy2" {
		t.Fatalf("自动切换把应急决定写进了用户的配置文件: active=%q", disk.Active)
	}
}

// TestDwellBlocksSecondSwitch 迟滞：刚切过一次，短期内不许再切。
// 来回切换会把正在传的连接一段一段掐断，比卡在死节点上更难受。
func TestDwellBlocksSecondSwitch(t *testing.T) {
	svc, _ := startTwoNodes(t)
	svc.probeCandidate = func(outbound.Dialer) error { return nil }

	svc.tryFailover("a-hy2")
	if got := svc.Snapshot().ActiveProfile; got != "b-trojan" {
		t.Fatalf("第一次切换没生效: %q", got)
	}

	// 立刻再试着切回 a-hy2：既受 dwell 约束，a-hy2 也在冷却里。
	svc.tryFailover("b-trojan")
	if got := svc.Snapshot().ActiveProfile; got != "b-trojan" {
		t.Fatalf("驻留期内又切了一次: %q", got)
	}

	// 把时间推到驻留期之后，冷却也过期——这时才允许再动。
	svc.mu.Lock()
	svc.switchedAt = time.Now().Add(-switchDwell - time.Second)
	svc.cooling = nil
	svc.mu.Unlock()
	svc.tryFailover("b-trojan")
	if got := svc.Snapshot().ActiveProfile; got != "a-hy2" {
		t.Fatalf("冷却与驻留都过期后仍不切换: %q", got)
	}
}

// TestUnreachableCandidateIsSkipped 替代品自己也连不上时不能切过去。
func TestUnreachableCandidateIsSkipped(t *testing.T) {
	svc, _ := startTwoNodes(t)
	svc.probeCandidate = func(outbound.Dialer) error { return errors.New("试拨不通") }

	svc.tryFailover("a-hy2")
	if got := svc.Snapshot().ActiveProfile; got != "a-hy2" {
		t.Fatalf("候选不通却切过去了: %q", got)
	}
}

// TestManualPickClearsAutoSwitch 用户手动点名一个节点之后，
// 自动切换的结论必须作废——否则界面上显示的永远不是用户选的那个。
func TestManualPickClearsAutoSwitch(t *testing.T) {
	svc, _ := startTwoNodes(t)
	svc.probeCandidate = func(outbound.Dialer) error { return nil }
	svc.tryFailover("a-hy2")
	if !svc.Snapshot().AutoSwitched {
		t.Fatal("前置：应先处于自动切换状态")
	}

	if err := svc.SetActiveProfile("a-hy2"); err != nil {
		t.Fatalf("手动切换失败: %v", err)
	}
	snap := svc.Snapshot()
	if snap.AutoSwitched || snap.ActiveProfile != "a-hy2" {
		t.Fatalf("手动选择没压过自动切换: active=%q auto=%v", snap.ActiveProfile, snap.AutoSwitched)
	}
	if snap.Server != "127.0.0.1:4433" {
		t.Fatalf("手动切回 a-hy2 后地址不对: %q", snap.Server)
	}
}

// TestFailoverNeedsTwoNodes 只有一个节点时无处可切，不该做任何动作。
func TestFailoverNeedsTwoNodes(t *testing.T) {
	path := singleProfileConfig(t)
	svc := New(path, nil)
	if err := svc.Start(); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()
	svc.probeCandidate = func(outbound.Dialer) error { return nil }
	svc.tryFailover("a-hy2")
	if got := svc.Snapshot(); got.ActiveProfile != "a-hy2" || got.AutoSwitched {
		t.Fatalf("单节点配置下不该发生自动切换: %+v", got)
	}
}

// TestObserverWiredThroughRealTraffic 是上面那批测试补不上的那一块：
// 前面的用例都直接调 observeDialFault，等于假设了「路由器真的会把失败送过来」。
// 这里走一条真实的 SOCKS5 请求，让 hysteria 自己去撞一个没人听着的端口，
// 只有整条链通了一起，失败记账才会出现。
func TestObserverWiredThroughRealTraffic(t *testing.T) {
	dead := deadUDPPort(t)
	path := profileConfigAt(t, fmt.Sprintf("127.0.0.1:%d", dead), "127.0.0.1:4434")
	svc := New(path, nil)
	// 握手上限定 1s：撞一个死端点本来就是要等满超时，用生产那个 10s 的话
	// 这一条要跑十几秒，慢到没人愿意跑，而它恰恰是"观察者真的接在真实链路上"的唯一证据。
	svc.handshakeTO = time.Second
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop()

	port := portOf(t, svc.Snapshot(), "socks5")
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 3*time.Second)
	if err != nil {
		t.Fatalf("连 SOCKS5 入站: %v", err)
	}
	defer conn.Close()
	// VER=5, NMETHODS=1, METHODS=NO AUTH
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatalf("读协商: %v", err)
	}
	// CONNECT www.google.com:443。必须挑一个不被规则分去 DIRECT 的域名——
	// 这份配置的规则是 `DOMAIN-SUFFIX,example.com,DIRECT` + `FINAL,PROXY`，
	// 用 example.com 会直接走本地直连并成功，节点根本没被碰过。
	// 域名原样交给隧道解析，所以失败必然出在「拨节点」这一步。
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len("www.google.com"))}
	req = append(req, []byte("www.google.com")...)
	req = append(req, 0x01, 0xbb) // 端口 443
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	rep := make([]byte, 32)
	n, err := io.ReadAtLeast(conn, rep, 10)
	if err != nil {
		t.Fatalf("读 CONNECT 应答: %v", err)
	}
	if rep[1] == 0x00 {
		// 端口是内核刚分给我们、又立刻还回去的，拨通只可能是转瞬之间有东西占了它。
		// 这里不许 skip：一条静默不跑的守卫会让人以为这条链已经验过了，比没有更糟。
		t.Fatalf("拨 127.0.0.1:%d 竟然成功了，这条测试需要「节点拨不通」才成立", dead)
	}
	t.Logf("CONNECT 被拒（REP=%#x，%d 字节），符合预期", rep[1], n)

	// 一次拨号内部会重试 3 轮，每轮都是节点级错误，记账必须已经发生。
	count, hosts := svc.faultSummary("a-hy2")
	if count == 0 {
		t.Fatal("真实流量上的失败没有进到记账里——观察者没接上，或者判据没认出来")
	}
	t.Logf("已记账 %d 次节点级失败，涉及 %d 个不同目标", count, len(hosts))
}

// TestFailoverBusyBlocksRound 上一轮还在跑时，后来的触发必须立刻回去。
//
// 单飞与轮次冷却这两道门钉的是同一件线上事故：主节点 2026-10-20 10:52:47 掉线、
// 唯一备节点也握不上手，2 分钟里跑了 5 轮（10:52:49 / 10:53:21 / 10:53:39 /
// 10:54:04 / 10:54:39），每轮为每个候选节点付 8s 试拨，结论一句不变。
func TestFailoverBusyBlocksRound(t *testing.T) {
	svc, _ := startTwoNodes(t)
	var probes int
	svc.probeCandidate = func(outbound.Dialer) error { probes++; return errors.New("试拨不通") }

	svc.mu.Lock()
	svc.failoverBusy = true
	svc.failoverRoundAt = time.Time{} // 只留单飞这一道门，别把冷却的功劳算给它
	svc.mu.Unlock()

	svc.tryFailover("a-hy2")
	if probes != 0 {
		t.Fatalf("上一轮还在跑就又起了一轮：试拨跑了 %d 次", probes)
	}
}

// TestFailoverRoundCooldown 一轮跑完（无论成败）之后 roundCooldown 内不许再起第二轮，
// 过期之后又必须真的能起。
//
// 后半句才是这条用例存在的理由：单飞标志要是忘了释放，故障切换会永久死掉，
// 而症状是「节点再也没自动切过」——那比原来的重复试拨严重得多。
func TestFailoverRoundCooldown(t *testing.T) {
	svc, _ := startTwoNodes(t)
	var probes int
	svc.probeCandidate = func(outbound.Dialer) error { probes++; return errors.New("试拨不通") }

	svc.tryFailover("a-hy2")
	if probes != 1 {
		t.Fatalf("第一轮应恰好试拨一次, got %d", probes)
	}
	svc.tryFailover("a-hy2")
	if probes != 1 {
		t.Fatalf("轮次冷却没拦住，第二轮也去试拨了: probes=%d", probes)
	}

	svc.mu.Lock()
	svc.failoverRoundAt = time.Now().Add(-roundCooldown - time.Second)
	svc.mu.Unlock()
	svc.tryFailover("a-hy2")
	if probes != 2 {
		t.Fatalf("冷却过期后没能再起一轮（多半是 failoverBusy 没释放）: probes=%d", probes)
	}
}
