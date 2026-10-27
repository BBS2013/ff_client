package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
)

// newTestConfig 写一份最小可用配置：指向本地随机端口的 socks5 与 http 入站，
// 规则文件只留一条 FINAL，避免依赖仓库里的 assets 目录。
func newTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	rulesPath := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(rulesPath, []byte("DOMAIN-SUFFIX,example.com,DIRECT\nFINAL,PROXY\n"), 0o600); err != nil {
		t.Fatalf("写规则文件: %v", err)
	}
	geoPath := filepath.Join(dir, "missing.mmdb") // 故意不存在，验证 mmdb 缺失不阻断启动

	cfgPath := filepath.Join(dir, "config.yaml")
	body := fmt.Sprintf(`server:
  addr: "127.0.0.1:4433"
  auth: "test-auth"
  tls:
    sni: "example.invalid"
  bandwidth:
    up: "100 mbps"
    down: "100 mbps"
inbounds:
  - type: socks5
    listen: "127.0.0.1:0"
  - type: http
    listen: "127.0.0.1:0"
rules_file: %q
geoip:
  path: %q
dns:
  servers: ["127.0.0.1:53"]
log:
  level: warn
`, rulesPath, geoPath)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("写配置文件: %v", err)
	}
	return cfgPath
}

// portOf 从 Snapshot 的入站里取实际监听端口，:0 入站由内核分配。
func portOf(t *testing.T, snap Snapshot, typ string) int {
	t.Helper()
	for _, in := range snap.Inbounds {
		if in.Type != typ {
			continue
		}
		_, p, err := net.SplitHostPort(in.Addr)
		if err != nil {
			t.Fatalf("入站地址 %q 无法解析: %v", in.Addr, err)
		}
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		return n
	}
	t.Fatalf("快照里没有 %s 入站: %+v", typ, snap.Inbounds)
	return 0
}

func TestServiceStartStop(t *testing.T) {
	svc := New(newTestConfig(t), nil)
	defer svc.Stop()

	if snap := svc.Snapshot(); snap.Running {
		t.Fatal("未启动时 Running 应为 false")
	}
	// 未运行时也要能看到「将以什么配置启动」的静态信息，供 GUI 展示。
	if snap := svc.Snapshot(); snap.Server != "127.0.0.1:4433" {
		t.Fatalf("停止状态下应回填配置，Server = %q", snap.Server)
	}

	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	snap := svc.Snapshot()
	if !snap.Running || snap.UptimeMS < 0 {
		t.Fatalf("启动后快照不对: running=%v uptime=%d", snap.Running, snap.UptimeMS)
	}
	if snap.StartedAt == 0 {
		t.Fatal("启动后应有 StartedAt")
	}
	if snap.FinalPolicy != "PROXY" || snap.DomainRules == 0 {
		t.Fatalf("规则统计不对: FINAL=%q domain=%d", snap.FinalPolicy, snap.DomainRules)
	}
	// 测试配置里的 mmdb 不存在，GeoIP 应报不可用而不是让服务起不来。
	if snap.GeoIPOK {
		t.Fatal("mmdb 不存在时 GeoIPOK 应为 false")
	}

	for _, typ := range []string{"socks5", "http"} {
		p := portOf(t, snap, typ)
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 2*time.Second)
		if err != nil {
			t.Fatalf("%s 入站没在监听 %d: %v", typ, p, err)
		}
		_ = c.Close()
	}

	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if snap := svc.Snapshot(); snap.Running {
		t.Fatal("停止后 Running 应为 false")
	}

	// 端口必须真的释放：Stop 只是关监听，不改配置。
	for _, typ := range []string{"socks5", "http"} {
		p := portOf(t, svc.Snapshot(), typ)
		if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p), 300*time.Millisecond); err == nil {
			_ = c.Close()
			t.Fatalf("停止后 %s 端口 %d 仍在监听", typ, p)
		}
	}
}

// Connected 必须实打实问出站，不能从 Running 推。测试配置的地址不可达，
// 但重点在另一头：代理已启动、还没跑过任何流量时，hysteria2 握手还没发生，
// 此时如实报未连接才是对的；从 Running 推会把这个状态误报成已连接。
func TestSnapshotConnectedTracksHandshake(t *testing.T) {
	svc := New(newTestConfig(t), nil)
	defer svc.Stop()

	if snap := svc.Snapshot(); snap.Connected {
		t.Fatal("未启动时应为 false")
	}

	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	snap := svc.Snapshot()
	if !snap.Running {
		t.Fatal("启动后应为运行中")
	}
	if snap.Connected {
		t.Fatal("已启动但还没跑过流量，握手尚未发生，Connected 应为 false")
	}
	// Server 不依赖握手，运行中就必须有值，否则 GUI 连服务端地址都显示不出来。
	if snap.Server != "127.0.0.1:4433" {
		t.Fatalf("Server = %q, want 127.0.0.1:4433", snap.Server)
	}
	// 协议名也要报：界面得知道该显示 hysteria2 还是 trojan 的参数。
	if snap.ProxyType != config.ProtocolHysteria2 {
		t.Fatalf("ProxyType = %q, want %q", snap.ProxyType, config.ProtocolHysteria2)
	}
	if snap.ProxyStatus == "" {
		t.Fatal("ProxyStatus 为空：出站没给出可显示的服务端摘要")
	}

	if err := svc.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if snap := svc.Snapshot(); snap.Connected {
		t.Fatal("停止后应为 false")
	}
}

func TestServiceStopIsIdempotent(t *testing.T) {
	svc := New(newTestConfig(t), nil)
	if err := svc.Stop(); err != nil {
		t.Fatalf("未启动就 Stop 应为 nil，实际 %v", err)
	}
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := svc.Stop(); err != nil {
		t.Fatalf("首次 Stop: %v", err)
	}
	if err := svc.Stop(); err != nil {
		t.Fatalf("二次 Stop 应为 nil，实际 %v", err)
	}
}

// TestServiceRestart 覆盖 GUI「重启」按钮：已在运行时再 Start 应等价于重启，
// 且旧的监听端口要先被释放掉。
func TestServiceRestart(t *testing.T) {
	svc := New(newTestConfig(t), nil)
	defer svc.Stop()

	if err := svc.Start(); err != nil {
		t.Fatalf("首次 Start: %v", err)
	}
	first := portOf(t, svc.Snapshot(), "socks5")

	if err := svc.Start(); err != nil {
		t.Fatalf("运行中再次 Start: %v", err)
	}
	if snap := svc.Snapshot(); !snap.Running {
		t.Fatal("重启后应在运行")
	}
	second := portOf(t, svc.Snapshot(), "socks5")
	if first == second || second == 0 {
		t.Fatalf("重启应重新分配端口，首个=%d 第二个=%d", first, second)
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", first), 300*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatalf("重启后旧端口 %d 仍被占用", first)
	}
}

func TestServicePrepareIsIdempotent(t *testing.T) {
	svc := New(newTestConfig(t), nil)
	defer svc.Stop()

	if err := svc.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	rt := svc.Router()
	if rt == nil {
		t.Fatal("Prepare 后应有 router")
	}
	if err := svc.Prepare(); err != nil {
		t.Fatalf("重复 Prepare 应为 nil，实际 %v", err)
	}
	if svc.Router() != rt {
		t.Fatal("重复 Prepare 不应重建 router")
	}
	// Prepare 不监听任何端口。
	if snap := svc.Snapshot(); snap.Running {
		t.Fatal("Prepare 不应把服务标记为运行中")
	}
}

func TestServiceReloadRequiresRunning(t *testing.T) {
	svc := New(newTestConfig(t), nil)
	err := svc.Reload()
	if err == nil || !strings.Contains(err.Error(), "未运行") {
		t.Fatalf("未运行时 Reload 应报错说明未运行，实际 %v", err)
	}

	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer svc.Stop()
	// mmdb 不存在时 GeoIP 会保留失败，但规则本身能重载，因此这里不应报错。
	if err := svc.Reload(); err != nil {
		t.Fatalf("运行中 Reload: %v", err)
	}
}

func TestServiceStartReportsBadConfig(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(bad, []byte("server:\n  addr: \"\"\n"), 0o600); err != nil {
		t.Fatalf("写配置: %v", err)
	}
	svc := New(bad, nil)
	if err := svc.Start(); err == nil {
		t.Fatal("非法配置应当让 Start 失败")
	}
	if snap := svc.Snapshot(); snap.LastError == "" {
		t.Fatal("失败原因应记进快照供 GUI 展示")
	}
	if snap := svc.Snapshot(); snap.Running {
		t.Fatal("启动失败后不应是运行中")
	}
}

func TestServiceMetricsAlwaysPresent(t *testing.T) {
	if New("/nonexistent/config.yaml", nil).Metrics() == nil {
		t.Fatal("未传注册表时应自动建一个，GUI 不能拿到 nil")
	}
}

// TestServiceStartRecoversAfterPortFix 锁住一个曾经无解的故障：
// Start 失败后 prepare 装好的运行时状态一路留着，而 prepare 见到
// s.rt != nil 就直接返回。于是「端口被占用 → 在面板里换个端口 → 再启动」
// 永远拿着那份旧配置去绑同一个依旧被占用的端口，
// 用户改多少次都只看到同一句报错（托盘里也没有「重启」入口）。
func TestServiceStartRecoversAfterPortFix(t *testing.T) {
	cfgPath := newTestConfig(t)

	// 抢一个端口出来，让配置的 socks5 入站必然 bind 失败。
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("抢占端口: %v", err)
	}
	defer func() { _ = blocker.Close() }()
	_, busyPort, _ := net.SplitHostPort(blocker.Addr().String())

	// 把配置的 socks5 入站指到这个被占用的端口上。
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("读配置: %v", err)
	}
	cfg.Inbounds[0].Listen = "127.0.0.1:" + busyPort
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("写配置: %v", err)
	}

	svc := New(cfgPath, nil)
	defer svc.Stop()

	if err := svc.Start(); err == nil {
		t.Fatal("端口被占用时 Start 应当失败")
	}
	first := svc.Snapshot().LastError
	if first == "" {
		t.Fatal("失败原因应记进快照")
	}
	if svc.Snapshot().Running {
		t.Fatal("启动失败后不应是运行中")
	}

	// 用户在面板里把端口换掉，再点一次启动。这次必须能起来。
	cfg, err = config.Load(cfgPath)
	if err != nil {
		t.Fatalf("重新读配置: %v", err)
	}
	cfg.Inbounds[0].Listen = "127.0.0.1:0"
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatalf("写配置: %v", err)
	}

	if err := svc.Start(); err != nil {
		t.Fatalf("改掉端口后应能启动，实际仍失败: %v（首次错误: %s）", err, first)
	}
	snap := svc.Snapshot()
	if !snap.Running || len(snap.Inbounds) != 2 {
		t.Fatalf("重试后状态不对: running=%v inbounds=%d", snap.Running, len(snap.Inbounds))
	}
	if got := snap.Inbounds[0].Addr; got == "127.0.0.1:"+busyPort {
		t.Fatalf("重试后仍在用被占用的端口 %s，说明配置没有被重新读取", got)
	}
}

// TestServiceConcurrentStartSingleWinner 守住「启动」的原子性。
// 以前 Start 在 Prepare 前后各取一次锁、中间放掉一次，
// 托盘 goroutine 与 Wails 的 OnStartup 撞在一起时第二个 Start
// 会跳过锁获取直接去 bind 第一个正占着的端口，
// 于是代理明明在正常转发，用户看到的却是「端口已被占用，
// 先 pgrep 查查有没有另一个实例」。
func TestServiceConcurrentStartSingleWinner(t *testing.T) {
	svc := New(newTestConfig(t), nil)
	defer svc.Stop()

	const n = 4
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- svc.Start()
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Errorf("并发 Start 应当都成功（后到的等价于重启），实际: %v", err)
		}
	}
	snap := svc.Snapshot()
	if !snap.Running {
		t.Fatal("并发 Start 之后应处于运行中")
	}
	if snap.LastError != "" {
		t.Errorf("代理正常运行却残留 LastError: %q", snap.LastError)
	}
	if len(snap.Inbounds) != 2 {
		t.Errorf("入站数 = %d, 期望 2", len(snap.Inbounds))
	}
}

// TestServiceStatusReadableDuringStart 守住「界面不该假死」。
// 以前 Prepare/Start 抱着状态锁做 DNS 解析、编译整套规则、建网卡，
// 面板的每一次状态轮询都排在锁后面，界面白屏最长可达二十几秒，
// 连「停止」都发不出去。现在长操作都在锁外，状态读取必须始终可用。
func TestServiceStatusReadableDuringStart(t *testing.T) {
	svc := New(newTestConfig(t), nil)
	defer svc.Stop()

	startErr := make(chan error, 1)
	go func() { startErr <- svc.Start() }()

	// Start 进行中连续轮询状态：每一次都要在短时间内返回。
	// 用极短的预算，逼出「被长临界区堵住」这种回归。
	deadline := time.Now().Add(10 * time.Second)
	polls := 0
	for time.Now().Before(deadline) {
		select {
		case err := <-startErr:
			if err != nil {
				t.Fatalf("启动: %v", err)
			}
			// 启动已完成，剩下的循环不再有意义。
			polls++
			goto done
		default:
		}
		func() {
			done := make(chan struct{})
			go func() {
				_ = svc.Snapshot()
				_ = svc.TUNStatus()
				_ = svc.Mode()
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("状态轮询被启动流程堵住超过 2 秒，界面会假死")
			}
		}()
		polls++
	}
done:
	if polls == 0 {
		t.Fatal("没有成功轮询到状态")
	}
}

// TestServiceMutateSerializesWrites 守住配置文件的一致性。
// mutate 的读—改—存三步全程不碰状态锁，两个并发的界面操作
// （例如「切换到全局」与「新增节点」几乎同时点到）
// 会各自读到同一份基线、各自 Save，后写的把前一个的改动连同 .bak 一起抹掉。
func TestServiceMutateSerializesWrites(t *testing.T) {
	cfgPath := newTestConfig(t)
	svc := New(cfgPath, nil)
	defer svc.Stop()

	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("node-%d", i)
			_ = svc.AddProfile(ProfileSpec{Name: name, Addr: "127.0.0.1:4433", Auth: "a"})
		}(i)
	}
	wg.Wait()

	// 磁盘上的配置必须自洽：每个节点都还在，没有互相覆盖。
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("读配置: %v", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("配置解析失败（说明写入过程撕裂了文件）: %v", err)
	}
	_ = raw
	got := map[string]bool{}
	for _, p := range cfg.Proxies {
		got[p.Name] = true
	}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("node-%d", i)
		if !got[name] {
			t.Errorf("节点 %s 丢了：并发的配置写入互相覆盖了", name)
		}
	}
}

// TestSnapshotListsSerializeAsArrays 守住前后端之间的 JSON 契约：
// 快照里的列表字段必须是数组，不能是 null。
//
// 起因是 Engine.Skipped() 在没有规则被跳过时返回 nil slice，
// 直接赋值就序列化成 "rulesSkipped": null。前端读 .length 抛 TypeError，
// 整个状态面板被 Vue 降级成空注释节点，表现是 GUI 只剩顶栏、下面一片空白，
// 而且 window.onerror 抓不到任何报错，极难定位。列表字段一律编成空数组。
func TestSnapshotListsSerializeAsArrays(t *testing.T) {
	svc := New(newTestConfig(t), nil)
	defer svc.Stop()

	// 未启动与已启动两条路径都要查：前者 cfg 为 nil，后者会覆盖 RulesSkipped。
	if err := svc.Start(); err != nil {
		t.Fatalf("启动: %v", err)
	}
	for _, phase := range []string{"running", "stopped"} {
		if phase == "stopped" {
			if err := svc.Stop(); err != nil {
				t.Fatalf("停止: %v", err)
			}
		}
		raw, err := json.Marshal(svc.Snapshot())
		if err != nil {
			t.Fatalf("%s 序列化快照: %v", phase, err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s 解析快照: %v", phase, err)
		}
		for _, key := range []string{"inbounds", "rulesSkipped"} {
			if v, ok := got[key]; !ok {
				t.Errorf("%s: 快照缺字段 %s", phase, key)
			} else if v == nil {
				t.Errorf("%s: %s 序列化成 null，前端遍历会崩；JSON: %s", phase, key, raw)
			}
		}
	}
}

// TestProfileViewUDPMatchesOutbound 把界面上的 UDP 徽标钉在出站层的真实行为上。
//
// 徽标是从配置推导的，所以完全可能悄悄跑偏：哪天给 trojan 也放开了 UDP，
// 出站层能拨通而界面还在说「无 UDP」，用户就会照着一个不再成立的结论去排障。
//
// 这里刻意不靠类型断言来判能力——trojan 也有 DialUDP 方法，只是它必定回绝，
// 于是断言必然为真，一行代码就把守卫废掉了。能回答问题的只有一件事：
// 真去拨一次，看回来的是不是 ErrNoUDP。
//
// context 事先取消，于是这条用例不碰网络：hysteria2 会在握手里撞上取消并
// 返回 ctx 错误（不是 ErrNoUDP），trojan 直接回绝，两边都立刻返回。
func TestProfileViewUDPMatchesOutbound(t *testing.T) {
	cfg := &config.Config{}
	cfg.Proxies = []config.ProxyProfile{
		{Name: "hy", Server: config.ServerConfig{Type: config.ProtocolHysteria2, Addr: "203.0.113.1:443", Auth: "x"}},
		{Name: "tj", Server: config.ServerConfig{Type: config.ProtocolTrojan, Addr: "203.0.113.2:443", Auth: "x"}},
		{Name: "noType", Server: config.ServerConfig{Addr: "203.0.113.3:443", Auth: "x"}},
	}

	views := profileViews(cfg, "hy")
	if len(views) != len(cfg.Proxies) {
		t.Fatalf("视图条数 = %d, want %d", len(views), len(cfg.Proxies))
	}
	for i, p := range cfg.Proxies {
		real, err := outbound.New(p.Server, time.Second, nil, netip.Prefix{}, nil)
		if err != nil {
			t.Fatalf("造 %s 的出站: %v", p.Name, err)
		}
		pc, err := outbound.DialUDP(cancelledCtx(), real)
		if pc != nil {
			_ = pc.Close()
		}
		refuses := errors.Is(err, outbound.ErrNoUDP)
		if views[i].UDP == refuses {
			t.Errorf("%s: 界面说 UDP=%v，而真去拨 %v（err=%v）", p.Name, views[i].UDP, !refuses, err)
		}
	}
	// 没写 type 的按 hysteria2 处理，它的徽标也必须跟着走。
	if !views[2].UDP || views[2].Type != config.ProtocolHysteria2 {
		t.Errorf("没写 type 的节点：type=%q udp=%v, want hysteria2/true", views[2].Type, views[2].UDP)
	}
}

func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestBlocklistAppliedAndSurvivesReload 配置的 block: 段必须真的进到判定，
// 而且热重载之后还在。
//
// 后半段才是重点：Reload 换掉的是整个引擎，名单不跟着补一次就会在
// 下一次「重载规则」或订阅刷新之后**悄悄不再拦**。
// 而那恰好是最难发现的一类失效——没人会去盯一个本来就没在访问的域名。
func TestBlocklistAppliedAndSurvivesReload(t *testing.T) {
	cfgPath := newTestConfigWithBlock(t, []string{"ads.example.com"})
	svc := New(cfgPath, nil)
	if err := svc.Prepare(); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = svc.Stop() }()

	rt := svc.Router()
	if p, _ := rt.Decide(context.Background(), "x.ads.example.com"); p != "REJECT" {
		t.Fatalf("配置段的名单没生效，判定 = %q", p)
	}
	// 没在名单里的照旧走规则本身。
	if p, _ := rt.Decide(context.Background(), "www.example.com"); p != "DIRECT" {
		t.Errorf("未被拦的域名判定 = %q, 期望 DIRECT", p)
	}

	if err := svc.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if p, matched := rt.Decide(context.Background(), "x.ads.example.com"); p != "REJECT" {
		t.Fatalf("重载之后不拦了（判定 %q / %s）——名单在 Reload 里被换掉了", p, matched)
	}
}

// newTestConfigWithBlock 复用最小配置，只改规则文件与名单。
func newTestConfigWithBlock(t *testing.T, domains []string) string {
	t.Helper()
	base := newTestConfig(t)
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.Write(raw)
	b.WriteString("block:\n  domains: [")
	for i, d := range domains {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", d)
	}
	b.WriteString("]\n")
	out := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(out, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}
