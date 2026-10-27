package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
)

const legacyCfg = `server:
  addr: "example.com:443"
  auth: "s3cret"
  bandwidth: { up: "200 mbps", down: "1000 mbps" }
  congestion: bbr
inbounds:
  - { type: socks5, listen: "127.0.0.1:0" }
  - { type: http,   listen: "127.0.0.1:0" }
`

func writeCfg(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(legacyCfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeCfgWithAddr 同 writeCfg，只把服务端地址换成指定的那个。
// 给「不想顺带依赖 DNS」的用例用：节点名是按地址主机部分推出来的，
// 所以传 IP 时节点名就是那串 IP。
// writeCfgWithAddr 同 writeCfg，只把服务端地址换成指定的那个。
// 给「不想顺带依赖 DNS」的用例用：节点名按地址主机部分推导，传 IP 时节点名就是那串 IP。
func writeCfgWithAddr(t *testing.T, addr string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	body := strings.Replace(legacyCfg, `addr: "example.com:443"`, `addr: "`+addr+`"`, 1)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSetModePersistsWithoutRestart 切模式不该动正在跑的进程：
// 全局/规则来回切如果每次都要重建隧道，那这个开关基本没法用。
func TestSetModePersistsWithoutRestart(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	for _, m := range []string{"global", "direct", "rule"} {
		if err := svc.SetMode(m); err != nil {
			t.Fatalf("SetMode(%s): %v", m, err)
		}
		if got := svc.Mode(); got != m {
			t.Errorf("Mode() = %q, 期望 %q", got, m)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Mode != m {
			t.Errorf("没落盘: %q", cfg.Mode)
		}
		if snap := svc.Snapshot(); snap.Mode != m {
			t.Errorf("快照里的模式 = %q", snap.Mode)
		}
	}
	if err := svc.SetMode("turbo"); err == nil {
		t.Error("非法模式应报错")
	}
}

// TestProfileLifecycle 是「添加新增代理服务」的主链路：
// 新增 → 列出 → 选中 → 改名 → 删除，每一步都要落到磁盘并在快照里可见。
func TestProfileLifecycle(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	list, active, err := svc.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "example.com" || !list[0].Active {
		t.Fatalf("旧配置迁移结果不对: %+v active=%q", list, active)
	}
	if !list[0].AuthSet || list[0].Addr != "example.com:443" {
		t.Fatalf("节点字段没读全: %+v", list[0])
	}

	if err := svc.AddProfile(ProfileSpec{
		Name: "新加坡", Addr: "sg.example.com:443", Auth: "sg-key",
		BandwidthUp: "100 mbps", BandwidthDown: "500 mbps", Congestion: "cubic", FastOpen: true,
	}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	if err := svc.AddProfile(ProfileSpec{Name: "新加坡", Addr: "x:443", Auth: "y"}); err == nil {
		t.Error("重名节点应被拒绝")
	}
	if err := svc.AddProfile(ProfileSpec{Name: "美国"}); err == nil {
		t.Error("缺 auth 的节点应被拒绝")
	}

	list, active, err = svc.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || active != "example.com" {
		t.Fatalf("新增后 active 不该跟着变: %+v %q", list, active)
	}
	if list[1].Name != "新加坡" || list[1].Addr != "sg.example.com:443" || !list[1].AuthSet {
		t.Fatalf("新节点字段不对: %+v", list[1])
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxies[1].Server.Bandwidth.Up != "100 mbps" || cfg.Proxies[1].Server.Congestion != "cubic" ||
		!cfg.Proxies[1].Server.FastOpen || cfg.Proxies[1].Server.TLS.SNI != "sg.example.com" {
		t.Fatalf("新节点没存全: %+v", cfg.Proxies[1].Server)
	}

	// 切节点：配置与快照都要跟上，但没在跑就不该偷偷启动。
	if err := svc.SetActiveProfile("新加坡"); err != nil {
		t.Fatalf("SetActiveProfile: %v", err)
	}
	if err := svc.SetActiveProfile("没有这个节点"); err == nil {
		t.Error("切到不存在的节点应报错")
	}
	cfg, _ = config.Load(path)
	if cfg.Active != "新加坡" || cfg.ActiveServer().Addr != "sg.example.com:443" {
		t.Fatalf("切换没生效: active=%q server=%q", cfg.Active, cfg.ActiveServer().Addr)
	}
	snap := svc.Snapshot()
	if snap.ActiveProfile != "新加坡" || snap.Server != "sg.example.com:443" {
		t.Fatalf("快照没跟上: %+v", snap)
	}
	// 新节点的 sni/带宽该出现在快照里，界面靠它显示「当前用的是什么」。
	if snap.SNI != "sg.example.com" || snap.Congestion != "cubic" || snap.BandwidthUp != "100 mbps" {
		t.Fatalf("快照里的节点参数不对: %+v", snap)
	}

	// 改名：Active 必须跟着走，否则改名等于把选中项丢了。
	if err := svc.UpdateProfile("新加坡", ProfileSpec{Name: "SG-1", Addr: "sg2.example.com:443", Insecure: true}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	cfg, _ = config.Load(path)
	if cfg.Active != "SG-1" || cfg.ActiveServer().Addr != "sg2.example.com:443" || !cfg.ActiveServer().TLS.Insecure {
		t.Fatalf("改名/改址没生效: active=%q %+v", cfg.Active, cfg.ActiveServer())
	}
	if cfg.ActiveServer().Auth != "sg-key" {
		t.Fatalf("没填口令却被改掉了: %q", cfg.ActiveServer().Auth)
	}

	// 删掉当前选中的节点：应自动落到剩下的那个，而不是报错或留下悬空 active。
	if err := svc.RemoveProfile("SG-1"); err != nil {
		t.Fatalf("RemoveProfile: %v", err)
	}
	cfg, _ = config.Load(path)
	if len(cfg.Proxies) != 1 || cfg.Active != "example.com" {
		t.Fatalf("删除后状态不对: %+v active=%q", cfg.Proxies, cfg.Active)
	}
	if err := svc.RemoveProfile("example.com"); err == nil {
		t.Error("最后一个节点不该能删")
	}
	if err := svc.RemoveProfile("不存在"); err == nil {
		t.Error("删不存在的节点应报错")
	}
}

// TestSnapshotExposesTUN 未运行时也得把 TUN 的意图说清楚：
// 界面要能显示「将会用哪块网卡、假 IP 段是什么」。
func TestSnapshotExposesTUN(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	if err := svc.SetTUNEnabled(true); err != nil {
		t.Fatalf("SetTUNEnabled: %v", err)
	}
	st := svc.TUNStatus()
	if !st.Enabled || st.Device != "wps-tun" || st.Address != "172.19.0.1/30" ||
		st.FakeIPRange != "198.18.0.0/15" || !st.HijackDNS {
		t.Fatalf("TUN 状态不对: %+v", st)
	}
	if st.Running {
		t.Fatal("服务没跑，TUN 不该是 running")
	}
	if snap := svc.Snapshot(); !snap.TUN.Enabled || snap.Mode != string(config.ModeRule) {
		t.Fatalf("快照里的 TUN/模式不对: %+v", snap)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TUN.Enable {
		t.Fatal("tun.enable 没落盘")
	}
	if err := svc.SetTUNEnabled(false); err != nil {
		t.Fatal(err)
	}
	if svc.TUNStatus().Enabled {
		t.Error("关闭后仍报启用")
	}
}

// TUN 没开启时，界面那行「特权路径」也要如实回答「点开启之后由谁建网卡」。
// 这份状态以前在三处各写一遍字面量，Privilege 漏在两处里，
// 结果配了 tun.helper 的面板显示成「本进程直接开（要求面板以 root 运行）」——
// 普通用户的面板明明能开起来，看的人却以为开不了。
func TestStoppedTUNStillReportsPrivilegePath(t *testing.T) {
	path := writeCfg(t)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.TUN.Enable = false
	cfg.TUN.Helper = []string{"sudo", "-n", "/usr/local/bin/wps_app", "--tun-helper"}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	svc := New(path, nil)

	if got := svc.TUNStatus(); got.Privilege != "helper" || len(got.HelperCmd) != 4 {
		t.Fatalf("TUNStatus 特权路径 = %q cmd=%v，期望 helper + 四条 argv", got.Privilege, got.HelperCmd)
	}
	if snap := svc.Snapshot(); snap.TUN.Privilege != "helper" || len(snap.TUN.HelperCmd) != 4 {
		t.Fatalf("快照里的特权路径 = %q cmd=%v，期望 helper + 四条 argv", snap.TUN.Privilege, snap.TUN.HelperCmd)
	}

	// 没配 helper 时才该报 self。
	cfg.TUN.Helper = nil
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	if got := svc.TUNStatus(); got.Privilege != "self" {
		t.Fatalf("去掉 helper 后特权路径 = %q, 期望 self", got.Privilege)
	}
}

// TestTestProfileUnknownNodeIsNotFound 界面上点「测速」时，
// 认不出这个节点要说清是「没有这个节点」——而不是含糊地报一句连不上。
//
// 地址用 IP 字面量：写成域名的话，用例要先花 3s+5s 去解析节点，
// 最后"失败"失败在 DNS 上，测的就不是这条契约了。
func TestTestProfileUnknownNodeIsNotFound(t *testing.T) {
	path := writeCfgWithAddr(t, "127.0.0.1:4433")
	svc := New(path, nil)

	res := svc.TestProfile("不存在的节点", "")
	if res.OK {
		t.Fatal("不存在的节点不该报成功")
	}
	if !strings.Contains(res.Error, "不存在") {
		t.Errorf("应明确报「节点不存在」，实际 %q", res.Error)
	}
	if res.Name != "不存在的节点" {
		t.Errorf("失败结果也要带得上节点名，界面才知道是哪一行: %+v", res)
	}
	// 没找到节点就不该去拨：探测目标保持空，等于告诉界面"还没开始"。
	if res.Remote != "" {
		t.Errorf("未走到拨号却填了探测目标: %q", res.Remote)
	}
}

// TestTestProfileBrokenConfigSaysSo 配置本身读不通时，自检必须说清是**配置**坏，
// 而不是"节点连不上"——否则用户会去查网络和防火墙，而问题在自己的 YAML 里。
func TestTestProfileBrokenConfigSaysSo(t *testing.T) {
	path := writeCfgWithAddr(t, "127.0.0.1") // 缺端口：config.Load 就会拒
	svc := New(path, nil)

	start := time.Now()
	res := svc.TestProfile("127.0.0.1", "127.0.0.1:1")
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("这条用例花了 %v，不该依赖真实网络时序", elapsed.Round(time.Millisecond))
	}
	if res.OK {
		t.Fatal("配置不合法不该报成功")
	}
	for _, want := range []string{"missing port", "addr"} {
		if !strings.Contains(res.Error, want) {
			t.Errorf("失败原因里该含 %q，好让人一眼看出是配置问题: %q", want, res.Error)
		}
	}
	if strings.Contains(res.Error, "解析") || strings.Contains(res.Error, "no such host") {
		t.Errorf("原因不该来自 DNS: %q", res.Error)
	}
}

// 说明：这里刻意**不**测「节点沉默不回话」那一条。它要吃满自检预算
// （实测即便对端起一个回垃圾包的 UDP 服务，QUIC 也只把它当无关包，
// 一路重传到 15s 才放弃）——拿它断言的是时序而不是契约。
// 节点沉默死掉的分类与超时归因由 outbound 层的
// ErrHandshakeTimeout / TestDialContextKeepsOrDropsSharedConnByErrorClass 那批用例管。
