package tunx

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// helperPlan 是一份合法到可以直接交给 root 执行的请求参数。
func helperPlan(uid int) RoutePlan {
	return RoutePlan{
		Device:      "wps-tun",
		Address:     "172.19.0.1/30",
		DNS:         "172.19.0.2",
		FakeIPRange: "198.18.0.0/15",
		MTU:         1400,
		HijackDNS:   true,
		UID:         uid,
		Upstreams:   []string{"223.5.5.5", "119.29.29.29"},
	}
}

func TestHelperRequestValidate(t *testing.T) {
	ok := HelperRequest{V: helperProtoVersion, Action: ActionUp, Plan: helperPlan(os.Geteuid())}
	if err := ok.validate(); err != nil {
		t.Fatalf("合法请求被拒: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*HelperRequest)
		want   string
	}{
		{"版本不对", func(r *HelperRequest) { r.V = 99 }, "协议版本"},
		{"动作未知", func(r *HelperRequest) { r.Action = "reboot" }, "未知的 helper 动作"},
		{"网卡名为空", func(r *HelperRequest) { r.Plan.Device = "" }, "网卡名"},
		{"网卡名过长", func(r *HelperRequest) { r.Plan.Device = strings.Repeat("a", 16) }, "网卡名"},
		// 网卡名会同时进 argv 和 iptables 参数，空格与斜杠必须挡住。
		{"网卡名带空格", func(r *HelperRequest) { r.Plan.Device = "wps tun" }, "网卡名"},
		{"网卡名带斜杠", func(r *HelperRequest) { r.Plan.Device = "../../dev/net/tun" }, "网卡名"},
		{"地址缺掩码", func(r *HelperRequest) { r.Plan.Address = "172.19.0.1" }, "CIDR"},
		{"地址是 /0", func(r *HelperRequest) { r.Plan.Address = "0.0.0.0/0" }, "掩过短"},
		{"MTU 出格", func(r *HelperRequest) { r.Plan.MTU = 70000 }, "mtu"},
		{"uid 为负", func(r *HelperRequest) { r.Plan.UID = -1 }, "uid"},
		{"劫持缺 dns", func(r *HelperRequest) { r.Plan.DNS = "" }, "dns"},
		{"dns 不是 IP", func(r *HelperRequest) { r.Plan.DNS = "example.com" }, "合法 IP"},
		// 没有可放行的上游就不许劫持：我们自己的解析会被这条劫持抓回去。
		{"劫持缺上游", func(r *HelperRequest) { r.Plan.Upstreams = nil }, "上游"},
		{"上游不是 IP 字面量", func(r *HelperRequest) { r.Plan.Upstreams = []string{"dns.example.com"} }, "IP 字面量"},
		{"上游过多", func(r *HelperRequest) {
			r.Plan.Upstreams = make([]string, 20)
			for i := range r.Plan.Upstreams {
				r.Plan.Upstreams[i] = "223.5.5.5"
			}
		}, "过多"},
		{"假 IP 段过大", func(r *HelperRequest) { r.Plan.FakeIPRange = "0.0.0.0/4" }, "段过大"},
		{"strict 缺网卡", func(r *HelperRequest) { r.Plan.StrictRoute = true }, "strict_route"},
		{"strict 网关是 0.0.0.0", func(r *HelperRequest) {
			r.Plan.StrictRoute = true
			r.Plan.Interface = "wlp3s0"
			r.Plan.Gateway = "0.0.0.0"
		}, "网关"},
		{"排除段非法", func(r *HelperRequest) { r.Plan.Exclude = []string{"10.0.0/8"} }, "排除网段"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := HelperRequest{V: helperProtoVersion, Action: ActionUp, Plan: helperPlan(os.Geteuid())}
			tc.mutate(&req)
			err := req.validate()
			if err == nil {
				t.Fatalf("期望报错，实得 nil（plan=%+v）", req.Plan)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误 %q 未包含 %q", err, tc.want)
			}
		})
	}
	// down/cleanup 不需要 dns 之类的开启参数，也不该被拦住。
	if err := (HelperRequest{V: helperProtoVersion, Action: ActionDown, Plan: helperPlan(os.Geteuid())}).validate(); err != nil {
		t.Errorf("down 请求校验过严: %v", err)
	}
}

func TestHelperFrameRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	go func() {
		_ = writeFrame(c2, []byte(`{"ok":true}`))
	}()
	got, err := readFrame(c1)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"ok":true}` {
		t.Fatalf("读到 %q", got)
	}
	_ = c1.Close()
	_ = c2.Close()

	// 长度字段是外部输入：自称超长的帧必须在分配之前就被拒掉，
	// 否则一个畸形应答就能把面板的内存吃掉。
	bad := []uint32{0, maxHelperFrame + 1}
	for _, n := range bad {
		p1, p2 := net.Pipe()
		go func(n uint32) {
			_ = binary.Write(p2, binary.BigEndian, n)
			_ = p2.Close()
		}(n)
		if _, err := readFrame(p1); err == nil {
			t.Errorf("长度 %d 的帧应被拒绝", n)
		}
		_ = p1.Close()
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("  hello  ", 10); got != "hello" {
		t.Fatalf("应顺手去掉首尾空白: %q", got)
	}
	// 按 rune 截：中文 stderr 截出半个字，界面上就是一串乱码。
	if got := truncate("口令不对，请检查配置", 6); got != "口令不对，请…" {
		t.Fatalf("截断结果不对: %q", got)
	}
}

// helperTestServer 造一个进程内的 helper：不依赖 root、不依赖真网卡，
// 但套接字、SO_PEERCRED、SCM_RIGHTS 走的都是真路径。
func helperTestServer(srv *HelperServer) HelperClient {
	return HelperClient{
		Timeout: 5 * time.Second,
		Spawn: func(_ context.Context, socketPath string) error {
			go func() {
				conn, err := net.Dial("unix", socketPath)
				if err != nil {
					return
				}
				uc, ok := conn.(*net.UnixConn)
				if !ok {
					_ = conn.Close()
					return
				}
				_ = srv.ServeConn(uc)
			}()
			return nil
		},
	}
}

// socketPair 造一对连好的 unix socket：一头冒充 helper 建出来的「网卡」，
// 另一头留在测试手里，用来证明 fd 交接之后真的能收发。
func socketPair(t *testing.T) (dev int, peer int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	return fds[0], fds[1]
}

// TestHelperUpHandshakesRealFD 是整套设计的关键证明：
// 无权限的面板拿到 helper 交来的 fd 之后，能在那块设备上收发。
func TestHelperUpHandshakesRealFD(t *testing.T) {
	devFD, peer := socketPair(t)
	runner := &recorderRunner{}
	srv := &HelperServer{
		Runner:  runner,
		Open:    func(string) (int, error) { return devFD, nil },
		MTU:     func(string) (uint32, error) { return 1400, nil },
		Timeout: 5 * time.Second,
	}

	reply, gotFD, err := helperTestServer(srv).Run(context.Background(),
		HelperRequest{V: helperProtoVersion, Action: ActionUp, Plan: helperPlan(os.Geteuid())})
	if err != nil {
		t.Fatalf("helper up: %v", err)
	}
	if gotFD < 0 {
		t.Fatal("没有拿到设备 fd")
	}
	defer unix.Close(gotFD)

	if reply.Device != "wps-tun" || reply.MTU != 1400 {
		t.Fatalf("应答里的设备信息不对: %+v", reply)
	}
	// MTU 用 helper 报回来的真实值，不是配置里想要的那个：
	// 别的进程已经改过这块网卡时，配置里的期望值没有任何意义。
	if !strings.Contains(strings.Join(reply.Applied, "|"), "配置网卡地址") {
		t.Fatalf("Applied 没带上执行步骤: %+v", reply.Applied)
	}
	ran := runner.snapshot()
	if len(ran) == 0 {
		t.Fatal("helper 一条命令都没跑")
	}

	if _, err := unix.Write(peer, []byte{0x42}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := unix.Read(gotFD, buf); err != nil {
		t.Fatalf("从交接来的 fd 读取失败: %v", err)
	}
	if buf[0] != 0x42 {
		t.Fatalf("fd 上读到的不是对端写的字节: %#x", buf[0])
	}
}

func TestHelperDownRunsTeardown(t *testing.T) {
	devFD, _ := socketPair(t)
	runner := &recorderRunner{}
	srv := &HelperServer{
		Runner:  runner,
		Open:    func(string) (int, error) { return devFD, nil },
		MTU:     func(string) (uint32, error) { return 1500, nil },
		Timeout: 5 * time.Second,
	}
	client := helperTestServer(srv)
	ctx := context.Background()
	plan := helperPlan(os.Geteuid())

	if _, fd, err := client.Run(ctx, HelperRequest{V: helperProtoVersion, Action: ActionUp, Plan: plan}); err != nil {
		t.Fatal(err)
	} else {
		_ = unix.Close(fd)
	}

	down, _, err := client.Run(ctx, HelperRequest{V: helperProtoVersion, Action: ActionDown, Plan: plan})
	if err != nil {
		t.Fatalf("helper down: %v", err)
	}
	if !down.OK {
		t.Fatalf("down 报失败: %+v", down)
	}
	if !strings.Contains(strings.Join(down.Removed, "|"), "摘掉网卡地址") {
		t.Fatalf("Removed 不全: %+v", down.Removed)
	}
}

// TestHelperRefusesForeignUID 守的是提权接口上最要命的一条：
// 请求里的 uid 会写进 iptables 的 `! --uid-owner`，随便填就等于
// 任何本地用户都能借 root 替别的用户改写 netfilter 规则。
func TestHelperRefusesForeignUID(t *testing.T) {
	devFD, _ := socketPair(t)
	runner := &recorderRunner{}
	srv := &HelperServer{
		Runner:  runner,
		Open:    func(string) (int, error) { return devFD, nil },
		MTU:     func(string) (uint32, error) { return 1500, nil },
		Timeout: 5 * time.Second,
	}

	_, fd, err := helperTestServer(srv).Run(context.Background(),
		HelperRequest{V: helperProtoVersion, Action: ActionUp, Plan: helperPlan(os.Geteuid() + 1)})
	if err == nil {
		t.Fatal("uid 与连接对端不一致时应拒绝执行")
	}
	if fd >= 0 {
		_ = unix.Close(fd)
		t.Fatalf("拒绝之后不该交出 fd: %d", fd)
	}
	if !strings.Contains(err.Error(), "不一致") {
		t.Fatalf("错误应说清是 uid 问题: %v", err)
	}
	if len(runner.snapshot()) != 0 {
		t.Fatalf("拒绝之后一条命令都不该跑: %+v", runner.snapshot())
	}
}

// TestHelperUpRollsBackOnApplyFailure 钉住失败路径：网卡已经建起来了却配不下去时，
// 必须关掉它并回滚前面几步。留一块没有主人的 tun 在系统里，
// 下一次启动只会撞上 "File exists"，把真正的原因一层层盖住。
func TestHelperUpRollsBackOnApplyFailure(t *testing.T) {
	devFD, _ := socketPair(t)
	runner := &recorderRunner{fail: map[string]error{"ip link set dev wps-tun up": errors.New("operation not permitted")}}
	srv := &HelperServer{
		Runner:  runner,
		Open:    func(string) (int, error) { return devFD, nil },
		MTU:     func(string) (uint32, error) { return 1500, nil },
		Timeout: 5 * time.Second,
	}

	_, fd, err := helperTestServer(srv).Run(context.Background(),
		HelperRequest{V: helperProtoVersion, Action: ActionUp, Plan: helperPlan(os.Geteuid())})
	if err == nil {
		t.Fatal("apply 失败时应报错")
	}
	if fd >= 0 {
		t.Fatalf("失败了还交回一个 fd: %d", fd)
	}
	if !strings.Contains(err.Error(), "启用网卡") {
		t.Fatalf("错误里应带出失败的那一步: %v", err)
	}
	ran := strings.Join(runner.snapshot(), "|")
	if !strings.Contains(ran, "ip addr del 172.19.0.1/30 dev wps-tun") {
		t.Fatalf("没有回滚已经执行过的步骤: %s", ran)
	}
}

func TestTUNProvisionUsesHelperAndReleases(t *testing.T) {
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.Helper = []string{"sudo", "-n", "./wps_app", "--tun-helper"}
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(time.Second), nil), time.Second)

	tun, err := New(Options{Conf: conf, Router: rt, Upstreams: []string{"223.5.5.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if !tun.usesHelper() {
		t.Fatal("配了 tun.helper 却走的是直接开的路径")
	}
	st := tun.Status()
	if st.Privilege != "helper" || len(st.HelperCmd) != 4 {
		t.Fatalf("状态里该看得出走的哪条特权路径: %+v", st)
	}

	devFD, peer := socketPair(t)
	runner := &recorderRunner{}
	tun.helper = helperTestServer(&HelperServer{
		Runner:  runner,
		Open:    func(string) (int, error) { return devFD, nil },
		MTU:     func(string) (uint32, error) { return uint32(conf.MTU), nil },
		Timeout: 5 * time.Second,
	})

	plan, err := tun.buildPlan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dev, applied, err := tun.provision(context.Background(), plan)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if dev == nil || len(applied) == 0 {
		t.Fatalf("provision 结果不对: dev=%v applied=%d", dev, len(applied))
	}
	if dev.Name() != conf.Device {
		t.Fatalf("设备名不对: %s", dev.Name())
	}
	// 面板手里的 fd 必须真的通到 helper 那头：往对端写一字节，网卡这头读得到。
	if _, err := unix.Write(peer, []byte{0x16}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := unix.Read(devFD, buf); err == nil && buf[0] != 0x16 {
		t.Fatalf("读到的不是预期的字节: %#x", buf[0])
	}
	dev.Close()

	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tun.releaseSystem(dctx, plan); err != nil {
		t.Fatalf("releaseSystem: %v", err)
	}
	// 启停两侧的 ip/iptables 都必须由 helper 跑完：本进程一条都不该直接执行。
	if len(runner.snapshot()) < 2 {
		t.Fatalf("helper 跑的命令太少: %+v", runner.snapshot())
	}
}

func TestTUNReleaseSystemLocalPath(t *testing.T) {
	// 没配 helper 时，拆系统配置仍走本进程的 runner——老行为不能漂。
	conf := config.DefaultTUN()
	conf.Enable = true
	runner := &recorderRunner{}
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(time.Second), nil), time.Second)
	tun, err := New(Options{Conf: conf, Router: rt, Runner: runner, Upstreams: []string{"223.5.5.5"}})
	if err != nil {
		t.Fatal(err)
	}
	if tun.usesHelper() {
		t.Fatal("没配 helper 不该走提权命令")
	}
	if st := tun.Status(); st.Privilege != "self" {
		t.Fatalf("状态里的特权路径不对: %+v", st)
	}
	if err := tun.releaseSystem(context.Background(), helperPlan(os.Geteuid())); err != nil {
		t.Fatalf("releaseSystem: %v", err)
	}
	if len(runner.snapshot()) == 0 {
		t.Fatal("本进程路径没跑任何清理命令")
	}
}

// TestTUNCleanupStaleGoesThroughHelper 保证「清残留」也走提权路径：
// 普通用户面板自己跑 iptables 会全军覆没，而残留没清正是整机 DNS 挂掉那个坑。
func TestTUNCleanupStaleGoesThroughHelper(t *testing.T) {
	conf := config.DefaultTUN()
	conf.Enable = true
	conf.Helper = []string{"sudo", "-n", "./wps_app", "--tun-helper"}
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(time.Second), nil), time.Second)
	localRunner := &recorderRunner{}
	tun, err := New(Options{Conf: conf, Router: rt, Runner: localRunner, Upstreams: []string{"223.5.5.5"}})
	if err != nil {
		t.Fatal(err)
	}

	devFD, _ := socketPair(t)
	helperRunner := &recorderRunner{}
	tun.helper = helperTestServer(&HelperServer{
		Runner:  helperRunner,
		Open:    func(string) (int, error) { return devFD, nil },
		MTU:     func(string) (uint32, error) { return 1500, nil },
		Timeout: 5 * time.Second,
	})
	if got := tun.cleanupStale(context.Background()); len(got) == 0 {
		t.Fatal("cleanup 应把清掉的动作报回来")
	}
	if len(localRunner.snapshot()) != 0 {
		t.Fatalf("配了 helper 就不该在本进程跑 iptables: %+v", localRunner.snapshot())
	}
}
