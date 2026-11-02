package tunx

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// 这一组盯住「拆的时候 DNS 劫持有没有跟着拆干净」。
//
// 为什么它比路由那部分更要命：路由残留最多是让某个目标走错出口，
// 而劫持规则残留是把本机**所有** :53 指向一个已经不存在的地址——
// 整机解析全部超时，看起来像断网，实际上 nat 表里还挂着两条 DNAT。
// 进程被 kill -9 时我们的 defer 不会跑，所以每次启动都先无条件清一遍；
// 但「正常停止」这条路径必须自己拆干净，那才是绝大多数次数的实际情况。

// dnsRuleArgs 是 v4 劫持那几条会被删掉的规则的判据。
var dnsRuleArgs = []string{
	"-t nat -D OUTPUT -p udp --dport 53 -j wps_app_dns",
	"-t nat -D OUTPUT -p tcp --dport 53 -j wps_app_dns",
	"-t nat -F wps_app_dns",
	"-t nat -X wps_app_dns",
}

// hijackPlan 是「开着 DNS 劫持」的那份计划，两族都开。
func hijackPlan() RoutePlan {
	return RoutePlan{
		Device:       "wps-tun",
		Address:      "172.19.0.1/30",
		DNS:          "172.19.0.2",
		FakeIPRange:  "198.18.0.0/15",
		Address6:     "fd00:1::1/64",
		DNS6:         "fd00:1::2",
		FakeIPRange6: "fc00::/18",
		MTU:          1500,
		HijackDNS:    true,
		Upstreams:    []string{"223.5.5.5"},
	}
}

// TestStopRemovesEveryDNSRule 停止时必须把 v4 与 v6 的劫持规则逐条摘掉，
// 连挂在 POSTROUTING 上的回程 SNAT 也不能留——它不在自建链里，-F/-X 清不掉。
func TestStopRemovesEveryDNSRule(t *testing.T) {
	plan := hijackPlan()
	_, down, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	_, down6, err := plan.PlanV6()
	if err != nil {
		t.Fatal(err)
	}
	all := append(append([]Cmd{}, down...), down6...)

	for _, want := range dnsRuleArgs {
		if !hasCmd(all, "iptables", want) {
			t.Errorf("v4 的劫持规则没被摘掉: %q", want)
		}
	}
	for _, want := range []string{
		"-t nat -D OUTPUT -p udp --dport 53 -j wps_app_dns",
		"-t nat -D OUTPUT -p tcp --dport 53 -j wps_app_dns",
		"-t nat -F wps_app_dns",
		"-t nat -X wps_app_dns",
	} {
		if !hasCmd(all, "ip6tables", want) {
			t.Errorf("v6 的劫持规则没被摘掉: %q", want)
		}
	}
	// 回程 SNAT 必须逐条删：漏了的话这块网卡名以后被别的程序复用，
	// DNS 会被莫名改写源地址。
	for _, proto := range []string{"udp", "tcp"} {
		want := "-t nat -D POSTROUTING -o wps-tun -p " + proto + " --dport 53 -j SNAT --to-source 172.19.0.1"
		if !hasCmd(all, "iptables", want) {
			t.Errorf("v4 回程 SNAT（%s）没删: %q", proto, want)
		}
	}
	for _, proto := range []string{"udp", "tcp"} {
		want := "-t nat -D POSTROUTING -o wps-tun -p " + proto + " --dport 53 -j SNAT --to-source fd00:1::1"
		if !hasCmd(all, "ip6tables", want) {
			t.Errorf("v6 回程 SNAT（%s）没删: %q", proto, want)
		}
	}
}

// TestDNSTeardownPrecedesDeviceTeardown 拆的顺序不能反。
//
// 先摘 DNS 再拆网卡：反过来会留下一个中间状态——
// 网卡没了，但 iptables 还把 53 往黑洞里指。那一刻整机解析是瘫的，
// 而它只持续几毫秒，所以最难复现、也最难怀疑到顺序上。
func TestDNSTeardownPrecedesDeviceTeardown(t *testing.T) {
	_, down, err := hijackPlan().Plan()
	if err != nil {
		t.Fatal(err)
	}
	dnsAt, devAt := -1, -1
	for i, c := range down {
		if dnsAt < 0 && c.Bin == "iptables" && strings.Join(c.Args, " ") == "-t nat -D OUTPUT -p udp --dport 53 -j wps_app_dns" {
			dnsAt = i
		}
		if devAt < 0 && c.Bin == "ip" && strings.Join(c.Args, " ") == "link set dev wps-tun down" {
			devAt = i
		}
	}
	if dnsAt < 0 || devAt < 0 {
		t.Fatalf("down 列表里缺了某一步: dns=%d dev=%d", dnsAt, devAt)
	}
	if dnsAt > devAt {
		t.Errorf("DNS 劫持在网卡之后才摘（%d > %d），中途会把整机解析打瘫", dnsAt, devAt)
	}
}

// TestReleaseSystemRunsDNSCleanup 计划里写了摘除步骤不算数，
// 得确认拆除时真的把它们执行了——releaseSystem 正是 Stop 与启动回滚共用的那条路。
func TestReleaseSystemRunsDNSCleanup(t *testing.T) {
	plan := hijackPlan()
	runner := &recordingRunner{}
	tun := newDualTUN(t, runner)
	tun.plan = plan

	if err := tun.releaseSystem(context.Background(), plan); err != nil {
		t.Fatalf("拆除报错: %v", err)
	}
	ran := ""
	for _, c := range runner.ran {
		ran += c.String() + "\n"
	}
	for _, want := range dnsRuleArgs {
		if !strings.Contains(ran, want) {
			t.Errorf("拆除时没执行 %q:\n%s", want, ran)
		}
	}
	// 网卡地址与链路也必须一起拆：留着的话下次启动会撞上 File exists。
	if !strings.Contains(ran, "iptables -t nat -D POSTROUTING -o wps-tun -p udp --dport 53 -j SNAT --to-source 172.19.0.1") {
		t.Errorf("回程 SNAT 没删:\n%s", ran)
	}
}

// strictHijackPlan 是「开着劫持 + 接管默认路由」的那份计划。
// 加上接管是因为：只有那时「撤销默认路由」才是非 Optional 的一步，
// 下面两条用例才分得开「该报的」与「不该报的」。
func strictHijackPlan() RoutePlan {
	p := hijackPlan()
	p.StrictRoute = true
	p.Gateway = "10.60.0.254"
	p.Interface = "eth0"
	return p
}

// deviceGoneRunner 演的是网卡已经消失之后那个时刻的内核：
// 点名 wps-tun 的 ip 命令一律报 Cannot find device，别的都成功。
//
// 真实走到这一刻不需要什么意外——正常 Stop 就是先销毁协议栈，
// 而栈销毁链路时就把 fd 关了、设备没了。所以拆除列表里那几条**必然**报错。
type deviceGoneRunner struct {
	ran     []Cmd
	failure string
	failAll bool
}

func (r *deviceGoneRunner) Run(_ context.Context, c Cmd) (string, error) {
	r.ran = append(r.ran, c)
	if c.Bin != "ip" {
		return "", nil
	}
	joined := strings.Join(c.Args, " ")
	if r.failAll {
		if r.failure == "" {
			return "", errors.New("exit status 2")
		}
		return r.failure, errors.New("exit status 2")
	}
	if strings.Contains(joined, "wps-tun") {
		return `Cannot find device "wps-tun"`, errors.New("exit status 1")
	}
	return "", nil
}

// TestReleaseSystemTreatsGoneDeviceAsSuccess 是 netns 那条用例（TestNetnsStoppedTUNLeavesNoRouteIntoIt）
// 的脱机版本：没有 root 也要能守住同一件事。
//
// 曾经的错法是本地拆除只看"有没有报错"，于是每次停止都背着三条
// "Cannot find device wps-tun"——面板显示"TUN 已停止，但撤销时出错"，
// 而系统里其实干干净净，用户被教会对一个不存在的故障去重启机器。
func TestReleaseSystemTreatsGoneDeviceAsSuccess(t *testing.T) {
	plan := strictHijackPlan()
	runner := &deviceGoneRunner{}
	tun := newDualTUN(t, runner)
	tun.plan = plan

	if err := tun.releaseSystem(context.Background(), plan); err != nil {
		t.Fatalf("网卡先没了应当按成功处理，却报了: %v", err)
	}
	// 但也得确认真的执行过——"什么都不做"同样不会报错。
	ran := ""
	for _, c := range runner.ran {
		ran += c.String() + "\n"
	}
	for _, want := range []string{"route del default dev wps-tun", "addr del 172.19.0.1/30 dev wps-tun", "link set dev wps-tun down"} {
		if !strings.Contains(ran, want) {
			t.Errorf("没执行 %q:\n%s", want, ran)
		}
	}
}

// TestReleaseSystemStillReportsRealTeardownFailures 是上一条的另一半：
// 容忍不能变成"拆除这一步全都不算数"。
//
// 判据是错误文本，不是"反正拆除了就静默"。这里换成 EPERM：
// 那条撤销默认路由是非 Optional 的，报出来才说明撤销确实没做成。
func TestReleaseSystemStillReportsRealTeardownFailures(t *testing.T) {
	plan := strictHijackPlan()
	runner := &deviceGoneRunner{
		failAll: true,
		failure: "RTNETLINK answers: Operation not permitted",
	}
	tun := newDualTUN(t, runner)
	tun.plan = plan

	err := tun.releaseSystem(context.Background(), plan)
	if err == nil {
		t.Fatal("每一条 ip 命令都没做成，拆除却报告成功")
	}
	msg := err.Error()
	if !strings.Contains(msg, "撤销默认路由") {
		t.Errorf("非 Optional 的那步没报错出来:\n%s", msg)
	}
	// 反过来：Optional 的步骤（关网卡、摘地址）本来就不该挤进这句错误里，
	// 否则一次停止会刷出一屏与用户无关的噪声，把真正那条淹掉。
	for _, quiet := range []string{"关闭网卡", "摘掉网卡地址", "撤销假 IP 路由"} {
		if strings.Contains(msg, quiet) {
			t.Errorf("Optional 的步骤也被报成失败了: %s\n%s", quiet, msg)
		}
	}
}
