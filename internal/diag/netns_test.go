//go:build linux

package diag

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wps_app/internal/tunx"
)

// 这一组把 A33 那四句判据从「喂给替身的输出」升级成「内核真长成那样」。
//
// 为什么替身不够：单元用例里那份 `ip route show default` 的文本是我自己写的，
// 它只能证明「解析器认得我认识的那种写法」。而这个项目被这类事咬过两次——
// v6 网关写成 fe80::x%网卡 被 iproute2 整条拒掉、网关是本机地址时内核报
// "Gateway can not be a local address"：命令看着对、内核不吃，替身照样绿。
// 接管成立/残留/没成立这三句，必须有内核真的把默认路由交给 tun 的那一次。

const (
	diagDevice = "wps-tun"
	diagPhys   = "diagphys0"
	diagGW     = "10.77.0.254"
)

// diagMust 跑一条必须成功的命令。
func diagMust(t *testing.T, ctx context.Context, args ...string) string {
	t.Helper()
	out, err := tunx.ExecRunner{}.Run(ctx, tunx.Cmd{Bin: args[0], Args: args[1:]})
	if err != nil {
		t.Fatalf("%s 失败: %v（%s）", strings.Join(args, " "), err, out)
	}
	return out
}

// diagOK 跑一条「已经这样了也算成功」的命令。同一个 netns 会被多轮共用。
func diagOK(t *testing.T, ctx context.Context, args ...string) {
	t.Helper()
	_, _ = tunx.ExecRunner{}.Run(ctx, tunx.Cmd{Bin: args[0], Args: args[1:]})
}

// diagConfig 写一份够报告走完 TUN 那节的配置。
// 网卡名与地址必须和真装进内核的那一份一致，否则「指向 wps-tun」这句根本对不上。
func diagConfig(t *testing.T, strict bool) string {
	t.Helper()
	strictText := "false"
	if strict {
		strictText = "true"
	}
	body := "mode: rule\n" +
		"inbounds:\n  - type: socks5\n    listen: 127.0.0.1:17891\n" +
		"proxies:\n  - name: a\n    server:\n      type: hysteria2\n      addr: 192.0.2.1:443\n      auth: x\n" +
		"active: a\n" +
		"tun:\n  enable: true\n  device: " + diagDevice + "\n  address: 172.19.0.1/30\n" +
		"  dns: 172.19.0.2\n  fake_ip_range: 198.18.0.0/15\n" +
		"  hijack_dns: false\n  strict_route: " + strictText + "\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// diagReport 跑一次真实报告并返回文本。
func diagReport(t *testing.T, cfg string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var buf bytes.Buffer
	if err := Report(ctx, cfg, &buf); err != nil {
		t.Fatalf("报告没跑完: %v", err)
	}
	return buf.String()
}

// mustLineFor 挑出以某个前缀开头的那一行；找不到就失败——
// 「读不到那一行」与「那一行说得不对」是两种不同的故障，不能都算过。
func mustLineFor(t *testing.T, report, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(report, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), prefix) {
			return strings.TrimSpace(line)
		}
	}
	t.Fatalf("报告里没有以 %q 开头的一行:\n%s", prefix, report)
	return ""
}

// TestNetnsDiagVerdictsMatchKernel 把同一份内核现状分别喂给三种配置，
// 断言报告说的是此刻的真话。
func TestNetnsDiagVerdictsMatchKernel(t *testing.T) {
	if os.Getenv("WPS_NETNS") != "1" {
		t.Skip("需要私有网络命名空间（make test-offline / test-netns-fw 会打开 WPS_NETNS）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	r := tunx.ExecRunner{}

	// 物理侧：一块 dummy + 一条带网关的默认路由。网关必须不是本机地址。
	diagOK(t, ctx, "ip", "link", "add", diagPhys, "type", "dummy")
	t.Cleanup(func() {
		_, _ = r.Run(context.Background(), tunx.Cmd{Bin: "ip", Args: []string{"link", "del", diagPhys}})
	})
	diagOK(t, ctx, "ip", "addr", "add", "10.77.0.1/24", "dev", diagPhys)
	diagMust(t, ctx, "ip", "link", "set", diagPhys, "up")
	diagMust(t, ctx, "ip", "route", "replace", "default", "via", diagGW, "dev", diagPhys, "metric", "20600")

	if out, err := r.Run(ctx, tunx.Cmd{Bin: "ip", Args: []string{"tuntap", "add", "dev", diagDevice, "mode", "tun"}}); err != nil && !strings.Contains(out, "File exists") {
		t.Skipf("建不了 tun 网卡（多半没有 /dev/net/tun）: %v（%s）", err, out)
	}
	t.Cleanup(func() {
		_, _ = r.Run(context.Background(), tunx.Cmd{Bin: "ip", Args: []string{"link", "del", diagDevice}})
	})
	diagMust(t, ctx, "ip", "link", "set", diagDevice, "up")

	plan := tunx.RoutePlan{
		Device:      diagDevice,
		Address:     "172.19.0.1/30",
		FakeIPRange: "198.18.0.0/15",
		MTU:         1500,
		StrictRoute: true,
		Gateway:     diagGW,
		Interface:   diagPhys,
		Exclude:     []string{diagGW + "/32"},
	}
	up, down, err := plan.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if err := tunx.Apply(ctx, r, up); err != nil {
		t.Fatalf("把接管装进内核失败: %v", err)
	}
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		for _, c := range down {
			_, _ = r.Run(dctx, c)
		}
	})

	// 前提：内核此刻的默认路由确实指着 tun。报告的结论必须跟着这条事实走，
	// 所以这条得先看一眼——否则下面三句都可能对同一个假现状点头。
	if out := diagMust(t, ctx, "ip", "-o", "route", "show", "default"); !strings.Contains(out, "default dev "+diagDevice) {
		t.Fatalf("接管没真的装进内核，后面的判据无从判起:\n%s", out)
	}

	// 1) 配置要求接管，内核也确实是：接管成立。
	line := mustLineFor(t, diagReport(t, diagConfig(t, true)), "IPv4 默认路由")
	if !strings.Contains(line, "接管成立") || strings.Contains(line, "没成立") {
		t.Errorf("默认路由明明指着 %s 且配置要求接管，报告却说: %s", diagDevice, line)
	}

	// 2) 同一个现状，配置没要求接管：这就是没撤销干净的残留。
	//    这一句最有用——面板进程早没了，路由表不会替它认错。
	line = mustLineFor(t, diagReport(t, diagConfig(t, false)), "IPv4 默认路由")
	if !strings.Contains(line, "没撤销干净的残留") {
		t.Errorf("配置没要求接管而默认路由还指着 tun，报告没说这是残留: %s", line)
	}

	// 3) 撤掉那条路由：配置要求接管，内核不给 → 必须点名「没成立」并说出此刻走哪儿。
	diagMust(t, ctx, "ip", "route", "del", "default", "dev", diagDevice)
	line = mustLineFor(t, diagReport(t, diagConfig(t, true)), "IPv4 默认路由")
	if !strings.Contains(line, "接管没成立") || !strings.Contains(line, diagPhys) {
		t.Errorf("撤销之后报告没有改口（或没点名物理出口）: %s", line)
	}

	// IPv6 这一族在 netns 里本来就没默认路由，报告要说「与它无关」，
	// 不能因为 v4 接管了就顺带说 v6 也接管了——那正是这次要防的那种含糊。
	line = mustLineFor(t, diagReport(t, diagConfig(t, true)), "IPv6 默认路由")
	if !strings.Contains(line, "没有") && !strings.Contains(line, "读不到") {
		t.Errorf("这个 netns 里没有 v6 默认路由，报告却给出了接管结论: %s", line)
	}
}
