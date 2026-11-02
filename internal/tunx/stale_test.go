package tunx

import (
	"context"
	"strings"
	"testing"
)

// 这一组盯住「上次没关干净」那条路。
//
// 进程被 kill -9 时我们的 defer 不会跑，iptables 的 DNS 劫持规则就留在系统里，
// 而它指向的那个假 DNS 地址随网卡一起消失了——后果是本机解析全部超时。
// 所以每次启动都无条件清一遍。
//
// 但「精确删除」会打不中：改过 device 或 address 之后，删的命令和留下的规则
// 对不上，残留就一直挂在 nat 表里（我们真遇到过——复位后仍剩 2 条）。
// 于是有了那套「按内容扫 POSTROUTING」的兜底，而它必须只删我们自己的规则。

// staleRunner 假装 nat 表里有一堆规则，并记下被删掉的那些。
type staleRunner struct {
	listing string
	deleted []string
}

func (r *staleRunner) Run(_ context.Context, c Cmd) (string, error) {
	joined := strings.Join(c.Args, " ")
	if strings.HasPrefix(joined, "-t nat -S") {
		return r.listing, nil
	}
	if strings.Contains(joined, "-D") {
		r.deleted = append(r.deleted, joined)
	}
	return "", nil
}

func (r *staleRunner) deletesFor(needle string) int {
	n := 0
	for _, d := range r.deleted {
		if strings.Contains(d, needle) {
			n++
		}
	}
	return n
}

// 内容扫描那一路删的是「从 -S 输出里抄来的 spec」，里面带 -m udp / -m tcp
// 这两个匹配模块；而按已知参数发的精确删除没有。用它们把两条路分开，
// 才测得到兜底扫描本身的行为。
const sweptMarker = "-m udp --dport 53"

// TestCleanupStaleSweepsOurOwnSNAT 残留的 SNAT 要被按内容扫出来删掉，
// 且只删我们的那两条。
func TestCleanupStaleSweepsOurOwnSNAT(t *testing.T) {
	r := &staleRunner{listing: strings.Join([]string{
		"-P POSTROUTING ACCEPT",
		// 这两条是我们的：网卡名对得上、改写 53 端口源地址。
		"-A POSTROUTING -o wps-tun -p udp -m udp --dport 53 -j SNAT --to-source 172.19.0.1",
		"-A POSTROUTING -o wps-tun -p tcp -m tcp --dport 53 -j SNAT --to-source 172.19.0.1",
		// 这条是用户自己的 NAT，一格都不能碰。
		"-A POSTROUTING -o docker0 -j MASQUERADE",
		// 这条也是别人的：别的网卡上的 53 改写。
		"-A POSTROUTING -o eth9 -p udp -m udp --dport 53 -j SNAT --to-source 10.0.0.1",
	}, "\n")}

	done := CleanupStale(context.Background(), r, 1000, "wps-tun", "172.19.0.1/30")

	if got := r.deletesFor(sweptMarker); got != 1 {
		t.Errorf("该按内容删掉我们那条带 -m udp 的 SNAT，实际删了 %d 条: %v", got, r.deleted)
	}
	if got := r.deletesFor("-m tcp --dport 53"); got != 1 {
		t.Errorf("该按内容删掉我们那条带 -m tcp 的 SNAT，实际删了 %d 条: %v", got, r.deleted)
	}
	if got := r.deletesFor("MASQUERADE"); got != 0 {
		t.Errorf("删了用户自己的 MASQUERADE 规则: %v", r.deleted)
	}
	if got := r.deletesFor("-o eth9"); got != 0 {
		t.Errorf("删了别的网卡上的规则: %v", r.deleted)
	}
	// 返回值给日志用：清了几项要说得出来。
	if len(done) == 0 {
		t.Error("清掉了东西却没报告")
	}
}

// TestCleanupStaleUsesDefaultDeviceName 配置改过网卡名之后，旧名字的残留也要清掉。
//
// 这正是精确删除打不中的那种情况：现在配的是 wps0，残留挂在 wps-tun 上。
func TestCleanupStaleUsesDefaultDeviceName(t *testing.T) {
	r := &staleRunner{listing: strings.Join([]string{
		"-A POSTROUTING -o wps-tun -p udp -m udp --dport 53 -j SNAT --to-source 172.19.0.1",
	}, "\n")}
	CleanupStale(context.Background(), r, 1000, "wps0", "172.19.0.1/30")
	if got := r.deletesFor("-o wps-tun"); got != 1 {
		t.Errorf("旧网卡名上的残留没被清掉: %v", r.deleted)
	}
}

// TestCleanupStaleIgnoresForeignChain 不属于我们的规则一行都不该动。
func TestCleanupStaleIgnoresForeignChain(t *testing.T) {
	r := &staleRunner{listing: strings.Join([]string{
		"-P POSTROUTING ACCEPT",
		"-A POSTROUTING -s 172.17.0.0/16 -o eth0 -j MASQUERADE",
		"-A POSTROUTING -o eth0 -p tcp -m tcp --dport 443 -j SNAT --to-source 1.2.3.4",
	}, "\n")}
	done := CleanupStale(context.Background(), r, 1000, "wps-tun", "172.19.0.1/30")
	// 只有那几条按已知参数发的精确删除会被尝试（它们本来就允许失败），
	// 内容扫描这一路不该提出任何删除。
	for _, d := range r.deleted {
		if strings.Contains(d, "MASQUERADE") || strings.Contains(d, "--to-source 1.2.3.4") {
			t.Errorf("动了别人的规则: %s", d)
		}
	}
	// 那几条按已知参数发的精确删除照常会试（它们允许失败），
	// 但内容扫描这一路一条都不该提。
	for _, d := range done {
		if strings.Contains(d, "按内容") {
			t.Errorf("没有我们的规则却报告按内容清掉了: %s", d)
		}
	}
}

// duplicatedJumpListing 是「重复装载」留下的那张表：同一个跳转挂了两次，
// 外加一条别人的链——后者一行都不该动。
const duplicatedJumpListing = "-P OUTPUT ACCEPT\n" +
	"-N wps_app_dns\n" +
	"-A OUTPUT -p udp -m udp --dport 53 -j wps_app_dns\n" +
	"-A OUTPUT -p udp -m udp --dport 53 -j wps_app_dns\n" +
	"-A OUTPUT -p tcp -m tcp --dport 53 -j wps_app_dns\n" +
	"-A OUTPUT -p udp -m udp --dport 53 -j docker_dns\n"

// TestCleanupStaleSweepsEveryDuplicatedJump 残留清理必须**收敛回零**，
// 而不是收敛回「还剩一份」。
//
// 只 -D 一次不够：链还被剩下的那一份引用着，-X 就永远失败，
// 于是 nat 表里永久挂着一个指向早就不存在的 DNS 落点的劫持链——
// 症状是整机解析超时，而这块网卡早随着上一个进程一起没了。
// 这个失败在单份残留里看不见，只有装过两遍才会露出来。
func TestCleanupStaleSweepsEveryDuplicatedJump(t *testing.T) {
	for name, run := range map[string]func(context.Context, Runner) []string{
		// 两条路都要扫：v4 是每次启动走的那条，v6 是双栈接管配套的那条。
		"CleanupStale": func(ctx context.Context, r Runner) []string {
			return CleanupStale(ctx, r, 1000, "wps-tun", "172.19.0.1/30")
		},
		"applyStale6": func(ctx context.Context, r Runner) []string {
			return applyStale6(ctx, r, RoutePlan{UID: 1000, Device: "wps-tun", Address6: "fd00:1::1/64"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := &staleRunner{listing: duplicatedJumpListing}
			done := run(context.Background(), r)
			// 按内容扫出来的 spec 带 -m udp / -m tcp，按已知参数发的那几条没有：
			// 用这个区别才数得到「扫描」这一路自己摘了几份。
			if got := r.deletesFor("-D OUTPUT -p udp -m udp"); got != 2 {
				t.Errorf("两份 UDP 跳转只按内容摘了 %d 份", got)
			}
			if got := r.deletesFor("-D OUTPUT -p tcp -m tcp"); got != 1 {
				t.Errorf("TCP 跳转按内容摘了 %d 份，应 1 份", got)
			}
			if got := r.deletesFor("docker_dns"); got != 0 {
				t.Errorf("别人的劫持跳转被动了 %d 次", got)
			}
			// 摘不动的东西不该报告成功：done 里那几条必须真对应上面数到的份数。
			var swept int
			for _, d := range done {
				if strings.Contains(d, "按内容") {
					swept++
				}
			}
			if swept != 3 {
				t.Errorf("按内容摘掉 3 份却报告了 %d 项，清残留的账对不上", swept)
			}
		})
	}
}
