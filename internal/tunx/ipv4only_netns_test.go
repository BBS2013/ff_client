//go:build linux

package tunx

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"wps_app/internal/config"
)

// TestNetnsIPv4OnlyTakeover 补的是验收清单上那三种形状里少了的一种：
// **只有 v4 出口**的机器（v6-only 与双栈那两条早就有了）。
//
// 为什么这一种值得单独钉：它恰好是「两族必须分开」唯一能被证伪的场合——
// 只有一个族的出口时，把 v6 目标混进 v4 命令会被内核当场拒掉（invalid gateway），
// 而把 v6 也算成「已接管」则是在承诺一个根本走不通的接管。
// 面板那两格在这种机器上必须一格真一格假，而不是跟着 v4 一起亮。
func TestNetnsIPv4OnlyTakeover(t *testing.T) {
	if !fwReady() || !netnsReady() {
		t.Skip("需要 make test-netns-fw（WPS_FW=1 + 私有 netns）")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dev := config.DefaultTUN().Device
	r := ExecRunner{}
	fwEnsureNIC(t, ctx, r)
	fwMust(t, ctx, r, "ip", "route", "replace", "default", "via", restartGW, "dev", "fwphys0", "metric", "20600")
	// 这一条是整场戏的前提：**没有** v6 默认路由。同一次运行里别的用例可能刚在这张网
	// 装过一条，所以先显式清掉再检查——前提没立住，后面所有断言都是在演空戏。
	_, _ = r.Run(ctx, Cmd{Bin: "ip", Args: []string{"-6", "route", "del", "default"}})
	if out, _ := r.Run(ctx, Cmd{Bin: "ip", Args: []string{"-6", "-o", "route", "show", "default"}}); strings.TrimSpace(out) != "" {
		t.Fatalf("前置：这张网本该没有 v6 默认路由，现在有:\n%s", out)
	}

	// ipv6=true：用户要的是双栈接管；extraBypass 给一个「双栈节点」的 v6 地址。
	// 没有 v6 网关可钉，这一条必须被安静地跳过，而不是混进 v4 的 `ip route` 里。
	tun := startHijackTUN(t, ctx, true, true, "2001:db8::1")

	st := tun.Status()
	if !st.TakeoverV4 || st.TakeoverV6 {
		t.Errorf("面板那两格不对（want v4 已接管 / v6 未接管）: v4=%v v6=%v", st.TakeoverV4, st.TakeoverV6)
	}
	if st.TakeoverFrom != "kernel" {
		t.Errorf("这两格必须是内核读来的，不是进程记忆: %q", st.TakeoverFrom)
	}
	// 没有 v6 出口时连「假 v6」都不该发：应用拿到一个拨不通的地址，比拿到 NODATA 难查。
	if st.V6Ready {
		t.Errorf("这台机器没有 v6 出口，v6 假 IP 却报成可用——AAAA 会发一个拨不出去的地址")
	}

	v4def := fwMust(t, ctx, r, "ip", "-o", "route", "show", "default")
	if !strings.Contains(v4def, "default dev "+dev) {
		t.Errorf("v4 默认路由没交给 tun，这一族其实没接管:\n%s", v4def)
	}
	v6def := fwMust(t, ctx, r, "ip", "-6", "-o", "route", "show", "default")
	if strings.Contains(v6def, dev) {
		t.Errorf("没有 v6 出口却把 v6 默认路由装上了（那等于承诺了一个走不通的接管）:\n%s", v6def)
	}

	// 族的分界：v4 的绕行路由照装；v6 那个目标既不该出现在 v4 表里，
	// 也不该在没有 v6 网关时被硬塞进 v6 表。
	v4all := fwMust(t, ctx, r, "ip", "-o", "route", "show")
	if !strings.Contains(v4all, restartUpst) || !strings.Contains(v4all, restartGW) {
		t.Errorf("v4 上游的绕行路由没装上（我们自己的解析会被刚接管的默认路由抓回隧道）:\n%s", v4all)
	}
	if strings.Contains(v4all, "2001:db8::1") {
		t.Errorf("v6 目标混进了 v4 的路由命令——正是「双栈节点地址进错那组」的形态:\n%s", v4all)
	}
	v6all := fwMust(t, ctx, r, "ip", "-6", "-o", "route", "show")
	if strings.Contains(v6all, "2001:db8::1") {
		t.Errorf("没有 v6 网关却给 v6 目标装了绕行路由:\n%s", v6all)
	}

	// 接管不只是路由表上的样子：v4 这一族必须真的还能把查询送进我们的解析器。
	// 判据是**增量**——计数器在我发这条查询之前可能已经不是 0（启动过程自己就会解析），
	// 拿「>0」当证据会让这条用例在任何别的用例先跑过之后变成空跑。
	query := queryFor(t, "example.com.", dnsmessage.TypeA)
	base := tun.Status()
	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.WriteTo(query, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}); err != nil {
		t.Fatalf("查询没发出去: %v", err)
	}
	if !waitSome(30*time.Second, func() bool {
		s := tun.Status()
		return s.DNSServed+s.DNSFailed > base.DNSServed+base.DNSFailed
	}) {
		t.Errorf("v4 接管装好了，发往 8.8.8.8:53 的查询却没落进我们的解析器（基线 served=%d failed=%d）："+
			"路由是摆样子的", base.DNSServed, base.DNSFailed)
	}
}
