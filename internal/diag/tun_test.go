package diag

import (
	"context"
	"errors"
	"strings"
	"testing"

	"wps_app/internal/tunx"
)

// 这一组盯 TUN 那一节里「接管范围」那几行。
//
// 判据必须来自内核（`ip route`），不能来自本进程记得的状态：
// 面板那两格说的是"我们以为装上了什么"，而这份报告是给
// 「面板说接管了、浏览器却打不开」那种现场用的——两者不一致的那一刻才是它最值钱的一刻。

// stubRunner 按命令行返回预先录好的 `ip` 输出：带 -6 的那条给 v6，其余给 v4。
type stubRunner struct {
	v4Out string
	v6Out string
	err   error
}

func (s stubRunner) Run(_ context.Context, c tunx.Cmd) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	for _, a := range c.Args {
		if a == "-6" {
			return s.v6Out, nil
		}
	}
	return s.v4Out, nil
}

// lineFor 取报告里某一族的那一行。
//
// 四句判据是互斥的模板，所以断言必须落在"这一族这一行"上：
// 拿整篇文本比子串的话，另一族那行会把这一族说错的话掩掉——
// 第一版就是这么红的（IPv6 那句合法的「与配置一致」
// 让「IPv4 不许说与配置一致」这条断言再也无法成立）。
func lineFor(out, label string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, label) {
			return l
		}
	}
	return ""
}

func TestDiagStatesActualTakeoverPerFamily(t *testing.T) {
	const dev = "wps-tun"
	cases := []struct {
		name         string
		strict       bool
		v4, v6       string
		want4, want6 string
	}{
		{
			// 双栈都真接管了：两行都必须说"接管成立"。
			name:   "两族都在 tun 上",
			strict: true,
			v4:     "default dev wps-tun metric 100",
			v6:     "default dev wps-tun metric 100",
			want4:  "IPv4 默认路由指向 wps-tun：接管成立",
			want6:  "IPv6 默认路由指向 wps-tun：接管成立",
		},
		{
			// 这是最常见的那种"红得说不清"的时刻：配置要求接管，
			// v6 那一族却没装上。必须点名是哪一族、此刻走的哪儿。
			name:   "接管只装上了 v4",
			strict: true,
			v4:     "default dev wps-tun metric 100",
			v6:     "default via fe80::1 dev wlp3s0f0 metric 600",
			want4:  "接管成立",
			want6:  "接管没成立",
		},
		{
			// 残留：没要求接管，默认路由却还指着 tun。
			// 这一行是整份报告里最要紧的一句——它意味着机器现在没有出口。
			name:   "撤销没做干净",
			strict: false,
			v4:     "default dev wps-tun metric 100",
			v6:     "default via fe80::1 dev wlp3s0f0 metric 600",
			want4:  "没撤销干净的残留",
			want6:  "未接管，与配置一致",
		},
		{
			// 只有一族有默认路由的机器（纯 v4 网络）：另一族要说"与接管无关"，
			// 不能含含糊糊写成"未接管"，那会让人以为是我们没装上。
			// v4 这一族确实接管失败了，那句也照样得说。
			name:   "v6 本来就没出口",
			strict: true,
			v4:     "default via 192.168.5.1 dev wlp3s0f0 proto dhcp metric 20600",
			v6:     "",
			want4:  "接管没成立",
			want6:  "接管与否都与它无关",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &builder{}
			takeoverLines(b, context.Background(), stubRunner{v4Out: tc.v4, v6Out: tc.v6}, dev, tc.strict)
			out := b.String()
			for _, want := range []struct{ label, text string }{{"IPv4", tc.want4}, {"IPv6", tc.want6}} {
				line := lineFor(out, want.label)
				if line == "" {
					t.Fatalf("%s 那一行没有:\n%s", want.label, out)
				}
				if !strings.Contains(line, want.text) {
					t.Errorf("%s 那行该含 %q，实际是:\n%s", want.label, want.text, line)
				}
			}
		})
	}
}

// TestDiagSaysReadFailedInsteadOfSilence 是"读不到就写读不到"那条硬约束在这一节的落点：
// 没有 ip 命令（或者那一族的路由表读不了）时必须留下一行，
// 而不是安静地少两行——空白的报告会让人以为"接管没问题"。
func TestDiagSaysReadFailedInsteadOfSilence(t *testing.T) {
	b := &builder{}
	takeoverLines(b, context.Background(),
		stubRunner{err: errors.New(`exec: "ip": executable file not found`)}, "wps-tun", true)
	out := b.String()
	for _, label := range []string{"IPv4", "IPv6"} {
		line := lineFor(out, label)
		if !strings.Contains(line, "读不到") {
			t.Errorf("%s 那一行该写明读不到:\n%s", label, out)
		}
		if strings.Contains(line, "接管成立") {
			t.Errorf("读不到的时候不许下结论:\n%s", line)
		}
	}
}
