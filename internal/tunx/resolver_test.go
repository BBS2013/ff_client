package tunx

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
)

// resolverRunner 按「命令长什么样」给出预定输出。
// 这一段的成败全在解析与分支上，不需要真去动 resolvectl。
type resolverRunner struct {
	ran     []Cmd
	outputs map[string]string // key = strings.Join(Args, " ")
	failOn  map[string]error  // 命中 key 时返回这个错误
	hangOn  string            // 命中这个 key 就一直等到 ctx 结束
}

func (r *resolverRunner) Run(ctx context.Context, c Cmd) (string, error) {
	key := strings.Join(c.Args, " ")
	r.ran = append(r.ran, c)
	if err, bad := r.failOn[key]; bad {
		if r.hangOn == key {
			<-ctx.Done()
			return "", ctx.Err()
		}
		return r.outputs[key], err
	}
	if r.hangOn == key {
		<-ctx.Done()
		return "", ctx.Err()
	}
	return r.outputs[key], nil
}

func (r *resolverRunner) ranArgs(haystack string) bool {
	for _, c := range r.ran {
		if strings.Contains(strings.Join(c.Args, " "), haystack) {
			return true
		}
	}
	return false
}

// newResolverTUN 造一个只用来跑这一段逻辑的 TUN。
// 配置路径落在 t.TempDir() 里，状态文件也就跟着用例走。
func newResolverTUN(t *testing.T, r Runner) *TUN {
	t.Helper()
	conf := config.DefaultTUN()
	conf.Enable = true
	rt := router.New(mustEngine(t), outbound.NewSet(outbound.NewDirect(time.Second), outbound.NewDirect(time.Second)), time.Second)
	tun, err := New(Options{
		Conf:       conf,
		Router:     rt,
		Runner:     r,
		Upstreams:  []string{"223.5.5.5", "10.180.191.11"},
		ConfigPath: filepath.Join(t.TempDir(), "config.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return tun
}

// probeKey 是脚本里那条探针命令的键（`resolvectl dns` 的键就是字面量 "dns"）。
const probeKey = "query --legend=no " + hijackProbeName

func TestProbeHijackedVerdicts(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		runErr  error
		hang    bool
		rng     string
		want    resolverFeeds
		wantSub string
	}{
		{
			name: "落在假 IP 段内", out: hijackProbeName + ": 198.18.0.31", rng: "198.18.0.0/15", want: feedsYes,
			wantSub: "198.18.0.31",
		},
		{
			name: "落在段外（真 IP）", out: hijackProbeName + ": 142.250.1.2", rng: "198.18.0.0/15", want: feedsNo,
			wantSub: "段外",
		},
		{
			// 这是本轮现场的那一档：解析器把查询原发给上游，上游说没这个名。
			name:    "NXDOMAIN 也算没生效",
			runErr:  errors.New("Resolve failed: Domain is not registered"),
			rng:     "198.18.0.0/15",
			want:    feedsNo,
			wantSub: "NXDOMAIN",
		},
		{
			name: "解析器不答不能当成没生效", hang: true, rng: "198.18.0.0/15", want: feedsUnknown,
			wantSub: "没在",
		},
		{
			name: "假 IP 段没配就别下结论", out: hijackProbeName + ": 198.18.0.31", rng: "", want: feedsUnknown,
			wantSub: "假 IP 段",
		},
		{
			// 输出里先出现一个段外地址、后面才是真答案：必须扫完再判。
			// 见到第一个 IP 就下结论会把"确实收到了劫持答案"读成"没生效"，
			// 于是去改系统解析器——而那次改动完全不该发生。
			name: "段外地址在前、段内答案在后", out: hijackProbeName + ": 8.8.8.8, 198.18.0.31",
			rng: "198.18.0.0/15", want: feedsYes, wantSub: "198.18.0.31",
		},
		{
			// 有输出但一个地址都没有：那是 resolvectl 的报错原文（Temporary failure、
			// 权限错、Too many open queries），不是"劫持没生效"的证据。
			// 判成 feedsNo 会仅凭一行错误文本去改系统配置。
			name: "答了但没有地址不能当成没生效", out: "Temporary failure in name resolution",
			rng: "198.18.0.0/15", want: feedsUnknown, wantSub: "没给出地址",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &resolverRunner{
				outputs: map[string]string{probeKey: tc.out},
				failOn:  map[string]error{},
			}
			if tc.runErr != nil {
				r.failOn[probeKey] = tc.runErr
			}
			if tc.hang {
				r.hangOn = probeKey
			}
			// 挂起那一档必须靠预算自己收，不能让测试真等下去。
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			got, detail := probeHijacked(ctx, r, tc.rng)
			if got != tc.want {
				t.Fatalf("判成 %v（%s），想要 %v", got, detail, tc.want)
			}
			if !strings.Contains(detail, tc.wantSub) {
				t.Fatalf("详情没带上下文的关键词：%s", detail)
			}
		})
	}
}

func TestParseLinkDNS(t *testing.T) {
	out := "Global:\n" +
		"Link 2 (eno1):\n" +
		"Link 3 (wlp3s0f0): 10.180.191.11 10.180.191.12\n" +
		"Link 4 (docker0):\n" +
		"        DNS Servers: 1.1.1.1\n"
	got := parseLinkDNS(out)
	if len(got["wlp3s0f0"]) != 2 || got["wlp3s0f0"][0] != "10.180.191.11" {
		t.Fatalf("把默认出口那张卡读错了：%v", got["wlp3s0f0"])
	}
	if len(got["eno1"]) != 0 {
		t.Fatalf("没配上游的 link 应该读成空：%v", got["eno1"])
	}
	// `resolvectl status` 形态的缩进行不属于 `Link N (name):` 这种输出，
	// 混进来会让「当前上游」被读成别人配的地址，进而把接管落在错的 link 上。
	for _, v := range got["docker0"] {
		if v == "1.1.1.1" {
			t.Fatalf("把状态行误读成了上游：%v", got["docker0"])
		}
	}
}

func TestResolverStatePathFollowsConfig(t *testing.T) {
	if got := resolverStatePath(""); got != "" {
		t.Fatalf("没有配置路径时不该落盘，拿到 %q", got)
	}
	got := resolverStatePath("/etc/wps/config.yaml")
	if want := "/etc/wps/config.yaml-resolver.state"; got != want {
		t.Fatalf("状态文件该跟着配置文件搬家：%q，想要 %q", got, want)
	}
	// 相对路径也算：面板常以 ./wps_app-gui ./config.yaml 启动。
	// Join 会把 "./" 洗掉，与 sysproxy.StatePath 同一结果——这里断言的是"跟着配置走"，
	// 不是某种具体写法。
	if got := resolverStatePath("config.yaml"); got != "config.yaml-resolver.state" {
		t.Fatalf("相对配置路径推导错了：%q", got)
	}
}

// TestFeedsDeadTakesOverResolver 是本轮现场的正解：
// 上游全在放行清单里 → 探针答段外 → 改接系统解析器，并把原值记账。
func TestFeedsDeadTakesOverResolver(t *testing.T) {
	r := &resolverRunner{
		outputs: map[string]string{
			probeKey:                   hijackProbeName + ": 142.250.1.2",
			"dns":                      "Global:\nLink 3 (wlp3s0f0): 10.180.191.11 10.180.191.12\n",
			"-o route show default":    "default via 10.180.63.254 dev wlp3s0f0 proto dhcp metric 600",
			"-6 -o route show default": "",
			"flush-caches":             "",
		},
		failOn: map[string]error{},
	}
	tun := newResolverTUN(t, r)
	tun.mu.Lock()
	tun.checkResolverFeedsTUN(context.Background())
	tun.mu.Unlock()

	if !r.ranArgs("dns wlp3s0f0 172.19.0.2") {
		t.Fatalf("没把系统解析器改接过来：%+v", r.ran)
	}
	if r.ranArgs("revert") {
		t.Fatalf("接管阶段不该 revert：%+v", r.ran)
	}
	if tun.resolver.ledger == nil || strings.Join(tun.resolver.ledger.Prev, ",") != "10.180.191.11,10.180.191.12" {
		t.Fatalf("原值没记进账里：%+v", tun.resolver.ledger)
	}
	st := tun.Status()
	if st.ResolverFeeds != "taken-over" {
		t.Fatalf("界面该说 taken-over，拿到 %q", st.ResolverFeeds)
	}
	if st.ResolverLink != "wlp3s0f0" {
		t.Fatalf("界面没带出改了哪张 link：%+v", st)
	}
	// 账必须先落到磁盘：被 kill -9 之后只剩它能说明原值是什么。
	raw, err := os.ReadFile(resolverStatePath(tun.configPath))
	if err != nil {
		t.Fatalf("状态文件没落盘：%v", err)
	}
	var l resolverLedger
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatalf("状态文件读不懂：%v", err)
	}
	if l.sameApplied([]string{"172.19.0.2"}) != true || l.Link != "wlp3s0f0" {
		t.Fatalf("账记错了：%+v", l)
	}
}

// TestFeedsUnknownNeverTouchesResolver 守住最容易犯的那个错：
// 读不到结论（解析器不可达 / 没有 resolvectl）时最不该改系统配置——
// 那一刻写进去的地址指向一块随时会消失的网卡。
func TestFeedsUnknownNeverTouchesResolver(t *testing.T) {
	r := &resolverRunner{
		outputs: map[string]string{
			probeKey:                "",
			"dns":                   "Global:\nLink 3 (wlp3s0f0): 10.180.191.11\n",
			"-o route show default": "default via 10.180.63.254 dev wlp3s0f0",
		},
		failOn: map[string]error{probeKey: errors.New("Too many open queries")},
	}
	tun := newResolverTUN(t, r)
	tun.mu.Lock()
	tun.checkResolverFeedsTUN(context.Background())
	tun.mu.Unlock()

	if r.ranArgs("dns wlp3s0f0") {
		t.Fatalf("验不出结论却改了系统解析器：%+v", r.ran)
	}
	if got := tun.Status().ResolverFeeds; got != "unverified" {
		t.Fatalf("该如实说没验过，拿到 %q", got)
	}
	if _, err := os.Stat(resolverStatePath(tun.configPath)); !os.IsNotExist(err) {
		t.Fatalf("没动手就不该有账：%v", err)
	}
}

// TestFeedsYesLeavesResolverAlone 是正常机器的样子：劫持本来就在收别人的查询，
// 那就不该有任何理由去碰系统解析器。
func TestFeedsYesLeavesResolverAlone(t *testing.T) {
	r := &resolverRunner{
		outputs: map[string]string{probeKey: hijackProbeName + ": 198.18.0.9"},
		failOn:  map[string]error{},
	}
	tun := newResolverTUN(t, r)
	tun.mu.Lock()
	tun.checkResolverFeedsTUN(context.Background())
	tun.mu.Unlock()

	if r.ranArgs("dns wlp3s0f0") {
		t.Fatalf("劫持已经在生效，还去改系统解析器：%+v", r.ran)
	}
	if got := tun.Status().ResolverFeeds; got != "yes" {
		t.Fatalf("该报 yes，拿到 %q", got)
	}
}

// TestRestoreWritesPrevNotRevert 钉住本轮实测到的那条坑：
// `resolvectl revert <link>` 不会退回 DHCP 那一组，而是把 link 掏空——
// 用它「回滚」等于让整机解析死掉。
func TestRestoreWritesPrevNotRevert(t *testing.T) {
	r := &resolverRunner{outputs: map[string]string{}, failOn: map[string]error{}}
	tun := newResolverTUN(t, r)
	tun.resolver.ledger = &resolverLedger{
		Link:    "wlp3s0f0",
		Prev:    []string{"10.180.191.11", "10.180.191.12"},
		Applied: []string{"172.19.0.2"},
	}
	_ = writeResolverLedger(tun.configPath, tun.resolver.ledger)

	tun.mu.Lock()
	tun.restoreResolver(context.Background())
	tun.mu.Unlock()

	if !r.ranArgs("dns wlp3s0f0 10.180.191.11 10.180.191.12") {
		t.Fatalf("原值没写回去：%+v", r.ran)
	}
	if r.ranArgs("revert") {
		t.Fatalf("原值不为空时不该用 revert：%+v", r.ran)
	}
	if tun.resolver.ledger != nil {
		t.Fatalf("还原之后账还挂着，下次 Stop 会白写一遍")
	}
	if _, err := os.Stat(resolverStatePath(tun.configPath)); !os.IsNotExist(err) {
		t.Fatalf("状态文件没删干净：%v", err)
	}
}

// TestRestoreRevertsOnlyWhenPrevWasEmpty：DHCP 本来就没发上游时，
// 要的状态本身就是「这条 link 没有上游」，那时 revert 才是对的。
func TestRestoreRevertsOnlyWhenPrevWasEmpty(t *testing.T) {
	r := &resolverRunner{outputs: map[string]string{}, failOn: map[string]error{}}
	tun := newResolverTUN(t, r)
	tun.resolver.ledger = &resolverLedger{Link: "wlp3s0f0", Applied: []string{"172.19.0.2"}}
	tun.mu.Lock()
	tun.restoreResolver(context.Background())
	tun.mu.Unlock()
	if !r.ranArgs("revert wlp3s0f0") {
		t.Fatalf("原值为空时该撤销这条 link：%+v", r.ran)
	}
}

// TestRecoverLedgerAfterKill 是「面板被 kill -9」那一支：
// 网卡早没了，系统解析器还指着它的地址，账本必须能把它收回来。
func TestRecoverLedgerAfterKill(t *testing.T) {
	r := &resolverRunner{
		outputs: map[string]string{
			"dns": "Global:\nLink 3 (wlp3s0f0): 172.19.0.2\n",
		},
		failOn: map[string]error{},
	}
	tun := newResolverTUN(t, r)
	// 先造一份上一轮留下的账。
	if err := writeResolverLedger(tun.configPath, &resolverLedger{
		Link:    "wlp3s0f0",
		Prev:    []string{"10.180.191.11"},
		Applied: []string{"172.19.0.2"},
	}); err != nil {
		t.Fatal(err)
	}
	tun.mu.Lock()
	tun.recoverResolverLedger(context.Background())
	tun.mu.Unlock()

	if !r.ranArgs("dns wlp3s0f0 10.180.191.11") {
		t.Fatalf("被 kill 留下的接管没收回：%+v", r.ran)
	}
	if _, err := os.Stat(resolverStatePath(tun.configPath)); !os.IsNotExist(err) {
		t.Fatalf("收回来之后账该没了：%v", err)
	}
}

// TestRecoverLedgerDropsSomeoneElsesConfig 是另一侧：桌面用户或别的程序
// 已经改过解析器了，照旧账写回就是覆盖别人的决定。
func TestRecoverLedgerDropsSomeoneElsesConfig(t *testing.T) {
	r := &resolverRunner{
		outputs: map[string]string{
			"dns": "Global:\nLink 3 (wlp3s0f0): 8.8.8.8\n",
		},
		failOn: map[string]error{},
	}
	tun := newResolverTUN(t, r)
	if err := writeResolverLedger(tun.configPath, &resolverLedger{
		Link: "wlp3s0f0", Prev: []string{"10.180.191.11"}, Applied: []string{"172.19.0.2"},
	}); err != nil {
		t.Fatal(err)
	}
	tun.mu.Lock()
	tun.recoverResolverLedger(context.Background())
	tun.mu.Unlock()

	if r.ranArgs("dns wlp3s0f0") || r.ranArgs("revert") {
		t.Fatalf("当前值已经不是我们写的那组，还去改就是覆盖别人：%+v", r.ran)
	}
	if _, err := os.Stat(resolverStatePath(tun.configPath)); !os.IsNotExist(err) {
		t.Fatalf("过时的账不该留着：%v", err)
	}
}

// TestTakeoverDoesNotRecordItselfAsPrev 守的是第二次接管：
// 若把「当前值」当原值记下来，回滚就把解析器永久钉在自己身上，
// 而那块网卡随时会随进程消失。
func TestTakeoverDoesNotRecordItselfAsPrev(t *testing.T) {
	r := &resolverRunner{
		outputs: map[string]string{
			"dns": "Global:\nLink 3 (wlp3s0f0): 172.19.0.2\n",
		},
		failOn: map[string]error{},
	}
	tun := newResolverTUN(t, r)
	// 上一轮的账还在（当前值就是我们写的 172.19.0.2）。
	if err := writeResolverLedger(tun.configPath, &resolverLedger{
		Link: "wlp3s0f0", Prev: []string{"10.180.191.11"}, Applied: []string{"172.19.0.2"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := tun.takeoverResolver(context.Background(), "wlp3s0f0", []string{"172.19.0.2"}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(tun.resolver.ledger.Prev, ","); got != "10.180.191.11" {
		t.Fatalf("原值被自己覆盖了（%s），回滚就再也回不去", got)
	}
}

// TestSameAppliedIgnoresOrder 锁住「顺序不参与语义」这一条。
//
// resolvectl 回读的顺序与我们写入的顺序不保证一致（同一条 link 两次回读
// 的排列可以不同）。按字符串比会把"我们自己的配置"认成"别人改过了"，
// 于是被 kill 之后不再回滚——系统解析器永远指着已经消失的 tun 地址，
// 整机解析停在那儿，而症状看起来像代理挂了。
func TestSameAppliedIgnoresOrder(t *testing.T) {
	l := &resolverLedger{Applied: []string{"172.19.0.2", "10.180.191.11"}}
	if !l.sameApplied([]string{"10.180.191.11", "172.19.0.2"}) {
		t.Fatal("顺序换一下就被认成别人的配置了")
	}
	if !l.sameApplied([]string{"  10.180.191.11 ", "172.19.0.2"}) {
		t.Fatal("前后空白不该影响判定")
	}
	if l.sameApplied([]string{"10.180.191.11"}) {
		t.Fatal("少一个地址应当判为不同")
	}
	if l.sameApplied([]string{"10.180.191.11", "1.1.1.1"}) {
		t.Fatal("多一个地址应当判为不同")
	}
}

// TestReadResolverLedgerRejectsTamperedFields 锁住「磁盘上这份账按不可信输入校验」。
//
// 这个文件在配置旁边、属主还是桌面用户，而它的内容会原样进
// `resolvectl dns <link> <addr...>`：以 '-' 开头的值会被 iproute2 当成选项，
// 乱写的 link 名会让命令落到别的网络接口上。内存里那份都过过 ParseAddr，
// 磁盘上这份必须再过一遍——否则普通用户写一行 JSON 就能让 root 改系统解析器。
func TestReadResolverLedgerRejectsTamperedFields(t *testing.T) {
	cases := []struct {
		name  string
		led   resolverLedger
		valid bool
	}{
		{
			name:  "正常账",
			led:   resolverLedger{Link: "wlp3s0f0", Prev: []string{"10.180.191.11"}, Applied: []string{"172.19.0.2"}},
			valid: true,
		},
		{
			name:  "Prev 为空是合法的（DHCP 没发上游）",
			led:   resolverLedger{Link: "wlp3s0f0", Applied: []string{"172.19.0.2"}},
			valid: true,
		},
		{
			name:  "地址位被塞了选项",
			led:   resolverLedger{Link: "wlp3s0f0", Prev: []string{"--set-dns=1.1.1.1"}, Applied: []string{"172.19.0.2"}},
			valid: false,
		},
		{
			name:  "地址位被塞了域名",
			led:   resolverLedger{Link: "wlp3s0f0", Prev: []string{"evil.example"}, Applied: []string{"172.19.0.2"}},
			valid: false,
		},
		{
			name:  "link 名以短横线开头",
			led:   resolverLedger{Link: "-x", Prev: []string{"10.0.0.1"}, Applied: []string{"172.19.0.2"}},
			valid: false,
		},
		{
			name:  "link 名带路径分隔符",
			led:   resolverLedger{Link: "../etc", Prev: []string{"10.0.0.1"}, Applied: []string{"172.19.0.2"}},
			valid: false,
		},
		{
			name:  "没有 Applied 就无从判断归属",
			led:   resolverLedger{Link: "wlp3s0f0", Prev: []string{"10.0.0.1"}},
			valid: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			raw, err := json.Marshal(tc.led)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(resolverStatePath(path), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			got := readResolverLedger(path)
			if tc.valid && got == nil {
				t.Fatal("合法的账被判成读不懂，回滚会失效")
			}
			if !tc.valid && got != nil {
				t.Fatalf("被篡改的账被接受了：%+v", got)
			}
		})
	}
}
