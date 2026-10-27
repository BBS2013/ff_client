package rulesub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"wps_app/internal/rules"
)

const goodRules = "# 一条能用的规则集\nDOMAIN-SUFFIX,example.com,DIRECT\n"

func tmpPath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// fetcher 把 URL 当成常量返回，够用且不碰网络。
func fetcher(body string, err error) Fetcher {
	return func(context.Context, string) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte(body), nil
	}
}

// TestRefreshWritesCacheAndReportsChange 是主路径：拉下来、落盘、内容变了。
func TestRefreshWritesCacheAndReportsChange(t *testing.T) {
	path := tmpPath(t, "providers/a.txt")
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://example.com/a.txt", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := u.RefreshAll(context.Background()); n != 1 {
		t.Fatalf("变更条数 = %d, want 1", n)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读缓存: %v", err)
	}
	if string(got) != goodRules {
		t.Fatalf("缓存内容 = %q", got)
	}
}

// TestRefreshTwiceDoesNotReportChange 是「避免无谓重载」的那条：
// 每天都会拉到同一份文件，不该每天都把规则引擎重新编译一遍。
func TestRefreshTwiceDoesNotReportChange(t *testing.T) {
	path := tmpPath(t, "a.txt")
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://example.com/a.txt", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := u.RefreshAll(context.Background()); n != 1 {
		t.Fatalf("首次变更条数 = %d, want 1", n)
	}
	if n := u.RefreshAll(context.Background()); n != 0 {
		t.Fatalf("内容没变却报了 %d 条变更", n)
	}
}

// TestBrokenDownloadKeepsLastGoodCopy 是整个包最重要的一条：
// 拉到编译不过的内容时，磁盘上那份能用的必须原封不动。
// 覆掉它等于一次远端故障就能让用户的分流规则全废。
func TestBrokenDownloadKeepsLastGoodCopy(t *testing.T) {
	path := tmpPath(t, "a.txt")
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://example.com/a.txt", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	u.RefreshAll(context.Background())
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// HTML 错误页：很多站点限流/出故障时返回的就是它，而且状态码未必是 4xx。
	// 摘要与上次的不同，因此这次一定会走到 validate——它必须把这次挡下来。
	u2 := New(nil, nil, WithFetcher(fetcher("<html><body>404 Not Found</body></html>", nil)))
	if err := u2.Add("a", "https://example.com/a.txt", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := u2.RefreshAll(context.Background()); n != 0 {
		t.Fatalf("坏内容竟被算成 %d 条变更", n)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读缓存: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("坏内容覆盖了好缓存:\n%q\n%q", after, before)
	}
}

// TestValidateResolvesIncludeAgainstTheCacheDir 钉住校验发生的位置。
//
// 订阅内容里是可以带 #include 的，而 #include 的相对路径按「引用它的文件所在目录」解析。
// 校验时若把临时文件丢进 $TMPDIR，看到的就是一套和真正加载时完全不同的引用关系：
// 这种订阅要么每次都被判编译不过（缓存永远停在旧版本），
// 要么靠 #include? 静悄悄少掉一大段规则——后者没有任何报错，只是分流开始出错。
//
// 做法是让 include 指向一个**只在缓存目录里存在**的文件：
// 校验能过，就证明它编译的位置和真正加载的位置是同一个。
// TestValidateWithoutRulesDirRejectsEscape 默认（不传目录）时边界就是缓存目录本身，
// 越界的 include 必须被拒——这条是"订阅内容能读走任意文件"那个洞的守门测试。
func TestValidateWithoutRulesDirRejectsEscape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "providers", "a.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub.txt"), []byte("DOMAIN-SUFFIX,sub.example,DIRECT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	u := New(nil, nil, WithFetcher(fetcher("#include ../sub.txt\nFINAL,PROXY\n", nil)))
	if err := u.Add("a", "https://example.com/a.txt", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := u.RefreshAll(context.Background()); n != 0 {
		t.Fatalf("没给主规则集目录时，../ 的 include 必须被拒，实得更新 %d 条", n)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("被拒的内容不该落盘（保留旧缓存才是对的）")
	}
}

func TestValidateResolvesIncludeAgainstTheCacheDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "providers", "a.txt")
	// 这份子文件只存在于缓存目录，$TMPDIR 里永远没有同名文件。
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub.txt"),
		[]byte("DOMAIN-SUFFIX,sub.example,DIRECT\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	body := "#include ../sub.txt\nDOMAIN-SUFFIX,example.com,DIRECT\n"
	// WithRulesDir 说的是"这份订阅将来被哪个目录里的规则文件 include 进去"。
	// 不传就等于把边界缩到缓存目录本身，上面那行 ../ 会被引擎判成越界。
	u := New(nil, nil, WithFetcher(fetcher(body, nil)), WithRulesDir(dir))
	if err := u.Add("a", "https://example.com/a.txt", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := u.RefreshAll(context.Background()); n != 1 {
		t.Fatal("带 #include 的订阅内容没被接受，校验用的不是主规则集所在目录")
	}
	// 真按主规则集的方式加载一次，确认被引进来的规则确实在。
	main := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(main, []byte("#include providers/a.txt\nFINAL,PROXY\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(main, nil, nil)
	if err != nil {
		t.Fatalf("加载主规则集: %v", err)
	}
	if p, _ := eng.Match(context.Background(), "x.sub.example"); p != rules.PolicyDirect {
		t.Errorf("被 #include 进来的规则没生效: %s", p)
	}
}

// TestFetchErrorKeepsLastGoodCopy 同上，但走真实路径（拉取直接失败）。
func TestFetchErrorKeepsLastGoodCopy(t *testing.T) {
	path := tmpPath(t, "a.txt")
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://example.com/a.txt", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	u.RefreshAll(context.Background())

	u2 := New(nil, nil, WithFetcher(fetcher("", fmt.Errorf("dial tcp: 网络不可达"))))
	if err := u2.Add("a", "https://example.com/a.txt", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := u2.RefreshAll(context.Background()); n != 0 {
		t.Fatalf("拉取失败却报了 %d 条变更", n)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goodRules {
		t.Fatalf("缓存被改动了: %q", got)
	}
}

// TestRefreshSurvivesOneBadProvider 挡住「一条订阅拖垮其余」。
func TestRefreshSurvivesOneBadProvider(t *testing.T) {
	good := tmpPath(t, "good.txt")
	u := New(nil, nil)
	u.fetch = func(_ context.Context, url string) ([]byte, error) {
		if url == "bad" {
			return nil, fmt.Errorf("boom")
		}
		return []byte(goodRules), nil
	}
	if err := u.Add("bad", "bad", tmpPath(t, "bad.txt"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := u.Add("good", "good", good, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := u.RefreshAll(context.Background()); n != 1 {
		t.Fatalf("变更条数 = %d, want 1（只有 good 该算）", n)
	}
	if _, err := os.Stat(good); err != nil {
		t.Fatalf("好的那条没落盘: %v", err)
	}
}

// TestAddRejectsDuplicateCachePath：两条订阅写同一个文件，
// 表现出来是「规则内容随机跳变」，必须在这里挡住。
func TestAddRejectsDuplicateCachePath(t *testing.T) {
	dir := t.TempDir()
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://example.com/a", filepath.Join(dir, "same.txt"), time.Hour); err != nil {
		t.Fatal(err)
	}
	err := u.Add("b", "https://example.com/b", filepath.Join(dir, "same.txt"), time.Hour)
	if err == nil {
		t.Fatal("缓存路径重复却接受了")
	}
	if !strings.Contains(err.Error(), "same.txt") {
		t.Errorf("错误里应当点名冲突的路径，实得 %q", err)
	}
}

// TestAddRejectsRelativePathCollision 确认比较走的是绝对路径：
// "a/../x.txt" 与 "x.txt" 落到同一个文件上，只是拼法不同。
func TestAddRejectsRelativePathCollision(t *testing.T) {
	dir := t.TempDir()
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://example.com/a", filepath.Join(dir, "x.txt"), time.Hour); err != nil {
		t.Fatal(err)
	}
	odd := filepath.Join(dir, "sub", "..", "x.txt")
	if err := u.Add("b", "https://example.com/b", odd, time.Hour); err == nil {
		t.Fatal("同一文件的两种写法都被接受了")
	}
}

func TestAddRejectsEmptyFields(t *testing.T) {
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	for _, c := range []struct {
		name, url, path string
	}{
		{"", "https://e/a", "p"},
		{"  ", "https://e/a", "p"},
		{"a", "", "p"},
		{"a", "https://e/a", ""},
	} {
		if err := u.Add(c.name, c.url, c.path, time.Hour); err == nil {
			t.Errorf("name=%q url=%q path=%q 竟然被接受了", c.name, c.url, c.path)
		}
	}
}

// TestAddDefaultsInterval：留空取 24h，而不是 0（0 会变成每 tick 都拉）。
func TestAddDefaultsInterval(t *testing.T) {
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://e/a", tmpPath(t, "a"), 0); err != nil {
		t.Fatal(err)
	}
	if u.subs[0].Every != 24*time.Hour {
		t.Fatalf("默认周期 = %v, want 24h", u.subs[0].Every)
	}
}

// TestWriteAtomicCreatesDirs 覆盖默认缓存路径（providers/ 子目录还不存在）。
func TestWriteAtomicCreatesDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "providers", "a.txt")
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://e/a", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	u.RefreshAll(context.Background())
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("缓存没落盘: %v", err)
	}
}

// TestWriteAtomicLeavesNoTempFiles 确认临时文件不留在目录里：
// 天天拉的话，残留的 .wps-rulesub-* 会把 providers/ 目录塞满。
func TestWriteAtomicLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.txt")
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://e/a", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		u.fetch = fetcher(fmt.Sprintf("DOMAIN-SUFFIX,e%d.com,DIRECT\n", i), nil)
		u.subs[0].digest = "" // 逼它每次都真写一次
		u.RefreshAll(context.Background())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".wps-rulesub-") {
			t.Fatalf("临时文件残留: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("目录里除了缓存还有别的东西: %v", names)
	}
}

// TestHTTPFetchRejectsNon200：源站返回 404 时不能把错误页当规则集存下来。
//
// 断言要盯住"因为状态码被拒"这件事本身：只写 `err != nil` 的话，
// 哪天 URL 拼错、客户端被换成不认 https 的实现，测试照样绿，而 404 已经能落盘了。
func TestHTTPFetchRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()
	u := New(nil, nil)
	_, err := u.httpFetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("404 竟然当成功")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Fatalf("拒了，但不是因为状态码：%v", err)
	}
}

// TestHTTPFetchRejectsOversized 守住大小上限：远端返回无限流时不能把内存吃光。
func TestHTTPFetchRejectsOversized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		chunk := strings.Repeat("x", 1<<20)
		for i := 0; i < 65; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	u := New(nil, nil)
	_, err := u.httpFetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("超限响应竟然被收下了")
	}
	if !strings.Contains(err.Error(), "上限") {
		t.Fatalf("拒了，但不是因为超限：%v", err)
	}
}

// TestHTTPFetchHonorsContext 顺带保证超时真的生效，别让拉取把停机流程卡住。
func TestHTTPFetchHonorsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	u := New(nil, nil)
	_, err := u.httpFetch(ctx, srv.URL)
	if err == nil {
		t.Fatal("ctx 取消了竟然还成功")
	}
	// 必须是 ctx 的超时：换成"连不上源站"之类的错误也一样非空，但那条性质根本没被验过。
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("等到的不是超时错误：%v (%T)", err, err)
	}
}

// TestEndToEndOverHTTP 走完整的真实链路：httptest 当源站 → 落盘 → 引擎能读。
func TestEndToEndOverHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(goodRules))
	}))
	defer srv.Close()

	dir := t.TempDir()
	provider := filepath.Join(dir, "providers", "cn.txt")
	main := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(main, []byte("#include providers/cn.txt\nFINAL,PROXY\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	u := New(nil, nil)
	if err := u.Add("cn", srv.URL, provider, time.Hour); err != nil {
		t.Fatal(err)
	}
	if n := u.RefreshAll(context.Background()); n != 1 {
		t.Fatalf("变更条数 = %d, want 1", n)
	}
	// 关键的一步：订阅拉下来的文件真的能被 #include 引进主规则集。
	eng, err := rules.Load(main, nil, nil)
	if err != nil {
		t.Fatalf("#include 订阅缓存失败: %v", err)
	}
	if eng.Final() != rules.PolicyProxy {
		t.Fatalf("FINAL = %v, want PROXY", eng.Final())
	}
	if d, _ := eng.Stats(); d != 1 {
		t.Fatalf("域名规则 = %d, want 1（订阅那条应当被算进来）", d)
	}
}

// TestShortestClampsToAMinute：配置成 1s 会变成每分钟几十次远端请求。
func TestShortestClampsToAMinute(t *testing.T) {
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://e/a", tmpPath(t, "a"), time.Second); err != nil {
		t.Fatal(err)
	}
	if got := u.shortest(); got != time.Minute {
		t.Fatalf("tick = %v, want 1m", got)
	}
}

// TestRunReloadsOnlyOnChange：回调只在内容真的变了时被调用。
func TestRunReloadsOnlyOnChange(t *testing.T) {
	path := tmpPath(t, "a.txt")
	var calls atomic.Int32
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://e/a", path, time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		u.Run(ctx, func() { calls.Add(1) })
	}()
	// 起手那次会拉一次并重载；等它过去。
	waitFor(t, func() bool { return calls.Load() == 1 })
	// 周期是一小时，后面的 tick 不会再动它。
	time.Sleep(50 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("重载次数 = %d, want 1（内容没变不该再重载）", got)
	}
	cancel()
	<-done
}

// TestRunStopsOnContext 保证停机能走完，不会留下一条挂着的拉取。
func TestRunStopsOnContext(t *testing.T) {
	u := New(nil, nil, WithFetcher(fetcher(goodRules, nil)))
	if err := u.Add("a", "https://e/a", tmpPath(t, "a"), time.Hour); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		u.Run(ctx, nil)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run 没跟着 ctx 退出")
	}
}

// TestRunWithoutSubscriptionsReturns 是无订阅时的空转路径。
func TestRunWithoutSubscriptionsReturns(t *testing.T) {
	u := New(nil, nil)
	if u.Len() != 0 {
		t.Fatalf("Len = %d", u.Len())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { defer close(done); u.Run(ctx, nil) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("没有订阅时 Run 不该阻塞")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("等待条件超时")
}

// TestStatusIsSafeWhileLooping 面板每秒读 Status，拉取循环同时在写这些字段。
// 这条用例不为断言什么行为，只为让 -race 有机会抓到那把锁被漏掉的那天。
func TestStatusIsSafeWhileLooping(t *testing.T) {
	u := New(nil, nil, WithFetcher(func(context.Context, string) ([]byte, error) {
		return []byte("DOMAIN-SUFFIX,a.example,DIRECT\n"), nil
	}))
	dir := t.TempDir()
	for i := 0; i < 4; i++ {
		if err := u.Add(fmt.Sprintf("s%d", i), fmt.Sprintf("http://x/%d", i), filepath.Join(dir, fmt.Sprintf("%d.txt", i)), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		u.Run(ctx, func() {})
	}()
	for i := 0; i < 200; i++ {
		if len(u.Status()) != 4 {
			t.Fatal("订阅条数对不上，用例没构造起来")
		}
	}
	cancel()
	<-done
}

// TestExistingCacheSeedsTheDigest 磁盘上已有的缓存必须被当成"上次拉到的那份"。
//
// 不种子会发生两件实测到的事：启动时 prefetch 刚补齐，后台循环第一轮又拉一次，
// 拿到一模一样的字节却判成"内容变了"——重写文件 + 整引擎重载一遍，规则一条没变；
// 而界面在第一次拉取之前会报「缓存 0 字节」，文件明明在那儿。
func TestExistingCacheSeedsTheDigest(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cn.txt")
	body := "DOMAIN-SUFFIX,a.example,PROXY\n"
	if err := os.WriteFile(cache, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(cache)
	if err != nil {
		t.Fatal(err)
	}
	var hits int
	u := New(nil, nil, WithFetcher(func(context.Context, string) ([]byte, error) {
		hits++
		return []byte(body), nil // 远端与磁盘上那份一模一样
	}))
	if err := u.Add("cn", "http://x/cn.txt", cache, time.Hour); err != nil {
		t.Fatal(err)
	}
	changed := u.RefreshAll(context.Background())
	if changed != 0 {
		t.Errorf("内容没变却判成「变了」%d 条 —— 会白重载一遍引擎", changed)
	}
	after, err := os.Stat(cache)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("文件被重写了：inode/时间戳变了（%v → %v）", before.ModTime(), after.ModTime())
	}
	st := u.Status()
	if len(st) != 1 || st[0].Size != int64(len(body)) {
		t.Errorf("种子没生效，缓存大小报成 %+v", st)
	}
	if hits != 1 {
		t.Errorf("拉取次数 = %d, 期望 1", hits)
	}
}

// TestRefreshNowOverlapsWithLoop 手动拉取与后台那一轮会撞在同一条订阅上。
//
// 这条用例是补给 -race 的靶子：面板上的「立即拉取」把 refresh 变成了
// 第二个调用方，而 digest / lastAttempt 这些字段原本只有一条循环在动。
// 现场就撞出过一次真数据竞争（refreshDue 读 lastAttempt 不上锁）。
func TestRefreshNowOverlapsWithLoop(t *testing.T) {
	dir := t.TempDir()
	u := New(nil, nil, WithFetcher(func(context.Context, string) ([]byte, error) {
		time.Sleep(5 * time.Millisecond)
		return []byte("DOMAIN-SUFFIX,a.example,DIRECT\n"), nil
	}))
	for i := 0; i < 3; i++ {
		if err := u.Add(fmt.Sprintf("s%d", i), "http://x", filepath.Join(dir, fmt.Sprintf("%d.txt", i)), time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx, func() {}) // 起手就会拉一轮
	for i := 0; i < 8; i++ {
		if got := u.RefreshNow(ctx); len(got) != 3 {
			t.Fatalf("逐条结果应当有 3 条，得到 %+v", got)
		}
	}
	cancel()
}
