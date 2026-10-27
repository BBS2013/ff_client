// Package rulesub 把远程规则集拉到本地缓存上，供 rules_file 用 #include 引进去。
//
// 这一层刻意**不做判定**：真正生效的永远只是 rules_file 那一份规则。
// 于是订阅断了、拉慢了、拿到了坏文件，最坏结果是「规则还是上次那份」，
// 而不会凭空改掉分流方向——这条性质比订阅本身更值钱。
package rulesub

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/rules"
)

// maxSize 挡住「服务器返回了一个 4GB 的东西」这种响应。
// 正常规则集在几百 KB 到几 MB 之间，留 64MB 已经很宽松。
const maxSize = 64 << 20

// Fetcher 拉一条订阅。签名只给了 URL——校验用 rules.Load，
// 所以这里完全可以换个实现（比如走隧道）而不影响其余部分。
type Fetcher func(ctx context.Context, url string) ([]byte, error)

// Validate 是一份下载内容能不能被规则引擎吃下的判据。
// 用的是引擎自己的加载路径，因此「校验通过」等价于「重载时不会失败」。
type Validate func(data []byte) error

// Subscription 是一条订阅的运行态。
type Subscription struct {
	Name string
	URL  string
	// Path 是缓存落盘位置。
	Path string
	// Every 是拉取周期。
	Every time.Duration

	// digest 是上次成功写入的内容摘要，用来判断这次要不要重载。
	digest string
	// lastAttempt 记上一次**尝试**的时刻，而不是成功时刻：
	// 失败不该让下一次立刻重试，那会在服务不可达时把日志刷满。
	lastAttempt time.Time

	// 下面几个字段只为回答一个问题：「这条订阅现在到底好不好」。
	// 以前这件事只有日志知道，于是"订阅配了但早就不更新了"在界面上
	// 与"订阅很健康、只是这一轮没新东西"长得一模一样。
	//
	// lastOK 是上一次**拉成功**的时刻。内容没变也算成功：
	// 那说明远端活着，只是没有新东西——把这两种情况混成"没更新"是最容易误导人的。
	lastOK time.Time
	// lastErr 是最近一次失败的原文；一旦拉成功就清空。空串 = 没有未消化的故障。
	lastErr string
	// fails 是连续失败次数（成功即归零）。失败一次不值得报警，
	// 连着几次才是"这个源真的挂了"。
	fails int
	// size 是当前缓存内容的字节数。
	size int64
}

// Updater 按各自的周期拉取订阅，内容真的变了才回调 reload。
type Updater struct {
	client *http.Client
	// geo 与 resolver 传给校验用，因此 GEOIP 规则的订阅同样能验过。
	geo      rules.GeoLookup
	resolver rules.Resolver

	fetch Fetcher
	subs  []*Subscription
	// mu 护着上面那些运行态字段：拉取循环在写，面板每秒在读。
	// subs 切片本身在 Run 之前建好、之后只读，所以不护它。
	mu sync.Mutex
	// fetchMu 把"同一条订阅的两次拉取"排成队：面板上按「立即拉取」与
	// 后台定时器那一轮可能同时动同一条，两边都要读改 digest 并写同一个文件。
	// 单独立一把锁而不是复用 mu——mu 会被面板每 5 秒的 Status() 取，
	// 一次拉取最长两分钟，用它就是把界面冻住。
	fetchMu sync.Mutex
	// rulesDir 是主规则文件所在目录，也就是订阅内容里 #include 允许活动的范围。
	// 空即"就用缓存文件自己的目录"——那时 `#include ../sub.txt` 会被引擎判成越界。
	rulesDir string
}

// Option 是 Updater 的可选项。
type Option func(*Updater)

// WithRulesDir 告诉校验：这份订阅将来是被哪个目录里的规则文件 include 进来的。
// 不传就等于把边界缩到缓存目录本身，正常写法（`#include ../shared.txt`）会被拒。
func WithRulesDir(dir string) Option {
	return func(u *Updater) {
		u.rulesDir = dir
	}
}

// WithFetcher 换掉拉取实现，主要给测试用。
func WithFetcher(f Fetcher) Option {
	return func(u *Updater) {
		if f != nil {
			u.fetch = f
		}
	}
}

// WithHTTPClient 换掉 HTTP 客户端（例如限制超时）。
func WithHTTPClient(c *http.Client) Option {
	return func(u *Updater) {
		if c != nil {
			u.client = c
			u.fetch = u.httpFetch
		}
	}
}

// New 造一个 Updater。geo/resolver 只用于校验，可为 nil（但订阅里有 GEOIP 时会验不过）。
func New(geo rules.GeoLookup, resolver rules.Resolver, opts ...Option) *Updater {
	u := &Updater{
		client:   &http.Client{Timeout: 2 * time.Minute},
		geo:      geo,
		resolver: resolver,
	}
	u.fetch = u.httpFetch
	for _, o := range opts {
		o(u)
	}
	return u
}

// Add 登记一条订阅。重复的缓存路径在这里被挡住：两条订阅写同一个文件，
// 表现出来是「规则内容随机跳变」，几乎无从排查。
func (u *Updater) Add(name, url, path string, every time.Duration) error {
	name = trim(name)
	if name == "" {
		return fmt.Errorf("规则集订阅：name 不能为空")
	}
	if url == "" {
		return fmt.Errorf("规则集订阅 %q：url 不能为空", name)
	}
	if path == "" {
		return fmt.Errorf("规则集订阅 %q：缓存路径不能为空", name)
	}
	if every <= 0 {
		every = 24 * time.Hour
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("规则集订阅 %q：%w", name, err)
	}
	for _, s := range u.subs {
		if s.Path == abs {
			return fmt.Errorf("规则集订阅 %q：缓存路径 %s 与 %q 相同", name, abs, s.Name)
		}
		if s.Name == name {
			return fmt.Errorf("规则集订阅 %q：name 重复", name)
		}
	}
	sub := &Subscription{Name: name, URL: url, Path: abs, Every: every}
	// 缓存已经在磁盘上时，把它自己的摘要当作"上次拉到的那份"。
	//
	// 不这样做会有两个后果，都不是虚构的：
	//   - 启动那一刻 prefetch 刚把这份缓存补齐，后台循环第一轮又去拉一次，
	//     拿到一模一样的字节却判成"内容变了"→ 重写文件 + 整引擎重载一遍，
	//     而规则一条没变（实测日志里同一秒出现两条「已更新」）；
	//   - 界面在第一次拉取之前会报「缓存 0 字节」，而文件明明在那儿。
	// 读失败不影响登记：摘要留空，最坏退化成"多拉一次"，也就是今天的行为。
	if data, err := os.ReadFile(abs); err == nil && int64(len(data)) <= maxSize {
		sum := sha256.Sum256(data)
		sub.digest = hex.EncodeToString(sum[:])
		sub.size = int64(len(data))
	}
	u.subs = append(u.subs, sub)
	return nil
}

// Len 返回登记了几条。
func (u *Updater) Len() int { return len(u.subs) }

// Status 是一条订阅此刻的健康状况。
//
// 这里刻意**不带 URL**：订阅地址常常直接带鉴权 token，把它印到界面上等于
// 把口令摊进截图与前端日志。日志那边同样只印缓存路径，两处守同一条规矩。
type Status struct {
	Name  string
	Path  string
	Every time.Duration

	// LastAttempt 是上一次尝试的时刻（成功或失败都算）；零值 = 这个进程还没碰过它。
	LastAttempt time.Time
	// LastOK 是上一次拉成功的时刻；零值 = 从没成功过。
	LastOK time.Time
	// LastErr 是最近一次失败的原文；空串 = 没有未消化的故障。
	LastErr string
	// Fails 是连续失败次数。
	Fails int
	// Size 是当前缓存字节数；0 且 HasCache=false 表示这份缓存根本不存在。
	Size int64
	// HasCache 回答"这份订阅的规则此刻在不在磁盘上、能不能被 include 进去"。
	// 它与 LastOK 是两件事：拉通过但后来文件被人删了，这里就是假。
	HasCache bool
}

// Status 抄一份当前状态给界面。加锁是因为拉取循环正在写这些字段。
func (u *Updater) Status() []Status {
	out := make([]Status, 0, len(u.subs))
	u.mu.Lock()
	for _, s := range u.subs {
		st := Status{
			Name:        s.Name,
			Path:        s.Path,
			Every:       s.Every,
			LastAttempt: s.lastAttempt,
			LastOK:      s.lastOK,
			LastErr:     s.lastErr,
			Fails:       s.fails,
			Size:        s.size,
		}
		out = append(out, st)
	}
	u.mu.Unlock()
	for i := range out {
		if _, err := os.Stat(out[i].Path); err == nil {
			out[i].HasCache = true
		}
	}
	return out
}

// RefreshAll 立刻拉全部订阅，返回「内容真的变了」的条数。
// 任何一条失败都只影响它自己：一条订阅挂了不该拖垮其余的。
func (u *Updater) RefreshAll(ctx context.Context) int {
	changed := 0
	for _, s := range u.subs {
		ok, err := u.refresh(ctx, s)
		if err != nil {
			logx.Warnf("规则集订阅 %s 更新失败，继续用旧缓存: %v", s.Name, err)
			continue
		}
		if ok {
			changed++
		}
	}
	return changed
}

// RefreshMissing 只拉「本地还没有缓存」的订阅，返回条数。
//
// 它是给启动那一刻用的：缓存缺失意味着主规则集里那些 #include? 全被跳过了，
// 于是规则退化成只剩几条本地规则。此时若让拉取在后台慢慢跑，
// 头几秒的流量就会按一份**残缺的**规则集分流——
// 看起来像「刚启动时走了错路」，而这种症状极难归因。所以这条路径要同步等。
func (u *Updater) RefreshMissing(ctx context.Context) int {
	n := 0
	for _, s := range u.subs {
		if _, err := os.Stat(s.Path); err == nil {
			continue
		}
		ok, err := u.refresh(ctx, s)
		if err != nil {
			logx.Warnf("规则集订阅 %s 首次拉取失败，规则先按现有内容运行: %v", s.Name, err)
			continue
		}
		if ok {
			n++
		}
	}
	return n
}

// Run 到 ctx 结束为止，按周期刷新。reload 在内容变化时被调用。
//
// 唤醒用的定时器取所有订阅里最短的周期，而不是每条一个 goroutine：
// 周期通常差着数量级（N 条订阅就 N 个定时器），
// 而醒来后只会给到期的那些干活。
func (u *Updater) Run(ctx context.Context, reload func()) {
	if len(u.subs) == 0 {
		return
	}
	// 起手先拉一次：机器重启到第一次定时器之间可能隔着一整天，
	// 用户看到的会是「订阅配了但规则没更新」。
	// 走的是与定时器同一套到期判断，因此启动前已经同步补过的那些不会重拉一遍。
	if n := u.refreshDue(ctx, time.Now()); n > 0 {
		logx.Infof("规则集订阅：%d 条内容已更新，重载规则", n)
		if reload != nil {
			reload()
		}
	}

	tick := u.shortest()
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := u.refreshDue(ctx, time.Now()); n > 0 {
				logx.Infof("规则集订阅：%d 条内容已更新，重载规则", n)
				if reload != nil {
					reload()
				}
			}
		}
	}
}

// Outcome 是一条订阅"立刻拉一次"的结果。
type Outcome struct {
	Name    string
	Changed bool
	Err     string
}

// RefreshNow 无视周期，把每条订阅各拉一次并逐条回报。
//
// 与 RefreshAll 的区别只在返回值：那个只报"变了几条"给日志，
// 而界面上按了「立即拉取」之后必须说得出**哪一条**失败了、为什么，
// 否则按钮按下去只换来一句"完成"，与没动是一样的。
// 状态照常记账（lastOK/fails/size），所以拉完那一栏的数字会动。
func (u *Updater) RefreshNow(ctx context.Context) []Outcome {
	out := make([]Outcome, 0, len(u.subs))
	for _, s := range u.subs {
		changed, err := u.refresh(ctx, s)
		o := Outcome{Name: s.Name, Changed: changed}
		if err != nil {
			o.Err = err.Error()
			logx.Warnf("规则集订阅 %s 手动拉取失败，继续用旧缓存: %v", s.Name, err)
		}
		out = append(out, o)
	}
	return out
}

// refreshDue 只拉到期的那几条，返回内容真的变了的条数。
//
// 到期看的是上一次**尝试**的时刻而不是成功时刻：拉失败时按同样的节奏重试，
// 而不是每 tick 都重试一遍。
func (u *Updater) refreshDue(ctx context.Context, now time.Time) int {
	n := 0
	for _, s := range u.subs {
		// 到期判断也要读 lastAttempt，而它现在可能被两条路径写：
		// 后台这一轮，与面板上按下去的那一次。
		u.mu.Lock()
		last := s.lastAttempt
		u.mu.Unlock()
		if now.Sub(last) < s.Every {
			continue
		}
		ok, err := u.refresh(ctx, s)
		if err != nil {
			logx.Warnf("规则集订阅 %s 更新失败，继续用旧缓存: %v", s.Name, err)
			continue
		}
		if ok {
			n++
		}
	}
	return n
}

func (u *Updater) shortest() time.Duration {
	m := time.Duration(0)
	for _, s := range u.subs {
		if m == 0 || s.Every < m {
			m = s.Every
		}
	}
	if m <= 0 {
		m = time.Hour
	}
	// 下限免得配置成 1s 变成一个每分钟打几十次远端的循环。
	if m < time.Minute {
		return time.Minute
	}
	return m
}

// refresh 拉一条订阅，并把"这次到底成没成"记在订阅上。
//
// 三个入口（启动补拉、立即全拉、定时器）都走这里，所以记账只写一遍：
// 分散到各入口迟早会漏掉其中一个，而漏掉的那条在界面上永远显示"上次成功"。
func (u *Updater) refresh(ctx context.Context, s *Subscription) (bool, error) {
	// 尝试时刻在动手之前就记，而不是拉完再记：一次拉取最长两分钟，
	// 中途面板读到的是"上一轮"的时刻，那才是真的。
	u.mu.Lock()
	s.lastAttempt = time.Now()
	u.mu.Unlock()
	u.fetchMu.Lock()
	defer u.fetchMu.Unlock()
	changed, err := u.attempt(ctx, s)
	u.mu.Lock()
	if err != nil {
		s.lastErr = err.Error()
		s.fails++
	} else {
		s.lastOK = time.Now()
		s.lastErr = ""
		s.fails = 0
	}
	u.mu.Unlock()
	return changed, err
}

// attempt 是真正干活的那半：拉、比摘要、验、落盘。返回内容是否真的变了。
func (u *Updater) attempt(ctx context.Context, s *Subscription) (bool, error) {
	data, err := u.fetch(ctx, s.URL)
	if err != nil {
		return false, err
	}
	sum := sha256.Sum256(data)
	next := hex.EncodeToString(sum[:])
	if next == s.digest {
		u.mu.Lock()
		s.size = int64(len(data))
		u.mu.Unlock()
		return false, nil
	}
	// 落盘之前先验：一份 HTML 错误页或截断的下载如果直接覆盖缓存，
	// 下一次重载就会把整个规则集判成不可用。而订阅的价值全在「稳定」上。
	if err := u.validate(s.Path, data); err != nil {
		return false, fmt.Errorf("拉到的内容编译不过，丢弃（保留旧缓存）: %w", err)
	}
	if err := writeAtomic(s.Path, data); err != nil {
		return false, err
	}
	u.mu.Lock()
	s.digest = next
	s.size = int64(len(data))
	u.mu.Unlock()
	logx.Infof("规则集订阅 %s 已更新：%s（%d 字节）", s.Name, s.Path, len(data))
	return true, nil
}

// validate 把下载内容编译一遍，通过了才允许它替换缓存。
//
// target 是这份内容**将来要待的目录**。临时文件必须建在那里而不是 $TMPDIR：
// `#include` 的相对路径按「引用它的文件所在目录」解析，
// 于是放 $TMPDIR 编译时看到的是一套和真正加载时完全不同的引用关系——
// 订阅里带 `#include` 就会编译不过（被丢弃），带 `#include?` 则会静悄悄少掉一段规则。
// 校验的职责是回答「重载会不会失败」，那就得在重载会发生的地方问。
func (u *Updater) validate(target string, data []byte) error {
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("建 %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".wps-rulesub-check-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_, err = rules.LoadFrom(name, u.rulesDir, u.geo, u.resolver)
	return err
}

func (u *Updater) httpFetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	// 多读一个字节就能区分「刚好顶格」与「超了」，两种情况的处置不同。
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("响应超过 %d 字节上限", maxSize)
	}
	return data, nil
}

// writeAtomic 先写同目录下的临时文件再改名。
//
// 同目录是必须的：跨文件系统的 rename 不是原子的，那样中途掉电就会留下
// 一个半截的规则文件，而规则引擎读它时只会看到一句莫名其妙的解析错误。
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("建 %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".wps-rulesub-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if tmp != "" {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// 0644：规则集是明文公开数据，没必要做成 0600，
	// 而做成 0600 反而会在「服务以另一个 uid 重启」时让 #include 读不到。
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	tmp = ""
	return nil
}

func trim(s string) string { return strings.TrimSpace(s) }
