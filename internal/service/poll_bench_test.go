package service

// 面板每 5 秒把当前那一页整份重读一次。规则页那一轮里有两个绑定会读磁盘上的配置，
// 而代理**停着**的时候服务手上没有配置，只能现读。这一组基准量的就是
// "停着的时候刷一次规则页有多贵"——顺带也是那次修复的复现命令：
// BlockList 早先为了复用引擎的归一化，会把整张 GFW 名单（仓库那份 rules.txt
// 只有 38 行，但它 #include 了 ~200KB）每五秒重新编译一遍，现在不编译了。
//
// 为什么值得单独量：跑起来时走的是另一条分支（引擎已在内存里，直接问它），本来就不慢，
// 所以"面板不卡"在开发时几乎总是被开发机自己的状态掩盖着——
// 开发者开着代理测，用户停下来看日志时才会卡。
//
// 命令：`make bench`（也可单跑 `go test -bench . -benchtime 30x ./internal/service/`）。
//
// 只量"停着"的那一路，且刻意不调 Start：代理一跑起来就会占真实端口、
// 还会去抢正在跑的那个面板的单实例锁（接管式轮询最长 35 秒）。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wps_app/internal/config"
	"wps_app/internal/rules"
)

// repoAssets 找到仓库自带的规则集：基准要量的是真实规模，不是三行玩具规则。
// 找不到（断网门禁把工作目录换掉了）就跳过——拿 38 行规则量出来的"不卡"是假的。
func repoAssets(t testing.TB) string {
	t.Helper()
	for _, p := range []string{"../../assets/rules.txt", "assets/rules.txt"} {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			return abs
		}
	}
	t.Skip("找不到仓库自带的规则集，这一条量的就不是真实规模")
	return ""
}

// stoppedPollEnv 造一份"代理停着"的规则页现场：真实规则集 + N 条拦截域名。
func stoppedPollEnv(t testing.TB, blockCount int) (cfgPath, userFile string) {
	t.Helper()
	main := repoAssets(t)
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "config.yaml")
	block := ""
	if blockCount > 0 {
		list := make([]string, blockCount)
		for i := range list {
			list[i] = fmt.Sprintf("  - ad%d.example.net", i)
		}
		block = "block:\n  domains:\n" + strings.Join(list, "\n") + "\n"
	}
	body := "proxies:\n" +
		"  - name: \"n1\"\n" +
		"    server: { addr: \"127.0.0.1:14499\", auth: \"x\" }\n" +
		"active: n1\n" +
		"mode: rule\n" +
		"inbounds:\n" +
		"  - { type: socks5, listen: \"127.0.0.1:0\" }\n" +
		"rules_file: \"" + main + "\"\n" +
		block +
		"log: { level: \"error\" }\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, filepath.Join(filepath.Dir(main), rules.UserRuleFileName)
}

// BenchmarkRulesPagePollStopped 是面板停着时刷一次规则页的那一串调用。
// 面板实际还会读 RulesWatch 与 Subscriptions，但那两个不碰规则集，这里略。
func BenchmarkRulesPagePollStopped(b *testing.B) {
	cfgPath, _ := stoppedPollEnv(b, 0)
	svc := New(cfgPath, nil)
	for b.Loop() {
		// 顺序照抄 Rules.vue 的 load()：两份名单各读各的，判语最后算。
		if _, err := svc.ListUserRules(); err != nil {
			b.Fatal(err)
		}
		_ = svc.BlockList()
		if _, err := svc.UserRuleWarnings(); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkBlockListBigListStopped 单独看拦截名单很大时的那一路：
// 用户粘一份 AdGuard 名单（几千条）之后，这一栏每五秒都要重算一次死条目。
//
// 2026-10-19 实测（`make bench`，代理停着，机器上没有别的 go test 在跑）：
//
//	domains=200     0.22ms
//	domains=2000    1.74ms
//	domains=8000    7.5ms
//
// 同一格第一次记的是 0.40 / 3.15 / 11.3ms——那一次旁边正跑着另一个 `go test ./...`。
// 差 1.5 倍，正好是 README §9.3 定下"时延只断倍率"那条规矩的原因；
// 也正因为这样，这里的数字标了"机器上没有别的测试"这一条前提，
// 换一台机器、旁边在编译，请重跑 `make bench` 而不是拿这段做对比。
//
// 两半各占多少见下面的 BenchmarkBlockListSplitStopped。
func BenchmarkBlockListBigListStopped(b *testing.B) {
	for _, n := range []int{200, 2000, 8000} {
		b.Run(fmt.Sprintf("domains=%d", n), func(b *testing.B) {
			cfgPath, _ := stoppedPollEnv(b, n)
			svc := New(cfgPath, nil)
			for b.Loop() {
				_ = svc.BlockList()
			}
		})
	}
}

// BenchmarkBlockListSplitStopped 把上面那一条拆成两半，让"开销几乎全是 YAML 解析、
// 不是死条目判据"这句话可以用 `make bench` 复现，而不是只能引用一段一次性探针。
//
// 两半都读同一份 8000 条的配置：
//
//	load      —— 每五秒重读整份配置那份 YAML 的成本
//	deadCheck —— 拿到名单之后判"哪些条目已经死了"的成本
//
// 2026-10-19 实测：**load 6.14ms、deadCheck 1.12ms**，加起来 7.26ms，
// 与整条 7.5ms 对得上——也就是说这一路 85% 的代价花在重新解析配置上，
// 死条目判据只占六分之一。
//
// 结论决定了下一步该动哪里：要减的是前者。但给它加一层带失效的缓存，
// 省下的是 5 秒一次的 6ms（约 0.12% 单核），赔上的是
// "面板显示的名单其实是旧的"这一整类更难查的问题——不划算。
// 所以这一条是**留给后人的路标，不是一个待修的毛病**。
func BenchmarkBlockListSplitStopped(b *testing.B) {
	cfgPath, _ := stoppedPollEnv(b, 8000)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		b.Fatal(err)
	}
	list := rules.BlockDomainView(cfg.Block.Domains)
	if len(list) != 8000 {
		b.Fatalf("这份现场不该有 %d 条拦截域名", len(list))
	}

	b.Run("load", func(b *testing.B) {
		for b.Loop() {
			if _, err := config.Load(cfgPath); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("deadCheck", func(b *testing.B) {
		for b.Loop() {
			_ = rules.DeadBlockDomains(list)
		}
	})
}
