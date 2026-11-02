package rules

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// 这一组量的是**每条连接都要付的代价**：判定一个目标要走多远。
// 不是微优化表演——域名规则是线性扫的，仓库里那份规则集有 4500+ 条，
// 所以"命中在最后一条"和"一条都不命中"是两个完全不同的成本，
// 而它们恰恰是日常浏览里最常见的两种情况。

// realRules 指向仓库里那份真规则集（含 #include 展开）。
// 用真的那份而不是编一条小规则集：小规则集量不出上面说的那个形状。
func realRules(t testing.TB) (string, string) {
	t.Helper()
	rulesFile := filepath.Join("..", "..", "assets", "rules.txt")
	geoFile := filepath.Join("..", "..", "assets", "geoip.mmdb")
	// 两个文件都必须在场：rules.txt 随仓库走，geoip.mmdb 因许可不能入库（见 .gitignore）。
	// 缺文件时仍然判失败——这组基准量的是真规则集，静默跳过等于把性能闸关掉；
	// 但报错必须告诉人怎么补，而不是只给一句 open: no such file。
	for _, p := range []string{rulesFile, geoFile} {
		if _, err := os.Stat(p); err != nil {
			cwd, _ := os.Getwd()
			t.Fatalf("找不到 %s：先运行 ./scripts/fetch-assets.sh --seed（cwd=%s）", p, cwd)
		}
	}
	return rulesFile, geoFile
}

func loadReal(t testing.TB) *Engine {
	t.Helper()
	rulesFile, geoFile := realRules(t)
	geo, err := OpenGeoIP(geoFile)
	if err != nil {
		t.Fatalf("开 mmdb: %v", err)
	}
	e, err := Load(rulesFile, NewGeoRef(geo), nil)
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	return e
}

func BenchmarkLoadRealRules(b *testing.B) {
	rulesFile, geoFile := realRules(b)
	geo, err := OpenGeoIP(geoFile)
	if err != nil {
		b.Fatal(err)
	}
	ref := NewGeoRef(geo)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Load(rulesFile, ref, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMatchFirstHit 是最好看的一种：规则表第一条就命中。
func BenchmarkMatchFirstHit(b *testing.B) {
	e := loadReal(b)
	e.SetBlocklist([]string{"ads.example.com"})
	ctx := context.Background()
	host := firstDomainRuleHost(b, e)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, matched := e.Match(ctx, host); matched == "" {
			b.Fatal("第一条规则没命中，基准的构造不对")
		}
	}
}

// BenchmarkMatchMiss 一条都不命中：扫完整张域名表再落 FINAL。
// 与上面那条的差值就是"规则集长多大，每条连接就多付多少钱"。
func BenchmarkMatchMiss(b *testing.B) {
	e := loadReal(b)
	ctx := context.Background()
	const host = "definitely-not-in-any-ruleset.example"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, matched := e.Match(ctx, host)
		if matched != "FINAL" && p == "" {
			b.Fatalf("基准的落点不对: %s/%s", p, matched)
		}
	}
}

// BenchmarkMatchBlocked 量的是拦截名单在链条最前面的那一跳。
func BenchmarkMatchBlocked(b *testing.B) {
	e := loadReal(b)
	block := make([]string, 0, 128)
	for i := 0; i < 128; i++ {
		block = append(block, "ads"+string(rune('a'+i%26))+".example")
	}
	e.SetBlocklist(block)
	ctx := context.Background()
	host := block[len(block)-1] // 最后一条：名单也是线性扫的
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if p, _ := e.Match(ctx, host); p != PolicyReject {
			b.Fatalf("名单最后一条没命中，实得 %s", p)
		}
	}
}

// BenchmarkMatchIP 量 GEOIP 那一跳：mmdb 查询本身比整张域名表贵多少。
func BenchmarkMatchIP(b *testing.B) {
	e := loadReal(b)
	ctx := context.Background()
	const addr = "8.8.8.8"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, matched := e.Match(ctx, addr); matched == "" {
			b.Fatal("IP 判定没给出命中规则，基准的构造不对")
		}
	}
}

// firstDomainRuleHost 从引擎里取出第一条域名规则的目标，
// 保证"第一条就命中"这个前提是真的（规则文件改了也不会静默失真）。
func firstDomainRuleHost(t testing.TB, e *Engine) string {
	t.Helper()
	for _, r := range e.domainRules {
		if r.kind == kindDomainSuffix || r.kind == kindDomain || r.kind == kindDomainKeyword {
			return r.value
		}
	}
	t.Fatal("规则集里一条域名规则都没有，这组基准没法量；先运行 ./scripts/fetch-assets.sh --seed")
	return ""
}

// TestRealRulesAreBigEnoughToMatter 守住上面那组前提：
// 规则集缩到几百条时，"线性扫"这件事就不值得量了，基准也就失去了意义。
func TestRealRulesAreBigEnoughToMatter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("路径分隔符不同，这台机器上量不了")
	}
	e := loadReal(t)
	dom, ip := e.Stats()
	if dom < 1000 || ip < 1 {
		t.Fatalf("真规则集只有 域名 %d / IP %d 条，这组基准的前提不成立；先运行 ./scripts/fetch-assets.sh --seed", dom, ip)
	}
}
