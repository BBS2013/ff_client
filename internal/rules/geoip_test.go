package rules

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// 定位项目内的 mmdb：测试从包目录出发，需上溯到仓库根。
func geoipPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "assets", "geoip.mmdb")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("mmdb 未就绪（先执行 scripts/fetch-assets.sh）: %v", err)
	}
	return p
}

func TestOpenGeoIPMissingFile(t *testing.T) {
	if _, err := OpenGeoIP(filepath.Join(t.TempDir(), "absent.mmdb")); err == nil {
		t.Fatal("打开不存在的 mmdb 应报错")
	}
}

func TestNilGeoIPIsSafe(t *testing.T) {
	var g *GeoIP
	if cc, ok := g.Country(netip.MustParseAddr("114.114.114.114")); ok || cc != "" {
		t.Errorf("nil GeoIP 应返回零值，得到 (%q, %v)", cc, ok)
	}
}

func TestGeoRefNilLookup(t *testing.T) {
	// mmdb 缺失时 main 仍会启动，此时 GeoRef 包裹的是 nil，查询必须安全返回。
	r := NewGeoRef(nil)
	if cc, ok := r.Country(netip.MustParseAddr("8.8.8.8")); ok || cc != "" {
		t.Errorf("空 GeoRef 查询应返回零值，得到 (%q, %v)", cc, ok)
	}
}

func TestCountryLookup(t *testing.T) {
	g, err := OpenGeoIP(geoipPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	// 国内地址必须精确判为 CN——这是 GEOIP,CN,DIRECT 规则的全部依赖。
	for _, ip := range []string{"114.114.114.114", "223.5.5.5", "180.101.49.44"} {
		cc, ok := g.Country(netip.MustParseAddr(ip))
		if !ok || cc != "CN" {
			t.Errorf("%s 查到 (%q, %v), want (CN, true)", ip, cc, ok)
		}
	}

	// 国外地址绝不能被判为 CN——否则会被 GEOIP,CN,DIRECT 错误地直连出去。
	// 精简库（Country-only-cn-private.mmdb）不含境外数据，查不到归属是预期行为；
	// 完整库（Country.mmdb）下会返回真实归属。注意大厂自有机段返回的是**组织码**
	//（8.8.8.8 → GOOGLE、1.1.1.1 → CLOUDFLARE）而非 ISO 国家码，
	// 组织码不会命中任何 GEOIP 规则，连接会退化到 FINAL，属于安全侧。
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		if cc, ok := g.Country(netip.MustParseAddr(ip)); ok && cc == "CN" {
			t.Errorf("%s 被误判为 CN", ip)
		}
	}
}

// 设置 WPS_APP_GEOIP 可指向完整库（Country.mmdb）以验证境外归属。
func TestCountryLookupFullDatabase(t *testing.T) {
	p := os.Getenv("WPS_APP_GEOIP")
	if p == "" {
		t.Skip("未设置 WPS_APP_GEOIP，跳过完整库归属校验")
	}
	g, err := OpenGeoIP(p)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	// 注意：不能用 8.8.8.8 断言 US。GeoLite2 把 Google/Cloudflare 自有机段按组织标注，
	// 只有非自有机段才返回 ISO 国家码，否则这条断言会一直红。
	for _, ip := range []string{"9.9.9.9", "208.67.222.222", "17.253.144.10"} {
		if cc, ok := g.Country(netip.MustParseAddr(ip)); !ok || cc != "US" {
			t.Errorf("%s = (%q, %v), want (US, true)", ip, cc, ok)
		}
	}
	for _, ip := range []string{"114.114.114.114", "223.5.5.5"} {
		if cc, ok := g.Country(netip.MustParseAddr(ip)); !ok || cc != "CN" {
			t.Errorf("%s = (%q, %v), want (CN, true)", ip, cc, ok)
		}
	}

	// 大厂自有机段应返回组织码而非任何国家码，从而不会误命中 GEOIP 规则。
	for ip, want := range map[string]string{"8.8.8.8": "GOOGLE", "1.1.1.1": "CLOUDFLARE"} {
		if cc, ok := g.Country(netip.MustParseAddr(ip)); !ok || cc != want {
			t.Errorf("%s = (%q, %v), want (%q, true)", ip, cc, ok, want)
		}
	}
}

func TestPrivateRangesPresent(t *testing.T) {
	g, err := OpenGeoIP(geoipPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	// 私有地址在 cn-private 库中标记为 PRIVATE（少数版本记为 CN），两者都算命中。
	for _, ip := range []string{"192.168.1.1", "10.0.0.1", "127.0.0.1", "172.16.0.1"} {
		cc, ok := g.Country(netip.MustParseAddr(ip))
		if !ok {
			t.Errorf("私有地址 %s 应在 cn-private 库中命中，但查不到", ip)
			continue
		}
		if cc != "PRIVATE" && cc != "CN" {
			t.Errorf("私有地址 %s 归属为 %q，预期 PRIVATE 或 CN", ip, cc)
		}
	}
}

func TestIPv4MappedIPv6(t *testing.T) {
	g, err := OpenGeoIP(geoipPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	// ::ffff:114.114.114.114 应与 114.114.114.114 等价（Unmap 后再查）。
	mapped := netip.MustParseAddr("::ffff:114.114.114.114")
	ccMapped, okMapped := g.Country(mapped)
	ccPlain, okPlain := g.Country(netip.MustParseAddr("114.114.114.114"))
	if okMapped != okPlain || ccMapped != ccPlain {
		t.Errorf("映射地址查到 (%q,%v)，普通地址查到 (%q,%v)", ccMapped, okMapped, ccPlain, okPlain)
	}
}

func TestGeoRefSwapClosesOld(t *testing.T) {
	path := geoipPath(t)
	first, err := OpenGeoIP(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenGeoIP(path)
	if err != nil {
		t.Fatal(err)
	}

	ref := NewGeoRef(first)
	if _, ok := ref.Country(netip.MustParseAddr("114.114.114.114")); !ok {
		t.Fatal("swap 前应能查到 CN")
	}

	ref.Swap(second)
	if _, ok := ref.Country(netip.MustParseAddr("114.114.114.114")); !ok {
		t.Fatal("swap 后仍应能查到 CN")
	}
	// first 已被 Swap 关闭，这里不应崩溃，也不应影响查询。
	if _, ok := first.Country(netip.MustParseAddr("114.114.114.114")); ok {
		t.Error("Swap 后的旧库应已关闭")
	}
	second.Close()
}

// TestGeoRefConcurrentSwapAndLookup 锁住热重载时的 use-after-munmap。
//
// Swap 换库并关闭旧库，而每条入站连接都会走 Country()。
// 以前 Country 只在「取指针」这一步加读锁，随后就在锁外解引用；
// Swap 又把 Close 放在解锁之后。于是两者一交叉，
// 查询就会踩到已被 munmap 的 buffer——整个进程当场 SIGSEGV。
// 触发路径正是产品的卖点：`kill -HUP`、托盘「重载规则」、增删用户规则。
//
// 带 -race 跑本用例即可复现：maxminddb 的 Close 会把底层 buffer 置 nil，
// 与 Lookup 的读构成数据竞争。
func TestGeoRefConcurrentSwapAndLookup(t *testing.T) {
	p := geoipPath(t) // mmdb 未就绪时跳过，保持测试不依赖仓库外的下载步骤

	first, err := OpenGeoIP(p)
	if err != nil {
		t.Fatalf("打开 mmdb: %v", err)
	}
	r := NewGeoRef(first)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 读者：持续查国内地址，让查询与换库充分交错。
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cc, ok := r.Country(netip.MustParseAddr("114.114.114.114"))
				if ok && cc != "CN" {
					t.Errorf("114.114.114.114 查到 %q, 期望 CN", cc)
					return
				}
			}
		}()
	}

	// 换库者：不停开新库并 Swap 进去，中途也 Swap(nil)——
	// 这正是 stopLocked 里那一句 Swap(nil) 的用法。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 40; i++ {
			select {
			case <-stop:
				return
			default:
			}
			next, err := OpenGeoIP(p)
			if err != nil {
				t.Errorf("重开 mmdb: %v", err)
				return
			}
			r.Swap(next)
			if i%3 == 0 {
				r.Swap(nil)
			}
		}
	}()

	// 跑够时间让两者充分交错，再收工。
	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Swap(nil) 之后查询必须安全返回零值，而不是解引用已释放的库。
	if cc, ok := r.Country(netip.MustParseAddr("114.114.114.114")); ok {
		t.Errorf("Swap(nil) 之后查询应返回零值，得到 (%q, true)", cc)
	}
	// 重新装回一个库，确认热替换后仍可用。
	again, err := OpenGeoIP(p)
	if err != nil {
		t.Fatalf("重开 mmdb: %v", err)
	}
	r.Swap(again)
	if cc, ok := r.Country(netip.MustParseAddr("114.114.114.114")); !ok || cc != "CN" {
		t.Errorf("重新装库后应能查到 CN，得到 (%q, %v)", cc, ok)
	}
}
