package rules

// 「看解析」那一格要用的两个公开入口。
//
// 它们都是**包装**，不是新判定：判定本体仍然只有 matchIP 与 geo 那两份。
// 所以这里盯的性质是"包出来的结论与里面那份一致"，以及
// "库里没有这条"与"这不是 CN"必须是两个不同的答案。

import (
	"context"
	"net/netip"
	"testing"
)

func TestMatchIPAddrsAgreesWithThePrivatePath(t *testing.T) {
	geo := fakeGeo{"203.0.113.9": "US", "116.62.1.1": "CN"}
	body := "IP-CIDR,10.0.0.0/8,DIRECT\nGEOIP,CN,DIRECT\n"
	e := load(t, body, geo, nil)

	for _, tc := range []struct {
		name   string
		addrs  string
		want   Policy
		wantTo string
	}{
		{"内网段先命中", "10.0.0.5", PolicyDirect, "IP-CIDR,10.0.0.0/8,DIRECT"},
		{"归属码命中", "116.62.1.1", PolicyDirect, "GEOIP,CN,DIRECT"},
		{"一个都不命中就走兜底", "203.0.113.9", PolicyProxy, "FINAL"},
		// 多个地址取"任一命中即返回"：规则顺序在外层，所以内网那条赢，
		// 而不是"第一个地址说了算"。这一格要是写反了，面板会报出一条引擎根本不会用的规则。
		{"多地址按规则顺序而不是地址顺序", "203.0.113.9 10.0.0.5", PolicyDirect, "IP-CIDR,10.0.0.0/8,DIRECT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, desc := e.MatchIPAddrs(mustParseAll(t, tc.addrs))
			if got != tc.want || desc != tc.wantTo {
				t.Fatalf("MatchIPAddrs(%s) = %s/%q，想要 %s/%q", tc.addrs, got, desc, tc.want, tc.wantTo)
			}
		})
	}
}

// TestMatchIPAddrsIsNotASecondOpinion 断的是"公开入口与域名那条路同源"：
// 同一个地址，从 MatchNode（域名 → 解析 → IP 判定）走一遍，
// 与直接把它交给 MatchIPAddrs，必须得到同一句结论。
func TestMatchIPAddrsIsNotASecondOpinion(t *testing.T) {
	geo := fakeGeo{"116.62.1.1": "CN"}
	rs := fakeResolver{"cn-host.example": mustParseAll(t, "116.62.1.1")}
	e := load(t, "GEOIP,CN,DIRECT\n", geo, rs)

	p1, d1, _ := e.MatchNode(context.Background(), "cn-host.example")
	p2, d2 := e.MatchIPAddrs(rs["cn-host.example"])
	if p1 != p2 || d1 != d2 {
		t.Fatalf("两条路各说一套：%s/%q vs %s/%q", p1, d1, p2, d2)
	}
}

func TestCountryOfSeparatesUnknownFromNotCN(t *testing.T) {
	geo := fakeGeo{"116.62.1.1": "CN"}
	e := load(t, "IP-CIDR,10.0.0.0/8,DIRECT\n", geo, nil)

	if cc, ok := e.CountryOf(netip.MustParseAddr("116.62.1.1")); !ok || cc != "CN" {
		t.Errorf("库里有这条却答成 %q/%v", cc, ok)
	}
	// 库里没有：ok=false。这一格如果被当成"不是 CN"，
	// GEOIP,CN,DIRECT 就会在面板上被说成"判不中是因为它不是中国 IP"——那是编的。
	if _, ok := e.CountryOf(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("库里没有这条，不能报成查到了")
	}
	// IPv4 映射到 IPv6 形状（::ffff:116.62.1.1）必须与裸 IPv4 同一个答案：
	// 解析器回来的地址有两种形状，不 Unmap 的话同一台机器会被判成两个归属。
	mapped := netip.MustParseAddr("::ffff:116.62.1.1")
	if cc, ok := e.CountryOf(mapped); !ok || cc != "CN" {
		t.Errorf("IPv4 映射地址没被 Unmap：%q/%v", cc, ok)
	}
}

func TestCountryOfWithoutGeoDBSaysUnknown(t *testing.T) {
	// 没配 GeoIP 库：引擎照样能按 IP-CIDR 判，但归属码这一格必须是"不知道"。
	e := load(t, "IP-CIDR,10.0.0.0/8,DIRECT\n", nil, nil)
	if cc, ok := e.CountryOf(netip.MustParseAddr("116.62.1.1")); ok || cc != "" {
		t.Errorf("没库却答出 %q/%v——它会被显示成一个归属码", cc, ok)
	}
	if p, d := e.MatchIPAddrs(mustParseAll(t, "10.0.0.5")); p != PolicyDirect || d != "IP-CIDR,10.0.0.0/8,DIRECT" {
		t.Errorf("没库不该影响纯 IP-CIDR 的判定：%s/%q", p, d)
	}
}
