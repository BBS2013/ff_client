// 拦截名单里"什么也没多拦"那部分判据的验收。
//
// 判据会引导用户去删配置，所以除了报得准不准，还必须证明删掉是安全的：
// TestPruneBlockDomainsKeepsEveryVerdict 拿真引擎把删前删后逐个域名对一遍。
package rules

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// baseRules 是这几条测试用的最小规则集：一 FINAL 单独成文件会被判为
// "没有可用规则"（那是真在跑时的兜底判据），所以这里带一条永远轮不到的真规则。
const baseRules = "DOMAIN,keep.test,DIRECT\nFINAL,PROXY\n"

func TestDeadBlockDomains(t *testing.T) {
	cases := []struct {
		name string
		list []string
		want map[string]string // 被盖住的域名 → 盖住它的那条
	}{
		{
			name: "子域被父域盖住",
			list: []string{"ads.example.com", "example.com", "other.net"},
			want: map[string]string{"ads.example.com": "example.com"},
		},
		{
			name: "隔了几级也一样",
			list: []string{"api.ads.example.com", "example.com"},
			want: map[string]string{"api.ads.example.com": "example.com"},
		},
		{
			name: "中间那条也在名单里时，报最宽的那条",
			list: []string{"a.b.example.com", "b.example.com", "example.com"},
			want: map[string]string{"a.b.example.com": "example.com", "b.example.com": "example.com"},
		},
		{
			name: "相近后缀不算数（按点边界，不是字符串后缀）",
			list: []string{"notexample.com", "example.com"},
			want: nil,
		},
		{
			name: "单标签没有可剥的后缀",
			list: []string{"localhost", "example.com"},
			want: nil,
		},
		{
			name: "名单里只有一条时它不会把自己算成死的",
			list: []string{"example.com"},
			want: nil,
		},
		{
			name: "归一化写法的同一域名只报一次",
			list: []string{"Ads.Example.COM.", "ads.example.com", "example.com"},
			want: map[string]string{"ads.example.com": "example.com"},
		},
		{
			name: "顶层域也在名单里时，下面全是死的（真相就是这样）",
			list: []string{"com", "example.com"},
			want: map[string]string{"example.com": "com"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := map[string]string{}
			for _, d := range DeadBlockDomains(c.list) {
				got[d.Domain] = d.By
			}
			if !reflect.DeepEqual(got, c.want) && !(len(got) == 0 && len(c.want) == 0) {
				t.Errorf("报出的死条目 = %v，期望 %v", got, c.want)
			}
		})
	}
}

// TestDeadBlockDomainsOrderIndependent 判据不许因为 map 遍历顺序而每次给不同的话：
// 面板上这栏是常驻的，文字自己重排会被当成出了问题。
func TestDeadBlockDomainsOrderIndependent(t *testing.T) {
	list := []string{"a.b.example.com", "example.com", "ads.example.com", "b.example.com", "other.net"}
	first := DeadBlockDomains(list)
	for i := 0; i < 5; i++ {
		if got := DeadBlockDomains(list); !reflect.DeepEqual(got, first) {
			t.Fatalf("第 %d 次调用结果变了:\n%v\n%v", i, first, got)
		}
	}
	if len(first) != 3 {
		t.Errorf("期望 3 条死条目，得到 %d 条: %v", len(first), first)
	}
}

func TestDeadBlockStringSaysWhoAndWhat(t *testing.T) {
	got := DeadBlock{Domain: "ads.example.com", By: "example.com"}.String()
	for _, want := range []string{"example.com", "ads.example.com"} {
		if !strings.Contains(got, want) {
			t.Errorf("这句话里没有 %s: %q", want, got)
		}
	}
}

func TestPruneBlockDomainsNoopWhenNothingCovered(t *testing.T) {
	list := []string{"Ads.Example.COM.", "other.net", "third.net"}
	kept, removed := PruneBlockDomains(list)
	if removed != 0 {
		t.Errorf("没有死条目却删了 %d 条: %v", removed, kept)
	}
	// 归一化照做（大写与尾点在这里被抹平），顺序不动。
	want := []string{"ads.example.com", "other.net", "third.net"}
	if !reflect.DeepEqual(kept, want) {
		t.Errorf("kept = %v，期望 %v", kept, want)
	}
}

// TestPruneBlockDomainsKeepsEveryVerdict 是这一组里最该常驻的一条：
// 清理按钮会真的改配置文件，所以必须证明删完之后**每个域名的判定都没变**。
func TestPruneBlockDomainsKeepsEveryVerdict(t *testing.T) {
	lists := [][]string{
		{"ads.example.com", "example.com", "other.net"},
		{"a.b.example.com", "b.example.com", "example.com", "com"},
		{"x.co.uk", "co.uk", "bbc.co.uk", "notco.uk"},
		{"example.com", "com", "net", "example.net", "a.example.net"},
	}
	for i, list := range lists {
		kept, removed := PruneBlockDomains(list)
		if removed == 0 {
			t.Errorf("第 %d 份名单一条都没删，判据大概没生效: %v", i, list)
		}
		if dead := DeadBlockDomains(kept); len(dead) != 0 {
			t.Errorf("第 %d 份名单清理后还有死条目: %v", i, dead)
		}
		// 再清理一次不该再删任何东西，否则说明判据不是幂等的（面板会反复点）。
		if _, again := PruneBlockDomains(kept); again != 0 {
			t.Errorf("第 %d 份名单第二次清理又删了 %d 条", i, again)
		}

		hosts := append([]string{}, list...)
		for _, d := range list {
			hosts = append(hosts, "zz."+d, "a.b."+d)
		}
		hosts = append(hosts, "unrelated.org", "example.org", "notexample.com")

		before := load(t, baseRules, fakeGeo{}, fakeResolver{})
		before.SetBlocklist(list)
		after := load(t, baseRules, fakeGeo{}, fakeResolver{})
		after.SetBlocklist(kept)
		for _, h := range hosts {
			bp, _ := before.Match(context.Background(), h)
			ap, _ := after.Match(context.Background(), h)
			if bp != ap {
				t.Errorf("第 %d 份名单：%q 删前是 %s，删后变成 %s（清理不该改判定）", i, h, bp, ap)
			}
		}
	}
}

// TestDeadBlockDomainsNeverFlagsALiveEntry 是反向的守卫：判据说"被盖住"的每一条，
// 拿引擎验一遍它确实没多拦——注意验的是**差异**，不是策略本身：
// 死条目和盖住它的那条给出的策略都是 REJECT，只有换掉之后判定仍相同才说明没多拦。
func TestDeadBlockDomainsNeverFlagsALiveEntry(t *testing.T) {
	list := []string{"ads.example.com", "example.com", "a.b.example.com", "b.example.com", "other.net"}
	dead := DeadBlockDomains(list)
	if len(dead) == 0 {
		t.Fatalf("这份名单一条死条目都没报，判据大概没生效: %v", list)
	}
	// 去掉死条目再比：判定必须逐个域名都不变（PruneBlockDomains 的那条性质，
	// 这里换个入口再验一次，免得哪天改坏其中一处没人发现）。
	kept, removed := PruneBlockDomains(list)
	if removed != len(dead) {
		t.Errorf("判据报了 %d 条死条目，清理却删了 %d 条", len(dead), removed)
	}
	full := load(t, baseRules, fakeGeo{}, fakeResolver{})
	full.SetBlocklist(list)
	slim := load(t, baseRules, fakeGeo{}, fakeResolver{})
	slim.SetBlocklist(kept)
	for _, d := range dead {
		for _, h := range []string{d.Domain, "zz." + d.Domain, "a.b." + d.Domain} {
			fp, _ := full.Match(context.Background(), h)
			sp, _ := slim.Match(context.Background(), h)
			if fp != sp {
				t.Errorf("%s 在删前删后判定不同（%s / %s）", h, fp, sp)
			}
		}
	}
}
