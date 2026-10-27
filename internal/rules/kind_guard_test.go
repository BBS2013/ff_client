package rules

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKindTablesAgree 规则类型登记在两张表里（kindNames 给人看、kindByName 给解析用），
// 匹配和分表又各写一处。任何一处不同步，症状都是静默的：
// 要么日志里类型名显示成空串，要么规则解析成功却永远不命中。
func TestKindTablesAgree(t *testing.T) {
	for k := kind(0); k < kindCount; k++ {
		name := kindNames[k]
		if name == "" {
			t.Errorf("kind %d 没有名字：日志与界面上会显示成空串", k)
			continue
		}
		if got, ok := kindByName[name]; !ok || got != k {
			t.Errorf("kind %d 的名字 %q 反查不回来（得到 %v,%v）", k, name, got, ok)
		}
	}
	for name, k := range kindByName {
		if kindNames[k] != name {
			t.Errorf("kindByName[%q]=%d 但 kindNames 里是 %q：两张表不同步", name, k, kindNames[k])
		}
	}
}

// TestEveryKindIsDispatched 每种类型都必须真的被装进某张匹配表。
//
// 这就是"新增 kind 只补了解析、忘了补分发"那扇门：解析放行、加载不报错，
// 而规则一条都不命中——黑名单上凭空开个洞，日志一行都不会提。
func TestEveryKindIsDispatched(t *testing.T) {
	geo := fakeGeo{"10.0.0.1": "CN"}
	res := fakeResolver{"a.example": {netip.MustParseAddr("10.0.0.1")}}
	for k := kind(0); k < kindCount; k++ {
		name := kindNames[k]
		if name == "" {
			continue // 由上一条用例负责报
		}
		path := filepath.Join(t.TempDir(), "rules.txt")
		body := sampleRule(k) + "\nFINAL,PROXY\n"
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		e, err := Load(path, geo, res)
		if err != nil {
			if strings.Contains(err.Error(), "还没接入匹配") {
				t.Errorf("类型 %q 解析得过但没接入分发，规则会被静默丢弃: %v", name, err)
			}
			continue
		}
		domain, ip := e.Stats()
		if domain+ip == 0 {
			t.Errorf("类型 %q 加载后一条规则都没进表：等于写了个寂寞", name)
		}
	}
}

// TestEveryKindRoundTripsByName 面板上那一列必须报出用户真正写的类型名。
//
// 这条遍历的是 kindByName（注册表），所以新增一种类型而忘了让面板认识它，
// 这里会红一次——而不是等到界面上多出一行看不懂的 "OTHER"。
// 判据刻意只看 Type 字符串：可编辑性另有 IsDomain() 那条白名单。
func TestEveryKindRoundTripsByName(t *testing.T) {
	for name, k := range kindByName {
		list, err := parseUserRules(sampleRule(k) + "\n")
		if err != nil {
			t.Errorf("类型 %q 的样本行读不回来: %v", name, err)
			continue
		}
		if len(list) != 1 {
			t.Errorf("类型 %q 读出 %d 条，想要 1", name, len(list))
			continue
		}
		if list[0].Type != name {
			t.Errorf("类型 %q 在界面上会显示成 %q：那一列必须照实报", name, list[0].Type)
		}
	}
}

// sampleRule 给出每种类型一行语法正确的样本。
func sampleRule(k kind) string {
	switch k {
	case kindDomain:
		return "DOMAIN,a.example,DIRECT"
	case kindDomainSuffix:
		return "DOMAIN-SUFFIX,example.com,PROXY"
	case kindDomainKeyword:
		return "DOMAIN-KEYWORD,exa,PROXY"
	case kindDomainRegex:
		return "DOMAIN-REGEX,^a\\.example\\.(com|net)$,PROXY"
	case kindIPCIDR:
		return "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"
	case kindGeoIP:
		return "GEOIP,CN,DIRECT"
	}
	return kindNames[k] + ",x,DIRECT"
}
