// 这份名单里"写了但永远不会命中"的那些条。
//
// 为什么要专门算这件事：引擎按顺序取**第一条**命中的规则，而面板的「添加」一律追加在末尾。
// 于是"我明明加了 DOMAIN,www.example.com,DIRECT，为什么不生效"是必然会来的一幕——
// 前面那条 DOMAIN-SUFFIX,example.com,PROXY 把它压住了，而界面上两条并排摆着，
// 谁看起来都像是生效的。这条判据不需要猜网络，光看名单就能确定，所以没有理由不告诉用户。
package rules

import (
	"fmt"
	"strings"
)

// hostSet 是能从这个类型推出来的"它管哪些主机"的形状。
//
// regex 与未知类型是 unknown：正则的包含关系判不准（一般是不可判定的），
// 而这里宁可少说一句，也不要说错一句——"这条永远不会命中"是个会让人删规则的断言。
type hostSet int

const (
	setUnknown hostSet = iota
	setExact           // 只有一个域名
	setSuffix          // 某个域名及其所有子域
	setKeyword         // 含某个子串的所有域名
)

func shapeOf(typ string) hostSet {
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case "DOMAIN":
		return setExact
	case "DOMAIN-SUFFIX":
		return setSuffix
	case "DOMAIN-KEYWORD":
		return setKeyword
	}
	return setUnknown
}

// covers 判断 a 的取值范围是不是 b 的超集：b 命中的每个域名 a 都先命中。
// 两侧都已经是引擎归一化过的小写写法。
//
// 只列得出得动的关系，判不准的一律返回 false（见上面那段"宁可少说"）。
func covers(aTyp, aVal, bTyp, bVal string) bool {
	a, b := shapeOf(aTyp), shapeOf(bTyp)
	if a == setUnknown || b == setUnknown {
		return false
	}
	switch a {
	case setExact:
		// 一个点只能盖住一个点。
		return b == setExact && aVal == bVal
	case setSuffix:
		switch b {
		case setExact:
			return sameOrSubDomain(bVal, aVal)
		case setSuffix:
			return sameOrSubDomain(bVal, aVal)
		}
	case setKeyword:
		switch b {
		case setKeyword:
			// 含 "google.com" 的域名必然含 "google"。
			return strings.Contains(bVal, aVal)
		case setExact, setSuffix:
			// b 的每个取值都把 bVal 当子串带着走。
			return strings.Contains(bVal, aVal)
		}
	}
	return false
}

// sameOrSubDomain 判断 sub 是不是 root 本身或 root 的子域（按点边界，不是随便的后缀）。
func sameOrSubDomain(sub, root string) bool {
	return sub == root || strings.HasSuffix(sub, "."+root)
}

// DeadRule 是一条永远不会命中的规则，连同是谁先把它盖住的。
//
// 下标而不是行号：名单在面板里可以移动，而这句话要能指着表里那一行说"是你"。
type DeadRule struct {
	Index  int
	Line   string
	Reason string
}

// String 是给人看的那一句。面板与日志都读它，所以措辞里必须带上"怎么办"，
// 只说"这条是死的"等于把人留在原地。
func (d DeadRule) String() string {
	return fmt.Sprintf("第 %d 条 %s 永远不会命中：%s。要让它生效就把它挪到前面，否则删掉。", d.Index+1, d.Line, d.Reason)
}

// DeadRules 找出这份名单里永远不会命中的那些条。
//
// blocked 是配置的 block: 段（传原文即可，内部按引擎的写法归一）：
// 那份名单排在整张规则表**之前**（见 Engine.SetBlocklist），
// 所以被它盖住的自定义规则同样是死的——这一类尤其值得说，
// 因为"我给它加了走代理，它还是打不开"听起来完全像代理坏了。
func DeadRules(list []UserRule, blocked []string) []DeadRule {
	suffixes := NormalizeBlocklist(blocked)
	var out []DeadRule
	for i := range list {
		// 自己就是一条正则/未知类型的规则，判不出它是死的（但照样可能被别人盖住？
		// 判不出就别断言，交给重载与查走向）。
		if shapeOf(list[i].Type) == setUnknown {
			continue
		}
		// 被用户停用的那条不参与匹配表，也就谈不上"被盖住所以永远不命中"——
		// 它不命中是因为自己关了，这一栏再说一遍只是噪音，还会把真正的死规则淹掉。
		if list[i].Disabled {
			continue
		}
		why := ""
		for _, d := range suffixes {
			if covers("DOMAIN-SUFFIX", d, list[i].Type, list[i].Value) {
				why = fmt.Sprintf("拦截名单里的 %s 先把它拦下了（名单排在整张规则表之前）", d)
				break
			}
		}
		if why == "" {
			for j := 0; j < i; j++ {
				// 停用的那条**不进取匹配表**，所以它盖不住后面任何一条。
				// 这一句是这条判据正确性的关键：用户把第 1 条关掉之后，
				// 原本被它压住的第 5 条是**活了**，要是还按"它在前排"来判，
				// 界面会当面说一条现在真的生效的规则是死的——而人正是因为
				// 想让它生效才去关前面那条的。
				if list[j].Disabled {
					continue
				}
				if covers(list[j].Type, list[j].Value, list[i].Type, list[i].Value) {
					why = fmt.Sprintf("第 %d 条 %s 已经先覆盖了它", j+1, list[j].Line())
					break
				}
			}
		}
		if why != "" {
			out = append(out, DeadRule{Index: i, Line: list[i].Line(), Reason: why})
		}
	}
	return out
}

// DeadUserRules 是同一条判据的那份"一句话列表"，给只要文本的调用方用。
func DeadUserRules(list []UserRule, blocked []string) []string {
	var out []string
	for _, d := range DeadRules(list, blocked) {
		out = append(out, d.String())
	}
	return out
}
