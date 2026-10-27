// 拦截名单自己那份"装上了但什么也没多拦"的账。
//
// 名单位于整张规则表**之前**（见 Engine.SetBlocklist），而它是按后缀拦的：
// 名单里已经有 example.com 的情况下，再加一条 ads.example.com、api.ads.example.com
// 都不会让任何一个新域名被拦下。这不是用户的错——网上抄来的名单互相包含是常态，
// 抄完自己也看不出来，于是名单越滚越长，"我明明加了它怎么还在外连"的困惑就是这么来的。
//
// 只报"确实一条也没多拦"的：判据是**逐级剥后缀**而不是两两比大小，
// O(条目 × 标签数)，几万个条目的名单也不卡；也不会把活着的条目误判成死的。
package rules

import (
	"fmt"
	"sort"
	"strings"
)

// DeadBlock 是一条被更宽的条目盖住的拦截域名。
type DeadBlock struct {
	// Domain 是被盖住的那一条。
	Domain string
	// By 是盖住它的那一条：名单里已经有的、按后缀拦更宽的域名。
	By string
}

// String 是给人看的那一句，必须自带"怎么办"。
func (d DeadBlock) String() string {
	return fmt.Sprintf("%s 已经在名单里（按后缀拦，子域自动生效），所以 %s 这一条什么也没多拦。",
		d.By, d.Domain)
}

// DeadBlockDomains 找出这份名单里那些"装上了却什么都没多拦"的条目。
//
// 传原文即可（内部按引擎的写法归一、去重）。同一域名只会报一次。
func DeadBlockDomains(list []string) []DeadBlock {
	set := make(map[string]bool)
	for _, d := range NormalizeBlocklist(list) {
		set[d] = true
	}
	var out []DeadBlock
	for d := range set {
		if by := coveringRoot(d, set); by != "" {
			out = append(out, DeadBlock{Domain: d, By: by})
		}
	}
	// 上面是 map 遍历、顺序不定：判据每次都得给出同一份话，
	// 否则面板上这栏文字会自己重排，看着像出了问题。
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// coveringRoot 找名单里盖住 d 的那一条（d 的某一级点边界后缀），没有就返回空。
//
// d 自己不会被判成被自己盖住：候选全是严格更短的后缀。
// 取最短的那个匹配（最宽的那条）：a.b.example.com 被 example.com 盖住时，
// 先报 "b.example.com 已经在名单里" 会让用户去删一条本身也没多拦的条目。
func coveringRoot(d string, set map[string]bool) string {
	best := ""
	for rest := d; ; {
		i := strings.Index(rest, ".")
		if i < 0 {
			return best
		}
		rest = rest[i+1:]
		if set[rest] && (best == "" || len(rest) < len(best)) {
			best = rest
		}
	}
}

// PruneBlockDomains 去掉那些被更宽的条目盖住的项，返回剩下的名单与删掉的条数。
//
// 删掉它们不改变任何一个域名的判定结果：被删的那条的后缀链上，
// 总有一条"没被任何条目盖住"的（长度严格递减，链子必然终止），那条留着，
// 而它盖住的范围包含被删项盖住的全部范围。所以这是纯粹去重，不是改策略。
//
// 归一化顺带会把重复写法（大写、多余尾点、同一域名两条）合成一条，
// 它们在引擎里本来就只生效一次，所以返回的删除条数里也含这些——
// 引擎匹配的是归一化后的名单，删重复项同样不改结果。
//
// 用在界面上是用户的显式动作：这份名单是配置段，面板只替用户改他点的那一处。
func PruneBlockDomains(list []string) (kept []string, removed int) {
	dead := make(map[string]bool)
	for _, d := range DeadBlockDomains(list) {
		dead[d.Domain] = true
	}
	kept = make([]string, 0, len(list))
	for _, d := range NormalizeBlocklist(list) {
		if dead[d] {
			removed++
			continue
		}
		kept = append(kept, d)
	}
	return kept, removed
}
