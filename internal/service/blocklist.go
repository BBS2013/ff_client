package service

// 拦截名单的批量维护：粘一大段域名进去，以及把"装了却什么也没多拦"的条目清掉。
//
// 不复用 AddBlockDomain 那种一条一写盘的路径，是因为这份名单住在配置文件里：
// 逐条添加就是逐份读写配置再逐次 applyBlockLive，粘 500 条要写 500 次，
// 中途任何一次失败都留下半截名单，而用户要的是"粘一次，完事"。

import (
	"errors"
	"fmt"
	"strings"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/rules"
)

// blockDeadCap 是报给界面的死条目条数上限。
//
// 名单常是从网上抄来的几万条，被更宽条目盖住的那些同样能到几千条；面板每 5 秒轮询一次，
// 几千句话每轮都过一次 Wails 桥，面板会肉眼可见地卡。总数另有一个字段带出去，
// 所以截断不会让人误以为"就这些"。
const blockDeadCap = 200

// mutate 的回调里用这两个哨兵把"别写盘"这件事说清楚：
// mutate 一旦收到错误就会在 Save 之前返回，于是"什么都没变"不会留下备份文件。
var (
	errNoBlockLines   = errors.New("没有要添加的域名")
	errNothingAdded   = errors.New("没有新增的域名")
	errNothingToPrune = errors.New("没有可清理的条目")
)

// BlockImport 是一次批量粘贴拦截域名的结果。
//
// 字段的分工与 UserRuleImport 一样，每个都回答用户会问的一个问题：
// 读了几行、新增几条、名单里本来就有几条、哪几行被拒为什么、有几条装上却不会多拦什么。
// Written 单独说明"文件到底动了没有"——全被拒时不能顺着提示写"已保存"。
type BlockImport struct {
	Total    int      `json:"total"`
	Accepted int      `json:"accepted"`
	Existing int      `json:"existing"`
	Rejected []string `json:"rejected"`
	Dead     []string `json:"dead"`
	Written  bool     `json:"written"`
}

// parseBlockLine 把粘贴进来的一行读成一个裸域名。
//
// 除了裸域名，还收三种网上抄名单时的常见写法，因为它们占了实际粘贴量的一大半：
// AdGuard/uBlock 的 `||example.com^`、带修饰符的 `||example.com^$third-party`，
// 以及清单头部的 `[Adblock Plus 2.0]`（这一行是说明而不是域名）。
// 修饰符一律丢掉：这份名单只有"拦/不拦"两档，`$script` 之类的东西在这里没有对应物，
// 留着只会变成一条永远匹配不上的死配置。
//
// 明确拒掉的两种：例外规则 `@@||x`（它的意思正相反，收下来就变成了拦），
// 以及一行里挤了多个域名的 hosts 写法（`0.0.0.0 a.com b.com`）——
// 只取其中一条会把其余的悄悄丢掉，所以报错并告诉用户拆开。
func parseBlockLine(line string) (string, error) {
	s := strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		return "", errors.New("这是名单清单的头部标记（如 [Adblock Plus 2.0]），不是域名")
	case strings.HasPrefix(s, "@@"):
		return "", errors.New("这是例外规则（@@ 开头），意思是不要拦它；这份名单只收要拦的域名")
	}
	if strings.HasPrefix(s, "||") {
		s = s[2:]
	}
	if i := strings.IndexByte(s, '$'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(s, "^")
	if strings.ContainsAny(s, " \t") {
		return "", fmt.Errorf("%q 一行里有多个域名（hosts 写法或一条里挤了几条）；这份名单一行收一个，拆开再粘", s)
	}
	return config.NormalizeBlockDomain(s)
}

// AddBlockDomains 把一整段文本收进拦截名单。
//
// 一行一次判定、逐条记账：粘 200 条里有 1 条打错字是常事，整段丢回去等于让人重粘一遍。
// 落盘只有一次，落完才 applyBlockLive。
func (s *Service) AddBlockDomains(text string) (BlockImport, error) {
	imp := BlockImport{Rejected: []string{}, Dead: []string{}}
	var next []string
	seen := map[string]bool{}
	added := map[string]bool{}

	err := s.mutate(func(cfg *config.Config) error {
		for _, have := range rules.NormalizeBlocklist(cfg.Block.Domains) {
			seen[have] = true
			next = append(next, have)
		}
		for i, raw := range strings.Split(text, "\n") {
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
				continue
			}
			imp.Total++
			d, perr := parseBlockLine(line)
			if perr != nil {
				imp.Rejected = append(imp.Rejected, fmt.Sprintf("第 %d 行 %s：%v", i+1, briefLine(line), perr))
				continue
			}
			if seen[d] {
				imp.Existing++
				continue
			}
			seen[d] = true
			next = append(next, d)
			added[d] = true
			imp.Accepted++
		}
		if imp.Total == 0 {
			return errNoBlockLines
		}
		if imp.Accepted == 0 {
			// 一条都没新增：返回错误让 mutate 在写盘之前停下。
			// 直接返回 nil 的话配置照样会被重新序列化一遍——用户手写的排版被抹平，
			// 还多出一个内容一模一样的备份，而这次操作其实什么都没加。
			return errNothingAdded
		}
		cfg.Block.Domains = next
		return nil
	})
	if errors.Is(err, errNoBlockLines) {
		return imp, errors.New("没有要添加的域名：空行与 # / ! 注释不算")
	}
	if err != nil && !errors.Is(err, errNothingAdded) {
		return BlockImport{}, err
	}
	if imp.Accepted == 0 {
		if imp.Existing > 0 {
			logx.Infof("批量添加拦截域名: 读 %d 行，%d 条名单里本来就有，文件未改动", imp.Total, imp.Existing)
		}
		return imp, nil
	}
	imp.Written = true
	// 只报这次新加的：老的那些上面那一栏一直在说，重复一遍等于把"这次粘贴的问题"淹掉。
	for _, d := range rules.DeadBlockDomains(next) {
		if added[d.Domain] {
			imp.Dead = append(imp.Dead, d.String())
		}
	}
	logx.Infof("批量添加拦截域名: 读 %d 行，新增 %d，本来就有 %d，拒掉 %d",
		imp.Total, imp.Accepted, imp.Existing, len(imp.Rejected))
	if err := s.applyBlockLive(); err != nil {
		return imp, err
	}
	return imp, nil
}

// PruneBlockDomains 去掉名单里那些被更宽条目盖住的项（以及重复写法），返回删掉的条数。
//
// 这件事只改一份纯冗余：删掉的每一条，它盖住的域名都被留在名单里的某一条同样盖住
// （见 rules.PruneBlockDomains 的证明），所以没有任何一个域名的判定会变。
// 面板上它是一个要用户点一下的按钮——这份名单是配置段，清理是用户显式要的动作。
//
// 一条都删不掉时不写盘：config.Save 会留一份备份，为"什么都没变"制造一个历史条目没有意义。
func (s *Service) PruneBlockDomains() (int, error) {
	removed := 0
	kept := 0
	err := s.mutate(func(cfg *config.Config) error {
		k, n := rules.PruneBlockDomains(cfg.Block.Domains)
		removed, kept = n, len(k)
		if n == 0 {
			return errNothingToPrune
		}
		cfg.Block.Domains = k
		return nil
	})
	if errors.Is(err, errNothingToPrune) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	logx.Infof("拦截名单已清理 %d 条（重复或被更宽的条目盖住），剩 %d 条", removed, kept)
	if err := s.applyBlockLive(); err != nil {
		return removed, err
	}
	return removed, nil
}

// blockDeadSentences 把死条目写成一句话列表，并给出真实总数。
// 列表按域名排好序，所以面板上这栏文字不会自己重排。
func blockDeadSentences(list []string) (msgs []string, total int) {
	all := rules.DeadBlockDomains(list)
	total = len(all)
	msgs = []string{}
	for i, d := range all {
		if i >= blockDeadCap {
			break
		}
		msgs = append(msgs, d.String())
	}
	return msgs, total
}
