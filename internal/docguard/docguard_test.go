// Package docguard 守的是仓库自己的交付物：验收表一旦排错列，
// 「哪一条已经有证据」这件事就从文档上消失了——而这份表正是判验收的依据。
package docguard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Test 只依赖仓库里的文档，不需要网络、root 或构建产物。

var sepRow = regexp.MustCompile(`^\|[ |:\-]+$`)

// repoRoot 从测试所在目录往上找到仓库根（go test 的工作目录是本包目录）。
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		if _, err := os.Stat(filepath.Join(dir, "ACCEPTANCE.md")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("找不到 ACCEPTANCE.md，守卫扫了个空")
	return ""
}

// acceptanceTables 把 ACCEPTANCE.md 切成表：表头 + 分隔行 + 紧随其后的若干行。
// 代码块里的竖线不算（那是 shell 管道，不是分隔符）。
type table struct {
	start int // 表头行号（1 起）
	pipes int // 分隔行的竖线数，这一张表每行都必须是这个数
	end   int // 最后一行的行号
}

func tables(lines []string) []table {
	var out []table
	inFence := false
	for i := 0; i+1 < len(lines); i++ {
		s := strings.TrimSpace(lines[i])
		n := strings.TrimSpace(lines[i+1])
		if strings.HasPrefix(s, "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if !strings.HasPrefix(s, "|") || !sepRow.MatchString(n) {
			continue
		}
		tb := table{start: i + 1, pipes: strings.Count(n, "|"), end: i + 2}
		for j := i + 2; j < len(lines); j++ {
			t2 := strings.TrimSpace(lines[j])
			if strings.HasPrefix(t2, "```") || !strings.HasPrefix(t2, "|") {
				break
			}
			tb.end = j + 1
		}
		out = append(out, tb)
		i = tb.end - 1
	}
	return out
}

func TestAcceptanceTablesAreWellFormed(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "ACCEPTANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	tbs := tables(lines)
	if len(tbs) < 5 {
		t.Fatalf("只认出 %d 张表：判据或文件形状变了，这条守卫已经在看别的东西", len(tbs))
	}
	for _, tb := range tbs {
		for n := tb.start; n <= tb.end; n++ {
			line := lines[n-1]
			s := strings.TrimSpace(line)
			// 行首有空白却以 | 开头，说明这是一行表格被拆成了两行——
			// 第二行会被当成表外的东西，那一格的证据就从表里消失了。
			if line != s && strings.HasPrefix(s, "|") {
				t.Errorf("%d 行：表格行以空白开头（像是被拆成两行），渲染出来这一格会掉出表外：%s", n, s)
				continue
			}
			// 单元格里的竖线按 markdown 的写法转义成 \|（日志原文里就有），
			// 数分隔符时先把它去掉，否则一句引文就会让整张表"多出一列"。
			if got := strings.Count(strings.ReplaceAll(s, `\|`, ""), "|"); got != tb.pipes {
				t.Errorf("%d 行：%d 个竖线，本表的分隔行是 %d 个——列数不对齐，右侧各列会整体左移一格：%s",
					n, got, tb.pipes, s)
			}
		}
	}
}

// TestAcceptanceIDsAreUnique 编号重复意味着两行在讲两件事却共用一个证据号，
// 读的人会把其中一条当成另一条的补充。
func TestAcceptanceIDsAreUnique(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "ACCEPTANCE.md"))
	if err != nil {
		t.Fatal(err)
	}
	idRe := regexp.MustCompile(`^\|\s*(A\d+[a-z]?)\s*[| ]`)
	seen := map[string][]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if m := idRe.FindStringSubmatch(line); m != nil {
			seen[m[1]] = append(seen[m[1]], line)
		}
	}
	if len(seen) < 20 {
		t.Fatalf("只认出 %d 个编号：这条守卫没在看真的表", len(seen))
	}
	for id, rows := range seen {
		if len(rows) > 1 {
			t.Errorf("编号 %s 出现 %d 次，证据会被当成同一条", id, len(rows))
		}
	}
}
