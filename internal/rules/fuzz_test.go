// 规则解析的模糊测试。它的输入不是"用户手写的配置"，而是**远端订阅拉回来的字节**，
// 所以这一层的第一条要求同样是：任何输入都不许 panic，错误信息里不许带出多余的东西。
package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzParseLine(f *testing.F) {
	seeds := []string{
		"DOMAIN-SUFFIX,example.com,PROXY",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"GEOIP,CN,DIRECT",
		"FINAL,PROXY",
		"",
		",",
		",,,,",
		"DOMAIN,",
		"IP-CIDR,not-a-cidr,PROXY",
		"GEOIP,TOOLONG,PROXY",
		"DOMAIN-SUFFIX,example.com,PROXY,EXTRA",
		strings.Repeat("x", 1024),
		"BOGUS," + strings.Repeat("拦截", 200) + ",PROXY",
		// DOMAIN-REGEX：模式是这一层唯一会被**编译**的值，所以坏模式、
		// 超长模式与混了非法字节的模式都要有种子。
		`DOMAIN-REGEX,^(api|cdn)\.foo\.com$,PROXY`,
		"DOMAIN-REGEX,[unclosed,PROXY",
		"DOMAIN-REGEX," + strings.Repeat("(", 400) + ",PROXY",
		"DOMAIN-REGEX,[\xff\xfe,REJECT",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		// 不许 panic 是底线；下面是"没 panic 但答错了"的那些判据。
		r, isFinal, err := parseLine(line, 1)
		if err != nil {
			if isFinal {
				t.Fatalf("报错的同时又说它是 FINAL: %q", line)
			}
			// 错误信息会被面板与日志原样显示，所以两条硬要求：
			// 不许把整行（最长 1MB）带出去，也不许在截断处切碎多字节字符。
			// 上界要的是"有界"，不是"很小"：%q 会把非 ASCII 展开成 6 字节，
			// 而输入可以到 1MB——所以只要错误长度不跟着输入长就行。
			if len(err.Error()) > 1024 {
				t.Fatalf("错误信息长度 %d，没被截住", len(err.Error()))
			}
			if !utf8.ValidString(err.Error()) {
				t.Fatalf("错误信息被切在字符中间: %q", err.Error())
			}
			return
		}
		if !isFinal && r.policy == "" {
			t.Fatalf("解析成功却没有策略: %q", line)
		}
		if !isFinal && (r.kind < 0 || r.kind >= kindCount) {
			t.Fatalf("解析成功却给了一个不认识的规则类型 %d: %q", r.kind, line)
		}
		// desc() 会进日志与连接表，同样不许炸。
		_ = r.desc()
		// 解析出来的值必须还能被原样喂回去（面板的"删除这条规则"走的就是它）。
		if !isFinal && strings.Contains(r.desc(), "\x00") {
			t.Fatalf("desc() 里带了 NUL: %q", r.desc())
		}
	})
}

// FuzzIncludeLine 打的是整条 #include 处理链：识别指令 → 查控制字符 →
// 算路径 → 判越界 → 打开文件。只测 trimIncludeDirective 不够，
// 因为"拒收"这件事发生在后面几步，而错误信息会不会带出垃圾字节正取决于这些步。
func FuzzIncludeLine(f *testing.F) {
	for _, s := range []string{
		"#include ./a.txt", "#include? ./a.txt", "#include /etc/passwd",
		"#include ../../etc/passwd", "#include ", "#include", "#include\x17",
		"#include ./a\x1bb.txt", "#include \\evil\\share", "#include ./\x00",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if strings.ContainsAny(line, "\n\r") {
			return // 真实输入按行喂，带换行的字符串不属于这一层
		}
		dir, err := os.MkdirTemp("", "wps-fuzz-include")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		top := filepath.Join(dir, "rules.txt")
		body := line + "\nFINAL,PROXY\nDOMAIN-SUFFIX,a.example,PROXY\n"
		if err := os.WriteFile(top, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = Load(top, nil, nil)
		if err == nil {
			return
		}
		msg := err.Error()
		if len(msg) > 1024 {
			t.Fatalf("错误信息长度 %d，没被截住: %.120q", len(msg), msg)
		}
		// 错误会进日志、进面板：控制字符（尤其 ESC/BS/NUL）不许被原样带出去。
		for i := 0; i < len(msg); i++ {
			if c := msg[i]; c < 0x20 && c != '\n' || c == 0x7f {
				t.Fatalf("错误信息里带了控制字符 0x%02x: %q", c, msg)
			}
		}
		if !utf8.ValidString(msg) {
			t.Fatalf("错误信息不是合法 UTF-8: %q", msg)
		}
	})
}
