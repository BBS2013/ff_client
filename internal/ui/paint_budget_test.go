package ui

// 绘制预算守卫：面板跑在 WebKitGTK 的**软件光栅**下
// （gui.go 里 WebviewGpuPolicy=Never，理由就写在那个文件的注释里），
// 于是"样式好不好看"和"画不画得动"是同一件事的两面——而这一面此前从没被量过。
//
// 实测（README §9.7，`make paint`，同一构建内 A/B，dpr=2，真引擎 WebKitGTK+NEVER）：
//
//	规则页滚动帧时中位      128ms → 34ms
//	日志框内层滚动帧时中位   65ms → 33ms
//	切到设置页的首帧        126ms → 60ms
//
// 三条硬约束都来自那组数：
//
//	① 大表面（.card）不许带投影。环境影铺在 800×1000 的大盒子上时，
//	   软件光栅每帧都要把它裁出盒子再模糊一次，代价按面积计价。
//	② 会滚动的盒子不许带投影。它每帧都要重画，那层模糊也就每帧重画一遍。
//	③ 铺满视口的渐变不许留着。渐变是按像素混色的，这台机器的屏是 2 倍，
//	   一个视口就是 290 万像素；把它缩成顶部一条 320px 的带子，观感几乎一样。
//
// 谁把这三样加回去，这条测试会红，并把上面那几个数印在错误信息里。

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// cssBlock 取一段选择器的声明（第一个 "{" 到配对的 "}"）。
// 源文件里是 ".card {"（带空格），构建产物里是 ".card{"，两种都要认。
func cssBlock(css, selector string) string {
	re := regexp.MustCompile(regexp.QuoteMeta(selector) + `\s*\{`)
	loc := re.FindStringIndex(css)
	if loc == nil {
		return ""
	}
	rest := css[loc[1]:]
	end := strings.Index(rest, "}")
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func TestStyleKeepsLargeSurfacesCheap(t *testing.T) {
	css := frontendFile(t, "style.css")

	card := cssBlock(css, ".card")
	if card == "" {
		t.Fatal("frontend/src/style.css 里找不到 .card 的规则块")
	}
	if strings.Contains(card, "box-shadow") {
		t.Errorf(".card 上又出现 box-shadow 了：\n  %s\n"+
			"  大表面带投影时，软件光栅每帧都要裁+模糊一次，代价按盒子面积计价。\n"+
			"  实测（README §9.7，make paint）：规则页滚动帧时中位 124ms → 34ms 就是靠去掉它。\n"+
			"  要那点厚度感，用 border-top-color / border-bottom-color 分色（盒子内部不额外占绘制面积）。",
			strings.TrimSpace(card))
	}

	// 会滚动的盒子更贵：它自己的每一帧都要重画，那层阴影也跟着每帧重画。
	// 日志框原来就有一层 inset 阴影，内层滚动 65ms/帧 → 去掉后 33ms/帧。
	for _, blk := range cssBlocks(css) {
		body := blk[1]
		if !strings.Contains(body, "overflow-y: auto") && !strings.Contains(body, "overflow: auto") {
			continue
		}
		if strings.Contains(body, "box-shadow") {
			t.Errorf("会滚动的盒子 %s 上带着 box-shadow：\n  %s\n"+
				"  滚动时这层模糊每帧都要重画。实测（README §9.7）：日志框内层滚动 65ms/帧 → 33ms/帧。\n"+
				"  要那点立体感，用 border-top-color 之类的描边代替。",
				strings.TrimSpace(blk[0]), strings.TrimSpace(body))
		}
	}

	content := cssBlock(css, ".content")
	if content == "" {
		t.Fatal("frontend/src/style.css 里找不到 .content 的规则块")
	}
	// 天光必须限定在一条带子里：background 里的 size（"/ 100% 320px"）不能是整屏。
	size := regexp.MustCompile(`/\s*100%\s*(\d+)px`).FindStringSubmatch(content)
	if size == nil {
		t.Errorf(".content 的背景没有限定天光的范围（没有 \" / 100%% Npx \" 这样的 size）：\n  %s\n"+
			"  渐变是按像素混色的，铺满视口就是 290 万像素（这台机器是 2 倍屏）。\n"+
			"  实测（README §9.7）：切到设置页的首帧 126ms → 60ms。",
			strings.TrimSpace(content))
	} else {
		h, err := strconv.Atoi(size[1])
		if err != nil {
			t.Fatalf("解析天光带高度 %q: %v", size[1], err)
		}
		if h > 480 {
			t.Errorf(".content 的天光带 %dpx 太高了（上限 480px）：\n  %s\n"+
				"  这条带子每像素都要混一次色，带子越宽越贵。", h, strings.TrimSpace(content))
		}
	}
}

// cssBlocks 把样式表拆成 (选择器, 声明) 一组一组。
// 只取最内层的花括号对，所以 @media 里面的规则也能拆出来。
// 注释先剥掉：不然选择器那一格里会混进上一段的中文注释，报错时不好认。
func cssBlocks(css string) [][2]string {
	css = regexp.MustCompile(`/\*.*?\*/`).ReplaceAllString(css, "")
	re := regexp.MustCompile(`([^{}]+)\{([^{}]*)\}`)
	var out [][2]string
	for _, m := range re.FindAllStringSubmatch(css, -1) {
		out = append(out, [2]string{strings.TrimSpace(m[1]), m[2]})
	}
	return out
}
