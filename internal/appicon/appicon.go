// Package appicon 用带符号距离场（SDF）把应用图标画出来，不依赖任何图像工具链。
//
// 为什么不用现成 PNG：托盘 16~24px、窗口 256px、文档 512px 要用同一套设计，
// 手写 SDF 让"缩小后还认得出"变成可检查的属性（小尺寸换用简化几何），
// 而且构建机上不需要 rsvg/inkscape/cairo，出图只靠 go run。
//
// 图形语言：一个朝右开口的厚环 = 隧道口（这个软件的本职是把流量送进一条隧道），
// 从洞口出来的两条线分叉 = 规则分流（蓝箭头=走代理，绿圆点=直连落地）。
// 配色取自面板的主题变量（frontend/src/style.css 的 --accent / --ok），
// 图标和窗口看起来是一家的。
package appicon

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// design 是设计坐标系边长；渲染按 size/512 等比缩放，线宽一起缩。
const design = 512.0

// feather 是 SDF 转覆盖率时的羽化宽度（设计像素）。
const feather = 1.7

// 调色板。底板用深色，浅色/深色任务栏上都能保住轮廓。
// 色相与面板主题同源（frontend/src/style.css 的 --accent #3b82f6 / --ok #34d399），
// 深蓝到浅蓝三档是同一色相提亮，深色底板上不提亮一档会糊。
var (
	bgTop     = rgb(38, 48, 66)
	bgBottom  = rgb(15, 18, 24)
	highlight = rgb(255, 255, 255)

	ringBack = rgb(48, 98, 160)   // 内圈细环，只给纵深
	ringMain = rgb(70, 140, 214)  // 外圈主环
	ringMark = rgb(126, 205, 255) // 简化版唯一的那条环，小尺寸上要更亮

	proxyLane  = rgb(104, 168, 255)
	directLane = rgb(52, 211, 153)
)

type pix struct{ r, g, b float64 }

func rgb(r, g, b int) pix { return pix{float64(r), float64(g), float64(b)} }

// level 决定画多细。detailMark 给 ≤32px：小尺寸下"三层拱 + 分叉"会糊成一团，
// 这不是审美问题是像素预算——16px 里一条线只剩 1px。
type level int

const (
	detailMark level = iota
	detailFull
)

// PNG 输出一张 size×size 的图标（带透明边距），可直接喂 systray / Wails / favicon。
// 小于 48px 自动换成简化几何。
func PNG(size int) []byte {
	if size <= 0 {
		return nil
	}
	lv := detailFull
	if size < 48 {
		lv = detailMark
	}
	return render(size, lv)
}

// Tray 给托盘：systray 在 Linux 走 D-Bus，给 64px 让高分屏缩放后仍清晰。
// 注意它用简化几何——托盘实际显示只有 22px 左右。
func Tray() []byte { return mark(64) }

// Window 给窗口与关于页。
func Window() []byte { return PNG(256) }

// mark 强制用简化几何出图（尺寸任意）。
func mark(size int) []byte { return render(size, detailMark) }

func render(size int, lv level) []byte {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	scale := float64(size) / design
	const ss = 4 // 每像素 4×4 子样本，边缘的灰度过渡靠它，不靠事后模糊
	step := 1.0 / ss

	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var sr, sg, sb, sa float64
			for iy := 0; iy < ss; iy++ {
				for ix := 0; ix < ss; ix++ {
					x := (float64(px) + (float64(ix)+0.5)*step) / scale
					y := (float64(py) + (float64(iy)+0.5)*step) / scale
					c, cov := paint(x, y, lv)
					sr += c.r * cov
					sg += c.g * cov
					sb += c.b * cov
					sa += cov
				}
			}
			if sa == 0 {
				continue
			}
			n := float64(ss * ss)
			img.SetNRGBA(px, py, color.NRGBA{
				R: uint8(sr / sa),
				G: uint8(sg / sa),
				B: uint8(sb / sa),
				A: uint8(255 * sa / n),
			})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil // 编码一张像素图不会失败
	}
	return buf.Bytes()
}

// paint 返回设计坐标 (x,y) 上的颜色与覆盖率（0~1）。
func paint(x, y float64, lv level) (pix, float64) {
	// 底板：圆角方块，四周留 16 设计像素的透明边距，托盘渲染时不会被裁。
	tile := sdRoundRect(x, y, design/2, design/2, 240, 240, 108)
	cover := fill(tile)
	if cover <= 0 {
		return pix{}, 0
	}
	c := mix(bgTop, bgBottom, clamp01((y-16)/(design-32)))
	// 内侧一圈高光是深色背景下保住轮廓的关键，也是"这是个按钮/磁贴"的暗示。
	c = over(c, highlight, stroke(math.Abs(tile+1.6), 2.6)*0.15)

	if lv == detailMark {
		drawMark(x, y, &c)
	} else {
		drawFull(x, y, &c)
	}
	return c, cover
}

// drawFull 是 ≥48px 的完整版：一个朝右开口的厚圆环（隧道口）+ 从洞里出来的两条车道。
//
// 为什么是"环 + 缺口"而不是三层拱：三层嵌套的拱在 512px 上好看，
// 但读起来是彩虹/wifi；而"一个有洞口的环 + 线从洞里出来"一眼就是隧道通行。
// 后面那圈更暗更细的环只负责纵深，不参与叙事。
//
// 圆心刻意放在 237 而不是 256：整个图形（环 + 出洞的两条线）的包围盒
// 左右留白相等，环本身偏左是构图需要，不是画歪了。
func drawFull(x, y float64, c *pix) {
	const (
		cx, cy = 237.0, 256.0
		gap    = 0.82 // 洞口张开的半角（弧度），车道就从这里出去
		w      = 19.0
	)
	// 洞口的暗部：让环里看起来是"深的"而不是一块实心。
	*c = over(*c, pix{8, 10, 14}, fill(sdDisc(x, y, cx, cy, 98))*0.55)
	*c = over(*c, ringBack, stroke(sdArcRight(x, y, cx, cy, 90, gap), 20))
	*c = over(*c, ringMain, stroke(sdArcRight(x, y, cx, cy, 140, gap), 40))

	// 两条车道：蓝的继续被带走（箭头），绿的就地直连（圆点）。
	*c = over(*c, proxyLane, stroke(sdSegment(x, y, 253, 247, 387, 192), w))
	*c = over(*c, proxyLane, stroke(sdChevron(x, y, 413, 181, 48, -0.40, 0.44), w))
	*c = over(*c, directLane, stroke(sdSegment(x, y, 253, 265, 373, 322), w))
	*c = over(*c, directLane, fill(sdDisc(x, y, 392, 334, 17)))
}

// drawMark 是 16~32px 的简化版：一个粗环 + 一支穿洞口而出的箭头。
// 分叉在这个尺寸上只剩噪声，所以只留"环 + 箭头"这个骨架。
//
// 线宽比完整版粗好几倍不是审美选择是像素预算：16px 输出时缩放系数是 1/32，
// 完整版的 19 设计像素车道只剩 0.6px，直接消失；这里的 68 才有 2.1px。
func drawMark(x, y float64, c *pix) {
	const (
		cx, cy = 264.0, 256.0
		gap    = 0.95
	)
	*c = over(*c, pix{8, 10, 14}, fill(sdDisc(x, y, cx, cy, 104))*0.5)
	*c = over(*c, ringMark, stroke(sdArcRight(x, y, cx, cy, 148, gap), 76))
	*c = over(*c, proxyLane, stroke(sdSegment(x, y, 296, cy, 350, cy), 68))
	*c = over(*c, proxyLane, stroke(sdChevron(x, y, 396, cy, 78, 0, 0.5), 68))
}

// ---------- SDF 基本件 ----------

// sdRoundRect 返回到圆角矩形轮廓的有符号距离（形内为负）。
func sdRoundRect(x, y, cx, cy, hx, hy, rad float64) float64 {
	qx := math.Abs(x-cx) - hx + rad
	qy := math.Abs(y-cy) - hy + rad
	out := math.Hypot(math.Max(qx, 0), math.Max(qy, 0)) - rad
	return out + math.Min(math.Max(qx, qy), 0)
}

// sdArcRight 返回到一段圆弧的无符号距离：圆心 (cx,cy)、半径 r，
// 但右侧 |角度| < gap 的那段不画（洞口），落在这个扇形里的点算到最近弧端的距离。
func sdArcRight(x, y, cx, cy, r, gap float64) float64 {
	dx, dy := x-cx, y-cy
	if math.Abs(math.Atan2(dy, dx)) >= gap {
		return math.Abs(math.Hypot(dx, dy) - r)
	}
	ex, ey := r*math.Cos(gap), r*math.Sin(gap)
	d1 := math.Hypot(dx-ex, dy-ey)
	d2 := math.Hypot(dx-ex, dy+ey)
	return math.Min(d1, d2)
}

// sdSegment 返回点到线段的距离。
func sdSegment(x, y, ax, ay, bx, by float64) float64 {
	px, py := x-ax, y-ay
	vx, vy := bx-ax, by-ay
	t := clamp01((px*vx + py*vy) / (vx*vx + vy*vy))
	return math.Hypot(px-t*vx, py-t*vy)
}

// sdChevron 返回到箭头「›」两条臂的距离。tip 是尖端，dir 是箭头朝向（弧度），
// angle 是半张开角，arm 是臂长。
func sdChevron(x, y, tipX, tipY, arm, dir, angle float64) float64 {
	ax := tipX - arm*math.Cos(dir-angle)
	ay := tipY - arm*math.Sin(dir-angle)
	bx := tipX - arm*math.Cos(dir+angle)
	by := tipY - arm*math.Sin(dir+angle)
	return math.Min(sdSegment(x, y, ax, ay, tipX, tipY), sdSegment(x, y, bx, by, tipX, tipY))
}

func sdDisc(x, y, cx, cy, r float64) float64 {
	return math.Hypot(x-cx, y-cy) - r
}

// ---------- 覆盖与合成 ----------

// fill 用于有符号距离的填充形状：形内（d<0）全实，边缘一个 feather 宽度过渡。
func fill(d float64) float64 {
	t := (d + feather) / (2 * feather)
	if t <= 0 {
		return 1
	}
	if t >= 1 {
		return 0
	}
	return 1 - t*t*(3-2*t)
}

// stroke 用于"到中心线的距离"，画出宽 w 的圆头线。
func stroke(d, w float64) float64 { return fill(d - w/2) }

func mix(a, b pix, t float64) pix {
	return pix{
		r: a.r + (b.r-a.r)*t,
		g: a.g + (b.g-a.g)*t,
		b: a.b + (b.b-a.b)*t,
	}
}

// over 把一层叠到底色上。alpha 是这一层的覆盖率（含子样本平均）。
func over(dst, src pix, alpha float64) pix {
	if alpha <= 0 {
		return dst
	}
	if alpha > 1 {
		alpha = 1
	}
	return pix{
		r: dst.r + (src.r-dst.r)*alpha,
		g: dst.g + (src.g-dst.g)*alpha,
		b: dst.b + (src.b-dst.b)*alpha,
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}
