package appicon

import (
	"bytes"
	"image"
	"image/png"
	"testing"
)

// 图标是画出来的，不是素材文件：渲染逻辑一旦改坏，运行期只会表现成
// 「托盘没图」「窗口图标是个方块」，编译和界面都不会报错。
// 所以这里的断言全部针对"看得出来的性质"，而不是像素值快照。

func decode(t *testing.T, raw []byte) image.Image {
	t.Helper()
	if len(raw) == 0 {
		t.Fatal("渲染返回空字节，编码环节失败了")
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("不是合法 PNG: %v", err)
	}
	return img
}

func TestPNGSizes(t *testing.T) {
	for _, n := range []int{16, 22, 32, 48, 64, 128, 256, 512} {
		img := decode(t, PNG(n))
		b := img.Bounds()
		if b.Dx() != n || b.Dy() != n {
			t.Errorf("PNG(%d) = %dx%d", n, b.Dx(), b.Dy())
		}
	}
	if got := PNG(0); got != nil {
		t.Error("PNG(0) 应返回 nil，而不是空图")
	}
}

// TestDeterministic 同一尺寸两次渲染必须逐字节相同：
// 构建可复现（打包给别人时这点很重要），也排掉任何未初始化状态。
func TestDeterministic(t *testing.T) {
	a, b := PNG(64), PNG(64)
	if !bytes.Equal(a, b) {
		t.Fatal("同尺寸两次渲染不一致")
	}
	if !bytes.Equal(Tray(), mark(64)) {
		t.Fatal("Tray() 应等于 64px 的简化几何")
	}
	if !bytes.Equal(Window(), PNG(256)) {
		t.Fatal("Window() 应等于 256px 的完整版")
	}
}

// TestCornersTransparent 圆角底板 + 透明边距：四角不透明意味着托盘上是个方块。
func TestCornersTransparent(t *testing.T) {
	for _, raw := range [][]byte{PNG(64), PNG(256), Tray()} {
		img := decode(t, raw)
		b := img.Bounds()
		for _, p := range [][2]int{{b.Min.X, b.Min.Y}, {b.Max.X - 1, b.Min.Y}, {b.Min.X, b.Max.Y - 1}, {b.Max.X - 1, b.Max.Y - 1}} {
			if _, _, _, a := img.At(p[0], p[1]).RGBA(); a != 0 {
				t.Fatalf("角点 (%d,%d) 不透明 (a=%d)", p[0], p[1], a>>8)
			}
		}
	}
}

// TestEdgesAreAntialiased 必须存在半透明像素，否则说明子样本/羽化没生效，
// 缩到 16px 时环的边会呈锯齿。
func TestEdgesAreAntialiased(t *testing.T) {
	img := decode(t, PNG(64))
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a > 1<<12 && a < 1<<15 {
				return
			}
		}
	}
	t.Fatal("整张图只有全透/全不透，抗锯齿没生效")
}

// TestInkCoverage 图形的不透明面积要落在合理区间：
// 太低说明什么都没画出来，太高说明底板糊满整张图。
func TestInkCoverage(t *testing.T) {
	for _, n := range []int{32, 128} {
		img := decode(t, PNG(n))
		b := img.Bounds()
		var opaque int
		for y := b.Min.Y; y < b.Max.Y; y++ {
			for x := b.Min.X; x < b.Max.X; x++ {
				if _, _, _, a := img.At(x, y).RGBA(); a > 1<<15 {
					opaque++
				}
			}
		}
		frac := float64(opaque) / float64(b.Dx()*b.Dy())
		if frac < 0.55 || frac > 0.92 {
			t.Errorf("%dpx 不透明占比 %.2f，底板画得不对", n, frac)
		}
	}
}

// blueEnough 判断一个点是不是"隧道环的蓝"：蓝通道明显压过红通道。
func blueEnough(r, g, b uint32) bool { return b > 150<<8 && b > r+40<<8 }

// TestRingOpensToTheRight 这是整个图形的语义所在：环必须在左侧是实的、
// 右侧是开口的（车道从右边出去）。写成断言是因为"开口画反"在预览里很容易看漏。
//
// 坐标取自 drawFull：环心 (237,256)、半径 140。
func TestRingOpensToTheRight(t *testing.T) {
	img := decode(t, PNG(512))
	r, g, b, a := img.At(97, 256).RGBA() // 237-140：环的左弧正中
	if a>>8 < 250 || !blueEnough(r, g, b) {
		t.Errorf("环左侧应当是蓝色实心，实际 rgba=(%d,%d,%d,%d)", r>>8, g>>8, b>>8, a>>8)
	}
	r, g, b, _ = img.At(377, 256).RGBA() // 237+140：缺口里，只剩深色底板
	if blueEnough(r, g, b) {
		t.Errorf("环右侧是洞口，不该有蓝环，实际 rgb=(%d,%d,%d)", r>>8, g>>8, b>>8)
	}
}

// TestLanesExitTheMouth 两条车道一蓝一绿，都从洞口出发。
// 绿色（直连）只出现在完整版里，是"规则分流"这层含义的唯一载体。
func TestLanesExitTheMouth(t *testing.T) {
	img := decode(t, PNG(512))
	r, g, b, _ := img.At(392, 334).RGBA() // 绿车道末端的圆点
	if g <= 150<<8 || g <= r+60<<8 || g <= b+40<<8 {
		t.Errorf("绿点位置 rgb=(%d,%d,%d)，绿色没画出来", r>>8, g>>8, b>>8)
	}
}

// TestSmallSizesUseMarkGeometry 小尺寸必须换几何：同一坐标点上，
// 简化版是实心环、完整版是细环+分叉，两者不可能逐字节相同。
func TestSmallSizesUseMarkGeometry(t *testing.T) {
	if bytes.Equal(mark(256), PNG(256)) {
		t.Fatal("简化几何和完整版一模一样，说明尺寸分档没生效")
	}
	// 简化版只有一条粗环 + 一支箭头，绿色车道不该出现。
	img := decode(t, mark(256))
	for y := 0; y < 256; y++ {
		for x := 0; x < 256; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			if g > 150<<8 && g > r+60<<8 && g > b+40<<8 {
				t.Fatalf("简化几何里混进了绿色 (%d,%d)，分叉没被去掉", x, y)
			}
		}
	}
}
