package netdev

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeIfacer 是不碰真网卡的接口状态表。
type fakeIfacer struct {
	up    map[string]bool
	addrs map[string][]string
}

func (f fakeIfacer) Up(name string) bool { return f.up[name] }

func (f fakeIfacer) Addrs(name string) []string { return f.addrs[name] }

// fakeSysfs 造一棵 /sys/class/net 的假树，形状照抄真机：
//
//	<root>/<网卡>            -> 软链接到 <设备路径>/net/<网卡>
//	<设备路径>/net/<网卡>/phy80211   无线卡才有
//	<设备路径>/net/<网卡>/device     -> 相对软链接 ../../../<设备名>
//
// device 写成相对链接是刻意的：真机就是这么给的，只把假树写成绝对路径的话，
// 相对链接解不开这件事根本测不出来（第一版就是这么漏过去的）。
func fakeSysfs(t *testing.T, devs map[string]struct {
	wireless bool
	usb      bool
}) string {
	t.Helper()
	tmp := t.TempDir()
	root := filepath.Join(tmp, "class", "net")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, d := range devs {
		bus := filepath.Join(tmp, "devices", "pci0000:00", "0000:00:14.0")
		if !d.usb {
			bus = filepath.Join(tmp, "devices", "pci0000:00", "0000:00:1c.0")
		}
		devPath := filepath.Join(bus, "0000:03:00.0")
		if d.usb {
			devPath = filepath.Join(bus, "usb1", "1-1")
		}
		netDir := filepath.Join(devPath, "net", name)
		if err := os.MkdirAll(netDir, 0o755); err != nil {
			t.Fatalf("MkdirAll(%s): %v", netDir, err)
		}
		if d.wireless {
			if err := os.MkdirAll(filepath.Join(netDir, "phy80211"), 0o755); err != nil {
				t.Fatalf("MkdirAll: %v", err)
			}
		}
		rel := "../../../" + filepath.Base(devPath)
		if err := os.Symlink(rel, filepath.Join(netDir, "device")); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
		if err := os.Symlink(netDir, filepath.Join(root, name)); err != nil {
			t.Fatalf("Symlink: %v", err)
		}
	}
	return root
}

func bothUp(addrs ...string) fakeIfacer {
	up := map[string]bool{}
	a := map[string][]string{}
	for _, n := range []string{"wlp3s0f0", "wlx001f0578cdff"} {
		up[n] = true
		a[n] = addrs
	}
	return fakeIfacer{up: up, addrs: a}
}

// 内置走 PCI、USB 走 usb1，两张都要 UP 且有地址——这时才给得出「各走哪张」。
func TestDetectClassifiesBuiltinAndUSB(t *testing.T) {
	root := fakeSysfs(t, map[string]struct {
		wireless bool
		usb      bool
	}{
		"wlp3s0f0":        {wireless: true, usb: false},
		"wlx001f0578cdff": {wireless: true, usb: true},
		"eno1":            {wireless: false, usb: false},
	})

	set := detect(root, bothUp("10.0.0.5"))

	if len(set.Builtin) != 1 || set.Builtin[0].Name != "wlp3s0f0" {
		t.Fatalf("内置无线应只有 wlp3s0f0，得到 %+v", set.Builtin)
	}
	if len(set.USB) != 1 || set.USB[0].Name != "wlx001f0578cdff" {
		t.Fatalf("USB 无线应只有 wlx001f0578cdff，得到 %+v", set.USB)
	}
	d, p, ok := set.Picks()
	if !ok || d.Name != "wlp3s0f0" || p.Name != "wlx001f0578cdff" {
		t.Fatalf("Picks = %v,%v,%v；直连该拿内置、代理该拿 USB", d.Name, p.Name, ok)
	}
}

// 有线口不算无线：它既没有 phy80211，也没有 wireless 标记。
func TestDetectIgnoresWired(t *testing.T) {
	root := fakeSysfs(t, map[string]struct {
		wireless bool
		usb      bool
	}{
		"wlx001f0578cdff": {wireless: true, usb: true},
		"eno1":            {wireless: false, usb: false},
		"docker0":         {wireless: false, usb: false},
	})

	set := detect(root, bothUp("192.168.0.1"))

	if len(set.Builtin) != 0 {
		t.Fatalf("有线口不该被算成内置无线: %+v", set.Builtin)
	}
	if _, _, ok := set.Picks(); ok {
		t.Fatal("只有一张无线时不该给得出分流建议")
	}
}

// 只找到一张时必须照常分发——把全部流量钉到唯一那张卡上没有任何好处。
func TestPicksNeedsBoth(t *testing.T) {
	root := fakeSysfs(t, map[string]struct {
		wireless bool
		usb      bool
	}{
		"wlp3s0f0": {wireless: true, usb: false},
	})
	set := detect(root, bothUp("10.0.0.5"))

	if _, _, ok := set.Picks(); ok {
		t.Fatalf("只有内置一张时不该分流，得到 %+v", set)
	}
}

// 起来了却一个可路由地址都没有（还没拿到 DHCP）时不算数。
func TestDetectSkipsInterfaceWithoutAddress(t *testing.T) {
	root := fakeSysfs(t, map[string]struct {
		wireless bool
		usb      bool
	}{
		"wlp3s0f0":        {wireless: true, usb: false},
		"wlx001f0578cdff": {wireless: true, usb: true},
	})
	ifc := fakeIfacer{
		up:    map[string]bool{"wlp3s0f0": true, "wlx001f0578cdff": true},
		addrs: map[string][]string{"wlp3s0f0": {"10.0.0.5"}},
	}

	set := detect(root, ifc)

	if len(set.USB) != 0 {
		t.Fatalf("没有地址的网卡不该被选中: %+v", set.USB)
	}
	if _, _, ok := set.Picks(); ok {
		t.Fatal("少一张可用网卡时不该给得出分流建议")
	}
}

// 同一类里有多张时按名字定序，避免每次启动挑到的不是同一张。
func TestDetectIsDeterministic(t *testing.T) {
	root := fakeSysfs(t, map[string]struct {
		wireless bool
		usb      bool
	}{
		"wlx2": {wireless: true, usb: true},
		"wlx1": {wireless: true, usb: true},
	})
	ifc := fakeIfacer{
		up:    map[string]bool{"wlx1": true, "wlx2": true},
		addrs: map[string][]string{"wlx1": {"192.168.0.2"}, "wlx2": {"192.168.0.3"}},
	}

	set := detect(root, ifc)

	if len(set.USB) != 2 || set.USB[0].Name != "wlx1" || set.USB[1].Name != "wlx2" {
		t.Fatalf("同类网卡应按名字定序，得到 %+v", set.USB)
	}
}

// 读不到 sysfs 不该让整个进程起不来：没网卡信息等于不分流。
func TestDetectOnMissingSysfs(t *testing.T) {
	set := detect(filepath.Join(t.TempDir(), "没有这个目录"), bothUp("10.0.0.5"))

	if len(set.Builtin) != 0 || len(set.USB) != 0 {
		t.Fatalf("sysfs 读不到时应返回空集合，得到 %+v", set)
	}
}

// 「内置」按 sysfs 设备路径里有没有 usb 分段判定，不能是子串匹配。
func TestIsUSBNeedsPathSegment(t *testing.T) {
	root := fakeSysfs(t, map[string]struct {
		wireless bool
		usb      bool
	}{
		"wlan0": {wireless: true, usb: false},
	})
	// 造一条名字里带 usb、但分段本身不是 usb 的路径。
	dir := filepath.Join(root, "wlan9")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(filepath.Dir(root), "usbfoo")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "device")); err != nil {
		t.Fatal(err)
	}

	if isUSB(root, "wlan9") {
		t.Fatal("usbfoo 不是 usb 控制器的分段，不该判成 USB 设备")
	}
	if isUSB(root, "wlan0") {
		t.Fatal("PCI 路径不该判成 USB 设备")
	}
}

// 两张卡都在且都没点名：直连拿内置、代理拿 USB。
// 这一条盯住的是"默认类别分两侧"——默认若跟着直连侧走，
// 两边就会挑到同一张卡上，而外面只看到"没分流"，看不出是这个原因。
func TestResolveDefaultsToBuiltinDirectAndUSBProxy(t *testing.T) {
	set := Set{
		Builtin: []Wireless{{Name: "wlp3s0f0"}},
		USB:     []Wireless{{Name: "wlx001f0578cdff", USB: true}},
	}
	d, p, why := set.Resolve(Choice{}, Choice{})
	if d.Name != "wlp3s0f0" || p.Name != "wlx001f0578cdff" {
		t.Fatalf("默认分工错了: 直连 %q，代理 %q（%s）", d.Name, p.Name, why)
	}
	if why != "" {
		t.Errorf("一切照默认时不该有解释: %q", why)
	}
}

// 点名那张不在了，按它原来的类别顶上同类的那张，并把这件事说出来。
func TestResolveFallsBackWithinTheSameClass(t *testing.T) {
	set := Set{
		Builtin: []Wireless{{Name: "wlp3s0f0"}},
		USB:     []Wireless{{Name: "wlx001f0578cdfe", USB: true}},
	}
	d, p, why := set.Resolve(Choice{}, Choice{Dev: "wlx001f0578cdff", USB: true})
	if p.Name != "wlx001f0578cdfe" {
		t.Fatalf("该顶上同类的那张，得到 %q", p.Name)
	}
	if d.Name != "wlp3s0f0" {
		t.Errorf("直连侧不该跟着变，得到 %q", d.Name)
	}
	if !strings.Contains(why, "wlx001f0578cdfe") {
		t.Errorf("换了哪一张必须说出来: %q", why)
	}
}

// 点名的卡没了、那一类一张都不剩：这一侧空着，退回系统默认路由。
func TestResolveEmptyWhenTheNamedClassIsGone(t *testing.T) {
	set := Set{Builtin: []Wireless{{Name: "wlp3s0f0"}}}
	_, p, why := set.Resolve(Choice{}, Choice{Dev: "wlx001f0578cdff", USB: true})
	if p.Name != "" {
		t.Fatalf("那一类一张都不剩时该退回默认路由，得到 %q", p.Name)
	}
	if why == "" {
		t.Error("退回默认路由这件事必须说给上层听")
	}
}

// 两边点名同一张卡：收掉代理那一侧。
// 钉在同一张上与压根不钉是一回事，却会把「另一张卡还能分流」一起关掉。
func TestResolveRejectsTheSameCardOnBothSides(t *testing.T) {
	set := Set{
		Builtin: []Wireless{{Name: "wlp3s0f0"}},
		USB:     []Wireless{{Name: "wlx001f0578cdff", USB: true}},
	}
	d, p, why := set.Resolve(Choice{Dev: "wlp3s0f0"}, Choice{Dev: "wlp3s0f0"})
	if p.Name != "" {
		t.Errorf("撞车时该只收代理那一侧，得到 %q", p.Name)
	}
	if d.Name != "wlp3s0f0" {
		t.Errorf("直连那一侧不该跟着收掉，得到 %q", d.Name)
	}
	if !strings.Contains(why, "同一张卡") {
		t.Errorf("理由里要点破是撞车，得到 %q", why)
	}
}

// All 要先内置后 USB 且次序稳定：下拉里两张卡的先后不能每次启动都换。
func TestAllIsStableAndBuiltinsFirst(t *testing.T) {
	set := Set{
		Builtin: []Wireless{{Name: "wlan0"}, {Name: "wlp3s0f0"}},
		USB:     []Wireless{{Name: "wlx001f0578cdff", USB: true}},
	}
	got := set.All()
	if len(got) != 3 || got[0].Name != "wlan0" || got[1].Name != "wlp3s0f0" || got[2].Name != "wlx001f0578cdff" {
		t.Fatalf("次序不对: %+v", got)
	}
	if got[2].Kind() != "USB 无线" || got[0].Kind() != "内置无线" {
		t.Errorf("类别说法不对: %q / %q", got[0].Kind(), got[2].Kind())
	}
}

// 点名「直连走 USB 卡」时，代理那侧的默认也正好在 USB 上——
// 程序该让没点名的那一侧去另一类里找，而不是给出一个"彻底不分流"的死胡同。
func TestResolveUnnamedSideYieldsOnCollision(t *testing.T) {
	set := Set{
		Builtin: []Wireless{{Name: "wlp3s0f0"}},
		USB:     []Wireless{{Name: "wlx001f0578cdff", USB: true}},
	}
	d, p, why := set.Resolve(Choice{Dev: "wlx001f0578cdff", USB: true}, Choice{})
	if d.Name != "wlx001f0578cdff" {
		t.Fatalf("点名的直连卡不该动，得到 %q", d.Name)
	}
	if p.Name != "wlp3s0f0" {
		t.Errorf("没点名的代理侧该让到另一类，得到 %q", p.Name)
	}
	if why != "" {
		t.Errorf("让开是正常行为，不该报成理由: %q", why)
	}
}

// 让开的方向也要对称：点名代理走内置时，没点名的直连侧让到 USB 那张。
func TestResolveUnnamedDirectYieldsOnCollision(t *testing.T) {
	set := Set{
		Builtin: []Wireless{{Name: "wlp3s0f0"}},
		USB:     []Wireless{{Name: "wlx001f0578cdff", USB: true}},
	}
	d, p, _ := set.Resolve(Choice{}, Choice{Dev: "wlp3s0f0"})
	if p.Name != "wlp3s0f0" {
		t.Fatalf("点名的代理卡不该动，得到 %q", p.Name)
	}
	if d.Name != "wlx001f0578cdff" {
		t.Errorf("没点名的直连侧该让到另一类，得到 %q", d.Name)
	}
}
