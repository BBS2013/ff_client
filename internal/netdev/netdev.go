// Package netdev 探测本机的无线网卡，并按「内置」与「USB」分类。
//
// 分类只依据一件事：网卡的 sysfs 设备路径里有没有 usb 这一段。
// 它够用是因为两类网卡的驱动路径天然不同——内置的 PCI 设备挂在 pci0000:00/... 下，
// 而插在 USB 口上的无线网卡一定挂在某个 usbN/N-M 之下。
//
// 已知的一处误判：某些笔记本的无线模块（CNVi 一类）本身就走 USB 控制器，
// 会被算成 USB 无线。这类机器上两张卡的用途通常一样，分错也没有实际后果。
package netdev

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// sysClassNet 是读网卡 sysfs 的根目录。做成变量是为了让单测指向一棵假树。
var sysClassNet = "/sys/class/net"

// ifacer 是探测需要的全部接口信息。抽成接口是为了让单测不必真的去建网卡，
// 而接口状态与 sysfs 目录是两件独立的事，各自替换。
type ifacer interface {
	// Up 报告接口是否已启用。
	Up(name string) bool
	// Addrs 返回接口上除回环与链路本地之外的地址。
	Addrs(name string) []string
}

// Wireless 是一张可用的无线网卡。
type Wireless struct {
	// Name 是接口名（wlp3s0f0 之类）。绑定网卡认的是它，不是 MAC。
	Name string
	// USB 标记这张卡是不是插在 USB 口上的。
	USB bool
	// Addrs 是它当前拿到的、可路由的地址。列出来是为了让界面能说清
	// 「它到底有几条可用的地址」，而不只是报一个接口名。
	Addrs []string
}

// Set 是本机无线网卡的分类结果。
type Set struct {
	Builtin []Wireless
	USB     []Wireless
}

// Detect 列出本机可用的无线网卡，按内置 / USB 分类。
func Detect() Set {
	return detect(sysClassNet, netIfacer{})
}

// Picks 给出「两张都在时各该用哪张」的建议。
//
// 只有两张都存在才给得出建议：只有一张时把全部流量钉到它上面没有任何好处，
// 那还不如交给系统按路由表走——见 Config.IfaceSplit 的说明。
func (s Set) Picks() (direct, proxy Wireless, ok bool) {
	if len(s.Builtin) == 0 || len(s.USB) == 0 {
		return Wireless{}, Wireless{}, false
	}
	return s.Builtin[0], s.USB[0], true
}

// Choice 是某一侧点名要用的那张卡。
type Choice struct {
	// Dev 是接口名，留空表示这一侧不点名。
	Dev string
	// USB 是 Dev 那张卡属于哪一类。理由见 config.IfaceCard 的同名字段。
	USB bool
}

// Resolve 按用户点名的两张卡给出结果，没点名的按各自的默认类别自动挑：
// 直连默认内置、代理默认 USB——这个默认分工是本包的一部分而不是调用方的巧合。
//
// 撞到同一张卡时先让「没点名的那一侧」去另一类里找：点名「直连走 USB 卡」是很自然的一件事，
// 而代理那侧的默认也正好在 USB 上，程序该自己让开，而不是把用户推进"彻底不分流"的死胡同。
// 两边都点名了同一张才是无从让开的情形，那时只收代理那一侧并说明理由。
//
// why 是「为什么没挑到 / 挑到的不是点名那张」的说明，空串表示一切照默认来。
// 挑不到的那一侧返回空 Wireless，调用方据此退回系统默认路由。
func (s Set) Resolve(direct, proxy Choice) (d, p Wireless, why string) {
	d, dWhy := s.pick(direct, s.Builtin)
	p, pWhy := s.pick(proxy, s.USB)
	if d.Name != "" && d.Name == p.Name {
		if direct.Dev == "" {
			d, dWhy = s.pick(direct, s.USB)
		}
		if d.Name != "" && d.Name == p.Name && proxy.Dev == "" {
			p, pWhy = s.pick(proxy, s.Builtin)
		}
	}
	if d.Name != "" && d.Name == p.Name {
		// 两边点名同一张卡：钉在同一张上与压根不钉是一回事，
		// 却会把「另一张卡还在、还能分流」这件事一起关掉。
		// 这是用户能犯而程序不该默默执行的错，所以只收代理这一侧。
		p = Wireless{}
		pWhy = fmt.Sprintf("直连与代理点名了同一张卡 %s：代理这一侧退回系统默认路由", d.Name)
	}
	return d, p, joinWhy(dWhy, pWhy)
}

// pick 挑出一侧那张卡，def 是这一侧不点名时的默认类别。
//
// 点名的名字还在就直接用它（用户比探测清楚）；不在了就按它**原来的类别**顶上同类那一张，
// 这正是「拔掉 USB 卡再插一张新的」能被接住的地方。同一类一张都没有时返回空，
// 让上层退回系统路由——钉在一张已经不存在的卡上，那是最坏的失败方式。
func (s Set) pick(c Choice, def []Wireless) (Wireless, string) {
	if c.Dev != "" {
		if w, ok := s.find(c.Dev); ok {
			return w, ""
		}
	}
	if len(def) == 0 {
		if c.Dev == "" {
			return Wireless{}, ""
		}
		return Wireless{}, fmt.Sprintf("点名的 %s 已经不在了，同类也没有别的卡", c.Dev)
	}
	if c.Dev != "" {
		return def[0], fmt.Sprintf("点名的 %s 已经不在了，改用同类的 %s", c.Dev, def[0].Name)
	}
	return def[0], ""
}

func (s Set) find(name string) (Wireless, bool) {
	for _, list := range [][]Wireless{s.Builtin, s.USB} {
		for _, w := range list {
			if w.Name == name {
				return w, true
			}
		}
	}
	return Wireless{}, false
}

// joinWhy 把两侧的理由合成一句：两侧都有话说的时候只报代理那侧，
// 因为代理那侧不顶用才真的会让流量走错路，直连那侧退不退回都能通。
func joinWhy(direct, proxy string) string {
	if proxy != "" {
		return proxy
	}
	return direct
}

// All 返回全部可用的无线卡，先内置后 USB，供界面列成下拉项。
func (s Set) All() []Wireless {
	out := make([]Wireless, 0, len(s.Builtin)+len(s.USB))
	return append(append(out, s.Builtin...), s.USB...)
}

func detect(root string, ifc ifacer) Set {
	entries, err := os.ReadDir(root)
	if err != nil {
		// 读不到 sysfs 不是错误：没有网卡信息就等于没有分流可言，
		// 上层会照常按原样分发，只是不再提这件事。
		return Set{}
	}
	var set Set
	for _, e := range entries {
		name := e.Name()
		if !isWireless(root, name) {
			continue
		}
		if !ifc.Up(name) {
			continue
		}
		addrs := ifc.Addrs(name)
		if len(addrs) == 0 {
			// 起来了却一个可路由地址都没有（还没拿到 DHCP），
			// 钉上去的结果只是把连接全部拨失败，不如照常走系统路由。
			continue
		}
		w := Wireless{Name: name, USB: isUSB(root, name), Addrs: addrs}
		if w.USB {
			set.USB = append(set.USB, w)
		} else {
			set.Builtin = append(set.Builtin, w)
		}
	}
	// 同一类里有多张时按名字定序，避免每次启动挑到的那张不一样——
	// 那会让「分流到底走了哪张卡」变得没法复述。
	sort.Slice(set.Builtin, func(i, j int) bool { return set.Builtin[i].Name < set.Builtin[j].Name })
	sort.Slice(set.USB, func(i, j int) bool { return set.USB[i].Name < set.USB[j].Name })
	return set
}

// isWireless 判断这张卡是不是无线。
//
// phy80211 是 mac80211/cfg80211 驱动留下的软链接，wireless 是老式驱动留下的目录；
// 两者都有 / 两者都无的组合只在非无线网卡上出现（有线口不会有其中任何一个）。
func isWireless(root, name string) bool {
	for _, marker := range []string{"phy80211", "wireless"} {
		if _, err := os.Stat(filepath.Join(root, name, marker)); err == nil {
			return true
		}
	}
	return false
}

// isUSB 判断这张卡是不是挂在 USB 控制器下面。
func isUSB(root, name string) bool {
	// 必须把整条链解完，不能直接读链接字面量：/sys/class/net/<网卡> 本身也是软链接，
	// device 指向的是相对它的短路径（../../../1-1），光看那串字面量里永远没有 usb1。
	dest, err := filepath.EvalSymlinks(filepath.Join(root, name, "device"))
	if err != nil {
		return false
	}
	// 只认路径分段，且分段必须形如 usb1/usb2：内建的总线目录就是这样命名的。
	// 光判前缀会把 usbfoo 这类同名目录也算进来，而那不是 USB 控制器。
	for _, seg := range strings.Split(dest, "/") {
		if isUSBBus(seg) {
			return true
		}
	}
	return false
}

// isUSBBus 判断一个路径分段是不是 USB 总线目录（usb 开头、后面全是数字）。
func isUSBBus(seg string) bool {
	rest, ok := strings.CutPrefix(seg, "usb")
	if !ok || rest == "" {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// netIfacer 走内核给的真实接口状态。
type netIfacer struct{}

func (netIfacer) Up(name string) bool {
	iface, err := net.InterfaceByName(name)
	return err == nil && iface.Flags&net.FlagUp != 0
}

func (netIfacer) Addrs(name string) []string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	list, err := iface.Addrs()
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, a := range list {
		ip := addrIP(a)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}

// addrIP 从接口地址里取出 IP，剥掉前缀长度。
func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

// Describe 给出给人看的一行摘要，供日志与面板使用。
func (s Set) Describe() string {
	return fmt.Sprintf("内置无线 %s，USB 无线 %s", names(s.Builtin), names(s.USB))
}

// Kind 给出这张卡的中文类别，供下拉项与日志复用同一份说法。
func (w Wireless) Kind() string {
	if w.USB {
		return "USB 无线"
	}
	return "内置无线"
}

func names(ws []Wireless) string {
	if len(ws) == 0 {
		return "（无）"
	}
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Name)
	}
	return strings.Join(out, "、")
}
