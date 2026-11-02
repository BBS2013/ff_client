//go:build linux

package tunx

import (
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"

	devicetun "github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	tunstack "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// defaultTUNMTU 是 helper 没报回 MTU 时的兜底值（内核给 tun 的默认值也是它）。
const defaultTUNMTU = 1500

// linkDevice 是协议栈要的链路端点。gvisor 的 stack.LinkEndpoint 自带 Close()，
// 所以这里只补一个 Name()，卸载时好把「拆的是哪块网卡」写进日志。
type linkDevice interface {
	tunstack.LinkEndpoint
	Name() string
}

// openLinkDevice 创建（或复用）一块 TUN 网卡。
//
// 这一步就是 TUN 模式的特权门槛：/dev/net/tun 需要可写，
// 建接口需要 CAP_NET_ADMIN。缺权限时错误会原样带出去，
// 由 Start 换成一句人话提示，而不是假装起来了。
func openLinkDevice(name string, mtu uint32) (linkDevice, error) {
	if name == "" {
		return nil, errors.New("tun: 接口名不能为空")
	}
	// devicetun.Open 的返回类型 device.Device 里没有 Close，
	// 但底层 *tun.TUN 一定有（它同时嵌了 stack.LinkEndpoint）。
	// 这里用一次断言把关闭能力拿到手，断言失败时 fd 交给 GC 兜底。
	dev, err := devicetun.Open(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("打开 tun 设备 %s: %w", name, err)
	}
	ld, ok := dev.(linkDevice)
	if !ok {
		return nil, errors.New("tun: 设备未实现 Name()，无法纳管")
	}
	return ld, nil
}

// fdDevice 是「fd 由别人（提权 helper）创建、由本进程使用」的那条路。
//
// 建接口要 CAP_NET_ADMIN，读写它不需要：SCM_RIGHTS 把 fd 交给无权限进程之后，
// 内核照常把包投给它（Android 的 VpnService 就是这么把 tun 交给 app 的）。
// 所以只要 fd 还开着一个，网卡就活着；面板退出时 fd 自动关，接口跟着消失。
type fdDevice struct {
	tunstack.LinkEndpoint
	name string
	fd   int
	// closeOnce 是给第二次调用准备的：协议栈销毁这条链路时自己会调 Close()
	// （非 persistent 的 tun 就是在那一刻消失的），我们随后的那一次只该是空操作。
	// 少了这道闸，第二次 unix.Close 关的是**同一个数字**——
	// 而它可能已经被进程里另一处 open 拿去了，那种坏法排查起来完全没有方向。
	closeOnce sync.Once
}

func (d *fdDevice) Name() string { return d.name }

func (d *fdDevice) Close() {
	d.closeOnce.Do(func() {
		d.LinkEndpoint.Close()
		_ = unix.Close(d.fd)
	})
}

// deviceFromFD 用 helper 交来的 fd 构造链路端点。
//
// 参数必须与 devicetun.Open 内部完全一致（裸 IP 包、Readv 分发、不预留系统调用头），
// 否则协议栈会把 tun 头当载荷读，表现是「一条都通但全是乱码」这种最难查的故障。
// mtu 用内核上的真实值，不是配置里想要的那个——配置改不动已经被别的进程设过的 MTU。
func deviceFromFD(fd int, name string, mtu uint32) (linkDevice, error) {
	if fd < 0 {
		return nil, errors.New("tun: 没有拿到设备 fd")
	}
	if name == "" {
		name = "tun"
	}
	if mtu == 0 {
		mtu = defaultTUNMTU
	}
	ep, err := fdbased.New(&fdbased.Options{
		FDs:                   []int{fd},
		MTU:                   mtu,
		EthernetHeader:        false,
		PacketDispatchMode:    fdbased.Readv,
		MaxSyscallHeaderBytes: 0x00,
	})
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("用 fd %d 建 tun 端点: %w", fd, err)
	}
	return &fdDevice{LinkEndpoint: ep, name: name, fd: fd}, nil
}
