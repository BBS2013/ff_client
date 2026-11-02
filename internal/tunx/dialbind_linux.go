//go:build linux

package tunx

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// 这个文件只做一件事：以 root 造一条**钉在指定网卡上、且已连通**的 TCP socket，
// 把 fd 交给面板（SCM_RIGHTS，与 up 交回 tun fd 同一条通道）。
//
// 为什么值得为它开一个新动作：`SO_BINDTODEVICE` 在这类装了链路安全软件的机器上，
// 对普通进程是「setsockopt 返回成功、包一个都上不了线」——2026-10-29 实测
// uid 1000 绑 wlx/wlp 都超时，加上 ambient CAP_NET_RAW 仍然超时，只有 uid 0 出得去。
// 那时的界面敢写「代理钉在 wlx」，症状却是全部代理连接一起超时。
// 面板不因此改成 root 跑（那会丢托盘与桌面代理控制），而是把这一步交给已有的 helper。

// checkBindDev 认接口名。用的是与网卡那套同一个判据（validIfaceName），
// 不在这儿再写一遍"什么算合法名字"——两处各写一份迟早会不一样。
func checkBindDev(dev string) error {
	if !validIfaceName(dev) {
		return fmt.Errorf("dialbind 的接口名不合法: %q", dev)
	}
	return nil
}

// checkBindTarget 校验「要连的地址」。
//
// 三条硬规矩，都是把这条通道能做的事收窄：
// ① 必须是**已解析的 ip:port 字面量**——helper 里不许解析域名（故障现场重解析会拿到
// 假 IP，把出口拨到自己家，这一条与 kill 的 Allow 同源）；
// ② 不许是环回、链路本地、组播或未指定地址——这张通道是给"出网的节点连接"用的，
// 不是给本地服务当跳板的；
// ③ 必须出现在调用方给的名单里。
// 名单这一条要说实话：它**防的是面板自己的 bug**，不是防攻击者——配置文件本来就归
// 这个用户，他想加一个端点随时加得动。它挡住的是"以后某个代码路径把用户在界面上
// 输入的地址顺手交给 helper 去连"那种错，那种错会把 root 变成任意地址的连接者。
func checkBindTarget(addr string, allow []string) (netip.Addr, uint16, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("dialbind 的目标要写成 ip:port，得到 %q: %w", addr, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("dialbind 只接受已解析的 IP 字面量，%q 不是 IP"+
			"（域名请在面板那侧解析后再送来）", host)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return netip.Addr{}, 0, fmt.Errorf("dialbind 的端口不合法: %q", portStr)
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return netip.Addr{}, 0, fmt.Errorf("dialbind 拒绝连到 %s（这条通道只用于出网的节点端点）", ip)
	}
	want := net.JoinHostPort(ip.String(), fmt.Sprint(p))
	for _, a := range allow {
		if strings.TrimSpace(a) == want {
			return ip, uint16(p), nil
		}
	}
	return netip.Addr{}, 0, fmt.Errorf("dialbind 的目标 %s 不在请求给出的节点端点名单里（%d 条）",
		want, len(allow))
}

// dialBound 造 socket、钉到 dev、连到 addr，成功时返回 fd（调用方负责传出去或关掉）。
//
// 全程非阻塞 + poll：helper 是一个几十毫秒生命周期的进程，绝不能在任何一次系统调用上
// 无限期停住（那会把面板的整个提权通道拖死）。
func dialBound(dev, addr string, allow []string, budget time.Duration) (int, error) {
	if err := checkBindDev(dev); err != nil {
		return -1, err
	}
	ip, port, err := checkBindTarget(addr, allow)
	if err != nil {
		return -1, err
	}
	if budget <= 0 {
		return -1, fmt.Errorf("dialbind 的时间预算是 %v，不给拨号", budget)
	}

	family, sa, err := sockaddrFor(ip, port)
	if err != nil {
		return -1, err
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("建 socket 失败: %w", err)
	}
	fail := func(reason string, e error) (int, error) {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%s: %w", reason, e)
	}
	// root 才有资格问「这张卡是不是真的有网卡」，这里就顺势问一次：
	// 卡不在就别钉了，否则错误会以「连不上」的形式出现在一个谁也猜不到原因的地方。
	if _, err := net.InterfaceByName(dev); err != nil {
		return fail(fmt.Sprintf("网卡 %s 不在", dev), err)
	}
	if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, dev); err != nil {
		return fail(fmt.Sprintf("钉到 %s 失败", dev), err)
	}
	if err := unix.Connect(fd, sa); err != nil && !errors.Is(err, unix.EINPROGRESS) {
		return fail(fmt.Sprintf("连 %s 失败", addr), err)
	}
	// 非阻塞 connect 的结果要用一次 POLLOUT + SO_ERROR 才读得出来。
	deadline := time.Now().Add(budget)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return fail(fmt.Sprintf("连 %s 超时（钉在 %s 上发不出包？）", addr, dev), unix.ETIMEDOUT)
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, perr := unix.Poll(pfd, int(left.Milliseconds())+1)
		if perr != nil {
			if errors.Is(perr, unix.EINTR) {
				continue
			}
			return fail("等待连接结果失败", perr)
		}
		if n == 0 {
			continue // 还剩一点余量就再问一次；总预算花完时上面那条 left<=0 会收尾
		}
		if pfd[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return fail(fmt.Sprintf("连 %s 失败", addr), unix.ECONNREFUSED)
		}
		if pfd[0].Revents&unix.POLLOUT == 0 {
			continue
		}
		e, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return fail("读连接结果失败", err)
		}
		if e != 0 {
			return fail(fmt.Sprintf("连 %s 失败", addr), unix.Errno(e))
		}
		// 交出去之前把非阻塞清掉：对面要用 net.FileConn 接管这条 fd，而它要求是阻塞
		// socket；O_NONBLOCK 挂在共享的 open file description 上，dup 到对面还是非阻塞，
		// 那时 FileConn 会当场拒收——症状是"helper 明明回了 fd，面板却用不了"。
		if err := unix.SetNonblock(fd, false); err != nil {
			return fail("把 socket 调回阻塞模式失败", err)
		}
		return fd, nil
	}
}

// sockaddrFor 按地址族拼 connect 用的 sockaddr。
func sockaddrFor(ip netip.Addr, port uint16) (int, unix.Sockaddr, error) {
	a := ip.WithZone("") // 链路本地地址的 zone 在这里没有意义：我们已经拒绝链路本地地址了
	if a.Is4() {
		sa := &unix.SockaddrInet4{Port: int(port)}
		copy(sa.Addr[:], a.AsSlice())
		return unix.AF_INET, sa, nil
	}
	if a.Is6() {
		sa := &unix.SockaddrInet6{Port: int(port)}
		copy(sa.Addr[:], a.AsSlice())
		return unix.AF_INET6, sa, nil
	}
	return 0, nil, fmt.Errorf("不支持的地址族: %s", ip)
}

// doDialBind 是 ServeConn 的 dialbind 分支。
// 成功时把 fd 随应答交出去；失败时一个 fd 都不留（没人认领的 fd 是一个还活着的内核引用）。
func (h *HelperServer) doDialBind(req HelperRequest, budget time.Duration) (HelperReply, int, error) {
	fd, err := dialBound(req.BindDev, req.BindAddr, req.BindAllow, budget)
	if err != nil {
		return HelperReply{OK: false, Err: err.Error()}, -1, nil
	}
	return HelperReply{
		OK:      true,
		Applied: []string{fmt.Sprintf("已连 %s（钉在 %s）", req.BindAddr, req.BindDev)},
	}, fd, nil
}
