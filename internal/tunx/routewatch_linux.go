//go:build linux

package tunx

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
	"wps_app/internal/logx"
)

// openRouteEvents 订阅链路与 v4/v6 路由变化。
// 打不开就返回 nil，调用方退回定时轮询。返回的通道不会被关闭。
func openRouteEvents(ctx context.Context) <-chan struct{} {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		logx.Warnf("TUN: 打不开 netlink，退回定时看路由: %v", err)
		return nil
	}
	groups := uint32((1 << (unix.RTNLGRP_LINK - 1)) |
		(1 << (unix.RTNLGRP_IPV4_ROUTE - 1)) |
		(1 << (unix.RTNLGRP_IPV6_ROUTE - 1)))
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		_ = unix.Close(fd)
		logx.Warnf("TUN: 绑定路由事件失败，退回定时看路由: %v", err)
		return nil
	}
	ch := make(chan struct{}, 1)
	go func() {
		defer unix.Close(fd)
		buf := make([]byte, 8192)
		for {
			if ctx.Err() != nil {
				return
			}
			_, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
					pf := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
					_, _ = unix.Poll(pf, 1000)
					continue
				}
				if errors.Is(err, unix.ENOBUFS) {
					// 内核把来不及收的事件丢了。当作「有变化」，下一轮用 ip route 对一次。
					signalRoute(ch)
					continue
				}
				if ctx.Err() != nil {
					return
				}
				logx.Debugf("TUN: 读路由事件失败，监视继续靠慢速兜底: %v", err)
				return
			}
			signalRoute(ch)
		}
	}()
	return ch
}

func signalRoute(ch chan<- struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
