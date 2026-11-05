//go:build linux

package metrics

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// DupTCP 复制一条 TCP 连接的文件描述符，供旁路读 TCP_INFO。
//
// 必须在 splice 开始之前做完：splice 进行中再走 syscall.RawConn.Control
// 会等到那次拷贝结束，旁路观察就失去了意义，长传输仍会撞上最初的空闲截止时间。
// 调用方负责关闭返回的 fd。
func DupTCP(c net.Conn) (int, bool) {
	raw, err := RawConn(c)
	if err != nil || raw == nil {
		return -1, false
	}
	var fd int
	var dupErr error
	if err := raw.Control(func(orig uintptr) {
		fd, dupErr = unix.Dup(int(orig))
	}); err != nil || dupErr != nil {
		if fd > 0 {
			_ = unix.Close(fd)
		}
		return -1, false
	}
	return fd, true
}

func bytesSentFD(fd int) (uint64, bool) {
	info, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO)
	if err != nil || info == nil {
		return 0, false
	}
	return info.Bytes_sent, true
}

// WatchTCPWrite 在 stop 关闭之前，每当写出的字节有增长就调用 touch。
// fd 是 DupTCP 拿到的副本；看不出进度就立刻返回。
func WatchTCPWrite(fd int, every time.Duration, touch func(), stop <-chan struct{}) {
	if touch == nil || fd < 0 {
		return
	}
	if every < 50*time.Millisecond {
		every = 50 * time.Millisecond
	}
	last, ok := bytesSentFD(fd)
	if !ok {
		return
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			n, ok := bytesSentFD(fd)
			if !ok {
				return
			}
			if n != last {
				last = n
				touch()
			}
		}
	}
}
