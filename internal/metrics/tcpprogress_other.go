//go:build !linux

package metrics

import (
	"net"
	"time"
)

// DupTCP 在非 Linux 上没有这条旁路。
func DupTCP(net.Conn) (int, bool) { return -1, false }

// WatchTCPWrite 在非 Linux 上没有 TCP_INFO。
func WatchTCPWrite(int, time.Duration, func(), <-chan struct{}) {}
