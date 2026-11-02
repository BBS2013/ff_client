//go:build !linux

package service

import "net"

// boundDevice 在非 Linux 上恒为空：SO_BINDTODEVICE 是 Linux 的东西，
// 别的平台上本来就没有"把某条 socket 钉到某张网卡"这回事，
// 界面那一格也就退化成只报源地址（或不报）。
func boundDevice(conn net.Conn) string { return "" }
