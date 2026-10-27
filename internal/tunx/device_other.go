//go:build !linux

package tunx

import tunstack "gvisor.dev/gvisor/pkg/tcpip/stack"

// linkDevice 与 Linux 版本保持一致，方便上层不分平台。
type linkDevice interface {
	tunstack.LinkEndpoint
	Name() string
}

func openLinkDevice(name string, mtu uint32) (linkDevice, error) {
	return nil, ErrUnsupported
}

// deviceFromFD 与 Linux 版本同签名，非 Linux 上 TUN 本来就不支持，
// 保留它是为了让调用方不需要到处写构建标签。
func deviceFromFD(fd int, name string, mtu uint32) (linkDevice, error) {
	return nil, ErrUnsupported
}
