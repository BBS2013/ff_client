//go:build linux

package tunx

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestDialHelperRefusesEverythingButDialBind 是提权边界上最要紧的一条。
//
// 常驻 dial-helper 的套接字在用户自己的运行目录里：同 uid 的任何进程都连得上，
// 也能算出正确的 uid 通过 SO_PEERCRED。如果它复用完整的 serveRequest，
// 那么一个同 uid 的普通进程就能要求 root：
//
//   - 装一条默认路由（ActionUp / ActionReroute）
//   - 把本机 :53 全部 DNAT 到任意地址（ActionUp 里的劫持）
//   - 挂一条 DROP 全站的链（ActionKill）
//
// 而它本来只需要一件事：替我要一条钉在指定网卡上、已连通的 socket。
//
// 这条用例把请求直接喂给 helper（走真实协议），断言除 dialbind 之外统统被拒。
func TestDialHelperRefusesEverythingButDialBind(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "s")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = RunDialHelper(ctx, sock, os.Getuid()) }()

	waitSock(t, sock)
	conn := dialUnix(t, sock)

	cases := []struct {
		action string
		label  string
	}{
		{ActionUp, "开 tun 网卡 / 装默认路由 / DNAT :53"},
		{ActionDown, "拆网卡"},
		{ActionCleanup, "扫 iptables 残留"},
		{ActionReroute, "重钉绕行路由"},
		{ActionKill, "挂/摘断网保护"},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			req := HelperRequest{V: helperProtoVersion, Action: tc.action}
			req.Plan = RoutePlan{
				Device:      "wps-tun",
				Address:     "172.19.0.1/30",
				MTU:         1500,
				UID:         os.Getuid(),
				FakeIPRange: "198.18.0.0/15",
			}
			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatalf("连 helper: %v", err)
			}
			defer c.Close()
			payload, err := encodeRequest(req)
			if err != nil {
				t.Fatalf("编码请求: %v", err)
			}
			if err := writeFrame(c.(*net.UnixConn), payload); err != nil {
				t.Fatalf("发请求: %v", err)
			}
			reply, fds, err := readReplyWithFDs(c.(*net.UnixConn))
			closeAll(fds)
			if err != nil {
				t.Fatalf("读应答: %v", err)
			}
			if reply.OK {
				t.Fatalf("常驻 helper 接受了 %s（%s）——同 uid 的进程能借此拿到 root 能力",
					tc.action, tc.label)
			}
			if !strings.Contains(reply.Err, string(ActionDialBind)) {
				t.Errorf("拒绝理由没点名允许的动作: %q", reply.Err)
			}
		})
	}
	_ = conn
}

// TestSecureSocketDirRejectsSymlink 锁住"root 不在符号链接后面建套接字"。
//
// 攻击形状：面板把路径定在 /tmp/x/s，其中 /tmp/x 是可预测的名字。
// 同 uid 的进程抢在 root bind 之前把 /tmp/x 换成指向别处的符号链接，
// root 就会把套接字建到它挑的位置，紧接着的 Chown 还会把那个位置交给他。
func TestSecureSocketDirRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := secureSocketDir(link, os.Getuid()); err == nil {
		t.Fatal("符号链接目录被接受了：root 会把套接字建到攻击者挑的位置")
	}
	// 正常目录必须放行，否则这条修复会把功能一起关掉。
	ok := filepath.Join(base, "ok")
	if err := secureSocketDir(ok, os.Getuid()); err != nil {
		t.Fatalf("正常目录被拒了: %v", err)
	}
	// 权限必须被收紧到 0700。
	st, err := os.Stat(ok)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Fatalf("目录权限 = %o, want 0700", st.Mode().Perm())
	}
}

func waitSock(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("套接字 %s 没出现", path)
}

func dialUnix(t *testing.T, path string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("连 %s: %v", path, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

var _ = binary.BigEndian
var _ = unix.Geteuid
