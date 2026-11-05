//go:build linux

package tunx

import (
	"net"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestReplyDoesNotLeakFDs 锁住「fd 交出去之后本进程不再持有它」。
//
// 这是常驻 dial-helper 里最隐蔽的一处泄漏：一次性的 tun-helper 进程马上退出，
// 漏掉的 fd 随进程消失；常驻进程则每建一条分流连接就漏一个，直到 RLIMIT_NOFILE
// 用尽、之后所有钉网卡的拨号全部失败，而唯一的解法是重启面板。
//
// 更糟的是"关不掉"这一层：同一个 socket 的 fd 传给对端后，内核里是两个独立引用。
// 面板侧 Close() 只释放它那一个；root 侧这份不关，socket 就一直活着，
// 连接永远不断——面板明明关了连接，对端还看得见一个不发数据的连接。
//
// 判据必须落在**fd 总数**上，不能看某个具体编号：本地那份关掉之后，
// 接收端拿到的那个 fd 会立刻复用同一个号（同进程内测试尤其必然），
// 于是"这个号还有效吗"永远为真，测的是号有没有被复用，不是有没有泄漏。
func TestReplyDoesNotLeakFDs(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	srvFile := os.NewFile(uintptr(pair[0]), "srv")
	cliFile := os.NewFile(uintptr(pair[1]), "cli")
	defer srvFile.Close()
	defer cliFile.Close()

	srv, err := net.FileConn(srvFile)
	if err != nil {
		t.Fatalf("FileConn(srv): %v", err)
	}
	cli, err := net.FileConn(cliFile)
	if err != nil {
		t.Fatalf("FileConn(cli): %v", err)
	}
	defer srv.Close()
	defer cli.Close()
	srvUC, ok := srv.(*net.UnixConn)
	if !ok {
		t.Fatal("服务端不是 UnixConn")
	}
	cliUC, ok := cli.(*net.UnixConn)
	if !ok {
		t.Fatal("客户端不是 UnixConn")
	}

	// 先跑一轮热身，把"第一次会额外分配"的东西（socket 读缓冲、fd 表扩容）排除掉。
	round := func() error {
		var pipe [2]int
		if err := unix.Pipe(pipe[:]); err != nil {
			return err
		}
		writeFD := pipe[1]
		defer func() { _ = unix.Close(writeFD) }()

		done := make(chan error, 1)
		go func() { done <- (&HelperServer{}).reply(srvUC, HelperReply{OK: true}, []int{pipe[0]}) }()

		reply, fds, rerr := readReplyWithFDs(cliUC)
		if rerr != nil {
			return rerr
		}
		if err := <-done; err != nil {
			return err
		}
		if !reply.OK || len(fds) != 1 {
			closeAll(fds)
			return errFDBadReply
		}
		// 对端那份必须可用（顺带证明本地关掉不会把对端一起废掉）。
		if _, err := unix.Write(writeFD, []byte("x")); err != nil {
			closeAll(fds)
			return errFDBadReply
		}
		buf := make([]byte, 1)
		if n, err := unix.Read(fds[0], buf); err != nil || n != 1 {
			closeAll(fds)
			return errFDBadReply
		}
		closeAll(fds)
		return nil
	}

	if err := round(); err != nil {
		t.Fatalf("热身轮失败: %v", err)
	}
	baseline := openFDCount(t)

	const rounds = 64
	for i := 0; i < rounds; i++ {
		if err := round(); err != nil {
			t.Fatalf("第 %d 轮失败: %v", i+1, err)
		}
	}

	after := openFDCount(t)
	// 允许 0 增长。每轮都会开一根管道（2 个 fd）并全部关掉，净增长只能是泄漏。
	if after != baseline {
		t.Fatalf("%d 轮之后本进程 fd 从 %d 涨到 %d（多了 %d 个）——"+
			"常驻 helper 会每建一条分流连接漏一个，直到 RLIMIT_NOFILE 用尽",
			rounds, baseline, after, after-baseline)
	}
}

// errFDBadReply 是测试内部的失败标记，不参与被测逻辑。
var errFDBadReply = &fdBadReplyError{}

type fdBadReplyError struct{}

func (e *fdBadReplyError) Error() string { return "helper 应答里的 fd 不对" }

// openFDCount 数本进程此刻开着多少个 fd。
func openFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("读 /proc/self/fd: %v", err)
	}
	return len(entries)
}
