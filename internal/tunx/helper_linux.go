//go:build linux

package tunx

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	gvisortun "gvisor.dev/gvisor/pkg/tcpip/link/tun"

	"wps_app/internal/logx"
)

// helper 的连接参数就写在 argv 上，不走环境变量：
// sudo 会重置 env，而 argv 一定会原样传给子进程。
const connectFlag = "--tun-helper-connect="

// HelperServer 是提权侧的全部实现面。
//
// 两个函数字段是留给测试的接缝：真机上它们是 tun.Open 与 net.InterfaceByName，
// 单测里换成假的，就能在没有 root、没有网卡的情况下把整套协议与启停顺序跑一遍。
type HelperServer struct {
	Runner Runner
	// Open 创建（或附着）一块 tun 网卡并返回它的 fd。
	Open func(name string) (int, error)
	// MTU 返回网卡当前 MTU；建链路端点必须用内核上的真实值。
	MTU func(name string) (uint32, error)
	// Timeout 是单个请求的处理上限，默认 20s。
	Timeout time.Duration
}

func (h *HelperServer) open(name string) (int, error) {
	if h.Open != nil {
		return h.Open(name)
	}
	// gvisor 的 tun.Open 用 IFF_TUN|IFF_NO_PI：没有 4 字节协议头，
	// fd 上读写的就是裸 IP 包，与后面 fdbased 端点的 EthernetHeader=false 相配。
	return gvisortun.Open(name)
}

func (h *HelperServer) mtu(name string) (uint32, error) {
	if h.MTU != nil {
		return h.MTU(name)
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return uint32(iface.MTU), nil
}

func (h *HelperServer) runner() Runner {
	if h.Runner != nil {
		return h.Runner
	}
	return ExecRunner{}
}

// ServeConn 处理一条连接上的一个请求然后返回。
//
// 一个请求一条连接不是吝啬，而是要的：helper 每次被唤起只做一件事、做完就退，
// 就不存在「root 进程常驻、面板崩了它还挂着网卡」这种状态。
// 网卡的生命周期完全由面板手里那个 fd 决定，进程死了内核就把它收走。
func (h *HelperServer) ServeConn(conn *net.UnixConn) error {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	peer, perr := peerUID(conn)

	raw, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("读 helper 请求: %w", err)
	}
	req, err := decodeRequest(raw)
	if err != nil {
		return h.reply(conn, HelperReply{Err: err.Error()}, nil)
	}
	if verr := req.validate(); verr != nil {
		return h.reply(conn, HelperReply{Err: verr.Error()}, nil)
	}
	// 请求里的 uid 会被写进 iptables 的 `-m owner ! --uid-owner`，
	// 它必须是这条连接对面那个 uid——否则就是拿 root 替别人改排除规则。
	if perr != nil {
		return h.reply(conn, HelperReply{Err: fmt.Sprintf("取不到连接对端凭据: %v", perr)}, nil)
	}
	if req.Plan.UID != int(peer) {
		return h.reply(conn, HelperReply{Err: fmt.Sprintf(
			"请求里的 uid=%d 与连接对端 uid=%d 不一致，拒绝执行", req.Plan.UID, peer)}, nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	switch req.Action {
	case ActionUp:
		reply, fd, err := h.doUp(ctx, req.Plan)
		if err != nil {
			reply.Err = err.Error()
			reply.OK = false
			reply.Device = ""
			return h.reply(conn, reply, nil)
		}
		return h.reply(conn, reply, []int{fd})
	case ActionDown:
		// down 走独立的 ctx：清理路径不能被一个已经花完的时间预算一起取消。
		dctx, dcancel := context.WithTimeout(context.Background(), timeout)
		defer dcancel()
		reply, err := h.doDown(dctx, req.Plan)
		if err != nil {
			reply.Err = err.Error()
		}
		return h.reply(conn, reply, nil)
	case ActionCleanup:
		dctx, dcancel := context.WithTimeout(context.Background(), timeout)
		defer dcancel()
		reply := HelperReply{OK: true}
		reply.Removed = CleanupStale(dctx, h.runner(), req.Plan.UID, req.Plan.Device, req.Plan.Address)
		reply.Removed = append(reply.Removed, applyStale6(dctx, h.runner(), req.Plan)...)
		return h.reply(conn, reply, nil)
	default:
		return h.reply(conn, HelperReply{Err: fmt.Sprintf("未知的 helper 动作 %q", req.Action)}, nil)
	}
}

func (h *HelperServer) doUp(ctx context.Context, plan RoutePlan) (HelperReply, int, error) {
	fd, err := h.open(plan.Device)
	if err != nil {
		return HelperReply{}, -1, fmt.Errorf("创建 tun 网卡 %s 失败: %w（需要 CAP_NET_ADMIN，helper 请用 root 运行）", plan.Device, err)
	}
	up, _, perr := plan.Plan()
	if perr != nil {
		_ = unix.Close(fd)
		return HelperReply{}, -1, perr
	}
	if err := Apply(ctx, h.runner(), up); err != nil {
		// 网卡已经建起来了，必须关掉再报错：否则留下一个没有主人的 tun 接口，
		// 下一次启动会撞上 "File exists"，故障会一层层盖住真正的原因。
		_ = unix.Close(fd)
		_, down, _ := plan.Plan()
		dctx, dcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcancel()
		for _, c := range down {
			_, _ = h.runner().Run(dctx, c)
		}
		return HelperReply{}, -1, fmt.Errorf("配置 tun 网络失败: %w", err)
	}
	// v6 那一组单独成败：多半是内核没有 ip6table_nat。
	// 失败只降级 v6（AAAA 回 NODATA），绝不能因此把已经配好的 v4 也一起掀了。
	v6up, v6down, _ := plan.PlanV6()
	v6OK := len(v6up) > 0
	if v6OK {
		if err := Apply(ctx, h.runner(), v6up); err != nil {
			v6OK = false
			for _, c := range v6down {
				_, _ = h.runner().Run(ctx, c)
			}
		}
	}
	mtu, err := h.mtu(plan.Device)
	if err != nil {
		_ = unix.Close(fd)
		return HelperReply{}, -1, fmt.Errorf("读取 %s 的 MTU: %w", plan.Device, err)
	}
	// Applied 回传给面板显示：GUI 里那串「实际跑过哪些步骤」是排障的主要线索，
	// 走 helper 之后它来自 root 侧，不能因为换了执行者就丢掉。
	names := make([]string, 0, len(up)+len(v6up))
	for _, c := range up {
		names = append(names, c.Desc)
	}
	if v6OK {
		for _, c := range v6up {
			names = append(names, c.Desc)
		}
	}
	return HelperReply{OK: true, Applied: names, V6OK: v6OK, Device: plan.Device, MTU: mtu}, fd, nil
}

func (h *HelperServer) doDown(ctx context.Context, plan RoutePlan) (HelperReply, error) {
	_, down, err := plan.Plan()
	if err != nil {
		return HelperReply{OK: false}, err
	}
	// v6 的先拆：它的 down 不依赖网卡还在，最后再摘地址。
	if _, v6down, verr := plan.PlanV6(); verr == nil {
		down = append(v6down, down...)
	}
	reply := HelperReply{OK: true}
	var failed []string
	for _, c := range down {
		if _, err := h.runner().Run(ctx, c); err != nil {
			// Optional 的失败是常态（那些东西本来就不在），只有非 Optional 才算没拆干净。
			if !c.Optional {
				failed = append(failed, fmt.Sprintf("%s: %v", c.Desc, err))
			}
			continue
		}
		reply.Removed = append(reply.Removed, c.Desc)
	}
	if len(failed) > 0 {
		reply.OK = false
		reply.Err = "拆 TUN 时有步骤失败: " + strings.Join(failed, "; ")
	}
	return reply, nil
}

// reply 把应答（以及 up 时的 tun fd）发回面板。
func (h *HelperServer) reply(conn *net.UnixConn, r HelperReply, fds []int) error {
	payload, err := encodeReply(r)
	if err != nil {
		return err
	}
	if len(fds) == 0 {
		return writeFrame(conn, payload)
	}
	// 帧头与正文必须在同一次 sendmsg 里带着 rights 一起出去：
	// 流式 unix socket 上，控制消息是绑在某个字节位置上的，
	// 对面只要用不带控制缓冲的 Read 跨过那个位置，内核就把 fd 直接关掉当丢了。
	frame := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint32(frame[:headerLen], uint32(len(payload)))
	copy(frame[headerLen:], payload)
	// Sendmsg 一旦成功，fd 就已经挂进对端 socket 的接收队列：
	// 之后我们关掉自己这份副本不会让对端那个失效——这正是 Android VpnService
	// 把 tun fd 交给无权限 app 的同一条内核机制。
	if _, _, err := conn.WriteMsgUnix(frame, unix.UnixRights(fds...), nil); err != nil {
		return fmt.Errorf("发回 helper 应答与 fd: %w", err)
	}
	return nil
}

// peerUID 取这条 unix 套接字对端的有效 uid。
func peerUID(conn *net.UnixConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		cred *unix.Ucred
		cerr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	if cred == nil {
		return 0, errors.New("对端凭据为空")
	}
	return int(cred.Uid), nil
}

// HelperClient 用配置的 argv 唤起 helper，并把一次请求走完。
type HelperClient struct {
	Argv    []string
	Timeout time.Duration
	// Spawn 是「怎么把 helper 叫起来」。默认按 Argv 起子进程；
	// 单测里换成进程内的 ServeConn，就能在没有 root、没有网卡的情况下
	// 把「请求—应答—fd 交接」整条真实套接字路径跑一遍。
	Spawn func(ctx context.Context, socketPath string) error
}

// Run 执行一次请求。返回的 fd 只属于本进程，调用方负责关。
//
// 面板是监听方、helper 是拨号方：连接方向反过来越省事——路径由面板决定并
// 放进 argv，helper 不需要知道任何约定，也永远不接受别人递来的路径。
func (c HelperClient) Run(ctx context.Context, req HelperRequest) (HelperReply, int, error) {
	if len(c.Argv) == 0 && c.Spawn == nil {
		return HelperReply{}, -1, errors.New("没有配置 tun.helper 命令")
	}
	if err := req.validate(); err != nil {
		return HelperReply{}, -1, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 25 * time.Second
	}

	dir, err := os.MkdirTemp("", "wps_app-tun-helper-") // MkdirTemp 的目录就是 0700，属主是本进程 uid
	if err != nil {
		return HelperReply{}, -1, fmt.Errorf("建 helper 套接字目录: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := dir + "/s"

	ln, err := net.Listen("unix", path)
	if err != nil {
		return HelperReply{}, -1, fmt.Errorf("监听 helper 套接字: %w", err)
	}
	defer func() { _ = ln.Close() }()

	// cmd 与 stderr 只在真的起子进程时才有；进程内测试走 Spawn，两者都是零值。
	var (
		cmd    *exec.Cmd
		stderr cappedBuf
	)
	startHelper := func() error {
		if c.Spawn != nil {
			return c.Spawn(ctx, path)
		}
		argv := append(append([]string{}, c.Argv...), connectFlag+path)
		cmd = exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			// 两种失败长得一样、处方不同：sudo 要密码，或者父进程带着 no_new_privs
			// （从受限 shell / 沙箱里启动面板时必踩），后者配了免密也照样起不来。
			// 真跑起来之后的 stderr 由下面的"等 helper 连接超时"那条错误带出来。
			return fmt.Errorf("启动 tun.helper %q: %w（sudo 需免密，且父进程不能带 no_new_privs；可在启动面板的那个 shell 里跑 sudo -n true 验）", argv[0], err)
		}
		// 面板被 Ctrl+C 掉时 helper 也一起收掉，不留下一个握着网卡的 root 进程。
		go func() {
			<-ctx.Done()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}()
		return nil
	}
	if err := startHelper(); err != nil {
		return HelperReply{}, -1, err
	}
	// reap/wait 对「没有子进程」（进程内测试走 Spawn）必须是空操作，
	// 否则这两条路径会拿着 nil 的 cmd 直接 panic。
	reap := func() {
		if cmd == nil {
			return
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}
	wait := func() error {
		if cmd == nil {
			return nil
		}
		return cmd.Wait()
	}

	type acceptResult struct {
		conn *net.UnixConn
		err  error
	}
	done := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- acceptResult{err: err}
			return
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			_ = c.Close()
			done <- acceptResult{err: fmt.Errorf("accepted %T, 不是 unix 连接", c)}
			return
		}
		done <- acceptResult{conn: uc}
	}()

	var res acceptResult
	select {
	case res = <-done:
	case <-time.After(timeout):
		res = acceptResult{err: errors.New("等 helper 连接超时")}
	}
	if res.err != nil {
		reap()
		return HelperReply{}, -1, fmt.Errorf("helper 没有连回来: %w（stderr: %s）", res.err, truncate(stderr.String(), 300))
	}
	conn := res.conn
	defer func() { _ = conn.Close() }()

	payload, err := encodeRequest(req)
	if err != nil {
		return HelperReply{}, -1, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := writeFrame(conn, payload); err != nil {
		return HelperReply{}, -1, fmt.Errorf("发请求给 helper: %w", err)
	}

	reply, fds, err := readReplyWithFDs(conn)
	if err != nil {
		// 先等子进程退出再报错：不然 stderr 里那些「sudo: a password is required」
		// 这类关键信息会被我们抢先读走，界面上只剩一句空洞的 io 错误。
		reap()
		return HelperReply{}, -1, fmt.Errorf("读 helper 应答: %w（stderr: %s）", err, truncate(stderr.String(), 300))
	}
	if cerr := wait(); cerr != nil && reply.OK {
		logx.Debugf("tun.helper 退出码非零但应答是成功的: %v", cerr)
	}
	if !reply.OK {
		msg := reply.Err
		if msg == "" {
			msg = "helper 拒绝执行"
		}
		if extra := truncate(stderr.String(), 200); extra != "" {
			msg += "（stderr: " + extra + "）"
		}
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
		return reply, -1, errors.New(msg)
	}
	if req.Action == ActionUp {
		if len(fds) != 1 {
			closeAll(fds)
			return reply, -1, fmt.Errorf("helper 应答里带回来 %d 个 fd，期望 1 个", len(fds))
		}
		return reply, fds[0], nil
	}
	// down/cleanup 本来就不该带 fd 回来；带回来了也只能关掉——
	// 留着就是一个没人认领、还占着网卡的内核引用。
	closeAll(fds)
	return reply, -1, nil
}

// readReplyWithFDs 读一帧应答，并把控制消息里的 fd 全捞出来。
//
// 这里刻意一次都不用 conn.Read：流式 unix socket 上的控制消息绑在字节位置上，
// 只要有一次不带控制缓冲的读跨过了那个位置，内核就把随行的 fd 关掉当丢了。
// 全程 ReadMsgUnix 才能保证 fd 一定被收下来。
func readReplyWithFDs(conn *net.UnixConn) (HelperReply, []int, error) {
	var (
		buf     []byte
		fds     []int
		oob     = make([]byte, unix.CmsgSpace(4*16))
		chunk   = make([]byte, 4096)
		lastErr error
	)
	for {
		n, oobn, _, _, err := conn.ReadMsgUnix(chunk, oob)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if oobn > 0 {
			msgs, perr := unix.ParseSocketControlMessage(oob[:oobn])
			if perr != nil {
				closeAll(fds)
				return HelperReply{}, nil, perr
			}
			for i := range msgs {
				passed, gerr := unix.ParseUnixRights(&msgs[i])
				if gerr != nil {
					continue // 不是 fd 列表的控制消息（比如凭据），忽略
				}
				fds = append(fds, passed...)
			}
		}
		if len(buf) >= headerLen {
			size := int(binary.BigEndian.Uint32(buf[:headerLen]))
			if size <= 0 || size > maxHelperFrame {
				closeAll(fds)
				return HelperReply{}, fds, fmt.Errorf("helper 应答长度非法: %d", size)
			}
			if len(buf) >= headerLen+size {
				reply, derr := decodeReply(buf[headerLen : headerLen+size])
				if derr != nil {
					closeAll(fds)
				}
				return reply, fds, derr
			}
		}
		if err != nil {
			lastErr = err
			break
		}
	}
	closeAll(fds)
	if lastErr == nil {
		lastErr = io.ErrUnexpectedEOF
	}
	return HelperReply{}, nil, lastErr
}

func closeAll(fds []int) {
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}

// cappedBuf 是有上限的 stderr 收集缓冲：helper 若被塞了个话痨命令，
// 不能让它把面板进程的内存吃掉。
type cappedBuf struct {
	buf [4096]byte
	n   int
}

func (c *cappedBuf) Write(p []byte) (int, error) {
	if c.n < len(c.buf) {
		room := len(c.buf) - c.n
		if len(p) > room {
			copy(c.buf[c.n:], p[:room])
			c.n += room
			return len(p), nil // 超出部分丢掉，但告诉调用方「写成功了」
		}
		copy(c.buf[c.n:], p)
		c.n += len(p)
	}
	return len(p), nil
}

func (c *cappedBuf) String() string { return string(c.buf[:c.n]) }

// RunHelperForMain 是给 `wps_app --tun-helper` 用的入口：
// 拨回面板给的套接字，服务一个请求，然后返回让进程退出。
func RunHelperForMain(path string, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(context.Background(), "unix", path)
	if err != nil {
		return fmt.Errorf("连回面板的 helper 套接字 %s: %w", path, err)
	}
	conn, ok := raw.(*net.UnixConn)
	if !ok {
		_ = raw.Close()
		return errors.New("连到的不是 unix 套接字")
	}
	defer func() { _ = conn.Close() }()

	srv := &HelperServer{Timeout: timeout}
	// 只有 root 才可能建成网卡；不是 root 时不必装作能干，直接说清楚，
	// 免得面板那边收到一句 ip 命令的 EPERM 还得倒推是谁起的 helper。
	if os.Geteuid() != 0 {
		logx.Warnf("tun-helper 正以 uid=%d 运行，创建网卡与改路由多半会失败（请用 sudo 起面板，或在配置里给免密 sudo 的命令）", os.Geteuid())
	}
	return srv.ServeConn(conn)
}
