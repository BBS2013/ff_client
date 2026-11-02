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
	_, err := h.serveRequest(conn)
	return err
}

// serveRequest 处理**一次**请求，返回 more=false 表示对端已经走了。
//
// 为什么要拆成"一次"：常驻 helper 的一条连接要能承载多次请求（见 ServeConnLoop），
// 而 TUN 那条路仍然是一次请求一个进程——同一份代码两种用法，靠 more 这个返回区分。
func (h *HelperServer) serveRequest(conn *net.UnixConn) (bool, error) {
	timeout := h.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	peer, perr := peerUID(conn)

	raw, err := readFrame(conn)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
			return false, nil // 对端正常收工，不是错误
		}
		return false, fmt.Errorf("读 helper 请求: %w", err)
	}
	req, err := decodeRequest(raw)
	if err != nil {
		return true, h.reply(conn, HelperReply{Err: err.Error()}, nil)
	}
	if verr := req.validate(); verr != nil {
		return true, h.reply(conn, HelperReply{Err: verr.Error()}, nil)
	}
	// 请求里的 uid 会被写进 iptables 的 `-m owner ! --uid-owner`，
	// 它必须是这条连接对面那个 uid——否则就是拿 root 替别人改排除规则。
	if perr != nil {
		return true, h.reply(conn, HelperReply{Err: fmt.Sprintf("取不到连接对端凭据: %v", perr)}, nil)
	}
	if req.Plan.UID != int(peer) {
		return true, h.reply(conn, HelperReply{Err: fmt.Sprintf(
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
			return true, h.reply(conn, reply, nil)
		}
		return true, h.reply(conn, reply, []int{fd})
	case ActionDown:
		// down 走独立的 ctx：清理路径不能被一个已经花完的时间预算一起取消。
		dctx, dcancel := context.WithTimeout(context.Background(), timeout)
		defer dcancel()
		reply, err := h.doDown(dctx, req.Plan)
		if err != nil {
			reply.Err = err.Error()
		}
		return true, h.reply(conn, reply, nil)
	case ActionCleanup:
		dctx, dcancel := context.WithTimeout(context.Background(), timeout)
		defer dcancel()
		reply := HelperReply{OK: true}
		reply.Removed = CleanupStale(dctx, h.runner(), req.Plan.UID, req.Plan.Device, req.Plan.Address)
		reply.Removed = append(reply.Removed, applyStale6(dctx, h.runner(), req.Plan)...)
		// 残留的出站保护链也必须摘掉：面板被杀在故障期间时，那条 DROP 还在，
		// 而它拦的是用户机器上所有出站——不是一句「重启就好了」能交代的。
		reply.Removed = append(reply.Removed, CleanupKill(dctx, h.runner())...)
		return true, h.reply(conn, reply, nil)
	case ActionReroute:
		dctx, dcancel := context.WithTimeout(context.Background(), timeout)
		defer dcancel()
		reply, err := h.doReroute(dctx, req.Plan, *req.Prev)
		if err != nil {
			reply.Err = err.Error()
		}
		return true, h.reply(conn, reply, nil)
	case ActionKill:
		// 摘下保护走独立 ctx：解除封锁不该被一个已经花完的时间预算一起取消。
		dctx, dcancel := context.WithTimeout(context.Background(), timeout)
		defer dcancel()
		reply, err := h.doKill(dctx, req.Plan, req.Allow, req.KillArm)
		if err != nil {
			reply.Err = err.Error()
		}
		return true, h.reply(conn, reply, nil)
	case ActionDialBind:
		// dialbind 不 exec 任何命令、也不改任何配置：只造一条已经钉好并连上的 socket。
		// 预算取这一次请求剩下的时间——它不该把整条提权通道的超时吃满。
		budget := timeout
		if dl, ok := ctx.Deadline(); ok {
			budget = time.Until(dl)
		}
		reply, fd, err := h.doDialBind(req, budget)
		if err != nil {
			return true, h.reply(conn, HelperReply{OK: false, Err: err.Error()}, nil)
		}
		if !reply.OK || fd < 0 {
			if fd >= 0 {
				_ = unix.Close(fd) // 没人认领的 fd 是一个还活着的内核引用，不能留
			}
			return true, h.reply(conn, reply, nil)
		}
		return true, h.reply(conn, reply, []int{fd})
	default:
		return true, h.reply(conn, HelperReply{Err: fmt.Sprintf("未知的 helper 动作 %q", req.Action)}, nil)
	}
}

// doReroute 在网络变化后把绕行路由改钉到新网关。
//
// 命令由本包按两份计划现算（RoutePlan.RepinRoutes），helper 不接受调用方给的命令行。
// 旧的那些清理是尽力而为：旧路由本来就不在了也不该拦住重钉。
func (h *HelperServer) doReroute(ctx context.Context, plan, prev RoutePlan) (HelperReply, error) {
	up, cleanup := plan.RepinRoutes(prev)
	reply := HelperReply{OK: true}
	for _, c := range cleanup {
		if _, err := h.runner().Run(ctx, c); err != nil {
			reply.Removed = append(reply.Removed, c.Desc+"（清理失败）")
		}
	}
	if err := Apply(ctx, h.runner(), up); err != nil {
		reply.OK = false
		reply.Err = "重钉绕行路由失败: " + err.Error()
		return reply, err
	}
	for _, c := range up {
		reply.Applied = append(reply.Applied, c.Desc)
	}
	// v6 默认路由有没有真在位：拆旧的那条会失败（它本来就不在），不据此判断。
	reply.V6RouteOK = plan.usable6()
	return reply, nil
}

// doKill 挂上或摘下故障断网保护。规则同样由本包按 plan 现算（见 PlanKill），
// 请求里的 allow 只提供地址，不提供命令行。
//
// 挂到一半失败必须回滚。PlanKill 把挂载点（`-I OUTPUT 1`）排在最后，所以中途失败时
// 链是没挂上的、流量照旧——但那条半成品链必须删干净，否则下一次挂载读到的是一个
// 我们不再追踪的白名单。回滚用摘链那组命令，它们每一步都容错，
// 「本来就没挂上」不会把回滚也带失败。
//
// 摘下失败的方向正好相反，也更严重：链还在，DROP 还在拦用户此刻的流量。
// 所以它必须报错、必须进界面，绝不能当成一次无害的清理失败。
func (h *HelperServer) doKill(ctx context.Context, plan RoutePlan, allow []string, arm bool) (HelperReply, error) {
	if !arm {
		// 摘链只要链名，不看计划：strict_route 刚被关掉、白名单已经变了这些时刻
		// 正是最需要把闸门打开的时候，而那时 PlanKill 会拒绝生成计划。
		// 实现与本进程摘链、启动清理同一条（CleanupKill）：判据写三份早晚不一致，
		// 而这里不一致的代价是「面板说已关闭，内核里那条 DROP 链还在」。
		CleanupKill(ctx, h.runner())
		return HelperReply{OK: true, Applied: []string{"断网保护已解除"}}, nil
	}
	kp, err := plan.PlanKill(allow)
	if err != nil {
		return HelperReply{OK: false, KillReason: kp.Error()}, fmt.Errorf("生成断网保护规则失败: %w", err)
	}
	if err := Apply(ctx, h.runner(), kp.Arm); err != nil {
		reason := "保护挂到一半失败，已回滚，当前未生效: " + err.Error()
		if kp.Error() != "" {
			reason += "（" + kp.Error() + "）"
		}
		dctx, dcancel := context.WithTimeout(context.Background(), disarmTimeout)
		defer dcancel()
		for _, c := range kp.Disarm {
			_, _ = h.runner().Run(dctx, c)
		}
		return HelperReply{OK: false, KillReason: reason}, errors.New(reason)
	}
	reply := HelperReply{OK: true, KillV4: kp.V4, KillV6: kp.V6, KillReason: kp.Error()}
	for _, c := range kp.Arm {
		reply.Applied = append(reply.Applied, c.Desc)
	}
	return reply, nil
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
	v6OK := plan.v6FakeIPUsable() && len(v6up) > 0
	if v6OK {
		if err := Apply(ctx, h.runner(), v6up); err != nil {
			v6OK = false
			for _, c := range v6down {
				_, _ = h.runner().Run(ctx, c)
			}
		}
	}
	// v6 全局接管又是单独一组：它决定的是「v6 流量有没有被接管」，
	// 与 v6 假 IP 能不能用是两件事，必须各自成败、各自回滚。
	route6up, route6down, _ := plan.PlanV6Route()
	v6RouteOK := len(route6up) > 0
	if v6RouteOK {
		if err := Apply(ctx, h.runner(), route6up); err != nil {
			v6RouteOK = false
			for _, c := range route6down {
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
	names := make([]string, 0, len(up)+len(v6up)+len(route6up))
	for _, c := range up {
		names = append(names, c.Desc)
	}
	if v6OK {
		for _, c := range v6up {
			names = append(names, c.Desc)
		}
	}
	if v6RouteOK {
		for _, c := range route6up {
			names = append(names, c.Desc)
		}
	}
	return HelperReply{OK: true, Applied: names, V6OK: v6OK, V6RouteOK: v6RouteOK, Device: plan.Device, MTU: mtu}, fd, nil
}

func (h *HelperServer) doDown(ctx context.Context, plan RoutePlan) (HelperReply, error) {
	_, down, err := plan.Plan()
	if err != nil {
		return HelperReply{OK: false}, err
	}
	// v6 的先拆：它的 down 不依赖网卡还在，最后再摘地址。
	// v6 接管那一组也先拆：它装着 v6 默认路由，留着会让整机 v6 流量继续指向 tun。
	if _, v6down, verr := plan.PlanV6Route(); verr == nil {
		down = append(v6down, down...)
	}
	if _, v6down, verr := plan.PlanV6(); verr == nil {
		down = append(v6down, down...)
	}
	reply := HelperReply{OK: true}
	var failed []string
	for _, c := range down {
		out, err := h.runner().Run(ctx, c)
		if err != nil {
			// Optional 的失败是常态（那些东西本来就不在），只有非 Optional 才算没拆干净。
			// 判据和本地那一路共用一份，见 tolerates。
			if !tolerates(c, out) {
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
	// up 交回 tun fd，dialbind 交回一条钉住并已连通的 TCP socket fd：
	// 这两个动作的应答**必须**带一个 fd 回来，少一个都当失败处理，
	// 因为面板在那边等的就是这条 fd，拿不到就是拿不到。
	if req.Action == ActionUp || req.Action == ActionDialBind {
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

// DialBound 向 helper 要一条钉在 dev 上、已连通 addr 的 TCP 连接。
//
// 拿回来的是普通 net.Conn，调用方关掉它就行：fd 是从对面 dup 过来的，
// os.File 那份引用在 FileConn 之后立刻关掉，不留一个没人认领的描述符。
//
// 失败时原样递出 helper 那句拒绝（名单不合用、网卡不在、连不上……）——
// 这几种原因各自要去查的地方完全不同，包成一句"提权失败"就等于白跑一趟。
func (c HelperClient) DialBound(ctx context.Context, dev, addr string, allow []string) (net.Conn, error) {
	reply, fd, err := c.Run(ctx, DialBindRequest(os.Geteuid(), dev, addr, allow))
	if err != nil {
		return nil, err
	}
	if fd < 0 {
		if reply.Err != "" {
			return nil, errors.New(reply.Err)
		}
		return nil, errors.New("helper 没有交回 socket fd")
	}
	f := os.NewFile(uintptr(fd), "wps_app-bound-socket")
	defer func() { _ = f.Close() }()
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("接管 helper 交回的 socket 失败: %w", err)
	}
	return conn, nil
}
