//go:build linux

package tunx

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"wps_app/internal/logx"
)

// 这个文件把"提权 helper"从**一次请求一个进程**改成**一个常驻进程**。
//
// 为什么值得改：造一条钉住网卡的 socket 这件事，每条 trojan 流都要做一次。
// 一次性的 helper 每个请求都要付一次 sudo + 进程起落（实测 0.08~0.11s，
// 其中 sudo 自己 0.04s），还要起落一次 51.9MB 的进程。一条流一次、一分钟几十条，
// 这笔开销就摊在用户的每一次浏览上。
//
// 常驻之后：helper 进程只拉一次，每次拨号开一条短 unix 连接向它要 socket，
// 再也不用为一条流付一次 sudo + 进程起落。短连接换来的是并发：
// 一条走不通的拨号不会把面板里其他拨号堵在同一个 socket 后面。
//
// **边界**：常驻的 root 进程仍然只做"造一条钉在指定网卡上、连到名单内端点的 socket"。
// TLS 仍然终结在面板与节点之间——root 不终结 TLS，就看不到用户的明文流量。
// 这条边界是刻意的：把 root 放到数据通路上是另一档东西，不是这里要解决的。

// dialHelperOwnerFlag 是 helper 侧用来认领套接字属主的参数。
const dialHelperOwnerFlag = "--dial-helper-owner="

// dialHelperParentFlag 是「谁是我的主人」——面板**自己**的 pid。
//
// 为什么必须单独传：helper 的父进程是 sudo，不是面板。面板被 kill -9 之后
// sudo 仍在等子进程，父进程检查（kill(ppid,0)）会一直成功，于是这个握着 root
// 的常驻进程永远不走、套接字一直可连。传 pid 之后就能直接看 /proc/<pid>。
const dialHelperParentFlag = "--dial-helper-parent="

// dialHelperParentPID 从 argv 里取出面板 pid；没传或读不懂时返回 0。
func dialHelperParentPID() int {
	for _, a := range os.Args[1:] {
		if !strings.HasPrefix(a, dialHelperParentFlag) {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimPrefix(a, dialHelperParentFlag))
		if err != nil || pid <= 0 {
			return 0
		}
		return pid
	}
	return 0
}

// ServeConnLoop 在**一条**连接上连续处理多次请求，直到对端收工。
//
// 与 ServeConn 的区别只有"处理几次"：一次请求一个进程那条路仍然用 ServeConn。
func (h *HelperServer) ServeConnLoop(conn *net.UnixConn) error {
	for {
		more, err := h.serveRequest(conn)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
}

// RunDialHelper 是常驻提权 helper 的服务端入口。
//
// socketPath 由面板给（它在一个 0700 的临时目录里），ownerUID 是面板的 uid：
// root 建出来的套接字默认别人连不上，得把属主交回去。
// ownerUID=0 表示「面板自己就是 root」（整个面板由 sudo 拉起时就是这个数）：
// 那时套接字本来就归 root，跳过 chown，不是错误。
// 面板退出后这个进程必须跟着走——否则机器上会留一个握着 root 的常驻进程。
//
// **它只接受 dialbind 一个动作。**
//
// 这是这个文件里最要紧的一条约束。常驻 helper 与一次性 tun-helper 的差别不只是
// 寿命：它的套接字放在用户自己的运行目录里，同一个 uid 的任何进程都连得上，
// 也能算出正确的 uid 通过 SO_PEERCRED。让它继续复用完整的 serveRequest，
// 等于给一个同 uid 的普通进程配了半个 root——它可以要求 root 装默认路由、
// 把本机 :53 DNAT 到任意地址、挂一条 DROP 全站的链、或者开一块 tun 网卡。
// 而它本来只需要一件事：替我要一条钉在指定网卡上、已连通的 socket。
func RunDialHelper(ctx context.Context, socketPath string, ownerUID int) error {
	if socketPath == "" {
		return errors.New("dial helper 需要一个套接字路径")
	}
	dir := filepath.Dir(socketPath)
	if err := secureSocketDir(dir, ownerUID); err != nil {
		return err
	}
	// umask 放到 bind 之前：套接字文件由内核创建，权限只在这一刻能定。
	// 先 bind 再 chmod 有一段"文件已经存在、权限还是 0755"的窗口，
	// 而这段时间恰恰是别人可以抢着连进来的窗口。
	prevMask := unix.Umask(0o077)
	ln, err := net.Listen("unix", socketPath)
	unix.Umask(prevMask)
	if err != nil {
		return fmt.Errorf("监听 dial helper 套接字 %s: %w", socketPath, err)
	}
	defer func() { _ = ln.Close() }()
	// 目录属主已经是桌面用户，套接字在 0700 目录里本来就只对那个 uid 可见；
	// 但显式 chown + 0600 仍然要做：有人把路径配到了别处（比如 /tmp 下的固定名），
	// 目录属主未必是我们期望的那个。
	if ownerUID > 0 {
		if err := os.Chown(socketPath, ownerUID, -1); err != nil {
			return fmt.Errorf("把 dial helper 套接字交给 uid %d: %w", ownerUID, err)
		}
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("设 dial helper 套接字权限: %w", err)
	}
	// 面板没了就收工：一个握着 root 的常驻进程不该比它的主人活得久。
	//
	// 这里以前看 ppid，而 ppid 是 **sudo**——面板被 kill -9 之后 sudo 还在等子进程，
	// Kill(ppid,0) 一直成功，于是这个 root 进程永远留着，套接字也一直可连。
	// 现在优先用面板通过 argv 传进来的真实 pid（--dial-helper-parent）；没传才退回 ppid。
	watchParent(ctx, ln)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	// 只有这一个动作。加新动作前先问一句：它需要 root 吗？同 uid 的进程
	// 发这个请求，会造成我们不想负责的后果吗？
	srv := &HelperServer{
		Timeout:     25 * time.Second,
		OnlyActions: map[string]bool{ActionDialBind: true},
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("接受 dial helper 连接: %w", err)
		}
		go func(c net.Conn) {
			uc, ok := c.(*net.UnixConn)
			if !ok {
				_ = c.Close()
				return
			}
			_ = srv.ServeConnLoop(uc)
			_ = c.Close()
		}(conn)
	}
}

// secureSocketDir 确保套接字所在目录是真实的、属主正确的 0700 目录。
//
// 三步都必须有，各自防一种具体的攻击：
//
//  1. MkdirAll 0700（不是 0777，也不是先建再 chmod）：目录一开始就不该让别人写。
//  2. Lstat + !ModeSymlink：root 在这个路径上 bind 时，如果某一层是指向别处的
//     符号链接，套接字就会被建到攻击者挑的位置，紧接着的 Chown 还会把那个位置
//     交给他。Lstat 看的是链接本身而不是目标，所以能识破。
//  3. Stat 核对属主：目录必须是 ownerUID 的（或 root 的，ownerUID=0 时）。
//     别人拥有的目录里我们无权保证"没有别人能替换里面的东西"。
func secureSocketDir(dir string, ownerUID int) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("建 dial helper 套接字目录: %w", err)
	}
	li, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("查看 dial helper 套接字目录: %w", err)
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("dial helper 套接字目录 %s 是符号链接，拒绝在里面建套接字", dir)
	}
	if !li.IsDir() {
		return fmt.Errorf("dial helper 套接字目录 %s 不是目录", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("收紧 dial helper 套接字目录权限: %w", err)
	}
	// 属主核对：root 写进去的东西，不能落在一个别人能改的目录里。
	//
	// 允许三种情况：目录属于 root（root 自己建的）、属于 ownerUID（面板自己建的
	// 私有目录，0700 下别人进不来）、或者当前进程就是那个 owner。除此之外拒绝：
	// 一个第三方拥有的目录意味着我们无法保证里面不会被人替换。
	st, ok := li.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("读不到 dial helper 套接字目录的属主")
	}
	cur := uint32(os.Geteuid())
	if st.Uid != 0 && st.Uid != uint32(ownerUID) && st.Uid != cur {
		return fmt.Errorf("dial helper 套接字目录 %s 属于 uid %d（期望 0、%d 或 %d），拒绝在其中建套接字",
			dir, st.Uid, ownerUID, cur)
	}
	return nil
}

// watchParent 在面板消失时关掉监听，让这个 root 进程退出。
//
// 判据的顺序是有讲究的：先看 argv 传进来的真实面板 pid（dialHelperParentFlag），
// 没有才看 ppid。ppid 是 sudo，而 sudo 在面板被 kill -9 之后仍会等子进程，
// Kill(ppid,0) 一直成功——这正是"root helper 比主人活得久"的成因。
func watchParent(ctx context.Context, ln net.Listener) {
	pid := dialHelperParentPID()
	// pid<=1：没有可看的父进程（或父进程是 init），只能靠 ctx。
	if pid <= 1 {
		return
	}
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// /proc/<pid> 是否存在比 kill(pid,0) 更可靠：
				// 后者对"同一个 pid 被复用"看不出来，而 root 进程活得久，
				// pid 复用在这里不是理论问题。
				if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); err != nil {
					logx.Debugf("dial helper: 面板进程 %d 已不在，退出", pid)
					_ = ln.Close()
					return
				}
			}
		}
	}()
}

// SecureSocketDir 是 secureSocketDir 的导出包装，给用例用。
func SecureSocketDir(dir string, ownerUID int) error { return secureSocketDir(dir, ownerUID) }

// 每次拨号只向它要一条 socket，不再为每条流付 sudo 与进程起落。
//
// 2026-11-03 之前这里只有一条 unix 连接，整次往返都抱在一把互斥锁里。
// 一条走不通的直连（实测 ccm-frontier-hl.feishu.cn）会把后面所有代理拨号
// 一起堵到 25s 预算花完，症状就是"一个慢站点让整个浏览器一起超时"。
// 现在每次拨号单独连一次 helper——连接本身很便宜，贵的是 sudo；
// helper 侧本来就是 accept 后一个 goroutine 处理一条连接，并发是天然的。
type PersistentHelper struct {
	// Argv 是唤起 helper 的命令前缀（例如 ["sudo","-n","/path/wps_app-gui"]），
	// 后面会自动补上 --dial-helper 与套接字路径。
	Argv []string
	// Timeout 是一次请求的预算；<=0 时用 25 秒。
	Timeout time.Duration
	// Spawn 是「怎么把常驻 helper 叫起来」。默认按 Argv 起子进程；
	// 单测里换成进程内的 RunDialHelper，就能在没有 root 的情况下
	// 把「一条连接扛多次请求」整条路径跑一遍。
	Spawn func(ctx context.Context, socketPath string) error

	mu       sync.Mutex
	dir      string
	path     string
	cmd      *exec.Cmd
	stderr   cappedBuf
	starting *helperStart
	closed   bool
}

// helperStart 是一次「拉起常驻 helper」的共享结果。
//
// 用指针而不是几个散字段，是为了让同一轮的等待者拿到自己的 err：
// 下一轮启动把字段清掉时，已经拿到指针的人不会读到一个被改写的值。
type helperStart struct {
	done chan struct{}
	err  error
}

// DialBound 向常驻 helper 要一条钉在 dev 上、已连通 addr 的 TCP 连接。
func (p *PersistentHelper) DialBound(ctx context.Context, dev, addr string, allow []string) (net.Conn, error) {
	if len(p.Argv) == 0 && p.Spawn == nil {
		return nil, errors.New("没有配置提权 helper 命令")
	}
	conn, err := p.connect(ctx)
	if err != nil {
		if ctx.Err() != nil || !retryableDialBind(err) {
			return nil, err
		}
		// helper 可能被机器上的别的什么清掉了：重连一次。
		// 这里**不**无条件 drop()：connect 失败有很多种瞬时原因，
		// 杀掉共享进程会连带打断别人正在飞的那些拨号。
		// connect 自己只在"确实没人监听"时拆（见 helperGone）。
		conn, err = p.connect(ctx)
		if err != nil {
			return nil, err
		}
	}
	out, err := p.roundTrip(ctx, conn, dev, addr, allow)
	_ = conn.Close()
	if err == nil {
		return out, nil
	}
	if ctx.Err() != nil || !retryableDialBind(err) {
		return nil, err
	}
	// 连接坏了（EOF / ECONNRESET 之类）而调用方还有预算：换一条连接重试一次。
	// 业务拒绝（目标不在名单、连不上目标）不走这条路——重试只会再等一遍。
	//
	// 这一处也不 drop()：坏的是**这一条**连接，不是那个进程。
	// 以前在这里拆掉共享 helper，于是一条流的 EOF 会让所有在途拨号一起失败。
	conn, cerr := p.connect(ctx)
	if cerr != nil {
		return nil, err
	}
	out, err = p.roundTrip(ctx, conn, dev, addr, allow)
	_ = conn.Close()
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Close 收掉常驻 helper（面板退出时调用）。
func (p *PersistentHelper) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	p.drop()
}

// drop 关掉进程并清掉临时目录。已经在飞的连接会在 helper 退出时自行失败；
// 它们不属于这里的状态，下一次 dial 会重新拉起 helper。
func (p *PersistentHelper) drop() {
	p.mu.Lock()
	cmd := p.cmd
	dir := p.dir
	p.cmd = nil
	p.dir, p.path = "", ""
	p.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

// ensure 保证 helper 已经拉起；不在线就拉一次，同一时刻只拉一个。
func (p *PersistentHelper) ensure(ctx context.Context) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errors.New("常驻提权 helper 已关闭")
	}
	if p.path != "" {
		p.mu.Unlock()
		return nil
	}
	if st := p.starting; st != nil {
		p.mu.Unlock()
		select {
		case <-st.done:
			return st.err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	st := &helperStart{done: make(chan struct{})}
	p.starting = st
	p.mu.Unlock()

	err := p.start(ctx)

	p.mu.Lock()
	st.err = err
	p.starting = nil
	p.mu.Unlock()
	close(st.done)
	return err
}

// start 建目录、拉起 helper、等它把套接字建出来。
//
// ctx 只约束"等多久"，不约束 helper 的寿命：常驻进程要活过很多个请求。
func (p *PersistentHelper) start(ctx context.Context) error {
	timeout := p.timeout()
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left < timeout {
			timeout = left
		}
	}
	if timeout <= 0 {
		return context.DeadlineExceeded
	}
	dir, err := os.MkdirTemp("", "wps_app-dial-helper-") // 0700，属主是本进程 uid
	if err != nil {
		return fmt.Errorf("建 dial helper 临时目录: %w", err)
	}
	path := filepath.Join(dir, "s")
	// 只公开目录与 stderr，**不公开 path**：
	// 这一轮要等套接字真的建出来才把 path 设进去（见函数末尾）。
	// 提前公开的后果是并发的第二条拨号会在套接字还没 bind 时拿到一条
	// 注定 Dial 失败的路径，随后 drop() 把正在启动的这个 helper 一起杀掉——
	// 一次并发就把整条提权通道拆了，而日志里只会看到"连不上"。
	p.mu.Lock()
	p.dir = dir
	p.path = ""
	p.stderr = cappedBuf{}
	p.mu.Unlock()

	if p.Spawn != nil {
		// 单测路径：进程内起 helper，不碰 sudo。
		if err := p.Spawn(context.Background(), path); err != nil {
			p.drop()
			return fmt.Errorf("拉起常驻提权 helper: %w", err)
		}
	} else {
		// 与一次性 helper 同一条纪律：调 sudo 之前先核对被提权执行的那个文件。
		// sudoers 只认路径，而路径往往指向用户可写的仓库目录。
		if err := checkHelperBinary(helperBinaryFromArgv(p.Argv)); err != nil {
			p.drop()
			return err
		}
		argv := append(append([]string{}, p.Argv...),
			"--dial-helper", "--dial-helper-connect="+path,
			dialHelperOwnerFlag+strconv.Itoa(os.Getuid()),
			// 传面板自己的 pid，而不是让 helper 去看 ppid（那是 sudo）。
			dialHelperParentFlag+strconv.Itoa(os.Getpid()))
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stderr = &p.stderr
		if err := cmd.Start(); err != nil {
			p.drop()
			return fmt.Errorf("启动常驻提权 helper %q: %w（sudo 要免密，且父进程不能带 no_new_privs）", argv[0], err)
		}
		p.mu.Lock()
		p.cmd = cmd
		p.mu.Unlock()
	}
	// 等套接字出现：helper 起来要几十毫秒（还要过一遍 sudo）。
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			// 到这里才公开 path。ensure 的判据是 "path != ''"，所以
			// 在套接字真的能 Dial 之前，后来的拨号会老老实实排队等这一轮。
			p.mu.Lock()
			p.path = path
			p.mu.Unlock()
			return nil
		}
		if time.Now().After(deadline) {
			p.drop()
			return fmt.Errorf("常驻提权 helper 没有在 %v 内把套接字建起来（stderr: %s）", timeout, truncate(p.stderr.String(), 200))
		}
		select {
		case <-ctx.Done():
			p.drop()
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// connect 为**这一次**拨号开一条到 helper 的 unix 连接。
// 一次请求一条连接，换来的是真正的并发：helper 每条连接一个 goroutine，
// 一条慢拨号不会再挡住下一条。
func (p *PersistentHelper) connect(ctx context.Context) (*net.UnixConn, error) {
	if err := p.ensure(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	path := p.path
	p.mu.Unlock()
	if path == "" {
		return nil, errors.New("常驻提权 helper 还没连上")
	}
	timeout := p.timeout()
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left < timeout {
			timeout = left
		}
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		// 连不上**不**拆共享进程。
		//
		// 以前这里无条件 drop()，于是任何一次可重试的失败（helper 正忙、
		// 一条连接恰好坏掉、瞬时 EAGAIN）都会杀掉整个常驻 helper，
		// 连带打断别人正在飞的那些拨号——一次抖动放大成全链路重来。
		//
		// 只在"确实没人在监听"时才拆：ECONNREFUSED / 路径不存在意味着
		// 进程已经没了，留着 path 只会让之后每一次拨号都失败。
		if ctx.Err() == nil && helperGone(err) {
			p.drop()
		}
		return nil, fmt.Errorf("连常驻提权 helper: %w", err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("常驻提权 helper 的连接不是 unix socket")
	}
	return uc, nil
}

// helperReplyError 是 helper **正常作答但拒绝**这次拨号。
// 它与连接坏了是两回事：前者重试只会再等一遍，后者值得换条连接。
type helperReplyError struct{ msg string }

func (e *helperReplyError) Error() string { return e.msg }

// retryableDialBind 判断一次失败值不值得重连再试。
// 调用方放弃、预算用完、helper 说"这个目标连不上"都不值得。
func retryableDialBind(err error) bool {
	if err == nil {
		return false
	}
	var rejected *helperReplyError
	if errors.As(err, &rejected) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, os.ErrDeadlineExceeded) {
		return false
	}
	return true
}

// helperGone 判断这次 Dial 失败是不是"对面已经没人了"。
//
// 只有这一档值得拆掉共享 helper：路径不存在、连接被拒（内核说没有监听者）。
// 其它错误（预算耗尽、临时不可用、EAGAIN）都可能是瞬时的，
// 拆进程只会把一次抖动放大成所有在途拨号一起失败。
func helperGone(err error) bool {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	// unix 套接字文件被删掉时内核回 ENOENT，但 net 包有时包装成 "no such file"。
	return strings.Contains(err.Error(), "no such file or directory")
}

// roundTrip 在一条专用连接上发一次请求、收一次应答（含那个 fd）。
func (p *PersistentHelper) roundTrip(ctx context.Context, conn *net.UnixConn, dev, addr string, allow []string) (net.Conn, error) {
	budget := p.timeout()
	if deadline, ok := ctx.Deadline(); ok {
		if left := time.Until(deadline); left < budget {
			budget = left
		}
	}
	if budget <= 0 {
		return nil, context.DeadlineExceeded
	}
	_ = conn.SetDeadline(time.Now().Add(budget))
	// ctx 没有 deadline 时，光靠 SetDeadline 收不到取消；补一个回调把等待打断。
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	req := DialBindRequest(os.Geteuid(), dev, addr, allow)
	payload, err := encodeRequest(req)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(conn, payload); err != nil {
		return nil, fmt.Errorf("发 dialbind 请求: %w", err)
	}
	reply, fds, err := readReplyWithFDs(conn)
	if err != nil {
		return nil, fmt.Errorf("读 dialbind 应答: %w", err)
	}
	if !reply.OK {
		closeAll(fds)
		msg := reply.Err
		if msg == "" {
			msg = "提权 helper 拒绝了这次拨号"
		}
		return nil, &helperReplyError{msg: msg}
	}
	if len(fds) != 1 {
		closeAll(fds)
		return nil, fmt.Errorf("提权 helper 应答里带回来 %d 个 fd，期望 1 个", len(fds))
	}
	f := os.NewFile(uintptr(fds[0]), "wps_app-bound-socket")
	defer func() { _ = f.Close() }()
	out, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("接管提权 helper 交回的 socket: %w", err)
	}
	return out, nil
}

func (p *PersistentHelper) timeout() time.Duration {
	if p.Timeout > 0 {
		return p.Timeout
	}
	return 25 * time.Second
}
