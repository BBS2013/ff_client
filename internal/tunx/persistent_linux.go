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
	"sync"
	"syscall"
	"time"
)

// 这个文件把"提权 helper"从**一次请求一个进程**改成**一个常驻进程**。
//
// 为什么值得改：造一条钉住网卡的 socket 这件事，每条 trojan 流都要做一次。
// 一次性的 helper 每个请求都要付一次 sudo + 进程起落（实测 0.08~0.11s，
// 其中 sudo 自己 0.04s），还要起落一次 51.9MB 的进程。一条流一次、一分钟几十条，
// 这笔开销就摊在用户的每一次浏览上。
//
// 常驻之后：面板保持一条 unix 连接，按需要"钉住的 socket"，一次都不再起进程。
//
// **边界**：常驻的 root 进程仍然只做"造一条钉在指定网卡上、连到名单内端点的 socket"。
// TLS 仍然终结在面板与节点之间——root 不终结 TLS，就看不到用户的明文流量。
// 这条边界是刻意的：把 root 放到数据通路上是另一档东西，不是这里要解决的。

// dialHelperOwnerFlag 是 helper 侧用来认领套接字属主的参数。
const dialHelperOwnerFlag = "--dial-helper-owner="

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
func RunDialHelper(ctx context.Context, socketPath string, ownerUID int) error {
	if socketPath == "" {
		return errors.New("dial helper 需要一个套接字路径")
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("建 dial helper 套接字目录: %w", err)
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("监听 dial helper 套接字 %s: %w", socketPath, err)
	}
	defer func() { _ = ln.Close() }()
	if ownerUID > 0 {
		if err := os.Chown(socketPath, ownerUID, -1); err != nil {
			return fmt.Errorf("把 dial helper 套接字交给 uid %d: %w", ownerUID, err)
		}
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("设 dial helper 套接字权限: %w", err)
	}
	// 面板没了就收工：一个握着重启权的常驻 root 进程不该比它的主人活得久。
	ppid := os.Getppid()
	go func() {
		t := time.NewTicker(3 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if ppid <= 1 {
					return
				}
				if err := syscall.Kill(ppid, 0); err != nil && errors.Is(err, syscall.ESRCH) {
					_ = ln.Close()
					return
				}
			}
		}
	}()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	srv := &HelperServer{Timeout: 25 * time.Second}
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

// PersistentHelper 是**常驻**提权 helper 的客户端：与一个 root 子进程保持一条连接，
// 按需要向它要"钉住的 socket"。
//
// 与 HelperClient 的一次一进程相比，它省掉每条流的 sudo 与进程起落；
// 代价是它自己得管生命周期：拉起、按需重连、退出时收干净。
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

	mu     sync.Mutex
	dir    string
	path   string
	cmd    *exec.Cmd
	conn   *net.UnixConn
	stderr cappedBuf
}

// DialBound 向常驻 helper 要一条钉在 dev 上、已连通 addr 的 TCP 连接。
func (p *PersistentHelper) DialBound(ctx context.Context, dev, addr string, allow []string) (net.Conn, error) {
	if len(p.Argv) == 0 && p.Spawn == nil {
		return nil, errors.New("没有配置提权 helper 命令")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if err := p.ensure(); err != nil {
			return nil, err
		}
		conn, err := p.roundTrip(dev, addr, allow)
		if err == nil {
			return conn, nil
		}
		// 连接断了就重连再来一次：常驻 helper 可能被机器上的别的什么清掉了，
		// 一次就报"提权失败"会让用户以为这条路彻底不通。
		p.drop()
		if attempt == 1 {
			return nil, err
		}
	}
	return nil, errors.New("没能从提权 helper 拿到 socket")
}

// Close 收掉常驻 helper（面板退出时调用）。
func (p *PersistentHelper) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.drop()
}

// drop 关掉连接与进程，并清掉临时目录。
func (p *PersistentHelper) drop() {
	if p.conn != nil {
		_ = p.conn.Close()
		p.conn = nil
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		_, _ = p.cmd.Process.Wait()
	}
	p.cmd = nil
	if p.dir != "" {
		_ = os.RemoveAll(p.dir)
		p.dir, p.path = "", ""
	}
}

// ensure 保证"helper 在跑、连接在"；不在线就拉起来。
func (p *PersistentHelper) ensure() error {
	if p.conn != nil {
		return nil
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	dir, err := os.MkdirTemp("", "wps_app-dial-helper-") // 0700，属主是本进程 uid
	if err != nil {
		return fmt.Errorf("建 dial helper 临时目录: %w", err)
	}
	path := filepath.Join(dir, "s")
	if p.Spawn != nil {
		// 单测路径：进程内起 helper，不碰 sudo。
		p.dir, p.path = dir, path
		if err := p.Spawn(context.Background(), path); err != nil {
			_ = os.RemoveAll(dir)
			p.dir, p.path = "", ""
			return fmt.Errorf("拉起常驻提权 helper: %w", err)
		}
	} else {
		argv := append(append([]string{}, p.Argv...),
			"--dial-helper", "--dial-helper-connect="+path, dialHelperOwnerFlag+strconv.Itoa(os.Getuid()))
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stderr = &p.stderr
		if err := cmd.Start(); err != nil {
			_ = os.RemoveAll(dir)
			return fmt.Errorf("启动常驻提权 helper %q: %w（sudo 要免密，且父进程不能带 no_new_privs）", argv[0], err)
		}
		p.dir, p.path, p.cmd = dir, path, cmd
	}
	// 等套接字出现：helper 起来要几十毫秒（还要过一遍 sudo）。
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			p.drop()
			return fmt.Errorf("常驻提权 helper 没有在 %v 内把套接字建起来（stderr: %s）", timeout, truncate(p.stderr.String(), 200))
		}
		time.Sleep(10 * time.Millisecond)
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		p.drop()
		return fmt.Errorf("连常驻提权 helper: %w", err)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		p.drop()
		return errors.New("常驻提权 helper 的连接不是 unix socket")
	}
	p.conn = uc
	return nil
}

// roundTrip 发一次请求、收一次应答（含那个 fd）。
func (p *PersistentHelper) roundTrip(dev, addr string, allow []string) (net.Conn, error) {
	conn := p.conn
	if conn == nil {
		return nil, errors.New("常驻提权 helper 还没连上")
	}
	deadline := time.Now().Add(p.timeout())
	_ = conn.SetDeadline(deadline)
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
		if reply.Err != "" {
			return nil, errors.New(reply.Err)
		}
		return nil, errors.New("提权 helper 拒绝了这次拨号")
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
