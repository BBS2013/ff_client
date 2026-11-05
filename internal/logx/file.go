package logx

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"wps_app/internal/sudoown"
)

// 日志文件的上限与保留份数。20MB × 3 份足够覆盖"昨天那次为什么断了"，
// 又不至于让一个常驻程序悄悄吃掉几百 MB。
const (
	DefaultMaxBytes int64 = 20 << 20
	DefaultBackups        = 3
)

// rotatingFile 是一个按大小轮转的文件 sink。
//
// restoreLogOwner 把 root 面板新写出的日志还给桌面用户。
//
// 日志是 0600 且常被拿来排查故障；root 跑过一次面板后，普通用户连读都读不了。
// 这里只能 best-effort：logx 不能反过来打日志（会递归），失败就算了。
func restoreLogOwner(path string) {
	_ = sudoown.ToDesktopUser(path)
}

// 不用第三方库：轮转规则只有三条（超过上限、挪备份、重开文件），
// 而这份代码要在"日志本身就是排查手段"的场景里工作，少一层依赖少一个变量。
type rotatingFile struct {
	mu      sync.Mutex
	path    string
	max     int64
	backups int
	f       *os.File
	size    int64
}

func newRotatingFile(path string, max int64, backups int) (*rotatingFile, error) {
	if path == "" {
		return nil, errors.New("日志路径为空")
	}
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if backups < 0 {
		backups = 0
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	// 已有文件可能是 0644（比如用户手工建过）：权限按日志内容定，必须收紧。
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	// 文件可能是 root 刚建的（sudo 起的面板）：把属主还给 SUDO_USER。
	restoreLogOwner(path)
	return &rotatingFile{path: path, max: max, backups: backups, f: f, size: st.Size()}, nil
}

func (w *rotatingFile) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size > 0 && w.size+int64(len(p)) > w.max {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate 把 path 挪成 .1，旧的 .1 → .2 …… 只保留 backups 份。
func (w *rotatingFile) rotate() error {
	_ = w.f.Close()
	if w.backups > 0 {
		for i := w.backups - 1; i >= 1; i-- {
			old := fmt.Sprintf("%s.%d", w.path, i)
			next := fmt.Sprintf("%s.%d", w.path, i+1)
			_ = os.Rename(old, next) // 缺失的备份是常态，不算错误
		}
		_ = os.Rename(w.path, w.path+".1")
		restoreLogOwner(w.path + ".1")
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	restoreLogOwner(w.path)
	w.f = f
	w.size = 0
	return nil
}

func (w *rotatingFile) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// fileSink 负责在 Close 时把全局输出恢复原样。
type fileSink struct {
	once sync.Once
	old  io.Writer
	file *rotatingFile
}

func (s *fileSink) Close() error {
	var err error
	s.once.Do(func() {
		mu.Lock()
		output = s.old
		mu.Unlock()
		err = s.file.Close()
	})
	return err
}

// SetFileOutput 在保留原输出的同时，把日志再写一份到 path。
//
// 文件先写：面板的 stdout 是启动器给的 socket，启动器退出后它可能不可写，
// 不能因为控制台坏了就把文件日志也一起丢掉。
//
// **stdout 不是终端时不再抄一份。**
//
// 那个副本只有两个归宿，而两个都不需要它：
//   - GUI 面板的 stdout 是启动器给的管道/socket（start_wps_app-gui.sh 曾经
//     把它追加到仓库根的 wps_app-gui.out，0644、无上限）；
//   - systemd 部署时它进 journal，而 <config>.log 已经是同一份内容。
//
// 也就是说它是"同一批日志的第二份拷贝"，而且这一份没有轮转、没有 0600。
// 现场量过一次：wps_app-gui.out 8MB 与 config.yaml.log 前 8MB 逐行相同，
// 里面全是访问过哪些域名。多写一遍既费 IO，又多留一处没人管的访问记录。
//
// 交互终端（有人在终端里手工跑）仍然照抄：那是人在看，不是落盘。
func SetFileOutput(path string, maxBytes int64, backups int) (io.Closer, error) {
	w, err := newRotatingFile(path, maxBytes, backups)
	if err != nil {
		return nil, err
	}
	mu.Lock()
	old := output
	switch {
	case old == nil:
		output = w
	case isTerminalFn(old):
		output = io.MultiWriter(w, old)
	default:
		// 非终端：只写文件。
		output = w
	}
	mu.Unlock()
	return &fileSink{old: old, file: w}, nil
}

// isTerminalFn 是 isTerminal 的接缝：单测要演"人在终端里看"时换掉它。
// 用真 *os.File 去造终端需要 pty，代价远大于这条判断本身。
var isTerminalFn = isTerminal

// isTerminal 判断这个 writer 是不是一个真的终端（包括 os.Stdout 被重定向前的形状）。
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		// 多路复用器（io.MultiWriter）之类：保守起见当成"不是终端"，
		// 因为那说明输出已经被包过一层，多半也不是人在看。
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
