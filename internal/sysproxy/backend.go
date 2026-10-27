// 系统代理的「后端」：一种把系统代理指到本客户端的具体手段。
//
// 早期这里只有 gsettings 一条路，于是「系统代理」等价于「这台机器是 GNOME」。
// KDE 用户与无桌面环境的用户拿到的是一句「这台机器上没有 gsettings」，
// 于是去改 shellrc——而那恰恰是最不可逆、最容易把自己搞进代理死循环的做法。
//
// 三种后端的取舍：
//
//   - gnome：写 org.gnome.system.proxy。桌面自己管回滚，`mode none` 就干净。
//   - kde：写 kioslaverc 的 [Proxy Settings]。同样是桌面自己管，只是配置格式不同。
//   - env：写 ~/.config/environment.d 下的一个文件，让新起的进程读环境变量。
//     覆盖面最小（只对认 http_proxy 的程序、且只在改动之后启动的进程有效），
//     所以它是兜底而不是首选，界面上会照实说清楚。
//
// 选谁由 Detect 按 gnome → kde → env 的顺序试，也可以在配置里写死
// （sysproxy.backend）。写死不是为了炫技：探测本身可能因为 D-Bus 抽风而误判，
// 而"设置错了"和"没探测到"必须能被用户自己纠正回来。
package sysproxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// 后端标识，出现在配置、状态文件与界面里。
const (
	BackendGNOME = "gnome"
	BackendKDE   = "kde"
	BackendEnv   = "env"
	// BackendAuto 表示交给 Detect 决定。
	BackendAuto = "auto"
)

// Backend 是一种「把系统代理指到本客户端」的手段。
//
// 接口只有三件事：能不能用、怎么开、现在是什么样。
// 故意不设 Disable：关闭的语义由各自的快照决定（见 state.go），
// 而"怎么关"和"怎么开"是同一个后端的同一份知识，拆成两个方法只会让两者走偏。
type Backend interface {
	// Name 是上面的标识常量。
	Name() string
	// Probe 报告这台机器能不能用这个后端。用来做自动选择，
	// 也决定了界面上那个开关是否可点。
	Probe(ctx context.Context, r Runner) error
	// Apply 开或关。c.Enable 为 false 时是关闭。
	Apply(ctx context.Context, r Runner, c Config) error
	// Read 读回当前设置。Probe 失败时返回 ErrUnsupported。
	Read(ctx context.Context, r Runner) (Status, error)
}

// Detect 按偏好顺序挑一个能用的后端。
//
// 顺序是刻意的：桌面后端覆盖面最大且由桌面自己回滚，环境变量是最后手段。
// 用户显式指定的 backend 不会被这里覆盖——那是用户在说「就这个」。
func Detect(ctx context.Context, r Runner, prefer string) (Backend, error) {
	if r == nil {
		r = ExecRunner{}
	}
	if prefer != BackendAuto {
		b := lookup(prefer)
		if b == nil {
			// 不认识的名字**不能**当成 auto：用户明确点名了某个后端，
			// 我们照着做错了却显示成「自动选的」，他没有任何线索能发现。
			return nil, fmt.Errorf("%w（不认识的后端名 %q，可选 auto | gnome | kde | env）", ErrUnsupported, prefer)
		}
		if err := b.Probe(ctx, r); err != nil {
			return nil, fmt.Errorf("%w（指定 %q: %v）", ErrUnsupported, prefer, err)
		}
		return b, nil
	}
	for _, b := range backendsInPreferenceOrder() {
		if err := b.Probe(ctx, r); err == nil {
			return b, nil
		}
	}
	return nil, ErrUnsupported
}

func backendsInPreferenceOrder() []Backend {
	return []Backend{gnomeBackend{}, kdeBackend{}, envBackend{}}
}

// lookup 按名字取后端；不认识的名字返回 nil，交给调用方解释。
func lookup(name string) Backend {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case BackendGNOME:
		return gnomeBackend{}
	case BackendKDE:
		return kdeBackend{}
	case BackendEnv:
		return envBackend{}
	}
	return nil
}

// split 把 "127.0.0.1:7892" 拆成 host 与 port，空则取 fallback。
func split(addr, fallback string) (string, string) {
	if strings.TrimSpace(addr) == "" {
		addr = fallback
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "127.0.0.1", "7892"
	}
	return host, port
}

func orDefault(primary, fallback string) string {
	if strings.TrimSpace(primary) != "" {
		return primary
	}
	return fallback
}

// defaultBypass 是永远不该走代理的地址。
// 漏掉 localhost 会让本机自己访问自己绕一大圈，甚至死锁在代理端口上。
var defaultBypass = []string{"localhost", "127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

func mergeBypass(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in)+len(defaultBypass))
	for _, s := range append(append([]string{}, defaultBypass...), in...) {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// desktopHome 返回「桌面用户」的家目录。
//
// 面板为了开 TUN 常以 root 跑，但配置和代理设置都得落在桌面用户身上——
// 写到 /root 下面的话，桌面读的是自己的 ~/.config，我们的改动等于没做。
// 这也是 gsettings 要按 SUDO_USER 还原身份之外的另一半：文件路径同理。
func desktopHome() string {
	if os.Geteuid() == 0 {
		if su := os.Getenv("SUDO_USER"); su != "" {
			if home, err := userHome(su); err == nil && home != "" {
				return home
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

func userHome(name string) (string, error) {
	out, err := exec.Command("getent", "passwd", name).Output()
	if err != nil {
		return "", err
	}
	// passwd 格式：name:passwd:uid:gid:gecos:home:shell
	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 6 {
		return "", fmt.Errorf("passwd 里 %q 的记录不完整", name)
	}
	return fields[5], nil
}

func userUID(name string) (int, error) {
	out, err := exec.Command("id", "-u", name).Output()
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(out)))
}

// desktopPrefix 决定命令以谁的身份、用什么 D-Bus 地址执行。
func desktopPrefix() (args []string, env []string) {
	uid := os.Geteuid()
	user := os.Getenv("USER")
	if uid == 0 {
		if su := os.Getenv("SUDO_USER"); su != "" {
			user = su
		}
	}
	if user == "" {
		return nil, nil
	}
	if id, err := userUID(user); err == nil && id != uid {
		bus := "/run/user/" + strconv.Itoa(id) + "/bus"
		if _, statErr := os.Stat(bus); statErr == nil {
			env = []string{"DBUS_SESSION_BUS_ADDRESS=unix:path=" + bus, "DISPLAY=:0"}
			return []string{"sudo", "-n", "-u", user}, env
		}
	}
	return nil, env
}

// writeFileAtomic 先写临时文件、fsync、再 rename。
//
// 代理设置文件被改坏的后果是"整机断网且看不出原因"，所以这里必须原子替换：
// 直接 truncate 重写的话，中途断电/被杀会留下半截文件。
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".wps-sysproxy-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// kioskrc 里没有秘密，但沿用 0600：它是我们改出来的文件，
	// 没必要让别的用户能改（能被改就意味着代理指向可以被别人悄悄换掉）。
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// resolvePath 在桌面用户的家目录下拼路径。
// 传绝对路径时原样返回——配置显式给了位置就不该被家目录改写。
func resolvePath(home, path string) string {
	if home == "" || filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(home, path)
}
