// Package sysproxy 负责「把系统代理指到本客户端」。
//
// 支持三条路（见 backend.go）：GNOME 的 gsettings、KDE 的 kioslaverc、
// 以及兜底的环境变量文件。三条路都由桌面/会话自己回滚，
// 不往用户家目录里塞需要手工清理的痕迹——除非用户明确选了 env 那条，
// 而那也只是一个可整体删除的文件。
//
// 这一层只做「选后端 + 转交 + 记账」的调度；每条路怎么读写在自己的文件里，
// 状态快照怎么记在 state.go 里。
package sysproxy

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

// ErrUnsupported 表示这台机器上没有任何一种可用的手段。
var ErrUnsupported = errors.New("sysproxy: 这台机器上没有可用的系统代理后端（gsettings / kioslaverc / environment.d 都用不了）")

// Config 是一次设置的意图。
type Config struct {
	Enable bool
	// HTTPAddr/HTTPSAddr/SOCKSAddr 形如 127.0.0.1:7892，空则沿用本机默认入站。
	HTTPAddr  string
	HTTPSAddr string
	SOCKSAddr string
	// Bypass 是绕过代理的地址/域名列表， localhost 与私有网段默认带上。
	Bypass []string
	// Backend 指定用哪条路。留空即 BackendAuto。
	Backend string
}

// endpoints 是这一次要写给桌面的三组地址，空值按本机默认入站补齐。
//
// 三条后端和「记账时判断读数是不是我们自己的值」都必须从这里取同一份答案：
// 各自抄一份 fallback 常量的话，默认入站端口哪天改了，比对会静默判错，
// 表现是「关掉系统代理」反而把我们自己的地址又还原回桌面。
type endpoints struct {
	HTTPHost  string
	HTTPPort  string
	HTTPSHost string
	HTTPSPort string
	SOCKSHost string
	SOCKSPort string
}

// join 用与三条后端写入时相同的拼法，读数和比对才不会一个带方括号一个不带。
func joinHostPort(host, port string) string { return host + ":" + port }

func (e endpoints) HTTP() string  { return joinHostPort(e.HTTPHost, e.HTTPPort) }
func (e endpoints) HTTPS() string { return joinHostPort(e.HTTPSHost, e.HTTPSPort) }
func (e endpoints) SOCKS() string { return joinHostPort(e.SOCKSHost, e.SOCKSPort) }

func (c Config) endpoints() endpoints {
	h, p := split(c.HTTPAddr, "127.0.0.1:7892")
	sh, sp := split(orDefault(c.HTTPSAddr, c.HTTPAddr), "127.0.0.1:7892")
	so, sop := split(c.SOCKSAddr, "127.0.0.1:7891")
	return endpoints{HTTPHost: h, HTTPPort: p, HTTPSHost: sh, HTTPSPort: sp, SOCKSHost: so, SOCKSPort: sop}
}

// Status 是系统代理的当前读数，直接给界面显示。
type Status struct {
	Supported bool     `json:"supported"`
	Enabled   bool     `json:"enabled"`
	Backend   string   `json:"backend"`
	Mode      string   `json:"mode"`
	HTTP      string   `json:"http"`
	HTTPS     string   `json:"https"`
	SOCKS     string   `json:"socks"`
	Ignored   []string `json:"ignored"`
	// Note 是这条路特有的限制说明（例如 env 只对之后启动的进程有效）。
	// 界面上照实显示：把"覆盖不全"显示成"已开启"比不开还糟。
	Note string `json:"note,omitempty"`
	// Path 是后端实际改动的文件（只有文件型后端有），指给用户看。
	Path  string `json:"path,omitempty"`
	Error string `json:"error"`
}

// Runner 执行命令，测试时替换。
type Runner interface {
	Run(ctx context.Context, args []string, env []string) (string, error)
}

// ExecRunner 走真实进程。
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, args []string, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// Backends 是可选值，给配置校验与界面下拉共用。
func Backends() []string { return []string{BackendAuto, BackendGNOME, BackendKDE, BackendEnv} }

// ValidBackend 报告 name 是不是一个认识的后端名（空视作 auto）。
func ValidBackend(name string) bool {
	for _, b := range Backends() {
		if strings.EqualFold(strings.TrimSpace(name), b) {
			return true
		}
	}
	return false
}

// Resolve 按配置挑出后端。prefer 为空即自动探测。
func Resolve(ctx context.Context, r Runner, prefer string) (Backend, error) {
	if strings.TrimSpace(prefer) == "" {
		prefer = BackendAuto
	}
	return Detect(ctx, r, prefer)
}

// Apply 写入系统代理设置（选后端、转交）。
func Apply(ctx context.Context, r Runner, c Config) error {
	b, err := Resolve(ctx, r, c.Backend)
	if err != nil {
		return err
	}
	return b.Apply(ctx, r, c)
}

// Read 读回当前系统代理状态（选后端、转交）。
func Read(ctx context.Context, r Runner) (Status, error) { return ReadWith(ctx, r, "") }

// ReadWith 按指定后端读回状态；prefer 为空即自动探测。
func ReadWith(ctx context.Context, r Runner, prefer string) (Status, error) {
	b, err := Resolve(ctx, r, prefer)
	if err != nil {
		st := Status{Ignored: []string{}}
		st.Error = err.Error()
		return st, err
	}
	return b.Read(ctx, r)
}

// Probes 报告每个后端在这台机器上能不能用，给界面下拉与排障用。
func Probes(ctx context.Context, r Runner) map[string]string {
	out := map[string]string{}
	for _, b := range backendsInPreferenceOrder() {
		if err := b.Probe(ctx, r); err != nil {
			out[b.Name()] = err.Error()
		} else {
			out[b.Name()] = ""
		}
	}
	return out
}
