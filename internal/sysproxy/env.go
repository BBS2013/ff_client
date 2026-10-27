// env 后端：写 ~/.config/environment.d 下的一个文件，靠环境变量把代理发出去。
//
// 它是前两条路都走不通时的兜底，覆盖面也确实最小：
//
//   - 只对认 http_proxy/https_proxy/all_proxy/no_proxy 的程序有效；
//   - 只对**改动之后启动**的进程有效，已经在跑的应用拿不到；
//   - systemd 用户实例与登录会话都会读 environment.d，新起的 systemd 服务也算。
//
// 这些限制不在代码里绕得过去，所以界面照实写出来，而不是显示成"已开启"。
//
// 为什么写 environment.d 而不是往 ~/.bashrc 里塞 export：
// shellrc 只在交互式 shell 里生效，systemd 服务、GUI 程序、cron 全都读不到；
// 而 export 一旦写进去，注释掉比删掉容易，半年后没人说得清那行是谁加的。
// environment.d 是**一个文件**：删掉即完全还原，快照里也只需要记"本来有没有它"。
//
// 同时尽力调 systemctl --user set-environment，让当前这一会话里新起的进程
// 不用等重新登录就能读到。失败不影响正确性（新登录一定生效），故吞掉错误。
package sysproxy

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// envVarNames 是我们写出去的八个变量，大小写各一套。
// envNote 照实说清这条路覆盖不到什么。把它显示在界面上而不是藏起来：
// 用户看到"已开启"却发现某个程序没走代理，只能靠猜。
const envNote = "只对认 http_proxy/https_proxy/all_proxy 的程序有效，" +
	"且只对改动之后启动的进程生效——已经在跑的应用不会自动改道。"

var envVarNames = []string{
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
}

const (
	// envProxyFile 是相对家目录的路径。
	envProxyFile = ".config/environment.d/90-wps_app-proxy.conf"
	// envMarker 写进文件里的一行注释，用来在 `ls` 一眼认出这是谁写的。
	envMarker = "# 由 wps_app 系统代理开关写入；删掉这个文件即完全还原。"
)

type envBackend struct{}

func (envBackend) Name() string { return BackendEnv }

func (envBackend) Probe(context.Context, Runner) error {
	if desktopHome() == "" {
		return fmt.Errorf("找不到家目录，没法写 %s", envProxyFile)
	}
	return nil
}

func (b envBackend) Apply(ctx context.Context, r Runner, c Config) error {
	if r == nil {
		r = ExecRunner{}
	}
	path := resolvePath(desktopHome(), envProxyFile)
	if !c.Enable {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		dargs, denv := desktopPrefix()
		unsetEnv(r, dargs, denv)
		return nil
	}
	vars := envVars(c)
	if err := writeFileAtomic(path, []byte(envFileBody(vars))); err != nil {
		return err
	}
	dargs, denv := desktopPrefix()
	setEnv(r, dargs, denv, vars)
	return nil
}

// envVars 是启用时要写的那几对变量。
//
// 大小写两套都写：curl、git、wget 认小写，一批 Python 与 Java 库只认大写。
// 只写一套等于"一半的程序有效"，而那种状态比全不写更难查。
func envVars(c Config) [][2]string {
	e := c.endpoints()
	bypass := strings.Join(mergeBypass(c.Bypass), ",")
	httpURL, httpsURL, socksURL := "http://"+e.HTTP(), "http://"+e.HTTPS(), "socks5://"+e.SOCKS()
	return [][2]string{
		{"http_proxy", httpURL},
		{"https_proxy", httpsURL},
		{"all_proxy", socksURL},
		{"no_proxy", bypass},
		{"HTTP_PROXY", httpURL},
		{"HTTPS_PROXY", httpsURL},
		{"ALL_PROXY", socksURL},
		{"NO_PROXY", bypass},
	}
}

// envFileBody 把这些变量排成 environment.d 要的文件内容。
func envFileBody(vars [][2]string) string {
	var b strings.Builder
	b.WriteString(envMarker)
	b.WriteByte('\n')
	for _, kv := range vars {
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(kv[1])
		b.WriteByte('\n')
	}
	return b.String()
}

// EnvLikesOurs 报告快照里的文件内容是不是已经等于我们要写的那份。
// 命中时把它当"原状"记下来，等于关掉之后仍然把流量指回我们自己的端口。
func EnvLikesOurs(snap envSnapshot, c Config) bool {
	return snap.Existed && snap.Content == envFileBody(envVars(c))
}

func (b envBackend) Read(ctx context.Context, r Runner) (Status, error) {
	st := Status{Ignored: []string{}, Backend: BackendEnv}
	if err := b.Probe(ctx, r); err != nil {
		st.Error = ErrUnsupported.Error()
		return st, ErrUnsupported
	}
	path := resolvePath(desktopHome(), envProxyFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// 文件不存在 = 我们没开过。supported 仍然是 true，
		// 因为"没开"和"不支持"在界面上必须是两回事。
		st.Supported = true
		st.Mode = "None"
		st.Path = path
		st.Note = envNote
		return st, nil
	}
	if err != nil {
		st.Error = err.Error()
		return st, err
	}
	st.Supported = true
	st.Path = path
	st.Note = envNote
	vars := parseEnvFile(string(raw))
	if len(vars) == 0 {
		st.Mode = "None"
		return st, nil
	}
	st.Mode = "Environment"
	st.Enabled = true
	st.HTTP = trimScheme(vars["http_proxy"])
	st.HTTPS = trimScheme(vars["https_proxy"])
	st.SOCKS = trimScheme(vars["all_proxy"])
	for _, p := range strings.Split(vars["no_proxy"], ",") {
		if p = strings.TrimSpace(p); p != "" {
			st.Ignored = append(st.Ignored, p)
		}
	}
	// env 里的值可能已被用户手工改过。照实报出文件里的内容，
	// 界面上那一栏于是是"当前真的生效的是什么"，而不是"我们上次写了什么"。
	return st, nil
}

// Path 记下后端实际写的那个文件，界面上要指给用户看——
// env 后端不像 gsettings 那样有系统设置面板，不给路径用户根本不知道去哪儿删。
type envSnapshot struct {
	Existed bool   `json:"existed"`
	Content string `json:"content,omitempty"`
}

// CaptureEnv 取回现有 environment.d 文件的原文，供记账。
func CaptureEnv() (envSnapshot, error) {
	path := resolvePath(desktopHome(), envProxyFile)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return envSnapshot{Existed: false}, nil
	}
	if err != nil {
		return envSnapshot{}, err
	}
	return envSnapshot{Existed: true, Content: string(raw)}, nil
}

// RestoreEnv 按快照还原。Existed 为 false 表示本来就没有，删掉即可。
func RestoreEnv(snap envSnapshot) error {
	path := resolvePath(desktopHome(), envProxyFile)
	if !snap.Existed {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeFileAtomic(path, []byte(snap.Content))
}

func parseEnvFile(body string) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(body, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if k, v, ok := strings.Cut(t, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// setEnv / unsetEnv 尽力把变量灌进当前会话。
//
// systemctl --user set-environment 只影响**之后**由 systemd 起的进程，
// 已经跑着的应用是改不到的——这一点在界面文案里也照实说了。
func setEnv(r Runner, args, env []string, vars [][2]string) {
	if r == nil {
		return
	}
	pctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout)
	defer cancel()
	cmd := append(append([]string{}, args...), "systemctl", "--user", "set-environment")
	for _, v := range vars {
		cmd = append(cmd, v[0]+"="+v[1])
	}
	_, _ = r.Run(pctx, cmd, env)
}

func unsetEnv(r Runner, args, env []string) {
	if r == nil {
		return
	}
	pctx, cancel := context.WithTimeout(context.Background(), ProbeTimeout)
	defer cancel()
	cmd := append(append([]string{}, args...), "systemctl", "--user", "unset-environment")
	for _, n := range envVarNames {
		cmd = append(cmd, n)
	}
	_, _ = r.Run(pctx, cmd, env)
}
