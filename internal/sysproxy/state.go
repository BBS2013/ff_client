// 系统代理的「改动前读数」记账与还原。
//
// 为什么需要它：启用系统代理会把桌面（或会话环境）切到「指向本客户端」。
// 一旦进程异常消失（崩溃、SIGKILL、桌面会话重启），设置会永远停在这个状态：
// 所有遵循它的应用继续按 manual 取流量，却连一个已经不存在的端口——
// 整机断网，而且只报一句「代理连接被拒绝」。用户不会知道要回来跑
// `wps_app -sysproxy off`。
//
// 所以启用时先把原样读数落到状态文件，正常退出时还原；
// 万一上次是崩的，下次启动会发现「记录里的进程已经不在」，顺手还原一次。
//
// 记账里带后端名，是因为三条路的还原方式完全不同：
// GNOME 要逐个 gsettings 键写回去，KDE 要把 [Proxy Settings] 整段原文贴回，
// env 只要删掉（或写回）那一个文件。还原时若靠"重新探测"来选后端，
// 用户中途卸载了桌面就会还原到另一条路上，原来的设置留在那儿再也回不来。
package sysproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"wps_app/internal/procid"
)

// stateSuffix 是状态文件的后缀，跟配置与实例锁放在同一目录。
const stateSuffix = ".sysproxy.json"

// saved 是「我们动手之前桌面的样子」，加上用来判断宿主是否还活着的 pid。
//
// KDE 与 env 用各自的快照类型：它们要还原的是**文件内容**，
// 而不是一组「host/port/mode」这种可以逐键写回的读数。
type saved struct {
	PID int `json:"pid"`
	// Exe 记账那一刻本程序的可执行路径（绝对、已解析软链）。
	//
	// 光有 PID 不够：进程号会被回收再分给无关程序。到那一步，「宿主还活着」
	// 就再也判不成立，自愈永远不敢动手，桌面一直指着没人听的端口。
	// 老记账没这一项，holderAlive 退化到拿当前二进制的路径去比。
	Exe     string `json:"exe,omitempty"`
	Backend string `json:"backend,omitempty"`
	// 以下几项是 GNOME 的读数。Backend 为空的老状态文件按 gnome 读。
	Mode   string       `json:"mode,omitempty"`
	HTTP   string       `json:"http,omitempty"`
	HTTPS  string       `json:"https,omitempty"`
	SOCKS  string       `json:"socks,omitempty"`
	Ignore []string     `json:"ignore,omitempty"`
	KDE    *kdeSnapshot `json:"kde,omitempty"`
	Env    *envSnapshot `json:"env,omitempty"`
	// AlreadyOurs 记的是「改动前的读数本来就等于我们要写的值」。
	//
	// 这时候快照里的"原状"就是我们自己的地址：照它还原等于关掉之后
	// 桌面仍然指向本客户端的入站——开关看着坏了，进程一退出全机断网。
	// 命中时还原改走各后端的关闭路径（none / ProxyType=None / 删文件）。
	AlreadyOurs bool      `json:"alreadyOurs,omitempty"`
	SavedAt     time.Time `json:"savedAt"`
}

// backend 报出这份记账属于哪条路，老文件没有这一项时按 gnome 处理。
func (s saved) backend() string {
	if strings.TrimSpace(s.Backend) == "" {
		return BackendGNOME
	}
	return s.Backend
}

// StatePath 返回状态文件路径。约定与实例锁、.bak 一致：
// 都在配置文件旁边，用相对配置路径推导，重定向配置文件就一起搬家。
func StatePath(configPath string) string {
	dir, base := filepath.Split(configPath)
	if dir == "" {
		dir = "."
	}
	return filepath.Join(dir, base+stateSuffix)
}

// capture 按后端取「动手前的样子」。
func capture(ctx context.Context, r Runner, b Backend, c Config) (saved, error) {
	st := saved{
		PID:     os.Getpid(),
		Exe:     procid.Self(),
		Backend: b.Name(),
		SavedAt: time.Now(),
	}
	switch b.Name() {
	case BackendKDE:
		snap, err := CaptureKDE()
		if err != nil {
			return saved{}, fmt.Errorf("读不到 %s，无法备份: %w", kdeProxyFile, err)
		}
		st.KDE = &snap
		st.AlreadyOurs = KDELikesOurs(snap, c)
	case BackendEnv:
		snap, err := CaptureEnv()
		if err != nil {
			return saved{}, fmt.Errorf("读不到 %s，无法备份: %w", envProxyFile, err)
		}
		st.Env = &snap
		st.AlreadyOurs = EnvLikesOurs(snap, c)
	case BackendGNOME:
		before, err := b.Read(ctx, r)
		if err != nil {
			// 读不到原状态就不要动手：还原不了等于改了就回不来。
			return saved{}, fmt.Errorf("读不到当前系统代理设置，已放弃改动: %w", err)
		}
		st.Mode = orNone(before.Mode)
		st.HTTP = before.HTTP
		st.HTTPS = before.HTTPS
		st.SOCKS = before.SOCKS
		st.Ignore = before.Ignored
		e := c.endpoints()
		st.AlreadyOurs = st.Mode == "manual" && st.HTTP == e.HTTP() &&
			st.HTTPS == e.HTTPS() && st.SOCKS == e.SOCKS()
	default:
		// 不认识的后端绝不能再按 GNOME 记账：那样改的是新后端、记的是 gsettings 的账，
		// 还原时去写 gsettings → 新后端改的东西永远还原不了，
		// 桌面停在 mode=manual 指向一个已关的端口，整机断网且只报「代理连接被拒绝」。
		return saved{}, fmt.Errorf("后端 %q 还没接入记账，无法安全地改动系统代理", b.Name())
	}
	return st, nil
}

// Enable 打开系统代理，并把改动前的读数记到状态文件。
//
// 顺序是「先记账再动手」：宁可留下一个「记了账但没改成」的桌面，
// 也不要「改成了但没记账」的桌面——后者就是断网且无法自愈的那一种。
func Enable(ctx context.Context, r Runner, statePath string, c Config) error {
	if r == nil {
		r = ExecRunner{}
	}
	prev, err := peekSaved(statePath)
	if err != nil {
		return err
	}
	// 记账还在，说明上一轮改动还没还原。这时又启用一次，且后端和上次不是同一条，
	// 等于让两条后端同时生效：桌面指向其中一个，环境变量指向另一个，
	// 用户会得到「浏览器走代理、终端不走」这种互相打架的现场，
	// 而且关掉时只能还原其中一条，另一条就永久留下了。
	// 宁可拒绝，也不要造出这个局面。
	//
	// 显式点名的后端在这里就能比，不该为了判它对不对就先探一遍机器；
	// auto 要等 Resolve 出结果才知道落在哪条上，所以挪到后面再比一次。
	if want := strings.TrimSpace(c.Backend); prev != nil && want != "" && want != BackendAuto && prev.backend() != want {
		return stackedBackendErr(prev.backend(), statePath)
	}
	b, err := Resolve(ctx, r, c.Backend)
	if err != nil {
		return err
	}
	if prev != nil && prev.backend() != b.Name() {
		return stackedBackendErr(prev.backend(), statePath)
	}
	st, err := capture(ctx, r, b, c)
	if err != nil {
		return err
	}
	if err := writeState(statePath, st); err != nil {
		return fmt.Errorf("记账失败，已放弃改动系统代理: %w", err)
	}
	if err := b.Apply(ctx, r, c); err != nil {
		// 没改成就把账撤掉，别留一条会让下次启动乱还原的假记录。
		_ = os.Remove(statePath)
		return err
	}
	return nil
}

func stackedBackendErr(prev, statePath string) error {
	return fmt.Errorf("上一次启用（后端 %s）还没还原，先关掉系统代理再换后端；"+
		"若确认桌面已是原样，删掉 %s 后重试", prev, statePath)
}

// Disable 关闭系统代理。
//
// 有记账就还原成改动前的样子（用户原来可能是 manual 指向别的代理，
// 直接置 none 等于擅自改了别人的配置）；没有记账才退化成「关掉」。
func Disable(ctx context.Context, r Runner, statePath string, prefer string) error {
	if r == nil {
		r = ExecRunner{}
	}
	if _, err := os.Stat(statePath); err == nil {
		return Restore(ctx, r, statePath)
	}
	b, err := Resolve(ctx, r, prefer)
	if err != nil {
		return err
	}
	return b.Apply(ctx, r, Config{Enable: false, Backend: b.Name()})
}

// Restore 按状态文件把设置还原回去，并清掉记账。
// 没有状态文件时是空操作——没什么可还原的。
func Restore(ctx context.Context, r Runner, statePath string) error {
	if r == nil {
		r = ExecRunner{}
	}
	st, err := peekSaved(statePath)
	if err != nil {
		return err
	}
	if st == nil {
		return nil // 没有记账：没什么可还原的
	}
	if err := apply(ctx, r, *st); err != nil {
		return err
	}
	// 还原成功才算账清了。留着会让下次启动又还原一次，
	// 那会把用户在这期间自己改的设置又冲掉。
	return os.Remove(statePath)
}

// RecoverIfStale 在进程启动时调用：状态文件还在、但记账里那个实例已经确定不在了，
// 说明上次是异常退出，把设置还原回去。返回是否做了还原。
//
// 这是崩溃场景下唯一的自愈机会——崩掉的进程没有机会执行任何清理代码。
// 「确定不在」必须由可执行路径说出来（见 holderAlive）：只认 PID 的话，
// 号码被回收过一次就永远不敢自愈，桌面会一直停在已经不存在的端口上。
func RecoverIfStale(ctx context.Context, r Runner, statePath string) (bool, error) {
	st, err := peekSaved(statePath)
	if err != nil {
		// 读不懂就别乱动桌面：交回给用户判断，比猜一个原状去写安全。
		return false, err
	}
	if st == nil {
		return false, nil // 没有记账：无事可做，也不算错
	}
	if alive, _ := holderCheck(st.PID, st.Exe, realProc); alive {
		return false, nil // 宿主还在转发（另一个实例），别抢
	}
	if r == nil {
		r = ExecRunner{}
	}
	if err := apply(ctx, r, *st); err != nil {
		return false, err
	}
	if err := os.Remove(statePath); err != nil {
		return true, err
	}
	return true, nil
}

// apply 按记账里记的后端还原。
func apply(ctx context.Context, r Runner, st saved) error {
	// 记账里的"原状"就是我们自己的地址时，还原快照等于没关：
	// 走各后端的关闭路径（gnome 置 none、kde 收成 ProxyType=None、env 删文件）。
	if st.AlreadyOurs {
		b := lookup(st.backend())
		if b == nil {
			return fmt.Errorf("记账里的后端 %q 不认识，无法还原，请手工检查系统代理设置", st.Backend)
		}
		return b.Apply(ctx, r, Config{Enable: false, Backend: b.Name()})
	}
	switch st.backend() {
	case BackendKDE:
		if st.KDE == nil {
			return fmt.Errorf("记账里没有 KDE 快照，无法还原 %s", kdeProxyFile)
		}
		return RestoreKDE(*st.KDE)
	case BackendEnv:
		if st.Env == nil {
			return fmt.Errorf("记账里没有 env 快照，无法还原 %s", envProxyFile)
		}
		return RestoreEnv(*st.Env)
	case BackendGNOME:
		// 老记账没有 Backend 字段，saved.backend() 会把它算成 GNOME —— 那是兼容，
		// 不是兜底。真正不认识的名字必须报错，见下面 default。
		return applyGNOME(ctx, r, st)
	default:
		// 按 GNOME 还原一个不认识的后端，等于把 KDE/env 改过的东西
		// 用 gsettings 覆盖一遍：原状没回来，还多改了一处。
		return fmt.Errorf("记账里的后端 %q 还没接入还原，请手工检查系统代理设置", st.Backend)
	}
}

// applyGNOME 把记账里的读数逐键写回桌面。
func applyGNOME(ctx context.Context, r Runner, st saved) error {
	args, env := desktopPrefix()
	steps := [][]string{}
	// 与 Apply 同样的顺序纪律：值先摆好，mode 最后提交。
	if st.Mode == "manual" {
		httpHost, httpPort := split(st.HTTP, "127.0.0.1:7892")
		httpsHost, httpsPort := split(orDefault(st.HTTPS, st.HTTP), "127.0.0.1:7892")
		socksHost, socksPort := split(st.SOCKS, "127.0.0.1:7891")
		steps = append(steps,
			[]string{"gsettings", "set", schemaHTTP, "host", gvariantString(httpHost)},
			[]string{"gsettings", "set", schemaHTTP, "port", httpPort},
			[]string{"gsettings", "set", schemaHTTPS, "host", gvariantString(httpsHost)},
			[]string{"gsettings", "set", schemaHTTPS, "port", httpsPort},
			[]string{"gsettings", "set", schemaSOCKS, "host", gvariantString(socksHost)},
			[]string{"gsettings", "set", schemaSOCKS, "port", socksPort},
		)
		if len(st.Ignore) > 0 {
			steps = append(steps, []string{"gsettings", "set", schema, "ignore-hosts", gvariantList(st.Ignore)})
		}
	}
	steps = append(steps, []string{"gsettings", "set", schema, "mode", "'" + orNone(st.Mode) + "'"})
	for _, s := range steps {
		if out, err := r.Run(ctx, append(args, s...), env); err != nil {
			return fmt.Errorf("还原 gsettings %s %s: %w (%s)", s[2], s[3], err, out)
		}
	}
	return nil
}

// peekSaved 只看一眼记账，不做任何副作用。没有记账时返回 nil。
//
// 与 Restore 分开是因为这里问的是「上一轮还欠着还原吗」，
// 而不是「现在给我还原」——两者的失败处理方式不一样。
func peekSaved(path string) (*saved, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st saved
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("状态文件损坏，请手工恢复后删除 %s: %w", path, err)
	}
	return &st, nil
}

func writeState(path string, st saved) error {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, base), raw)
}

// procFS 是对 /proc 的读法，测试里换掉它就能造出「PID 被回收」「进程不归我们」这些现场。
// 自程序的身份也走口子：os.Executable 在测试里报什么错没法复现，
// 而「当前二进制读不到」恰恰是 holderAlive 必须保守处理的那一支。
type procFS struct {
	readlink func(string) (string, error)
	readFile func(string) ([]byte, error)
	self     func() string
}

var realProc = procFS{readlink: os.Readlink, readFile: os.ReadFile, self: procid.Self}

// holderCheck 判断记账里那个 PID 现在是不是「还在跑我们这个程序」，并配一句能直接印出来的原因。
//
// 四层，从权威到退化：
//  1. 进程不存在（kill 报 ESRCH）→ 死了，可以自愈；
//  2. /proc/<pid>/exe 读得到 → 直接比可执行路径。argv[0] 那种判断不能用来做这种决定：
//     改名、软链、exec -a 都会骗过去，而 PID 被回收给一个无关程序时也只会看名字认错；
//     重编译留下的 " (deleted)" 尾巴算同身份，否则每次改完代码重启都判成「不是我们」；
//  3. exe 读不到（进程不归这个 uid，比如旧实例是 sudo 起的）→ 只剩 world-readable 的 comm，
//     名字明确对不上才判死；
//  4. 两条线索都断了 → 按「还活着」处理。
//
// 判不出身份时按「还活着」处理，也就是**不**动桌面：少还原一次是桌面停在一个
// 已经不存在的端口上（整机断网，而且只报「代理连接被拒绝」），多还原一次是
// 用户自己改的设置被冲掉。前者用户不知道有 `-sysproxy off` 这条救法，后者知道
// ——所以拿不准的时候赌"什么都不做"，把决定权留给用户。
func holderCheck(pid int, exe string, fs procFS) (alive bool, why string) {
	if pid <= 0 {
		return false, "记账里没有一个有效的宿主进程号"
	}
	if err := syscall.Kill(pid, 0); err != nil && !errors.Is(err, syscall.EPERM) {
		return false, fmt.Sprintf("宿主 PID %d 已经不在了", pid)
	}
	// EPERM 是「进程在，只是不归我们动」（旧实例用 sudo 起过）。
	// 当成死了去自愈，等于抢走一个还在转发的实例的桌面设置。
	// 僵尸：号码还在、exe 链接已经没了，但它早就不转发任何东西了。
	// 把它算成"还活着"，这份记账就永远不敢自愈，桌面一直停在没人听的端口上。
	if st, err := procid.State(pid, fs.readFile); err == nil && st == 'Z' {
		return false, fmt.Sprintf("宿主 PID %d 已经是僵尸进程", pid)
	}
	want := exe
	if want == "" {
		want = fs.self() // 老记账没写 exe，只能拿当前这个二进制去比
	}
	if want == "" {
		return true, fmt.Sprintf("认不出 PID %d 是谁，也不知道本程序的可执行路径，按「还活着」处理", pid)
	}
	if link, err := procid.ExePath(pid, fs.readlink); err == nil {
		if procid.Same(link, want) {
			return true, fmt.Sprintf("宿主 PID %d 还开着（%s）", pid, link)
		}
		// 记账里写了路径 → 比出来不一样就是号码被回收，允许自愈。
		// 老记账没写路径时不能这么武断：同一个程序的两个构建
		// （命令行版 wps_app 与面板版 wps_app-gui）路径不同，
		// 于是普通用户跑一次 CLI，就会把一个还在转发的面板的桌面设置抢走。
		// 这一种再问一次进程名：名字对得上就不动桌面。
		if exe == "" {
			if name, nerr := procid.Comm(pid, fs.readFile); nerr == nil && sameProgram(name, filepath.Base(want)) {
				return true, fmt.Sprintf("宿主 PID %d 还开着（%s，与本机程序同名）", pid, link)
			}
		}
		return false, fmt.Sprintf("PID %d 现在跑的是 %s，不是记账里那个实例（进程号被回收了）", pid, link)
	}
	name, cerr := procid.Comm(pid, fs.readFile)
	if cerr != nil {
		return true, fmt.Sprintf("读不到 PID %d 的身份（%v），按「还活着」处理", pid, cerr)
	}
	if procid.NameMatches(name, want) {
		return true, fmt.Sprintf("宿主 PID %d 还开着（读不到可执行路径，按进程名 %s 认）", pid, name)
	}
	return false, fmt.Sprintf("PID %d 现在跑的是 %s，不是记账里那个实例（进程号被回收了）", pid, name)
}

// Ledger 是「上一轮启用还欠不欠一次还原」的读数，只用来回答诊断问题，没有任何副作用。
//
// 单独导出是因为这是全套系统代理逻辑里最难自己看出来的一处：桌面上写着 manual
// 指向一个没人听的端口时，只有这份记账知道「是谁改的、他还在不在、下次启动会不会自动还」。
type Ledger struct {
	Exists  bool      // 有没有记账文件
	PID     int       // 记账里的宿主进程号
	Exe     string    // 记账时本程序的可执行路径
	Backend string    // 改动走的是哪条路（gnome / kde / env）
	Holder  string    // 宿主现在是谁、还活着——一句可以直接印出来的话
	Alive   bool      // 宿主是否仍被认定为本程序的实例
	Stale   bool      // 记账还在、宿主确定不在了：下次启动会自动还原
	SavedAt time.Time // 记账时刻
	// AlreadyOurs 为真时，还原走的是「关掉」（各后端置 none / 删文件），
	// 而不是照快照再写一遍——因为那份快照本来就是本客户端的地址。
	AlreadyOurs bool
	// ReadErr 只在这份读数本身读不出来说话。留着损坏的记账是刻意的
	// （用户还能自己看一眼它原来记了什么），所以这里不能把它印成「没有记账」。
	ReadErr string
}

// ReadLedger 读一眼记账并判断宿主，不动桌面也不删文件。
func ReadLedger(statePath string) (Ledger, error) {
	st, err := peekSaved(statePath)
	if err != nil {
		return Ledger{ReadErr: err.Error(), Holder: "读不懂这份记账"}, err
	}
	if st == nil {
		return Ledger{}, nil
	}
	alive, why := holderCheck(st.PID, st.Exe, realProc)
	return Ledger{
		Exists:      true,
		PID:         st.PID,
		Exe:         st.Exe,
		Backend:     st.backend(),
		Holder:      why,
		Alive:       alive,
		Stale:       !alive,
		SavedAt:     st.SavedAt,
		AlreadyOurs: st.AlreadyOurs,
	}, nil
}

// sameProgram 认"同一个程序的两个构建"：wps_app 与 wps_app-gui 是同一份代码的
// 两种产物，测试跑起来又叫 sysproxy.test。只比 basename 会把它们当成三个程序，
// 于是普通用户跑一次 CLI 就能把面板的桌面设置抢走。
func sameProgram(holder, self string) bool {
	stem := func(s string) string {
		s = strings.TrimPrefix(strings.TrimSpace(s), "./")
		s = strings.TrimSuffix(s, "-gui")
		if i := strings.IndexByte(s, '.'); i > 0 {
			s = s[:i] // 去掉 .test / .app 这类运行时的尾巴
		}
		return s
	}
	a, b := stem(holder), stem(self)
	return a != "" && a == b
}

// orNone 把空的 mode 归一成 none。
func orNone(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return "none"
	}
	return mode
}
