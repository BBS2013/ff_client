// Command wps_app 是一个专注 hysteria2 协议的本地代理客户端。
// 提供 SOCKS5 与 HTTP 两个入站，按规则集在直连与代理之间分流。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"wps_app/internal/buildinfo"
	"wps_app/internal/config"
	"wps_app/internal/diag"
	"wps_app/internal/logx"
	"wps_app/internal/router"
	"wps_app/internal/service"
	"wps_app/internal/sysproxy"
	"wps_app/internal/tunx"
)

const dialTimeout = 15 * time.Second

// defaultConfigPath 是未指定配置文件时的默认值。
const defaultConfigPath = "./config.yaml"

// defaultCheckHost 是没写 -check-host 时唯一被巡检的目标。
const defaultCheckHost = "www.gstatic.com:443"

// targetsFlag 让 -check-host 既能重复给、也能逗号分隔，攒成一个列表。
//
// 它刻意不带默认值：默认目标在 parseArgs 末尾统一补。
// 把默认值当列表第一项的话，用户点名要查三个站，结果第一条永远是 gstatic，
// 汇总里的 ok 数也对不上他给的目标数。
type targetsFlag struct{ dst *[]string }

func (t targetsFlag) String() string {
	if t.dst == nil {
		return ""
	}
	return strings.Join(*t.dst, ",")
}

func (t targetsFlag) Set(s string) error {
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*t.dst = append(*t.dst, p)
		}
	}
	return nil
}

// boolFlags 是布尔开关，拆分参数时不吃掉后面那个参数。
var boolFlags = map[string]bool{"check": true, "gui": true, "cli": true, "h": true, "help": true, "tun-helper": true, "dial-helper": true, "version": true}

// splitArgs 把命令行拆成 flag 部分与位置参数部分。
// 标准库 flag.Parse 遇到第一个非 flag 参数就会停止，导致
// `wps_app /etc/wps_app/config.yaml -check` 里的 -check 被当成多余参数，
// 所以这里先手工分离，再交给 FlagSet 解析。
// `--` 之后一律视为位置参数。
func splitArgs(in []string) (flagArgs, positional []string) {
	for i := 0; i < len(in); i++ {
		a := in[i]
		if a == "--" {
			positional = append(positional, in[i+1:]...)
			return flagArgs, positional
		}
		if len(a) > 1 && a[0] == '-' {
			flagArgs = append(flagArgs, a)
			name := strings.TrimLeft(a, "-")
			if strings.ContainsRune(name, '=') {
				continue // 取值已内联在 -c=xxx 里
			}
			if !boolFlags[name] && i+1 < len(in) {
				i++
				flagArgs = append(flagArgs, in[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return flagArgs, positional
}

// options 是命令行选项的解析结果。
type options struct {
	configPath string
	checkOnly  bool
	checkHosts []string
	checkFetch []string
	gui        bool
	cliOnly    bool
	mode       string
	tunReset   bool
	sysProxy   string
	// diag 打印一份离线诊断报告后退出：不抢实例锁、不启停任何东西。
	diag bool
	// version 打印版本、源码指纹与构建时刻后退出；不读配置、不碰网络。
	version bool
	// logFile 让日志除原输出外再写一份到文件（0600，20MB × 3 轮转）。
	// GUI 没写这个参数时默认写 <config>.log；CLI 只有显式给了才写。
	logFile string
	// pprof 是可选的本机性能诊断监听地址（只允许回环）。默认关。
	pprof string
	// tunHelper 让同一个二进制以提权 helper 身份跑一次：面板把 argv 配上 sudo，
	// 自己则以普通用户身份保住系统托盘（见 internal/tunx/helper_linux.go）。
	tunHelper        bool
	tunHelperConnect string
	// dialHelper 让同一个二进制以**常驻**提权 helper 身份运行：面板保持一条连接，
	// 按需要一条"钉在指定网卡上、已连通"的 socket（见 internal/tunx/persistent_linux.go）。
	// 与 tun-helper 的差别只有"活多久、扛几次"：那个一次请求一个进程，这个一直活着。
	dialHelper        bool
	dialHelperConnect string
	dialHelperOwner   string
}

// newFlagSet 构造命令行选项集合。
func newFlagSet(o *options) *flag.FlagSet {
	fs := flag.NewFlagSet("wps_app", flag.ContinueOnError)
	fs.StringVar(&o.configPath, "c", "", "配置文件路径（也可写成唯一的位置参数）")
	fs.BoolVar(&o.checkOnly, "check", false, "只做连通性自检：连上服务端并逐个拨号后退出")
	fs.Var(targetsFlag{dst: &o.checkFetch}, "check-fetch",
		"经隧道真的取一个页面（http/https URL，逗号分隔）：状态码不是 2xx/3xx 即判失败")
	fs.Var(targetsFlag{dst: &o.checkHosts}, "check-host",
		"自检使用的目标地址，可重复给也可逗号分隔（默认 "+defaultCheckHost+"）")
	fs.BoolVar(&o.gui, "gui", false, "启动桌面控制面板与系统托盘（需用 gui 构建标签编译）")
	fs.BoolVar(&o.cliOnly, "cli", false, "强制命令行模式：只跑代理服务不开界面（gui 构建下也有效）")
	fs.StringVar(&o.mode, "mode", "", "本次运行使用的分流模式：rule | global | direct（不写回配置文件）")
	fs.BoolVar(&o.tunReset, "tun-reset", false, "清理 TUN 遗留的 iptables 劫持规则与网卡后退出")
	fs.StringVar(&o.sysProxy, "sysproxy", "", "设置桌面系统代理：on | off | restore | status（写完即退出）")
	fs.BoolVar(&o.diag, "diag", false, "打印一份离线诊断报告（口令已掩码、不碰外网）后退出")
	fs.BoolVar(&o.version, "version", false, "打印版本、源码指纹与构建时刻后退出")
	fs.StringVar(&o.logFile, "log-file", "", "日志同时写入这个文件（0600，20MB×3 轮转）；GUI 不写时默认 <config>.log")
	fs.StringVar(&o.pprof, "pprof", "", "开启 pprof 诊断监听（只允许回环地址，如 127.0.0.1:6060；默认关）")
	fs.BoolVar(&o.tunHelper, "tun-helper", false, "以 TUN 提权 helper 身份运行：连回面板、开/关网卡、退出（面板通过 tun.helper 配置唤起，需要 root）")
	fs.BoolVar(&o.dialHelper, "dial-helper", false, "以常驻提权 helper 身份运行：替面板造钉在指定网卡上的 socket（面板通过 tun.helper 配置唤起，需要 root）")
	fs.StringVar(&o.dialHelperConnect, "dial-helper-connect", "", "常驻 helper 要监听的套接字路径（由面板自动传入）")
	fs.StringVar(&o.dialHelperOwner, "dial-helper-owner", "", "常驻 helper 要把套接字交给哪个 uid（由面板自动传入）")
	fs.StringVar(&o.tunHelperConnect, "tun-helper-connect", "", "helper 模式下要连接的套接字路径（由面板自动传入，不用手写）")
	return fs
}

// printUsage 输出命令行用法。
func printUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "用法: wps_app [选项] [配置文件]\n\n选项:\n")
	fs.SetOutput(os.Stderr)
	fs.PrintDefaults()
}

// parseArgs 解析命令行。配置文件既可用 -c 指定，也可作为唯一的位置参数，
// 两种写法可以任意组合：`wps_app -c a.yaml -check` 与 `wps_app a.yaml -check` 等价。
// 出错时不自己打印，由调用方统一输出一份错误加一份用法。
func parseArgs(argv []string) (options, error) {
	var o options
	fs := newFlagSet(&o)
	fs.SetOutput(io.Discard)

	flagArgs, positional := splitArgs(argv)
	if err := fs.Parse(flagArgs); err != nil {
		return o, err
	}
	if len(positional) > 1 {
		return o, fmt.Errorf("多余的位置参数 %v", positional[1:])
	}
	if len(positional) == 1 {
		if o.configPath != "" && o.configPath != positional[0] {
			return o, fmt.Errorf("配置文件路径指定了两次（-c %s 与位置参数 %s）", o.configPath, positional[0])
		}
		o.configPath = positional[0]
	}
	if o.configPath == "" {
		o.configPath = defaultConfigPath
	}
	if len(o.checkHosts) == 0 && len(o.checkFetch) == 0 {
		// 默认目标只在"什么都没点名"时补。
		// 点名要取页面的人不该被一条他没要求的 gstatic 拨号巡检拖走退出码——
		// 本机直连 gstatic 经常是 reset 的，那条失败会被读成"我取的页面也没通"。
		o.checkHosts = []string{defaultCheckHost}
	}
	if len(o.checkFetch) > 0 {
		// 写了 -check-fetch 就是"我要验通不通"，不该还得手动配 -check，
		// 否则这条命令静默变成"正常启动代理服务"。
		o.checkOnly = true
	}
	return o, nil
}

func main() {
	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		var probe options
		fs := newFlagSet(&probe)
		if errors.Is(err, flag.ErrHelp) {
			printUsage(fs)
			os.Exit(0)
		}
		// -h / -help 属于主动查询用法，退出码用 0；其余是命令行用法错误，用 2。
		fmt.Fprintf(os.Stderr, "wps_app: %v\n\n", err)
		printUsage(fs)
		os.Exit(2)
	}
	if err := runCLI(opts); err != nil {
		fmt.Fprintf(os.Stderr, "wps_app: %v\n", err)
		os.Exit(1)
	}
}

// runCLI 是 CLI 模式的入口，需要界面时改走 GUI 装配。
func runCLI(o options) error {
	if o.version {
		fmt.Println(buildinfo.Summary())
		// 第二行是给机器读的：面板在唤起 root 之前会拿同一个二进制跑一次 -version，
		// 用这个数比一比「tun.helper 那个文件是不是和我同一份提权协议」。
		// 为什么值得单列一行：版本对不上是「此后再试多少次都一样」的失败，
		// 而发现它的代价本来是一次 sudo + 一个 root 进程 + 一条注定被拒的应答。
		fmt.Printf("提权协议 %d\n", tunx.HelperProto())
		return nil
	}
	// 显式给了 -log-file 就现在打开：一键式命令（-check/-diag/-sysproxy）也照写。
	// GUI 的默认日志在 runGUI 里按 <config>.log 打开，避免与这里重复。
	logOpened := false
	if o.logFile != "" {
		if closer, err := openLogFile(o.logFile); err != nil {
			logx.Warnf("日志文件打不开（%s）: %v；继续只用原输出", o.logFile, err)
		} else {
			defer func() { _ = closer.Close() }()
			logOpened = true
			logx.Infof("日志同时写入 %s（%dMB × %d 轮转）", o.logFile, logx.DefaultMaxBytes>>20, logx.DefaultBackups)
		}
	}
	if o.pprof != "" {
		addr, err := pprofListenAddr(o.pprof)
		if err != nil {
			return err
		}
		go func() {
			logx.Warnf("pprof 已开启：%s（只监听回环；诊断完请重启关掉）", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				logx.Warnf("pprof 退出: %v", err)
			}
		}()
	}
	if o.tunHelper {
		return tunHelperCommand(o.tunHelperConnect)
	}
	if o.dialHelper {
		return dialHelperCommand(o.dialHelperConnect, o.dialHelperOwner)
	}
	if o.tunReset {
		return tunCleanup(o.configPath)
	}
	if o.sysProxy != "" {
		return sysProxyCommand(o.sysProxy, o.configPath)
	}
	if o.diag {
		return diagReport(o.configPath)
	}
	if wantGUI(o) {
		return runGUI(o.configPath, o.logFile, logOpened)
	}
	return run(o.configPath, o.checkOnly, o.checkHosts, o.checkFetch, o.mode)
}

// openLogFile 把相对路径钉成绝对路径再打开：调用方可能在 runGUI 里 chdir，
// 相对路径会在打开之后指向别处，轮转时就会把新文件建到错误目录。
func openLogFile(path string) (io.Closer, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	return logx.SetFileOutput(abs, logx.DefaultMaxBytes, logx.DefaultBackups)
}

// pprofListenAddr 只放行回环地址。
//
// pprof 的堆快照里有访问过的域名、连接目标与令牌；把一个默认关的诊断口
// 开到 0.0.0.0 等于给局域网发一份运行期内存转储。这里宁可拒绝，
// 也不做"先开再提醒"的自动降级。
func pprofListenAddr(raw string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("-pprof %q: %w", raw, err)
	}
	if port == "" {
		return "", fmt.Errorf("-pprof %q: 缺端口", raw)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("-pprof %q: 只允许回环地址（127.0.0.1 或 ::1）", raw)
	}
	return net.JoinHostPort(host, port), nil
}

// wantGUI 决定这次启动是开桌面界面还是只跑代理服务。
//
// defaultGUI 由构建标签给出：带 gui 标签的产物（wps_app-gui）默认开界面，
// 从文件管理器双击就能出窗口，不必先记住要带 -gui；不带标签的 wps_app 仍是
// 纯命令行，systemd 部署路径不受影响。-cli 是反向开关，需要在 gui 构建上
// 跑纯服务端时用它（比如无桌面的机器上排查问题）。
//
// -check 自带「连一下就退出」的语义，所以压过默认开界面；但显式写了 -gui 时
// 仍然开界面，这与本次改动前的行为一致（那时只有 -gui 一条判据）。
func wantGUIWith(o options, defaultGUI bool) bool {
	if o.gui {
		return true
	}
	if o.checkOnly {
		return false
	}
	return defaultGUI && !o.cliOnly
}

func wantGUI(o options) bool { return wantGUIWith(o, guiDefault) }

// run 只做信号循环，装配与启停都委派给 service.Service。
// GUI 模式走的是同一份 service 逻辑，两边行为因此不会漂移。
func run(configPath string, checkOnly bool, checkHosts, checkFetch []string, mode string) error {
	svc := service.New(configPath, nil)
	if mode != "" {
		// 必须在 Prepare 之前定下来：Prepare 里装配路由器时就会用它。
		m, err := config.ParseMode(mode)
		if err != nil {
			return err
		}
		if err := svc.OverrideMode(m); err != nil {
			return err
		}
	}
	if err := svc.Prepare(); err != nil {
		return err
	}
	defer func() { _ = svc.Stop() }()

	if checkOnly {
		// 两条巡检都做时，先拨号后取页面：拨号失败时原因更靠前（电路就没通），
		// 取页面的报错则专门负责"电路通了但那一跳没把页面带回来"。
		// checkHosts 为空是 -check-fetch 单独使用时的正常形状（见 parseArgs），
		// 这时不硬塞一个默认目标去失败。
		if len(checkHosts) == 0 && len(checkFetch) == 0 {
			return errors.New("自检没给任何目标：-check-host 与 -check-fetch 至少要写一个")
		}
		var dialErr error
		if len(checkHosts) > 0 {
			dialErr = selfCheck(svc.Router(), checkHosts, os.Stdout)
		}
		if len(checkFetch) == 0 {
			return dialErr
		}
		fetchErr := fetchCheck(svc.Router(), checkFetch, checkPerTargetTimeout, os.Stdout)
		if dialErr != nil {
			return dialErr
		}
		return fetchErr
	}
	// 崩溃自愈：上一次若是异常退出，桌面还停在 mode=manual 指向一个
	// 已经不存在的端口。这里顺手还债，避免用户一启动就发现整机没网。
	func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer rcancel()
		done, err := sysproxy.RecoverIfStale(rctx, nil, sysproxy.StatePath(configPath))
		if err != nil {
			logx.Warnf("上次异常退出后还原系统代理失败: %v", err)
		} else if done {
			logx.Infof("检测到上次异常退出，已把桌面系统代理还原回原样")
		}
		if w := sysproxy.OrphanWarning(rctx, nil, sysproxy.StatePath(configPath), sysProxyTarget(configPath)); w != "" {
			logx.Warnf("%s", w)
		}
	}()
	if err := svc.Start(); err != nil {
		return err
	}
	// 正常退出（含 SIGINT/SIGTERM）时还原桌面系统代理。
	// 开着它而进程没了的话，桌面会永远停在 mode=manual 指向一个
	// 已经关闭的端口：整机断网，且只报一句「代理连接被拒绝」。
	// 崩溃/SIGKILL 那一路由下次启动的 sysproxy.RecoverIfStale 兜底。
	defer func() {
		rctx, rcancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer rcancel()
		statePath := sysproxy.StatePath(configPath)
		target := sysProxyTarget(configPath)
		if err := sysproxy.Restore(rctx, nil, statePath); err != nil {
			logx.Errorf("退出时还原系统代理失败（桌面可能仍指向本客户端的已关闭端口，可手工跑 -sysproxy restore）: %v", err)
			return
		}
		// 没有记账时上面那句是空操作，而桌面完全可能指着这些端口——上一轮的账被
		// 别的实例吃掉了。退出前必须再兜一次，否则进程没了、桌面还留着，
		// 全机应用一起去连一个已经不存在的端口，只报一句「代理连接被拒绝」。
		// 面板退出在 internal/ui 里做同样一层，两条路都得收干净。
		orphan, err := sysproxy.IsOrphan(rctx, nil, statePath, target)
		if err != nil {
			logx.Warnf("退出时确认桌面代理归属失败，保持原样: %v", err)
			return
		}
		if !orphan {
			return
		}
		if err := sysproxy.Disable(rctx, nil, statePath, target.Backend); err != nil {
			logx.Errorf("退出时关掉桌面系统代理失败（可用 -sysproxy off 手工关掉）: %v", err)
			return
		}
		logx.Infof("桌面系统代理指着本客户端却没有记账，退出时已切回关闭")
	}()
	logx.Infof("发送 SIGHUP 重载规则与 GeoIP，SIGINT/SIGTERM 退出")

	// --- 信号处理 ---
	hup := make(chan os.Signal, 1)
	stop := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(hup)
	defer signal.Stop(stop)

	for {
		select {
		case <-hup:
			logx.Infof("收到 SIGHUP，重载 GeoIP 与规则")
			if err := svc.Reload(); err != nil {
				logx.Errorf("重载失败: %v", err)
			}
		case <-stop:
			logx.Infof("收到退出信号，正在关闭")
			return nil
		}
	}
}

// tunCleanup 拆掉 TUN 可能留下的 iptables 劫持规则。
//
// TUN 模式会往 nat 表里挂 :53 重定向，进程被 kill -9 时这些规则不会自己消失，
// 而它指向的假 DNS 地址随网卡一起没了——后果是本机解析全部超时。
// 这条命令是给「机器 DNS 突然坏了、怀疑是上次 TUN 没关干净」准备的一键复位。
func tunCleanup(configPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// 能读到配置就按它的网卡名与地址精确清理；读不到就按默认名兜底扫一遍。
	device, address := config.DefaultTUN().Device, config.DefaultTUN().Address
	var helper []string
	if cfg, err := config.Load(configPath); err == nil {
		device, address, helper = cfg.TUN.Device, cfg.TUN.Address, cfg.TUN.Helper
	} else if configPath != "" {
		logx.Debugf("读配置失败，按默认网卡名清理: %v", err)
	}
	var cleaned []string
	if len(helper) > 0 {
		// 配了提权命令就必须让它来清：本进程是普通用户时，
		// 直接在下面跑 iptables 会全军覆没，而「残留没清」正是整机 DNS 挂掉那个坑。
		reply, _, err := tunx.HelperClient{Argv: helper}.Run(ctx, tunx.CleanupRequest(os.Geteuid(), device, address))
		if err != nil {
			return fmt.Errorf("经 tun.helper 清理残留失败: %w", err)
		}
		cleaned = reply.Removed
	} else {
		cleaned = tunx.CleanupStale(ctx, nil, os.Geteuid(), device, address)
		// -tun-reset 是「网络不对劲」时的应急入口，故障断网保护的那条链正是会造出
		// 这种症状的东西：本机出站被白名单收着，而留下它的那个进程早就没了。
		cleaned = append(cleaned, tunx.CleanupKill(ctx, nil)...)
	}
	logx.Infof("TUN 残留清理完成：%d 项（网卡本身随进程退出消失）", len(cleaned))
	return nil
}

// tunHelperCommand 是提权 helper 的入口。
//
// 它不读配置文件、不开监听、不碰代理：root 侧能做的事越少越好审查，
// 全部行为由面板发来的一份已校验 RoutePlan 决定。
func tunHelperCommand(path string) error {
	if path == "" {
		return errors.New("--tun-helper 需要 --tun-helper-connect=<面板给的套接字路径>（这个参数由面板自动加上，手写时别漏）")
	}
	return tunx.RunHelperForMain(path, 25*time.Second)
}

// parseDialHelperOwner 把 --dial-helper-owner 的值翻成 uid。
//
// **0 必须判为合法**：它表示「面板自己就是 root」（整个面板由 sudo 拉起时 os.Getuid()
// 就是 0），那时套接字本来就归 root，helper 侧的 chown 跳过即可，不是错误。
// 判 "uid <= 0" 时这条最大的真实取值会被拒，症状极具误导性——helper 明明收到了
// owner 参数，却报「需要 --dial-helper-owner」，看上去像参数没传过来。
// 空串与非数字仍算「没传」：老版本的唤起方就得被这里挡住。
func parseDialHelperOwner(owner string) (int, error) {
	uid, err := strconv.Atoi(strings.TrimSpace(owner))
	if err != nil || uid < 0 {
		return 0, errors.New("--dial-helper 需要 --dial-helper-owner=<面板的 uid>（由面板自动加上）")
	}
	return uid, nil
}

// dialHelperCommand 是常驻提权 helper 的入口。
//
// 与 tunHelperCommand 同一个纪律：它不读配置、不碰代理、不看用户的流量，
// 只做一件事——替面板造一条钉在指定网卡上、且已连通的 socket。
// TLS 仍然终结在面板与节点之间，所以 root 看不到任何明文。
func dialHelperCommand(path, owner string) error {
	if path == "" {
		return errors.New("--dial-helper 需要 --dial-helper-connect=<套接字路径>（由面板自动加上）")
	}
	uid, err := parseDialHelperOwner(owner)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	return tunx.RunDialHelper(ctx, path, uid)
}

// diagReport 打印诊断报告。
//
// 它刻意走"早退"那一条路：不碰实例锁、不建服务。
// 面板还活着的时候才是这份报告最被需要的时候，
// 而那时候端口与锁都被占着——照常规启动路径走，会直接把旧实例接管掉。
func diagReport(configPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return diag.Report(ctx, configPath, os.Stdout)
}

// sysProxyTarget 从配置里凑出一次系统代理操作的意图：走哪条后端、指哪两个端口。
//
// 三条使用路径（-sysproxy on、状态输出、启动时的孤儿检查）共用同一个答案，
// 判据本身在 config 里，那边能单测。
func sysProxyTarget(configPath string) sysproxy.Config {
	target := sysproxy.Config{Enable: true}
	cfg, err := config.Load(configPath)
	if err != nil {
		return target // 配置读不到就用本机默认入站：与 sysproxy 自己的兜底同一套
	}
	target.Backend, target.HTTPAddr, target.SOCKSAddr = cfg.SystemProxyTarget()
	return target
}

// sysProxyCommand 在无界面时也能开关桌面系统代理。
//
// 与 GUI 里的开关走的是同一份 sysproxy 逻辑，因此两条路径的行为不会漂移；
// 它同时是唯一能在没有窗口时确认「系统代理到底指到哪儿了」的入口。
//
// on/off 都经过记账状态文件：on 会先记下改动前的读数，off 按那份记录还原。
// restore 是给「上次崩了、桌面还指着一个已经不存在的端口」准备的补救命令。
func sysProxyCommand(action string, configPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	statePath := sysproxy.StatePath(configPath)
	target := sysProxyTarget(configPath)
	backend := target.Backend
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "on":
		if err := sysproxy.Enable(ctx, nil, statePath, target); err != nil {
			return err
		}
	case "off":
		if err := sysproxy.Disable(ctx, nil, statePath, backend); err != nil {
			return err
		}
	case "restore":
		if err := sysproxy.Restore(ctx, nil, statePath); err != nil {
			return err
		}
		fmt.Printf("已尝试按 %s 还原系统代理（没有记账文件时是空操作）\n", statePath)
	case "status":
	default:
		return fmt.Errorf("-sysproxy 只接受 on | off | restore | status，收到 %q", action)
	}
	st, err := sysproxy.ReadWith(ctx, nil, backend)
	if err != nil {
		return err
	}
	if !st.Supported {
		fmt.Println("UNSUPPORTED 这台机器上 gsettings / kioslaverc / environment.d 都用不了")
		return nil
	}
	fmt.Printf("%s backend=%s mode=%s http=%s socks=%s ignore=%s\n",
		map[bool]string{true: "ON", false: "OFF"}[st.Enabled], st.Backend, st.Mode, st.HTTP, st.SOCKS, strings.Join(st.Ignored, ","))
	if st.Path != "" {
		fmt.Printf("     改动落在 %s（删掉或改回它即完全还原）\n", st.Path)
	}
	if st.Note != "" {
		fmt.Printf("     注意：%s\n", st.Note)
	}
	printLedger(os.Stdout, statePath, st, target)
	return nil
}

// printLedger 说清「上一轮改动还欠不欠一次还原」。
//
// 桌面读数答不了这个问题：它只知道现在设置指到哪儿，不知道为什么。
// 而整机断网最难受的那一种——上一轮崩在启用状态下——只有这份记账知道
// 改的人是谁、他还在不在、下次启动会不会自动还。四种情况必须四种话，
// 把「读不懂」印成「没有记账」会让用户以为一切正常。
func printLedger(w io.Writer, statePath string, st sysproxy.Status, target sysproxy.Config) {
	led, err := sysproxy.ReadLedger(statePath)
	at := "时间未知"
	if !led.SavedAt.IsZero() {
		at = led.SavedAt.Format("2006-01-02 15:04:05")
	}
	ours := ""
	if led.AlreadyOurs {
		ours = "，还原时直接关掉（改动前就指着本程序）"
	}
	switch {
	case err != nil:
		fmt.Fprintf(w, "     记账 %s 读不懂：%s\n"+
			"     先手工核对桌面设置，确认后再决定要不要删掉这个文件\n", statePath, led.ReadErr)
	case !led.Exists:
		fmt.Fprintf(w, "     没有记账：桌面上这组设置不是本程序改的，退出不欠还原\n")
		// 上面那句只在"桌面没指着我们"时成立。指着我们却没记账，
		// 是上一轮的记账被吃掉的那一种：本进程一退出，桌面就指向没人听的端口。
		if sysproxy.LikesOurs(st, target) {
			fmt.Fprintf(w, "     警告：%s\n", sysproxy.OrphanHint(statePath))
		}
	case led.Alive:
		fmt.Fprintf(w, "     记账 %s（%s 由 %s 后端记下）：%s%s\n     宿主还在，不会自动还原\n",
			statePath, at, led.Backend, led.Holder, ours)
	default:
		fmt.Fprintf(w, "     记账 %s（%s 由 %s 后端记下）：%s%s\n     下次启动会自动还原；急用可跑 -sysproxy restore\n",
			statePath, at, led.Backend, led.Holder, ours)
	}
}

// selfCheck 建立一次代理连接验证端到端可用性。
// checkDial 拨一个目标并回报命中结果；连接在返回前关掉。
type checkDial func(ctx context.Context, target string) (router.Result, error)

// checkPerTargetTimeout 是单个巡检目标的预算。
const checkPerTargetTimeout = 40 * time.Second

// selfCheck 用路由器逐个巡检给定的目标。
func selfCheck(rt *router.Router, targets []string, w io.Writer) error {
	return checkTargets(dialOnce(rt), targets, checkPerTargetTimeout, w)
}

func dialOnce(rt *router.Router) checkDial {
	return func(ctx context.Context, target string) (router.Result, error) {
		conn, res, err := rt.Dial(ctx, target)
		if err != nil {
			return router.Result{}, err
		}
		defer conn.Close()
		return res, nil
	}
}

// checkTargets 逐个巡检并把每目标一行结果写出去，任一失败则整体返回错误。
//
// 三件事是刻意的：
//  1. 不 fail-fast。巡检要回答的是「哪一类不通」，第一个失败就退出等于
//     只回答了一个，用户分不清是隧道整体没起来还是只有某条规则的路劲有问题。
//  2. 每个目标各自一份预算，而且由这里用 select 兜住：下游不认 ctx 时
//     （DNS 卡在内核路径、TUN 半死）也不能拖死整轮。
//  3. 每行都带上命中的规则与出站，一次巡检顺带验了分流。
//
// 「OK」的含义按出站方向分两种，别读成"源站可达"：
// DIRECT 是真的和本地地址建成了 TCP；PROXY 只证明到节点的电路建好了，
// 最后一跳由节点去连——连一个关闭的端口这里照样是 OK。
// 要验目标本身通不通，得再看后面的应用层请求。
func checkTargets(dial checkDial, targets []string, budget time.Duration, w io.Writer) error {
	if len(targets) == 0 {
		return errors.New("没有可巡检的目标")
	}
	failed := make([]string, 0, len(targets))
	for _, target := range targets {
		res, err := dialWithDeadline(dial, target, budget)
		if err != nil {
			failed = append(failed, target)
			logx.Warnf("自检失败: %s: %v", target, err)
			fmt.Fprintf(w, "FAIL %s %v\n", target, err)
			continue
		}
		logx.Infof("自检通过: %s 经 %s 出站（命中 %s）", target, res.Outbound, res.Matched)
		fmt.Fprintf(w, "OK %s via %s matched=%s\n", target, res.Outbound, res.Matched)
	}
	fmt.Fprintf(w, "SUMMARY ok=%d fail=%d total=%d\n", len(targets)-len(failed), len(failed), len(targets))
	if len(failed) > 0 {
		return fmt.Errorf("%d/%d 个目标自检失败: %s", len(failed), len(targets), strings.Join(failed, ", "))
	}
	return nil
}

// dialWithDeadline 给单次拨号套一个自己的预算。
//
// 超时后那个 goroutine 会留在原地：这条命令跑完就退出，
// 比「为了不留 goroutine 而让整轮巡检挂死」划算。
func dialWithDeadline(dial checkDial, target string, budget time.Duration) (router.Result, error) {
	type outcome struct {
		res router.Result
		err error
	}
	ch := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	go func() {
		res, err := dial(ctx, target)
		ch <- outcome{res: res, err: err}
	}()
	select {
	case o := <-ch:
		return o.res, o.err
	case <-ctx.Done():
		return router.Result{}, fmt.Errorf("超时（预算 %s）", budget)
	}
}
