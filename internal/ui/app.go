// Package ui 是 GUI 的绑定层：把 service.Service 与 metrics.Registry 的状态
// 投影成前端能直接用的普通值，经 Wails 送到 WebView。
//
// 刻意不 import wails 本身。Wails 的 Bind 只需要一个带导出方法的结构体，
// 参数与返回值可 JSON 序列化即可，框架类型一概不必出现在这一层。带来的好处是
// 这一整层能在默认构建（无 gui 标签、无 CGO）下跑 go test ./...，
// 绑定逻辑的正确性不必等真出窗才能验证。
package ui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/diag"
	"wps_app/internal/logx"
	"wps_app/internal/metrics"
	"wps_app/internal/rules"
	"wps_app/internal/service"
	"wps_app/internal/sysproxy"
	"wps_app/internal/tunx"
)

// diagFileName 是面板导出的诊断报告名，固定不变（每次覆盖）。
const diagFileName = "wps_app-diag.txt"

// 环形缓冲的容量：历史连接 500 条，速率序列 900 点（15 分钟）。
const (
	historyCap = 500
	seriesCap  = 900
)

// App 是 Wails 绑定的唯一结构体。所有导出方法都会被前端调用，
// 因此参数与返回值必须可 JSON 序列化，且不要返回 error 之外的内部状态。
type App struct {
	svc  *service.Service
	logs *logBuffer
	// startedAt 是本进程启动时刻，只为「磁盘上的二进制比这份界面新」那一格而留着
	// （见 buildinfo.go）。
	startedAt time.Time
	// removeHook 在 Close 时摘掉日志钩子，防止反复 New 之后钩子越挂越多。
	removeHook func()
	// lastLedger 是上一次投影给界面的记账状态，只为"变化时才写日志"而留着。
	// 它必须和 ledgerMu 成对使用：绑定方法会被 Wails 派到别的 goroutine 上调，
	// 而 Close 在主 goroutine 上读它。
	ledgerMu   sync.Mutex
	lastLedger SysProxyLedger
	// sysProxyMu 护着下面那个标志：「停止」与「启动」两条路都会碰它，
	// 而绑定方法跑在 Wails 的其它 goroutine 上。
	sysProxyMu sync.Mutex
	// sysProxyPaused 记的是「桌面上这根指向本程序的指针，是刚才那次停止替用户拔掉的」。
	// 只有为这个原因关掉的，启动时才该原样放回去；用户自己关的、或原来就不是我们的，
	// 都不该由启动来替他改桌面。
	sysProxyPaused bool
}

// New 装配 GUI 用的服务与统计。它会注册一个日志钩子并启动速率采样 goroutine，
// 用完必须调 Close，否则钩子会一直挂着。
func New(cfgPath string) *App {
	reg := metrics.NewRegistry(historyCap, seriesCap)
	usagePath := metrics.UsagePath(cfgPath)
	prior, err := metrics.LoadUsage(usagePath)
	switch {
	case err == nil:
		// 先 EnableUsage 再 StartSampler：那条 goroutine 起来之后才读路径，
		// 反过来就是"第一分钟不会落盘"。
		reg.EnableUsage(usagePath)
		reg.ApplyPrior(prior)
		if len(prior.Nodes) > 0 {
			reg.SetUsageOutcome(metrics.UsageLoaded)
		}
	case errors.Is(err, metrics.ErrUsageTooNew):
		// 比本程序新的账本：既不套用（格式没读过，套了就是猜），也不回写
		// （回写会把它的新字段抹掉）。于是这一栏退回"只有本次会话"，
		// 界面上那句"累计"也就跟着不出现——不出现比出现但错要好。
		reg.SetUsageOutcome(metrics.UsageTooNew)
		logx.Warnf("节点用量账本是本程序不认识的新格式，这一轮只报本次会话的量，也不会写回去: %v", err)
	default:
		// 读不出来的那份已经被挪去 .bad 了（见 LoadUsage），所以照常开写。
		reg.SetUsageOutcome(metrics.UsageUnreadable)
		logx.Warnf("节点用量账本读不出，本次从空账开始（坏掉的那份留在原地备查）: %v", err)
		reg.EnableUsage(usagePath)
	}
	reg.StartSampler()
	a := &App{
		svc:       service.New(cfgPath, reg),
		logs:      newLogBuffer(logCapacity),
		startedAt: time.Now(),
	}
	a.removeHook = logx.AddHook(a.logs.add)
	// 崩溃自愈：上一次如果是异常退出（崩溃 / kill -9），桌面会永远停在
	// mode=manual 指向一个已经不存在的端口——整机断网，且只报「代理连接被拒绝」。
	// 崩掉的进程没有机会执行清理，所以由这次启动来还债。
	if done, err := a.recoverStaleSysProxy(); err != nil {
		logx.Warnf("上次异常退出后还原系统代理失败，桌面可能仍指向本客户端的已关闭端口: %v", err)
	} else if done {
		logx.Infof("检测到上次异常退出，已把桌面系统代理还原回原样")
	}
	// 记账那一行不在这里读：它可能要再问一次桌面后端，
	// 留给前端每次显示窗口时的 pollSys（也免得每个测试进程都去碰真桌面）。
	return a
}

// sysProxyTarget 取配置里的系统代理意图（后端 + 两个入站地址）。
// 配置读不到时全空，由 sysproxy 按本机默认入站兜底。
func (a *App) sysProxyTarget() (backend, http, socks string) {
	if cfg, err := config.Load(a.svc.ConfigPath()); err == nil {
		return cfg.SystemProxyTarget()
	}
	return "", "", ""
}

// recoverStaleSysProxy 只在「记账里的进程已经不在」时才动桌面。
func (a *App) recoverStaleSysProxy() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sysproxyTimeout)
	defer cancel()
	return sysproxy.RecoverIfStale(ctx, sysxRunner, sysproxy.StatePath(a.svc.ConfigPath()))
}

// Close 释放统计 goroutine 与日志钩子，并停掉代理。不保证幂等之外的语义。
func (a *App) Close() error {
	if a.removeHook != nil {
		a.removeHook()
		a.removeHook = nil
	}
	a.svc.Metrics().StopSampler()
	// 先收桌面指针再关端口，和 Stop 同一个顺序：反过来就留出一个
	// 「mode=manual 指着一个正在被关闭的端口」的窗口，而那个窗口的表现是整机断网。
	relErr := a.releaseSystemProxy("退出")
	err := a.svc.Stop()
	if relErr != nil && err == nil {
		err = relErr
	}
	return err
}

// 刻意不把底层 service 导出成方法。Wails 会把绑定结构体的每个导出方法都挂到
// window.go.ui.App 上，而 *service.Service 里含 mutex 与 listener，序列化不出
// 有意义的结果。需要底层的调用方（同包的托盘）直接用 a.svc 即可。

// logFileName 是「导出日志」落在配置文件旁边的名字。
// 与诊断报告同一套规矩：固定名字、每次覆盖，带时间戳的名字会把配置目录变成日志堆。
const logFileName = "wps_app-log.txt"

// ExportLogs 把面板内存里那份日志环形缓冲写成文件，返回它的绝对路径。
//
// 存在的理由：出问题的时刻往往已经滚过去了，而"把刚才那二十分钟发给别人看"
// 今天只能开终端去 tail 一个不一定存在的文件——面板是双击启动的，
// 那种情况下 stdout 根本没有去处，日志只活在这 1000 条里。
//
// 前言里必须写清三件事，否则这份文件会被当成完整历史使用：
// 它只有最近 1000 条、更老的已被覆盖；单条超长的带着"已截断"标记；
// 以及**里面有访问过的域名**——那是浏览记录，所以权限给到 0600，
// 而不是诊断报告那种"可以直接贴给别人"的默认值。
func (a *App) ExportLogs() (string, error) {
	path := filepath.Join(filepath.Dir(a.svc.ConfigPath()), logFileName)
	page := a.logs.page(0)
	var b strings.Builder
	b.WriteString("wps_app 面板日志导出\n\n")
	b.WriteString("导出时间：" + time.Now().Format("2006-01-02 15:04:05") + "\n")
	fmt.Fprintf(&b, "共 %d 条。这是内存里那份环形缓冲的全部（上限 %d 条），"+
		"更老的已经被覆盖；要长期留档请在启动时把输出重定向到文件。\n", len(page.Entries), logCapacity)
	b.WriteString("单条超过 8 KiB 的带着「已截断，原长 N 字节」的标记。\n")
	b.WriteString("口令与订阅地址里的 token 已按诊断报告同一套规则掩过。\n")
	b.WriteString("注意：里面有本机访问过的域名，等于一份浏览记录——0600，别贴到公开的地方。\n")
	b.WriteString(strings.Repeat("-", 72) + "\n")
	for _, e := range page.Entries {
		fmt.Fprintf(&b, "%s %-5s %s\n", e.Time, e.Level, e.Msg)
	}
	if err := os.WriteFile(path, []byte(diag.MaskText(a.svc.ConfigPath(), b.String())), 0o600); err != nil {
		return "", fmt.Errorf("写 %s 失败: %w", path, err)
	}
	logx.Infof("日志已写出：%s（%d 条，口令已掩码）", path, len(page.Entries))
	return path, nil
}

// FetchPage 让面板真取一个页面回来（见 service.PageFetch 为什么存在）。
//
// 预算是 `service.FetchBudget`（15 秒）：这一问是人在界面前等着的，比命令行那条
// （每目标一份预算）要短，但也必须够走完一次 TLS 握手加一个慢站点。
// 超时走 error，但那句不是 Go 的 socket 原文——service 那侧换成了
// "<拨到的地址> 在 15 秒内没回话（这一格的预算就是 15 秒）"，
// 因为界面上摆着 `read tcp 127.0.0.1:37292->…: i/o timeout` 没人看得懂在等什么。
func (a *App) FetchPage(raw string) (service.PageFetch, error) {
	ctx, cancel := context.WithTimeout(context.Background(), service.FetchBudget)
	defer cancel()
	return a.svc.FetchPage(ctx, raw)
}

// ProbeDNS 问一次当前解析器：这批 IP 是什么、引擎会照着它们判成什么。
//
// 预算给 5 秒：解析器自己那份 timeout 通常是 2~3 秒，多个上游是并行问的，
// 5 秒足够它问完并退回，又不至于让人在界面前干等一次 DNS 故障。
// 与 FetchPage 同一个规矩：**问不出地址不是查询失败**（那走 Note），
// 只有"没在跑"与"没填名字"这两种问不出来的才报 error。
//
// fresh=true 是界面上「重问（不用缓存）」那一下：它会**写回缓存**，
// 也就是改掉引擎下一刻的判定依据，不是一次只读查看。
// upstream 非空是「只重问这一家」：只问那一个上游并写回，合并那一路刻意不再走。
// 两个都给时以 upstream 为准（见 service.ProbeDNS）。
func (a *App) ProbeDNS(host string, fresh bool, upstream string) (service.DNSProbe, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.svc.ProbeDNS(ctx, host, fresh, upstream)
}

// ---------- 状态与控制 ----------

// ExportDiagnostics 把离线诊断报告写到配置文件旁边，返回它的绝对路径。
//
// 存在的理由：会开面板的人未必愿意开终端。报告本身不含口令（见 internal/diag），
// 所以这一句"点一下就能贴给别人"是安全的。
// 固定文件名、每次覆盖：带时间戳的名字会把配置目录变成日志堆。
func (a *App) ExportDiagnostics() (string, error) {
	path := filepath.Join(filepath.Dir(a.svc.ConfigPath()), diagFileName)
	f, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("写 %s 失败: %w", path, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Report 只在建服务之外读配置与桌面，不碰监听端口，所以面板运行中也能跑。
	rerr := diag.Report(ctx, a.svc.ConfigPath(), f)
	if cerr := f.Close(); cerr != nil && rerr == nil {
		rerr = cerr
	}
	if rerr != nil {
		return "", rerr
	}
	logx.Infof("诊断报告已写出：%s（不含口令）", path)
	return path, nil
}

// Status 返回服务状态总览。
func (a *App) Status() service.Snapshot { return a.svc.Snapshot() }

// Start 启动代理。已在运行时等价于重启。
//
// 端口真的绑上之后再放回桌面指针：inboundAddrs 取的是实际监听的地址，
// 先写桌面等于把用户导向一个还没在收流量的端口。
func (a *App) Start() error {
	if err := a.svc.Start(); err != nil {
		return err
	}
	a.restoreSystemProxy(false, "启动")
	return nil
}

// Stop 停止代理，端口立即释放。未运行时是空操作。
//
// 释放端口前先拔掉桌面上指着它们的指针。「停止代理」要的是"不过代理了"，
// 而不是"上不了网"：只要 mode 还是 manual 指向 127.0.0.1:7892，
// 端口一关，全机遵循系统代理的程序就都报「代理连接被拒绝」，
// 看上去和网络挂了一模一样。
func (a *App) Stop() error {
	relErr := a.releaseSystemProxy("停止")
	err := a.svc.Stop()
	// 停下来是这份账最自然的落盘点：用户按完"停止"很可能就直接关窗口，
	// 而定时那一次最快也要等一分钟，最后这段流量正好落在缝里。
	if ferr := a.svc.Metrics().FlushUsage(); ferr != nil {
		logx.Warnf("停止时节点用量没落盘: %v", ferr)
	}
	if err != nil {
		return err
	}
	// 端口已经关了，这一步失败必须让用户知道：那意味着桌面还挂着一根死指针。
	return relErr
}

// Restart 停止后重新启动，用于让改过的配置立即生效。
//
// 这里不先拔桌面指针：它只是被同一个端口重启几秒钟，来回写 mode
// 等于让所有程序重连两次，还会把"直连"闪出来骗人。
// 但端口可能真的换了（配置写 listen: 127.0.0.1:0 时每次都是新的），
// 所以起来之后要把指针重新对准实际在收流量那个地址。
func (a *App) Restart() error {
	ours := a.desktopPointsAtUs()
	if err := a.svc.Stop(); err != nil {
		return err
	}
	if err := a.svc.Start(); err != nil {
		return err
	}
	a.restoreSystemProxy(ours, "重启")
	return nil
}

// Reload 热重载 GeoIP 与规则，不影响正在跑的连接。
func (a *App) Reload() error { return a.svc.Reload() }

// ---------- 流量 ----------

// Traffic 返回连接表与速率序列。
func (a *App) Traffic() metrics.Snapshot { return a.svc.Metrics().Snapshot() }

// ResetStats 清空累计流量与历史连接。它只管**本次会话**：
// 跨重启那份累计是另一个动作（ClearUsageStats），因为"这个月过完了"和
// "我想重新看一眼刚才那几分钟"是两件事，合成一个按钮就会有人误删月度数。
func (a *App) ResetStats() { a.svc.Metrics().Reset() }

// ClearUsageStats 把"累计（跨重启）"那一栏也归零，并把起点拨到当下，
// 紧接着落一次盘——不清盘等于下次启动又把旧账读回来，白清。
func (a *App) ClearUsageStats() error {
	reg := a.svc.Metrics()
	reg.ClearUsageCumulative()
	reg.SetUsageOutcome(metrics.UsageEmpty)
	if err := reg.FlushUsage(); err != nil {
		// 账已经清了但没落盘：下次启动会回到清之前的样子。
		// 这句错误信息要如实说这一点，不能只说"失败了"。
		return fmt.Errorf("累计已在本机清零，但没能写进账本文件——下次启动会读回清零之前的数: %w", err)
	}
	logx.Infof("节点用量的跨重启累计已清零，重新起算")
	return nil
}

// ---------- 日志 ----------

// Logs 返回 Seq 大于 after 的日志增量。after <= 0 表示取全部。
func (a *App) Logs(after int64) LogPage { return a.logs.page(after) }

// ---------- 配置 ----------

// ReadConfig 返回掩码后的配置表单。
func (a *App) ReadConfig() (ConfigForm, error) { return readForm(a.svc.ConfigPath()) }

// SaveConfig 校验并保存配置，原文件会先备份成 <path>.bak。
// 保存不重启进程；前端提示用户点「重启」才会生效。
func (a *App) SaveConfig(f ConfigForm) error { return writeForm(a.svc.ConfigPath(), f) }

// ---------- 分流模式 ----------

// SetMode 切换 rule / global / direct。运行中即时生效，不断流。
func (a *App) SetMode(mode string) error { return a.svc.SetMode(mode) }

// ---------- 代理服务 ----------

// ProfileList 是节点面板的数据源。
type ProfileList struct {
	Profiles []service.ProfileView `json:"profiles"`
	Active   string                `json:"active"`
	Mode     string                `json:"mode"`
}

// Profiles 返回全部节点、当前选中项与模式。
func (a *App) Profiles() (ProfileList, error) {
	list, active, err := a.svc.Profiles()
	if err != nil {
		return ProfileList{Profiles: []service.ProfileView{}, Mode: string(config.ModeRule)}, err
	}
	return ProfileList{Profiles: list, Active: active, Mode: a.svc.Mode()}, nil
}

// Protocols 返回节点可选的协议名。
//
// 面板的下拉由它填充，这样"再加一种协议"只需要在 config 里登记一处；
// 返回副本是因为绑定层出去的切片前端也能改，别把包级变量交出去。
func (a *App) Protocols() []string {
	return append([]string{}, config.Protocols...)
}

// AddProfile 新增一个代理服务。新节点不会被自动选中，
// 「加了就立刻换隧道」这种事应该由用户点一下确认。
func (a *App) AddProfile(p service.ProfileSpec) error { return a.svc.AddProfile(p) }

// UpdateProfile 改写指定节点。name 是旧名字，用于定位。
func (a *App) UpdateProfile(name string, p service.ProfileSpec) error {
	return a.svc.UpdateProfile(name, p)
}

// RemoveProfile 删除节点；删的正是当前选中项时会自动重启服务。
func (a *App) RemoveProfile(name string) error { return a.svc.RemoveProfile(name) }

// SetActiveProfile 切到指定节点。
func (a *App) SetActiveProfile(name string) error { return a.svc.SetActiveProfile(name) }

// TestProfile 单独握手测一个节点的建链耗时，不影响当前隧道。
func (a *App) TestProfile(name, target string) service.ProfileTest {
	return a.svc.TestProfile(name, target)
}

// ---------- TUN ----------

// SetTUNEnabled 开/关 TUN 模式。开启需要 CAP_NET_ADMIN，
// 缺权限时返回的错误会同时留在 Status().TUN.LastError 里。
func (a *App) SetTUNEnabled(enable bool) error { return a.svc.SetTUNEnabled(enable) }

// TUNStatus 返回 TUN 状态。
func (a *App) TUNStatus() tunx.Status { return a.svc.TUNStatus() }

// ---------- 按网卡分流 ----------

// SetIfaceSplitEnabled 开/关「两张无线都在时按网卡分流」。
// 开启时会重建隧道让代理流量真的换到 USB 无线那张卡上。
func (a *App) SetIfaceSplitEnabled(enable bool) error { return a.svc.SetIfaceSplitEnabled(enable) }

// SetIfaceSplitCards 指定哪张卡走直连、哪张卡走代理。空串即那一侧交给系统默认路由。
// 换到代理那一侧时会重建隧道：已经建好的那条连接换不了网卡。
func (a *App) SetIfaceSplitCards(direct, proxy string) error {
	return a.svc.SetIfaceSplitCards(direct, proxy)
}

// IfaceSplitStatus 返回分流状态，含「为什么现在没分流」。
func (a *App) IfaceSplitStatus() service.IfaceSplitStatus { return a.svc.IfaceSplitStatus() }

// ---------- 自定义域名规则 ----------

// UserRules 返回「哪些域名走代理、哪些不走」里用户自己写的那些。
func (a *App) UserRules() ([]rules.UserRule, error) { return a.svc.ListUserRules() }

// AddUserRule 新增或改策略，写完立即热重载，界面上加完就能看到效果。
func (a *App) AddUserRule(r rules.UserRule) error { return a.svc.AddUserRule(r) }

// RemoveUserRule 删除一条。
func (a *App) RemoveUserRule(typ, value string) error { return a.svc.RemoveUserRule(typ, value) }

// UserRuleHits 返回每条自定义规则本次会话用过多少次。
// 与判语那一栏是两种问法：判语推得出"永远轮不到"，只有计数说得出"轮到过没有"。
func (a *App) UserRuleHits() ([]service.RuleHit, error) { return a.svc.UserRuleHits() }

// SetUserRuleDisabled 停用/打开一条规则。单独一个方法而不是复用 AddUserRule：
// 手写的 IP-CIDR / GEOIP 走 AddUserRule 会被"只收域名类型"拒掉，
// 而那几条恰恰最想临时关掉来排查。
func (a *App) SetUserRuleDisabled(typ, value string, off bool) error {
	return a.svc.SetUserRuleDisabled(typ, value, off)
}

// MoveUserRule 把一条规则挪到名单里的第 to 格（0 起）。
// 顺序在这套规则里是有语义的——命中第一条就停，所以挪位置改的是行为，不只是排列。
func (a *App) MoveUserRule(typ, value string, to int) error {
	return a.svc.MoveUserRule(typ, value, to)
}

// BlockList 返回正在生效的拦截名单，供规则页那一栏显示。
func (a *App) BlockList() service.BlockView { return a.svc.BlockList() }

// UserRuleWarnings 返回这份自定义规则里的问题（被盖住的、以及钉了不存在节点的）。
// 面板把它摆在规则表上面：顺序改完了还是会有别压不住的情况，
// 而钉错节点那一类是**直接失败**，混进"永远不会命中"里只会让人照着错误的方向去查。
func (a *App) UserRuleWarnings() ([]service.RuleWarning, error) { return a.svc.UserRuleWarnings() }

// AddUserRules 一次收下一整段粘进来的规则。返回的结果要说得出逐行的下场：
// 新增几条、覆盖了几条已有的、哪几行被拒、以及有没有装上但永远不会命中。
func (a *App) AddUserRules(text, defType, defPolicy string) (service.UserRuleImport, error) {
	return a.svc.AddUserRules(text, defType, defPolicy)
}

// AddBlockDomain 加一条拦截域名：写进配置的 block: 段，并立即铺到引擎上。
// 把归一化后的域名回给界面，提示才说得出"实际存进去的是哪一条"。
func (a *App) AddBlockDomain(domain string) (string, error) { return a.svc.AddBlockDomain(domain) }

// RemoveBlockDomain 删一条。
func (a *App) RemoveBlockDomain(domain string) error { return a.svc.RemoveBlockDomain(domain) }

// AddBlockDomains 一次收下一整段粘进来的拦截域名（裸域名或 AdGuard 写法）。
// 逐行的下场由后端记账后回传：新增几条、名单里本来就有几条、哪几行被拒为什么、
// 以及有没有装上却什么也没多拦的。成批加名单是常事，逐条写盘既慢又容易半途失败。
func (a *App) AddBlockDomains(text string) (service.BlockImport, error) {
	return a.svc.AddBlockDomains(text)
}

// PruneBlockDomains 清掉名单里那些被更宽条目盖住的冗余项，返回删掉的条数。
// 这件事不改任何一个域名的判定（见 service.PruneBlockDomains 的说明），
// 但它会写配置文件，所以由用户点一下才做。
func (a *App) PruneBlockDomains() (int, error) { return a.svc.PruneBlockDomains() }

// ProbeHost 回答「这个域名现在实际怎么走、被哪条命中」。
func (a *App) ProbeHost(host string) (service.ProbeResult, error) { return a.svc.Probe(host) }

// RefreshProvidersNow 是订阅栏上那个「立即拉取」：等一小时周期不是"立即"。
// 整轮给 30 秒预算——远端不可达时每条最多要两分钟，
// 与其让按钮转五分钟，不如让剩下的几条以超时如实报出来。
func (a *App) RefreshProvidersNow() (service.ProviderRefreshReport, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return a.svc.RefreshProviders(ctx)
}

// Subscriptions 回答「订阅现在到底怎么样了」：上次拉到什么时候、连着失败几次、
// 缓存还在不在、下一次大概何时。URL 不带出来——订阅地址常含鉴权 token。
func (a *App) Subscriptions() service.SubscriptionsView { return a.svc.Subscriptions() }

// RulesWatch 回答「我改这份规则文件会不会自己生效」：被看着的是哪些文件、
// 上次生效是什么时候、哪些可选 include 因为文件不存在而根本不在清单里。
func (a *App) RulesWatch() service.RulesWatchView { return a.svc.RulesWatchView() }

// ---------- 系统代理 ----------

// sysproxyTimeout 是每一次系统代理操作的预算上限。
//
// gsettings 走 D-Bus，总有卡住的可能（总线地址指向一个不响应的套接字、
// dconf 锁被别人长期持有）。没有预算的话，Wails 的绑定调用会被永久挂住：
// 界面上那个开关点下去再也不动，而且因为绑定调用是同步的，
// 整个前端的事件循环都被这一次调用拖住。
const sysproxyTimeout = 10 * time.Second

// sysxRunner 是本包的系统代理后端接缝：nil 即真实后端（gsettings / kioslaverc /
// environment.d），测试在 TestMain 里换成假的。
//
// 必须整包换，不能只在新增的用例里换：`Stop` 与 `Close` 现在都会动桌面设置，
// 而测试用的配置里入站就是 7891/7892——在开发机上跑一次 go test
// 就把跑测试那个人代理指针改掉了。这类副作用要默认是假的，靠人记得注入迟早失手。
var sysxRunner sysproxy.Runner

// withTimeout 跑一个接受 ctx 的系统代理操作，并给它加上时间预算。
// gsettings 走 D-Bus，总有卡住的可能，而 Wails 的绑定调用是同步的：
// 卡一次就等于整个界面失去响应。
func withTimeout(fn func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), sysproxyTimeout)
	defer cancel()
	return fn(ctx)
}

// ---------- 系统代理 ----------

// SystemProxyStatus 读回桌面当前的代理设置。
func (a *App) SystemProxyStatus() sysproxy.Status {
	st, err := a.withTimeoutRead()
	if err != nil && st.Error == "" {
		st.Error = err.Error()
	}
	return st
}

func (a *App) withTimeoutRead() (sysproxy.Status, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sysproxyTimeout)
	defer cancel()
	return sysproxy.ReadWith(ctx, sysxRunner, a.sysProxyBackend())
}

// sysProxyBackend 报出配置里指定的后端（空即自动）。
//
// 状态读数必须走和开关同一条路：读的是 gnome、写的却是 kde，
// 界面上就会显示「没开」，而实际上刚把用户桌面改了。
func (a *App) sysProxyBackend() string {
	backend, _, _ := a.sysProxyTarget()
	return backend
}

// sysProxyEnableConfig 凑出「把桌面指到本客户端」这一次写入的意图。
// 开关、停止后的恢复、重启后的对齐三条路必须共用一份，各自凑端口迟早写歪。
func (a *App) sysProxyEnableConfig() sysproxy.Config {
	httpAddr, socksAddr := a.inboundAddrs()
	return sysproxy.Config{
		Enable:    true,
		Backend:   a.sysProxyBackend(),
		HTTPAddr:  httpAddr,
		SOCKSAddr: socksAddr,
	}
}

// SetSystemProxy 把桌面代理指向本客户端的入站。关闭即还原成改动前的样子。
func (a *App) SetSystemProxy(enable bool) error {
	statePath := sysproxy.StatePath(a.svc.ConfigPath())
	backend := a.sysProxyBackend()
	if !enable {
		err := withTimeout(func(ctx context.Context) error {
			return sysproxy.Disable(ctx, sysxRunner, statePath, backend)
		})
		if err == nil {
			// 用户亲手关的，就不该由下一次「启动」替他打开。
			a.setSysProxyPaused(false)
			// 开关这条路原来不留日志：桌面上谁改的、什么时候改的，
			// 日志里一个字都没有。等哪天要查「桌面怎么指着我们的」，
			// 这一句就是唯一的目击证人。
			logx.Infof("已按界面操作把桌面系统代理切回关闭")
		}
		return err
	}
	c := a.sysProxyEnableConfig()
	err := withTimeout(func(ctx context.Context) error {
		return sysproxy.Enable(ctx, sysxRunner, statePath, c)
	})
	if err == nil {
		a.setSysProxyPaused(false) // 现在这根指针是用户要的了，停止时该由停止拔掉它
		logx.Infof("已按界面操作把桌面系统代理指向本客户端入站（http %s / socks %s），记账 %s",
			c.HTTPAddr, c.SOCKSAddr, statePath)
	}
	return err
}

// releaseSystemProxy 在释放入站端口之前收掉桌面上指着它们的那根指针。
//
// 两种账都要认：有记账就还原成改动前的样子（用户原来可能自己配了别的代理，
// 置 none 等于擅自改别人的设置）；没记账但桌面读数正好等于本程序的入站
// ——就是上一轮记账被吃掉的那种——只能退化成「关掉」，因为留着它，
// 端口一关整机就没网，而唯一的报错是「代理连接被拒绝」。
// 两者都不成立的桌面不归我们管，一个字都不该写。
//
// why 只用在日志上：界面上「停止」和「退出」是两件事，话要说对。
func (a *App) releaseSystemProxy(why string) error {
	statePath := sysproxy.StatePath(a.svc.ConfigPath())
	led, _ := sysproxy.ReadLedger(statePath)
	ours := a.desktopPointsAtUs()
	if !led.Exists && !ours {
		return nil
	}
	backend := a.sysProxyBackend()
	err := withTimeout(func(ctx context.Context) error {
		return sysproxy.Disable(ctx, sysxRunner, statePath, backend)
	})
	if err != nil {
		logx.Errorf("%s时关闭桌面系统代理失败，桌面可能仍指向即将关闭的端口（可跑 -sysproxy off 手工关掉）: %v", why, err)
		return err
	}
	if ours {
		// 停止之前桌面是指着我们的，那"启动"就该把它接回去。
		// 只看记账在不在是不够的：账记的是改动前的原状，照着它还完就等于
		// 用户按一次停止之后再也回不到代理状态，界面上开关还是黑的。
		a.setSysProxyPaused(true)
		if led.Exists {
			logx.Infof("已按记账把桌面系统代理还原回原样，流量改为直连")
		} else {
			logx.Infof("已把桌面系统代理切回关闭，流量改为直连（没有记账，只能关掉）")
		}
	} else {
		logx.Infof("已按记账还原桌面系统代理（桌面当前并未指向本程序）")
	}
	return nil
}

// restoreSystemProxy 把桌面指针放回本客户端当前实际在收流量的入站。
//
// 只在「这根指针该由我们负责」时才写：ours 是调用方在停端口之前问出来的
// 「桌面本来就指着我们」，暂停标志是上一次停止替用户拔掉的。两个都不成立，
// 就说明桌面现在这样是用户自己的选择，启动不该去改它。
func (a *App) restoreSystemProxy(ours bool, why string) {
	paused := a.takeSysProxyPaused()
	if !paused && !ours {
		return
	}
	c := a.sysProxyEnableConfig()
	if err := withTimeout(func(ctx context.Context) error {
		return sysproxy.Enable(ctx, sysxRunner, sysproxy.StatePath(a.svc.ConfigPath()), c)
	}); err != nil {
		if paused {
			a.setSysProxyPaused(true) // 还没放回去，下一次启动继续试
		}
		logx.Errorf("%s后恢复桌面系统代理失败，流量将继续直连（可在界面重新打开系统代理开关）: %v", why, err)
		return
	}
	logx.Infof("已把桌面系统代理指回本客户端入站（http %s / socks %s）", c.HTTPAddr, c.SOCKSAddr)
}

func (a *App) setSysProxyPaused(v bool) {
	a.sysProxyMu.Lock()
	defer a.sysProxyMu.Unlock()
	a.sysProxyPaused = v
}

// takeSysProxyPaused 读出并清零暂停标志：一次恢复只该消费一次「是我关的」。
func (a *App) takeSysProxyPaused() bool {
	a.sysProxyMu.Lock()
	defer a.sysProxyMu.Unlock()
	v := a.sysProxyPaused
	a.sysProxyPaused = false
	return v
}

// inboundAddrs 取当前实际监听的 http 与 socks5 地址，
// 这样「系统代理」永远指向真的在收流量的端口，而不是配置里写的那个。
func (a *App) inboundAddrs() (http string, socks string) {
	snap := a.svc.Snapshot()
	for _, in := range snap.Inbounds {
		if !in.Active {
			continue
		}
		switch in.Type {
		case "http":
			if http == "" {
				http = in.Addr
			}
		case "socks5":
			if socks == "" {
				socks = in.Addr
			}
		}
	}
	return http, socks
}
