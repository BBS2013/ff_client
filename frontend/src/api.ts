// api.ts 是前端与 Go 侧唯一的通信面。
//
// 这里没有 wailsjs/ 目录：本项目绕开了 `wails build` CLI（见计划的选型表），
// 直接用 go build + go:embed，因此改为手写对 window.go 的调用声明。
// Wails 绑定路径由 internal/binding/reflect.go 决定：
//   pkgPath = 去掉结构名后的类型串 -> internal/ui 里的 App 落在 "ui" 包
//   方法名保持 Go 原样（大写开头），不做任何大小写转换
// 所以调用路径固定是 window.go.ui.App.Status(...)。

import type {
  ConfigForm,
  LogPage,
  ProfileList,
  ProfileSpec,
  ProfileTest,
  ProbeResult,
  PageFetch,
  DNSProbe,
  AddrView,
  UpstreamView,
  BuildInfo,
  BlockImport,
  BlockView,
  RulesFileView,
  RulesWatchView,
  ProviderRefresh,
  ProviderRefreshReport,
  RuleHit,
  RuleWarning,
  SubscriptionView,
  SubscriptionsView,
  Status,
  SystemProxyStatus,
  SysProxyLedger,
  UserRule,
  UserRuleImport,
  TrafficSnapshot,
  TUNStatus,
  IfaceSplitStatus,
  IfaceCardView
} from './types'

export interface AppBridge {
  Status(): Promise<Status>
  Start(): Promise<void>
  Stop(): Promise<void>
  Restart(): Promise<void>
  Reload(): Promise<void>
  Traffic(): Promise<TrafficSnapshot>
  ResetStats(): Promise<void>
  /** 把"累计（跨重启）"那一栏也清零并重新起算。与 ResetStats 是两件事。 */
  ClearUsageStats(): Promise<void>
  Logs(after: number): Promise<LogPage>
  ReadConfig(): Promise<ConfigForm>
  SaveConfig(form: ConfigForm): Promise<void>
  SetMode(mode: string): Promise<void>
  Profiles(): Promise<ProfileList>
  Protocols(): Promise<string[]>
  AddProfile(p: ProfileSpec): Promise<void>
  UpdateProfile(name: string, p: ProfileSpec): Promise<void>
  RemoveProfile(name: string): Promise<void>
  SetActiveProfile(name: string): Promise<void>
  TestProfile(name: string, target: string): Promise<ProfileTest>
  SetTUNEnabled(enable: boolean): Promise<void>
  TUNStatus(): Promise<TUNStatus>
  SetIfaceSplitEnabled(enable: boolean): Promise<void>
  SetIfaceSplitCards(direct: string, proxy: string): Promise<void>
  IfaceSplitStatus(): Promise<IfaceSplitStatus>
  SetSystemProxy(enable: boolean): Promise<void>
  SystemProxyStatus(): Promise<SystemProxyStatus>
  SystemProxyLedger(): Promise<SysProxyLedger>
  ExportDiagnostics(): Promise<string>
  /** 把内存里那份日志缓冲写成文件（面板上那个「导出日志」）。 */
  ExportLogs(): Promise<string>
  UserRules(): Promise<UserRule[]>
  AddUserRule(rule: UserRule): Promise<void>
  RemoveUserRule(type: string, value: string): Promise<void>
  SetUserRuleDisabled(type: string, value: string, off: boolean): Promise<void>
  MoveUserRule(type: string, value: string, to: number): Promise<void>
  UserRuleWarnings(): Promise<RuleWarning[]>
  UserRuleHits(): Promise<RuleHit[]>
  AddUserRules(text: string, defType: string, defPolicy: string): Promise<UserRuleImport>
  ProbeHost(host: string): Promise<ProbeResult>
  /** 按规则真取一个页面回来：与 ProbeHost 是一对，那边答"该怎么走"，这边答"实际回什么"。 */
  FetchPage(url: string): Promise<PageFetch>
  /** 第三问：引擎此刻拿去判定的到底是哪批 IP，以及每个地址的归属码。
   *  fresh=true 是「重问（不用缓存）」那一下：它会写回缓存，改掉引擎下一刻的判定依据。 */
  ProbeDNS(host: string, fresh: boolean, upstream: string): Promise<DNSProbe>
  /** 这份界面是哪一次构建：内嵌资源名 + 磁盘上二进制的改动时间。 */
  BuildInfo(): Promise<BuildInfo>
  BlockList(): Promise<BlockView>
  RulesWatch(): Promise<RulesWatchView>
  Subscriptions(): Promise<SubscriptionsView>
  RefreshProvidersNow(): Promise<ProviderRefreshReport>
  AddBlockDomain(domain: string): Promise<string>
  RemoveBlockDomain(domain: string): Promise<void>
  AddBlockDomains(text: string): Promise<BlockImport>
  PruneBlockDomains(): Promise<number>
}

type Bindings = Record<string, Record<string, unknown>>

function nativeBridge(): AppBridge | null {
  const g = (window as unknown as { go?: Bindings }).go
  if (!g) {
    return null
  }
  const direct = g['ui']?.['App']
  if (direct) {
    return direct as AppBridge
  }
  // 兜底：万一包名推导和预期不一致，就扫一遍找出唯一带 Status 方法的结构体。
  // 这只影响本函数一次，命中即返回，不会给运行期添额外开销。
  for (const pkg of Object.keys(g)) {
    for (const name of Object.keys(g[pkg])) {
      const candidate = g[pkg][name] as Partial<AppBridge>
      if (typeof candidate.Status === 'function') {
        return candidate as AppBridge
      }
    }
  }
  return null
}

const native = nativeBridge()

/** 是否有真实的 Wails 后端。没有时界面会显示「演示数据」角标。 */
export const isDemo = native === null

function missingBridge(): AppBridge {
  const fail = (): Promise<never> => Promise.reject(new Error('没有连接后面板'))
  return new Proxy({} as AppBridge, {
    get: () => fail
  })
}

// real 在演示构建里会等 demo.ts 到了再换掉。生产构建里 native 一定有，下面的 import 会被删掉。
let real: AppBridge = native ?? missingBridge()
let ready: Promise<void> = Promise.resolve()
if (native === null && import.meta.env.VITE_DEMO === '1') {
  ready = import('./demo').then((m) => {
    real = m.scenarioBridge(m.demoBridge())
  })
}

const bridge: AppBridge = new Proxy({} as AppBridge, {
  get(_target, prop: string | symbol) {
    return (...args: unknown[]) => {
      const invoke = () =>
        (real as unknown as Record<string, (...a: unknown[]) => unknown>)[String(prop)](...args)
      if (native !== null) {
        return invoke()
      }
      return ready.then(invoke)
    }
  }
})

export function errorText(err: unknown): string {
  if (err instanceof Error) {
    return err.message
  }
  if (typeof err === 'string') {
    return err
  }
  return String(err)
}

export const status = (): Promise<Status> => bridge.Status()
export const startProxy = (): Promise<void> => bridge.Start()
export const stopProxy = (): Promise<void> => bridge.Stop()
export const restartProxy = (): Promise<void> => bridge.Restart()
export const reloadRules = (): Promise<void> => bridge.Reload()
export const traffic = (): Promise<TrafficSnapshot> => bridge.Traffic()
export const resetStats = (): Promise<void> => bridge.ResetStats()
export const clearUsageStats = (): Promise<void> => bridge.ClearUsageStats()
export const logs = (after: number): Promise<LogPage> => bridge.Logs(after)
export const readConfig = (): Promise<ConfigForm> => bridge.ReadConfig()
export const saveConfig = (form: ConfigForm): Promise<void> => bridge.SaveConfig(form)
export const setMode = (mode: string): Promise<void> => bridge.SetMode(mode)
export const profiles = (): Promise<ProfileList> => bridge.Profiles()
export const protocols = (): Promise<string[]> => bridge.Protocols()
export const addProfile = (p: ProfileSpec): Promise<void> => bridge.AddProfile(p)
export const updateProfile = (name: string, p: ProfileSpec): Promise<void> => bridge.UpdateProfile(name, p)
export const removeProfile = (name: string): Promise<void> => bridge.RemoveProfile(name)
export const setActiveProfile = (name: string): Promise<void> => bridge.SetActiveProfile(name)
export const testProfile = (name: string, target: string): Promise<ProfileTest> => bridge.TestProfile(name, target)
export const setTUNEnabled = (enable: boolean): Promise<void> => bridge.SetTUNEnabled(enable)
export const tunStatus = (): Promise<TUNStatus> => bridge.TUNStatus()
export const setIfaceSplitEnabled = (enable: boolean): Promise<void> =>
  bridge.SetIfaceSplitEnabled(enable)
/** 指定哪张卡走直连、哪张卡走代理；空串即那一侧交给系统默认路由。 */
export const setIfaceSplitCards = (direct: string, proxy: string): Promise<void> =>
  bridge.SetIfaceSplitCards(direct, proxy)
export const ifaceSplitStatus = (): Promise<IfaceSplitStatus> => bridge.IfaceSplitStatus()
export const setSystemProxy = (enable: boolean): Promise<void> => bridge.SetSystemProxy(enable)
export const systemProxyStatus = (): Promise<SystemProxyStatus> => bridge.SystemProxyStatus()
export const systemProxyLedger = (): Promise<SysProxyLedger> => bridge.SystemProxyLedger()
export const exportDiagnostics = (): Promise<string> => bridge.ExportDiagnostics()
export const exportLogs = (): Promise<string> => bridge.ExportLogs()
export const userRules = (): Promise<UserRule[]> => bridge.UserRules()
export const addUserRule = (rule: UserRule): Promise<void> => bridge.AddUserRule(rule)
export const removeUserRule = (type: string, value: string): Promise<void> => bridge.RemoveUserRule(type, value)
export const setUserRuleDisabled = (type: string, value: string, off: boolean): Promise<void> =>
  bridge.SetUserRuleDisabled(type, value, off)

/** 把一条规则挪到名单里的第 to 格（0 起）。顺序就是命中顺序，所以这改的是行为。 */
export const moveUserRule = (type: string, value: string, to: number): Promise<void> =>
  bridge.MoveUserRule(type, value, to)

/** 这份名单里永远不会命中的那些条，一条一句话。 */
export const userRuleWarnings = (): Promise<RuleWarning[]> => bridge.UserRuleWarnings()
export const userRuleHits = (): Promise<RuleHit[]> => bridge.UserRuleHits()

/** 一次粘一整段：每行可以是裸域名，也可以是完整的 TYPE,VALUE,POLICY 行。 */
export const addUserRules = (text: string, defType: string, defPolicy: string): Promise<UserRuleImport> =>
  bridge.AddUserRules(text, defType, defPolicy)
export const probeHost = (host: string): Promise<ProbeResult> => bridge.ProbeHost(host)
/** 按规则真取一个页面回来。取回 4xx 是答案不是异常（见 internal/service/pagefetch.go）。 */
export const fetchPage = (url: string): Promise<PageFetch> => bridge.FetchPage(url)
/** 问一次当前解析器：这批 IP 是什么、引擎会照着它们判成什么。解析不出走 Note，不走异常。 */
export const probeDNS = (host: string, fresh: boolean, upstream: string): Promise<DNSProbe> =>
  bridge.ProbeDNS(host, fresh, upstream)
export const buildInfo = (): Promise<BuildInfo> => bridge.BuildInfo()
export const blockList = (): Promise<BlockView> => bridge.BlockList()
export const rulesWatch = (): Promise<RulesWatchView> => bridge.RulesWatch()
export const subscriptions = (): Promise<SubscriptionsView> => bridge.Subscriptions()
export const refreshProviders = (): Promise<ProviderRefreshReport> => bridge.RefreshProvidersNow()
export const addBlockDomain = (domain: string): Promise<string> => bridge.AddBlockDomain(domain)
export const removeBlockDomain = (domain: string): Promise<void> => bridge.RemoveBlockDomain(domain)

/** 一次收下一整段粘进来的拦截域名：裸域名、AdGuard 的 ||域名^、带修饰符的 ||域名^$third-party 都收。 */
export const addBlockDomains = (text: string): Promise<BlockImport> => bridge.AddBlockDomains(text)

/** 清理被更宽条目盖住的冗余项，返回删掉的条数。不会改任何一个域名的判定。 */
export const pruneBlockDomains = (): Promise<number> => bridge.PruneBlockDomains()
