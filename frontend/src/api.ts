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

interface AppBridge {
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

// ---------------------------------------------------------------------------
// 浏览器里 npm run dev 跑时根本没有 Wails 运行时。
// 给一份演示数据让界面能单独调试布局，但它不是真实状态，UI 会明确标出。
// 演示模式下所有「会改动系统」的操作一律报错，避免让人误以为配置真存进去了。
// ---------------------------------------------------------------------------

const DEMO_HOSTS = [
  'www.example.com',
  'cdn.jsdelivr.net',
  'registry.npmjs.org',
  'mirrors.aliyun.com',
  'api.github.com',
  'www.bing.com'
]
const DEMO_MATCHED = ['GEOIP,CN,DIRECT', 'FINAL', 'DOMAIN-SUFFIX,github.com,PROXY', 'GEOIP,CN,DIRECT']

let demoMode = 'rule'
let demoActive = 'demo-sg'
let demoTUN = false
let demoIfaceSplit = false
/**
 * 把演示"代理在不在跑"这件事交给场景层。
 *
 * 为什么要有这个东西：`?demo=down` 原来只覆写了 Status 与 Traffic，
 * 而 base 里的 `running` 还是 true —— 于是同一屏上并排站着
 * 「代理未运行」的顶栏和「名单正在生效」的拦截栏（BlockList.live、RulesWatch.watching
 * 都照 running 答）。这正是 §9.3 记过的那个形状：换掉一个字段，由它派生的那几格原封不动。
 * 演示数据自相矛盾，界面调试就会照着假象改判据。
 */
let setDemoRunning: (on: boolean) => void = () => {}
// 演示用的两张卡照抄这台机器真实的命名：下拉里的「内置 / USB」标签、
// 以及地址那一栏要看着像真的，否则这块 UI 只在接了后端之后才看得出对不对。
const demoCards: IfaceCardView[] = [
  { name: 'wlp3s0f0', usb: false, addrs: ['10.180.56.140'] },
  { name: 'wlx001f0578cdff', usb: true, addrs: ['192.168.0.23'] }
]
const demoSplitCards = { direct: 'wlp3s0f0', proxy: 'wlx001f0578cdff' }
/**
 * 演示里"分流此刻真的生效吗"——与 Go 那侧 `IfaceSplitStatus.active` 同一条式子：
 * 开关开着、且模式是规则。这个判断原来在三个地方各抄一遍，
 * 探测那一格是第四个，所以先收成一个函数再往下用。
 */
const demoSplitActive = () => demoIfaceSplit && demoMode === 'rule'
/** 合并那份答案是不是就是这个上游给的（照 Go 侧 whichUpstreamAnswered 那条式子）。 */
const sameSet = (u: UpstreamView, merged: string[]): boolean =>
  !u.err && u.addrs.length === merged.length && u.addrs.every((a) => merged.includes(a))
/** 某个策略此刻被钉在哪张卡上；没分流就是空串（与 `Split.DevForPolicy` 同语义）。 */
const demoIfaceFor = (policy: string): string => {
  if (!demoSplitActive() || policy === 'REJECT') {
    return ''
  }
  return policy === 'PROXY' ? demoSplitCards.proxy : demoSplitCards.direct
}
let demoSysProxy = false
const demoLedgerPath = './config.yaml.sysproxy.json'
// 留一条 REJECT：那一行是只读的（策略开关只有两档），
// 演示数据里带上它，这块渲染才不至于只有在接了后端之后才能被看到。
// 演示用的拦截名单：可变，好让「添加/删除」在没接后端时也能被点通。

// demoBlockDead 照 Go 的 rules.DeadBlockDomains 算出"装了却什么也没多拦"的条目：
// 逐级剥点边界后缀，某一级已经在名单里就算被盖住，取最宽的那一级当理由。
// 演示模式存在的意义是提前看到真面板长什么样，判据形状与措辞都得对得上。
interface DemoDead {
  domain: string
  by: string
}

function demoBlockDead(): DemoDead[] {
  const set = new Set(demoBlock)
  const out: DemoDead[] = []
  for (const d of demoBlock) {
    let by = ''
    for (let rest = d; ;) {
      const i = rest.indexOf('.')
      if (i < 0) {
        break
      }
      rest = rest.slice(i + 1)
      if (set.has(rest) && (by === '' || rest.length < by.length)) {
        by = rest
      }
    }
    if (by !== '') {
      out.push({ domain: d, by })
    }
  }
  return out.sort((a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0))
}

/** 措辞与 Go 的 DeadBlock.String() 逐字一致。 */
function demoBlockDeadText(d: DemoDead): string {
  return `${d.by} 已经在名单里（按后缀拦，子域自动生效），所以 ${d.domain} 这一条什么也没多拦。`
}

// demoParseBlockLine 照 Go 的 parseBlockLine 读一行：裸域名、AdGuard 的 ||x^、带修饰符的 ||x^$third-party；
// 拒掉例外规则 @@||x、清单头部 [xxx]、一行多域名（hosts 写法）。
function demoParseBlockLine(line: string): { ok: true; domain: string } | { ok: false; why: string } {
  let s = line.trim()
  if (s.startsWith('[') && s.endsWith(']')) {
    return { ok: false, why: '这是名单清单的头部标记（如 [Adblock Plus 2.0]），不是域名' }
  }
  if (s.startsWith('@@')) {
    return { ok: false, why: '这是例外规则（@@ 开头），意思是不要拦它；这份名单只收要拦的域名' }
  }
  if (s.startsWith('||')) {
    s = s.slice(2)
  }
  const dollar = s.indexOf('$')
  if (dollar >= 0) {
    s = s.slice(0, dollar)
  }
  if (s.endsWith('^')) {
    s = s.slice(0, -1)
  }
  if (/\s/.test(s)) {
    return { ok: false, why: `"${s}" 一行里有多个域名（hosts 写法或一条里挤了几条）；这份名单一行收一个，拆开再粘` }
  }
  s = s.toLowerCase().replace(/^\.|\.$/g, '')
  if (s === '') {
    return { ok: false, why: '是空项；空域名归一化后是空后缀，等于拦下所有域名' }
  }
  if (/[@/: ,#]/.test(s)) {
    return { ok: false, why: `"${line.trim()}" 不像域名：这里只收裸域名（含子域自动生效），不要带协议、路径、端口或 IP 段` }
  }
  return { ok: true, domain: s }
}

const demoBlock: string[] = [
  'ads.example.com',
  // 这一条演示的是「装了却什么也没多拦」：ads.example.com 已经在名单里，按后缀拦，子域自动生效。
  'pixel.ads.example.com',
  'track.example.net',
  'telemetry.corp.example'
]

const demoRules: UserRule[] = [
  { type: 'DOMAIN-SUFFIX', value: 'example.cn', policy: 'DIRECT', node: '', disabled: false },
  // 钉住某个节点的那一条：界面上要能看出"这条不走当前节点"。
  { type: 'DOMAIN-SUFFIX', value: 'office.corp', policy: 'PROXY', node: 'demo-us', disabled: false },
  // 这一条演示另一种问题：节点被改名/删掉了，规则里的 node= 还留着旧名字。
  // 演示数据里必须有它，「这份名单里有问题」那一栏的第二类判语才有东西可看。
  { type: 'DOMAIN-SUFFIX', value: 'wiki.corp', policy: 'PROXY', node: 'demo-tokyo', disabled: false },
  { type: 'DOMAIN-SUFFIX', value: 'ads.example.com', policy: 'REJECT', node: '', disabled: false },
  // 手写的那几类：Go 侧照实报类型名，界面里只读。演示数据也要有它们，
  // 否则"只读那一行长什么样"在 ?demo= 里根本看不见。
  // 第 3 条这条是"写了但不生效"的样子：前面那条 ads.example.com 的后缀先命中，
  // 所以它永远轮不到。演示数据里得有一条，界面那一栏才有东西可看。
  { type: 'DOMAIN', value: 'track.ads.example.com', policy: 'PROXY', node: '', disabled: false },
  { type: 'IP-CIDR', value: '10.0.0.0/8', policy: 'DIRECT', node: '', disabled: false },
  { type: 'DOMAIN-REGEX', value: '^(api|cdn)\\.foo\\.com$', policy: 'PROXY', node: '', disabled: false },
  // 一条被停用的：界面上要能看出"这条在名单里但此刻不生效"是什么样子（灰掉 + 已停用）。
  { type: 'DOMAIN-SUFFIX', value: 'legacy.internal', policy: 'DIRECT', node: '', disabled: true }
]
/**
 * 演示侧的尺寸解析，只为把 quotaText 换算成演示里的百分比用。
 * 权威实现是 Go 那边的 config.ParseSize（面板真用时读的是它换算的结果），
 * 所以这里刻意只覆盖界面上真会写出来的那几种写法，不追求等价。
 */
function demoSizeToBytes(text: string): number {
  const m = /^\s*([0-9]*\.?[0-9]+)\s*(kib|mib|gib|tib|pib|kb|mb|gb|tb|pb|k|m|g|t|p|b)?\s*$/i.exec(text)
  if (!m) {
    return 0
  }
  const n = parseFloat(m[1])
  const table: Record<string, number> = {
    kib: 1024, mib: 1024 ** 2, gib: 1024 ** 3, tib: 1024 ** 4, pib: 1024 ** 5,
    k: 1e3, m: 1e6, g: 1e9, t: 1e12, p: 1e15
  }
  const unit = (m[2] || 'b').toLowerCase().replace(/b$/, '')
  return Math.floor(n * (unit === 'b' ? 1 : (table[unit] ?? 1)))
}

const demoProfiles = [
  // 一个有配额、一个没有：这样"没设配额就不该出现那一行"这一档在演示里也看得见。
  {
    name: 'demo-sg', type: 'hysteria2', addr: 'demo.example.com:443', sni: 'demo.example.com',
    // 11GB 是台小 VPS 的真配额数量级，而它让"已用 67%"这种有用的读数出现在演示里
    // （写 1000GB 的话永远显示 0%，那一行的排版就等于没被看过）。
    authSet: true, udp: true, active: true, quotaText: '11GB', quotaBytes: demoSizeToBytes('11GB')
  },
  {
    name: 'demo-us', type: 'trojan', addr: 'us.demo.example.com:8443', sni: 'us.demo.example.com',
    authSet: true, udp: false, active: false, quotaText: '', quotaBytes: 0
  }
]

// 判语要对着"配置里此刻有哪些节点"说话，而这个名单就是 demoProfiles 本身。
// 抄一份数组会把两者分家：用户在演示里改名之后判语还按旧名单算，
// 于是当面说一条好端端的规则钉了个不存在的节点。
const demoNodeNames = (): string[] => demoProfiles.map((p) => p.name)

/**
 * 演示日志每一类落在哪个级别——照后端实际用的那个函数抄，不是照"看起来合理"猜：
 * 拦截（inbound/block.go 的 Warnf）与拨不通（socks5.go 的 Warnf）是 WARN，
 * 重载规则失败（service.go 的 Errorf）是 ERROR，节点握手流水（outbound/trojan.go）是 DEBUG。
 * 级别挂错一档，日志页那排阈值按钮演示出来的就是假的分布。
 */
const DEMO_LOG_LEVEL: Record<string, string> = {
  block: 'WARN',
  fail: 'WARN',
  error: 'ERROR',
  debug: 'DEBUG',
  info: 'INFO'
}

function demoBridge(): AppBridge {
  const started = Date.now() - 5 * 3600 * 1000
  let running = true
  setDemoRunning = (on: boolean) => {
    running = on
  }
  // demoPriorOn 只为一件事存在：让「累计也清零」在演示里真的能把那一栏变没，
  // 而不是点下去数字纹丝不动——那种按钮没法验收。
  let demoPriorOn = true
  let totalUp = 0
  let totalDown = 0
  const startAt = () => Date.now()
  const conn = (i: number, active: boolean): TrafficSnapshot['active'][number] => {
    const start = startAt() - (active ? 20 + i * 37 : 60 + i * 11) * 1000
    const up = (i + 1) * 8123 + (active ? 0 : 100)
    const down = (i + 2) * 24017 + (active ? 0 : 100)
    totalUp += up
    totalDown += down
    const matched = DEMO_MATCHED[i % DEMO_MATCHED.length]
    const direct = matched.endsWith(',DIRECT')
    return {
      // id 必须**由这条连接本身决定**，不能是"第几次调用工厂"。
      // 真后端是 metrics.Registry 在建连接那一刻 seq.Add(1)，之后每次快照都不变；
      // 而连接表的行是 `:key="c.id"`，拿自增数当 id 会让每一轮轮询的 key 全变，
      // 于是整张表被拆掉重建（实测 300 行 = 每秒 307 增 + 307 删），
      // ?demo=big 那台测流畅度的尺子量的就不是生产的代价了。
      id: 100 + i,
      start,
      duration: Date.now() - start,
      inbound: i % 3 === 0 ? 'http' : 'socks5',
      client: `127.0.0.1:${50000 + i}`,
      host: DEMO_HOSTS[i % DEMO_HOSTS.length],
      port: '443',
      target: '',
      // 这一格写的是决策的枚举原值（DIRECT / PROXY / REJECT），与 Go 那侧
      // `Conn.Policy = string(res.Policy)` 同一个式子。别拿走向的中文或规则类型填进来：
      // 演示里写一个后端产不出的值，界面对着它调出来的样式在真后端上永远不出现
      // （这条由 internal/ui/demo_words_test.go 盯着）。
      policy: direct ? 'DIRECT' : 'PROXY',
      matched,
      // 走向要跟命中规则一致。演示数据里让 GEOIP,CN,DIRECT 显示成"走代理"，
      // 连接表的走向统计就自相矛盾——照着这种数据调 UI，会调歪。
      outbound: direct ? 'DIRECT' : 'PROXY',
      // outbound 是策略分组的名字，node 才是"实际走了哪个节点"。演示数据必须两个都给：
      // 只给一个的话，照着 demo 调这一列，会以为它们是一回事。
      // 名字取自下面那两个真节点，别造一个节点列表里不存在的名字。
      node: direct ? 'DIRECT' : i % 4 === 1 ? 'demo-us' : 'demo-sg',
      // 网卡那一格走同一个式子：分流开关没拨开（或模式不在 rule）时必须是空串。
      // 原来这里写死两张卡名，于是连接表说"这条走了 USB 卡"、总览那个开关却说没开分流——
      // 同一屏两份读数打脸，是这一层最不该留的错（§9.3 记过两次了）。
      // 要在演示里看那一列：总览把「按网卡分流」拨开即可。
      iface: demoIfaceFor(direct ? 'DIRECT' : 'PROXY'),
      // 正常建起来的连接没有错误。这一格留空串，失败的那种见下面那条 Refuse 形状。
      err: '',
      up,
      down
    }
  }

  // 「看解析」的缓存那一格要有东西可演：同一个名字第二次问必须报"命中缓存"，
  // 而它不能靠时间猜（演示里两次点击可以隔一毫秒）。
  // 记的是**过期时刻**而不是"问过没有"：Go 那边过期后 cacheHit 认账、报没命中，
  // 演示要是永远报命中，那"还剩 N 秒自己变新"这一格在这里就永远演不出来，
  // 而人点开演示正是为了看清界面上每种状态长什么样。
  const DEMO_DNS_TTL_MS = 60_000
  // 名字 -> 上一次被点名刷新的那个上游。合并那一份从此按它算。
  // 名字 -> 被点名刷过的那个上游，**连同它那份答案的过期时刻**（两个 Map 一起走，键是同一个名字）。
  // 记过期是刻意的：分叉那一格的话是「这只管到这条缓存过期为止」，
  // 演示要是把偏好记成永久的，那句话在 ?demo= 下就永远演不出来——而那正是这枚按钮唯一的代价说明。
  const demoPreferred = new Map<string, string>()
  const demoPreferredUntil = new Map<string, number>()
  const demoProbed = new Map<string, number>()

  /**
   * 演示侧的"这一条会怎么走"只写这一遍，「查走向」「取一个真页面」「看解析」三格共用。
   *
   * 原来这套式子内联在 ProbeHost 里。取页面那一格也要报同四列（走向/依据/节点/网卡），
   * 抄两遍的话两格迟早各说一套——Go 那侧正是为了这个才只留一份 `Router.decide`，
   * 而 `Preview` 与真拨号共用它（internal/router/preview.go）。
   */
  const demoDecide = (h: string): Omit<ProbeResult, 'host'> => {
    const one = (policy: string, matched: string, pinned = '') => ({
      policy,
      matched,
      mode: demoMode,
      // 节点那一格照 Go 那条式子来：只有判成 PROXY 才有"落到谁头上"，
      // 钉住的名字优先，没钉就是当前活动的那个。
      node: policy === 'PROXY' ? pinned || demoActive : '',
      // 网卡那一格与 Go 同一条规矩：没在跑就不答（分流要真探测到两张卡才算生效），
      // 而模式一离开「规则」，Go 那侧就把绑定收回了（ifacesplit.go 的 want），
      // 所以这里也答空串。
      iface: running ? demoIfaceFor(policy) : '',
      // live 跟着演示的"在跑/停着"走：停着的时候这句必须是 false，
      // 否则「未运行，按磁盘规则算」那一档在演示里永远演示不出来。
      live: running
    })
    // 与 Go 的 `Router.decide` 同一个顺序：**模式压过规则集**。
    // 这一格原来直接去查规则，于是切到「全局」之后它还在报"命中某条域名规则"，
    // 而真转发那一刻根本不看规则——探测框是这一页上唯一该说真话的地方。
    if (demoMode === 'global' || demoMode === 'direct') {
      return one(demoMode === 'global' ? 'PROXY' : 'DIRECT', `MODE,${demoMode.toUpperCase()}`)
    }
    // 规则模式：名单排在规则文件之前（§5.1 里那条硬要求），
    // 不照这个顺序写，演示就会在"名单压得过放行规则"这一格上说反。
    const blocked = demoBlock.find((d) => h === d || h.endsWith('.' + d))
    if (blocked) {
      return one('REJECT', `DOMAIN-SUFFIX,${blocked},REJECT(block)`)
    }
    // 停用的那条（`,off`）不参与判定——Go 那侧引擎就是这么做到的，
    // 而探测框答的是"现在会怎么走"：让演示里的停用规则继续被命中，
    // 演示就成了唯一会说假话的那一块界面（面板上它明明标着"已停用"）。
    const hit = demoRules.find(
      (r) =>
        !r.disabled &&
        ((r.type === 'DOMAIN' && r.value === h) ||
          (r.type === 'DOMAIN-SUFFIX' && (h === r.value || h.endsWith('.' + r.value))) ||
          (r.type === 'DOMAIN-KEYWORD' && h.includes(r.value)) ||
          // 演示侧用 JS 正则近似 Go 的 RE2（不锚定、忽略大小写同一个 (?i)）。
          // 这里只为让"查走向"那一栏在 ?demo= 下有东西可看，判据以后端为准。
          (r.type === 'DOMAIN-REGEX' && new RegExp(r.value, 'i').test(h)))
    )
    if (hit) {
      // 命中依据带上节点名，与 Go 侧 desc() 同一个写法：钉住谁就写谁。
      return one(
        hit.policy,
        `${hit.type},${hit.value},${hit.policy}${hit.node ? `(node=${hit.node})` : ''}`,
        hit.node
      )
    }
    return one('PROXY', 'FINAL')
  }

  return {
    async Status() {
      return {
        running,
        mode: demoMode,
        profiles: demoProfiles.map((p) => ({ ...p, active: p.name === demoActive })),
        activeProfile: demoActive,
        autoSwitched: false,
        ifaceSplit: {
          enabled: demoIfaceSplit,
          active: demoSplitActive(),
          directDev: demoSplitCards.direct,
          proxyDev: demoSplitCards.proxy,
          note: '',
          cards: demoCards
        },
        tun: {
          enabled: demoTUN,
          running: demoTUN,
          device: 'wps-tun',
          address: '172.19.0.1/30',
          dns: '172.19.0.2',
          fakeIpRange: '198.18.0.0/15',
          hijackDns: true,
          strictRoute: false,
          fakeIps: demoTUN ? 12 : 0,
          active: demoTUN ? 2 : 0,
          dnsServed: demoTUN ? 137 : 0,
          startedAt: demoTUN ? Date.now() - 60_000 : 0,
          lastError: '',
          applied: demoTUN
            ? ['配置网卡地址', '启用网卡', '把假 IP 网段路由进 tun', '挂载 UDP DNS 劫持', '给网卡加 v6 地址']
            : [],
          privilege: 'helper',
          helperCmd: ['sudo', '-n', '/home/chery/wps_app/wps_app', '--tun-helper'],
          ipv6: demoTUN,
          v6Ready: demoTUN
        },
        startedAt: running ? started : 0,
        uptimeMs: running ? Date.now() - started : 0,
        server: 'demo.example.com:443',
        configPath: '/etc/wps_app/config.yaml',
        inbounds: [
          { type: 'socks5', listen: '127.0.0.1:7891', addr: '127.0.0.1:7891', auth: true, active: running },
          { type: 'http', listen: '127.0.0.1:7892', addr: '127.0.0.1:7892', auth: false, active: running }
        ],
        geoipPath: './assets/geoip.mmdb',
        geoipOk: true,
        rulesFile: './assets/rules.txt',
        domainRules: 1284,
        ipRules: 306,
        // 给一个非零值，让「拦截 N 条」这一档在脱离后端开发时也能被看到。
        blockedRules: 12,
        finalPolicy: 'PROXY',
        rulesSkipped: [],
        authSet: true,
        sni: 'demo.example.com',
        bandwidthUp: '200 mbps',
        bandwidthDown: '1000 mbps',
        congestion: 'bbr',
        connected: running,
        proxyType: 'hysteria2',
        proxyStatus: '203.0.113.9:443 (QUIC 隧道已建, bbr)',
        lastError: ''
      }
    },
    async Start() {
      running = true
    },
    async Stop() {
      running = false
    },
    async Restart() {
      running = true
    },
    async Reload() {},
    async Traffic() {
      const active = running ? [0, 1, 2].map((i) => conn(i, true)) : []
      if (running) {
        // 拦下来的连接一个字节都没有，所以不能走 conn() 那个工厂（它会累加总量）。
        // 演示数据里放一条，是为了让总览的「拦截 N 条」与流量页的 REJECT 标签
        // 在没接后端时也能被看到——那一行是 v-if，不造数据就永远验证不到。
        active.push({
          id: 150,
          start: startAt() - 8000,
          duration: 8000,
          inbound: 'socks5',
          client: '127.0.0.1:50999',
          host: 'ads.example.com',
          port: '443',
          target: '',
          policy: 'REJECT',
          matched: 'DOMAIN-SUFFIX,ads.example.com,REJECT(block)',
          outbound: 'REJECT',
          node: 'REJECT',
          // 被拦下的连接压根没有出站，也就没有网卡可言。
          iface: '',
          // 被拦不是"拨失败"：它压根没打算拨。这一格留空，走向才是「已拦截」。
          err: '',
          up: 0,
          down: 0
        })
      }
      const history = running ? [3, 4, 5, 6, 7].map((i) => conn(i, false)) : []
      if (running) {
        // 拨不通的那一条：和上面那条被拦的一样，是"不造数据就永远验证不到"的一行。
        // 形状照抄 metrics.Registry.Refuse 的产物——零字节、时长 0、
        // 但路由判定留着（它本来要怎么走是这一行最有信息量的部分）。
        history.push({
          // id 是定死的：连接表 :key="c.id"，每轮换一个 id 就是整表拆掉重建
          // （理由见上面 conn() 里那段注释）。
          id: 151,
          start: startAt() - 15000,
          duration: 0,
          inbound: 'socks5',
          client: '127.0.0.1:50998',
          host: 'broken.example.org',
          port: '443',
          target: 'broken.example.org:443',
          policy: 'PROXY',
          matched: 'DOMAIN-SUFFIX,example.org,PROXY',
          outbound: 'PROXY',
          node: 'demo-us',
          iface: '',
          err: 'dial tcp 203.0.113.7:443: connect: connection refused',
          up: 0,
          down: 0
        })
        // 第二条失败的是**一个 IP 字面量、非 443 端口**：它专门演示那一格里两个按钮
        // 为什么条件不同——IP 不能拿去建域名规则（建出来永远不命中），
        // 但"取一次 http://10.0.0.5:8080/"是完全合理的一问。
        // 端口不是 443，所以带过去的网址协议是 http（见 ConnectionsTable 的 fetchURL）。
        //
        // 判定那几格写的是 PROXY / FINAL，不是"IP-CIDR,DIRECT"：演示侧的 decide 只认域名规则，
        // 而这一行点「取页面」之后那一格算出来的就是 PROXY / FINAL。
        // 同一屏上两份读数不许打脸（§9.3 记过两次了）——要表达"真实引擎会按 IP 规则直连"
        // 得靠后端，不是靠编一行演示数据。
        history.push({
          id: 152,
          start: startAt() - 9000,
          duration: 0,
          inbound: 'http',
          client: '127.0.0.1:51002',
          host: '10.0.0.5',
          port: '8080',
          target: '10.0.0.5:8080',
          policy: 'PROXY',
          matched: 'FINAL',
          outbound: 'PROXY',
          node: 'demo-sg',
          // 一条字节都没走出去的拒绝，网卡那一格留空：与上面那条同一形状，
          // 别让"它本来会走哪张卡"看起来像个已经发生的事实。
          iface: '',
          err: 'dial tcp 10.0.0.5:8080: i/o timeout',
          up: 0,
          down: 0
        })
      }
      const series: TrafficSnapshot['series'] = []
      for (let i = 0; i < 90; i++) {
        series.push({
          t: Date.now() - (89 - i) * 1000,
          up: Math.abs(Math.sin(i / 6)) * 3.2e6,
          down: Math.abs(Math.cos(i / 7)) * 1.1e7
        })
      }
      return {
        active,
        history,
        series,
        // 各节点用量：演示里给三条，含"当前节点之外还有一个被自动切换用掉过"的样子，
        // 这样不接后端也能看到那张表在节点切换后的形态。
        byNode: running
          ? [
              // 名字必须真的是节点列表里那两个之一：这张表与连接表共用 node 这个值，
              // 面板上"点一行去筛连接"就靠它们说同一个字符串。
              // 早先这里写过 demo-hk——配置里根本不存在的节点，
              // 照着那份数据调 UI 会调出一个对不上号的筛子。
              // prior 是"上一次进程留下的账"，所以这里刻意摆三个不同的样子：
              // 有账的（sg）、账更多的（us）、压根没账的（DIRECT，直连不计配额）。
              // 只摆一种的话，"这一栏什么时候该消失"就永远没被看过。
              { node: 'demo-sg', up: 412000000, down: 1830000000, conns: 431, prior: demoPriorOn ? 5200000000 : 0 },
              { node: 'DIRECT', up: 30000000, down: 610000000, conns: 96, prior: 0 },
              { node: 'demo-us', up: 210000000, down: 90000000, conns: 58, prior: demoPriorOn ? 900000000 : 0 }
            ]
          : [],
        // 累计的两个时刻也要有：界面拿它们说"自 X 起累计 / 上次落盘 Y 前"。
        // 「累计也清零」之后一起归零，那一整句要从界面上消失——
        // 不是显示成"自 1970-01-01 起"，那比没有更难看。
        priorSince: demoPriorOn ? Date.now() - 12 * 86400000 : 0,
        priorSavedAt: demoPriorOn ? Date.now() - 90 * 1000 : 0,
        // 与上面两个数同一口径：有基数就是 loaded，清零之后是 empty。
        // too-new / unreadable 那两种状态演示里靠手改这个串来看（README §9.5.2）。
        usageState: demoPriorOn ? 'loaded' : 'empty',
        // 最近拦截留痕：与上面那条被拦连接同源，规则原文照真实格式写。
        recentBlocked: running
          ? [
              {
                host: 'ads.example.com',
                rule: 'DOMAIN-SUFFIX,ads.example.com,REJECT(block)',
                count: 7,
                lastAt: Date.now() - 42 * 1000
              },
              {
                host: 'track.example.net',
                rule: 'DOMAIN-SUFFIX,track.example.net,REJECT(block)',
                count: 3,
                lastAt: Date.now() - 5 * 60 * 1000
              }
            ]
          : [],
        activeCount: active.length,
        totalConns: active.length + history.length,
        // 从上面那两个数组里数出来，不另写一个数：这一格今天已经因为
        // "换了一个数组却留着由它派生的数"翻过一次（见 big 场景那段注释）。
        totalFailed: [...active, ...history].filter((c) => c.err !== '').length,
        // 累计拦截：给一个比「当前活跃里被拦的那条」大一点的数，
        // 让累计与活跃两栏在没接后端时也同时有内容可看。
        totalBlocked: running ? 12 : 0,
        totalUp: 48 * 1024 * 1024,
        totalDown: 512 * 1024 * 1024
      }
    },
    async ResetStats() {},
    async ClearUsageStats() {
      demoPriorOn = false
    },
    async Logs(after: number) {
      const entries = Array.from({ length: 12 }, (_, i) => {
        const s = Math.max(after, 1) + i + 1
        // 掺一条真的拦截日志：日志页有「只看拦截」快捷过滤，演示数据里没有这一行，
        // 那个按钮点下去就是 0 条，看着像功能坏了。
        //
        // 四个级别同样都要有料，理由和上面那条一样：日志页那排阈值按钮里
        // ≥ ERROR 在只有 INFO/WARN 的数据上永远点出 0 条，≥ DEBUG 与「全部」
        // 的区别永远演示不出来——而这两格恰恰是"有没有出事"那一问的入口。
        // 措辞照生产抄：拦截与拨不通是 WARN（inbound/block.go、socks5.go），
        // ERROR 是重载规则失败（service.go），DEBUG 是按连接发的节点流水（outbound/trojan.go）。
        const kind =
          i % 6 === 0
            ? 'block'
            : i % 7 === 0
              ? 'fail'
              : i % 5 === 0
                ? 'error'
                : i % 4 === 0
                  ? 'debug'
                  : 'info'
        return {
          seq: s,
          time: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
          level: DEMO_LOG_LEVEL[kind],
          msg:
            kind === 'block'
              ? 'socks5 拦截 ads.example.com:443 [DOMAIN-SUFFIX,ads.example.com,REJECT(block)]（按拦截名单，客户端不会收到原因）'
              : kind === 'fail'
                ? 'socks5 127.0.0.1:53211 -> api.example.com:443 失败: dial tcp 203.0.113.9:443: i/o timeout'
                : kind === 'error'
                  ? '重载规则失败，继续使用旧规则: 打开 ./assets/geoip.mmdb: no such file or directory'
                  : kind === 'debug'
                    ? 'trojan: 已连接 demo.example.com:443（SNI=demo.example.com, 目标 demo.example.com:443）'
                    : `转发 127.0.0.1:5000${i} -> demo.example.com:443 (PROXY)`
        }
      })
      // latest 必须是"这一页里最大的那个 seq"，不是条数。真后端返回的是 b.seq
      // （缓冲里已分配的最大序号），前端拿它当游标下次来拉增量。
      // 之前这里返回 entries.length，游标永远停在 12：每一轮都重新发出 seq 13..24，
      // 于是日志页其实是同样 12 行的若干份拷贝，而 :key="e.seq" 全部撞车。
      // 生产构建里 Vue 把重复 key 的告警去掉了，所以这个错在面板上完全看不出来。
      return { entries, latest: entries[entries.length - 1].seq, truncated: false }
    },
    async ReadConfig() {
      return {
        path: '/etc/wps_app/config.yaml',
        mode: demoMode,
        activeName: demoActive,
        activeAddr: 'demo.example.com:443',
        inbounds: [
          { type: 'socks5', listen: '127.0.0.1:7891', username: '********', password: '********' },
          { type: 'http', listen: '127.0.0.1:7892', username: '', password: '' }
        ],
        geoipPath: './assets/geoip.mmdb',
        rulesFile: './assets/rules.txt',
        dnsServers: ['223.5.5.5', '119.29.29.29'],
        dnsTimeout: '3s',
        dnsCache: '5m0s',
        logLevel: 'info',
        tun: {
          enable: demoTUN,
          device: 'wps-tun',
          address: '172.19.0.1/30',
          mtu: 1500,
          dns: '172.19.0.2',
          fakeIpRange: '198.18.0.0/15',
          hijackDns: true,
          strictRoute: false,
          routeExclude: []
        }
      }
    },
    async SaveConfig() {
      throw new Error('当前是浏览器演示模式，没有真实后端，配置不会落盘')
    },
    async SetMode(m: string) {
      demoMode = m
    },
    async Profiles() {
      return {
        profiles: demoProfiles.map((p) => ({ ...p, active: p.name === demoActive })),
        active: demoActive,
        mode: demoMode
      }
    },
    async Protocols() {
      return ['hysteria2', 'trojan']
    },
    async AddProfile(p: ProfileSpec) {
      if (demoProfiles.some((x) => x.name === p.name)) {
        throw new Error(`节点名 ${p.name} 已存在`)
      }
      const type = p.type || 'hysteria2'
      demoProfiles.push({
        name: p.name,
        type,
        addr: p.addr,
        sni: p.sni,
        authSet: p.auth !== '',
        udp: type === 'hysteria2',
        active: false,
        quotaText: p.quota || '',
        quotaBytes: demoSizeToBytes(p.quota || '')
      })
    },
    async UpdateProfile(name: string, p: ProfileSpec) {
      const hit = demoProfiles.find((x) => x.name === name)
      if (!hit) {
        throw new Error(`节点 ${name} 不存在`)
      }
      hit.name = p.name || name
      hit.type = p.type || hit.type
      hit.addr = p.addr || hit.addr
      hit.sni = p.sni || hit.sni
      // 与后端同一约定：留空是"不改"，不是"清除"。
      if (p.quota) {
        hit.quotaText = p.quota
        hit.quotaBytes = demoSizeToBytes(p.quota)
      }
    },
    async RemoveProfile(name: string) {
      if (demoProfiles.length <= 1) {
        throw new Error('至少保留一个代理服务')
      }
      const i = demoProfiles.findIndex((x) => x.name === name)
      if (i < 0) {
        throw new Error(`节点 ${name} 不存在`)
      }
      demoProfiles.splice(i, 1)
      if (demoActive === name) {
        demoActive = demoProfiles[0].name
      }
    },
    async SetActiveProfile(name: string) {
      if (!demoProfiles.some((x) => x.name === name)) {
        throw new Error(`节点 ${name} 不存在`)
      }
      demoActive = name
    },
    async TestProfile(name: string, target: string): Promise<ProfileTest> {
      const remote = target || 'www.gstatic.com:443'
      // 演示数据里留出两种现场，界面三种状态各看得见一个：
      // demo-sg 是真取回了页面，demo-us 是"隧道正常、节点把流量交给兼底 web 服务器"
      // 那一类——延迟好看、握手正常、页面一个也打不开。
      if (name === 'demo-us') {
        return {
          name, ok: true, latencyMs: 214, remote, error: '',
          pageChecked: true, page: '',
          pageErr: 'TLS 握手失败: tls: first record does not look like a TLS handshake'
        }
      }
      return {
        name, ok: true, latencyMs: 87, remote, error: '',
        pageChecked: true, page: 'https 204 0 字节', pageErr: ''
      }
    },
    async SetTUNEnabled(enable: boolean) {
      demoTUN = enable
    },
    async SetIfaceSplitEnabled(enable: boolean) {
      demoIfaceSplit = enable
    },
    async SetIfaceSplitCards(direct: string, proxy: string) {
      // 照 Go 那条判据：两边钉同一张卡会让整条分流一起消失，不该默默执行。
      if (direct !== '' && direct === proxy) {
        throw new Error(`直连与代理不能选同一张网卡（${direct}）：请改选另一张，或让其中一侧留空走系统默认路由`)
      }
      demoSplitCards.direct = direct
      demoSplitCards.proxy = proxy
    },
    async IfaceSplitStatus() {
      return {
        enabled: demoIfaceSplit,
        active: demoSplitActive(),
        directDev: demoSplitCards.direct,
        proxyDev: demoSplitCards.proxy,
        note: '',
        cards: demoCards
      }
    },
    async TUNStatus() {
      return {
        enabled: demoTUN,
        running: demoTUN,
        device: 'wps-tun',
        address: '172.19.0.1/30',
        dns: '172.19.0.2',
        fakeIpRange: '198.18.0.0/15',
        hijackDns: true,
        strictRoute: false,
        fakeIps: demoTUN ? 12 : 0,
        active: demoTUN ? 2 : 0,
        dnsServed: demoTUN ? 137 : 0,
        startedAt: demoTUN ? Date.now() - 60_000 : 0,
        lastError: '',
        applied: [],
        privilege: 'self',
        helperCmd: [],
        ipv6: false,
        v6Ready: false
      }
    },
    async SetSystemProxy() {
      throw new Error('演示模式不会改动系统代理')
    },
    async UserRules() {
      return demoRules.map((r) => ({ ...r }))
    },
    async AddUserRule(rule: UserRule) {
      const key = `${rule.type},${rule.value}`
      const hit = demoRules.find((r) => `${r.type},${r.value}` === key)
      if (hit) {
        // 内容三个字段一起覆盖：漏了 node 就等于"改个走向把固定节点弄丢了"。
        // 但 disabled **不跟过来**——停用属于这一行的开关，不属于这一行写的内容，
        // 唯一会动它的是 SetUserRuleDisabled 那一枚按钮。真后端就是这么做的
        // （UpsertUserRule 覆盖时把旧的 Disabled 带过去），两边必须同一行为。
        hit.policy = rule.policy
        hit.node = rule.node ?? ''
      } else {
        demoRules.push({ type: rule.type, value: rule.value, policy: rule.policy, node: rule.node ?? '', disabled: rule.disabled ?? false })
      }
    },
    async RemoveUserRule(type: string, value: string) {
      const i = demoRules.findIndex((r) => r.type === type && r.value === value)
      if (i < 0) {
        throw new Error(`没有找到规则 ${type},${value}`)
      }
      demoRules.splice(i, 1)
    },
    async SetUserRuleDisabled(type: string, value: string, off: boolean) {
      const hit = demoRules.find((r) => r.type === type && r.value === value)
      if (!hit) {
        throw new Error(`没有找到规则 ${type},${value}`)
      }
      hit.disabled = off
    },
    async MoveUserRule(type: string, value: string, to: number) {
      // 与真后端同一套判据：找不到、越界都要响，别写出一份没人要求过的顺序。
      const i = demoRules.findIndex((r) => r.type === type && r.value === value)
      if (i < 0) {
        throw new Error(`没有找到规则 ${type},${value}`)
      }
      if (to < 0 || to >= demoRules.length) {
        throw new Error(`位置 ${to} 超出这份名单的范围（共 ${demoRules.length} 条）`)
      }
      const moved = demoRules.splice(i, 1)[0]
      demoRules.splice(to, 0, moved)
    },
    async AddUserRules(text: string, defType: string, defPolicy: string): Promise<UserRuleImport> {
      // 演示侧按同一套形状算：裸域名走界面上选的默认类型与策略，
      // 带逗号的行拆成 类型,域名,策略；判据本身以后端为准。
      const imp: UserRuleImport = { total: 0, accepted: 0, updated: 0, rejected: [], dead: [], written: false }
      const lines = text.split('\n')
      const touched: string[] = []
      lines.forEach((raw, i) => {
        const line = raw.trim()
        if (line === '' || line.startsWith('#')) {
          return
        }
        imp.total++
        const f = line.split(',').map((x) => x.trim())
        let type = defType
        let value = line.toLowerCase()
        let policy = defPolicy
        if (f.length >= 2) {
          if (f.length !== 3) {
            imp.rejected.push(`第 ${i + 1} 行 ${line}：要写成 类型,域名,策略`)
            return
          }
          type = f[0].toUpperCase()
          value = f[1].toLowerCase()
          policy = f[2].toUpperCase()
          if (!['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].includes(type)) {
            imp.rejected.push(`第 ${i + 1} 行 ${line}：${type} 这一类只能在文件里手写，批量添加不收`)
            return
          }
          if (!['PROXY', 'DIRECT'].includes(policy)) {
            imp.rejected.push(`第 ${i + 1} 行 ${line}：批量添加只接受 PROXY / DIRECT`)
            return
          }
        }
        const key = `${type},${value}`
        const hit = demoRules.find((r) => `${r.type},${r.value}` === key)
        if (hit) {
          hit.policy = policy
          imp.updated++
        } else {
          demoRules.push({ type, value, policy, node: '', disabled: false })
          imp.accepted++
        }
        touched.push(`${type},${value},${policy}`)
      })
      if (imp.total === 0) {
        throw new Error('没有要添加的行：空行与 # 注释不算')
      }
      if (imp.accepted + imp.updated === 0) {
        return imp
      }
      imp.written = true
      // 那句话的形状要和 Go 侧 DeadRule.String() 一致：
      // 演示模式存在的意义就是"提前看到真面板长什么样"，措辞对不上就等于没验。
      imp.dead = touched.flatMap((t) => {
        const [type, value] = t.split(',')
        const idx = demoRules.findIndex((r) => `${r.type},${r.value}` === `${type},${value}`)
        for (let j = 0; j < idx; j++) {
          const p = demoRules[j]
          let hits = false
          if (p.type === 'DOMAIN-SUFFIX') {
            hits = value === p.value || value.endsWith('.' + p.value)
          } else if (p.type === 'DOMAIN-KEYWORD') {
            hits = value.includes(p.value)
          } else if (p.type === 'DOMAIN') {
            hits = value === p.value
          }
          if (hits) {
            return [
              `第 ${idx + 1} 条 ${t} 永远不会命中：` +
                `第 ${j + 1} 条 ${p.type},${p.value},${p.policy} 已经先覆盖了它。` +
                '要让它生效就把它挪到前面，否则删掉。'
            ]
          }
        }
        return []
      })
      return imp
    },
    async UserRuleHits(): Promise<RuleHit[]> {
      // 演示侧的计数是编的，但**编的形状**要跟真后端一致：
      // 按 TYPE,VALUE 归并、没轮到的那条给 0，而不是干脆不出现在列表里。
      // 真判据在 metrics.Registry.RuleHits（连接登记那一刻加的）。
      return demoRules.map((r, i) => ({ key: `${r.type},${r.value}`, hits: i % 4 === 0 ? (i * 7) % 130 : 0 }))
    },
    async UserRuleWarnings(): Promise<RuleWarning[]> {
      // 演示侧只抄"后缀压住后面的精确域名/子域"这一条最常见的形状，
      // 外加一类钉错节点的。真判据在 Go 侧（rules.DeadRules 与配置里的节点名单）——
      // 归一化写法只有一份权威，这里抄两份就会和后端分家，
      // 而分家的那一侧会当面说一条活规则是死的。
      const out: RuleWarning[] = []
      demoRules.forEach((r, i) => {
        if (r.type !== 'DOMAIN' && r.type !== 'DOMAIN-SUFFIX') {
          return
        }
        // 停用的那条本来就不参与匹配，谈不上"被盖住"。
        if (r.disabled) {
          return
        }
        for (let j = 0; j < i; j++) {
          const p = demoRules[j]
          // 关着的那条盖不住后面任何一条——和 Go 侧 DeadRules 同一判据。
          if (p.disabled) {
            continue
          }
          const hits =
            (p.type === 'DOMAIN-SUFFIX' && (r.value === p.value || r.value.endsWith('.' + p.value))) ||
            (p.type === 'DOMAIN-KEYWORD' && r.value.includes(p.value))
          if (hits) {
            out.push({
              kind: 'shadow',
              line: `${r.type},${r.value},${r.policy}`,
              why:
                `第 ${j + 1} 条 ${p.type},${p.value},${p.policy} 已经先覆盖了它。` +
                '要让它生效就把它挪到前面，否则删掉。'
            })
            return
          }
        }
      })
      // 演示节点名只有这两个；钉在别处的就是"改名之后规则没跟着改"那一幕。
      const known = demoNodeNames()
      demoRules.forEach((r) => {
        // 停用的那条不参与匹配，永远不会有连接"走到它然后失败"——和 Go 侧同一口径。
        if (r.disabled || !r.node || known.includes(r.node)) {
          return
        }
        out.push({
          kind: 'node-missing',
          line: `${r.type},${r.value},${r.policy},node=${r.node}`,
          why:
            `它钉的节点 "${r.node}" 不在配置的节点列表里（改名或删除之后规则不会跟着改）。` +
            '这类规则不会回落当前节点：走到它的连接会直接失败，日志里会出现这个名字。' +
            '把节点改回这个名字，或者去掉这一行的 node=。'
        })
      })
      return out
    },
    async AddBlockDomain(domain: string): Promise<string> {
      const d = domain.trim().toLowerCase().replace(/\.$/, '')
      if (!d || d === '.') {
        throw new Error(`拦截域名 "${domain}" 不合法`)
      }
      if (!demoBlock.includes(d)) {
        demoBlock.push(d)
      }
      // 和真后端一样回归一化后的写法，界面那条提示在演示模式下也照得到真样子。
      return d
    },
    async RemoveBlockDomain(domain: string) {
      const i = demoBlock.indexOf(domain)
      if (i < 0) {
        throw new Error(`名单里没有 ${domain}`)
      }
      demoBlock.splice(i, 1)
    },
    async BlockList() {
      // 演示数据与真后端同形：域名 + 生效标志 + 模式。
      const dead = demoBlockDead()
      return {
        domains: [...demoBlock],
        live: running,
        mode: demoMode,
        path: './config.yaml',
        dead: dead.slice(0, 200).map(demoBlockDeadText),
        deadTotal: dead.length
      }
    },
    async AddBlockDomains(text: string): Promise<BlockImport> {
      const imp: BlockImport = { total: 0, accepted: 0, existing: 0, rejected: [], dead: [], written: false }
      const added: string[] = []
      const seen = new Set(demoBlock)
      text.split('\n').forEach((raw, i) => {
        const line = raw.trim()
        if (line === '' || line.startsWith('#') || line.startsWith('!')) {
          return
        }
        imp.total++
        const got = demoParseBlockLine(line)
        if (!got.ok) {
          imp.rejected.push(`第 ${i + 1} 行 ${line.length > 60 ? line.slice(0, 60) + '…' : line}：${got.why}`)
          return
        }
        if (seen.has(got.domain)) {
          imp.existing++
          return
        }
        seen.add(got.domain)
        demoBlock.push(got.domain)
        added.push(got.domain)
        imp.accepted++
      })
      if (imp.total === 0) {
        throw new Error('没有要添加的域名：空行与 # / ! 注释不算')
      }
      if (imp.accepted === 0) {
        return imp
      }
      imp.written = true
      const fresh = new Set(added)
      imp.dead = demoBlockDead()
        .filter((d) => fresh.has(d.domain))
        .map(demoBlockDeadText)
      return imp
    },
    async PruneBlockDomains(): Promise<number> {
      const dead = new Set(demoBlockDead().map((d) => d.domain))
      const kept = demoBlock.filter((d) => !dead.has(d))
      const removed = demoBlock.length - kept.length
      demoBlock.splice(0, demoBlock.length, ...kept)
      return removed
    },
    async RulesWatch() {
      // 演示数据与真后端同形：没跑时 watching=false 且清单为空，
      // lastReload 也是空串——那一栏必须说"没在监视"，而不是画成"没有文件要看"。
      const files: RulesFileView[] = running
        ? [
            { path: './assets/rules.txt', size: 18342, modTime: '2026-10-17 08:41:02', readable: true },
            { path: './assets/user-rules.txt', size: 412, modTime: '2026-10-17 08:56:33', readable: true },
            { path: './providers/cn.txt', size: 30118, modTime: '2026-10-17 06:30:11', readable: true }
          ]
        : []
      return {
        watching: running,
        intervalSec: 5,
        files,
        lastReload: running ? '08:56:33' : ''
      }
    },
    async Subscriptions() {
      // 三条订阅各演一种处境：健康、连着失败、缓存被人删了。
      // 这一栏存在的意义就是把这三种"界面上原本长得一样"的状态分开说。
      const now = Date.now()
      const items: SubscriptionView[] = [
        {
          name: 'apple-tv',
          path: './providers/apple.txt',
          everySec: 86400,
          lastAttemptMs: now - 42000,
          lastOkMs: now - 42000,
          nextDueMs: now + 86358000,
          lastErr: '',
          fails: 0,
          size: 18244,
          hasCache: true
        },
        {
          name: 'anti-ads',
          path: './providers/ads.txt',
          everySec: 3600,
          lastAttemptMs: now - 90000,
          lastOkMs: now - 7200000,
          nextDueMs: now - 30000,
          lastErr: '拉取失败：HTTP 502（保留旧缓存）',
          fails: 3,
          size: 96120,
          hasCache: true
        },
        {
          name: 'gfw-list',
          path: './providers/gfw.txt',
          everySec: 86400,
          lastAttemptMs: now - 600000,
          lastOkMs: now - 600000,
          nextDueMs: now + 85800000,
          lastErr: '',
          fails: 0,
          size: 0,
          hasCache: false
        }
      ]
      if (!running) {
        // 没在跑：条目还在（配置里写了），但一个时刻都没有。
        return {
          configured: items.length,
          running: false,
          items: items.map((x) => ({
            ...x,
            lastAttemptMs: 0,
            lastOkMs: 0,
            nextDueMs: 0,
            lastErr: '',
            fails: 0,
            hasCache: x.hasCache
          })),
          errors: [],
          configErr: ''
        } satisfies SubscriptionsView
      }
      return {
        configured: items.length,
        running: true,
        items,
        errors: [],
        configErr: ''
      } satisfies SubscriptionsView
    },
    async RefreshProvidersNow() {
      // 演示里也走一遍"逐条结果"：一条换了新内容、一条失败，
      // 这样不连真远端也能看到按钮那两句话长什么样。
      if (!running) {
        throw new Error('代理没在跑，没有订阅循环可拉')
      }
      const results: ProviderRefresh[] = [
        { name: 'apple-tv', changed: true, err: '' },
        { name: 'anti-ads', changed: false, err: '拉取失败：HTTP 502（保留旧缓存）' },
        { name: 'gfw-list', changed: false, err: '' }
      ]
      return { results, reloaded: true, reloadErr: '' } satisfies ProviderRefreshReport
    },
    async ProbeHost(host: string) {
      const h = host.trim().toLowerCase().replace(/\.$/, '')
      return { host, ...demoDecide(h) }
    },
    async FetchPage(url: string) {
      // 这一格的三道"问不出来"必须与 Go 那三道对齐：空串、不支持的 scheme、代理没在跑。
      // 顺序也照 service.FetchPage：它先问路由器有没有出站，再洗输入。
      if (!running) {
        throw new Error('代理没在跑：先点「启动」再取页面')
      }
      const raw = url.trim()
      if (!raw) {
        throw new Error('先填一个网址')
      }
      // 与 httpprobe.Parse 同一条规矩：只认 http/https，其它 scheme 没有"取页面"这层含义。
      // 这里不用 `new URL(raw)` 兜第一步——它对一个裸域名（example.com）直接抛
      // "Invalid URL"，而后端那句是"只支持 http/https，得到 \"\""，两句话教的东西不一样。
      const m = /^([a-zA-Z][a-zA-Z\d+.-]*):\/\//.exec(raw)
      const scheme = (m?.[1] || '').toLowerCase()
      if (scheme !== 'http' && scheme !== 'https') {
        throw new Error(`只支持 http/https，得到 ${JSON.stringify(scheme)}`)
      }
      let u: URL
      try {
        u = new URL(raw)
      } catch {
        throw new Error(`URL 读不懂：${raw}`)
      }
      const host = u.hostname.toLowerCase()
      if (!host) {
        throw new Error('URL 里没有主机名')
      }
      const viaTLS = scheme === 'https'
      const port = u.port || (viaTLS ? '443' : '80')
      const path = u.pathname || '/'
      const d = demoDecide(host)
      // 被名单拦下时 Go 那侧压根没发请求：拨号就返回 `命中拦截名单: <依据>`，
      // 状态码是 0。这一句要 throw 而不是摆一张 4xx 卡片——那一格的颜色不一样。
      if (d.policy === 'REJECT') {
        throw new Error(`命中拦截名单: ${d.matched}`)
      }
      // 输入那三道（空、scheme、没在跑）当场拒——它们是"话没说清楚"，不等网络。
      // 从这里往下是"真的取一次"，演示里也照真相等一小会儿：这一格在生产里
      // 是 100ms～15s 的动作，秒回的话「取页面中…」那一档、以及"它不该把这一页
      // 别的按钮一起冻住"这两件事永远演示不出来（演示缺档就等于没验收）。
      await new Promise((r) => setTimeout(r, 450))
      // 演示里也要能演"到点没回话"那一档：api.example.com 是演示数据里那个拨不通的站点
      // （连接表与日志里都是它）。句子照 Go 那侧 plainTimeout 的写法，
      // 15 秒这个数由 internal/ui/demo_words_test.go 拿去与 service.FetchBudget 核对——
      // 不然改了预算，演示会一直说一个后端不会说的秒数。
      if (host === 'api.example.com') {
        throw new Error(`${host}:${port} 在 15 秒内没回话（这一格的预算就是 15 秒）`)
      }
      // 回什么，按"这一条实际落到哪个节点"决定，不是按域名编：
      // demo-us 是那个"隧道建得起来、对面却是台兜底 web 服务器"的节点——
      // 任何站点都回同一张 400，而「查走向」那一格完全正常。
      // 这一对就是这一格存在的理由（真实事故照搬）。要在演示里看到它：
      // 到「节点」页把活动节点切到 demo-us，再取一次同一个网址。
      const fallback = d.policy === 'PROXY' && d.node === 'demo-us'
      // 连通性探测那些地址本来就是空响应：204 + 零字节 + 没有 Server 头，
      // 这一档顺带把"没带 Server 头"那种形状也演示出来。
      const ping = /generate_?204|connectivity-check|detectportal|csi_portal/i.test(raw)
      const code = fallback ? 400 : ping ? 204 : viaTLS ? 200 : 301
      const server = fallback ? 'nginx/1.18.0 (Ubuntu)' : code === 204 ? '' : code === 301 ? 'nginx/1.18.0' : 'ECS/1.3.7'
      const location = code === 301 ? `https://${u.host}${path}` : ''
      const body = fallback ? 154 : code === 204 ? 0 : code === 301 ? 162 : 1256
      const ok = !fallback
      // 拼法照 Outcome.String()：`http(s) 200 server=xxx N 字节 → 去向`。
      // 通时后端把这一句原样带回来当"结论"，演示要是写成另一套字，
      // 照着演示调出来的那一行排版接到真后端就是歪的。
      const line = [
        `${viaTLS ? 'https' : 'http'} ${code}`,
        server ? `server=${server}` : '',
        `${body} 字节`,
        location ? `→ ${location.slice(0, 60)}` : ''
      ]
        .filter(Boolean)
        .join(' ')
      return {
        // 回显丢掉查询串与 userinfo：订阅地址的 key 常挂在查询串上，而这一格的内容会被截图发出去。
        url: `${scheme}://${u.host}${path}`,
        addr: `${host}:${port}`,
        code,
        server,
        body,
        viaTLS,
        location,
        ok,
        // 取回一张 400 **不是查询失败**，那正是这一问的答案——所以 ok=false 也要正常返回。
        reason: ok ? line : `HTTP ${code}（${server || '没带 Server 头的服务'}）——电路是通的，但这一跳没把页面取回来`,
        policy: d.policy,
        matched: d.matched,
        node: d.node,
        iface: d.iface
      } satisfies PageFetch
    },
    async ProbeDNS(host: string, fresh: boolean, upstream: string) {
      // 四道"问不出来"与 Go 那四道对齐：没在跑、空输入、点名的上游不在配置里。
      // 顺序也照 service.ProbeDNS：它先看解析器起没起来。
      if (!running) {
        throw new Error('代理没在跑：这套解析器还没起来，先点「启动」')
      }
      const name = host.trim().toLowerCase().replace(/\.$/, '')
      if (!name) {
        throw new Error('先填一个域名')
      }
      const servers = ['223.5.5.5:53', '119.29.29.29:53']
      if (upstream && !servers.includes(upstream)) {
        throw new Error(`重问 ${upstream} 没成功：这个上游不在配置里（dns.servers），没刷任何东西`)
      }
      await new Promise((r) => setTimeout(r, 120))
      // 地址是照名字编的，但编得**有规律**：同一个名字每次拿到同一批，
      // 这样"命中缓存"那一格才讲得通（第二次问换一批地址就是漏了）。
      // 203.0.113.0/24、203.0.114.0/24 与 116.62.0.0/16 都取在文档/示例段，
      // 不会被人当成"这台机器真解析出过这个地址"。
      const seed = ([...name].reduce((a, c) => (a * 31 + c.charCodeAt(0)) % 254, 7) + 1) | 0
      // 这一档是给 §10.7 那个真故事准备的：www.googletagmanager.com 在 2026-10-19
      // 那次实测里就是"一个上游给污染答案、另一个给真地址"的分叉形状。
      // 两个上游各问各的、各自计时；合并那一份按"先回来的那个"取——
      // 与 dnsx.query 的"任一成功即采用"同一个语义，不是这里另编一套。
      const split = name === 'www.googletagmanager.com' || name.endsWith('.cn')
      const real = `203.0.113.${seed}`
      const polluted = `116.62.${(seed % 60) + 1}.${(seed % 250) + 1}`
      const per: UpstreamView[] = [
        {
          server: '223.5.5.5:53',
          addrs: split ? [polluted] : [real],
          policy: split ? 'DIRECT' : 'PROXY',
          matched: split ? 'GEOIP,CN,DIRECT' : 'FINAL',
          ms: 18,
          err: ''
        },
        { server: '119.29.29.29:53', addrs: [real], policy: 'PROXY', matched: 'FINAL', ms: 24, err: '' }
      ]
      // 被点名刷过的那一家：合并那一份在它过期之前都按它算。
      const keptUntil = demoPreferredUntil.get(name) ?? 0
      const preferred = upstream || (keptUntil > Date.now() ? demoPreferred.get(name) ?? '' : '')
      const chosen = per.find((u) => u.server === preferred) ?? per[0]
      const merged = chosen.addrs
      const addrs: AddrView[] = merged.map((a) =>
        // 116.62.0.0/16 在演示的假库里是 CN；文档段刻意标成"库里没有这条"，
        // 让"不知道"与"不是 CN"是两句话这一档在演示里也看得见。
        a.startsWith('116.') ? { addr: a, country: 'CN', known: true } : { addr: a, country: '', known: false }
      )
      const d = demoDecide(name)
      // 缓存语义照 Go 那一条：读**不**续期（左边的过期时刻不动），过期后认账报"没命中"，
      // 而重问那一路一定写回一份新的——演示要是把这两条丢了，界面上"还剩 N 秒"和
      // "这批已经写回缓存"两种话就永远演示不出来。
      const now = Date.now()
      const expireAt = demoProbed.get(name) ?? 0
      // 点名刷那一家之后，Go 读的是刚写回的那份：报"命中缓存"，但 Fresh 仍为真。
      const cached = upstream ? true : !fresh && expireAt > now
      if (upstream) {
        demoPreferred.set(name, upstream)
        demoPreferredUntil.set(name, now + DEMO_DNS_TTL_MS)
        demoProbed.set(name, now + DEMO_DNS_TTL_MS)
      } else if (!cached) {
        demoProbed.set(name, now + DEMO_DNS_TTL_MS)
      }
      return {
        host: name,
        via: 'direct',
        tunnelOn: false,
        cached,
        fresh: fresh || upstream !== '',
        refreshed: upstream,
        ttlMs: cached && !upstream ? Math.max(0, expireAt - now) : DEMO_DNS_TTL_MS,
        ms: cached ? 0 : 120,
        upstreams: servers,
        addrs,
        perUpstream: per,
        divergent: split,
        // 与 Go 同一条式子：合并那份与哪个上游完全相同就指认谁；对不上就空串，不猜。
        used: sameSet(per[0], merged) ? per[0].server : sameSet(per[1], merged) ? per[1].server : '',
        // 域名那一段走同一份 demoDecide（与「查走向」同源），IP 那一段是"只看这批地址"的答案。
        // 两半不一样正是这一格最有信息量的那种读数。
        policy: d.policy,
        matched: d.matched,
        ipPolicy: chosen.policy,
        ipMatched: chosen.matched,
        note: ''
      } satisfies DNSProbe
    },
    async BuildInfo() {
      // 演示里没有"内嵌"这件事——浏览器加载的就是 dist 本身。
      // 所以这一格报的是"演示页自己用的那个 JS 文件"，newerOnDisk 恒为 false：
      // 造一个 true 出来只会让人去查一个不存在的旧进程。
      return {
        exePath: '（演示模式：没有本机二进制）',
        exeModTime: 0,
        startedAt: started,
        frontend: '（演示）',
        newerOnDisk: false
      } satisfies BuildInfo
    },
    async SystemProxyStatus() {
      return {
        supported: true,
        enabled: demoSysProxy,
        mode: demoSysProxy ? 'manual' : 'none',
        http: '127.0.0.1:7892',
        https: '127.0.0.1:7892',
        socks: '127.0.0.1:7891',
        ignored: ['localhost'],
        error: '',
        backend: 'gnome',
        note: '',
        path: ''
      }
    },
    async ExportDiagnostics() {
      // 演示模式不写任何文件：这一句要如实说，不能让按钮看起来"导出成功"了。
      return './wps_app-diag.txt（演示模式没有真的写文件）'
    },
    async ExportLogs() {
      // 同一条规矩：演示模式不落盘，也不假装落盘。
      return './wps_app-log.txt（演示模式没有真的写文件；真面板写的是内存里那 1000 条）'
    },
    async SystemProxyLedger() {
      // 演示模式不会真的去改系统代理（SetSystemProxy 直接抛），
      // 所以基础读数永远是"没有记账"。要看 live/stale/orphan 用 ?demo= 选。
      return {
        state: 'none' as const,
        text: '没有记账：桌面上这组设置不是本程序改的，退出不欠还原',
        path: demoLedgerPath
      }
    }
  }
}

const native = nativeBridge()

/**
 * scenarioBridge 在演示桥上再叠一层，专门制造「只有出错才见得到」的界面状态。
 * 浏览器里用 ?demo= 选：
 *   normal   默认，一切正常
 *   down     代理没跑：所有"未运行"分支
 *   fail     每个调用都抛：验证读不到不会被画成"一切正常"或"没有数据"
 *   partial  顶栏活着、其余调用抛：验证每一页单独报错
 *   flaky    第一读成功、之后重读全抛：验证"屏幕上那份是过期读数"会被标出来
 *   orphan   桌面指着本程序却没有记账：验证这一行会红，而不是被省略
 *   stale    记账还在、宿主已不在：验证"欠一次自动还原"是醒目但不恐慌
 *   live     这个进程自己改的桌面：验证安静的那一句不会被画成告警
 *   switched 故障自动切换生效并带理由
 *   big      名单很大（450 条规则 / 1200 条拦截域名）：验证"一次只画前几百条"
 *            那个窗口、表尾的「再多画 / 全部画出」，以及拦截名单那个搜索框。
 *            这两样都只在条数过阈值时才出现，默认那 7 条规则 + 3 条域名永远碰不到它们。
 * *   sub      订阅那一栏的"配了 4 条、实际在拉 3 条"
 *   usage-new   账本版本比本程序新：验证"累计"整栏消失时说的是"我读不懂"，不是"没账"
 *   usage-bad   账本读不出来（原件已挪去 .bad）：上面那句换成另一种说法
 *   evicted  失败计数不是零、表里却一条失败都没有：验证总览那一格说
 *            "最近一次已被历史缓冲挤出"，而不是冒充"本次还没有"
 *
 * 为什么值得放进代码而不是每次临时改演示数据：这些状态要能被反复看到，
 * 否则改完 UI 就得手改源码验一遍再改回来，第三次起就没人验了。
 * 真面板走 window.go，永远碰不到这个函数。
 */
function scenarioBridge(base: AppBridge): AppBridge {
  const name =
    typeof location === 'undefined'
      ? 'normal'
      : new URLSearchParams(location.search).get('demo') ?? 'normal'

  const failWith = (msg: string) => async (): Promise<never> => {
    throw new Error(msg)
  }

  if (name === 'fail') {
    const fail = failWith('演示场景：后端不可达')
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(base)) {
      out[key] = fail
    }
    return out as unknown as AppBridge
  }

  if (name === 'partial') {
    // Status/Traffic 照常，其它一律抛——这就是"Wails 方法单独坏了"的样子。
    const fail = failWith('演示场景：这一页读不到')
    return {
      ...base,
      UserRules: fail,
      BlockList: fail,
      RulesWatch: fail,
      Subscriptions: fail,
      RefreshProvidersNow: fail,
      Profiles: fail,
      Protocols: fail,
      AddUserRule: fail,
      RemoveUserRule: fail,
      SetUserRuleDisabled: fail,
      ClearUsageStats: fail,
      MoveUserRule: fail,
      AddUserRules: fail,
      UserRuleWarnings: fail,
      UserRuleHits: fail,
      AddBlockDomain: fail,
      RemoveBlockDomain: fail,
      AddBlockDomains: fail,
      PruneBlockDomains: fail,
      ProbeHost: fail,
      // 与「查走向」同一页、同一类读数，坏也要一起坏：
      // 这一格在 ?demo=partial 下必须也是红的，否则"那一页读不到"只演示了一半。
      FetchPage: fail,
      ProbeDNS: fail,
      BuildInfo: fail,
      AddProfile: fail,
      UpdateProfile: fail,
      RemoveProfile: fail,
      SetActiveProfile: fail,
      TestProfile: fail,
      ReadConfig: fail,
      SaveConfig: fail,
      SystemProxyStatus: fail,
      SystemProxyLedger: fail,
      ExportDiagnostics: fail,
      ExportLogs: fail,
      TUNStatus: fail
    }
  }

  if (name === 'flaky') {
    // 第一次读成功、之后每次重读都抛：用来看「读数已过期」那一档。
    // 这一档比 fail 更阴——屏幕上是有内容的，只是那份内容已经不新鲜了。
    const calls: Record<string, number> = {}
    const flake = (key: string, fn: () => unknown) => async () => {
      calls[key] = (calls[key] ?? 0) + 1
      if (calls[key] === 1) {
        return fn()
      }
      throw new Error('演示场景：重读失败')
    }
    return {
      ...base,
      Status: flake('st', () => base.Status()) as AppBridge['Status'],
      Traffic: flake('tr', () => base.Traffic()) as AppBridge['Traffic'],
      UserRules: flake('ur', () => base.UserRules()) as AppBridge['UserRules'],
      BlockList: flake('bl', () => base.BlockList()) as AppBridge['BlockList'],
      RulesWatch: flake('rw', () => base.RulesWatch()) as AppBridge['RulesWatch'],
      UserRuleWarnings: flake('uw', () => base.UserRuleWarnings()) as AppBridge['UserRuleWarnings'],
      Subscriptions: flake('sb', () => base.Subscriptions()) as AppBridge['Subscriptions'],
      Profiles: flake('pf', () => base.Profiles()) as AppBridge['Profiles'],
      Protocols: flake('pr', () => base.Protocols()) as AppBridge['Protocols']
    }
  }

  if (name === 'down') {
    // 先把演示自己的"在跑"翻掉，再覆写读数：只覆写 Status 的话，
    // base 里那些照 running 答的字段（名单 live、规则监视 watching、探测 live）
    // 会停在"在跑"，同一屏上出现两份互相打脸的状态。
    setDemoRunning(false)
    return {
      ...base,
      Status: async () => {
        const s = await base.Status()
        // 停着但配置读得到：真实后端在这种状态下依然报协议名（那是"将以什么启动"），
        // 所以这里不清空 proxyType，专门用来看界面上"按配置，未运行"那一档。
        return {
          ...s,
          running: false,
          startedAt: 0,
          uptimeMs: 0,
          connected: false,
          proxyStatus: '',
          // 真后端在没运行的那一支里根本不填 GeoIPOK（没打开过就是没打开过），
          // 演示数据跟着一起 falsy，才能看到界面上"代理未运行，还没打开过"那一档。
          geoipOk: false,
          // 入站跟着 running 走：真后端在停止后把 Active 置 false，
          // 演示数据若还写「监听中」，界面就会画出一幅没有的东西（这一格只能信后端）。
          inbounds: s.inbounds.map((ib) => ({ ...ib, active: false, addr: ib.listen }))
        }
      },
      Traffic: async () => ({
        active: [],
        history: [],
        byNode: [],
        series: [],
        recentBlocked: [],
        activeCount: 0,
        totalConns: 0,
        totalBlocked: 0,
        totalFailed: 0,
        totalUp: 0,
        totalDown: 0,
        priorSince: 0,
        priorSavedAt: 0,
        usageState: 'empty'
      })
    }
  }

  // 记账那三种"只有崩过、删过文件才见得到"的读数。
  // 桌面读数跟着一起改成"开着"：不然会出现「开关是关的、却说宿主还开着」
  // 这种自相矛盾的演示数据，界面调试时会照着假象去改判据。
  const ledgerScenario = (state: 'orphan' | 'stale' | 'live', text: string): AppBridge => {
    demoSysProxy = true
    return {
      ...base,
      SystemProxyLedger: async () => ({ state, text, path: demoLedgerPath })
    }
  }

  if (name === 'orphan') {
    // 桌面被上一轮改成指向我们，而记账文件已经不在了：
    // 本进程退出时不会还原，而其它格子全是绿的——这一行是唯一的线索。
    return ledgerScenario('orphan', '桌面正指着本程序的入站，但没有记账：本进程退出时不会还原桌面')
  }

  if (name === 'stale') {
    // 上一轮崩在启用状态：记账还在、宿主已经不在，下次启动会自动还一次。
    return ledgerScenario(
      'stale',
      '宿主 PID 4242 已经不在了，下次启动会自动还一次（改动前就指着本程序，还原等于关掉）'
    )
  }

  if (name === 'live') {
    // 最常见的那一种：这个进程自己改的桌面，退出时由它自己还原。
    return ledgerScenario(
      'live',
      '宿主 PID 4242 还开着（./wps_app-gui）— 崩溃时不会有下一个实例接手还原，正常退出时由它自己还'
    )
  }

  // 账本被拒那两种收场。界面对它们各写了一句不同的话，而话只有点得出来才算被验收过：
  // 之前那两种是靠临时改演示字符串看一遍的，那不是一档可重复的入口（§9.5.2 记着）。
  if (name === 'usage-new' || name === 'usage-bad') {
    const state = name === 'usage-new' ? 'too-new' : 'unreadable'
    return {
      ...base,
      Traffic: async () => {
        const t = await base.Traffic()
        // 真后端在这两种收场下**不会**把账本当基数用（读不懂就是没用），
        // 所以"累计"那几格必须跟着归零：只改 usageState 会演示出
        // 「累计在、却说这文件我读不懂」这种屏幕上不可能存在的组合。
        return {
          ...t,
          usageState: state,
          priorSince: 0,
          priorSavedAt: 0,
          byNode: t.byNode.map((n) => ({ ...n, prior: 0 }))
        }
      }
    }
  }

  // 「失败计数活过环形缓冲」是 §10.2 里的设计：TotalFailed 单独存，
  // 而表里只留最后 500 条。于是生产上会出现"计数不是零、表里一条失败都看不到"的形状，
  // 界面对它有专门一句话（"最近一次已被历史缓冲挤出"）。
  // 那一档在演示里从来出不来，那句话就等于没人验过——所以补一档。
  if (name === 'evicted') {
    return {
      ...base,
      Traffic: async () => {
        const t = await base.Traffic()
        return {
          ...t,
          active: t.active.map((c) => ({ ...c, err: '' })),
          history: t.history.map((c) => ({ ...c, err: '' })),
          // 只改这一个数是有意的：totalConns 由数组算出来，
          // 而 totalFailed 是后端单独存的累计量，两者本来就不该互相推导。
          totalFailed: 1284
        }
      }
    }
  }

  if (name === 'switched') {
    return {
      ...base,
      Status: async () => {
        const s = await base.Status()
        return {
          ...s,
          autoSwitched: true,
          switchReason: '配置里的节点 demo-sg 在 30s 内有 4 次节点级失败（涉及 3 个不同目标）'
        }
      }
    }
  }

  if (name === 'sub') {
    // 「配了 4 条、实际只在拉 3 条」那一档：差的那条不会自己冒出来，
    // 只有把被拒原因一起摊开，用户才知道有一条订阅从来没生效过。
    return {
      ...base,
      async Subscriptions() {
        const v = await base.Subscriptions()
        return {
          ...v,
          configured: v.items.length + 1,
          errors: ['规则集订阅 "dup"：缓存路径 ./providers/ads.txt 与 "anti-ads" 相同']
        }
      }
    }
  }

  if (name === 'big') {
    // 直接往演示数据那两个数组里灌，而不是在这里改写返回值：
    // 窗口那一栏要能删一条、要能点「全部画出」之后看见真东西，
    // 只把读数换成一大份的话，删除按钮动的还是底下那 7 条，界面当场自相矛盾。
    for (let i = 0; i < 450; i++) {
      demoRules.push({
        type: 'DOMAIN-SUFFIX',
        value: `site${i}.bulk.example`,
        policy: i % 3 === 0 ? 'DIRECT' : 'PROXY',
        node: '',
        disabled: false
      })
    }
    for (let i = 0; i < 1200; i++) {
      demoBlock.push(`ad${i}.tracknet.example`)
    }
    // 几条"装了却什么也没多拦"的，让死条目那一栏在这个场景里也有东西可看。
    demoBlock.push('www.ad7.tracknet.example', 'api.ad11.tracknet.example')
    // 日志页：前端那个缓冲的上限是 2000 行（App.vue 的 LOG_CAP），
    // 而真后端是一个环形缓冲——跑得久的进程一开始就是满的。
    // 默认那 12 行/轮的演示数据要等十几分钟才填得满，所以这一格在 ?demo= 里
    // 从来没按它真正的稳态形状被看过。第一口就给满，之后每轮照常补 12 行。
    let flooded = false
    // 每轮轮询让每条连接的字节数与时长往前走一点。
    // 不这么做的话这一格量不到东西：conn() 造的 up/down/duration 全由 i 决定，
    // 300 行每一轮的读数一模一样，Vue 无格可补，于是"每秒 8 处变更"看着像生产的代价，
    // 其实那台尺子在量一张不会动的表。真后端每秒都在长。
    let bigTick = 0
    // 「最近结束」那一份在真后端是一个 500 条的环（`internal/ui/app.go` 的 historyCap），
    // 每秒有几条从活跃滚进来、尾巴上滚掉几条。这一档原来只灌活跃那 300 行，
    // 于是"两张表一共 800 行、每秒都在动"这个**生产稳态**从来没被量过——
    // 而流量页是全应用唯一一张每秒整份重读的长表。
    let bigHistory: TrafficSnapshot['history'] = []
    return {
      ...base,
      // 流量页：活跃连接那一份**没有上限**（metrics.Registry.active 就是"此刻在跑的每条"），
      // 而这一页每 1 秒整份重读一次（App.vue 的 POLL_MS），Snapshot 会把它们全部
      // 拷出来、排序、过一遍 Wails 桥。默认演示只有 4 条，所以这台机器真忙起来
      // 是什么代价，从来没被量过。这里按"浏览器开 300 个连接"那一档量一次。
      async Traffic() {
        const snap = await base.Traffic()
        // 从真读数里复制出形状（不是另写一份假结构，那会漂），只换掉影响渲染的几个字段。
        const seed = snap.active
        if (!seed.length) {
          return snap
        }
        bigTick++
        const many = Array.from({ length: 300 }, (_, i) => {
          const s = seed[i % seed.length]
          return {
            ...s,
            // id 只由 i 决定，**不从 seed 上继承**。这一档存在的意义是量"300 行每秒都在
            // 变"的代价，而连接表的行是 `:key="c.id"`：只要 id 跟着每轮变，
            // Vue 就把整张表拆掉重建，量到的根本不是生产的代价（实测每秒 307 增 + 307 删、
            // 6 秒里 36 个 long task，而生产是零）。写成 900000 + i 而不是 s.id + i*1000，
            // 是为了让这件事**不依赖 seed 自己稳不稳**。
            id: 900000 + i,
            host: `bulk${i}.example.com`,
            client: `127.0.0.1:${5000 + (i % 900)}`,
            // 每条涨得不一样，免得所有行的文本长度同时进位、量出一种现实中不会出现的整齐。
            up: s.up + bigTick * (1 + (i % 17)) * 512,
            down: s.down + bigTick * (1 + (i % 29)) * 1024,
            duration: s.duration + bigTick * 1000
          }
        })
        // activeCount 不是"另外报一个数"：生产代码里它就是 len(active)
        // （metrics.Registry.Snapshot 里那句 ActiveCount: len(active)），
        // 而 base.Traffic() 下面也是照这个式子推出来的。
        if (snap.history.length && !bigHistory.length) {
          bigHistory = Array.from({ length: 500 }, (_, i) => {
            const s = snap.history[i % snap.history.length]
            return {
              ...s,
              // id 只由 i 决定，与上面那 300 行同一个道理：这一档要量的是"位置在动、
              // 行还是那些行"，id 每轮变就退化成整表重建。
              id: 700000 + i,
              host: `done${i}.bulk.example`,
              client: `127.0.0.1:${6000 + (i % 700)}`
            }
          })
        }
        if (bigHistory.length) {
          // 每轮把尾巴三条挪到最前 = "刚结束三条、环尾被挤出"。
          for (let k = 0; k < 3; k++) {
            bigHistory.unshift(bigHistory[bigHistory.length - 1])
            bigHistory.pop()
          }
        }
        const big = bigHistory.length ? bigHistory : snap.history
        // 问题正是出在"照抄一份再换掉其中一个字段"：`{...snap, active: many}`
        // 会把那两个**由 active 推出来的数**原封不动继承下来，
        // 于是屏幕上并排出现「显示 75 / 4」「全部 9」「拦截 75」三个互相矛盾的数。
        return {
          ...snap,
          active: many,
          history: big,
          activeCount: many.length,
          totalConns: many.length + big.length
          // 已知松的一处：byNode 那几行的 conns 是"本次会话累计"，
          // 默认演示里本来就比 totalConns 大（585 vs 9），这一档没跟着放大。
          // 它不影响这一格要量的东西（一次画几百行的代价），
          // 但别拿它当"两张表的条数应当互相对得上"的证据——那条只在 Go 侧成立。
        }
      },
      async Logs(after: number) {
        const p = await base.Logs(after)
        if (flooded) {
          return p
        }
        flooded = true
        const now = Date.now()
        // 这一档量的是"一次画两千行有多贵"，但它同时是日志页那排阈值按钮
        // 唯一的满负荷样本：全铺 INFO/WARN 的话，≥ ERROR 与 ≥ DEBUG 两格在这份
        // 数据上永远点出空列表，「只看拦截」也一样——那三格就没法在满负荷下验收。
        // 级别与措辞都照生产抄（见 DEMO_LOG_LEVEL 的注释）。
        const many = Array.from({ length: 2000 }, (_, i) => {
          const kind =
            i % 37 === 0
              ? 'fail'
              : i % 53 === 0
                ? 'block'
                : i % 91 === 0
                  ? 'error'
                  : i % 13 === 0
                    ? 'debug'
                    : 'info'
          return {
            seq: i + 1,
            time: new Date(now - (2000 - i) * 900).toLocaleTimeString('zh-CN', { hour12: false }),
            level: DEMO_LOG_LEVEL[kind],
            msg:
              kind === 'fail'
                ? `socks5 127.0.0.1:${50000 + (i % 900)} -> site${i}.bulk.example:443 失败: dial tcp 203.0.113.9:443: i/o timeout`
                : kind === 'block'
                  ? `socks5 拦截 ads${i}.example.com:443 [DOMAIN-SUFFIX,example.com,REJECT(block)]（按拦截名单，客户端不会收到原因）`
                  : kind === 'error'
                    ? '重载规则失败，继续使用旧规则: 打开 ./assets/geoip.mmdb: no such file or directory'
                    : kind === 'debug'
                      ? `trojan: 已连接 demo.example.com:443（SNI=demo.example.com, 目标 site${i}.bulk.example:443）`
                      : `转发 127.0.0.1:${4000 + (i % 900)} -> site${i}.bulk.example:443 (PROXY)`
          }
        })
        return { entries: many, latest: many[many.length - 1].seq, truncated: false }
      }
    }
  }

  return base
}

const bridge: AppBridge = native ? native : scenarioBridge(demoBridge())

/** 是否有真实的 Wails 后端。没有时界面会显示「演示数据」角标。 */
export const isDemo = native === null

/** 把后端返回的 error 归一成字符串。Wails 把 Go 的 error 当作 Promise rejection 抛出，值就是 error.Error()。 */
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
