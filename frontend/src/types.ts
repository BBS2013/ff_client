// types.ts 与 Go 侧结构逐字段对齐，字段名全部取自 json tag。
// 对应关系：
//   InboundStatus   <- internal/service.InboundStatus
//   Status          <- internal/service.Snapshot
//   ConnView/Sample/TrafficSnapshot <- internal/metrics
//   InboundForm/ConfigForm         <- internal/ui.ConfigForm
//   LogEntry/LogPage                <- internal/ui.LogPage
//
// 这份对应由 internal/ui/projection_guard_test.go 逐字段检查（双向）：
// 少一个字段 JSON 不会报错，只会让界面默默显示空值，所以必须有个红测试替我们盯着。
// 新增跨边界的结构体时，除了在这里加 interface，还要在测试的 typePairs 里登记一行，
// 否则第二个守卫会报"这个结构体没进表，字段名对错没人管"。

/** 一个代理服务（hysteria2 或 trojan 节点）。口令不出现在这里，只报有没有设置。 */
export interface ProfileView {
  name: string
  /** 协议名：hysteria2 / trojan */
  type: string
  addr: string
  sni: string
  authSet: boolean
  /** 该节点能否转发 UDP（UDP 目前只有 hysteria2 节点支持） */
  udp: boolean
  active: boolean
  /** 这个节点的配额（字节），0 = 没设。用来算百分比 */
  quotaBytes: number
  /** 人写下来的那句原文（"1.5TiB"）。界面用它说话，用 quotaBytes 算数 */
  quotaText: string
  /**
   * 自动切换给这个节点设的冷却到期时刻（Unix 毫秒），0 = 不在冷却里。
   * 只约束自动切换：手动选它永远有效。不说清的话，用户手动选回一个还在冷却的节点，
   * 下一次自动切换又把它切走，看起来像「程序不听我的」。
   */
  coolingUntil: number
}

/** 新增/修改节点时提交的表单。auth 留空表示沿用磁盘上的原值；type 留空同理。 */
export interface ProfileSpec {
  name: string
  type: string
  addr: string
  auth: string
  sni: string
  insecure: boolean
  bandwidthUp: string
  bandwidthDown: string
  congestion: string
  fastOpen: boolean
  /** 配额原文（"1000GB"）。空 = 不改这个节点的配额，不是清除 */
  quota: string
}

export interface ProfileList {
  profiles: ProfileView[]
  active: string
  mode: string
}

/** 一次节点连通性自检的结果。 */
export interface ProfileTest {
  name: string
  ok: boolean
  latencyMs: number
  remote: string
  error: string
  /** 电路通了之后有没有真的去取一个页面。没探过（电路就没通）时是 false。 */
  pageChecked: boolean
  /** 取到了：一行读数（状态码 + Server + 字节数）。 */
  page: string
  /** 没取到：失败原文。与 page 互斥，界面上靠它分出「通」和「电路通但页面取不回」。 */
  pageErr: string
  /**
   * 非空 = 这次测速的代理流量没有按普通方式钉在点名的网卡上，内容是分流给出的原因
   * （普通进程钉不上、由提权 helper 代劳……）。「节点不通」和「我根本没走到那张卡上」
   * 是两种要做不同决定的红。
   */
  splitNote: string
  /**
   * 到节点那一条连接实际用的源地址（如 192.168.0.104）。
   * 只有 TCP 系（trojan）给得出：它是内核回读的事实，不是我们的意图——
   * 主机路由、策略路由、helper 代劳钉卡，各种情形下它都说得对。
   * hysteria2 给不出来（QUIC 流的 LocalAddr 是伪地址，会写成服务器 IP），
   * 那一族走 hopDev。
   */
  hopAddr: string
  /**
   * 隧道 socket 实际钉住的设备名（如 wlx001f0578cdff）。
   *
   * trojan（TCP）这边它是从 socket 自己身上回读的（SO_BINDTODEVICE 的现值），
   * 与 `ss` 里那个 %dev 后缀同源，所以会和 hopAddr 一起出现，拼成「源地址%设备」；
   * hysteria2（QUIC）拿不到源地址（LocalAddr 是伪地址），只剩这一个说得出口。
   * 都没有就留空，那一句整句不显示——没证据就闭嘴，别拿"打算绑哪张卡"顶替。
   */
  hopDev: string
}

export interface RuleTraffic {
  /** 引擎写下的命中依据原文，与连接表「命中」那一列是同一个字符串 */
  rule: string
  up: number
  down: number
  /** 真的搬过字节的连接数。与规则页的「命中次数」不是一个口径：那个含被拦与拨不通的 */
  conns: number
  /** 非零表示这一行合了多少条规则（只出现在最后一行）；0 就是单独一条 */
  folded?: number
}

export interface TUNStatus {
  enabled: boolean
  running: boolean
  device: string
  address: string
  dns: string
  fakeIpRange: string
  hijackDns: boolean
  strictRoute: boolean
  fakeIps: number
  active: number
  dnsServed: number
  /**
   * 回了 SERVFAIL 的查询数（一个上游都没答上）。
   * 与 dnsServed 分开是有意的：以前失败也计进"已应答"，
   * 上游全挂时那个数照样涨，而它的用途正是证明劫持在工作。
   */
  dnsFailed: number
  /** 最近一次解析失败的时刻（Unix 毫秒），0 表示还没发生过。界面上"现在还在失败吗"靠它，不靠累计数。 */
  dnsFailedAt: number
  startedAt: number
  lastError: string
  applied: string[]
  /** 特权路径：self=本进程直接开（需要 root），helper=交给 tun.helper 提权命令 */
  privilege: string
  /** helper 模式下实际会执行的命令，只用于显示 */
  helperCmd: string[]
  /** 用户要不要 IPv6 假 IP（tun.ipv6）。false = 没要，别当成故障看 */
  ipv6: boolean
  /** v6 那一组命令是否真的装上了；ipv6 为 true 而它是 false 时 AAAA 回 NODATA */
  v6Ready: boolean
  /** IPv4 默认路由是否真的交给了 tun（全局接管） */
  takeoverV4: boolean
  /** IPv6 默认路由是否真的交给了 tun。false 时 v6 流量绕开隧道，仍走物理出口 */
  takeoverV6: boolean
  /**
   * 上面两格的来源：kernel 是刚问过路由表，memory 是问不到（只能按进程记忆推），
   * not-running 是 TUN 根本没在跑。界面对 memory 这一档必须明说不是实测。
   */
  takeoverFrom: string
  /** 网络变化后重钉绕行路由的次数；不为 0 说明「换网之后自己恢复了」 */
  routeFixes: number
  /** 上一次重钉的时刻（Unix 毫秒），0 表示还没发生过 */
  lastRouteFix: number
  /** 用户有没有开故障断网保护（tun.kill_switch）。它和 killArmed 是两件事 */
  killEnabled: boolean
  /** 保护此刻是否真的挂在网上 */
  killArmed: boolean
  /** 两族各自有没有被保护住：只护住一半是常态，必须分开报 */
  killV4: boolean
  killV6: boolean
  /** 没挂上（或只挂上一族）的原因；killEnabled 为真而这里非空 = 用户以为有、实际没有 */
  killReason: string
  /**
   * 系统解析器的查询到底进不进 tun：
   * yes=实测收得到；no=收不到（TUN 对不认代理环境变量的程序形同关闭）；
   * taken-over=本来收不到、已被面板把系统解析器改接过来；
   * unverified=验不出来（没有 resolvectl 或解析器没回答），也没动过系统。
   *
   * 四档而不是布尔：「没验过」与「验出没生效」是两句话，
   * 只有后者需要用户动手，而把它们合成一格就会在最该说清楚的场合含糊。
   */
  resolverFeeds: string
  /** 配着上面那句的证据：探针域名与答案，或者失败原因 */
  resolverDetail: string
  /** 接管过才有值：改的是哪张 link */
  resolverLink: string
  /** 接管过才有值：原上游。还原只能靠它——`resolvectl revert` 会把这条 link 直接掏空 */
  resolverPrev: string[]
}

export interface SystemProxyStatus {
  supported: boolean
  enabled: boolean
  mode: string
  http: string
  https: string
  socks: string
  ignored: string[]
  error: string
  /** 实际生效的后端：gnome | kde | env；不支持时为空 */
  backend: string
  /** 后端特有的生效范围说明（如 env 只对改动之后启动的进程生效） */
  note: string
  /** 改动落在哪个文件（env 为空，KDE 环境可能读不到） */
  path: string
}

/** 系统代理记账那一行：Go 侧 ui.LedgerView。 */
export interface SysProxyLedger {
  /**
   * 五种来自 Go 的状态，加上一种前端自己合成的：
   * none 没有记账；orphan 桌面指着我们却没记账；stale 欠一次自愈；
   * live 宿主还开着；unreadable 记账读不懂；
   * error 只在前端调不动绑定时使用——Go 永远不会报这个值，
   * 因为"读不到记账"和"记账说没有问题"是两回事。
   */
  state: 'none' | 'orphan' | 'stale' | 'live' | 'unreadable' | 'error'
  /** 直接印出来的一句话 */
  text: string
  /** 记账文件路径，让用户知道去哪儿自查 */
  path: string
}

/**
 * 一张本机可用的无线网卡，Go 侧 service.IfaceCardView。
 * 只在按网卡分流开着时才有内容——那时每 5 秒探测一次并顺手存下。
 */
export interface IfaceCardView {
  name: string
  /** 是不是插在 USB 口上的；界面上用它区分「内置 / USB」 */
  usb: boolean
  addrs: string[]
}

/**
 * 「两张无线都在时按网卡分流」的状态，Go 侧 service.IfaceSplitStatus。
 */
export interface IfaceSplitStatus {
  /** 开关本身：直连与代理各走一张无线卡 */
  enabled: boolean
  /** 此刻真的生效：开关开着 + 规则模式 + 两张卡都找到了 */
  active: boolean
  /** 选中的两张接口名，没选到时为空串 */
  directDev: string
  proxyDev: string
  /** 为什么现在没分流（只讲配置层面的原因）；没有这类原因时是空串 */
  note: string
  /** 下拉里的可选项。开关没开时是空数组——那时不探测，也就没有网卡可列 */
  cards: IfaceCardView[]
}

export interface InboundStatus {  type: string
  listen: string
  /** 实际监听地址；配置里写 127.0.0.1:0 时这里是内核分配的端口 */
  addr: string
  auth: boolean
  active: boolean
}

export interface Status {
  running: boolean
  /** rule / global / direct */
  mode: string
  profiles: ProfileView[]
  activeProfile: string
  /** 当前生效的节点是故障自动切换选出来的，并不等于配置文件里写的那个 */
  autoSwitched: boolean
  /** 自动切换的理由，未自动切换时为空 */
  switchReason?: string
  /**
   * 上一次自动切换发生的时刻（Unix 毫秒），0 = 本次运行没切过。
   * 光有 autoSwitched 那个布尔值不够：用户要判断的是「刚才那下是不是它干的」，
   * 那需要一个时间戳去和现象对齐。
   */
  autoSwitchedAt: number
  tun: TUNStatus
  ifaceSplit: IfaceSplitStatus
  /** Unix 毫秒，未运行时为 0 */
  startedAt: number
  uptimeMs: number
  server: string
  configPath: string
  inbounds: InboundStatus[]
  geoipPath: string
  geoipOk: boolean
  rulesFile: string
  domainRules: number
  ipRules: number
  /** 配置 block: 段装进去的拦截条数 */
  blockedRules: number
  finalPolicy: string
  rulesSkipped: string[]
  authSet: boolean
  sni: string
  bandwidthUp: string
  bandwidthDown: string
  congestion: string
  connected: boolean
  /** 当前出站协议：hysteria2 / trojan */
  proxyType: string
  /** 出站给的一句话摘要：已解析地址、SNI、隧道是否已建 */
  proxyStatus: string
  lastError: string
}

export interface ConnView {
  id: number
  /** Unix 毫秒，连接建立时刻 */
  start: number
  /** 毫秒。活跃连接由后端按采样时刻算，历史连接是实际存活时长 */
  duration: number
  inbound: string
  client: string
  host: string
  port: string
  target: string
  policy: string
  /** 命中的规则原文，如 GEOIP,CN,DIRECT 或 FINAL */
  matched: string
  outbound: string
  /**
   * 这条连接**实际**落在哪个去处名下：节点名、DIRECT，或被拦时是 REJECT。
   * 与 outbound 不是一回事——那是策略分组的名字（PROXY / DIRECT），
   * 而节点会自动切换、规则也能钉节点，所以「走了代理」答不出走的是哪个代理。
   */
  node: string
  /** 走了哪张网卡（wlp3s0f0 之类）；没开网卡分流时是空串 */
  iface: string
  /**
   * 非空表示这条连接**根本没建起来**（拨号失败），值就是那一句错误。
   * 空串是"没有失败"，不是"还不知道失败"。零字节、时长 0。
   */
  err: string
  up: number
  down: number
}

export interface Sample {
  /** Unix 毫秒 */
  t: number
  /** 字节/秒 */
  up: number
  /** 字节/秒 */
  down: number
}

/** 最近被拦的一个目标：同一 host + 同一条命中规则合并成一条，只更新次数与最近时刻。 */
export interface BlockedHit {
  host: string
  /** 命中的规则原文，如 DOMAIN-SUFFIX,ads.example.com,REJECT(block) */
  rule: string
  count: number
  /** 最近一次撞上的时刻（Unix 毫秒） */
  lastAt: number
}

export interface TrafficSnapshot {
  /** 已按流量降序排好，前端不必再排 */
  active: ConnView[]
  /** 按结束时间倒序 */
  history: ConnView[]
  series: Sample[]
  /** 最近被拦的目标，新→旧（上限 32 条，见 §5.1） */
  recentBlocked: BlockedHit[]
  activeCount: number
  totalConns: number
  /** 本次运行累计被拦的连接数（含还没收尾的）——拦截对客户端静默，这是本机的凭据 */
  totalBlocked: number
  /** 本次运行累计「拨不通」的连接数。与 totalBlocked 分开：拦下是按规则办，这个是出事了 */
  totalFailed: number
  totalUp: number
  totalDown: number
  /** 各去处本次用掉的字节，按**累计**降序；被拦的不占行（零字节只会稀释这张表） */
  byNode: NodeTraffic[]
  /** 字节记在哪条命中依据名下，按量降序；行数有上限，超出部分折进最后一行（folded） */
  byRule: RuleTraffic[]
  /**
   * 跨重启那份账的起点，Unix 毫秒；0 = 没有累计。
   * 「累计也清零」会把它拨到当下，于是这一栏读作"自 X 起累计"。
   */
  priorSince: number
  /** 上一次落盘的时刻，Unix 毫秒。崩溃会丢掉这之后的量，所以累计可能少算。 */
  priorSavedAt: number
  /**
   * 这一轮账本的收场：loaded / empty / too-new / unreadable。
   * 后两种要专门说一句——"没有累计"和"有一本累计但本程序不敢用"
   * 在屏幕上长得一样，而它们的处置方式完全不同。
   */
  usageState: string
}

export interface NodeTraffic {
  /** 节点名，或 DIRECT（直连的字节同样是"没走节点"的答案） */
  node: string
  up: number
  down: number
  conns: number
  /**
   * 上一次进程落盘时这个节点已经跑掉的字节（up+down 合在一起）。
   * 「累计」= up + down + prior；0 表示没有跨重启的账。见 README §9.5.2。
   */
  prior: number
}

export interface InboundForm {
  type: string
  listen: string
  /** 未设置凭据时为空串，设置了则是 ******** */
  username: string
  password: string
}

export interface TUNForm {
  enable: boolean
  device: string
  address: string
  mtu: number
  dns: string
  fakeIpRange: string
  hijackDns: boolean
  strictRoute: boolean
  routeExclude: string[]
  /** 故障断网保护：默认关闭，只在 strictRoute 下有意义 */
  killSwitch: boolean
}

export interface ConfigForm {
  path: string
  /** rule / global / direct，界面改的是「文件里的默认值」，即时切换走 SetMode */
  mode: string
  /** 只读：当前选中节点的名字与地址，节点增删改在节点面板里做 */
  activeName: string
  activeAddr: string
  inbounds: InboundForm[]
  geoipPath: string
  rulesFile: string
  dnsServers: string[]
  dnsTimeout: string
  dnsCache: string
  logLevel: string
  tun: TUNForm
}

/** 一条自定义域名规则（面板「域名规则」维护，优先于内置规则集）。 */
export interface UserRule {
  /**
   * Go 侧照实报规则类型：面板能改的是 DOMAIN-SUFFIX / DOMAIN / DOMAIN-KEYWORD，
   * 手写的 IP-CIDR / GEOIP / DOMAIN-REGEX 会以它们本来的名字出现（只读）。
   */
  type: string
  value: string
  /** PROXY | DIRECT | REJECT（REJECT 与"手写的非域名类型"都只读） */
  policy: string
  /**
   * 非空 = 这条规则的 PROXY 流量钉到配置里那个名字的节点，
   * 而不是"当前选中的那个"。规则行的第四个可选字段（node=名字），
   * 只有 PROXY 能带；DIRECT/REJECT 带它会被后端当场拒掉。
   */
  node: string
  /**
   * true = 这一条被停用了：留在名单里、留在面板上，但不参与匹配。
   * 规则行上的 `,off`（见 §5.8）。存在的理由是"我想看看是不是这条把网站弄坏的"
   * 今天只能靠删掉它来试，而删掉之后就记不得原来写的是什么了。
   */
  disabled: boolean
}

/** 一次批量粘贴的下场：每一行都要有答案，否则用户只能自己数。 */
export interface UserRuleImport {
  /** 读到的非空、非注释行数。0 与"整段都是注释"是同一件事，界面上照实说。 */
  total: number
  /** 名单里原来没有、这次新加上的条数 */
  accepted: number
  /** 同类型同域名已经存在、这次被覆盖掉的条数——必须单列，不然用户不知道自己改了谁 */
  updated: number
  /** 被拒的哪几行，一行一句原因 */
  rejected: string[]
  /** 这次收下的行里，哪些装上但永远不会命中 */
  dead: string[]
  /** 文件到底动了没有。全被拒时是 false，提示就不许写"已保存" */
  written: boolean
}

/**
 * 一条自定义规则在本次会话里被用过的次数。
 * 与判语是两种问法：判语推得出"永远轮不到"，只有计数说得出"轮到过没有"。
 */
export interface RuleHit {
  /** TYPE,VALUE —— 也就是规则表那一行的身份 */
  key: string
  /** 这一条定过多少条连接。0 有两种意思（还没轮到 / 其实没用），所以它不下结论 */
  hits: number
}

/**
 * 规则页「这份名单里有问题」那一栏的一条判语。
 * 拆成 line + why 而不是一整句：用户自己写的那一行要用等宽字体单独立出来，
 * 「为什么」与「怎么办」合成后半句。界面不用去句子中间找位置。
 */
export interface RuleWarning {
  /** 'shadow' = 被前面的规则盖住，永远轮不到；'node-missing' = 钉的节点已经不存在 */
  kind: string
  /** 用户写的那一行，原样照抄（含 node= 那一段） */
  line: string
  /** 后半句：为什么有这个问题，以及怎么办 */
  why: string
}

/** 规则页「拦截域名」那一栏的答案。 */
export interface BlockView {
  /** 正在生效的名单（已归一化：小写、去尾点、去重） */
  domains: string[]
  /** false = 代理没在跑，这份是按磁盘配置算的 */
  live: boolean
  /** 直连模式下名单整体让开，界面必须一起说明 */
  mode: string
  /** 名单住在哪个文件里（配置段，界面只读） */
  path: string
  /** 装了却什么也没多拦的条目，一句一条：名单按后缀拦，已有 example.com 时再加 ads.example.com 是空操作 */
  dead: string[]
  /** 死条目的真实总数——dead 最多带前 200 条，几千条每轮都搬过桥面板会卡 */
  deadTotal: number
}

/** 一次批量粘贴拦截域名的结果。 */
export interface BlockImport {
  /** 读到的非空、非注释行数 */
  total: number
  /** 名单里原来没有、这次新加上的条数 */
  accepted: number
  /** 名单里本来就有（含同一次粘贴里重复的），这次什么都没加 */
  existing: number
  /** 被拒的哪几行，一行一句原因（例外规则、hosts 一行多域名、带协议路径的…） */
  rejected: string[]
  /** 这次新加的行里，哪些装上却不会多拦下任何东西 */
  dead: string[]
  /** 文件到底动了没有。全被拒或全是已有条目时是 false，提示就不许写"已保存" */
  written: boolean
}

export interface RulesFileView {
  path: string
  size: number
  /** 空串 = 这一轮读不到这个文件（被删了，或编辑器正把它挪走） */
  modTime: string
  /** 与 modTime 为空是同一件事的两种问法：界面要分得开"读不到"与"空文件" */
  readable: boolean
}

export interface RulesWatchView {
  /** false = 此刻没在监视，改文件不会自己生效。空文件列表不等于"没什么可看" */
  watching: boolean
  /** 轮询间隔，用来解释"改了为什么还要等几秒" */
  intervalSec: number
  files: RulesFileView[]
  /** 最近一次成功重载的时刻；空串 = 本次运行还没有过重载 */
  lastReload: string
}

export interface SubscriptionView {
  name: string
  /** 缓存落盘位置。URL 不上界面：订阅地址常直接带鉴权 token。 */
  path: string
  everySec: number
  /** 上一次尝试的时刻（成功失败都算）；0 = 这个进程还没碰过它 */
  lastAttemptMs: number
  /** 上一次拉成功的时刻；0 = 从没成功过 */
  lastOkMs: number
  /** 下一次大概什么时候拉；0 = 没在跑，不会去拉 */
  nextDueMs: number
  /** 空串 = 没有未消化的故障 */
  lastErr: string
  /** 连续失败次数，拉成功即归零 */
  fails: number
  size: number
  /** 缓存此刻在不在磁盘上。与 lastOkMs 是两件事：拉通过但文件被人删了就是这种现场。 */
  hasCache: boolean
}

export interface ProviderRefresh {
  name: string
  /** 这一条这次有没有真的换到新内容 */
  changed: boolean
  /** 这一条失败的原因；空串 = 拉通了（内容没变也算拉通） */
  err: string
}

export interface ProviderRefreshReport {
  results: ProviderRefresh[]
  /** 只在"确有内容变了、且按新内容成功重载了规则"时为真 */
  reloaded: boolean
  /** 非空 = 内容变了但重载失败，此刻**仍在用旧规则**服务 */
  reloadErr: string
}

export interface SubscriptionsView {
  /** 配置里启用了几条。0 与"读不到配置"是两回事，后者看 configErr。 */
  configured: number
  /** false = 循环没在跑；这时 items 里的时刻全是 0，不许画成"很久没更新" */
  running: boolean
  items: SubscriptionView[]
  /** 启动时被拒的条目原文（重名、缓存路径撞车…） */
  errors: string[]
  /** 非空 = 连配置都没读到，上面那些数字全都不可信 */
  configErr: string
}

export interface ProbeResult {
  host: string
  policy: string
  /** 命中的规则原文，如 DOMAIN-SUFFIX,notion.so,PROXY / MODE,GLOBAL / FINAL */
  matched: string
  mode: string
  /**
   * 判成 PROXY 时字节会记到谁头上：规则钉住的名字，没钉就是当前活动节点。
   * 直连与拦截是空串（那两侧的 "DIRECT"/"REJECT" 是去处名，不是节点名）。
   * 代理没在跑时它来自磁盘：钉住的用钉住的，否则用配置里 active 那一个。
   */
  node: string
  /** 这条流量会被钉在哪张网卡上（按网卡分流）；空串 = 没钉，代理没在跑时也留空 */
  iface: string
  /** false = 代理没在跑，按磁盘上的规则集算的 */
  live: boolean
}

/**
 * 「取一个真页面」的一次结果：这一格与 ProbeResult 是一对，
 * 那边答"按规则会怎么走"，这边答"那它实际回什么"。
 *
 * 分开是因为两者会不一致：节点对面是一台兜底 web 服务器时，
 * 判定正常、电路也建得起来，而任何站点回来的都是同一个 400。
 */
export interface PageFetch {
  /** 回显用的网址：查询串与 userinfo 已经去掉（订阅 key 常挂在查询串上，而这一格会被截图） */
  url: string
  /** 真正拨出去的 host:port（补上默认端口之后） */
  addr: string
  /** HTTP 状态码；0 = 连上了但没拿到状态行 */
  code: number
  /** `Server:` 头——兜底 web 服务器就是在这里露馅的 */
  server: string
  /** 数到的正文字节（探针有上限，不是整页大小） */
  body: number
  /** 这一条走的是 https（TLS 在本地做，交给节点的是明文 CONNECT） */
  viaTLS: boolean
  /** 3xx 的去向：跳到一个登录页也是一种"没通" */
  location: string
  /**
   * **取回一个 400 不是"查询失败"**，那正是这一问的答案。
   * ok=false 而界面仍要摆出状态码与 `Server:`，所以这是一格而不是异常。
   */
  ok: boolean
  /** 给人看的那一句：不通时是"为什么不算通"，通时是状态行那一串 */
  reason: string
  /** 以下四格是这一条**实际**走的判定（拨号那一刻的路由结果），与 ProbeResult 同名同源 */
  policy: string
  matched: string
  node: string
  iface: string
}

/** 一个地址"被怎么看"：归属码 + 库里到底有没有这条。 */
export interface AddrView {
  addr: string
  /** GeoIP 归属码（CN / US / …）。空串可能是"没配库"，也可能是"库里没有这条" */
  country: string
  /** false = 不知道。把"不知道"显示成"不是 CN"是把一个未知报成结论 */
  known: boolean
}

/** 一个上游的回话，以及"只看它给的那批地址会判成什么"。 */
export interface UpstreamView {
  server: string
  addrs: string[]
  policy: string
  matched: string
  ms: number
  /** 非空 = 这个上游没答上来（超时、REFUSED…）。它仍然要摆出来：少报一档比报难看更糟 */
  err: string
}

/**
 * 「看解析」的一次读数：诊断三连里的第三问。
 * 查走向答"按规则该怎么走"，取页面答"它实际回什么"，
 * 这一格答中间那一问——**引擎此刻拿去判定的到底是哪批 IP**。
 */
export interface DNSProbe {
  /** 洗过的查询名（小写、去尾点） */
  host: string
  /** 这次真的走了哪条路：direct / tunnel。没注入隧道拨号器时报 direct，不假装走了隧道 */
  via: string
  /** 配置里让不让经隧道问上游。与 via 分开：「配了但隧道没起来」是第三种状态 */
  tunnelOn: boolean
  /** 这份答案是缓存里的，没出门问 */
  cached: boolean
  /**
   * 这一次是按「不用缓存」按下去的：没读缓存，问完把新答案写回了缓存。
   * 它和 cached 不是一对反义词——cached 讲"这份答案从哪儿来"，
   * fresh 讲"你这一下**改掉了**什么"。少了后一句，界面就没法说
   * "引擎下一刻拿的是这批"，而这一按动的正是引擎下一刻的判定依据。
   */
  fresh: boolean
  /**
   * 非空 = 这一次是**只点名重问这一个上游**，值就是它。
   * 单独报是因为这一按之后合并那一路刻意没再走（再走等于让另一个上游把刚写回的又盖掉），
   * 界面不说清刷的是哪一家，人就以为刷的是整条路径。
   */
  refreshed: string
  /**
   * 这份答案**还剩多久**自己变新：命中缓存 = 剩余时间，刚问到 = 整条 TTL。
   * 0 = 不适用（IP 字面量那条路根本不经过缓存）。
   */
  ttlMs: number
  /** 这次用了多久（新鲜不新鲜看 cached，不看它） */
  ms: number
  /** 配置里那几个上游；查污染时第一个要看的就是这份名单 */
  upstreams: string[]
  /** 引擎此刻拿去判定的那批地址 */
  addrs: AddrView[]
  /**
   * 挨个上游各问一遍的结果（不合并、不抢先返回）。
   * 这一份才是"哪个上游在说谎"那一问的答案——上面 addrs 走的是"任一成功即采用"。
   */
  perUpstream: UpstreamView[]
  /** 至少两个上游给了不同的地址集合。一个上游回两条地址**不算**分叉 */
  divergent: boolean
  /** 上面那份合并答案对应的是哪个上游；空串 = 说不清（只有一个上游，或与谁都不完全相同） */
  used: string
  /** 引擎对这个域名的完整判定（域名规则可能先命中） */
  policy: string
  matched: string
  /** 只看这批 IP 会判成什么。两半不一样 = 域名规则先命中，DNS 根本没参与这次结论 */
  ipPolicy: string
  ipMatched: string
  /** 为什么这一格是空的：解析不出、没配 GeoIP 库这类。空表不写一句会被读成"这域名没地址" */
  note: string
}

/**
 * 这份界面自己是哪一次构建。存在的理由很具体：界面是 go:embed 进二进制的，
 * 磁盘上重新构建过多少次都不关正在跑的那个进程的事，
 * 于是"面板上怎么没有那个界面"的第一嫌疑始终是**进程旧**，而不是改动没做。
 * 与其让人去比 `strings wps_app-gui | grep index-` 和 `ls frontend/dist`，
 * 不如把这两个数摆到同一屏上，并直接给出结论（newerOnDisk）。
 */
export interface BuildInfo {
  /** VERSION 文件里的版本号 */
  version: string
  /** 源码指纹：git 短 commit（脏树带 -dirty），没有 git 时是内容哈希 */
  stamp: string
  /** 构建时刻（UTC ISO 8601）；空 = 没走构建脚本 */
  builtAt: string
  /** 本进程的可执行文件路径 */
  exePath: string
  /** 磁盘上那份二进制的改动时间（Unix 毫秒），0 = 没读到 */
  exeModTime: number
  /** 本进程启动时刻（Unix 毫秒） */
  startedAt: number
  /** 内嵌 index.html 引用的 JS 资源名，如 index-cZ8NrLDR.js；空 = 这份产物不带界面 */
  frontend: string
  /** 磁盘上的二进制比本进程新：你看到的界面是旧的 */
  newerOnDisk: boolean
}

export interface LogEntry {
  seq: number
  /** 形如 15:04:05，后端已经格式化好 */
  time: string
  level: string
  msg: string
}

export interface LogPage {
  entries: LogEntry[]
  /** 缓冲里最新的 Seq，下次带上它做增量拉取 */
  latest: number
  /** 中间被环形缓冲覆盖过，调用方必须整表替换而不是追加 */
  truncated: boolean
}

/**
 * 用户点下去、后端还没回读到的那几个瞬间。
 * 只用来把 knob 与高亮先拨到目标位置，不参与任何判断（见 App.vue 的 act）。
 */
export interface Pending {
  mode?: string
  profile?: string
  tun?: boolean
  sysproxy?: boolean
  ifaceSplit?: boolean
}
