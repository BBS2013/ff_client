<script setup lang="ts">
// App.vue 是唯一的数据出口：所有后端调用都从这里发起，子组件只管显示。
//
// 为什么用 1 秒轮询而不是 Wails 事件订阅：
// 事件订阅要把「谁在订阅、何时退订」和窗口生命周期对齐，托盘隐藏、面板重开
// 这些路径很容易漏掉退订导致回调打在已销毁的组件上。轮询没有这类竞态，
// 而且窗口隐藏时可以直接停掉，代理照样跑，CPU 也不涨。
//
// 忙态分两层也在这里定：全局动作（启停、切模式、切节点、TUN、系统代理）共用
// 一个 busy，它们会互相打断，灰掉是对的；页内动作（测速、存节点、改规则、
// 保存配置）由各自组件自己管，不该让「正在测速」把顶栏的「停止」也灰掉。
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import Dashboard from './components/Dashboard.vue'
import LogStream from './components/LogStream.vue'
import Nodes from './components/Nodes.vue'
import Rules from './components/Rules.vue'
import Settings from './components/Settings.vue'
import TopBar from './components/TopBar.vue'
import Traffic from './components/Traffic.vue'
import ShortcutHelp from './components/ShortcutHelp.vue'
import type { LogEntry, Pending, ProfileTest, Status, SysProxyLedger, SystemProxyStatus, TrafficSnapshot } from './types'
import { formatClock, modeText, TUN_PHASE_TEXT, tunPhase } from './format'
import { nodeTests } from './nodetests'
import { agoText } from './ageclock'
import {
  errorText,
  isDemo,
  logs,
  reloadRules,
  resetStats,
  restartProxy,
  setMode,
  setActiveProfile,
  setSystemProxy,
  setTUNEnabled,
  setIfaceSplitEnabled,
  setIfaceSplitCards,
  startProxy,
  status,
  stopProxy,
  systemProxyLedger,
  systemProxyStatus,
  traffic
} from './api'

const POLL_MS = 1000

/** 日志页开很久时 entries 不能无限长：后端环形缓冲本身有上限，前端跟着封顶。 */
const LOG_CAP = 2000

type View = 'overview' | 'nodes' | 'rules' | 'traffic' | 'logs' | 'settings'

const VIEWS: Array<{ id: View; label: string }> = [
  { id: 'overview', label: '总览' },
  { id: 'nodes', label: '节点' },
  { id: 'rules', label: '规则' },
  { id: 'traffic', label: '流量' },
  { id: 'logs', label: '日志' },
  { id: 'settings', label: '设置' }
]

const EMPTY_STATUS: Status = {
  running: false,
  mode: 'rule',
  profiles: [],
  activeProfile: '',
  autoSwitched: false,
  autoSwitchedAt: 0,
  ifaceSplit: {
    enabled: false,
    active: false,
    directDev: '',
    proxyDev: '',
    note: '',
    cards: []
  },
  tun: {
    enabled: false,
    running: false,
    device: '',
    address: '',
    dns: '',
    fakeIpRange: '',
    hijackDns: false,
    strictRoute: false,
    fakeIps: 0,
    active: 0,
    dnsServed: 0,
    dnsFailed: 0,
    dnsFailedAt: 0,
    startedAt: 0,
    lastError: '',
    applied: [],
    privilege: '',
    helperCmd: [],
    ipv6: false,
    v6Ready: false,
    takeoverV4: false,
    takeoverV6: false,
    takeoverFrom: '',
    routeFixes: 0,
    lastRouteFix: 0,
    killEnabled: false,
    killArmed: false,
    killV4: false,
    killV6: false,
    killReason: ''
  },
  startedAt: 0,
  uptimeMs: 0,
  server: '',
  configPath: '',
  inbounds: [],
  geoipPath: '',
  geoipOk: false,
  rulesFile: '',
  domainRules: 0,
  ipRules: 0,
  blockedRules: 0,
  finalPolicy: '',
  rulesSkipped: [],
  authSet: false,
  sni: '',
  bandwidthUp: '',
  bandwidthDown: '',
  congestion: '',
  connected: false,
  proxyType: '',
  proxyStatus: '',
  lastError: ''
}

const EMPTY_TRAFFIC: TrafficSnapshot = {
  active: [],
  history: [],
  byNode: [],
  byRule: [],
  series: [],
  recentBlocked: [],
  priorSince: 0,
  priorSavedAt: 0,
  usageState: '',
  activeCount: 0,
  totalConns: 0,
  totalBlocked: 0,
  totalFailed: 0,
  totalUp: 0,
  totalDown: 0
}

/** 读不到时的系统代理读数：supported=false、error 非空，界面上就是"读取失败"这一档。 */
/**
 * 读不到记账时的读数。state='error' 是前端自己造的那一档：
 * Go 永远不会报它——「调不动绑定」和「记账说没问题」是两回事，
 * 合成一个 error 才不会那一栏一直停在"读取中…"骗人等下一轮。
 */
const ERR_LEDGER: SysProxyLedger = { state: 'error', text: '', path: '' }

const EMPTY_SYS: SystemProxyStatus = {
  supported: false,
  enabled: false,
  mode: '',
  http: '',
  https: '',
  socks: '',
  ignored: [],
  error: '',
  backend: '',
  note: '',
  path: ''
}

const view = ref<View>('overview')

/**
 * 从连接表点「加规则」带过来的域名。
 *
 * 这一页与规则页之间原来隔着三步：在表里读域名 → 复制 → 切页 → 粘进表单。
 * 而"该怎么走"这个决定恰恰是在看着这条连接的时候做的，不是在填表的时候做的。
 *
 * 只带域名，不带策略：策略是用户到了规则页要做的选择，替他猜一个
 * （比如照抄这条连接实际的走向）等于把一个可能不对的默认值藏进表单里。
 * 规则页拿到它之后会清空，所以第二次进来不会被上一次的域名影响。
 */
const ruleSeed = ref('')

function onSeedRule(host: string): void {
  ruleSeed.value = host
  view.value = 'rules'
}

/**
 * 从流量页那条「拨不通」的连接带过来的一个网址：切到规则页、填进「取一个真页面」、聚焦。
 *
 * 与上面那条的区别只有一件：**不自动跑**。协议那一格是照端口猜的（443/没端口 = https），
 * 让人看一眼再按回车，比替他跑错一次再让他去查"为什么 TLS 握手失败"省事。
 */
const fetchSeed = ref('')

function onSeedFetch(url: string): void {
  fetchSeed.value = url
  view.value = 'rules'
}

/** 同上，带过去的是一个域名（不带协议、不自动跑）：填进「看解析」并聚焦。 */
const dnsSeed = ref('')

function onSeedDNS(host: string): void {
  dnsSeed.value = host
  view.value = 'rules'
}

/**
 * 总览上那一格「拨不通 N」点过来：切到流量页**并且直接筛好**。
 * 只 goto 的话用户落在一张 300 行的表前，还得自己找到那个档——
 * 他从总览过来要的答案是"是哪些"，不是"再找一遍"。
 */
const waySeed = ref('')

function onShowFailures(): void {
  waySeed.value = 'failed'
  view.value = 'traffic'
}

/**
 * 浏览器里用 ?view= 直接落到某一页。
 *
 * 和 api.ts 里那套 ?demo= 场景是同一个理由：界面改完要能反复看到每一页，
 * 否则"截图看一眼总览"就算验过了，另外五页的排版坏了没人知道。
 * 真面板走 Wails，location.search 是空的，这里永远取默认值。
 */
{
  const want =
    typeof location === 'undefined'
      ? null
      : new URLSearchParams(location.search).get('view')
  if (want && VIEWS.some((v) => v.id === want)) {
    view.value = want as View
  }
}
const snap = ref<Status>(EMPTY_STATUS)
const tr = ref<TrafficSnapshot>(EMPTY_TRAFFIC)
const sys = ref<SystemProxyStatus | null>(null)
/** 系统代理的记账读数：那个 ON 是谁改的、退出会不会还原。null 只在第一批读数到来前出现。 */
const ledger = ref<SysProxyLedger | null>(null)
/**
 * 当前节点最近一次测速的读数，供总览页那一行用。
 *
 * 数据来自节点页那份跨页留着的结果（`nodetests.ts`），这里不发新请求：
 * 测速是用户点出来的，不该因为切到总览就自己跑一遍（每跑一次都要经节点多取一次页面）。
 * null 就是"这个节点还没测过"，界面上必须这么说，不许留白让人以为一切正常。
 */
const activeTest = computed<(ProfileTest & { ago: string }) | null>(() => {
  const entry = nodeTests[snap.value.activeProfile]
  if (!entry) {
    return null
  }
  return { ...entry.res, ago: agoText(entry.at) }
})
const entries = ref<LogEntry[]>([])
/** 缓冲被覆盖过，LogStream 用它提示「这里不连续」 */
const logTruncated = ref(false)
/** 第一批日志是否真的读到了：没读到之前那一页只能写"正在读"，不能写"还没有日志"。 */
const logsLoaded = ref(false)
const busy = ref('')
const banner = ref('')
const pollError = ref('')
/** 是否成功读到过至少一帧状态。没读到过就不该渲染任何"看起来正常"的空状态。 */
const loadedOnce = ref(false)
/** 最近一次「所有读数都拿到」的时刻。失败时用它说明"界面上这些数字是几点停下的"。 */
const lastOkAt = ref(0)
/**
 * 读不到数据时返回"读数停在几点"，一切正常时返回空串。
 * 曾经读到过、现在读不到，比从来没读到过更危险：旧数字长得和实时数字一模一样。
 */
const staleAt = computed(() =>
  loadedOnce.value && pollError.value !== '' && lastOkAt.value > 0
    ? formatClock(lastOkAt.value)
    : ''
)

/** 日志增量拉取的游标：下次带上本地最大的 Seq。 */
let logCursor = 0
let timer: number | null = null
let polling = false
/** 轮询进行中又来了一次（例如某个操作做完要立刻回读），记一笔，本轮结束补一次。 */
let pollAgain = false

/**
 * 用户点下去、后端还没回读到的那几个瞬间，见 types.ts 的 Pending。
 * 只用来把 knob/高亮先拨到目标位置；操作一结束就清掉，一切以 Status() 回读为准——
 * 请求失败时后端可能根本没动，让乐观状态常驻就会显示出一个不存在的「TUN 已关」。
 */
const pending = ref<Partial<Pending>>({})

const last = computed(() => {
  const s = tr.value.series
  return s.length ? s[s.length - 1] : null
})

/**
 * 侧栏每页右侧那个数字。只在"读到了、且这个数有意义"时给，
 * 否则留空——把 EMPTY_STATUS 的 0 画上去等于在说"你有 0 个节点"，
 * 而真实情况可能是一次都没读成功。
 */
const railCounts = computed<Partial<Record<View, string>>>(() => {
  if (!loadedOnce.value) {
    return {}
  }
  const out: Partial<Record<View, string>> = {}
  if (snap.value.profiles.length > 0) {
    out.nodes = String(snap.value.profiles.length)
  }
  const rules = snap.value.domainRules + snap.value.ipRules
  if (rules > 0) {
    out.rules = rules >= 1000 ? `${(rules / 1000).toFixed(1)}k` : String(rules)
  }
  if (tr.value.activeCount > 0) {
    out.traffic = String(tr.value.activeCount)
  }
  return out
})

/** 顶栏标题：六个页面共用一条工具栏时，翻页在顶部毫无反馈。 */
const viewTitle = computed(() => VIEWS.find((v) => v.id === view.value)?.label ?? '')

/* ---------- 侧栏底部那两盏灯 ----------
   TUN 与系统代理是"现在是什么状态"，不是"此刻要按的按钮"，
   所以从顶栏挪到侧栏：顶栏原来十来个控件挤在 1080px 里必然换行。 */

const tunPhaseNow = computed(() => tunPhase(snap.value.tun, pending.value.tun))
const tunOn = computed(() => tunPhaseNow.value === 'on' || tunPhaseNow.value === 'starting')
/**
 * 稳态下设备名比"运行中"更有用；过渡态那几个字必须占位，否则看着像点了没反应。
 *
 * 但一次都没读成功时不许写"未启用"：EMPTY_STATUS 的 tun.running 是 false，
 * 拿它推出来的"未启用"其实是在替一个我们并不知道的状态编故事。
 * 顶栏原来靠"只印 TUN 两个字"绕开了这个坑，这里得明说"未知"。
 */
const tunValue = computed(() => {
  if (!loadedOnce.value && pending.value.tun === undefined) {
    return '未知'
  }
  return tunPhaseNow.value === 'on'
    ? snap.value.tun.device || '运行中'
    : TUN_PHASE_TEXT[tunPhaseNow.value]
})
const sysOn = computed(() => pending.value.sysproxy ?? sys.value?.enabled ?? false)
// 这一格平时只说"开没开"。但"开着而没人负责还原"是另一件事：
// 进程一走桌面就指向死端口，整机断网——所以它必须在侧栏也看得出来，
// 而不是等人翻回总览页。stale 不升级：那是下一次启动会自动还的，不用吓人。
const sysAlarm = computed(() => {
  const st = ledger.value?.state ?? ''
  return st === 'orphan' || st === 'unreadable' || st === 'error'
})
const sysValue = computed(() => {
  if (busy.value === 'sysproxy') return sysOn.value ? '设置中…' : '恢复中…'
  if (sys.value === null) return '读取中…'
  if (sys.value.error) return '读不到'
  return sysOn.value ? sys.value.http || '已开启' : '未开启'
})
const sysTitle = computed(() => {
  if (sys.value === null) return '系统代理状态还没读到，点击去设置'
  if (sys.value.error) return `系统代理状态读不到：${sys.value.error}，点击去设置`
  const base = sysOn.value
    ? `系统代理已指向 ${sys.value.http || '本客户端'}，点击去设置`
    : '系统代理未开启，点击去设置'
  return sysAlarm.value && ledger.value ? `${base}（${ledger.value.text}）` : base
})

function flash(msg: string): void {
  banner.value = msg
  window.setTimeout(() => {
    if (banner.value === msg) {
      banner.value = ''
    }
  }, 4000)
}

/**
 * 后端的环形缓冲可能已经把我们要的区间覆盖掉了。
 * 这时报 Truncated，前端只能整表替换——在缺口上做追加等于骗人。
 */
function mergeLogs(patch: Awaited<ReturnType<typeof logs>>): void {
  if (patch.truncated || patch.entries.length === 0) {
    if (patch.entries.length > 0) {
      entries.value = patch.entries.slice(-LOG_CAP)
      logTruncated.value = patch.truncated
    }
    logCursor = Math.max(logCursor, patch.latest)
    return
  }
  entries.value = entries.value.concat(patch.entries).slice(-LOG_CAP)
  logCursor = patch.latest
}

async function poll(): Promise<void> {
  if (polling) {
    // 正在拉的那一轮可能已经带着"操作前"的状态发出去了。这里不能直接 return：
    // act() 的 finally 会 await 它，静默跳过就等于让用户再多等一个轮询周期。
    pollAgain = true
    return
  }
  polling = true
  try {
    do {
      pollAgain = false
      // 三个读数各拿各的。Promise.all 的语义是"一个坏全作废"：
      // 流量拉失败会把还活着的 Status 一起冻在旧值上，而顶栏照样写"运行中"。
      const [s, t] = await Promise.allSettled([status(), traffic()])
      const bad: string[] = []
      if (s.status === 'fulfilled') {
        snap.value = s.value
      } else {
        bad.push(`状态 ${errorText(s.reason)}`)
      }
      if (t.status === 'fulfilled') {
        tr.value = t.value
      } else {
        bad.push(`流量 ${errorText(t.reason)}`)
      }
      if (view.value === 'logs') {
        try {
          mergeLogs(await logs(logCursor))
          logsLoaded.value = true
        } catch (err) {
          bad.push(`日志 ${errorText(err)}`)
        }
      }
      if (bad.length === 0) {
        pollError.value = ''
        loadedOnce.value = true
        lastOkAt.value = Date.now()
      } else {
        // 失败时界面停在几点必须说出来：不说，旧数字看起来就是实时数字。
        const at = lastOkAt.value > 0 ? `，界面停在 ${formatClock(lastOkAt.value)}` : ''
        pollError.value = `读取失败：${bad.join('；')}${at}`
      }
    } while (pollAgain)
  } catch (err) {
    pollError.value = `读取状态失败：${errorText(err)}`
  } finally {
    polling = false
  }
}

// 切到日志页要立刻补一批，不能等下一次轮询。
//
// 实测过代价：点「日志」之后首屏内容要 0.55~0.6 秒才出现，中间那一格写的是
// "正在读第一批日志…"。那半秒纯粹是轮询相位——demo=normal 与 demo=big 两档
// 量出来一样，说明跟数据量无关，只是运气不好赶上 ticker 还没走到。
// 用户主动切页就是一个明确的"现在就要"信号，没必要替他省这一次往返。
watch(view, (v) => {
  if (v === 'logs') {
    void poll()
  }
})

/** 记账那一行也一样不在 Status 里，而且读它可能要再问一次后端，所以跟着桌面读数一起补。 */
async function pollLedger(): Promise<void> {
  try {
    ledger.value = await systemProxyLedger()
  } catch (err) {
    ledger.value = { ...ERR_LEDGER, text: `读不到记账：${errorText(err)}` }
  }
}

/** 系统代理不在 Status 里，单独读：桌面侧可能被别的程序改，所以每次重新显示窗口都补读一次。 */
async function pollSys(): Promise<void> {
  // 两份读数各读各的：记账读不懂不该让桌面那栏退回"读取中"，反过来也一样。
  void pollLedger()
  try {
    sys.value = await systemProxyStatus()
  } catch (err) {
    // 不能只把错误塞进全局提示、让 sys 停在 null：那一栏会一直显示"读取中…"，
    // 而它其实已经确定读不到了。合成一个"只有 error"的读数，
    // 三个组件里现成的 sys.error 分支就会把它讲对。
    sys.value = { ...EMPTY_SYS, error: errorText(err) }
  }
}

/** 包一层：所有全局操作共用同一套忙状态与错误提示，避免每个按钮各写一遍。 */
async function act(name: string, fn: () => Promise<void>, done: string, p: Partial<Pending> = {}): Promise<void> {
  if (busy.value !== '') {
    return
  }
  busy.value = name
  pending.value = { ...pending.value, ...p }
  try {
    await fn()
    flash(done)
  } catch (err) {
    flash(`${done.replace(/。$/, '')}失败：${errorText(err)}`)
  } finally {
    busy.value = ''
    const rest = { ...pending.value }
    for (const k of Object.keys(p) as Array<keyof Pending>) {
      delete rest[k]
    }
    pending.value = rest
    // 操作后立刻拉一次，界面不等下一秒的轮询。
    await poll()
  }
}

const onStart = (): Promise<void> => act('start', startProxy, '已启动代理。')
const onStop = (): Promise<void> => act('stop', stopProxy, '已停止代理，桌面代理指针已收回，流量走直连。')
/**
 * 应急出口（总览页「一键解绑」）：走的是与「停止代理」同一条后端路径，
 * 差别只在提示语——上不了网的人正盯着"桌面指针收回没有"这件事，
 * 所以这句要把它写出来，而不是只说"已停止"。
 */
const onUnbind = (): Promise<void> =>
  act('stop', stopProxy, '已解绑：桌面代理指针已收回、入站端口已关闭，现在走直连；节点与规则没动。')
/** 解绑之后回到接管状态：启动代理，并按需把桌面指针放回去。 */
const onRebind = (): Promise<void> =>
  act('start', startProxy, '已重新接管：代理已启动，桌面代理指针已放回。')
const onRestart = (): Promise<void> => act('restart', restartProxy, '已重启代理。')
const onReload = (): Promise<void> => act('reload', reloadRules, '已重载规则。')
const onReset = (): Promise<void> =>
  act('reset', async () => {
    await resetStats()
    entries.value = []
  }, '已清空统计。')

const onMode = (m: string): Promise<void> =>
  act(
    `mode:${m}`,
    () => setMode(m),
    `已切到${modeText(m)}模式。`,
    { mode: m }
  )

const onProfile = (name: string): Promise<void> =>
  act(`profile:${name}`, () => setActiveProfile(name), `已切换到节点 ${name}。`, { profile: name })

const onTUN = (enable: boolean): Promise<void> =>
  act('tun', () => setTUNEnabled(enable), enable ? 'TUN 模式已开启。' : 'TUN 模式已关闭。', { tun: enable })

const onSysProxy = (enable: boolean): Promise<void> =>
  act(
    'sysproxy',
    () => setSystemProxy(enable),
    enable ? '系统代理已指向本客户端。' : '系统代理已关闭。',
    { sysproxy: enable }
  ).then(pollSys)

/** 开它要重建隧道让代理真的换到 USB 无线那张卡上，所以同样先拨 knob 再等后端。 */
const onIfaceSplit = (enable: boolean): Promise<void> =>
  act(
    'ifaceSplit',
    () => setIfaceSplitEnabled(enable),
    enable ? '已开启按网卡分流。' : '已关闭按网卡分流。',
    { ifaceSplit: enable }
  )

/**
 * 换一张卡走直连或代理。落在代理那一侧时要重建隧道，代价与换节点同档，
 * 因此同样走 act()：按钮在这期间禁用，且失败要说清是后端拒绝了还是网络没成。
 */
const onIfaceSplitCards = (direct: string, proxy: string): Promise<void> =>
  act(
    'ifaceCards',
    () => setIfaceSplitCards(direct, proxy),
    '已按新的网卡分工。'
  )

/** 子组件只递字符串过来，切页这件事归这里管。 */
/** 子组件只递字符串过来，切页这件事归这里管。 */
function goto(v: string): void {
  if (VIEWS.some((x) => x.id === v)) {
    view.value = v as View
  }
}

/* ---------- 键盘 ----------
   这是个常驻托盘的工具窗口，多数时候只有键盘在手上：切页、找那条过滤框，
   这些动作每做一次都要摸一次鼠标，累积起来就是"这软件用起来很慢"的观感。

   刻意**不给**启停/切模式/切节点配键：一个键就能把整机流量改道，
   而误按的那一下不会自己解释。浮层里把这条理由写在明面上。 */

const SHORTCUTS: Array<{ combo: string; what: string }> = [
  { combo: 'Alt + 1…6', what: '跳到侧栏上的第 N 页（1 总览 … 6 设置）' },
  { combo: '/', what: '聚焦当前页的过滤框（规则、流量、日志三页有）；这一页有两个框时，再按一次跳到下一个' },
  { combo: '?', what: '打开 / 关掉这张说明' },
  { combo: 'Esc', what: '关掉说明；说明没开时，离开当前输入框' }
]

const helpOpen = ref(false)

/** 只看得到"当前这一页"的过滤框：总览与日志用的是 v-show，隐藏时元素还在 DOM 里。
 *  offsetParent 为 null 就是没布局出来，比再传一层 props 干净。
 *  data-focus-shortcut 只往表单控件上挂（input/textarea），下面按可禁用+可全选来读。
 *
 *  一页上可能有**两个**这样的框（规则页：上面那张表的过滤框 + 下面拦截名单的搜索框），
 *  所以按下去要往下一个跳，而不是永远回到第一个——
 *  否则第二个框挂着这个属性却永远拿不到焦点，等于给了一个假的提示。
 *  只有一个框时行为不变。
 *
 *  "现在在哪个框上"直接问 document.activeElement，自己记一份会过期：
 *  用户用鼠标点进第二个框之后，记着的那个还是第一个，下一次 / 就会跳回上面去。 */
function focusFilter(): boolean {
  const pool = Array.from(
    document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>('[data-focus-shortcut]')
  ).filter((el) => el.offsetParent !== null && !el.disabled)
  if (pool.length === 0) {
    return false
  }
  const active = document.activeElement as HTMLElement | null
  const at = active ? pool.indexOf(active as HTMLInputElement) : -1
  const next = pool[at + 1] ?? pool[0]
  next.focus()
  // 可全选的文框才 select：对已经选好的东西再选一次只是噪音。
  if (typeof next.select === 'function') {
    next.select()
  }
  return true
}

function onKeydown(e: KeyboardEvent): void {
  const el = e.target as HTMLElement | null
  const typing =
    !!el &&
    (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)

  // 带 Alt 的组合先处理：光标在搜索框里时"Alt+3 去规则页"也是用户明确要的，
  // 不该因为"正在输入"被吞掉。但 Ctrl/Cmd 的一律放行给系统与应用（复制、粘贴、退出）。
  if (e.altKey && !e.ctrlKey && !e.metaKey && !e.shiftKey) {
    const n = Number(e.key)
    if (Number.isInteger(n) && n >= 1 && n <= VIEWS.length) {
      e.preventDefault()
      view.value = VIEWS[n - 1].id
      return
    }
  }

  if (e.key === 'Escape') {
    if (helpOpen.value) {
      helpOpen.value = false
      return
    }
    if (typing) {
      el?.blur()
    }
    return
  }

  // 浮层开着时其它键都不动：说明是给人读的，读的时候不该把页翻走。
  if (helpOpen.value) {
    return
  }

  if (typing) {
    // 光标在输入框里时，`?` 与 `/` 都是用户要打的那个字符本身——
    // 过滤框里搜 "?"、搜 "/api" 是完全正常的动作，把它们吃掉的界面会被当成坏了。
    // Alt+数字在上面已经处理过（那是明确要跳页，不算打字）。
    return
  }

  if (e.key === '?') {
    // Shift+/ 就是 '?'，浏览器给的 event.key 已经是 '?'，这里只认它。
    e.preventDefault()
    helpOpen.value = true
    return
  }

  if (e.key === '/') {
    e.preventDefault()
    if (!focusFilter()) {
      flash('这一页没有过滤框。')
    }
  }
}

function onVisibility(): void {
  // 窗口被隐藏（托盘模式、或最小化）就不必再轮询，代理本身照常运行。
  if (document.hidden) {
    stopTimer()
  } else {
    startTimer()
    void poll()
    void pollSys()
  }
}

function startTimer(): void {
  if (timer === null) {
    timer = window.setInterval(() => void poll(), POLL_MS)
  }
}

function stopTimer(): void {
  if (timer !== null) {
    window.clearInterval(timer)
    timer = null
  }
}

onMounted(() => {
  startTimer()
  void poll()
  void pollSys()
  document.addEventListener('visibilitychange', onVisibility)
  window.addEventListener('keydown', onKeydown)
})

onBeforeUnmount(() => {
  stopTimer()
  document.removeEventListener('visibilitychange', onVisibility)
  window.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <div class="shell">
    <nav class="rail" aria-label="页面">
      <span class="brand">
        <svg class="mark" viewBox="0 0 20 20" aria-hidden="true">
          <path d="M14.6 5.4a6.2 6.2 0 1 0 0 9.2" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
          <path d="M10 10h6" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" />
          <circle cx="10" cy="10" r="2.1" fill="var(--ok)" />
        </svg>
        wps_app
      </span>

      <span class="rail-label">控制台</span>

      <button
        v-for="v in VIEWS"
        :key="v.id"
        type="button"
        :class="{ on: view === v.id }"
        @click="view = v.id"
      >
        <svg class="rail-ico" viewBox="0 0 16 16" fill="none" aria-hidden="true">
          <template v-if="v.id === 'overview'">
            <rect x="1.5" y="1.5" width="5.5" height="5.5" rx="1.5" stroke="currentColor" stroke-width="1.4" />
            <rect x="9" y="1.5" width="5.5" height="5.5" rx="1.5" stroke="currentColor" stroke-width="1.4" />
            <rect x="1.5" y="9" width="5.5" height="5.5" rx="1.5" stroke="currentColor" stroke-width="1.4" />
            <rect x="9" y="9" width="5.5" height="5.5" rx="1.5" stroke="currentColor" stroke-width="1.4" />
          </template>
          <template v-else-if="v.id === 'nodes'">
            <circle cx="8" cy="3.2" r="1.8" stroke="currentColor" stroke-width="1.4" />
            <circle cx="3.2" cy="12.4" r="1.8" stroke="currentColor" stroke-width="1.4" />
            <circle cx="12.8" cy="12.4" r="1.8" stroke="currentColor" stroke-width="1.4" />
            <path d="M8 5v3.4M8 8.4 4.6 11.3M8 8.4l3.4 2.9" stroke="currentColor" stroke-width="1.4" />
          </template>
          <template v-else-if="v.id === 'rules'">
            <path d="M2.5 4h11M2.5 8h11M2.5 12h7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          </template>
          <template v-else-if="v.id === 'traffic'">
            <path d="M2 11.5 5.5 7l3 2.6L14 3.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
            <path d="M2 14h12" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
          </template>
          <template v-else-if="v.id === 'logs'">
            <rect x="2" y="2.5" width="12" height="11" rx="2" stroke="currentColor" stroke-width="1.4" />
            <path d="M4.5 6l2 2-2 2M8 10h3.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
          </template>
          <template v-else>
            <circle cx="8" cy="8" r="2.4" stroke="currentColor" stroke-width="1.4" />
            <path d="M8 1.6v2M8 12.4v2M1.6 8h2M12.4 8h2M3.5 3.5l1.4 1.4M11.1 11.1l1.4 1.4M12.5 3.5l-1.4 1.4M4.9 11.1l-1.4 1.4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" />
          </template>
        </svg>
        {{ v.label }}
        <span v-if="railCounts[v.id]" class="count">{{ railCounts[v.id] }}</span>
      </button>

      <div class="rail-foot">
        <span class="rail-label">全局状态</span>
        <button
          type="button"
          class="status-row"
          :class="{
            on: tunOn,
            pending: busy === 'tun' || tunPhaseNow === 'starting' || tunPhaseNow === 'stopping'
          }"
          :title="`TUN ${TUN_PHASE_TEXT[tunPhaseNow]}，点击去设置`"
          @click="goto('settings')"
        >
          <i aria-hidden="true"></i>
          <span class="k">TUN</span>
          <span class="v">{{ tunValue }}</span>
        </button>
        <button
          type="button"
          class="status-row"
          :class="{
            on: sysOn && !sysAlarm,
            alarm: sysAlarm,
            pending: busy === 'sysproxy'
          }"
          :title="sysTitle"
          @click="goto('settings')"
        >
          <i aria-hidden="true"></i>
          <span class="k">系统代理</span>
          <span class="v">{{ sysValue }}</span>
        </button>
      </div>

      <button
        type="button"
        class="kbd-hint"
        title="键盘快捷键（?）"
        aria-haspopup="dialog"
        :aria-expanded="helpOpen"
        @click="helpOpen = !helpOpen"
      >
        快捷键 <kbd>?</kbd>
      </button>

      <span v-if="isDemo" class="demo">演示数据</span>
    </nav>

    <div class="main">
      <TopBar
        :title="viewTitle"
        :status="snap"
        :last="last"
        :busy="busy"
        :pending="pending"
        :ready="loadedOnce"
        :stale-at="staleAt"
        @start="onStart"
        @stop="onStop"
        @mode="onMode"
        @profile="onProfile"
      />

      <main class="content">
        <p v-if="banner" class="flash banner">{{ banner }}</p>
        <p v-if="pollError" class="flash alert">{{ pollError }}</p>

        <!-- 一次都没读成功之前，不要把 EMPTY_STATUS 画成一张"一切正常、只是没开"的图。
             后端没起来时界面会同时显示「已停止」「活跃连接 0」「配置里没有启用的入站」
             「还没有采样点，启动代理并产生流量后…」——每一条都在替一个我们并不知道的
             状态编故事，而真实情况可能只是读取一直失败。 -->
        <section v-if="!loadedOnce" class="boot">
          <div class="boot-inner">
            <span class="boot-orb" :class="{ bad: pollError !== '' }" aria-hidden="true"></span>
            <h2>{{ pollError ? '读不到后端状态' : '正在连接后端…' }}</h2>
            <p v-if="pollError" class="alert">{{ pollError }}</p>
            <p class="hint">
              {{ pollError
                ? '这通常意味着面板与代理进程之间的调用失败了；下面这些数字在拿到真实状态之前不会显示。'
                : '拿到第一帧状态后就正常渲染，不需要手动刷新。' }}
            </p>
          </div>
        </section>
        <template v-else>
        <!-- 总览与日志用 v-show：切回来立刻有内容，不用等一次接口往返。
             其余用 v-if：图表要重建 canvas，节点/规则/设置要从后端重读真实状态。 -->
        <div v-show="view === 'overview'">
          <Dashboard
            :status="snap"
            :traffic="tr"
            :sys="sys"
            :ledger="ledger"
            :last-test="activeTest"
            :busy="busy"
            :pending="pending"
            :stale="staleAt !== ''"
            @restart="onRestart"
            @reload="onReload"
            @unbind="onUnbind"
            @rebind="onRebind"
            @tun="onTUN"
            @sysproxy="onSysProxy"
            @iface-split="onIfaceSplit"
            @iface-cards="onIfaceSplitCards"
            @goto="goto"
            @show-failures="onShowFailures"
          />
        </div>
        <Nodes v-if="view === 'nodes'" :running="snap.running" :by-node="tr.byNode" />
        <Rules
          v-if="view === 'rules'"
          :status="snap"
          :blocked-total="tr.totalBlocked"
          :recent-blocked="tr.recentBlocked"
          :seed="ruleSeed"
          :fetch-seed="fetchSeed"
          :dns-seed="dnsSeed"
          @seeded="ruleSeed = ''"
          @seeded-fetch="fetchSeed = ''"
          @seeded-dns="dnsSeed = ''"
        />
        <Traffic
          v-if="view === 'traffic'"
          :traffic="tr"
          :busy="busy"
          :seed-way="waySeed"
          @reset="onReset"
          @rule="onSeedRule"
          @fetch="onSeedFetch"
          @dns="onSeedDNS"
          @seeded-way="waySeed = ''"
        />
        <div v-show="view === 'logs'">
          <LogStream :entries="entries" :truncated="logTruncated" :loaded="logsLoaded" />
        </div>
        <Settings
          v-if="view === 'settings'"
          :status="snap"
          :sys="sys"
          :ledger="ledger"
          :busy="busy"
          :pending="pending"
          @tun="onTUN"
          @sysproxy="onSysProxy"
          @goto="goto"
        />
        </template>
      </main>
    </div>

    <ShortcutHelp v-if="helpOpen" :keys="SHORTCUTS" @close="helpOpen = false" />
  </div>
</template>

<style scoped>
/* 侧栏底部那个入口：不做成显眼按钮，它是"想知道才看"的东西。 */
.kbd-hint {
  margin-top: var(--sp-3);
  align-self: flex-start;
  display: inline-flex;
  gap: 5px;
  align-items: center;
  padding: 3px 8px;
  border: 1px solid var(--line-2);
  border-radius: var(--r-pill);
  background: transparent;
  color: var(--muted);
  font-size: var(--fs-micro);
  cursor: pointer;
}

.kbd-hint:hover {
  color: var(--fg-2);
  border-color: var(--line-3);
}

.kbd-hint kbd {
  padding: 0 4px;
  border: 1px solid var(--line-2);
  border-radius: 4px;
  font-family: var(--mono);
}

.flash {
  margin: var(--sp-3) var(--sp-5) 0;
}

/* 启动/读不到时的整屏占位：居中、有呼吸感，而不是左上角一张小卡片。 */
.boot {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 60vh;
  padding: var(--sp-8) var(--sp-6);
}

.boot-inner {
  max-width: 420px;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: var(--sp-3);
  text-align: center;
}

.boot-inner h2 {
  margin: 0;
  font-size: var(--fs-title);
  font-weight: 600;
  letter-spacing: -0.015em;
}

.boot-inner .alert,
.boot-inner .hint {
  text-align: left;
}

/* 那颗呼吸的光点：读不到后端时它是琥珀色的，别用蓝色假装一切正常。 */
.boot-orb {
  width: 46px;
  height: 46px;
  border-radius: 50%;
  background: radial-gradient(circle at 50% 40%, var(--accent-bright), var(--accent) 62%, transparent 72%);
  box-shadow: 0 0 34px rgba(59, 130, 246, 0.55);
  animation: orb 1.9s var(--ease-in-out) infinite;
}

.boot-orb.bad {
  background: radial-gradient(circle at 50% 40%, var(--warn-bright), var(--warn) 62%, transparent 72%);
  box-shadow: 0 0 34px rgba(251, 191, 36, 0.45);
  animation: none;
}

@keyframes orb {
  0%,
  100% {
    opacity: 0.5;
    transform: scale(0.88);
  }
  50% {
    opacity: 1;
    transform: scale(1);
  }
}

/* 演示数据是"这些数字不是真的"这种级别的警告，必须一直看得见。
   放在侧栏最底下：固定浮在内容右下角会压住表格最后一行。 */
.demo {
  margin-top: var(--sp-3);
  align-self: flex-start;
  padding: 3px 9px;
  border: 1px solid var(--warn-line);
  border-radius: var(--r-pill);
  background: var(--warn-bg);
  color: var(--warn-bright);
  font-size: var(--fs-micro);
  font-weight: 500;
  letter-spacing: 0.02em;
}
</style>
