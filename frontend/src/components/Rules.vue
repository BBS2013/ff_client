<script setup lang="ts">
// Rules 只管分流：自定义域名规则（哪些走代理、哪些直连）+ 「这个域名现在怎么走」的探测。
//
// 内置规则集的计数直接取自 App.vue 已有的 Status，不额外发请求；
// 这里唯一的数据源是 userRules()，因为它不在 Status 里。
// `watch` 这个名字在本组件里已经给了「规则文件监视」那一栏的读数，
// 所以这里带别名引进来，而不是把那个改名——它出现在模板里，改名要连界面一起动。
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch as vueWatch } from 'vue'
import type {
  BlockImport,
  BlockedHit,
  BlockView,
  DNSProbe,
  ProviderRefreshReport,
  RulesWatchView,
  RuleWarning,
  Status,
  SubscriptionsView,
  UserRule,
  UserRuleImport
} from '../types'
import {
  addBlockDomain,
  addBlockDomains,
  addUserRule,
  addUserRules,
  blockList,
  errorText,
  fetchPage,
  moveUserRule,
  probeDNS,
  probeHost,
  profiles,
  pruneBlockDomains,
  refreshProviders,
  removeBlockDomain,
  setUserRuleDisabled,
  removeUserRule,
  rulesWatch,
  userRuleHits,
  userRuleWarnings,
  subscriptions,
  userRules
} from '../api'
import { formatAgo, formatBytes, formatDuration, geoipText, modeText, policyClass, policyText } from '../format'
import { agoText, ttlLeft } from '../ageclock'
import type { ProbeEntry } from '../probes'
import {
  DNS_HISTORY,
  dnsHistory,
  fetchHistory,
  probeStore,
  rememberDNS,
  rememberFetch,
  rememberProbe,
  safeLabel,
  staleWhy
} from '../probes'

const props = defineProps<{
  status: Status
  /** 本次运行累计被拦的条数，来自连接注册表：名单装着却一条都没拦到，也该看得见。 */
  blockedTotal: number
  /**
   * 最近被拦的目标（新→旧，上限 32 条）。连接表是几百条的环形流水，
   * 一个页面就能把刚才那批广告请求冲掉；拦截又完全静默，
   * 所以"刚才那个拦住了吗"得有一份不随流水滚走的答案。
   */
  recentBlocked: BlockedHit[]
  /**
   * 从连接表「加规则」带过来的域名。非空就填进上面那张表单并聚焦，
   * 然后立刻用 seeded 事件请父级清空——不清空的话，用户下次自己进规则页
   * 会被一个上一次留下的域名占着表单。
   */
  seed?: string
  /**
   * 从流量页那条「拨不通」的连接带过来的一个网址（已经拼好协议）。
   * 填进「取一个真页面」并聚焦，**不自动跑**：协议是照端口猜的，让人看一眼再按回车。
   */
  fetchSeed?: string
  /** 从流量页那条失败连接带过来的域名：填进「看解析」并聚焦，不自动跑。 */
  dnsSeed?: string
}>()

const emit = defineEmits<{
  (e: 'seeded'): void
  (e: 'seededFetch'): void
  (e: 'seededDNS'): void
}>()

const RULE_TYPES = [
  { id: 'DOMAIN-SUFFIX', label: '域名及其子域', hint: 'example.com 与 *.example.com' },
  { id: 'DOMAIN', label: '精确域名', hint: '只有 example.com 本身' },
  { id: 'DOMAIN-KEYWORD', label: '域名含关键字', hint: '出现该串即命中' }
]

const rules = ref<UserRule[]>([])
// 拦截名单住在配置的 block: 段，这里只读展示。
// 为什么必须在这一页露出来：名单对客户端是完全静默的（不回任何拒绝信息），
// 用户能确认"到底拦住了什么、装上了没有"的地方就只剩界面与日志。
const block = ref<BlockView | null>(null)
const blockDraft = ref('')

/* 拦截名单那堆 chip 和上面那张表是同一道题，而且更极端：
   一个 chip 是 span + 按钮 + svg ≈ 4 个节点，而"批量粘贴（成百上千条用这个）"
   这一栏就是为了让用户把整份 AdGuard 名单粘进来——8000 条就是三万多个节点，
   每五秒整份重读一次时全都要重新 diff。
   另外几千个 chip 摊成一团也是读不完的，所以这里同时给一个框：
   窗口管"画多少"，过滤框管"找得到那一条"。 */
const BLOCK_WINDOW = 300
const blockWindow = ref(BLOCK_WINDOW)
const blockFilter = ref('')
const matchedBlock = computed(() => {
  const q = blockFilter.value.trim().toLowerCase()
  const list = block.value?.domains ?? []
  if (!q) {
    return list
  }
  return list.filter((d) => d.includes(q))
})
const visibleBlock = computed(() => matchedBlock.value.slice(0, blockWindow.value))
const hiddenBlockCount = computed(() => matchedBlock.value.length - visibleBlock.value.length)

vueWatch(blockFilter, () => {
  blockWindow.value = BLOCK_WINDOW
})

/**
 * 加一条拦截域名。
 *
 * 空白输入先在前端挡住，别发一次注定失败的请求再报。
 * 这条没套 run()：提示要用**后端归一化后**的写法，还要分得清"真加了"和"本来就有"，
 * 而 run() 的 done 是发起之前就定好的字符串，做不到。
 */
async function onAddBlock(): Promise<void> {
  const raw = blockDraft.value.trim()
  if (!raw) {
    failure.value = '请先填要拦的域名，例如 ads.example.com'
    return
  }
  if (busy.value !== '') {
    return
  }
  busy.value = 'add-block'
  notice.value = ''
  failure.value = ''
  const had = block.value?.domains ?? []
  try {
    const saved = await addBlockDomain(raw)
    notice.value = had.includes(saved)
      ? `${saved} 本来就在名单里，没有改动。`
      : `已把 ${saved} 加入拦截名单（含其子域，立即生效）。`
    await load()
  } catch (err) {
    failure.value = `添加拦截域名失败：${errorText(err)}`
  } finally {
    busy.value = ''
    blockDraft.value = ''
  }
}

/**
 * 这一条留痕的 host 是否就是名单里那一条。
 * 只做大小写层面的比对（名单本身已由后端归一化）；
 * 撞上来的是子域时返回 false——该删的是父域那条，前端不替后端猜。
 */
function inBlockList(host: string): boolean {
  const d = host.trim().toLowerCase()
  return !!block.value?.domains.some((x) => x.toLowerCase() === d)
}

/** 删一条。删除走的是后端校验过的精确匹配，前端不做归一化以免两边规则不同。 */
const onRemoveBlock = (d: string): Promise<boolean> =>
  run('rm-block', () => removeBlockDomain(d), `已把 ${d} 移出拦截名单。`)

/* ---------- 批量粘贴拦截域名 ----------
   网上抄来的名单动辄几百上千条，逐条点「添加」既慢又危险：那条路径每一行都要
   整份读写一次配置，中途任何一次失败都留下半截名单。粘贴框另外收 AdGuard 写法
   （||域名^ 与 ||域名^$修饰符），因为抄来的名单基本都长那个样子。 */
const blockBatchOpen = ref(false)
const blockBatchText = ref('')
const blockBatchResult = ref<BlockImport | null>(null)

/** 结果那一句。模板里直接拼的话，插值两侧的空白会混进句子中间（"、 拒掉"）。 */
function blockBatchSummary(r: BlockImport): string {
  const parts = [`读到 ${r.total} 行：新增 ${r.accepted} 条`]
  if (r.existing > 0) {
    parts.push(`${r.existing} 条名单里本来就有`)
  }
  if (r.rejected.length > 0) {
    parts.push(`拒掉 ${r.rejected.length} 行`)
  }
  return parts.join('，') + (r.written ? '。' : '——名单原样没动。')
}

async function onBlockBatchAdd(): Promise<void> {
  if (busy.value !== '') {
    return
  }
  if (blockBatchText.value.trim() === '') {
    failure.value = '先把要拦的域名粘进来，一行一个（AdGuard 的 ||域名^ 也收）'
    return
  }
  failure.value = ''
  notice.value = ''
  busy.value = 'batch-block'
  try {
    const r = await addBlockDomains(blockBatchText.value)
    blockBatchResult.value = r
    await load()
    if (!r.written) {
      notice.value =
        r.existing > 0
          ? `那 ${r.total} 行里 ${r.existing} 条名单里本来就有，名单原样没动。`
          : `这 ${r.total} 行一条都没收下，名单原样没动。`
    } else {
      notice.value =
        `已保存：新增 ${r.accepted} 条` +
        (r.existing > 0 ? `，${r.existing} 条本来就有` : '') +
        (r.rejected.length > 0 ? `，拒掉 ${r.rejected.length} 行` : '') +
        (r.dead.length > 0 ? `；其中 ${r.dead.length} 条什么也没多拦` : '') +
        '。'
    }
    if (r.written) {
      blockBatchText.value = ''
    }
  } catch (err) {
    failure.value = `批量添加失败：${errorText(err)}`
  } finally {
    busy.value = ''
  }
}

/**
 * 清理被更宽条目盖住的冗余项。
 *
 * 这按钮改的是配置文件，所以只给一个明确说了后果的确认框：
 * 用户要能自己判断"删掉它"是不是在放弃什么——答案是没有，
 * 留着的那条盖住的范围一模一样（见 rules.PruneBlockDomains）。
 */
async function onPruneBlock(): Promise<void> {
  if (busy.value !== '') {
    return
  }
  const n = block.value?.deadTotal ?? 0
  if (n === 0) {
    return
  }
  if (!window.confirm(`清掉 ${n} 条什么也没多拦的条目？\n\n名单里更宽的那条照旧拦着同样的域名，删掉不改任何判定。`)) {
    return
  }
  // 提示要说实际删了几条，而 run() 的那句是发起之前就定死的，所以这里自己走一遍。
  busy.value = 'prune-block'
  failure.value = ''
  notice.value = ''
  try {
    const removed = await pruneBlockDomains()
    notice.value = removed === 0 ? '没有可清理的条目。' : `清掉了 ${removed} 条冗余条目，拦截范围不变。`
    await load()
  } catch (err) {
    failure.value = `清理失败：${errorText(err)}`
  } finally {
    busy.value = ''
  }
}
// 草稿里 disabled 恒为 false：新加的一条没有"先加上再关掉"这一说，
// 要关就加完之后点那一行的「停用」。留着这个字段只是为了让草稿和 UserRule 同形。
const ruleDraft = ref<UserRule>({ type: 'DOMAIN-SUFFIX', value: '', policy: 'PROXY', node: '', disabled: false })

/* ---------- 批量粘贴 ----------
   一份名单动辄上百条，逐条填三个字段是没有人会做的事。
   粘贴框接受两种写法：一行一个裸域名（按上面选好的类型与策略补全），
   或者一整行 类型,域名,策略 原样搬过来。 */
const batchOpen = ref(false)
const batchText = ref('')
const batchResult = ref<UserRuleImport | null>(null)

async function onBatchAdd(): Promise<void> {
  if (busy.value !== '') {
    return
  }
  if (batchText.value.trim() === '') {
    failure.value = '先把要加的域名粘进来，一行一个（也可以写成 类型,域名,策略）'
    return
  }
  failure.value = ''
  notice.value = ''
  busy.value = 'batch-rule'
  try {
    const r = await addUserRules(batchText.value, ruleDraft.value.type, ruleDraft.value.policy)
    batchResult.value = r
    await load()
    if (r.total === 0) {
      notice.value = '那些行里没有一条规则：空行与 # 注释不算。'
    } else if (!r.written) {
      // 一条都没收下时文件是原样的，这句必须说：写完"已保存"就是当着人撒谎。
      notice.value = `这 ${r.total} 行一条都没收下，名单原样没动。`
    } else {
      notice.value =
        `已保存：新增 ${r.accepted} 条、覆盖 ${r.updated} 条` +
        (r.rejected.length > 0 ? `，另有 ${r.rejected.length} 行被拒` : '') +
        (r.dead.length > 0 ? `；其中 ${r.dead.length} 条装上但永远不会命中` : '') +
        '。'
    }
    if (r.written) {
      batchText.value = ''
      if (ruleFilter.value !== '') {
        ruleFilter.value = ''
      }
    }
  } catch (err) {
    failure.value = `批量添加失败：${errorText(err)}`
  } finally {
    busy.value = ''
  }
}

/**
 * 这一行能不能在面板上改。判据和 Go 侧的 `UserRule.IsDomain()` 是同一套
 * （类型在白名单里、且不是拦截行），两边各写一处时以 Go 为准——
 * 它才是真的会写盘的那一侧。界面上"只读"的文字和一个会落盘的按钮同时出现，
 * 比少一个按钮糟得多：用户按下去了，而那一行说他不能按。
 */
/* 可选的固定节点：名单来自配置里的节点，不是随便填的字符串。
   后端会照名字去装配那只出站，名字对不上就直接报错（绝不回落当前节点），
   所以这里只让人从现有名字里挑，避免当场写出一条永远连不通的规则。 */
const nodeNames = ref<string[]>([])

/** 节点名单读到了、而这一行钉的名字不在里面，才算"钉坏了"。
    名单空着 = 还没读到（读失败或还没读），那时说"没问题"才是诚实的。 */
const pinBroken = (r: UserRule): boolean => nodeNames.value.length > 0 && r.node !== '' && !nodeNames.value.includes(r.node)

/** 这一行的钉住能不能在面板里就地换。三个条件缺一不可：
    只读行（手写的 IP-CIDR / GEOIP / 拦截行）改了会连带丢掉原样；
    直连与拦截没有"走哪个节点"这回事；
    而节点名单没读到时，下拉里只剩「当前节点」一项，
    点下去等于把用户钉得好好的节点悄悄清掉——那不如不给这个下拉。 */
const pinEditable = (r: UserRule): boolean =>
  editableRule(r) && r.policy === 'PROXY' && nodeNames.value.length > 0

const EDITABLE_TYPES: string[] = RULE_TYPES.map((x) => x.id)
const editableRule = (r: UserRule): boolean =>
  EDITABLE_TYPES.includes(r.type) && (r.policy === 'PROXY' || r.policy === 'DIRECT')

/** 只读的那一行要说清"为什么只读"和"去哪儿改"，两种原因给的话不一样。 */
function readonlyNote(r: UserRule): string {
  if (r.policy === 'REJECT') {
    return '拦截规则（这一行只读；要改名单用下面「拦截域名」那一栏）'
  }
  return `手写的 ${r.type} 规则（只读，改它要直接编辑 user-rules.txt）`
}
// 两格的读数存在 ../probes（模块级），组件里只留输入框的即时值。
// 换页回来输入框不该是空的——用户刚查的那个域名，往往正是他接下来要改一个词再查一遍的那个。
const probeName = ref(probeStore.host.q)
const probeRes = computed(() => probeStore.host.res)
const fetchUrl = ref(probeStore.page.q)
const fetchUrlEl = ref<HTMLInputElement | null>(null)
const fetchRes = computed(() => probeStore.page.res)
// 取页面的失败只写在这一格里，不并进页面顶部那条 failure：
// "这一页读不到"与"这个网址取不到"是两件事，混在一句里就没人知道该去改哪一个。
const fetchErr = computed(() => probeStore.page.err)
// 取页面用的是**自己那一份**忙标志，不是这一页共用的 `busy`。
// `busy !== ''` 挂着「添加规则」「停用」「删除」「移出名单」那一整排，
// 而取页面最长要等 15 秒（service.FetchBudget）——A/B 实测：共用 `busy` 时一次取页面
// 在飞行中把 **53 个**按钮冻成灰的，换成独立标志之后只冻它自己那颗。
// 慢的只读动作不占写锁：那把锁是为"同一时刻只能有一个改动"设计的。
const fetchBusy = ref(false)

/**
 * 会改变这两格答案的东西，除模式之外就这四类。
 *
 * 模式单独存（见 probes.ts 的 entry），因为"模式切了"与"名单动过"
 * 是两句不同的话：前者重查一次就换答案，后者还得先去看是哪一条。
 * 名单每 5 秒整份重读一次，内容没变这个串就不变——所以它不会因为"又刷了一轮"而假报过期。
 */
const decideStamp = computed(() =>
  [
    props.status.activeProfile,
    props.status.ifaceSplit?.enabled
      ? `${props.status.ifaceSplit.proxyDev}/${props.status.ifaceSplit.directDev}`
      : '-',
    rules.value
      .map((r) => `${r.type},${r.value},${r.policy},${r.node || '-'},${r.disabled ? 'off' : 'on'}`)
      .join(';'),
    // 还没读到过拦截名单时留一个固定值：读不到与读到空是两件事，
    // 但在这里都只是"我还不知道那份名单长什么样"，不该被当成"名单动过"。
    block.value ? block.value.domains.join(',') : 'unknown'
  ].join('|')
)
const probeWhy = computed(() => staleWhy(probeStore.host, props.status.mode, decideStamp.value))
const fetchWhy = computed(() => staleWhy(probeStore.page, props.status.mode, decideStamp.value))
// 第三格：看解析。同一套现场、同一套过期判据（那两列判定跟着模式与名单走）。
const dnsName = ref(probeStore.dns.q)
const dnsNameEl = ref<HTMLInputElement | null>(null)
const dnsRes = computed(() => probeStore.dns.res)
const dnsErr = computed(() => probeStore.dns.err)
const dnsWhy = computed(() => staleWhy(probeStore.dns, props.status.mode, decideStamp.value))
const dnsAgo = computed(() => agoText(probeStore.dns.at))
const dnsBusy = ref<'' | 'ask' | 'fresh'>('')
// 有效期跟着上面那个 5 秒的钟倒：后端报的那个"还剩多久"是它回话那一刻的数，
// 原样摆着不动，三分钟后就成了假话。倒到 0 以下要说"早过了、只是没人再问"，
// 那一句正是「重问（不用缓存）」这枚按钮存在的理由。
const dnsTtl = computed(() => (dnsRes.value ? ttlLeft(probeStore.dns.at, dnsRes.value.ttlMs) : 0))
const dnsTtlStale = computed(() => !!dnsRes.value && dnsRes.value.ttlMs > 0 && dnsTtl.value <= 0)
const dnsTtlLine = computed<string>(() => {
  const r = dnsRes.value
  if (!r || r.ttlMs <= 0) {
    return ''
  }
  if (dnsTtlStale.value) {
    return '这一份已经过了缓存的有效期：上面这批只是还没人再问，拿「重问（不用缓存）」换一批'
  }
  return `${r.cached ? '缓存里这份还剩' : '刚问到的这份能用'} ${formatDuration(dnsTtl.value)}，到点自己换成新的`
})
const probeAgo = computed(() => agoText(probeStore.host.at))
const fetchAgo = computed(() => agoText(probeStore.page.at))
const notice = ref('')
const failure = ref('')
const busy = ref('')

// 读到过一次成功，才算「知道这份名单长什么样」。
// 没读到过的时候，空列表只能显示成读不到——把它写成「还没有规则」，
// 是把一次失败冒充成了一个关于磁盘的事实。
//
// stale 是另一半：以前读到过、这次重读失败。此时屏幕上那份是**旧**读数，
// 不标出来的话，"118 条"看着就像刚刚核对过。
// 规则文件监视那一栏：服务在跑时改文件会自己生效，界面要能回答
// "被看着的是哪些文件、上次生效是什么时候"，否则"还在等第二轮"与"这功能没开"
// 在同一片空白里长得一模一样。
const watch = ref<RulesWatchView | null>(null)
const watchKnown = ref(false)
const watchStale = ref(false)
const watchError = ref('')

/* ---------- 这一栏：名单里写了但不会按你想的走 ----------
   两类问题：一类是被前面的规则盖住（"加了却不生效"），一类是钉的节点已经改名/删掉。
   判据都在后端算（归一化写法与节点名单只有一份权威），这里只负责把它说的话摆出来。 */
const warnings = ref<RuleWarning[]>([])
const warnKnown = ref(false)
// 每条规则本次会话命中过多少次，键是 TYPE,VALUE。
// 单独一份读数的理由见 UserRuleHits：判语说的是"结构上永远轮不到"，
// 而一份几百条的名单里更多的是"活着、但从没轮到过"——那种只能观察，推不出来。
const ruleHits = ref<Record<string, number>>({})
const hitOf = (r: UserRule): number => ruleHits.value[`${r.type},${r.value}`] ?? 0
const warnStale = ref(false)
const warnError = ref('')

// 头部要按"有哪几类"说话，否则只钉错节点的那份名单会被说成"永远不会命中"。
// 两类各自数各自的，**不要拿总数去减**：后端哪天多一种 Kind，减法会把新那类
// 悄悄算进"钉的节点不存在"里，于是界面当面说错话，而测试全绿。
const shadowCount = computed(() => warnings.value.filter((w) => w.kind === 'shadow').length)
const nodeMissingCount = computed(() => warnings.value.filter((w) => w.kind === 'node-missing').length)
// 界面还不认识的 Kind 不能装作不存在：总数里有它，可两句分类的话都不会提到它，
// 于是这块看着自洽、其实少了几条。宁可明说"有 N 条没认出来"。
const unknownKinds = computed(() =>
  warnings.value.filter((w) => w.kind !== 'shadow' && w.kind !== 'node-missing')
)


async function loadWarnings(): Promise<void> {
  // 计数与判语各自一份读数、各自一处失败：命中数读不到不该把判语一起打成"读不到"，
  // 反过来也不行——两栏回答的是两个问题。
  try {
    const h = await userRuleHits()
    const m: Record<string, number> = {}
    for (const x of h ?? []) {
      m[x.key] = x.hits
    }
    ruleHits.value = m
  } catch {
    // 这一份读数读不到就整列按 0 显示，不再多造一个"未知"状态：
    // 后端那里是一次纯内存的 map 快照，唯一会失败的是它顺带调的 ListUserRules——
    // 而那个一失败，上面那张表本身就是空的，轮不到这一列来说话。
    ruleHits.value = {}
  }
  try {
    const w = await userRuleWarnings()
    if (!w) {
      warnError.value = '后端回了空读数'
      warnStale.value = warnKnown.value
      return
    }
    warnings.value = w
    warnKnown.value = true
    warnStale.value = false
    warnError.value = ''
  } catch (err) {
    // 读不到这件事写在自己那一栏，不抢页面顶部那条 failure：
    // 两份名单都还好好的，只是这一句判语没拿到。
    warnError.value = errorText(err)
    warnStale.value = warnKnown.value
  }
}

const pulling = ref(false)
const pullReport = ref<ProviderRefreshReport | null>(null)
const pullError = ref('')

/**
 * 「立即拉取」按下去之后要说得出**哪一条**怎么样了。
 *
 * 只回一句"完成"与按钮根本没动是同一个观感——所以逐条列：
 * 变了的说变了，失败的原样带出原因，重载失败更要单说，
 * 因为那一刻规则还是旧的，用户却刚看到"内容变了"。
 */
async function onPullNow(): Promise<void> {
  if (pulling.value) {
    return
  }
  pulling.value = true
  pullError.value = ''
  try {
    pullReport.value = await refreshProviders()
    await loadSubs()
  } catch (err) {
    pullReport.value = null
    pullError.value = errorText(err)
  } finally {
    pulling.value = false
  }
}

const pullText = computed(() => {
  const r = pullReport.value
  if (!r) {
    return ''
  }
  const changed = r.results.filter((x) => x.changed).map((x) => x.name)
  const failed = r.results.filter((x) => x.err !== '')
  const bits: string[] = []
  bits.push(changed.length ? `${changed.join('、')} 拿到新内容` : '没有一条拿到新内容')
  if (failed.length) {
    bits.push(`失败：${failed.map((x) => `${x.name}（${x.err}）`).join('；')}`)
  }
  if (r.reloadErr) {
    bits.push(`但规则重载失败，仍在用旧的那份：${r.reloadErr}`)
  } else if (r.reloaded) {
    bits.push('已按新内容重载规则')
  }
  return bits.join('。') + '。'
})

const pullBad = computed(() => {
  const r = pullReport.value
  return !!pullError.value || (!!r && (r.results.some((x) => x.err !== '') || r.reloadErr !== ''))
})

// 表头右侧那一小截：读不到 ≠ 读取中 ≠ 没在监视 ≠ 看着 N 个文件。
const watchHead = computed(() => {
  if (!watch.value) {
    return watchError.value ? '读不到' : '读取中…'
  }
  return watch.value.watching ? `看着 ${watch.value.files.length} 个文件` : '没在监视'
})

const subs = ref<SubscriptionsView | null>(null)
const subsKnown = ref(false)
const subsStale = ref(false)
const subsError = ref('')

async function loadSubs(): Promise<void> {
  try {
    const v = await subscriptions()
    if (!v) {
      subsError.value = '后端回了空读数'
      subsStale.value = subsKnown.value
      return
    }
    subs.value = v
    subsKnown.value = true
    subsStale.value = false
    subsError.value = ''
    if (!v.running && (pullReport.value || pullError.value)) {
      // 上一次「立即拉取」的结果属于那个还在跑的循环。循环停了还把它挂在下面，
      // 就成了「已按新内容重载规则」与「没在跑」同屏——两句都对，拼起来是假的。
      pullReport.value = null
      pullError.value = ''
    }
  } catch (err) {
    subsError.value = errorText(err)
    subsStale.value = subsKnown.value
  }
}

/** 订阅条数那一截：没配、配了没在跑、在跑，是三种不同的处境。 */
const subsHead = computed(() => {
  if (!subs.value) {
    return subsError.value ? '读不到' : '读取中…'
  }
  const v = subs.value
  if (v.configErr) {
    return '读不到配置'
  }
  if (!v.configured) {
    return '没配订阅'
  }
  return v.running ? `${v.items.length}/${v.configured} 条在拉` : '没在跑'
})

/** 周期只报最大那一档：配置写 24h 时"每 1天 0小时 0分"是噪音。 */
function everyText(sec: number): string {
  if (sec <= 0) {
    return '周期未知'
  }
  if (sec < 60) {
    return `${sec} 秒`
  }
  if (sec < 3600) {
    return `${Math.round(sec / 60)} 分钟`
  }
  if (sec < 86400) {
    return `${Math.round(sec / 3600)} 小时`
  }
  return `${Math.round(sec / 86400)} 天`
}

/** "还有多久"。formatAgo 是往回看的，未来的时刻交给它会说成"0 秒前"。 */
function formatAhead(ms: number): string {
  const left = ms - Date.now()
  if (ms <= 0) {
    return '未知'
  }
  if (left <= 0) {
    return '就在这一轮'
  }
  const m = Math.round(left / 60000)
  if (m < 60) {
    return `${m} 分后`
  }
  const h = Math.floor(m / 60)
  if (h < 24) {
    return `${h} 小时后`
  }
  return `${Math.floor(h / 24)} 天后`
}

async function loadWatch(): Promise<void> {
  try {
    const v = await rulesWatch()
    if (!v) {
      // 后端这里总该回一份读数。回了空就是没读到，说清楚，
      // 别让表头停在「读取中…」——那一档的意思是"还没轮到它"，不是"它坏了"。
      watchError.value = '后端回了空读数'
      watchStale.value = watchKnown.value
      return
    }
    watch.value = v
    watchKnown.value = true
    watchStale.value = false
    watchError.value = ''
  } catch (err) {
    // 错误写在这一栏自己身上，不抢页面顶部那条 failure：
    // 两份名单也可能同时读不到，共用一行就只会剩下一个原因，
    // 而"名单读不到"与"只是没读到文件时间"要派人去查的地方完全不同。
    watchError.value = errorText(err)
    watchStale.value = watchKnown.value
  }
}

const rulesKnown = ref(false)
const rulesStale = ref(false)
const blockKnown = ref(false)
const blockStale = ref(false)

async function load(): Promise<void> {
  failure.value = ''
  // 两份名单各读各的：自定义规则读失败不该把拦截名单一起打成"读不到"，
  // 反过来也不行——两句话是两件事，混成一条「读取自定义规则失败」就会把人派去查错的地方。
  const errs: string[] = []
  try {
    rules.value = (await userRules()) ?? []
    // 节点名单和规则一起读：加规则时要能从现有节点里挑一个钉住，
    // 而名单读失败不该把这张表整个打成"读不到"，单独 catch。
    try {
      const pl = await profiles()
      nodeNames.value = (pl?.profiles ?? []).map((x) => x.name)
    } catch {
      nodeNames.value = []
    }
    rulesKnown.value = true
    rulesStale.value = false
  } catch (err) {
    errs.push(`自定义规则 ${errorText(err)}`)
    rulesStale.value = rulesKnown.value
  }
  try {
    const b = await blockList()
    if (!b) {
      // 后端这里总该回一份名单（哪怕是空的）。回了个 null 就是没读到，
      // 不能顺手把 blockKnown 置真——那一栏会永远停在「读取中…」。
      errs.push('拦截名单 返回了空读数')
      blockStale.value = blockKnown.value
    } else {
      block.value = b
      blockKnown.value = true
      blockStale.value = false
    }
  } catch (err) {
    errs.push(`拦截名单 ${errorText(err)}`)
    blockStale.value = blockKnown.value
  }
  if (errs.length > 0) {
    failure.value = `读取失败：${errs.join('；')}`
  }
  // 这两栏都不并进 errs：它们坏了不影响上面两份名单，
  // 混在一起会让"名单读不到"和"只是没读到订阅状态"看起来是同一种事故。
  await Promise.all([loadWatch(), loadSubs(), loadWarnings()])
}

/** 写操作共用：置忙、执行、提示、回读磁盘与运行态的真实值。返回"这次是否写成了"。 */
async function run(key: string, fn: () => Promise<void>, done: string): Promise<boolean> {
  if (busy.value !== '') {
    return false
  }
  busy.value = key
  notice.value = ''
  failure.value = ''
  try {
    await fn()
    notice.value = done
    await load()
    return true
  } catch (err) {
    failure.value = `${done.replace(/。$/, '')}失败：${errorText(err)}`
    return false
  } finally {
    busy.value = ''
  }
}

const ruleFilter = ref('')

/**
 * 按关键字过滤那份自定义规则表。
 *
 * 为什么要它：这份名单会一直长（本机已经 118 条），而找一条已有规则
 * 是改规则之前最常做的动作——没有过滤框就只能滚动加肉眼，
 * 找不到时又会误以为"我没加过"，于是加出一条重复的。
 * 匹配范围包含走向的中文说法，输「直连」也该能筛出那一类。
 */
const shownRules = computed(() => {  const q = ruleFilter.value.trim().toLowerCase()
  if (!q) {
    return rules.value
  }
  return rules.value.filter(
    (r) =>
      r.value.toLowerCase().includes(q) ||
      r.type.toLowerCase().includes(q) ||
      policyText(r.policy).toLowerCase().includes(q) ||
      r.policy.toLowerCase().includes(q)
  )
})

/* ---------- 只画看得见的那几十行 ----------
   成批粘贴之后这张表动辄几百上千行，而一行是 ~19 个 DOM 节点。
   面板每 5 秒整份重读一次规则，`rules.value` 每次都是新数组、新对象，
   Vue 只能把每一行重新 diff 一遍——本机实测 907 行时清一次过滤要 266ms，
   也就是每五秒一次四分之一秒的停顿，而且它正发生在人看着这一页的时候。
   所以按窗口画：先画前若干行，要更多再给。
   过滤仍然走整份名单（上面那个 computed），筛出来几条就画几条，窗口只在"没筛完"时兜底。 */
const RULE_WINDOW = 200
const ruleWindow = ref(RULE_WINDOW)
const visibleRules = computed(() => shownRules.value.slice(0, ruleWindow.value))
const hiddenRuleCount = computed(() => shownRules.value.length - visibleRules.value.length)

/* 跳过这张表用的那一条。表里每行 6~7 个控件，画满 200 行就是一千多个 Tab 停靠点，
   而同一页下面还有「拦截域名」那一栏——不数一下没人会相信要按多少次，所以把数字摆出来。
   数的是 DOM 里真的能聚焦的东西，不按"行数 × 每行几个"估：
   只读行、直连行、有没有节点名单，每行的控件数都不一样，估的那份迟早和实际对不上。 */
const tableWrap = ref<HTMLElement | null>(null)
const tableControlCount = ref(0)
function recountTableControls(): void {
  tableControlCount.value =
    tableWrap.value?.querySelectorAll('a[href], button, input, select, textarea').length ?? 0
}
vueWatch(
  () => [visibleRules.value.length, nodeNames.value.length, busy.value],
  () => void nextTick(recountTableControls),
  { immediate: true }
)

// 点后跳过去之后要把焦点真的放到那一栏上：目标是个 <section>，
// 本身不可聚焦，光靠锚点滚动会让 Tab 还停在原地，等于只滚了个屏。
function focusBlockSection(e: Event): void {
  e.preventDefault()
  const el = document.getElementById('wps-block-section')
  el?.scrollIntoView({ block: 'start' })
  el?.focus({ preventScroll: true })
}

// 换关键字等于换了一份"要看的东西"，窗口要回到起点：
// 留着上一次展开到的一千多行，人从长名单切回短名单时最容易误以为界面卡住了。
vueWatch(ruleFilter, () => {
  ruleWindow.value = RULE_WINDOW
})

// 从连接表带过来的域名：填进表单、聚焦，然后请父级清空这份种子。
// 类型固定成 DOMAIN-SUFFIX 而不是"域名及其子域"里的其它两档——
// 用户看到的是一个正在跑的连接，他多半想管的是这个域名连同它的子域，
// 而且这一档是表单的默认值，不覆盖它就不会有"切了页结果选了个没选过的"。
const draftValueEl = ref<HTMLInputElement | null>(null)
vueWatch(
  () => props.seed,
  (host) => {
    if (!host) {
      return
    }
    ruleDraft.value.value = host
    emit('seeded')
    void nextTick(() => draftValueEl.value?.focus())
  },
  { immediate: true }
)

// 从「拨不通」那一行带过来的网址：填好、聚焦，但不自动跑（协议是猜的，让人确认一下）。
// immediate 那一条不能省：这一页是 v-if 挂的，切过来时组件才创建，
// 不带 immediate 的话第一次带值进来会被当成"没有变化"，什么也不会填。
vueWatch(
  () => props.fetchSeed,
  (url) => {
    if (!url) {
      return
    }
    fetchUrl.value = url
    emit('seededFetch')
    void nextTick(() => fetchUrlEl.value?.focus())
  },
  { immediate: true }
)

async function onAddRule(): Promise<void> {
  const value = ruleDraft.value.value.trim()
  if (!value) {
    failure.value = '请先填域名，例如 notion.so'
    return
  }
  failure.value = ''
  const ok = await run(
    'add-rule',
    // 直连没有"节点"可言：选了直连还留着节点名，写出来就是一条后端会当场拒掉的行。
    () =>
      addUserRule({
        type: ruleDraft.value.type,
        value,
        policy: ruleDraft.value.policy,
        node: ruleDraft.value.policy === 'PROXY' ? ruleDraft.value.node : '',
        // 新加的一条当然是生效的：这里没有"沿用上一条的开关"这回事。
        disabled: false
      }),
    `已保存规则：${value} ${ruleDraft.value.policy === 'PROXY' ? '走代理' : '直连'}。`
  )
  // 存完了就把筛选放开：还留着旧关键字的话，新那条十有八九不在结果里，
  // 于是提示说"已保存"、表里却一行都没多——那是最容易被当成"没存上"的一幕。
  // 删除/改走向不清：用户盯的就是刚才那一行，筛选条件对他还有用。
  if (ok && ruleFilter.value !== '') {
    ruleFilter.value = ''
  }
  ruleDraft.value = { ...ruleDraft.value, value: '' }
}

/** 策略的人话名在 format.ts：这里曾经自己抄了一份三元表达式，
 *  结果 REJECT 和空值都掉进「直连」那一档——拦死的域名被说成随便走。 */

/**
 * 点策略标签就地反转：改一条规则的走向应该是「点一下」，而不是删了重加。
 *
 * 钉住节点的规则翻向"直连"时必须把节点名一起放掉：后端接受不了 DIRECT + node=
 * （直连没有节点可走，留着只会让这一行保存失败）。放掉是有意的一次信息损失，
 * 所以提示里要说出放开了谁——回头想再钉上，就在上面那一栏重新选一次。
 */
function onFlipRule(r: UserRule): Promise<boolean> {
  const next = r.policy === 'PROXY' ? 'DIRECT' : 'PROXY'
  const freed = r.policy === 'PROXY' && r.node !== ''
  return run(
    `flip:${r.type},${r.value}`,
    // 走向没变到"直连"时 node 原样带上：后端是整条替换的，
    // 漏了它等于"改个走向把固定节点弄丢了"。disabled 同理——
    // 改一条停用的规则的走向，不该顺手把它打开。
    () =>
      addUserRule({
        type: r.type,
        value: r.value,
        policy: next,
        node: next === 'PROXY' ? r.node : '',
        disabled: r.disabled
      }),
    `已把 ${r.value} 改为${next === 'PROXY' ? '走代理' : '直连'}。` + (freed ? `同时放开了钉住的 ${r.node}。` : '')
  )
}

/**
 * 停用/打开一条规则。
 *
 * 存在的理由：想查"是不是这一条把某个网站弄坏的"，以前唯一的办法是删掉它，
 * 而删掉之后就记不得原来写的是什么了（从订阅抄来的那几条尤其）。
 *
 * 走一个专门的接口而不是把整条规则重发给 AddUserRule：那条会 Normalize，
 * 只收域名类型，于是手写的 IP-CIDR / GEOIP / DOMAIN-REGEX 关不掉——
 * 而那几条恰恰是最想临时关掉的。这里后端只翻一个布尔，那一行其余部分原样不动。
 */
function onToggleRule(r: UserRule): Promise<boolean> {
  const next = !r.disabled
  return run(
    `toggle:${r.type},${r.value}`,
    () => setUserRuleDisabled(r.type, r.value, next),
    next
      ? `已停用 ${r.value}：它还留在名单里，但不再参与匹配。原来被它压住的规则会开始生效。`
      : `已重新启用 ${r.value}。`
  )
}

/**
 * 就地换掉一条已存在规则钉住的节点。
 *
 * 这一格存在的理由很简单：判语那一栏会告诉用户"这条钉的节点已经没了"，
 * 可除了删掉重加就没有别的办法——那等于把"发现问题"做完了，
 * 把"解决问题"留给人家去手改 user-rules.txt。
 * 后端是整条替换的，所以这里必须把 type/value/policy 原样带回去，只换 node。
 */
function onSetRulePin(r: UserRule, node: string): Promise<boolean> {
  return run(
    `pin:${r.type},${r.value}`,
    () => addUserRule({ type: r.type, value: r.value, policy: r.policy, node, disabled: r.disabled }),
    node === ''
      ? `已让 ${r.value} 回到「当前节点」，跟着顶栏那个选择走。`
      : `已把 ${r.value} 钉到 ${node}。`
  )
}

const onRemoveRule = (r: UserRule): Promise<boolean> =>
  run(`rm-rule:${r.type},${r.value}`, () => removeUserRule(r.type, r.value), `已删除 ${r.value} 的规则。`)

/* ---------- 命中顺序 ----------
   引擎取**第一条**命中的规则，所以名单里的位置就是优先级。
   面板加规则一律追加在末尾，于是"后加的精确域名被前面那条 SUFFIX 压住、
   一条都不生效"是必然会出现的一幕；没有上下移动，用户只能去手改文件。 */

/** 这条在整份名单里的位置（0 起）。筛过之后屏幕上看到的是它，序号也报它。 */
const absIndex = (r: UserRule): number => rules.value.indexOf(r)

/**
 * 上移/下移一格该落到哪一格。
 *
 * 目标取「屏幕上紧邻那条在整份名单里的位置」：筛着看的时候点↑才是
 * "挪到我看见的那条前面"。按屏幕行号去算后端位置，点了会像没动。
 */
function moveTarget(r: UserRule, dir: -1 | 1): number | null {
  const vis = shownRules.value
  const k = vis.findIndex((x) => x === r)
  if (k < 0) {
    return null
  }
  const nb = vis[k + dir]
  return nb ? rules.value.indexOf(nb) : null
}

const canUp = (r: UserRule): boolean => absIndex(r) > 0 && moveTarget(r, -1) !== null
const canDown = (r: UserRule): boolean => moveTarget(r, 1) !== null

function onMoveRule(r: UserRule, dir: -1 | 1 | 'top'): Promise<boolean> {
  const from = absIndex(r)
  const to = dir === 'top' ? 0 : moveTarget(r, dir)
  if (to === null || to === from) {
    return Promise.resolve(false)
  }
  const where = dir === 'top' ? '最前面' : `第 ${to + 1} 位`
  return run(
    `move:${r.type},${r.value}`,
    () => moveUserRule(r.type, r.value, to),
    `已把 ${r.value} 挪到${where}，命中顺序随即生效。`
  )
}

async function onProbe(): Promise<void> {
  const host = probeName.value.trim()
  if (!host) {
    failure.value = '请先填要查的域名'
    return
  }
  failure.value = ''
  busy.value = 'probe'
  // 现场在**发起那一刻**取，不在回来之后取：查询期间人可能就把模式切了，
  // 那时候存的要是新现场，这一格就永远不会被标成过期。
  const mode = props.status.mode
  const stamp = decideStamp.value
  try {
    rememberProbe(host, await probeHost(host), mode, stamp)
  } catch (err) {
    failure.value = `查询失败：${errorText(err)}`
  } finally {
    busy.value = ''
  }
}

// 「看解析」也接同一个 seed：从失败行点过来时填好域名、聚焦，人按回车才问。
vueWatch(
  () => props.dnsSeed,
  (host) => {
    if (!host) {
      return
    }
    dnsName.value = host
    emit('seededDNS')
    void nextTick(() => dnsNameEl.value?.focus())
  },
  { immediate: true }
)

// 取页面：结果与"取不到"那一句都存进同一份 store（见 ../probes 为什么存在）。
async function onFetchPage(): Promise<void> {
  if (fetchBusy.value) {
    return
  }
  const raw = fetchUrl.value.trim()
  if (!raw) {
    // 这不是"一份取不到的读数"，是一句关于输入的话：res 是 null，
    // 而 staleWhy 只给真拿到过答复的那份判过期（见 probes.ts），所以它不会去过期。
    rememberFetch('', null, '先填一个网址', props.status.mode, decideStamp.value)
    return
  }
  const mode = props.status.mode
  const stamp = decideStamp.value
  fetchBusy.value = true
  try {
    rememberFetch(raw, await fetchPage(raw), '', mode, stamp)
  } catch (err) {
    rememberFetch(raw, null, errorText(err), mode, stamp)
  } finally {
    fetchBusy.value = false
  }
}

/**
 * 「最近解析过」那一列左边的小标：四种来源必须一眼分得开。
 * 「缓存」那几行是当时引擎**真正在用**的那份，两档"刷新"是人按出来的——
 * 把它们混成一个"查过"，这一串就退化成访问日志了。
 */
function dnsHistTag(h: ProbeEntry<DNSProbe>): { text: string; cls: string } {
  if (!h.res) {
    return { text: '问不出', cls: 'err' }
  }
  if (h.res.refreshed) {
    return { text: '刷这一家', cls: 'warn' }
  }
  if (h.res.fresh) {
    return { text: '整条重问', cls: 'warn' }
  }
  if (h.res.cached) {
    return { text: '缓存', cls: 'mut' }
  }
  return { text: '新问', cls: 'direct' }
}

// 第三问：这批 IP 是什么。它自己那份忙标志，理由与取页面同一条（慢的只读动作不占写锁）。
//
// fresh=true 是「重问（不用缓存）」那一路。它不是一次"再看一眼"：
// 后端会跳过缓存去问、并把新答案**写回缓存**，也就是换掉了引擎下一刻判定用的那批地址。
// 所以这一按在界面上必须与「解析」说不同的话——两枚按钮干不同的事却报同一句
// "这就是引擎用的那批"，是最容易让人以为"点哪个都一样"的那种界面。
async function onProbeDNS(fresh: boolean, upstream: string): Promise<void> {
  if (dnsBusy.value) {
    return
  }
  const name = dnsName.value.trim()
  const mode = props.status.mode
  const stamp = decideStamp.value
  if (!name) {
    rememberDNS('', null, '先填一个域名', mode, stamp)
    return
  }
  dnsBusy.value = fresh || upstream ? 'fresh' : 'ask'
  try {
    rememberDNS(name, await probeDNS(name, fresh, upstream), '', mode, stamp)
  } catch (err) {
    rememberDNS(name, null, errorText(err), mode, stamp)
  } finally {
    dnsBusy.value = ''
  }
}

// 5 秒一轮，与后端轮询规则文件的节奏对齐：面板上"上次生效"的时刻
// 因此最多滞后一轮，改完文件不用手动刷新页面就能看到它动起来。
//
// 这里整份重读（不只是监视与订阅那两栏）：这一页说的是"磁盘上现在有哪些规则"，
// 而 user-rules.txt 是可以被编辑器、被 `> file`、被另一台机器上的脚本改写的。
// 只刷监视栏就会出现最难查的一幕——监视说"刚按新文件重载过"，
// 下面那张表却还摆着旧名单，于是界面上一切看起来都对，内容是过期的。
let timer = 0
/**
 * 在途保护：一轮还没回来就不再叠一轮。
 *
 * 这不是为了省几个请求，而是为了顺序：这一轮会打七次后端（规则、节点、
 * 拦截、监视、订阅、警告、命中），慢的时候超过 5 秒是可能的。
 * 没有这把锁时两轮会叠着跑，后发的先回就先把旧名单写进表里，
 * 于是界面在"新 → 旧 → 新"之间跳，看起来像规则自己变回去了。
 */
let loading = false
/**
 * 窗口隐藏（托盘）时停表。
 *
 * 这一页是 v-if 挂卸的，但用户停在规则页再点关闭窗口时组件并不会卸载
 * （gui.go 是 HideWindowOnClose），于是那七次调用照旧每 5 秒打一次后端，
 * 而人根本看不见这一页。隐藏期间唯一在长的东西是日志。
 */
let hidden = false

async function tick(): Promise<void> {
  if (loading || hidden) {
    return
  }
  loading = true
  try {
    await load()
  } finally {
    loading = false
  }
}

function onVisibility(): void {
  const wasHidden = hidden
  hidden = document.hidden
  // 重新显示时立刻补一轮：隐藏期间磁盘上可能已经改过了，
  // 让人盯着 5 秒前的旧表没意义。
  if (wasHidden && !hidden) {
    void tick()
  }
}

onMounted(() => {
  hidden = document.hidden
  void tick()
  timer = window.setInterval(() => void tick(), 5000)
  document.addEventListener('visibilitychange', onVisibility)
  window.addEventListener('focus', onVisibility)
})
onBeforeUnmount(() => {
  // 这一页是 v-if 挂卸的：不摘定时器，切走之后它还在每 5 秒敲一次后端。
  window.clearInterval(timer)
  document.removeEventListener('visibilitychange', onVisibility)
  window.removeEventListener('focus', onVisibility)
})
</script>

<template>
  <div class="view">
    <p v-if="notice" class="banner">{{ notice }}</p>
    <p v-if="failure" class="alert">{{ failure }}</p>

    <section class="card">
      <h2>
        自定义域名规则
        <span class="count">
          {{
            rulesKnown
              ? ruleFilter.trim() !== ''
                ? `显示 ${shownRules.length} / ${rules.length} 条`
                : `${rules.length} 条`
              : '条数未知'
          }}
          <span v-if="rulesStale" class="warn">· 读数已过期</span>
          · 优先于内置规则集
        </span>
      </h2>

      <div class="fields add">
        <select v-model="ruleDraft.type" aria-label="匹配方式">
          <option v-for="t in RULE_TYPES" :key="t.id" :value="t.id">{{ t.label }}</option>
        </select>
        <input
          ref="draftValueEl"
          v-model="ruleDraft.value"
          class="value"
          placeholder="notion.so"
          aria-label="域名"
          @keyup.enter="onAddRule"
        />
        <div class="seg" role="group" aria-label="走向">
          <button
            type="button"
            :class="{ on: ruleDraft.policy === 'PROXY' }"
            @click="ruleDraft.policy = 'PROXY'"
          >
            走代理
          </button>
          <button
            type="button"
            :class="{ on: ruleDraft.policy === 'DIRECT' }"
            @click="ruleDraft.policy = 'DIRECT'"
          >
            直连
          </button>
        </div>
        <!-- 固定节点：只从现有节点里挑。后端拿名字去装配那只出站，
             对不上就报错（绝不回落当前节点），所以这里不给手填自由文本。 -->
        <select
          v-model="ruleDraft.node"
          class="pin-select"
          aria-label="固定节点"
          :disabled="ruleDraft.policy !== 'PROXY' || nodeNames.length === 0"
          :title="ruleDraft.policy === 'PROXY' ? '这条只走选中的节点；换节点用“当前节点”那一档' : '直连没有节点可走'"
        >
          <option value="">当前节点</option>
          <option v-for="n in nodeNames" :key="n" :value="n">钉住 {{ n }}</option>
        </select>
        <button type="button" class="btn primary" :disabled="busy !== ''" @click="onAddRule">
          {{ busy === 'add-rule' ? '保存中…' : '添加规则' }}
        </button>
      </div>
      <div class="fields batch-toggle">
        <button type="button" class="btn ghost" @click="batchOpen = !batchOpen">
          {{ batchOpen ? '收起批量粘贴' : '批量粘贴' }}
        </button>
        <span class="mut">一行一个域名，或直接写完整的 类型,域名,策略</span>
      </div>

      <div v-if="batchOpen" class="batch">
        <textarea
          v-model="batchText"
          class="batch-text"
          rows="6"
          spellcheck="false"
          placeholder="notion.so&#10;ads.example.com&#10;DOMAIN-SUFFIX,example.cn,DIRECT"
          aria-label="要批量添加的规则"
        ></textarea>
        <div class="fields">
          <button type="button" class="btn primary" :disabled="busy !== ''" @click="onBatchAdd">
            {{ busy === 'batch-rule' ? '正在收…' : '加入名单' }}
          </button>
          <span class="mut">
            裸域名按上面选好的「{{ RULE_TYPES.find((x) => x.id === ruleDraft.type)?.label }}」与「{{
              ruleDraft.policy === 'PROXY' ? '走代理' : '直连'
            }}」补全
          </span>
        </div>

        <div v-if="batchResult" class="batch-out">
          <p>
            读到 <strong>{{ batchResult.total }}</strong> 行：新增 {{ batchResult.accepted }} 条、
            覆盖 {{ batchResult.updated }} 条、拒掉 {{ batchResult.rejected.length }} 行。
            <span v-if="!batchResult.written" class="warn">名单原样没动。</span>
          </p>
          <ul v-if="batchResult.rejected.length > 0" class="reject">
            <li v-for="(t, i) in batchResult.rejected" :key="'r' + i">{{ t }}</li>
          </ul>
          <ul v-if="batchResult.dead.length > 0" class="dead">
            <li v-for="(t, i) in batchResult.dead" :key="'d' + i">
              <span class="mono">{{ t }}</span>
            </li>
          </ul>
        </div>
      </div>
      <p class="hint">
        {{ RULE_TYPES.find((x) => x.id === ruleDraft.type)?.hint }} ·
        保存后立即热重载，不用重启代理。
      </p>

      <!-- 判语要说在表前面：这一页剩下的几栏讲的都算"哪条生效"，
           结论摆在表下面等于要用户先读完名单再想起去找判语。
           读失败与"没有问题"必须分开：没读到过时什么都不断言，
           读到过但这次读不到就照旧列出那份，并标上过期。 -->
      <div v-if="warnings.length > 0" class="alert warn dead-box">
        <p>
          这份名单里有 <strong>{{ warnings.length }}</strong> 条写得对却走不到想去的地方。
          <span v-if="warnStale" class="warn">· 读数已过期</span>
        </p>
        <!-- 分类那一小段一句一行。每句都得写在一行里：模板换行会被折成一个空格，
             而中文标点后多出一个空格是很显眼的脏。 -->
        <ul class="kinds">
          <li v-if="shadowCount > 0">
            <strong>{{ shadowCount }}</strong> 条<strong>永远不会命中</strong>——引擎按顺序取<strong>第一条</strong>命中的规则，被前面的规则盖住就一条都轮不到
          </li>
          <li v-if="nodeMissingCount > 0">
            <strong>{{ nodeMissingCount }}</strong> 条<strong>钉的节点不在配置里</strong>，走到它们的连接会直接失败，不会回落当前节点
          </li>
          <li v-if="unknownKinds.length > 0">
            <strong>{{ unknownKinds.length }}</strong> 条是这一版界面没认出来的问题（<span class="mono">{{
              [...new Set(unknownKinds.map((w) => w.kind))].join(' / ')
            }}</span>），判语原样列在下面
          </li>
        </ul>
        <ul class="dead">
          <li v-for="(w, i) in warnings" :key="i">
            <!-- 用户写的那一行照原样立出来：他要在文件里找的就是它，
                 而"为什么"和"怎么办"是后端的话，用正文字体分开。 -->
            <span class="mono">{{ w.line }}</span>
            <span>{{ w.why }}</span>
          </li>
        </ul>
      </div>
      <p v-if="warnError !== ''" class="alert warn">
        「这份名单里的问题」这一栏读不到：{{ warnError }}。
        {{ warnStale ? '上面那份是上一次读到的，可能已经不是现在这个样子。' : '所以这里既不能说有风险，也不能说没有。' }}
      </p>

      <div class="filter">
        <input
          v-model="ruleFilter"
          type="search"
          data-focus-shortcut
          placeholder="按域名 / 匹配方式 / 走向过滤，例如 google 或 直连"
          aria-label="自定义规则过滤"
        />
        <button
          v-if="ruleFilter !== ''"
          type="button"
          class="btn ghost"
          @click="ruleFilter = ''"
        >
          清除过滤
        </button>
      </div>

      <!-- 键盘用户的"跳过导航"：这一张表每行有 6~7 个控件，画满 200 行就是
           一千多个 Tab 停靠点，而下面「拦截域名」那一栏也在同一页上。
           没有这一条，从表头按 Tab 走到下一栏要按一千多次——不是难，是做不到。
           平时不占版面，Tab 到它才现形（见 .skip-link 的样式）。
           条数说出来是让人在按下去之前就知道省掉多少下。 -->
      <a
        v-if="tableControlCount > 20"
        class="skip-link"
        href="#wps-block-section"
        @click="focusBlockSection"
      >
        跳过这张规则表（{{ tableControlCount }} 个控件），到「拦截域名」
      </a>

      <div ref="tableWrap" class="table-wrap">
        <table class="grid-table">
          <thead>
            <tr>
              <th class="num" title="名单里的位置就是命中优先级：排在前面的先命中">序</th>
              <th>匹配</th>
              <th>域名</th>
              <th>走向</th>
              <th class="num" title="本次会话里这一条定过多少条连接。清空统计或重启面板会归零；改过走向或节点的那一条也算重新开始数">命中</th>
              <th class="num">操作</th>
            </tr>
          </thead>
          <tbody>
            <!-- 一条都没筛出来时必须说"在 N 条里没找到"：画一张空表会被读成
                 "你还没写过自定义规则"，那正好把人推向重复添加。 -->
            <tr v-if="ruleFilter !== '' && shownRules.length === 0">
              <td colspan="6" class="mut">
                {{ rules.length }} 条里没有匹配「{{ ruleFilter.trim() }}」的规则。
                换个关键字，或点上面的「清除过滤」看全部。
              </td>
            </tr>
            <tr
              v-for="r in visibleRules"
              :key="r.type + ',' + r.value"
              :class="{ off: r.disabled }"
            >
              <td class="num ord">
                <span class="pos">{{ absIndex(r) + 1 }}</span>
                <span class="ord-act">
                  <button
                    type="button"
                    class="btn sm ghost"
                    :disabled="busy !== '' || !canUp(r)"
                    title="上移一位"
                    @click="onMoveRule(r, -1)"
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    class="btn sm ghost"
                    :disabled="busy !== '' || !canDown(r)"
                    title="下移一位"
                    @click="onMoveRule(r, 1)"
                  >
                    ↓
                  </button>
                  <button
                    type="button"
                    class="btn sm ghost"
                    :disabled="busy !== '' || absIndex(r) === 0"
                    title="挪到最前面：排在前面的先命中，这一条就能盖住前面那些压住它的规则"
                    @click="onMoveRule(r, 'top')"
                  >
                    顶
                  </button>
                </span>
              </td>
              <td class="mut">{{ r.type }}</td>
              <td class="mono">{{ r.value }}</td>
              <td>
                <span class="pill" :class="policyClass(r.policy)">{{ policyText(r.policy) }}</span>
                <!-- 停用了还显示"走代理"是半句谎话：这一条此刻谁都不走。
                     标在这里而不是只把整行变灰，是因为灰度在深色主题里很容易看不出来，
                     而"这条不生效"是这一行此刻最重要的事实。 -->
                <span v-if="r.disabled" class="pill off-pill">已停用</span>
                <!-- 钉住谁必须看得见：这条流量的去处和"当前节点"不是一回事，
                     只写"走代理"会让人以为它跟着顶栏那个选择走。
                     节点被改名/删掉之后这一格要当场说破：上面判语那一栏是唯一
                     报这件事的地方，可它是按名单顺序摊开的，用户未必扫到对应那一条。
                     名单读不到（nodeNames 为空）时一律按"没问题"处理——
                     读失败不等于节点不存在，那种时候染色等于凭空指控一条好规则。 -->
                <select
                  v-if="pinEditable(r)"
                  class="pin-select inline"
                  :class="{ broken: pinBroken(r) }"
                  :value="r.node"
                  :disabled="busy !== ''"
                  :aria-label="`这条走哪个节点：${r.value}`"
                  :title="pinBroken(r) ? `配置里没有叫 ${r.node} 的节点，这条走不通（不会回落当前节点）；换一个或选「当前节点」` : '这条只走选中的节点'"
                  @change="onSetRulePin(r, ($event.target as HTMLSelectElement).value)"
                >
                  <!-- 坏名字得自己占一项：下拉里若没有当前值，浏览器会显示成空白，
                       于是"钉了个不存在的节点"这一格看起来像"没钉"——正好把要说的反话说了。 -->
                  <option v-if="pinBroken(r)" :value="r.node">⚠ {{ r.node }}（已不存在）</option>
                  <option value="">当前节点</option>
                  <option v-for="n in nodeNames" :key="n" :value="n">{{ n }}</option>
                </select>
                <span
                  v-else-if="r.node"
                  class="pin-tag"
                  :class="{ broken: pinBroken(r) }"
                  :title="pinBroken(r) ? `配置里没有叫 ${r.node} 的节点，这条走不通（不会回落当前节点）` : `这条只走 ${r.node}`"
                  >→ {{ r.node }}</span
                >
              </td>
              <td class="num">
                <!-- 0 留着但排得淡：一份几百条的名单里"0 次"很多，
                     全用正常字重会把真正有数的那几条淹掉。 -->
                <span v-if="hitOf(r) === 0" class="mut">0</span>
                <span v-else>{{ hitOf(r) }}</span>
              </td>
              <td class="num">
                <!-- 停用/打开排在最前面，而且**只读行也有**：
                     手写的 IP-CIDR / GEOIP 恰恰是最想临时关掉来排查的那几条，
                     而它们不能走"改走向"那个按钮（那个会 Normalize，只收域名类型）。
                     停用不改这条的走向，也不删它，所以不在"只读"的限制里。 -->
                <button
                  type="button"
                  class="btn sm ghost"
                  :disabled="busy !== ''"
                  :title="r.disabled ? '重新参与匹配' : '暂时不参与匹配，但留在名单里'"
                  @click="onToggleRule(r)"
                >
                  {{ r.disabled ? '启用' : '停用' }}
                </button>
                <span v-if="!editableRule(r)" class="mut">{{ readonlyNote(r) }}</span>
                <!-- 拦截行只读：那个一键翻转会把「不许出网」悄悄改成走代理或直连，
                     等于在面板里手滑就把黑名单放开。成批名单请用配置的 block: 段。
                     移动不在这个限制里——换顺序不会改这条的走向。 -->
                <span v-else class="row-act">
                  <button type="button" class="btn sm ghost" :disabled="busy !== ''" @click="onFlipRule(r)">
                    改为{{ r.policy === 'PROXY' ? '直连' : '走代理' }}
                  </button>
                  <button type="button" class="btn sm ghost danger" :disabled="busy !== ''" @click="onRemoveRule(r)">
                    删除
                  </button>
                </span>
              </td>
            </tr>
            <tr v-if="hiddenRuleCount > 0">
              <td colspan="6" class="mut window-row">
                只画出了前 <strong>{{ visibleRules.length }}</strong> 条，还有
                <strong>{{ hiddenRuleCount }}</strong> 条没画——一屏几千行没人读得完，
                而这一页每五秒就要把它们全重画一遍。
                <button type="button" class="btn sm ghost" @click="ruleWindow += RULE_WINDOW">
                  再多画 {{ Math.min(RULE_WINDOW, hiddenRuleCount) }} 条
                </button>
                <button type="button" class="btn sm ghost" @click="ruleWindow = shownRules.length">
                  全部画出（{{ shownRules.length }} 条）
                </button>
                <!-- 面板加规则一律追加在名单末尾，而这里默认画的是开头：
                     刚粘完 900 条却看见的还是原来那 7 条，人会以为没加上。
                     这句话就是补这一格的——不展开窗口，因为窗口一展开就回到每五秒重画几千行。 -->
                <span class="win-note">
                  过滤框搜的是整份名单，不用先展开。
                  <template v-if="ruleFilter.trim() === ''">
                    刚添加的规则排在名单<strong>末尾</strong>（优先级最低），多半在没画出来的那一段里。
                  </template>
                </span>
              </td>
            </tr>
            <tr v-if="rules.length === 0">
              <td colspan="6" class="mut">
                {{
                  rulesKnown
                    ? '还没有自定义规则。上面填个域名，选「走代理」或「直连」即可。'
                    : '还没读到过这份名单，所以这里既不是「有规则」也不是「没规则」——先解决上面的错误。'
                }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="hint">
        最左那一列是这条在名单里的位置——引擎命中第一条就停，所以位置就是优先级。
        <span class="mono">↑</span> 与 <span class="mono">↓</span> 和相邻那条换位，
        <span class="mono">顶</span> 挪到最前面；正筛着的时候上下会灰掉（邻居被筛掉了，没得换），
        <span class="mono">顶</span> 仍然可用。
      </p>

      <p class="hint">
        上面那三种是面板能改的全部。手写的
        <span class="mono">IP-CIDR</span> / <span class="mono">GEOIP</span> /
        <span class="mono">DOMAIN-REGEX</span> 行原样保留、只读显示（移动它们是可以的），
        要改内容就直接编辑 <span class="mono">user-rules.txt</span>——
        进程在跑时文件一改就自动生效，面板这一栏跟着刷新。
      </p>
    </section>

    <!-- 拦截名单：配置段维护，界面只读。放在自定义规则正下面，
         因为这页讲的就是"哪些域名出不出去"，少这一栏就只能去翻 YAML。 -->
    <section id="wps-block-section" class="card skip-target" tabindex="-1">
      <h2>
        拦截域名
        <span class="count">
          {{ blockKnown ? `${block?.domains.length ?? 0} 条` : '条数未知' }}
          <span v-if="blockStale" class="warn">· 读数已过期</span>
        </span>
      </h2>

      <p v-if="!block" class="mut">{{ blockKnown ? '读取中…' : '还没读到过这份名单——上面若是错误，说明读它失败了。' }}</p>
      <template v-else>
        <div class="fields add">
          <input
            v-model="blockDraft"
            class="value"
            placeholder="要拦的域名，例如 ads.example.com"
            aria-label="拦截域名"
            @keyup.enter="onAddBlock"
          />
          <button type="button" class="btn primary" :disabled="busy !== ''" @click="onAddBlock">
            {{ busy === 'add-block' ? '添加中…' : '添加' }}
          </button>
        </div>

        <div class="fields batch-toggle">
          <button type="button" class="btn ghost" @click="blockBatchOpen = !blockBatchOpen">
            {{ blockBatchOpen ? '收起批量粘贴' : '批量粘贴（成百上千条用这个）' }}
          </button>
        </div>

        <div v-if="blockBatchOpen" class="batch">
          <textarea
            v-model="blockBatchText"
            class="batch-text"
            rows="6"
            spellcheck="false"
            placeholder="一行一个域名，例如：
ads.example.com
||track.example.net^
||cdn.example.org^$third-party

# 与 ! 开头的行是注释；@@||x 是例外规则（不要拦它），这份名单不收。"
            aria-label="批量粘贴拦截域名"
          ></textarea>
          <div class="fields">
            <button type="button" class="btn primary" :disabled="busy !== ''" @click="onBlockBatchAdd">
              {{ busy === 'batch-block' ? '正在收…' : '加入名单' }}
            </button>
            <span class="mut">整段只写一次盘；上面那份名单是按后缀拦的，父域已经在名单里就不用再粘子域了。</span>
          </div>
          <div v-if="blockBatchResult" class="batch-out">
            <p :class="{ warn: !blockBatchResult.written }">{{ blockBatchSummary(blockBatchResult) }}</p>
            <ul v-if="blockBatchResult.rejected.length > 0" class="reject">
              <li v-for="(t, i) in blockBatchResult.rejected" :key="'r' + i">{{ t }}</li>
            </ul>
            <ul v-if="blockBatchResult.dead.length > 0" class="dead">
              <li v-for="(t, i) in blockBatchResult.dead" :key="'d' + i">
                {{ t }}
              </li>
            </ul>
          </div>
        </div>

        <!-- 几十条往上就没有人会在这一团 chip 里找东西了，所以给一个框。
             短名单不显示它：三五条域名一眼看完，多一个输入框只是多一处要理解的东西。 -->
        <div v-if="block.domains.length > 40" class="fields filter">
          <input
            v-model="blockFilter"
            type="search"
            data-focus-shortcut
            placeholder="在这份名单里找，例如 example.com"
            aria-label="拦截名单过滤"
          />
        </div>

        <div v-if="matchedBlock.length" class="chips">
          <span v-for="d in visibleBlock" :key="d" class="chip">
            <span class="mono">{{ d }}</span>
            <button
              type="button"
              class="chip-x"
              :disabled="busy !== ''"
              :aria-label="`把 ${d} 移出拦截名单`"
              :title="`把 ${d} 移出拦截名单`"
              @click="onRemoveBlock(d)"
            >
              <svg viewBox="0 0 10 10" aria-hidden="true">
                <path d="M2.5 2.5 7.5 7.5M7.5 2.5 2.5 7.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
              </svg>
            </button>
          </span>
        </div>
        <!-- 「筛没了」与「名单本来就是空的」是两件事，混成一句会把人推向重复添加。 -->
        <p v-else-if="block.domains.length" class="mut">
          {{ block.domains.length }} 条里没有匹配「{{ blockFilter.trim() }}」的域名。换个关键字或清空这一栏。
        </p>
        <p v-else class="mut">
          名单是空的，现在不拦任何域名。上面填一个域名点「添加」，或直接在
          <span class="mono">config.yaml</span> 的 <span class="mono">block:</span> 段里写。
        </p>
        <p v-if="hiddenBlockCount > 0" class="mut window-row">
          只画出了前 <strong>{{ visibleBlock.length }}</strong> 条，还有
          <strong>{{ hiddenBlockCount }}</strong> 条没画（这一栏每五秒要把整份名单重画一遍）。
          <button type="button" class="btn sm ghost" @click="blockWindow += BLOCK_WINDOW">
            再多画 {{ Math.min(BLOCK_WINDOW, hiddenBlockCount) }} 条
          </button>
          <button type="button" class="btn sm ghost" @click="blockWindow = matchedBlock.length">
            全部画出（{{ matchedBlock.length }} 条）
          </button>
        </p>

        <!-- 死条目排在累计数前面：它是名单自己的问题（装了没多拦），
             累计数是运行的结果，两件事混在一句提示里会互相盖过。 -->
        <div v-if="block.deadTotal > 0" class="batch-out dead-box">
          <p>
            名单里有 <strong>{{ block.deadTotal }}</strong> 条什么也没多拦：按后缀拦，父域已经在名单里，
            子域那条就是空操作。留着不影响拦截，只是让人以为"我加了它怎么还在外连"。
          </p>
          <ul class="dead">
            <li v-for="(t, i) in block.dead" :key="'b' + i">{{ t }}</li>
          </ul>
          <p v-if="block.deadTotal > block.dead.length" class="mut">
            这里只列出前 {{ block.dead.length }} 条，共 {{ block.deadTotal }} 条。
          </p>
          <button type="button" class="btn sm" :disabled="busy !== ''" @click="onPruneBlock">
            {{ busy === 'prune-block' ? '清理中…' : `清掉这 ${block.deadTotal} 条冗余` }}
          </button>
          <p class="mut">
            清理只是去重：更宽的那条盖住的范围一模一样，删掉不改变任何一个域名的判定。
          </p>
        </div>

        <p v-if="block.live && block.mode !== 'direct'" class="mut tail">
          本次运行已经拦下
          <b>{{ blockedTotal }}</b>
          条（0 就是 0：名单装着，但还没有连接撞上它）。应用那边不会收到任何原因，
          这件事只有这一页和日志说得出。
        </p>

        <!-- 留痕放在累计数下面：它回答的是"刚才那一个到底拦没拦"，
             而连接表是环形流水，几秒就会被别的请求冲掉。 -->
        <div v-if="recentBlocked.length" class="hits">
          <h3>最近拦下 {{ recentBlocked.length }} 个目标（历史留痕：把域名移出名单，这条记录还在，到点或「清空统计」才走）</h3>
          <ul>
            <li v-for="h in recentBlocked" :key="h.host + '|' + h.rule" class="hit">
              <span class="hit-main">
                <span class="line1">
                  <span class="mono">{{ h.host }}</span>
                  <span class="mut">×{{ h.count }} · {{ formatAgo(h.lastAt) }}</span>
                </span>
                <!-- 规则原文是这栏里最长的字符串，让它自己截断，别把整栏撑出横向滚动。 -->
                <span class="mono mut rule">{{ h.rule }}</span>
              </span>
              <!-- 一键放开：拦错了最远的距离就是"要回去翻名单才知道删哪条"。
                   只有 host 本身就在名单里才给按钮——撞上来的是子域时该删的是那条父域，
                   前端不去猜父域（归一化是后端的事），这一行就只展示。 -->
              <button
                v-if="inBlockList(h.host)"
                type="button"
                class="btn sm"
                :disabled="busy !== ''"
                @click="onRemoveBlock(h.host)"
              >
                移出名单
              </button>
            </li>
          </ul>
        </div>
        <p v-else-if="block.live" class="mut tail">
          还没有拦截留痕：本次运行没有连接撞上名单（点「清空统计」或重启面板也会把它清掉）。
        </p>

        <p class="hint tail">
          命中即<strong>静默丢弃</strong>：不回 SOCKS 失败应答、也不回 HTTP 502，应用只会等到超时——
          原因只能在这一页和日志里看。按后缀匹配，含所有子域；这份名单排在规则文件<b>之前</b>，
          压得过 <span class="mono">DOMAIN-SUFFIX,x,DIRECT</span> 这类放行规则。
        </p>
        <p v-if="!block.live" class="alert warn tail">
          代理没在跑，上面这份是按 <span class="mono">{{ block.path }}</span> 现算的，还没有任何东西真的被拦。
        </p>
        <p v-else-if="block.mode === 'direct'" class="alert warn tail">
          当前是「直连」模式——<b>黑名单整体让开</b>，这 {{ block.domains.length }} 条现在一条都不拦。
          这是刻意留的逃生阀：切回「规则」模式才生效。
        </p>
        <p v-else class="mut tail">
          名单住在 <span class="mono">{{ block.path }}</span> 的 <span class="mono">block:</span> 段里——
          上面「添加 / 删除」改的就是这一份，写完立刻热装载，不用点「重载规则」。
          零散几条也可以直接写进规则文件用 <span class="mono">REJECT</span> 策略。
        </p>
      </template>
    </section>

    <!-- 探测与内置规则集都是"看一眼"的信息，并排放，省一屏。 -->
    <div class="g2">
      <section class="card">
        <h2>查走向</h2>
        <div class="fields">
          <input
            v-model="probeName"
            class="probe"
            placeholder="www.notion.so"
            aria-label="要查的域名"
            @keyup.enter="onProbe"
          />
          <button type="button" class="btn" :disabled="busy !== ''" @click="onProbe">
            {{ busy === 'probe' ? '查询中…' : '查询' }}
          </button>
          <span v-if="probeRes" class="probe-out">
            <span class="pill" :class="policyClass(probeRes.policy)">{{ policyText(probeRes.policy) }}</span>
            <span class="mut">
              命中 <span class="mono">{{ probeRes.matched }}</span> · 模式 {{ modeText(probeRes.mode) }}
              <!-- 落到哪个节点：判定那一段与真拨号同源（都走 Router.decide），
                   而探测刻意不去建出站——解析节点地址不是这一问的一部分（见 internal/router/preview.go）。
                   所以"查走向"能先答完"为什么会这样"，不用人再去表里找一条同类连接。
                   直连与拦截时后端给的是空串——那不是节点，没必要造一个词出来。 -->
              <template v-if="probeRes.node"> · 落到 <span class="mono">{{ probeRes.node }}</span></template>
              <!-- 网卡那一格只在真的钉上了时出现（没开分流、或代理没在跑时后端给空串），
                   与连接表那一列同一个判据：不是一列全空的东西不摆出来。 -->
              <template v-if="probeRes.iface"> · 走网卡 <span class="mono">{{ probeRes.iface }}</span></template>
              <template v-if="!probeRes.live">（未运行，按磁盘规则算）</template>
              <!-- 这行"几时查的"是跨页留着读数的另一半：没有它，五分钟前的答复
                   与五秒前的答复在屏幕上长得一模一样。agoText 读的是模块级那个钟，
                   所以这一行会自己走字，不用重查。 -->
              · {{ probeAgo }}查的
            </span>
          </span>
        </div>
        <p v-if="probeWhy" class="alert warn">
          上面那一句<strong>已经不是现在的答复</strong>：{{ probeWhy }}。重新查一次才算现在。
        </p>
        <p class="hint">
          这些规则写在 <span class="mono">assets/user-rules.txt</span>，被主规则集引在<b>最前面</b>，
          所以能盖住内置的被墙域名表。
        </p>
      </section>

      <section class="card">
        <h2>取一个真页面</h2>
        <div class="fields">
          <input
            v-model="fetchUrl"
            ref="fetchUrlEl"
            class="probe"
            placeholder="https://www.gstatic.com/generate_204"
            aria-label="要取的网址"
            @keyup.enter="onFetchPage"
          />
          <button type="button" class="btn" :disabled="fetchBusy" @click="onFetchPage">
            {{ fetchBusy ? '取页面中…' : '取页面' }}
          </button>
        </div>
        <!-- 飞行中不摆上一次的结果：那会让"这次还没回话"看起来像"这次也是 200"。 -->
        <p v-if="fetchBusy" class="mut">正在按规则取……（要真建一次电路、真发一个请求）</p>
        <p v-else-if="fetchErr" class="alert warn">
          取不到：<strong>{{ fetchErr }}</strong>
          <!-- 这一句与下面那张"取回来但不算通"的卡片是两件事：
               拨不通 / URL 写错 / 被名单拦下才是取不到，回了 4xx 是取到了。 -->
        </p>
        <dl v-else-if="fetchRes" class="kv">
          <dt>取的</dt>
          <dd class="mono">{{ fetchRes.url || '—' }}</dd>
          <dt>拨到</dt>
          <dd>
            <span class="mono">{{ fetchRes.addr }}</span>
            <span class="mut">{{ fetchRes.viaTLS ? 'https（TLS 在本地做，交给节点的是明文 CONNECT）' : 'http（明文）' }}</span>
          </dd>
          <dt>回话</dt>
          <dd>
            <!-- 状态码用红绿那颗 pill：取回 400 也是"有答案"，
                 所以这一行不能只在通了的时候才出现。 -->
            <span class="pill" :class="fetchRes.ok ? 'direct' : 'err'">
              {{ fetchRes.code ? `HTTP ${fetchRes.code}` : '没回状态行' }}
            </span>
            <span class="mut">{{ fetchRes.server || '没带 Server 头' }} · {{ formatBytes(fetchRes.body) }}</span>
          </dd>
          <template v-if="fetchRes.location">
            <dt>跳到</dt>
            <dd class="mono">{{ fetchRes.location }}</dd>
          </template>
          <!-- 结论只在"取到了但不算通"时出现：通的时候后端那句是
               `https 200 server=ECS 1256 字节`——与上面「回话」那一行是同一句话说两遍，
               摆出来只会把真正要看的那一行挤下去。不通时它是这一格里最有信息量的一行。 -->
          <template v-if="!fetchRes.ok">
            <dt>结论</dt>
            <dd class="warn">{{ fetchRes.reason }}</dd>
          </template>
          <dt>这一条走的</dt>
          <dd>
            <span class="pill" :class="policyClass(fetchRes.policy)">{{ policyText(fetchRes.policy) }}</span>
            <span class="mut">命中 <span class="mono">{{ fetchRes.matched }}</span></span>
            <template v-if="fetchRes.node">
              <span class="mut">· 落到 <span class="mono">{{ fetchRes.node }}</span></span>
            </template>
            <template v-if="fetchRes.iface">
              <span class="mut">· 走网卡 <span class="mono">{{ fetchRes.iface }}</span></span>
            </template>
            <span class="mut">· {{ fetchAgo }}取的</span>
          </dd>
        </dl>
        <!-- 判定那几列会跟着模式与名单走，状态码那几行不会：
             所以这里只作废前者，不整格标灰——把"它回过 400"也说成"不算数"，
             就从一个撒谎走到另一个撒谎了。 -->
        <p v-if="fetchWhy" class="alert warn">
          上面「这一条走的」那几列<strong>已经不是现在的判定</strong>：{{ fetchWhy }}。
          状态码与 <span class="mono">Server:</span> 那几行不受影响，那是真的取回来过的东西。
        </p>
        <!-- 只留最近几次的一份流水：这一格要回答的常常不是"这一次怎么样"，
             而是"刚才还好好的，现在怎么全是 400"、"同一个网址在这个节点通、
             在那个节点不通"。只看最后一次就得靠人自己截图去比。
             一次的时候不摆——那一行与上面那一格说的是同一件事。 -->
        <details v-if="fetchHistory.length > 1" class="more">
          <summary>最近取过 {{ fetchHistory.length }} 次</summary>
          <ul class="hist">
            <li v-for="h in fetchHistory" :key="h.at">
              <span class="mut">{{ agoText(h.at) }}</span>
              <span class="pill" :class="h.res && h.res.ok ? 'direct' : 'err'">
                {{ h.res ? (h.res.code ? `HTTP ${h.res.code}` : '没回状态行') : '取不到' }}
              </span>
              <span class="mono">{{ safeLabel(h) }}</span>
              <span v-if="h.res" class="mut">
                {{ policyText(h.res.policy) }}<template v-if="h.res.node"> · {{ h.res.node }}</template>
              </span>
              <span v-else class="why">{{ h.err }}</span>
            </li>
          </ul>
          <p class="mut">
            只留最近 6 次，重启就没。走向与节点那一格是<strong>那一次</strong>的实际判定，
            不当作现在的答案——要看此刻的走向用上面「查走向」。
          </p>
        </details>
        <p class="hint">
          这一格与上面「查走向」是一对：那边答<b>按规则该怎么走</b>，这边答<b>它实际回什么</b>。
          两者会不一致——节点对面是一台兜底 web 服务器时，判定完全正常、电路也建得起来，
          而任何站点回来的都是同一个 400。只看判定那一格看不出来，取一次页面就说漏嘴了
          （状态码与 <span class="mono">Server:</span> 头）。
          回显的网址会去掉查询串与账号信息，订阅 key 常挂在那上面，而这一格的内容通常要被截图发出去。
        </p>
      </section>

      <section class="card">
        <h2>看解析</h2>
        <div class="fields">
          <input
            v-model="dnsName"
            ref="dnsNameEl"
            class="probe"
            placeholder="www.example.com"
            aria-label="要解析的域名"
            @keyup.enter="onProbeDNS(false, '')"
          />
          <button type="button" class="btn" :disabled="!!dnsBusy" @click="onProbeDNS(false, '')">
            {{ dnsBusy === 'ask' ? '解析中…' : '解析' }}
          </button>
          <button
            type="button"
            class="btn"
            :disabled="!!dnsBusy || !dnsName.trim()"
            title="跳过缓存重新问一次上游，并把新答案写回缓存——引擎下一刻就按这批地址判定"
            @click="onProbeDNS(true, '')"
          >
            {{ dnsBusy === 'fresh' ? '重问中…' : '重问（不用缓存）' }}
          </button>
        </div>
        <p v-if="dnsBusy" class="mut">
          {{ dnsBusy === 'fresh' ? '正在跳过缓存问上游，拿到后会替换缓存里那份……' : '正在问上游……' }}
        </p>
        <p v-else-if="dnsErr" class="alert warn">问不出来：<strong>{{ dnsErr }}</strong></p>
        <dl v-else-if="dnsRes" class="kv">
          <dt>问的</dt>
          <dd class="mono">{{ dnsRes.host }}</dd>
          <dt>拿到</dt>
          <dd>
            <span v-if="dnsRes.addrs.length === 0" class="warn">一个地址都没拿到</span>
            <ul v-else class="hist">
              <li v-for="a in dnsRes.addrs" :key="a.addr">
                <span class="mono">{{ a.addr }}</span>
                <!-- 归属码那颗 pill 分三档：CN 黄（它会把流量往直连拉）、
                     非 CN 绿、库里没有走中性。把"不知道"画成任何一个颜色都是假话。 -->
                <span class="pill" :class="a.known ? (a.country === 'CN' ? 'warn' : 'direct') : 'mut'">
                  {{ a.known ? a.country : '库里没有这条' }}
                </span>
              </li>
            </ul>
          </dd>
          <dt>怎么问的</dt>
          <dd>
            <span class="mut">{{ dnsRes.via === 'tunnel' ? '经当前节点问上游' : '本机直连上游' }}</span>
            <span class="mut">{{ dnsRes.cached ? `没出门问，这份是缓存里的（${dnsRes.ms}ms）` : `出门问的，用了 ${dnsRes.ms}ms` }}</span>
            <span v-if="dnsTtlLine" :class="dnsTtlStale ? 'warn' : 'mut'">{{ dnsTtlLine }}</span>
            <!-- 这一句不能省：这一按动的不是"看一眼"，是引擎下一刻的判定依据。
                 把它写成与「解析」同一句话，人就会以为两个按钮是同一个动作的两种说法。 -->
            <span v-if="dnsRes.refreshed" class="warn">
              刚把 <span class="mono">{{ dnsRes.refreshed }}</span> 那一份重问回来并写回缓存。
              合并那一路这次刻意没再走——再走一遍就会被另一个上游的答案盖掉，那一按等于没按
            </span>
            <span v-else-if="dnsRes.fresh" class="warn">
              这一按跳过了缓存，新答案已经写回去——上面这批就是引擎下一刻拿去判定的那批
            </span>
            <span class="mut">{{ dnsRes.tunnelOn ? '配置允许经隧道解析' : '配置没开隧道解析' }}</span>
          </dd>
          <dt>上游</dt>
          <dd class="mono">{{ dnsRes.upstreams.length ? dnsRes.upstreams.join(' · ') : '配置里没写上游' }}</dd>
          <!-- 挨个上游各问一遍：合并那份只留先回来的一个，
               而"哪个上游在说谎"是查污染时唯一想知道的事。 -->
          <dt>每个上游</dt>
          <dd>
            <ul class="hist">
              <li v-for="u in dnsRes.perUpstream" :key="u.server">
                <span class="mono">{{ u.server }}</span>
                <span v-if="u.err" class="warn">没答上来：{{ u.err }}</span>
                <template v-else>
                  <span class="mono">{{ u.addrs.join(' ') }}</span>
                  <span class="pill" :class="policyClass(u.policy)">{{ policyText(u.policy) }}</span>
                  <span class="mut">{{ u.matched }} · {{ u.ms }}ms</span>
                </template>
                <span v-if="u.server === dnsRes.used" class="mut">← 引擎用的是这份</span>
                <!-- 分叉时唯一有用的动作：怀疑谁就刷谁。上面那枚「重问」走的是合并那一路
                     （任一成功即采用），很可能把同一份脏答案再抄一遍回来。 -->
                <button
                  type="button"
                  class="btn sm ghost"
                  :disabled="!!dnsBusy"
                  :title="`只重问 ${u.server} 这一家，并把它的回答写回缓存（引擎下一刻就按它判）`"
                  @click="onProbeDNS(false, u.server)"
                >
                  只重问这一家
                </button>
              </li>
            </ul>
          </dd>
          <dt>只看这批 IP</dt>
          <dd>
            <span class="pill" :class="policyClass(dnsRes.ipPolicy)">{{ policyText(dnsRes.ipPolicy) }}</span>
            <span class="mut">命中 <span class="mono">{{ dnsRes.ipMatched }}</span></span>
          </dd>
          <dt>引擎实际判的</dt>
          <dd>
            <span class="pill" :class="policyClass(dnsRes.policy)">{{ policyText(dnsRes.policy) }}</span>
            <span class="mut">命中 <span class="mono">{{ dnsRes.matched }}</span></span>
            <span v-if="dnsRes.matched !== dnsRes.ipMatched" class="mut">
              —— 域名规则先命中，这批 IP 根本没参与这次结论
            </span>
            <span class="mut">· {{ dnsAgo }}问的</span>
          </dd>
          <template v-if="dnsRes.note">
            <dt>说明</dt>
            <dd class="warn">{{ dnsRes.note }}</dd>
          </template>
        </dl>
        <!-- 分叉要说在最前面：这一档不是"信息多一点"，而是"这台机器的判定建立在运气上"。 -->
        <p v-if="dnsRes && dnsRes.divergent" class="alert warn">
          这几个上游给了<b>不同的地址</b>。引擎用的是<b>先回来的那一份</b>——
          不是"更好的"那一份，它甚至不知道还有另一份。同一个域名"有时直连、有时绕隧道"
          就是这么来的；要治它得换上游或改 <span class="mono">dns.servers</span>，改规则没用。
          想先按可信那一家跑着，就点它行末的「只重问这一家」——
          <b>这只管到这条缓存过期为止</b>，到点之后合并那一路仍然继续碰运气。
        </p>
        <p v-if="dnsWhy" class="alert warn">
          上面「引擎实际判的」那一列<strong>已经不是现在的判定</strong>：{{ dnsWhy }}。
          那批 IP 本身仍然有效（它们就是此刻缓存里的答案），要重判一次请再点「解析」。
        </p>
        <!-- 这一串存在的理由与「最近取过」同一条，而且更具体：污染是**间歇性**的，
             "十分钟前给 CN 段、刚才给真地址"这句话只在两次读数并排时才成立。
             一次的时候不摆——那一行与上面那一格说的是同一件事。 -->
        <details v-if="dnsHistory.length > 1" class="more">
          <summary>最近解析过 {{ dnsHistory.length }} 次</summary>
          <ul class="hist">
            <li v-for="h in dnsHistory" :key="h.at">
              <span class="mut">{{ agoText(h.at) }}</span>
              <span class="pill" :class="dnsHistTag(h).cls">{{ dnsHistTag(h).text }}</span>
              <span class="mono">{{ h.q }}</span>
              <template v-if="h.res">
                <span class="mono">{{ h.res.addrs.length ? h.res.addrs[0].addr : '一个地址都没有' }}</span>
                <span v-if="h.res.addrs.length > 1" class="mut">等 {{ h.res.addrs.length }} 个</span>
                <span class="mut">{{ policyText(h.res.ipPolicy) }}</span>
              </template>
              <span v-else class="why">{{ h.err }}</span>
            </li>
          </ul>
          <p class="mut">
            只留最近 {{ DNS_HISTORY }} 次，重启就没。这一串的价值是<strong>同一个名字前后两次答案不一样</strong>：
            污染是间歇性的，只看最后一次看不出来。「缓存」那几行是当时引擎真正在用那份，
            两档「重问」是人按出来的——所以它们分开标，不混成"查过"。
          </p>
        </details>
        <p class="hint">
          这是诊断三连的第三问：「查走向」答<b>按规则该怎么走</b>，「取一个真页面」答
          <b>它实际回什么</b>，这一格答中间那一问——<b>引擎此刻拿去判定的到底是哪批 IP</b>。
          判成代理的域名根本不解析（名字原样交给节点远端解），所以这一格只对
          <b>会落到 IP / GEOIP 规则</b>的名字有内容。归属码是照本机视角问出来的：
          同一个 CDN 域名从节点那头问会得到<b>另一个</b>归属，这正是
          <span class="mono">tunnel_resolve</span> 默认关着的原因（见 §6 那段实测）。
          两档手动重问都会往日志里记一行<b>「手动重问 …」</b>（写回了哪一批地址、问的是哪一家），
          普通「解析」不记——那一问引擎每秒都在做。
        </p>
      </section>

      <section class="card">
        <h2>内置规则集</h2>
        <dl class="kv">
          <dt>规则文件</dt>
          <dd class="mono">{{ status.rulesFile }}</dd>
          <dt>条数</dt>
          <dd>域名 {{ status.domainRules }} · IP {{ status.ipRules }}</dd>
          <dt>兜底</dt>
          <dd>
            <span class="pill" :class="policyClass(status.finalPolicy)">{{ policyText(status.finalPolicy) }}</span>
          </dd>
          <dt>GeoIP</dt>
          <dd>
            <span :class="status.geoipOk ? 'ok' : status.running && status.geoipPath ? 'warn' : 'mut'">
              {{ geoipText(status.geoipPath, status.geoipOk, status.running) }}
            </span>
            <span class="mono mut">{{ status.geoipPath }}</span>
          </dd>
          <template v-if="status.rulesSkipped.length">
            <dt>被跳过</dt>
            <dd class="warn">{{ status.rulesSkipped.join('、') }}</dd>
          </template>
        </dl>
      </section>

      <section class="card">
        <h2>
          规则文件（自动重载）
          <span class="count" :class="{ warn: !watch && !!watchError }">
            {{ watchHead }}
            <span v-if="watchStale" class="warn">· 读数已过期</span>
          </span>
        </h2>

        <p v-if="!watch" class="mut">
          {{ watchError ? `读不到监视状态：${watchError}` : '还没读到监视状态。' }}
        </p>
        <template v-else>
          <!-- 没在跑时不能说"0 个文件"：那读起来像"没有文件需要看"，
               而真实情况是"看了也不会生效"。两句话得各不相同。 -->
          <p v-if="!watch.watching" class="mut">
            代理没在跑，改规则文件不会自动生效；下次启动时才会按新文件加载。
            主文件路径写在上面的「内置规则集」里。
          </p>
          <template v-else>
            <p class="mut">
              每 {{ watch.intervalSec }} 秒看一轮，改动要连续两轮看到同一个状态才动手，
              所以改完最多等 {{ watch.intervalSec * 2 }} 秒出头生效。
              上一次生效：
              <strong v-if="watch.lastReload" class="mono">{{ watch.lastReload }}</strong>
              <span v-else>本次运行还没有过重载</span>。
            </p>
            <ul class="files">
              <li v-for="f in watch.files" :key="f.path">
                <span class="mono">{{ f.path }}</span>
                <span v-if="f.readable" class="mut">{{ formatBytes(f.size) }} · {{ f.modTime }}</span>
                <span v-else class="warn">读不到（文件此刻不在）</span>
              </li>
            </ul>
            <p class="mut">
              这里列的是引擎<strong>真的打开过</strong>的那些文件，含
              <span class="mono">#include</span> 进来的每一层——改这一列之外的文件不会触发重载。
            </p>
          </template>
        </template>
      </section>

      <section class="card">
        <h2>
          规则集订阅
          <span class="count" :class="{ warn: !subs && !!subsError }">
            {{ subsHead }}
            <span v-if="subsStale" class="warn">· 读数已过期</span>
          </span>
        </h2>

        <p v-if="!subs" class="mut">
          {{ subsError ? `读不到订阅状态：${subsError}` : '还没读到订阅状态。' }}
        </p>
        <template v-else-if="subs.configErr">
          <!-- 连配置都没读到，那"几条订阅"这种数字一个都不能报——
               报了就是在拿一份不存在的名册说话。 -->
          <p class="alert">读不到配置，这一栏的数字都不可信：{{ subs.configErr }}</p>
        </template>
        <template v-else-if="!subs.configured">
          <p class="mut">
            没配远程规则集。要用的话在 <span class="mono">config.yaml</span> 的
            <span class="mono">rule_providers:</span> 段里加一条（见 README §5.3）。
          </p>
        </template>
        <template v-else>
          <p v-if="!subs.running" class="mut">
            代理没在跑，这 {{ subs.configured }} 条订阅不会去拉；缓存还是磁盘上那份。
          </p>
          <p v-else class="mut">
            拉下来的内容先编译一遍才允许覆盖缓存；拉不到就用旧的那份，
            所以订阅断了分流不会走错路，只是规则停在上周那份上。
            <button type="button" class="btn" :disabled="pulling" @click="onPullNow">
              {{ pulling ? '拉取中…' : '立即拉取' }}
            </button>
          </p>

          <p v-if="pullError || pullReport" :class="pullBad ? 'alert' : 'notice'">
            {{ pullError ? `拉取失败：${pullError}` : pullText }}
          </p>
          <p v-if="subs.errors.length" class="alert">
            配置里 {{ subs.configured }} 条，实际在拉 {{ subs.items.length }} 条。
            这些条目在启动时被拒，从来没生效过：
            <span v-for="(e, i) in subs.errors" :key="i" class="mono err-line">{{ e }}</span>
          </p>

          <ul class="subs">
            <li v-for="x in subs.items" :key="x.name">
              <div class="head">
                <strong>{{ x.name }}</strong>
                <span class="mut">
                  每 {{ everyText(x.everySec) }} ·
                  {{ x.hasCache ? `缓存 ${formatBytes(x.size)}` : '缓存不在' }}
                </span>
              </div>
              <div class="state">
                <!-- 三件事各说各的，互不遮蔽：缓存不在、这次拉失败、上一次成功是几点。
                     最要命的是失败那一行——规则停在旧缓存上，此时"旧到什么时候"
                     恰恰是人最需要的那个数，不能因为报了失败就不说。 -->
                <span v-if="!x.hasCache" class="err">
                  这份缓存此刻不在磁盘上：它对应的那段规则现在没进引擎
                </span>
                <span v-if="x.fails > 0" class="err">
                  连着失败 {{ x.fails }} 次（最近一次 {{ formatAgo(x.lastAttemptMs) }}）：{{ x.lastErr }}
                </span>
                <span v-if="x.lastOkMs > 0" class="mut">上次拉于 {{ formatAgo(x.lastOkMs) }}</span>
                <template v-else-if="subs.running">
                  <span v-if="x.hasCache" class="mut">缓存是启动前补的那份，后台这一轮还没拉过</span>
                  <span v-else class="warn">这个进程还没成功拉过它</span>
                </template>
                <span v-if="subs.running && x.nextDueMs > 0" class="mut">· 下次 {{ formatAhead(x.nextDueMs) }}</span>
              </div>
              <div class="mut path mono">{{ x.path }}</div>
            </li>
          </ul>
          <p class="mut">
            这里只报订阅名与缓存路径，不报 URL：订阅地址常直接带鉴权 token，
            印出来就等于摊进截图里。
          </p>
        </template>
      </section>
    </div>
  </div>
</template>

<style scoped>
/* 规则表的筛选行。放在组件里而不是全局 style.css：
   连接表早就有自己的一套 .filter（scoped），全局同名规则会串过去改它的间距。 */
.filter {
  display: flex;
  gap: var(--sp-2);
  align-items: center;
  margin: var(--sp-2) 0 0;
}
.filter input {
  flex: 1;
  min-width: 0;
}
/* 拦截名单做成一枚枚 chip：域名和它的删除动作是一体的，
   原来那种"文字靠左、删除靠最右"的网格，名单一短就满屏都是飘着的红字。 */
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  max-height: 220px;
  overflow: auto;
  margin-top: var(--sp-1);
}

.chip {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  padding: 3px 4px 3px 10px;
  border: 1px solid var(--warn-line);
  border-radius: var(--r-pill);
  background: var(--warn-bg);
  color: var(--warn-bright);
  font-size: var(--fs-caption);
}

.chip-x {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 17px;
  height: 17px;
  padding: 0;
  border: 0;
  border-radius: 50%;
  background: rgba(251, 191, 36, 0.16);
  color: var(--warn-bright);
  cursor: pointer;
  transition: background var(--dur-fast) var(--ease), transform var(--dur-fast) var(--ease);
}

.chip-x svg {
  width: 8px;
  height: 8px;
}

.chip-x:hover:not(:disabled) {
  background: rgba(251, 191, 36, 0.34);
}

.chip-x:active:not(:disabled) {
  transform: scale(0.88);
}

.chip-x:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}

.add .value {
  flex: 1 1 200px;
}

/* 最近拦截留痕：一行一条，文字在左、动作在右且垂直居中。 */
.hits {
  margin-top: var(--sp-4);
  padding-top: var(--sp-3);
  border-top: 1px solid var(--line);
}

.hits h3 {
  margin: 0 0 var(--sp-2);
  font-size: var(--fs-caption);
  font-weight: 500;
  color: var(--muted);
}

.hits ul {
  list-style: none;
  margin: 0;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: var(--sp-2);
  max-height: 220px;
  overflow: auto;
}

.hit {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  min-width: 0;
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: var(--r-sm);
  background: rgba(0, 0, 0, 0.2);
}

.hit-main {
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
  flex: 1 1 auto;
}

.hits li .btn {
  flex: 0 0 auto;
}

.line1 {
  display: flex;
  justify-content: space-between;
  gap: var(--sp-2);
  min-width: 0;
  font-size: var(--fs-sm);
}

.rule {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: var(--fs-micro);
}

.probe {
  flex: 1 1 260px;
}

.probe-out {
  display: inline-flex;
  align-items: baseline;
  gap: 6px;
  font-size: var(--fs-sm);
}

/* 「最近取过」那一列：一行一次尝试。
   必须 flex-wrap + overflow-wrap——一长串 URL 在 flex 里的 min-content 是"整个 token"，
   不写这两条就会把 558px 宽的那一栏撑破（§10.4 记过同一类坑，中文那边是"一个字"，
   英文 token 这边是"一整串"，两头都得防）。 */
.hist {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin: 6px 0 0;
  padding: 0;
  list-style: none;
  font-size: var(--fs-sm);
}

.hist li {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 4px 8px;
}

.hist .mono {
  overflow-wrap: anywhere;
}

.hist .why {
  color: var(--err-bright);
  overflow-wrap: anywhere;
}

.row-act {
  display: flex;
  justify-content: flex-end;
  gap: 2px;
}

/* 序：这一列的数字就是命中优先级。数字和移动按钮放同一格，
   是因为"它排第几"与"挪一挪"是同一件事的两半，拆开会让人找不到入口。 */
.ord {
  white-space: nowrap;
}

.ord > .pos {
  display: inline-block;
  min-width: 20px;
  margin-right: var(--sp-2);
  color: var(--muted);
  font-family: var(--mono);
  font-size: var(--fs-caption);
  font-variant-numeric: tabular-nums;
}

.ord-act {
  display: inline-flex;
  gap: 2px;
  vertical-align: middle;
}

.ord-act > .btn {
  min-width: 26px;
  padding: 0 6px;
}

/* 这一盒里面是"一句结论 + 分类 + 逐条"三段，只有这里真的需要 flex：竖着排。
   （`.alert` 本身从 flex 改回普通块，就是因为横着排会把一句话拆成几栏——
   中文在 flex 里的 min-content 是一个字，900px 下第一栏被挤成"这份名单/里有 2 条/"
   那种一字一行，整盒高到 229px。2026-10-20 截图为证。） */
.dead-box {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
}

.dead-box p {
  margin: 0;
}

.pin-select {
  min-width: 108px;
}

/* 停用的那一行：整行压暗一档，再配一个明确的"已停用"标记。
   只有暗没有字是不够的——深色主题下 60% 亮度很容易被看成"就是这么个颜色"。 */
tbody tr.off td {
  opacity: 0.55;
}

tbody tr.off td.mono,
tbody tr.off td .mono {
  text-decoration: line-through;
}

.off-pill {
  margin-left: var(--sp-1);
  border-color: var(--muted);
  background: transparent;
  color: var(--muted);
}

/* .window-row 那一组已挪到全局 style.css：日志流也用窗口渲染，两处不能长两个样。 */

.pin-tag {
  margin-left: var(--sp-1);
  padding: 1px 6px;
  border: 1px solid var(--accent-line);
  border-radius: var(--r-pill);
  background: var(--accent-bg);
  color: var(--accent-bright);
  font-family: var(--mono);
  font-size: var(--fs-micro);
  white-space: nowrap;
}

/* 钉的节点已经不在配置里：这一格用危险色，而不是和好的钉住项长得一样。
   危险色不是"提醒注意"，是"这一格说的事情不成立"。 */
.pin-tag.broken {
  border-color: var(--err-line);
  background: var(--err-bg);
  color: var(--err-bright);
  text-decoration: line-through;
}

/* 表里那个就地换节点的下拉：尺寸要贴着旁边那颗 pill，不然一行里
   会有一半高度是被控件撑出来的。坏掉的那一条同样标红。 */
.pin-select.inline {
  margin-left: var(--sp-1);
  padding: 1px 4px;
  border: 1px solid var(--accent-line);
  border-radius: var(--r-pill);
  background: var(--accent-bg);
  color: var(--accent-bright);
  font-family: var(--mono);
  font-size: var(--fs-micro);
  min-width: 0;
  max-width: 168px;
}

.pin-select.inline.broken {
  border-color: var(--err-line);
  background: var(--err-bg);
  color: var(--err-bright);
}

.batch-toggle {
  margin-top: var(--sp-2);
  align-items: center;
}

.batch {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
  margin: var(--sp-2) 0 var(--sp-3);
}

.batch-text {
  width: 100%;
  min-height: 110px;
  padding: var(--sp-2) var(--sp-3);
  border: 1px solid var(--line-2);
  border-radius: var(--r-sm);
  background: var(--surface-2);
  color: var(--fg);
  font-family: var(--mono);
  font-size: var(--fs-sm);
  line-height: 1.5;
  resize: vertical;
}

.batch-out {
  display: flex;
  flex-direction: column;
  gap: var(--sp-1);
  padding: var(--sp-2) var(--sp-3);
  border: 1px solid var(--line);
  border-radius: var(--r-sm);
  background: var(--surface-2);
  font-size: var(--fs-sm);
}

.batch-out p {
  margin: 0;
}

.reject,
.dead {
  margin: var(--sp-1) 0 0;
  padding-left: var(--sp-5);
}

/* 分类那一小段：紧跟在结论句后面，用点列而不是整段文字，
   读的人要的是"哪几类、各几条"，不是又一句散文。 */
.kinds {
  margin: var(--sp-1) 0 0;
  padding-left: var(--sp-5);
  list-style: disc;
}

.kinds li {
  margin: 2px 0;
  font-size: var(--fs-sm);
}

/* 用户写的那一行与后端给的理由之间要断得开：两段都是中文，
   挤在一起会读成一句话，而前半段是要拿去文件里搜的字面串。 */
.dead li .mono {
  margin-right: var(--sp-2);
}

.reject li,
.dead li {
  margin: 2px 0;
  font-size: var(--fs-sm);
}

.mut {
  color: var(--muted);
}
</style>
