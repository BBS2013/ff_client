<script setup lang="ts">
// ConnectionsTable 实时连接表。上半是活跃连接，下半是已结束连接，
// 两者的顺序都由后端排好（活跃按流量降序、历史按结束时间倒序），前端不再重排。
import { computed, nextTick, ref, watch } from 'vue'
import type { ConnView, TrafficSnapshot } from '../types'
import { formatBytes, formatDuration, trimHost } from '../format'

const props = defineProps<{
  traffic: TrafficSnapshot
  busy: string
  /**
   * 从总览那一格"拨不通 N"跳过来时带着的档：落到这一页就直接筛好。
   * 只当初始值用，用完立刻 emit 让父层清掉——留着它，用户手动切走档位
   * 之后会被下一次轮询拽回来。
   */
  seedWay?: string
}>()

const emit = defineEmits<{
  (e: 'reset'): void
  (e: 'rule', host: string): void
  (e: 'fetch', url: string): void
  (e: 'dns', host: string): void
  (e: 'seededWay'): void
}>()


/**
 * 把这一行的目标拼成一个能直接拿去「取一个真页面」的 URL。
 *
 * 用的是 `host` + `port` 两个字段，不去解析 `target` 那一串：
 * `target` 是后端 `net.JoinHostPort` 的产物（IPv6 会带方括号），
 * 而字符串里再认一次"哪个冒号是端口分隔符"是给自己找错——
 * `fe80::1` 这种裸 IPv6 里有冒号却没端口，照冒号切会把 "1" 当成端口。
 * 第一版就是这么写的，实测把 `10.0.0.5:8080` 拼成了 `https://10.0.0.5/`。
 *
 * 端口决定协议——443 或压根没写端口就 https，其余按 http。
 * 这一句**是猜的**，但猜出来的东西摆在输入框里看得见、能改，
 * 不是藏在后端里的默认值。按钮只挂在失败的那几行上：
 * 一条正常结束的连接没什么好取的，而"这条为什么不通"正是那一行要问的第二个问题。
 */
function fetchURL(c: ConnView): string {
  const port = c.port.trim()
  let host = c.host.trim()
  if (!host) {
    return ''
  }
  if (host.includes(':') && !host.includes(']')) {
    host = `[${host}]`
  }
  const secure = port === '' || port === '443'
  const target = port && port !== (secure ? '443' : '80') ? `${host}:${port}` : host
  return `${secure ? 'https' : 'http'}://${target}/`
}

/**
 * 这一条能不能"拿去加一条域名规则"。
 *
 * 连接的目标可能是 IP 字面量（直连一个内网地址、或假 IP 没还原成域名的那一类），
 * 给它建 DOMAIN-SUFFIX 规则是建不成的：normalizeHost 之后它匹配不上任何查询，
 * 于是用户得到一条看起来写好了、其实永远不会命中的规则。
 * 所以 IP 那一类干脆不给这个按钮，而不是给了再让后端报错。
 */
/**
 * 活跃表里那一片「加规则」按钮的停靠点计数，给表前的跳过链接用。
 * 这张表原本一个可聚焦元素都没有（行全是文本），加了行内按钮之后
 * 300 条活跃连接就是 300 个 Tab 停靠点，而下面还有「最近结束」整张表。
 * 数的是 DOM 里真的能聚焦的东西，不按行数估：IP 字面量那些行没有这个按钮。
 */
// 只有值得跳的时候才给这条链接。4 个控件也摆一条"跳过"，
// 那是把一个小表说成一个大障碍，反而添乱。
const SKIP_THRESHOLD = 20
const activeWrap = ref<HTMLElement | null>(null)
const activeControlCount = ref(0)
function recountActiveControls(): void {
  activeControlCount.value =
    activeWrap.value?.querySelectorAll('a[href], button, input, select, textarea').length ?? 0
}
watch([() => props.traffic.active, () => props.traffic.activeCount], () => void nextTick(recountActiveControls), {
  immediate: true
})

function focusHistory(e: Event): void {
  e.preventDefault()
  const el = document.getElementById('wps-history-section')
  el?.scrollIntoView({ block: 'start' })
  el?.focus({ preventScroll: true })
}

function ruleSeedable(c: ConnView): boolean {
  const h = trimHost(c.host)
  if (!h || h.includes('/')) {
    return false
  }
  // 含冒号的是 IPv6；纯数字加点的是 IPv4。两者都不是域名。
  if (h.includes(':')) {
    return false
  }
  return !/^[0-9.]+$/.test(h)
}

// 活跃连接的时长用本地时钟自己算：后端每秒才采样一次，
// 直接显示它会让秒数原地卡住，本地算反而更顺。
function liveDuration(c: ConnView): number {
  return Math.max(0, Date.now() - c.start)
}

function target(c: ConnView): string {
  if (c.target) {
    return c.target
  }
  return c.port ? `${trimHost(c.host)}:${c.port}` : trimHost(c.host)
}

/**
 * 连接的走向档位。
 *
 * 这里原本假定「出站要么是节点名要么是 DIRECT」。加了拦截之后这个假定不成立了：
 * REJECT 落到 else 里就显示成「走代理」，而用户点进这一页恰恰是为了搞清楚
 * "这个网站为什么打不开"——把被拦的连接标成走代理，等于把他往反方向引。
 *
 * 'failed' 是同一个坑的第二次：拨不通的连接带着 `outbound=PROXY`（判定已经做完了，
 * 只是没拨通），不先挡一层它就会显示成「走代理」——而那正是用户要找的那一行。
 */
type Way = 'proxy' | 'direct' | 'blocked' | 'failed'

function wayOf(c: ConnView): Way {
  if (c.err !== '') {
    return 'failed'
  }
  if (c.outbound === 'REJECT') {
    return 'blocked'
  }
  return c.outbound === 'DIRECT' ? 'direct' : 'proxy'
}

const WAY_TEXT: Record<Way, string> = { proxy: '走代理', direct: '直连', blocked: '已拦截', failed: '拨不通' }
const WAY_CLASS: Record<Way, string> = { proxy: 'proxy', direct: 'direct', blocked: 'warn', failed: 'err' }

/**
 * 走向那一格里要不要再写"实际走的哪个节点"。
 *
 * 只有走代理那一档有意义：直连的 node 就是 DIRECT、被拦的就是 REJECT，
 * 与上面那颗 pill 是同一句话说两遍。而 PROXY 这一档，outbound 只说"走了代理"，
 * 节点会自动切换、规则也能钉节点，所以"走的是哪一个"是另一个事实——
 * 上面那张「各节点用量」按的就是它，两张表必须说同一个字符串。
 */
function nodeText(c: ConnView): string {
  return wayOf(c) === 'proxy' ? c.node : ''
}

// 命中规则的可读化：GEOIP,CN,DIRECT 一眼能看懂，FINAL 就是兜底。
function matchedText(c: ConnView): string {
  return c.matched || '（未记录）'
}

/**
 * 过滤：一张表能装几百条，"刚才那个域名"和"被拦的那批"都得能捞出来。
 * 走向与关键字共用一份，活跃与历史两张表同时受它约束——
 * 分开过滤会出现"活跃里筛了、历史没筛"这种自相矛盾的屏。
 */
const kw = ref('')
const way = ref<Way | 'all'>('all')
// 「只看走某个节点的连接」不并进 kw 那个文本框：节点名当子串去匹配整行，
// 会把 tokyo.example.com 这种恰好带同名域名的直连也捞进来——
// 用户点的是「各节点用量」那一行，他要的是**这个节点**名下的连接，一个不多。
const onlyNode = ref('')

function matches(c: ConnView): boolean {
  if (way.value !== 'all' && wayOf(c) !== way.value) {
    return false
  }
  if (onlyNode.value !== '' && c.node !== onlyNode.value) {
    return false
  }
  const k = kw.value.trim().toLowerCase()
  if (!k) {
    return true
  }
  return `${target(c)} ${c.host} ${c.client} ${c.inbound} ${c.matched} ${c.outbound} ${c.node} ${c.iface} ${c.err}`
    .toLowerCase()
    .includes(k)
}

const rows = computed(() => props.traffic.active.filter(matches))
const historyRows = computed(() => props.traffic.history.filter(matches))

/**
 * 「最近结束」那张表一次只画前 120 行。这是量出来的决定，不是审美。
 *
 * 演示里按生产稳态灌满（300 活跃 + 500 已结束，后者就是 `internal/ui/app.go`
 * 的 historyCap），切到这一页的耗时从默认那几条的 24~34ms 涨到 118~202ms；
 * 多出来的那 ~90ms 全是画行。而**稳态每秒的补帧是干净的**（10 秒 600 帧、
 * 0 个 long task、p95 17.3ms），所以代价只在"切进来那一下"——正是要治的那一下。
 *
 * 尾部那些行几乎没人逐条翻：真要找一条具体的连接用的是上面的筛选框，
 * 一筛就只剩几条，窗口不会挡路（窗口取的是**筛完**之后的前 120 条）。
 *
 * 活跃那一张**不窗口**：它此刻在跑的就是都要看见，而且它的条数由真实并发决定，
 * 不是一个人造的 500 环。
 */
const HIST_WINDOW = 120
const histWindow = ref(HIST_WINDOW)
const shownHistory = computed(() => historyRows.value.slice(0, histWindow.value))
// 不写成 `historyRows.length - shownHistory.value`：那会在 shownHistory
// 自己的初始化里引用它，TS 只会给一个隐式 any（而且式子本身更绕）。
const hiddenHistory = computed(() => Math.max(0, historyRows.value.length - histWindow.value))

// 筛选条件一变就把窗口收回去。留着"上一次点过全部画出"的状态，
// 下一次进这一页又要整表重建，窗口等于白加。
watch([kw, way, onlyNode], () => {
  histWindow.value = HIST_WINDOW
})

// 网卡那一列只在真的有连接走了某张卡时才出现。
// 没开分流时每行的 iface 都是空串，挂一列全空的东西只是噪音；
// 而这一页在分流开启时才是它真正要回答的问题：「这张卡在干什么」。
const showIface = computed(() => hasIface(props.traffic.active))
const showHistoryIface = computed(() => hasIface(props.traffic.history))

function hasIface(list: ConnView[]): boolean {
  return list.some((c) => c.iface !== '')
}

// 各档的条数直接标在按钮上：这一页最常见的动作就是"看看拦了多少"，
// 不该需要先点进去才数得出来。
const tally = computed(() => {
  const t = { proxy: 0, direct: 0, blocked: 0, failed: 0 }
  for (const c of [...props.traffic.active, ...props.traffic.history]) {
    t[wayOf(c)]++
  }
  return t
})

const filtering = computed(() => kw.value.trim() !== '' || way.value !== 'all' || onlyNode.value !== '')

function resetFilter(): void {
  kw.value = ''
  way.value = 'all'
  onlyNode.value = ''
}

/**
 * 上面「各节点用量」那一行的入口：点一行 = 只看这个节点名下的连接。
 * 再点一次取消。它不清掉文本框里已有的关键字——两个条件叠着是"交集"，
 * 偷偷清掉用户打进去的东西才是更难解释的屏。
 */
function filterByNode(node: string): void {
  onlyNode.value = onlyNode.value === node ? '' : node
}

/**
 * 从总览那一格跳过来时带着的档。
 *
 * 这个 watch 必须排在 way / onlyNode 这些状态**之后**：写在它们上面时
 * `immediate: true` 会在 setup 里就访问还没初始化的 const，
 * 于是种子静默失效——视图切过去了、筛选没套上，而页面看上去一切正常。
 * （就是这么来的：第一次实现时它放在文件顶部，测出来"点了没筛"。）
 */
watch(
  () => props.seedWay,
  (w) => {
    if (!w) {
      return
    }
    way.value = w as Way
    emit('seededWay')
  },
  // immediate：这一页是 v-if 挂出来的，挂载那一刻种子已经在 props 上了。
  { immediate: true }
)

defineExpose({ filterByNode })
</script>

<template>
  <div class="wrap">
    <div class="filter">
      <input
        v-model="kw"
        class="kw"
        placeholder="按域名 / 客户端 / 命中规则过滤"
        aria-label="连接过滤"
        data-focus-shortcut
      />
      <div class="seg" role="group" aria-label="按走向过滤">
        <button type="button" :class="{ on: way === 'all' }" @click="way = 'all'">
          全部 {{ traffic.activeCount + traffic.history.length }}
        </button>
        <button type="button" :class="{ on: way === 'proxy' }" @click="way = 'proxy'">
          走代理 {{ tally.proxy }}
        </button>
        <button type="button" :class="{ on: way === 'direct' }" @click="way = 'direct'">
          直连 {{ tally.direct }}
        </button>
        <button type="button" :class="{ on: way === 'blocked' }" @click="way = 'blocked'">
          拦截 {{ tally.blocked }}
        </button>
        <button type="button" :class="{ on: way === 'failed' }" @click="way = 'failed'">
          拨不通 {{ tally.failed }}
        </button>
      </div>
      <button
        v-if="onlyNode !== ''"
        type="button"
        class="btn sm ghost"
        title="取消「只看这个节点」"
        @click="onlyNode = ''"
      >
        只看节点 {{ onlyNode }}（取消）
      </button>
      <button v-if="filtering" type="button" class="btn sm ghost" @click="resetFilter">清除过滤</button>
    </div>

    <!-- 表前一条跳过链接：这张表每行一个「加规则」，几百条连接就是几百个 Tab 停靠点，
         而下面还有整张「最近结束」。条数直接印出来，让人按之前就知道省掉多少下。 -->
    <a
      v-if="activeControlCount > SKIP_THRESHOLD"
      class="skip-link"
      href="#wps-history-section"
      @click="focusHistory"
    >
      跳过活跃连接表（{{ activeControlCount }} 个控件），到「最近结束」
    </a>

    <section class="card">
      <h2>
        活跃连接
        <span class="count">
          {{ filtering ? `显示 ${rows.length} / ${traffic.activeCount}` : traffic.activeCount }}
        </span>
      </h2>
      <div ref="activeWrap" class="table-wrap">
        <table class="grid-table">
          <thead>
            <tr>
              <th>客户端</th>
              <th>入站</th>
              <th>目标</th>
              <th>命中规则</th>
              <th>走向</th>
              <th v-if="showIface">网卡</th>
              <th class="num">上行</th>
              <th class="num">下行</th>
              <th class="num">时长</th>
              <th class="num">规则</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in rows" :key="c.id">
              <td class="mono">{{ c.client }}</td>
              <td><span class="pill">{{ c.inbound }}</span></td>
              <td class="mono">{{ target(c) }}</td>
              <td class="mut">{{ matchedText(c) }}</td>
              <td>
                <span class="pill" :class="WAY_CLASS[wayOf(c)]">{{ WAY_TEXT[wayOf(c)] }}</span>
                <span v-if="nodeText(c)" class="mono node-name">{{ nodeText(c) }}</span>
                <!-- 失败的原因整句挂在 title 上：那一格里塞不下 240 个字符，
                     而"是什么错"恰恰是人点开这一行要看的第一个东西。 -->
                <span v-if="c.err" class="mono err-text" :title="c.err">{{ c.err }}</span>
              </td>
              <td v-if="showIface" class="mono">{{ c.iface }}</td>
              <td class="num">{{ formatBytes(c.up) }}</td>
              <td class="num">{{ formatBytes(c.down) }}</td>
              <td class="num">{{ formatDuration(liveDuration(c)) }}</td>
              <td class="num">
                <!-- 看见就能改：这一页是"谁在怎么走"，规则页是"该怎么走"，
                     中间原来隔着"复制域名 → 切页 → 粘进表单"三步，
                     而人会直接在表里读那个域名。按钮就在读到的地方。
                     IP 字面量那一类不给这个按钮（见 ruleSeedable）：
                     给它建域名规则会得到一条"看着写好了、其实永远不命中"的规则。 -->
                <button
                  v-if="ruleSeedable(c)"
                  type="button"
                  class="btn sm ghost"
                  :title="`用 ${trimHost(c.host)} 去规则页填一条`"
                  :aria-label="`为 ${trimHost(c.host)} 新建一条域名规则`"
                  @click="emit('rule', trimHost(c.host))"
                >
                  加规则
                </button>
                <!-- 第二个动作只给失败的那几行：拨不通的时候人真正想问的是
                     "那它到底回什么"，而这一问现在有一格能答（规则页「取一个真页面」）。
                     带过去的是一个填好的网址，不自动跑——协议那格是照端口猜的，
                     让人看一眼再按回车，比替他跑错一次强。 -->
                <button
                  v-if="c.err"
                  type="button"
                  class="btn sm ghost"
                  :title="`去规则页真取一次 ${c.host}`"
                  :aria-label="`取一次 ${c.host} 这个页面`"
                  @click="emit('fetch', fetchURL(c))"
                >
                  取页面
                </button>
                <!-- 第三个动作同样只给失败行：拨不通的时候除了"它回什么"，
                     还有一句"引擎是照着哪几个 IP 决定要直连的"。
                     三个按钮是一套完整问诊，缺一个就得让人自己复制域名去翻页。 -->
                <button
                  v-if="c.err"
                  type="button"
                  class="btn sm ghost"
                  :title="`去规则页看 ${trimHost(c.host)} 解析成什么`"
                  :aria-label="`看 ${trimHost(c.host)} 的解析结果`"
                  @click="emit('dns', trimHost(c.host))"
                >
                  看解析
                </button>
              </td>
            </tr>
            <tr v-if="rows.length === 0">
              <td :colspan="showIface ? 10 : 9" class="mut">
                {{
                  filtering && traffic.activeCount > 0
                    ? `过滤后没有匹配的活跃连接（一共 ${traffic.activeCount} 条）。`
                    : '当前没有活跃连接。'
                }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>

    <section id="wps-history-section" class="card skip-target" tabindex="-1">
      <h2>
        最近结束
        <span class="count">
          {{
            filtering
              ? `显示 ${shownHistory.length} / 累计 ${traffic.totalConns} 条`
              : `累计 ${traffic.totalConns} 条`
          }}
        </span>
        <span class="act">
          <button type="button" class="btn sm ghost" :disabled="busy !== ''" @click="emit('reset')">
            清空统计
          </button>
        </span>
      </h2>
      <div class="table-wrap">
        <table class="grid-table">
          <thead>
            <tr>
              <th>目标</th>
              <th>入站</th>
              <th>命中规则</th>
              <th>走向</th>
              <th v-if="showHistoryIface">网卡</th>
              <th class="num">上行</th>
              <th class="num">下行</th>
              <th class="num">时长</th>
              <th class="num">规则</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="c in shownHistory" :key="c.id">
              <td class="mono">{{ target(c) }}</td>
              <td><span class="pill">{{ c.inbound }}</span></td>
              <td class="mut">{{ matchedText(c) }}</td>
              <td>
                <span class="pill" :class="WAY_CLASS[wayOf(c)]">{{ WAY_TEXT[wayOf(c)] }}</span>
                <span v-if="nodeText(c)" class="mono node-name">{{ nodeText(c) }}</span>
                <!-- 失败的原因整句挂在 title 上：那一格里塞不下 240 个字符，
                     而"是什么错"恰恰是人点开这一行要看的第一个东西。 -->
                <span v-if="c.err" class="mono err-text" :title="c.err">{{ c.err }}</span>
              </td>
              <td v-if="showHistoryIface" class="mono">{{ c.iface }}</td>
              <td class="num">{{ formatBytes(c.up) }}</td>
              <td class="num">{{ formatBytes(c.down) }}</td>
              <td class="num">{{ formatDuration(c.duration) }}</td>
              <td class="num">
                <!-- 看见就能改：这一页是"谁在怎么走"，规则页是"该怎么走"，
                     中间原来隔着"复制域名 → 切页 → 粘进表单"三步，
                     而人会直接在表里读那个域名。按钮就在读到的地方。
                     IP 字面量那一类不给这个按钮（见 ruleSeedable）：
                     给它建域名规则会得到一条"看着写好了、其实永远不命中"的规则。 -->
                <button
                  v-if="ruleSeedable(c)"
                  type="button"
                  class="btn sm ghost"
                  :title="`用 ${trimHost(c.host)} 去规则页填一条`"
                  :aria-label="`为 ${trimHost(c.host)} 新建一条域名规则`"
                  @click="emit('rule', trimHost(c.host))"
                >
                  加规则
                </button>
                <!-- 第二个动作只给失败的那几行：拨不通的时候人真正想问的是
                     "那它到底回什么"，而这一问现在有一格能答（规则页「取一个真页面」）。
                     带过去的是一个填好的网址，不自动跑——协议那格是照端口猜的，
                     让人看一眼再按回车，比替他跑错一次强。 -->
                <button
                  v-if="c.err"
                  type="button"
                  class="btn sm ghost"
                  :title="`去规则页真取一次 ${c.host}`"
                  :aria-label="`取一次 ${c.host} 这个页面`"
                  @click="emit('fetch', fetchURL(c))"
                >
                  取页面
                </button>
                <!-- 第三个动作同样只给失败行：拨不通的时候除了"它回什么"，
                     还有一句"引擎是照着哪几个 IP 决定要直连的"。
                     三个按钮是一套完整问诊，缺一个就得让人自己复制域名去翻页。 -->
                <button
                  v-if="c.err"
                  type="button"
                  class="btn sm ghost"
                  :title="`去规则页看 ${trimHost(c.host)} 解析成什么`"
                  :aria-label="`看 ${trimHost(c.host)} 的解析结果`"
                  @click="emit('dns', trimHost(c.host))"
                >
                  看解析
                </button>
              </td>
            </tr>
            <tr v-if="historyRows.length === 0">
              <td :colspan="showHistoryIface ? 9 : 8" class="mut">
                {{
                  filtering && traffic.history.length > 0
                    ? `过滤后没有匹配的已结束连接（一共 ${traffic.history.length} 条）。`
                    : '还没有已结束的连接。'
                }}
              </td>
            </tr>
            <!-- 窗口那一行：说清"没画"不等于"没有"，并把两个出口给出来。
                 与日志页那一栏同一个写法（§9.3），别让人以为尾巴上的连接消失了。 -->
            <tr v-if="hiddenHistory > 0" class="window-row">
              <td :colspan="showHistoryIface ? 9 : 8">
                只画了最近 {{ shownHistory.length }} 条，下面还有
                <strong>{{ hiddenHistory }}</strong> 条没画（它们仍在统计与「各节点用量」里）。
                <button type="button" class="btn sm ghost" @click="histWindow += HIST_WINDOW">
                  再多画 {{ Math.min(HIST_WINDOW, hiddenHistory) }} 条
                </button>
                <button type="button" class="btn sm ghost" @click="histWindow = historyRows.length">
                  全部画出
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<style scoped>
.wrap {
  display: flex;
  flex-direction: column;
  gap: var(--sp-3);
}

/* 过滤条：不装进卡片，两张表共用一条，所以放在它们上面。 */
.filter {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.filter .kw {
  flex: 1 1 220px;
  min-width: 0;
}

.mut {
  color: var(--muted);
}

/* 失败原因：只放得下一小截，整句在 title 里。它排在走向那颗 pill 后面，
   所以字号与节点名同一档，颜色跟着 .pill.err 走。 */
.err-text {
  display: inline-block;
  max-width: 190px;
  margin-left: 6px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  vertical-align: bottom;
  font-size: var(--fs-caption);
  color: var(--err-bright);
}

/* 节点名跟在走向那颗 pill 后面：它不是另一个状态，而是同一个状态的更具体的答案，
   所以字号和颜色都比 pill 低一档，不让一格里摆出两个并列的强调。
   nowrap 是必需的——节点名里带连字符（demo-us）时，列一挤就在连字符处断成两行，
   一行连接被撑成两行高，整张表的密度掉一半。 */
.node-name {
  margin-left: 6px;
  font-size: var(--fs-caption);
  color: var(--muted);
  white-space: nowrap;
}
</style>
