<script setup lang="ts">
import { computed, nextTick, ref, watch as vueWatch } from 'vue'
import type { Ref } from 'vue'
import type { BlockView, DNSProbe, Status, UserRule } from '../types'
import { errorText, fetchPage, probeDNS, probeHost } from '../api'
import { formatBytes, formatDuration, modeText, policyClass, policyText } from '../format'
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

type PageIO = {
  busy: Ref<string>
  notice: Ref<string>
  failure: Ref<string>
  load: () => Promise<void>
  run: (key: string, fn: () => Promise<void>, done: string) => Promise<boolean>
}
const props = defineProps<{
  page: PageIO
  status: Status
  rules: UserRule[]
  block: BlockView | null
  fetchSeed?: string
  dnsSeed?: string
}>()

const emit = defineEmits<{
  (e: 'seededFetch'): void
  (e: 'seededDNS'): void
}>()

const busy = props.page.busy
const failure = props.page.failure
const rules = computed(() => props.rules)
const block = computed(() => props.block)

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
</script>

<template>
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
</template>
