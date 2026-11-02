<script setup lang="ts">
// Dashboard 是「一屏看完」的总览页：实时数字、速率曲线、出站隧道、
// 入站与规则、两个全局开关、流量走向。
//
// 它不发任何请求，也不拥有任何状态——数据从 App.vue 的轮询里来，
// 操作以 emit 交回去，这样「正在执行哪个操作」只需要在一处维护。
import { computed } from 'vue'
import Amount from './Amount.vue'
import RateChart from './RateChart.vue'
import type { Pending, ProfileTest, Status, SysProxyLedger, SystemProxyStatus, TrafficSnapshot } from '../types'
import { formatAgo, formatBytes, formatClock, formatRate, geoipText, policyClass, policyText, recentlyFailed, TUN_PHASE_TEXT, tunPhase } from '../format'

const props = defineProps<{
  status: Status
  traffic: TrafficSnapshot
  sys: SystemProxyStatus | null
  /** 系统代理记账那一行；null 只在第一批读数到来之前出现，那时写"读取中"而不是"没问题"。 */
  ledger: SysProxyLedger | null
  /**
   * 当前节点最近一次测速的读数（跨页留着那份）。null 是"这个节点还没测过"，
   * 不是"测过且没问题"——两者必须分开，否则一行空白就被读成一切正常。
   */
  lastTest: (ProfileTest & { ago: string }) | null
  busy: string
  pending: Pending
  /** 读数停止更新中：那两格写的是"实时"，停更时必须变空，不能拿最后一次采样冒充现在。 */
  stale: boolean
}>()

const emit = defineEmits<{
  (e: 'restart'): void
  (e: 'reload'): void
  /** 应急出口：解除代理（收回桌面指针 + 关端口），让机器立刻回到直连。 */
  (e: 'unbind'): void
  /** 解绑之后回到接管状态。 */
  (e: 'rebind'): void
  (e: 'tun', enable: boolean): void
  (e: 'sysproxy', enable: boolean): void
  (e: 'ifaceSplit', enable: boolean): void
  (e: 'ifaceCards', direct: string, proxy: string): void
  (e: 'goto', view: string): void
  /** 那一格被点了：去流量页并直接筛「拨不通」。 */
  (e: 'showFailures'): void
}>()

const idle = computed(() => props.busy !== '')

/**
 * 最近一次拨不通的时刻。这一格要回答的是"还在坏吗"，而总数回答不了：
 * 真数据上见过一屏 236 条拨不通、全是同一批域名——那是刚才八分钟里的事，
 * 还是昨天早上留下的，只看那个数分不出来。
 * 失败行的 duration 是 0（压根没建起来），所以它的开始时刻就是那一次的时刻。
 */
const lastFailureAt = computed(() => {
  let t = 0
  for (const c of props.traffic.active) {
    if (c.err !== '' && c.start > t) {
      t = c.start
    }
  }
  for (const c of props.traffic.history) {
    if (c.err !== '' && c.start > t) {
      t = c.start
    }
  }
  return t
})

const lastFailureText = computed(() => {
  if (props.stale) {
    return '读数停更中'
  }
  if (lastFailureAt.value > 0) {
    return `最近 ${formatAgo(lastFailureAt.value)}`
  }
  // 总数不是零却找不到任何一条失败记录，只有一种解释：那 500 条历史已经把它挤掉了。
  // 这时候说"本次还没有"就是假话——计数是专门为了活过环形缓冲才单独存的。
  return props.traffic.totalFailed > 0 ? '最近一次已被历史缓冲挤出' : '本次还没有'
})
const tun = computed(() => props.status.tun)
/**
 * 「现在还在解析失败吗」——用最近一次失败的时刻判，不用累计数（理由见 recentlyFailed）。
 * 窗口 2 分钟：够长，不会跟着轮询闪；够短，上游真挂着的时候它一定亮着。
 */
const dnsFailing = computed(
  () => tun.value.running && recentlyFailed(tun.value.dnsFailedAt, 120_000, Date.now()),
)
const sys = computed(() => props.sys)
const ifaceSplit = computed(() => props.status.ifaceSplit)
const phase = computed(() => tunPhase(props.status.tun, props.pending.tun))
/** knob 跟着"用户要去的值"走，别等后端那几秒：拆 TUN 是真的慢。 */
const tunChecked = computed(() => props.pending.tun ?? props.status.tun.running)
const sysChecked = computed(() => props.pending.sysproxy ?? props.sys?.enabled ?? false)
const splitChecked = computed(
  () => props.pending.ifaceSplit ?? ifaceSplit.value?.enabled ?? false
)
// 记账那一句话完全来自 Go（五种状态各有措辞，那边有单测）；这里只管要不要为它提高音量。
const ledgerText = computed(() => (props.ledger ? props.ledger.text : '记账：读取中…'))

/**
 * 总览页这一行只回答一个问题：**现在这条隧道到底能不能取回页面**。
 *
 * 「已建链」与那个 ms 数都只到电路那一层。兼底型节点（隧道正常、节点把流量
 * 交给一个兼底的 web 服务器）在旧界面上看起来一切正常，而浏览器一个页都打不开。
 * 读数来自节点页那份跨页保留的结果——这里不发请求：测速是用户点出来的，
 * 不该因为切到总览就自己跑一遍（每跑一次都要经那个节点多取一次页面）。
 */
const lastTest = computed<(ProfileTest & { ago: string }) | null>(() => props.lastTest)

const lastTestText = computed(() => {
  const t = lastTest.value
  if (!t) {
    return ''
  }
  if (!t.ok) {
    return '不通'
  }
  // 电路通了，再看应用层那一格。三档各有句子，不许合并成"正常"两个字。
  if (!t.pageChecked) {
    return `${t.latencyMs} ms · 页面没探`
  }
  if (t.pageErr !== '') {
    return `${t.latencyMs} ms · 电路通了，页面取不回`
  }
  return `${t.latencyMs} ms · 页面 ${t.page}`
})

/** 音量：不通与"页面取不回"都要响，"页面没探"是中性，取回了才算绿。 */
function tone(): string {
  const t = lastTest.value
  if (!t) {
    return 'mut'
  }
  // 类名只有 proxy / direct / warn / err 四种（style.css），写 'bad' 会静默落回灰底。
  if (!t.ok || t.pageErr !== '') {
    return 'err'
  }
  return t.pageChecked ? 'proxy' : 'mut'
}

const lastTestTone = computed(tone)

/** 那一行下面的补充：两种失败原文各说各的，别混成一句"出错了"。 */
const lastTestDetail = computed(() => {
  const t = lastTest.value
  if (!t) {
    return ''
  }
  return t.ok ? t.pageErr : t.error
})
/** 声音大小：orphan/读不懂/调不动 = 红，欠一次自愈 = 黄，其余安静。 */
const ledgerAlert = computed(() => {
  const st = props.ledger?.state ?? ''
  if (st === 'orphan' || st === 'unreadable' || st === 'error') return 'err'
  if (st === 'stale') return 'warn'
  return ''
})
/**
 * TUN 那一行的说明。
 *
 * 与 `sysNote`、`splitNote` 同一条原则：**"开关开着"与"现在真的在代理"是两件事**。
 * TUN 开着而模式是直连时，流量确实进了这张网卡（假 IP 也照样发），
 * 但路由那一步 `ModeDirect` 直接放行——进了网卡不等于上了隧道。
 * 判据在 Go 那边：`tunx.TUN` 拿的是同一个 `router.Router`，
 * 三种入站（SOCKS5 / HTTP / TUN）共用一份 mode，所以这句话对 TUN 同样成立。
 */
const tunNote = computed(() => {
  const word = TUN_PHASE_TEXT[phase.value]
  if (phase.value !== 'on') {
    return phase.value === 'idle' ? `${word}（代理未运行）` : word
  }
  const body = `${word} · ${tun.value.device} · 假 IP ${tun.value.fakeIps} 条`
  if (props.status.mode === 'direct') {
    return `${body} · 但当前是「直连」模式：进了网卡的流量也是直接出去，不经节点`
  }
  return body
})

/**
 * 系统代理那一行的说明：把原来摊在模板里的一长串三元表达式收进 computed。
 *
 * 与下面 `splitNote` 同一条原则：**"开关开着"与"现在真的在代理"是两件事**。
 * 直连模式下这个开关确实是开的（浏览器把流量交给面板），而面板把它们原样直接放出去——
 * 于是"我明明开了代理开关"与"国外站还是打不开"同时成立，
 * 而这两句话在界面上没有任何一处对不上，人就去找第三个原因。
 */
const sysNote = computed(() => {
  if (props.busy === 'sysproxy') {
    return sysChecked.value ? '设置中…' : '恢复中…'
  }
  const s = props.sys
  if (!s) return '读取中…'
  if (!s.supported) return s.error ? `读取失败：${s.error}` : '本机无可用后端'
  if (!s.enabled) {
    return '未开启'
  }
  const addr = s.http || '已开启'
  if (props.status.mode === 'direct') {
    return `${addr} · 但当前是「直连」模式：交给面板的流量会原样直接出去`
  }
  return addr
})

/**
 * 按网卡分流那一行的说明。
 *
 * 「开关开着」与「现在真的分流了」是两件事，必须分开说：
 * 只有两张无线都在、且当前是规则模式，代理才会走 USB 无线那张卡。
 * 理由句来自 Go（它知道是「只找到一张卡」还是「没有钉网卡权限」），
 * 这里只补运行期那两种——还没启动、当前不是规则模式。
 */
const splitNote = computed(() => {
  if (props.busy === 'ifaceSplit') {
    return splitChecked.value ? '设置中…' : '收回中…'
  }
  const s = ifaceSplit.value
  if (!s) return '读取中…'
  if (!s.enabled) return '未开启：直连与代理都按系统默认路由走'
  if (s.active) return `已生效 · 直连 ${s.directDev} · 代理 ${s.proxyDev}`
  if (s.note !== '') return s.note
  if (!props.status.running) return '将在代理启动后探测网卡'
  return `当前是 ${props.status.mode} 模式，切回规则模式后生效`
})

/** 一个下拉项：值是接口名，标签要能让人认出这是哪张卡。 */
interface SplitOption {
  value: string
  label: string
}

/**
 * 某一侧的下拉项。
 *
 * "自动" 放在第一项且默认值是它：程序本来就按内置直连、USB 代理挑，
 * 不点下拉的人拿到的就是那套行为——多一个"不选"不该成为另一条路。
 *
 * 当前生效的那张卡即使这轮探测不到（刚被拔掉、还没到下一轮）也要留在列表里：
 * 少了它，浏览器会默默显示第一项，看着像"已经换成别的卡了"。
 */
function splitOptions(side: 'direct' | 'proxy'): SplitOption[] {
  const s = ifaceSplit.value
  const cards = s?.cards ?? []
  const current = side === 'direct' ? (s?.directDev ?? '') : (s?.proxyDev ?? '')
  const out: SplitOption[] = [
    { value: '', label: side === 'direct' ? '自动：内置无线' : '自动：USB 无线' }
  ]
  for (const c of cards) {
    out.push({
      value: c.name,
      label: `${c.name} · ${c.usb ? 'USB 无线' : '内置无线'} · ${c.addrs.join('、') || '暂无地址'}`
    })
  }
  if (current !== '' && !cards.some((c) => c.name === current)) {
    out.push({ value: current, label: `${current} · 此刻不在（已拔掉或刚换）` })
  }
  return out
}

const directOptions = computed(() => splitOptions('direct'))
const proxyOptions = computed(() => splitOptions('proxy'))

/** 改一侧就把另一侧当前的值原样带回去：后端收的是两张卡，不是一次单边改动。 */
function onPickCard(side: 'direct' | 'proxy', ev: Event): void {
  const value = (ev.target as HTMLSelectElement).value
  const s = ifaceSplit.value
  const direct = side === 'direct' ? value : (s?.directDev ?? '')
  const proxy = side === 'proxy' ? value : (s?.proxyDev ?? '')
  emit('ifaceCards', direct, proxy)
}

/** 最后一个采样点就是「现在多快」，不必自己算平均——但停更时它不是"现在"。 */
const last = computed(() => {
  if (props.stale) {
    return null
  }
  const s = props.traffic.series
  return s.length ? s[s.length - 1] : null
})

/**
 * 本次启动的墙钟时刻。
 * uptime 会说"已运行 3 小时"，但对不上日志——排查时要的是几点起来的。
 * 后端把 startedAt 一起投影出来就是为了这个（换节点不会改它，重启才会，
 * 所以它同时是"刚才那次到底有没有重启"的证据）。
 */
const bootedAt = computed(() =>
  props.status.running && props.status.startedAt > 0 ? formatClock(props.status.startedAt) : ''
)

/**
 * server 形如 host:port，取 host 部分用来和 SNI 比较。
 * IPv6 字面量带方括号（[::1]:443），按 lastIndexOf(':') 切会切出 "[::1"，
 * 于是每条 IPv6 节点都会被说成"SNI 与地址不同"。
 */
const serverHost = computed(() => {
  const a = props.status.server
  if (a.startsWith('[')) {
    const end = a.indexOf(']')
    return end > 0 ? a.slice(1, end) : a
  }
  const i = a.lastIndexOf(':')
  return i > 0 ? a.slice(0, i) : a
})

const total = computed(() => props.traffic.totalUp + props.traffic.totalDown)

/** 走向分三类：DIRECT 直连、REJECT 被拦，其余（节点名或 PROXY）才算走代理。 */
const split = computed(() => {
  let proxyConns = 0
  let directConns = 0
  let blockedConns = 0
  let proxyBytes = 0
  let directBytes = 0
  for (const c of props.traffic.active) {
    const bytes = c.up + c.down
    if (c.outbound === 'REJECT') {
      // 拦下来的连接一个字节都没有，所以只数条数：
      // 混进 else 里就成了「走代理 N 条」里凭空多出来的一批，
      // 而用户看到的却是这些网站根本打不开。
      blockedConns++
      continue
    }
    if (c.outbound === 'DIRECT') {
      directConns++
      directBytes += bytes
    } else {
      proxyConns++
      proxyBytes += bytes
    }
  }
  const sum = proxyBytes + directBytes
  return {
    proxyConns,
    directConns,
    blockedConns,
    proxyBytes,
    directBytes,
    proxyPct: sum > 0 ? Math.round((proxyBytes / sum) * 100) : 0,
    directPct: sum > 0 ? Math.round((directBytes / sum) * 100) : 0
  }
})
</script>

<template>
  <div class="view">
    <div class="stats five">
      <div class="stat down">
        <b class="down"><Amount :text="last ? formatRate(last.down) : '—'" /></b>
        <span>实时下行</span>
      </div>
      <div class="stat up">
        <b class="up"><Amount :text="last ? formatRate(last.up) : '—'" /></b>
        <span>实时上行</span>
      </div>
      <div class="stat">
        <b>{{ stale ? '—' : traffic.activeCount }}</b>
        <span>活跃连接</span>
      </div>
      <div
        class="stat"
        title="本进程经手搬过的字节：从 SOCKS5 / HTTP / TUN 进来的连接。选择性 TUN 下没进 tun 的直连流量不计入；它也不是系统网卡总流量。"
      >
        <b><Amount :text="formatBytes(total)" /></b>
        <span>本次累计流量</span>
      </div>
      <!-- 「拨不通」单独占一格，而且刻意不跟「累计拦截」共用一个"异常数"：
           拦下是按规则办（是这台机器在干活），拨不通是出事了。
           合成一个数，用户就没法从数字本身看出该不该担心。
           0 的时候它是安静的灰字，不是红色 0——一屏里不该有假警报。 -->
      <button
        type="button"
        class="stat stat-btn"
        :class="{ bad: !stale && traffic.totalFailed > 0 }"
        :disabled="stale || traffic.totalFailed === 0"
        :title="stale ? '这一轮的读数没拿到，所以既不能说有问题，也不能说没有' : traffic.totalFailed > 0 ? '点一下看是哪几条、各是什么错' : '本次运行没有拨不通的连接'"
        @click="emit('showFailures')"
      >
        <b>{{ stale ? '—' : traffic.totalFailed }}</b>
        <span>拨不通</span>
        <!-- 光有总数答不了那一问。真数据上见过这个形状：一屏 236 条拨不通，
             全是同一批域名——那是刚才八分钟里的事，还是昨天留下的，数字本身看不出来。
             "还在坏吗"要由最近一次的时间来回答。 -->
        <span class="when">{{ lastFailureText }}</span>
      </button>
    </div>

    <!-- 应急出口，刻意放在总览最上面：上不了网的人不会去翻卡片找开关。
         "解绑"只解两样东西——桌面那根指向本程序的指针、以及入站端口；
         节点、规则、配置文件一个字都不改。这句说明必须写清，
         否则读的人会以为点一下把自己的配置清了，关键时刻反而不敢按。 -->
    <section class="card">
      <h2>
        一键解绑
        <span class="act">
          <button
            v-if="status.running"
            type="button"
            class="btn danger"
            :disabled="idle"
            title="收回桌面系统代理指针并关闭入站端口，流量立刻回到直连；节点与规则不动"
            @click="emit('unbind')"
          >
            {{ busy === 'stop' ? '处理中…' : '解除代理' }}
          </button>
          <button
            v-else
            type="button"
            class="btn primary"
            :disabled="idle"
            title="启动代理，并把桌面系统代理指针放回本机入站"
            @click="emit('rebind')"
          >
            {{ busy === 'start' ? '处理中…' : '重新接管' }}
          </button>
        </span>
      </h2>
      <p class="hint tail">
        {{
          status.running
            ? '代理正在接管。上不了网点「解除代理」：桌面代理指针会被收回、入站端口关掉，流量立刻走直连——节点与规则一个字都不改。'
            : '当前已解绑：代理没在跑，桌面代理指针也已收回，流量走直连。要恢复就点「重新接管」。'
        }}
      </p>
    </section>

    <section class="card">
      <h2>
        最近 15 分钟速率
        <span class="act legend">
          <span><i class="sw-up"></i>上行</span>
          <span><i class="sw-down"></i>下行</span>
        </span>
      </h2>
      <RateChart :series="traffic.series" compact />
    </section>

    <div class="g2">
      <section class="card">
        <h2>
          出站隧道
          <span class="act">
            <button type="button" class="btn sm ghost" :disabled="idle" @click="emit('restart')">重启</button>
            <button type="button" class="btn sm ghost" :disabled="idle" @click="emit('reload')">重载规则</button>
          </span>
        </h2>
        <dl class="kv">
          <dt>节点</dt>
          <dd>{{ status.activeProfile || '未选择' }}</dd>
          <dt>协议</dt>
          <dd>
            <!-- 取不到协议时不能默认显示 hysteria2：Go 侧只在运行分支里填这个字段，
                 停着的时候它是空的。写个假默认值，用户就以为正跑着一条 QUIC 隧道，
                 还会照着 QUIC 的思路去排查（拥塞算法、带宽）。 -->
            <template v-if="status.proxyType">
              {{ status.proxyType }}
              <template v-if="status.proxyType === 'hysteria2'">
                · {{ status.congestion || '—' }}
                <span class="mut">↑{{ status.bandwidthUp || '不限' }} ↓{{ status.bandwidthDown || '不限' }}</span>
              </template>
              <!-- 停着的时候这一行读的是磁盘配置，不是"正在用的协议"。
                   不点明，用户会以为有一条没在跑的隧道。 -->
              <span v-if="!status.running" class="mut">（按配置，未运行）</span>
            </template>
            <span v-else class="mut">读不到在用协议</span>
          </dd>
          <dt>地址</dt>
          <dd class="mono">{{ status.server || '—' }}</dd>
          <dt>SNI</dt>
          <dd class="mono">
            {{ status.sni || '跟随地址' }}
            <span v-if="status.sni && status.sni !== serverHost" class="mut">（与地址不同，证书按这个校验）</span>
          </dd>
          <dt>隧道</dt>
          <dd>
            <span class="pill" :class="status.connected ? 'proxy' : 'mut'">
              {{ status.connected ? '已建链' : '未握手' }}
            </span>
            <!-- 摘要为空不等于"等第一次流量"：隧道报错时后端也可能给不出这句话。
                 兜底文案要按"我们到底知不知道"来写，不然一个未知就被说成了正常。 -->
            <span class="mono mut">
              {{ status.proxyStatus || (status.running ? '还没有隧道读数' : '代理未运行') }}
            </span>
            <span v-if="bootedAt" class="mut">· 本次启动 {{ bootedAt }}</span>
          </dd>
          <dt>上次测速</dt>
          <dd>
            <template v-if="!lastTest">
              <span class="mut">这个节点没测过</span>
              <button type="button" class="btn sm ghost" @click="emit('goto', 'nodes')">去节点页测</button>
            </template>
            <template v-else>
              <span class="pill" :class="lastTestTone">{{ lastTestText }}</span>
              <span class="mut">· {{ lastTest.ago }}测的</span>
              <!-- 失败原文摊在版面上，不藏进悬停：DNS 失败、证书对不上、
                   兼底 web 服务器三种情况要去查的地方完全不同。 -->
              <span v-if="lastTestDetail" class="why-line">{{ lastTestDetail }}</span>
            </template>
          </dd>
          <dt>认证口令</dt>
          <dd class="mut">{{ status.authSet ? '已设置，不经界面' : '未设置' }}</dd>
          <dt>配置文件</dt>
          <dd class="mono mut">{{ status.configPath }}</dd>
        </dl>
        <!-- 自动切换的理由必须摆在版面上，不能只挂在顶栏"自动"徽标的悬停提示里：
             触屏、键盘操作和截图反馈都读不到 title，而"节点怎么自己变了"正是最需要解释的事。 -->
        <p v-if="status.autoSwitched" class="alert warn tail">
          {{ status.switchReason || '当前生效的节点是故障自动切换选出来的，但后端没给出理由——把这条当成缺陷来看。' }}
          <span v-if="status.autoSwitchedAt" class="mut">
            （切换发生在 {{ formatAgo(status.autoSwitchedAt) }}）
          </span>
        </p>
        <p v-if="status.lastError" class="alert tail">{{ status.lastError }}</p>
        <!-- 断网保护改变了「能不能上网」这件事本身，所以摆在首页而不是设置页里。
             两条都要：挂上了要喊，装不上更要喊——后者是用户以为有、实际没有。 -->
        <p v-if="status.tun.killArmed" class="alert warn tail">
          故障断网保护已挂上：本机出站只放行节点、DNS 上游与本地网段，其余丢弃。
          <span class="mut">节点恢复或你手动选点后会自动解除。</span>
        </p>
        <p v-else-if="status.tun.killEnabled && status.tun.killReason" class="alert warn tail">
          故障断网保护未生效：{{ status.tun.killReason }}
        </p>
        <!-- 解析失败喊在版面上，而不是只留在设置页：它是"某些站打不开"最常见的原因，
             又不会出现在连接表里（DNS 查询不是被转发的连接）。
             不写清"只影响判成直连的域名"，用户会把"代理域名照常能开"当成代理坏了的证据。 -->
        <p v-if="dnsFailing" class="alert warn tail">
          本机 DNS 解析失败 {{ status.tun.dnsFailed }} 次：一个上游都没答上。
          <span class="mut">
            只影响判成直连的域名（代理域名领假 IP，本来就不做解析）；上游恢复后自己就好，不需要重启。
          </span>
        </p>
      </section>

      <section class="card">
        <h2>
          入站与规则
          <span class="act">
            <button type="button" class="btn sm ghost" @click="emit('goto', 'rules')">自定义规则</button>
          </span>
        </h2>
        <dl class="kv">
          <template v-for="ib in status.inbounds" :key="ib.type + ib.listen">
            <dt>{{ ib.type.toUpperCase() }}</dt>
            <dd>
              <span class="mono">{{ ib.addr || ib.listen }}</span>
              <span :class="ib.active ? 'ok' : 'mut'">{{ ib.active ? '监听中' : '已关闭' }}</span>
              <span v-if="ib.auth" class="mut">· 需认证</span>
            </dd>
          </template>
          <template v-if="status.inbounds.length === 0">
            <dt>入站</dt>
            <dd class="mut">配置里没有启用的入站</dd>
          </template>
          <dt>规则</dt>
          <dd>
            域名 {{ status.domainRules }} / IP {{ status.ipRules }}
            <template v-if="status.blockedRules > 0"> / 拦截 {{ status.blockedRules }}</template>
            · 兜底
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
    </div>

    <div class="g2">
      <section class="card">
        <h2>全局开关</h2>
        <!-- 一行一个开关，整行都是点区（label 包住文字与开关）：
             只让 38×22 的轨道可点的话，这一卡片里最难瞄准的就是它。
             说明写在名字下面，开关统一靠右。 -->
        <div class="switch-list">
          <label class="switch-item">
            <span class="si-text">
              <span class="si-title">TUN 模式</span>
              <span
                class="si-note mono"
                :class="{ warn: phase === 'stopping' || phase === 'starting' }"
                >{{ tunNote }}</span
              >
            </span>
            <span class="switch">
              <input
                type="checkbox"
                :checked="tunChecked"
                :disabled="idle"
                aria-label="TUN 模式"
                @change="emit('tun', ($event.target as HTMLInputElement).checked)"
              />
              <span class="track" aria-hidden="true"></span>
            </span>
          </label>

          <label
            class="switch-item"
            title="总开关：打开会启动代理并接管桌面；关闭会恢复桌面指针并停止代理（监听、隧道、TUN 一起停）"
          >
            <span class="si-text">
              <span class="si-title">系统代理</span>
              <span class="si-note mono">{{ sysNote }}</span>
            </span>
            <span class="switch">
              <input
                type="checkbox"
                :checked="sysChecked"
                :disabled="idle || !(sys?.supported ?? false)"
                aria-label="系统代理"
                @change="emit('sysproxy', ($event.target as HTMLInputElement).checked)"
              />
              <span class="track" aria-hidden="true"></span>
            </span>
          </label>

          <label class="switch-item">
            <span class="si-text">
              <span class="si-title">按网卡分流</span>
              <span class="si-note mono">{{ splitNote }}</span>
            </span>
            <span class="switch">
              <input
                type="checkbox"
                :checked="splitChecked"
                :disabled="idle"
                aria-label="按网卡分流"
                @change="emit('ifaceSplit', ($event.target as HTMLInputElement).checked)"
              />
              <span class="track" aria-hidden="true"></span>
            </span>
          </label>
          <!-- 分工写在开关旁边，而不是藏进设置页：这一行就是「直连和代理分别走哪张卡」，
               开关开着却看不出走哪儿去，等于让人回日志里猜。 -->
          <div v-if="splitChecked" class="split-cards">
            <label class="sc-field">
              <span class="sc-key">直连走</span>
              <select
                :value="ifaceSplit?.directDev ?? ''"
                :disabled="idle"
                aria-label="直连走哪张网卡"
                @change="onPickCard('direct', $event)"
              >
                <option v-for="o in directOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
              </select>
            </label>
            <label class="sc-field">
              <span class="sc-key">代理走</span>
              <select
                :value="ifaceSplit?.proxyDev ?? ''"
                :disabled="idle"
                aria-label="代理走哪张网卡"
                @change="onPickCard('proxy', $event)"
              >
                <option v-for="o in proxyOptions" :key="o.value" :value="o.value">{{ o.label }}</option>
              </select>
            </label>
            <p class="sc-hint mono">
              点哪张卡就钉哪张；卡片被拔掉或换成同类的另一张时，每 5 秒探一次并自动跟上。
            </p>
          </div>
        </div>
        <!-- 那个 ON 到底是谁改的、退出会不会还原，只有记账知道。
             安静的两种也照样写出来：省略掉就等于把"没人负责还原"藏进一片绿色里。 -->
        <p v-if="ledgerAlert" class="alert tail" :class="{ warn: ledgerAlert === 'warn' }">{{ ledgerText }}</p>
        <p v-else class="ledger-line mono mut" :title="ledger?.path">{{ ledgerText }}</p>
        <p v-if="tun.lastError" class="alert tail">{{ tun.lastError }}</p>
      </section>

      <section class="card">
        <h2>
          流量走向
          <span class="count">活跃 {{ traffic.activeCount }} 条</span>
          <span class="act">
            <button type="button" class="btn sm ghost" @click="emit('goto', 'traffic')">看全部连接</button>
          </span>
        </h2>
        <!-- 一条堆叠条而不是两条各自的量尺：这两档是"同一块饼的两份"，
             分开放就把互补关系画丢了，也看不出总长其实恒定。 -->
        <div v-if="split.proxyBytes + split.directBytes > 0" class="splitbar" aria-hidden="true">
          <span class="sb-proxy" :style="{ width: split.proxyPct + '%' }"></span>
          <span class="sb-direct" :style="{ width: split.directPct + '%' }"></span>
        </div>
        <div class="split-legend">
          <div class="sl-row">
            <i class="dot proxy"></i>
            <span class="sl-k">走代理</span>
            <span class="sl-v">{{ split.proxyConns }} 条 · {{ formatBytes(split.proxyBytes) }}</span>
            <b>{{ split.proxyBytes + split.directBytes > 0 ? split.proxyPct + '%' : '—' }}</b>
          </div>
          <div class="sl-row">
            <i class="dot direct"></i>
            <span class="sl-k">直连</span>
            <span class="sl-v">{{ split.directConns }} 条 · {{ formatBytes(split.directBytes) }}</span>
            <b>{{ split.proxyBytes + split.directBytes > 0 ? split.directPct + '%' : '—' }}</b>
          </div>
          <div class="sl-row blocked">
            <i class="dot blocked"></i>
            <span class="sl-k">拦截</span>
            <span class="sl-v">当前 {{ split.blockedConns }} 条 · 本次累计 {{ traffic.totalBlocked }} 条</span>
          </div>
        </div>
        <p class="hint tail">
          占比按活跃连接当前已传输的字节算，连接结束就移出这里。
          「累计」是命中拦截名单被静默丢弃的条数：客户端那边什么都收不到，
          这个数与连接表就是本机唯一的凭据，重启后归零。
        </p>
      </section>
    </div>
  </div>
</template>

<style scoped>
/* 那一格是个按钮，但它的样子必须和旁边四格完全一致：
   它先要读成一个数字，其次才是一个可以点的东西。
   所以这里只把 button 的默认外观抹掉，配色与那条左侧强调栏都沿用 .stat 的规矩。 */
.stat-btn {
  appearance: none;
  font: inherit;
  color: inherit;
  text-align: left;
  cursor: pointer;
}

/* 第三行那句"最近 N 秒前"：它比标签再小一档，但颜色仍走 --muted——
   这一格是"有没有出事"的入口，把说明写成几乎看不见的灰，等于没有那条。 */
.when {
  font-size: var(--fs-caption);
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.stat-btn:disabled {
  cursor: default;
}
/* 0 的时候它是安静的：一屏里不该有假警报。
   有了数才亮红，并且这时候才可以点。 */
.stat-btn.bad::before {
  background: var(--err-bright);
  box-shadow: 0 0 12px rgba(248, 113, 113, 0.45);
}
.stat-btn.bad b {
  color: var(--err-bright);
}
/* 测速那一行的失败原文必须自己占一行：它是给人读的整句话，
   跟在徽标后面会被挤成半截，而这一行存在的意义就是"别让人猜"。 */
.why-line {
  display: block;
  margin-left: 0;
  margin-top: 3px;
  font-size: var(--fs-micro);
  line-height: 1.35;
  color: var(--muted);
  overflow-wrap: anywhere;
}
.legend {
  gap: 14px;
}

.legend i {
  display: inline-block;
  width: 8px;
  height: 8px;
  margin-right: 5px;
  border-radius: var(--r-pill);
}

.legend .sw-up {
  background: var(--accent);
}

.legend .sw-down {
  background: var(--ok);
}

.tail {
  margin-top: var(--sp-3);
}

/* ---------- 全局开关 ---------- */

.switch-list {
  display: flex;
  flex-direction: column;
}

.switch-item {
  display: flex;
  align-items: center;
  gap: var(--sp-4);
  padding: 10px 0;
  border-bottom: 1px solid var(--line);
  cursor: pointer;
}

.switch-item:last-child {
  border-bottom: 0;
  padding-bottom: 2px;
}

/* 整行已经是点区了，开关自己不用再撑出 30px 的行高。 */
.switch-item .switch {
  min-height: 0;
  gap: 0;
}

.switch-item:hover .si-title {
  color: #fff;
}

.si-text {
  display: flex;
  flex-direction: column;
  gap: 1px;
  min-width: 0;
}

.si-title {
  font-size: var(--fs-body);
  font-weight: 500;
  color: var(--fg);
}

.si-note {
  font-size: var(--fs-caption);
  color: var(--muted);
  overflow-wrap: anywhere;
}

.si-note.warn {
  color: var(--warn-bright);
}

/* ---------- 网卡分工 ---------- */

/* 缩进一点，让它在视觉上从属于上面那个开关而不是与之并列。 */
.split-cards {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
  padding: var(--sp-2) 0 10px var(--sp-4);
  border-bottom: 1px solid var(--line);
}

.switch-item:last-child + .split-cards {
  border-bottom: 0;
}

.sc-field {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
}

.sc-key {
  flex: 0 0 52px;
  font-size: var(--fs-caption);
  color: var(--muted);
}

.sc-field select {
  flex: 1 1 auto;
  font-family: var(--mono);
}

.sc-hint {
  margin: 0;
  font-size: var(--fs-caption);
  line-height: 1.5;
  color: var(--muted-2);
}

/* 记账那一行是"安静的说明"，不许画成告警，但也要和上面的开关组分开。 */
.ledger-line {
  margin-top: var(--sp-3);
  padding-top: var(--sp-3);
  border-top: 1px solid var(--line);
  font-size: var(--fs-caption);
  line-height: 1.5;
}

/* ---------- 流量走向 ---------- */

.splitbar {
  display: flex;
  height: 8px;
  border-radius: var(--r-pill);
  background: rgba(255, 255, 255, 0.06);
  box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.35);
  overflow: hidden;
  margin-bottom: var(--sp-3);
}

.splitbar span {
  display: block;
  height: 100%;
  transition: width var(--dur-slow) var(--ease);
}

.sb-proxy {
  background: linear-gradient(90deg, #2f77ee, #5a9bff);
}

.sb-direct {
  background: linear-gradient(90deg, #22b882, #34d399);
}

.split-legend {
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.sl-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: var(--fs-caption);
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: var(--r-pill);
  flex: 0 0 auto;
}

.dot.proxy {
  background: var(--accent);
  box-shadow: 0 0 8px rgba(59, 130, 246, 0.6);
}

.dot.direct {
  background: var(--ok);
  box-shadow: 0 0 8px rgba(52, 211, 153, 0.55);
}

.dot.blocked {
  background: var(--warn);
  box-shadow: 0 0 8px rgba(251, 191, 36, 0.5);
}

.sl-k {
  flex: 0 0 auto;
  color: var(--fg-2);
}

.sl-v {
  margin-left: auto;
  color: var(--muted);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.sl-row b {
  flex: 0 0 42px;
  text-align: right;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
  color: var(--fg);
}

/* 拦截那一行没有百分比：它不占字节，只数条数。
   给它编一个 0% 等于说"它也是这块饼的一份"。 */
.sl-row.blocked b {
  display: none;
}
</style>
