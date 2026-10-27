import { reactive, ref } from 'vue'
import type { DNSProbe, PageFetch, ProbeResult } from './types'
import { modeText } from './format'
import { startAgeClock } from './ageclock'

/**
 * 「查走向」与「取一个真页面」的读数放在模块级，理由有两条，第二条更要紧。
 *
 * ① 换页会把组件整个拆掉重装，存在组件里等于"结果被翻页翻掉了"——
 *    而这两格最常见的用法恰恰是"查一下 → 去流量页看那条连接 → 回来接着看"。
 * ② **旧读数会撒谎**：查完把模式从「规则」切到「直连」，那一格还写着
 *    「走代理 命中 FINAL · 模式 rule」，而顶栏同一屏上写着「直连」
 *    （2026-10-20 实测：切模式前后那一格的文字一字不差）。
 *    跨页留着读数会把这件事从"几秒"放大到"多久都有可能"，
 *    所以这里存的不是结果，是**结果 + 拿它时的现场**（模式与那份名单的指纹）。
 *    留着不是问题，不标出它是旧的才是问题。
 */
export interface ProbeEntry<T> {
  /** 用户当时输入的那个域名 / 网址，原样留着，回来时回填输入框。 */
  q: string
  /** 取到的读数；没取到（或压根没取）就是 null。 */
  res: T | null
  /** "问不出来"那一句（只有取页面那一格用得上）。与 res 互斥。 */
  err: string
  /** 拿这份读数的时刻（Date.now() 毫秒）。0 = 还没有过。 */
  at: number
  /** 拿它时是什么模式；与现在的 `status.mode` 不同就是旧的。 */
  mode: string
  /** 拿它时那份"会改变答案的名单"的指纹（见 Rules.vue 的 decideStamp）。 */
  stamp: string
}

function blank<T>(): ProbeEntry<T> {
  return { q: '', res: null, err: '', at: 0, mode: '', stamp: '' }
}

export const probeStore = reactive<{
  host: ProbeEntry<ProbeResult>
  page: ProbeEntry<PageFetch>
  dns: ProbeEntry<DNSProbe>
}>({
  host: blank(),
  page: blank(),
  dns: blank()
})

export function rememberProbe(q: string, res: ProbeResult, mode: string, stamp: string): void {
  probeStore.host = { q, res, err: '', at: Date.now(), mode, stamp }
  startAgeClock()
}

/** 「看解析」那份读数：与上面两格同一套现场（模式 + 名单指纹），所以过期判据共用。 */
export function rememberDNS(q: string, res: DNSProbe | null, err: string, mode: string, stamp: string): void {
  const e: ProbeEntry<DNSProbe> = { q, res, err, at: Date.now(), mode, stamp }
  probeStore.dns = e
  startAgeClock()
  if (q) {
    dnsHistory.value = [e, ...dnsHistory.value].slice(0, DNS_HISTORY)
  }
}

/**
 * 最近解析过的几次（新的在前）。
 *
 * 为什么这一格也要一串，比取页面那一串更具体：**污染是间歇性的**。
 * "223.5.5.5 十分钟前给 116.62.x（CN 段，于是直连），刚才给 93.184.x"——
 * 这句话是整件事的证据，而它只在**两次读数并排**时才成立。只看最后一次，
 * 人要么得截图去比，要么就得信"刚才那次就是常态"，而后者正是 §10.7 那次误判的形状。
 *
 * 上限与取页面同一档（6 次）：这一串只活在内存里、换页不清。
 */
export const DNS_HISTORY = 6
export const dnsHistory = ref<ProbeEntry<DNSProbe>[]>([])

/**
 * 最近取过的几次（新的在前）。
 *
 * 为什么要有这一份：这一格是为"隧道正常、对面却是台兜底 web 服务器"那种节点加的，
 * 而那件事的**证据形态是一串**——"十分钟前还是 200，现在全是 400"、
 * "同一个网址在 demo-sg 回 200、切到 demo-us 回 400"。只看最后一次，
 * 就得靠人自己截图去比。
 *
 * 上限写死在这里（不是配置项）：这一份只活在内存里、换页不清，
 * 没有上限就是"开着面板取着玩"会一直长；六次足够把上面那两种对比摆下。
 *
 * 只记**真的发出去过的那几次**：空输入那种"话没说清楚"不算一次尝试。
 */
export const FETCH_HISTORY = 6
export const fetchHistory = ref<ProbeEntry<PageFetch>[]>([])

export function rememberFetch(q: string, res: PageFetch | null, err: string, mode: string, stamp: string): void {
  const e: ProbeEntry<PageFetch> = { q, res, err, at: Date.now(), mode, stamp }
  probeStore.page = e
  startAgeClock()
  if (q) {
    fetchHistory.value = [e, ...fetchHistory.value].slice(0, FETCH_HISTORY)
  }
}

/**
 * 这一次尝试在"最近取过"那一列里显示成什么。
 *
 * 通与不通都只给**去掉查询串**的那一份：取成功时用后端洗好的 `url`，
 * 取失败时（压根没走到后端）自己摘一次——订阅地址的 key 常挂在查询串上，
 * 而这一列的存在理由就是让人截图发出去。裸摘不动的（输入本来就读不懂）
 * 宁可显示一句"读不懂"，也不把原样贴出去。
 */
export function safeLabel(e: ProbeEntry<PageFetch>): string {
  if (e.res) {
    return e.res.url || e.res.addr
  }
  try {
    return new URL(e.q).hostname || '（输入读不懂）'
  } catch {
    return '（输入读不懂）'
  }
}

/**
 * 这份读数还作不作数，以及不作数的**理由**。
 *
 * 空串 = 仍然作数。理由要说得具体：「模式切过去了」与「名单动过」
 * 是两件不同的事，前者重查一次就换答案，后者还得先去看是哪一条。
 */
export function staleWhy(e: ProbeEntry<unknown>, mode: string, stamp: string): string {
  // 只有真拿到过答复才谈得上"过期"：那一句"取不到：先填一个网址"不跟着模式变。
  if (!e.at || !e.res || (e.mode === mode && e.stamp === stamp)) {
    return ''
  }
  if (e.mode !== mode) {
    return `那一次是在「${modeText(e.mode)}」模式下查的，现在已经是「${modeText(mode)}」`
  }
  return '命中依据要看的那份名单（自定义规则 / 拦截域名 / 活动节点 / 网卡分流）在这之后动过'
}
