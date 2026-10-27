// format.ts 展示层格式化。全部是纯函数，改坏了也不会影响数据本身。

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

/** 字节数转成人类可读，如 1536 -> "1.5 KB" */
export function formatBytes(n: number): string {
  if (!isFinite(n) || n <= 0) {
    return '0 B'
  }
  let v = n
  let i = 0
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024
    i++
  }
  return `${i === 0 ? Math.round(v) : v.toFixed(1)} ${UNITS[i]}`
}

/** 速率，字节/秒 -> "1.5 MB/s" */
export function formatRate(bytesPerSec: number): string {
  if (!isFinite(bytesPerSec) || bytesPerSec <= 0) {
    return '0 B/s'
  }
  return `${formatBytes(bytesPerSec)}/s`
}

/**
 * 把 "10.4 MB/s" 拆成数字与单位两段。
 *
 * 统计块里数字要放到 30px 才压得住，可单位跟着一起放大的话
 * "512.0 MB" 那种五位串就把格子撑爆、被省略号截断（流量页五个并排时必现）。
 * 拆开之后数字大、单位小，既读得清又不会截。
 *
 * 认不出「数字 + 单位」这种形状的串（"—"、"未测"、纯文字）原样落在 value 里，
 * unit 留空——拆不出来不等于要编一个单位出来。
 */
export interface Amount {
  value: string
  unit: string
}

export function splitAmount(text: string): Amount {
  const m = /^([\d.,]+)\s*(.+)$/.exec(text)
  return m ? { value: m[1], unit: m[2] } : { value: text, unit: '' }
}

/**
 * 时长（毫秒）转成中文可读串。
 * 超过一天才带日期部分，避免连接表里塞满 "0天"。
 */
export function formatDuration(ms: number): string {
  if (!isFinite(ms) || ms <= 0) {
    return '0s'
  }
  const total = Math.floor(ms / 1000)
  const d = Math.floor(total / 86400)
  const h = Math.floor((total % 86400) / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (d > 0) {
    return `${d}天 ${h}小时 ${m}分`
  }
  if (h > 0) {
    return `${h}小时 ${m}分 ${s}秒`
  }
  if (m > 0) {
    return `${m}分 ${s}秒`
  }
  return `${s}秒`
}

/** Unix 毫秒 -> 本地 HH:MM:SS，图表坐标轴用 */
export function formatClock(ms: number): string {
  const d = new Date(ms)
  const p = (v: number) => String(v).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/**
 * 「多久之前」。留痕、缓存这类地方要的是量级而不是秒针，
 * 所以不到一分钟就说秒，之后逐级变粗。
 * 0 或负数是"没有这个时刻"，必须回未知——写成"很久前"是在编。
 */
export function formatAgo(ms: number): string {
  if (!isFinite(ms) || ms <= 0) {
    return '未知'
  }
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000))
  if (s < 60) {
    return `${s} 秒前`
  }
  if (s < 3600) {
    return `${Math.floor(s / 60)} 分钟前`
  }
  if (s < 86400) {
    return `${Math.floor(s / 3600)} 小时前`
  }
  return `${Math.floor(s / 86400)} 天前`
}

/** 去掉 IPv6 的方括号，让表格窄一点 */
export function trimHost(host: string): string {
  if (!host) {
    return ''
  }
  return host.replace(/^\[|\]$/g, '')
}

/**
 * TUN 开关该显示成什么。
 *
 * 拆 TUN 是真的慢（等协议栈收尾上限 3s，再经提权 helper 跑一遍 iptables），
 * 所以界面上必须有一段"正在关闭"的可见状态，而不是让开关原地变暗装作没事。
 * 好消息是后端已经把答案给全了：SetTUNEnabled 先写盘再动手，
 * 于是 enabled 与 running 会短暂错位——running 还在但 enabled 已经关了，
 * 只可能是"正在拆"。这一格不需要前端自己编状态。
 * pending 是用户刚点下去、回读还没到的那一下，用它先把 knob 拨到位。
 */
export function tunPhase(
  t: { enabled: boolean; running: boolean },
  pending?: boolean
): 'on' | 'off' | 'starting' | 'stopping' | 'idle' {
  if (pending !== undefined) {
    return pending ? 'starting' : 'stopping'
  }
  if (t.running) {
    return t.enabled ? 'on' : 'stopping'
  }
  if (t.enabled) {
    // 代理没跑起来（或启动失败）时的稳态，不是"正在启动"。
    return 'idle'
  }
  return 'off'
}

/** tunPhase 的人话。 */
export const TUN_PHASE_TEXT: Record<ReturnType<typeof tunPhase>, string> = {
  on: '运行中',
  off: '未启用',
  starting: '启动中…',
  stopping: '关闭中…',
  idle: '已启用但未运行'
}

/**
 * GeoIP 库这一格该说什么。
 *
 * 后端只给了一个 bool，但这里其实有四件事，混成两句就会骗人：
 *   已加载 / 没配路径 / 配了但打不开 / 代理压根没运行（还没试过）。
 * 最后一种最容易被写成"未加载（按规则表匹配）"，
 * 用户以为 GEOIP 规则还在工作，实际上停着的时候谁都没判过。
 */
export function geoipText(path: string, ok: boolean, running: boolean): string {
  if (ok) {
    return '已加载'
  }
  if (!path) {
    return '未配置：GEOIP 规则不参与判定'
  }
  if (!running) {
    return '代理未运行，还没打开过'
  }
  return '打不开：GEOIP 规则不参与判定（域名规则照常）'
}

/**
 * 分流策略的人话名。三个组件（总览 / 规则 / 设置）都要用它，
 * 所以放在这里而不是各自抄一份 `=== 'DIRECT' ? .. : ..`。
 *
 * 关键是**不许有 else 兜底**：策略的取值不止两种，
 * 把 REJECT 或空值落到"走代理"那一档，就是在给用户一张假图——
 * 兜底策略写成 REJECT 时界面说"兜底走代理"，用户会以为没命中的流量出去了。
 */
export function policyText(p: string): string {
  switch (p) {
    case 'DIRECT':
      return '直连'
    case 'PROXY':
      return '走代理'
    case 'REJECT':
      return '已拦截'
    case '':
      return '未知'
    default:
      return p
  }
}

/**
 * 模式那三个取值的中文名。顶栏上它们是按钮上的字，
 * 而「这份读数是哪个模式下拿的」这类话也要用同一套名字——
 * 两处各写一份，改一个忘一个就会出现顶栏写「直连」、告警写「direct」。
 */
export function modeText(m: string): string {
  switch (m) {
    case 'rule':
      return '规则'
    case 'global':
      return '全局'
    case 'direct':
      return '直连'
    case '':
      return '未知'
    default:
      return m
  }
}

export function policyClass(p: string): string {
  switch (p) {
    case 'DIRECT':
      return 'direct'
    case 'PROXY':
      return 'proxy'
    case 'REJECT':
      return 'warn'
    default:
      // 空值与没见过的取值都走中性样式：报错/未就绪不该长得像"一切正常"。
      return 'mut'
  }
}
