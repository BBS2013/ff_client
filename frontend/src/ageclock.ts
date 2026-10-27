import { ref } from 'vue'
import { formatAgo } from './format'

/**
 * 一个 5 秒走一格的钟，只为让「N 秒前」那一行自己动。
 *
 * 它不发任何请求，也不属于任何一个组件：换页会把组件拆掉重装，
 * 而"这份读数几时拿的"恰恰是**跨页留着的那类读数**必须带着的东西
 * （节点测速、查走向、取页面都靠它）。所以钟放在模块级，只起一次。
 */
const tick = ref(0)
let timer: ReturnType<typeof setInterval> | undefined

export function startAgeClock(): void {
  if (timer !== undefined) {
    return
  }
  timer = setInterval(() => {
    tick.value++
  }, 5000)
}

/**
 * 「这次数是几时拿的」。
 *
 * 五秒以内说「刚刚」——`0 秒前` 在界面上读起来像出错了，
 * 而这一行本来就是给人核对新鲜度的。判据没变，只是别把刚拿的写成旧的。
 */
export function agoText(at: number): string {
  // 读一下：没有这行，用它的 computed 就不依赖这个钟，那一行会永远停在读数那一刻。
  void tick.value
  if (!at) {
    return ''
  }
  if (Date.now() - at < 5000) {
    return '刚刚'
  }
  return formatAgo(at)
}

/**
 * 一份带有效期的读数**现在**还剩多久（毫秒，可为负 = 早过了）。
 *
 * 必须在这里自己倒着算，不能把后端报的那个瞬时值直接摆到界面上：
 * 后端那句"还剩 4 分 32 秒"说的是它回话那一刻，挂着不动的话三分钟后就是一句假话。
 * 起点用拿到它的那一刻（`at`），于是这一行跟着上面那个钟一起走，
 * 倒到 0 之后界面还能老实说出"这一份早过了有效期、只是没人再问"。
 */
export function ttlLeft(at: number, ttlMs: number): number {
  void tick.value
  if (!at || ttlMs <= 0) {
    return 0
  }
  return at + ttlMs - Date.now()
}
