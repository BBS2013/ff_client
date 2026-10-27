import { reactive } from 'vue'
import type { ProfileTest } from './types'
import { startAgeClock } from './ageclock'

/**
 * 测速结果放在模块级，不放在组件里。
 *
 * 换页会把组件整个拆掉重装，存在组件状态里等于"结果被翻页翻掉了"：
 * 用户看到的是「未测」，于是他重测一遍——而每次测速都要经那个节点
 * 建一次链、再取一次页面，这不是一次本地刷新该付出的价钱。
 * 放在这里，切去总览再看回来，数还在；总览也能回答"当前这个节点刚才测过没有"。
 */
export interface NodeTestEntry {
  /** 这一次测速的完整结果。 */
  res: ProfileTest
  /**
   * 这次读数的时刻（Date.now() 的毫秒）。
   * 结果会跨页留着，没有这个时间戳就是把十分钟前的数当刚测的报。
   */
  at: number
}

export const nodeTests = reactive<Record<string, NodeTestEntry | undefined>>({})

export function rememberTest(name: string, res: ProfileTest): void {
  nodeTests[name] = { res, at: Date.now() }
  // 「几秒前测的」那一行由 ageclock 推着走字；第一次记下读数才起它。
  startAgeClock()
}

/**
 * 丢掉已经不存在的节点的读数。
 *
 * 改名与删除都会留下没人看的键。留着不出错，但「这条读数属于哪个节点」
 * 会变成靠名字猜——而名字正是这次操作改掉的那个东西。
 */
export function pruneTests(names: Set<string>): void {
  for (const name of Object.keys(nodeTests)) {
    if (!names.has(name)) {
      delete nodeTests[name]
    }
  }
}
