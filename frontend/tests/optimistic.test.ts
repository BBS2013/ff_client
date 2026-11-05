import { describe, expect, it } from 'vitest'
import { releaseWritten, resyncBeforeRelease } from '../src/optimistic'

// 这一组钉住的是界面上的先后顺序：
// 系统代理那一栏的真相在桌面设置里，动作做完必须先把新读数拿回来，
// 再撤掉乐观值。反过来做，界面会闪一下上一次轮询的旧值——
// 旧值是「关」的时候，用户看到的就是「点开就自动关闭」。
describe('resyncBeforeRelease', () => {
  it('回读完成后才撤乐观值', async () => {
    const order: string[] = []
    await resyncBeforeRelease(
      () => {
        order.push('release')
      },
      async () => {
        order.push('resync-start')
        await Promise.resolve()
        order.push('resync-end')
      }
    )
    expect(order).toEqual(['resync-start', 'resync-end', 'release'])
  })

  it('回读失败也要撤乐观值（不能卡在「设置中」）', async () => {
    let released = false
    await resyncBeforeRelease(
      () => {
        released = true
      },
      async () => {
        throw new Error('读不到桌面设置')
      }
    )
    expect(released).toBe(true)
  })

  it('没有回读时直接撤', async () => {
    let released = false
    await resyncBeforeRelease(() => {
      released = true
    })
    expect(released).toBe(true)
  })
})

// pending 是跨动作共享的一份，所以"撤"必须是有条件的。
//
// 现场形状：用户点了 TUN 开关，回读还没回来（gsettings 单次预算 10 秒），
// 又切了节点。第二次动作把 pending.profile 拨上去；这时第一次的回读落地，
// 它的 release 如果无条件 delete，就会把刚拨上去的 profile 一起清掉——
// 界面闪回上一个轮询周期的旧节点名，用户看到的是"我点的被改回去了"。
describe('releaseWritten', () => {
  it('只撤本次写入的键', () => {
    const got = releaseWritten({ tun: false, profile: 'hk-2' }, { tun: false })
    expect(got).toEqual({ profile: 'hk-2' })
  })

  it('同键已被写成新目标时不撤', () => {
    const got = releaseWritten({ tun: true }, { tun: false })
    expect(got).toEqual({ tun: true })
  })

  it('值仍相等才撤（不是只看键存在）', () => {
    expect(releaseWritten({ tun: false }, { tun: false })).toEqual({})
    expect(releaseWritten({ tun: false }, { tun: true })).toEqual({ tun: false })
  })

  it('撤销后不改动原对象', () => {
    const before = { tun: false, mode: 'global' }
    const after = releaseWritten(before, { tun: false })
    expect(before).toEqual({ tun: false, mode: 'global' })
    expect(after).toEqual({ mode: 'global' })
  })
})
