/**
 * 乐观值与回读的先后顺序。
 *
 * 界面上的开关常常有两份值：用户刚点的（乐观值）与从系统读回来的（真值）。
 * 动作做完就撤乐观值、再去读真值，中间那一小段界面显示的是**上一次**读到的旧值——
 * 旧值是「关」的时候，用户看到的就是「点开系统代理，它自己又关掉了」。
 *
 * 所以顺序不能反：回读先落定，乐观值再撤。
 */
export async function resyncBeforeRelease(
  release: () => void,
  resync?: () => Promise<void>
): Promise<void> {
  if (!resync) {
    release()
    return
  }
  try {
    await resync()
  } catch {
    // 读不回来也照样撤掉乐观值：界面显示旧读数，好过一直卡在「设置中」。
  } finally {
    release()
  }
}

/**
 * 从一份乐观状态里摘掉"本次写入的那些键"，只摘仍等于本次目标值的。
 *
 * 为什么不能无条件 delete：pending 是跨动作共享的一份。TUN 开关与节点切换
 * 可能前后脚发生——先那次动作的回读晚到，它的 release 执行时 pending 里
 * 已经躺着后一次刚拨上去的值。无差别删除会把后来那个也清掉，
 * 界面于是闪回上一个轮询周期的旧读数，看起来就是"我点的被改回去了"。
 *
 * 判据是"值仍相等"而不是"键存在"：同键被写了新目标时，旧动作也不该动它。
 */
export function releaseWritten<T extends object>(current: T, written: Partial<T>): T {
  const rest: Record<string, unknown> = { ...(current as Record<string, unknown>) }
  const from = written as Record<string, unknown>
  for (const k of Object.keys(from)) {
    if (rest[k] === from[k]) {
      delete rest[k]
    }
  }
  return rest as T
}
