import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { agoText, startAgeClock, ttlLeft } from '../src/ageclock'

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-10-27T00:00:00Z'))
})

afterEach(() => {
  vi.useRealTimers()
})

describe('agoText', () => {
  it('没有时刻就返回空串', () => {
    expect(agoText(0)).toBe('')
  })

  it('五秒以内说刚刚，之后交给 formatAgo', () => {
    const now = Date.now()
    expect(agoText(now - 1_000)).toBe('刚刚')
    expect(agoText(now - 5_000)).toBe('5 秒前')
    expect(agoText(now - 60_000)).toBe('1 分钟前')
  })
})

describe('ttlLeft', () => {
  it('按拿到读数的时刻自己倒着算', () => {
    const now = Date.now()
    expect(ttlLeft(0, 1_000)).toBe(0)
    expect(ttlLeft(now - 1_000, 5_000)).toBe(4_000)
    expect(ttlLeft(now - 6_000, 5_000)).toBe(-1_000)
    expect(ttlLeft(now, 0)).toBe(0)
  })

  it('钟走一格，剩余时间跟着少', () => {
    const now = Date.now()
    const before = ttlLeft(now - 1_000, 5_000)
    startAgeClock()
    startAgeClock() // 重复调用不应起第二个钟（至少不应报错）
    vi.advanceTimersByTime(5_000)
    const after = ttlLeft(now - 1_000, 5_000)
    expect(after).toBe(before - 5_000)
  })
})
