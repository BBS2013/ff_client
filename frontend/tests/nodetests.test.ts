import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ProfileTest } from '../src/types'
import { nodeTests, pruneTests, rememberTest } from '../src/nodetests'

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-10-27T00:00:00Z'))
  for (const k of Object.keys(nodeTests)) {
    delete nodeTests[k]
  }
})

afterEach(() => {
  vi.useRealTimers()
  for (const k of Object.keys(nodeTests)) {
    delete nodeTests[k]
  }
})

describe('rememberTest', () => {
  it('记下结果与读数时刻', () => {
    const res = { ok: true } as unknown as ProfileTest
    rememberTest('a', res)
    expect(nodeTests.a?.res).toStrictEqual(res)
    expect(nodeTests.a?.at).toBe(Date.now())
  })
})

describe('pruneTests', () => {
  it('只留下还存在的节点', () => {
    rememberTest('a', {} as ProfileTest)
    rememberTest('b', {} as ProfileTest)
    pruneTests(new Set(['b']))
    expect(nodeTests.a).toBeUndefined()
    expect(nodeTests.b).toBeDefined()
  })
})
