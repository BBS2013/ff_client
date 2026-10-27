import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { DNSProbe, PageFetch, ProbeResult } from '../src/types'
import {
  DNS_HISTORY,
  FETCH_HISTORY,
  dnsHistory,
  fetchHistory,
  probeStore,
  rememberDNS,
  rememberFetch,
  rememberProbe,
  safeLabel,
  staleWhy
} from '../src/probes'

const blank = { q: '', res: null, err: '', at: 0, mode: '', stamp: '' }

beforeEach(() => {
  vi.useFakeTimers()
  vi.setSystemTime(new Date('2026-10-27T00:00:00Z'))
  dnsHistory.value = []
  fetchHistory.value = []
})

afterEach(() => {
  vi.useRealTimers()
})

describe('safeLabel', () => {
  it('成功时用后端洗好的 url，其次 addr', () => {
    expect(safeLabel({ ...blank, res: { url: 'https://e/x' } as unknown as PageFetch })).toBe('https://e/x')
    expect(safeLabel({ ...blank, res: { url: '', addr: '1.2.3.4:443' } as unknown as PageFetch })).toBe('1.2.3.4:443')
  })

  it('失败时只留 hostname，扔掉查询串', () => {
    expect(safeLabel({ ...blank, q: 'https://user:pass@example.com/p?token=secret' })).toBe('example.com')
  })

  it('输入读不懂就明说', () => {
    expect(safeLabel({ ...blank, q: 'not a url' })).toBe('（输入读不懂）')
  })
})

describe('staleWhy', () => {
  const entry = { ...blank, at: 1, res: {} as ProbeResult, mode: 'rule', stamp: 's1' }

  it('没拿到答复、或现场没变，不算旧', () => {
    expect(staleWhy({ ...blank }, 'direct', 's1')).toBe('')
    expect(staleWhy({ ...entry, res: null }, 'direct', 's1')).toBe('')
    expect(staleWhy(entry, 'rule', 's1')).toBe('')
  })

  it('模式变了与名单变了要说成两件事', () => {
    const byMode = staleWhy(entry, 'direct', 's1')
    expect(byMode).toContain('直连')
    expect(byMode).toContain('规则')
    expect(staleWhy(entry, 'rule', 's2')).toContain('动过')
  })
})

describe('rememberProbe', () => {
  it('记下输入、读数、模式与指纹', () => {
    rememberProbe('example.com', {} as ProbeResult, 'rule', 's1')
    expect(probeStore.host.q).toBe('example.com')
    expect(probeStore.host.mode).toBe('rule')
    expect(probeStore.host.stamp).toBe('s1')
    expect(probeStore.host.at).toBe(Date.now())
    expect(dnsHistory.value).toHaveLength(0)
    expect(fetchHistory.value).toHaveLength(0)
  })
})

describe('rememberDNS / rememberFetch', () => {
  it('空输入不算一次尝试，不进历史', () => {
    rememberDNS('', null, 'err', 'rule', 's1')
    rememberFetch('', null, 'err', 'rule', 's1')
    expect(dnsHistory.value).toHaveLength(0)
    expect(fetchHistory.value).toHaveLength(0)
  })

  it('历史新的在前，并封顶', () => {
    for (let i = 0; i < DNS_HISTORY + 2; i++) {
      rememberDNS(`d${i}.example`, null, 'err', 'rule', 's1')
    }
    expect(dnsHistory.value).toHaveLength(DNS_HISTORY)
    expect(dnsHistory.value[0].q).toBe(`d${DNS_HISTORY + 1}.example`)

    for (let i = 0; i < FETCH_HISTORY + 2; i++) {
      rememberFetch(`https://f${i}.example/x`, null, 'err', 'direct', 's2')
    }
    expect(fetchHistory.value).toHaveLength(FETCH_HISTORY)
    expect(fetchHistory.value[0].q).toBe(`https://f${FETCH_HISTORY + 1}.example/x`)
  })

  it('DNS 与取页面各自保留现场', () => {
    rememberDNS('a.example', null, '问不出来', 'rule', 's1')
    expect(probeStore.dns.err).toBe('问不出来')
    expect(probeStore.dns.at).toBe(Date.now())

    const res = { url: 'https://a.example/' } as unknown as PageFetch
    rememberFetch('https://a.example/', res, '', 'direct', 's2')
    expect(probeStore.page.res).toStrictEqual(res)
    expect(probeStore.page.mode).toBe('direct')
  })

  it('dns 读数带上了 DNSProbe 本身', () => {
    const res = { host: 'a.example' } as unknown as DNSProbe
    rememberDNS('a.example', res, '', 'rule', 's1')
    expect(probeStore.dns.res).toStrictEqual(res)
  })
})
