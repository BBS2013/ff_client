import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  formatAgo,
  formatBytes,
  formatClock,
  formatDuration,
  formatRate,
  geoipText,
  modeText,
  policyClass,
  policyText,
  splitAmount,
  trimHost,
  tunPhase,
  TUN_PHASE_TEXT
} from '../src/format'

afterEach(() => {
  vi.useRealTimers()
})

describe('formatBytes / formatRate', () => {
  it('零、负数与非数字都回到 0 B', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(-1)).toBe('0 B')
    expect(formatBytes(Number.NaN)).toBe('0 B')
    expect(formatRate(0)).toBe('0 B/s')
    expect(formatRate(Number.POSITIVE_INFINITY)).toBe('0 B/s')
  })

  it('按 1024 进位，非整字节保留一位小数', () => {
    expect(formatBytes(1)).toBe('1 B')
    expect(formatBytes(1023)).toBe('1023 B')
    expect(formatBytes(1024)).toBe('1.0 KB')
    expect(formatBytes(1536)).toBe('1.5 KB')
    expect(formatBytes(1024 ** 2)).toBe('1.0 MB')
    expect(formatBytes(1.5 * 1024 ** 3)).toBe('1.5 GB')
  })

  it('速率后缀是 /s', () => {
    expect(formatRate(1536)).toBe('1.5 KB/s')
  })
})

describe('splitAmount', () => {
  it('拆数字与单位', () => {
    expect(splitAmount('1.5 MB/s')).toEqual({ value: '1.5', unit: 'MB/s' })
    expect(splitAmount('512.0 MB')).toEqual({ value: '512.0', unit: 'MB' })
    expect(splitAmount('1,024 B')).toEqual({ value: '1,024', unit: 'B' })
  })

  it('拆不出来的原样放 value，不编单位', () => {
    expect(splitAmount('—')).toEqual({ value: '—', unit: '' })
    expect(splitAmount('未测')).toEqual({ value: '未测', unit: '' })
  })
})

describe('formatDuration', () => {
  it('按天/时/分/秒逐级变粗', () => {
    expect(formatDuration(0)).toBe('0s')
    expect(formatDuration(-1)).toBe('0s')
    expect(formatDuration(1000)).toBe('1秒')
    expect(formatDuration(61_000)).toBe('1分 1秒')
    expect(formatDuration(3_661_000)).toBe('1小时 1分 1秒')
    expect(formatDuration(90_061_000)).toBe('1天 1小时 1分')
  })
})

describe('formatClock', () => {
  it('输出 HH:MM:SS', () => {
    expect(formatClock(Date.UTC(2026, 9, 27, 0, 0, 0))).toMatch(/^\d{2}:\d{2}:\d{2}$/)
  })
})

describe('formatAgo', () => {
  it('0 与负数是未知，不写成很久前', () => {
    expect(formatAgo(0)).toBe('未知')
    expect(formatAgo(-1)).toBe('未知')
    expect(formatAgo(Number.NaN)).toBe('未知')
  })

  it('按秒/分/时/天分档', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-10-27T00:00:00Z'))
    const now = Date.now()
    expect(formatAgo(now - 5_000)).toBe('5 秒前')
    expect(formatAgo(now - 90_000)).toBe('1 分钟前')
    expect(formatAgo(now - 7_200_000)).toBe('2 小时前')
    expect(formatAgo(now - 172_800_000)).toBe('2 天前')
    expect(formatAgo(now + 10_000)).toBe('0 秒前')
  })
})

describe('trimHost', () => {
  it('只去掉 IPv6 方括号', () => {
    expect(trimHost('[::1]')).toBe('::1')
    expect(trimHost('example.com')).toBe('example.com')
    expect(trimHost('')).toBe('')
  })
})

describe('tunPhase / TUN_PHASE_TEXT', () => {
  it('pending 优先，其次看 running 与 enabled 的错位', () => {
    expect(tunPhase({ enabled: false, running: false }, true)).toBe('starting')
    expect(tunPhase({ enabled: true, running: true }, false)).toBe('stopping')
    expect(tunPhase({ enabled: true, running: true })).toBe('on')
    expect(tunPhase({ enabled: false, running: true })).toBe('stopping')
    expect(tunPhase({ enabled: true, running: false })).toBe('idle')
    expect(tunPhase({ enabled: false, running: false })).toBe('off')
  })

  it('每种状态都有话', () => {
    for (const k of ['on', 'off', 'starting', 'stopping', 'idle'] as const) {
      expect(TUN_PHASE_TEXT[k]).toBeTruthy()
    }
  })
})

describe('geoipText', () => {
  it('四种情况四种话', () => {
    expect(geoipText('/x.mmdb', true, true)).toBe('已加载')
    expect(geoipText('', false, true)).toContain('未配置')
    expect(geoipText('/x.mmdb', false, false)).toContain('还没打开过')
    expect(geoipText('/x.mmdb', false, true)).toContain('打不开')
  })
})

describe('policyText / modeText / policyClass', () => {
  it('策略不兜底成走代理', () => {
    expect(policyText('DIRECT')).toBe('直连')
    expect(policyText('PROXY')).toBe('走代理')
    expect(policyText('REJECT')).toBe('已拦截')
    expect(policyText('')).toBe('未知')
    expect(policyText('FUTURE')).toBe('FUTURE')
  })

  it('模式名统一', () => {
    expect(modeText('rule')).toBe('规则')
    expect(modeText('global')).toBe('全局')
    expect(modeText('direct')).toBe('直连')
    expect(modeText('')).toBe('未知')
    expect(modeText('future')).toBe('future')
  })

  it('未知策略走中性样式', () => {
    expect(policyClass('DIRECT')).toBe('direct')
    expect(policyClass('PROXY')).toBe('proxy')
    expect(policyClass('REJECT')).toBe('warn')
    expect(policyClass('')).toBe('mut')
    expect(policyClass('FUTURE')).toBe('mut')
  })
})
