<script setup lang="ts">
// RateChart 是 ECharts 速率图，总览页用紧凑版、流量页用大图。
// 按需引入而非整包，产物小一个量级。
//
// 两个页面可能同时挂着实例（总览用 v-show 常驻），所以这里用 ResizeObserver
// 判断容器宽度：隐藏时宽度为 0，直接跳过 setOption，不给看不见的 canvas 每秒重绘。
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { Sample } from '../types'
import { formatClock, formatRate } from '../format'

echarts.use([LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer])

const props = defineProps<{
  series: Sample[]
  compact?: boolean
}>()

const el = ref<HTMLElement | null>(null)
let chart: echarts.ECharts | null = null
let ro: ResizeObserver | null = null

const hasData = computed(() => props.series.length > 0)

/**
 * 从 style.css 的 token 里取色，而不是在这里再抄一份十六进制。
 *
 * 原来图表里的 #3b82f6 / #8b95a7 / #272d37 是手抄的第二份色板：
 * 设计层改一次颜色，界面其他地方都跟了，只有这张图还停在旧色上。
 */
function palette() {
  const cs = getComputedStyle(document.documentElement)
  const v = (name: string) => cs.getPropertyValue(name).trim()
  return {
    up: v('--accent'),
    down: v('--ok'),
    text: v('--muted'),
    grid: v('--line-2'),
    surface: v('--surface-3')
  }
}

/** 面积从 26% 不透明度衰减到 0：平涂一块色会把曲线"压扁"成色块。 */
function fade(rgb: string, alpha: number): string {
  return `rgba(${rgb}, ${alpha})`
}

/** 把 "#3b82f6" 拆成 echarts 渐变要的 "59,130,246"。 */
function rgbTriplet(hex: string): string {
  const m = /^#?([\da-f]{2})([\da-f]{2})([\da-f]{2})$/i.exec(hex)
  if (!m) {
    return '255,255,255'
  }
  return `${parseInt(m[1], 16)},${parseInt(m[2], 16)},${parseInt(m[3], 16)}`
}

function option(): echarts.EChartsCoreOption {
  const pts = props.series
  const compact = !!props.compact
  const c = palette()
  const rgb = { up: rgbTriplet(c.up), down: rgbTriplet(c.down) }

  const line = (name: string, key: 'up' | 'down', color: string, data: [number, number][]) => ({
    name,
    type: 'line',
    showSymbol: false,
    // 极轻的平滑：完全折线读起来像示波器，太圆滑又会把真实的尖峰抹平。
    smooth: 0.16,
    smoothMonotone: 'x',
    sampling: 'lttb',
    lineStyle: { color, width: 1.8 },
    areaStyle: {
      color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
        { offset: 0, color: fade(rgb[key], 0.26) },
        { offset: 1, color: fade(rgb[key], 0) }
      ])
    },
    data
  })

  return {
    backgroundColor: 'transparent',
    animation: false,
    grid: { left: compact ? 52 : 60, right: 14, top: compact ? 12 : 40, bottom: compact ? 18 : 28, containLabel: false },
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(23, 28, 37, 0.94)',
      borderColor: 'rgba(255,255,255,0.12)',
      borderWidth: 1,
      padding: [8, 11],
      extraCssText: 'border-radius:10px;box-shadow:0 8px 28px rgba(0,0,0,.55);backdrop-filter:blur(12px)',
      textStyle: { color: '#f2f4f8', fontSize: 12 },
      axisPointer: {
        type: 'line',
        lineStyle: { color: 'rgba(255,255,255,0.22)', width: 1, type: [4, 4] }
      },
      formatter: (params: unknown) => {
        // axis 触发时 ECharts 传进来的是「同一时刻所有系列」的数组，顺序不保证，
        // 所以这里只借用 marker 与 seriesName，数值统一取自己的数组 pts。
        const arr = params as Array<{
          axisValue: number
          seriesName: string
          marker: string
          value: [number, number]
        }>
        if (!arr.length) {
          return ''
        }
        const head = `<div style="font-weight:600;margin-bottom:4px">${formatClock(arr[0].axisValue)}</div>`
        const body = arr
          .map(
            (p) =>
              `<div style="display:flex;align-items:center;gap:6px">${p.marker}` +
              `<span style="opacity:.7">${p.seriesName}</span>` +
              `<b style="margin-left:auto;font-variant-numeric:tabular-nums">${formatRate(p.value[1])}</b></div>`
          )
          .join('')
        return `${head}${body}`
      }
    },
    legend: compact
      ? { show: false }
      : {
          data: ['上行', '下行'],
          top: 6,
          right: 4,
          itemWidth: 10,
          itemHeight: 10,
          itemGap: 16,
          // 默认的"线段加圆点"图例看起来像控件坏了，换成一块小圆角方块。
          icon: 'roundRect',
          textStyle: { color: c.text, fontSize: 12 }
        },
    xAxis: {
      type: 'time',
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: {
        color: c.text,
        fontSize: 11,
        hideOverlap: true,
        formatter: (v: number) => formatClock(v)
      },
      splitLine: { show: false }
    },
    yAxis: {
      type: 'value',
      // 不写轴名：那条孤零零挂在左上角的 "B/s" 既不在刻度旁边也不在标题旁边。
      // 卡片标题已经说了"速率"，悬停里给的是完整的 "10.4 MB/s"，单位不会丢。
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: {
        color: c.text,
        fontSize: 11,
        formatter: (v: number) => formatRate(v).replace('/s', '')
      },
      // 虚线网格比实线轻，密一点也不要紧——实线一密就成了栅格纸。
      splitLine: { lineStyle: { color: c.grid, type: [3, 5], width: 1 } }
    },
    series: [
      line('上行', 'up', c.up, pts.map((p) => [p.t, p.up])),
      line('下行', 'down', c.down, pts.map((p) => [p.t, p.down]))
    ]
  }
}

function sizeOf(): number {
  return el.value?.clientWidth ?? 0
}

function render(): void {
  if (!chart || sizeOf() === 0) {
    return
  }
  // notMerge=true 表示不与旧配置合并、直接整体替换：点数每秒都在变，
  // 合并反而要额外处理新旧长度不一致。代价是丢掉动画过渡，
  // 但采样间隔本来就 1 秒，平滑动画在这里只会让曲线看起来在追赶。
  chart.setOption(option(), { notMerge: false, lazyUpdate: true })
}

/** 从隐藏切到可见时容器才有宽度，这时必须补一次 resize + 重绘。 */
function onResize(): void {
  if (!chart || sizeOf() === 0) {
    return
  }
  chart.resize()
  render()
}

watch(() => [props.series, props.compact], render)

onMounted(() => {
  if (!el.value) {
    return
  }
  chart = echarts.init(el.value, undefined, { renderer: 'canvas' })
  render()
  if (typeof ResizeObserver !== 'undefined') {
    ro = new ResizeObserver(onResize)
    ro.observe(el.value)
  } else {
    window.addEventListener('resize', onResize)
  }
})

onBeforeUnmount(() => {
  ro?.disconnect()
  ro = null
  window.removeEventListener('resize', onResize)
  chart?.dispose()
  chart = null
})
</script>

<template>
  <div>
    <div ref="el" class="chart" :class="{ compact }"></div>
    <p v-if="!hasData" class="empty">
      还没有采样点。启动代理并产生流量后，这里会逐秒增长。
    </p>
  </div>
</template>
