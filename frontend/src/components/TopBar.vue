<script setup lang="ts">
// TopBar 是常驻工具栏：不管当前在哪一页，都要能一眼看到「现在怎么走」，
// 并且不翻页就能启停、换模式、换节点。
//
// 它只读 App.vue 已有的数据（Status + 最后一个采样点），不自己发请求：
// profiles 与 activeProfile 本来就在 Status 里，多开一条轮询纯属浪费。
//
// 版式：左边是「在哪页 + 跑得怎么样」，右边是「我要做什么」。
// 原来品牌、状态灯、模式、节点、速率、两个开关、启停全挤在同一条里没有主次，
// 品牌已经搬去侧栏，这里就只剩状态与动作两组。
import { computed } from 'vue'
import type { Pending, Sample, Status } from '../types'
import { formatDuration, formatRate } from '../format'

const props = defineProps<{
  /** 当前页名，让翻页在顶部也有反馈。 */
  title: string
  status: Status
  last: Sample | null
  busy: string
  pending: Pending
  /** 是否已经成功读到过至少一帧状态。没读到过时这一排不许写「已停止」「未配置节点」。 */
  ready: boolean
  /** 曾经读到过、现在读不到：非空时是"界面停在几点"。旧数字长得和实时数字一样，必须点名。 */
  staleAt: string
}>()

const emit = defineEmits<{
  (e: 'start'): void
  (e: 'stop'): void
  (e: 'mode', mode: string): void
  (e: 'profile', name: string): void
}>()

const MODES = [
  { id: 'rule', label: '规则' },
  { id: 'global', label: '全局' },
  { id: 'direct', label: '直连' }
]

const running = computed(() => props.status.running)
const idle = computed(() => props.busy !== '')
const uptime = computed(() => (running.value ? formatDuration(props.status.uptimeMs) : '—'))
// 停更时速率必须跟着变空：那两个字是"实时上行/下行"，把最后一次采样继续挂着，
// 等于在 LED 已经承认"读数停了"的同一排里，旁边两个数字装作还是活的。
const up = computed(() => (props.staleAt || !props.last ? '—' : formatRate(props.last.up)))
const down = computed(() => (props.staleAt || !props.last ? '—' : formatRate(props.last.down)))
const mode = computed(() => props.pending.mode ?? props.status.mode)
const profile = computed(() => props.pending.profile ?? props.status.activeProfile)
</script>

<template>
  <header class="topbar">
    <h1 class="page-title">{{ title }}</h1>
    <span class="bar-sep" aria-hidden="true"></span>

    <span
      class="led"
      :class="{
        on: ready && running && !staleAt,
        live: ready && running && !staleAt,
        stale: !!staleAt
      }"
      :aria-label="
        staleAt
          ? `读不到后端状态，界面停在 ${staleAt}`
          : !ready
            ? '读不到后端状态'
            : running
              ? `代理运行中，已运行 ${uptime}`
              : '代理已停止'
      "
    >
      <i aria-hidden="true"></i>
      {{ staleAt ? '读数停止更新' : ready ? (running ? '运行中' : '已停止') : '状态未知' }}
      <b>{{ staleAt ? `停在 ${staleAt}` : uptime }}</b>
    </span>

    <span class="grow"></span>

    <span class="rate" aria-label="实时速率">
      <span class="r">
        <svg class="arrow" viewBox="0 0 12 12" aria-hidden="true"><path d="M6 10V2.4M2.8 5.6 6 2.4l3.2 3.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <b class="up">{{ up }}</b>
      </span>
      <span class="r">
        <svg class="arrow" viewBox="0 0 12 12" aria-hidden="true"><path d="M6 2v7.6M2.8 6.4 6 9.6l3.2-3.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <b class="down">{{ down }}</b>
      </span>
    </span>

    <div class="seg" role="group" aria-label="分流模式">
      <button
        v-for="m in MODES"
        :key="m.id"
        type="button"
        :class="{ on: mode === m.id }"
        :disabled="idle"
        :title="m.id === 'rule' ? '按规则集分流：国内直连，被墙域名走隧道' : m.id === 'global' ? '所有流量都走当前节点，规则集不参与' : '所有流量都直连，隧道闲置'"
        @click="emit('mode', m.id)"
      >
        {{ m.label }}
      </button>
    </div>

    <label class="picker">
      <span class="picker-label">节点</span>
      <select
        :value="profile"
        :disabled="idle || !ready || status.profiles.length === 0"
        @change="emit('profile', ($event.target as HTMLSelectElement).value)"
      >
        <option v-if="status.profiles.length === 0" value="">
          {{ ready ? '未配置节点' : '读不到节点' }}
        </option>
        <option v-for="p in status.profiles" :key="p.name" :value="p.name">
          {{ p.name }} · {{ p.type || '—' }}
        </option>
      </select>
      <!-- 自动切换必须看得出来：否则用户选过的节点自己变了，却没有任何地方解释。 -->
      <span v-if="status.autoSwitched" class="auto" :title="status.switchReason || ''">
        自动
      </span>
    </label>

    <button v-if="!running" type="button" class="btn primary" :disabled="idle" @click="emit('start')">
      启动
    </button>
    <button v-else type="button" class="btn danger" :disabled="idle" @click="emit('stop')">停止</button>
  </header>
</template>

<style scoped>
/* 工具栏里可缩的几样都给了 min-width:0 + 省略号：
   nowrap 之下不写这个的话，长文本会把右边的启停按钮直接顶出窗口。 */
.topbar > * {
  flex: 0 0 auto;
}

.page-title {
  flex: 0 0 auto;
}

/* 运行时长跟在状态词后面，用等宽数字，免得每秒跳字宽。 */
.led b {
  font-weight: 500;
  color: var(--fg);
  font-variant-numeric: tabular-nums;
}

/* 状态灯是这条里唯一会随文案长短大幅变化的一项，让它自己缩。 */
.topbar .led:first-of-type {
  flex: 0 1 auto;
  min-width: 0;
  overflow: hidden;
}

.led[disabled] {
  opacity: 0.5;
}

button.led {
  font: inherit;
  cursor: pointer;
  transition: background var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease),
    color var(--dur-fast) var(--ease);
}

button.led:hover:not(:disabled) {
  border-color: var(--line-3);
  color: var(--fg);
  background: rgba(255, 255, 255, 0.08);
}

button.led:active:not(:disabled) {
  transform: scale(0.975);
}

/* 读数停止更新：琥珀色，且不去点亮那个绿色的"运行中"灯。
   停更时的画面是"代理还在跑、只是我看不见了"，跟"代理停了"必须区分开。 */
.led.stale {
  color: var(--warn-bright);
  border-color: var(--warn-line);
  background: var(--warn-bg);
}

.led.stale i {
  background: var(--warn);
  box-shadow: 0 0 8px rgba(251, 191, 36, 0.85);
}

/* 实时速率：箭头用图形而不是 ↑↓ 字符——中英文混排时那两个箭头
   在不同字体下基线乱跳，跟旁边的数字对不齐。 */
.rate {
  display: inline-flex;
  align-items: center;
  gap: var(--sp-3);
}

.rate .r {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.rate .arrow {
  width: 11px;
  height: 11px;
  flex: 0 0 auto;
}

.rate b {
  font-family: var(--mono);
  font-size: var(--fs-caption);
  font-weight: 500;
  font-variant-numeric: tabular-nums;
  letter-spacing: -0.01em;
}

.rate .up {
  color: var(--accent-bright);
}

.rate .down {
  color: var(--ok-bright);
}

/* 节点选择器：标签与下拉框是一组。下拉框给上限而不给下限，
   节点名很长时它自己截断，不去挤压右边的控件。 */
.picker {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  min-width: 0;
  font-size: var(--fs-caption);
  color: var(--muted);
}

.picker select {
  font-size: var(--fs-sm);
  min-width: 0;
  max-width: 158px;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* 自动切换的标记：小、不抢节点名的位置，但要一眼能看到。
   悬停出完整理由，是因为理由里带失败次数与目标数，展开会把顶栏挤变形。 */
.picker .auto {
  padding: 2px 7px;
  border: 1px solid var(--warn-line);
  border-radius: var(--r-pill);
  font-size: var(--fs-micro);
  font-weight: 500;
  line-height: 1.5;
  color: var(--warn-bright);
  background: var(--warn-bg);
  cursor: help;
  white-space: nowrap;
}
</style>
