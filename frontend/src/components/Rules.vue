<script setup lang="ts">
// Rules 只管分流：自定义域名规则（哪些走代理、哪些直连）+ 「这个域名现在怎么走」的探测。
import { onBeforeUnmount, onMounted, ref } from 'vue'
import type { BlockView, BlockedHit, Status, UserRule } from '../types'
import { errorText } from '../api'
import BlockList from './BlockList.vue'
import ProbePanel from './ProbePanel.vue'
import RulesMeta from './RulesMeta.vue'
import UserRuleTable from './UserRuleTable.vue'

const props = defineProps<{
  status: Status
  /** 本次运行累计被拦的条数，来自连接注册表：名单装着却一条都没拦到，也该看得见。 */
  blockedTotal: number
  /**
   * 最近被拦的目标（新→旧，上限 32 条）。连接表是几百条的环形流水，
   * 一个页面就能把刚才那批广告请求冲掉；拦截又完全静默，
   * 所以"刚才那个拦住了吗"得有一份不随流水滚走的答案。
   */
  recentBlocked: BlockedHit[]
  /**
   * 从连接表「加规则」带过来的域名。非空就填进上面那张表单并聚焦，
   * 然后立刻用 seeded 事件请父级清空——不清空的话，用户下次自己进规则页
   * 会被一个上一次留下的域名占着表单。
   */
  seed?: string
  /**
   * 从流量页那条「拨不通」的连接带过来的一个网址（已经拼好协议）。
   * 填进「取一个真页面」并聚焦，**不自动跑**：协议是照端口猜的，让人看一眼再按回车。
   */
  fetchSeed?: string
  /** 从流量页那条失败连接带过来的域名：填进「看解析」并聚焦，不自动跑。 */
  dnsSeed?: string
}>()

const emit = defineEmits<{
  (e: 'seeded'): void
  (e: 'seededFetch'): void
  (e: 'seededDNS'): void
}>()

const notice = ref('')
const failure = ref('')
const busy = ref('')

const ruleTable = ref<{
  reload: () => Promise<string>
  loadWarnings: () => Promise<void>
} | null>(null)
const blockList = ref<{
  reload: () => Promise<string>
} | null>(null)
const rulesMeta = ref<{
  reload: () => Promise<string>
} | null>(null)

const rulesSnap = ref<UserRule[]>([])
const blockSnap = ref<BlockView | null>(null)
function onRules(list: UserRule[]): void {
  rulesSnap.value = list
}
function onBlock(list: BlockView | null): void {
  blockSnap.value = list
}

async function load(): Promise<void> {
  failure.value = ''
  // 两份名单各读各的：自定义规则读失败不该把拦截名单一起打成"读不到"，
  // 反过来也不行——两句话是两件事，混成一条「读取自定义规则失败」就会把人派去查错的地方。
  const errs: string[] = []
  const rulesPane = ruleTable.value
  const blockPane = blockList.value
  const metaPane = rulesMeta.value
  if (rulesPane === null || blockPane === null || metaPane === null) {
    return
  }
  const ruleErr = await rulesPane.reload()
  if (ruleErr !== '') {
    errs.push(ruleErr)
  }
  const blockErr = await blockPane.reload()
  if (blockErr !== '') {
    errs.push(blockErr)
  }
  if (errs.length > 0) {
    failure.value = `读取失败：${errs.join('；')}`
  }
  // 这两栏都不并进 errs：它们坏了不影响上面两份名单，
  // 混在一起会让"名单读不到"和"只是没读到订阅状态"看起来是同一种事故。
  await Promise.all([metaPane.reload(), rulesPane.loadWarnings()])
}

async function run(key: string, fn: () => Promise<void>, done: string): Promise<boolean> {
  if (busy.value !== '') {
    return false
  }
  busy.value = key
  notice.value = ''
  failure.value = ''
  try {
    await fn()
    notice.value = done
    await load()
    return true
  } catch (err) {
    failure.value = `${done.replace(/。$/, '')}失败：${errorText(err)}`
    return false
  } finally {
    busy.value = ''
  }
}
const page = {
  busy,
  notice,
  failure,
  load,
  run
}

// 5 秒一轮，与后端轮询规则文件的节奏对齐：面板上"上次生效"的时刻
// 因此最多滞后一轮，改完文件不用手动刷新页面就能看到它动起来。
//
// 这里整份重读（不只是监视与订阅那两栏）：这一页说的是"磁盘上现在有哪些规则"，
// 而 user-rules.txt 是可以被编辑器、被 `> file`、被另一台机器上的脚本改写的。
// 只刷监视栏就会出现最难查的一幕——监视说"刚按新文件重载过"，
// 下面那张表却还摆着旧名单，于是界面上一切看起来都对，内容是过期的。
let timer = 0
/**
 * 在途保护：一轮还没回来就不再叠一轮。
 *
 * 这不是为了省几个请求，而是为了顺序：这一轮会打七次后端（规则、节点、
 * 拦截、监视、订阅、警告、命中），慢的时候超过 5 秒是可能的。
 * 没有这把锁时两轮会叠着跑，后发的先回就先把旧名单写进表里，
 * 于是界面在"新 → 旧 → 新"之间跳，看起来像规则自己变回去了。
 */
let loading = false
/**
 * 窗口隐藏（托盘）时停表。
 *
 * 这一页是 v-if 挂卸的，但用户停在规则页再点关闭窗口时组件并不会卸载
 * （gui.go 是 HideWindowOnClose），于是那七次调用照旧每 5 秒打一次后端，
 * 而人根本看不见这一页。隐藏期间唯一在长的东西是日志。
 */
let hidden = false

async function tick(): Promise<void> {
  if (loading || hidden) {
    return
  }
  loading = true
  try {
    await load()
  } finally {
    loading = false
  }
}

function onVisibility(): void {
  const wasHidden = hidden
  hidden = document.hidden
  // 重新显示时立刻补一轮：隐藏期间磁盘上可能已经改过了，
  // 让人盯着 5 秒前的旧表没意义。
  if (wasHidden && !hidden) {
    void tick()
  }
}

onMounted(() => {
  hidden = document.hidden
  void tick()
  timer = window.setInterval(() => void tick(), 5000)
  document.addEventListener('visibilitychange', onVisibility)
  window.addEventListener('focus', onVisibility)
})
onBeforeUnmount(() => {
  // 这一页是 v-if 挂卸的：不摘定时器，切走之后它还在每 5 秒敲一次后端。
  window.clearInterval(timer)
  document.removeEventListener('visibilitychange', onVisibility)
  window.removeEventListener('focus', onVisibility)
})
</script>

<template>
  <div class="view rules-view">
    <p v-if="notice" class="banner">{{ notice }}</p>
    <p v-if="failure" class="alert">{{ failure }}</p>

    <UserRuleTable
      ref="ruleTable"
      :page="page"
      :seed="seed"
      @seeded="emit('seeded')"
      @rules="onRules"
    />

    <!-- 拦截名单：配置段维护，界面只读。放在自定义规则正下面，
         因为这页讲的就是"哪些域名出不出去"，少这一栏就只能去翻 YAML。 -->
    <BlockList
      ref="blockList"
      :page="page"
      :blocked-total="blockedTotal"
      :recent-blocked="recentBlocked"
      @block="onBlock"
    />

    <!-- 探测与内置规则集都是"看一眼"的信息，并排放，省一屏。 -->
    <div class="g2">
      <ProbePanel
        :page="page"
        :status="status"
        :rules="rulesSnap"
        :block="blockSnap"
        :fetch-seed="fetchSeed"
        :dns-seed="dnsSeed"
        @seeded-fetch="emit('seededFetch')"
        @seeded-dns="emit('seededDNS')"
      />
      <RulesMeta ref="rulesMeta" :status="status" />
    </div>
  </div>
</template>

<style src="./rules-panel.css"></style>
