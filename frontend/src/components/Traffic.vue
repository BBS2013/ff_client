<script setup lang="ts">
// Traffic 把「速率曲线 + 连接明细」放在同一屏：看图发现异常，往下滚就是明细，
// 不用在两个页签之间来回跳。
//
// 这里不做时间窗切换：后端环形缓冲就是 900 点 / 15 分钟，
// 摆一个「1 分钟 / 15 分钟 / 全程」的按钮组出来，其中两个选项是同一个东西。
import Amount from './Amount.vue'
import RateChart from './RateChart.vue'
import ConnectionsTable from './ConnectionsTable.vue'
import type { TrafficSnapshot } from '../types'
import { computed, ref } from 'vue'
import { clearUsageStats, errorText } from '../api'
import { formatAgo, formatBytes } from '../format'

const props = defineProps<{
  traffic: TrafficSnapshot
  busy: string
  /** 总览跳过来时要直接套上的走向档，见 ConnectionsTable 的同名 prop。 */
  seedWay?: string
}>()

// 「各节点用量」那一行点下去要动的是下面那张连接表的过滤条件，
// 而那个条件住在 ConnectionsTable 里面。把整个过滤状态下提到这里来管，
// 就得把 kw / way / onlyNode 三个都搬一遍——为了一个点击动作拆掉一个自洽的小组件不划算，
// 所以这里只留一个入口：子组件 expose 出来的 filterByNode。
const connTable = ref<InstanceType<typeof ConnectionsTable> | null>(null)

/** 条形按最大那一档归一：绝对值已经写在右边了，条只管"谁多谁少"。 */
function barWidth(bytes: number): string {
  if (nodeMax.value <= 0) {
    return '0%'
  }
  return `${Math.max(2, Math.round((bytes / nodeMax.value) * 100))}%`
}

/**
 * 点一行 = 让下面那张连接表只列走这个节点的连接（再点一次取消）。
 * 顺带把表滚进视野：不滚的话，点完这屏看上去什么都没变，
 * 而这一行存在的意义就是"这 3GB 是谁用掉的、都花在哪些连接上"。
 */
function focusRule(rule: string): void {
  connTable.value?.filterByRule(rule)
}

function focusNode(node: string): void {
  connTable.value?.filterByNode(node)
  ;(connTable.value?.$el as HTMLElement | undefined)?.scrollIntoView({ block: 'start', behavior: 'smooth' })
}

/** 一行的总量：本次双向 + 上一次进程留下的那份。条、排序、"累计"三个字用的是同一个数。 */
function nodeTotal(n: TrafficSnapshot['byNode'][number]): number {
  return n.up + n.down + n.prior
}

const nodeMax = computed(() => {
  let m = 0
  for (const n of props.traffic.byNode) {
    m = Math.max(m, nodeTotal(n))
  }
  return m
})

const hasPrior = computed(() => props.traffic.byNode.some((n) => n.prior > 0))

/**
 * 那句"累计是从哪来的"。
 *
 * 非写不可的理由：这一栏从此不再是"本次会话"的数，而"累计"两个字天然让人觉得它精确。
 * 它不精确——最后一次落盘之后到崩溃之前那一段是丢掉的，所以它只会少算、不会多算。
 * 这句得摆在版面上，不能只留在代码注释里（见 README §9.5.2）。
 */
const priorNote = computed(() => {
  if (!hasPrior.value) {
    return ''
  }
  const t = props.traffic
  const since = t.priorSince
    ? `自 ${new Date(t.priorSince).toLocaleDateString('zh-CN', { month: '2-digit', day: '2-digit' })} 起算`
    : '起点未知（那份账本没带起点）'
  const saved = t.priorSavedAt ? `，最后一次落盘 ${formatAgo(t.priorSavedAt)}` : ''
  return `累计是跨重启的：${since}${saved}。崩溃或强杀会丢掉那之后的量——这一栏只会少算，不会多算。`
})

/**
 * 账本被拒之门外时的那两句话。
 *
 * 为什么值得单独写：这两种情况下"累计"会整个从界面上消失，而它消失的样子
 * 和"这是一台新装的机器"一模一样。用户看到的是一个没有累计的流量页，
 * 想到的是"这程序是不是没在记账"，而真相是"记了，但这个版本读不懂"
 * 或"文件坏了，已经挪走备查"。处置方式完全不同，所以话要分开说。
 */
const usageProblem = computed(() => {
  switch (props.traffic.usageState) {
    case 'too-new':
      return '跨重启的累计这一档暂时不显示：那份账本是比本程序更新的格式，本程序既不套用也不回写它（所以它不会被覆盖）。用写出它的那个版本跑一次就会恢复。'
    case 'unreadable':
      return '跨重启的累计这一档暂时不显示：那份账本读不出来，坏掉的原文件已挪到旁边留作证据（同名加 .bad），本次从空账开始记。'
    default:
      return ''
  }
})

const usageBusy = ref(false)
const usageError = ref('')

/**
 * 「累计也清零」是这一页唯一不可恢复的动作，所以点它要先问一句，
 * 而且要把"要毁掉什么"写进问句：只写「确定吗？」的确认框等于让人闭着眼睛点第二下。
 *
 * 旁边那个「清空统计」刻意不问——它清的是本次会话的数，等几分钟就回来了。
 * 两个都问会把确认变成条件反射，那时候真正该拦的那一个也拦不住了。
 */
function confirmClearUsage(): boolean {
  const nodes = props.traffic.byNode.filter((n) => n.prior > 0)
  if (nodes.length === 0) {
    return true // 没有累计可毁（正常走不到这里：那一格没账时按钮根本不渲染）
  }
  const total = nodes.reduce((s, n) => s + n.prior, 0)
  const top = nodes.reduce((a, n) => (n.prior > a.prior ? n : a), nodes[0])
  const from = props.traffic.priorSince
    ? new Date(props.traffic.priorSince).toLocaleString('zh-CN', { hour12: false })
    : '（没有起点）'
  return window.confirm(
    `要清掉「跨重启累计」吗？\n\n` +
      `现在累计 ${formatBytes(total)}（最大一档：${top.node} ${formatBytes(top.prior)}），自 ${from} 起算。\n` +
      `这一步不可恢复：那份账本会被重写。本次会话的读数不受影响。`
  )
}

async function clearUsage(): Promise<void> {
  if (!confirmClearUsage()) {
    return
  }
  usageBusy.value = true
  usageError.value = ''
  try {
    await clearUsageStats()
  } catch (e) {
    usageError.value = errorText(e)
  } finally {
    usageBusy.value = false
  }
}

const emit = defineEmits<{
  (e: 'reset'): void
  (e: 'rule', host: string): void
  (e: 'fetch', url: string): void
  (e: 'dns', host: string): void
  (e: 'seededWay'): void
}>()
</script>

<template>
  <div class="view">
    <div class="stats five">
      <div class="stat up">
        <b class="up"><Amount :text="formatBytes(traffic.totalUp)" /></b>
        <span>累计上行</span>
      </div>
      <div class="stat down">
        <b class="down"><Amount :text="formatBytes(traffic.totalDown)" /></b>
        <span>累计下行</span>
      </div>
      <div class="stat">
        <b><Amount :text="formatBytes(traffic.totalUp + traffic.totalDown)" /></b>
        <span>总流量</span>
      </div>
      <div class="stat">
        <b>{{ traffic.totalConns }}</b>
        <span>累计连接</span>
      </div>
      <div class="stat blocked">
        <b class="blocked">{{ traffic.totalBlocked }}</b>
        <span>累计拦截</span>
      </div>
    </div>

    <!-- 「累计拦截」这四个字背后是一件应用侧完全静默的事：不回拒绝、只让它超时。
         这句话以前只挂在 title 上，触屏、键盘和截图都读不到，所以摆在版面上。 -->
    <p class="hint">
      累计拦截是命中拦截名单被静默丢掉的连接数（含还没收尾的）：应用那边收不到任何原因，
      这一格、下面的连接表和日志是本机唯一的凭据。点「清空统计」或重启面板都会把它归零。
    </p>

    <!-- 这几个数字的口径。不写清楚的话，「总流量」会被读成「这台机器上了多少网」，
         而它其实是「本进程搬了多少字节」。 -->
    <p class="hint">
      这几格是<b>本进程经手的载荷</b>：从 SOCKS5 / HTTP / TUN 进来的连接搬了多少字节
      （本次会话；下面「各节点用量」那一档的「累计」另含上一次进程落盘留下的账）。
      它<b>不是</b>「这台机器的上网流量」——选择性 TUN 下判成直连的真 IP 流量根本不进 tun，不计入；
      全局接管下进了 tun 的 TCP/UDP 才算，ICMP 等其它协议不走隧道，也不计入。
      系统网卡总流量与进程级归属本面板都不采集：前者要读网卡计数（含协议头与重传），
      后者要 socket 归属、权限与兼容性另议——两者都不与这里的字节统计混为一谈。
    </p>

    <section class="card">
      <h2>实时速率 · 最近 15 分钟</h2>
      <RateChart :series="traffic.series" />
    </section>

    <section class="card">
      <h2>
        按规则汇总
        <span class="count">本次会话 · 谁在搬流量</span>
      </h2>
      <!-- 节点那张表答"量记在哪个去处"，这张答"是哪条规则放行的"。
           两者不能互相替代：节点会随故障切换而变，规则不会。 -->
      <p v-if="traffic.byRule.length === 0" class="mut">
        还没有按规则归类的流量。跑起来之后这里按命中依据分行，最后一行可能是若干条规则的合并。
      </p>
      <ul v-else class="nodes">
        <li v-for="row in traffic.byRule" :key="row.rule">
          <button
            v-if="!row.folded"
            type="button"
            class="name mono node-link"
            :title="`只看命中 ${row.rule} 的连接（再点一次取消）`"
            @click="focusRule(row.rule)"
          >
            {{ row.rule }}
          </button>
          <!-- 合并行不接筛选：它不是一条规则，点下去筛不出任何东西。 -->
          <span v-else class="name mono mut">{{ row.rule }}</span>
          <span class="bar" :style="{ width: barWidth(row.up + row.down) }" aria-hidden="true"></span>
          <span class="amt"><Amount :text="formatBytes(row.up + row.down)" /></span>
          <span class="mut detail">
            ↑{{ formatBytes(row.up) }} · ↓{{ formatBytes(row.down) }} · {{ row.conns }} 条
            <template v-if="row.folded">· 由 {{ row.folded }} 条规则合并</template>
          </span>
        </li>
      </ul>
      <p class="hint">
        口径提醒：这张表只数**真的搬过字节**的连接，与规则页那一栏「命中次数」不是一件事——
        被拦下与拨不通的都算命中，却一个字节也没有。
        直连真 IP 或 DoH 那类拿不到域名的流量只会命中 IP/端口类规则，域名规则对它不生效。
      </p>
    </section>

    <section class="card">
      <h2>
        各节点用量
        <span class="count">{{ hasPrior ? '本次 + 跨重启累计' : '本次会话累计' }}</span>
      </h2>
      <!-- 这张表存在的理由：节点会自动切换。切换之后只看总数回答不了
           "这个月的量是谁用掉的"，而很多节点的流量是按配额算的。 -->
      <p v-if="traffic.byNode.length === 0" class="mut">
        本次还没有记到任何去处名下的流量。跑起来之后这里会按节点分行，直连单独算一行。
      </p>
      <ul v-else class="nodes">
        <li v-for="n in traffic.byNode" :key="n.node">
          <button
            type="button"
            class="name mono node-link"
            :title="`只看走 ${n.node} 的连接（再点一次取消）`"
            @click="focusNode(n.node)"
          >
            {{ n.node }}
          </button>
          <span class="bar" :style="{ width: barWidth(nodeTotal(n)) }" aria-hidden="true"></span>
          <span class="amt"><Amount :text="formatBytes(nodeTotal(n))" /></span>
          <span class="mut detail">
            ↑{{ formatBytes(n.up) }} · ↓{{ formatBytes(n.down) }} · {{ n.conns }} 条
            <template v-if="n.prior > 0">· 上次进程 {{ formatBytes(n.prior) }}</template>
          </span>
        </li>
      </ul>
      <p v-if="priorNote" class="hint">{{ priorNote }}</p>
      <p v-if="usageProblem" class="alert warn">{{ usageProblem }}</p>
      <p v-if="hasPrior" class="hint">
        「累计也清零」是给按月计费的节点用的：重新起算，界面上那句"自 X 起算"跟着改。
        它和「清空统计」不是一件事——后者只清本次会话，误点不该抹掉一个月的账。
        点它会先问一句，问句里写着要清掉多少、从什么时候起算的那份账。
        <button
          type="button"
          class="btn sm ghost"
          :disabled="usageBusy || busy !== ''"
          @click="clearUsage"
        >
          {{ usageBusy ? '正在清…' : '累计也清零' }}
        </button>
      </p>
      <p v-if="usageError" class="alert warn">累计没清掉：{{ usageError }}</p>
      <p class="hint">
        直连单独一行（那些字节没走节点）；被拦的不占行，它一个字节都没有。
        自动切换过节点时，这里会同时列出用过的每一个节点——这正是这张表要回答的问题。
        点左边那个名字，下面的连接表就只列走它的连接；连接表「走向」那一格里也各自写着节点名，
        两张表说的是同一个字符串。
      </p>
    </section>

    <ConnectionsTable
      ref="connTable"
      :traffic="traffic"
      :busy="busy"
      :seed-way="seedWay"
      @reset="emit('reset')"
      @rule="(host) => emit('rule', host)"
      @fetch="(url) => emit('fetch', url)"
      @dns="(host) => emit('dns', host)"
      @seeded-way="emit('seededWay')"
    />
  </div>
</template>

<style scoped>
.nodes {
  list-style: none;
  margin: var(--sp-2) 0 0;
  padding: 0;
  display: grid;
  gap: 6px;
}
.nodes li {
  display: grid;
  grid-template-columns: minmax(90px, 1.4fr) minmax(40px, 3fr) auto;
  gap: 4px 10px;
  align-items: center;
}
.nodes .name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
/* 名字现在是个按钮，但点下去只是给下面那张表加一个过滤条件——
   不值得为此多一个视觉块，所以外观维持原来那行文本，只给可点的线索。 */
.nodes .node-link {
  appearance: none;
  background: none;
  border: 0;
  margin: 0;
  padding: 0;
  font: inherit;
  color: inherit;
  text-align: left;
  cursor: pointer;
}
.nodes .node-link:hover,
.nodes .node-link:focus-visible {
  text-decoration: underline;
}
.nodes .bar {
  height: 6px;
  border-radius: 3px;
  background: linear-gradient(90deg, var(--accent, #6aa6ff), rgba(106, 166, 255, 0.35));
  min-width: 2px;
}
.nodes .amt {
  justify-self: end;
  font-variant-numeric: tabular-nums;
}
.nodes .detail {
  grid-column: 2 / -1;
  font-size: var(--fs-caption);
}
</style>
