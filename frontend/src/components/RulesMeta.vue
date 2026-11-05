<script setup lang="ts">
import { computed, ref } from 'vue'
import type { ProviderRefreshReport, RulesWatchView, Status, SubscriptionsView } from '../types'
import { errorText, refreshProviders, rulesWatch, subscriptions } from '../api'
import { formatAgo, formatBytes, geoipText, policyClass, policyText } from '../format'

// 内置规则集的计数直接取自 App.vue 已有的 Status，不额外发请求；
defineProps<{
  status: Status
}>()

// `watch` 这个名字在本组件里已经给了「规则文件监视」那一栏的读数，
// 所以这里带别名引进来，而不是把那个改名——它出现在模板里，改名要连界面一起动。
// 规则文件监视那一栏：服务在跑时改文件会自己生效，界面要能回答
// "被看着的是哪些文件、上次生效是什么时候"，否则"还在等第二轮"与"这功能没开"
// 在同一片空白里长得一模一样。

const watch = ref<RulesWatchView | null>(null)
const watchKnown = ref(false)
const watchStale = ref(false)
const watchError = ref('')

const pulling = ref(false)
const pullReport = ref<ProviderRefreshReport | null>(null)
const pullError = ref('')

/**
 * 「立即拉取」按下去之后要说得出**哪一条**怎么样了。
 *
 * 只回一句"完成"与按钮根本没动是同一个观感——所以逐条列：
 * 变了的说变了，失败的原样带出原因，重载失败更要单说，
 * 因为那一刻规则还是旧的，用户却刚看到"内容变了"。
 */
async function onPullNow(): Promise<void> {
  if (pulling.value) {
    return
  }
  pulling.value = true
  pullError.value = ''
  try {
    pullReport.value = await refreshProviders()
    await loadSubs()
  } catch (err) {
    pullReport.value = null
    pullError.value = errorText(err)
  } finally {
    pulling.value = false
  }
}

const pullText = computed(() => {
  const r = pullReport.value
  if (!r) {
    return ''
  }
  const changed = r.results.filter((x) => x.changed).map((x) => x.name)
  const failed = r.results.filter((x) => x.err !== '')
  const bits: string[] = []
  bits.push(changed.length ? `${changed.join('、')} 拿到新内容` : '没有一条拿到新内容')
  if (failed.length) {
    bits.push(`失败：${failed.map((x) => `${x.name}（${x.err}）`).join('；')}`)
  }
  if (r.reloadErr) {
    bits.push(`但规则重载失败，仍在用旧的那份：${r.reloadErr}`)
  } else if (r.reloaded) {
    bits.push('已按新内容重载规则')
  }
  return bits.join('。') + '。'
})

const pullBad = computed(() => {
  const r = pullReport.value
  return !!pullError.value || (!!r && (r.results.some((x) => x.err !== '') || r.reloadErr !== ''))
})

// 表头右侧那一小截：读不到 ≠ 读取中 ≠ 没在监视 ≠ 看着 N 个文件。
const watchHead = computed(() => {
  if (!watch.value) {
    return watchError.value ? '读不到' : '读取中…'
  }
  return watch.value.watching ? `看着 ${watch.value.files.length} 个文件` : '没在监视'
})

const subs = ref<SubscriptionsView | null>(null)
const subsKnown = ref(false)
const subsStale = ref(false)
const subsError = ref('')

async function loadSubs(): Promise<void> {
  try {
    const v = await subscriptions()
    if (!v) {
      subsError.value = '后端回了空读数'
      subsStale.value = subsKnown.value
      return
    }
    subs.value = v
    subsKnown.value = true
    subsStale.value = false
    subsError.value = ''
    if (!v.running && (pullReport.value || pullError.value)) {
      // 上一次「立即拉取」的结果属于那个还在跑的循环。循环停了还把它挂在下面，
      // 就成了「已按新内容重载规则」与「没在跑」同屏——两句都对，拼起来是假的。
      pullReport.value = null
      pullError.value = ''
    }
  } catch (err) {
    subsError.value = errorText(err)
    subsStale.value = subsKnown.value
  }
}

/** 订阅条数那一截：没配、配了没在跑、在跑，是三种不同的处境。 */
const subsHead = computed(() => {
  if (!subs.value) {
    return subsError.value ? '读不到' : '读取中…'
  }
  const v = subs.value
  if (v.configErr) {
    return '读不到配置'
  }
  if (!v.configured) {
    return '没配订阅'
  }
  return v.running ? `${v.items.length}/${v.configured} 条在拉` : '没在跑'
})

/** 周期只报最大那一档：配置写 24h 时"每 1天 0小时 0分"是噪音。 */
function everyText(sec: number): string {
  if (sec <= 0) {
    return '周期未知'
  }
  if (sec < 60) {
    return `${sec} 秒`
  }
  if (sec < 3600) {
    return `${Math.round(sec / 60)} 分钟`
  }
  if (sec < 86400) {
    return `${Math.round(sec / 3600)} 小时`
  }
  return `${Math.round(sec / 86400)} 天`
}

/** "还有多久"。formatAgo 是往回看的，未来的时刻交给它会说成"0 秒前"。 */
function formatAhead(ms: number): string {
  const left = ms - Date.now()
  if (ms <= 0) {
    return '未知'
  }
  if (left <= 0) {
    return '就在这一轮'
  }
  const m = Math.round(left / 60000)
  if (m < 60) {
    return `${m} 分后`
  }
  const h = Math.floor(m / 60)
  if (h < 24) {
    return `${h} 小时后`
  }
  return `${Math.floor(h / 24)} 天后`
}

async function loadWatch(): Promise<void> {
  try {
    const v = await rulesWatch()
    if (!v) {
      // 后端这里总该回一份读数。回了空就是没读到，说清楚，
      // 别让表头停在「读取中…」——那一档的意思是"还没轮到它"，不是"它坏了"。
      watchError.value = '后端回了空读数'
      watchStale.value = watchKnown.value
      return
    }
    watch.value = v
    watchKnown.value = true
    watchStale.value = false
    watchError.value = ''
  } catch (err) {
    // 错误写在这一栏自己身上，不抢页面顶部那条 failure：
    // 两份名单也可能同时读不到，共用一行就只会剩下一个原因，
    // 而"名单读不到"与"只是没读到文件时间"要派人去查的地方完全不同。
    watchError.value = errorText(err)
    watchStale.value = watchKnown.value
  }
}


async function reload(): Promise<string> {
  await Promise.all([loadWatch(), loadSubs()])
  return ''
}

defineExpose({ reload })
</script>

<template>
      <section class="card">
        <h2>内置规则集</h2>
        <dl class="kv">
          <dt>规则文件</dt>
          <dd class="mono">{{ status.rulesFile }}</dd>
          <dt>条数</dt>
          <dd>域名 {{ status.domainRules }} · IP {{ status.ipRules }}</dd>
          <dt>兜底</dt>
          <dd>
            <span class="pill" :class="policyClass(status.finalPolicy)">{{ policyText(status.finalPolicy) }}</span>
          </dd>
          <dt>GeoIP</dt>
          <dd>
            <span :class="status.geoipOk ? 'ok' : status.running && status.geoipPath ? 'warn' : 'mut'">
              {{ geoipText(status.geoipPath, status.geoipOk, status.running) }}
            </span>
            <span class="mono mut">{{ status.geoipPath }}</span>
          </dd>
          <template v-if="status.rulesSkipped.length">
            <dt>被跳过</dt>
            <dd class="warn">{{ status.rulesSkipped.join('、') }}</dd>
          </template>
        </dl>
      </section>

      <section class="card">
        <h2>
          规则文件（自动重载）
          <span class="count" :class="{ warn: !watch && !!watchError }">
            {{ watchHead }}
            <span v-if="watchStale" class="warn">· 读数已过期</span>
          </span>
        </h2>

        <p v-if="!watch" class="mut">
          {{ watchError ? `读不到监视状态：${watchError}` : '还没读到监视状态。' }}
        </p>
        <template v-else>
          <!-- 没在跑时不能说"0 个文件"：那读起来像"没有文件需要看"，
               而真实情况是"看了也不会生效"。两句话得各不相同。 -->
          <p v-if="!watch.watching" class="mut">
            代理没在跑，改规则文件不会自动生效；下次启动时才会按新文件加载。
            主文件路径写在上面的「内置规则集」里。
          </p>
          <template v-else>
            <p class="mut">
              每 {{ watch.intervalSec }} 秒看一轮，改动要连续两轮看到同一个状态才动手，
              所以改完最多等 {{ watch.intervalSec * 2 }} 秒出头生效。
              上一次生效：
              <strong v-if="watch.lastReload" class="mono">{{ watch.lastReload }}</strong>
              <span v-else>本次运行还没有过重载</span>。
            </p>
            <ul class="files">
              <li v-for="f in watch.files" :key="f.path">
                <span class="mono">{{ f.path }}</span>
                <span v-if="f.readable" class="mut">{{ formatBytes(f.size) }} · {{ f.modTime }}</span>
                <span v-else class="warn">读不到（文件此刻不在）</span>
              </li>
            </ul>
            <p class="mut">
              这里列的是引擎<strong>真的打开过</strong>的那些文件，含
              <span class="mono">#include</span> 进来的每一层——改这一列之外的文件不会触发重载。
            </p>
          </template>
        </template>
      </section>

      <section class="card">
        <h2>
          规则集订阅
          <span class="count" :class="{ warn: !subs && !!subsError }">
            {{ subsHead }}
            <span v-if="subsStale" class="warn">· 读数已过期</span>
          </span>
        </h2>

        <p v-if="!subs" class="mut">
          {{ subsError ? `读不到订阅状态：${subsError}` : '还没读到订阅状态。' }}
        </p>
        <template v-else-if="subs.configErr">
          <!-- 连配置都没读到，那"几条订阅"这种数字一个都不能报——
               报了就是在拿一份不存在的名册说话。 -->
          <p class="alert">读不到配置，这一栏的数字都不可信：{{ subs.configErr }}</p>
        </template>
        <template v-else-if="!subs.configured">
          <p class="mut">
            没配远程规则集。要用的话在 <span class="mono">config.yaml</span> 的
            <span class="mono">rule_providers:</span> 段里加一条（见 README §5.3）。
          </p>
        </template>
        <template v-else>
          <p v-if="!subs.running" class="mut">
            代理没在跑，这 {{ subs.configured }} 条订阅不会去拉；缓存还是磁盘上那份。
          </p>
          <p v-else class="mut">
            拉下来的内容先编译一遍才允许覆盖缓存；拉不到就用旧的那份，
            所以订阅断了分流不会走错路，只是规则停在上周那份上。
            <button type="button" class="btn" :disabled="pulling" @click="onPullNow">
              {{ pulling ? '拉取中…' : '立即拉取' }}
            </button>
          </p>

          <p v-if="pullError || pullReport" :class="pullBad ? 'alert' : 'notice'">
            {{ pullError ? `拉取失败：${pullError}` : pullText }}
          </p>
          <p v-if="subs.errors.length" class="alert">
            配置里 {{ subs.configured }} 条，实际在拉 {{ subs.items.length }} 条。
            这些条目在启动时被拒，从来没生效过：
            <span v-for="(e, i) in subs.errors" :key="i" class="mono err-line">{{ e }}</span>
          </p>

          <ul class="subs">
            <li v-for="x in subs.items" :key="x.name">
              <div class="head">
                <strong>{{ x.name }}</strong>
                <span class="mut">
                  每 {{ everyText(x.everySec) }} ·
                  {{ x.hasCache ? `缓存 ${formatBytes(x.size)}` : '缓存不在' }}
                </span>
              </div>
              <div class="state">
                <!-- 三件事各说各的，互不遮蔽：缓存不在、这次拉失败、上一次成功是几点。
                     最要命的是失败那一行——规则停在旧缓存上，此时"旧到什么时候"
                     恰恰是人最需要的那个数，不能因为报了失败就不说。 -->
                <span v-if="!x.hasCache" class="err">
                  这份缓存此刻不在磁盘上：它对应的那段规则现在没进引擎
                </span>
                <span v-if="x.fails > 0" class="err">
                  连着失败 {{ x.fails }} 次（最近一次 {{ formatAgo(x.lastAttemptMs) }}）：{{ x.lastErr }}
                </span>
                <span v-if="x.lastOkMs > 0" class="mut">上次拉于 {{ formatAgo(x.lastOkMs) }}</span>
                <template v-else-if="subs.running">
                  <span v-if="x.hasCache" class="mut">缓存是启动前补的那份，后台这一轮还没拉过</span>
                  <span v-else class="warn">这个进程还没成功拉过它</span>
                </template>
                <span v-if="subs.running && x.nextDueMs > 0" class="mut">· 下次 {{ formatAhead(x.nextDueMs) }}</span>
              </div>
              <div class="mut path mono">{{ x.path }}</div>
            </li>
          </ul>
          <p class="mut">
            这里只报订阅名与缓存路径，不报 URL：订阅地址常直接带鉴权 token，
            印出来就等于摊进截图里。
          </p>
        </template>
      </section>
</template>
