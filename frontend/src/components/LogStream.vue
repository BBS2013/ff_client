<script setup lang="ts">
// LogStream 只负责显示与过滤，拉取逻辑在 App.vue。
// 条目由 App.vue 按 Seq 增量合并好：后端报 Truncated 时整表替换，
// 否则追加。这里不再关心数据是怎么来的。
import { computed, nextTick, ref, watch } from 'vue'
import type { LogEntry } from '../types'

const props = defineProps<{
  entries: LogEntry[]
  truncated: boolean
  /** 第一批日志是否真的读到了。没读到之前"0 条"只能写"正在读"，不能写"还没有日志"。 */
  loaded: boolean
}>()

const keyword = ref('')
const follow = ref(true)
const body = ref<HTMLElement | null>(null)

const filtered = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  const min = level.value.min
  return props.entries.filter((e) => {
    if (min >= 0 && rankOf(e) < min) {
      return false
    }
    return kw === '' || e.msg.toLowerCase().includes(kw)
  })
})

/* ---------- 只画最后那几百行 ----------
   这一页自己攒的缓冲上限是 2000 行（App.vue 的 LOG_CAP；后端那份环形缓冲是 1000 条，
   两边不是一个数，别把它们说成一个）。一行是四个 span，命中的关键字再套一层 <mark>。
   本机实测（?demo=big，缓冲满 2000 行）切到这一页要 190ms 才画出来，
   而同一套导航里别的视图都在 33ms 那格——它们最多画 200 行（规则页那一档实测 100~133ms）。
   日志又和规则表不一样：它是"往下长"的，人打开就只看末尾那几十行，
   所以窗口开在尾部，前头那些留给人主动展开。
   过滤照旧走整份缓冲（上面那个 computed），藏起来的只是"画"这一步。 */
const LOG_WINDOW = 200
const logWindow = ref(LOG_WINDOW)
const shown = computed(() => {
  const all = filtered.value
  return all.length <= logWindow.value ? all : all.slice(all.length - logWindow.value)
})
const hiddenLines = computed(() => filtered.value.length - shown.value.length)

// 展开窗口是在末尾之上**追加**旧行，浏览器不会因此重算 scrollTop：
// 不重新贴底的话，点一下"再多画"，画面就悄悄从最新那行滑走了。
async function growWindow(): Promise<void> {
  logWindow.value += LOG_WINDOW
  await nextTick()
  if (follow.value && body.value) {
    body.value.scrollTop = body.value.scrollHeight
  }
}

/** 快捷过滤用的关键字：与日志里那行「… 拦截 <目标> […]」的动词一致。 */
const BLOCK_FILTER = '拦截'

const quickOn = computed(() => keyword.value.trim() === BLOCK_FILTER)

function toggleQuick(): void {
  keyword.value = quickOn.value ? '' : BLOCK_FILTER
}

/**
 * 级别过滤用的是「**及以上**」，不是精确匹配。
 *
 * 这一页最常见的动作是"有没有出过事"，而旧的那排按钮是精确匹配：
 * 点 WARN 就看不到 ERROR，于是回答这个问题要点两次、记两个数。
 * 改成阈值之后一格就够：≥ WARN 就是"警告和错误"。
 * 想单看某一级的具体那行，用旁边的关键字框——那才是它擅长的。
 *
 * 少了一个按钮不是少了功能：≥ DEBUG 与「全部」是同一件事（DEBUG 已经是最低级），
 * 摆两个选项出来其中一个是另一个的别名，只会让人以为它们有区别。
 */
const LEVELS = [
  { label: '全部', min: -1, title: '所有级别都显示' },
  { label: '≥ INFO', min: 1, title: '只显示 INFO 及以上（藏掉 DEBUG）' },
  { label: '≥ WARN', min: 2, title: '只显示 WARN 与 ERROR：有没有出事看这一档' },
  { label: '≥ ERROR', min: 3, title: '只显示 ERROR' }
] as const

const RANK: Record<string, number> = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 }
const levelIdx = ref(0)

/**
 * 读不出级别的行按最低一档算（后端 `Level.String()` 是封闭集合，正常不会走到这里）。
 * 判成"最高"会让一条读不懂的行冒充错误，判成最低只是它被阈值藏起来——
 * 后者是更便宜的错。
 */
function rankOf(e: LogEntry): number {
  return RANK[e.level] ?? 0
}

const level = computed(() => LEVELS[levelIdx.value])

// 换过滤条件等于换了一份"要看的东西"，窗口回到尾部那一两百行：
// 留着上一次展开的几千行，人从长名单切回短名单时最容易误以为界面卡住了。
// 这一格必须排在 levelIdx 之后：watch 的依赖数组是 setup 里同步求值的，
// 放在它上面会在组件建立时就读到 TDZ 里的 ref，整页直接白。
watch([levelIdx, keyword], () => {
  logWindow.value = LOG_WINDOW
})

/** 每档的条数按阈值累加着数出来，与按钮的语义一致：≥ WARN 那颗上的数就是 WARN+ERROR。 */
const tally = computed(() => {
  const t = [-1, 0, 0, 0]
  for (const e of props.entries) {
    const r = rankOf(e)
    for (let i = 1; i < t.length; i++) {
      if (r >= i) {
        t[i]++
      }
    }
  }
  t[0] = props.entries.length
  return t
})

/** 把命中的关键字切出来单独着色。不用 v-html：日志内容是外部输入。 */
const parts = computed(() => {
  const kw = keyword.value.trim()
  if (!kw) {
    return null
  }
  const lower = kw.toLowerCase()
  return (msg: string): Array<{ text: string; hit: boolean }> => {
    const out: Array<{ text: string; hit: boolean }> = []
    let rest = msg
    for (;;) {
      const i = rest.toLowerCase().indexOf(lower)
      if (i < 0) {
        out.push({ text: rest, hit: false })
        return out
      }
      if (i > 0) {
        out.push({ text: rest.slice(0, i), hit: false })
      }
      out.push({ text: rest.slice(i, i + kw.length), hit: true })
      rest = rest.slice(i + kw.length)
    }
  }
})

function split(msg: string): Array<{ text: string; hit: boolean }> {
  return parts.value ? parts.value(msg) : [{ text: msg, hit: false }]
}

// 跟随滚动只在「开着且用户确实在底部」时生效：
// 用户往回翻历史时强行把他拽回底部，是这类日志窗最招人烦的行为。
// 这里的键换不换成"末尾那条的序号"没有区别，实测过：watch 的 getter 每次返回
// 新数组，Vue 按对象身份比，于是 entries 一变它就触发——行数只是恰好跟着变。
// 留着行数，是因为它少一个 computed 就是少一个概念。
watch(
  () => [filtered.value.length, levelIdx.value, keyword.value],
  async () => {
    if (!follow.value) {
      return
    }
    await nextTick()
    if (body.value) {
      body.value.scrollTop = body.value.scrollHeight
    }
    seenSeq.value = newestSeq.value
  }
)

function onScroll(): void {
  const el = body.value
  if (!el) {
    return
  }
  const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24
  follow.value = atBottom
  if (atBottom) {
    seenSeq.value = newestSeq.value
  }
}

/* ---------- 往回翻过的人要有一条回来的路 ----------
   「跟随最新」一关，新行就一直积在视线以下，而那扇窗里除了拖滚动条没有任何东西
   告诉他"底下又走了多少"。日志恰恰是出事时才翻的东西：人往上找一行旧错误，
   回来时应该有一个落点，不是一段距离。 */
const newestSeq = computed(() => {
  const e = props.entries
  return e.length === 0 ? 0 : e[e.length - 1].seq
})

/** 上一次贴在末尾时看到的最后一条。人离开底部之后到的行都算在它后面。 */
const seenSeq = ref(0)

// 数的是**过滤后**的新行：挂着「只看拦截」时，新来的 500 行转发日志不该报成"新 500 条"，
// 那 500 条在这一屏上根本看不见。
const behind = computed(() => {
  let n = 0
  for (const e of filtered.value) {
    if (e.seq > seenSeq.value) {
      n++
    }
  }
  return n
})

async function jumpToLatest(): Promise<void> {
  follow.value = true
  seenSeq.value = newestSeq.value
  await nextTick()
  if (body.value) {
    body.value.scrollTop = body.value.scrollHeight
  }
}
</script>

<template>
  <div class="view">
    <section class="card">
      <h2>
        日志流
        <span class="count">{{ filtered.length }} / {{ entries.length }} 条</span>
        <span class="act">
          <input
            v-model="keyword"
            class="kw"
            placeholder="过滤关键字"
            aria-label="过滤关键字"
            data-focus-shortcut
          />
          <!-- 一键到"拦截"：这件事在应用侧是完全静默的，日志是它唯一的自证之地，
               所以得让人一次点到位，而不是要求他记得手打中文关键字。 -->
          <div class="seg" role="group" aria-label="快捷过滤">
            <button type="button" :class="{ on: quickOn }" @click="toggleQuick">只看拦截</button>
          </div>
          <div class="seg" role="group" aria-label="按级别过滤（含以上）">
            <button
              v-for="(l, i) in LEVELS"
              :key="l.label"
              type="button"
              :class="{ on: levelIdx === i }"
              :title="l.title"
              @click="levelIdx = i"
            >
              {{ l.label }}<template v-if="i > 0">&nbsp;{{ tally[i] }}</template>
            </button>
          </div>
          <label class="switch">
            <input v-model="follow" type="checkbox" />
            <span class="track" aria-hidden="true"></span>
            <span>跟随最新</span>
          </label>
        </span>
      </h2>

      <p v-if="truncated" class="alert warn">
        日志产生得比界面刷新快，中间一段已被后端环形缓冲覆盖，这里只显示仍然保留的部分。
      </p>

      <!-- 这一行说的是"画了多少"，不是"有多少"：上面那个计数已经是过滤后的全量，
           两者不是一回事，所以措辞分开写，别让人以为缓冲里只剩 200 条。 -->
      <p v-if="hiddenLines > 0" class="mut window-row">
        只画出了最后 <strong>{{ shown.length }}</strong> 行，上面还有
        <strong>{{ hiddenLines }}</strong> 行没画——两千行一次铺开实测要 190ms，
        那是切这一页时谁都感觉得到的一段停顿。
        <button type="button" class="btn sm ghost" @click="growWindow">
          再多画 {{ Math.min(LOG_WINDOW, hiddenLines) }} 行
        </button>
        <button type="button" class="btn sm ghost" @click="logWindow = filtered.length">
          全部画出（{{ filtered.length }} 行）
        </button>
        <span class="win-note">过滤搜的是整份缓冲，不用先展开。</span>
      </p>

      <div ref="body" class="logbox" @scroll="onScroll">
        <div v-for="e in shown" :key="e.seq" class="logline" :class="e.level.toLowerCase()">
          <span class="logtime">{{ e.time }}</span>
          <span class="loglevel">{{ e.level }}</span>
          <span class="logmsg">
            <template v-for="(p, i) in split(e.msg)" :key="i">
              <mark v-if="p.hit">{{ p.text }}</mark>
              <template v-else>{{ p.text }}</template>
            </template>
          </span>
        </div>
        <p v-if="filtered.length === 0" class="empty">
          {{
            !loaded
              ? '正在读第一批日志…'
              : entries.length === 0
                ? '还没有日志。启动代理或重载规则就会有了。'
                : '当前过滤条件下没有日志，换个关键字或切回「全部」。'
          }}
        </p>
      </div>

      <!-- 这一条只在人已经离开末尾时出现：日志是出事时才翻的东西，往上找一行旧错误时
           新行一直积在视线以下，而那扇窗里除了拖滚动条没有别的落点。
           样式沿用 .window-row：它和"还有多少行没画"是同一类东西——边界的说明，不是数据。 -->
      <p v-if="!follow" class="mut window-row">
        {{
          behind > 0
            ? `翻走这一段又来了 ${behind} 行（按当前过滤算）`
            : '末尾暂时没有新行，跳回去就是滚到底'
        }}
        <button type="button" class="btn sm ghost" @click="jumpToLatest">回到最新</button>
      </p>
    </section>
  </div>
</template>

<style scoped>
.kw {
  width: 150px;
}

.logbox {
  margin-top: 4px;
}
</style>
