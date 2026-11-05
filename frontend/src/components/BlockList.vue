<script setup lang="ts">
import { computed, ref, watch as vueWatch } from 'vue'
import type { Ref } from 'vue'
import type { BlockImport, BlockedHit, BlockView } from '../types'
import {
  addBlockDomain,
  addBlockDomains,
  blockList,
  errorText,
  pruneBlockDomains,
  removeBlockDomain
} from '../api'
import { formatAgo } from '../format'

type PageIO = {
  busy: Ref<string>
  notice: Ref<string>
  failure: Ref<string>
  load: () => Promise<void>
  run: (key: string, fn: () => Promise<void>, done: string) => Promise<boolean>
}
const props = defineProps<{
  page: PageIO
  blockedTotal: number
  recentBlocked: BlockedHit[]
}>()

const emit = defineEmits<{
  (e: 'block', list: BlockView | null): void
}>()

const busy = props.page.busy
const notice = props.page.notice
const failure = props.page.failure
const load = props.page.load
const run = props.page.run

// 拦截名单住在配置的 block: 段，这里只读展示。
// 为什么必须在这一页露出来：名单对客户端是完全静默的（不回任何拒绝信息），
// 用户能确认"到底拦住了什么、装上了没有"的地方就只剩界面与日志。
const block = ref<BlockView | null>(null)
const blockDraft = ref('')

/* 拦截名单那堆 chip 和上面那张表是同一道题，而且更极端：
   一个 chip 是 span + 按钮 + svg ≈ 4 个节点，而"批量粘贴（成百上千条用这个）"
   这一栏就是为了让用户把整份 AdGuard 名单粘进来——8000 条就是三万多个节点，
   每五秒整份重读一次时全都要重新 diff。
   另外几千个 chip 摊成一团也是读不完的，所以这里同时给一个框：
   窗口管"画多少"，过滤框管"找得到那一条"。 */
const BLOCK_WINDOW = 300
const blockWindow = ref(BLOCK_WINDOW)
const blockFilter = ref('')
const matchedBlock = computed(() => {
  const q = blockFilter.value.trim().toLowerCase()
  const list = block.value?.domains ?? []
  if (!q) {
    return list
  }
  return list.filter((d) => d.includes(q))
})
const visibleBlock = computed(() => matchedBlock.value.slice(0, blockWindow.value))
const hiddenBlockCount = computed(() => matchedBlock.value.length - visibleBlock.value.length)

vueWatch(blockFilter, () => {
  blockWindow.value = BLOCK_WINDOW
})

/**
 * 加一条拦截域名。
 *
 * 空白输入先在前端挡住，别发一次注定失败的请求再报。
 * 这条没套 run()：提示要用**后端归一化后**的写法，还要分得清"真加了"和"本来就有"，
 * 而 run() 的 done 是发起之前就定好的字符串，做不到。
 */
async function onAddBlock(): Promise<void> {
  const raw = blockDraft.value.trim()
  if (!raw) {
    failure.value = '请先填要拦的域名，例如 ads.example.com'
    return
  }
  if (busy.value !== '') {
    return
  }
  busy.value = 'add-block'
  notice.value = ''
  failure.value = ''
  const had = block.value?.domains ?? []
  try {
    const saved = await addBlockDomain(raw)
    notice.value = had.includes(saved)
      ? `${saved} 本来就在名单里，没有改动。`
      : `已把 ${saved} 加入拦截名单（含其子域，立即生效）。`
    await load()
  } catch (err) {
    failure.value = `添加拦截域名失败：${errorText(err)}`
  } finally {
    busy.value = ''
    blockDraft.value = ''
  }
}

/**
 * 这一条留痕的 host 是否就是名单里那一条。
 * 只做大小写层面的比对（名单本身已由后端归一化）；
 * 撞上来的是子域时返回 false——该删的是父域那条，前端不替后端猜。
 */
function inBlockList(host: string): boolean {
  const d = host.trim().toLowerCase()
  return !!block.value?.domains.some((x) => x.toLowerCase() === d)
}

/** 删一条。删除走的是后端校验过的精确匹配，前端不做归一化以免两边规则不同。 */
const onRemoveBlock = (d: string): Promise<boolean> =>
  run('rm-block', () => removeBlockDomain(d), `已把 ${d} 移出拦截名单。`)

/* ---------- 批量粘贴拦截域名 ----------
   网上抄来的名单动辄几百上千条，逐条点「添加」既慢又危险：那条路径每一行都要
   整份读写一次配置，中途任何一次失败都留下半截名单。粘贴框另外收 AdGuard 写法
   （||域名^ 与 ||域名^$修饰符），因为抄来的名单基本都长那个样子。 */
const blockBatchOpen = ref(false)
const blockBatchText = ref('')
const blockBatchResult = ref<BlockImport | null>(null)

/** 结果那一句。模板里直接拼的话，插值两侧的空白会混进句子中间（"、 拒掉"）。 */
function blockBatchSummary(r: BlockImport): string {
  const parts = [`读到 ${r.total} 行：新增 ${r.accepted} 条`]
  if (r.existing > 0) {
    parts.push(`${r.existing} 条名单里本来就有`)
  }
  if (r.rejected.length > 0) {
    parts.push(`拒掉 ${r.rejected.length} 行`)
  }
  return parts.join('，') + (r.written ? '。' : '——名单原样没动。')
}

async function onBlockBatchAdd(): Promise<void> {
  if (busy.value !== '') {
    return
  }
  if (blockBatchText.value.trim() === '') {
    failure.value = '先把要拦的域名粘进来，一行一个（AdGuard 的 ||域名^ 也收）'
    return
  }
  failure.value = ''
  notice.value = ''
  busy.value = 'batch-block'
  try {
    const r = await addBlockDomains(blockBatchText.value)
    blockBatchResult.value = r
    await load()
    if (!r.written) {
      notice.value =
        r.existing > 0
          ? `那 ${r.total} 行里 ${r.existing} 条名单里本来就有，名单原样没动。`
          : `这 ${r.total} 行一条都没收下，名单原样没动。`
    } else {
      notice.value =
        `已保存：新增 ${r.accepted} 条` +
        (r.existing > 0 ? `，${r.existing} 条本来就有` : '') +
        (r.rejected.length > 0 ? `，拒掉 ${r.rejected.length} 行` : '') +
        (r.dead.length > 0 ? `；其中 ${r.dead.length} 条什么也没多拦` : '') +
        '。'
    }
    if (r.written) {
      blockBatchText.value = ''
    }
  } catch (err) {
    failure.value = `批量添加失败：${errorText(err)}`
  } finally {
    busy.value = ''
  }
}

/**
 * 清理被更宽条目盖住的冗余项。
 *
 * 这按钮改的是配置文件，所以只给一个明确说了后果的确认框：
 * 用户要能自己判断"删掉它"是不是在放弃什么——答案是没有，
 * 留着的那条盖住的范围一模一样（见 rules.PruneBlockDomains）。
 */
async function onPruneBlock(): Promise<void> {
  if (busy.value !== '') {
    return
  }
  const n = block.value?.deadTotal ?? 0
  if (n === 0) {
    return
  }
  if (!window.confirm(`清掉 ${n} 条什么也没多拦的条目？\n\n名单里更宽的那条照旧拦着同样的域名，删掉不改任何判定。`)) {
    return
  }
  // 提示要说实际删了几条，而 run() 的那句是发起之前就定死的，所以这里自己走一遍。
  busy.value = 'prune-block'
  failure.value = ''
  notice.value = ''
  try {
    const removed = await pruneBlockDomains()
    notice.value = removed === 0 ? '没有可清理的条目。' : `清掉了 ${removed} 条冗余条目，拦截范围不变。`
    await load()
  } catch (err) {
    failure.value = `清理失败：${errorText(err)}`
  } finally {
    busy.value = ''
  }
}

// 同上：过期指纹要知道拦截名单现在长什么样，父级不为此再读一次。
vueWatch(block, (list) => emit('block', list))

const blockKnown = ref(false)
const blockStale = ref(false)


async function reload(): Promise<string> {
  try {
    const b = await blockList()
    if (!b) {
      // 后端这里总该回一份名单（哪怕是空的）。回了个 null 就是没读到，
      // 不能顺手把 blockKnown 置真——那一栏会永远停在「读取中…」。
      blockStale.value = blockKnown.value
      return '拦截名单 返回了空读数'
    }
    block.value = b
    blockKnown.value = true
    blockStale.value = false
    return ''
  } catch (err) {
    blockStale.value = blockKnown.value
    return `拦截名单 ${errorText(err)}`
  }
}

defineExpose({ reload })
</script>

<template>
    <section id="wps-block-section" class="card skip-target" tabindex="-1">
      <h2>
        拦截域名
        <span class="count">
          {{ blockKnown ? `${block?.domains.length ?? 0} 条` : '条数未知' }}
          <span v-if="blockStale" class="warn">· 读数已过期</span>
        </span>
      </h2>

      <p v-if="!block" class="mut">{{ blockKnown ? '读取中…' : '还没读到过这份名单——上面若是错误，说明读它失败了。' }}</p>
      <template v-else>
        <div class="fields add">
          <input
            v-model="blockDraft"
            class="value"
            placeholder="要拦的域名，例如 ads.example.com"
            aria-label="拦截域名"
            @keyup.enter="onAddBlock"
          />
          <button type="button" class="btn primary" :disabled="busy !== ''" @click="onAddBlock">
            {{ busy === 'add-block' ? '添加中…' : '添加' }}
          </button>
        </div>

        <div class="fields batch-toggle">
          <button type="button" class="btn ghost" @click="blockBatchOpen = !blockBatchOpen">
            {{ blockBatchOpen ? '收起批量粘贴' : '批量粘贴（成百上千条用这个）' }}
          </button>
        </div>

        <div v-if="blockBatchOpen" class="batch">
          <textarea
            v-model="blockBatchText"
            class="batch-text"
            rows="6"
            spellcheck="false"
            placeholder="一行一个域名，例如：
ads.example.com
||track.example.net^
||cdn.example.org^$third-party

# 与 ! 开头的行是注释；@@||x 是例外规则（不要拦它），这份名单不收。"
            aria-label="批量粘贴拦截域名"
          ></textarea>
          <div class="fields">
            <button type="button" class="btn primary" :disabled="busy !== ''" @click="onBlockBatchAdd">
              {{ busy === 'batch-block' ? '正在收…' : '加入名单' }}
            </button>
            <span class="mut">整段只写一次盘；上面那份名单是按后缀拦的，父域已经在名单里就不用再粘子域了。</span>
          </div>
          <div v-if="blockBatchResult" class="batch-out">
            <p :class="{ warn: !blockBatchResult.written }">{{ blockBatchSummary(blockBatchResult) }}</p>
            <ul v-if="blockBatchResult.rejected.length > 0" class="reject">
              <li v-for="(t, i) in blockBatchResult.rejected" :key="'r' + i">{{ t }}</li>
            </ul>
            <ul v-if="blockBatchResult.dead.length > 0" class="dead">
              <li v-for="(t, i) in blockBatchResult.dead" :key="'d' + i">
                {{ t }}
              </li>
            </ul>
          </div>
        </div>

        <!-- 几十条往上就没有人会在这一团 chip 里找东西了，所以给一个框。
             短名单不显示它：三五条域名一眼看完，多一个输入框只是多一处要理解的东西。 -->
        <div v-if="block.domains.length > 40" class="fields filter">
          <input
            v-model="blockFilter"
            type="search"
            data-focus-shortcut
            placeholder="在这份名单里找，例如 example.com"
            aria-label="拦截名单过滤"
          />
        </div>

        <div v-if="matchedBlock.length" class="chips">
          <span v-for="d in visibleBlock" :key="d" class="chip">
            <span class="mono">{{ d }}</span>
            <button
              type="button"
              class="chip-x"
              :disabled="busy !== ''"
              :aria-label="`把 ${d} 移出拦截名单`"
              :title="`把 ${d} 移出拦截名单`"
              @click="onRemoveBlock(d)"
            >
              <svg viewBox="0 0 10 10" aria-hidden="true">
                <path d="M2.5 2.5 7.5 7.5M7.5 2.5 2.5 7.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
              </svg>
            </button>
          </span>
        </div>
        <!-- 「筛没了」与「名单本来就是空的」是两件事，混成一句会把人推向重复添加。 -->
        <p v-else-if="block.domains.length" class="mut">
          {{ block.domains.length }} 条里没有匹配「{{ blockFilter.trim() }}」的域名。换个关键字或清空这一栏。
        </p>
        <p v-else class="mut">
          名单是空的，现在不拦任何域名。上面填一个域名点「添加」，或直接在
          <span class="mono">config.yaml</span> 的 <span class="mono">block:</span> 段里写。
        </p>
        <p v-if="hiddenBlockCount > 0" class="mut window-row">
          只画出了前 <strong>{{ visibleBlock.length }}</strong> 条，还有
          <strong>{{ hiddenBlockCount }}</strong> 条没画（这一栏每五秒要把整份名单重画一遍）。
          <button type="button" class="btn sm ghost" @click="blockWindow += BLOCK_WINDOW">
            再多画 {{ Math.min(BLOCK_WINDOW, hiddenBlockCount) }} 条
          </button>
          <button type="button" class="btn sm ghost" @click="blockWindow = matchedBlock.length">
            全部画出（{{ matchedBlock.length }} 条）
          </button>
        </p>

        <!-- 死条目排在累计数前面：它是名单自己的问题（装了没多拦），
             累计数是运行的结果，两件事混在一句提示里会互相盖过。 -->
        <div v-if="block.deadTotal > 0" class="batch-out dead-box">
          <p>
            名单里有 <strong>{{ block.deadTotal }}</strong> 条什么也没多拦：按后缀拦，父域已经在名单里，
            子域那条就是空操作。留着不影响拦截，只是让人以为"我加了它怎么还在外连"。
          </p>
          <ul class="dead">
            <li v-for="(t, i) in block.dead" :key="'b' + i">{{ t }}</li>
          </ul>
          <p v-if="block.deadTotal > block.dead.length" class="mut">
            这里只列出前 {{ block.dead.length }} 条，共 {{ block.deadTotal }} 条。
          </p>
          <button type="button" class="btn sm" :disabled="busy !== ''" @click="onPruneBlock">
            {{ busy === 'prune-block' ? '清理中…' : `清掉这 ${block.deadTotal} 条冗余` }}
          </button>
          <p class="mut">
            清理只是去重：更宽的那条盖住的范围一模一样，删掉不改变任何一个域名的判定。
          </p>
        </div>

        <p v-if="block.live && block.mode !== 'direct'" class="mut tail">
          本次运行已经拦下
          <b>{{ blockedTotal }}</b>
          条（0 就是 0：名单装着，但还没有连接撞上它）。应用那边不会收到任何原因，
          这件事只有这一页和日志说得出。
        </p>

        <!-- 留痕放在累计数下面：它回答的是"刚才那一个到底拦没拦"，
             而连接表是环形流水，几秒就会被别的请求冲掉。 -->
        <div v-if="recentBlocked.length" class="hits">
          <h3>最近拦下 {{ recentBlocked.length }} 个目标（历史留痕：把域名移出名单，这条记录还在，到点或「清空统计」才走）</h3>
          <ul>
            <li v-for="h in recentBlocked" :key="h.host + '|' + h.rule" class="hit">
              <span class="hit-main">
                <span class="line1">
                  <span class="mono">{{ h.host }}</span>
                  <span class="mut">×{{ h.count }} · {{ formatAgo(h.lastAt) }}</span>
                </span>
                <!-- 规则原文是这栏里最长的字符串，让它自己截断，别把整栏撑出横向滚动。 -->
                <span class="mono mut rule">{{ h.rule }}</span>
              </span>
              <!-- 一键放开：拦错了最远的距离就是"要回去翻名单才知道删哪条"。
                   只有 host 本身就在名单里才给按钮——撞上来的是子域时该删的是那条父域，
                   前端不去猜父域（归一化是后端的事），这一行就只展示。 -->
              <button
                v-if="inBlockList(h.host)"
                type="button"
                class="btn sm"
                :disabled="busy !== ''"
                @click="onRemoveBlock(h.host)"
              >
                移出名单
              </button>
            </li>
          </ul>
        </div>
        <p v-else-if="block.live" class="mut tail">
          还没有拦截留痕：本次运行没有连接撞上名单（点「清空统计」或重启面板也会把它清掉）。
        </p>

        <p class="hint tail">
          命中即<strong>静默丢弃</strong>：不回 SOCKS 失败应答、也不回 HTTP 502，应用只会等到超时——
          原因只能在这一页和日志里看。按后缀匹配，含所有子域；这份名单排在规则文件<b>之前</b>，
          压得过 <span class="mono">DOMAIN-SUFFIX,x,DIRECT</span> 这类放行规则。
        </p>
        <p v-if="!block.live" class="alert warn tail">
          代理没在跑，上面这份是按 <span class="mono">{{ block.path }}</span> 现算的，还没有任何东西真的被拦。
        </p>
        <p v-else-if="block.mode === 'direct'" class="alert warn tail">
          当前是「直连」模式——<b>黑名单整体让开</b>，这 {{ block.domains.length }} 条现在一条都不拦。
          这是刻意留的逃生阀：切回「规则」模式才生效。
        </p>
        <p v-else class="mut tail">
          名单住在 <span class="mono">{{ block.path }}</span> 的 <span class="mono">block:</span> 段里——
          上面「添加 / 删除」改的就是这一份，写完立刻热装载，不用点「重载规则」。
          零散几条也可以直接写进规则文件用 <span class="mono">REJECT</span> 策略。
        </p>
      </template>
    </section>
</template>
