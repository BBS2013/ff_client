<script setup lang="ts">
import { computed, nextTick, ref, watch as vueWatch } from 'vue'
import type { Ref } from 'vue'
import type { RuleWarning, UserRule, UserRuleImport } from '../types'
import {
  addUserRule,
  addUserRules,
  errorText,
  moveUserRule,
  profiles,
  removeUserRule,
  setUserRuleDisabled,
  userRuleHits,
  userRuleWarnings,
  userRules
} from '../api'
import { policyClass, policyText } from '../format'

type PageIO = {
  busy: Ref<string>
  notice: Ref<string>
  failure: Ref<string>
  load: () => Promise<void>
  run: (key: string, fn: () => Promise<void>, done: string) => Promise<boolean>
}
const props = defineProps<{
  page: PageIO
  seed?: string
}>()

const emit = defineEmits<{
  (e: 'seeded'): void
  (e: 'rules', list: UserRule[]): void
}>()

const busy = props.page.busy
const notice = props.page.notice
const failure = props.page.failure
const load = props.page.load
const run = props.page.run

const RULE_TYPES = [
  { id: 'DOMAIN-SUFFIX', label: '域名及其子域', hint: 'example.com 与 *.example.com' },
  { id: 'DOMAIN', label: '精确域名', hint: '只有 example.com 本身' },
  { id: 'DOMAIN-KEYWORD', label: '域名含关键字', hint: '出现该串即命中' }
]

// 这里唯一的数据源是 userRules()，因为它不在 Status 里。
const rules = ref<UserRule[]>([])

// 查走向那三格的过期指纹要看这份名单。它住在这一栏里，父级只拿当前这份去算指纹，不另打请求。
vueWatch(rules, (list) => emit('rules', list))

// 草稿里 disabled 恒为 false：新加的一条没有"先加上再关掉"这一说，
// 要关就加完之后点那一行的「停用」。留着这个字段只是为了让草稿和 UserRule 同形。
const ruleDraft = ref<UserRule>({ type: 'DOMAIN-SUFFIX', value: '', policy: 'PROXY', node: '', disabled: false })

/* ---------- 批量粘贴 ----------
   一份名单动辄上百条，逐条填三个字段是没有人会做的事。
   粘贴框接受两种写法：一行一个裸域名（按上面选好的类型与策略补全），
   或者一整行 类型,域名,策略 原样搬过来。 */
const batchOpen = ref(false)
const batchText = ref('')
const batchResult = ref<UserRuleImport | null>(null)

async function onBatchAdd(): Promise<void> {
  if (busy.value !== '') {
    return
  }
  if (batchText.value.trim() === '') {
    failure.value = '先把要加的域名粘进来，一行一个（也可以写成 类型,域名,策略）'
    return
  }
  failure.value = ''
  notice.value = ''
  busy.value = 'batch-rule'
  try {
    const r = await addUserRules(batchText.value, ruleDraft.value.type, ruleDraft.value.policy)
    batchResult.value = r
    await load()
    if (r.total === 0) {
      notice.value = '那些行里没有一条规则：空行与 # 注释不算。'
    } else if (!r.written) {
      // 一条都没收下时文件是原样的，这句必须说：写完"已保存"就是当着人撒谎。
      notice.value = `这 ${r.total} 行一条都没收下，名单原样没动。`
    } else {
      notice.value =
        `已保存：新增 ${r.accepted} 条、覆盖 ${r.updated} 条` +
        (r.rejected.length > 0 ? `，另有 ${r.rejected.length} 行被拒` : '') +
        (r.dead.length > 0 ? `；其中 ${r.dead.length} 条装上但永远不会命中` : '') +
        '。'
    }
    if (r.written) {
      batchText.value = ''
      if (ruleFilter.value !== '') {
        ruleFilter.value = ''
      }
    }
  } catch (err) {
    failure.value = `批量添加失败：${errorText(err)}`
  } finally {
    busy.value = ''
  }
}

/**
 * 这一行能不能在面板上改。判据和 Go 侧的 `UserRule.IsDomain()` 是同一套
 * （类型在白名单里、且不是拦截行），两边各写一处时以 Go 为准——
 * 它才是真的会写盘的那一侧。界面上"只读"的文字和一个会落盘的按钮同时出现，
 * 比少一个按钮糟得多：用户按下去了，而那一行说他不能按。
 */
/* 可选的固定节点：名单来自配置里的节点，不是随便填的字符串。
   后端会照名字去装配那只出站，名字对不上就直接报错（绝不回落当前节点），
   所以这里只让人从现有名字里挑，避免当场写出一条永远连不通的规则。 */
const nodeNames = ref<string[]>([])

/** 节点名单读到了、而这一行钉的名字不在里面，才算"钉坏了"。
    名单空着 = 还没读到（读失败或还没读），那时说"没问题"才是诚实的。 */
const pinBroken = (r: UserRule): boolean => nodeNames.value.length > 0 && r.node !== '' && !nodeNames.value.includes(r.node)

/** 这一行的钉住能不能在面板里就地换。三个条件缺一不可：
    只读行（手写的 IP-CIDR / GEOIP / 拦截行）改了会连带丢掉原样；
    直连与拦截没有"走哪个节点"这回事；
    而节点名单没读到时，下拉里只剩「当前节点」一项，
    点下去等于把用户钉得好好的节点悄悄清掉——那不如不给这个下拉。 */
const pinEditable = (r: UserRule): boolean =>
  editableRule(r) && r.policy === 'PROXY' && nodeNames.value.length > 0

const EDITABLE_TYPES: string[] = RULE_TYPES.map((x) => x.id)
const editableRule = (r: UserRule): boolean =>
  EDITABLE_TYPES.includes(r.type) && (r.policy === 'PROXY' || r.policy === 'DIRECT')

/** 只读的那一行要说清"为什么只读"和"去哪儿改"，两种原因给的话不一样。 */
function readonlyNote(r: UserRule): string {
  if (r.policy === 'REJECT') {
    return '拦截规则（这一行只读；要改名单用下面「拦截域名」那一栏）'
  }
  return `手写的 ${r.type} 规则（只读，改它要直接编辑 user-rules.txt）`
}

/* ---------- 这一栏：名单里写了但不会按你想的走 ----------
   两类问题：一类是被前面的规则盖住（"加了却不生效"），一类是钉的节点已经改名/删掉。
   判据都在后端算（归一化写法与节点名单只有一份权威），这里只负责把它说的话摆出来。 */
const warnings = ref<RuleWarning[]>([])
const warnKnown = ref(false)
// 每条规则本次会话命中过多少次，键是 TYPE,VALUE。
// 单独一份读数的理由见 UserRuleHits：判语说的是"结构上永远轮不到"，
// 而一份几百条的名单里更多的是"活着、但从没轮到过"——那种只能观察，推不出来。
const ruleHits = ref<Record<string, number>>({})
const hitOf = (r: UserRule): number => ruleHits.value[`${r.type},${r.value}`] ?? 0
const warnStale = ref(false)
const warnError = ref('')

// 头部要按"有哪几类"说话，否则只钉错节点的那份名单会被说成"永远不会命中"。
// 两类各自数各自的，**不要拿总数去减**：后端哪天多一种 Kind，减法会把新那类
// 悄悄算进"钉的节点不存在"里，于是界面当面说错话，而测试全绿。
const shadowCount = computed(() => warnings.value.filter((w) => w.kind === 'shadow').length)
const nodeMissingCount = computed(() => warnings.value.filter((w) => w.kind === 'node-missing').length)
// 界面还不认识的 Kind 不能装作不存在：总数里有它，可两句分类的话都不会提到它，
// 于是这块看着自洽、其实少了几条。宁可明说"有 N 条没认出来"。
const unknownKinds = computed(() =>
  warnings.value.filter((w) => w.kind !== 'shadow' && w.kind !== 'node-missing')
)


async function loadWarnings(): Promise<void> {
  // 计数与判语各自一份读数、各自一处失败：命中数读不到不该把判语一起打成"读不到"，
  // 反过来也不行——两栏回答的是两个问题。
  try {
    const h = await userRuleHits()
    const m: Record<string, number> = {}
    for (const x of h ?? []) {
      m[x.key] = x.hits
    }
    ruleHits.value = m
  } catch {
    // 这一份读数读不到就整列按 0 显示，不再多造一个"未知"状态：
    // 后端那里是一次纯内存的 map 快照，唯一会失败的是它顺带调的 ListUserRules——
    // 而那个一失败，上面那张表本身就是空的，轮不到这一列来说话。
    ruleHits.value = {}
  }
  try {
    const w = await userRuleWarnings()
    if (!w) {
      warnError.value = '后端回了空读数'
      warnStale.value = warnKnown.value
      return
    }
    warnings.value = w
    warnKnown.value = true
    warnStale.value = false
    warnError.value = ''
  } catch (err) {
    // 读不到这件事写在自己那一栏，不抢页面顶部那条 failure：
    // 两份名单都还好好的，只是这一句判语没拿到。
    warnError.value = errorText(err)
    warnStale.value = warnKnown.value
  }
}

// 读到过一次成功，才算「知道这份名单长什么样」。
// 没读到过的时候，空列表只能显示成读不到——把它写成「还没有规则」，
// 是把一次失败冒充成了一个关于磁盘的事实。
//
// stale 是另一半：以前读到过、这次重读失败。此时屏幕上那份是**旧**读数，
// 不标出来的话，"118 条"看着就像刚刚核对过。

const rulesKnown = ref(false)
const rulesStale = ref(false)


async function reload(): Promise<string> {
  try {
    rules.value = (await userRules()) ?? []
    // 节点名单和规则一起读：加规则时要能从现有节点里挑一个钉住，
    // 而名单读失败不该把这张表整个打成"读不到"，单独 catch。
    try {
      const pl = await profiles()
      nodeNames.value = (pl?.profiles ?? []).map((x) => x.name)
    } catch {
      nodeNames.value = []
    }
    rulesKnown.value = true
    rulesStale.value = false
    return ''
  } catch (err) {
    rulesStale.value = rulesKnown.value
    return `自定义规则 ${errorText(err)}`
  }
}

const ruleFilter = ref('')

/**
 * 按关键字过滤那份自定义规则表。
 *
 * 为什么要它：这份名单会一直长（本机已经 118 条），而找一条已有规则
 * 是改规则之前最常做的动作——没有过滤框就只能滚动加肉眼，
 * 找不到时又会误以为"我没加过"，于是加出一条重复的。
 * 匹配范围包含走向的中文说法，输「直连」也该能筛出那一类。
 */
const shownRules = computed(() => {  const q = ruleFilter.value.trim().toLowerCase()
  if (!q) {
    return rules.value
  }
  return rules.value.filter(
    (r) =>
      r.value.toLowerCase().includes(q) ||
      r.type.toLowerCase().includes(q) ||
      policyText(r.policy).toLowerCase().includes(q) ||
      r.policy.toLowerCase().includes(q)
  )
})

/* ---------- 只画看得见的那几十行 ----------
   成批粘贴之后这张表动辄几百上千行，而一行是 ~19 个 DOM 节点。
   面板每 5 秒整份重读一次规则，`rules.value` 每次都是新数组、新对象，
   Vue 只能把每一行重新 diff 一遍——本机实测 907 行时清一次过滤要 266ms，
   也就是每五秒一次四分之一秒的停顿，而且它正发生在人看着这一页的时候。
   所以按窗口画：先画前若干行，要更多再给。
   过滤仍然走整份名单（上面那个 computed），筛出来几条就画几条，窗口只在"没筛完"时兜底。 */
const RULE_WINDOW = 200
const ruleWindow = ref(RULE_WINDOW)
const visibleRules = computed(() => shownRules.value.slice(0, ruleWindow.value))
const hiddenRuleCount = computed(() => shownRules.value.length - visibleRules.value.length)

/* 跳过这张表用的那一条。表里每行 6~7 个控件，画满 200 行就是一千多个 Tab 停靠点，
   而同一页下面还有「拦截域名」那一栏——不数一下没人会相信要按多少次，所以把数字摆出来。
   数的是 DOM 里真的能聚焦的东西，不按"行数 × 每行几个"估：
   只读行、直连行、有没有节点名单，每行的控件数都不一样，估的那份迟早和实际对不上。 */
const tableWrap = ref<HTMLElement | null>(null)
const tableControlCount = ref(0)
function recountTableControls(): void {
  tableControlCount.value =
    tableWrap.value?.querySelectorAll('a[href], button, input, select, textarea').length ?? 0
}
vueWatch(
  () => [visibleRules.value.length, nodeNames.value.length, busy.value],
  () => void nextTick(recountTableControls),
  { immediate: true }
)

// 点后跳过去之后要把焦点真的放到那一栏上：目标是个 <section>，
// 本身不可聚焦，光靠锚点滚动会让 Tab 还停在原地，等于只滚了个屏。
function focusBlockSection(e: Event): void {
  e.preventDefault()
  const el = document.getElementById('wps-block-section')
  el?.scrollIntoView({ block: 'start' })
  el?.focus({ preventScroll: true })
}

// 换关键字等于换了一份"要看的东西"，窗口要回到起点：
// 留着上一次展开到的一千多行，人从长名单切回短名单时最容易误以为界面卡住了。
vueWatch(ruleFilter, () => {
  ruleWindow.value = RULE_WINDOW
})

// 从连接表带过来的域名：填进表单、聚焦，然后请父级清空这份种子。
// 类型固定成 DOMAIN-SUFFIX 而不是"域名及其子域"里的其它两档——
// 用户看到的是一个正在跑的连接，他多半想管的是这个域名连同它的子域，
// 而且这一档是表单的默认值，不覆盖它就不会有"切了页结果选了个没选过的"。
const draftValueEl = ref<HTMLInputElement | null>(null)
vueWatch(
  () => props.seed,
  (host) => {
    if (!host) {
      return
    }
    ruleDraft.value.value = host
    emit('seeded')
    void nextTick(() => draftValueEl.value?.focus())
  },
  { immediate: true }
)

async function onAddRule(): Promise<void> {
  const value = ruleDraft.value.value.trim()
  if (!value) {
    failure.value = '请先填域名，例如 notion.so'
    return
  }
  failure.value = ''
  const ok = await run(
    'add-rule',
    // 直连没有"节点"可言：选了直连还留着节点名，写出来就是一条后端会当场拒掉的行。
    () =>
      addUserRule({
        type: ruleDraft.value.type,
        value,
        policy: ruleDraft.value.policy,
        node: ruleDraft.value.policy === 'PROXY' ? ruleDraft.value.node : '',
        // 新加的一条当然是生效的：这里没有"沿用上一条的开关"这回事。
        disabled: false
      }),
    `已保存规则：${value} ${ruleDraft.value.policy === 'PROXY' ? '走代理' : '直连'}。`
  )
  // 存完了就把筛选放开：还留着旧关键字的话，新那条十有八九不在结果里，
  // 于是提示说"已保存"、表里却一行都没多——那是最容易被当成"没存上"的一幕。
  // 删除/改走向不清：用户盯的就是刚才那一行，筛选条件对他还有用。
  if (ok && ruleFilter.value !== '') {
    ruleFilter.value = ''
  }
  ruleDraft.value = { ...ruleDraft.value, value: '' }
}

/** 策略的人话名在 format.ts：这里曾经自己抄了一份三元表达式，
 *  结果 REJECT 和空值都掉进「直连」那一档——拦死的域名被说成随便走。 */

/**
 * 点策略标签就地反转：改一条规则的走向应该是「点一下」，而不是删了重加。
 *
 * 钉住节点的规则翻向"直连"时必须把节点名一起放掉：后端接受不了 DIRECT + node=
 * （直连没有节点可走，留着只会让这一行保存失败）。放掉是有意的一次信息损失，
 * 所以提示里要说出放开了谁——回头想再钉上，就在上面那一栏重新选一次。
 */
function onFlipRule(r: UserRule): Promise<boolean> {
  const next = r.policy === 'PROXY' ? 'DIRECT' : 'PROXY'
  const freed = r.policy === 'PROXY' && r.node !== ''
  return run(
    `flip:${r.type},${r.value}`,
    // 走向没变到"直连"时 node 原样带上：后端是整条替换的，
    // 漏了它等于"改个走向把固定节点弄丢了"。disabled 同理——
    // 改一条停用的规则的走向，不该顺手把它打开。
    () =>
      addUserRule({
        type: r.type,
        value: r.value,
        policy: next,
        node: next === 'PROXY' ? r.node : '',
        disabled: r.disabled
      }),
    `已把 ${r.value} 改为${next === 'PROXY' ? '走代理' : '直连'}。` + (freed ? `同时放开了钉住的 ${r.node}。` : '')
  )
}

/**
 * 停用/打开一条规则。
 *
 * 存在的理由：想查"是不是这一条把某个网站弄坏的"，以前唯一的办法是删掉它，
 * 而删掉之后就记不得原来写的是什么了（从订阅抄来的那几条尤其）。
 *
 * 走一个专门的接口而不是把整条规则重发给 AddUserRule：那条会 Normalize，
 * 只收域名类型，于是手写的 IP-CIDR / GEOIP / DOMAIN-REGEX 关不掉——
 * 而那几条恰恰是最想临时关掉的。这里后端只翻一个布尔，那一行其余部分原样不动。
 */
function onToggleRule(r: UserRule): Promise<boolean> {
  const next = !r.disabled
  return run(
    `toggle:${r.type},${r.value}`,
    () => setUserRuleDisabled(r.type, r.value, next),
    next
      ? `已停用 ${r.value}：它还留在名单里，但不再参与匹配。原来被它压住的规则会开始生效。`
      : `已重新启用 ${r.value}。`
  )
}

/**
 * 就地换掉一条已存在规则钉住的节点。
 *
 * 这一格存在的理由很简单：判语那一栏会告诉用户"这条钉的节点已经没了"，
 * 可除了删掉重加就没有别的办法——那等于把"发现问题"做完了，
 * 把"解决问题"留给人家去手改 user-rules.txt。
 * 后端是整条替换的，所以这里必须把 type/value/policy 原样带回去，只换 node。
 */
function onSetRulePin(r: UserRule, node: string): Promise<boolean> {
  return run(
    `pin:${r.type},${r.value}`,
    () => addUserRule({ type: r.type, value: r.value, policy: r.policy, node, disabled: r.disabled }),
    node === ''
      ? `已让 ${r.value} 回到「当前节点」，跟着顶栏那个选择走。`
      : `已把 ${r.value} 钉到 ${node}。`
  )
}

const onRemoveRule = (r: UserRule): Promise<boolean> =>
  run(`rm-rule:${r.type},${r.value}`, () => removeUserRule(r.type, r.value), `已删除 ${r.value} 的规则。`)

/* ---------- 命中顺序 ----------
   引擎取**第一条**命中的规则，所以名单里的位置就是优先级。
   面板加规则一律追加在末尾，于是"后加的精确域名被前面那条 SUFFIX 压住、
   一条都不生效"是必然会出现的一幕；没有上下移动，用户只能去手改文件。 */

/** 这条在整份名单里的位置（0 起）。筛过之后屏幕上看到的是它，序号也报它。 */
const absIndex = (r: UserRule): number => rules.value.indexOf(r)

/**
 * 上移/下移一格该落到哪一格。
 *
 * 目标取「屏幕上紧邻那条在整份名单里的位置」：筛着看的时候点↑才是
 * "挪到我看见的那条前面"。按屏幕行号去算后端位置，点了会像没动。
 */
function moveTarget(r: UserRule, dir: -1 | 1): number | null {
  const vis = shownRules.value
  const k = vis.findIndex((x) => x === r)
  if (k < 0) {
    return null
  }
  const nb = vis[k + dir]
  return nb ? rules.value.indexOf(nb) : null
}

const canUp = (r: UserRule): boolean => absIndex(r) > 0 && moveTarget(r, -1) !== null
const canDown = (r: UserRule): boolean => moveTarget(r, 1) !== null

function onMoveRule(r: UserRule, dir: -1 | 1 | 'top'): Promise<boolean> {
  const from = absIndex(r)
  const to = dir === 'top' ? 0 : moveTarget(r, dir)
  if (to === null || to === from) {
    return Promise.resolve(false)
  }
  const where = dir === 'top' ? '最前面' : `第 ${to + 1} 位`
  return run(
    `move:${r.type},${r.value}`,
    () => moveUserRule(r.type, r.value, to),
    `已把 ${r.value} 挪到${where}，命中顺序随即生效。`
  )
}

defineExpose({ reload, loadWarnings })
</script>

<template>
    <section class="card">
      <h2>
        自定义域名规则
        <span class="count">
          {{
            rulesKnown
              ? ruleFilter.trim() !== ''
                ? `显示 ${shownRules.length} / ${rules.length} 条`
                : `${rules.length} 条`
              : '条数未知'
          }}
          <span v-if="rulesStale" class="warn">· 读数已过期</span>
          · 优先于内置规则集
        </span>
      </h2>

      <div class="fields add">
        <select v-model="ruleDraft.type" aria-label="匹配方式">
          <option v-for="t in RULE_TYPES" :key="t.id" :value="t.id">{{ t.label }}</option>
        </select>
        <input
          ref="draftValueEl"
          v-model="ruleDraft.value"
          class="value"
          placeholder="notion.so"
          aria-label="域名"
          @keyup.enter="onAddRule"
        />
        <div class="seg" role="group" aria-label="走向">
          <button
            type="button"
            :class="{ on: ruleDraft.policy === 'PROXY' }"
            @click="ruleDraft.policy = 'PROXY'"
          >
            走代理
          </button>
          <button
            type="button"
            :class="{ on: ruleDraft.policy === 'DIRECT' }"
            @click="ruleDraft.policy = 'DIRECT'"
          >
            直连
          </button>
        </div>
        <!-- 固定节点：只从现有节点里挑。后端拿名字去装配那只出站，
             对不上就报错（绝不回落当前节点），所以这里不给手填自由文本。 -->
        <select
          v-model="ruleDraft.node"
          class="pin-select"
          aria-label="固定节点"
          :disabled="ruleDraft.policy !== 'PROXY' || nodeNames.length === 0"
          :title="ruleDraft.policy === 'PROXY' ? '这条只走选中的节点；换节点用“当前节点”那一档' : '直连没有节点可走'"
        >
          <option value="">当前节点</option>
          <option v-for="n in nodeNames" :key="n" :value="n">钉住 {{ n }}</option>
        </select>
        <button type="button" class="btn primary" :disabled="busy !== ''" @click="onAddRule">
          {{ busy === 'add-rule' ? '保存中…' : '添加规则' }}
        </button>
      </div>
      <div class="fields batch-toggle">
        <button type="button" class="btn ghost" @click="batchOpen = !batchOpen">
          {{ batchOpen ? '收起批量粘贴' : '批量粘贴' }}
        </button>
        <span class="mut">一行一个域名，或直接写完整的 类型,域名,策略</span>
      </div>

      <div v-if="batchOpen" class="batch">
        <textarea
          v-model="batchText"
          class="batch-text"
          rows="6"
          spellcheck="false"
          placeholder="notion.so&#10;ads.example.com&#10;DOMAIN-SUFFIX,example.cn,DIRECT"
          aria-label="要批量添加的规则"
        ></textarea>
        <div class="fields">
          <button type="button" class="btn primary" :disabled="busy !== ''" @click="onBatchAdd">
            {{ busy === 'batch-rule' ? '正在收…' : '加入名单' }}
          </button>
          <span class="mut">
            裸域名按上面选好的「{{ RULE_TYPES.find((x) => x.id === ruleDraft.type)?.label }}」与「{{
              ruleDraft.policy === 'PROXY' ? '走代理' : '直连'
            }}」补全
          </span>
        </div>

        <div v-if="batchResult" class="batch-out">
          <p>
            读到 <strong>{{ batchResult.total }}</strong> 行：新增 {{ batchResult.accepted }} 条、
            覆盖 {{ batchResult.updated }} 条、拒掉 {{ batchResult.rejected.length }} 行。
            <span v-if="!batchResult.written" class="warn">名单原样没动。</span>
          </p>
          <ul v-if="batchResult.rejected.length > 0" class="reject">
            <li v-for="(t, i) in batchResult.rejected" :key="'r' + i">{{ t }}</li>
          </ul>
          <ul v-if="batchResult.dead.length > 0" class="dead">
            <li v-for="(t, i) in batchResult.dead" :key="'d' + i">
              <span class="mono">{{ t }}</span>
            </li>
          </ul>
        </div>
      </div>
      <p class="hint">
        {{ RULE_TYPES.find((x) => x.id === ruleDraft.type)?.hint }} ·
        保存后立即热重载，不用重启代理。
      </p>

      <!-- 判语要说在表前面：这一页剩下的几栏讲的都算"哪条生效"，
           结论摆在表下面等于要用户先读完名单再想起去找判语。
           读失败与"没有问题"必须分开：没读到过时什么都不断言，
           读到过但这次读不到就照旧列出那份，并标上过期。 -->
      <div v-if="warnings.length > 0" class="alert warn dead-box">
        <p>
          这份名单里有 <strong>{{ warnings.length }}</strong> 条写得对却走不到想去的地方。
          <span v-if="warnStale" class="warn">· 读数已过期</span>
        </p>
        <!-- 分类那一小段一句一行。每句都得写在一行里：模板换行会被折成一个空格，
             而中文标点后多出一个空格是很显眼的脏。 -->
        <ul class="kinds">
          <li v-if="shadowCount > 0">
            <strong>{{ shadowCount }}</strong> 条<strong>永远不会命中</strong>——引擎按顺序取<strong>第一条</strong>命中的规则，被前面的规则盖住就一条都轮不到
          </li>
          <li v-if="nodeMissingCount > 0">
            <strong>{{ nodeMissingCount }}</strong> 条<strong>钉的节点不在配置里</strong>，走到它们的连接会直接失败，不会回落当前节点
          </li>
          <li v-if="unknownKinds.length > 0">
            <strong>{{ unknownKinds.length }}</strong> 条是这一版界面没认出来的问题（<span class="mono">{{
              [...new Set(unknownKinds.map((w) => w.kind))].join(' / ')
            }}</span>），判语原样列在下面
          </li>
        </ul>
        <ul class="dead">
          <li v-for="(w, i) in warnings" :key="i">
            <!-- 用户写的那一行照原样立出来：他要在文件里找的就是它，
                 而"为什么"和"怎么办"是后端的话，用正文字体分开。 -->
            <span class="mono">{{ w.line }}</span>
            <span>{{ w.why }}</span>
          </li>
        </ul>
      </div>
      <p v-if="warnError !== ''" class="alert warn">
        「这份名单里的问题」这一栏读不到：{{ warnError }}。
        {{ warnStale ? '上面那份是上一次读到的，可能已经不是现在这个样子。' : '所以这里既不能说有风险，也不能说没有。' }}
      </p>

      <div class="filter">
        <input
          v-model="ruleFilter"
          type="search"
          data-focus-shortcut
          placeholder="按域名 / 匹配方式 / 走向过滤，例如 google 或 直连"
          aria-label="自定义规则过滤"
        />
        <button
          v-if="ruleFilter !== ''"
          type="button"
          class="btn ghost"
          @click="ruleFilter = ''"
        >
          清除过滤
        </button>
      </div>

      <!-- 键盘用户的"跳过导航"：这一张表每行有 6~7 个控件，画满 200 行就是
           一千多个 Tab 停靠点，而下面「拦截域名」那一栏也在同一页上。
           没有这一条，从表头按 Tab 走到下一栏要按一千多次——不是难，是做不到。
           平时不占版面，Tab 到它才现形（见 .skip-link 的样式）。
           条数说出来是让人在按下去之前就知道省掉多少下。 -->
      <a
        v-if="tableControlCount > 20"
        class="skip-link"
        href="#wps-block-section"
        @click="focusBlockSection"
      >
        跳过这张规则表（{{ tableControlCount }} 个控件），到「拦截域名」
      </a>

      <div ref="tableWrap" class="table-wrap">
        <table class="grid-table">
          <thead>
            <tr>
              <th class="num" title="名单里的位置就是命中优先级：排在前面的先命中">序</th>
              <th>匹配</th>
              <th>域名</th>
              <th>走向</th>
              <th class="num" title="本次会话里这一条定过多少条连接。清空统计或重启面板会归零；改过走向或节点的那一条也算重新开始数">命中</th>
              <th class="num">操作</th>
            </tr>
          </thead>
          <tbody>
            <!-- 一条都没筛出来时必须说"在 N 条里没找到"：画一张空表会被读成
                 "你还没写过自定义规则"，那正好把人推向重复添加。 -->
            <tr v-if="ruleFilter !== '' && shownRules.length === 0">
              <td colspan="6" class="mut">
                {{ rules.length }} 条里没有匹配「{{ ruleFilter.trim() }}」的规则。
                换个关键字，或点上面的「清除过滤」看全部。
              </td>
            </tr>
            <tr
              v-for="r in visibleRules"
              :key="r.type + ',' + r.value"
              :class="{ off: r.disabled }"
            >
              <td class="num ord">
                <span class="pos">{{ absIndex(r) + 1 }}</span>
                <span class="ord-act">
                  <button
                    type="button"
                    class="btn sm ghost"
                    :disabled="busy !== '' || !canUp(r)"
                    title="上移一位"
                    @click="onMoveRule(r, -1)"
                  >
                    ↑
                  </button>
                  <button
                    type="button"
                    class="btn sm ghost"
                    :disabled="busy !== '' || !canDown(r)"
                    title="下移一位"
                    @click="onMoveRule(r, 1)"
                  >
                    ↓
                  </button>
                  <button
                    type="button"
                    class="btn sm ghost"
                    :disabled="busy !== '' || absIndex(r) === 0"
                    title="挪到最前面：排在前面的先命中，这一条就能盖住前面那些压住它的规则"
                    @click="onMoveRule(r, 'top')"
                  >
                    顶
                  </button>
                </span>
              </td>
              <td class="mut">{{ r.type }}</td>
              <td class="mono">{{ r.value }}</td>
              <td>
                <span class="pill" :class="policyClass(r.policy)">{{ policyText(r.policy) }}</span>
                <!-- 停用了还显示"走代理"是半句谎话：这一条此刻谁都不走。
                     标在这里而不是只把整行变灰，是因为灰度在深色主题里很容易看不出来，
                     而"这条不生效"是这一行此刻最重要的事实。 -->
                <span v-if="r.disabled" class="pill off-pill">已停用</span>
                <!-- 钉住谁必须看得见：这条流量的去处和"当前节点"不是一回事，
                     只写"走代理"会让人以为它跟着顶栏那个选择走。
                     节点被改名/删掉之后这一格要当场说破：上面判语那一栏是唯一
                     报这件事的地方，可它是按名单顺序摊开的，用户未必扫到对应那一条。
                     名单读不到（nodeNames 为空）时一律按"没问题"处理——
                     读失败不等于节点不存在，那种时候染色等于凭空指控一条好规则。 -->
                <select
                  v-if="pinEditable(r)"
                  class="pin-select inline"
                  :class="{ broken: pinBroken(r) }"
                  :value="r.node"
                  :disabled="busy !== ''"
                  :aria-label="`这条走哪个节点：${r.value}`"
                  :title="pinBroken(r) ? `配置里没有叫 ${r.node} 的节点，这条走不通（不会回落当前节点）；换一个或选「当前节点」` : '这条只走选中的节点'"
                  @change="onSetRulePin(r, ($event.target as HTMLSelectElement).value)"
                >
                  <!-- 坏名字得自己占一项：下拉里若没有当前值，浏览器会显示成空白，
                       于是"钉了个不存在的节点"这一格看起来像"没钉"——正好把要说的反话说了。 -->
                  <option v-if="pinBroken(r)" :value="r.node">⚠ {{ r.node }}（已不存在）</option>
                  <option value="">当前节点</option>
                  <option v-for="n in nodeNames" :key="n" :value="n">{{ n }}</option>
                </select>
                <span
                  v-else-if="r.node"
                  class="pin-tag"
                  :class="{ broken: pinBroken(r) }"
                  :title="pinBroken(r) ? `配置里没有叫 ${r.node} 的节点，这条走不通（不会回落当前节点）` : `这条只走 ${r.node}`"
                  >→ {{ r.node }}</span
                >
              </td>
              <td class="num">
                <!-- 0 留着但排得淡：一份几百条的名单里"0 次"很多，
                     全用正常字重会把真正有数的那几条淹掉。 -->
                <span v-if="hitOf(r) === 0" class="mut">0</span>
                <span v-else>{{ hitOf(r) }}</span>
              </td>
              <td class="num">
                <!-- 停用/打开排在最前面，而且**只读行也有**：
                     手写的 IP-CIDR / GEOIP 恰恰是最想临时关掉来排查的那几条，
                     而它们不能走"改走向"那个按钮（那个会 Normalize，只收域名类型）。
                     停用不改这条的走向，也不删它，所以不在"只读"的限制里。 -->
                <button
                  type="button"
                  class="btn sm ghost"
                  :disabled="busy !== ''"
                  :title="r.disabled ? '重新参与匹配' : '暂时不参与匹配，但留在名单里'"
                  @click="onToggleRule(r)"
                >
                  {{ r.disabled ? '启用' : '停用' }}
                </button>
                <span v-if="!editableRule(r)" class="mut">{{ readonlyNote(r) }}</span>
                <!-- 拦截行只读：那个一键翻转会把「不许出网」悄悄改成走代理或直连，
                     等于在面板里手滑就把黑名单放开。成批名单请用配置的 block: 段。
                     移动不在这个限制里——换顺序不会改这条的走向。 -->
                <span v-else class="row-act">
                  <button type="button" class="btn sm ghost" :disabled="busy !== ''" @click="onFlipRule(r)">
                    改为{{ r.policy === 'PROXY' ? '直连' : '走代理' }}
                  </button>
                  <button type="button" class="btn sm ghost danger" :disabled="busy !== ''" @click="onRemoveRule(r)">
                    删除
                  </button>
                </span>
              </td>
            </tr>
            <tr v-if="hiddenRuleCount > 0">
              <td colspan="6" class="mut window-row">
                只画出了前 <strong>{{ visibleRules.length }}</strong> 条，还有
                <strong>{{ hiddenRuleCount }}</strong> 条没画——一屏几千行没人读得完，
                而这一页每五秒就要把它们全重画一遍。
                <button type="button" class="btn sm ghost" @click="ruleWindow += RULE_WINDOW">
                  再多画 {{ Math.min(RULE_WINDOW, hiddenRuleCount) }} 条
                </button>
                <button type="button" class="btn sm ghost" @click="ruleWindow = shownRules.length">
                  全部画出（{{ shownRules.length }} 条）
                </button>
                <!-- 面板加规则一律追加在名单末尾，而这里默认画的是开头：
                     刚粘完 900 条却看见的还是原来那 7 条，人会以为没加上。
                     这句话就是补这一格的——不展开窗口，因为窗口一展开就回到每五秒重画几千行。 -->
                <span class="win-note">
                  过滤框搜的是整份名单，不用先展开。
                  <template v-if="ruleFilter.trim() === ''">
                    刚添加的规则排在名单<strong>末尾</strong>（优先级最低），多半在没画出来的那一段里。
                  </template>
                </span>
              </td>
            </tr>
            <tr v-if="rules.length === 0">
              <td colspan="6" class="mut">
                {{
                  rulesKnown
                    ? '还没有自定义规则。上面填个域名，选「走代理」或「直连」即可。'
                    : '还没读到过这份名单，所以这里既不是「有规则」也不是「没规则」——先解决上面的错误。'
                }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <p class="hint">
        最左那一列是这条在名单里的位置——引擎命中第一条就停，所以位置就是优先级。
        <span class="mono">↑</span> 与 <span class="mono">↓</span> 和相邻那条换位，
        <span class="mono">顶</span> 挪到最前面；正筛着的时候上下会灰掉（邻居被筛掉了，没得换），
        <span class="mono">顶</span> 仍然可用。
      </p>

      <p class="hint">
        上面那三种是面板能改的全部。手写的
        <span class="mono">IP-CIDR</span> / <span class="mono">GEOIP</span> /
        <span class="mono">DOMAIN-REGEX</span> 行原样保留、只读显示（移动它们是可以的），
        要改内容就直接编辑 <span class="mono">user-rules.txt</span>——
        进程在跑时文件一改就自动生效，面板这一栏跟着刷新。
      </p>
    </section>
</template>
