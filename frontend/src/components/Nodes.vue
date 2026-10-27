<script setup lang="ts">
// Nodes 只管节点：列、测速、选用、增删改。
//
// 它刻意自己发请求、自己管忙状态，不走 App.vue 的 act()：
// 共用一个 busy 会让「正在测速」把顶栏的「停止」按钮也一起灰掉。
// 全局动作（启停、切模式、切节点开关）的忙态在 App.vue，页内的在这里。
import { computed, onMounted, ref } from 'vue'
import type { NodeTraffic, ProfileSpec, ProfileTest, ProfileView } from '../types'
import {
  addProfile,
  errorText,
  profiles,
  protocols,
  removeProfile,
  setActiveProfile,
  testProfile,
  updateProfile
} from '../api'
import { formatBytes } from '../format'
import { nodeTests, pruneTests, rememberTest } from '../nodetests'
import { agoText } from '../ageclock'

const props = defineProps<{ running: boolean; byNode: NodeTraffic[] }>()

/**
 * 这个节点本次会话用掉了多少。
 *
 * 放在选节点这一页而不是只放流量页：配额是节点的属性，
 * "要不要切过去"的决策点上看得见"它已经跑了多少 / 别的节点跑了多少"才有意义。
 * 自动切换过之后尤其重要——不看这里，只会以为量都是当前这个节点用的。
 */
const usageOf = computed(() => {
  const m = new Map<string, NodeTraffic>()
  for (const n of props.byNode) {
    m.set(n.node, n)
  }
  return m
})

/**
 * 这一行要说的那几个数。
 *
 * 有了跨重启那份账之后，"这个节点没跑过"和"这个节点这个月已经跑了 40GB、
 * 但本次会话还没走过它"是两件完全不同的事——后者恰恰是**不该切过去**的那个。
 * 所以 prior 只在它真的存在时才写出来，且和"本次"分开写，不合成一个含混的数。
 */
function usageText(name: string): string {
  const u = usageOf.value.get(name)
  if (!u) {
    return '本次没有它的量'
  }
  const session = u.up + u.down
  const parts: string[] = []
  if (session > 0 || u.conns > 0) {
    parts.push(`本次 ${formatBytes(session)} · ${u.conns} 条`)
  } else if (u.prior > 0) {
    parts.push('本次没跑过')
  } else {
    return '本次没有它的量'
  }
  if (u.prior > 0) {
    parts.push(`累计 ${formatBytes(session + u.prior)}`)
  }
  return parts.join(' · ')
}

/**
 * 配额那一行（没设配额的节点没有这一行）。
 *
 * 用的量是**累计**——本次会话加上上一次进程留在账本里的那份：
 * 配额是按周期结算的，只看本次的话重启一次就像重新买了一张卡。
 * 也正因如此，这一行依赖 §9.5.2 那份落盘的账，它俩是一套东西。
 *
 * 颜色分三档而不是"超了才红"：配额这件事有用的是**提前**知道，
 * 到 100% 才提示等于让人在月底被降速之后才发现。
 */
const quotaOf = computed(() => {
  const m = new Map<string, { text: string; cls: string; pct: number }>()
  for (const p of list.value) {
    if (!p.quotaBytes) {
      continue
    }
    const u = usageOf.value.get(p.name)
    const used = u ? u.up + u.down + u.prior : 0
    const pct = Math.round((used / p.quotaBytes) * 100)
    const left = p.quotaBytes > used ? p.quotaBytes - used : 0
    m.set(p.name, {
      pct,
      cls: pct >= 100 ? 'err' : pct >= 80 ? 'warn' : 'mut',
      // 尾巴那句话说的是"接下来会怎样"，所以超了和快超了必须是两种说法：
      // 已经超了还写"再跑下去要超配额了"，等于在用户最需要准确信息的那一刻说反话。
      text:
        `配额 ${p.quotaText || formatBytes(p.quotaBytes)} · 已用 ${pct}%` +
        (left ? ` · 剩 ${formatBytes(left)}` : '') +
        (pct >= 100 ? ' ——已经超了，留意降速或停服' : pct >= 80 ? ' ——再跑下去要超配额了' : '')
    })
  }
  return m
})

const CONGESTIONS = ['bbr', 'bbrv2', 'cubic', 'reno']

/** 协议名由后端给出（config.Protocols），界面不自己写死一份免得对不上。 */
const PROTOCOL_HINTS: Record<string, string> = {
  hysteria2: 'QUIC 隧道，支持带宽整形与拥塞算法选择',
  trojan: 'TCP + TLS 隧道，只有地址/口令/SNI 有用；目前不转发 UDP'
}

const list = ref<ProfileView[]>([])
const active = ref('')
const protocolChoices = ref<string[]>([])
const failure = ref('')
const notice = ref('')
const busy = ref('')

// 和 Rules 页同一个道理：读到过一次才算知道有几个节点。
// 读失败却写「还没有节点」，用户就会去点「新增节点」，把磁盘上好好的配置盖掉。
const listKnown = ref(false)

/** pendingRemove 非空表示这个名字已经点过一次「删除」、正在等第二次确认。 */
const pendingRemove = ref('')

/** editing 非空表示正在编辑某个节点；'' 表示新增。 */
const editing = ref<string | null>(null)
const draft = ref<ProfileSpec>(blankSpec())
/**
 * 读数从模块级那份拿（见 `nodetests.ts`），这里只把它换算成界面要的形状。
 *
 * `ago` 是必须的一行：结果现在跨页留着，没有"这次数是什么时候的"，
 * 一个十分钟前的延迟就会被读成刚刚测出来的。
 */
const tests = computed<Record<string, ProfileTest & { ago: string }>>(() => {
  const out: Record<string, ProfileTest & { ago: string }> = {}
  for (const [name, entry] of Object.entries(nodeTests)) {
    if (entry) {
      out[name] = { ...entry.res, ago: agoText(entry.at) }
    }
  }
  return out
})

/**
 * 后端在电路通了之后顺带取页面的地址，与 `internal/service` 里那个常量同一句。
 * 写在这里只为给悬停说明用——判据和取哪个页面都由后端决定。
 */
const pageProbeURL = 'https://www.gstatic.com/generate_204'

function blankSpec(): ProfileSpec {
  return {
    name: '',
    type: 'hysteria2',
    addr: '',
    auth: '',
    sni: '',
    insecure: false,
    bandwidthUp: '200 mbps',
    bandwidthDown: '1000 mbps',
    congestion: 'bbr',
    fastOpen: true,
    quota: ''
  }
}

/** 当前草稿是不是 trojan：hysteria2 专属字段该整个藏起来。 */
const isTrojan = (): boolean => draft.value.type === 'trojan'

const editorOpen = computed(() => editing.value !== null)

/** 延迟条按 300ms 满格折算，超过就顶满——比较谁快谁慢看的是长度不是小数点。 */
function latencyClass(ms: number): string {
  if (ms < 80) {
    return 'meter'
  }
  return ms < 160 ? 'meter mid' : 'meter bad'
}

function latencyWidth(ms: number): string {
  return `${Math.max(6, Math.min(100, Math.round((ms / 300) * 100)))}%`
}

async function load(): Promise<void> {
  failure.value = ''
  try {
    const [p, ps] = await Promise.all([profiles(), protocols()])
    list.value = p.profiles ?? []
    active.value = p.active
    protocolChoices.value = ps ?? []
    listKnown.value = true
    // 回读之后顺手清掉已经没有归属的读数：改名与删除都会留下没人看的键，
    // 而名字正是这次操作改掉的那个东西，留着就成了"这条数属于哪个节点"靠猜。
    pruneTests(new Set(list.value.map((x) => x.name)))
  } catch (err) {
    failure.value = `读取节点失败：${errorText(err)}`
  }
}

/** 所有写操作共用：置忙、执行、提示、回读。回读是必须的——界面显示的应当是磁盘与运行态的真实值。 */
async function run(key: string, fn: () => Promise<void>, done: string): Promise<void> {
  if (busy.value !== '') {
    return
  }
  busy.value = key
  notice.value = ''
  failure.value = ''
  pendingRemove.value = ''
  try {
    await fn()
    notice.value = done
    await load()
  } catch (err) {
    failure.value = `${done.replace(/。$/, '')}失败：${errorText(err)}`
  } finally {
    busy.value = ''
  }
}

const onUse = (name: string): Promise<void> =>
  run(`use:${name}`, () => setActiveProfile(name), `已切换到节点 ${name}。`)

/**
 * 删除要确认两次。
 *
 * 它改的是磁盘上的配置，撤不回来；删的又恰好是在用的节点时，后端会静默改选剩下的
 * 第一个节点，正在用的那条隧道当场断掉。一次点击做不完这件事，所以第一次只把
 * 后果摆出来，第二次才真删。（不用浏览器对话框：面板里它会被 webview 吞掉或挡住。）
 */
function askRemove(name: string): void {
  pendingRemove.value = pendingRemove.value === name ? '' : name
  notice.value = ''
  failure.value = ''
}

const onRemove = (name: string): Promise<void> =>
  run(`rm:${name}`, () => removeProfile(name), `已删除节点 ${name}。`)

/**
 * 等第二次确认时，把这次删除真正会发生的事写在表头下面。
 * 「删在用的节点会改选另一个」这件事发生在 Go 侧（RemoveProfile 先装配新出站再改配置），
 * 界面上不写出来，用户只会看到节点名莫名其妙换了一个。
 */
const removeWarning = computed(() => {
  const name = pendingRemove.value
  if (name === '') {
    return ''
  }
  if (list.value.length <= 1) {
    return `确认删除「${name}」？这是最后一个节点——客户端没有节点就起不来，后端会拒绝这次删除。`
  }
  if (list.value.some((p) => p.name === name && p.active)) {
    return `确认删除「${name}」？它正在使用中：后端会改选剩下的第一个节点，当前这条隧道随即断开，`
      + '走代理的连接要重连。这一步直接写盘，撤不回来。'
  }
  return `确认删除「${name}」？这一步直接写盘，撤不回来。`
})

const onTest = async (name: string): Promise<void> => {
  busy.value = `test:${name}`
  notice.value = ''
  failure.value = ''
  try {
    const res = await testProfile(name, 'www.gstatic.com:443')
    rememberTest(name, res)
  } catch (err) {
    failure.value = `测速失败：${errorText(err)}`
  } finally {
    busy.value = ''
  }
}

/** 逐个测：并发握手会让每条延迟都被彼此拖高，测出来的数就没意义了。 */
async function onTestAll(): Promise<void> {
  if (busy.value !== '') {
    return
  }
  busy.value = 'test-all'
  notice.value = ''
  failure.value = ''
  for (const p of list.value) {
    try {
      const res = await testProfile(p.name, 'www.gstatic.com:443')
      rememberTest(p.name, res)
    } catch (err) {
      failure.value = `测到 ${p.name} 时失败：${errorText(err)}`
      break
    }
  }
  busy.value = ''
}

function startAdd(): void {
  editing.value = ''
  pendingRemove.value = ''
  draft.value = blankSpec()
}

function startEdit(p: ProfileView): void {
  editing.value = p.name
  pendingRemove.value = ''
  // 口令不回显：留空表示不改。这与后端「掩码即沿用原值」的约定一致。
  //
  // 协议也照"留空即不改"办：这里以前写的是 `p.type || 'hysteria2'`，
  // 于是一个协议名没读上来的节点，只要用户在表单里点一次保存，
  // 就被真的改成 hysteria2 —— 显示层的缺口变成了写盘的破坏。
  draft.value = {
    ...blankSpec(),
    name: p.name,
    type: p.type,
    addr: p.addr,
    sni: p.sni,
    auth: '',
    // 配额把原文带回来：留空在这套表单里的意思是"不改"，
    // 所以不回填就等于让用户对着一个空白格猜"这个节点到底有没有额度"。
    quota: p.quotaText
  }
}

const onSaveProfile = (): Promise<void> =>
  run('save-profile', async () => {
    if (editing.value === '') {
      await addProfile(draft.value)
    } else if (editing.value !== null) {
      await updateProfile(editing.value, draft.value)
    }
    editing.value = null
  }, editing.value === '' ? '已新增代理服务。' : '已保存节点修改。')

onMounted(load)
</script>

<template>
  <div class="view">
    <p v-if="notice" class="banner">{{ notice }}</p>
    <p v-if="failure" class="alert">{{ failure }}</p>

    <section class="card">
      <h2>
        节点
        <span class="count">{{ listKnown ? `${list.length} 个` : '个数未知' }} · 当前 {{ active || '未选择' }}</span>
        <span class="act">
          <button type="button" class="btn sm ghost" :disabled="busy !== '' || list.length === 0" @click="onTestAll">
            {{ busy === 'test-all' ? '测速中…' : '全部测速' }}
          </button>
          <button type="button" class="btn sm" :disabled="editorOpen" @click="startAdd">新增节点</button>
        </span>
      </h2>

      <p v-if="removeWarning" class="alert warn">{{ removeWarning }}</p>

      <div class="table-wrap">
        <table class="grid-table">
          <thead>
            <tr>
              <th>节点</th>
              <th>协议</th>
              <th>地址</th>
              <th>SNI</th>
              <th>口令</th>
              <th class="lat">延迟</th>
              <th class="num">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="p in list" :key="p.name" :class="{ current: p.active }">
              <td class="name">
                <b>{{ p.name }}</b>
                <span v-if="p.active" class="pill proxy">使用中</span>
                <span
                  class="mut usage"
                  :title="`${p.name}：本次会话是这一轮跑掉的，累计含上一次进程留下的账（可能少算最后一段）`"
                >
                  {{ usageText(p.name) }}
                </span>
                <span v-if="quotaOf.get(p.name)" :class="['usage', quotaOf.get(p.name)!.cls]">
                  {{ quotaOf.get(p.name)!.text }}
                </span>
              </td>
              <td class="proto">
                <!-- 协议名缺失就写个横杠，不写 hysteria2：
                     写死一个默认值会让人以为这条节点走 QUIC，然后按 QUIC 去排查。 -->
                {{ p.type || '—' }}
                <span
                  class="pill"
                  :class="p.udp ? 'direct' : 'warn'"
                  :title="p.udp
                    ? '这个节点能转发 UDP：QUIC / 游戏 / 语音都走得通'
                    : '这个节点不转发 UDP：QUIC 流量会被明确拒绝，表现为应用超时'"
                >{{ p.udp ? 'UDP' : '无 UDP' }}</span>
              </td>
              <td class="mono">{{ p.addr || '—' }}</td>
              <td class="mono">{{ p.sni || '跟随地址' }}</td>
              <td class="auth mut">{{ p.authSet ? '已设置' : '未设置' }}</td>
              <td class="lat">
                <template v-if="tests[p.name]">
                  <span v-if="tests[p.name].ok" :class="latencyClass(tests[p.name].latencyMs)">
                    <span class="bar"><i :style="{ width: latencyWidth(tests[p.name].latencyMs) }"></i></span>
                    <span>{{ tests[p.name].latencyMs }} ms</span>
                  </span>
                  <span v-else class="meter bad">
                    <span class="bar"><i style="width: 100%"></i></span>
                    <span>不通</span>
                  </span>
                  <!-- 测的到底是哪个 IP：一个域名可以解析到好几个地址，
                       后端报的那个才是这次握手真正用的，不写出来就只能猜。 -->
                  <small v-if="tests[p.name].remote" class="mut remote">{{ tests[p.name].remote }}</small>
                  <!-- 结果跨页留着之后，"这是什么时候的数"就变成必须写出来的东西：
                       没有这一行，一次十分钟前的测速会被当成刚刚测的。 -->
                  <small class="ago">{{ tests[p.name].ago }}测的</small>
                  <!-- 失败原因写在版面上，不藏在悬停里：DNS 失败、证书失败、超时
                       三种情况各自要去查的地方完全不同，只说"不通"等于让人猜。 -->
                  <small v-if="!tests[p.name].ok && tests[p.name].error" class="why">
                    {{ tests[p.name].error }}
                  </small>
                  <!-- 电路通了不等于页面取回来。兼底型节点就是这个缺口：隧道正常建立，
                       节点那边把流量交给一个兼底的 web 服务器，任何站点回来的都是同一张
                       400 页面——延迟、握手、探测全都好看，浏览器一个页面都打不开。
                       所以这一行必须单独有它自己的句子，不能并到上面那个 ms 数里。 -->
                  <small
                    v-if="tests[p.name].pageChecked && !tests[p.name].pageErr"
                    class="page ok"
                    :title="`取的是 ${pageProbeURL}：状态码、Server 头与字节数都是原样报回来的`"
                  >页面 {{ tests[p.name].page }}</small>
                  <small
                    v-else-if="tests[p.name].pageChecked"
                    class="page bad"
                    :title="`电路通了，但经这个节点取 ${pageProbeURL} 没取回页面。失败原文：`"
                  >电路通了，页面取不回</small>
                  <small
                    v-if="tests[p.name].pageChecked && tests[p.name].pageErr"
                    class="why"
                  >{{ tests[p.name].pageErr }}</small>
                </template>
                <span v-else class="mut">未测</span>
              </td>
              <td class="num">
                <span class="row-act">
                  <button v-if="!p.active" type="button" class="btn sm" :disabled="busy !== ''" @click="onUse(p.name)">
                    选用
                  </button>
                  <button type="button" class="btn sm ghost" :disabled="busy !== ''" @click="onTest(p.name)">
                    {{ busy === `test:${p.name}` ? '测速中…' : '测速' }}
                  </button>
                  <button type="button" class="btn sm ghost" :disabled="busy !== '' || editorOpen" @click="startEdit(p)">
                    编辑
                  </button>
                  <template v-if="pendingRemove === p.name">
                    <button type="button" class="btn sm danger" :disabled="busy !== ''" @click="onRemove(p.name)">
                      确认删除
                    </button>
                    <button type="button" class="btn sm ghost" :disabled="busy !== ''" @click="pendingRemove = ''">
                      取消
                    </button>
                  </template>
                  <button
                    v-else
                    type="button"
                    class="btn sm ghost danger"
                    :disabled="busy !== '' || editorOpen"
                    @click="askRemove(p.name)"
                  >
                    删除
                  </button>
                </span>
              </td>
            </tr>
            <tr v-if="list.length === 0">
              <td colspan="7" class="mut">
                {{
                  listKnown
                    ? '还没有节点，点上面的「新增节点」加一个。'
                    : '没读到过节点列表——上面若是错误，这里既不是「有节点」也不是「没节点」。'
                }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="editing !== null" class="editor">
        <h2>{{ editing === '' ? '新增节点' : `编辑 ${editing}` }}</h2>
        <div class="form">
          <label>
            名称
            <input v-model="draft.name" placeholder="新加坡-1" />
          </label>
          <label>
            协议
            <select v-model="draft.type">
              <!-- 后端没给出协议名时（老配置、或读失败）给一个明说"保持不变"的空选项：
                   没有这一条，下拉框会显示成第一项 hysteria2，
                   看着像"当前就是它"，而模型里其实是空。 -->
              <option v-if="!draft.type" value="">读不到当前协议（保存则保持不变）</option>
              <option v-for="pt in protocolChoices" :key="pt" :value="pt">{{ pt }}</option>
            </select>
          </label>
          <label>
            地址
            <input v-model="draft.addr" class="mono" placeholder="example.com:443" />
          </label>
          <label>
            认证口令
            <input
              v-model="draft.auth"
              type="password"
              autocomplete="new-password"
              :placeholder="editing === '' ? '必填' : '留空表示不改'"
            />
          </label>
          <label>
            SNI
            <input v-model="draft.sni" class="mono" placeholder="留空则跟随地址" />
          </label>
          <!-- 配额与协议无关：trojan 节点照样按流量结算。 -->
          <label>
            配额
            <input v-model="draft.quota" class="mono" placeholder="1000GB / 1.5TiB，留空不改" />
            <span class="hint">
              留空是"保持原样"，不是"清除"——要取消配额，请在配置文件里删掉那一行。
            </span>
          </label>
          <!-- 带宽/拥塞是 hysteria2 独有的，trojan 节点上显示出来只会误导。 -->
          <template v-if="!isTrojan()">
            <label>
              上行带宽
              <input v-model="draft.bandwidthUp" placeholder="200 mbps" />
            </label>
            <label>
              下行带宽
              <input v-model="draft.bandwidthDown" placeholder="1000 mbps" />
            </label>
            <label>
              拥塞控制
              <select v-model="draft.congestion">
                <option v-for="c in CONGESTIONS" :key="c" :value="c">{{ c }}</option>
              </select>
            </label>
          </template>
        </div>
        <p class="hint proto">{{ PROTOCOL_HINTS[draft.type] ?? '' }}</p>
        <div class="editor-foot">
          <div class="row">
            <label v-if="!isTrojan()" class="switch">
              <input v-model="draft.fastOpen" type="checkbox" />
              <span class="track" aria-hidden="true"></span>
              <span>启用 TFO</span>
            </label>
            <label class="switch">
              <input v-model="draft.insecure" type="checkbox" />
              <span class="track" aria-hidden="true"></span>
              <span>跳过证书校验</span>
            </label>
          </div>
          <div class="row">
            <button type="button" class="btn ghost" :disabled="busy !== ''" @click="editing = null">取消</button>
            <button type="button" class="btn primary" :disabled="busy !== ''" @click="onSaveProfile">
              {{ busy === 'save-profile' ? '保存中…' : '保存节点' }}
            </button>
          </div>
        </div>
        <p v-if="!running" class="hint">代理当前未运行，保存只改磁盘上的配置，启动后才生效。</p>
      </div>

      <div class="notes">
        <p v-if="list.some((p) => !p.udp)" class="hint">
          标着「无 UDP」的节点不转发 UDP：QUIC（HTTP/3）、语音、游戏那类流量会被明确拒绝，
          表现是"网页都正常，就某个 App 一直转圈"。要这类流量就选 hysteria2 节点。
        </p>
        <p class="hint">
          新增节点不会被自动选中；切节点只换出站、不重启服务（约 0.1 秒），
          监听、网卡、路由和正在直连的连接都不受影响，只有已建立的那条隧道会断开。
        </p>
      </div>
    </section>
  </div>
</template>

<style scoped>
.name .usage {
  display: block;
  font-size: var(--fs-caption);
  margin-top: 1px;
}
/* 徽标与节点名同一条基线。原来 b 是 display:block，把「使用中」顶到名字上面，
   行高凭空多一行，两行还都左对齐成一坨，看着像表格坏了。 */
.name {
  display: flex;
  align-items: center;
  gap: 7px;
  max-width: 13em;
}

.name b {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
  color: var(--fg);
}

/* 协议名与能力徽标别被挤到两行去；口令和延迟同理。
   这张表列多，浏览器分宽度时会把短词逐字竖排（「已/设/置」），行高随之炸开。 */
.proto,
td.auth,
.lat {
  white-space: nowrap;
}

.proto .pill {
  margin-left: 2px;
}

/* 测速失败原因：允许换行，但别把这一列拉宽——表格右侧还有操作按钮。 */
.why {
  display: block;
  margin-top: 2px;
  max-width: 16em;
  font-size: var(--fs-micro);
  line-height: 1.35;
  color: var(--muted);
  white-space: normal;
  overflow-wrap: anywhere;
}

/* 「页面」那一行是应用层的结论，与上面的 ms 数是两件事，所以给它自己的颜色：
   取回了才是绿的，电路通了但取不回要红——把它画成中性灰会被读成"还没测"。 */
.page {
  display: block;
  margin-top: 2px;
  font-size: var(--fs-micro);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.page.ok {
  color: var(--ok);
}

.page.bad {
  color: var(--err);
  font-weight: 600;
}

/* 测速结果现在跨页留着，于是"这条数几时测的"必须一起留着。 */
.ago {
  display: block;
  margin-top: 1px;
  font-size: var(--fs-micro);
  color: var(--muted-2);
  white-space: nowrap;
}

/* 地址和 SNI 是这张表里唯一能无限长的两列，让它们先让宽度。
   硬撑的结果是右侧的操作按钮被挤出可视区——那比看不全地址严重得多。 */
td.mono {
  max-width: 11em;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* 操作区：整排都是无边框的，只有「选用」这个真正的主动作带描边，
   一眼能看出该点哪个。删除永远在最右，位置固定。 */
.row-act {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 2px;
}

.row-act .btn.sm.ghost {
  border-color: transparent;
  background: transparent;
  box-shadow: none;
}

.row-act .btn.sm.ghost:hover:not(:disabled) {
  background: rgba(255, 255, 255, 0.08);
}

/* 使用中那一行的标记：把这一行整体提一档亮度，
   不用读徽标也知道隧道现在挂在谁身上。 */
tr.current td {
  background: rgba(59, 130, 246, 0.05);
}

tr.current td:first-child {
  box-shadow: inset 2px 0 0 var(--accent);
}

/* 底部说明：这是文档不是数据，收成一条脚注块，
   但仍摆在版面上（不藏进悬停提示）——触屏与截图都读得到。 */
.notes {
  margin-top: var(--sp-4);
  padding-top: var(--sp-3);
  border-top: 1px solid var(--line);
  display: flex;
  flex-direction: column;
  gap: 7px;
}

.editor {
  margin-top: var(--sp-5);
  padding: var(--sp-4);
  border: 1px solid var(--line);
  border-radius: var(--r-md);
  background: rgba(0, 0, 0, 0.22);
  box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.3);
}

.editor h2 {
  margin: 0 0 var(--sp-3);
  font-size: var(--fs-lead);
  font-weight: 600;
  letter-spacing: -0.01em;
  color: var(--fg);
}

.proto {
  margin-top: var(--sp-3);
}

.editor-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-3);
  flex-wrap: wrap;
  margin-top: var(--sp-4);
}

.mut {
  color: var(--muted);
}

/* 实测地址：跟在延迟下面一行，字号小一档，别抢延迟那个数。 */
.remote {
  display: block;
  font-size: var(--fs-micro);
  font-family: var(--mono);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  max-width: 14em;
  color: var(--muted);
}
</style>
