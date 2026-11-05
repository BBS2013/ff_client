<script setup lang="ts">
// Settings 编辑 config.yaml，外加两个"改一次管很久"的全局设置（系统代理、TUN 参数）。
// 三条必须守住的红线：
//  1. 明文口令永远不显示。后端 readForm 只给 ********，改了就写新值，没改就原样保留。
//  2. 留空 = 不改，不是清空。对应后端的「留空即不变」语义。
//  3. 保存后必须提示重启才生效——配置文件改了，运行中的代理不会自己换端口。
import { computed, onMounted, ref } from 'vue'
import type { BuildInfo, ConfigForm, InboundForm, Pending, Status, SysProxyLedger, SystemProxyStatus } from '../types'
import { buildInfo, errorText, exportDiagnostics, exportLogs, readConfig, saveConfig } from '../api'
import { TUN_PHASE_TEXT, formatClock, tunPhase } from '../format'

const props = defineProps<{
  status: Status
  sys: SystemProxyStatus | null
  /** 系统代理记账那一行：措辞全在 Go 那边，这里只挑颜色 */
  ledger: SysProxyLedger | null
  busy: string
  pending: Pending
}>()

const emit = defineEmits<{
  (e: 'tun', enable: boolean): void
  (e: 'sysproxy', enable: boolean): void
  (e: 'goto', view: string): void
}>()

const form = ref<ConfigForm | null>(null)
const loading = ref(true)
const saving = ref(false)
const notice = ref('')
const failure = ref('')

// DNS 与 route_exclude 在配置里是列表，这里用「一行一个」呈现，比逗号分隔更好读。
// 后端 splitList 会把逗号也拆开，所以两种写法它都认。
const dnsText = ref('')
const excludeText = ref('')

const LOG_LEVELS = ['debug', 'info', 'warn', 'error']
const tun = computed(() => props.status.tun)
const phase = computed(() => tunPhase(props.status.tun, props.pending.tun))
/** knob 跟着用户点下去的那个值走：拆 TUN 要等协议栈收尾与 iptables，慢是设计内的。 */
const tunChecked = computed(() => props.pending.tun ?? props.status.tun.running)
const sysChecked = computed(() => props.pending.sysproxy ?? props.sys?.enabled ?? false)

/**
 * 后端名翻译成人话。三条路的覆盖面差别很大，
 * 只显示 "kde" 用户没法判断自己是不是该去改 KDE 设置。
 */
const BACKEND_TEXT: Record<string, string> = {
  gnome: 'GNOME（gsettings）',
  kde: 'KDE（kioslaverc）',
  env: '环境变量（environment.d）',
}
// 「这份界面是哪一次构建」——只在进这一页时读一次：它描述的是进程本身，
// 不会在页面停留期间变化（会变的只有磁盘上那份二进制，而那正是重新读一次要告诉你的事）。
const build = ref<BuildInfo | null>(null)
const buildError = ref('')
const buildTimeText = computed(() =>
  build.value && build.value.exeModTime > 0
    ? new Date(build.value.exeModTime).toLocaleString('zh-CN', { hour12: false })
    : '（读不到）'
)
const startedText = computed(() =>
  build.value ? new Date(build.value.startedAt).toLocaleString('zh-CN', { hour12: false }) : '（读不到）'
)

async function loadBuild(): Promise<void> {
  try {
    build.value = await buildInfo()
    buildError.value = ''
  } catch (err) {
    buildError.value = errorText(err)
  }
}

const diagBusy = ref(false)
const diagPath = ref('')
const diagError = ref('')
const logBusy = ref(false)
const logPath = ref('')
const logError = ref('')

async function onExportLogs(): Promise<void> {
  logBusy.value = true
  logError.value = ''
  try {
    logPath.value = await exportLogs()
  } catch (err) {
    logError.value = errorText(err)
  } finally {
    logBusy.value = false
  }
}

async function onDiag(): Promise<void> {
  diagBusy.value = true
  diagError.value = ''
  try {
    diagPath.value = await exportDiagnostics()
  } catch (err) {
    diagError.value = errorText(err)
  } finally {
    diagBusy.value = false
  }
}

const sysBackend = computed(() => BACKEND_TEXT[props.sys?.backend ?? ''] ?? '—')
// 记账那五种状态各有一句话，措辞只在 Go 那边有一份（那边有单测）；
// 这里只决定"要不要用告警色"——安静的两种不许画成红。
const ledgerText = computed(() => (props.ledger ? props.ledger.text : '记账：读取中…'))
const ledgerTone = computed(() => {
  const st = props.ledger?.state ?? ''
  if (st === 'orphan' || st === 'unreadable' || st === 'error' || st === 'stale') return 'warn'
  return 'mut'
})

function blankInbound(): InboundForm {
  return { type: 'socks5', listen: '127.0.0.1:7891', username: '', password: '' }
}

async function load(): Promise<void> {
  loading.value = true
  failure.value = ''
  try {
    const f = await readConfig()
    form.value = f
    dnsText.value = (f.dnsServers ?? []).join('\n')
    excludeText.value = (f.tun?.routeExclude ?? []).join('\n')
    // 与配置读数分开走：这一格读不到不该把整页说成"读取配置失败"，
    // 而它自己会在卡片里写明读不到。
    void loadBuild()
  } catch (err) {
    failure.value = `读取配置失败：${errorText(err)}`
  } finally {
    loading.value = false
  }
}

async function save(): Promise<void> {
  if (!form.value) {
    return
  }
  saving.value = true
  notice.value = ''
  failure.value = ''
  const mtu = Number(form.value.tun.mtu)
  const payload: ConfigForm = {
    ...form.value,
    dnsServers: dnsText.value.split('\n'),
    tun: {
      ...form.value.tun,
      routeExclude: excludeText.value.split('\n'),
      // 清空 MTU 输入框会让 v-model.number 给出 NaN，NaN 过不了 JSON 边界；
      // 这里按「没填」处理，交给后端沿用磁盘上的原值。
      mtu: Number.isFinite(mtu) && mtu > 0 ? Math.round(mtu) : 0,
      // enable 不在表单里改：开关走 SetTUNEnabled，它自己会把同一个字段写盘。
      // 这里若按打开表单那一刻的旧值回写，就会把用户刚点开的 TUN 在磁盘上关掉。
      enable: props.status.tun.enabled
    }
  }
  try {
    await saveConfig(payload)
    // 保存后重新拉一次：后端会把掩码和「留空即不变」的字段原样回填，
    // 这样界面显示的始终是磁盘上的真实状态，而不是用户刚敲的半成品。
    await load()
    notice.value = props.status.running
      ? '已保存（原文件已备份为 config.yaml.bak）。代理需重启后才会使用新配置。保存会按规范格式重写整个文件，原有注释不会保留。'
      : '已保存（原文件已备份为 config.yaml.bak）。下次启动生效。保存会按规范格式重写整个文件，原有注释不会保留。'
  } catch (err) {
    failure.value = `保存失败：${errorText(err)}`
  } finally {
    saving.value = false
  }
}

function addInbound(): void {
  form.value?.inbounds.push(blankInbound())
}

function removeInbound(i: number): void {
  form.value?.inbounds.splice(i, 1)
}

// http 入站不支持认证，界面上直接把凭据两栏藏掉，免得填了被后端拒绝。
function needsAuth(inb: InboundForm): boolean {
  return inb.type === 'socks5'
}

onMounted(load)
</script>

<template>
  <div class="view">
    <section v-if="loading" class="card">
      <p class="empty">正在读取配置…</p>
    </section>

    <section v-else-if="!form" class="card">
      <p class="alert">{{ failure || '配置不可读' }}</p>
      <button type="button" class="btn" @click="load">重试</button>
    </section>

    <template v-else>
      <p v-if="notice" class="banner">{{ notice }}</p>
      <p v-if="failure" class="alert">{{ failure }}</p>

      <section class="card">
        <h2>
          当前节点
          <span class="act">
            <button type="button" class="btn sm ghost" @click="emit('goto', 'nodes')">去节点页管理</button>
          </span>
        </h2>
        <dl class="kv">
          <dt>节点</dt>
          <dd>{{ form.activeName || '—' }}</dd>
          <dt>地址</dt>
          <dd class="mono">{{ form.activeAddr || '—' }}</dd>
          <dt>文件里的默认模式</dt>
          <dd>{{ form.mode }}</dd>
        </dl>
        <p class="hint">
          节点的新增、编辑、删除与切换在「节点」页做，这里只读展示。
          这样口令不会被表单的「留空即不变」语义裹挟，改一个节点也不会顺手改掉全局配置。
        </p>
      </section>

      <section class="card">
        <h2>
          入站
          <span class="count">{{ form.inbounds.length }} 条</span>
          <span class="act">
            <button type="button" class="btn sm ghost" @click="addInbound">新增入站</button>
          </span>
        </h2>
        <div class="table-wrap">
          <table class="grid-table">
            <thead>
              <tr>
                <th>协议</th>
                <th>监听地址</th>
                <th>用户名</th>
                <th>口令</th>
                <th class="num">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(inb, i) in form.inbounds" :key="`${i}-${inb.type}-${inb.listen}-${inb.allowLan}`">
                <td>
                  <select v-model="inb.type" aria-label="入站协议">
                    <option value="socks5">SOCKS5</option>
                    <option value="http">HTTP</option>
                  </select>
                </td>
                <td><input v-model="inb.listen" class="mono listen" placeholder="127.0.0.1:7891" aria-label="监听地址" /></td>
                <td v-if="needsAuth(inb)">
                  <input v-model="inb.username" type="password" aria-label="用户名" placeholder="可留空" />
                </td>
                <td v-else class="mut" colspan="2">HTTP 入站不支持认证</td>
                <td v-if="needsAuth(inb)">
                  <input v-model="inb.password" type="password" aria-label="口令" placeholder="可留空" />
                </td>
                <td class="num">
                  <button type="button" class="btn sm ghost danger" @click="removeInbound(i)">删除</button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-if="form.inbounds.length === 0" class="alert tail">
          至少要保留一个入站，否则保存会被后端拒绝。
        </p>
        <p class="alert warn tail">
          监听地址不要用 0.0.0.0 / :: 或局域网 IP，除非 SOCKS5 已填写用户名与口令，或在 YAML 里显式写了
          <code>allow_lan: true</code>。否则保存会被拒绝——对网段开放的无认证代理等于把本机流量出口借给整段局域网。
        </p>
      </section>

      <section class="card">
        <h2>规则、DNS 与日志</h2>
        <div class="form">
          <label>
            规则文件
            <input v-model="form.rulesFile" class="mono" placeholder="./assets/rules.txt" />
          </label>
          <label>
            GeoIP 数据库
            <input v-model="form.geoipPath" class="mono" placeholder="./assets/geoip.mmdb" />
          </label>
          <label>
            DNS 服务器（一行一个）
            <textarea v-model="dnsText" rows="3" placeholder="223.5.5.5"></textarea>
          </label>
          <label>
            DNS 超时
            <input v-model="form.dnsTimeout" placeholder="3s" />
          </label>
          <label>
            DNS 缓存
            <input v-model="form.dnsCache" placeholder="300s" />
          </label>
          <label>
            日志级别
            <select v-model="form.logLevel">
              <option v-for="l in LOG_LEVELS" :key="l" :value="l">{{ l }}</option>
            </select>
          </label>
        </div>
      </section>

      <section class="card">
        <h2>
          TUN 模式
          <span class="count">
            {{ TUN_PHASE_TEXT[phase] }}{{ phase === 'on' ? ` · ${tun.device}` : '' }}
          </span>
        </h2>
        <p v-if="tun.lastError" class="alert">{{ tun.lastError }}</p>
        <div class="form">
          <label>
            网卡名
            <input v-model="form.tun.device" class="mono" placeholder="wps-tun" />
          </label>
          <label>
            网卡地址
            <input v-model="form.tun.address" class="mono" placeholder="172.19.0.1/30" />
          </label>
          <label>
            DNS 劫持点
            <input v-model="form.tun.dns" class="mono" placeholder="172.19.0.2" />
          </label>
          <label>
            假 IP 段
            <input v-model="form.tun.fakeIpRange" class="mono" placeholder="198.18.0.0/15" />
          </label>
          <label>
            MTU
            <input v-model.number="form.tun.mtu" type="number" min="576" max="9000" placeholder="1500" />
          </label>
          <label>
            路由排除（一行一个网段）
            <textarea v-model="excludeText" rows="2" placeholder="192.168.0.0/16"></textarea>
          </label>
        </div>
        <div class="row checks">
          <label class="switch">
            <input v-model="form.tun.hijackDns" type="checkbox" />
            <span class="track" aria-hidden="true"></span>
            <span>劫持本机 :53 查询</span>
          </label>
          <label class="switch">
            <input v-model="form.tun.strictRoute" type="checkbox" />
            <span class="track" aria-hidden="true"></span>
            <span>接管默认路由（进阶，需 route_exclude 配合）</span>
          </label>
          <label class="switch">
            <input v-model="form.tun.killSwitch" type="checkbox" />
            <span class="track" aria-hidden="true"></span>
            <span>故障断网保护（切换放弃时只放行节点，其余丢弃）</span>
          </label>
          <span class="grow"></span>
          <label class="switch">
            <input
              type="checkbox"
              :checked="tunChecked"
              :disabled="busy !== ''"
              @change="emit('tun', ($event.target as HTMLInputElement).checked)"
            />
            <span class="track" aria-hidden="true"></span>
            <span>立即开启 / 关闭</span>
          </label>
        </div>

        <dl class="kv live">
          <dt>特权路径</dt>
          <dd v-if="tun.privilege === 'helper'">
            提权命令代开（面板是普通用户，托盘能常驻）
            <div class="mono mut">{{ (tun.helperCmd ?? []).join(' ') }}</div>
          </dd>
          <dd v-else>
            本进程直接开
            <span class="mut">（要求面板以 root 运行；root 进程连不上桌面会话总线，托盘图标会注册不上）</span>
          </dd>
          <dt>假 IP</dt>
          <dd>
            在册 {{ tun.fakeIps }} 条 · 已应答 DNS {{ tun.dnsServed }} 次 · 活跃 {{ tun.active }} 条
            <span class="mut">（假 IP 大于 0 说明 DNS 劫持确实在工作）</span>
            <div v-if="tun.dnsFailed > 0" class="mut">
              另有 {{ tun.dnsFailed }} 次回了 SERVFAIL：一个上游都没答上。
              只有判成直连的域名才会真去解析，所以这些失败对应的是直连域名——
              代理域名领假 IP，本来就不做解析，也不会算进这两个数
            </div>
          </dd>
          <dt>已执行</dt>
          <dd class="mono">{{ (tun.applied ?? []).join(' → ') || '—' }}</dd>
          <dt>IPv6 假 IP</dt>
          <dd v-if="!tun.ipv6">未启用<span class="mut">（配置里 tun.ipv6: false，系统里不会有一条 v6 命令）</span></dd>
          <dd v-else-if="!tun.running">已启用<span class="mut">（TUN 未运行）</span></dd>
          <dd v-else-if="tun.v6Ready">
            已接管
            <span class="mut">（v4/v6 各有各的假 IP 网段，AAAA 也发假地址）</span>
          </dd>
          <dd v-else>
            已启用但没装上
            <span class="mut">（多半是内核未加载 ip6table_nat；AAAA 回 NODATA，应用退回 A 记录）</span>
          </dd>
          <dt>接管范围</dt>
          <dd v-if="!tun.strictRoute">
            未接管默认路由
            <span class="mut">（只接管判成走代理的假 IP；直连真 IP 的流量绕开 tun）</span>
          </dd>
          <dd v-else-if="!tun.running">
            计划接管默认路由<span class="mut">（TUN 未运行，尚未生效）</span>
          </dd>
          <dd v-else>
            IPv4 {{ tun.takeoverV4 ? '已接管' : '未接管' }} · IPv6 {{ tun.takeoverV6 ? '已接管' : '未接管' }}
            <span class="mut">
              （跟着网络监视器每 5 秒问一次内核：默认路由此刻到底交给了谁；ICMP 等非 TCP/UDP 流量不走这条路）
            </span>
            <!-- 读不到路由表时那两格退回进程记忆——必须说出来，不能冒充实测：
                 「我们装过」与「现在还在」在 DHCP 抢回路由的那一刻是两句话。 -->
            <div v-if="tun.takeoverFrom === 'memory'" class="mut">
              读不到本机路由表，以上两格是按本进程装过的东西推的，不是实测
            </div>
            <div v-if="tun.takeoverV4 && !tun.takeoverV6" class="mut">
              IPv6 流量仍走物理出口，没有进隧道
            </div>
            <div v-if="tun.routeFixes > 0" class="mut">
              网络变化后自动重钉过绕行路由 {{ tun.routeFixes }} 次（最近一次
              {{ formatClock(tun.lastRouteFix) }}）
            </div>
          </dd>
          <dt>故障断网保护</dt>
          <dd v-if="!tun.killEnabled">
            未启用
            <span class="mut">（tun.kill_switch: false；自动切换放弃时出站不会被收窄）</span>
          </dd>
          <!-- 开了但注定装不上：这必须在设置时就看清，不能等故障那天才发现闸门根本没落下 -->
          <dd v-else-if="!tun.strictRoute" class="warn">
            已启用，但不会生效
            <span class="mut">（只在接管默认路由时有意义：选择性 TUN 里直连本来就该出去）</span>
          </dd>
          <dd v-else-if="tun.killArmed" class="warn">
            已挂上<span class="mut">（本机生成的出站只放行节点、DNS 上游与本地网段）</span>
            <div class="mut">
              IPv4 {{ tun.killV4 ? '已收住' : '未收住' }} · IPv6
              {{ tun.killV6 ? '已收住' : '未收住' }}
            </div>
            <div v-if="tun.killReason" class="mut">{{ tun.killReason }}</div>
          </dd>
          <!-- 触发过又没装上：界面必须说「未生效」，不能显示成一道开着的保护 -->
          <dd v-else-if="tun.killReason" class="warn">
            未生效<span class="mut">（{{ tun.killReason }}）</span>
          </dd>
          <dd v-else>
            已启用，等待故障触发
            <span class="mut">（自动切换判定「没有一个节点能用」时才会挂上；节点通了或你手动换点即解除）</span>
          </dd>
        </dl>
        <p class="hint">
          工作方式：判成走代理的域名，DNS 直接回一个假 IP，应用连假 IP 时才进 tun；
          判成直连的域名回真 IP，流量根本不进 tun——直连不绕路，也不会自环。
        </p>
        <p class="hint">
          能力边界：只转发 TCP/UDP。ICMP（ping）等其它协议不进隧道，IPv4 与 IPv6 都一样，
          而且全局接管下本机协议栈会替 echo request 应答——ping 得通不代表对端真的可达，
          也别用它判断隧道状态；组播与链路本地的邻居发现仍走物理网卡（接管只改默认路由，
          这类地址命中的是直连路由和本地表），回环与广播走内核本地路由，
          route_exclude 里的网段钉回物理网关；
          UDP 只有 hysteria2 节点带得动——trojan 是 TCP 协议，直连（DIRECT）也不发 UDP，
          这两条路都会明确拒绝并在流量页留一行带原因的记录（UDP 传不回错误给应用，这是本机唯一的说明）；
          DoH 或直接用 IP 的流量即使进了 tun 也可能没有域名信息，域名规则命中不了。
        </p>
      </section>

      <section class="card savebar">
        <div class="path-block">
          <div class="mono mut">写入 {{ form.path }}</div>
          <div class="hint">保存会按规范格式重写 config.yaml，原有注释不会保留；需要保留请先自行备份。</div>
        </div>
        <div class="row">
          <button type="button" class="btn ghost" :disabled="saving" @click="load">放弃修改</button>
          <button type="button" class="btn primary" :disabled="saving" @click="save">
            {{ saving ? '保存中…' : '保存配置' }}
          </button>
        </div>
      </section>
    </template>

    <!-- 系统代理这一栏在 <template v-else> 外面：它读的是桌面设置，不依赖 config.yaml。
         配置读不到的时候，"把桌面代理关掉/还原"恰恰是最需要还能点得动的一件事——
         跟着表单一起藏起来，等于用户在改坏配置之后被锁在改不动系统代理的状态里。 -->
    <section class="card">
      <h2>
        系统代理
        <span class="act">
          <label
            class="switch"
            title="总开关：打开会启动代理并接管桌面；关闭会恢复桌面指针并停止代理（监听、隧道、TUN 一起停）"
          >
            <input
              type="checkbox"
              :checked="sysChecked"
              :disabled="busy !== '' || !(sys?.supported ?? false)"
              @change="emit('sysproxy', ($event.target as HTMLInputElement).checked)"
            />
            <span class="track" aria-hidden="true"></span>
            <span>{{ busy === 'sysproxy' ? '处理中…' : sys?.error ? '读不到' : sys?.enabled ? '已开启' : '已关闭' }}</span>
          </label>
        </span>
      </h2>
      <dl class="kv">
        <dt>后端</dt>
        <dd>{{ sysBackend }}<span v-if="sys?.path" class="mut mono"> · {{ sys.path }}</span></dd>
        <dt>HTTP</dt>
        <dd class="mono">{{ sys?.http || '—' }}</dd>
        <!-- HTTPS 在 GNOME/KDE 里是独立一项，与 HTTP 可以不同。
             用 HTTP 的读数冒充这一行，用户就会以为两者一致，
             而只改了 https 的场景下界面一直在报旧值。 -->
        <dt>HTTPS</dt>
        <dd class="mono">
          {{ sys?.https || '—' }}
          <span v-if="sys?.https && sys.https !== sys.http" class="mut">（与 HTTP 不同）</span>
        </dd>
        <dt>SOCKS</dt>
        <dd class="mono">{{ sys?.socks || '—' }}</dd>
        <dt>绕过</dt>
        <dd>{{ (sys?.ignored ?? []).join('、') || '—' }}</dd>
        <!-- 这一行回答的是"那个 ON 归谁负责、退出会不会还原"。
             桌面读数本身答不了：它只知道现在是什么，不知道为什么。 -->
        <dt>记账</dt>
        <dd :class="ledgerTone" :title="ledger?.path">{{ ledgerText }}</dd>
      </dl>
      <!-- 读取失败和"这台机器不支持"是两件事，必须分开说。
           混成一句「三个后端都不认」，用户会去装桌面组件，
           而真实原因可能只是 D-Bus 卡住超时。 -->
      <p v-if="sys?.error" class="alert warn tail">
        读不到桌面代理设置：{{ sys.error }}
        <template v-if="!sys.supported">
          （因此这台机器上系统代理开关不可用；可以改用 TUN 模式，或手动设置环境变量。）
        </template>
      </p>
      <p v-else-if="sys && !sys.supported" class="alert warn tail">
        这台机器上没找到可用的桌面代理后端（gsettings / kioslaverc / environment.d 都不认），
        系统代理开关不可用。可以改用 TUN 模式，或手动设置环境变量。
      </p>
      <p v-else-if="sys?.note" class="hint tail">{{ sys.note }}</p>
      <p v-else-if="sys && !status.running" class="hint tail">
        代理目前没在运行；打开这个总开关会自动启动它。启动失败时桌面指针不会被改动。
      </p>
      <p v-else class="hint tail">
        这是总开关：打开会启动代理并把桌面指向它；关闭会恢复桌面原状并停止代理
        （监听、隧道、TUN 一起停）。状态会被记住，下次启动按上次的开关恢复。
        按改动前的读数还原，不是无脑置空。
      </p>
    </section>

      <section class="card">
        <h2>
          诊断信息
          <span class="act">
            <button
              type="button"
              class="btn sm ghost"
              :disabled="diagBusy"
              @click="onDiag"
            >
              {{ diagBusy ? '正在写…' : '导出诊断信息' }}
            </button>
          </span>
          <span class="act">
            <button
              type="button"
              class="btn sm ghost"
              :disabled="logBusy"
              @click="onExportLogs"
            >
              {{ logBusy ? '正在写…' : '导出日志' }}
            </button>
          </span>
        </h2>
        <p class="hint">
          把「现在为什么不通」要翻的十几处（入站是否在听、规则与拦截条数、DNS 现状、
          TUN、系统代理读数与记账）收成一份文本，写在配置文件旁边。
          节点密钥、入站口令与订阅地址的 key 都不会进去，可以直接贴给别人。
        </p>
        <p v-if="diagPath" class="mono mut">{{ diagPath }}</p>
        <p v-if="diagError" class="alert warn tail">导出失败：{{ diagError }}</p>
        <p v-if="logPath" class="mono mut">{{ logPath }}</p>
        <p v-if="logError" class="alert warn tail">日志没写出去：{{ logError }}</p>
        <!-- 与诊断报告不一样的那一点必须单独说：这一份里有访问过的域名。 -->
        <p class="hint tail">
          「导出日志」写的是内存里那 1000 条（更老的已被环形缓冲覆盖），
          里面有本机访问过的域名——那等于一份浏览记录，所以文件权限是 0600，
          也别往公开的地方贴。口令与订阅 token 已按诊断报告同一套规则掩过。
        </p>
      </section>

      <!-- 这一格治的是一种很具体的困惑："我改了界面，怎么面板上没有"。
           界面是 embed 进二进制的，跑着的进程画面停在启动那一刻，
           所以磁盘上构建过多少次都不会自己出现——第一嫌疑始终是进程旧。 -->
      <section class="card">
        <h2>这份界面是哪一次构建</h2>
        <dl class="kv">
          <dt>版本</dt>
          <dd class="mono">{{ build?.version || '（未注入）' }}</dd>
          <dt>源码指纹</dt>
          <dd class="mono">{{ build?.stamp || '（未注入）' }}</dd>
          <dt>构建于</dt>
          <dd class="mono">{{ build?.builtAt || '（未注入，可能不是脚本构建）' }}</dd>
          <dt>内嵌前端</dt>
          <dd class="mono">{{ build?.frontend || '（这份产物不带内嵌界面）' }}</dd>
          <dt>二进制</dt>
          <dd class="mono">{{ build?.exePath || '（读不到）' }}</dd>
          <dt>磁盘上编于</dt>
          <dd>{{ buildTimeText }}</dd>
          <dt>本进程起于</dt>
          <dd>{{ startedText }}</dd>
        </dl>
        <p v-if="build?.newerOnDisk" class="alert warn tail">
          磁盘上的二进制比正在跑的这份新（{{ buildTimeText }} 编）——
          <b>你现在看到的界面不是最新的</b>，重启面板才会换过去。
          重启会掐断正在走的隧道几秒，所以这一步留给你自己挑时间。
        </p>
        <p v-else-if="buildError" class="alert warn tail">构建信息读不到：{{ buildError }}</p>
        <!-- 剩下两句要分清楚：只有真读到磁盘上那份二进制，"是同一份"这句话才成立。
             演示模式压根没有可比的对象，跟着说"界面是最新的"就是一句假话。 -->
        <p v-else-if="build && build.exeModTime > 0" class="hint tail">
          磁盘上这份与正在跑的是同一份，界面是最新的。
        </p>
        <p v-else class="hint tail">演示模式没有可比的对象：这一格要接了后端才有意义。</p>
      </section>
  </div>
</template>

<style scoped>
.tail {
  margin-top: 10px;
}

.mut {
  color: var(--muted);
}

.listen {
  width: 150px;
}

.checks {
  margin-top: 10px;
  justify-content: flex-start;
}

.live {
  margin-top: 12px;
  padding-top: 12px;
  border-top: 1px dashed var(--line-2);
}

/* 保存条贴在页面末尾，左右两栏：左边说清写到哪里、有什么副作用，右边是动作。 */
.savebar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.path-block {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}
</style>
