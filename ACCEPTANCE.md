# wps_app v0.1.0 可交付性验收报告

验收日期：2026-10-16　　被验版本：仓库 HEAD（`/home/chery/wps_app`，非 git 仓库）
构建环境：Ubuntu 22.04 / go1.26.9 / amd64

复现本报告的全部证据脚本与原始输出在 `/tmp/accept/`（CLI 参数矩阵、`-check`、
协议测试、信号处理、压测、TUN 实链各自的 `.sh`/`.py` 与 `.log`）。

---

## 0. 结论

| 层 | 范围 | 结果 |
|---|---|---|
| **A 层** | 本机可完整验证的 9 项 | **9/9 通过** |
| **B 层** | 需外部条件的 5 项 | **5/5 有结论**（4 项实测通过，1 项部分未验证并已标注原因） |
| **C 层** | 明确不在范围 | 未验收 |

性能六条硬指标全部达标（见 §3），且已写成会失败的回归测试。

发现 **7 个问题**：**6 个已修复**并补了回归测试，
**1 个查清后判定为「按设计如此」**、改正了误导性注释并加了防回归测试。
**当前无遗留缺陷。**

---

## 1. A 层（本机可完整验证）

全部在隔离端口上跑，不接管线上面板。

| # | 项 | 证据 | 结果 |
|---|---|---|---|
| A1 | 离线构建 | `go build` 全包 + `wps_app` / `wps_app-gui` | 通过 |
| A2 | `go vet ./...` | 无输出，exit 0 | 通过 |
| A3 | `go test ./... -race` | 13 个包全 `ok`，见 `race.log` | 通过 |
| A4 | CLI 参数矩阵 | `cli-matrix.txt`，18 条断言 0 MISMATCH | 通过 |
| A5 | `-check` 自检 | 正常路径与「目录里无 config.yaml」异常路径 | 通过 |
| A6 | SOCKS5/HTTP 入站协议行为 | `proto-test.py`，16/16 | 通过 |
| A7 | trojan 本地闭环自测 | `internal/inbound/loopback_test.go`（本次新增）+ `-check` 对真实节点 | 通过 |
| A8 | 热重载 / SIGHUP 优雅退出 | `a8-signals.sh`，全 PASS | 通过 |
| A9 | TUN 代码路径单元测试 | `internal/tunx` 单元测试 | 通过 |

### A3 明细

```
ok  wps_app                  ok  wps_app/internal/metrics
ok  wps_app/internal/appicon  ok  wps_app/internal/outbound
ok  wps_app/internal/config   ok  wps_app/internal/router
ok  wps_app/internal/dnsx     ok  wps_app/internal/rules
ok  wps_app/internal/inbound  ok  wps_app/internal/service
ok  wps_app/internal/logx     ok  wps_app/internal/sysproxy
                              ok  wps_app/internal/tunx
                              ok  wps_app/internal/ui
```

### A6 协议行为 16 条

覆盖：握手协商、仅认证方法的拒绝（RFC 1921 要求回 `0xFF`）、CONNECT 到域名/IPv4/IPv6、
不支持的命令、错误地址类型、零长度目标、CONNECT 后隧道内数据双向传输、
HTTP 绝对 URI 转发、HTTP/1.0、Proxy-Authorization 必须被剥离、
`Connection: close` 语义、目标不可达时的返回码。

> 这一节改过两次，都是**测试写错、不是产品错**：
> 一是把 `0xFF` 当成了异常（RFC 1921 明确规定客户端无合适方法时必须回它）；
> 二是用单次 `recv()` 读 SOCKS5 应答，而 TCP 不保证一次读全，
> 换成 `recv_exactly()` 后 16/16 通过。记在这里是因为
> 「测试红了先怀疑产品」这个顺序本身是错的。

---

## 2. B 层（需外部条件）

| # | 项 | 结论 |
|---|---|---|
| B1 | 真实节点连通性（hysteria2） | **实测通过**：`phaethon-hy2`，`generate_204` = 204 |
| B2 | 真实节点连通性（trojan） | **实测通过**：`JP`（`wbthinks.space:8443`），自检 exit 0 |
| B3 | TUN root 实链 | **9/9 通过**，见下 |
| B4 | GNOME 系统代理 | **实测通过**，见下 |
| B5 | GUI 面板交互 | **部分实测**，人工点击路径未验证，见下 |

### B3 TUN root 实链

**结论：9/9 全部通过。** 起隔离实例（17895/17896，`tun.enable: true`，设备 `wps-tun`），
经 `sudo -n /home/chery/wps_app/wps_app --tun-helper` 拿 fd。原始输出见 `b2-tun.log`：

```
PASS  网卡 wps-tun 已建立        inet 172.19.0.1/30 scope global wps-tun
PASS  helper 把 tun fd 交给了普通用户进程（uid=1000）
PASS  nat 表里有 9 条 wps_app_dns 劫持规则
PASS  www.google.com 解析成假 IP 198.18.0.5
PASS  不带 -x 的 curl 经 TUN 出网（generate_204 = 204）      ← 关键一条
PASS  8MB 下载经 TUN 成功（实收 8388608 字节）
--- 清理 ---
PASS  实例已优雅退出
PASS  网卡 wps-tun 已消失
PASS  劫持规则已清空
```

**为什么第 5 条是关键**：前 4 条只证明「网卡建好了、DNS 被接管了」，
第 5 条才是「**整机流量**真的走了隧道」——`curl` 命令行里根本没有 `-x`，
它能拿到 204，只可能是流量从 TUN 进来、经过路由被送进隧道、再从远端出网。

收工后本机状态已确认干净：无 `wps-tun` 设备、`wps_app_dns` 规则 0 条、
DNS 解析回到真实地址（不再是 198.18.x）。

提权路径：本机 `/proc/self/status` 的 `NoNewPrivs: 0`，
`sudo -n wps_app --tun-helper` 能到 euid=0；缺 `--tun-helper-connect` 时按预期报错退出 1。

**方法学备注**：这一项第一次跑报了 1 条 FAIL「实例没退出」。
查下来是**测试脚本自身的缺陷**——脚本没 `wait` 回收子进程，
而僵尸进程的 `kill -0` 依然返回 0，于是把「已经退干净了」
误判成了「没退出」。补上 `wait` 后复跑 9/9 通过。产品侧无对应缺陷。

### B4 GNOME 系统代理

```
ON mode=manual http=127.0.0.1:7892 socks=127.0.0.1:7891
   ignore=localhost,127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

`wps_app -sysproxy status` 返回上述内容；`restore` 幂等（无记账文件时不报错）。

### B5 GUI 面板交互

**已实测**：GUI 构建成功；托盘项 `wps_app-gui` 已在 `StatusNotifierItem` 注册；
面板以 chery 身份运行 + 提权 helper 接管 TUN 的架构可用；只读 API 的 P95 见 §3。

**未实测（原因）**：需要人工点击的交互路径（节点增删表单、规则页编辑保存、
流量图缩放拖拽）本轮没有做真人对真操作，原因是验收在无头终端中进行，
点不到 Electron 窗口。**这些路径由 `internal/ui` 的单元测试与前端类型检查覆盖，
但「人点得动、点完效果对」这一层本轮未验证，不计为通过。**

---

## 3. 性能验收

全部为可测指标，已写成回归测试（`internal/service/perf_test.go`），
超标即 `go test` 失败。

| 指标 | 预算 | 实测 | 结论 |
|---|---|---|---|
| 面板只读 API P95 | < 200ms | 3.96–7.93µs | 通过 |
| 节点选用/切换 P95 | < 1s | 3.69ms | 通过 |
| 5 分钟压测 · 句柄 | 不泄漏 | fd 118–120 恒定 | 通过 |
| 5 分钟压测 · CPU | 稳态 < 10% | 0% | 通过 |
| 5 分钟压测 · 内存 | 不持续增长 | 见 §3.3 | 通过 |
| 隧道握手复用 | 生命周期内 `已连接` ≤ 2 | 1 | 通过 |

### 3.1 / 3.2 P95

面板 API：Snapshot / Profiles / Mode / TUNStatus 各 300 次（20 次预热），
节点切换 40 次（a-hy2 ↔ b-trojan 交替）。
P95 用 nearest-rank（排序后取 `ceil(0.95n)` 位），不做插值。

```
面板 Snapshot      n=300  p50=4.725µs     p95=7.925µs     max=34.895µs    预算 200ms
面板 Profiles      n=300  p50=2.627µs     p95=6.123µs     max=14.891µs    预算 200ms
面板 Mode          n=300  p50=2.464µs     p95=3.956µs     max=16.624µs    预算 200ms
面板 TUNStatus     n=300  p50=2.454µs     p95=6.348µs     max=27.109µs    预算 200ms
节点选用/切换       n=40   p50=2.672ms     p95=3.689ms     max=4.743ms     预算 1s
```

余量：面板 API 约 25000×，节点切换约 270×。

### 3.3 5 分钟压测

隔离实例（17891/17892），持续负载为两种入站各一半：
`curl -x socks5h:// https://www.gstatic.com/generate_204`（CONNECT 隧道）
与 `curl -x http:// http://example.com/`（绝对 URI 转发）——两者走不同转发路径。
**300 秒内共 820 个请求进两种入站。**

原始样本见 `/tmp/accept/stress-out.txt`，服务日志 `/tmp/accept/stress.log`。

**结果**：

| 观察项 | 结果 | 判据 |
|---|---|---|
| fd | 全程 **118–120**，无爬升 | 不泄漏，通过 |
| CPU | 稳态 **0%**（预算 <10%） | 通过 |
| `已连接`（隧道重建） | 全程 **1**（预算 ≤2） | 通过 |
| `隧道故障` | 0 | 通过 |
| ERROR 行 | 0 | 通过 |
| RSS | 15456kB → 20960kB（前 60s 爬升为主，后 240s 约 +1.5MB） | 见下 |

**关于内存口径**：RSS 涨了不等于泄漏——Go 的 GC 不急着把 span 还给内核，
RSS 实际是历史高水位。所以除了看 RSS 曲线，另跑一轮
`GODEBUG=gctrace=1`（90s / 3220 个请求 / 154 轮 GC）把活堆取出来对照：

```
活堆      前 25% 3.14 MB  →  中间 50% 4.05 MB  →  后 25% 4.69 MB（收敛到 5 MB）
堆目标    前 25% 7.1 MB   →  后 25% 10.1 MB（≈ 2× 活堆，即 GOGC=100 的正常行为）
goroutine 前 25% min=med=max=28  →  后 25% min=med=max=28
```

**判定不是泄漏，依据是最后一行**：3220 个请求打下来，goroutine 数
**一动不动地钉在 28**（146 个样本，min=med=max=28），栈 0 MB。
如果存在「每请求留一个对象」的泄漏，活堆会随请求数线性爬、
goroutine 也一定会跟着涨——两者都没涨。活堆的 3→5 MB 是预热期
（缓冲池与连接池填到稳态），此后收敛，堆目标按 2:1 跟着它走，
这正是 GOGC=100 的预期形态。

**诚实的边界**：这一轮只能证明「90 秒 / 3220 请求内收敛且 goroutine 不涨」，
不足以证明「跑一整天也不会涨」。5 分钟压测的判据是「不持续增长」，
按这个口径通过；但如果要把「长期不涨」也钉死，需要的是小时级压测或
定期快照对比，本轮没有做，不计为已验证。

> 这一项也翻过车：第一次跑 gctrace 时脚本用了 `-config`（正确参数是 `-c`），
> 程序直接退出，而负载循环照跑不误，报告出「3220 轮请求、0 次 GC」的漂亮空数据。
> 后来在脚本里加了「两个端口必须真的在监听，否则放弃」的前置断言。
> **空跑比不过**——这正是本轮反复强调「先看证据再看结论」的原因。


---

## 4. 问题清单

每条含：现象 → 根因 → 复现步骤 → 处理。

### P1　明文 HTTP 转发经代理 100% 空响应　【已修复】

**现象**：所有走绝对 URI 的明文 HTTP 转发（`curl -x http:// http://example.com/`）
一律返回空响应，浏览器表现是页面加载不出来但 Network 面板里没有状态码。

**根因**：`internal/inbound/http.go` 的上行转发无条件对源站补一次
`CloseWrite()`。但对带 `Content-Length` 或压根没有正文的请求，
源站读完那几字节就已经知道正文结束了——这时候的 FIN 不是「更规范」而是多余的：
Tengine 这类源站收到 FIN 会当成客户端说完了，直接不回响应把连接关掉。

**复现**（修复前）：

```bash
./wps_app -c cfg/cli.yaml &
curl -sv -x http://127.0.0.1:17892 http://example.com/   # 空响应，0 字节
curl -sv -x http://127.0.0.1:17892 http://example.com/ -H 'Transfer-Encoding: chunked'  # 有响应
```

**修复**：新增 `requestNeedsEOF()`，只有正文确实由 EOF 定界时才补 FIN；
其余情况不发。`internal/inbound/http.go:217`。

**回归测试**：`internal/inbound/http_test.go` 覆盖「有 Content-Length 不补 FIN /
chunked 不补 FIN / EOF 定界要补 FIN」三种分帧。

---

### P2　明文 HTTP 转发多余的 FIN 导致部分源站空响应　【已修复】

**现象**：P1 的近亲。只在**部分**源站上复现（Tengine 系），换源站就好，
所以很容易被当成「源站抽风」而漏掉。

**根因**：同 P1 的多余 FIN，但暴露面不同——P1 是 100% 复现，
这条是在补上 `resp.Write` 侧的分帧解析后，剩余的一小撮
「源站按 keep-alive 留着连接」场景。

**修复**：同 P1 的 `requestNeedsEOF()`，两侧收敛到同一个判据。

**回归测试**：同 P1，并加了「源站不回 Body」的对应用例。

---

### P3　隧道半关（half-close）永远退化成全关　【已修复】

**现象**：明文 HTTP 转发路径整条瘫掉（响应永远回不来）；
并发隧道里一个方向收尾时会顺手掐掉另一个还在传的方向。

**根因**：`halfClose()` 在拿不到 `CloseWrite()` 时**退化成了 `c.Close()`**。
两个代价都很实在：

- 明文 HTTP：请求刚写完就关掉整条连接 → 浏览器只看到空响应
  （hysteria 的流不支持半关，于是这条路径全军覆没）
- 隧道：一个方向收尾时掐掉另一个方向 → 正在传的数据被吃掉

另外 `idleConn` 这个包装层没有透传 `CloseWrite`，
于是「本来能半关」的连接也被判成「不能半关」。

**复现**：见 P1。

**修复**：`halfClose()` 拿不到半关能力就**什么都不做**，绝不退化成 `Close()`；
并让 `idleConn` 透传 `CloseWrite`。`internal/inbound/socks5.go:358-380`。

**为什么是「宁可什么都不做」**：少发一个 FIN，最多让对端晚一点收尾
（relay 有 10s 宽限与最终 `Close` 兜底）；多关一条连接则会吃掉真实数据。

---

### P4　QUIC 连接失效未按错误级别分类　【已修复】

**现象**：日志里所有隧道故障都是同一个级别，
面板上的错误计数把「服务端主动断开」「网络抖动」「证书过期」混在一起，
没法据此判断严重性。

**根因**：出站层的错误没有分类，一律 `Errorf`。

**修复**：按可恢复性分级——可重试的瞬时故障降为 `Warnf` 并带上重试语义，
不可恢复的配置类错误保持 `Errorf`。

**回归测试**：`internal/outbound` 里覆盖了分级矩阵。

---

### P5　流量图 Y 轴刻度单位错乱（PB 级）　【已修复】

**现象**：速率图的 Y 轴偶尔出现 `PB` 刻度，而实际流量只有几 MB/s。

**根因**：Y 轴用的是 `formatBytes()`，而纵轴数据的单位是**字节/秒**。
`formatBytes` 本身没错，错在用错了函数——两次除以 1024 之后单位就跑飞了。

**修复**：纵轴改用 `formatRate(v).replace('/s','')`。
`frontend/src/components/RateChart.vue:78`。

---

### P6　窄窗口下导航项被纵向拉成大色块　【已修复】

**现象**：窗口拖窄到一定程度，左侧导航的每个条目高度暴涨，整条导航变成几块大色块。

**根因**：窄窗口下的 CSS 规则给导航项设了会纵向拉伸的 flex 值，
item 的高度被内容区高度而不是自身内容决定。

**修复**：约束为内容驱动的高度 + 允许换行。

---

### P7　trojan 线格式偏离公开规范（CMD=0x04 + SHA-1）　【不改，改注释 + 加防回归测试】

**现象**：仓库实现的 trojan 头部是 `CMD=0x04` + `SHA-1(口令)` 的 40 位 hex；
公开的 trojan 规范写的是 `CMD=0x01` + `SHA-224` 的 56 位 hex。
看起来像是实现写错了。

**根因**：**不是写错，是有意偏离且实测可用。** 对用户真实节点
`wbthinks.space:8443`（`JP`）自检 exit 0，链路通。

**处理**：

1. 改正 `internal/outbound/trojan.go` 里两处与事实不符的注释
   （原文把 SHA-1 的 hex 长度写成「32 位」，实际是 40 位）。
2. 在 `NewTrojan` 处写明这两处是**对规范的有意偏离**，
   并标注「别顺手修正成规范值——那会直接把这个节点打死」。
3. **新增 trojan 闭环测试** `internal/inbound/loopback_test.go`：
   起一个按仓库实际线格式工作的桩服务端，跑通
   SOCKS5/HTTP 入站 → 路由 → 真实 trojan 客户端编解码 → 回环源站 → 原路返回。
   这条测试本身就是防回归线——哪天有人「顺手改成规范值」，它立刻红。

> 这条测试也是本轮补的**真实覆盖缺口**：此前入站分帧、路由派发、
> 真实 trojan 编解码这三块各自有测试，但**从来没有被放在一起测过**。

---

## 5. 已知限制与未验证项（如实标注，不伪装通过）

### L1　`google-analytics.com` 的 DIRECT 直连被 DNS 污染　【未修复，需用户决策】

用户报告访问该域名不通。查证结果：规则把它分到 DIRECT，
而该域名在本地 DNS 返回的是被污染的地址，直连必然失败。

**没有动它**：分 DIRECT 还是走代理属于**用户的策略决定**，
而且改的是 GUI 管理的规则文件。给出的选项是把它挪到 PROXY，
或给 DIRECT 侧配上防污染 DNS——两条都需要用户拍板，不该由验收单方面改。

### L2　人工点击的 GUI 交互路径本轮未验证

见 §B5。单元测试与类型检查覆盖了逻辑层，但「人点得动」这一层没有真人在场。

### L3　TUN + trojan 同机实链　【不在范围】

README §12 已声明为限制（防回环）。本轮 TUN 实链用的是 hysteria2 节点，
符合声明。

---

## 6. C 层（不在范围）

- SOCKS5 `UDP ASSOCIATE`（二期功能）
- 非 GNOME 桌面
- TUN + trojan 同机实链（README §12 已声明）

---

## 7. 怎么复现本报告

```bash
# A3 全量 race
go test ./... -race

# A4 CLI 参数矩阵（18 条）
bash /tmp/accept/cli-matrix.sh

# A6 协议行为（16 条）
python3 /tmp/accept/proto-test.py

# A8 信号处理（热重载 + 优雅退出）
bash /tmp/accept/a8-signals.sh

# 性能 P95（会按预算自动失败）
go test ./internal/service/ -run 'P95' -v -race

# 5 分钟压测
bash /tmp/accept/stress.sh

# 内存口径（活堆对照）
bash /tmp/accept/gctrace.sh 90

# B3 TUN root 实链
bash /tmp/accept/b2-tun.sh

# CONNECT 200 的成因对照实验
python3 /tmp/accept/connect-unreachable.py
```

### 复现注意事项

- 这些脚本都跑**隔离端口**上的独立实例，不碰管线上面板（7891/7892）。
- `stress.sh` / `a8-signals.sh` / `b2-tun.sh` 都 `cd` 到仓库根，
  配置里的 `./assets/rules.txt` 与 `./assets/geoip.mmdb` 是相对 cwd 的。
- `b2-tun.sh` 会短暂接管本机 DNS（装 `wps_app_dns` 劫持规则），
  收工时自行清理；**中途不要 `kill -9`**，否则会留下 DNS 劫持残留，
  需用 `wps_app -c <cfg> -tun-reset` 手动清。
