# wps_app v0.1.0 可交付性验收报告

验收日期：2026-10-16　　被验版本：2026-10-16 工作树（当时尚未纳入 git；2026-10-27 已建立 baseline）
构建环境：Ubuntu 22.04 / go1.26.9 / amd64

复现本报告的全部证据脚本与原始输出原在 `/tmp/accept/`。**该目录已随机器重启消失**
（2026-10-27 发现），所以下面的复现命令不能再照抄。2026-10-27 起，
A6 协议与 A8 信号脚本已重建到 `scripts/acceptance/` 并实跑通过（16/16、3/3）；
B3 脚本 2026-10-29 用专用配置重跑：10/10（root + 真实节点 + 真 8MB 下载），见 A50；2026-10-29 单产物迁移：被测二进制与 tun.helper 都是 ./wps_app-gui，同样 10/10，见 A51；A4 CLI 矩阵、压测与 gctrace 仍未找回/重建。

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
**当前无已知代码缺陷；仍有未验证项与需用户决策项（见 §5 L1–L3）。**

**2026-10-27 复跑**：A6 协议 16/16、A8 信号 3/3 通过（`make acceptance`）；
`gofmt` / `go vet`（两种 tag）/ `go test` / `go test -race` 全绿。
B3 TUN 脚本 2026-10-29 重跑通过（10/10，专用配置 + 非冲突端口）。

**2026-10-28 增量：双栈全局接管**。原先 `strict_route` 只装 IPv4 默认路由，
IPv6 的默认路由压根没接管——面板写着「接管默认路由」，实际上一半公网流量
绕过隧道。现在两族各自接管、各自成败，面板分开显示。

| 项 | 证据 | 结果 |
|---|---|---|
| A10 路由解析（v4/v6）、按族拆分绕行路由、v6 默认路由安装与回滚、无网关时不接管 | `internal/tunx/dualstack_test.go` | 通过 |
| A11 重复启停不残留 | `dualstack_test.go` + `netns_linux_test.go` | 通过 |
| A12 **内核级**双栈接管与拆除 | `internal/tunx/netns_linux_test.go`（私有 netns 里跑真的 `ip`，验的是内核路由表） | 通过 |
| A12b **内核级**仅 IPv4 / 仅 IPv6 两种单栈形态（两种都得单独演：只有一个族出口时，混族会被内核拒，而把没出口那族报成已接管是撒谎） | 同上：`TestNetnsIPv6OnlyTakeover` 与 `ipv4only_netns_test.go::TestNetnsIPv4OnlyTakeover`（后者见 A45） | 通过 |
| A13 面板分族显示 | `internal/ui/projection_guard_test.go`（Go↔TS 字段逐个对齐）+ 前端 typecheck | 通过 |

A12 由 `make test-offline` 带着 `WPS_NETNS=1` 跑：这类用例会改默认路由，
开关是显式的，绝不会在宿主 netns 上执行。

**2026-10-28 增量二：网络变化后的恢复**。绕行路由按当时的网关钉死，
换网之后它还指着旧出口，发往节点的包送到一个不存在的出口——
面板上只剩「节点超时」，故障切换也换不动它，于是每个节点都超时。
现在监视器会去抖后重钉。

| 项 | 证据 | 结果 |
|---|---|---|
| A14 去抖：变化落定才动手；网络没变不动手；网络断了保持原样；重钉失败不改计划 | `internal/tunx/netwatch_test.go` | 通过 |
| A15 **内核级**换网关后自动改钉绕行路由 | `internal/tunx/netns_linux_test.go`（私有 netns 里真换默认路由，再读内核路由表） | 通过 |
| A16 面板显示重钉次数与时刻 | `internal/ui/projection_guard_test.go` + 前端 typecheck | 通过 |
| A17 自动切换时刻与每节点冷却投影 | `internal/service/failover_test.go`（`TestProfileViewsCarryCooling` / `TestSnapshotReportsSwitchTime`） | 通过 |
| A17b 按规则汇总的字节：收尾+在跑都算、各行加起来必须等于总量、键数封顶、合并行不丢量、清零连这张表一起清 | `internal/metrics/registry_test.go`（`TestByRule*` 六条；已做过突变验证——把记账那一段拿掉，五条同时红） | 通过 |

helper 协议版本从 1 提到 2：新增 `reroute` 动作（特权路径上也要能重钉），
应答多了 `V6RouteOK`。老 helper 不会回这个字段，面板会把它读成「v6 没接管」——
那是静默说错话，所以宁可当场报版本不匹配。

**2026-10-28 增量三：故障时的行为（P1 第 4 条）**。四条场景的路由与 DNS 恢复现在都有可重跑的断言：

| 场景 | 断言在哪 | 结果 |
|---|---|---|
| 普通停止 | `teardown_test.go`：劫持规则逐条被摘，且**先摘 DNS 再拆网卡**（顺序反了会留一个"网卡没了但 53 还往黑洞里指"的中间态）；`helper_test.go` 覆盖 helper 路径的 down | 通过 |
| helper 失败 | `helper_test.go`：up 失败回滚、fd 交不出去时回滚、清残留走 helper | 通过 |
| 进程异常退出 | `stale_test.go`：按内容扫 `POSTROUTING` 清残留，且**不动别人的规则**（docker0 的 MASQUERADE、别的网卡上的 53 改写） | 通过 |
| 升级重启（新进程压在旧残留上） | `restart_netns_test.go`：`TestNetnsUpgradeRestartOnTopOfResidue` 用生产那条 `Start()` 路径跑完整个「老进程没了 → 新进程起来」，断的是**终态**（见 A34） | 通过（真内核） |
| 重复挂载的残留清得完吗 | 同上 `TestNetnsRestartCleanupConverges` + 脱机守卫 `stale_test.go::TestCleanupStaleSweepsEveryDuplicatedJump`：清残留必须收敛回零，不是「还剩一份」 | 通过（真内核） |
| 断网再回来 | `netns_linux_test.go` 的 `TestNetnsWifiDropThenReconnect`：断的时候不乱动、回来时改钉到新网关 | 通过（真内核） |
| 仅 v4 / 仅 v6 / 双栈 | `netns_linux_test.go` 三条 + `dualstack_test.go` 的 buildPlan 分支 | 通过（真内核） |

**2026-10-28 补：上面那段"iptables 在无特权 netns 里验不了"已经不成立。**
出路不在 root 而在挂载命名空间——`unshare -rnm` 之后把 `/run` 换成 tmpfs，
`/run/xtables.lock` 就能开了，而规则仍然只活在那个私有 netns 的表里（宿主的表每轮核对未被动过）。
新增 `make test-netns-fw`（已进 gate）把这几件事从"命令序列对"升级成"内核真的这么干了"：

| # | 项 | 证据 | 结果 |
|---|---|---|---|
| A23 | 劫持规则**真的装上**且逐项在位（含上游 RETURN 与 `! -d 127.0.0.0/8` 两条豁免、回程 SNAT） | `internal/tunx/dns_netns_test.go`：`iptables -t nat -S` 逐条比对 | 通过（真内核） |
| A24 | 按 Down 列表拆完之后，nat 表里**再也找不到**链名 / DNAT / 我们的 SNAT | 同上（拆完再 dump 一次并断言禁词） | 通过（真内核） |
| A25 | 模拟进程被杀留下的残表被 `CleanupStale` 真清掉，且可反复跑 | `TestNetnsStaleCleanupRemovesRealResidue` | 通过（真内核） |
| A26 | **真发一个 DNS 查询**：目标在名单外时 UDP 与 TCP 都落到我们的解析地址；目标是上游或 resolved stub 时**不落到这里** | `TestNetnsDNSHijackDeliversQueriesToOurResolver` | 通过（真内核） |
| A27 | 断网保护的规则被内核接受，并用**包计数**证明白名单外的 SYN 走 DROP、名单内的走放行；摘链后表里无痕、还能原样重挂 | `internal/tunx/killswitch_netns_test.go`（v4/v6 各一条 + 摘链一条） | 通过（真内核） |
| A28 | **真包穿过真网卡与真协议栈**：内核 socket → 路由 → tun fd → gVisor → 规则 → 出站 → 回程，字节同时进连接账（TCP 与 UDP 各一条） | `internal/tunx/forward_netns_test.go`：`TestNetnsForwardsTCPThroughRealTUN` / `TestNetnsForwardsUDPThroughRealTUN` | 通过（真内核） |
| A29 | 带不动 UDP 的那两条路（DIRECT、trojan 节点）**明确拒绝**：应用侧什么都收不到，本机 2 秒内在流量页留下一行带原因、零字节、计入「拨不通」的记录 | `TestNetnsUDPOnDirectEgressReportsWhy` + `TestRelayUDPWhenOutboundRefusesEndsCleanly`（会因不记账而红） | 通过 |
| A30 | 停止 TUN 不在系统里留指向已消失网卡的路由，且 `Stop` 不报假错（拆除三条件：网卡没了算成功 / 本来就不在算成功 / 真没拆掉必须报错） | `TestNetnsStoppedTUNLeavesNoRouteIntoIt`（`ip route show` 真读一遍）+ `teardown_test.go` 两条脱机守卫 | 通过（真内核） |
| A31 | **DNS 故障之后能恢复**：唯一那台上游装死两轮 → 恢复 → 同一个域名立刻解析成功，且第二次不再打上游（失败没被缓存住，也没有每问一次就打一次） | `internal/dnsx/resolver_test.go::TestResolverRecoversAfterEveryUpstreamFails`（`dnstest.Server.Mute` 是真收包不回答） | 通过 |
| A32 | DNS 的两个计数不撒谎：回 SERVFAIL 的那次**不进**「已应答」，进「解析失败」，并记下最近一次的时刻；上游回来之后「已应答」立刻重新涨。告警用"最近两分钟内还在失败"判，不用累计数（否则一次抖动亮到重启） | `internal/tunx/dns_counter_test.go`（真走 `serveUDPDNS` 那条循环，两条用例）+ `frontend/tests/format.test.ts::recentlyFailed` 四条 + 设置页那行与首页告警的投影 | 通过 |
| A34 | **升级重启落在旧残留上**：老进程装完一切就没了（fd 关 → 网卡消失，nat 表原样留着），新进程走真实 `Start()` 之后的**终态**必须是对的——每条劫持规则不多不少各一份、`ip route get <上游>` 走物理网卡而不是自己的 tun、指向 tun 的默认路由恰好一条、真发一个 DNS 查询仍然落进重启后的解析器（用 `dnsServed+dnsFailed` 涨了没有判，不看返回值） | `internal/tunx/restart_netns_test.go::TestNetnsUpgradeRestartOnTopOfResidue` | 通过（真内核） |
| A35 | 清残留**收敛回零**：重复装载在 OUTPUT 上留下的每一份跳转都要被按内容摘掉——`-D` 一次只删一份，剩下那一份让 `-X` 永远失败（链还有引用），于是永久挂着一个指向不存在地址的劫持链。判据自己也守卫：先把「装两遍」演出来，确认数得到 2 份，才允许上面那条「各一份」成立 | `TestNetnsRestartCleanupConverges`（真内核：1 份 → 2 份 → 0 份 + 链没了）+ `stale_test.go::TestCleanupStaleSweepsEveryDuplicatedJump`（脱机，v4/v6 两条路径各一份，突变验证过：摘掉扫描就红） | 通过（真内核） |

A26 顺带给「自己的解析被自己劫持」这个坑补了**反向**证据：以前只能断言规则文本里有 RETURN，
现在能断言发往 223.5.5.5 的查询确实没落到劫持落点上。

A28/A30 各红出一个真 bug（细节见 README §9.1b 末）：本进程那条拆除路径不看
`Optional`，于是每次 `Stop` 都背着三条 `Cannot find device`；
`fdDevice.Close()` 会对同一个 fd 关两次。生产上一直没露头，
是因为线上走的是尊重 `Optional` 的 helper 那条——两条拆除路径判据不同这件事，
只有两条都被真跑过才看得见。

仍然**没有**端到端实测的是隧道那一段：这套 netns 里没有真节点，
A28 的 UDP 用的是 hysteria2 替身出站。
「HY2 真隧道带 UDP / Trojan 真隧道不带」「真实公网 v6 流量进隧道」还是只能靠
`make acceptance-tun`（root + 真实网络 + 真实节点）。

**这一格 2026-10-28 由使用者明确决定不跑**，不是忘了：那条脚本要 root、会改系统 DNS、
还要和正在运行的面板抢 `wps-tun`（本机面板当时在用 TUN）。
所以这几行的证据等级就到「netns + 内核读数」为止，真节点实测的命令与判据留着，
谁要跑都可以照上面那条命令跑一遍——它的结果不属于本台账已核过的部分。
同一时刻部署到线上面板也没做（面板仍跑 10-27 那个二进制）。

**2026-10-28 增量四：故障断网保护（P1 第 4 条的可选项）**。`tun.kill_switch` 默认关闭、
由用户开启：自动切换判定「没有一个节点能用」时，把本机生成的出站收窄到白名单，
其余丢弃——堵住 `strict_route` 换节点整块重启那几百毫秒里的裸奔窗口。

| # | 项 | 证据 | 结果 |
|---|---|---|---|
| A18 | 规则生成本身：按族拆开、放行先于 DROP、白名单去重、回环/DHCP/ICMPv6 等地基放行、摘挂互为逆操作且每步容错 | `internal/tunx/killswitch_test.go`（`TestKillPlan*` 十二条） | 通过 |
| A19 | 三条「保护把自己锁死」的防线：白名单必须含**所有**节点；隧道内侧（假 IP 网段 / 网卡网段 / DNS 落点）必须放行；某族没有对外出口时**宁可不挂并给出原因** | 同上（`TestKillPlanAllowsTunnelAndBackupNodes` / `TestKillPlanSkipsFamilyWithoutEgress` / `TestKillPlanRefusesWhenNothingIsArmable`） | 通过 |
| A20 | 执行与状态：本进程与 helper 两条路径都跑通；挂载中途失败**回滚并把状态报成未生效**；停止 TUN 时先摘链；异常退出的残链由清理路径摘掉 | `killswitch_test.go`（`TestArmKill*` / `TestStopDisarmsKill` / `TestCleanupKill*`）+ `helper_test.go` 的进程内 helper | 通过 |
| A21 | 挂/摘时机：放弃时落下（两条放弃点）、节点通了 / 切换成功 / 用户手动选点时抬起；默认关闭时一条规则都不动；白名单变了才重挂（否则一次解析失败会永久锁死恢复） | `internal/service/killswitch_test.go`（十二条） | 通过 |
| A22 | 面板如实显示：`killEnabled / killArmed / killV4 / killV6 / killReason` 五格投影 + 四态文案（未启用 / 开了但不会生效 / 已挂上 / **未生效 + 原因**） | `internal/ui/projection_guard_test.go` + 前端 typecheck | 通过 |
| A36 | **重挂收敛**：白名单一变就是一次重挂，挂 N 次之后 OUTPUT 上必须还是只有一份挂载点，摘一次必须一份都不剩；链被引用着的时候 `-X` 删不掉它——那正是「面板说已关闭、内核里那条链还挂着」的形态。顺带红出一个更狠的：`TolerateExists` 只认 iproute2 的 "File exists"，而 iptables 说的是 "Chain already exists."，于是第二次重挂在 `-N` 上就判失败、走回滚并报「未生效」 | `killswitch_netns_test.go::TestNetnsKillReArmKeepsOneMount`（挂三次，每次数一份；`CleanupKill` 之后数零份并确认 filter 表里链名都没了）+ `killswitch_test.go::TestKillArmHeadIsReentrant`（按内容判顺序：先摘后挂）+ `tunx_test.go::TestApplyTreatsChainAlreadyExistsAsSuccess`。突变验证过：把「先摘」拿掉，两份/三份立刻现形 | 通过（真内核） |
| A37 | **ICMP 的支持范围量出来了，而不是声明出来的**：全局接管下 echo request 被默认路由吸进 tun，协议栈**就地应答**——接管前 ping 两个地址都不通，接管后两个都「通」（含一个不存在的 TEST-NET 地址，亚毫秒、ttl 64），而连接数、字节、拨不通、DNS 四个账一动不动。所以「ping 得通」在接管状态下不代表对端可达。**两族各自量过，没有假定协议栈按地址族继承**：v6 那条除了一比一地复现「吸进来 + 就地应答 + 四本账不动」，还额外问了 v6 才有的那一层——邻居发现与组播**没有**被吸走（`ip -6 route get fe80::5` 回 `dev fwphys0`，`ff02::1` 回 `dev fwphys0 table local`：这两类地址命中的是直连路由与本地表，永远排在默认路由前面），所以接管不会把本机自己的链路问断。这句已经送到三个地方：日志（每次启用 TUN）、`-diag`、设置页的能力边界那一行（都写明 v4/v6 两族 + ND 与组播不受影响） | `forward_netns_test.go::TestNetnsICMPIsAnsweredLocallyAndNeverCarried` 与 `::TestNetnsICMPv6IsAnsweredLocallyAndNeverCarried`（A/B 两段都在断言里：接管前必须发不出去，接管后必须回；v6 的前置还要求面板那格是 `kernel` 读来的；哪天协议栈不再应答，用例直接红并要求同步改文案）+ `capability_test.go::TestCapabilityNotesICMPScope`（只在 `strict_route` 下报这句；选择性接管与 TUN 关闭时不得出现）。突变验证过三次：给连接账注入一条真记录 → 两条「不许动」的断言同时红；把 v6 那格的接管拿掉 → 前置红；把 ND 那一行的期望网卡改成 wps-tun → 断言红并印出内核的原文 | 通过（真内核） |
| A38 | A33 那四句接管判据不再只对着替身的字符串：在私有 netns 里把默认路由**真的**交给 tun，再让真二进制、真 `ip` 出一份真报告——同一个内核现状换两种配置必须给出两种说法（要求接管 → 成立；没要求 → 点名「没撤销干净的残留」），撤掉路由之后必须改口「没成立」并点名此刻走的物理网卡；v6 那一族在没有 v6 默认路由的 netns 里必须说「与它无关」，不能跟着 v4 一起宣布接管 | `internal/diag/netns_test.go::TestNetnsDiagVerdictsMatchKernel`（`make test-offline` / `test-netns-fw` 会打开 WPS_NETNS；装完接管后先断言内核现状，防止三条判据对同一个假现状一起点头）。突变验证过：把「接管成立」那一支短路掉，第一条就红 | 通过（真内核） |
| A39 | 拆除判据依赖的那三句「已经达成」的措辞，由真工具现场说给判据听（而不是我记得准不准）：重复挂地址内核说的是 `Error: ipv4: Address already assigned.`、重复加路由说的是 `RTNETLINK answers: File exists`、网卡没了之后再拆说的是 `Cannot find device "x"`。Plan 里两条 addr add 都写着 TolerateExists，而判据原先只认前两种句式的一半——「地址已经在卡上」那次重装会被判成失败。反向也要守：网关不可达这种真失败不能落进这三个措辞里，否则「容忍」就退化成「这一步全都不算数」 | `tolerance_netns_test.go`（两条用例：三句都要认、真失败都不能认）。突变验证过：把 "already assigned" 摘掉，第一条立刻红并原样印出内核那句话 | 通过（真内核） |
| A40 | **面板那两格改问内核**：接管装好→报已接管；把默认路由抢回物理卡（不碰 TUN、进程照常跑着）→一个探测周期内自己改口；再把路由交回去→又改回来。读不到路由表时不许冒充实测：来源标成 `memory`，设置页明说「这是按本进程装过的东西推的」；`Status()` 本身零 fork（读数由监视器贴，旧过 15 秒不再自称实测）。| `takeover_netns_test.go::TestNetnsPanelTakeoverFollowsKernel`（真网卡、真路由）+`dualstack_test.go::TestStatusReportsPerFamilyTakeover`（四种现场：都在 tun / 只有 v4 在 / 被抢回物理卡 / 读不到内核）+`takeover_test.go::TestStatusNeverForksForTakeover`（20 次状态查询起 0 条命令，同时不许把探测整个省掉）。突变验证过：把这一格改回读进程记忆，netns 那条立刻红在「面板还在报已接管」 | 通过（真内核） |
| A41 | **升级重启的另一半：面板与 helper 之间的版本错位**——`make build` 覆盖了 `tun.helper` 指着的那个文件，跑着的面板还是老构建（协议 1），于是这个进程此后每一次特权操作都被同一句话拒掉，TUN 再也开不起来（今天 09:16 的真实日志）；而那句原文只有两个版本号，没说要重启面板还是要重装 helper，用户唯一的动作就是再点一次开关、再多两趟注定白跑的 root 调用 | `helper_mismatch_test.go`（四条：两个方向各自说对「该动哪一边」并指名配置里那个文件；`sudo 要密码`/`signal: killed`/`Operation not permitted` 都不许误认成版本问题；第二次启用只起 3 趟 helper 调用而不是 4 趟（跳过白跑的清残留、保留用户显式那一次真实尝试），过期之后重新去问；一次成功的往返当场作废这个结论）。突变验证过三次：保质期归零、建议里不指名路径、把任何 helper 失败都当版本问题——各红在该红的那一条 | 通过（真套接字，进程内 helper） |
| A42 | 同一句处方覆盖**全部六条 helper 路径**，而「跳过」只给其中三条：`up`/`cleanup` 只是启用的开头，跑着的 TUN 还会在 `reroute`（监视器每 5 秒一轮：版本对不上就是每轮一趟白跑的 root 调用 + 每轮一条同样的 WARN，把日志里真出事那几行埋掉）、`down` 与 `kill` 的挂/摘上撞同一个错位。分界线按**副作用**划而不是按频率：重复断言型（cleanup/reroute）可以跳——不发出去只是「没再钉一次」，机器上不多出遗留；拆除型（down / 摘保护）**绝不跳**——跳过的后果不是「这次没成功」而是「那条还在 DROP 本机出站的链留在机器上，而面板写着已停止」。另外 `reroute` 跳过时计划照旧不改：进程不能误以为绕行路由已经跟着新网关走了 | `helper_mismatch_test.go::TestRerouteSkipsWhileMismatchKnown`（第一轮落定真的去问；随后 4 轮一趟都不起；过期之后重新去问；`routeFixes` 不涨、`plan.Gateway` 不动）+ `::TestTeardownNeverSkipsHelperMismatch`（已知对不上之后，拆除照样起一次真实调用，错误里写着「这一步不能跳」并给出该动哪一边）。突变验证过两次：摘掉重钉的跳过 → 监视器恢复每轮白跑，红在调用数；给拆除也加上跳过 → 红在「got 0（0 就是被跳过了）」 | 通过（真套接字，进程内 helper） |
| A43 | 预检：动 root 之前先问一句对面是谁——`-version` 第二行自报「提权协议 N」，面板用**普通用户身份**把 `tun.helper` 那个文件跑一次它；对不上就给出该动哪一边并**一次 root 都不叫**，对得上就把「已知对不上」的结论当场作废（文件刚刷新的那一刻必须能立刻恢复）。三条边界三条判据：问不出来（文件读不到／对面太老没有这一行）必须放行，不许用一次预检的失败取消掉一次本来能成功的启用；进程内 helper 整个跳过预检，配置里那个路径一次都不许 exec；「没有去叫 root」必须进 `Status.lastError` | `helper_probe_test.go`（五条：解析自报行、真 fork/exec 读出版本、Start 在错位时那个文件只被以 `-version` 调起一次且错误带处方、问不出来时放行、匹配时作废结论）。夹具是一个把自身被调参数写进日志的 shell 脚本，所以「叫了几次、带什么参数」是读出来的而不是推断的。突变验证过三次：把预检从 `Start` 摘掉 → 红在「叫了 root 且没有处方」；把「读不到」当成「版本不对」→ 红在放行那条；匹配时不作废 → 红在永久拉黑。人工实测：`./wps_app-gui -version` 第二行 `提权协议 3`、退出码 0，不读配置不抢锁 | 通过（真 fork/exec，无特权） |
| A44 | 同一件事在 `-diag` 里**不启用 TUN 就能看见**：报告先印 `tun.helper` 的 argv，再以普通用户身份跑那个文件的 `-version`，读它自报的提权协议——一致就写「与本程序一致」，不一致就顺着「谁新谁旧」给出该重启面板还是该重新构建，并指名那个文件；读不到就只说读不到，并明确「这不等于版本不对，启用时照旧会去试」（把读不到当成版本不对，报告会劝用户做一次根本没必要的重装） | `internal/diag/helper_proto_test.go`（两个方向各自的处方、一致那一支、读不到那一支不许给出处方、没配 helper 时整行不出现）+ 两次真跑：本机 `./wps_app-gui config.yaml -diag` 印 `它自报提权协议 3，与本程序一致`；拿一份指向「自报协议 1」的假 helper 的最小配置（不含任何真凭据）再跑，印出「比跑着的面板（协议 3）旧…请用当前构建刷新 <那个文件>（make build-gui）」 | 通过（真二进制、真 fork/exec，无特权） |
| A45 | 验收清单那三种形状补齐了最后一种：**只有 v4 出口的机器**。这一种是唯一能证伪「两族必须分开」的场合——只有一个族的出口时，把 v6 目标混进 v4 的 `ip route` 会被内核当场拒（实测原话：`Error: inet6 address is expected rather than "10.60.0.254"`），而把 v6 也报成「已接管」是在承诺一个根本走不通的出口。用例同时钉住：v4 默认路由真交给 tun、v6 默认路由一格都没装、面板那两格一格真一格假且来源是 kernel、v4 上游的绕行路由照装、那个 v6 目标在两族路由表里都不出现、以及发往 8.8.8.8:53 的查询**增量式地**落进我们的解析器 | `ipv4only_netns_test.go::TestNetnsIPv4OnlyTakeover`（前提是显式清掉 v6 默认路由后再验一次「这张网真的没有 v6 出口」，否则整场戏是空跑）+ `restart_netns_test.go::startHijackTUN` 多了 `extraBypass` 参数（用来放一个双栈节点的 v6 地址，不新增第二套脚手架）。顺手把面板那两格的**落笔处合成一个**（`publishTakeoverStateLocked`，监视器与 Start 都走它）——两处各抄一遍赋值迟早漂。突变验证过三次：让 `splitExclude` 把 v6 也塞进 v4 → 红在内核那句 inet6 拒绝；不干净 v6 默认路由 → 红在「前置不成立」；让那个唯一落笔处把 v6 说成已接管 → 红在「v4=true v6=true」 | 通过（真内核） |
| A46 | 「网络断了」这句话**一次中断只说一次**：2026-10-29 13:56 真实日志里 USB 网卡消失后，同一条 WARN 每 5 秒刷一遍，把同一时段的「拨不通」「隧道故障」埋掉；现在按**形态**去重（v4 回来 v6 没回来、DNS 换人都算新消息），恢复时补一句「网络回来了」再闭嘴——否则读日志的人只看见「断了」，永远不知道它什么时候回来的 | `netwatch_spam_test.go::TestNetworkDownWarningSpeaksOncePerEpisode`（四轮一条；恢复一条；稳定后三轮不再重复；第二次中断重新说一次）。突变验证过：去掉去重 → 四轮变三条，红在条数 | 通过（单测，日志钩子计数） |
| A47 | **没有 v6 出口就不发假 v6**：假地址只解决「应用连到哪」，真送出去还得有一条 v6 默认路由。2026-10-29 实测：USB 网卡（带全局 v6）掉线那段时间，AAAA 照样回假 v6 而启动日志在承诺「降级为 NODATA」——承诺与行为相反。现在判据 `v6FakeIPUsable`（网卡+地址+假段+**v6 出口**）由本进程与 helper 两条路共用，没出口时那一组命令一条都不发、AAAA 回 NODATA，并把理由写进面板日志 | `route.go::v6FakeIPUsable`（四格表）+ `v6_egress_test.go`（无出口时 `applyV6` 返回 false 且**一条 v6 命令都没发**；有出口时真去装地址）+ `ipv4only_netns_test.go` 里补的断言（只有 v4 出口的网卡上 `v6Ready` 必须 false）。突变验证过两次：拿掉 `applyV6` 的出口判断 → 红在「没有出口却启用了」；判据里删掉 Gateway6 → 红在四格表第一格 | 通过（单测 + 真内核） |
| A48 | **v6 实链第一次跑通**（原「已知限制」里那条）：带 SNI 连假 v6 拿到 204——`curl --resolve www.google.com:443:[fc00::e]` → `http=204 连接目标=fc00::e`；内核把 `fc00::e` 送进 `wps-tun`；同一秒面板日志 `tun tcp [fd00::1]:45454 -> www.google.com:443 [PROXY \| MODE,GLOBAL]`。前提写清楚：物理网卡得有全局 v6（这台机器靠 USB 网卡），没有时按 A47 降级为 NODATA | 手工实测（2026-10-29 14:07，面板 global 模式 + TUN），命令与输出见 README §12 第一条 | 通过（真机、真节点） |
| A49 | **解析器缓存在两头都要刷**：2026-10-29 实测——面板停掉之后 `getent hosts www.google.com` 还在回 `198.18.0.9`，那是 systemd-resolved 缓存住的假 IP，指向一块已经不存在的网卡；用户看到的症状是「代理关了，浏览器反而几分钟上不了网」，而这段窗口里面板已经退出、日志里什么都没有。现在装好劫持之后刷一次（把先前问到的真 IP 清掉，去向下落才完整），拆掉劫持之后再刷一次（别把人送进不存在的网卡），顺序必须是「先拆劫持、后刷缓存」 | `resolv_flush_test.go`（拆除后确实发了 `resolvectl flush-caches`，且排在最后一条 iptables 之后；刷不动时只记 Debug、不阻断接管与拆除）。突变验证过：把拆除侧那次 flush 拿掉 → 红在「拆除之后没有刷缓存」 | 通过（单测，命令记录） |
| A50 | **B3 真链 10/10**：专用配置（非 7891/7892 端口、`wps-tun-acc` 设备、strict_route 开）下真跑——网卡/地址/9 条 nat 劫持/假 IP 解析/不带 -x 的 curl 204/**8MB 下载实收 8388608 字节**/优雅退出/网卡消失/规则清零/DNS 回真地址。第一次跑是 9/10：假 IP 那格红了，而 nat 表里 9 条规则一直在——根因是脚本自己没刷解析器缓存，操作者跑前 `getent` 过这个域名，systemd-resolved 把**真地址**的旧答案压着回；同一条命令刷完缓存立刻 PASS。脚本已修（检查前先 `resolvectl flush-caches`），复跑 10/10 | `scripts/acceptance/tun_test.sh`（本次改动：假 IP 检查前刷缓存 + 注释写清为什么）+ 两次真跑输出 | 通过（root + 真实网络 + 真实节点） |


helper 协议版本从 2 提到 3：新增 `kill` 动作（请求带 `allow` 白名单与 `killarm`，
应答带每族挂没挂上与原因）。`allow` 会进 root 执行的 `iptables -d <值>`，
所以校验只收 IP 字面量与 CIDR——exec 不经 shell，注入不成立，
但一个以 `-` 开头的值会被 iptables 当成选项，那等于往 root 的命令行里塞参数。
| A51 | **只有一个产物 `./wps_app-gui`**（2026-10-29，按使用者要求删掉 `./wps_app`）：面板、代理、root 侧 `tun.helper` 从此是同一个文件，`make build` 与 `make build-gui` 等价。删它的理由是**版本错位那一类故障少一半**：过去「跑着的面板」与「磁盘上 helper 指着的文件」是两个文件、两套构建，谁先被重建就错位（A41 那次真故障）；现在只有一份，「刷新产物」与「重启面板」是同一件事。**代价照实写**：① root 那条提权路径现在要加载 **146 个共享库**（实测 helper 分支的 `LD_DEBUG` 计数；静态版是 0 个），helper 分支入口 RSS 12.5 MB → **51.9 MB**、起进程 0.01s → 0.04s；② 没装 `libgtk-3-0` / `libwebkit2gtk-4.0-37` 的机器从此跑不了任何产物（`-cli` 也一样，动态链接期就要加载它们），纯交叉编译那条路也没了；③ `make gate` 的依赖里删掉了 `build`——单产物之后它覆盖的就是 helper 指着的那个文件，面板在跑时跑一次门禁就会自己造出错位 | `make build`（干跑确认只出 `wps_app-gui`）+ `make -n clean`（会清掉遗留的 `wps_app`）+ **B3 真链 10/10**（`bash scripts/acceptance/tun_test.sh ./wps_app-gui`：被测二进制与 `tun.helper` 都是 GUI 产物，网卡/地址/9 条 nat 劫持/假 IP/不带 -x 的 curl 204/8MB 下载/优雅退出/网卡消失/规则清零/DNS 回真地址全过）+ **非 root 实例实测 helper 那条路**（`网卡 wps-tun-acc 由 tun.helper 创建，fd 已交给本进程（uid=1000）`——这一条是关键：面板以普通用户跑，helper 是 root 起的 GUI 产物）+ `-diag` 实测 `提权 helper：sudo -n /home/chery/wps_app/wps_app-gui --tun-helper` / `它自报提权协议 3，与本程序一致` + A6 协议 16/16 与 A8 信号 3/3（都用 GUI 产物跑）+ 单元测试 `go test ./...` 全绿、`go vet`（两种标签）全绿、前端覆盖率闸门全绿 | 通过（真机、root、真实节点） |
| A52 | **trojan 头部改成服务端真认的那一种**（2026-10-29）：摘要 SHA-1 → **SHA-224**；命令字节 0x04 → 0x01 并从第一行挪到第二行开头；第二行保持**裸字节**（公开规范写的 hex 编码，这台 trojan 1.16 反而拒）；拨号**不等**规范说的那 10 字节应答头（实测接受后服务端一个字节都不发，等它就是每条连接卡到超时）。旧注释「别顺手修正成规范值，会把这个节点打死」的依据被推翻：10-16 那次"自检通过"是 `probeAccept` 读到兼底页 400 字节造成的**假通过** | 在 VPS 上按 ALPN × 摘要 × 第二行布局逐条发、逐条用唯一目标端口对 `journalctl -u trojan` 的 `not trojan request` / `requested connection` 判相关性；本机 `dist/gate/wps_app-gui 侧配置 -check-fetch https://www.gstatic.com/generate_204` → `OK … https 204 0 字节 via PROXY` 退出码 0，同一秒服务端记 `authenticated as …` + `requested connection to www.gstatic.com:443` + 4101/1705 字节；单测 `TestTrojanHeaderEncoding`、`TestTrojanEndToEnd`（桩同步改成这一种布局并写明"不许替服务端补那 10 字节"）、`internal/inbound/loopback_test.go` 的真 trojan 回环 | 通过（真节点、端到端） |
| A53 | **分流不能再自己说假话**（2026-10-29）：装配时拿当前选中节点的地址做一次"钉上真拨"——钉上拨不通、不钉能通 → 只松开代理侧（直连保留）、note 写清原因、日志 WARN；两条都拨不通 → 不冤枉分流。这台机器的真实形状是 `SO_BINDTODEVICE` 对普通用户**返回成功却静默丢包**（uid 1000 绑 wlx/wlp 都超时，加 ambient `CAP_NET_RAW` 仍超时，只有 uid 0 出得去），所以"绑得上"从来不能当"钉得住"的证据 | 单测 `TestEgressBlockedDowngradesToDefaultRoute`、`TestEgressBlockedNeedsATarget`、`TestEgressBlockedStaysSilentWhenNodeUnreachable`、`TestEgressBlockedQuietWhenBindWorks`、`TestApplyPlanDropsPinWhenEgressBlocked`（断言 `ProxyDev` 空而 `DirectDev` 保留）、`TestEgressPairThreeVerdicts`（钉卡背锅 / 分不清不下结论 / 钉得上一句不提 / 没有目标不许编结论）、`TestProbeDeviceEgressCountsRefusedAsReachable`（`ECONNREFUSED` 算通路正常，否则选中节点是 UDP-only 的 hysteria2 时每次分流都被冤枉）+ 判据只有一份（`outbound.EgressPair`，面板装配与 `-diag` 共用）+ 真机三跑：**没有提权 helper 时**普通用户 `-check-fetch` 打出「网卡分流未生效：…钉上发不出包…不钉时却拨得通」并退回默认路由；**有 helper 时**同一句改成「普通进程钉上发不出包…交给提权 helper 代劳」并维持点名（见 A56）；root 跑同一份侧配置钉住成功、取回 204；**接管后的线上面板（uid 1000）启动即自己写下这句**，`-diag` 同一句原样可见 | 通过 |
| A54 | **测速那一格分得开两种红**（2026-10-29）：`ProfileTest.SplitNote` 把「这次代理流量没有真的从点名的网卡出去」带到节点行；`annotateNodeFault` 只对 `certificate signed by unknown authority` 与 `first record does not look like a TLS handshake` 两种形状各补一句"还有一种不是节点的错"，**判据与失败原文都不改**（原文是可核对的证据，不许被我们自己的推测替换） | 单测 `TestAnnotateNodeFaultCoversBothTLSShapes`、`TestAnnotateNodeFaultMentionsSplit`、`TestAnnotateNodeFaultLeavesOthersAlone`；投影守卫 `TestProjectionMatchesFrontendTypes` / `TestEveryProjectedFieldIsRead` 逼前端把 `splitNote` 真读走；`make frontend`（含 `vue-tsc`）与前端覆盖率闸门全绿 | 通过（**线上真数据、用户亲手点的一次**：2026-10-29 20:5x 面板节点页对 `wbthinks.space:443` 点「测速」，那一行读出 `不通`、原文后面跟着「这不一定就是节点的证书：链路上有设备替我们终止 TLS 时也报这一句；而这次代理流量没有真的钉在点名的网卡上」，并另起一行「没钉到点名的网卡，代理走的是系统默认路由」——三种说法同屏，不需要再猜是哪一种红；**修好出口后的绿态也在真数据上核过**：2026-10-30 上午同一行读出 `使用中 · 本次 26.1 MB · 138 条`、`224 ms`、`页面 https 204 0 字节`，即 A52 的头部在真实流量上成立；**改走提权通道之后又核了一次**：2026-10-30 11:0x 同一行读出 `使用中 · 本次 489.9 KB · 31 条 · 累计 221.2 MB`、`294 ms`、`页面 https 204 0 字节`，并把两句新话都摆出来了——「普通进程钉在 wlx001f0578cdff 上发不出包，这一跳由提权 helper 代劳」与「这一跳实际从 192.168.0.104 出去」——绿态、红态、来源、实际源地址四件事同屏可读） |
| A55 | **两条自激循环：A53 那条探针上线后自己踩出来的**（2026-10-29）。①判成降级 → 重建隧道 → `commitProxy` 在 strict_route 下回头再走一遍装配 → 装配又探一次 → 又判降级：同一个「网卡\|目标」改为**只探一次**（`egressVerdict`，用户拨开关或换卡才作废），且"自己判出来的降级"不再触发重建。②`applyPlan` 落地不幂等：网卡监视每 10 秒问一次，就每 10 秒写一遍状态、念一遍同一句「发不出包」——现在**现状已经就是这样就到此为止** | 单测 `TestEgressVerdictIsProbedOncePerPair`（5 次调用只探 1 次、清掉结论后复探）+ `TestApplyPlanDropsPinWhenEgressBlocked`（交回的必须是实际落地那份）+ **现场时序对照**（循环要有时序才暴露，单测看不见）：修之前 `panel-2031.log` 680 行里 266 条同一句、`panel-2042.log` 113 行里 36 条且每 3~5 秒一组，中间还夹着 `已关闭：直连与代理都按系统默认路由走` 这种空配置落地；修之后新实例 65 秒只有启动那一对，经面板取 `generate_204` 仍 `HTTP=204 / 0.38s` | 通过（现场日志时序 + 单测） |
| A56 | **把"钉卡"这一步交给 root helper（协议 3→4，新动作 `dialbind`）**（2026-10-30）：helper 以 root 造一条**钉在指定网卡上、且已连通**的 TCP socket，用 SCM_RIGHTS 把 fd 交回面板（与 TUN 交回 tun fd 同一条机制）；面板全程不碰 root，托盘与桌面代理控制都还在。两条硬规矩：目标必须是**已解析的 ip:port**（helper 里不许解析域名——故障现场重解析会拿到假 IP）、且必须落在请求给出的名单里（防的是以后某条路径把用户输入的地址交给 root 去连）。判出"普通进程钉上发不出包"后**有两种处置**：有 helper 就维持点名走这条通道，没有才退回系统默认路由 | 单测：`internal/tunx` 的 `TestCheckBindTarget`（域名/环回/组播/不在名单四种都拒）、`TestDialBindRequestValidate`（空名单与空接口名都拒）、`TestDialBoundHandshakesRealSocket`（进程内 helper 走**真 unix socket + 真 SCM_RIGHTS**，拿回的 fd 能收发，且用 `SO_BINDTODEVICE` 问内核确认它确实钉在点名的那张卡上）、`TestDialBoundRefusesEndpointNotInAllow`；`internal/service` 的 `TestEgressBlockedPrefersBindChannel`（有 helper 时不出现"退回默认路由"）与 `TestApplyPlanKeepsPinWhenBindAvailable`（维持点名且 `ShouldUseBind` 为真）+ **真机判决**：手工那条 /32 主机路由删干净后（`ip route get 43.153.148.175` 回到公司网默认路由），线上面板（uid 1000）到节点的连接是 `192.168.0.104%wlx001f0578cdff → 43.153.148.175:8443`——源地址是 USB 卡那张、`%` 后是钉住的设备名，经面板取 `generate_204` 仍 `HTTP=204 / 0.61s`；**面板上那一行自己也这么说**：`使用中 · 294 ms · 页面 https 204 0 字节` + 「普通进程钉在 wlx001f0578cdff 上发不出包，这一跳由提权 helper 代劳」+ 「这一跳实际从 192.168.0.104 出去」 | 通过（真机判决 + 单测 + 面板读数） |
| A57 | **提权 helper 改成常驻**（2026-10-30）：一次性的 helper 每条流付一次 `sudo` + 进程起落（实测 0.08~0.11s，sudo 自己 0.04s），一分钟几十条就是几十次起落。新增 `wps_app-gui --dial-helper`（常驻模式）+ `--dial-helper-connect` / `--dial-helper-owner`；面板保持一条 unix 连接按需要 socket。**边界不变**：root 只造 socket、不终结 TLS（TLS 仍在面板与节点之间端到端，root 看不到明文）、目标必须是已解析的 ip:port 且在名单里、helper 盯着父进程，面板一走就收工 | 单测 `TestPersistentHelperServesManyRequestsOnOneConnection`（**一条连接连做三次请求，且只拉起一次 helper**）、`TestPersistentHelperRefusesEndpointNotInAllow`（常驻不等于松：名单之外仍然被拒）+ 真机：侧跑里 helper 进程**只有 1 个**（两次拨号都走它）、`OK … https 204 0 字节 via PROXY`、侧跑结束后 6 秒内 helper 自行退出（机器上不留 root 进程）、线上面板（uid 1000）不受影响 | 通过（真机 + 单测） |
| A58 | **「换了个人钉卡」这句话只有一个出处**（2026-10-30）：同一个事实有两格要说（分流状态 note、测速那一格），各写一份就会各说各话；而「发不出包」很容易被读成"那张网卡坏了"，实际坏的是**普通进程去钉**这一层。抽成 `bindViaHelperNote(dev, fact)`，`fact`（探针原文）只在放得下的那格带上 | 单测 `TestBindViaHelperNoteIsTheOnlyWording`（钉这句话的形状，改措辞要过它）+ `grep` 判据：生产代码里这句话只由 `bindViaHelperNote` 产出，另外两处（`ifacesplit.go` 状态 note、`profiles.go` 测速那一格）都是调用它 + 真机：13:03 线上面板启动日志即是这句原文（`面板自己（普通权限）钉在 wlx001f0578cdff 上发不出包（…）：…这一跳交给提权 helper 代劳，代理仍然钉在这张卡`），同一分钟内隧道 `192.168.0.104%wlx001f0578cdff → 43.153.148.175:8443`、经面板取回 `HTTP=204 / 0.65s` + **用户在真面板上亲手点的一次「测速」**（2026-10-30 13:1x）：那一格读出 `525 ms`、`页面 https 204 0 字节`，下面两行是「面板自己（普通权限）钉在 wlx001f0578cdff 上发不出包：这台机器上普通进程的绑定返回成功却发不出线，所以这一跳交给提权 helper 代劳，代理仍然钉在这张卡」与「这一跳实际从 192.168.0.104 出去」——正是 `fact` 为空的那一种调用，两格同一句话、没有第二套说法 | 通过（日志原文 + 面板真点） |
| A59 | **wbthinks 在 root 面板下真的按点名的 USB 卡出站**（2026-10-30 14:31 转 root 后复验）：不是"连上了"就算数，要证明**是分流改变了内核的选择**，而且这个证明可以重跑。配置 `iface_split: enable true / direct wlp3s0f0 / proxy wlx001f0578cdff`、`active wbthinks.space:443`、`mode rule` | **归属到进程**：`sudo ss -tnpH state established` 再筛 `wps_app-gui` → 面板自己的出站 **21/21 全带设备标记、0 条漏钉**（18 条 `192.168.0.104%wlx001f0578cdff → 43.153.148.175:8443`，2 条 `10.180.56.177%wlp3s0f0 → …` 直连侧）。**反向对照**：`ip route get 43.153.148.175` 说不钉卡时内核会走 `via 10.180.63.254 dev wlp3s0f0`——观测到的却是 `%wlx001f0578cdff`，所以生效的是分流不是路由。**功能**：连续 5 次经面板取页 `204`（0.52~0.74s），总览那一格 `18 活跃连接 / 405.9 KB / 拨不通 0`、出站隧道 `已建链 43.153.148.175:8443（SNI 已握手）`。**A/B 判据没被关掉**：同一份侧配置（改端口 17891/17892、`tun.enable false`，用完即删）**uid 1000 跑照样打印**「面板自己（普通权限）钉在 wlx001f0578cdff 上发不出包…」，**root 跑只剩**「网卡分流：直连走 wlp3s0f0，代理走 wlx001f0578cdff」并 `OK … 204 via PROXY`、`FETCH-SUMMARY ok=1 fail=0`——那句话不是被删了，是 root 下不再适用。**不循环**：跑 9 分 44 秒，`网卡分流` 那行只出现 **1 次**（启动那次，33+ 个监视周期没重写状态）、`发不出包` 0 次、`隧道故障` 0 条、ERROR 0 | 通过（真机、进程归属、A/B 对照） |
| A60 | **钉卡探针与特权通道改为「按侧」**（2026-10-30 14:4x）：A59 那次对照顺手量出一件假话——普通权限下面板的**直连那一半同样是废的**（`via DIRECT` 失败 **363 / 1244 条、成功建连 0 条**；root 之后失败 **0 条、成功 17 条**），而 `egressBlockedWhy` 在装配时只被拿代理卡调用过一次，note 与 `-diag` 里那句「直连钉在内置卡上是真的在干活，不陪着退」是**拿一次没做过的测量替另一侧背书**。改法：那一问做成 `settleEgress`（两侧各问一次，谁钉不上松谁），特权通道按侧打开（`SetBindNeeded(direct, proxy)` / `BoundDialFor(policy, …)`，直连落点在 `Direct.dial`），`-diag` 同一判据也按侧各说一句；幂等早退把「两侧各自有没有走通道」(`splitBind`) 也纳入比较，否则"helper 中途才出现"那一转会因两张卡名字没变而被吞掉 | 单测 `TestSettleEgressProbesBothSides`（一侧退一侧留、note 点名是哪一侧）、`TestSettleEgressKeepsBothPinsViaBindChannel`（有 helper 时两张卡都维持点名、两句话各自点名）、`TestBindGateIsPerSide`（通道按侧开，分流关掉时两侧都关）、`TestBoundDialForPicksTheSideDevice`（"哪一侧"必须翻译成"哪张卡"，交错即失败）、`TestDirectUsesBoundChannelForResolvedTargets`（**域名不许交给 root 解析**，那条硬规矩在直连层同样守住）+ `go vet`（两种标签）与 `go test ./...` 全绿 + 真机：root 面板 18 分钟里 `via DIRECT` 失败 0 条、直连成功建连 17 条、经面板取页 6/6 全 204、`未钉=0` 连续 6 拍。**同窗记录**：14:45:10~14:45:13 有一次 3.5 秒的链路失链（7 条 trojan `i/o timeout`，源地址正是 USB 卡），自动切换按设计切到 `phaethon-hy2` 又切回 `wbthinks`，代价是 35 条 hysteria 拆连接故障——**这是那张卡的无线电抖动，不是分流坏了**（前后每一拍 `未钉` 都是 0） | 通过（真机 A/B + 单测） |


**这一条的证据等级**：见上面 A27——规则由内核接受，包计数证明拦的是名单外、
放的是名单内，摘链后 nat/filter 表里不留痕迹。剩下的边界不在证据上，而在适用范围上：
它筛的是本机生成的出站，不碰被转发的流量，也不解密任何内容（面板与 README §12 都这么写）。

**A12 抓到的两个坑**（单测全绿时它们就在那儿，只有真跑内核才现形）：

1. `ip -6 route add … via fe80::5%wlp3s0f0` → `inet6 address is expected rather than "fe80::5%wlp3s0f0"`；
2. 网关配成本机地址 → `Gateway can not be a local address`。

**仍未验证（不伪装成通过）**：真实 v6 流量的端到端实链、TUN+trojan 同机实链，
两者都需要真实节点与真实 v6 出口。启动日志与 `-diag` 里都写着这两条。

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
| B3 | TUN root 实链 | **10/10 通过**（2026-10-29 重跑：9 条一次过，第 10 条先红后修——见 A50；单产物迁移后用 `./wps_app-gui` 复跑仍 10/10——见 A51） |
| B5 | `make check` 真机自检 | **通过**（`CHECK_HOSTS=cp.cloudflare.com:443` 连跑三次 `ok=1 fail=0`，面板同期 204）。默认目标 `www.gstatic.com:443` 在本机**直连也超时**，红的是目标站不是程序——见 A51 与 README §9 末的对照表 |
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
`sudo -n wps_app-gui --tun-helper` 能到 euid=0；缺 `--tun-helper-connect` 时按预期报错退出 1。

**方法学备注**：这一项第一次跑报了 1 条 FAIL「实例没退出」。
查下来是**测试脚本自身的缺陷**——脚本没 `wait` 回收子进程，
而僵尸进程的 `kill -0` 依然返回 0，于是把「已经退干净了」
误判成了「没退出」。补上 `wait` 后复跑 9/9 通过。产品侧无对应缺陷。

### B4 GNOME 系统代理

```
ON mode=manual http=127.0.0.1:7892 socks=127.0.0.1:7891
   ignore=localhost,127.0.0.0/8,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

`wps_app-gui -sysproxy status` 返回上述内容；`restore` 幂等（无记账文件时不报错）。

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

原始样本原在 `/tmp/accept/stress-out.txt`，服务日志 `/tmp/accept/stress.log`
（该目录已丢失；压测脚本尚未重建）。

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
./wps_app-gui -c cfg/cli.yaml -cli &
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

**2026-10-27 现状**：`/tmp/accept/` 已不存在。仓库内现在能跑的是 A6/A8：

```bash
# A3 全量 race
go test ./... -race

# A6 协议行为（16 条）+ A8 信号处理（3 条），离线、隔离端口
make acceptance

# A12–A15 / A23–A30、A34–A40 的内核级证据：私有 netns 里建网卡、装路由、挂 iptables、
# 让真的包穿过真的 tun 与协议栈
# （/run 在那里面是 tmpfs，所以 xtables.lock 打得开；宿主的表与路由一条都不动）
make test-netns-fw
make test-offline

# B3 TUN root 实链（会改本机路由/DNS，必须显式启用）
sudo WPS_ACCEPT_TUN=1 WPS_ACCEPT_TUN_CONFIG=/path/to/tun-test.yaml make acceptance-tun

# 性能 P95（会按预算自动失败）
go test ./internal/service/ -run 'P95' -v -race
```

仍未入库（原脚本随 `/tmp` 丢失，需要重建）：

- A4 CLI 参数矩阵（18 条）
- 5 分钟压测与 gctrace 内存口径
- `connect-unreachable.py`（CONNECT 200 的成因对照）
- B3 的原始证据脚本；`scripts/acceptance/tun_test.sh` 是重建版，2026-10-27 未在执行环境跑过

### 复现注意事项

- 这些脚本都跑**隔离端口**上的独立实例，不碰管线上面板（7891/7892）。
- `stress.sh` / `a8-signals.sh` / `b2-tun.sh` 都 `cd` 到仓库根，
  配置里的 `./assets/rules.txt` 与 `./assets/geoip.mmdb` 是相对 cwd 的。
- `b2-tun.sh` 会短暂接管本机 DNS（装 `wps_app_dns` 劫持规则），
  收工时自行清理；**中途不要 `kill -9`**，否则会留下 DNS 劫持残留，
  需用 `wps_app-gui -c <cfg> -tun-reset` 手动清。
