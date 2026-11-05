# Makefile 管四类事：构建（只有一个产物）、前端产物、测试（含断网跑）、打包与自检。
#
# 只有一个产物：
#   make build / make build-gui -> 带 GTK3/WebKit2GTK 的桌面面板 ./wps_app-gui
#
# 2026-10-29 删掉了第二个产物 ./wps_app（CGO_ENABLED=0 的静态命令行版）。理由：
# 面板与 `tun.helper` 从此是同一个文件，不再有「重建了其中一个、另一个还是旧的」
# 这种漂移——2026-10-29 那次 TUN 开不起来就是它（面板协议 1 vs 磁盘 helper 协议 3）。
# 代价写在这里，别只写在 README 里：
#   1) root 那条提权路径现在要加载 146 个共享库（实测 helper 分支 LD_DEBUG 计数），
#      静态版是 0 个；helper 分支入口的 RSS 从 12.5 MB 变 51.9 MB，起进程 0.01s→0.04s。
#   2) 没装 libgtk-3 / libwebkit2gtk-4.0 的机器从此跑不了任何产物：无头/systemd 部署
#      要 `./wps_app-gui config.yaml -cli`，而 -cli 也躲不过动态链接期加载这些库。
#   3) 交叉编译产物只能在那台机器上 `make build-gui`（GTK 需要目标机的 sysroot）。
# 不带 gui 标签的那份编译仍由 vet/test/race 覆盖（它们在没有标签的目录下构建整个包）。

GUI_BIN  := wps_app-gui
# 版本/源码指纹/构建时刻由 scripts/build-ldflags.sh 一处生成：build-gui 与 package 都调它，
# 所以产物的自报口径不会分叉。
# gui 把 GTK/WebKit 运行时限制在 GUI 产物里；production 是 Wails 自己的标签。
GUI_TAGS := gui production
# gate 的 GUI 产物单独放：它验证的是"能不能链接、能不能跑"，不该覆盖
# ./wps_app-gui 这个正在被面板使用的发布产物。dist/ 已在 .gitignore 里。
GATE_DIR     := dist/gate
GATE_GUI_BIN := $(GATE_DIR)/wps_app-gui

.PHONY: all build build-gui gate-gui gate-pr frontend frontend-test test test-offline test-netns-fw fuzz-smoke bench latency paint race vet vet-nogui vet-gui fmt fmt-check gate clean check package acceptance acceptance-tun soak soak-once probe-attribution dist-check hooks install-helper cover

all: build

## 默认构建 = 面板构建。保留这个名字是为了旧习惯与脚本里那句 `make build`；
## 它不再有第二个产物。
build: build-gui

## 唯一的产物：先出前端产物再编 Go。完整逻辑见 scripts/build-gui.sh。
## 这是发布/手工重建用的目标：它会覆盖 ./wps_app-gui——而这个文件现在同时是
## tun.helper 指着的那个文件，所以**面板在跑时重建它会让 helper 与面板分属两个构建**
## （协议号对不上时预检会直接拒绝起 root 并点名该动哪一边）。刷新产物后重启面板。
build-gui:
	./scripts/build-gui.sh

## gate 专用的 GUI 构建：产物进 dist/gate/，绝不覆盖 ./wps_app-gui。
## 前端由 frontend 目标先构建，这里只做 go build 的链接验证。
gate-gui: frontend
	mkdir -p $(GATE_DIR)
	WPS_GUI_OUT="$(abspath $(GATE_GUI_BIN))" ./scripts/build-gui.sh --skip-frontend

## 只重建前端产物，供本地调样式时快速迭代。
frontend:
	cd frontend && npm run build
	./scripts/check-dist.sh

## 单独验一次“index.html 引用的哈希资源真的在磁盘上、而且已入库”。
## 2026-11-02 的教训：只提交 tracked 文件时，index.html 会指向未跟踪的新 assets，
## go:embed 进二进制的页面直接白屏；这个检查已挂在上面的 frontend 目标里。
## 2026-11-05 同一形状又来了一次，所以它现在还会对照 git 索引（见脚本头）。
dist-check:
	@./scripts/check-dist.sh

## 安装仓库自带的 git 钩子。不是 .git/hooks 里放一份副本就算数：
## 钩子本身随仓库版本化（scripts/hooks/），装的这一步才是一次性动作。
## 没有 .git（解压出来的源码包）时安静跳过，不当作错误。
hooks:
	@if [ -d .git/hooks ]; then \
		install -m 0755 scripts/hooks/pre-commit .git/hooks/pre-commit; \
		echo "已安装 pre-commit 钩子"; \
	else \
		echo "没有 .git，跳过钩子安装"; \
	fi

## 前端纯函数测试 + 覆盖率闸门（format/ageclock/nodetests/probes）。
## 组件交互仍靠人工点验；这里守的是"算得对不对"。
frontend-test:
	cd frontend && npm run test:coverage

## test 带 -timeout 是有原因的：死锁的症状不是"测试失败"，是"门禁挂住"。
## 今天加一个投影字段时，Snapshot 在持锁期间调了另一个要抢同一把锁的读方法
## （sync.Mutex 不可重入），面板第一次轮询就把自己锁死——
## 没有 -timeout 的话，这要等 10 分钟才出声，而且看起来像"脚本卡住了"。
## 240 秒既够最慢的那个包，又能在挂住时把 goroutine 栈打出来，直接点名是谁在等锁。
test:
	go test ./... -timeout 240s

## cover 写出覆盖率文件，不设阈值。数字在 dist/ 下，不进仓库。
cover:
	mkdir -p dist
	go test ./... -count=1 -coverprofile=dist/coverage.out -timeout 240s
	go tool cover -func=dist/coverage.out | tail -1

## test-offline 在一个只有回环的网络命名空间里跑全套测试：
## 任何一条用例只要还偷偷依赖真实 DNS / 外网 / 本机路由，这里就会红。
## 平时 `make test` 在开发机上跑是绿的，因为机器什么都有——那种绿说明不了"离线也能跑"。
## 需要非特权用户命名空间（unshare -rn）；内核关掉它时这条会直接报错，不要改成 skip。
## WPS_NETNS=1 打开「会真改路由」的用例（internal/tunx/netns_linux_test.go、
## internal/diag/netns_test.go）：它们在私有 netns 里建网卡、装默认路由，绝不能跑在宿主 netns 上。
## -p 1 是必需的，不是保守：整个 `go test ./...` 共享同那一个 netns，而默认路由全表只有一条——
## 两个包并行装各自的接管就会互相踩（谁先装上都算"现状"），断言就成了掷硬币。
## 串行只慢几十秒，换来的是这两组证据每次都对着同一份内核状态说话。
test-offline:
	unshare -rn bash -c 'ip link set lo up && WPS_NETNS=1 GOFLAGS=-mod=vendor GOPROXY=off go test ./... -count=1 -p 1 -timeout 300s'

## test-netns-fw 在私有 netns 里跑「真 iptables」那一组（internal/tunx/killswitch_netns_test.go）。
## 为什么要多一个挂载命名空间：iptables 起来第一句就要打开 /run/xtables.lock，
## 那个文件属于宿主里的 root，非特权 userns 打不开——过去「netns 里验不了防火墙规则」
## 就是这么来的。把 /run 换成 tmpfs 之后链装得上、包计数读得到，
## 而所有规则只活在这个私有 netns 里，宿主的表一条不动。
## 开关是显式的 WPS_FW=1：开着却建不了链会判失败而不是 skip——那是脚手架坏了。
test-netns-fw:
	unshare -rnm bash -c 'mount -t tmpfs tmpfs /run && ip link set lo up && WPS_NETNS=1 WPS_FW=1 GOFLAGS=-mod=vendor GOPROXY=off go test ./internal/tunx -count=1 -timeout 180s'

## fuzz-smoke 给每个模糊目标跑 FUZZTIME（默认 10s）。输入全是"本机任何进程都能发过来"
## 或"远端订阅能写过来"的字节，所以断网也能跑；它查的是同一条底线：不许 panic、
## 不许越界读、错误信息不许把垃圾字节原样带进日志。
## 跑出来的新用例落在 testdata/fuzz/<目标>/ 下——那是常驻回归种子，值得留在仓库里。
FUZZTIME ?= 10s
## fuzz-smoke 走 scripts/fuzz-once.sh 而不是裸 go test：
## 那一步只对"引擎被截止时间掐断"这一种红重试一次（判据是有没有落样本文件），
## 真找到坏输入时绝不重试。理由与实测次数写在那个脚本的头上。
fuzz-smoke:
	./scripts/fuzz-once.sh internal/rules FuzzParseLine $(FUZZTIME)
	./scripts/fuzz-once.sh internal/rules FuzzIncludeLine $(FUZZTIME)
	./scripts/fuzz-once.sh internal/inbound FuzzSocks5Addr $(FUZZTIME)
	./scripts/fuzz-once.sh internal/inbound FuzzAssocPacket $(FUZZTIME)
	./scripts/fuzz-once.sh internal/inbound FuzzAppendAddr $(FUZZTIME)
	./scripts/fuzz-once.sh internal/tunx FuzzDNSServe $(FUZZTIME)
	./scripts/fuzz-once.sh internal/tunx FuzzReadFrame $(FUZZTIME)

## bench 跑三组，因为面板上"慢"有三个不同的来源，各自只在不同的包上量得出来：
##   internal/rules   每条连接都要付的判定代价 + 启动时装配规则集的代价
##   internal/service 规则页每 5 秒那一轮读的是什么（含"停着的时候"那条路径）
##   internal/metrics 流量页每秒那一轮（Snapshot 持锁做全部拷贝与排序）
## 数字与它们得出的结论都记在 README §9.3：改这三处前后都该跑一次，
## 而且 §9.3 里"量出来不用改"的那几格也是靠这三条命令复现的——
## 复现不了的数字和没量过等价。后两组的 -benchtime 用次数而不是时长：
## 它们的构造成本（灌 800 条连接）本身就要几十毫秒，按秒数取平均会把它算进分子。
bench:
	go test ./internal/rules -run NONE -bench 'Load|Match' -benchtime=300ms
	go test ./internal/service -run NONE -bench 'Poll|BlockList' -benchtime=100x
	go test ./internal/metrics -run NONE -bench 'Snapshot' -benchtime=200x

## latency 量的是面板那一侧：切到某一页那一下要多久。
## 与 bench 分开是因为它不进 Go 测试——它要一个伺服着的 dist 与一个浏览器。
## 前置（缺任何一条脚本直接退出码 2，不会量出一份看着正常的假数）：
## make frontend、frontend/dist 上有 python3 -m http.server 5199、本机装了 agent-browser。
## 数字与判据见 README §9.3 末了那张表。
latency:
	./scripts/panel-latency.sh

## paint 量的是**面板真正用的渲染引擎**里的帧时代价：WebKitGTK + 硬件加速 NEVER。
## 与 latency 分开是因为两把尺子量的不是同一件事：
## latency 跑在 GPU 加速的浏览器里，量的是"切页/键入那一下"的挂载代价；
## 这一条跑在同一个 WebKitGTK 里，量的是滚动时的帧时——面板在真机上是 Never 策略
## （gui.go 写了为什么不能换），软件光栅下的帧时与加速渲染下不是一回事。
## 前置与用法见 scripts/panel-paint.py 的抬头；数字与判据见 README §9.4。
## 追加参数：make paint ARGS="--css oldLook"（盖回改之前那版样式做 A/B）。
## 演示数据不进面板二进制。量帧时单独打一份带 VITE_DEMO 的产物到 frontend/dist-paint，
## 静态伺服要指这个目录，而不是 frontend/dist。
PAINT_ARGS ?=
paint:
	cd frontend && VITE_DEMO=1 npx vite build --outDir dist-paint
	./scripts/panel-paint.py $(PAINT_ARGS)

race:
	go test -race ./... -timeout 6m

## vet 两种构建都要跑。只跑默认构建会漏掉 `//go:build gui` 下的文件——
## gui.go 里一个没用到的 import 就是这么溜过去、直到 make build-gui 才红的。
## vet-nogui 不拉 GTK/WebKit pkg-config，给 gate-pr / 无 dev 包环境用；
## vet-gui 需要 libgtk-3-dev 与 webkit 开发包（与 gate-gui 同档）。
vet-nogui:
	go vet ./...

vet-gui:
	go vet -tags "$(GUI_TAGS)" ./...

vet: vet-nogui vet-gui

fmt:
	gofmt -l .

## fmt-check 与 fmt 的差别是有没有退出码：fmt 只把没格式化的文件列出来，
## 退出码照样是 0——挂在门禁里等于没有这道门。
## 只查自己写的代码：vendor 里上游文件本来就不符合本仓库的格式，
## 拿 `gofmt -l .` 去过，会永远列出上百条噪音，然后没人再看这个输出。
fmt-check:
	@out=$$(gofmt -l internal *.go 2>/dev/null); \
	if [ -n "$$out" ]; then echo "未格式化的文件："; echo "$$out"; exit 1; fi; \
	echo "格式 OK"

## gate 是"改完东西跑这一条"的全套离线门禁：不碰外网、不碰线上配置、不碰正在跑的面板。
##
## 与 check 的区别要说清：check 拿仓库里的 config.yaml 做真机自检，
## 它会向你的节点与订阅源发请求、可能重写订阅缓存——那是"部署前自己看一眼"，
## 不是回归门禁。gate 只验证代码，断网的机器上、CI 上都能跑。
## 里面刻意含 gate-gui：只有它会把 `//go:build gui` 下的文件真链接一遍，
## vet 能查语法、查不出链接期的缺失符号。产物固定写到 dist/gate/，
## 所以 gate 跑完后 ./wps_app-gui（正在跑的面板，也是 tun.helper 指着的那个文件）
## 的字节与 mtime 都不变。
## gate 的依赖里刻意**没有** build：单产物之后 `make build` 覆盖的就是 helper 那个文件，
## 面板在跑时跑一次门禁就会自己造出「面板 vs helper 两个构建」的漂移。
## 不带 gui 标签的那份编译由 vet/test/race 覆盖（它们在没有标签的目录下构建整个包），
## 链接验证由 gate-gui 覆盖，所以少一个 build 不会漏掉什么。
## 跑门禁前先确认**没有**在跑的面板：全局模式（mode: global）下系统解析器对任何域名都回
## 198.18.x 假 IP，`internal/service` 与 `internal/diag` 里那几条「拨一个必然失败的地址」
## 会因此真的拨通（2026-10-29 实际踩过一次，停了面板三条全绿）。
## 现在这几条都带上了前提检查：解析器在编答案时它们会**带原因地跳过**而不是红
## （`switch_test.go::fakeDNSActive`、`diag_test.go::TestReportNormalResolvConfIsQuiet` 已收窄判据）；
## 但跳过等于这一格没验，所以门禁轮次仍应在面板停着的时候跑。
## gate-pr 是 PR / CI 快路径：格式、vet-nogui、Go 单测、前端构建（含 vue-tsc 与 dist 自洽）、前端单测。
## 不含 vet-gui / race / test-offline / test-netns-fw / fuzz-smoke / gate-gui（后者见 .github/workflows/nightly.yml）。
gate-pr: fmt-check vet-nogui test frontend frontend-test
	@echo "PR 门禁通过（未含 race / 离线 netns / fuzz / gate-gui；本地全套仍用 make gate）"

gate: fmt-check vet test race test-offline test-netns-fw fuzz-smoke frontend frontend-test gate-gui
	@echo "全套门禁通过（GUI 产物: $(GATE_GUI_BIN)，未触碰 ./$(GUI_BIN)）"

## package 出两个包：给使用者的运行包（预编译产物）与含 vendor 的源码包。
## 细节与三条红线（不带 config.yaml / 不带 GeoLite2 / 不带你的 user-rules）见 scripts/package.sh。
package:
	./scripts/package.sh

## 这三个目标都跑「当前这份产物」，但**绝不覆盖 ./$(GUI_BIN)**。
## 单产物之后 ./$(GUI_BIN) 同时是正在跑的面板和 tun.helper 指着的那个文件：
## 覆盖它等于让跑着的进程与磁盘上的文件分属两个构建（协议号对不上时 TUN 直接开不了），
## 而且正在跑的那个进程会持着被删掉的 inode（/proc/<pid>/exe 显示 deleted）。
## 所以它们用 gate-gui 那条路：产物进 dist/gate/，发布产物一个字都不动。
## 为什么不是 build：build 现在就是 build-gui，它覆盖的正是 ./$(GUI_BIN)。
## （2026-10-29 实测踩过：`make check` 覆盖之后跑着的面板 exe 变成 "(deleted)"。）

## check 是程序自带的配置与链路自检，与 go test 互补。
## 面板二进制默认开界面，这里必须带 -cli：只跑代理服务、不起窗口也不起托盘。
##
## CHECK_HOSTS 用来换自检目标（逗号分隔，格式 host:port）。为什么要有这个出口：
## 默认目标是 www.gstatic.com:443，而本机**直连**它也拨不通（实测不经代理同样超时），
## 于是默认跑法在某些网络下必然红——那是目标站不通，不是程序坏了。
## 换成一个真能拨到的目标才问得出「程序通不通」这个问题。
## 例：make check CHECK_HOSTS=cp.cloudflare.com:443
CHECK_HOSTS ?=
check: gate-gui
ifeq ($(CHECK_HOSTS),)
	./$(GATE_GUI_BIN) config.yaml -check
else
	./$(GATE_GUI_BIN) config.yaml -check -check-host $(CHECK_HOSTS)
endif

## acceptance 是仓库内可离线跑的验收：A6 协议 16 项 + A8 信号。
## 自己起隔离实例（17891/17892），不碰线上 7891/7892、不碰外网。
acceptance: gate-gui
	python3 scripts/acceptance/proto_test.py --binary ./$(GATE_GUI_BIN)
	bash scripts/acceptance/signals_test.sh ./$(GATE_GUI_BIN)

## acceptance-tun 是 B3 根权限实链（会改本机路由/DNS）。默认不跑：
## 没有 WPS_ACCEPT_TUN=1 或专用配置时脚本会打印 SKIP 并以 2 退出。
## 被测二进制与 tun.helper 现在都是 ./$(GUI_BIN)：2026-10-29 实测 10/10。
## 注意：它默认起的是 dist/gate/ 那份，所以专用配置里的 tun.helper 必须指着同一份，
## 否则验的是「产物 A + helper B」——那不是本机线上的形状。
acceptance-tun: gate-gui
	bash scripts/acceptance/tun_test.sh ./$(GATE_GUI_BIN)

## soak 被动采样正在跑的面板（不重启、不发信号），默认每 5 分钟一条。
## CSV 在 dist/ 下；--summary 汇总已有 CSV。
soak:
	./scripts/panel-soak.sh

## soak-once 只采一条，用来验证采样器本身。
soak-once:
	./scripts/panel-soak.sh --once

## probe-attribution 只读地量一遍「连接归到哪个进程」在这台机器上给到哪一步：
## 内核 BTF / lockdown / 两个 sysctl / 本进程 capabilities / 第三方内核模块，
## 外加同 uid 的 socket→pid 反查能不能真做出来（含耗时）。
## 为什么值得一个目标：这三档实现的门槛是**机器的属性**，换机器就要重量一遍；
## 而 README 里那条"先评估再考虑 eBPF"的结论只有能被重跑，才不是空话。
probe-attribution:
	./scripts/probe-socket-attribution.sh

## install-helper 把提权用的那份产物装到 root 拥有的位置。
##
## 为什么不是"直接用仓库里的 ./wps_app-gui"：sudoers 只认**路径**，不认内容。
## 仓库目录属于普通用户、可写，于是同一个用户的任何进程（git checkout、
## go build、一次误 mv）都能换掉那个文件，下一次 helper 调用就以 root 执行。
## 装到 /usr/local/libexec 之后，那条免密规则指向的文件只有 root 能改。
##
## 装完记得把 config.yaml 里的 tun.helper 指向这里（README §4.3 有完整的
## sudoers 片段），并在面板里重启一次让它重新读配置。
HELPER_DIR  ?= /usr/local/libexec/wps_app
HELPER_BIN  := $(HELPER_DIR)/wps_app-gui

install-helper: $(GUI_BIN)
	@install -d -o root -g root -m 0755 $(HELPER_DIR)
	@install -o root -g root -m 0755 $(GUI_BIN) $(HELPER_BIN)
	@echo "已安装 $(HELPER_BIN)（root:root 0755，目录 root:root 0755）"
	@echo "接下来：把 config.yaml 的 tun.helper 改成"
	@echo "  [\"sudo\", \"-n\", \"$(HELPER_BIN)\", \"--tun-helper\"]"
	@echo "并在 /etc/sudoers.d/ 里只放行这一条完整 argv（README §4.3）。"

clean:
	rm -f $(GUI_BIN)
	# wps_app 这个名字已经不是产物了（见文件头），但它可能还躺在旧检出的仓库根目录里，
	# 而且 tun.helper 可能还指着它——顺手清掉，免得下次起面板去叫一个没人维护的文件。
	rm -f wps_app
	rm -rf frontend/dist
