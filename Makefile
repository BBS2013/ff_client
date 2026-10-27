# Makefile 管四类事：两种构建（命令行 / 桌面面板）、前端产物、测试（含断网跑）、打包与自检。
#
# 两种产物靠构建标签 gui 分开，这是刻意设计：
#   make build       -> 静态 stripped 二进制，无 CGO、无 GTK 依赖，给 systemd 部署
#   make build-gui   -> 带 GTK3/WebKit2GTK 的桌面面板，需要图形环境
# 两者都是单进程，GUI 进程内部自己跑着代理，不依赖另一个守护进程。

BIN      := wps_app
GUI_BIN  := wps_app-gui
LDFLAGS  := -s -w
# gui 把 GTK/WebKit 运行时限制在 GUI 产物里；production 是 Wails 自己的标签。
GUI_TAGS := gui production

.PHONY: all build build-gui frontend test test-offline fuzz-smoke bench latency paint race vet fmt fmt-check gate clean check package

all: build

## 默认构建：静态、无 CGO、systemd 可直接部署。
build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BIN) .

## GUI 构建：先出前端产物再编 Go。完整逻辑见 scripts/build-gui.sh。
build-gui:
	./scripts/build-gui.sh

## 只重建前端产物，供本地调样式时快速迭代。
frontend:
	cd frontend && npm run build

## test 带 -timeout 是有原因的：死锁的症状不是"测试失败"，是"门禁挂住"。
## 今天加一个投影字段时，Snapshot 在持锁期间调了另一个要抢同一把锁的读方法
## （sync.Mutex 不可重入），面板第一次轮询就把自己锁死——
## 没有 -timeout 的话，这要等 10 分钟才出声，而且看起来像"脚本卡住了"。
## 240 秒既够最慢的那个包，又能在挂住时把 goroutine 栈打出来，直接点名是谁在等锁。
test:
	go test ./... -timeout 240s

## test-offline 在一个只有回环的网络命名空间里跑全套测试：
## 任何一条用例只要还偷偷依赖真实 DNS / 外网 / 本机路由，这里就会红。
## 平时 `make test` 在开发机上跑是绿的，因为机器什么都有——那种绿说明不了"离线也能跑"。
## 需要非特权用户命名空间（unshare -rn）；内核关掉它时这条会直接报错，不要改成 skip。
test-offline:
	unshare -rn bash -c 'ip link set lo up && GOFLAGS=-mod=vendor GOPROXY=off go test ./... -count=1 -timeout 240s'

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
PAINT_ARGS ?=
paint:
	./scripts/panel-paint.py $(PAINT_ARGS)

race:
	go test -race ./... -timeout 6m

## vet 两种构建都要跑。只跑默认构建会漏掉 `//go:build gui` 下的文件——
## gui.go 里一个没用到的 import 就是这么溜过去、直到 make build-gui 才红的。
vet:
	go vet ./...
	go vet -tags "$(GUI_TAGS)" ./...

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
## 里面刻意含 build-gui：只有它会把 `//go:build gui` 下的文件真链接一遍，
## vet 能查语法、查不出链接期的缺失符号。
gate: fmt-check build vet test race test-offline fuzz-smoke frontend build-gui
	@echo "全套门禁通过"

## package 出两个包：给使用者的运行包（预编译产物）与含 vendor 的源码包。
## 细节与三条红线（不带 config.yaml / 不带 GeoLite2 / 不带你的 user-rules）见 scripts/package.sh。
package:
	./scripts/package.sh

## check 是程序自带的配置与链路自检，与 go test 互补。
check: build
	./$(BIN) config.yaml -check

clean:
	rm -f $(BIN) $(GUI_BIN)
	rm -rf frontend/dist
