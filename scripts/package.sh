#!/usr/bin/env bash
# 一条命令出两个包：
#
#   dist/wps_app-<ver>-linux-<arch>.tar.gz   给使用者：预编译产物 + 资源 + 说明，解压即用
#   dist/wps_app-<ver>-src.tar.gz            给编译者：源码 + vendor/，GOPROXY=off 也能 make
#
# 用法:
#   ./scripts/package.sh                 # 出两个包
#   ./scripts/package.sh --no-src        # 只出运行包
#   ./scripts/package.sh --no-gui        # 明确不要 GUI（缺 WebKit 开发包时用）
#   ./scripts/package.sh --frontend      # 顺手 npm 重构建前端（默认复用已有 frontend/dist）
#   ./scripts/package.sh --with-geoip    # 明知故犯地把 geoip.mmdb 打进包（见下面 NOTICE 的理由）
#
# 三条不能进包的东西，脚本会主动拦住：
#   1) config.yaml / *.bak / *.lock —— 里面是你真实节点的口令和运行痕迹；
#      包里给的是 config.example.yaml（全是占位符），并在收尾处做一次口令泄露扫描。
#      它们旁边的两份记账同理不带：<config>.sysproxy.json 与 <config>.usage.json——
#      后者是你各个月跑掉多少流量的记录，和口令一样属于"不该跟包走"的东西。
#      （脚本是"逐项列出来拷"，所以这三份本来就不在名单上；写在这里是为了加文件时别改成全拷。）
#   2) assets/geoip.mmdb —— MaxMind GeoLite2 的许可不允许把数据库文件随作品再分发；
#      程序缺它只是 GEOIP 规则不生效（照常启动），所以让对方自己跑 scripts/fetch-assets.sh。
#      同理不带 gfw.txt / gfw-proxy.txt（第三方数据）。--with-geoip 是给"我知道我在干什么"的人的出口。
#   3) assets/user-rules.txt —— 你在面板里加的自定义域名规则，它反映你的使用习惯，不该跟包走。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"

BUILD_SRC=1
BUILD_FRONTEND=0
WITH_GEOIP=0
NO_GUI=0
for arg in "$@"; do
  case "$arg" in
    --no-src)     BUILD_SRC=0 ;;
    --no-gui)     NO_GUI=1 ;;
    --frontend)   BUILD_FRONTEND=1 ;;
    --with-geoip) WITH_GEOIP=1 ;;
    -h|--help)    sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $arg" >&2; exit 1 ;;
  esac
done

VER="unknown"
[[ -f "$ROOT/VERSION" ]] && VER="$(tr -d '[:space:]' <"$ROOT/VERSION")"
GOARCH="$(go env GOARCH)"
GOOS="$(go env GOOS)"
NAME="wps_app-$VER-$GOOS-$GOARCH"
STAGE="$DIST/$NAME"

# 编译一律走 vendor：没有网络也能出包，且保证包里的依赖版本就是这个目录里的那份。
export GOFLAGS=-mod=vendor
export GOPROXY=off
LDFLAGS="$("$ROOT/scripts/build-ldflags.sh")"

say() { printf '==> %s\n' "$*"; }

if [[ $BUILD_FRONTEND -eq 1 ]]; then
  say "重构建前端（npm）"
  (cd "$ROOT/frontend" && npm ci && npm run build)
elif [[ ! -f "$ROOT/frontend/dist/index.html" ]]; then
  echo "缺少 frontend/dist：先跑 ./scripts/build-gui.sh 或带 --frontend。" >&2
  exit 1
fi

rm -rf "$STAGE"
mkdir -p "$STAGE/assets" "$STAGE/scripts"

say "编译命令行产物（静态、零依赖）"
# -trimpath 不只是让构建可复现：不带它，二进制的调试段里会留下你机器上的绝对路径。
CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o "$STAGE/wps_app" "$ROOT"
"$STAGE/wps_app" -version >"$STAGE/BUILD-INFO.txt"

say "编译图形面板（需要 GTK3/WebKit2GTK 的开发包）"
if [[ $NO_GUI -eq 1 ]]; then
  echo "    跳过：显式给了 --no-gui。"
elif pkg-config --exists webkit2gtk-4.0 2>/dev/null && pkg-config --exists gtk+-3.0 2>/dev/null; then
  go build -trimpath -tags "gui production" -ldflags "$LDFLAGS" -o "$STAGE/wps_app-gui" "$ROOT"
else
  echo "!! 本机没有 libgtk-3-dev / libwebkit2gtk-4.0-dev，运行包会没有 wps_app-gui。" >&2
  echo "   装上开发包再打包；确实只要命令行版，请显式加 --no-gui。" >&2
  exit 1
fi

say "拷资源与文档"
cp "$ROOT/config.example.yaml" "$STAGE/config.example.yaml"
cp "$ROOT/README.md" "$STAGE/README.md"
cp "$ROOT/assets/rules.txt" "$STAGE/assets/rules.txt"
[[ -f "$ROOT/assets/user-rules.txt" ]] || echo "FINAL,PROXY" >"$STAGE/assets/user-rules.txt"
cp "$ROOT/scripts/fetch-assets.sh" "$STAGE/scripts/fetch-assets.sh"
cp "$ROOT/scripts/check-deps.sh" "$STAGE/check-deps.sh"
chmod +x "$STAGE/check-deps.sh" "$STAGE/scripts/fetch-assets.sh"
if [[ $WITH_GEOIP -eq 1 && -f "$ROOT/assets/geoip.mmdb" ]]; then
  echo "    注意：你指定了 --with-geoip，GeoLite2 的再分发责任由你承担。" >&2
  cp "$ROOT/assets/geoip.mmdb" "$STAGE/assets/geoip.mmdb"
fi

cat >"$STAGE/NOTICE.md" <<'EOF'
# 第三方内容与许可

- 二进制里静态/动态链接了 Go 依赖（hysteria2 core、tun2socks、gVisor、Wails、
  fyne systray、maxminddb、yaml.v3、x/net、x/sys 等）。源码包里 `vendor/` 完整保留了
  每个模块的源码与各自的 LICENSE 文件，位置就是 `vendor/<模块路径>/LICENSE`。
- `assets/rules.txt`、`assets/user-rules.txt` 是本项目的作者写的规则集与规则文件。
- `assets/geoip.mmdb` 与 gfw 系规则数据 **不在本包里**：
  GeoLite2 的许可不允许第三方再分发数据库文件，规则数据同理。
  需要它们在目标机上自取：

      ./scripts/fetch-assets.sh          # 只拉 GeoIP（可选）
      ./scripts/fetch-assets.sh --seed   # 再拉 gfw 列表并生成 gfw-proxy.txt

  缺这些文件不影响启动与代理，只是 GEOIP / 未列入 rules.txt 的域名会退到 FINAL 策略。
EOF

cat >"$STAGE/INSTALL.md" <<'EOF'
# 三分钟跑起来

先体检（只读，不改系统）：

    ./check-deps.sh

## 只要浏览器走代理（推荐从这条开始）

    cp config.example.yaml config.yaml      # 然后把节点地址/口令改成你自己的
    ./wps_app-gui config.yaml               # 出窗口与托盘
    # 在「节点与模式」里把「系统代理」打开，浏览器立刻生效，不用改任何环境变量

没有图形界面、或者不想装 GTK/WebKit 就用命令行版（静态二进制，零依赖）：

    ./wps_app config.yaml &
    curl -x http://127.0.0.1:7892 -sS -o /dev/null -w '%{http_code}\n' https://www.google.com/
    curl --socks5-hostname 127.0.0.1:7891 -sS -o /dev/null -w '%{http_code}\n' https://www.google.com/

## 先拉一句资源，否则"规则模式"其实等于全局代理

包里的 `assets/rules.txt` 只有规则骨架；域名清单（gfw 系）与 GeoIP 属于第三方数据，
因为许可不随包发（见 NOTICE.md）。没拉它们时域名规则是 **0 条**，所有连接落到兜底
`FINAL,PROXY`——表现是"国内站点也绕了一圈出去"，而不是报错。

    ./scripts/fetch-assets.sh --seed                  # 拉 GeoIP + gfw 列表，规则集才完整
    kill -HUP $(pgrep -x wps_app)                     # 热重载，不用重启

不想拉数据也能精准控制：在面板「节点与模式 → 域名规则」里，把你常用的几个域名加进去即可。

## 想全局接管（TUN，包括不认代理环境变量的应用）

TUN 要特权，两种给法（README §4.3 讲了原理与差别）：

    # A. 面板仍以普通用户跑，只把"开网卡 + 改路由"交给提权 helper（托盘正常）
    #    config.yaml 里打开 tun.enable 与 tun.helper，并给该用户配免密 sudo
    # B. 直接 sudo 跑面板（TUN 可用，但 root 连不上桌面会话总线，托盘图标会没有）
    sudo ./wps_app-gui config.yaml

    sudo ./wps_app config.yaml -check        # 只验一次与服务端的链路
    sudo ./wps_app config.yaml -tun-reset    # 上次被 kill -9 后本机 DNS 挂了就用它复位

## 打包给别人的注意事项

- \`config.yaml\` 里是你的口令，别连同它一起发出去；包里给的是 config.example.yaml。
- 想要规则集与 GeoIP：在目标机上跑 \`./scripts/fetch-assets.sh\`（许可原因没随包发）。
- 换机子/换发行版遇到图形面板起不来，先看 \`check-deps.sh\` 报的缺库列表。
EOF

say "自检：产物里不该留下本机绝对路径（-trimpath 的作用）"
# 打进二进制的构建路径会暴露用户名/目录结构，也是最容易被忽略的一处泄漏。
leak=$(strings "$STAGE/wps_app" | grep -c "$HOME" || true)
if [[ "$leak" != "0" ]]; then
  echo "    !! 静态产物里出现 $leak 处本机路径（\$HOME），检查 -trimpath 是否被去掉" >&2
  exit 1
fi

# collect_secrets 把"这份配置里哪些值算秘密"列出来，一行一个。
#
# 以前只扫 auth:，那是假设"这个程序里只有节点口令是秘密"——不成立：
# 入站可以配 username/password（SOCKS 认证），订阅 url 里那一段路径或
# ?token= 常常就是鉴权凭据（很多人用的就是带 token 的分享链接）。
# 漏掉任何一类，后果都是"包发出去、别人的订阅账号跟着出去了"。
collect_secrets() {
  local cfg="$1"
  # 1) 明写的凭据字段。
  #    必须按"值"抓而不是按"整行是这个键"抓：YAML 的流式写法
  #    （server: { addr: "…", auth: "…" }）里 auth 不在行首，
  #    按行首匹配的旧写法对这种配置**一个值都抓不到**，扫描会静默全绿。
  grep -oE '(^|[^A-Za-z0-9_-])(auth|password|username|token|secret|key)[[:space:]]*:[[:space:]]*("[^"]*"|[^",}[:space:]]+)' "$cfg" \
    | sed -E 's/^[^:]*:[[:space:]]*//; s/^"(.*)"$/\1/'
  # 2) URL 里的 userinfo（https://user:pass@host/…）
  grep -oE 'https?://[^[:space:]\"]+' "$cfg" | sed -nE 's|^https?://([^/@]+)@.*$|\1|p'
  # 3) URL 的路径与查询——订阅 token 通常就住在这里
  grep -oE 'https?://[^[:space:]\"]+' "$cfg" | sed -nE 's|^https?://[^/]+(/.*)$|\1|p' 
}

SRC_DIR=""
if [[ $BUILD_SRC -eq 1 ]]; then
  say "准备源码树（先备好，和运行包一起过泄露扫描）"
  SRC="$DIST/wps_app-$VER-src"
  SRC_DIR="$SRC"
  rm -rf "$SRC"
  mkdir -p "$SRC/assets" "$SRC/scripts" "$SRC/frontend"
  # 逐项列出来拷，而不是"全拷 + 排除"：漏排除一次就是把口令发出去一次。
  cp "$ROOT"/*.go "$ROOT/go.mod" "$ROOT/go.sum" "$ROOT/Makefile" "$ROOT/README.md" "$ROOT/ACCEPTANCE.md" "$SRC/"
  [[ -f "$ROOT/VERSION" ]] && cp "$ROOT/VERSION" "$SRC/VERSION"
  cp "$ROOT/config.example.yaml" "$SRC/"
  cp "$ROOT/assets/rules.txt" "$SRC/assets/"
  # 不拷 assets/user-rules.txt：那是你在面板里加的域名清单，反映使用习惯
  cp -a "$ROOT/internal" "$ROOT/scripts" "$ROOT/vendor" "$SRC/"
  [[ -d "$ROOT/packaging" ]] && cp -a "$ROOT/packaging" "$SRC/"
  # dist 是 go:embed 的输入：带着它，对方没有 node 也能编出图形面板
  cp -a "$ROOT/frontend/dist" "$SRC/frontend/"
  cp -a "$ROOT/frontend/src" "$SRC/frontend/"
  cp -a "$ROOT/frontend/tests" "$SRC/frontend/"
  cp "$ROOT/frontend"/*.json "$ROOT/frontend"/*.html "$ROOT/frontend"/vite.config.* "$ROOT/frontend"/vitest.config.* "$SRC/frontend/" 2>/dev/null || true
  find "$SRC" -name '*.bak' -delete
fi

# 扫的是两个包的全部内容与"将要被打进包"的每一个字段。
# 只扫运行包会漏掉源码包；只扫 auth 会漏掉订阅 token——这两条都是"发出去才看得见"的错。
SCAN_CFG="${PACKAGE_CONFIG:-$ROOT/config.yaml}"
if [[ -f "$SCAN_CFG" ]]; then
  say "泄露扫描（$SCAN_CFG 里的每个凭据值都不许出现在包里）"
  hits=0
  checked=0
  while IFS= read -r secret; do
    [[ -z "$secret" || ${#secret} -lt 4 ]] && continue   # 太短的占位符没有鉴别力
    checked=$((checked + 1))
    for tree in "$STAGE" "$SRC_DIR"; do
      [[ -d "$tree" ]] || continue
      if grep -rqiF -- "$secret" "$tree"; then
        echo "    !! 包里出现了本地配置里的凭据（长度 ${#secret}），中止打包" >&2
        hits=$((hits + 1))
      fi
    done
  done < <(collect_secrets "$SCAN_CFG" | sort -u)
  ((hits == 0)) || exit 1
  say "    扫了 $checked 个凭据值 × 运行包/源码包，未发现泄漏"
else
  echo "    注意：没有 $SCAN_CFG 可参照，泄露扫描跳过（发出去之前自己再看一眼包内容）" >&2
fi

say "打运行包"
tar -C "$DIST" -czf "$DIST/$NAME.tar.gz" "$NAME"
if [[ $BUILD_SRC -eq 1 ]]; then
  say "打源码包"
  tar -C "$DIST" -czf "$DIST/wps_app-$VER-src.tar.gz" "wps_app-$VER-src"
  rm -rf "$SRC"
fi

say "生成校验和"
(
  cd "$DIST"
  sha256sum "$NAME.tar.gz" >SHA256SUMS
  if [[ $BUILD_SRC -eq 1 ]]; then
    sha256sum "wps_app-$VER-src.tar.gz" >>SHA256SUMS
  fi
)
echo "    接收端校验： (cd dist && sha256sum -c SHA256SUMS)"

say "产物"
ls -l "$DIST" | awk 'NR>1 && $5 > 0 {printf "    %9s  %s\n", $1, $9}'
