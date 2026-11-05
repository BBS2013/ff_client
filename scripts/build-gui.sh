#!/usr/bin/env bash
# 构建带 GUI 的 wps_app 二进制。
#
# 用法:
#   ./scripts/build-gui.sh              # 装依赖（缺依赖才装）→ 构建前端 → go build
#   ./scripts/build-gui.sh --skip-frontend   # 复用已有的 frontend/dist，只重编 Go
#   WPS_GUI_OUT=/tmp/x ./scripts/build-gui.sh --skip-frontend
#                                       # 输出到别处。make gate 用这条把产物放进
#                                       # dist/gate/，避免覆盖正在跑的面板二进制。
#
# 与 make build-gui 等价，这个脚本只是为了在没有 make 的机器上也能出产物。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# 默认仍是仓库根下的 wps_app-gui（发布/手工重建的惯用位置）；
# gate 之类的验证构建必须用 WPS_GUI_OUT 指到临时目录。
OUT="${WPS_GUI_OUT:-$ROOT/wps_app-gui}"
# gui 是我们的隔离标签（把 GTK/WebKit 运行时关在默认构建之外），
# production 是 Wails 自己的。两个都要给，缺一个都编不出可用产物。
# Ubuntu 24.04+ / GitHub Actions 往往只有 webkit2gtk-4.1 开发包，Wails 用 webkit2_41 标签切换 pkg-config。
TAGS="gui production"
if ! pkg-config --exists webkit2gtk-4.0 2>/dev/null; then
  if pkg-config --exists webkit2gtk-4.1 2>/dev/null; then
    TAGS="gui production webkit2_41"
  fi
fi
# 与 Makefile/package.sh 共用同一份注入：版本、源码指纹、构建时刻。
LDFLAGS="$("$ROOT/scripts/build-ldflags.sh")"

SKIP_FRONTEND=0
for arg in "$@"; do
  case "$arg" in
    --skip-frontend) SKIP_FRONTEND=1 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $arg" >&2; exit 1 ;;
  esac
done

if [ "$SKIP_FRONTEND" -eq 0 ]; then
  echo "==> 构建前端（frontend/dist）"
  cd "$ROOT/frontend"
  # node_modules 已有就不重装，CI 里首次跑会自动落到这里。
  [ -d node_modules ] || npm ci
  npm run build
  "$ROOT/scripts/check-dist.sh"
  # vite.config.ts 里 outDir 是相对 frontend/ 的 'dist'。
  # gui.go 的 //go:embed all:frontend/dist 按这个路径找，别改成 ../frontend/dist。
  [ -f "$ROOT/frontend/dist/index.html" ] || { echo "前端产物缺失: frontend/dist/index.html" >&2; exit 1; }
  cd "$ROOT"
fi

echo "==> 编译 GUI 二进制"
# Wails 的 GTK 后端必须走 CGO，CGO_ENABLED=0 编不出窗口。
mkdir -p "$(dirname "$OUT")"
CGO_ENABLED=1 go build -trimpath -buildvcs=false -tags "$TAGS" -ldflags="$LDFLAGS" -o "$OUT" .

echo "完成: $OUT ($(du -h "$OUT" | cut -f1))"
echo "提示: 这是唯一产物——面板、代理、root 侧 tun.helper 都指着它。"
echo "      它依赖系统已装 libgtk-3 与 libwebkit2gtk-4.0；没有图形界面就加 -cli 跑："
echo "      $OUT config.yaml -cli"
echo "      面板正在跑时重建它会覆盖 tun.helper 指着的那个文件，重建完要重启面板。"
