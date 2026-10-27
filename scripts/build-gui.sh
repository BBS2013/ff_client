#!/usr/bin/env bash
# 构建带 GUI 的 wps_app 二进制。
#
# 用法:
#   ./scripts/build-gui.sh              # 装依赖（缺依赖才装）→ 构建前端 → go build
#   ./scripts/build-gui.sh --skip-frontend   # 复用已有的 frontend/dist，只重编 Go
#
# 与 make build-gui 等价，这个脚本只是为了在没有 make 的机器上也能出产物。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/wps_app-gui"
# gui 是我们的隔离标签（把 GTK/WebKit 运行时关在默认构建之外），
# production 是 Wails 自己的。两个都要给，缺一个都编不出可用产物。
TAGS="gui production"
LDFLAGS="-s -w"

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
  # vite.config.ts 里 outDir 是相对 frontend/ 的 'dist'。
  # gui.go 的 //go:embed all:frontend/dist 按这个路径找，别改成 ../frontend/dist。
  [ -f "$ROOT/frontend/dist/index.html" ] || { echo "前端产物缺失: frontend/dist/index.html" >&2; exit 1; }
  cd "$ROOT"
fi

echo "==> 编译 GUI 二进制"
# Wails 的 GTK 后端必须走 CGO，CGO_ENABLED=0 编不出窗口。
CGO_ENABLED=1 go build -tags "$TAGS" -ldflags="$LDFLAGS" -o "$OUT" .

echo "完成: $OUT ($(du -h "$OUT" | cut -f1))"
echo "提示: GUI 产物依赖系统已装 libgtk-3 与 libwebkit2gtk-4.0；服务端部署仍用默认的 make build。"
