#!/usr/bin/env bash
# 拉取 GeoIP mmdb 与可选的规则种子。
#
# 用法:
#   ./scripts/fetch-assets.sh              # 只拉默认的 227KB 国内库
#   ./scripts/fetch-assets.sh --seed       # 再拉 gfw.txt 并生成 assets/gfw-proxy.txt
#   ./scripts/fetch-assets.sh --full-geo   # 把 mmdb 换成 7.6MB 全球库（可与 --seed 同用）
#
# 拉取完成后可 `kill -HUP $(pgrep -f wps_app)` 热重载，无需重启。

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS="$ROOT/assets"
MIRROR="https://cdn.jsdelivr.net/gh"

# 说明：raw.githubusercontent.com 在部分网络下不可达，统一走 jsdelivr。
# 文件名首字母大小写敏感，Country.mmdb 的大写 C 是关键。
GEO_REPO="Loyalsoldier/geoip@release"
GEO_SMALL="Country-only-cn-private.mmdb"   # 227 KB，仅中国 + 私有地址
GEO_FULL="Country.mmdb"                    # 7.6 MB，全球

SEED_URL="$MIRROR/Loyalsoldier/v2ray-rules-dat@release/gfw.txt"

FULL_GEO=0
WITH_SEED=0
for arg in "$@"; do
  case "$arg" in
    --full-geo) FULL_GEO=1 ;;
    --seed)     WITH_SEED=1 ;;
    -h|--help)  sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $arg" >&2; exit 1 ;;
  esac
done

mkdir -p "$ASSETS"

fetch() {
  local url="$1" dest="$2"
  echo "下载 $url"
  if ! curl -fsSL --max-time 120 -o "$dest.tmp" "$url"; then
    echo "下载失败: $url" >&2
    rm -f "$dest.tmp"
    return 1
  fi
  # 简单的非空校验，避免把错误页当成 mmdb 存进去。
  if [ ! -s "$dest.tmp" ]; then
    echo "下载内容为空: $url" >&2
    rm -f "$dest.tmp"
    return 1
  fi
  mv "$dest.tmp" "$dest"
  ls -lh "$dest"
}

GEO_FILE="$GEO_SMALL"
[ "$FULL_GEO" -eq 1 ] && GEO_FILE="$GEO_FULL"

fetch "$MIRROR/$GEO_REPO/$GEO_FILE" "$ASSETS/geoip.mmdb"
echo "GeoIP 就绪: $ASSETS/geoip.mmdb"

if [ "$WITH_SEED" -eq 1 ]; then
  fetch "$SEED_URL" "$ASSETS/gfw.txt"
  # gfw.txt 每行是裸域名，转成 wps_app 的规则语法。
  # 生成独立文件，不覆盖 rules.txt —— 需要时自行 include 或合并。
  awk '
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    { print "DOMAIN-SUFFIX," tolower($0) ",PROXY" }
  ' "$ASSETS/gfw.txt" > "$ASSETS/gfw-proxy.txt"
  echo "规则种子已生成: $ASSETS/gfw-proxy.txt ($(wc -l < "$ASSETS/gfw-proxy.txt") 条)"
  echo "提示：把其中需要的条目合并进 $ASSETS/rules.txt 后再 SIGHUP 重载。"
fi

echo "完成。"
