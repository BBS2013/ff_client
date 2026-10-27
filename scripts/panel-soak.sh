#!/usr/bin/env bash
# 被动采样正在跑的面板：RSS / fd / 线程数。
#
# 它**不重启、不发信号、不改配置**，只读 /proc 与 ps。目的就是先回答
# "挂一周到底涨不涨"——主动压测会把正在用的面板打断，那是另一件事。
#
# 用法：
#   scripts/panel-soak.sh                 # 每 5 分钟采一次，直到面板退出
#   scripts/panel-soak.sh --once          # 立刻采一条，冒烟验证
#   scripts/panel-soak.sh --pid 89519 --interval 60 --samples 10
#   scripts/panel-soak.sh --summary dist/panel-soak-89519-*.csv
#
# 输出 CSV 在 dist/ 下（已 gitignore），列：
#   time,epoch,main_rss_kb,tree_rss_kb,webkit_rss_kb,fds,threads,procs
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INTERVAL=300
SAMPLES=0
PID=""
OUT=""
SUMMARY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --pid) PID="${2:?}"; shift 2 ;;
    --interval) INTERVAL="${2:?}"; shift 2 ;;
    --samples) SAMPLES="${2:?}"; shift 2 ;;
    --out) OUT="${2:?}"; shift 2 ;;
    --once) SAMPLES=1; shift ;;
    --summary) SUMMARY="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

summarize() {
  local file="$1"
  [[ -r "$file" ]] || { echo "读不到 CSV: $file" >&2; exit 2; }
  awk -F, '
    NR == 1 { next }
    NR == 2 { first_tree = $4; first_fds = $6; first_threads = $7 }
    {
      last_tree = $4; last_fds = $6; last_threads = $7
      if ($4 > max_tree) max_tree = $4
      n++
    }
    END {
      if (n == 0) { print "CSV 里没有样本"; exit 1 }
      growth = (first_tree > 0) ? (last_tree - first_tree) * 100 / first_tree : 0
      printf "样本 %d 条\n", n
      printf "tree RSS: 首 %.1f MB → 末 %.1f MB（最大 %.1f MB，变化 %+.1f%%）\n", first_tree/1024, last_tree/1024, max_tree/1024, growth
      printf "fd: %d → %d（%+d）\n", first_fds, last_fds, last_fds - first_fds
      printf "线程: %d → %d（%+d）\n", first_threads, last_threads, last_threads - first_threads
    }
  ' "$file"
}

if [[ -n "$SUMMARY" ]]; then
  summarize "$SUMMARY"
  exit 0
fi

if [[ -z "$PID" ]]; then
  PID="$(pgrep -x wps_app-gui | head -1 || true)"
fi
if [[ -z "$PID" ]]; then
  echo "没有找到正在跑的 wps_app-gui；用 --pid 指定，或先启动面板" >&2
  exit 2
fi
if ! kill -0 "$PID" 2>/dev/null; then
  echo "PID $PID 不存在" >&2
  exit 2
fi
if [[ -z "$OUT" ]]; then
  mkdir -p "$ROOT/dist"
  OUT="$ROOT/dist/panel-soak-$PID-$(date +%Y%m%d-%H%M%S).csv"
else
  mkdir -p "$(dirname "$OUT")"
fi

descendants() {
  local parent="$1" child
  for child in $(pgrep -P "$parent" 2>/dev/null || true); do
    echo "$child"
    descendants "$child"
  done
}

sample_once() {
  local main rss fds threads tree web nprocs now epoch
  main="$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ' || true)"
  [[ -n "$main" ]] || return 1
  read -r tree web nprocs < <(
    { echo "$PID"; descendants "$PID"; } | while read -r p; do
      ps -o rss=,comm= -p "$p" 2>/dev/null || true
    done | awk '{ rss += $1; n++; line = $0; if (line ~ /WebKit/) web += $1 } END { print rss+0, web+0, n+0 }'
  )
  fds="$(find "/proc/$PID/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
  threads="$(find "/proc/$PID/task" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
  now="$(date '+%Y-%m-%dT%H:%M:%S%z')"
  epoch="$(date +%s)"
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$now" "$epoch" "$main" "$tree" "$web" "$fds" "$threads" "$nprocs" >>"$OUT"
  printf '[%s] main %.0fMB · tree %.0fMB · webkit %.0fMB · fd %s · threads %s\n' \
    "$now" "$(awk -v v="$main" 'BEGIN{print v/1024}')" "$(awk -v v="$tree" 'BEGIN{print v/1024}')" \
    "$(awk -v v="$web" 'BEGIN{print v/1024}')" "$fds" "$threads"
}

printf 'time,epoch,main_rss_kb,tree_rss_kb,webkit_rss_kb,fds,threads,procs\n' >"$OUT"
echo "采样 PID $PID → $OUT（间隔 ${INTERVAL}s；不重启、不发信号）"

i=0
while :; do
  if ! sample_once; then
    echo "PID $PID 已退出，采样结束" >&2
    break
  fi
  i=$((i + 1))
  [[ "$SAMPLES" -gt 0 && "$i" -ge "$SAMPLES" ]] && break
  sleep "$INTERVAL"
done

echo
summarize "$OUT"
