#!/usr/bin/env bash
# 跑一个模糊测试目标，最多两次。
#
# 为什么允许第二次：go test -fuzz 的截止时间落在"引擎正在换下一批输入"的那一刻时，
# 它会以 `context deadline exceeded` 结束并报 FAIL——没有坏输入、没有落任何样本，
# 重跑就是绿的。本仓库的 fuzz-smoke 是 7 个目标 × 10 秒，实测约 40 次里撞上一次，
# 一次红就够教给人坏习惯："再跑一遍看看"——
# 而一个可以被重跑掉的红，很快就会变成整条门禁都被重跑掉。
# （次数要说准：这是连着跑过的第 6 次门禁里、42 个目标跑中见过的 1 次，
#   不是统计出来的概率——所以判据用"有没有落样本"，不靠"多久一次"来猜。）
#
# 所以这里只重试那**一种**失败，而且判据不是错误文本（那会随 Go 版本变），
# 是"有没有真的找到坏输入"：go 找到时会往 testdata/fuzz/<目标>/ 里写样本文件。
# 写了样本 = 真发现，绝不重试，原样报错并把样本位置指给人看。
#
# 用法: ./scripts/fuzz-once.sh internal/inbound FuzzAssocPacket 10s

set -uo pipefail

if [[ $# -lt 2 ]]; then
  echo "用法: $0 <包路径> <目标名> [时长]" >&2
  exit 2
fi

PKG="$1"
NAME="$2"
DUR="${3:-10s}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORPUS="$ROOT/$PKG/testdata/fuzz/$NAME"

count_samples() { [[ -d "$CORPUS" ]] && find "$CORPUS" -maxdepth 1 -type f | wc -l || echo 0; }

run_fuzz() {
  (cd "$ROOT" && GOFLAGS=-mod=vendor GOPROXY=off go test "./$PKG" -run=NONE -fuzz="$NAME" -fuzztime="$DUR" 2>&1)
}

before=$(count_samples)
out=$(run_fuzz)
rc=$?
after=$(count_samples)

if ((rc == 0)); then
  if printf '%s' "$out" | grep -q 'no fuzz tests'; then
    echo "✗ $PKG/$NAME 没有这个模糊目标（go test 仍返回 0，门禁会假绿）" >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    exit 1
  fi
  printf '%s\n' "$out" | tail -2
  exit 0
fi

if ((after > before)) || printf '%s' "$out" | grep -qF 'writing corpus'; then
  echo "✗ $PKG/$NAME 找到坏输入（不重试）。样本落在 ${CORPUS#$ROOT/}：" >&2
  printf '%s\n' "$out" | sed 's/^/    /'
  exit 1
fi

if ! printf '%s' "$out" | grep -qF 'context deadline exceeded'; then
  echo "✗ $PKG/$NAME 失败，且不是截止时间那种红（不重试）：" >&2
  printf '%s\n' "$out" | sed 's/^/    /'
  exit 1
fi

echo "! $PKG/$NAME 第一次是被截止时间掐断的（没有坏输入样本），重跑一次确认" >&2
out=$(run_fuzz)
rc=$?
after=$(count_samples)
if ((rc != 0)) || ((after > before)); then
  echo "✗ $PKG/$NAME 重跑仍然红——这不是抖动，得当真问题查：" >&2
  printf '%s\n' "$out" | sed 's/^/    /'
  exit 1
fi
printf 'ok（重试后通过）%s\n' "$NAME"
exit 0
