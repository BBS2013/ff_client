#!/usr/bin/env bash
# 守的是“提交后的 frontend/dist 能自洽”：index.html 引用的每个 assets/* 必须真存在。
#
# 2026-11-02 的工作区里 index.html 已经指向新的哈希文件，而新文件还没入库；
# 只提交 tracked 的变更会让 go:embed 进二进制的页面白屏。门禁先拦这一下。
set -euo pipefail
cd "$(dirname "$0")/.."

index=frontend/dist/index.html
if [[ ! -f "$index" ]]; then
  echo "缺少 $index" >&2
  exit 1
fi

refs=$(grep -oE 'assets/[A-Za-z0-9._-]+' "$index" | sort -u || true)
if [[ -z "$refs" ]]; then
  echo "$index 没有引用任何 assets/* 资源" >&2
  exit 1
fi

missing=0
while IFS= read -r ref; do
  [[ -n "$ref" ]] || continue
  if [[ ! -f "frontend/dist/$ref" ]]; then
    echo "frontend/dist/index.html 引用了不存在的资源: $ref" >&2
    missing=1
  fi
done <<< "$refs"
exit "$missing"