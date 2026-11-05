#!/usr/bin/env bash
# 守的是“提交后的 frontend/dist 能自洽”：index.html 引用的每个 assets/* 必须
#   1) 在磁盘上存在（工作区形状对）；
#   2) 已被 git 跟踪（提交后形状也对）。
#
# 第 2 条是 2026-11-02 白屏事故的根因：那天 index.html 已经指向新的哈希文件，
# 而新文件还没入库。只提交 tracked 的变更，go:embed 进二进制的那份 dist 里
# 就只剩一个指向不存在文件的 index.html —— 界面直接白屏，而磁盘上一切正常，
# 所以只查“文件在不在”的那版脚本是绿的。
#
# 不在 git 工作树里（比如解压出来的源码包）时只做第 1 条：包里没有 .git，
# 把“没跟踪”判成失败会让接收方连构建都跑不起来。
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

in_git=0
if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  in_git=1
fi

tracked=""
if ((in_git)); then
  # --error-unmatch 在路径没被跟踪时退出码非 0，正是我们要的那个信号。
  tracked=$(git ls-files -- frontend/dist)
fi

missing=0
while IFS= read -r ref; do
  [[ -n "$ref" ]] || continue
  if [[ ! -f "frontend/dist/$ref" ]]; then
    echo "frontend/dist/index.html 引用了不存在的资源: $ref" >&2
    missing=1
    continue
  fi
  if ((in_git)); then
    if ! grep -qxF "frontend/dist/$ref" <<<"$tracked"; then
      echo "frontend/dist/index.html 引用的资源没有被 git 跟踪: $ref" >&2
      echo "  只提交已跟踪文件会让嵌入页面的 index.html 指向一个不存在的文件（白屏）。" >&2
      echo "  修法：git add frontend/dist && git commit（哈希资源必须与 index.html 同一次提交）" >&2
      missing=1
    fi
  fi
done <<<"$refs"

# 反向一条：dist 里有未被引用的旧哈希文件不是错误（构建残留），
# 但被跟踪的旧哈希文件必须真的还在磁盘上，否则提交树里是一堆空引用。
if ((in_git)); then
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    case "$path" in frontend/dist/assets/*) ;; *) continue ;; esac
    base=${path#frontend/dist/}
    if ! grep -qxF "$base" <<<"$refs"; then
      # 旧的、已不被 index.html 引用的资源：允许存在，只在对不上磁盘时抱怨。
      continue
    fi
    if [[ ! -f "$path" ]]; then
      echo "$path 已被 git 跟踪，但磁盘上不存在" >&2
      missing=1
    fi
  done <<<"$tracked"
fi

exit "$missing"
