#!/usr/bin/env bash
# 打印源码指纹。有 git 时用短 commit（脏树加 -dirty）；
# 没有 git（例如源码包解压出来的树）时用内容哈希。
#
# 判据刻意不用 mtime：拷贝/解压会改 mtime，而这份值要回答的是
# 「两台机器上编出来的是不是同一份源码」。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  stamp="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
  # 未跟踪的新源码文件也算脏：否则新增一个 .go 文件后指纹仍说"干净"。
  if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
    stamp="$stamp-dirty"
  fi
  echo "$stamp"
  exit 0
fi

# 没有 git：对会进构建的文件做内容哈希。排除依赖、产物、运行期秘密与私人规则，
# 它们要么可复现，要么根本不该影响"源码是哪一份"。
find . -type f \
  ! -path './vendor/*' \
  ! -path './frontend/node_modules/*' \
  ! -path './dist/*' \
  ! -path './.git/*' \
  ! -path './.spike/*' \
  ! -path './config.yaml*' \
  ! -path './assets/user-rules.txt*' \
  ! -name '*.log' -a ! -name '*.log.*' \
  ! -name 'wps_app' -a ! -name 'wps_app-gui' \
  -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  | sha256sum \
  | cut -c1-12
