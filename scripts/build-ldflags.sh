#!/usr/bin/env bash
# 打印两份产物共用的 ldflags：版本、源码指纹、构建时刻。
# Makefile、build-gui.sh、package.sh 都调用这一处，避免三份口径漂移。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

stamp="$("$ROOT/scripts/build-stamp.sh")"
version="unknown"
if [[ -f "$ROOT/VERSION" ]]; then
  version="$(tr -d '[:space:]' <"$ROOT/VERSION")"
fi
built_at="${WPS_BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

printf -- '-s -w -X wps_app/internal/buildinfo.Version=%s -X wps_app/internal/buildinfo.Stamp=%s -X wps_app/internal/buildinfo.BuiltAt=%s\n' \
  "$version" "$stamp" "$built_at"
