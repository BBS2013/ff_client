#!/usr/bin/env bash
# A8 信号处理验收：SIGHUP 只重载、SIGTERM 优雅退出、端口被释放。
#
# 与 A6 一样自己起隔离实例（17891/17892），不碰线上面板的 7891/7892，
# 不碰外网。用法：
#   bash scripts/acceptance/signals_test.sh ./wps_app
#
# 退出码：0 = 通过；1 = 失败；2 = 前置不满足（端口被占、二进制缺失）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${1:-$ROOT/wps_app}"
[[ -x "$BIN" ]] || { echo "找不到可执行文件: $BIN" >&2; exit 2; }

TMP="$(mktemp -d -t wps-accept-signals.XXXXXX)"
PID=""
cleanup() {
  if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
    kill -TERM "$PID" 2>/dev/null || true
    sleep 0.2
    kill -KILL "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

port_busy() { ss -ltn 2>/dev/null | grep -qE ":$1[[:space:]]"; }
for p in 17891 17892; do
  if port_busy "$p"; then
    echo "端口 $p 已被占用：验收脚本不会去动别人的进程，先腾出来" >&2
    exit 2
  fi
done

cat >"$TMP/rules.txt" <<'EOF'
DOMAIN,acceptance.invalid,DIRECT
FINAL,DIRECT
EOF
cat >"$TMP/config.yaml" <<EOF
proxies:
  - name: "acceptance-direct"
    server:
      type: hysteria2
      addr: "127.0.0.1:9"
      auth: "acceptance"
      tls:
        sni: "localhost"
        insecure: true
active: "acceptance-direct"
mode: direct
inbounds:
  - type: socks5
    listen: "127.0.0.1:17891"
  - type: http
    listen: "127.0.0.1:17892"
rules_file: "$TMP/rules.txt"
tun:
  enable: false
dns:
  servers:
    - 127.0.0.1
  timeout: 1s
log:
  level: info
EOF

"$BIN" -c "$TMP/config.yaml" -cli >"$TMP/proxy.log" 2>&1 &
PID=$!

wait_for_port() {
  local port="$1" i
  for i in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
      exec 3>&- 2>/dev/null || true
      return 0
    fi
    sleep 0.1
  done
  return 1
}

fail() {
  echo "FAIL  $*"
  echo "--- 代理日志尾部 ---"
  tail -30 "$TMP/proxy.log" || true
  exit 1
}

if ! wait_for_port 17891 || ! wait_for_port 17892; then
  fail "隔离实例没有在 17891/17892 上监听"
fi
echo "PASS  隔离实例已监听 17891/17892"

kill -HUP "$PID"
sleep 0.5
if ! kill -0 "$PID" 2>/dev/null; then
  fail "SIGHUP 之后进程退出了；它应该只重载规则"
fi
if ! port_busy 17891 || ! port_busy 17892; then
  fail "SIGHUP 之后监听器消失了"
fi
echo "PASS  SIGHUP 后进程仍在、监听仍在"

kill -TERM "$PID"
for _ in $(seq 1 100); do
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$PID" 2>/dev/null; then
  fail "SIGTERM 后 10 秒内没有退出"
fi

rc=0
wait "$PID" || rc=$?
PID=""
if [[ "$rc" -ne 0 ]]; then
  fail "SIGTERM 退出码是 $rc，期望 0"
fi
echo "PASS  SIGTERM 后 10 秒内以 0 退出"

if port_busy 17891 || port_busy 17892; then
  fail "退出后端口仍在监听"
fi
echo "PASS  退出后 17891/17892 已释放"

echo
echo "A8 3/3 通过"
