#!/usr/bin/env bash
# B3 TUN root 实链验收（**会改本机路由与 DNS，默认不跑**）。
#
# 这份脚本从 ACCEPTANCE.md §B3 的断言重建。它需要一个已经配好
# tun.enable: true、且指向真实 hysteria2 节点的**专用**配置：
#   - 入站端口不能是 7891/7892（避免和线上面板抢）；
#   - tun.device 不能是线上面板正在用的设备（脚本会拒绝已存在的设备）；
#   - 需要 root、/dev/net/tun、ip、iptables、curl。
#
# 用法：
#   sudo WPS_ACCEPT_TUN=1 \
#        WPS_ACCEPT_TUN_CONFIG=/path/to/tun-test.yaml \
#        bash scripts/acceptance/tun_test.sh ./wps_app-gui
#
# 退出码：0 = 9/9；1 = 有 FAIL；2 = 前置不满足（未显式启用、缺 root/配置/工具）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${1:-$ROOT/wps_app-gui}"
CFG="${WPS_ACCEPT_TUN_CONFIG:-}"

skip() { echo "SKIP  $*" >&2; exit 2; }

[[ "${WPS_ACCEPT_TUN:-0}" == "1" ]] || skip "没有 WPS_ACCEPT_TUN=1；这是会改系统路由与 DNS 的根权限测试，不默认跑"
[[ -n "$CFG" && -r "$CFG" ]] || skip "没有可读的 WPS_ACCEPT_TUN_CONFIG"
[[ -x "$BIN" ]] || skip "找不到可执行文件: $BIN"
[[ "$(id -u)" -eq 0 ]] || skip "请用 sudo 跑本脚本（它要建 tun、改路由、清 iptables）"
[[ -e /dev/net/tun ]] || skip "没有 /dev/net/tun"
for c in ip iptables curl; do
  command -v "$c" >/dev/null 2>&1 || skip "缺少命令: $c"
done

grep -qE '^[[:space:]]*enable:[[:space:]]*true' "$CFG" || skip "配置里 tun.enable 不是 true"
read -r DEV ADDR < <(python3 - "$CFG" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
def grab(key, default=""):
    m = re.search(r'^\s*' + key + r':\s*["\']?([^"\'\s#]+)', text, re.M)
    return m.group(1) if m else default
print(grab("device", "wps-tun"), grab("address", ""))
PY
)
DEV="${DEV:-wps-tun}"
[[ -n "$ADDR" ]] || skip "配置里没有 tun.address"
if ip link show "$DEV" >/dev/null 2>&1; then
  skip "设备 $DEV 已经存在；先确认它不是线上面板正在用的 TUN，再手动清掉"
fi
if grep -qE 'listen:[[:space:]]*"?127\.0\.0\.1:789[12]' "$CFG"; then
  skip "配置里的入站端口是 7891/7892；请换成隔离端口再跑"
fi

TMP="$(mktemp -d -t wps-accept-tun.XXXXXX)"
PID=""
cleanup() {
  if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
    kill -TERM "$PID" 2>/dev/null || true
    sleep 1
    kill -KILL "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  # 这个复位只碰这份专用配置指向的设备/规则；失败不掩盖原来的退出码。
  "$BIN" -c "$CFG" -tun-reset >/dev/null 2>&1 || true
  rm -rf "$TMP"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok()   { echo "PASS  $*"; PASS=$((PASS + 1)); }
bad()  { echo "FAIL  $*"; FAIL=$((FAIL + 1)); }

"$BIN" -c "$CFG" -cli >"$TMP/proxy.log" 2>&1 &
PID=$!

for _ in $(seq 1 200); do
  ip link show "$DEV" >/dev/null 2>&1 && break
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.1
done
if ip link show "$DEV" >/dev/null 2>&1; then
  ok "网卡 $DEV 已建立（$(ip -4 addr show dev "$DEV" | awk '/inet / {print $2; exit}')）"
else
  bad "网卡 $DEV 没有建立"
  tail -40 "$TMP/proxy.log" || true
  echo "B3 中断：$PASS 条 PASS，$FAIL 条 FAIL"
  exit 1
fi

if ip -4 addr show dev "$DEV" | grep -qF "$ADDR"; then
  ok "地址 $ADDR 已挂到 $DEV"
else
  bad "地址 $ADDR 不在 $DEV 上"
fi

HIJACK="$(iptables -t nat -S 2>/dev/null | grep -c 'wps_app_dns' || true)"
if [[ "$HIJACK" -gt 0 ]]; then
  ok "nat 表里有 $HIJACK 条 wps_app_dns 劫持规则"
else
  bad "nat 表里没有 wps_app_dns 规则"
fi

# 先刷一遍系统解析器缓存再问：这个域名在跑之前很可能刚被问过（比如操作者自己 getent 过），
# systemd-resolved 会把那次**真地址**的答案压着回给我们，于是劫持明明在工作，这一格却判失败。
# 2026-10-29 实测踩过：同一条命令刷完缓存立刻变 PASS，而 nat 表里 9 条劫持规则一直在。
resolvectl flush-caches >/dev/null 2>&1 || true
sleep 1
FAKE="$(getent ahostsv4 www.google.com 2>/dev/null | awk 'NR==1 {print $1}')"
if [[ "$FAKE" == 198.18.* ]]; then
  ok "www.google.com 解析成假 IP $FAKE"
else
  bad "www.google.com 没有解析成 198.18.x.x（读到 ${FAKE:-空}）"
fi

CODE="$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' https://www.gstatic.com/generate_204 2>"$TMP/curl.log" || true)"
if [[ "$CODE" == "204" ]]; then
  ok "不带 -x 的 curl 经 TUN 出网（generate_204 = 204）"
else
  bad "不带 -x 的 curl 没有拿到 204（实得 ${CODE:-空}；$(tail -1 "$TMP/curl.log" 2>/dev/null || true)）"
fi

URL="${WPS_ACCEPT_TUN_URL:-https://speed.cloudflare.com/__down?bytes=8388608}"
if curl -sS --max-time 120 -o "$TMP/download.bin" "$URL" 2>"$TMP/dl.log"; then
  SIZE="$(stat -c '%s' "$TMP/download.bin" 2>/dev/null || echo 0)"
  if [[ "$SIZE" -eq 8388608 ]]; then
    ok "8MB 下载经 TUN 成功（实收 $SIZE 字节）"
  else
    bad "下载字节数不对：$SIZE，期望 8388608"
  fi
else
  bad "8MB 下载失败（$(tail -1 "$TMP/dl.log" 2>/dev/null || true)）"
fi

kill -TERM "$PID"
for _ in $(seq 1 200); do
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.1
done
rc=0
wait "$PID" || rc=$?
PID=""
if [[ "$rc" -eq 0 ]]; then
  ok "实例已优雅退出（exit 0）"
else
  bad "实例退出码 $rc，期望 0"
fi

if ip link show "$DEV" >/dev/null 2>&1; then
  bad "退出后网卡 $DEV 仍在"
else
  ok "退出后网卡 $DEV 已消失"
fi

LEFT="$(iptables -t nat -S 2>/dev/null | grep -c 'wps_app_dns' || true)"
if [[ "$LEFT" -eq 0 ]]; then
  ok "退出后 wps_app_dns 劫持规则已清空"
else
  bad "退出后仍有 $LEFT 条 wps_app_dns 规则"
fi

REAL="$(getent ahostsv4 www.google.com 2>/dev/null | awk 'NR==1 {print $1}')"
if [[ -n "$REAL" && "$REAL" != 198.18.* ]]; then
  ok "DNS 已回到真实地址（$REAL）"
else
  bad "DNS 没有回到真实地址（读到 ${REAL:-空}）"
fi

echo
echo "B3 结果：$PASS 条 PASS，$FAIL 条 FAIL"
[[ "$FAIL" -eq 0 ]]
