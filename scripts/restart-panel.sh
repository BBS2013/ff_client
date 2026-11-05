#!/usr/bin/env bash
# 重启面板（普通用户身份）。
#
# 为什么要有这个脚本：面板必须以**普通用户**跑，不是 root。
#   - gui.go 是 HideWindowOnClose：点 X 只隐藏窗口。托盘不在 = 窗口藏了就再也
#     叫不回来，用户的观感就是"关了就没了"。
#   - root 进程的 systray 注册必然失败（会话总线按 EXTERNAL 认 uid，root 不是
#     属主），于是 root 只能靠 -tray-helper 起一个桌面用户身份的子进程来显示托盘。
#   - root 还带来一堆所有权问题：配置、账本、日志全变成 root:root。
#
# 需要 root 的活（建网卡、钉网卡）交给 tun.helper，见 README §4.3。
#
# 用法：
#   scripts/restart-panel.sh              # 重启面板
#   scripts/restart-panel.sh --no-rebuild # 不重建产物，只重启
#
# 之前这个脚本只存在于 dist/restart-panel.sh（被 .gitignore 忽略），
# 于是换一台机器、或者清一次 dist/ 就丢了，而它是这台机器上唯一正确的起法。
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/wps_app-gui"
CONFIG="${WPS_CONFIG:-$ROOT/config.yaml}"

if [ "$(id -u)" -eq 0 ]; then
  echo "不要用 root 跑面板：托盘会连不上会话总线，且配置/账本会变成 root:root。" >&2
  echo "需要 root 的操作由 tun.helper 负责（README §4.3）。" >&2
  exit 1
fi

rebuild=1
for a in "$@"; do
  case "$a" in
    --no-rebuild) rebuild=0 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "不认识的参数: $a" >&2; exit 2 ;;
  esac
done

# --- 停旧实例 ---------------------------------------------------------------
#
# 只发给**锁文件里记着的那个 pid**，不再用 `pkill -x wps_app-gui`：
#   - pkill -x 会杀掉所有同名进程，包括托盘助手（它跑在同一个用户名下、
#     名字也叫 wps_app-gui）与任何别的实例；
#   - SIGKILL 会跳过拆路由、摘 iptables、还原系统代理这三段收尾，
#     留下的正好是"整机 DNS 挂掉"与"桌面指着死端口"这两种最难查的状态。
#
# 等待上限与 systemd 的 TimeoutStopSec=40 对齐：停止要等 TUN 协议栈把连接
# 走完（实测最长 14 秒）再加上系统代理还原，20 秒是不够的。
LOCK="$CONFIG.lock"
pid=""
if [ -r "$LOCK" ]; then
  pid="$(tr -dc '0-9' <"$LOCK" | head -c 10 || true)"
fi

stop_pid() {
  local p="$1"
  [ -n "$p" ] || return 0
  kill -0 "$p" 2>/dev/null || return 0
  echo "停止面板 PID $p（SIGTERM，最多等 40 秒）…"
  kill -TERM "$p" 2>/dev/null || true
  for _ in $(seq 1 160); do
    kill -0 "$p" 2>/dev/null || return 0
    sleep 0.25
  done
  echo "面板没有在 40 秒内退出；它可能卡在 TUN 收尾上。" >&2
  echo "先看日志：$CONFIG.log 与 config.yaml.log.1（上一轮）。" >&2
  echo "仍然要强制结束的话，请自己确认它没有在用 TUN 之后再 kill -KILL $p。" >&2
  return 1
}

if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
  stop_pid "$pid" || exit 1
else
  echo "锁文件里没有活着的实例（$LOCK），直接启动。"
fi

# --- 重建产物 ---------------------------------------------------------------
#
# 单产物之后 ./wps_app-gui 同时是面板与 tun.helper 指着的文件，所以刷新它必须
# **先编到临时文件、再 mv**：同文件系统下 mv 是 rename，原子、没有"文件不存在"
# 的窗口。正在跑的进程继续持着旧 inode，不会被打断；而 rm 再 cp 那几十毫秒里
# 磁盘上根本没有这个文件，helper 每次是新起的进程、读的就是这个路径。
if [ "$rebuild" -eq 1 ]; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  echo "重建产物 → $tmpdir/wps_app-gui"
  WPS_GUI_OUT="$tmpdir/wps_app-gui" "$ROOT/scripts/build-gui.sh"
  mv -f "$tmpdir/wps_app-gui" "$BIN"
  echo "产物已替换（原子 rename）"
fi

[ -x "$BIN" ] || { echo "找不到可执行文件: $BIN" >&2; exit 1; }

# --- 拉起 -------------------------------------------------------------------
#
# 四个变量缺一个都不行：没有 DBUS_SESSION_BUS_ADDRESS 就没有托盘，
# 没有 XDG_RUNTIME_DIR 时 WebKit 会警告并退到 /tmp。
uid="$(id -u)"
export DISPLAY="${DISPLAY:-:0}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$uid}"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$uid/bus}"
if [ -z "${XAUTHORITY:-}" ] || [ ! -r "${XAUTHORITY:-}" ]; then
  for p in "/run/user/$uid/gdm/Xauthority" "$HOME/.Xauthority"; do
    if [ -r "$p" ]; then
      XAUTHORITY="$p"
      break
    fi
  done
fi
export XAUTHORITY="${XAUTHORITY:-}"

# stdout 交给 journald（有 journalctl 时）或 /dev/null，**不再追加到仓库根目录**。
# 以前那份 wps_app-gui.out 是 0644、无上限追加，里面全是逐条连接的访问日志
# （访问过哪些域名）。程序自己的日志走 <config>.log（0600、20MB × 3 轮转），
# 那一份才是排障要看的。
echo "以普通用户启动: $BIN $CONFIG"
if command -v systemd-cat >/dev/null 2>&1; then
  setsid systemd-cat -t wps_app "$BIN" "$CONFIG" >/dev/null 2>&1 &
else
  setsid "$BIN" "$CONFIG" >/dev/null 2>&1 &
fi
sleep 1

newpid="$(tr -dc '0-9' <"$LOCK" 2>/dev/null | head -c 10 || true)"
if [ -n "$newpid" ] && kill -0 "$newpid" 2>/dev/null; then
  echo "已启动，PID=$newpid"
  echo "日志: $CONFIG.log"
else
  echo "启动失败（锁文件里没有活着的 pid）。看 $CONFIG.log 或直接前台跑一次：" >&2
  echo "  $BIN $CONFIG -cli" >&2
  exit 1
fi
