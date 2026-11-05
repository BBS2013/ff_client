#!/usr/bin/env bash
# 【不推荐】以 root 启动整个面板。
#
# 这个模式仍然可用（它在本机跑过一个阶段），但**不是默认做法**，代价很实：
#
#   - root 进程连不上用户会话总线，托盘必须靠一个额外的托盘助手子进程（
#     gui.go 里的 RunTrayBridge）才能显示。那条桥是额外的一条攻击面。
#   - 配置、账本、日志全变成 root:root：普通用户既读不到也改不了，
#     下一次以普通用户启动时会因为读不到记账而无法还原桌面代理。
#   - 面板里的 WebKit 渲染进程同样是 root。前端只要有一处注入（模板、样式、
#     一个被篡改的内嵌页面），拿到的就是 root 而不是用户权限。
#   - HOME 被设成仓库目录时，WebKit 还会把缓存写进检出目录（.cache/、.local/）。
#
# 正确做法是 scripts/restart-panel.sh：面板以普通用户跑，需要 root 的活
# （建网卡、钉网卡）交给装在 root 拥有的路径下的 tun.helper（make install-helper）。
#
# 只有一种场合还需要它：机器上只有 root 会话、确实起不来普通用户面板。
# 即使那样，也请用 `sudo -u <用户>` 起托盘助手，别让前端也在 root 里跑。
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/wps_app-gui"
CONFIG="$SCRIPT_DIR/config.yaml"

echo "警告：这是 root 面板模式，不是推荐做法。" >&2
echo "      普通用户面板请用 scripts/restart-panel.sh（见本脚本头注释）。" >&2

if [ ! -x "$BIN" ]; then
  echo "找不到可执行文件: $BIN" >&2
  exit 1
fi
if [ ! -f "$CONFIG" ]; then
  echo "找不到配置文件: $CONFIG" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  if ! sudo -n true 2>/dev/null; then
    echo "需要 root 权限，但 sudo 不免密。请在终端执行: sudo $0" >&2
    exit 1
  fi
  exec sudo -n -- "$0" "$@"
fi

# 桌面用户：优先 sudo 留下的 SUDO_USER；从 root shell 直接跑时，用脚本上一级目录的属主。
DESKTOP_USER="${SUDO_USER:-}"
DESKTOP_HOME="$(dirname -- "$SCRIPT_DIR")"
if [ -z "$DESKTOP_USER" ] || [ "$DESKTOP_USER" = "root" ]; then
  DESKTOP_USER="$(stat -c '%U' "$DESKTOP_HOME" 2>/dev/null || true)"
fi
if [ -z "$DESKTOP_USER" ] || [ "$DESKTOP_USER" = "root" ]; then
  echo "判断不出桌面用户；请从桌面用户会话里用 sudo 运行。" >&2
  exit 1
fi
DESKTOP_UID="$(id -u "$DESKTOP_USER")"

export HOME="$DESKTOP_HOME"
export DISPLAY="${DISPLAY:-:0}"
export XDG_RUNTIME_DIR="/run/user/$DESKTOP_UID"
export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$DESKTOP_UID/bus"
export SUDO_USER="$DESKTOP_USER"

if [ -z "${XAUTHORITY:-}" ] || [ ! -r "${XAUTHORITY:-}" ]; then
  for p in "/run/user/$DESKTOP_UID/gdm/Xauthority" "$DESKTOP_HOME/.Xauthority"; do
    if [ -r "$p" ]; then
      XAUTHORITY="$p"
      break
    fi
  done
fi
export XAUTHORITY

# 停旧实例：只发给锁文件里那个 pid，不用 pkill -x。
#
# `pkill -x wps_app-gui` 以 root 跑会杀掉所有用户的同名进程（托盘助手也是这个名字），
# 而 `-KILL` 会跳过拆路由、摘 iptables、还原系统代理这三段收尾——留下的正是
# "整机 DNS 挂掉"与"桌面指着死端口"这两种最难查的状态。
LOCK="$CONFIG.lock"
OLD_PID="$(tr -dc '0-9' <"$LOCK" 2>/dev/null | head -c 10 || true)"
if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
  echo "停止已有面板 PID $OLD_PID（SIGTERM，最多等 40 秒）…"
  kill -TERM "$OLD_PID" 2>/dev/null || true
  for _ in $(seq 1 160); do
    kill -0 "$OLD_PID" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$OLD_PID" 2>/dev/null; then
    echo "旧实例没有在 40 秒内退出。它可能卡在 TUN 收尾上，先看 $CONFIG.log。" >&2
    echo "确认它没在用 TUN 之后再 kill -KILL $OLD_PID。" >&2
    exit 1
  fi
fi

# stdout 不再追加到仓库根目录。
# 以前那份 wps_app-gui.out 是 0644、无上限追加，内容是逐条连接的访问日志。
# 程序自己的日志走 <config>.log（0600、20MB × 3 轮转）。
echo "以 root 启动: $BIN $CONFIG"
setsid "$BIN" "$CONFIG" >/dev/null 2>&1 < /dev/null &
sleep 1

APP_PID="$(tr -dc '0-9' <"$LOCK" 2>/dev/null | head -c 10 || true)"
if [ -n "$APP_PID" ] && kill -0 "$APP_PID" 2>/dev/null; then
  echo "已启动，PID=$APP_PID"
  echo "日志: $CONFIG.log"
else
  echo "启动失败，看 $CONFIG.log" >&2
  exit 1
fi
