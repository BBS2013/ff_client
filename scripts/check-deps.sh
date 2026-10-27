#!/usr/bin/env bash
# 给「拿到包的人」用的体检脚本。只读，不改系统、不装东西——缺什么它告诉你命令，
# 装不装由你决定。
#
# 用法: ./check-deps.sh          # 检查当前目录这套产物能不能跑
#       ./check-deps.sh --gui    # 额外检查图形面板需要的系统库

set -uo pipefail

want_gui=0
[[ "${1:-}" == "--gui" ]] && want_gui=1

pass=0
warn=0
bad=0

ok()   { printf '  [ok]   %s\n' "$1"; pass=$((pass + 1)); }
note() { printf '  [注意] %s\n' "$1"; warn=$((warn + 1)); }
no()   { printf '  [缺少] %s\n' "$1"; bad=$((bad + 1)); }

echo "== 机器与产物 =="
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)  ok "Linux x86_64，与预编译产物匹配" ;;
  Linux/aarch64) note "这是 aarch64，包里的预编译产物是 x86_64 的，用源码包自己 make build" ;;
  *)             no  "只支持 Linux（当前 $(uname -s)/$(uname -m)）" ;;
esac

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for b in wps_app wps_app-gui; do
  if [[ -x "$here/$b" ]]; then
    # 静态与否决定「能不能扔到别的机器直接跑」，用 file 判最稳（不依赖 ldd 的行为差异）
    if file "$here/$b" | grep -q "statically linked"; then
      ok "$b 是静态二进制，不依赖系统库"
    else
      ok "$b 存在（动态链接，见下面的系统库检查）"
    fi
  else
    note "没找到 $b（只有另一个产物也够用）"
  fi
done

if [[ $want_gui -eq 1 || -x "$here/wps_app-gui" ]]; then
  echo "== 图形面板需要的系统库 =="
  # WebKitGTK 不支持静态链接，而且它要从库目录里拉起 WebKitNetworkProcess /
  # WebKitWebProcess 两个子进程，所以这几样只能装在系统里。
  #
  # 判据用 ldd 直接问产物，不用 `ldconfig -p` 去猜：ldconfig 在 /usr/sbin，
  # 普通用户的 PATH 里没有它，用它检查会在装好了 GTK 的机器上报"全都缺"。
  if [[ ! -x "$here/wps_app-gui" ]]; then
    note "没有 wps_app-gui 产物可检查（用 --gui 时需要它）"
  elif ! command -v ldd >/dev/null 2>&1; then
    note "本机没有 ldd，无法核对图形面板的动态依赖"
  else
    missing="$(ldd "$here/wps_app-gui" 2>/dev/null | awk '/not found/{print $1}')"
    if [[ -z "$missing" ]]; then
      ok "GTK3 / WebKit2GTK 依赖齐全，面板能起"
    else
      no "缺：$(echo "$missing" | tr '\n' ' ')"
      echo "         Ubuntu/Debian: sudo apt install libgtk-3-0 libwebkit2gtk-4.0-37 libepoxy0"
      echo "         Fedora:        sudo dnf install gtk3 webkit2gtk4 libepoxy"
      echo "         装不上就用命令行的 wps_app（静态、零依赖），功能只差一个图形界面。"
    fi
  fi
fi

echo "== 命令行模式需要 / 可选的 =="
if [[ -w /dev/net/tun ]]; then
  ok "/dev/net/tun 可写，具备开 TUN 的条件"
elif [[ -e /dev/net/tun ]]; then
  note "/dev/net/tun 存在但当前用户不可写：TUN 需要 sudo 跑，或按 README §4.3 配 tun.helper"
else
  note "没有 /dev/net/tun：TUN 模式不可用。SOCKS5/HTTP 代理不受影响。"
fi

for c in ip iptables; do
  if command -v $c >/dev/null 2>&1; then
    ok "$c 可用（TUN 要靠它配地址、路由与劫持）"
  else
    no "$c 不存在，TUN 起不来（Debian/Ubuntu 装 iproute2 iptables）"
  fi
done

if sudo -n true 2>/dev/null; then
  ok "免密 sudo 可用，可以直接跑面板或用 tun.helper"
else
  note "免密 sudo 不可用：想用 TUN 就 sudo ./wps_app config.yaml，或者只用系统代理模式"
fi

echo "== 端口占用 =="
for p in 7891 7892; do
  if ss -tln 2>/dev/null | grep -q "127.0.0.1:$p "; then
    note "127.0.0.1:$p 已被占用——多半是已经有一个 wps_app 在跑（pgrep -x wps_app 看得到）"
  else
    ok "127.0.0.1:$p 空闲"
  fi
done

echo "== 托盘（只有桌面环境相关，缺了不影响代理） =="
if command -v busctl >/dev/null 2>&1 && busctl --user list 2>/dev/null | grep -q StatusNotifierWatcher; then
  ok "桌面有托盘宿主，面板右上角会有图标"
else
  note "没检测到托盘宿主（无桌面或 GNOME 没装 AppIndicator 扩展）。"
  note "  若用 root 跑面板，托盘一定注册不上——那是会话总线的权限，改用普通用户 + tun.helper。"
fi

echo
echo "小结：$pass 项正常，$warn 项需要注意，$bad 项缺失。"
((bad == 0)) || exit 1
exit 0
