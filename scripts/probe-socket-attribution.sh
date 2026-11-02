#!/usr/bin/env bash
# probe-socket-attribution.sh —— 「连接归到哪个进程」这件事的权限与兼容性探针。
#
# 为什么需要它而不是在 README 里写一段推断：这条能力要的不是"能不能想到实现"，
# 而是"在这台机器上到底给不给做"。三档实现（同 uid 的 /proc 反查、netlink INET_DIAG、
# eBPF）各自卡在完全不同的门槛上，而这些门槛是**机器的属性**：
# 换一台机器、换一个内核参数、装没装 EDR，结论就变。所以判据要能重跑。
#
# 全程只读：不装模块、不 attach 任何探针、不改任何内核参数、不对外发包。
# 输出是一份可以直接贴进报告的事实清单。需要 python3（与 make paint 同一个工具链依赖）。
set -euo pipefail

line() { printf '%s\n' "$*"; }

line "== 内核与 eBPF 前置条件 =="
line "kernel            $(uname -r)"
if [ -e /sys/kernel/btf/vmlinux ]; then
	line "BTF               在（$(stat -c %s /sys/kernel/btf/vmlinux) 字节）——CO-RE 可读类型信息这一步通"
else
	line "BTF               不在——带重定位的 eBPF 程序基本无从谈起"
fi
if [ -r /sys/kernel/security/lockdown ]; then
	line "lockdown          $(tr -d '\n' < /sys/kernel/security/lockdown)"
else
	line "lockdown          读不到（没挂 securityfs？未知就写未知）"
fi
for k in kernel/unprivileged_bpf_disabled kernel/perf_event_paranoid; do
	p="/proc/sys/$k"
	if [ -r "$p" ]; then
		line "$(printf '%-34s' "$k") $(cat "$p")"
	else
		line "$(printf '%-34s' "$k") 读不到"
	fi
done

line ""
line "== 本进程的能力集（决定 eBPF/INET_DIAG 要不要走 root）=="
if command -v capsh >/dev/null 2>&1; then
	line "CapEff 展开       $(capsh --print 2>/dev/null | sed -n '1p')"
fi
# 注意 `|| true` 与那个冒号：文件里的键是 "CapEff:\t..."，
# 少写冒号会让 grep 一无所获而退出码非零——在 set -e 下整份报告会静默断在这里，
# 表现成"探针跑过了但少了两节"，比报错更糟。
grep -E '^Cap(Eff|Prm):' /proc/self/status | sed 's/^/  /' || line "  capabilities 读不到"

line ""
line "== 第三方内核模块（EDR 一类，socket 层探针的同层竞争者）=="
if [ -r /proc/modules ]; then
	# `|| true` 是必需的：没命中时 grep 退出码非零，而这台机器上"没命中"是正常结果。
	# 少了它，set -e 会让整份报告在什么都没说的情况下断掉——静默断掉。
	hits=$(awk '{print $1}' /proc/modules | grep -Ei 'qax|tdsf|tianqing|360|edr|hook' | tr '\n' ' ' || true)
	if [ -n "${hits// /}" ]; then
		line "命中              $hits"
		line "	← 这些不是发行版自带模块。往 socket 层再挂东西之前，"
		line "	  得先在装着它们的机器上证明网络不受影响，而不是反过来。"
	else
		line "命中              无（只见发行版模块）"
	fi
	line "模块总数          $(wc -l < /proc/modules)"
fi

line ""
line "== 最低那一档：同 uid 的 socket 反查（无 root、无 eBPF）=="
# 正向：从 /proc/net/tcp 拿本 uid 的监听 inode；反向：在某个进程的 fd 里找它。
# 这一步是整份评估里唯一能当场证伪的命题：能不能把一条 socket 归回一个 pid。
python3 - <<'PY'
import glob, os, re, time

def listen_inodes(path):
    out = []
    try:
        lines = open(path).read().splitlines()[1:]
    except OSError:
        return out
    for f in (l.split() for l in lines):
        # 列：sl local rem st tx:rx tr:tm when retrnsmt uid timeout inode
        if len(f) < 10 or f[3] != '0A' or f[7] != str(os.getuid()):
            continue
        out.append((f[1], f[9]))
    return out

mine = listen_inodes('/proc/net/tcp') + listen_inodes('/proc/net/tcp6')
want = {ino for _, ino in mine}
print(f"  本 uid（{os.getuid()}）的 TCP 监听 {len(mine)} 条，待反查的 inode {len(want)} 个")

# 一趟扫完，建一张 inode -> (pid, fd) 的表。
# 每个 inode 各扫一遍也会得到同样的结论，但成本乘 N——
# 而这一步的**成本本身就是评估结论的一部分**（面板要每秒采样一次），所以只扫一趟并计时。
t0 = time.monotonic()
owner, scanned = {}, 0
for fd in glob.glob('/proc/[0-9]*/fd/*'):
    scanned += 1
    pid = fd.split('/')[2]
    try:
        link = os.readlink(fd)
    except OSError:
        # 进程刚好退出、或者不是我们的 uid：这一条看不见，不是错误。
        continue
    m = re.match(r'socket:\[(\d+)\]', link)
    if m and m.group(1) in want:
        owner.setdefault(m.group(1), (pid, fd.split('/')[-1]))
cost = time.monotonic() - t0

for local, ino in mine[:8]:
    host, port = local.split(':')
    pid, fdno = owner.get(ino, ('?', '?'))
    comm = ''
    if pid != '?':
        try:
            comm = ' ' + open(f'/proc/{pid}/comm').read().strip()
        except OSError:
            comm = ''
    print(f"    {host}:{int(port, 16)}  inode={ino:<9} → pid {pid}{comm} fd {fdno}")

print(f"  扫了 {scanned} 个 fd 条目，耗时 {cost * 1000:.0f} ms")
print("  读不到别的 uid 的 fd 是常态：这一档天生只覆盖桌面自己那批进程。")
PY

line ""
line "== 这份探针不下结论 =="
line "结论写在 README「进程归属」那一节。这里只回答一件事：这台机器给到哪一步。"
