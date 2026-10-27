#!/usr/bin/env bash
# 量「切到某一页那一下要多久」：六页 × 两种数据量，打印每页的中位数。
#
# 为什么要单独一个脚本，而不是"想起来手测一次"：
# 面板的流畅度以前只有**稳态**的数（§9.3：连接表每秒补帧、0 个 long task）。
# 稳态干净不等于切页不卡——2026-10-20 就是这样发现「最近结束」那张表
# 在 800 行时切进来要 118~202ms，而同一个页面稳态一帧都不掉。
# 挂载代价是一个**没人量过的维度**，而它一旦被人加回来（多画一张表、
# 把窗口调大、往行里塞一个 <select>）不会有任何测试变红。
# 所以把它做成一条能重跑的命令，而不是一段写在 README 里的往事。
#
# 判据为什么是"切下去 → 两次 requestAnimationFrame 之后"：
# Vue 的 DOM 更新在微任务里，一帧之内可能还没画上；两帧之后画完是
# 这一格量过的最贴近"人看见"的时刻。33ms 是这把尺子自己的底噪
# （60fps 下两帧），所以**低于 ~34ms 的数只能读成"没量到代价"**。
#
# 预算为什么给到 250ms 这么松：这不是规格，是**绊线**。
# 绝对毫秒数会随机器负载漂（同一台机器上跑着别人的 go test 就能顶高几倍），
# 断绝对值会得到"红一次就去改预算"的坏习惯。绊线的用途只有一个：
# 有人把某一页整表画出来、切进去要半秒的时候，让它响。
# 要量准代价就照 README §10.12 那张表的做法：同一台机器、同一份数据，
# 改动前后各跑一次比中位数。
#
# 用法：
#   scripts/panel-latency.sh            # 打印表格，超过预算则退出码 1
#   scripts/panel-latency.sh 400        # 换切页预算
#   TYPE_BUDGET=60 scripts/panel-latency.sh   # 换键入预算
set -euo pipefail

BUDGET="${1:-250}"
TYPE_BUDGET="${TYPE_BUDGET:-150}"
# 端口可以换（PORT=5198 跑一次就知道前置检查会不会拦住）：
# 这一条不是为了日常用，是为了让"检查本身"能被负对照。
PORT="${PORT:-5199}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/frontend/dist"

die() { printf '量不了：%s\n' "$1" >&2; exit 2; }

# ---- 前置检查：缺任何一条就退出，不许量出一份看起来正常的假数 ----
command -v agent-browser >/dev/null 2>&1 || die "本机没有 agent-browser（这个脚本靠它驱动页面）"
[ -f "$DIST/index.html" ] || die "没有 $DIST/index.html：先 make frontend"

# 探本机端口必须绕开代理，否则 7892 那个 HTTP 代理会把请求截走，
# 得到一个"服务器没起"的假结论（本机踩过多次）。
page_html() { curl -s --noproxy '*' --max-time 5 "http://127.0.0.1:$PORT/index.html" || true; }
html="$(page_html)"
[ -n "$html" ] || die "http://127.0.0.1:$PORT 没应答：在 frontend/dist 里起一个 python3 -m http.server $PORT"

# 伺服的那份必须就是磁盘上这份。不查这一条的话，服务器可能正拿着
# 一个旧构建（甚至旧目录），量出来的数与刚改的代码无关。
served="$(printf '%s' "$html" | grep -oE 'index-[A-Za-z0-9_-]+\.js' | head -1)"
disk="$(cd "$DIST/assets" && ls index-*.js | head -1)"
[ -n "$served" ] && [ "$served" = "$disk" ] \
  || die "伺服的是 $served、磁盘上是 $disk：对不上就别量（先 make frontend，必要时重启那个 http.server）"

# ---- 量 ----
# 一次 eval 里做三轮"切到某一页 → 回总览"，返回三个数。
# 三轮而不是三轮取平均：中位数才抗得住旁边有个 GC 的干扰。
JS_SAMPLE='async (page) => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const raf2 = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  const nav = (t) => [...document.querySelectorAll("button")].find((b) => b.textContent.trim().startsWith(t));
  if (!nav(page) || !nav("总览")) return null;
  const out = [];
  for (let k = 0; k < 3; k++) {
    nav("总览").click(); await wait(450); await raf2();
    const t0 = performance.now();
    nav(page).click(); await raf2();
    out.push(+(performance.now() - t0).toFixed(1));
    await wait(450);
  }
  return out;
}'

PAGES=(节点 规则 流量 日志 设置 总览)
SCENARIOS=("" big)

printf '页面      默认数据   ?demo=big\n'
worst=0
worst_page=''
for page in "${PAGES[@]}"; do
  row=()
  for sc in "${SCENARIOS[@]}"; do
    url="http://127.0.0.1:$PORT/index.html?demo=$sc&view=overview&cb=$RANDOM"
    agent-browser open "$url" >/dev/null 2>&1 || die "agent-browser 打不开 $url"
    sleep 1.2
    arg="$(printf '%s' "$page" | sed 's/.*/"&"/')"
    raw="$(agent-browser eval "(async () => { const f = $JS_SAMPLE; return JSON.stringify(await f($arg)); })()" 2>/dev/null | tail -1)"
    med="$(printf '%s' "$raw" | node -e '
      let s = "";
      process.stdin.on("data", (d) => (s += d)).on("end", () => {
        try {
          const a = JSON.parse(JSON.parse(s));
          if (!Array.isArray(a) || !a.length) { console.log("n/a"); return; }
          a.sort((x, y) => x - y);
          console.log(a[Math.floor(a.length / 2)].toFixed(1));
        } catch { console.log("n/a"); }
      });')"
    row+=("$med")
    if [ "$med" != "n/a" ]; then
      worse="$(node -e "console.log(Math.max($med, $worst))")"
      if [ "$worse" != "$worst" ]; then worst="$worse"; worst_page="$page($sc)"; fi
    fi
  done
  printf '%-8s  %8s  %8s\n' "$page" "${row[0]}" "${row[1]}"
done

# 全 n/a 也是一种"没量到"：必须报红，不能打印一张空表就退 0。
if [ "$worst" = "0" ]; then
  die "六页一个数都没拿到（多半是页面结构变了、nav 找不到按钮）——别把这张空表当成通过"
fi

printf '\n最差：%s = %sms，预算 %sms\n' "$worst_page" "$worst" "$BUDGET"
awk -v a="$worst" -v b="$BUDGET" 'BEGIN { exit (a > b ? 1 : 0) }' \
  || { printf '红：有一页切进去超过预算。\n' >&2; exit 1; }

# ---- 键入延迟 ----
# 切页量的是"挂载那一下"，这一档量的是**打字那一下**：改一次筛选关键字，
# 到 DOM 画完为止。它比切页更贴近"人手上的感觉"，而它从来没人量过——
# 一个页面可以挂载 33ms 很干净、每敲一个字却要 200ms（过滤器每敲一次重算整表 + 重画窗口）。
#
# 判据与上面那张表**不是一把尺子**：这里不等 rAF，只等 Vue 的调度器与
# MutationObserver 回调（都是微任务），所以底噪接近 0ms 而不是 33ms。
# 两张表的数字不能横着比。
#
# 每一轮取"打进去"与"清空"两个动作里更慢的那个：清空往往更贵（要把整个窗口重画出来），
# 而打字贵在重算。只量一边会漏。
# 三个"必须红"的判据：观察不到 DOM 变化（这一笔压根没量到）、
# 关键字没筛掉任何行（量的不是筛选那条路）、两轮都拿不到数（结构变了）。
JS_TYPE='async (label) => {
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));
  const inp = document.querySelector('"'"'input[aria-label="'"'"' + label + '"'"'"]'"'"');
  if (!inp) return { err: "找不到筛选框" };
  const scope = inp.closest("section") || document.body;
  const rowTexts = () => [...scope.querySelectorAll("tbody tr")].map((tr) => tr.innerText);
  const setVal = (v) => {
    const d = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value");
    d.set.call(inp, v);
    inp.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const sample = async (v) => {
    let hit = false;
    const obs = new MutationObserver(() => { hit = true; });
    obs.observe(scope, { childList: true, subtree: true, characterData: true });
    const t0 = performance.now();
    setVal(v);
    await new Promise((r) => setTimeout(r, 0));
    const dt = performance.now() - t0;
    obs.disconnect();
    return { dt: +dt.toFixed(1), hit };
  };
  const base = () => rowTexts().join("||");
  const cands = (texts) => {
    // 从表里前几行抓一批"像域名 / 主机名 / 协议名"的 token 当候选关键字。
    // 不猜哪个是筛选框真的搜的列——下面会**逐个试**，取第一个真让表变了的。
    const out = [];
    for (const t of texts.slice(0, 8)) {
      for (const m of t.matchAll(/[A-Za-z0-9][A-Za-z0-9._-]{2,}/g)) {
        if (!out.includes(m[0])) out.push(m[0]);
      }
    }
    return out;
  };
  const out = [];
  for (let k = 0; k < 3; k++) {
    setVal(""); await wait(260);
    const texts = rowTexts();
    if (texts.length < 3) return { err: "表里不足 3 行（" + texts.length + "）" };
    const b0 = base();
    const list = cands(texts);
    let best = null;
    for (const kw of list) {
      const a = await sample(kw);
      const changed = base() !== b0;
      const b = await sample("");
      if (a.hit && changed) {
        best = Math.max(a.dt, b.dt);
        break;
      }
    }
    // "关键字没让表变"这一档必须报红而不是给个数：
    // 第一版就是栽在这里——它从行内抓 token，抓到的常常是"每一行都有"的那一个
    // （监听地址 127.0.0.1、匹配方式 DOMAIN-SUFFIX），或者抓到**筛选框根本不搜的那一列**。
    // 那种情况下量到的只是"改一次输入框"的代价，跟重算整表一点关系都没有。
    if (best === null) return { err: "试了 " + list.length + " 个关键字，表都没变（筛选搜的是哪一列？）" };
    out.push(best);
  }
  return out;
}'

TYPERS=("规则:自定义规则过滤" "流量:连接过滤")
printf '\n键入延迟（改一次筛选 → DOM 画完，取"打进去/清空"里更慢的那个）\n'
printf '页面      默认数据   ?demo=big\n'
tworst=0
tworst_page=''
for spec in "${TYPERS[@]}"; do
  page="${spec%%:*}"
  label="${spec#*:}"
  view=rules
  [ "$page" = "流量" ] && view=traffic
  row=()
  for sc in "${SCENARIOS[@]}"; do
    url="http://127.0.0.1:$PORT/index.html?demo=$sc&view=$view&cb=$RANDOM"
    agent-browser open "$url" >/dev/null 2>&1 || die "agent-browser 打不开 $url"
    sleep 1.2
    arg="$(printf '%s' "$label" | sed 's/.*/"&"/')"
    raw="$(agent-browser eval "(async () => { const f = $JS_TYPE; return JSON.stringify(await f($arg)); })()" 2>/dev/null | tail -1)"
    med="$(printf '%s' "$raw" | node -e '
      let s = "";
      process.stdin.on("data", (d) => (s += d)).on("end", () => {
        try {
          const a = JSON.parse(JSON.parse(s));
          if (Array.isArray(a) && a.length) {
            a.sort((x, y) => x - y);
            console.log(a[Math.floor(a.length / 2)].toFixed(1));
            return;
          }
          // 量不到必须把原因带出来：一张全是 n/a 的表与"没跑"只隔一行字。
          console.log("n/a:" + (a && a.err ? a.err : "没拿到数"));
        } catch { console.log("n/a:eval 没回东西"); }
      });')"
    row+=("$med")
    num="${med%%:*}"
    if [ "$num" != "n/a" ]; then
      worse="$(node -e "console.log(Math.max($num, $tworst))")"
      if [ "$worse" != "$tworst" ]; then tworst="$worse"; tworst_page="$page($sc)"; fi
    else
      printf '  · %s %s → %s\n' "$page" "${sc:-默认}" "$med" >&2
    fi
  done
  printf '%-8s  %8s  %8s\n' "$page" "${row[0]%%:*}" "${row[1]%%:*}"
done

if [ "$tworst" = "0" ]; then
  die "键入延迟一个数都没拿到（筛选框改名了？关键字没筛掉任何行？观察不到 DOM 变化？）——别把这张空表当成通过"
fi

printf '\n键入最差：%s = %sms，预算 %sms\n' "$tworst_page" "$tworst" "$TYPE_BUDGET"
awk -v a="$tworst" -v b="$TYPE_BUDGET" 'BEGIN { exit (a > b ? 1 : 0) }' \
  || { printf '红：改一次筛选超过预算。\n' >&2; exit 1; }
