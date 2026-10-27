#!/usr/bin/env python3
"""在**面板真正用的渲染引擎**里量帧时代价。

为什么要有这个脚本
------------------
仓库里已有一条 `make latency`，它量切页与键入的挂载代价，跑在
agent-browser（Chromium，GPU 加速）里。数字一直很干净：默认数据下六页
全是 33ms 底噪，稳态零个 long task。

但面板不是跑在 Chromium 里。gui.go 明确把 Wails 的 WebviewGpuPolicy 设成
`Never`（那里写了原因：OnDemand 在部分驱动上直接白屏），于是真面板是
**WebKitGTK + 软件光栅**。同一页在两处量出来的东西不一样：

    流量页（demo=big，滚动帧时中位）
      Chromium（GPU 加速）      16.7ms
      WebKitGTK + NEVER        37~47ms
    规则页（demo=normal，滚动帧时中位）
      Chromium（GPU 加速）      16.7ms
      WebKitGTK + NEVER        82~123ms

也就是说：**"稳态干净"这一格此前量的是加速渲染下的干净**，
软件光栅下同一份界面并不干净。这个脚本换到同一个引擎里量。

它只加载 `frontend/dist` + `?demo=`（纯前端演示桥），
不碰后端、不碰 config.yaml、不碰桌面系统代理。

前置
----
  make frontend                        产物要与磁盘一致
  frontend/dist 上起静态伺服           python3 -m http.server 5199
  python3-gi + gir1.2-webkit2-4.0      本机装的是 WebKitGTK 2.50
  xvfb-run                             不想在真桌面上弹窗时用它

用法
----
  scripts/panel-paint.py                        # 六页，外层滚动容器
  scripts/panel-paint.py --inner                # 内层滚动容器（日志那块）
  scripts/panel-paint.py --css oldLook          # 盖回"改之前"那版样式做 A/B
  scripts/panel-paint.py --demo big --scale 2   # 压力档 / HiDPI 倍率
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time

# A/B 用的样式覆盖：每一项只动一件事，量的是"这一项值多少毫秒"。
OVERRIDES = {
    # 改回"改之前"那一版：卡片带环境影 + 内容区径向天光。
    "oldLook": (
        ".card{box-shadow:var(--hairline-top),var(--elev-2)!important;"
        "border-top-color:var(--line)!important;border-bottom-color:var(--line)!important}"
        ".content{background:radial-gradient(120% 60% at 50% -10%,rgba(59,130,246,0.055),"
        "transparent 62%),var(--bg)!important}"
    ),
    "noshadow": "*{box-shadow:none!important}",
    "contentshadow": ".content *{box-shadow:none!important}",
    "cardShadow": ".card{box-shadow:var(--hairline-top),var(--elev-2)!important}",
    "nobackdrop": ".rail,.topbar{-webkit-backdrop-filter:none!important;backdrop-filter:none!important}",
    "notrans": "*{transition:none!important;animation:none!important}",
    "btnNoShadow": ".btn{box-shadow:none!important}",
    "flatBg": ".content{background:var(--bg)!important}.card{background:var(--surface)!important}",
    "contentFlat": ".content{background:var(--bg)!important}",
    # 让视口外的卡片不参与绘制（WebKit 18+ 支持 content-visibility）
    "contentVis": ".card{content-visibility:auto!important;contain-intrinsic-size:auto 400px!important}",
    "noLogShadow": ".logbox{box-shadow:none!important}",
    "noLogRadius": ".logbox{border-radius:0!important}",
    "noLogBoth": ".logbox{box-shadow:none!important;border-radius:0!important}",
    "noLogLineBg": ".logline{background:transparent!important}",
    # 诊断用：把文字变透明（盒子照画）/ 把整页藏起来（什么都不画），
    # 两者一比就知道剩下的首帧代价是在"画字"还是在"画盒子"。
    "noText": ".content,.content *{color:transparent!important}",
    "noPaint": ".content *{visibility:hidden!important}",
    "contentVisAll": (".card,.g2>*,section.card{content-visibility:auto!important;"
                       "contain-intrinsic-size:auto 400px!important}"),
    # 天光缩成顶部一条带：渐变只在这条带里按像素算，别的都是平色
    "glowBand": (".content{background:radial-gradient(120% 60% at 50% -10%,rgba(59,130,246,0.055),"
                 "transparent 62%) no-repeat 0 0/100% 320px,var(--bg)!important}"),
    "glowBandLinear": (".content{background:linear-gradient(180deg,rgba(59,130,246,0.075),"
                       "rgba(0,0,0,0) 100%) no-repeat 0 0/100% 320px,var(--bg)!important}"),
    "cardFlat": ".card{background:var(--surface)!important}",
    "hideViewAnim": ".view{animation:none!important}",
}

JS = r"""
(async () => {
  const CFG = __CFG__;
  const raf = (n, step, el) => new Promise((res) => {
    const ts = []; let last = performance.now(); let i = 0;
    const tick = (t) => {
      ts.push(t - last); last = t;
      if (step) el.scrollTop += step;
      if (++i >= n) { res(ts); return; }
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  const stat = (a) => {
    const s = [...a].sort((x, y) => x - y);
    const q = (p) => +(s[Math.min(s.length - 1, Math.floor(s.length * p))] || 0).toFixed(1);
    return { n: s.length, med: q(0.5), p95: q(0.95), max: +s[s.length - 1].toFixed(1),
             over33: a.filter((x) => x > 33).length, over80: a.filter((x) => x > 80).length };
  };
  const settle = async () => {
    // 有些页自己每 5 秒拉一次数据（规则页就是）。不等它落定就开测，
    // 量到的是"表在半路被整张换掉"的代价，不是滚动的代价——
    // 第一版探针就在这里把只有 8 行的一页量成了 73ms。
    let prev = -1;
    for (let i = 0; i < 40; i++) {
      const now = document.querySelectorAll("*").length + document.querySelectorAll("tbody tr").length;
      if (now === prev) return now;
      prev = now;
      await new Promise((r) => setTimeout(r, 700));
    }
    return prev;
  };
  const done = (o) => { window.__P_RESULT = JSON.stringify(o); document.title = "PROBE"; };
  const nav = (t) => [...document.querySelectorAll(".rail button")].find((b) => b.textContent.trim().startsWith(t));
  const raf2 = () => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  const out = { dpr: window.devicePixelRatio, nodes: document.querySelectorAll("*").length,
                rows: document.querySelectorAll("tbody tr").length };
  if (CFG.resize) {
    // 整窗重画那一下：窗宽一变，WebKit 要把整个视口重新画一遍（用户那边的说法是
    // "拖动/恢复后发白重绘"）。这里连续记帧间隔，中途由 Python 改一次窗宽，
    // 那一帧的间隔就是整窗重画的代价。
    const ts = [];
    let last = performance.now();
    await new Promise((res) => {
      const tick = (t) => {
        ts.push(+(t - last).toFixed(1));
        last = t;
        // rAF 给的时间戳是"这一帧开始的时刻"，比 performance.now() 早，
        // 所以不能拿它跟 now 比大小（第一版就是这么把循环写退的）。
        if (ts.length < 300) requestAnimationFrame(tick); else res();
      };
      requestAnimationFrame(tick);
    });
    const sorted = [...ts].sort((a, b) => a - b);
    out.frames = ts.length;
    out.med = sorted[Math.floor(sorted.length / 2)];
    out.max = sorted[sorted.length - 1];
    out.top5 = sorted.slice(-5).reverse();
    done(out);
    return;
  }
  if (CFG.idle) {
    // 稳态：面板每秒轮询一次，那一轮要重画表。这里数 6 秒里的帧与 long task，
    // 看"每秒那次更新"是不是把界面按住了（用户那边的话是"数字不实时更新"）。
    const lt = [];
    new PerformanceObserver((l) => { for (const e of l.getEntries()) lt.push(+e.duration.toFixed(1)); })
      .observe({ entryTypes: ["longtask"] });
    let frames = 0; const t0 = performance.now();
    const count = (t) => { frames++; if (t - t0 < 6000) requestAnimationFrame(count); };
    requestAnimationFrame(count);
    await new Promise((r) => setTimeout(r, 6300));
    out.seconds = +((performance.now() - t0) / 1000).toFixed(1);
    out.frames = frames;
    out.longTasks = lt;
    done(out);
    return;
  }
  if (CFG.switch) {
    // 切页那一下：点侧栏 → 两帧之后 DOM 画完（和 scripts/panel-latency.sh 同一把尺子，
    // 只是换到面板真正的引擎上量）。
    // 拆两段：DOM 改完（Vue 干活完）到画出来（两帧之后）。
    // 两段混在一起量，看不出"是 Vue 慢"还是"是画得慢"。
    out.switch = {};
    // 同一页量两次：第一次是"字形冷缓存"（要现栅格化这一页所有的字），
    // 第二次是热的。用户天天来回切，真实体感更接近第二次，
    // 所以两次数都留着，别拿第一次去代表日常。
    for (const p of ["节点", "规则", "流量", "日志", "设置", "总览"]) {
      const hits = [];
      for (let k = 0; k < 2; k++) {
        nav("总览").click(); await raf2(); await new Promise((r) => setTimeout(r, 250));
        const t0 = performance.now();
        let tDom = 0;
        const obs = new MutationObserver(() => { if (!tDom) tDom = performance.now(); });
        obs.observe(document.querySelector(".content"), { childList: true, subtree: true, characterData: true });
        nav(p).click();
        await new Promise((r) => setTimeout(r, 0));
        if (!tDom) tDom = performance.now();
        // 强制一次同步布局，把"样式+布局"从"绘制"里分出来：
        // offsetHeight 读一次就把挂起的样式计算与布局跑完（同步）。
        const tLayout0 = performance.now();
        void document.querySelector(".content").offsetHeight;
        const tLayout = performance.now() - tLayout0;
        await raf2();
        const t1 = performance.now();
        obs.disconnect();
        hits.push([+(tDom - t0).toFixed(1), +tLayout.toFixed(1), +(t1 - t0).toFixed(1)]);
      }
      out.switch[p] = hits;
    }
    done(out);
    return;
  }
  let sc = null;
  if (CFG.inner) {
    sc = [...document.querySelectorAll(".content *")].filter((el) => {
      const cs = getComputedStyle(el);
      return /(auto|scroll)/.test(cs.overflowY) && el.scrollHeight > el.clientHeight + 40;
    }).sort((a, b) => b.scrollHeight - a.scrollHeight)[0] || null;
    if (!sc) { out.err = "这一页没有内层滚动容器"; done(out); return; }
    out.inner = sc.className.toString().slice(0, 30);
  } else {
    sc = document.querySelector(".content");
  }
  out.area = sc ? [sc.scrollHeight, sc.clientHeight] : null;
  await settle();
  sc.scrollTop = 0;
  await new Promise((r) => setTimeout(r, 400));
  out.warm = stat(await raf(30, 40, sc)).med;
  sc.scrollTop = 0;
  await new Promise((r) => setTimeout(r, 250));
  out.rowsBefore = document.querySelectorAll("tbody tr").length;
  out.scroll = stat(await raf(80, 40, sc));
  out.rowsAfter = document.querySelectorAll("tbody tr").length;
  done(out);
})()
"""


JS_PAYLOAD = r"""
(async () => {
  // 面板每秒从后端拿一次读数，Wails 把它当**字符串**送进页面（window.wails.Callback("…")），
  // 页面再 JSON.parse。这里量的是这一步在面板真正的引擎里要花多久。
  const N = __N__;
  const row = { id: 1, start: 1750000000000, duration: 1200, inbound: "http",
                client: "127.0.0.1:54321", host: "www.example.com", port: "443",
                target: "www.example.com:443", policy: "PROXY", matched: "FINAL",
                outbound: "proxy", node: "hysteria-main", iface: "",
                err: "", up: 123456, down: 987654 };
  const rows = [];
  let bytes = 0;
  while (bytes < N) {
    rows.push(Object.assign({}, row, { id: rows.length + 1 }));
    bytes += JSON.stringify(row).length;
  }
  const s = JSON.stringify({ active: rows, history: rows, series: [] });
  const t0 = performance.now();
  JSON.parse(s);
  const parse = performance.now() - t0;
  const t1 = performance.now();
  new Function("return " + s)();
  const evalsrc = performance.now() - t1;
  window.__P_RESULT = JSON.stringify({ bytes: s.length, rows: rows.length,
                                       parse: +parse.toFixed(2), evalsrc: +evalsrc.toFixed(2) });
  document.title = "PROBE";
})()
"""


def worker(url, scale, inner, css, payload_bytes, switch_pages, gpu="never", offscreen=False,
           idle=False, resize=False):
    """在当前 DISPLAY（通常是 xvfb-run 给的）里开一个 WebKitGTK 窗，量完打一行 JSON。"""
    # GDK_SCALE 必须在 GTK 初始化之前定下来，否则量到的还是 1 倍像素。
    os.environ["GDK_SCALE"] = str(scale)
    os.environ["GDK_DPI_SCALE"] = "1"
    os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")

    import gi

    gi.require_version("Gtk", "3.0")
    gi.require_version("WebKit2", "4.0")
    from gi.repository import GLib, Gtk, WebKit2

    win = Gtk.Window()
    win.set_default_size(1080, 720)
    # --offscreen：把窗放到可见区外面，照样会被画（X11 照常出帧），
    # 但不会在用户的桌面上弹出来抢注意力。
    win.move(3000, 0 if offscreen else 0)
    cfg = WebKit2.Settings.new()
    # 默认与 gui.go 里的 WebviewGpuPolicy: Never 保持一致
    policy = {"never": WebKit2.HardwareAccelerationPolicy.NEVER,
              "always": WebKit2.HardwareAccelerationPolicy.ALWAYS,
              "ondemand": WebKit2.HardwareAccelerationPolicy.ON_DEMAND}[gpu]
    cfg.set_property("hardware-acceleration-policy", policy)
    # 打到 stderr：stdout 那行是结果 JSON，不能掺别的。
    print("[worker] policy=%s requested=%s" % (cfg.get_property("hardware-acceleration-policy"), gpu),
          file=sys.stderr)
    view = WebKit2.WebView.new_with_settings(cfg)
    win.add(view)
    win.show_all()

    state = {"loaded": False, "deadline": time.time() + 240}
    view.connect(
        "load-changed",
        lambda w, ev: state.__setitem__("loaded", ev == WebKit2.LoadEvent.FINISHED),
    )
    view.load_uri(url)

    def emit(*a):
        print(view.run_javascript_finish(a[1]).get_js_value().to_string(), flush=True)
        Gtk.main_quit()

    def on_loaded():
        if not state["loaded"]:
            return True
        if payload_bytes:
            view.run_javascript(
                JS_PAYLOAD.replace("__N__", str(payload_bytes)), None, None, None
            )
            GLib.timeout_add(150, poll)
            return False
        if css:
            view.run_javascript(
                "(()=>{const s=document.createElement('style');s.textContent=%s;"
                "document.head.appendChild(s)})()" % json.dumps(OVERRIDES[css]),
                None,
                lambda *a: GLib.timeout_add(500, run_probe),
                None,
            )
        else:
            GLib.timeout_add(500, run_probe)
        return False

    def do_resize():
        win.resize(1400, 900)
        win.queue_draw()
        GLib.timeout_add(700, do_resize_back)
        return False

    def do_resize_back():
        win.resize(1080, 720)
        win.queue_draw()
        return False

    def run_probe():
        if resize:
            GLib.timeout_add(1200, do_resize)
        js = JS.replace("__CFG__", json.dumps({"inner": inner, "switch": switch_pages,
                                               "idle": idle, "resize": resize}))
        view.run_javascript(js, None, None, None)
        GLib.timeout_add(150, poll)
        return False

    def poll():
        if (view.get_title() or "") == "PROBE":
            view.run_javascript("window.__P_RESULT || '{}'", None, emit, None)
            return False
        if time.time() > state["deadline"]:
            print(json.dumps({"err": "timeout"}), flush=True)
            Gtk.main_quit()
        return True

    GLib.timeout_add(100, on_loaded)
    Gtk.main()


def run_view(url, scale, inner, css, screen="3200x1900x24", payload_bytes=0, switch_pages=False,
             gpu="never", offscreen=False, no_xvfb=False, idle=False, resize=False):
    """在 Xvfb 里跑一次 worker，拿到它打的那行 JSON。"""
    cmd = []
    if not no_xvfb:
        cmd += ["xvfb-run", "-a", "-s", "-screen 0 %s" % screen]
    cmd += [
        sys.executable, os.path.abspath(__file__),
        "--worker", "--url", url, "--scale", str(scale),
        "--gpu", gpu,
    ]
    if offscreen:
        cmd.append("--offscreen")
    if inner:
        cmd.append("--inner")
    if css:
        cmd += ["--css", css]
    if payload_bytes:
        cmd += ["--payload-bytes", str(payload_bytes)]
    if switch_pages:
        cmd.append("--switch")
    if idle:
        cmd.append("--idle")
    if resize:
        cmd.append("--resize")
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"err": "worker 超时"}
    for line in reversed(p.stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except Exception:
                continue
    return {"err": (p.stderr or p.stdout or "拿不到数").strip()[-160:]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:5199/index.html?demo=normal&view=")
    ap.add_argument("--demo", default="normal")
    ap.add_argument("--scale", default="2", help="GDK_SCALE；面板在 HiDPI 屏上是 2")
    ap.add_argument("--inner", action="store_true", help="量内层滚动容器（日志那块）")
    ap.add_argument("--css", choices=sorted(OVERRIDES), default=None)
    ap.add_argument("--views", default="overview,nodes,rules,traffic,logs,settings")
    ap.add_argument("--resize", action="store_true",
                    help="量整窗重画：量到一半把窗改宽一次，看那一帧的间隔")
    ap.add_argument("--idle", action="store_true",
                    help="量稳态：6 秒里的帧数与 long task（每秒轮询那一轮）")
    ap.add_argument("--switch", dest="switch_pages", action="store_true",
                    help="量切页那一下（点侧栏 → 两帧后画完）")
    ap.add_argument("--payload-bytes", type=int, default=0,
                    help="只量一件事：把这么大的读数 JSON.parse 进这个引擎要多久")
    ap.add_argument("--gpu", choices=("never", "always", "ondemand"), default="never",
                    help="硬件加速策略；面板现在用的是 never（gui.go 里有理由）")
    ap.add_argument("--no-xvfb", action="store_true",
                    help="用真 DISPLAY 而不是 Xvfb（量硬件加速那一档时需要）")
    ap.add_argument("--offscreen", action="store_true", help="把窗放到可见区外面")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.worker:
        worker(args.url, args.scale, args.inner, args.css, args.payload_bytes,
               args.switch_pages, args.gpu, args.offscreen, args.idle, args.resize)
        return

    if not shutil.which("xvfb-run"):
        print("量不了：缺 xvfb-run（用它避免在真桌面上弹窗）", file=sys.stderr)
        sys.exit(2)
    print("渲染引擎：WebKitGTK + hardware-acceleration-policy=%s，scale=%s，demo=%s"
          % (args.gpu, args.scale, args.demo))
    if args.payload_bytes:
        d = run_view(args.url, args.scale, args.inner, args.css,
                     payload_bytes=args.payload_bytes)
        print("载荷 %s 字节：JSON.parse %sms，作为源码求值 %sms"
              % (d.get("bytes"), d.get("parse"), d.get("evalsrc")), flush=True)
        return
    if args.resize:
        d = run_view(args.url + "overview", args.scale, args.inner, args.css,
                     gpu=args.gpu, offscreen=args.offscreen, no_xvfb=args.no_xvfb,
                     resize=True)
        print("整窗重画：帧中位 %sms，最长 %sms，最长五帧 %s"
              % (d.get("med"), d.get("max"), d.get("top5")), flush=True)
        return
    if args.idle:
        d = run_view(args.url + "overview", args.scale, args.inner, args.css,
                     gpu=args.gpu, offscreen=args.offscreen, no_xvfb=args.no_xvfb,
                     idle=True)
        print("稳态 %s 秒：%s 帧（%.1f 帧/秒），long task %s 个 %s"
              % (d.get("seconds"), d.get("frames"),
                 (d.get("frames") or 0) / max(1, d.get("seconds") or 1),
                 len(d.get("longTasks") or []), d.get("longTasks")), flush=True)
        return
    if args.switch_pages:
        d = run_view(args.url + "overview", args.scale, args.inner, args.css,
                     switch_pages=True, gpu=args.gpu, offscreen=args.offscreen,
                     no_xvfb=args.no_xvfb)
        sw = d.get("switch") or {}
        for k, v in sw.items():
            if isinstance(v, list) and v and isinstance(v[0], list):
                a, b = v[0], v[1]
                print("切到 %-6s 第一次 DOM %5sms 布局 %5sms 画完 %5sms ｜ 第二次 DOM %5sms 布局 %5sms 画完 %5sms"
                      % (k, a[0], a[1], a[2], b[0], b[1], b[2]), flush=True)
            elif isinstance(v, list):
                print("切到 %-6s DOM改完 %6sms   画完 %6sms" % (k, v[0], v[1]), flush=True)
            else:
                print("切到 %-6s %6sms" % (k, v), flush=True)
        return
    for v in args.views.split(","):
        url = args.url + v
        url = url.replace("demo=normal", "demo=%s" % args.demo)
        d = run_view(url, args.scale, args.inner, args.css, gpu=args.gpu,
                     offscreen=args.offscreen, no_xvfb=args.no_xvfb)
        s = d.get("scroll") or {}
        print("%-9s med=%-6s p95=%-6s over33=%-4s nodes=%-5s rows=%s->%s %s"
              % (v, s.get("med"), s.get("p95"), s.get("over33"), d.get("nodes"),
                 d.get("rowsBefore"), d.get("rowsAfter"), d.get("err") or ""),
              flush=True)


if __name__ == "__main__":
    main()
