package main

// check_fetch.go 是 `-check-fetch`：真的取一个页面回来，而不是只把电路建起来。
//
// 为什么要有这条：`-check` / `-check-host` 只做 TCP 拨号。走代理时它证明的是
// "本机到节点的电路通了"，最后一跳由节点去连——于是有一类节点会骗过它：
// 隧道正常建立，节点那边把流量交给一个兼底的 web 服务器，
// 任何站点回来的都是同一个 400 页面。TCP 拨号看这个一切正常，
// 而用户的浏览器一个页面都打不开。
// 取一次真页面能把它区分出来：状态码与 `Server:` 头会当场说漏嘴。
//
// 怎么发这个请求、怎么判这个结果都在 internal/httpprobe 里，
// 面板上的节点测速用的是同一份——两条路对"通"的判据不许各自漂移。
// 这一层只管"按规则拨出去、把巡检的形状摆好"。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"wps_app/internal/httpprobe"
	"wps_app/internal/logx"
	"wps_app/internal/router"
	"wps_app/internal/service"
)

// pageFetch 是"取一个页面"这一步。签名与 checkDial 同一个形状、同一个理由：
// "一个目标卡住会不会拖死整轮"必须能用一个不认 ctx 的假实现测出来，
// 那就不能把这一步焊死在路由器上。
type pageFetch func(ctx context.Context, raw string) (httpprobe.Outcome, router.Result, error)

// fetchCheck 用"取真页面"的方式逐个巡检目标。
func fetchCheck(rt *router.Router, urls []string, budget time.Duration, w io.Writer) error {
	return fetchPages(func(ctx context.Context, raw string) (httpprobe.Outcome, router.Result, error) {
		return fetchOnce(ctx, rt, raw)
	}, urls, budget, w)
}

// fetchPages 与 checkTargets 同一套规矩：
// 不 fail-fast、每个目标各自一份预算、任一失败则整体返回错误（退出码给脚本用）。
func fetchPages(fetch pageFetch, urls []string, budget time.Duration, w io.Writer) error {
	if len(urls) == 0 {
		return errors.New("没有可巡检的 URL")
	}
	failed := make([]string, 0, len(urls))
	for _, raw := range urls {
		out, res, err := fetchWithDeadline(fetch, raw, budget)
		if err != nil {
			failed = append(failed, raw)
			logx.Warnf("取页面失败: %s: %v", raw, err)
			// 失败行也要说清走的是哪条出站——「400 是经 PROXY 拿到的」和
			// 「400 是直连拿到的」指向完全不同的根因。
			// 拨号本身就没成功时拿不到出站名，这时不硬编一个。
			via := ""
			if res.Outbound != "" {
				via = " via " + res.Outbound
			}
			fmt.Fprintf(w, "FAIL %s %v%s\n", raw, err, via)
			continue
		}
		logx.Infof("取页面通过: %s → %s（经 %s 出站，命中 %s）", raw, out, res.Outbound, res.Matched)
		fmt.Fprintf(w, "OK %s %s via %s matched=%s\n", raw, out, res.Outbound, res.Matched)
	}
	fmt.Fprintf(w, "FETCH-SUMMARY ok=%d fail=%d total=%d\n", len(urls)-len(failed), len(failed), len(urls))
	if len(failed) > 0 {
		return fmt.Errorf("%d/%d 个目标没取回页面: %s", len(failed), len(urls), strings.Join(failed, ", "))
	}
	return nil
}

// fetchWithDeadline 给单次取页面套一个预算。
// 超时后 goroutine 留在原地：这条命令跑完就退出，与 dialWithDeadline 同一个取舍。
func fetchWithDeadline(fetch pageFetch, raw string, budget time.Duration) (httpprobe.Outcome, router.Result, error) {
	type outcome struct {
		res httpprobe.Outcome
		r   router.Result
		err error
	}
	ch := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	go func() {
		res, r, err := fetch(ctx, raw)
		ch <- outcome{res: res, r: r, err: err}
	}()
	select {
	case o := <-ch:
		cancel()
		return o.res, o.r, o.err
	case <-ctx.Done():
		cancel()
		return httpprobe.Outcome{}, router.Result{}, fmt.Errorf("超时（预算 %s）", budget)
	}
}

// fetchOnce 只是 service.FetchViaRouter 的一层壳：命令行与面板上那一格
// 必须共用同一份"怎么拨、怎么读、怎么判"，两条路各写一遍迟早会漂移。
func fetchOnce(ctx context.Context, rt *router.Router, raw string) (httpprobe.Outcome, router.Result, error) {
	return service.FetchViaRouter(ctx, rt, raw)
}
