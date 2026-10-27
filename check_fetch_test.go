package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"wps_app/internal/httpprobe"
	"wps_app/internal/outbound"
	"wps_app/internal/router"
	"wps_app/internal/rules"
)

// 探针本身（拆 URL、发请求、判状态码）在 internal/httpprobe 里测，
// 这里只管巡检这一层：接上真路由器跑完整链路、不 fail-fast、各自一份预算。

// serveOnce 起一个只回一次的本地假服务器（只走回环，断网命名空间里也能跑）。
// 与 internal/httpprobe 测试里那份同形——跨包没法共用测试替身，重复的是假服务器，
// 不是判据。
func serveOnce(t *testing.T, reply func(req string) string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		br := bufio.NewReader(conn)
		req, _ := br.ReadString('\n')
		headers := req
		for {
			line, err := br.ReadString('\n')
			if err != nil || strings.TrimRight(line, "\r\n") == "" {
				break
			}
			headers += line
		}
		_, _ = conn.Write([]byte(reply(headers)))
	}()
	a := ln.Addr().(*net.TCPAddr)
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(a.Port))
}

// directRouter 拼一个只走直连的真路由器，接进 fetchCheck 里跑完整链路。
//
// 之所以自己拼、不复用服务层那套：这里要的是一个更窄的现场——
// 出站集合里只有一个 DIRECT，于是取回来的页面必然来自回环上的假服务器，
// 断网命名空间里也不会漂到外网去。
//
// 规则里除 FINAL 之外必须再留一条真的规则：只剩 FINAL 会被引擎以
// 「no usable rules found」拒掉，那是「规则文件写错了却静默全走 FINAL」
// 那道护栏在起作用，不是测试环境的问题。
func directRouter(t *testing.T) *router.Router {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(path, []byte("DOMAIN-SUFFIX,local.test,DIRECT\nFINAL,DIRECT\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	eng, err := rules.Load(path, nil, nil)
	if err != nil {
		t.Fatalf("加载规则: %v", err)
	}
	set := outbound.NewSet(outbound.NewDirect(3*time.Second), nil).WithNode("（测试用的直连）")
	return router.New(eng, set, 3*time.Second)
}

// TestFetchCheckThroughARouter 从 URL 一路走到判定，中间用的是真的路由器。
//
// 探针的单测覆盖了发请求与判状态码，但"拨出来的那条连接是不是就是路由器按规则
// 选的那条"只有接上真路由器才算数——那正是这条命令存在的意义
// （走代理时它要证明"经隧道能取回页面"）。
// 这里用 FINAL,DIRECT + 回环上的假服务器：不碰外网，断网命名空间里也跑得动。
func TestFetchCheckThroughARouter(t *testing.T) {
	addr := serveOnce(t, func(string) string {
		return "HTTP/1.1 404 Not Found\r\nServer: fallback-nginx/1.28.3\r\nContent-Length: 4\r\n\r\nbody"
	})
	var out bytes.Buffer
	target := "http://" + addr + "/missing"
	err := fetchCheck(directRouter(t), []string{target}, 5*time.Second, &out)
	if err == nil {
		t.Fatalf("404 应当判失败，输出：\n%s", out.String())
	}
	text := out.String()
	if !strings.Contains(text, "FAIL "+target) {
		t.Errorf("失败行应当带上这个 URL：\n%s", text)
	}
	// 关键的那句：状态码 + 是谁回的。兼底型节点就是在这里露馅的。
	if !strings.Contains(text, "HTTP 404") || !strings.Contains(text, "fallback-nginx/1.28.3") {
		t.Errorf("报错里该带上状态码与 Server 头：\n%s", text)
	}
	if !strings.Contains(text, "via DIRECT") {
		t.Errorf("失败行也该说明它走的是哪条出站：\n%s", text)
	}
	if !strings.Contains(text, "FETCH-SUMMARY ok=0 fail=1 total=1") {
		t.Errorf("少了汇总行：\n%s", text)
	}
}

// TestFetchCheckPassesOnARealPage 2xx 那条路也要走一遍，
// 不然"永远报失败"的实现同样能过上面那条用例。
func TestFetchCheckPassesOnARealPage(t *testing.T) {
	addr := serveOnce(t, func(string) string {
		return "HTTP/1.1 204 No Content\r\nServer: edge/1.0\r\n\r\n"
	})
	var out bytes.Buffer
	if err := fetchCheck(directRouter(t), []string{"http://" + addr + "/"}, 5*time.Second, &out); err != nil {
		t.Fatalf("204 应当判通：%v\n%s", err, out.String())
	}
	text := out.String()
	if !strings.Contains(text, "OK http://"+addr+"/") || !strings.Contains(text, "204") {
		t.Errorf("成功行不对：\n%s", text)
	}
	// 成功行同样要带出站——"经隧道能取回页面"这句话的全部价值就在于它说清了经的是哪条。
	if !strings.Contains(text, "via DIRECT") || !strings.Contains(text, "matched=") {
		t.Errorf("成功行该说明走的是哪条出站、按哪条规则：\n%s", text)
	}
}

// TestFetchCheckBadSchemeIsReportedPerTarget 拆不出 URL 也要按"这个目标失败"算，
// 而不是让整轮巡检直接退出——与 -check-host 同一条不 fail-fast 的规矩。
func TestFetchCheckBadSchemeIsReportedPerTarget(t *testing.T) {
	var out bytes.Buffer
	rt := directRouter(t)
	err := fetchCheck(rt, []string{"ftp://example.com/", "http://127.0.0.1:1/"}, 5*time.Second, &out)
	if err == nil {
		t.Fatal("两个都该失败")
	}
	text := out.String()
	if !strings.Contains(text, "只支持 http/https") {
		t.Errorf("scheme 不对应当直接说清：\n%s", text)
	}
	if !strings.Contains(text, "fail=2") {
		t.Errorf("两个目标都该计入失败：\n%s", text)
	}
	// 第二个是拨号都没成功，这条上没有任何出站可报——
	// 不许为了让每行都整齐而编一个 "via DIRECT" 出来。
	if strings.Contains(text, "FAIL http://127.0.0.1:1/ via") {
		t.Errorf("拨号失败不该报出站：\n%s", text)
	}
}

// TestFetchPagesEachTargetGetsOwnDeadline 与 -check-host 那条同名规矩：
// 共用一份总预算时，第一个卡住的目标会把后面全部饿死，
// 于是巡检剩下的一半永远不报，看起来像"什么都没发生"。
// 这里用的是不认 ctx 的假实现——真实取页面会认 ctx，但守卫不能建在下游的配合上。
func TestFetchPagesEachTargetGetsOwnDeadline(t *testing.T) {
	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- fetchPages(func(ctx context.Context, raw string) (httpprobe.Outcome, router.Result, error) {
			if strings.Contains(raw, "hang") {
				select {} // 完全不认 ctx：模拟卡在不动的那条路
			}
			return httpprobe.Outcome{Code: 204}, router.Result{Outbound: "DIRECT", Matched: "FINAL"}, nil
		}, []string{"http://hang.example/", "http://after.example/"}, 30*time.Millisecond, &out)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("卡住的目标应被判失败")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("预算没兜住卡死的取页面，整轮巡检挂死了")
	}
	text := out.String()
	if !strings.Contains(text, "FAIL http://hang.example/ 超时") {
		t.Errorf("卡住的目标要如实报超时：\n%s", text)
	}
	if !strings.Contains(text, "OK http://after.example/") {
		t.Errorf("后面的目标被第一个的超时拖掉了：\n%s", text)
	}
}

// fetchPages 收到的空列表不能当成"全通过"。
// 退出码 0 加一句"没有可巡检的 URL"，脚本读出来的是"都通了"。
func TestFetchPagesEmptyListIsAnError(t *testing.T) {
	if err := fetchPages(nil, nil, time.Second, io.Discard); err == nil {
		t.Fatal("一个目标都没有时不该当成功")
	}
}
