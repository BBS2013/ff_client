package service

// 「取一个真页面」那一格的判据。
//
// 这一格存在的理由全在"取回来的东西怎么算答案"上，所以测试盯的不是能不能连通，
// 而是三件容易写歪的事：
//   1. 取回一个 400 是**答案**，不是查询失败——当 error 返回，界面就只剩
//      "查询失败"四个字，而用户要看的偏偏是那个状态码与是谁在回话；
//   2. 回显的网址不许带查询串（订阅地址的 key 常挂在那儿，而这一格会被截图发出去）；
//   3. 它报的规则/节点必须与真拨号同源，不能是另算一遍的。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func startedSvc(t *testing.T) *Service {
	t.Helper()
	cfgPath, _ := userRulesEnv(t)
	svc := New(cfgPath, nil)
	if err := svc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = svc.Stop() })
	return svc
}

func TestFetchPageTakesARealAnswer(t *testing.T) {
	svc := startedSvc(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "origin-svc/1.2")
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	res, err := svc.FetchPage(context.Background(), srv.URL+"/x?token=TOPSECRET")
	if err != nil {
		t.Fatalf("取一个 200 却报失败: %v (%+v)", err, res)
	}
	if !res.OK || res.Code != 200 {
		t.Errorf("判成 %v / 状态码 %d，想要通了且是 200", res.OK, res.Code)
	}
	if res.Server != "origin-svc/1.2" {
		t.Errorf("Server 头没带回来: %q", res.Server)
	}
	if res.Body <= 0 {
		t.Errorf("正文字节数没数到: %d", res.Body)
	}
	// 回显里不能有查询串：这一格的内容会被截图发给别人。
	if strings.Contains(res.URL, "TOPSECRET") || strings.Contains(res.URL, "?") {
		t.Errorf("回显的网址带着查询串: %q", res.URL)
	}
	// 127.0.0.1 在这份规则下走 FINAL,DIRECT，与真拨号同一个结论。
	if res.Policy != "DIRECT" || res.Matched != "FINAL" {
		t.Errorf("判定读数不对: %+v", res)
	}
	if res.Addr == "" {
		t.Error("没报出真正拨出去的 host:port")
	}
}

// TestFetchPageBadAnswerIsNotAFailure 是这一格最容易写歪的那一处。
func TestFetchPageBadAnswerIsNotAFailure(t *testing.T) {
	svc := startedSvc(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	res, err := svc.FetchPage(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("取回 400 是答案不是失败，却当错误返回了: %v", err)
	}
	if res.OK || res.Code != 400 {
		t.Errorf("判成了 %+v，想要 ok=false / code=400", res)
	}
	if !strings.Contains(res.Reason, "400") || !strings.Contains(res.Reason, "nginx") {
		t.Errorf("Reason 里看不出是谁回的话: %q", res.Reason)
	}
}

func TestFetchPageRefusesWhatItCannotAsk(t *testing.T) {
	svc := startedSvc(t)
	for _, bad := range []string{"", "   ", "not-a-url", "ftp://example.com/x", "https://"} {
		if _, err := svc.FetchPage(context.Background(), bad); err == nil {
			t.Errorf("空/坏输入 %q 居然答出来了", bad)
		}
	}

	// 没在跑时直说"先启动"：这一格不能拿一份没有路由器的读数冒充答案。
	cfgPath, _ := userRulesEnv(t)
	off := New(cfgPath, nil)
	if _, err := off.FetchPage(context.Background(), "https://example.com"); err == nil ||
		!strings.Contains(err.Error(), "没在跑") {
		t.Errorf("停着的时候这一格该拒绝: %v", err)
	}
}

// TestFetchPageHonoursDeadline：对端不回话时要在预算内给出"超时"这句话，
// 而不是让面板那一次调用挂死（绑定方法跑在 Wails 的 goroutine 上）。
func TestFetchPageHonoursDeadline(t *testing.T) {
	svc := startedSvc(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := svc.FetchPage(ctx, srv.URL)
	spent := time.Since(start)
	t.Logf("预算 100ms，实际用了 %v", spent.Round(10*time.Millisecond))
	if err == nil {
		t.Fatal("超时期望有错误")
	}
	// 超时那一句必须是能读的话：以前直接透出 Go 的 socket 原文
	// （`读状态行失败: read tcp 127.0.0.1:37292->127.0.0.1:39649: i/o timeout`），
	// 那两串是本机临时端口，既不是用户填的地址、也不告诉他等了多久。
	msg := err.Error()
	if strings.Contains(msg, "read tcp") || strings.Contains(msg, "i/o timeout") {
		t.Errorf("超时那句还是 socket 原文: %q", msg)
	}
	if !strings.Contains(msg, "秒") || !strings.Contains(msg, "127.0.0.1") {
		t.Errorf("超时那句该报出拨到哪儿、等了多久: %q", msg)
	}
	// 断的是"没等到对端回话就收尾"：handler 睡 2 秒，所以判据要卡在两者之间。
	// 原来写成 `> 2s` 才算红——那等于只有"完全无视 ctx 且刚好在 2.00s 之后返回"才被抓到，
	// 一个把超时拖到 1.9s 的实现照样绿。留 10 倍余量在两侧，红绿才各自说得清。
	if spent > time.Second {
		t.Errorf("没在预算里收尾，实际等了 %v（handler 睡 2s，取页面那一步不该等它）", spent.Round(time.Millisecond))
	}
}
