package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/httpprobe"
	"wps_app/internal/outbound"
)

// 界面点「测速」时，「电路通了」和「页面取回来了」是两件事，必须分开报。
// 兼底型节点就是这个缺口：隧道正常建立，节点那边把流量交给一个兼底 web 服务器，
// 任何站点回来的都是同一张 400 页面——握手、探测、延迟全都好看。

// probeDialer 用真的直连出站当「节点」：目标全在回环上，不碰外网。
// 这里要证的是 pageProbe 把读数写进了 ProfileTest 的哪一格，
// 所以宁可拿真拨号，也不要一个什么都能编出来的假连接。
func probeDialer() outbound.Dialer { return outbound.NewDirect(3 * time.Second) }

func newProbeContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestPageProbeWritesTheVerdictOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	var res ProfileTest
	pageProbe(newProbeContext(t), probeDialer(), srv.URL+"/generate_204", &res)

	if !res.PageChecked {
		t.Fatal("探过就必须标出「探过了」")
	}
	if res.PageErr != "" {
		t.Fatalf("204 不该有失败原文：%q", res.PageErr)
	}
	if !strings.Contains(res.Page, "204") {
		t.Errorf("读数里该有状态码：%q", res.Page)
	}
}

// 这一条就是旧测速抓不住、而现在能抓住的那个现场。
func TestPageProbeReportsFallbackNode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.28.3 (Ubuntu)")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer srv.Close()

	var res ProfileTest
	pageProbe(newProbeContext(t), probeDialer(), srv.URL+"/", &res)

	if !res.PageChecked {
		t.Fatal("探过就要标 PageChecked，否则界面会把「没探」和「探了但失败」混成一格")
	}
	// 全部意义所在：页面没取回来时必须有一句话能把它说清。
	if !strings.Contains(res.PageErr, "HTTP 400") || !strings.Contains(res.PageErr, "nginx/1.28.3") {
		t.Errorf("失败原文该带上状态码与 Server 头：%q", res.PageErr)
	}
	if res.Page != "" {
		t.Errorf("判失败时不该同时给一个成功读数：%q", res.Page)
	}
}

// 拨号都没成功时也要留一句原文，而不是安静地把这一格留空——
// 留空会被读成「没探」，而实际是「探了、这一步就没过去」。
func TestPageProbeReportsDialFailure(t *testing.T) {
	var res ProfileTest
	pageProbe(newProbeContext(t), probeDialer(), "http://127.0.0.1:1/", &res)
	if !res.PageChecked {
		t.Fatal("拨不通也算探过了")
	}
	if !strings.Contains(res.PageErr, "拨 127.0.0.1:1 失败") {
		t.Errorf("失败原文该说清是拨号这一步：%q", res.PageErr)
	}
}

// 探针地址用不了（scheme 不对）同样是一格失败，不许当「没探」。
func TestPageProbeReportsUnusableProbeURL(t *testing.T) {
	var res ProfileTest
	pageProbe(context.Background(), probeDialer(), "ftp://example.com/", &res)
	if !res.PageChecked || !strings.Contains(res.PageErr, "只支持 http/https") {
		t.Fatalf("该当场给出「用不了」那句：%+v", res)
	}
}

// 界面上「测速」这一行写的就是那个常量地址，README 也按它写的。
// 这条守卫只为把它钉住：改了代码不说一句，文档与界面就会开始互相矛盾。
func TestProfilePageProbeIsTheDocumentedPage(t *testing.T) {
	got, err := httpprobe.Parse(profilePageProbe)
	if err != nil {
		t.Fatalf("探针地址应当永远拆得开: %v", err)
	}
	if got.Host != "www.gstatic.com" || got.Port != "443" || got.Path != "/generate_204" || !got.UseTLS {
		t.Errorf("探针地址变成了 %+v（README §6 与界面文案都按 https://www.gstatic.com/generate_204 写的）", got)
	}
}

// 电路就没通时不许探页面，也不许留下任何「页面」读数——
// 那会让一行「节点连不上」旁边挂上一句看起来像结论的话。
func TestTestProfileSkipsPageProbeWhenCircuitFails(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)
	if err := svc.AddProfile(ProfileSpec{
		Name: "dead", Type: config.ProtocolTrojan, Addr: "127.0.0.1:1", Auth: "pw", Insecure: true,
	}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	res := svc.TestProfile("dead", "127.0.0.1:1")
	if res.OK {
		t.Fatalf("连不上的节点不该报成功: %+v", res)
	}
	if res.PageChecked || res.Page != "" || res.PageErr != "" {
		t.Errorf("电路失败时页面那一格该完全没动：%+v", res)
	}
}
