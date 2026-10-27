package service

// 节点配额在"界面 ↔ 配置"这条路上的行为。
//
// 换算与校验本身在 internal/config（ParseSize 那张表），这里管的是三件更容易错的事：
// 新增节点带上配额、改节点时留空不许把已有配额洗掉、填错了要在当场报而不是写进盘里。

import (
	"os"
	"strings"
	"testing"
)

func TestProfileQuotaRoundTrip(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	if err := svc.AddProfile(ProfileSpec{
		Name: "东京", Addr: "jp.example.com:443", Auth: "k", Quota: "1000GB",
	}); err != nil {
		t.Fatalf("AddProfile: %v", err)
	}
	list, _, err := svc.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	var jp *ProfileView
	for i := range list {
		if list[i].Name == "东京" {
			jp = &list[i]
		}
	}
	if jp == nil {
		t.Fatal("新节点没进列表")
	}
	if jp.QuotaText != "1000GB" || jp.QuotaBytes != 1e12 {
		t.Errorf("配额没带进来: text=%q bytes=%d", jp.QuotaText, jp.QuotaBytes)
	}
	// 原来那个节点不该被"继承"出配额来：AddProfile 的缺省项是从第一个节点抄的，
	// 抄连接参数是对的，抄配额就等于凭空给人立了个额度。
	for _, p := range list {
		if p.Name != "东京" && p.QuotaBytes != 0 {
			t.Errorf("节点 %q 没配过配额却带着 %d 字节额度", p.Name, p.QuotaBytes)
		}
	}

	// 改地址时不填配额：原值必须留着。这是这套 spec 的通用约定
	// （空串 = 没填），配额这种"抄一次要用一年"的字段最需要它。
	if err := svc.UpdateProfile("东京", ProfileSpec{Addr: "jp2.example.com:443"}); err != nil {
		t.Fatalf("UpdateProfile: %v", err)
	}
	list, _, _ = svc.Profiles()
	for _, p := range list {
		if p.Name == "东京" && p.QuotaText != "1000GB" {
			t.Errorf("改了一次地址，配额变成 %q 了", p.QuotaText)
		}
	}

	// 填错了要当场报，而且不能已经写进盘里。
	before := readFile(t, path)
	if err := svc.UpdateProfile("东京", ProfileSpec{Quota: "1000 吉"}); err == nil {
		t.Fatal("坏配额被接受了")
	} else if !strings.Contains(err.Error(), "size") {
		t.Errorf("错误没在说尺寸: %v", err)
	}
	if got := readFile(t, path); got != before {
		t.Error("被拒绝的配额写进配置文件了")
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
