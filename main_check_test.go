package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"wps_app/internal/router"
)

// fakeDial 按目标名给出预设结果；名字在 fails 里就报错。
func fakeDial(fails map[string]error) checkDial {
	return func(_ context.Context, target string) (router.Result, error) {
		if err := fails[target]; err != nil {
			return router.Result{}, err
		}
		return router.Result{
			Host:     target,
			Matched:  "MATCHED(" + target + ")",
			Outbound: "demo",
		}, nil
	}
}

func TestCheckTargetsAllPass(t *testing.T) {
	var out strings.Builder
	targets := []string{"a.example:443", "b.example:443"}
	if err := checkTargets(fakeDial(nil), targets, time.Second, &out); err != nil {
		t.Fatalf("全通过时不该报错: %v", err)
	}
	got := out.String()
	for _, want := range []string{"OK a.example:443", "OK b.example:443", "SUMMARY ok=2 fail=0 total=2"} {
		if !strings.Contains(got, want) {
			t.Errorf("输出里缺 %q:\n%s", want, got)
		}
	}
	// 顺序必须跟着命令行给的目标走：脚本要按行号对上是哪一个。
	if strings.Index(got, "a.example") > strings.Index(got, "b.example") {
		t.Errorf("目标顺序被打乱了:\n%s", got)
	}
}

// TestCheckTargetsDoNotFailFast 一个目标失败必须继续跑完其余。
//
// 巡检的意义就是"知道哪一类不通"：第一下失败就退出，用户只看到一个错，
// 分不清是隧道整体没起来还是只有某条规则的那条路有问题。
func TestCheckTargetsDoNotFailFast(t *testing.T) {
	dial := fakeDial(map[string]error{"bad.example:443": errors.New("connection refused")})
	var out strings.Builder
	err := checkTargets(dial, []string{"a.example:443", "bad.example:443", "c.example:443"}, time.Second, &out)
	if err == nil {
		t.Fatal("有目标失败时应返回错误（退出码要给脚本用）")
	}
	if !strings.Contains(err.Error(), "bad.example:443") {
		t.Errorf("错误里应点名失败的目标: %v", err)
	}
	got := out.String()
	for _, want := range []string{"OK a.example:443", "FAIL bad.example:443", "OK c.example:443", "SUMMARY ok=2 fail=1 total=3"} {
		if !strings.Contains(got, want) {
			t.Errorf("跑了中间那个就停了或缺 %q:\n%s", want, got)
		}
	}
}

// TestCheckTargetsEachGetsOwnDeadline 每个目标各自一份超时。
//
// 共用一个总预算的话，第一个卡住的目标会把后面全部饿死——
// 巡检剩下的一半永远不报，看起来就像"什么都没发生"。
func TestCheckTargetsEachGetsOwnDeadline(t *testing.T) {
	dial := func(ctx context.Context, target string) (router.Result, error) {
		if target == "hang.example:443" {
			// 完全无视 ctx：模拟一个卡在不动的拨号路径。
			// 超时必须由 checkTargets 自己兜住，不能指望下游配合。
			select {}
		}
		return router.Result{Host: target, Matched: "M", Outbound: "demo"}, nil
	}
	var out strings.Builder
	done := make(chan error, 1)
	go func() {
		done <- checkTargets(dial, []string{"hang.example:443", "after.example:443"}, 20*time.Millisecond, &out)
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("卡住的目标应被判失败")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("超时没兜住卡死的拨号，整轮巡检挂死了")
	}
	got := out.String()
	if !strings.Contains(got, "FAIL hang.example:443") {
		t.Errorf("卡住的目标要如实报失败:\n%s", got)
	}
	if !strings.Contains(got, "OK after.example:443") {
		t.Errorf("后面的目标被第一个的超时拖掉了:\n%s", got)
	}
}

func TestCheckTargetsEmptyListIsAnError(t *testing.T) {
	if err := checkTargets(fakeDial(nil), nil, time.Second, io.Discard); err == nil {
		t.Fatal("一个目标都没有时不该当成功")
	}
}

// TestCheckTargetsReportsHitPolicy 每一行都要带上命中的规则与出站。
// 一次巡检于是同时验了两件事：通不通，以及按哪条路走。
func TestCheckTargetsReportsHitPolicy(t *testing.T) {
	var out strings.Builder
	if err := checkTargets(fakeDial(nil), []string{"a.example:443"}, time.Second, &out); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"via demo", "matched=MATCHED(a.example:443)"} {
		if !strings.Contains(got, want) {
			t.Errorf("缺 %q:\n%s", want, got)
		}
	}
}
