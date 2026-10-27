package service

import (
	"testing"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
)

// 只有规则模式才分流：全局与直连模式下这张卡不该介入。
func TestApplySplitGateFollowsMode(t *testing.T) {
	sp := outbound.NewSplit("wlp3s0f0", "wlx001f0578cdff")
	svc := New(writeCfg(t), nil)
	svc.split = sp

	for _, tc := range []struct {
		mode config.Mode
		want bool
	}{
		{config.ModeRule, true},
		{config.ModeGlobal, false},
		{config.ModeDirect, false},
		{config.ModeRule, true},
	} {
		svc.applySplitGate(tc.mode)
		if got := sp.Active(); got != tc.want {
			t.Errorf("模式 %s 之后闸门 = %v，期望 %v", tc.mode, got, tc.want)
		}
		if got, want := sp.DirectDev() != "", tc.want; got != want {
			t.Errorf("模式 %s 之后直连网卡 %q 与闸门不一致", tc.mode, sp.DirectDev())
		}
	}
}

// 开关状态必须落盘：它是配置项，下一次启动要读回同一份。
func TestSetIfaceSplitEnabledPersists(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	for _, want := range []bool{true, false, true} {
		if err := svc.SetIfaceSplitEnabled(want); err != nil {
			t.Fatalf("SetIfaceSplitEnabled(%v): %v", want, err)
		}
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.IfaceSplit.Enable != want {
			t.Fatalf("落盘的值 = %v，期望 %v", cfg.IfaceSplit.Enable, want)
		}
		if got := svc.Snapshot().IfaceSplit.Enabled; got != want {
			t.Fatalf("快照里的开关 = %v，期望 %v", got, want)
		}
	}
}

// 开关打开但没在跑时，界面不能显示成"已生效"。
func TestIfaceSplitNotActiveWhileStopped(t *testing.T) {
	svc := New(writeCfg(t), nil)
	svc.split = outbound.NewSplit("wlp3s0f0", "wlx001f0578cdff")
	svc.split.SetActive(true)

	st := svc.IfaceSplitStatus()
	if st.Active {
		t.Fatal("服务没在跑时不该显示分流已生效")
	}
}

// 探测不到两张卡时开关照样能开——它只是不生效，界面靠 Note 说清原因。
func TestIfaceSplitWithoutTwoCardsStillSwitches(t *testing.T) {
	path := writeCfg(t)
	svc := New(path, nil)

	if err := svc.SetIfaceSplitEnabled(true); err != nil {
		t.Fatalf("SetIfaceSplitEnabled: %v", err)
	}
	st := svc.Snapshot().IfaceSplit
	if !st.Enabled {
		t.Fatal("开关没打开")
	}
	// 选中哪两张取决于这台机器的网卡，测试只断言"要么选到两张、要么说清没选到"。
	if (st.DirectDev == "") != (st.ProxyDev == "") {
		t.Fatalf("两张网卡只选中了一张，这比不选更糟: %+v", st)
	}
	if st.DirectDev == "" && st.Note == "" {
		t.Fatalf("没选到网卡时必须给出原因: %+v", st)
	}
}
