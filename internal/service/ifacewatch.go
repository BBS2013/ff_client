// 网卡插拔的监视器。
//
// 为什么要有它：USB 无线卡是会被拔的，而"代理钉在那张卡上"这件事
// 一旦那张卡没了就会从"分流"变成"全部代理一起失败"——
// socket 建在旧卡上，界面却还写着"已生效"。
// 只有把探测放在运行期反复做，才能在卡消失的那一刻就把它收回系统路由，
// 卡再插回来时再钉上去。
//
// 一条纪律：只有「变化落定了」才动手。连续两轮看到同一个新结果才落地——
// 网卡丢一次 DHCP 就会短暂地"没地址"，那种抖动不该换来两次隧道重建。
// 写法与规则文件的热重载监视器同源，见 ruleswatch.go。
package service

import (
	"context"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/netdev"
)

// ifaceWatchInterval 是看一次网卡的时间。5 秒是"拔了卡不用管它"
// 与"不变成常驻 sysfs 轮询"之间的折中；一次检查就是一遍 /sys/class/net 加几次 netlink。
const ifaceWatchInterval = 5 * time.Second

// syncSplitWatch 让监视循环跟着开关走：开着才起，关着就停。
//
// 没在运行时不起：那时候还没有正在承载流量的隧道要救，
// 而下一次探测本来就会在 Start 时发生一次。
func (s *Service) syncSplitWatch() {
	s.mu.Lock()
	cfg, rt := s.cfg, s.rt
	s.mu.Unlock()
	if cfg != nil && cfg.IfaceSplit.Enable && rt != nil {
		s.startIfaceWatch()
		return
	}
	s.stopIfaceWatch()
}

func (s *Service) startIfaceWatch() {
	s.mu.Lock()
	if s.ifaceWatchCancel != nil {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.ifaceWatchCancel = cancel
	s.mu.Unlock()

	go s.ifaceWatchLoop(ctx)
}

func (s *Service) stopIfaceWatch() {
	s.mu.Lock()
	cancel := s.ifaceWatchCancel
	s.ifaceWatchCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Service) ifaceWatchLoop(ctx context.Context) {
	ticker := time.NewTicker(ifaceWatchInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.checkIfaceChanged()
		}
	}
}

// checkIfaceChanged 走一轮：重新探测 → 重新解析 → 问要不要动手。
// 抽成方法是因为测试要能一轮一轮地驱动它，而不是睡 5 秒等定时器。
func (s *Service) checkIfaceChanged() {
	s.mu.Lock()
	cfg, rt, prev := s.cfg, s.rt, s.ifaceSeen
	d, p := s.split.Devices()
	s.mu.Unlock()
	if rt == nil || cfg == nil || !cfg.IfaceSplit.Enable {
		return
	}
	set := netdev.Detect()
	plan := resolveSplit(set, cfg.IfaceSplit)
	s.mu.Lock()
	s.ifaceSeen = plan.pick
	s.mu.Unlock()

	// 下拉里的可选网卡跟着这一轮一起更新：它们本来就是同一份探测结果。
	// 写在这儿而不是等真正要动手时——只换了张卡没换绑定的那一侧，
	// 界面上那张卡也得立刻能选。
	s.mu.Lock()
	s.ifaceCards = plan.cards
	s.mu.Unlock()

	if !ifaceSettled(pickOf(d, p), prev, plan.pick) {
		return
	}
	if err := s.applyPlan(plan, true); err != nil {
		logx.Warnf("网卡变化后重设分流失败: %v", err)
		return
	}
	logx.Infof("检测到网卡变化：直连走 %s，代理走 %s（%s）",
		devOr(plan.pick.direct, "系统默认路由"), devOr(plan.pick.proxy, "系统默认路由"), set.Describe())
}

// ifaceSettled 回答「这一轮的结果能不能动手」。
//
// 基线为空时不动手：那时的动作该是记住现状，而不是照着一个还没建立的事实去改绑定。
func ifaceSettled(base, prev, now splitPick) bool {
	if base == (splitPick{}) {
		return false
	}
	if now.same(base) {
		return false
	}
	// 与上一轮也不同 = 还在动，等它停下来。
	return now.same(prev)
}
