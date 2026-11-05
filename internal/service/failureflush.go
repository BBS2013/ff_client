package service

import (
	"context"
	"time"

	"wps_app/internal/logx"
)

// failureFlushInterval 是失败日志的汇总周期，与 logx.FlushFailureWindow 同值。
//
// 为什么让 service 驱动它而不是让 logx 自己起 goroutine：
// logx 是一个被所有测试用到的包，里面藏一个后台 goroutine 会让"测试之间互不
// 干扰"这件事变难（上一个用例留下的定时器会在下一个用例里打日志）。
// 由 service 的生命周期持有它，启停边界就很清楚。
const failureFlushInterval = logx.FlushFailureWindow

// startFailureFlush 起失败日志的汇总循环。已经在跑就不重复起。
func (s *Service) startFailureFlush() {
	s.mu.Lock()
	if s.failureFlushCancel != nil {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.failureFlushCancel = cancel
	s.mu.Unlock()

	go func() {
		t := time.NewTicker(failureFlushInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				// 收尾前把最后那批打出来：一次会话的最后 60 秒里累计的失败
				// 不该因为进程退出就凭空消失——那是"刚才到底出了什么事"
				// 最该留下来的部分。
				logx.FlushFailures()
				return
			case <-t.C:
				logx.FlushFailures()
			}
		}
	}()
}

// stopFailureFlush 停掉汇总循环。停止时不额外 flush：
// 循环自己在 ctx.Done 里会做最后一次。
func (s *Service) stopFailureFlush() {
	s.mu.Lock()
	cancel := s.failureFlushCancel
	s.failureFlushCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
