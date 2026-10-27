// 规则集订阅在界面上的那一栏。
//
// 为什么要有它：订阅这一层从头到尾只在说话时用一个渠道——日志。
// 于是三种完全不同的处境在界面上长得一样：
//   - 拉得好好的，只是这一轮远端没有新内容；
//   - 连着失败，规则停在上周那份上；
//   - 配置里写了但启动时被拒（重名、缓存路径撞车），压根没在拉。
//
// 这一栏把这三件事分开说。它不改变任何行为：拉取、验内容、保旧缓存
// 那些性质一条都不动，只是把已经发生的事摊开。
package service

import (
	"context"
	"fmt"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/rulesub"
)

// SubscriptionView 是一条订阅的此刻状况。
//
// 时刻一律用毫秒时间戳、0 表示"从没发生过"，不用字符串：
// 界面那边已经有 formatAgo/formatClock 这套格式化，Go 侧再定一次格式
// 就会变成"两处各有一套时间说法"，跨天与本地时区最容易在这里错开。
type SubscriptionView struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	EverySec int    `json:"everySec"`

	// LastAttemptMs 是上一次**尝试**的时刻（成功失败都算）；0 = 这个进程还没碰过它。
	LastAttemptMs int64 `json:"lastAttemptMs"`
	// LastOkMs 是上一次拉成功的时刻；0 = 从没成功过。
	LastOkMs int64 `json:"lastOkMs"`
	// NextDueMs 是下一次大概什么时候拉；0 = 没在跑，不会去拉。
	NextDueMs int64 `json:"nextDueMs"`

	// LastErr 是最近一次失败的原文；空串 = 没有未消化的故障。
	LastErr string `json:"lastErr"`
	// Fails 是连续失败次数（拉成功即归零）。
	Fails int `json:"fails"`
	// Size 是缓存内容字节数。
	Size int64 `json:"size"`
	// HasCache 是"这份缓存此刻在不在磁盘上"。它与 LastOkMs 是两件事：
	// 拉通过、之后文件被人删了，这里就是假——那正是"订阅看着健康、
	// 规则却少了一整段"的那种现场。
	HasCache bool `json:"hasCache"`
}

// SubscriptionsView 是订阅这一栏的全部读数。
type SubscriptionsView struct {
	// Configured 是配置里启用了几条订阅。0 与"读不到配置"是两回事，
	// 后者由 ConfigErr 说明。
	Configured int `json:"configured"`
	// Running 是订阅循环此刻在不在跑。假的时候 Items 里的时刻字段全是 0，
	// 界面必须说"代理没在跑，不会去拉"，不能把 0 画成"很久没更新"。
	Running bool               `json:"running"`
	Items   []SubscriptionView `json:"items"`
	// Errors 是启动时被拒的条目原文（重名、缓存路径相同…）。
	// 只记不拦：一条配错的订阅不该让其余几条一起消失。
	Errors []string `json:"errors"`
	// ConfigErr 非空 = 连配置都没读到，这时上面的数字全都不可信。
	ConfigErr string `json:"configErr"`
}

// Subscriptions 读订阅现状。没在跑时按配置列出条目，
// 好让"配了但没生效"与"根本没配"在界面上是两句话。
func (s *Service) Subscriptions() SubscriptionsView {
	s.mu.Lock()
	up, errs, cfg := s.providers, append([]string(nil), s.providerErrs...), s.cfg
	s.mu.Unlock()

	v := SubscriptionsView{Items: []SubscriptionView{}, Errors: errs}

	if cfg == nil {
		loaded, err := config.Load(s.cfgPath)
		if err != nil {
			v.ConfigErr = err.Error()
			return v
		}
		cfg = loaded
	}
	enabled := make([]config.RuleProvider, 0, len(cfg.RuleProviders))
	for _, p := range cfg.RuleProviders {
		if p.IsEnabled() {
			enabled = append(enabled, p)
		}
	}
	v.Configured = len(enabled)

	if up != nil {
		v.Running = true
		now := time.Now()
		for _, st := range up.Status() {
			v.Items = append(v.Items, runningView(st, now))
		}
		return v
	}
	for _, p := range enabled {
		v.Items = append(v.Items, SubscriptionView{
			Name:     p.Name,
			Path:     cfg.ProviderPath(p),
			EverySec: int(p.Every() / time.Second),
		})
	}
	return v
}

func runningView(st rulesub.Status, now time.Time) SubscriptionView {
	out := SubscriptionView{
		Name:     st.Name,
		Path:     st.Path,
		EverySec: int(st.Every / time.Second),
		LastErr:  st.LastErr,
		Fails:    st.Fails,
		Size:     st.Size,
		HasCache: st.HasCache,
	}
	if !st.LastAttempt.IsZero() {
		out.LastAttemptMs = millis(st.LastAttempt)
		// 下一次 = 上次尝试 + 周期。失败也照这个走：这一层的重试节奏
		// 本来就按尝试算，报"下次尝试"比报"下次成功"诚实。
		if next := st.LastAttempt.Add(st.Every); next.After(now) {
			out.NextDueMs = millis(next)
		} else {
			out.NextDueMs = millis(now) // 已经到期，下一轮就会动
		}
	}
	if !st.LastOK.IsZero() {
		out.LastOkMs = millis(st.LastOK)
	}
	return out
}

func millis(t time.Time) int64 { return t.UnixMilli() }

// ProviderRefresh 是一条订阅"立即拉取"的结果。
type ProviderRefresh struct {
	Name    string `json:"name"`
	Changed bool   `json:"changed"`
	// Err 是这一条失败的原因；空串 = 这条拉通了（内容没变也算拉通）。
	Err string `json:"err"`
}

// ProviderRefreshReport 是一次「立即拉取」的整体结果。
type ProviderRefreshReport struct {
	Results []ProviderRefresh `json:"results"`
	// Reloaded 只在"确有内容变了、且按新内容成功重载了规则"时为真。
	Reloaded bool `json:"reloaded"`
	// ReloadErr 非空 = 内容变了但规则重载失败，此时**仍在用旧规则服务**，
	// 这一句必须让界面说得出，否则用户以为新规则已经生效了。
	ReloadErr string `json:"reloadErr"`
}

// RefreshProviders 无视周期，把每条订阅各拉一次。
//
// 没在跑就直接报错而不是返回空报告：空报告在界面上与"拉了、什么都没变"
// 是同一个样子，而那两件事差得远。
func (s *Service) RefreshProviders(ctx context.Context) (ProviderRefreshReport, error) {
	s.mu.Lock()
	up := s.providers
	s.mu.Unlock()
	if up == nil {
		return ProviderRefreshReport{}, fmt.Errorf("代理没在跑，没有订阅循环可拉")
	}
	rep := ProviderRefreshReport{Results: []ProviderRefresh{}}
	anyChanged := false
	for _, o := range up.RefreshNow(ctx) {
		rep.Results = append(rep.Results, ProviderRefresh{Name: o.Name, Changed: o.Changed, Err: o.Err})
		anyChanged = anyChanged || o.Changed
	}
	if !anyChanged {
		return rep, nil
	}
	// 与后台循环同一句话：内容变了就重载，重载失败保留旧规则。
	if err := s.Reload(); err != nil {
		rep.ReloadErr = err.Error()
		return rep, nil
	}
	rep.Reloaded = true
	return rep, nil
}
