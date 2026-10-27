package service

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/dnsx"
	"wps_app/internal/logx"
	"wps_app/internal/rules"
	"wps_app/internal/rulesub"
)

// ruleResolverFor 挑规则判定用的解析入口。
func ruleResolverFor(cfg *config.Config, base *dnsx.Resolver) rules.Resolver {
	if cfg.DNS.TunnelResolveOn() {
		return tunnelResolver{r: base}
	}
	return base
}

// buildProviders 按配置组装订阅列表。一条配错的订阅只记警告，
// 它不该让已经配好的那几条也一起消失，更不该拖垮整个启动。
func buildProviders(cfg *config.Config, geo rules.GeoLookup, resolver rules.Resolver) (*rulesub.Updater, []string) {
	up := rulesub.New(geo, resolver, rulesub.WithRulesDir(filepath.Dir(cfg.RulesFile)))
	var rejected []string
	for _, p := range cfg.RuleProviders {
		if !p.IsEnabled() {
			continue
		}
		name := strings.TrimSpace(p.Name)
		if err := up.Add(name, strings.TrimSpace(p.URL), cfg.ProviderPath(p), p.Every()); err != nil {
			rejected = append(rejected, err.Error())
			logx.Warnf("规则集订阅未启用: %v", err)
		}
	}
	return up, rejected
}

// prefetchProviders 在加载规则之前把「本地还没有」的缓存补齐。
//
// 给一个明确的短预算：远端不可达时等再久也拉不到，而这期间面板一直是「启动中」。
// 拉不到就返回，让服务按现有（本地那部分）规则继续跑。
func prefetchProviders(cfg *config.Config, geo rules.GeoLookup, resolver rules.Resolver) {
	up, _ := buildProviders(cfg, geo, resolver)
	if up.Len() == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if n := up.RefreshMissing(ctx); n > 0 {
		logx.Infof("规则集订阅：启动前补齐了 %d 份缓存", n)
	}
}

// startRuleProviders 起规则集订阅的后台循环。
//
// 配置里一条可用的订阅都没有就什么都不做——绝大多数用户不需要这个功能，
// 不该为它常驻一个 goroutine 和一个定时器。
func (s *Service) startRuleProviders(cfg *config.Config) {
	if cfg == nil || len(cfg.RuleProviders) == 0 {
		return
	}
	s.mu.Lock()
	geoRef, resolve := s.geoRef, s.resolve
	s.mu.Unlock()

	up, rejected := buildProviders(cfg, geoRef, resolve)
	if up.Len() == 0 {
		s.mu.Lock()
		s.providerErrs = rejected
		s.mu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.rulesubCancel = cancel
	// 存下来是给面板看的：不存的话，"订阅配了几条、上次拉到什么时候、
	// 为什么少了一条"这些问题只有日志答得出，而日志是最后手段。
	s.providers, s.providerErrs = up, rejected
	s.mu.Unlock()

	logx.Infof("规则集订阅已启用：%d 条", up.Len())
	go up.Run(ctx, func() {
		// 重载路径与 SIGHUP 一样：失败时保留旧规则继续服务。
		if err := s.Reload(); err != nil {
			logx.Warnf("订阅更新后重载规则失败，继续用旧规则: %v", err)
		}
	})
}

// stopRuleProviders 停掉订阅循环。已经停过就什么都不做。
func (s *Service) stopRuleProviders() {
	s.mu.Lock()
	cancel := s.rulesubCancel
	s.rulesubCancel = nil
	s.providers, s.providerErrs = nil, nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}
