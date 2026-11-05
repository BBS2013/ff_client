package service

import (
	"time"

	"wps_app/internal/config"
	"wps_app/internal/dnsx"
)

// newResolver 按配置装配解析器。
//
// 三个装配点（主服务、节点测速、规则里的 node= 固定节点）都必须走这里：
// 解析器一旦分层不一致，就会出现「规则判定看到的地址」与「实际拨的地址」不是同一批——
// 那正是 dnsx 的 WithResolver 注释里记过一次的问题（见 outbound/direct.go）。
// 分三处各写一遍 `dnsx.New(...)`，漏一处就会让内网域名在其中一条路上复发。
//
// 内网分层（internal_servers + internal_domains）是可选的：
// 没配就与从前完全一致（只有公网上游）。
func newResolver(cfg *config.Config) (*dnsx.Resolver, error) {
	timeout := cfg.DNS.Timeout.Duration
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ttl := cfg.DNS.Cache.Duration
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if !cfg.DNS.InternalEnabled() {
		return dnsx.New(cfg.DNS.Servers, timeout, ttl)
	}
	return dnsx.NewWithInternal(cfg.DNS.Servers, cfg.DNS.InternalServers, cfg.DNS.InternalDomains, timeout, ttl)
}
