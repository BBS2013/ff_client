package service

import (
	"fmt"
	"net/netip"
	"strings"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/outbound"
)

// nodeDialer 按节点名造一只出站，是规则里 node= 那条路的唯一实现入口。
//
// 懒建：没被任何规则钉住的节点不该白占一条隧道（每只 hysteria2 客户端都带着
// 自己的 QUIC 状态与心跳）。造出来的一只由 outbound.Set 缓存，
// 停机、换配置时由 Set.Close / DropNode 收尾。
func (s *Service) nodeDialer(name string) (outbound.Conn, error) {
	s.mu.Lock()
	cfg, resolve, to := s.cfg, s.resolve, s.handshakeTO
	split := s.split
	s.mu.Unlock()
	if cfg == nil {
		return nil, fmt.Errorf("规则把流量钉到节点 %s，但配置还没装配好", name)
	}
	var srv *config.ServerConfig
	for i := range cfg.Proxies {
		if cfg.Proxies[i].Name == name {
			srv = &cfg.Proxies[i].Server
			break
		}
	}
	if srv == nil {
		// 报错而不是改用当前活动节点：用户钉它正因为不想让它去别处，
		// 悄悄换个节点走出去是拿别人的出口干这件事（见 GetNode 同一条理由）。
		return nil, fmt.Errorf("规则把流量钉到节点 %s，而配置里没有这个名字", name)
	}
	if resolve == nil {
		// 兜底与测速那条路一致：解析节点域名必须走直连 DNS，
		// 否则 TUN 开着时会把自家网卡的假 IP 当节点地址去拨。
		r, err := newResolver(cfg)
		if err != nil {
			return nil, err
		}
		resolve = r
	}
	return outbound.New(*srv, to, resolve, fakeRange(cfg), split)
}

// dropPinnedNodes 丢掉固定节点那批临时出站并关掉它们。没在跑就什么都不做。
func (s *Service) dropPinnedNodes() {
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()
	if rt == nil {
		return
	}
	rt.DropPinnedNodes()
}

// stageActive 按「active 改成 name 之后」的当前配置装配一只候选出站，不改任何东西。
// 服务没在跑时返回 (nil, nil)：没有正在使用的出站需要换，下一次 Start 自然读新配置。
//
// 分成「先装配、再落盘」两步是为了堵住一个自相矛盾的状态：装配要解析节点域名，
// 是会失败的，而 active 一旦写进配置就收不回来。先落盘再装配的话，
// 失败那一刻快照里的 ActiveProfile/Server 说的是新节点，
// Connected/ProxyStatus 却还挂在旧节点上，流量也真的还在走旧节点——
// 界面显示"已切换"，实际什么都没切。
func (s *Service) stageActive(name string) (outbound.Conn, error) {
	s.mu.Lock()
	rt, cfg, resolve, split := s.rt, s.cfg, s.resolve, s.split
	s.mu.Unlock()
	if rt == nil || cfg == nil {
		return nil, nil
	}
	cand := *cfg // 浅拷贝够用：只改 Active，节点列表照原样读
	cand.Active = name
	proxy, err := outbound.New(cand.ActiveServer(), s.handshakeTO, resolve, fakeRange(&cand), split)
	if err != nil {
		return nil, fmt.Errorf("装配节点 %q 失败: %w", name, err)
	}
	return proxy, nil
}

// commitProxy 把 stageActive 装配好的那只换成正在使用的 PROXY 出站，
// 不动监听、规则、协议栈、网卡与路由——换节点改变的只有「出口是谁」。
//
// 以前这里走的是整块重启：TUN 在跑时要拆了重建（含多次 sudo 与二十来条
// ip/iptables），点一下「选用」要等两三秒，界面上看就是卡死，
// 还顺手把正在传的、与新节点毫无关系的连接全打断。
//
// 出站的构造在这两个方法里都落在第一个临界区之外：它要解析节点域名（最长 5s），
// 抱着 s.mu 做网络解析，面板每次状态轮询都会排在这条锁后面——那等于把卡顿
// 从"重启网卡"换成"等 DNS"，问题没走。
func (s *Service) commitProxy(proxy outbound.Conn) error {
	s.mu.Lock()
	rt, cfg := s.rt, s.cfg
	strictRunning := s.tun != nil && s.tun.Status().Running && cfg != nil && cfg.TUN.StrictRoute
	s.mu.Unlock()
	if rt == nil || cfg == nil || proxy == nil {
		// 没在跑，或者压根不需要换：新 active 已经在磁盘上，下次 Start 自然用它。
		if proxy != nil {
			_ = proxy.Close()
		}
		return nil
	}
	if strictRunning {
		// strict_route 的防环路路由钉的是「当前节点的 IP」，换节点必须重算，
		// 这一条只能整块重启。慢，但 strict_route 是默认关闭的实验特性。
		_ = proxy.Close()
		logx.Infof("strict_route 已启用：换节点要重算绕过路由，走整块重启")
		return s.Start()
	}

	srv := cfg.ActiveServer()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt != rt {
		// 期间被 Stop/Start 过一轮：新路由器已经按新配置装配好了，这次作废。
		_ = proxy.Close()
		return nil
	}
	// 节点名与出站一起交出去：按节点算用量靠的就是这一刻对上号。
	old, err := s.rt.SwapProxy(proxy, cfg.Active)
	if err != nil {
		_ = proxy.Close()
		return err
	}
	s.proxy = proxy
	if old != nil {
		_ = old.Close()
	}
	// 解析器的隧道入口要跟着换：旧隧道已经关了，而且换节点就是换问 DNS 的位置。
	s.bindTunnelResolver(cfg, proxy)
	logx.Infof("已切到节点 %s（%s · %s），监听与网卡未受影响", cfg.Active, srv.Protocol(), srv.Addr)
	return nil
}

// fakeRange 把配置里的假 IP 段变成「节点地址不许落在这里」的判据。
// 解析不出来时返回零值（不额外拦）：假 IP 段没配或写错，自有配置校验去报，
// 这里不该再制造第二种错误。
func fakeRange(cfg *config.Config) netip.Prefix {
	if cfg == nil {
		return netip.Prefix{}
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(cfg.TUN.FakeIPRange))
	if err != nil {
		return netip.Prefix{}
	}
	return p
}
