package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/dnsx"
	"wps_app/internal/logx"
	"wps_app/internal/tunx"
)

// startTUN 建起 TUN 入站。刻意不持有 s.mu：tunx.Start 会解析域名并执行
// ip/iptables 与提权 helper，最长 20 秒。
func (s *Service) startTUN(cfg *config.Config) error {
	s.mu.Lock()
	if s.tun != nil && s.tun.Status().Running {
		s.mu.Unlock()
		return nil
	}
	if s.rt == nil || s.resolve == nil {
		s.mu.Unlock()
		return fmt.Errorf("服务未装配，无法启动 TUN")
	}
	rt, resolve, reg := s.rt, s.resolve, s.reg
	s.mu.Unlock()

	// 先把"没端到端验过"的组合说在前面：TUN 不通时，用户第一步该换的是
	// 有证据的那条路，而不是从 DHCP 开始怀疑。
	for _, note := range tunx.CapabilityNotes(cfg) {
		logx.Warnf("%s", note)
	}

	t, err := tunx.New(tunx.Options{
		Conf:   cfg.TUN,
		Router: rt,
		Lookup: resolve.LookupIP,
		Reg:    reg,
		Bypass: s.selfEgressIPs(cfg, resolve),
		// Upstreams 是 iptables 放行清单：发往这些地址的 :53 查询原样放行，
		// 不被自己的劫持规则改写。
		//
		// 内网上游必须一起列进来——否则解析器问公司 DNS 的那条查询会被
		// 自己劫持到 tun 的 DNS 上，形成"问自己"的环（route.go 的 RETURN 规则
		// 只按这份清单放行）。公网上游原本就在清单里，内网上游是新增的那一半。
		// 清单与 strict_route 的绕行路由共用 resolverUpstreamHosts，
		// 免得"两处该一致"只靠注释守着（那里漏过内网那一半）。
		Upstreams: resolverUpstreamHosts(cfg),
		// 接管系统解析器那笔账落在配置文件旁边：换配置文件就等于换一台机器的账本。
		// 而这份清单（公网+内网上游）正是劫持收不到查询时要去核对的那一半，
		// 两者由同一个配置推导，不该在两个地方各写一遍。
		ConfigPath: s.ConfigPath(),
		// 网络从坏变好时把出口的退避清零：见 Options.OnNetworkRecovered。
		OnNetworkRecovered: s.resetOutboundBackoff,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := t.Start(ctx); err != nil {
		// 句柄留着：Status 里的 LastError 是界面唯一的错误来源，
		// 丢了句柄就只剩日志里一行字。
		s.mu.Lock()
		s.tun, s.killOp = t, t
		s.mu.Unlock()
		return err
	}
	s.mu.Lock()
	s.tun, s.killOp = t, t
	s.mu.Unlock()
	return nil
}

// resetOutboundBackoff 在网络恢复时把出口节点的重连退避清零。
//
// 只清"当前生效的那一个"出站的退避——没在用的节点退避着也无所谓，
// 真用到它时自然会重连。也不动已建立的连接：隧道本来通着的话这次是空操作。
//
// 为什么这件事归 service：只有它知道当前生效的是哪个出站（会随节点切换变），
// 而 tunx/netwatch 不该知道 hysteria 长什么样。
func (s *Service) resetOutboundBackoff() {
	s.mu.Lock()
	d := s.proxy
	s.mu.Unlock()
	if d == nil {
		return
	}
	if r, ok := d.(interface{ ResetBackoff() }); ok {
		r.ResetBackoff()
	}
}

// stopTUN 拆掉 TUN。不持有 s.mu：拆除要等协议栈把连接走完并执行
// iptables 清理，实测最长 14 秒。
func (s *Service) stopTUN() error {
	s.mu.Lock()
	t := s.tun
	s.mu.Unlock()
	if t == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := t.Stop(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tun != t {
		return err
	}
	if err != nil {
		// 拆不干净就留着句柄，不要置 nil。
		// 残留的 nat 表劫持规则是一次机器级的 DNS 改写（全部 :53 被指向
		// 一块已经不在的网卡地址），句柄还在才有下一次重试拆除的机会；
		// 一旦丢掉句柄，界面上再没有任何入口能清理它，只能手敲 -tun-reset。
		return err
	}
	s.tun, s.killOp = nil, nil
	return nil
}

// selfEgressIPs 列出「我们自己要拨出去」的地址：当前节点的服务端与 DNS 上游。
// strict_route 下这些必须钉在物理路由上，否则我们发出的包会被自己的 tun 抓回去。
// 会做 DNS 解析，调用方不应持有 s.mu。
func (s *Service) selfEgressIPs(cfg *config.Config, resolve *dnsx.Resolver) []string {
	if cfg == nil {
		return nil
	}
	addr := cfg.ActiveServer().Addr
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	out := make([]string, 0, 4)
	if ip := net.ParseIP(host); ip != nil {
		out = append(out, ip.String())
	} else if resolve != nil {
		dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addrs, rerr := resolve.LookupIP(dctx, host)
		cancel()
		if rerr == nil {
			for _, a := range addrs {
				out = append(out, a.String())
			}
		} else {
			logx.Warnf("TUN: 解析代理服务端 %s 失败，strict_route 的防环路路由不完整: %v", host, rerr)
		}
	}
	for _, srv := range resolverUpstreamHosts(cfg) {
		if ip := net.ParseIP(srv); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

// resolverUpstreamHosts 列出解析器会去连的上游主机（已剥掉端口，未过滤成 IP）。
//
// 为什么要有这一处：同一份上游清单在两处被用到，而"两处该一致"这件事
// 只靠注释守着是不够的——
//   - iptables 的放行清单（tunx 的 Upstreams）：发往这些地址的 :53 原样放行，
//     否则解析器问上游的查询会被自己的劫持规则改写，形成"问自己"；
//   - strict_route 的绕行路由（selfEgressIPs）：这些地址必须钉回物理网关，
//     否则接管默认路由之后，连上游 DNS 的包也会进 tun。
//
// 以前后一处只用了 cfg.DNS.Servers（公网那一半），内网上游只进了前一处。
// 结果是在默认关闭的 strict_route 下开内网分层：公网 DNS 有绕行、内网 DNS 没有，
// 于是问公司 DNS 的查询进了 tunnel，而它恰恰是内网域名唯一能问的那条路。
// 按配置里"内网上游是公网上游之外的另一半"这个事实，两处都该是全集。
func resolverUpstreamHosts(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	all := make([]string, 0, len(cfg.DNS.Servers)+len(cfg.DNS.InternalServers))
	all = append(all, cfg.DNS.Servers...)
	all = append(all, cfg.DNS.InternalServers...)
	out := make([]string, 0, len(all))
	for _, srv := range all {
		srv = strings.TrimSpace(srv)
		if srv == "" {
			continue
		}
		h, _, err := net.SplitHostPort(srv)
		if err != nil {
			h = srv
		}
		out = append(out, h)
	}
	return out
}

// ---------- TUN ----------

// SetTUNEnabled 打开或关闭 TUN 模式，并落盘。
// 运行中会即时起/拆网卡，不需要重启整个代理。
func (s *Service) SetTUNEnabled(enable bool) error {
	if err := s.mutate(func(cfg *config.Config) error {
		cfg.TUN.Enable = enable
		return nil
	}); err != nil {
		return err
	}
	// 与 Start/Stop 串行：起/拆网卡也是长操作，不该与一次重启穿插。
	s.opMu.Lock()
	defer s.opMu.Unlock()

	s.mu.Lock()
	if s.cfg != nil {
		s.cfg.TUN.Enable = enable
	}
	running := s.running && s.rt != nil
	cfg := s.cfg
	s.mu.Unlock()

	if !running || cfg == nil {
		logx.Infof("TUN 开关设为 %v（当前未运行，启动后生效）", enable)
		return nil
	}
	if !enable {
		return s.stopTUN()
	}
	return s.startTUN(cfg)
}

// tunStatusFromConfig 用配置文件回答 TUN 的状态：还没开启、或整个服务没起来时，
// 界面照样要能看见网卡名、地址，以及「点开启之后由谁去建网卡」。
//
// 这份构造被三处共用（未运行时的快照、运行中但 TUN 未开启、TUNStatus）。
// 以前每处各写一遍字面量，Privilege 漏在两处里，面板于是把「配了 tun.helper」
// 显示成「本进程直接开（要求面板以 root 运行）」——看到这句的用户只会以为开不起来。
func tunStatusFromConfig(tc config.TUNConfig) tunx.Status {
	st := tunx.Status{
		Enabled:     tc.Enable,
		Device:      tc.Device,
		Address:     tc.Address,
		DNS:         tc.DNS,
		FakeIPRange: tc.FakeIPRange,
		HijackDNS:   tc.DNSHijackEnabled(),
		StrictRoute: tc.StrictRoute,
		// TUN 没在跑，V6Ready 只能是 false。但「用户要不要 v6」仍然要报出来——
		// 面板上这一栏是「开着的」还是「没要的」，两者的排查方向完全不同。
		IPv6:    tc.IPv6On(),
		V6Ready: false,
		// 保护「开没开」来自配置，TUN 没在跑时也一样要报——界面上
		// 「用户没要这道保护」和「要了，但现在挂不上」是两回事。
		KillEnabled: tc.KillSwitch,
		HelperCmd:   tc.Helper,
		Privilege:   "self",
		Applied:     []string{},
	}
	if len(tc.Helper) > 0 {
		st.Privilege = "helper"
	}
	return st
}

// TUNStatus 返回 TUN 当前状态（未启用时也是一个可用的零值结构）。
func (s *Service) TUNStatus() tunx.Status {
	// 同 Snapshot：磁盘读在锁外做。
	cfg := s.diskConfig()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tun != nil {
		return s.tun.Status()
	}
	if cfg != nil {
		return tunStatusFromConfig(cfg.TUN)
	}
	return tunx.Status{Applied: []string{}}
}
