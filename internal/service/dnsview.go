package service

import (
	"context"
	"net/netip"

	"wps_app/internal/config"
	"wps_app/internal/dnsx"
	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

// tunnelResolver 让「IP/GEOIP 规则触发的那次解析」从节点的视角问上游。
//
// 为什么值得单开一个类型而不是给 rules.Resolver 加个路径参数：
// 规则引擎不该知道自己要的 IP 是从哪儿问来的，那是部署决策不是匹配语义。
// 它继续只问「这个域名解析成什么」，视角由这里替它选。
//
// **但这个视角默认不用**（dns.TunnelResolve 默认关）。原以为「从节点侧问上游
// 能避开污染，于是 GEOIP,CN 能判得更准」，2026-10-16 实测证明是反的：
// geo-CDN 按提问者位置给答案，节点视角给出的中国域名往往是**海外**地址，
// 于是 `GEOIP,CN,DIRECT` 判不中、国内流量白绕一圈隧道。
// 完整数据见 config.DNSConfig.TunnelResolve 的注释。
//
// 保留这条路径而不是删掉，因为有一类场景它确实对：
// 当你打算**把这个 IP 直接送进隧道**时，该问的就是"从隧道那头看不看得见"，
// 那时节点视角才是正确的视角。等 UDP 与远端解析的边界理清后可能用得上。
//
// 一条必须留住的边界：拨节点之前先要解析节点地址，那时隧道还不存在，
// 所以 outbound.HostResolver 用的始终是 dnsx.Resolver 的直连入口（LookupIP），
// 只有这里的调用会走隧道。
type tunnelResolver struct {
	r *dnsx.Resolver
}

// 编译期就固化住「本类型只服务规则判定」这件事，
// 免得哪天被当成通用解析器递给需要直连语义的调用方。
var _ rules.Resolver = tunnelResolver{}

func (t tunnelResolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return t.r.LookupIPVia(ctx, host, dnsx.PathTunnel)
}

// bindTunnelResolver 把解析器的隧道入口换到当前出站。
//
// 换节点之后必须重新绑定，两件事都会出错：
//
//	旧隧道可能已经被关掉，继续用它拨 DNS 只会超时；
//	不同地区的节点问同一个上游会得到不同归属，缓存里的旧视角会悄悄改变判定。
//	  dnsx 在 SetTunnel 里递增代数来作废这类缓存，这里负责真的调它。
func (s *Service) bindTunnelResolver(cfg *config.Config, proxy outbound.Conn) {
	if cfg == nil || proxy == nil || s.resolve == nil {
		return
	}
	if !cfg.DNS.TunnelResolveOn() {
		// 关掉了就明确解绑，而不是留着上一条隧道：
		// 否则「配置说不用隧道」和「实际还在经隧道问 DNS」会同时成立。
		s.resolve.SetTunnel(nil)
		return
	}
	s.resolve.SetTunnel(proxy.DialContext)
}
