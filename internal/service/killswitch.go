// 故障断网保护的装配层。
//
// 这一层只做三件事：判断该不该动闸门、算出放行名单、把动作串行起来。
// 规则本身在 tunx.PlanKill 里，执行在哪一侧由 TUN 的 helper 配置决定。
//
// 「什么时候挂」只有自动工具不敢替用户决定，所以它的入口只有两个：
// 自动切换放弃的那一刻（见 failover.go），以及配置里明确开了这道保护。
// 「什么时候放行」则必须宽：任何一条经当前节点建起来的连接都算，
// 因为那道闸门一旦关上而没人负责打开，症状是「网络一直断着」——
// 比原来那个坏节点更难查，也更容易被归错给软件本身。
package service

import (
	"context"
	"net"
	"slices"
	"strings"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/outbound"
	"wps_app/internal/tunx"
)

// killSwitch 是故障断网保护需要的三个动作。生产实现就是那块 *tunx.TUN。
type killSwitch interface {
	ArmKill(context.Context, []string) error
	DisarmKill() error
	Kill() tunx.KillState
}

const (
	// killOpTimeout 是挂/摘保护本身的时间上限。它比一次候选节点试拨短：
	// 挂闸门这件事不该把整轮自动切换拖长。
	killOpTimeout = 12 * time.Second
	// killResolveTimeout 是算白名单时给每个节点域名的解析时间。
	// 故障现场多半解析不出东西，等久了只是让闸门晚一点落下。
	killResolveTimeout = 3 * time.Second
)

// armKill 挂上故障断网保护。why 只用来写日志：用户要能对上「哪一下触发了它」。
//
// 没开配置时这里一条规则都不动——这道保护是默认关闭的，
// 而它动的东西是本机所有出站。
func (s *Service) armKill(why string) {
	s.mu.Lock()
	cfg, tun := s.cfg, s.killOp
	s.mu.Unlock()
	if cfg == nil || !cfg.TUN.KillSwitch {
		return
	}
	if tun == nil {
		// 这一句必须说出口：用户开了保护、故障也发生了，却没有 TUN 可以挂闸门。
		// 默默不做是最坏的写法——界面上看起来「保护是开着的」。
		logx.Warnf("故障断网保护未生效：TUN 没有运行，挂不上闸门（%s）", why)
		return
	}
	// 串行：一轮故障里每一次拨号失败都会想挂一次（成因见 roundCooldown 那段），
	// 而每一次都要付一趟 helper 往返。
	s.killMu.Lock()
	defer s.killMu.Unlock()
	allow := s.killAllowList(cfg)
	key := strings.Join(slices.Sorted(slices.Values(allow)), "|")
	if tun.Kill().Armed && key == s.killAllowKey {
		// 已经挂着、名单也没变：重挂同一份规则不会更保险，只会闪断一次放行。
		return
	}
	// 名单变了就必须重挂。这一条看着多余，却是那道闸门唯一能自己松开的机会：
	// 挂上那一刻某个节点的域名没解析出来，它就不在白名单里，
	// 于是自动切换试拨它会被我们自己的 DROP 拒掉——保护把自己锁成了永久故障。
	ctx, cancel := context.WithTimeout(context.Background(), killOpTimeout)
	defer cancel()
	if err := tun.ArmKill(ctx, allow); err != nil {
		// 「未生效」三个字必须出现在日志里，也要出现在界面上：
		// 一道没装成功的保护，和最危险的那种状态在用户眼里长得一样。
		logx.Warnf("故障断网保护未生效（%s）: %v", why, err)
		return
	}
	s.killAllowKey = key
	st := tun.Kill()
	logx.Warnf("故障断网保护已挂上（%s）：本机出站只放行节点、DNS 上游与本地网段，其余丢弃（补充放行 %d 个地址）",
		why, len(allow))
	if st.Reason != "" {
		logx.Warnf("保护只挂上了一半，另一族没有覆盖：%s", st.Reason)
	}
}

// disarmKill 摘掉保护。没挂过时它什么都不做，包括不做一次没有意义的 helper 往返。
func (s *Service) disarmKill(why string) {
	s.mu.Lock()
	tun := s.killOp
	s.mu.Unlock()
	if tun == nil || !tun.Kill().Armed {
		return
	}
	s.killMu.Lock()
	defer s.killMu.Unlock()
	// 再问一次：拿到 killMu 之前可能已经有别的路径摘过了。
	if !tun.Kill().Armed {
		return
	}
	if err := tun.DisarmKill(); err != nil {
		// 这条路径上的失败比挂上失败更该喊出来：闸门还压着，而流量本来已经通了。
		logx.Warnf("故障断网保护没能解除，本机出站可能仍被限制（%s）: %v", why, err)
		return
	}
	logx.Infof("故障断网保护已解除（%s）", why)
}

// observeDialOK 实现 router.RecoverObserver：一次成功的拨号就是「节点又通了」。
//
// 判据与 observeDialFault 对称，也因此同样只认当前活动节点：旧出站迟到的成功
// 不能替新节点宣布恢复。
func (s *Service) observeDialOK(d outbound.Dialer) {
	s.mu.Lock()
	enabled := s.cfg != nil && s.cfg.TUN.KillSwitch
	tun := s.killOp
	// 绝大多数调用在这里就回去了：保护没挂着时，一条成功连接不该换来一趟
	// 摘链往返，而这条路径每条连接都要走一遍。
	armed := tun != nil && tun.Kill().Armed
	// 只认当前活动节点（与 observeDialFault 同一条判据）：旧出站迟到的成功
	// 不能替新节点宣布恢复。
	current := d != nil && outbound.Dialer(s.proxy) == d
	s.mu.Unlock()
	if !enabled || !armed || !current {
		return
	}
	// 闸门要开，但不能抱着 s.mu 去动 iptables——那会让面板轮询集体卡住。
	go s.disarmKill("节点已恢复正常")
}

// killAllowList 汇总「所有节点的端点地址」，不只是当前活动那一个。
//
// 这是这道保护最容易把自己锁死的地方：白名单里只有活动节点时，自动切换去试拨
// 备用节点会被我们自己的 DROP 拒掉，而报错和「备用节点也死了」一模一样——
// 「故障保护」就此变成「永远恢复不了」。
//
// 域名必须当场解析：节点换 IP 是常事，只收字面量等于把真节点锁在门外。
// 解析不出来的那一个会少一条放行规则，这件事要写进日志而不是静默跳过，
// 否则现场看到的又是一个「节点明明活着却连不上」。
func (s *Service) killAllowList(cfg *config.Config) []string {
	s.mu.Lock()
	resolve := s.resolve
	s.mu.Unlock()
	if cfg == nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Proxies))
	seen := make(map[string]bool, len(cfg.Proxies))
	var domains []string
	add := func(addr string) {
		if addr == "" || seen[addr] {
			return
		}
		seen[addr] = true
		out = append(out, addr)
	}
	for _, p := range cfg.Proxies {
		host, _, err := net.SplitHostPort(p.Server.Addr)
		if err != nil {
			host = p.Server.Addr
		}
		if host == "" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			add(ip.String())
			continue
		}
		if !slices.Contains(domains, host) {
			domains = append(domains, host)
		}
	}
	if len(domains) == 0 {
		return out
	}
	if resolve == nil {
		logx.Warnf("故障保护白名单要解析 %d 个节点域名，但解析器不在：这些节点可能不会被放行", len(domains))
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), killResolveTimeout)
	defer cancel()
	for _, host := range domains {
		addrs, err := resolve.LookupIP(ctx, host)
		if err != nil {
			logx.Warnf("故障保护白名单解析节点域名 %s 失败，这一路不会被放行: %v", host, err)
			continue
		}
		for _, a := range addrs {
			add(a.String())
		}
	}
	return out
}
