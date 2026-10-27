package service

import (
	"context"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/logx"
	"wps_app/internal/outbound"
)

// 故障自动切换。
//
// 判据刻意只用「转发路径上真实发生的节点级失败」，不做主动心跳：
// 主动探测要额外拨号、要选探测目标、还会在节点其实好好的时候把探测点当成故障
// （TestProfile 就是这么把「服务端拨不通这个目标」当成节点死了的）。
// 真实流量产生的错误已经过 outbound.NodeFault 分级，剩下的只是数次数。
//
// 但这也意味着：隧道挂了而恰好没人发起新连接时，不会自动切。
// 空转的检测要主动探测，那一版的坑见下面 probeTarget 的注释。
const (
	// faultWindow 是统计窗口。窗口外的失败不作数——一次半小时前的握手超时
	// 不该在现在把节点判死。
	faultWindow = 2 * time.Minute
	// faultThreshold 是窗口内至少要有多少次节点级失败才考虑切换。
	faultThreshold = 3
	// faultDistinctHosts 要求这些失败至少来自这么多个不同目标。
	// 这一条是防误报的关键：某个网站自己挂了不算节点挂了。
	faultDistinctHosts = 2
	// switchDwell 是切到一个节点之后的最短驻留时间。
	// 每次切换都会掐掉旧隧道上所有正在传的连接（换节点 = 换隧道），
	// 来回切比卡在死节点上更糟——README 里记过一次每分钟 6-14 次重连的事故。
	switchDwell = 5 * time.Minute
	// candidateTimeout 是给每个候选节点做一次握手的时间上限。
	candidateTimeout = 8 * time.Second
	// roundCooldown 是两轮自动切换之间的最短间隔，不论上一轮成没成。
	//
	// 触发源是转发路径上的拨号失败，而节点死掉的时候这个数不是「三次」而是
	// 「每秒几十次」：判据一旦满足，每一次失败都会 go 一个新 goroutine 去跑整轮，
	// 每轮为每个候选节点付 8s 试拨。2026-10-20 线上实测：主节点 10:52:47 掉线、
	// 唯一备节点也握不上手，2 分钟内打了 5 轮（10:52:49 / 10:53:21 / 10:53:39 /
	// 10:54:04 / 10:54:39），每一轮结论都一样「所有候选节点都试过了，保持现状」。
	// 这些轮次只是在抢 CPU 与往日志里灌水，换不来任何一个可用节点。
	//
	// 60s 比 switchDwell 宽：上一轮全失败时本来也切不动（dwell 只在切成功时起算），
	// 所以这条只会推迟「坏节点被再试一次」，不会推迟任何一次真正的切换。
	roundCooldown = 60 * time.Second
)

// nodeFault 是一个节点的节点级失败流水。
type nodeFault struct {
	// 时间与目标成对存放：只有次数会分不清「三个网站都连不上」和
	// 「同一个网站试了三次」，而这两种情况的结论完全相反。
	stamps []faultStamp
}

type faultStamp struct {
	at     time.Time
	target string
}

// observeDialFault 实现 router.FaultObserver：攒下节点级失败，够了就动手。
//
// 这个方法在每条拨号失败路径上都会被调用，所以它必须只做记账：
// 真正的切换放到一个独立的 goroutine 里做——它会解析域名、握手候选节点、
// 还可能在 strict_route 下触发整块重启，抱着 s.mu 做这些等于让面板轮询集体卡死。
func (s *Service) observeDialFault(target string, d outbound.Dialer, err error) {
	if !outbound.ReportNodeFailure(d, err) {
		// 目标被拒、调用方超时、直连出站的失败都到不了下面——
		// 尤其是直连：那是用户自己的网络，不是节点的错。
		return
	}
	// 只统计当前活动节点。路由器里的 PROXY 出站可能已经被换掉了，
	// 旧出站迟到的错误不该记在新节点头上。
	s.mu.Lock()
	if d == nil || outbound.Dialer(s.proxy) != d {
		s.mu.Unlock()
		return
	}
	cfg := s.cfg
	name := s.activeNameLocked(cfg)
	if name == "" {
		s.mu.Unlock()
		return
	}
	ready := s.recordFaultLocked(name, target)
	s.mu.Unlock()

	if !ready {
		return
	}
	go s.tryFailover(name)
}

// recordFaultLocked 记一次失败并判断是否够格触发切换。必须在 s.mu 下调用。
func (s *Service) recordFaultLocked(name, target string) bool {
	if s.faults == nil {
		s.faults = make(map[string]*nodeFault)
	}
	f := s.faults[name]
	if f == nil {
		f = &nodeFault{}
		s.faults[name] = f
	}
	cutoff := time.Now().Add(-faultWindow)
	f.stamps = append(f.stamps, faultStamp{at: time.Now(), target: strings.TrimSpace(target)})
	keep := f.stamps[:0]
	for _, st := range f.stamps {
		if st.at.After(cutoff) {
			keep = append(keep, st)
		}
	}
	f.stamps = keep
	if len(f.stamps) < faultThreshold {
		return false
	}
	hosts := make(map[string]bool)
	for _, st := range f.stamps {
		if st.target != "" {
			hosts[st.target] = true
		}
	}
	return len(hosts) >= faultDistinctHosts
}

// tryFailover 在另一个 goroutine 里把活动节点换掉。
//
// 锁的次序很要紧：这里不得持 opMu（Start 可能抱着它 35s 以上），
// 也不得持 mu 跨 over 网络的操作；commitProxy 自己会再拿 mu，
// 而 strict_route 那条路会走到 Start（拿 opMu）——抱着 opMu 进来就是自死锁。
//
// 进来先过三道门，全都在 mu 下面判定并当场认领这一轮：
// 迟滞（dwell）、单飞（busy）、轮次冷却（roundCooldown）。
// 认领必须和判定在同一把锁里：两个 goroutine 先各自读完再各自置位，
// 结果是两轮同时跑、各自为同一个候选节点付一次 8s 试拨。
func (s *Service) tryFailover(from string) {
	s.mu.Lock()
	cfg := s.cfg
	if cfg == nil || len(cfg.Proxies) < 2 {
		s.mu.Unlock()
		return // 只有一个节点时切了也没处切
	}
	dwellOK := s.switchedAt.IsZero() || time.Since(s.switchedAt) >= switchDwell
	roundOK := !s.failoverBusy &&
		(s.failoverRoundAt.IsZero() || time.Since(s.failoverRoundAt) >= roundCooldown)
	if !dwellOK {
		s.mu.Unlock()
		logx.Debugf("距上次自动切换不足 %v，暂不再切（避免来回掐断正在传的连接）", switchDwell)
		return
	}
	if !roundOK {
		// 上一轮还在跑、或者刚跑完不到 roundCooldown。这一轮的结论不会变：
		// 候选节点不会因为多问了一次就忽然能握手，所以这里连日志都不灌。
		s.mu.Unlock()
		return
	}
	cooling := make(map[string]time.Time, len(s.cooling))
	for k, v := range s.cooling {
		cooling[k] = v
	}
	s.failoverBusy = true
	s.failoverRoundAt = time.Now()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.failoverBusy = false
		s.mu.Unlock()
	}()

	candidates := make([]string, 0, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		if p.Name == from {
			continue
		}
		if until, ok := cooling[p.Name]; ok && time.Now().Before(until) {
			continue
		}
		candidates = append(candidates, p.Name)
	}
	if len(candidates) == 0 {
		logx.Warnf("节点 %q 连续失败但没找到可用替代品（其余节点都在冷却里）", from)
		return
	}

	for _, name := range candidates {
		proxy, err := s.stageActive(name)
		if err != nil {
			// 装配失败最常见的原因是节点域名解析不出来，那本身就是不可用。
			logx.Warnf("候选节点 %q 装不起来，跳过: %v", name, err)
			continue
		}
		s.mu.Lock()
		probe := s.probeCandidate
		s.mu.Unlock()
		if probe == nil {
			probe = probeOutbound
		}
		if err := probe(proxy); err != nil {
			_ = proxy.Close()
			logx.Warnf("候选节点 %q 试拨失败，跳过: %v", name, err)
			continue
		}
		if err := s.commitFailover(from, name, proxy); err != nil {
			_ = proxy.Close()
			logx.Warnf("自动切换到 %q 失败: %v", name, err)
			return
		}
		return
	}
	logx.Warnf("节点 %q 判定故障，但所有候选节点都试过了，保持现状", from)
}

// commitFailover 把切换落实。
//
// 默认只改内存里的 failoverOverride，不写配置文件：一次应急决定不该悄悄改掉
// 用户选的节点，而且 config.Save 每次都会覆盖 config.yaml.bak，
// 抖动几次下来用户原本的配置备份就没了。
//
// strict_route 是唯一的例外，也是唯一必须落盘的情况：那条路径只能整块重启，
// 而重启会从磁盘重读 active——不落盘的话重启一执行就把刚做的切换冲掉了。
func (s *Service) commitFailover(from, to string, proxy outbound.Conn) error {
	s.mu.Lock()
	cfg := s.cfg
	strict := cfg != nil && cfg.TUN.StrictRoute && s.tun != nil && s.tun.Status().Running
	s.mu.Unlock()

	if strict {
		// 用户已经知情：strict_route 下换节点要重算防环路路由，代价是数秒全断。
		// 这条日志必须在动手之前打，否则事后看不出这一下断流是谁引起的。
		logx.Warnf("自动切换 %s → %s：strict_route 已启用，接下来要重算绕过路由并整块重启，"+
			"期间会有数秒完全断流（这是 strict_route 换节点的唯一办法）", from, to)
		if err := s.mutate(func(c *config.Config) error {
			c.Active = to
			return nil
		}); err != nil {
			return fmt.Errorf("strict_route 下切换要写回 active: %w", err)
		}
	}

	s.mu.Lock()
	if !strict {
		s.failoverOverride = to
	}
	s.switchedAt = time.Now()
	// 刚放弃的节点冷却 dwell 这么久：不然一轮失败就把它切回去，来回掐。
	if s.cooling == nil {
		s.cooling = make(map[string]time.Time)
	}
	s.cooling[from] = time.Now().Add(switchDwell)
	// 切换成功了，节拍就此交回 switchDwell（它比 roundCooldown 长得多，而且是按
	// "上一次真切换"算的）。不清这一条的话，一台机器上同时挂着两道门：
	// dwell 过期了但 roundAt 没过，症状是"自动切换再也不工作"，谁也想不到是这里。
	s.failoverRoundAt = time.Time{}
	// 新节点的流水清零，它才开始被单独计数。
	delete(s.faults, to)
	s.mu.Unlock()

	if err := s.commitProxy(proxy); err != nil {
		return err
	}
	logx.Infof("已自动切换节点 %s → %s（%s 连续 %d 次节点级失败）",
		from, to, from, faultThreshold)
	return nil
}

// probeOutbound 用刚装配好的出站做一次真实建链，验它能不能出海。
//
// 目标选 www.gstatic.com:443：节点拨不通它会被 isTargetRefused 判成
// 「目标问题」而不是节点问题吗？不会——这里的判据是反的，我们要的是
// 「这只出站能不能把一条连接建起来」，所以任何错误都算失败。
// 只在候选之间做一次性比较时才用它，别把它当健康信号长期采。
func probeOutbound(d outbound.Dialer) error {
	ctx, cancel := context.WithTimeout(context.Background(), candidateTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, net.JoinHostPort(probeHost, "443"))
	if err != nil {
		return err
	}
	return conn.Close()
}

// probeHost 是候选节点的一次性试拨目标。
const probeHost = "www.gstatic.com"

// activeNameLocked 返回本次运行真正生效的节点名。必须在 s.mu 下调用。
func (s *Service) activeNameLocked(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if s.failoverOverride != "" {
		for _, p := range cfg.Proxies {
			if p.Name == s.failoverOverride {
				return p.Name
			}
		}
		// override 指向的节点已经不在了（多半是刚被删掉）：把它丢掉，
		// 别让整个服务对着一个不存在的名字判断健康。
		s.failoverOverride = ""
	}
	return cfg.Active
}

// activeServerFor 按本次运行生效的 active 取节点参数。
// cfg 为 nil 时返回零值，让调用方自己决定怎么报错。
func activeServerFor(cfg *config.Config, override string) (config.ServerConfig, string) {
	if cfg == nil {
		return config.ServerConfig{}, ""
	}
	if override != "" {
		for _, p := range cfg.Proxies {
			if p.Name == override {
				return p.Server, p.Name
			}
		}
		// 节点已被删除：override 失效，安静回落到配置里的值，
		// 而不是让启动失败——配置文件说的那个节点还在，能出海。
	}
	return cfg.ActiveServer(), cfg.Active
}

// faultSummary 给快照用：当前活动节点在窗口内的失败次数与不同目标。
func (s *Service) faultSummary(name string) (count int, hosts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.faultSummaryLocked(name)
}

// faultSummaryLocked 是 faultSummary 的本体。必须在 s.mu 下调用。
//
// 界面上「为什么它自己切了节点」必须能问出来，否则用户只会觉得软件在乱动。
func (s *Service) faultSummaryLocked(name string) (count int, hosts []string) {
	f := s.faults[name]
	if f == nil {
		return 0, nil
	}
	cutoff := time.Now().Add(-faultWindow)
	seen := map[string]bool{}
	for _, st := range f.stamps {
		if st.at.After(cutoff) {
			count++
			if st.target != "" {
				seen[st.target] = true
			}
		}
	}
	return count, slices.Sorted(maps.Keys(seen))
}
