// Package dnsx 提供多上游 DNS 解析与 TTL 缓存，同一个上游可以按直连或隧道两条路径问。
package dnsx

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"wps_app/internal/logx"
)

// graceWindow 已经拿到一份结果后，等待另一份（AAAA）多久就放弃。
const graceWindow = 250 * time.Millisecond

// maxCacheEntries 是缓存条目上限。缓存本身只在命中时清理过期项，
// 而查得越多域名它就越大——长时间运行的客户端（TUN 模式尤其明显）
// 没有上界就会一直涨下去。
const maxCacheEntries = 4096

type cacheEntry struct {
	addrs  []netip.Addr
	expire time.Time
}

type call struct {
	done  chan struct{}
	path  Path
	addrs []netip.Addr
	err   error
}

// Path 是一次解析从哪儿发起。
type Path int

const (
	// PathDirect 从本机直接问上游。节点地址必须走这条路（见 SetTunnel 的说明），
	// 它也是 LookupIP 的默认路径，等价于加这个参数之前的全部行为。
	PathDirect Path = iota
	// PathTunnel 经当前 PROXY 出站去问同一批上游。
	// 上游没换，换的是发起位置：伪造 IP 是本机到上游那条路径上的产物，
	// 从隧道另一侧问同一个上游，拿回来的就是真答案。
	PathTunnel
)

func (p Path) String() string {
	if p == PathTunnel {
		return "tunnel"
	}
	return "direct"
}

// TunnelDial 拨一个上游地址（"223.5.5.5:53"），拿到一条流式连接。
// 由服务层注入，因为「当前用哪只出站」是服务层的状态，解析器不该知道。
type TunnelDial func(ctx context.Context, addr string) (net.Conn, error)

// Resolver 并发安全。
//
// 默认所有查询都直连上游；只有显式按 PathTunnel 取才会走隧道。
// 反过来说，任何一条「不知道该选哪条路」的调用都该用 PathDirect：
// 节点地址、上游地址本身、以及一切在隧道建立之前就要完成的事。
type Resolver struct {
	servers []string
	timeout time.Duration
	ttl     time.Duration

	// internalServers 是「内网专用」的上游，与 servers 分开。
	//
	// 为什么要分开：公司内网的 DNS 对外网域名是会污染的（实测 www.google.com
	// 被答成 157.240.7.20，落在 Facebook 段），而公网 DNS 对内网域名同样答不对
	// （yfjira.mychery.com 被答成华为云 WAF 的公网入口 123.60.194.157，
	// 拨过去只会拿到 418 拦截页）。两边各错一半，混在一个列表里互相竞速，
	// 结果就是同一份配置在 1/3 的时间里不可用。
	//
	// 分层之后：内网域名的答案只从内网上游取，公网域名的答案只从公网上游取，
	// 不存在竞速，也就不存在"看运气"。代价是要能判断"这个域名算不算内网"——
	// 那由调用方通过 domain_suffixes 给出，不在解析器里猜。
	internalServers []string
	// domainSuffixes 是走内网上游的域名后缀（小写、带前导点）。
	// 空表示不启用内网分层，所有域名都走公网上游。
	domainSuffixes []string

	// tunnel 未注入时，PathTunnel 自动退化成直连而不是报错：
	// 规则判定拿不到 IP 会退到兜底策略，那比「隧道没起来所以整个分流不干活」好。
	tunnel atomic.Pointer[TunnelDial]

	mu       sync.Mutex
	cache    map[string]*cacheEntry
	inflight map[string]*call
	// tunnelEpoch 用来让「换节点」能作废隧道路径的缓存：
	// 不同地区的节点问同一个上游会得到不同答案（尤其 GEOIP 相关的域名），
	// 切完节点还抱着旧答案，判定的依据就是上一个节点的视角。
	tunnelEpoch int64
}

// New 创建解析器。servers 为空时返回错误。
func New(servers []string, timeout, ttl time.Duration) (*Resolver, error) {
	return NewWithInternal(servers, nil, nil, timeout, ttl)
}

// NewWithInternal 创建解析器，并额外指定内网专用的上游与域名后缀。
//
// internalServers 为空时与 New 等价（不启用内网分层）。
// domainSuffixes 为空时内网上游不会被使用——没有后缀就无从判断某个域名算不算内网，
// 而"对所有域名都问内网 DNS"正是要避开的做法：内网 DNS 对外网域名是污染的。
func NewWithInternal(servers, internalServers, domainSuffixes []string, timeout, ttl time.Duration) (*Resolver, error) {
	if len(servers) == 0 {
		return nil, fmt.Errorf("dns: no upstream servers configured")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if ttl <= 0 {
		ttl = 300 * time.Second
	}
	clean := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// 容忍 "1.1.1.1" 这种省略端口的写法，补上 53。
		// 也允许写域名形式的上游，由 net.Resolver 负责解析。
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			host, port = s, "53"
		}
		clean = append(clean, net.JoinHostPort(host, port))
	}
	if len(clean) == 0 {
		return nil, fmt.Errorf("dns: no valid upstream servers")
	}
	cleanInternal := cleanServers(internalServers)
	cleanSuffix := cleanSuffixes(domainSuffixes)
	// 有内网上游却没有后缀，等于内网上游永远不会被问到——那不如直接报错，
	// 否则用户以为自己配好了内网分层，实际上它一次都没生效。
	if len(cleanInternal) > 0 && len(cleanSuffix) == 0 {
		return nil, fmt.Errorf("dns: 配了内网 DNS 上游却没有内网域名后缀，内网分层不会生效")
	}
	return &Resolver{
		servers:         clean,
		internalServers: cleanInternal,
		domainSuffixes:  cleanSuffix,
		timeout:         timeout,
		ttl:             ttl,
		cache:           make(map[string]*cacheEntry),
		inflight:        make(map[string]*call),
	}, nil
}

// cleanServers 把上游列表洗成 host:port 形式，空项丢掉。
func cleanServers(servers []string) []string {
	clean := make([]string, 0, len(servers))
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			host, port = s, "53"
		}
		clean = append(clean, net.JoinHostPort(host, port))
	}
	return clean
}

// cleanSuffixes 洗后缀列表：统一小写、补前导点、去重。
func cleanSuffixes(suffixes []string) []string {
	out := make([]string, 0, len(suffixes))
	seen := make(map[string]bool)
	for _, s := range suffixes {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !strings.HasPrefix(s, ".") {
			s = "." + s
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// SetTunnel 注入（或传 nil 清掉）隧道拨号器。
//
// 用注入而不是构造参数：隧道要等节点装配好才存在，而解析器是装配节点的前置
// ——hysteria.go:55-68 记过一次真机死锁「要起 TUN 得先解析节点、解析节点得先有可用 DNS」。
// 先有解析器、后挂隧道，那个环才解得开。
//
// 注入之后也**不能**把隧道路径当唯一路径：节点地址与上游地址本身必须永远走直连。
// 隧道没建好、节点被换掉、拨号失败，任何一种情况下解析都不能停。
func (r *Resolver) SetTunnel(dial TunnelDial) {
	if dial == nil {
		r.tunnel.Store(nil)
		return
	}
	r.tunnel.Store(&dial)
	// 挂上或换掉隧道都意味着「换一个视角问上游」，旧答案该作废。
	r.mu.Lock()
	r.tunnelEpoch++
	r.mu.Unlock()
}

// key 给缓存与合并查询加上路径维度。
//
// 少了这一维，被污染的直连答案和干净的隧道答案会互相覆盖：
// 隧道答案先到、直连随后盖上去，规则判定就退回污染结果；
// 反过来则隧道还没起来时缓存里躺着一条没人知道是从哪问来的答案。
// 隧道路径还额外带上代数：换节点等于换出口位置，旧节点问出来的归属不该继续用。
func (r *Resolver) key(path Path, host string) string {
	if path != PathTunnel {
		return host
	}
	r.mu.Lock()
	epoch := r.tunnelEpoch
	r.mu.Unlock()
	return "tunnel|" + strconv.FormatInt(int64(epoch), 10) + "|" + host
}

// LookupIP 返回 host 的 A/AAAA 结果，走直连路径。
//
// 这是 rules.Resolver 与 outbound.HostResolver 两个接口共同要求的方法，
// 保持它的原语义很重要：拨节点之前先要用它，那时隧道还不存在。
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.lookup(ctx, host, PathDirect)
}

// LookupIPVia 按指定路径解析。隧道路径失败时自动退回直连，
// 并在错误信息里如实说明退回了——规则判定宁可基于一个可能被污染的答案继续工作，
// 也不该因为隧道不通而整个不再产出结论。
func (r *Resolver) LookupIPVia(ctx context.Context, host string, path Path) ([]netip.Addr, error) {
	if path != PathTunnel {
		return r.lookup(ctx, host, PathDirect)
	}
	if r.tunnel.Load() == nil {
		// 没注入隧道拨号器：等价于直连，别制造一种「配了但没接上」的第三种状态。
		return r.lookup(ctx, host, PathDirect)
	}
	addrs, err := r.lookup(ctx, host, PathTunnel)
	if err == nil {
		return addrs, nil
	}
	direct, derr := r.lookup(ctx, host, PathDirect)
	if derr != nil {
		// 两条路都不通：报隧道的错，它才是调用方真正想要的那条。
		return nil, fmt.Errorf("dns via tunnel: %w (直连也失败: %v)", err, derr)
	}
	logx.Debugf("dns: %s 隧道解析失败(%v)，退回直连结果 %v——注意这批 IP 可能被污染", host, err, direct)
	return direct, nil
}

// normalizeHost 把调用方给的名字洗成查询名。
//
// 第二个返回值有效表示这压根不是域名、而是一个 IP 字面量——那时"解析"就是它自己。
// lookup 与 Probe 共用这一份：两处各写一遍"怎么洗名字"迟早洗出两种结果，
// 而那时缓存键就对不上，一次探测会把真查询的缓存挤到一边去。
func normalizeHost(host string) (string, netip.Addr) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if addr, err := netip.ParseAddr(h); err == nil {
		return h, addr.Unmap()
	}
	return h, netip.Addr{}
}

// ProbeResult 是一次"此刻再问一次会拿到什么"的读数。
type ProbeResult struct {
	// Host 是洗过的查询名（小写、去尾点）。
	Host string
	// Path 是这次问的路径：direct 还是 tunnel。
	Path Path
	// Addrs 是拿到的地址；解析不出是空表，不是错误之外的第三种状态。
	Addrs []netip.Addr
	// Cached 为真表示这份答案是缓存里的，没有真的出门问。
	// 它必须是后端给的事实，不能让人从"耗时 0ms"反推——那一格反推不出来 TTL。
	Cached bool
	// TtlMs 是这份答案**还剩多久**算新鲜（命中缓存就是剩余时间，刚问到的就是整条 TTL）。
	// 没有它，"命中缓存"只说"这是旧的"，却不告诉人再等多久它会自己变。
	TtlMs int64
	// Ms 是这次探测花了多久（缓存命中就是 0 附近）。
	Ms int64
}

// Probe 答"现在再查一次这个域名会拿到什么、是从哪儿拿的"。
//
// 它与 LookupIP 走的是同一份缓存与同一个键，所以这里看到的地址就是
// 规则引擎下一刻会拿去判定的那批——不是另问一遍得到的第二个真相。
func (r *Resolver) Probe(ctx context.Context, host string, path Path) (ProbeResult, error) {
	return r.probe(ctx, host, path, false)
}

// ProbeFresh 与 Probe 同一件事，但**先不看缓存**，问完把新答案写回缓存。
//
// 存在的理由很具体：报"命中缓存"之后，人下一个动作就是"那给我一份新的"——
// 而今天除了重启进程没有别的办法。写回缓存是刻意的：
// 这一按的语义就是"我认为这条缓存是脏的"，只问不看、把脏的那份留着等于没修。
// 它改的是**引擎下一刻的判定依据**，所以界面上必须把这件事说清楚（见 Rules.vue 那一格）。
func (r *Resolver) ProbeFresh(ctx context.Context, host string, path Path) (ProbeResult, error) {
	return r.probe(ctx, host, path, true)
}

func (r *Resolver) probe(ctx context.Context, host string, path Path, fresh bool) (ProbeResult, error) {
	h, literal := normalizeHost(host)
	if h == "" {
		return ProbeResult{}, fmt.Errorf("dns: empty host")
	}
	start := time.Now()
	if literal.IsValid() {
		return ProbeResult{Host: h, Path: path, Addrs: []netip.Addr{literal}, Ms: time.Since(start).Milliseconds()}, nil
	}
	if path == PathTunnel && r.tunnel.Load() == nil {
		// 没注入隧道拨号器时，要隧道也等价于直连——与 LookupIPVia 同一条规矩：
		// 别制造"配了但没接上"那种第三种状态。这里更要紧的是**报出来的是直连**：
		// 面板那格会说"这批 IP 是从节点那头问来的"，而它其实是本机问的。
		path = PathDirect
	}
	key := r.key(path, h)
	if !fresh {
		if addrs, ttl, ok := r.cacheHit(key); ok {
			return ProbeResult{
				Host: h, Path: path, Addrs: addrs, Cached: true, TtlMs: ttl,
				Ms: time.Since(start).Milliseconds(),
			}, nil
		}
	}
	addrs, err := r.resolve(ctx, h, path, fresh)
	out := ProbeResult{Host: h, Path: path, Addrs: addrs, Ms: time.Since(start).Milliseconds()}
	// 刚写进去的那份，剩余时间就是整条 TTL：这一格要说的是"多久之后它会自己变"，
	// 不是"我这次花了多久"。
	if _, ttl, ok := r.cacheHit(key); ok {
		out.TtlMs = ttl
	}
	return out, err
}

// lookup 是两条路径共用的本体。
func (r *Resolver) lookup(ctx context.Context, host string, path Path) ([]netip.Addr, error) {
	return r.resolve(ctx, host, path, false)
}

// resolve 是真正的解析。bypassCache 只跳过"读"，不跳过"写"——
// 见 ProbeFresh 的说明：手动重问的语义就是"这条缓存是脏的"。
func (r *Resolver) resolve(ctx context.Context, host string, path Path, bypassCache bool) ([]netip.Addr, error) {
	h, literal := normalizeHost(host)
	if h == "" {
		return nil, fmt.Errorf("dns: empty host")
	}
	if literal.IsValid() {
		return []netip.Addr{literal}, nil
	}
	key := r.key(path, h)

	if !bypassCache {
		if addrs := r.fromCache(key); addrs != nil {
			logx.Debugf("dns: %s(%s) 命中缓存 -> %v", h, path, addrs)
			return addrs, nil
		}
	}

	r.mu.Lock()
	if c, ok := r.inflight[key]; ok {
		// 同一域名同一路径的并发查询合并为一次。
		r.mu.Unlock()
		select {
		case <-c.done:
			return c.addrs, c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &call{done: make(chan struct{}), path: path}
	r.inflight[key] = c
	r.mu.Unlock()

	// 查询不能挂在首个调用者的 ctx 上。那个 ctx 属于一次具体的拨号
	// （通常带 15~30 秒超时），它一取消，所有共享这次查询的等待者就一起
	// 拿到 ctx.Err()——哪怕它们自己的 ctx 还活着。断开取消、只保留 query
	// 自己的超时，等待者那边则各自 select 自己的 ctx（见上面的 inflight 分支）。
	c.addrs, c.err = r.query(context.WithoutCancel(ctx), h, path)

	r.mu.Lock()
	delete(r.inflight, key)
	if c.err == nil && len(c.addrs) > 0 {
		r.putLocked(key, c.addrs)
	}
	r.mu.Unlock()
	close(c.done)

	return c.addrs, c.err
}

// putLocked 写缓存并维持上限。调用方必须持有 mu。
func (r *Resolver) putLocked(h string, addrs []netip.Addr) {
	r.cache[h] = &cacheEntry{addrs: addrs, expire: time.Now().Add(r.ttl)}
	if len(r.cache) <= maxCacheEntries {
		return
	}
	// 先清过期项，通常就够了。
	now := time.Now()
	for k, e := range r.cache {
		if now.After(e.expire) {
			delete(r.cache, k)
		}
	}
	// 还超就继续淘汰。缓存没有「哪个更该留」的先验，
	// 随机丢到上限即可——这只是一层加速，不参与正确性。
	for k := range r.cache {
		if len(r.cache) <= maxCacheEntries {
			break
		}
		delete(r.cache, k)
	}
}

func (r *Resolver) fromCache(h string) []netip.Addr {
	addrs, _, ok := r.cacheHit(h)
	if !ok {
		return nil
	}
	return addrs
}

// cacheHit 返回缓存里那份答案，以及**它还剩多少毫秒有效**。
// 剩余时间必须一起给：只报"命中缓存"而不说它还有多久会自己过期，
// 人就无法判断"再等一会儿会不会变"和"我必须手动重问"这两种情况的区别。
func (r *Resolver) cacheHit(key string) ([]netip.Addr, int64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[key]
	if !ok {
		return nil, 0, false
	}
	left := time.Until(e.expire)
	if left <= 0 {
		delete(r.cache, key)
		return nil, 0, false
	}
	return e.addrs, left.Milliseconds(), true
}

// UpstreamAnswer 是**一个上游**对同一个名字的回话。
type UpstreamAnswer struct {
	Server string
	Addrs  []netip.Addr
	// Ms 是这个上游自己花了多久（并行问，所以各自计时才有意义）。
	Ms int64
	// Err 非空表示这个上游没答上来（超时、REFUSED、格式错都在这儿）。
	// 用字符串而不是 error：这一份是给人看的报告，不参与控制流，
	// 而 error 值跨了 Wails 桥之后本来就只剩一句文本。
	Err string
}

// ProbeEach 挨个问一遍所有上游，**不合并、不抢先返回**。
//
// 为什么需要它：`query` 是"任一成功即采用"，于是两个上游给出不同答案时
// （本机视角被污染、公共 DNS 给出真地址，或反过来）面板只能看到先回来的那个，
// 而"到底哪个上游在说谎"恰恰是查污染时唯一想知道的事。
// 这条路径不写缓存也不读缓存——它问的是"每个上游怎么说"，
// 拿别人的合并答案来回答就是答非所问。
func (r *Resolver) ProbeEach(ctx context.Context, host string, path Path) []UpstreamAnswer {
	h, literal := normalizeHost(host)
	out := make([]UpstreamAnswer, len(r.servers))
	for i, s := range r.servers {
		out[i] = UpstreamAnswer{Server: s}
	}
	if h == "" {
		return out
	}
	// IP 字面量没有"问上游"这回事：每个上游都该给出同一个答案，别去问。
	if literal.IsValid() {
		for i := range out {
			out[i].Addrs = []netip.Addr{literal}
		}
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var wg sync.WaitGroup
	for i, srv := range r.servers {
		wg.Add(1)
		go func(i int, server string) {
			defer wg.Done()
			start := time.Now()
			addrs, err := r.queryOne(ctx, server, h, path)
			out[i].Ms = time.Since(start).Milliseconds()
			if err != nil {
				out[i].Err = err.Error()
				return
			}
			out[i].Addrs = addrs
		}(i, srv)
	}
	wg.Wait()
	return out
}

// ProbeEachRefresh 是面板上那一枚「只重问这一个上游」：问完**写回这一条域名的缓存**，
// 所以引擎下一刻拿到的就是刚问回来的那批，不用等 TTL 到点。
//
// 它与 ProbeFresh 的分工值得说清楚，两个都叫"重问"但动的东西不一样：
//   - ProbeFresh 走的是引擎那条完整路径（多上游按"任一成功即采用"合并）再写回，
//     它答的是"整条路径重新问一遍会拿到什么"；
//   - 这一只问 `only` 里点名的那几个上游，一个都不多问，写回的也是被点名那个的答案。
//     怀疑的是哪一家的答案就刷哪一家，这件事只有坐在这格前面的人知道，这里不替他决定。
//
// `only` 为空 / 一个都不在配置里 → 什么都不刷、原样报出来，而不是"当作没传"把全部上游问一遍：
// 那会把"只刷这一个"执行成"全刷"，正是这一按要避免的那件事。
func (r *Resolver) ProbeEachRefresh(ctx context.Context, host string, path Path, only []string) []UpstreamAnswer {
	h, literal := normalizeHost(host)
	out := make([]UpstreamAnswer, 0, len(only))
	if h == "" {
		return out
	}
	if path == PathTunnel && r.tunnel.Load() == nil {
		// 与 probe / ProbeEach 同一条退路：没注入隧道拨号器时要隧道也等价于直连。
		// 这里更要紧的是**写回哪个键**——按直连问回来的就得写进直连那份，
		// 否则这一按刷的是 A 那份缓存、引擎读的是 B 那份，看起来什么都没变。
		path = PathDirect
	}
	// IP 字面量没有"问上游"这回事，也没有缓存条目可刷。
	if literal.IsValid() {
		for _, s := range only {
			out = append(out, UpstreamAnswer{Server: s, Addrs: []netip.Addr{literal}})
		}
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	key := r.key(path, h)

	var wg sync.WaitGroup
	out = make([]UpstreamAnswer, len(only))
	for i, srv := range only {
		out[i] = UpstreamAnswer{Server: srv}
		if !r.hasServer(srv) {
			out[i].Err = "这个上游不在配置里（dns.servers），没刷任何东西"
			continue
		}
		wg.Add(1)
		go func(i int, server string) {
			defer wg.Done()
			start := time.Now()
			addrs, err := r.queryOne(ctx, server, h, path)
			out[i].Ms = time.Since(start).Milliseconds()
			if err != nil {
				out[i].Err = err.Error()
				return
			}
			out[i].Addrs = addrs
			// 问不到地址时**不**写缓存：拿一份空答案把原来那份能用的挤掉，
			// 比让人再按一次更糟——这一按的承诺是"换成新的"，不是"换成没有"。
			r.prime(key, addrs)
		}(i, srv)
	}
	wg.Wait()
	return out
}

// prime 把一份刚问到的答案放进缓存。
// 不借道 resolve：那条路会按"任一成功即采用"把多个上游合并成一份，
// 而这一按的承诺是**只把被点名那一个的读数换成新的**。
func (r *Resolver) prime(key string, addrs []netip.Addr) {
	if len(addrs) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.putLocked(key, addrs)
}

func (r *Resolver) hasServer(want string) bool {
	for _, s := range r.servers {
		if s == want {
			return true
		}
	}
	return false
}

// hasInternalAddr 判断这批地址里有没有"内网地址"。
//
// 判据是 RFC1918（10/8、172.16/12、192.168/16）、CGNAT（100.64/10）与 ULA（fc00::/7）。
//
// 为什么不把回环（127/8）算进来：回环地址是**环路信号**，不是内网地址。
// 解析器一旦把域名答成 127.0.0.1，连接就会回到本机——
// direct.go 的 checkLoop 只能挡住"拨自己的入站端口"，挡不住"拨本机的另一个服务"。
// 把它当内网答案等于把污染放进来，正是这一层要防的事。
//
// 链接本地（169.254/16、fe80::/10）同样排除：它只在链路上有意义，
// 跨路由器不可达，与"公司内网服务"不是一回事。
func hasInternalAddr(addrs []netip.Addr) bool {
	for _, a := range addrs {
		if isInternalAddr(a) {
			return true
		}
	}
	return false
}

// internalPrefixes 是"内网地址"对应的网段：
// RFC1918（10/8、172.16/12、192.168/16）、CGNAT（100.64/10）与 ULA（fc00::/7）。
//
// 刻意不含回环（127/8）与链接本地（169.254/16、fe80::/10）：
// 前者是环路信号，后者只在链路上有意义，与"公司内网服务"不是一回事。
var internalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// isInternalAddr 判断单个地址是不是内网地址（不含回环与链接本地）。
func isInternalAddr(a netip.Addr) bool {
	a = a.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return false
	}
	for _, p := range internalPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// prioritizeInternal 把内网地址排到候选集前面，公网地址保留在后面。
//
// 不丢弃公网地址：多地址重试（direct.go 的 preferV4）需要完整候选集，
// 内网地址连不上时仍应有机会试公网那一条。
func prioritizeInternal(addrs []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if isInternalAddr(a) {
			out = append(out, a)
		}
	}
	for _, a := range addrs {
		if !isInternalAddr(a) {
			out = append(out, a)
		}
	}
	return out
}

// serversFor 决定这个域名该问哪些上游。
//
// 内网后缀的域名走内网上游，其余走公网上游。两组不混在一起：
// 混在一起就是"谁先回来谁说了算"，而两边的答案各错一半（见 query 的注释）。
//
// 内网 DNS 对外网域名是污染的（实测 www.google.com 被答成 Facebook 段），
// 公网 DNS 对内网域名也是错的（实测 yfjira.mychery.com 被答成 WAF 公网入口）。
// 所以**分组是按域名走的，不是按答案走的**——
// 不去猜"这个答案像不像内网地址"，而是先由配置说清哪些域名算内网。
func (r *Resolver) serversFor(host string) []string {
	servers, _ := r.routeFor(host)
	return servers
}

// routeFor 在 serversFor 之上多答一句「这是不是内网那一层」。
//
// 裁决规则必须按层分开，所以调用方不能只看上游列表：两层拿到的是两个不同的
// 切片，但真正决定语义的是"这组上游属不属于内网"。用一个布尔值说出来，
// 比让 query 去比切片地址（或再调一次 serversFor 猜）可靠。
func (r *Resolver) routeFor(host string) (servers []string, internal bool) {
	if len(r.internalServers) == 0 || len(r.domainSuffixes) == 0 {
		return r.servers, false
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, suffix := range r.domainSuffixes {
		if h == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(h, suffix) {
			return r.internalServers, true
		}
	}
	return r.servers, false
}

// InternalServers 是内网专用的上游列表（按配置的顺序）。
func (r *Resolver) InternalServers() []string {
	out := make([]string, len(r.internalServers))
	copy(out, r.internalServers)
	return out
}

// DomainSuffixes 是走内网上游的域名后缀。
func (r *Resolver) DomainSuffixes() []string {
	out := make([]string, len(r.domainSuffixes))
	copy(out, r.domainSuffixes)
	return out
}

// Servers 是配置里那几个上游，按配置的顺序。
// 面板要能把"问的是哪几个"写出来，而它不该自己去猜顺序。
func (r *Resolver) Servers() []string {
	out := make([]string, len(r.servers))
	copy(out, r.servers)
	return out
}

// query 并行查询同一层的所有上游，然后裁决。
//
// 旧语义是「任一成功即采用」——那等于拼延迟。实测（公司内网 + 公网双栈）：
//
//	127.0.0.53  ~23ms   -> 172.25.51.92    （公司内网真实地址）
//	119.29.29.29 ~30ms  -> 123.60.194.157  （华为云 WAF 入口，回 418 拦截页）
//	223.5.5.5   ~42ms   -> 123.60.194.157
//
// 三家都"成功"（都给出了合法地址），于是谁先回来谁说了算：
// 30 次实测里内网地址只赢了 20 次。**失败的 1/3 不是偶发抖动**——
// 答案会被 5 分钟 TTL 缓存黏住，坏答案一进来，接下来 5 分钟全部拨 WAF 入口，
// 表现是日志里一片 DIRECT、页面全是「访问被拦截！」。
//
// 现在是两层，各走各的上游，互不竞速：
//
//	内网后缀的域名 -> 只问 internalServers（公司 DNS）
//	其余域名      -> 只问 servers（公网 DNS）
//
// 裁决规则**按层不同**，这是这条函数里最容易改错的一处：
//
//	内网层：私有段（RFC1918 / CGNAT / ULA）只有公司 DNS 才会给，所以出现私有
//	       地址就直接用它，不必等其余上游。层内没有私有地址时才退回"先到先得"。
//	公网层：私有地址恰恰是污染的典型手法（把域名指到 10.x 或回环），所以**不**
//	       让私有地址赢；第一份非空的公网答案就是答案。
//
// 两条共同点：拿到第一个可用答案就返回，不再等其余上游。等齐所有上游等于把
// 未命中延迟从"最快的那家"变成"最慢的那家"——有一家上游黑洞时每次未命中都要
// 打满 timeout，而这段时间里已经拿到的正确答案被白白丢掉。
//
// 回环地址不参与内网优先：127.0.0.1 是环路信号（见 direct.go 的 checkLoop），
// 把它当成"内网答案"会把连接引回本机。
func (r *Resolver) query(ctx context.Context, host string, path Path) ([]netip.Addr, error) {
	servers, internal := r.routeFor(host)
	if len(servers) == 0 {
		return nil, fmt.Errorf("dns %s: 没有可用的上游", host)
	}
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	// cancel 不只是省资源：第一份可用答案到手后，其余上游的查询还挂在 ctx 上，
	// 它们要么拖住 net.Resolver 的连接，要么在我们已经返回之后才醒来。
	defer cancel()

	type result struct {
		addrs []netip.Addr
		err   error
	}
	results := make(chan result, len(servers))
	for _, srv := range servers {
		go func(server string) {
			ips, err := r.queryOne(ctx, server, host, path)
			results <- result{addrs: ips, err: err}
		}(srv)
	}

	var (
		lastErr  error
		best     []netip.Addr
		haveBest bool
		// polluted 记住公网层看到的私有地址。它不参与裁决，只作最后兜底：
		// 所有上游都给私有地址时（分裂视野的域名确实存在）总比解析失败强。
		polluted     []netip.Addr
		havePolluted bool
	)
	for range servers {
		select {
		case res := <-results:
			if res.err != nil {
				lastErr = res.err
				continue
			}
			if len(res.addrs) == 0 {
				continue
			}
			// 内网层：私有地址胜出，直接用它，不必等其余上游。
			if internal {
				if hasInternalAddr(res.addrs) {
					return prioritizeInternal(res.addrs), nil
				}
				if !haveBest {
					best, haveBest = res.addrs, true
				}
				continue
			}
			// 公网层：私有地址**不是**答案，是污染的典型形状（把域名指到 10.x）。
			// 记下来兜底，继续等一份像样的公网答案——但绝不为它提前返回。
			if hasInternalAddr(res.addrs) {
				if !havePolluted {
					polluted, havePolluted = res.addrs, true
				}
				continue
			}
			// 公网层的第一份非空公网答案就是答案，与旧语义一致。
			return res.addrs, nil
		case <-ctx.Done():
			// 已经拿到过可用答案时绝不能把它丢掉：超时只是"其余上游没回"，
			// 不是"这次解析失败"。丢掉它等于让调用方为一次成功的解析再付一次失败。
			if haveBest {
				logx.Debugf("dns: %s 有上游未在 %v 内应答，采用先到的答案 %v", host, r.timeout, best)
				return best, nil
			}
			if havePolluted {
				logx.Debugf("dns: %s 只拿到公网上游给的私有地址 %v（可能是污染），按兜底采用", host, polluted)
				return polluted, nil
			}
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return nil, fmt.Errorf("dns %s: %w", host, lastErr)
		}
	}
	if haveBest {
		return best, nil
	}
	if havePolluted {
		logx.Debugf("dns: %s 所有公网上游都只给了私有地址 %v（可能是污染），按兜底采用", host, polluted)
		return polluted, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no answer")
	}
	logx.Debugf("dns: %s 解析失败: %v", host, lastErr)
	return nil, fmt.Errorf("dns %s: %w", host, lastErr)
}

// queryOne 同时查 A 与 AAAA。任一先成功即采用，并给另一个 grace 窗口合并结果。
func (r *Resolver) queryOne(ctx context.Context, server, host string, path Path) ([]netip.Addr, error) {
	started := time.Now()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// 隧道路径：把上游地址交给当前出站，拿到一条穿过隧道的流。
			//
			// 这里刻意无视 network 参数、即便 stdlib 先来问 "udp" 也只给流式连接。
			// net.Resolver 是按返回值的类型决定分帧的（dnsclient_unix.go:194-198）：
			// 返回 PacketConn 才走 UDP 报文，否则退回带 2 字节长度前缀的 DNS-over-TCP。
			// 所以"要 UDP 却拿到 stream"不是降级，而是一条完全合法的查询通道。
			//
			// 走 stream 也是现在唯一走得通的路：trojan 压根不承载 UDP，
			// hysteria2 的 UDP 会话还没接进来。等它接上之后，这里可以再分一支走报文。
			if path == PathTunnel {
				if dial := r.tunnel.Load(); dial != nil {
					return (*dial)(ctx, server)
				}
			}
			d := net.Dialer{Timeout: r.timeout}
			return d.DialContext(ctx, network, server)
		},
	}
	type res struct {
		addrs []net.IP
		err   error
	}
	ch := make(chan res, 2)
	go func() {
		a, err := resolver.LookupIP(ctx, "ip4", host)
		ch <- res{a, err}
	}()
	go func() {
		a, err := resolver.LookupIP(ctx, "ip6", host)
		ch <- res{a, err}
	}()

	var out []netip.Addr
	var lastErr error
	remaining := 2
collect:
	for remaining > 0 {
		// 拿到第一个成功结果后，只等 grace 窗口合并另一个，
		// 避免为了等 AAAA 白等一整个超时。
		wait := r.timeout
		if len(out) > 0 {
			wait = graceWindow
		}
		timer := time.NewTimer(wait)
		select {
		case rr := <-ch:
			timer.Stop()
			remaining--
			if rr.err == nil {
				for _, a := range rr.addrs {
					if ip, ok := netip.AddrFromSlice(a); ok {
						out = append(out, ip.Unmap())
					}
				}
			} else {
				lastErr = rr.err
			}
		case <-timer.C:
			// 已有结果就不再纠缠；否则视为超时失败。
			if len(out) > 0 {
				break collect
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("upstream %s timeout", server)
			}
			return nil, lastErr
		case <-ctx.Done():
			timer.Stop()
			// 整个 query 的预算用完了，但这一台上游可能已经把答案给了
			// （A 回来了、AAAA 还在路上，正是最常见的形状）。把拿到的那份交出去：
			// 让一次已经成功的解析因为"另一个族没回"变成失败，等于把
			// 上游的慢算成目标不可达，而调用方还要为它再付一次重试。
			if len(out) > 0 {
				break collect
			}
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return nil, lastErr
		}
	}
	if len(out) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("empty answer")
		}
		return nil, lastErr
	}
	// 记录实际上游：debug 级别下可直接核对查询没发往配置之外的服务器。
	logx.Debugf("dns: %s(%s) 经上游 %s 解析为 %v（%s）", host, path, server, out, time.Since(started).Round(time.Millisecond))
	return out, nil
}
