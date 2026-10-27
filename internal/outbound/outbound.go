// Package outbound 定义出站抽象：路由器按规则选出某个出站来建立连接。
package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"wps_app/internal/config"
)

// Policy 是规则可用的出站策略名。
type Policy string

const (
	PolicyDirect Policy = "DIRECT"
	PolicyProxy  Policy = "PROXY"
	// PolicyReject 不对应任何出站：命中拦截名单，不该走到这里。
	// 它存在的意义是让「拦截被误当成代理」这种事在编译期与运行期都拦得住
	// ——见 Set.Get 里那条单独分支的理由。
	PolicyReject Policy = "REJECT"
)

// Dialer 是出站的统一接口。实现必须保证自身的出站流量
// 不经过本进程的入站监听端口，否则会形成环路。
type Dialer interface {
	// Name 返回出站名称，用于日志。
	Name() string
	// DialContext 建立到 addr 的 TCP 连接。
	DialContext(ctx context.Context, addr string) (net.Conn, error)
	// Close 释放资源。
	Close() error
}

// Conn 是「可被面板观测的出站」：除了拨号，还要能回答
// 「隧道到底建起来了没有」以及一句给人看的摘要。
//
// 只靠 Dialer 是不够的：入站在监听不等于隧道可用，面板必须把这两件事分开显示，
// 否则用户看到的是「代理运行中」而实际所有 PROXY 流量都在超时。
type Conn interface {
	Dialer
	// Connected 报告最近一次握手是否成功。
	Connected() bool
	// Status 返回服务端摘要（地址、SNI、是否已握手等），可为空。
	Status() string
}

// NodeFault 报告「这个错误算不算节点本身的故障」。
//
// 判定必须留在各协议里，公共层不该拿 errors.Is 猜：三家的错误形态差别太大——
// hysteria2 有 quic 的强类型错误，还额外区分「服务端拨不通这个目标」；
// trojan 只有裸 TLS/TCP 错误，而且它的服务端拨不通目标时是直接挂断，
// 压根不给出目标级信号。
//
// 用类型断言取而不是塞进 Conn：Conn 是每条转发路径都要过的窄接口，
// 只有故障切换关心这件事，不值得为此拓宽所有实现。
type NodeFault interface {
	// NodeFailure 报告 err 是否意味着「这个节点不行了」，
	// 而不是「节点好好的，只是它拨不通你要的那个目标」或「调用方自己放弃了」。
	NodeFailure(err error) bool
}

// ReportNodeFailure 替调用方做类型断言。
//
// 没实现 NodeFault 的产出一律算「不可判定」→ false：
// 判不出是谁的错就去切节点，切错了只会把好好的连接白白打断。
func ReportNodeFailure(d Dialer, err error) bool {
	nf, ok := d.(NodeFault)
	if !ok {
		return false
	}
	return nf.NodeFailure(err)
}

// New 按配置里的 type 造对应协议的出站。
//
// 这里是「协议」与「其余一切」的唯一接缝：规则、模式、TUN、测速都只认 Conn，
// 再加一种协议只需要多一个 case 与一个实现文件。
//
// resolver 与 reject 必须由调用方给对：前者是「用哪套 DNS 找节点」，
// 后者是「不许把哪些地址当节点」（本客户端的假 IP 段）。
// 两者凑错都会把「连节点」变成「连自己」，而且症状是连接超时，不是报错。
// split 传 nil 即不做网卡分流（见 Split）。
func New(sc config.ServerConfig, handshakeTimeout time.Duration, resolver HostResolver, reject netip.Prefix, split *Split) (Conn, error) {
	// 用 ParseProtocol 而不是 sc.Protocol()：后者会把不认识的名字悄悄变成 hysteria2，
	// 于是下面那条 default 永远走不到——新协议被当 hysteria2 拨，
	// 症状是超时而不是报错，照着超时去查网络永远查不到根因。
	proto, err := config.ParseProtocol(sc.Type)
	if err != nil {
		return nil, err
	}
	switch proto {
	case config.ProtocolTrojan:
		t, err := NewTrojan(sc, handshakeTimeout, resolver, reject)
		if err != nil {
			return nil, err
		}
		return t.WithSplit(split), nil
	case config.ProtocolHysteria2:
		h, err := NewHysteria(sc, handshakeTimeout, resolver, reject)
		if err != nil {
			return nil, err
		}
		return h.WithSplit(split), nil
	default:
		// 不能落到 hysteria2 兜底：新协议会被拿 hysteria 的方式去拨
		// （auth 当 QUIC key、TLS 参数整个忽略），症状是超时而不是报错，
		// 照着超时去查网络配置永远查不到根因。
		return nil, fmt.Errorf("协议 %q 还没接入出站实现，拒绝装配而不是按 hysteria2 拨", proto)
	}
}

// NodeFactory 按节点名造一只出站。
//
// 它是「规则把某条域名固定到指定节点」这条路的唯一入口，而且**由装配方提供**：
// 出站集合自己不认识配置文件，更不该去读它。传 nil 就等于这一路没接上，
// GetNode 会明确报错而不是偷偷改用当前节点（见 GetNode 那段）。
type NodeFactory func(name string) (Conn, error)

// Set 是当前可用的出站集合。
//
// PROXY 出站可以整只换掉（切节点）：监听、规则、协议栈都不关心对面是哪个节点，
// 换掉这只 dialer 就是换出口。用锁而不是重建整个 Set，是为了让「切节点」
// 不再要求把网卡与端口一起拆掉重来。
type Set struct {
	mu     sync.RWMutex
	direct Dialer
	proxy  Dialer
	// node 是当前 PROXY 出站背后那个节点的名字，只用于"按节点算用量"。
	node string
	// nodes 是按名字临时造出来的固定节点出站。
	//
	// 懒建：没被任何规则粘住的节点不该白占一条隧道（每个 hysteria2 客户端都带着
	// 自己的 QUIC 状态），而被粘住的也不该每条连接重造一只（握手是按连接计的）。
	nodes map[string]Dialer
	// factory 见 NodeFactory。
	factory NodeFactory
}

// NewSet 组装出站集合。
func NewSet(direct, proxy Dialer) *Set {
	return &Set{direct: direct, proxy: proxy}
}

// WithNode 给初始的 PROXY 出站标上节点名，链式写法。
func (s *Set) WithNode(name string) *Set {
	s.node = name
	return s
}

// WithNodeFactory 装上固定节点用的工厂，链式写法。没装过它的 Set 不支持 GetNode。
func (s *Set) WithNodeFactory(f NodeFactory) *Set {
	s.factory = f
	return s
}

// SwapProxy 换上新的 PROXY 出站与其节点名，返回旧的那只（由调用方负责关闭）。
//
// 节点名和出站必须在同一次加锁里一起换：分成两步就存在"字节记到旧节点头上"的窗口，
// 而按节点算用量这件事唯一的价值就是它记得准。
//
// 顺带丢掉新名字那份缓存：这个名字现在由 proxy 那只承载，留着缓存等于
// 对同一台服务器开两条隧道（一条走规则钉的，一条走活动节点）。
func (s *Set) SwapProxy(next Dialer, node string) Dialer {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.proxy
	s.proxy = next
	s.node = node
	dropped := s.nodes[node]
	if dropped != nil {
		delete(s.nodes, node)
		_ = dropped.Close()
	}
	return old
}

// GetNode 返回钉到某个节点名上的那只出站。
//
// 三条不许含糊的地方：
//   - 名字不认识（配置里没这个节点）一律**报错**，绝不回落到当前活动节点。
//     "这条域名固定走 US-LA"变成"走此刻随便哪个节点"是彻底的误导——
//     用户钉它通常正因为不想让它去别处，而症状与正常转发一模一样。
//   - 钉的就是当前活动节点时复用 proxy 那一只，不再另造。
//   - 造好的一只存进缓存；并发下两条同时造，输的那个自己关掉，别漏。
func (s *Set) GetNode(name string) (Dialer, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("outbound: 固定节点名为空")
	}
	s.mu.RLock()
	cached := s.nodes[name]
	proxy, proxyName := s.proxy, s.node
	factory := s.factory
	s.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}
	if name == proxyName && proxy != nil {
		return proxy, nil
	}
	if factory == nil {
		return nil, fmt.Errorf("规则要把流量固定到节点 %s，但出站集合没装节点工厂", name)
	}
	next, err := factory(name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if old := s.nodes[name]; old != nil {
		s.mu.Unlock()
		_ = next.Close()
		return old, nil
	}
	if s.nodes == nil {
		s.nodes = make(map[string]Dialer)
	}
	s.nodes[name] = next
	s.mu.Unlock()
	return next, nil
}

// DropNode 丢掉某个节点的缓存出站并返回它们（由调用方关闭）；名字传空 = 全部丢掉。
//
// 改过或删过某个节点的配置之后必须调它：缓存里那只还拿着旧的 addr/auth/口令，
// 而界面已经显示成新配置了——继续用它，症状是"改了节点参数却像没生效"。
func (s *Set) DropNode(name string) []Dialer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.nodes) == 0 {
		return nil
	}
	var dropped []Dialer
	if name == "" {
		dropped = make([]Dialer, 0, len(s.nodes))
		for k, d := range s.nodes {
			dropped = append(dropped, d)
			delete(s.nodes, k)
		}
		return dropped
	}
	if d := s.nodes[name]; d != nil {
		dropped = append(dropped, d)
		delete(s.nodes, name)
	}
	return dropped
}

// Node 返回当前 PROXY 出站背后的节点名。没设置过时回一个显式的占位，
// 让界面上能看出"这条字节属于哪个节点"这件事没被记全，而不是静默归到空名字下。
func (s *Set) Node() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.node == "" {
		return "（未命名节点）"
	}
	return s.node
}

// Proxy 返回当前的 PROXY 出站。
func (s *Set) Proxy() Dialer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.proxy
}

// Get 按策略返回出站，未知策略按 PROXY 处理（fail-open 到代理）。
func (s *Set) Get(p Policy) (Dialer, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch p {
	case PolicyDirect:
		if s.direct == nil {
			return nil, fmt.Errorf("direct outbound not available")
		}
		return s.direct, nil
	case PolicyReject:
		// 未知策略回落到代理是这里既有的决定，但拦截必须单独拒绝：
		// 一旦 REJECT 漏进 default，黑名单就反转为"这些域名专门走代理"，
		// 而症状与正常转发一模一样，没人看得出来。
		return nil, fmt.Errorf("REJECT 不是一个出站，拦截应在选择出站之前就被挡下")
	default:
		if s.proxy == nil {
			return nil, fmt.Errorf("proxy outbound not available")
		}
		return s.proxy, nil
	}
}

// Close 关闭所有出站。
func (s *Set) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var firstErr error
	closeAll := func(d Dialer) {
		if d == nil {
			return
		}
		if err := d.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	closeAll(s.direct)
	closeAll(s.proxy)
	// 缓存里那些固定节点的出站也归这个 Set 管：装配方只握着 Set，
	// 漏掉这张表就是每次换节点/停机都留下几直到不了对的隧道。
	for name, d := range s.nodes {
		closeAll(d)
		delete(s.nodes, name)
	}
	s.direct, s.proxy = nil, nil
	return firstErr
}
