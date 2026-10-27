// Package tunx 实现 TUN 入站：虚拟网卡 + 用户态 TCP/IP 协议栈。
//
// 设计取向与 Clash 的 tun 模式一致——「假 IP + DNS 劫持」，而不是抢默认路由：
//
//	应用查询 example.com
//	  → 我们的 DNS（tun.dns）按当前模式与规则判定
//	      PROXY  → 回一个 fake_ip_range 里的假 IP，并把 假IP↔域名 记进 FakeStore
//	      DIRECT → 用 dnsx 解析出真 IP 回给它
//	  → 应用连接假 IP，命中「假 IP 网段 dev tun」这条路由，进入 tun
//	  → 协议栈把这条 TCP/UDP 交给我们，反查回域名，交给 router 决策并拨号
//
// 好处很实在：直连流量完全不进 tun（不绕路、不减速、也不会因为我们自己发出的
// 包再被 tun 抓回来而形成环路），只有真正需要代理的流量才走这一遭。
package tunx

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// 假 IP 表的上限与默认存活时间。上限按段大小留出足够空间，
// 再老于 ttl 的映射会被回收，避免长期运行后假 IP 段被耗尽。
const (
	defaultFakeTTL = 4 * time.Hour
	maxFakeEntries = 1 << 16
)

type fakeEntry struct {
	domain  string
	addr    netip.Addr
	expires time.Time
}

// domainKey 是「域名 + 族」。同一个域名会同时持有一个 A 假 IP 和一个 AAAA 假 IP，
// 所以不能只拿域名当键。
type domainKey struct {
	domain string
	v6     bool
}

// fakeRange 是一个假 IP 段。v4 与 v6 各有一个，可以只有一个。
type fakeRange struct {
	prefix netip.Prefix
	// base 是段首地址（已按 prefix mask 过）。
	base netip.Addr
	// size 是段内可分配地址数。v6 段实际是天文数字，
	// 取 2^64-1 只是为了让扫描有上限：真跑满的那天早于任何机器的寿命。
	size uint64
	// next 是下一个候选下标。0 与 size-1（广播）不参与分配。
	next uint64
	used map[netip.Addr]struct{}
}

// addrAt 把段内下标换成地址。越出段的直接返回无效地址，
// 于是调用方的 Contains 检查天然兜住了前缀小于 /30 这类边界。
func (r *fakeRange) addrAt(i uint64) netip.Addr {
	var a netip.Addr
	if r.prefix.Addr().Is4() {
		a = uint32ToIPv4(ipv4ToUint(r.base.As4()) + uint32(i))
	} else {
		b := r.base.As16()
		binary.BigEndian.PutUint64(b[8:], i)
		a = netip.AddrFrom16(b)
	}
	if !r.prefix.Contains(a) {
		return netip.Addr{}
	}
	return a
}

// FakeStore 维护 域名→假 IP 与 假 IP→域名 两张表。并发安全。
//
// IPv4 与 IPv6 是两个独立的段（v6 可以没配）：分配时各走各的，
// 反查时哪一族都行——进来的连接只看它落在不在某个段里。
type FakeStore struct {
	mu     sync.Mutex
	v4     *fakeRange
	v6     *fakeRange
	byAddr map[netip.Addr]*fakeEntry
	byName map[domainKey]*fakeEntry
	ttl    time.Duration
}

// NewFakeStore 按 CIDR 建表。cidr6 为空表示不分配 IPv6 假 IP——
// 此时 AAAA 仍回 NODATA，应用会老实地退回 A 记录。
func NewFakeStore(cidr, cidr6 string, ttl time.Duration) (*FakeStore, error) {
	v4, err := newFakeRange(cidr, true)
	if err != nil {
		return nil, err
	}
	var v6 *fakeRange
	if c := strings.TrimSpace(cidr6); c != "" {
		if v6, err = newFakeRange(c, false); err != nil {
			return nil, err
		}
	}
	if ttl <= 0 {
		ttl = defaultFakeTTL
	}
	return &FakeStore{
		v4:     v4,
		v6:     v6,
		byAddr: make(map[netip.Addr]*fakeEntry),
		byName: make(map[domainKey]*fakeEntry),
		ttl:    ttl,
	}, nil
}

func newFakeRange(cidr string, want4 bool) (*fakeRange, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("fake ip range %q: %w", cidr, err)
	}
	if prefix.Addr().Is4() != want4 {
		fam := "IPv6"
		if want4 {
			fam = "IPv4"
		}
		return nil, fmt.Errorf("fake ip range %q: 这里要的是 %s 段", cidr, fam)
	}
	base := prefix.Masked().Addr()
	var size uint64
	if want4 {
		// 网络地址与广播地址不参与分配。
		size = uint64(1) << (32 - prefix.Bits())
	} else {
		size = ^uint64(0)
	}
	return &fakeRange{prefix: prefix, base: base, size: size, used: map[netip.Addr]struct{}{}}, nil
}

// HasV6 报告有没有 IPv6 段。没配段时 AAAA 必须回 NODATA：
// 发一个没有路由的假 v6 地址出去，应用会一直连到超时，
// 而 NODATA 只是让它退回 A 记录——后者才是能工作的降级。
func (s *FakeStore) HasV6() bool { return s != nil && s.v6 != nil }

// Allocate 返回该域名的 IPv4 假 IP，已分配过就复用（顺带续期）。
func (s *FakeStore) Allocate(domain string) (netip.Addr, error) { return s.allocate(domain, s.v4) }

// Allocate6 同上，但取 IPv6 段里的地址。没配 v6 段时报错。
func (s *FakeStore) Allocate6(domain string) (netip.Addr, error) {
	if s.v6 == nil {
		return netip.Addr{}, fmt.Errorf("没配置 IPv6 假 IP 网段")
	}
	return s.allocate(domain, s.v6)
}

func (s *FakeStore) allocate(domain string, r *fakeRange) (netip.Addr, error) {
	key := normalizeDomain(domain)
	if key == "" {
		return netip.Addr{}, fmt.Errorf("空域名")
	}
	if r == nil {
		return netip.Addr{}, fmt.Errorf("没有可用的假 IP 网段")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	dk := domainKey{domain: key, v6: r.prefix.Addr().Is6()}
	if e, ok := s.byName[dk]; ok && now.Before(e.expires) {
		e.expires = now.Add(s.ttl)
		return e.addr, nil
	}
	s.evict(now)

	addr, err := s.take(r)
	if err != nil {
		return netip.Addr{}, err
	}
	e := &fakeEntry{domain: key, addr: addr, expires: now.Add(s.ttl)}
	s.byName[dk] = e
	s.byAddr[addr] = e
	r.used[addr] = struct{}{}
	return addr, nil
}

// take 顺序取下一个未用的假 IP；段满时先清掉过期项再重试一次。
func (s *FakeStore) take(r *fakeRange) (netip.Addr, error) {
	// 一轮的长度按段大小截到在册上限量级：v6 段名义上有 2^64 个地址，
	// 按名义大小扫一圈等于永远扫不完。
	span := r.size
	if span > uint64(maxFakeEntries)*2 {
		span = uint64(maxFakeEntries) * 2
	}
	for attempts := 0; attempts < 2; attempts++ {
		for i := uint64(0); i < span; i++ {
			r.next++
			if r.next == 0 || r.next >= r.size {
				r.next = 1
			}
			a := r.addrAt(r.next)
			if !a.IsValid() {
				continue
			}
			if _, used := r.used[a]; used {
				continue
			}
			return a, nil
		}
		// 一轮走完都没空位：全表都是活的映射，只能回收过期的。
		s.evict(time.Now().Add(s.ttl))
		if len(s.byAddr) >= maxFakeEntries {
			return netip.Addr{}, fmt.Errorf("假 IP 段 %s 已耗尽", r.prefix.String())
		}
	}
	return netip.Addr{}, fmt.Errorf("假 IP 段 %s 已耗尽", r.prefix.String())
}

// evict 清掉 expires 早于 now 的映射，并在超出上限时按到期时间从前往后砍。
func (s *FakeStore) evict(now time.Time) {
	for k, e := range s.byName {
		if !now.After(e.expires) {
			continue
		}
		delete(s.byAddr, e.addr)
		if r := s.rangeOf(e.addr); r != nil {
			delete(r.used, e.addr)
		}
		delete(s.byName, k)
	}
	if len(s.byName) <= maxFakeEntries {
		return
	}
	byAge := make([]*fakeEntry, 0, len(s.byName))
	for _, e := range s.byName {
		byAge = append(byAge, e)
	}
	sort.Slice(byAge, func(i, j int) bool { return byAge[i].expires.Before(byAge[j].expires) })
	for _, e := range byAge[:len(byAge)-maxFakeEntries] {
		delete(s.byAddr, e.addr)
		if r := s.rangeOf(e.addr); r != nil {
			delete(r.used, e.addr)
		}
		delete(s.byName, domainKey{domain: e.domain, v6: e.addr.Is6()})
	}
}

func (s *FakeStore) rangeOf(addr netip.Addr) *fakeRange {
	if addr.Is4() {
		return s.v4
	}
	return s.v6
}

// Lookup 由假 IP 反查域名。命中说明这个连接确实是经我们 DNS 发出去的。
func (s *FakeStore) Lookup(addr netip.Addr) (string, bool) {
	if !addr.IsValid() {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byAddr[addr]
	if !ok || time.Now().After(e.expires) {
		return "", false
	}
	return e.domain, true
}

// Len 返回当前在册的假 IP 数量，供状态面板展示。
func (s *FakeStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byAddr)
}

// Contains 判断地址是否落在任一假 IP 段内。
// 段内却查不到域名的连接必须由调用方拒绝：拨这种地址等于把包送回 tun。
func (s *FakeStore) Contains(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if s.v4 != nil && s.v4.prefix.Contains(addr) {
		return true
	}
	return s.v6 != nil && s.v6.prefix.Contains(addr)
}

func normalizeDomain(d string) string {
	out := make([]byte, 0, len(d))
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	return string(out)
}

func ipv4ToUint(ip [4]byte) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIPv4(u uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}
