package rules

import (
	"fmt"
	"net/netip"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

// GeoIP 封装 mmdb 查询，线程安全。
type GeoIP struct {
	db *maxminddb.Reader
}

// geoRecord 是 mmdb 中我们关心的字段。
type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// OpenGeoIP 打开指定路径的 mmdb 文件。
func OpenGeoIP(path string) (*GeoIP, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geoip %q: %w", path, err)
	}
	return &GeoIP{db: db}, nil
}

// Country 返回 IP 所属国家码（如 CN、US）。查不到返回空串与 false。
func (g *GeoIP) Country(ip netip.Addr) (string, bool) {
	if g == nil || g.db == nil {
		return "", false
	}
	res := g.db.Lookup(ip.Unmap())
	if err := res.Err(); err != nil {
		return "", false
	}
	if !res.Found() {
		return "", false
	}
	var rec geoRecord
	if err := res.Decode(&rec); err != nil {
		return "", false
	}
	if rec.Country.ISOCode != "" {
		return rec.Country.ISOCode, true
	}
	if rec.RegisteredCountry.ISOCode != "" {
		return rec.RegisteredCountry.ISOCode, true
	}
	return "", false
}

// Close 释放 mmdb。
func (g *GeoIP) Close() error {
	if g == nil || g.db == nil {
		return nil
	}
	return g.db.Close()
}

// GeoRef 持有一个可热替换的 mmdb，上层持有 *GeoRef 即可在不中断服务的前提下
// 切换底层数据库。
type GeoRef struct {
	mu sync.RWMutex
	g  *GeoIP
}

// NewGeoRef 创建引用。
func NewGeoRef(g *GeoIP) *GeoRef { return &GeoRef{g: g} }

// Swap 换入新的 mmdb 并关闭旧的。
func (r *GeoRef) Swap(next *GeoIP) {
	// 关闭必须发生在写锁内。只换指针、把 Close 放到解锁之后的话，
	// 会留下一个「读者已经取到旧指针、但旧库已被 munmap」的窗口——
	// 而 Close 对 maxminddb 是破坏性的（关掉就是置空底层 buffer），
	// 那条读路径会直接踩到已释放的内存。
	r.mu.Lock()
	defer r.mu.Unlock()
	old := r.g
	r.g = next
	if old != nil {
		_ = old.Close()
	}
}

// Country 查询 IP 所属国家码。
func (r *GeoRef) Country(ip netip.Addr) (string, bool) {
	// 读锁要覆盖整个查询，不能只用来取指针。
	// 每条入站连接都会走到这里，而 Swap（SIGHUP 重载、托盘「重载规则」、
	// 增删用户规则）随时可能换库并释放旧库：指针一旦在解锁后使用，
	// 热重载一次就是一次 use-after-munmap，整个进程当场 SIGSEGV。
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.g.Country(ip)
}
