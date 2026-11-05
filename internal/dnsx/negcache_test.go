package dnsx

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestNegativeCacheExpires(t *testing.T) {
	srv := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	r := newTestResolver(t, []string{srv.Addr}, time.Minute)
	r.negTTL = 30 * time.Millisecond

	srv.Mute(true)
	if _, err := r.LookupIP(context.Background(), "neg.example"); err == nil {
		t.Fatal("上游装死时不该有答案")
	}
	n := srv.Queries()
	if _, err := r.LookupIP(context.Background(), "neg.example"); err == nil {
		t.Fatal("负缓存应直接返回失败")
	}
	if got := srv.Queries(); got != n {
		t.Fatalf("负缓存期间仍在问上游: %d -> %d", n, got)
	}

	srv.Mute(false)
	time.Sleep(r.negTTL + 20*time.Millisecond)
	addrs, err := r.LookupIP(context.Background(), "neg.example")
	if err != nil || len(addrs) == 0 {
		t.Fatalf("过期后应重新问到: %v %v", addrs, err)
	}
}

func TestCacheKeepsRecentlyUsed(t *testing.T) {
	srv := startFakeDNS(t, 0, net.ParseIP("93.184.216.34"))
	r := newTestResolver(t, []string{srv.Addr}, time.Minute)
	r.maxEntries = 2

	for _, name := range []string{"old.example", "keep.example", "new.example"} {
		if _, err := r.LookupIP(context.Background(), name); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// 碰一下 keep，让它比 old 更近。此时缓存里最多 2 条，old 应当已经在插入 new 时被丢掉。
	if _, err := r.LookupIP(context.Background(), "keep.example"); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	_, oldThere := r.cache[r.key(PathDirect, "old.example")]
	_, keepThere := r.cache[r.key(PathDirect, "keep.example")]
	_, newThere := r.cache[r.key(PathDirect, "new.example")]
	r.mu.Unlock()
	if oldThere {
		t.Fatal("最久没用的 old 还在缓存里")
	}
	if !keepThere || !newThere {
		t.Fatalf("最近用过的条目被丢掉了 keep=%v new=%v", keepThere, newThere)
	}
}
