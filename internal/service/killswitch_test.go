package service

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/outbound"
	"wps_app/internal/tunx"
)

// 这一组盯的是「什么时候该动闸门」。
//
// 规则长什么样在 tunx 那层已经测够了；这里要钉住的是时机：
// 自动切换放弃时必须落下，节点通了/切成功了/用户手动点名时必须抬起。
// 落下没人抬起 = 网络一直断着；该落不落 = 故障期间流量裸奔。两边都是真事故。

// fakeKill 是故障保护的记账替身。
type fakeKill struct {
	mu       sync.Mutex
	arms     [][]string
	disarms  int
	state    tunx.KillState
	armError error
}

func (f *fakeKill) ArmKill(_ context.Context, allow []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.arms = append(f.arms, allow)
	if f.armError != nil {
		// 与真实现同形：失败也要把原因留下，界面据此才说得出「未生效」。
		f.state = tunx.KillState{Reason: f.armError.Error()}
		return f.armError
	}
	f.state = tunx.KillState{Armed: true, V4: true}
	return nil
}

func (f *fakeKill) DisarmKill() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disarms++
	f.state = tunx.KillState{}
	return nil
}

func (f *fakeKill) Kill() tunx.KillState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

func (f *fakeKill) counts() (arms, disarms int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.arms), f.disarms
}

func (f *fakeKill) lastAllow() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.arms) == 0 {
		return nil
	}
	return f.arms[len(f.arms)-1]
}

// killReady 起一个「开了保护、执行面就位」的服务。
//
// 只翻 KillSwitch/StrictRoute 这两个开关，不翻 TUN.Enable：后者会让服务去真开网卡。
func killReady(t *testing.T) (*Service, *fakeKill) {
	t.Helper()
	svc, _ := startTwoNodes(t)
	if err := svc.mutate(func(c *config.Config) error {
		c.TUN.StrictRoute = true
		c.TUN.KillSwitch = true
		return nil
	}); err != nil {
		t.Fatalf("开保护开关: %v", err)
	}
	fake := &fakeKill{}
	svc.mu.Lock()
	svc.killOp = fake
	svc.mu.Unlock()
	return svc, fake
}

// TestFailoverGiveUpArmsKillSwitch：所有候选都不通时闸门必须落下。
func TestFailoverGiveUpArmsKillSwitch(t *testing.T) {
	svc, fake := killReady(t)
	svc.probeCandidate = func(outbound.Dialer) error { return errors.New("试拨不通") }

	svc.tryFailover("a-hy2")

	if arms, _ := fake.counts(); arms != 1 {
		t.Fatalf("放弃时没挂保护（或挂多了）: arms=%d", arms)
	}
	// 白名单必须两个节点都在：只有活动节点的话，下一次试拨备用节点会被
	// 自己的规则拒掉，报错和「备用节点也死了」一模一样。
	allow := fake.lastAllow()
	if !slices.Contains(allow, "127.0.0.1") {
		t.Fatalf("白名单里没有节点地址: %v", allow)
	}
	for i, a := range allow {
		if slices.Index(allow[:i], a) >= 0 {
			t.Errorf("同一个地址重复放行 %s: %v", a, allow)
		}
	}
}

// TestFailoverNoCandidatesAlsoArms：其余节点都在冷却里时同样要落下。
//
// 「无处可切」和「切不过去」对用户的机器是同一件事：流量正一条条失败在坏节点上。
func TestFailoverNoCandidatesAlsoArms(t *testing.T) {
	svc, fake := killReady(t)
	svc.mu.Lock()
	svc.cooling = map[string]time.Time{"b-trojan": time.Now().Add(time.Minute)}
	svc.mu.Unlock()

	svc.tryFailover("a-hy2")
	if arms, _ := fake.counts(); arms != 1 {
		t.Fatalf("没有候选时没挂保护: arms=%d", arms)
	}
}

// TestKillSwitchStaysClosedWhenConfigOff：默认关闭这条必须真成立。
//
// 这道保护动的是本机所有出站。用户没开，就不能有一行规则被写进去——
// 哪怕一次「看起来更安全」的自作主张。
func TestKillSwitchStaysClosedWhenConfigOff(t *testing.T) {
	svc, _ := startTwoNodes(t)
	fake := &fakeKill{}
	svc.mu.Lock()
	svc.killOp = fake
	svc.mu.Unlock()

	svc.probeCandidate = func(outbound.Dialer) error { return errors.New("试拨不通") }
	svc.tryFailover("a-hy2")
	if arms, _ := fake.counts(); arms != 0 {
		t.Fatalf("没开保护也挂了闸门: arms=%d", arms)
	}
}

// TestArmKillIsIdempotentUntilAllowListChanges：同一份名单不重挂。
//
// 重挂会把已经放行的连接闪断一次（-F 把链清空），而节点掉线时每一次拨号失败
// 都会想挂一次。名单变了才必须重挂——见下面那条用例，那是唯一的自救通道。
func TestArmKillIsIdempotentUntilAllowListChanges(t *testing.T) {
	svc, fake := killReady(t)
	svc.armKill("第一轮")
	svc.armKill("第二轮")
	svc.armKill("第三轮")
	if arms, _ := fake.counts(); arms != 1 {
		t.Fatalf("名单没变却挂了 %d 次", arms)
	}
}

// TestArmKillRefreshesWhenAllowListGrows 是那道闸门唯一能自己松开的机会。
//
// 挂上那一刻某个节点的域名没解析出来，它就不在白名单里；此后自动切换试拨它
// 会被我们自己的 DROP 拒掉。等那个地址终于解析出来时必须重挂，
// 否则「故障保护」就永久变成「谁也连不上」。
func TestArmKillRefreshesWhenAllowListGrows(t *testing.T) {
	svc, fake := killReady(t)
	svc.armKill("第一轮")
	if err := svc.mutate(func(c *config.Config) error {
		c.Proxies = append(c.Proxies, config.ProxyProfile{
			Name:   "c-late",
			Server: config.ServerConfig{Addr: "203.0.113.66:443", Auth: "x"},
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	svc.armKill("第二轮")
	if arms, _ := fake.counts(); arms != 2 {
		t.Fatalf("白名单变了却没有重挂: arms=%d", arms)
	}
	if !slices.Contains(fake.lastAllow(), "203.0.113.66") {
		t.Errorf("新节点的地址没进白名单: %v", fake.lastAllow())
	}
}

// TestArmKillFailureDoesNotLatchTheKey：挂失败时不记录名单。
//
// 记了的话，下一轮就会因为「名单没变」而跳过重挂——于是这一次失败就成了永久的
// 「保护看起来开着，其实一条规则都没有」。
func TestArmKillFailureDoesNotLatchTheKey(t *testing.T) {
	svc, fake := killReady(t)
	fake.mu.Lock()
	fake.armError = errors.New("iptables 拒绝")
	fake.mu.Unlock()

	svc.armKill("第一轮")
	if st := fake.Kill(); st.Armed || st.Reason == "" {
		t.Fatalf("挂失败却要报未生效: %+v", st)
	}
	fake.mu.Lock()
	fake.armError = nil
	fake.mu.Unlock()
	svc.armKill("第二轮")
	if arms, _ := fake.counts(); arms != 2 {
		t.Fatalf("上一轮失败后这一轮没重试: arms=%d", arms)
	}
	if !fake.Kill().Armed {
		t.Error("重试成功了却没报已挂上")
	}
}

// TestKillAllowListCarriesEveryNode：白名单来自所有节点，不止 active。
func TestKillAllowListCarriesEveryNode(t *testing.T) {
	svc, _ := startTwoNodes(t)
	var cfg *config.Config
	svc.mu.Lock()
	cfg = svc.cfg
	svc.mu.Unlock()
	got := svc.killAllowList(cfg)
	if len(got) == 0 {
		t.Fatal("白名单是空的")
	}
	seen := map[string]bool{}
	for _, a := range got {
		if seen[a] {
			t.Errorf("重复的放行地址 %s：日志里全是看不出区别的行", a)
		}
		seen[a] = true
	}
}

// TestDialOnProxyDisarmsKillSwitch：节点通了就得放行。
//
// 这是唯一的抬起信号——失败观察者只能告诉我们坏了几次。
// 它落在 goroutine 里（不能抱着 s.mu 去动 iptables），所以要等它跑完。
func TestDialOnProxyDisarmsKillSwitch(t *testing.T) {
	svc, fake := killReady(t)
	svc.armKill("故障")
	armsBefore, _ := fake.counts()
	if armsBefore != 1 {
		t.Fatalf("前置：应先挂上: arms=%d", armsBefore)
	}

	svc.observeDialOK(outbound.Dialer(svc.proxy))
	if !waitUntil(2*time.Second, func() bool {
		_, d := fake.counts()
		return d > 0
	}) {
		t.Fatal("节点恢复后没有解除保护")
	}
	if fake.Kill().Armed {
		t.Error("解除后仍报挂着")
	}
}

// TestDialOnOtherDialerDoesNotDisarm：直连成功不能替节点宣布恢复。
//
// 用户自己的网络通不通与隧道活没活是两件事——判据与 observeDialFault 对称。
func TestDialOnOtherDialerDoesNotDisarm(t *testing.T) {
	svc, fake := killReady(t)
	svc.armKill("故障")
	svc.observeDialOK(outbound.Dialer(nopDialer{}))
	// 同一份判据的另一半会异步落下去，给它一点时间再认定「确实没解除」。
	if waitUntil(300*time.Millisecond, func() bool {
		_, d := fake.counts()
		return d > 0
	}) {
		t.Fatal("一次直连成功把保护解除了")
	}
}

// TestDialOKIsCheapWhenNotArmed：这条路径每条连接都要走。
//
// 保护没挂着时去摘链，等于每条正常连接都付一趟 helper 往返——
// 而它换来的只是「本来就没有」这个错误。
func TestDialOKIsCheapWhenNotArmed(t *testing.T) {
	svc, fake := killReady(t)
	for i := 0; i < 50; i++ {
		svc.observeDialOK(outbound.Dialer(svc.proxy))
	}
	time.Sleep(200 * time.Millisecond)
	if _, d := fake.counts(); d != 0 {
		t.Fatalf("没挂保护时不该动闸门: disarms=%d", d)
	}
}

// TestManualPickDisarmsKillSwitch：人工点名节点是这把锁的手动出口。
//
// 自动切换判死时备用节点的地址可能还没进白名单，于是它连不上、也切不过去；
// 用户亲手指了一个之后还继续拦着，就是把用户的决定挡在自己的规则后面。
func TestManualPickDisarmsKillSwitch(t *testing.T) {
	svc, fake := killReady(t)
	svc.armKill("故障")
	if err := svc.SetActiveProfile("b-trojan"); err != nil {
		t.Fatalf("手动切换: %v", err)
	}
	if _, d := fake.counts(); d != 1 {
		t.Fatalf("手动选点后没解除保护: disarms=%d", d)
	}
}

// TestSuccessfulFailoverDisarms：切成功了就该放行。
func TestSuccessfulFailoverDisarms(t *testing.T) {
	svc, fake := killReady(t)
	svc.probeCandidate = func(outbound.Dialer) error { return nil }
	svc.armKill("故障")
	svc.tryFailover("a-hy2")
	if got := svc.Snapshot().ActiveProfile; got == "a-hy2" {
		t.Fatalf("前置没成立：这一轮没切过去（%q），后面的断言无从谈起", got)
	}
	if _, d := fake.counts(); d == 0 {
		t.Fatal("切换成功后仍压着出站")
	}
}

// waitUntil 给一个异步动作一点时间：disarm 是在 goroutine 里跑的。
func waitUntil(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return cond()
}
