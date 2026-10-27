package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"wps_app/internal/config"
	"wps_app/internal/dnsx"
	"wps_app/internal/httpprobe"
	"wps_app/internal/logx"
	"wps_app/internal/outbound"
)

// ProfileView 是一个代理服务在界面上的样子。
// 口令不过 Wails 边界，这里只报「有没有填」。
type ProfileView struct {
	Name string `json:"name"`
	// Type 是协议名（hysteria2 / trojan），界面靠它告诉用户这个节点走的是什么。
	Type    string `json:"type"`
	Addr    string `json:"addr"`
	SNI     string `json:"sni"`
	AuthSet bool   `json:"authSet"`
	// UDP 说清这个节点能不能转发 UDP。UDP 现在只有 hysteria2 节点支持，
	// 界面上必须把这件事讲在前面——否则 QUIC 应用会「看着通了却一直超时」。
	UDP    bool `json:"udp"`
	Active bool `json:"active"`
	// QuotaBytes 是这个节点的配额（字节），0 = 没设。见 config.ProxyProfile.Quota。
	QuotaBytes uint64 `json:"quotaBytes"`
	// QuotaText 是人写下来的那一句原文（"1.5TiB"）。界面用它说话，
	// 用 QuotaBytes 算百分比——两份各有分工，不是同一个值的两份拷贝。
	QuotaText string `json:"quotaText"`
}

// ProfileSpec 是新增/修改一个节点时要填的字段。
// Auth 可以是掩码占位符，表示「沿用磁盘上的原值」。
//
// Type 是协议名，留空表示沿用（新增时继承现有节点、修改时保持原样）：
// 界面把它做成下拉，两个协议的字段差异由 config 那层统一处理。
type ProfileSpec struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Addr          string `json:"addr"`
	Auth          string `json:"auth"`
	SNI           string `json:"sni"`
	Insecure      bool   `json:"insecure"`
	BandwidthUp   string `json:"bandwidthUp"`
	BandwidthDown string `json:"bandwidthDown"`
	Congestion    string `json:"congestion"`
	FastOpen      bool   `json:"fastOpen"`
	// Quota 是"1000GB"这种原文。留空 = 不改这个节点的配额
	// （与上面每一个字段同一套约定：空串是"没填"，不是"清空"，
	//  所以面板上没有把配额抹掉的入口——那要在配置文件里删那一行）。
	Quota string `json:"quota"`
}

// ---------- 分流模式 ----------

// Mode 返回当前生效的分流模式。
func (s *Service) Mode() string {
	// 与 Snapshot 同一个理由：读文件不能占用状态锁。
	cfg := s.diskConfig()

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rt != nil {
		return string(s.rt.Mode())
	}
	if s.cfg != nil {
		return string(s.cfg.ModeValue())
	}
	if cfg != nil {
		return string(cfg.ModeValue())
	}
	return string(config.ModeRule)
}

// SetMode 切换分流模式并落盘。
//
// 不重启进程：模式只影响「新连接怎么决策」，路由器里换一个原子值就够，
// 已经在传的连接按原路走完。这也是全局/规则之间来回切几乎零成本的原因。
func (s *Service) SetMode(mode string) error {
	m, err := config.ParseMode(mode)
	if err != nil {
		return err
	}
	if err := s.mutate(func(cfg *config.Config) error {
		cfg.Mode = string(m)
		return nil
	}); err != nil {
		return err
	}
	s.mu.Lock()
	rt := s.rt
	s.mu.Unlock()
	// 闸门跟着模式走：只有规则模式才分流。
	// 切完之后新连接立刻改走另一条路，正在传的那些按原路走完——与切模式本身的语义一致。
	s.applySplitGate(m)
	if rt != nil {
		rt.SetMode(m)
		return nil
	}
	// 没在跑就只改文件，下次 Start 会读新模式。
	s.mu.Lock()
	if s.cfg != nil {
		s.cfg.Mode = string(m)
	}
	s.mu.Unlock()
	logx.Infof("分流模式已设为 %s（当前未运行，启动后生效）", m)
	return nil
}

// OverrideMode 让命令行临时覆盖配置里的分流模式，不落盘。
//
// 与 SetMode 的区别就在这一个字：SetMode 是给界面用的，用户点了就要长期生效；
// OverrideMode 是给「这次先按全局跑一下看看」用的，改文件反而会造成困扰。
func (s *Service) OverrideMode(m config.Mode) error {
	if _, err := config.ParseMode(string(m)); err != nil {
		return err
	}
	s.mu.Lock()
	s.modeOverride = m
	rt := s.rt
	s.mu.Unlock()
	s.applySplitGate(m)
	if rt != nil {
		rt.SetMode(m)
	}
	return nil
}

// ---------- 代理服务（节点） ----------

// Profiles 返回全部节点与当前选中的名字。
func (s *Service) Profiles() ([]ProfileView, string, error) {
	// 走缓存：面板每次渲染设置页都会调它，而它只是一次纯读。
	cfg := s.diskConfig()
	if cfg == nil {
		// 缓存是空的说明真读过一次且失败了，把原因如实带回去，
		// 而不是返回一个空的节点列表让界面显示「没有节点」。
		if _, err := config.Load(s.cfgPath); err != nil {
			return nil, "", err
		}
		return nil, "", fmt.Errorf("配置不可用")
	}
	_, activeName := activeServerFor(cfg, s.activeOverride())
	return profileViews(cfg, activeName), activeName, nil
}

// activeOverride 读出本次运行的自动切换结果。
func (s *Service) activeOverride() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failoverOverride
}

// SetActiveProfile 切到某个节点。
//
// 顺序是「先装配、再落盘、最后提交」，理由见 stageActive：装配会失败，
// 而配置一旦写下去就收不回来了。
func (s *Service) SetActiveProfile(name string) error {
	proxy, err := s.stageActive(name)
	if err != nil {
		return err
	}
	if err := s.mutate(func(cfg *config.Config) error {
		found := false
		for _, p := range cfg.Proxies {
			if p.Name == name {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("节点 %q 不存在", name)
		}
		cfg.Active = name
		return nil
	}); err != nil {
		if proxy != nil {
			_ = proxy.Close()
		}
		return err
	}
	// 用户明确点名了要哪个节点，自动切换的那个结论就此作废：
	// 留着它，界面上看到的永远不是用户选的那个，而且没人能解释为什么。
	s.clearFailoverOverride()
	return s.commitProxy(proxy)
}

// clearFailoverOverride 丢掉本次运行的自动切换结果，并清空失败流水。
func (s *Service) clearFailoverOverride() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failoverOverride = ""
	s.switchedAt = time.Time{}
	s.cooling = nil
	s.faults = nil
	// 轮次冷却也要一起清：用户刚亲手点过节点，下一次自动切换不该被上一轮的账卡住。
	s.failoverRoundAt = time.Time{}
}

// AddProfile 新增一个节点。名字重复直接拒绝，
// 因为 active 是按名字寻址的，两个同名节点会让「切到哪个」变成玄学。
func (s *Service) AddProfile(p ProfileSpec) error {
	name := sanitizeName(p.Name, p.Addr)
	if name == "" {
		return fmt.Errorf("节点名不能为空")
	}
	return s.mutate(func(cfg *config.Config) error {
		for _, old := range cfg.Proxies {
			if old.Name == name {
				return fmt.Errorf("节点名 %q 已存在", name)
			}
		}
		srv := cfg.Proxies[0].Server // 缺省项沿用现有节点，界面只需填协议、地址与密钥
		srv.Type = pick(strings.TrimSpace(p.Type), srv.Type)
		if _, err := config.ParseProtocol(srv.Type); err != nil {
			return err
		}
		srv.Addr = strings.TrimSpace(p.Addr)
		srv.Congestion = pick(p.Congestion, srv.Congestion)
		if bw := strings.TrimSpace(p.BandwidthUp); bw != "" {
			srv.Bandwidth.Up = bw
		}
		if bw := strings.TrimSpace(p.BandwidthDown); bw != "" {
			srv.Bandwidth.Down = bw
		}
		srv.TLS.SNI = strings.TrimSpace(p.SNI)
		srv.TLS.Insecure = p.Insecure
		srv.FastOpen = p.FastOpen
		// trojan 没有拥塞算法、带宽和 TCP fastopen 的概念，从 hysteria2 节点
		// 继承这些字段只会让面板显示一句与实际无关的「本节点跑 BBR 200mbps」。
		if srv.Protocol() == config.ProtocolTrojan {
			srv.Bandwidth = config.BandwidthConfig{}
			srv.Congestion = ""
			srv.FastOpen = false
		}
		if auth := strings.TrimSpace(p.Auth); auth != "" && auth != maskedSecret {
			srv.Auth = auth
		}
		if srv.Auth == "" {
			return fmt.Errorf("节点 %q 缺少 auth", name)
		}
		quota, err := parseQuotaField(p.Quota)
		if err != nil {
			return err
		}
		cfg.Proxies = append(cfg.Proxies, config.ProxyProfile{Name: name, Server: srv, Quota: quota})
		return nil
	})
}

// UpdateProfile 就地改写某个节点的连接参数；auth 留空或仍是掩码就保持原值。
func (s *Service) UpdateProfile(name string, p ProfileSpec) error {
	return s.mutate(func(cfg *config.Config) error {
		for i := range cfg.Proxies {
			if cfg.Proxies[i].Name != name {
				continue
			}
			srv := cfg.Proxies[i].Server
			if t := strings.TrimSpace(p.Type); t != "" {
				if _, err := config.ParseProtocol(t); err != nil {
					return err
				}
				srv.Type = t
			}
			if addr := strings.TrimSpace(p.Addr); addr != "" {
				srv.Addr = addr
			}
			if auth := strings.TrimSpace(p.Auth); auth != "" && auth != maskedSecret {
				srv.Auth = auth
			}
			if sni := strings.TrimSpace(p.SNI); sni != "" {
				srv.TLS.SNI = sni
			}
			if bw := strings.TrimSpace(p.BandwidthUp); bw != "" {
				srv.Bandwidth.Up = bw
			}
			if bw := strings.TrimSpace(p.BandwidthDown); bw != "" {
				srv.Bandwidth.Down = bw
			}
			if c := strings.TrimSpace(p.Congestion); c != "" {
				srv.Congestion = c
			}
			srv.TLS.Insecure = p.Insecure
			srv.FastOpen = p.FastOpen
			if srv.Protocol() == config.ProtocolTrojan {
				// 协议被改成 trojan：hysteria2 专属字段清掉，理由见 AddProfile。
				srv.Bandwidth = config.BandwidthConfig{}
				srv.Congestion = ""
				srv.FastOpen = false
			}
			quota, err := parseQuotaField(p.Quota)
			if err != nil {
				return err
			}
			if quota != "" {
				cfg.Proxies[i].Quota = quota
			}
			cfg.Proxies[i].Server = srv
			if next := sanitizeName(p.Name, name); next != "" && next != name {
				for j := range cfg.Proxies {
					if cfg.Proxies[j].Name == next {
						return fmt.Errorf("节点名 %q 已存在", next)
					}
				}
				cfg.Proxies[i].Name = next
				if cfg.Active == name {
					cfg.Active = next
				}
			}
			return nil
		}
		return fmt.Errorf("节点 %q 不存在", name)
	})
}

// RemoveProfile 删掉一个节点。最后一个不许删：没有节点的客户端起不来，
// 而「界面点了一下结果软件打不开」是最难解释的故障。
func (s *Service) RemoveProfile(name string) error {
	// 删的若是当前选中的节点，active 会落到剩下的第一个上。
	// 先按那个节点把出站装配成功再动配置：装配会解析节点域名，失败时配置还来得及不改。
	var staged outbound.Conn
	if cfg := s.diskConfig(); cfg != nil && cfg.Active == name {
		for _, p := range cfg.Proxies {
			if p.Name != name {
				proxy, err := s.stageActive(p.Name)
				if err != nil {
					return err
				}
				staged = proxy
				break
			}
		}
	}

	activated := false
	newActive := ""
	if err := s.mutate(func(cfg *config.Config) error {
		kept := make([]config.ProxyProfile, 0, len(cfg.Proxies))
		for _, p := range cfg.Proxies {
			if p.Name != name {
				kept = append(kept, p)
			}
		}
		if len(kept) == len(cfg.Proxies) {
			return fmt.Errorf("节点 %q 不存在", name)
		}
		if len(kept) == 0 {
			return fmt.Errorf("至少保留一个代理服务")
		}
		cfg.Proxies = kept
		if cfg.Active == name {
			cfg.Active = kept[0].Name
			newActive = cfg.Active
			activated = true
		}
		return nil
	}); err != nil {
		if staged != nil {
			_ = staged.Close()
		}
		return err
	}
	if !activated {
		// 删的是没在用的节点：运行中的服务与它没有任何关系，
		// 不该为了"配置少了一条记录"把监听、网卡和正在传的连接全拆一遍。
		if staged != nil {
			_ = staged.Close()
		}
		return nil
	}
	if staged == nil {
		// 预演阶段读不到配置（第一次读盘就失败过），只能事后装配。
		// 仍比旧写法自洽：配置此刻已经是新节点了，最坏是"没换出站"而不是"两个节点各说一半"。
		proxy, err := s.stageActive(newActive)
		if err != nil {
			return err
		}
		staged = proxy
	}
	return s.commitProxy(staged)
}

// ProfileTest 是一次节点连通性自检结果。
type ProfileTest struct {
	Name      string `json:"name"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latencyMs"`
	Remote    string `json:"remote"`
	Error     string `json:"error"`
	// 下面三个是应用层那一步（取一个真页面）的读数，与上面的电路分开：
	// 电路通了不等于页面取回来。PageChecked 说探没探过，
	// 探过之后 PageErr 非空就是失败原文，为空就是 Page 那行读数。
	PageChecked bool   `json:"pageChecked"`
	Page        string `json:"page"`
	PageErr     string `json:"pageErr"`
}

// TestProfile 用指定节点单独握手并拨一次目标，量出建链耗时。
//
// 它与当前选中的节点无关：单独建一条临时出站，测完就关，
// 因此在界面上点「测速」不会打断正在跑的隧道。
func (s *Service) TestProfile(name, target string) ProfileTest {
	res := ProfileTest{Name: name}
	cfg, err := config.Load(s.cfgPath)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	var profile *config.ProxyProfile
	for i := range cfg.Proxies {
		if cfg.Proxies[i].Name == name {
			profile = &cfg.Proxies[i]
			break
		}
	}
	if profile == nil {
		res.Error = fmt.Sprintf("节点 %q 不存在", name)
		return res
	}
	if strings.TrimSpace(target) == "" {
		target = "www.gstatic.com:443"
	}
	res.Remote = target
	// 解析节点地址必须和真实出站用同一套直连 DNS。以前这里传的是 nil，
	// 于是退回系统解析——而 TUN 开着时系统解析正被我们自己的劫持改写过：
	// 节点域名通常不在规则集里、落到 FINAL=PROXY，会被答成一个假 IP，
	// 测速因此去连自家网卡，报回来的是 "connection reset by peer"
	// 这种和配置毫无关系、根本照着没法修的话（jp 节点实测踩过）。
	s.mu.Lock()
	resolve := s.resolve
	split := s.split
	s.mu.Unlock()
	if resolve == nil {
		r, rerr := dnsx.New(cfg.DNS.Servers, cfg.DNS.Timeout.Duration, cfg.DNS.Cache.Duration)
		if rerr != nil {
			res.Error = rerr.Error()
			return res
		}
		resolve = r
	}
	proxy, err := outbound.New(profile.Server, 8*time.Second, resolve, fakeRange(cfg), split)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer func() { _ = proxy.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := proxy.DialContext(ctx, target)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.LatencyMS = time.Since(start).Milliseconds()
	probeErr := probeAccept(conn)
	_ = conn.Close()
	if probeErr != nil {
		res.Error = probeErr.Error()
		return res
	}
	res.OK = true
	// 应用层再验一次：电路通了不等于页面取回来。
	pageProbe(ctx, proxy, profilePageProbe, &res)
	return res
}

// profilePageProbe 是节点测速顺带取页面的那个地址。
// 永远是同一个：它回答的是"这个节点能不能把一个境外页面取回来"，
// 那是节点级的问题，与这次拨的是哪个目标无关。
const profilePageProbe = "https://www.gstatic.com/generate_204"

// pageProbe 在电路已通的前提下单独再拨一次，取一个真页面回来判定。
//
// 为什么要多这一下：`probeAccept` 只看得出一个把连接直接关掉的节点。
// 另有一类节点是隧道正常建立、服务端把流量交给一个兼底的 web 服务器，
// 任何站点回来的都是同一张 400 页面——握手、探测、延迟全都好看，
// 而用户的浏览器一个页面都打不开。状态码与 `Server:` 头会当场把它说漏。
// 判据与命令行 `-check-fetch` 共用 internal/httpprobe，两条路不会各自漂移。
//
// 不复用上面那条连接：`probeAccept` 已经在它上面读过一次，
// 拿去做 TLS 握手会失败，而那看起来像节点的锅。
// 预算沿用测速那个 ctx 的剩余时间——一次点击不该比今天更慢。
func pageProbe(ctx context.Context, dialer outbound.Dialer, raw string, res *ProfileTest) {
	res.PageChecked = true
	t, err := httpprobe.Parse(raw)
	if err != nil {
		// 常量拆不开属于代码写错，但这里仍然要给一句原文：
		// 留一个空读数会被界面读成"没探"，而实际是"探了、连探针本身都没发出去"。
		res.PageErr = "探针地址用不了: " + err.Error()
		return
	}
	conn, derr := dialer.DialContext(ctx, t.Addr())
	if derr != nil {
		res.PageErr = fmt.Sprintf("拨 %s 失败: %v", t.Addr(), derr)
		return
	}
	defer func() { _ = conn.Close() }()
	out, ferr := httpprobe.Fetch(ctx, conn, t)
	if ferr == nil {
		ferr = out.Judge()
	}
	if ferr != nil {
		res.PageErr = ferr.Error()
		return
	}
	res.Page = out.String()
}

// authProbeTimeout 是测速探测读的等待时间。
const authProbeTimeout = 400 * time.Millisecond

// probeAccept 探一次「服务端是否还活着」。
//
// trojan 的口令校验发生在 TLS 握手之后：头部发完，DialContext 就成功了，
// 而口令不对的服务端是直接把连接关掉——不返回任何错误码。
// 只看握手结果的测速会把一条配错口令的节点显示成「87 ms 正常」。
//
// 所以握手后再读一字节：读到东西或读超时都算正常（正常服务端发完头部就沉默，
// 在等我们的第一个字节），只有读回一个真正的错误才算失败。
// hysteria2 走同一条路径也成立：它的认证在 QUIC 握手里，到这一步连接必然是好的。
func probeAccept(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(authProbeTimeout)); err != nil {
		// 设不上超时就不探了：探针是用来发现坏配置的，不该自己变成测速卡住的原因。
		return nil
	}
	n, err := conn.Read(make([]byte, 1))
	if n > 0 || err == nil {
		return nil
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return nil
	}
	return fmt.Errorf("服务端在读完请求头后断开了连接（口令不对或目标不可达）: %w", err)
}

// ---------- 内部小工具 ----------

// maskedSecret 与 ui 层保持一致：表单里回显的占位符不是真口令。
const maskedSecret = "********"

func profileViews(cfg *config.Config, activeName string) []ProfileView {
	out := make([]ProfileView, 0, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		out = append(out, ProfileView{
			Name:    p.Name,
			Type:    p.Server.Protocol(),
			Addr:    p.Server.Addr,
			SNI:     p.Server.TLS.SNI,
			AuthSet: strings.TrimSpace(p.Server.Auth) != "",
			UDP:     p.Server.Protocol() == config.ProtocolHysteria2,
			// 打「使用中」标要看本次运行真正生效的那个名字，
			// 而不是配置文件里写的那个：自动切换之后两者会不一样。
			Active: p.Name == activeName,
			// 配额给两份：换算后的字节用来算百分比，
			// 原文用来说话。只给字节的话，写 "1.5TiB" 的人会在界面上
			// 看到 "1.6 TB"——同一个数换了单位，人就以为程序把配置改了。
			QuotaBytes: p.QuotaBytes(),
			QuotaText:  strings.TrimSpace(p.Quota),
		})
	}
	return out
}

// parseQuotaField 把界面上填的配额先过一遍尺寸解析。
// 不留到 Save 里的 Validate 去报：那时错误会从"写盘失败"那条路绕回来，
// 指不清是哪一格填错了。
func parseQuotaField(q string) (string, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return "", nil
	}
	if _, err := config.ParseSize(q); err != nil {
		return "", err
	}
	return q, nil
}

func sanitizeName(name, fallback string) string {
	if n := strings.TrimSpace(name); n != "" {
		return n
	}
	return strings.TrimSpace(fallback)
}

func pick(a, b string) string {
	if s := strings.TrimSpace(a); s != "" {
		return s
	}
	return b
}
