package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"wps_app/internal/config"
)

// MaskedSecret 是密码类字段回给前端时的占位符。
//
// 明文口令永远不过 Wails 边界：读配置时换成这个串，回写时如果拿到的仍是它，
// 就沿用磁盘上的原值。前端要改口令就填新值，不填就保持不变。
const MaskedSecret = "********"

// InboundForm 是一条入站监听的可编辑形态。
type InboundForm struct {
	Type   string `json:"type"`
	Listen string `json:"listen"`
	// Username/Password 是掩码值，不是明文；HTTP 入站恒为空。
	Username string `json:"username"`
	Password string `json:"password"`
}

// TUNForm 是 TUN 模式的可编辑形态。字段与 config.TUNConfig 一一对应，
// 只有 HijackDNS 展平成 bool（配置里是指针，指针过不了 JSON 边界）。
type TUNForm struct {
	Enable       bool     `json:"enable"`
	Device       string   `json:"device"`
	Address      string   `json:"address"`
	MTU          int      `json:"mtu"`
	DNS          string   `json:"dns"`
	FakeIPRange  string   `json:"fakeIpRange"`
	HijackDNS    bool     `json:"hijackDns"`
	StrictRoute  bool     `json:"strictRoute"`
	RouteExclude []string `json:"routeExclude"`
}

// ConfigForm 是配置表单的可编辑投影，字段全为普通值。
//
// 刻意不复用 config.Config：Duration 需要以 "3s" 这样的字符串进出界面，
// 口令需要掩码，直接把配置结构体送出去会同时泄漏凭据和纳秒数。
//
// 节点列表不在这里——增删改节点走 Profiles/AddProfile/UpdateProfile/
// RemoveProfile 这组专用方法。表单一次改一整份列表，会把「掩码口令」
// 「改名」「当前选中项」三件事搅在一起，出问题很难归因。
type ConfigForm struct {
	Path       string `json:"path"`
	Mode       string `json:"mode"`
	ActiveName string `json:"activeName"`
	ActiveAddr string `json:"activeAddr"`

	Inbounds  []InboundForm `json:"inbounds"`
	GeoIPPath string        `json:"geoipPath"`
	RulesFile string        `json:"rulesFile"`

	DNSServers []string `json:"dnsServers"`
	DNSTimeout string   `json:"dnsTimeout"`
	DNSCache   string   `json:"dnsCache"`
	LogLevel   string   `json:"logLevel"`

	TUN TUNForm `json:"tun"`
}

// readForm 读磁盘配置并转成掩码后的表单。
func readForm(path string) (ConfigForm, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return ConfigForm{}, err
	}
	f := ConfigForm{
		Path:       path,
		Mode:       string(cfg.ModeValue()),
		ActiveName: cfg.Active,
		ActiveAddr: cfg.ActiveServer().Addr,
		GeoIPPath:  cfg.GeoIP.Path,
		RulesFile:  cfg.RulesFile,
		DNSServers: append([]string(nil), cfg.DNS.Servers...),
		DNSTimeout: cfg.DNS.Timeout.String(),
		DNSCache:   cfg.DNS.Cache.String(),
		LogLevel:   cfg.Log.Level,
		Inbounds:   make([]InboundForm, 0, len(cfg.Inbounds)),
		TUN: TUNForm{
			Enable:       cfg.TUN.Enable,
			Device:       cfg.TUN.Device,
			Address:      cfg.TUN.Address,
			MTU:          cfg.TUN.MTU,
			DNS:          cfg.TUN.DNS,
			FakeIPRange:  cfg.TUN.FakeIPRange,
			HijackDNS:    cfg.TUN.DNSHijackEnabled(),
			StrictRoute:  cfg.TUN.StrictRoute,
			RouteExclude: append([]string(nil), cfg.TUN.RouteExclude...),
		},
	}
	for _, in := range cfg.Inbounds {
		item := InboundForm{Type: in.Type, Listen: in.Listen}
		if in.Username != "" {
			item.Username = MaskedSecret
		}
		if in.Password != "" {
			item.Password = MaskedSecret
		}
		f.Inbounds = append(f.Inbounds, item)
	}
	if f.DNSServers == nil {
		f.DNSServers = []string{}
	}
	if f.TUN.RouteExclude == nil {
		f.TUN.RouteExclude = []string{}
	}
	return f, nil
}

// writeForm 把表单覆盖到磁盘配置上并保存。
//
// cur 先 Load 一遍，用途有二：一是拿回被掩码挡住的真实口令，
// 二是让「留空即不变」的语义有参照物——空串代表用户没动这个字段，
// 而不是「把值清空」。
func writeForm(path string, f ConfigForm) error {
	cur, err := config.Load(path)
	if err != nil {
		return err
	}
	next := *cur
	if mode, err := config.ParseMode(f.Mode); err != nil {
		return fmt.Errorf("mode: %w", err)
	} else {
		next.Mode = string(mode)
	}

	setIfNotEmpty(&next.RulesFile, f.RulesFile)
	setIfNotEmpty(&next.GeoIP.Path, f.GeoIPPath)
	setIfNotEmpty(&next.Log.Level, f.LogLevel)
	if servers := splitList(f.DNSServers); servers != nil {
		next.DNS.Servers = servers
	}
	if f.DNSTimeout != "" {
		d, err := parseDuration(f.DNSTimeout)
		if err != nil {
			return fmt.Errorf("dns.timeout: %w", err)
		}
		next.DNS.Timeout = config.Duration{Duration: d}
	}
	if f.DNSCache != "" {
		d, err := parseDuration(f.DNSCache)
		if err != nil {
			return fmt.Errorf("dns.cache: %w", err)
		}
		next.DNS.Cache = config.Duration{Duration: d}
	}
	if len(f.Inbounds) > 0 {
		inbounds := make([]config.InboundConfig, 0, len(f.Inbounds))
		for _, in := range f.Inbounds {
			item := config.InboundConfig{Type: strings.TrimSpace(in.Type), Listen: strings.TrimSpace(in.Listen)}
			// 入站的口令与 auth 同理：拿到掩码就沿用原来的，
			// 留空表示「这条入站不用认证」。
			old := findInbound(cur.Inbounds, item.Type, item.Listen)
			if in.Username != MaskedSecret {
				item.Username = in.Username
			} else if old != nil {
				item.Username = old.Username
			}
			if in.Password != MaskedSecret {
				item.Password = in.Password
			} else if old != nil {
				item.Password = old.Password
			}
			inbounds = append(inbounds, item)
		}
		next.Inbounds = inbounds
	}

	// TUN 段落：整块替换，但把「什么都没填」当成「没动过」。
	// 否则界面提交一个只改日志级别的空表单，就会顺手把用户的网卡名、
	// 假 IP 段全清零——这类静默清空比报错难查十倍。
	if f.TUN.Enable || f.TUN.Device != "" || f.TUN.Address != "" || f.TUN.FakeIPRange != "" {
		keep := cur.TUN
		next.TUN = config.TUNConfig{
			Enable:       f.TUN.Enable,
			Device:       strings.TrimSpace(f.TUN.Device),
			Address:      strings.TrimSpace(f.TUN.Address),
			MTU:          f.TUN.MTU,
			DNS:          strings.TrimSpace(f.TUN.DNS),
			FakeIPRange:  strings.TrimSpace(f.TUN.FakeIPRange),
			HijackDNS:    &f.TUN.HijackDNS,
			StrictRoute:  f.TUN.StrictRoute,
			RouteExclude: splitList(f.TUN.RouteExclude),
		}
		// 留空的子项沿用磁盘上的值。注意方向：是「新值为空才回填」，
		// 反过来写会把用户刚填的网卡名又盖回旧名。
		if next.TUN.Device == "" {
			next.TUN.Device = keep.Device
		}
		if next.TUN.Address == "" {
			next.TUN.Address = keep.Address
		}
		if next.TUN.DNS == "" {
			next.TUN.DNS = keep.DNS
		}
		if next.TUN.FakeIPRange == "" {
			next.TUN.FakeIPRange = keep.FakeIPRange
		}
		if next.TUN.MTU == 0 {
			next.TUN.MTU = keep.MTU
		}
		if next.TUN.RouteExclude == nil {
			next.TUN.RouteExclude = keep.RouteExclude
		}
		// helper 是「用哪条命令提权」，刻意不做成表单字段：让它跟着表单进出，
		// 等于允许一次「顺手保存」改写 root 的命令行。
		// 这一项只能在 config.yaml 里改，改完重启面板生效。
		next.TUN.Helper = keep.Helper
		// v6 那一组同理。带着进表单就意味着界面得展示它们，
		// 而漏展示又会被上面那句「留空即沿用」静悄悄改回去。
		// 不如明确只保留：一次面板保存不该动到用户的 IPv6 选择。
		next.TUN.Address6 = keep.Address6
		next.TUN.FakeIPRange6 = keep.FakeIPRange6
		next.TUN.IPv6 = keep.IPv6
	}

	return config.Save(path, &next)
}

// findInbound 按类型与监听地址找回原配置，用于还原被掩码的入站凭据。
func findInbound(list []config.InboundConfig, typ, listen string) *config.InboundConfig {
	for i := range list {
		if list[i].Type == typ && list[i].Listen == listen {
			return &list[i]
		}
	}
	return nil
}

func setIfNotEmpty(dst *string, v string) {
	if s := strings.TrimSpace(v); s != "" {
		*dst = s
	}
}

// parseDuration 解析表单里的 "3s" / "300" 这类时长输入。
//
// 空串由调用方提前挡掉；无单位的纯数字按「秒」处理，与 config.Duration 的
// UnmarshalYAML 保持一致，免得同一个字符串在读与写两条路上含义不同。
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return time.Duration(n * float64(time.Second)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return d, nil
}

// splitList 把逗号分隔的输入拆成列表。全空返回 nil，表示「没动这个字段」。
func splitList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		for _, part := range strings.Split(s, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
