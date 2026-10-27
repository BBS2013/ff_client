package tunx

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
)

// helper 协议版本：面板与 helper 来自同一个二进制，版本对不上只可能是
// 「用新的面板配了老的 sudoers 路径」这种部署错位，必须当场说清而不是行为漂移。
const helperProtoVersion = 1

// helper 只做这三件事。任何一件都不接受调用方给的命令行，
// 全部动作由本包按 RoutePlan 现算——这是把 root 权限收窄成「只能按我们的规矩开网卡」的关键。
const (
	ActionUp      = "up"
	ActionDown    = "down"
	ActionCleanup = "cleanup"
)

// HelperRequest 是面板发给 helper 的请求。
type HelperRequest struct {
	V      int       `json:"v"`
	Action string    `json:"action"`
	Plan   RoutePlan `json:"plan"`
}

// HelperReply 是 helper 的应答。up 成功时另附一个 tun 设备 fd（见 SendReply）。
type HelperReply struct {
	OK      bool     `json:"ok"`
	Err     string   `json:"err,omitempty"`
	Applied []string `json:"applied,omitempty"` // 实际执行过的步骤描述，直接进面板日志
	// V6OK 报告 v6 那一组命令是否全装上了。false 时面板据此让 AAAA 回 NODATA。
	V6OK    bool     `json:"v6ok,omitempty"`
	Device  string   `json:"device,omitempty"`
	MTU     uint32   `json:"mtu,omitempty"` // 网卡上的真实 MTU，建端点要以它为准
	Removed []string `json:"removed,omitempty"`
}

// nameChar 判断网卡名里的单个字符。网卡名会进 argv，虽然 exec 不经 shell、
// 注入不成立，但把它收紧到肉眼可辨的范围，出错时也更像人写的东西。
func validIfaceName(s string) bool {
	if s == "" || len(s) > 15 { // IFNAMSIZ-1，超了内核直接报错
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	// "." 与 ".." 不是网卡名，却能让后续拼路径/比前缀的逻辑出怪事。
	return s != "." && s != ".."
}

// validate 把请求里所有会被 root 用掉的参数过一遍。
//
// 这里的每一条都是在防「普通用户借 helper 把手伸进别的接口或别的路由」：
// helper 的父进程是 sudo 起来的 root，能做的事远比面板多，所以校验必须按
// 「输入不可信」来写，而不是按「反正配置是我们自己填的」。
func (r HelperRequest) validate() error {
	if r.V != helperProtoVersion {
		return fmt.Errorf("helper 协议版本 %d 不被支持（本程序是 %d）", r.V, helperProtoVersion)
	}
	switch r.Action {
	case ActionUp, ActionDown, ActionCleanup:
	default:
		return fmt.Errorf("未知的 helper 动作 %q", r.Action)
	}
	p := r.Plan
	if !validIfaceName(p.Device) {
		return fmt.Errorf("网卡名不合法: %q", p.Device)
	}
	if p.Address == "" {
		return errors.New("address 必填")
	}
	prefix, err := netip.ParsePrefix(p.Address)
	if err != nil {
		return fmt.Errorf("address %q 不是合法 CIDR: %w", p.Address, err)
	}
	// 网卡地址是 /0 意味着「把整个地址空间让给 tun」，那不是这台机器想要的配置。
	if prefix.Bits() == 0 {
		return fmt.Errorf("address %q 的掩过短，拒绝执行", p.Address)
	}
	if p.MTU < 0 || p.MTU > 65535 {
		return fmt.Errorf("mtu %d 超出范围", p.MTU)
	}
	if p.UID < 0 {
		return fmt.Errorf("uid 不能为负")
	}
	if p.HijackDNS {
		if p.DNS == "" {
			return errors.New("开启 DNS 劫持必须给出 dns 地址")
		}
		if net.ParseIP(p.DNS) == nil {
			return fmt.Errorf("dns %q 不是合法 IP", p.DNS)
		}
		// 上游地址会变成劫持链里的 `-d <ip>/32`，所以必须是字面量 IP，
		// 而且要给出至少一个——没有可放行的上游就不许劫持（自己吃自己）。
		if len(p.Upstreams) == 0 {
			return errors.New("开启 DNS 劫持必须给出要放行的上游地址")
		}
		if len(p.Upstreams) > 16 {
			// 每个上游两条规则。给个上限，免得一次写入几百条规则把 nat 表变成迷宫。
			return fmt.Errorf("上游数量 %d 过多", len(p.Upstreams))
		}
		for _, up := range p.Upstreams {
			if net.ParseIP(strings.TrimSpace(up)) == nil {
				return fmt.Errorf("上游 DNS %q 不是 IP 字面量", up)
			}
		}
	}
	if p.FakeIPRange != "" {
		fp, err := netip.ParsePrefix(p.FakeIPRange)
		if err != nil {
			return fmt.Errorf("fake_ip_range %q 不是合法 CIDR: %w", p.FakeIPRange, err)
		}
		if fp.Bits() < 8 {
			return fmt.Errorf("fake_ip_range %q 段过大，拒绝写入路由", p.FakeIPRange)
		}
	}
	// v6 那一组同样会被 root 用掉（ip -6 route / ip6tables），逐个校验。
	if p.Address6 != "" {
		ap, err := netip.ParsePrefix(p.Address6)
		if err != nil {
			return fmt.Errorf("address6 %q 不是合法 CIDR: %w", p.Address6, err)
		}
		if !ap.Addr().Is6() {
			return fmt.Errorf("address6 %q 必须是 IPv6 地址", p.Address6)
		}
		if ap.Bits() == 0 {
			return fmt.Errorf("address6 %q 的掩过短，拒绝执行", p.Address6)
		}
	}
	if p.FakeIPRange6 != "" {
		fp, err := netip.ParsePrefix(p.FakeIPRange6)
		if err != nil {
			return fmt.Errorf("fake_ip_range6 %q 不是合法 CIDR: %w", p.FakeIPRange6, err)
		}
		if !fp.Addr().Is6() {
			return fmt.Errorf("fake_ip_range6 %q 必须是 IPv6 网段", p.FakeIPRange6)
		}
		// /8 及更短会把整块 v6 地址空间路由进 tun；/33 及更长又放不下假 IP。
		if fp.Bits() < 8 || fp.Bits() > 32 {
			return fmt.Errorf("fake_ip_range6 %q 的段大小不合适（需 /8~/32）", p.FakeIPRange6)
		}
	}
	if p.DNS6 != "" && net.ParseIP(p.DNS6) == nil {
		return fmt.Errorf("dns6 %q 不是合法 IP", p.DNS6)
	}
	if p.StrictRoute {
		// 改默认路由是最容易把机器搞挂的一步，网关与网卡信息必须齐全且合法。
		if !validIfaceName(p.Interface) {
			return fmt.Errorf("strict_route 的网卡名不合法: %q", p.Interface)
		}
		if net.ParseIP(p.Gateway) == nil {
			return fmt.Errorf("strict_route 的网关 %q 不是合法 IP", p.Gateway)
		}
		if p.Gateway == "0.0.0.0" || p.Gateway == "::" {
			return fmt.Errorf("strict_route 的网关 %q 无效", p.Gateway)
		}
	}
	for _, cidr := range p.Exclude {
		if _, err := netip.ParsePrefix(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("排除网段 %q 不是合法 CIDR", cidr)
		}
	}
	// up 之外，down/cleanup 只需要网卡与地址；提前把 up 会用到的字段验齐，
	// 免得 helper 在 down 路径上因为一个无关的空值罢工。
	return nil
}

// truncate 把一段外部文本压进错误信息里；按 rune 切，免得把中文截成半个字。
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if n <= 0 || len(s) <= n {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}

// CleanupRequest 生成「清残留」请求：只需要网卡名与地址。
func CleanupRequest(uid int, device, address string) HelperRequest {
	return HelperRequest{
		V:      helperProtoVersion,
		Action: ActionCleanup,
		Plan:   RoutePlan{Device: device, Address: address, UID: uid},
	}
}

// 帧格式：4 字节大端长度 + JSON。长度上限是为了让一个畸形请求撑不爆内存，
// 而不是为了性能——请求体里最宽的字段就是 Exclude 列表。
const (
	maxHelperFrame = 1 << 16
	headerLen      = 4
)

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxHelperFrame {
		return fmt.Errorf("helper 报文过大: %d 字节", len(payload))
	}
	var head [headerLen]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(payload)))
	if _, err := w.Write(head[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var head [headerLen]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n == 0 || n > maxHelperFrame {
		return nil, fmt.Errorf("helper 报文长度非法: %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// encodeRequest/decodeRequest 把请求在 JSON 与字节之间来回搬。
// 单独拆出来是为了能让校验逻辑在没有 unix socket、没有 root 的情况下被完整测试。
func encodeRequest(req HelperRequest) ([]byte, error) { return json.Marshal(req) }

func decodeRequest(buf []byte) (HelperRequest, error) {
	var req HelperRequest
	if err := json.Unmarshal(buf, &req); err != nil {
		return req, fmt.Errorf("helper 请求解析失败: %w", err)
	}
	return req, nil
}

func encodeReply(reply HelperReply) ([]byte, error) { return json.Marshal(reply) }

func decodeReply(buf []byte) (HelperReply, error) {
	var reply HelperReply
	if err := json.Unmarshal(buf, &reply); err != nil {
		return reply, fmt.Errorf("helper 应答解析失败: %w", err)
	}
	return reply, nil
}
