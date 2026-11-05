package inbound

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"wps_app/internal/logx"
	"wps_app/internal/metrics"
	"wps_app/internal/outbound"
	"wps_app/internal/rules"
)

// udpAssocIdle 是一条 UDP 关联在完全静默后回收的窗口。
//
// 关联的生命由控制连接决定（RFC 1928：控制连接一断，关联即作废），
// 但客户端完全可能连上就再不发任何包、也不断开。十分钟足够覆盖
// 「开着一条关联等下一场游戏」这类用法，又不至于让空连接无限期挂着。
const udpAssocIdle = 10 * time.Minute

// udpAssocBuffer 是关联收发的缓冲，取满 64K 与 IP 层上限一致：
// 小于它的读会把报文尾巴直接截掉，而丢的正是对端最后的若干字节。
const udpAssocBuffer = 65535

// udpAssocQueue 是客户端→隧道这一侧的单向排队深度。
//
// UDP 本来就没有「排不进去」的语义，队列满了丢最新的包即可，
// 有界是为了不让一个只发不收的客户端把内存吃光。
const udpAssocQueue = 64

// datagram 是一个已剥掉 SOCKS5 头、准备进隧道的 UDP 报文。
// from 是它实际到达中继口时的来源，回包要照着这个地址送回去。
type datagram struct {
	addr string
	data []byte
	from *net.UDPAddr
}

// serveUDPAssociate 处理一条 UDP ASSOCIATE。
//
// 关联的生命挂在控制连接上：一个 TCP 连接对应一个本进程内的 UDP 中继 socket，
// 客户端把报文发给它、中继再按规则转到出站。关联本身不含任何目标——
// 每个报文自带地址，这才是 UDP 转发该有的样子。
func (s *SOCKS5) serveUDPAssociate(ctl net.Conn) {
	uc, bound, clientIP, err := bindAssocSocket(ctl)
	if err != nil {
		logx.Warnf("socks5 %s: UDP ASSOCIATE 建中继失败: %v", ctl.RemoteAddr(), err)
		_ = reply(ctl, repGeneralFailure)
		return
	}
	defer uc.Close()
	if err := replyAddr(ctl, repSuccess, bound); err != nil {
		return
	}
	logx.Debugf("socks5 %s: UDP 关联已建立在 %s", ctl.RemoteAddr(), bound)

	// 控制连接一断就整条关联作废。客户端在这之后不会再发请求，
	// 继续读只是为了等它的 EOF——顺带关掉中继 socket，那正是唤醒主循环的手段。
	go func() {
		_ = ctl.SetReadDeadline(time.Time{})
		_, _ = io.Copy(io.Discard, ctl)
		_ = uc.Close()
	}()

	in := make(chan datagram, udpAssocQueue)
	go readAssocPackets(uc, clientIP, in)
	s.pumpAssoc(ctl, uc, in)
}

// readAssocPackets 从中继 socket 读客户端的报文，剥掉 SOCKS5 UDP 头后送进 in。
// 出错或空闲回收时关闭 in，主循环随之收尾。
func readAssocPackets(uc *net.UDPConn, clientIP net.IP, in chan<- datagram) {
	defer close(in)
	buf := make([]byte, udpAssocBuffer)
	for {
		_ = uc.SetReadDeadline(time.Now().Add(udpAssocIdle))
		n, from, err := uc.ReadFromUDP(buf)
		if err != nil {
			if isTimeout(err) {
				logx.Debugf("socks5: UDP 关联空闲 %v，已回收", udpAssocIdle)
			}
			return
		}
		// 中继 socket 绑在一个具体的本地地址上，同机任何一个进程都够得着。
		// 只认发起这条控制连接的那个 IP：SOCKS5 UDP 报文本身没有身份，
		// 关联的权限就是「这条 TCP 连接」的那一份，不能让别的进程搭车。
		if !from.IP.Equal(clientIP) {
			continue
		}
		addr, payload, ok := parseAssocPacket(buf[:n])
		if !ok {
			continue
		}
		// 必须拷一份再入队。payload 是上面那块**循环复用**的 buf 的子切片，
		// 而读循环与 pumpAssoc 是两个 goroutine：只要这一包在队列里排队
		// （深度 64），或者下游还在 WriteTo 里拷，下一次 ReadFromUDP 就会
		// 把它的字节直接改写掉。症状是 UDP 载荷串包——音视频花屏、
		// QUIC 握手随机失败，而日志里一切正常。
		// TUN 那一侧没有这个问题：它在同一个 goroutine 里读完立刻发。
		data := append([]byte(nil), payload...)
		select {
		case in <- datagram{addr: addr, data: data, from: from}:
		default:
			logx.Debugf("socks5: UDP 关联队列已满，丢弃发往 %s 的一包", addr)
		}
	}
}

// pumpAssoc 是关联的主循环：按第一个报文的地址定一次出站，之后每包各走各的。
//
// 之所以延迟到第一个报文才拨号：RFC 1928 规定客户端要等 ASSOCIATE 应答才发包，
// 而应答里那个 DST.ADDR/DST.PORT 只是客户端自己的本地地址，对判定毫无用处。
// 于是唯一拿得到的真实目标是第一个报文——拿它去判规则，与 CONNECT 路径同一套依据。
func (s *SOCKS5) pumpAssoc(ctl net.Conn, uc *net.UDPConn, in <-chan datagram) {
	var (
		pc      outbound.PacketConn
		rec     *metrics.Conn
		client  atomic.Pointer[net.UDPAddr]
		decided bool
	)
	// refused 记住已经进过连接表的失败目标。
	//
	// 为什么不能像以前那样"一次关联只记一行"：那条判据挂在一个**布尔值**上，
	// 而首包拨号失败恰恰是最会复现的失败（DIRECT 明确不支持 UDP、会话数到 512、
	// 一次瞬时超时）。decided 一置真，整条关联在剩下 10 分钟里就再也不拨号了，
	// 后续每个包都掉进 `pc == nil` 直接丢弃，而表里只有一行、日志里只有一句——
	// 用户看到的是"UDP 全哑了，但面板说没问题"。
	//
	// 改成按目标去重：同一个目标只记一行（客户端狂重试也不刷屏），
	// 但换一个目标就会重新拨号、重新判定。
	refused := make(map[string]struct{}, 2)
	defer func() {
		if pc != nil {
			_ = pc.Close()
		}
		s.reg.End(rec)
	}()

	for d := range in {
		// 回包要发给客户端真正发包的那个 UDP 口，不是中继口自己。
		// 记最近一次看到的来源：客户端换了源口发包，跟着它走才不会石沉大海。
		client.Store(d.from)
		if !decided {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			p, res, err := s.router.DialUDPHost(ctx, d.addr, "")
			cancel()
			if err != nil {
				// 「这条路本来就不通」必须说得像一句人话：应用侧只看得见
				// 自己的报文石沉大海——UDP 传不回任何错误码，重试是它唯一的表达方式。
				logx.Warnf("socks5 %s: UDP 未转发（报文发往 %s）：%v", ctl.RemoteAddr(), d.addr, err)
				// 记一行就够（同一目标不重复记），但**不要把 decided 置真**：
				// 拨号失败不等于"这条关联的出站已经定下来了"。让下一个包再试一次，
				// 一次瞬时失败就不会把整条关联废掉 10 分钟。
				if _, seen := refused[d.addr]; !seen {
					refused[d.addr] = struct{}{}
					s.reg.Refuse("socks5-udp", ctl.RemoteAddr().String(), d.addr, res, err.Error())
				}
				continue
			}
			decided = true
			pc = p
			rec = s.reg.Begin("socks5-udp", ctl.RemoteAddr().String(), res)
			logx.Infof("socks5-udp %s -> %s [%s | %s]", ctl.RemoteAddr(), d.addr, res.Outbound, res.Matched)
			go s.relayAssocReplies(uc, p, &client, rec)
		}
		if pc == nil {
			continue
		}
		if err := pc.WriteTo(d.data, d.addr); err != nil {
			logx.Debugf("socks5: UDP 发往 %s 失败: %v", d.addr, err)
			continue
		}
		// 上行必须计数，否则这条连接在面板上永远是"只下行"，
		// 而按节点/按规则的账在 End 时把 Up 并进去，于是节点用量少算一截。
		// TUN 那一侧一直是两侧都计（countUp/countDown），这里是对齐。
		countUp(rec, len(d.data))
	}
}

// relayAssocReplies 把隧道回来的报文封上 SOCKS5 UDP 头发回客户端。
func (s *SOCKS5) relayAssocReplies(uc *net.UDPConn, pc outbound.PacketConn, client *atomic.Pointer[net.UDPAddr], rec *metrics.Conn) {
	buf := make([]byte, udpAssocBuffer)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt, err := buildAssocPacket(from, buf[:n])
		if err != nil {
			logx.Debugf("socks5: UDP 回包地址 %q 无法编码: %v", from, err)
			continue
		}
		countDown(rec, n)
		if _, err := uc.WriteToUDP(pkt, client.Load()); err != nil {
			return
		}
	}
}

func countUp(rec *metrics.Conn, n int) {
	if rec != nil {
		rec.Up.Add(uint64(n))
	}
}

func countDown(rec *metrics.Conn, n int) {
	if rec != nil {
		rec.Down.Add(uint64(n))
	}
}

// bindAssocSocket 在控制连接的本地地址上开一个 UDP 中继 socket。
//
// 绑同一个地址而不是无脑绑回环：客户端的路由表未必有 127.0.0.1/8
// （部分移动端与容器环境就没有），落在回环上的应答到不了它。
// 本地地址是通配时改用客户端连过来的那个地址——那是客户端必然能收到回包的地址；
// 绝不能顺势绑成通配，那样谁都往这个口上发包。
func bindAssocSocket(ctl net.Conn) (uc *net.UDPConn, bound string, clientIP net.IP, err error) {
	local, err := hostIP(ctl.LocalAddr().String())
	if err != nil {
		return nil, "", nil, err
	}
	clientIP, err = hostIP(ctl.RemoteAddr().String())
	if err != nil {
		return nil, "", nil, err
	}
	if local.IsUnspecified() {
		local = clientIP
	}
	uc, err = net.ListenUDP("udp", &net.UDPAddr{IP: local, Port: 0})
	if err != nil {
		return nil, "", nil, err
	}
	return uc, uc.LocalAddr().String(), clientIP, nil
}

func hostIP(hostport string) (net.IP, error) {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.New("地址不是 IP 字面量: " + host)
	}
	return ip, nil
}

// parseAssocPacket 剥掉 SOCKS5 UDP 请求头：RSV(2) FRAG(1) ATYP(1) ADDR PORT DATA。
func parseAssocPacket(p []byte) (addr string, payload []byte, ok bool) {
	if len(p) < 4+1 {
		return "", nil, false
	}
	if p[2] != 0 {
		// FRAG != 0 是分片。本地回环不会把这种小报文分片，
		// 收到就说明对方在用一种我们没实现的封装——收下只会拼出错误的报文。
		return "", nil, false
	}
	host, n, err := readAddrN(bytes.NewReader(p[4:]), p[3])
	if err != nil {
		return "", nil, false
	}
	if len(p) < 4+n+2 {
		return "", nil, false
	}
	port := binary.BigEndian.Uint16(p[4+n : 4+n+2])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), p[4+n+2:], true
}

// buildAssocPacket 按 SOCKS5 UDP 报文头把一个应答封回去。
func buildAssocPacket(from string, payload []byte) ([]byte, error) {
	out := make([]byte, 0, 10+len(payload))
	out = append(out, 0x00, 0x00, 0x00) // RSV, RSV, FRAG
	out, err := appendAddr(out, from)
	if err != nil {
		return nil, err
	}
	return append(out, payload...), nil
}

// appendAddr 按 ATYP 编码一段地址。回给客户端的每个报文头都要用，
// 而源地址既可能是 IP 字面量也可能是域名——隧道那边给什么就照什么编码。
func appendAddr(dst []byte, hostport string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return nil, errors.New("端口不可编码: " + portStr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(append(dst, atypIPv4), v4...)
		} else {
			dst = append(append(dst, atypIPv6), ip.To16()...)
		}
	} else {
		// 域名分支要和 readAddrN 用同一把尺子：那边拒收的字符这边不能编出去，
		// 否则"我们封的应答自己解不开"这种不对称会在中继路径上变成静默丢包。
		// IP 字面量走不到这里（上面 ParseIP 已经分走了），所以带 ':' 的 IPv6 不受影响。
		if !rules.ValidHostName(host) {
			return nil, errors.New("主机名里有 ATYP 域名编不了的字符: " + briefHost(host))
		}
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("域名长度超出 ATYP 可编码范围: " + briefHost(host))
		}
		dst = append(dst, atypDomain, byte(len(host)))
		dst = append(dst, host...)
	}
	return binary.BigEndian.AppendUint16(dst, uint16(p)), nil
}

// replyAddr 写回 SOCKS5 应答，并把 BND.ADDR/BND.PORT 填成真实地址。
// UDP ASSOCIATE 必须这么做：客户端是照着这两个字段往哪儿发包的。
func replyAddr(c net.Conn, code byte, bound string) error {
	buf := []byte{socks5Version, code, 0x00}
	buf, err := appendAddr(buf, bound)
	if err != nil {
		return err
	}
	_, werr := c.Write(buf)
	return werr
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// briefHost 只给错误信息用：主机名可能是对端给的任意字节，别整段带进日志。
func briefHost(s string) string {
	if len(s) <= 32 {
		return s
	}
	return s[:32] + "…"
}
