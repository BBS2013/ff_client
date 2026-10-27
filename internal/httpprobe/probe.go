// Package httpprobe 是"真的取一个页面回来"这一小段，与拨号、路由、界面都无关。
//
// 为什么要单独一层：只把电路建起来的检查会漏掉一整类节点——隧道正常建立，
// 节点那边把流量交给一个兼底的 web 服务器，任何站点回来的都是同一张 400 页面。
// TCP 拨号看这个一切正常，用户的浏览器一个页面都打不开。
// 发一次最小 HTTP 请求、看状态码与 `Server:` 头，就能把它和真节点区分开。
//
// 命令行的 `-check-fetch`（见 check_fetch.go）与面板上的节点测速共用这里，
// 两条路对"通"的判据因此不会各自漂移。
package httpprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 响应头最多读这么多，正文只数不存（数到上限就停）。
// 探针要回答的是"有没有正常响应"，不是下载整个页面。
const (
	maxHeaderBytes = 32 << 10
	maxBodyCount   = 4 << 20

	// fallbackBudget 是给"ctx 里没带截止"这一路兜的底。
	// 调用方本来都该给一个（巡检与测速都是），这里兜的是"忘了给"而不是"下游不返回"。
	fallbackBudget = 30 * time.Second
)

var (
	statusLineRe = regexp.MustCompile(`^HTTP/\d(?:\.\d)? (\d{3})`)
	serverRe     = regexp.MustCompile(`(?i)^server:\s*(.+?)\s*$`)
)

// Target 是从 URL 里拆出来的拨号与请求信息。
type Target struct {
	Host   string
	Port   string
	Path   string
	UseTLS bool
}

// Parse 把 URL 拆成 Target。只接受 http/https：其它 scheme 没有"取页面"这层含义。
func Parse(raw string) (Target, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return Target{}, fmt.Errorf("URL 读不懂: %w", err)
	}
	var t Target
	switch strings.ToLower(u.Scheme) {
	case "http":
	case "https":
		t.UseTLS = true
	default:
		return Target{}, fmt.Errorf("只支持 http/https，得到 %q", u.Scheme)
	}
	t.Host = u.Hostname()
	if t.Host == "" {
		return Target{}, errors.New("URL 里没有主机名")
	}
	t.Port = u.Port()
	if t.Port == "" {
		if t.UseTLS {
			t.Port = "443"
		} else {
			t.Port = "80"
		}
	}
	t.Path = u.RequestURI()
	return t, nil
}

// Addr 是拨号用的 host:port。
func (t Target) Addr() string { return net.JoinHostPort(t.Host, t.Port) }

// Outcome 是一次取页面的结果。
type Outcome struct {
	Code     int    // HTTP 状态码；0 表示没拿到状态行
	Server   string // `Server:` 头，没有则空
	Body     int64  // 数到的正文字节（上限 maxBodyCount）
	ViaTLS   bool
	Location string // 3xx 时给出去向：跳到一个登录页也是一种"没通"
}

// String 是给人看的那一行。
func (o Outcome) String() string {
	kind := "http"
	if o.ViaTLS {
		kind = "https"
	}
	parts := []string{fmt.Sprintf("%s %d", kind, o.Code)}
	if o.Server != "" {
		parts = append(parts, "server="+o.Server)
	}
	parts = append(parts, fmt.Sprintf("%d 字节", o.Body))
	if o.Location != "" {
		parts = append(parts, "→ "+truncate(o.Location, 60))
	}
	return strings.Join(parts, " ")
}

// Judge 决定这次取页面算不算通。
//
// 2xx/3xx 算通：3xx 是站点自己的跳转策略，浏览器会跟着走，
// 把它判成失败会让一堆正常站点报红。4xx/5xx 算失败——
// 兼底 web 服务器露馅的正是这里（它对任何 Host 都回 400/403/502）。
func (o Outcome) Judge() error {
	switch {
	case o.Code == 0:
		return errors.New("对端没回 HTTP 状态行（连上了但没说 HTTP 话）")
	case o.Code >= 200 && o.Code < 400:
		return nil
	default:
		who := o.Server
		if who == "" {
			who = "没带 Server 头的服务"
		}
		return fmt.Errorf("HTTP %d（%s）——电路是通的，但这一跳没把页面取回来", o.Code, who)
	}
}

// Fetch 在已经连上的 conn 上走一次最小 HTTP 请求。
// path 为空时按 "/" 处理；t.UseTLS 决定是否先做 TLS 握手。
func Fetch(ctx context.Context, conn net.Conn, t Target) (Outcome, error) {
	var out Outcome
	path := t.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if t.UseTLS {
		// SNI 与证书校验都按真实主机名走：兼底服务器常见的是证书对不上，
		// 跳过校验就等于把这条线索也扔了。
		tc := tls.Client(conn, &tls.Config{ServerName: t.Host})
		if err := tc.HandshakeContext(ctx); err != nil {
			return out, fmt.Errorf("TLS 握手失败: %w", err)
		}
		defer tc.Close()
		out.ViaTLS = true
		conn = tc
	}
	// 整体截止由调用方给（每条目标一份预算）；这里再保一层，
	// 免得对端半开时卡在 ReadString 上把预算耗光还不出结果。
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(fallbackBudget)
	}
	_ = conn.SetDeadline(deadline)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: wps_app-check\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, t.Host)
	if _, err := io.WriteString(conn, req); err != nil {
		return out, fmt.Errorf("发请求失败: %w", err)
	}

	// 头与正文必须从同一个 reader 里读：bufio 会预读，
	// 换一个 reader 就把已经缓冲走的开头那几个字节丢了，正文数出来偏少。
	br := bufio.NewReader(conn)
	status, err := readStatus(br)
	if err != nil {
		return out, err
	}
	m := statusLineRe.FindStringSubmatch(status)
	if m == nil {
		// 拿到的第一行不是 HTTP 状态行：这本身就是答案，别硬猜。
		return out, fmt.Errorf("第一行不是 HTTP 响应: %q", trimLine(status))
	}
	code, err := strconv.Atoi(m[1])
	if err != nil {
		return out, fmt.Errorf("状态码读不出: %q", status)
	}
	out.Code = code

	// 头里只关心 Server 与 Location，其余丢掉。读够上限就停：
	// 一个永不给出空行的对端不该把这里的内存吃光。
	headerBytes := len(status) + 2
	for {
		line, err := br.ReadString('\n')
		headerBytes += len(line)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out, fmt.Errorf("读响应头失败: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if headerBytes > maxHeaderBytes {
			return out, fmt.Errorf("响应头超过 %d 字节，不读了", maxHeaderBytes)
		}
		if mm := serverRe.FindStringSubmatch(line); mm != nil {
			out.Server = mm[1]
		} else if strings.HasPrefix(strings.ToLower(line), "location:") {
			out.Location = strings.TrimSpace(line[len("location:"):])
		}
	}
	// 正文只数不存。读到一个错误不算失败——状态码已经拿到了。
	n, _ := io.CopyN(io.Discard, br, maxBodyCount)
	out.Body = n
	return out, nil
}

// readStatus 读状态行。空行与 BOM 容错：有代理会在前面塞 CRLF。
func readStatus(br *bufio.Reader) (string, error) {
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && strings.TrimSpace(line) != "" {
				return strings.TrimRight(line, "\r\n"), nil
			}
			return "", fmt.Errorf("读状态行失败: %w", err)
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		return strings.TrimRight(strings.TrimPrefix(line, "\xef\xbb\xbf"), "\r\n"), nil
	}
}

func trimLine(s string) string { return truncate(strings.TrimSpace(s), 80) }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
