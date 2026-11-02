#!/usr/bin/env python3
"""A6 协议行为验收：SOCKS5 / HTTP 入站的 16 条断言。

原来这一份在 /tmp/accept/proto-test.py，机器重启后就没了（ACCEPTANCE.md 的
复现命令因此全部失效）。现在它跟着仓库走：自己起一个隔离实例、自己起本地目标，
不碰线上端口（7891/7892）、不碰外网、不碰正在跑的面板。

用法：
    python3 scripts/acceptance/proto_test.py --binary ./wps_app-gui

退出码：0 = 全部通过（IPv6 不可用时记 SKIP，不算失败）；1 = 有 FAIL 或起不来。
"""

import argparse
import http.server
import os
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

SOCKS_PORT = 17891
HTTP_PORT = 17892
DNS_PORT = 17897
WEB_PORT = 17898
ECHO_PORT = 17899

READ_TIMEOUT = 3.0


class CheckError(AssertionError):
    pass


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("连接提前关闭")
        buf += chunk
    return buf


class LocalDNS:
    """只回答 A = 127.0.0.1；其他类型回 NODATA。够让 CONNECT 域名那条离线可跑。"""

    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.settimeout(0.2)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()

    def _serve(self):
        while not self.stop.is_set():
            try:
                data, peer = self.sock.recvfrom(1500)
            except socket.timeout:
                continue
            except OSError:
                return
            reply = self._answer(data)
            if reply:
                try:
                    self.sock.sendto(reply, peer)
                except OSError:
                    pass

    @staticmethod
    def _answer(data):
        if len(data) < 12:
            return b""
        qd = struct.unpack("!H", data[4:6])[0]
        if qd < 1:
            return b""
        i = 12
        while i < len(data):
            n = data[i]
            i += 1
            if n == 0:
                break
            i += n
        if i + 4 > len(data):
            return b""
        qtype, _qclass = struct.unpack("!HH", data[i:i + 4])
        question = data[12:i + 4]
        if qtype == 1:  # A
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
            ancount = 1
        else:
            answer = b""
            ancount = 0
        header = data[:2] + struct.pack("!HHHHH", 0x8180, 1, ancount, 0, 0)
        return header + question + answer


class LocalEcho:
    def __init__(self, family, addr):
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.sock.bind(addr)
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.sock.close()

    def _serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    @staticmethod
    def _handle(conn):
        with conn:
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)


HTTP_RECORDS = []
HTTP_LOCK = threading.Lock()


class TargetHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        with HTTP_LOCK:
            HTTP_RECORDS.append({"path": self.path, "headers": dict(self.headers.items())})
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def wait_port(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def config_text(tmpdir):
    rules = os.path.join(tmpdir, "rules.txt")
    with open(rules, "w", encoding="utf-8") as f:
        f.write("DOMAIN,acceptance.invalid,DIRECT\nFINAL,DIRECT\n")
    return f"""\
proxies:
  - name: "acceptance-direct"
    server:
      type: hysteria2
      addr: "127.0.0.1:9"
      auth: "acceptance"
      tls:
        sni: "localhost"
        insecure: true
active: "acceptance-direct"
mode: direct
inbounds:
  - type: socks5
    listen: "127.0.0.1:{SOCKS_PORT}"
  - type: http
    listen: "127.0.0.1:{HTTP_PORT}"
rules_file: "{rules}"
tun:
  enable: false
dns:
  servers:
    - "127.0.0.1:{DNS_PORT}"
  timeout: 1s
log:
  level: info
"""


def preflight_ports():
    for port in (SOCKS_PORT, HTTP_PORT, DNS_PORT, WEB_PORT, ECHO_PORT):
        try:
            with socket.create_connection(("127.0.0.1", port), 0.1):
                raise SystemExit(f"端口 {port} 已被占用：验收脚本不会去动别人的进程，先腾出来")
        except OSError:
            continue


def start_proxy(binary, tmpdir):
    cfg = os.path.join(tmpdir, "config.yaml")
    with open(cfg, "w", encoding="utf-8") as f:
        f.write(config_text(tmpdir))
    log = open(os.path.join(tmpdir, "proxy.log"), "wb")
    proc = subprocess.Popen(
        [binary, "-c", cfg, "-cli"],
        cwd=os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    if not (wait_port(SOCKS_PORT) and wait_port(HTTP_PORT)):
        log.close()
        tail = ""
        with open(os.path.join(tmpdir, "proxy.log"), "r", errors="replace") as f:
            tail = f.read()[-3000:]
        try:
            proc.kill()
        except OSError:
            pass
        raise SystemExit(f"代理没有起来。日志尾部：\n{tail}")
    return proc, log


def stop_proxy(proc, log):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    log.close()


def socks_handshake(methods):
    s = socket.create_connection(("127.0.0.1", SOCKS_PORT), READ_TIMEOUT)
    s.settimeout(READ_TIMEOUT)
    s.sendall(b"\x05" + bytes([len(methods)]) + methods)
    return s, recv_exact(s, 2)


def socks_request(s, atyp, addr, port, cmd=1):
    if atyp == 1:
        body = socket.inet_aton(addr)
    elif atyp == 4:
        body = socket.inet_pton(socket.AF_INET6, addr)
    elif atyp == 3:
        raw = addr.encode()
        body = bytes([len(raw)]) + raw
    else:
        body = b""
    s.sendall(b"\x05" + bytes([cmd]) + b"\x00" + bytes([atyp]) + body + struct.pack("!H", port))
    head = recv_exact(s, 4)
    _ver, rep, _rsv, ratyp = head
    if ratyp == 1:
        recv_exact(s, 4 + 2)
    elif ratyp == 4:
        recv_exact(s, 16 + 2)
    elif ratyp == 3:
        n = recv_exact(s, 1)[0]
        recv_exact(s, n + 2)
    return rep


def connect_via_socks(atyp, addr, port):
    s, (ver, method) = socks_handshake(b"\x00")
    if (ver, method) != (5, 0):
        s.close()
        raise CheckError(f"协商失败: {ver:#x}/{method:#x}")
    rep = socks_request(s, atyp, addr, port)
    if rep != 0:
        s.close()
        raise CheckError(f"CONNECT 失败: rep={rep}")
    return s


def http_roundtrip(raw):
    s = socket.create_connection(("127.0.0.1", HTTP_PORT), READ_TIMEOUT)
    s.settimeout(READ_TIMEOUT)
    s.sendall(raw)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if len(data) > 2_000_000:
            break
    s.close()
    return data


def status_code(resp):
    line = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")
    parts = line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise CheckError(f"响应行读不懂: {line!r}")
    return int(parts[1])


def check(name, fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - 验收脚本要把任何异常都变成一条 FAIL
        print(f"FAIL  {name}: {exc}")
        return False
    print(f"PASS  {name}")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="./wps_app-gui")
    args = ap.parse_args()
    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        raise SystemExit(f"找不到二进制: {binary}")

    preflight_ports()
    tmpdir = tempfile.mkdtemp(prefix="wps-accept-proto-")
    dns = LocalDNS(DNS_PORT)
    web = ThreadingHTTPServer(("127.0.0.1", WEB_PORT), TargetHandler)
    echo4 = LocalEcho(socket.AF_INET, ("127.0.0.1", ECHO_PORT))
    try:
        echo6 = LocalEcho(socket.AF_INET6, ("::1", ECHO_PORT))
    except OSError:
        echo6 = None
    web_thread = threading.Thread(target=web.serve_forever, daemon=True)

    dns.start()
    echo4.start()
    if echo6:
        echo6.start()
    web_thread.start()
    proc, log = start_proxy(binary, tmpdir)

    results = []
    try:
        def t_no_auth():
            s, (ver, method) = socks_handshake(b"\x00")
            s.close()
            if (ver, method) != (5, 0):
                raise CheckError(f"期望 05 00，实得 {ver:#x} {method:#x}")

        def t_auth_only():
            s, (ver, method) = socks_handshake(b"\x02")
            s.close()
            if (ver, method) != (5, 0xFF):
                raise CheckError(f"期望 05 ff，实得 {ver:#x} {method:#x}")

        def t_connect_domain():
            s = connect_via_socks(3, "accept.local", ECHO_PORT)
            with s:
                s.sendall(b"domain")
                if recv_exact(s, 6) != b"domain":
                    raise CheckError("回显不一致")

        def t_connect_v4():
            s = connect_via_socks(1, "127.0.0.1", ECHO_PORT)
            with s:
                s.sendall(b"v4")
                if recv_exact(s, 2) != b"v4":
                    raise CheckError("回显不一致")

        def t_connect_v6():
            if echo6 is None:
                raise CheckError("SKIP: 本机没有 ::1")
            s = connect_via_socks(4, "::1", ECHO_PORT)
            with s:
                s.sendall(b"v6")
                if recv_exact(s, 2) != b"v6":
                    raise CheckError("回显不一致")

        def t_bad_cmd():
            s, (ver, method) = socks_handshake(b"\x00")
            if (ver, method) != (5, 0):
                s.close()
                raise CheckError("协商失败")
            try:
                rep = socks_request(s, 1, "127.0.0.1", ECHO_PORT, cmd=2)
            except EOFError:
                s.close()
                raise CheckError("服务端直接断开，没有回 REP")
            s.close()
            if rep != 7:
                raise CheckError(f"期望 REP=7（命令不支持），实得 {rep}")

        def t_bad_atyp():
            s, (ver, method) = socks_handshake(b"\x00")
            if (ver, method) != (5, 0):
                s.close()
                raise CheckError("协商失败")
            try:
                rep = socks_request(s, 9, "", ECHO_PORT)
            except EOFError:
                s.close()
                return  # 直接拒绝并断开也算对
            s.close()
            if rep == 0:
                raise CheckError("非法 ATYP 被接受")

        def t_zero_domain():
            s, (ver, method) = socks_handshake(b"\x00")
            if (ver, method) != (5, 0):
                s.close()
                raise CheckError("协商失败")
            try:
                rep = socks_request(s, 3, "", ECHO_PORT)
            except EOFError:
                s.close()
                return  # 断开算拒绝
            s.close()
            if rep == 0:
                raise CheckError("零长度域名被接受")

        def t_bidirectional():
            payload = os.urandom(64 << 10)
            s = connect_via_socks(1, "127.0.0.1", ECHO_PORT)
            with s:
                s.sendall(payload)
                if recv_exact(s, len(payload)) != payload:
                    raise CheckError("64KiB 双向数据不一致")

        def t_http_absolute():
            resp = http_roundtrip(
                f"GET http://127.0.0.1:{WEB_PORT}/abs HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{WEB_PORT}\r\nConnection: close\r\n\r\n".encode()
            )
            if status_code(resp) != 200:
                raise CheckError(f"状态码 {status_code(resp)}")
            if b"ok" not in resp:
                raise CheckError("响应体里没有 ok")

        def t_http_10():
            resp = http_roundtrip(
                f"GET http://127.0.0.1:{WEB_PORT}/old HTTP/1.0\r\n"
                f"Host: 127.0.0.1:{WEB_PORT}\r\n\r\n".encode()
            )
            if status_code(resp) != 200:
                raise CheckError(f"状态码 {status_code(resp)}")

        def t_strip_proxy_auth():
            with HTTP_LOCK:
                HTTP_RECORDS.clear()
            resp = http_roundtrip(
                f"GET http://127.0.0.1:{WEB_PORT}/auth HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{WEB_PORT}\r\n"
                "Proxy-Authorization: Basic c2VjcmV0\r\n"
                "Connection: close\r\n\r\n".encode()
            )
            if status_code(resp) != 200:
                raise CheckError(f"状态码 {status_code(resp)}")
            with HTTP_LOCK:
                if not HTTP_RECORDS:
                    raise CheckError("目标没收到请求")
                headers = {k.lower() for k in HTTP_RECORDS[-1]["headers"]}
            if "proxy-authorization" in headers:
                raise CheckError("Proxy-Authorization 被转发到了源站")

        def t_http_connect():
            s = socket.create_connection(("127.0.0.1", HTTP_PORT), READ_TIMEOUT)
            s.settimeout(READ_TIMEOUT)
            s.sendall(
                f"CONNECT 127.0.0.1:{ECHO_PORT} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{ECHO_PORT}\r\n\r\n".encode()
            )
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = s.recv(4096)
                if not chunk:
                    raise CheckError("CONNECT 隧道在读响应头时被关")
                head += chunk
            if b" 200 " not in head.split(b"\r\n", 1)[0] + b" ":
                raise CheckError(f"CONNECT 没回 200: {head[:80]!r}")
            with s:
                s.sendall(b"tunnel")
                if recv_exact(s, 6) != b"tunnel":
                    raise CheckError("隧道回显不一致")

        def t_http_connection_close():
            resp = http_roundtrip(
                f"GET http://127.0.0.1:{WEB_PORT}/close HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{WEB_PORT}\r\nConnection: close\r\n\r\n".encode()
            )
            if status_code(resp) != 200:
                raise CheckError(f"状态码 {status_code(resp)}")
            # http_roundtrip 读到 EOF 才返回；能走到这里说明服务端确实关了。

        def t_http_connect_unreachable():
            s = socket.create_connection(("127.0.0.1", HTTP_PORT), READ_TIMEOUT)
            s.settimeout(READ_TIMEOUT)
            s.sendall(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
            resp = b""
            try:
                while b"\r\n" not in resp:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
            finally:
                s.close()
            if not resp:
                raise CheckError("不可达目标没有任何响应")
            code = status_code(resp)
            if code == 200:
                raise CheckError("不可达目标回了 200")
            if code not in (502, 503, 504):
                raise CheckError(f"不可达目标回了 {code}，期望 502/503/504")

        def t_socks_unreachable():
            s, (ver, method) = socks_handshake(b"\x00")
            if (ver, method) != (5, 0):
                s.close()
                raise CheckError("协商失败")
            try:
                rep = socks_request(s, 1, "127.0.0.1", 1)
            except EOFError:
                s.close()
                return  # 断开也算拒绝
            s.close()
            if rep == 0:
                raise CheckError("不可达目标回了成功")

        cases = [
            ("SOCKS5 无认证协商", t_no_auth),
            ("SOCKS5 仅认证方法 -> 05 ff", t_auth_only),
            ("SOCKS5 CONNECT 域名（本地 DNS）", t_connect_domain),
            ("SOCKS5 CONNECT IPv4", t_connect_v4),
            ("SOCKS5 CONNECT IPv6", t_connect_v6),
            ("SOCKS5 不支持的命令 -> REP 7", t_bad_cmd),
            ("SOCKS5 非法 ATYP 被拒", t_bad_atyp),
            ("SOCKS5 零长度域名被拒", t_zero_domain),
            ("SOCKS5 64KiB 双向数据", t_bidirectional),
            ("HTTP 绝对 URI 转发", t_http_absolute),
            ("HTTP/1.0 请求", t_http_10),
            ("Proxy-Authorization 不转发", t_strip_proxy_auth),
            ("HTTP CONNECT 隧道", t_http_connect),
            ("Connection: close 后关闭", t_http_connection_close),
            ("HTTP CONNECT 不可达 -> 5xx", t_http_connect_unreachable),
            ("SOCKS5 不可达目标被拒", t_socks_unreachable),
        ]
        for name, fn in cases:
            if fn is t_connect_v6 and echo6 is None:
                print(f"SKIP  {name}: 本机没有 ::1")
                continue
            results.append((name, check(name, fn)))
    finally:
        stop_proxy(proc, log)
        web.shutdown()
        web.server_close()
        dns.close()
        echo4.close()
        if echo6:
            echo6.close()

    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} 通过")
    if failed:
        print("失败：" + "、".join(failed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
