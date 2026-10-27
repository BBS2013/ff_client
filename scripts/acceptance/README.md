# 验收脚本（仓库内版）

`ACCEPTANCE.md` 原来把证据脚本放在 `/tmp/accept/`，机器重启后整个目录消失，
报告里的复现命令随之失效（2026-10-27 发现）。这里把它们放回仓库：

| 脚本 | 对应 | 前置 | 碰什么 |
|---|---|---|---|
| `proto_test.py` | A6 协议行为 16 项 | 无（本地回环） | 隔离实例 17891/17892 + 本地 DNS/HTTP/Echo |
| `signals_test.sh` | A8 SIGHUP / SIGTERM | 无（本地回环） | 隔离实例 17891/17892 |
| `tun_test.sh` | B3 TUN root 实链 | root、`/dev/net/tun`、真实节点、专用配置 | **会改本机路由与 DNS** |

```bash
make acceptance                 # A6 + A8，离线可跑
sudo WPS_ACCEPT_TUN=1 WPS_ACCEPT_TUN_CONFIG=/path/to/tun-test.yaml \
     make acceptance-tun        # B3，显式启用，默认不跑
```

三条约束：

1. **不碰线上面板。** 固定使用 17891/17892，并且启动前会检查端口；
   7891/7892 上正在跑的实例不会被信号、锁或配置影响。
2. **不碰外网。** A6 的 DNS 由脚本自己回答（`accept.local -> 127.0.0.1`），
   HTTP/Echo 目标也都在本地。
3. **B3 不伪装通过。** 没有 `WPS_ACCEPT_TUN=1` 或专用配置时打印 `SKIP` 并以 2 退出；
   它需要真实节点，无法在 CI/断网机器上跑。2026-10-27 这次重建没有在本机执行 B3。

失败时脚本会打印代理日志尾部；A6 的每条断言都有 PASS/FAIL/SKIP 字样，
退出码 1 表示至少一条 FAIL。
