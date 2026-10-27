# systemd 用户级自愈

面板与代理在同一个进程里，崩溃就是断网。这份 unit 用
`Restart=on-failure` 把"下一次启动"自动化，配合面板启动时的系统代理记账自愈，
比拆成两个进程便宜得多。

## 安装

```bash
mkdir -p ~/.config/systemd/user
cp packaging/systemd/wps_app-gui.service ~/.config/systemd/user/
# 编辑 ExecStart：二进制与配置换成你的绝对路径
systemctl --user daemon-reload
systemctl --user enable --now wps_app-gui.service
```

如果面板是手动起的，先退掉它再启用 unit：两份实例抢同一把
`<config>.lock`，后启动的只会报"已有另一个实例"。

## 验证

```bash
systemctl --user status wps_app-gui.service
# 模拟崩溃（会掐断正在走的隧道几秒，挑个方便的时间）：
kill -9 "$(systemctl --user show -p MainPID --value wps_app-gui.service)"
sleep 4
systemctl --user show -p MainPID --value wps_app-gui.service   # 应该是一个新 PID
ss -ltn | grep -E ':7891|:7892'
```

`Restart=on-failure` 只接崩溃/非零退出，不接托盘里的"退出"——那是用户的意图。
TUN helper 的免密 sudo 仍按 README §4.3 配置；unit 里刻意没有加
`NoNewPrivileges=yes`，加了会让 sudo 失效。
