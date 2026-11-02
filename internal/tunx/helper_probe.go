package tunx

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"wps_app/internal/logx"
)

// 这一管做的是「动 root 之前先问一句对面是谁」。
//
// 起因是 2026-10-29 的真实故障（见 A41）：跑着的面板是提交版构建（提权协议 1），
// 而 `make build-gui` 把 `tun.helper` 指着的那个文件刷成了工作树版本（协议 3）。
// 那个进程此后每一次启用 TUN 都会：起一个 sudo、生一个 root 进程、
// 发一份注定被拒的请求、读回一句只有版本号的拒绝——一遍又一遍。
// 而这件事在动 root 之前就能问出来：同一个二进制本来就自报协议版本（`-version` 第二行）。

// helperProtoLine 是 `-version` 输出里那行机器可读的自述。
var helperProtoLine = regexp.MustCompile(`提权协议 (\d+)`)

// helperProbeBudget 是「问一句」的时间上限。它必须短：
// 这是一次预检，不是第二次握手——真挂住了就该退回原来的路径去试，而不是把启用卡死。
const helperProbeBudget = 3 * time.Second

// parseHelperProto 从 `-version` 的输出里读对面自报的提权协议号。
// 读不出来分两种，都要如实区别：那份 helper 太老（没有这一行），
// 或者它压根没按预期输出（被别的什么占了这个名字）。
func parseHelperProto(out string) (int, error) {
	m := helperProtoLine.FindStringSubmatch(out)
	if m == nil {
		return 0, errors.New("那份 helper 没有自报提权协议（它比本程序老）")
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, fmt.Errorf("helper 自报的提权协议读不出数字: %q", m[1])
	}
	return n, nil
}

// ProbeHelperProto 以**普通用户身份**跑一次 helper 文件的 -version，读它自报的提权协议号。
// 导出它是为了让 `-diag` 也能在不启用 TUN 的情况下说出「那个文件是谁」——
// 版本错位这一类故障，光看面板日志要等到用户真的点了一次开关才看得见。
//
// 不起 sudo：这里要的不是特权，而是「那个文件说自己是谁」，而 `-version`
// 在 main 的第一件事就是打印它并退出——不读配置、不抢实例锁、不碰网络、不开界面。
// 这也是这条预检可以放在动 root 之前的全部理由。
func ProbeHelperProto(ctx context.Context, path string) (int, error) {
	if path == "" {
		return 0, errors.New("没配 tun.helper")
	}
	cctx, cancel := context.WithTimeout(ctx, helperProbeBudget)
	defer cancel()
	out, err := exec.CommandContext(cctx, path, "-version").Output()
	if err != nil {
		return 0, fmt.Errorf("读不到 %s 的版本自述: %w", path, err)
	}
	return parseHelperProto(string(out))
}

// preflightHelper 在叫 root 之前先比一次协议。返回的 error 是**结论**：
// 它对，就别再去叫了（叫了也是白叫）；它拿不到结论时必须放行，
// 让原来的那条路照走——预检不许把一个本来可能成功的启用变成失败。
//
// 进程内 helper（Spawn，测试用）跳过：那种场合「对面的文件」根本不存在。
func (t *TUN) preflightHelper(ctx context.Context) error {
	if t.helper.Spawn != nil {
		return nil
	}
	path := helperPath(t.conf.Helper)
	if path == "" {
		return nil
	}
	theirs, err := ProbeHelperProto(ctx, path)
	if err != nil {
		// 问不出来就照常尝试。这里不能装作知道：把「读不到」当成「版本不对」，
		// 就等于用一次预检的失败去取消一次本来能成功的启用。
		logx.Debugf("TUN: 没能预先问出 helper 的协议版本（%v），照常尝试", err)
		return nil
	}
	if theirs == helperProtoVersion {
		t.clearHelperMismatch()
		return nil
	}
	t.helperMismatchAt.Store(time.Now().UnixMilli())
	return fmt.Errorf("没有去叫 root：%s",
		helperMismatchAdvice(helperProtoVersion, theirs, t.conf.Helper))
}
