// 桌面指着本程序的入站，却没有任何记账——最难受的一种孤儿状态。
//
// 这里只查、不改：没有记账就不知道改动前是什么样子，猜一份"原状"写回桌面
// 比不动更糟（用户可能自己配了另一个代理，也可能这就是他要的）。
// 但"本进程退出时不会还原桌面"这件事必须说出口，否则下一次开机整机没网，
// 而日志里一句错都没有——因为每一步都成功了。
package sysproxy

import (
	"context"
	"errors"
	"fmt"
)

// OrphanWarning 返回一句该警告用户的话；没有问题时返回空串。
//
// 「哪条后端算无桌面」「读不到怎么处置」都收在这里：两个调用方（GUI 启动、CLI 启动）
// 各抄一份的话，早晚抄出两种结果，而这件事的两种结果差着一整机断网。
func OrphanWarning(ctx context.Context, r Runner, statePath string, c Config) string {
	orphan, err := orphanStatus(ctx, r, statePath, c)
	switch {
	case errors.Is(err, ErrUnsupported):
		return "" // 这台机器上没有可用的桌面手段，这件事本来就不成立
	case err != nil:
		return fmt.Sprintf("查不成系统代理的记账状态（%s）：%v", statePath, err)
	case orphan:
		return OrphanHint(statePath)
	}
	return ""
}

// orphanStatus 回答：桌面上现在这组「指向本客户端」的设置，是不是没人负责还原。
//
// 返回 true 的条件很窄：没有记账，而桌面读数又正好等于这次要写的三组地址。
// 窄是有原因的——误报会让用户在好好的桌面上去找一个不存在的故障。
func orphanStatus(ctx context.Context, r Runner, statePath string, c Config) (bool, error) {
	st, err := peekSaved(statePath)
	if err != nil {
		return false, err
	}
	if st != nil {
		return false, nil // 有记账：还原路径认得它，不欠解释
	}
	status, err := ReadWith(ctx, r, c.Backend)
	if err != nil {
		return false, err
	}
	return LikesOurs(status, c), nil
}

// IsOrphan 回答：桌面上这组「指向本客户端」的设置有没有人负责还原。
//
// 导出来是因为退出路径必须问这同一个问题：Restore 没有记账时是空操作，
// 光靠它兜不住这种桌面——进程一没，全机应用就一起去连一个已经不存在的端口。
// 判据和启动时那句警告必须是同一份，否则会出现"启动说有事、退出说没事"。
func IsOrphan(ctx context.Context, r Runner, statePath string, c Config) (bool, error) {
	return orphanStatus(ctx, r, statePath, c)
}

// LikesOurs 判断一份桌面读数是不是「我们任何一条后端会写出来的那组值」。
//
// 三条后端的 Mode 写法各不相同（manual / Manual / Environment），
// 所以这里只看 Enabled 加三组地址，不碰 Mode。
// 导出是因为 `-sysproxy status` 已经读过一次桌面，不该为了同一个答案再读一遍。
func LikesOurs(st Status, c Config) bool {
	if !st.Supported || !st.Enabled {
		return false
	}
	e := c.endpoints()
	return st.HTTP == e.HTTP() && st.HTTPS == e.HTTPS() && st.SOCKS == e.SOCKS()
}

// OrphanHint 是给日志与终端的一句话：先说清后果，再给两条能照着做的路。
func OrphanHint(statePath string) string {
	return fmt.Sprintf("系统代理正指着本客户端的入站，但记账文件 %s 不存在：本进程退出时不会还原桌面。"+
		"想要这层保护就再跑一次 -sysproxy on（它会认出桌面已经是我们的，补上记账；"+
		"注意这一步仍会按本机默认重写一遍设置，含绕过列表）；不需要就在退出前 -sysproxy off", statePath)
}
