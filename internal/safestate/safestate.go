// Package safestate 是「以 root 身份往用户目录写状态文件」这一件事的唯一实现。
//
// 为什么值得单独一个包：这个仓库里有五处会在**提权之后**写文件——配置回写
// 与它的 .orig/.bak、系统代理账本、解析器接管账本、用户规则文件的 .bak、
// 用量账本。它们各自的原子写都写得不错（临时文件 + fsync + rename），
// 但漏了同一件事：**目标路径本身可能是符号链接**。
//
// 那一层的后果不是"写错地方"这么轻。root 面板（或 root helper）跟一个
// 普通用户控制的符号链接走，就变成"普通用户指定 root 往任意路径写内容"——
// 而这里写进去的东西里包含节点口令、代理账本、iptables 决策依据。
// O_NOFOLLOW 与"先 Lstat 再 rename"挡的正是这一条。
package safestate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WriteFile 原子且不跟随符号链接地写一份状态文件。
//
// 三条约束，各自防一种具体的失败：
//
//  1. **临时文件 + fsync + rename**：被 kill -9 或断电时，要么还是旧内容、
//     要么已经是新内容，不会是半截。半截的账本比没有账本更糟——读不懂的账本
//     会被当成"没有账"，于是退出时不再还原桌面/解析器。
//  2. **不跟随符号链接**：rename 的目标被 Lstat 过，是链接就拒绝。
//     （只查目标本身：中间目录属于用户自己的家目录，那是正常的。）
//  3. **先写 tmp 再 rename**，所以权限在 rename 之前就定好：不会出现
//     "文件已经存在、权限还是 0644"的窗口。
func WriteFile(path string, data []byte, perm os.FileMode) error {
	if err := rejectSymlink(path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("建目录 %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".wps-state-*")
	if err != nil {
		return fmt.Errorf("建临时文件于 %s: %w", dir, err)
	}
	name := tmp.Name()
	// rename 成功后这两步都是空操作；失败时清掉半成品，别在配置目录留垃圾。
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, perm); err != nil {
		return err
	}
	// rename 会换 inode，所以属主要在这里显式还原：
	// root 面板替桌面用户落盘时，留下 root:root 0600 的文件等于让用户
	// 既读不到也改不了自己那份账。属主还原失败不推翻这次写入——
	// 内容已经写对了，为此报错会让调用方撤账，反而造出"改了却没记账"。
	if st, serr := os.Stat(path); serr == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			_ = os.Chown(name, int(sys.Uid), int(sys.Gid))
		}
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return nil
}

// rejectSymlink 拒绝把状态文件写到符号链接后面。
//
// 只查最后一段：中间目录如果本身就是符号链接，那是用户对自己家目录的处置，
// 不属于这条攻击面（攻击面是"用户让 root 往别处写"）。
//
// 目标不存在（首次写）是正常路径，不是错误。
func rejectSymlink(path string) error {
	li, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if li.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s 是符号链接，拒绝写入（提权写状态文件不能跟随链接）", path)
	}
	return nil
}

// RejectSymlink 是 rejectSymlink 的导出版本，给需要在别处先查一遍的调用方。
func RejectSymlink(path string) error { return rejectSymlink(path) }
