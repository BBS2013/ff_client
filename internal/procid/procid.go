// Package procid 回答一个和安全有关的问题：「这个 PID 现在跑的是不是我们这个程序的另一个实例」。
//
// 只比 PID 不够——进程号会被回收再分给无关程序；只比 argv[0] 也不够——
// 那是程序自己写进去的，改名、软链、exec -a 都能变。内核在 /proc/<pid>/exe
// 上给了权威答案，这个包只负责把它读成可比较的路径，结论留给调用方：
//
//   - 实例锁接管要在「确认同身份」时敢发 SIGTERM；
//   - 系统代理记账要在拿不准时绝不动桌面。
//
// 两边方向相反，所以共用读法、各写各的判断。
package procid

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DeletedSuffix 是重编译之后内核给 /proc/<pid>/exe 加的尾巴。
// 那是同一个二进制的上一版，必须算同身份：否则每次改完代码再启动，
// 旧实例都会被认成「不是我们」，接管与自愈恰好在最需要它们的时候失灵。
const DeletedSuffix = " (deleted)"

// commMax 是内核 comm 的长度上限（TASK_COMM_LEN 去掉结尾 NUL）。
// 只有被截断到这个长度的名字，才允许按前缀去比原名。
const commMax = 15

// Self 返回本程序的可执行路径，跟着符号链接解析到真实文件；读不到给空串。
func Self() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		return resolved
	}
	return exe
}

// ExePath 读 /proc/<pid>/exe 并去掉 DeletedSuffix。
//
// readlink 由调用方注入，这样「链接读不到」「带着 (deleted)」这些现场都能在测试里造出来；
// 真机上就传 os.Readlink。
func ExePath(pid int, readlink func(string) (string, error)) (string, error) {
	link, err := readlink(ProcPath(pid, "exe"))
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(link, DeletedSuffix), nil
}

// Comm 读 /proc/<pid>/comm。exe 因为权限读不到时，它是唯一还能跨 uid 拿到的身份线索。
func Comm(pid int, readFile func(string) ([]byte, error)) (string, error) {
	raw, err := readFile(ProcPath(pid, "comm"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// State 读 /proc/<pid>/stat 里的进程状态字符（R/S/D/Z/T…）。
//
// 要它是因为僵尸进程杀不掉也活不好：kill(pid, 0) 对它照样成功，
// 而它已经不转发任何流量。把它算成"还活着"，等于让一份该自愈的记账永远不敢动桌面。
// stat 的第二个字段是括号里的 comm，里面可以有空格甚至 ')'，所以从最后一个 ')' 之后取。
func State(pid int, readFile func(string) ([]byte, error)) (byte, error) {
	raw, err := readFile(ProcPath(pid, "stat"))
	if err != nil {
		return 0, err
	}
	body := string(raw)
	end := strings.LastIndexByte(body, ')')
	if end < 0 || len(body) <= end+2 {
		return 0, fmt.Errorf("无法解析 /proc/%d/stat", pid)
	}
	fields := strings.Fields(body[end+1:])
	if len(fields) == 0 {
		return 0, fmt.Errorf("无法解析 /proc/%d/stat", pid)
	}
	return fields[0][0], nil
}

// ProcPath 拼 /proc/<pid>/<file>。
func ProcPath(pid int, file string) string {
	return "/proc/" + strconv.Itoa(pid) + "/" + file
}

// Same 比较两个可执行路径。任一边为空都算不相同——
// 空是「读不到」，不是「读到了一个空路径」，判不出身份时调用方要按「不确定」处理。
func Same(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// NameMatches 用进程名比对可执行文件名，只在 comm 被截断过时放宽成前缀。
// 这是 exe 读不到时的退化判断，只用来排除「PID 被回收给了一个名字都对不上的程序」。
func NameMatches(comm, exe string) bool {
	base := filepath.Base(exe)
	if comm == "" || base == "" {
		return false
	}
	if comm == base {
		return true
	}
	return len(comm) == commMax && strings.HasPrefix(base, comm)
}
