//go:build race

package service

// raceEnabled 告诉那几条时延预算"这一轮跑在 -race 下"。
//
// 竞态检测会给每次内存访问插桩，实测能把这一格的时延顶到平常的好几倍——
// 那不是"面板变慢了"，是量具本身变慢了。所以带 race 时这些预算直接跳过：
// 一条在 race 下必红、在平常下有用的断言，最后只会被人把预算调到失去意义，
// 或者干脆整条注释掉。
const raceEnabled = true
