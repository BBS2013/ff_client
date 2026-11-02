package main

import (
	"flag"
	"reflect"
	"strings"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		name      string
		in        []string
		wantFlags []string
		wantPos   []string
	}{
		{
			name: "空参数",
		},
		{
			name:      "仅 flag",
			in:        []string{"-check"},
			wantFlags: []string{"-check"},
		},
		{
			name:      "flag 取值紧随其后",
			in:        []string{"-c", "config.yaml", "-check"},
			wantFlags: []string{"-c", "config.yaml", "-check"},
		},
		{
			name:      "布尔开关不吃掉后面的位置参数",
			in:        []string{"config.yaml", "-check"},
			wantFlags: []string{"-check"},
			wantPos:   []string{"config.yaml"},
		},
		{
			name:      "位置参数在前且后面还跟 flag",
			in:        []string{"/etc/wps_app/config.yaml", "-check", "-check-host", "www.baidu.com:443"},
			wantFlags: []string{"-check", "-check-host", "www.baidu.com:443"},
			wantPos:   []string{"/etc/wps_app/config.yaml"},
		},
		{
			name:      "内联取值",
			in:        []string{"-c=/tmp/a.yaml", "-check"},
			wantFlags: []string{"-c=/tmp/a.yaml", "-check"},
		},
		{
			name:      "双横线写法",
			in:        []string{"--check-host", "1.1.1.1:443"},
			wantFlags: []string{"--check-host", "1.1.1.1:443"},
		},
		{
			name:      "双横线 -- 之后一律是位置参数",
			in:        []string{"-check", "--", "-weird.yaml"},
			wantFlags: []string{"-check"},
			wantPos:   []string{"-weird.yaml"},
		},
		{
			name:    "多个位置参数都保留，交由调用方报错",
			in:      []string{"a.yaml", "b.yaml"},
			wantPos: []string{"a.yaml", "b.yaml"},
		},
		{
			name:    "单个横线不算 flag",
			in:      []string{"-"},
			wantPos: []string{"-"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotFlags, gotPos := splitArgs(tc.in)
			if !reflect.DeepEqual(gotFlags, tc.wantFlags) {
				t.Errorf("flagArgs = %v, want %v", gotFlags, tc.wantFlags)
			}
			if !reflect.DeepEqual(gotPos, tc.wantPos) {
				t.Errorf("positional = %v, want %v", gotPos, tc.wantPos)
			}
		})
	}
}

func TestParseArgs(t *testing.T) {
	cases := []struct {
		name    string
		argv    []string
		want    options
		wantErr string
	}{
		{
			name: "无参数时用默认配置",
			argv: nil,
			want: options{configPath: "./config.yaml", checkHosts: []string{"www.gstatic.com:443"}},
		},
		{
			name: "-c 形式",
			argv: []string{"-c", "/etc/wps_app/config.yaml"},
			want: options{configPath: "/etc/wps_app/config.yaml", checkHosts: []string{"www.gstatic.com:443"}},
		},
		{
			name: "位置参数形式（systemd ExecStart 用的就是这种）",
			argv: []string{"/etc/wps_app/config.yaml"},
			want: options{configPath: "/etc/wps_app/config.yaml", checkHosts: []string{"www.gstatic.com:443"}},
		},
		{
			name: "位置参数在前、flag 在后",
			argv: []string{"config.yaml", "-check"},
			want: options{configPath: "config.yaml", checkOnly: true, checkHosts: []string{"www.gstatic.com:443"}},
		},
		{
			name: "位置参数在最前、后面跟两个 flag",
			argv: []string{"config.yaml", "-check", "-check-host", "www.baidu.com:443"},
			want: options{configPath: "config.yaml", checkOnly: true, checkHosts: []string{"www.baidu.com:443"}},
		},
		{
			name: "flag 与位置参数交错",
			argv: []string{"-check", "config.yaml", "-check-host", "1.1.1.1:443"},
			want: options{configPath: "config.yaml", checkOnly: true, checkHosts: []string{"1.1.1.1:443"}},
		},
		{
			name: "-c 与位置参数给同一个路径不算冲突",
			argv: []string{"-c", "config.yaml", "config.yaml"},
			want: options{configPath: "config.yaml", checkHosts: []string{"www.gstatic.com:443"}},
		},
		{
			name:    "多余的位置参数应报错",
			argv:    []string{"a.yaml", "b.yaml"},
			wantErr: "多余的位置参数",
		},
		{
			name:    "配置文件路径给两次且不一致应报错",
			argv:    []string{"-c", "a.yaml", "b.yaml"},
			wantErr: "指定了两次",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseArgs(tc.argv)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("parseArgs(%v) 期望报错，实际 nil（解析结果 %+v）", tc.argv, got)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("错误 %q 不含期望子串 %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseArgs(%v): %v", tc.argv, err)
			}
			// options 里有切片之后不能用 == 比，这里按值深比。
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseArgs(%v) = %+v, want %+v", tc.argv, got, tc.want)
			}
		})
	}
}

func TestParseArgsHelpReturnsErrHelp(t *testing.T) {
	for _, argv := range [][]string{{"-h"}, {"--help"}, {"config.yaml", "-h"}} {
		if _, err := parseArgs(argv); err == nil || !strings.Contains(err.Error(), flag.ErrHelp.Error()) {
			t.Errorf("parseArgs(%v) 期望 ErrHelp，实际 %v", argv, err)
		}
	}
}

func TestParseArgsRejectsUnknownFlag(t *testing.T) {
	if _, err := parseArgs([]string{"-nope"}); err == nil {
		t.Fatal("未知 flag 应当报错")
	}
}

// TestWantGUI 钉住「什么时候开界面」这张决策表。
//
// 双击没反应就是这么来的：双击走的是空命令行，产物若默认不开界面，进程会
// 在后台把代理跑起来但什么都不显示。因此 gui 构建下的空参数必须是 true，
// 而默认构建（systemd 部署）必须保持 false。
func TestWantGUI(t *testing.T) {
	cases := []struct {
		name       string
		o          options
		defaultGUI bool
		want       bool
	}{
		{"gui 构建·双击空参数出窗口", options{}, true, true},
		{"默认构建·双击仍只跑服务", options{}, false, false},
		{"gui 构建·-cli 关掉界面", options{cliOnly: true}, true, false},
		{"gui 构建·-gui 压过 -cli", options{gui: true, cliOnly: true}, true, true},
		{"默认构建·-gui 照样要界面", options{gui: true}, false, true},
		{"gui 构建·-check 不开界面", options{checkOnly: true}, true, false},
		{"显式 -gui 压过 -check（沿用旧行为）", options{gui: true, checkOnly: true}, true, true},
		{"默认构建·无标志只跑服务", options{cliOnly: false}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := wantGUIWith(tc.o, tc.defaultGUI); got != tc.want {
				t.Errorf("wantGUIWith(%+v, %v) = %v, want %v", tc.o, tc.defaultGUI, got, tc.want)
			}
		})
	}
}

// TestCliFlagParsedWithoutEatingNextArg 确认 -cli 是布尔开关，
// 不会像取值型 flag 那样把后面的配置文件路径吞掉。
func TestCliFlagParsedWithoutEatingNextArg(t *testing.T) {
	o, err := parseArgs([]string{"-cli", "other.yaml"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !o.cliOnly {
		t.Error("-cli 应当被解析为 true")
	}
	if o.configPath != "other.yaml" {
		t.Errorf("配置路径 = %q, want %q", o.configPath, "other.yaml")
	}
}

// TestDialHelperOwnerZeroIsLegal 盯住 owner=0 这一档。
//
// 整个面板由 sudo 拉起时它就是这一档（os.Getuid() == 0）：套接字本来就归 root，
// helper 不需要 chown，但绝不表示"没传 owner"。历史上这里判过 uid <= 0，
// 结果 root 面板每次请求都被拒，报的却是「需要 --dial-helper-owner」——
// 一条自相矛盾的报错，把人往"参数没拼上"那条错路上引。
func TestDialHelperOwnerZeroIsLegal(t *testing.T) {
	cases := []struct {
		name    string
		owner   string
		want    int
		wantErr bool
	}{
		{name: "root 面板", owner: "0", want: 0},
		{name: "普通面板", owner: "1000", want: 1000},
		{name: "带空白也不算没传", owner: " 1000 ", want: 1000},
		{name: "没传", owner: "", wantErr: true},
		{name: "非数字", owner: "root", wantErr: true},
		{name: "负数", owner: "-1", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseDialHelperOwner(c.owner)
			if c.wantErr {
				if err == nil {
					t.Fatalf("owner=%q 期望报错，实际通过并得到 uid=%d", c.owner, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("owner=%q 应当被接受，实际报错: %v", c.owner, err)
			}
			if got != c.want {
				t.Fatalf("owner=%q 解析为 %d, want %d", c.owner, got, c.want)
			}
		})
	}
	// 缺路径优先报缺路径，别让 owner 的错盖住它。
	if err := dialHelperCommand("", "0"); err == nil || !strings.Contains(err.Error(), "dial-helper-connect") {
		t.Fatalf("缺套接字路径时应说清缺什么: %v", err)
	}
	if err := dialHelperCommand("/tmp/wps/s", ""); err == nil || !strings.Contains(err.Error(), "dial-helper-owner") {
		t.Fatalf("缺 owner 时应说清缺什么: %v", err)
	}
}

// TestGuiDefaultMatchesBuildTag 确认这份测试二进制自己的默认模式符合预期：
// 无标签构建必须是纯命令行，否则 systemd 部署路径会被 GUI 依赖污染。
func TestGuiDefaultMatchesBuildTag(t *testing.T) {
	want := guiDefault
	if want {
		t.Skip("当前是带 gui 标签的构建，默认开界面是预期行为")
	}
	if wantGUI(options{}) {
		t.Error("无标签构建下空参数不应开界面")
	}
}

// TestParseArgsCheckFetch -check-fetch 的两条命令行规矩。
//
// 一是它自己就代表"我要自检"：少了这条，只写 -check-fetch 的人会得到
// "静默正常启动代理服务"，那条命令看起来像没生效。
// 二是不再塞默认的 gstatic 拨号目标：那条他没要求的巡检一旦失败，
// 退出码和报错都会指向一个他没点名的地址。
func TestParseArgsCheckFetch(t *testing.T) {
	cases := []struct {
		name      string
		argv      []string
		wantCheck bool
		wantFetch []string
		wantHosts []string
	}{
		{
			name:      "只给 -check-fetch：不用配 -check，也不塞默认拨号目标",
			argv:      []string{"-check-fetch", "https://www.baidu.com"},
			wantCheck: true, wantFetch: []string{"https://www.baidu.com"},
		},
		{
			name:      "逗号分隔多个 URL",
			argv:      []string{"-check-fetch", "https://a.test/, http://b.test/generate_204"},
			wantCheck: true, wantFetch: []string{"https://a.test/", "http://b.test/generate_204"},
		},
		{
			name:      "同时点名 -check-host：两条都跑，各查各的",
			argv:      []string{"-check-host", "a:443", "-check-fetch", "https://b.test/"},
			wantCheck: true,
			wantFetch: []string{"https://b.test/"},
			wantHosts: []string{"a:443"},
		},
		{
			name:      "只给 -check：仍按老形状补默认拨号目标",
			argv:      []string{"-check"},
			wantCheck: true, wantHosts: []string{"www.gstatic.com:443"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseArgs(append([]string{"config.yaml"}, c.argv...))
			if err != nil {
				t.Fatal(err)
			}
			if got.checkOnly != c.wantCheck {
				t.Errorf("checkOnly = %v, want %v", got.checkOnly, c.wantCheck)
			}
			if !reflect.DeepEqual(got.checkFetch, c.wantFetch) {
				t.Errorf("checkFetch = %v, want %v", got.checkFetch, c.wantFetch)
			}
			if !reflect.DeepEqual(got.checkHosts, c.wantHosts) {
				t.Errorf("checkHosts = %v, want %v（nil 与空是不同的：非空才会跑拨号巡检）", got.checkHosts, c.wantHosts)
			}
		})
	}
}

// TestParseArgsTUNHelper 覆盖 helper 那条命令行：面板是照这个形状拼 argv 的，
// 这里漂了，root 侧就会当成「普通启动」再开一个代理，那是最难查的一种自我复制。
func TestParseArgsTUNHelper(t *testing.T) {
	o, err := parseArgs([]string{"--tun-helper", "--tun-helper-connect=/tmp/wps/s"})
	if err != nil {
		t.Fatalf("parseArgs: %v", err)
	}
	if !o.tunHelper {
		t.Fatal("--tun-helper 没被识别成布尔开关")
	}
	if o.tunHelperConnect != "/tmp/wps/s" {
		t.Fatalf("连接路径 = %q", o.tunHelperConnect)
	}
	// helper 不读配置：默认路径不该被当成位置参数塞进来（那会让它试图起代理）。
	if o.configPath != defaultConfigPath {
		t.Fatalf("configPath 被动过: %q", o.configPath)
	}

	// 分开写的形式也得认：--tun-helper-connect 不是布尔开关，要吃掉后面那个参数。
	o2, err := parseArgs([]string{"--tun-helper", "--tun-helper-connect", "/run/user/1000/x/s"})
	if err != nil || o2.tunHelperConnect != "/run/user/1000/x/s" {
		t.Fatalf("分开写的形式没解析对: %+v err=%v", o2, err)
	}

	if err := tunHelperCommand(""); err == nil || !strings.Contains(err.Error(), "tun-helper-connect") {
		t.Fatalf("缺连接路径时应说清缺什么: %v", err)
	}
}

// TestParseArgsCheckHosts 巡检目标可以重复给，也可以逗号分隔，两种混用。
//
// 给了任何一个 `-check-host` 就**替换**默认目标而不是追加：
// 默认值留在列表里的话，用户点名要查三个站，结果第一条永远是 gstatic，
// 汇总里的 ok=4 也对不上他给的目标数。
func TestParseArgsCheckHosts(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want []string
	}{
		{"没给就用默认", []string{"-check"}, []string{"www.gstatic.com:443"}},
		{"重复给", []string{"-check", "-check-host", "a:443", "-check-host", "b:443"}, []string{"a:443", "b:443"}},
		{"逗号分隔并去掉空格", []string{"-check-host", "a:443, b:443 ,c:443"}, []string{"a:443", "b:443", "c:443"}},
		{"两种混用保持顺序", []string{"-check-host", "a:443,b:443", "-check-host", "c:443"}, []string{"a:443", "b:443", "c:443"}},
		{"全空也回落到默认", []string{"-check-host", " , "}, []string{"www.gstatic.com:443"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseArgs(append([]string{"config.yaml"}, c.argv...))
			if err != nil {
				t.Fatal(err)
			}
			if len(got.checkHosts) != len(c.want) {
				t.Fatalf("目标数 %d 个 %v，期望 %v", len(got.checkHosts), got.checkHosts, c.want)
			}
			for i := range c.want {
				if got.checkHosts[i] != c.want[i] {
					t.Errorf("第 %d 个 = %q, 期望 %q（整体 %v）", i, got.checkHosts[i], c.want[i], got.checkHosts)
				}
			}
		})
	}
}

func TestParseArgsVersion(t *testing.T) {
	o, err := parseArgs([]string{"-version"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.version {
		t.Fatal("-version 没有被解析成 version 动作")
	}
	// -version 不该顺带要求一个真实配置文件；默认值仍然可以指向 config.yaml，
	// 但 runCLI 会在读配置之前就返回。
	if o.configPath == "" {
		t.Error("默认配置路径被清空了：这会让 -version 的解析路径与其它选项不一致")
	}
}
