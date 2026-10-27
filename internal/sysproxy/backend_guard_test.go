package sysproxy

import (
	"context"
	"strings"
	"testing"
)

// TestBackendListsAgree 后端名在项目里抄了好几份：偏好顺序、lookup、
// 给配置校验用的清单、记账/还原的 switch。少同步一处就会静默走错，
// 而后端管的是**用户的系统设置**，走错的后果是桌面回不来、整机断网。
//
// 这条用例把"这几份必须一致"变成测试，而不是靠记得。
func TestBackendListsAgree(t *testing.T) {
	order := backendsInPreferenceOrder()
	if len(order) == 0 {
		t.Fatal("偏好顺序是空的")
	}
	seen := map[string]bool{}
	for _, b := range order {
		name := b.Name()
		if seen[name] {
			t.Errorf("偏好顺序里 %q 出现了两次，探测会白做一遍", name)
		}
		seen[name] = true
		if lookup(name) == nil {
			t.Errorf("%q 在偏好顺序里但 lookup 认不出：探测通过却没法按名字指定", name)
		}
		if !ValidBackend(name) {
			t.Errorf("%q 在偏好顺序里却被配置校验拒绝：自动能用、写死反而报错", name)
		}
	}
	// auto 不是后端本身，允许清单里除了各后端只剩它。
	for _, name := range Backends() {
		if name == BackendAuto {
			continue
		}
		if !seen[name] {
			t.Errorf("%q 被 Backends() 允许、却没有进偏好顺序：钉死它能过校验，却没人去探测", name)
		}
	}
}

// TestUnknownBackendCannotBeAccounted 后端一旦接入探测却没接记账，
// 必须拒绝改动系统代理，而不是按 GNOME 记账。
//
// 按 GNOME 记账的后果是单向的：改的是新后端、记的是 gsettings 的账，
// 还原时去写 gsettings —— 新后端改的东西永远还原不了。
func TestUnknownBackendCannotBeAccounted(t *testing.T) {
	stub := stubBackend{name: "wayland"}
	if _, err := capture(context.Background(), &rec{}, stub, Config{Enable: true}); err == nil {
		t.Fatal("未接入记账的后端必须拒绝改动，而不是按 GNOME 记一份")
	} else if !strings.Contains(err.Error(), "wayland") {
		t.Errorf("错误里要点名是哪个后端: %v", err)
	}
	err := apply(context.Background(), &rec{}, saved{Backend: "wayland"})
	if err == nil || !strings.Contains(err.Error(), "wayland") {
		t.Errorf("还原遇到未接入的后端应点名报错: %v", err)
	}
}

// stubBackend 是一个"接进了探测、忘了接记账"的后端，专门用来走上面那条守卫。
type stubBackend struct{ name string }

func (b stubBackend) Name() string                        { return b.name }
func (b stubBackend) Probe(context.Context, Runner) error { return nil }
func (b stubBackend) Apply(context.Context, Runner, Config) error {
	return ErrUnsupported
}
func (b stubBackend) Read(context.Context, Runner) (Status, error) {
	return Status{Backend: b.name, Supported: true}, nil
}
