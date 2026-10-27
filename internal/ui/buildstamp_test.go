package ui

import (
	"testing"
	"time"

	"wps_app/internal/buildinfo"
)

// TestBuildInfoCarriesBuildStamp 盯的是设置页那三行：
// 版本、源码指纹、构建时刻必须从注入值走到投影里，不能在 ui 包重新编一个。
func TestBuildInfoCarriesBuildStamp(t *testing.T) {
	oldV, oldS, oldB := buildinfo.Version, buildinfo.Stamp, buildinfo.BuiltAt
	defer func() { buildinfo.Version, buildinfo.Stamp, buildinfo.BuiltAt = oldV, oldS, oldB }()

	buildinfo.Version, buildinfo.Stamp, buildinfo.BuiltAt = "0.1.0", "abc123-dirty", "2026-10-27T00:00:00Z"
	info := buildInfo(time.Now(), "index-Ab12Cd34.js")
	if info.Version != "0.1.0" || info.Stamp != "abc123-dirty" || info.BuiltAt != "2026-10-27T00:00:00Z" {
		t.Errorf("构建指纹没进投影: %+v", info)
	}
}
