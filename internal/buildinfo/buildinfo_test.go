package buildinfo

import (
	"runtime"
	"strings"
	"testing"
)

func TestSummaryIncludesVersionStampAndBuildTime(t *testing.T) {
	oldV, oldS, oldB := Version, Stamp, BuiltAt
	defer func() { Version, Stamp, BuiltAt = oldV, oldS, oldB }()

	Version, Stamp, BuiltAt = "0.1.0", "abc123-dirty", "2026-10-27T00:00:00Z"
	got := Summary()
	for _, want := range []string{"0.1.0", "abc123-dirty", "2026-10-27T00:00:00Z", runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(got, want) {
			t.Errorf("Summary() = %q，缺少 %q", got, want)
		}
	}
}

func TestSummaryOmitsEmptyBuiltAt(t *testing.T) {
	oldV, oldS, oldB := Version, Stamp, BuiltAt
	defer func() { Version, Stamp, BuiltAt = oldV, oldS, oldB }()

	Version, Stamp, BuiltAt = "0.1.0", "abc123", ""
	if got := Summary(); strings.Contains(got, "built") {
		t.Errorf("没有构建时刻却出现了 built: %q", got)
	}
}
