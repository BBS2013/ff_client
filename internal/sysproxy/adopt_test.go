package sysproxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAdoptLedgerRetargetsLivePanel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml.sysproxy.json")
	st := saved{
		PID:     111,
		Exe:     "/old/wps_app-gui",
		Backend: BackendGNOME,
		Mode:    "none",
		SavedAt: time.Now(),
	}
	if err := writeState(path, st); err != nil {
		t.Fatalf("写账本: %v", err)
	}
	if err := AdoptLedger(path, 222, "/new/wps_app-gui"); err != nil {
		t.Fatalf("AdoptLedger: %v", err)
	}
	got, err := peekSaved(path)
	if err != nil {
		t.Fatalf("读回账本: %v", err)
	}
	if got.PID != 222 || got.Exe != "/new/wps_app-gui" {
		t.Fatalf("账本宿主没改成面板: pid=%d exe=%q", got.PID, got.Exe)
	}
	if got.Mode != "none" || got.Backend != BackendGNOME {
		t.Fatalf("改宿主时不该动原状: %+v", got)
	}
}

func TestAdoptLedgerWithoutFileIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.sysproxy.json")
	if err := AdoptLedger(path, 123, "/x"); err != nil {
		t.Fatalf("没有账本时应当空操作: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("没有账本时不该凭空造一份: %v", err)
	}
}
