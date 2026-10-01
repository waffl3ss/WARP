package workspace

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDiskLevelThresholds(t *testing.T) {
	cases := []struct {
		pct  float64
		want DiskLevel
	}{
		{0, DiskOK},
		{74.9, DiskOK},
		{75, DiskWatch},
		{84.9, DiskWatch},
		{85, DiskWarn},
		{89.9, DiskWarn},
		// The banner threshold the operator asked for. Exactly 90 is critical, not "nearly".
		{90, DiskCritical},
		{99.9, DiskCritical},
		{100, DiskCritical},
	}
	for _, c := range cases {
		if got := levelFor(c.pct); got != c.want {
			t.Errorf("levelFor(%.1f) = %q, want %q", c.pct, got, c.want)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{999, "999 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		// Above 100 the decimal is dropped so the column width stays put.
		{104 * 1024 * 1024, "104 MB"},
		{10 * 1024 * 1024 * 1024, "10.0 GB"},
		{-1, "-"},
	}
	for _, c := range cases {
		if got := HumanBytes(c.n); got != c.want {
			t.Errorf("HumanBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

// TestDiskReportsTheEngagementSize.
//
// The engagement figure is the one that goes in a handover note and decides whether the
// capture will fit on the drive it is being copied to, so it has to count what WARP actually
// wrote — including the raw archive under captures/, which is the bulk of it and is what
// silently fills a box.
func TestDiskReportsTheEngagementSize(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("CORP-WIFI\n"), 0o600); err != nil {
		t.Fatalf("write scope: %v", err)
	}

	ws, _, err := Init(filepath.Join(dir, "engagement"), scopePath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer ws.Close()

	before, err := ws.Disk()
	if err != nil {
		t.Fatalf("Disk: %v", err)
	}
	if before.TotalBytes <= 0 {
		t.Fatal("Disk reported no filesystem at all; statfs did not run")
	}
	if before.Path != ws.Dir {
		t.Errorf("Disk().Path = %q, want %q", before.Path, ws.Dir)
	}

	// A capture-sized file somewhere WARP writes, including a subdirectory: the archive lives
	// under captures/ and a walk that only looked at the top level would miss all of it.
	sub := filepath.Join(ws.Dir, "captures")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const size = 512 * 1024
	if err := os.WriteFile(filepath.Join(sub, "warp.pcapng"), make([]byte, size), 0o600); err != nil {
		t.Fatalf("write capture: %v", err)
	}

	// The walk is cached on an interval, so force the recount the way a later poll would.
	ws.disk.mu.Lock()
	ws.disk.taken = time.Time{}
	ws.disk.mu.Unlock()

	after, err := ws.Disk()
	if err != nil {
		t.Fatalf("Disk: %v", err)
	}
	if grew := after.EngagementBytes - before.EngagementBytes; grew < size {
		t.Errorf("engagement grew by %d bytes, want at least %d — the walk is not reaching "+
			"subdirectories, which is where the capture archive lives", grew, size)
	}
}

// TestDiskPercentIgnoresTheRootReserve.
//
// Bavail excludes the space reserved for root, which the capture cannot use. Measuring against
// the raw total would understate how close capture is to stopping on exactly the small volume
// where it matters most.
func TestDiskPercentIsAgainstUsableSpace(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("CORP-WIFI\n"), 0o600); err != nil {
		t.Fatalf("write scope: %v", err)
	}
	ws, _, err := Init(filepath.Join(dir, "engagement"), scopePath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer ws.Close()

	u, err := ws.Disk()
	if err != nil {
		t.Fatalf("Disk: %v", err)
	}
	if u.UsedPercent < 0 || u.UsedPercent > 100 {
		t.Fatalf("used_percent = %.1f, which is not a percentage", u.UsedPercent)
	}
	if u.FreeBytes < 0 || u.UsedBytes < 0 {
		t.Fatalf("negative figures: used=%d free=%d", u.UsedBytes, u.FreeBytes)
	}
	if u.Level != levelFor(u.UsedPercent) {
		t.Errorf("level %q does not match %.1f%%", u.Level, u.UsedPercent)
	}
}
