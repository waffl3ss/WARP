package workspace

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Disk usage reporting for the engagement directory.
//
// An engagement fills a disk quietly. The raw pcapng archive is the bulk of it and grows with
// airtime rather than with anything on screen, so nothing an operator is watching hints at how
// close the box is to full - and the failure mode is not a warning, it is captures that stop
// being written, on a NUC in a closet, discovered when someone comes back for it. Both
// frontends carry the number for that reason.
//
// Two figures, because they answer different questions. "How much has this engagement
// produced" is what goes in a handover note and decides whether it will fit on the drive it is
// being copied to. "How much is left on the filesystem" is what decides whether capture is
// about to stop, and it counts everything on the volume, not just WARP's share.

// DiskUsage is the state of the filesystem holding the engagement, plus what the engagement
// itself has written.
type DiskUsage struct {
	// Path is the engagement directory these figures are about.
	Path string `json:"path"`

	// TotalBytes, UsedBytes and FreeBytes describe the filesystem.
	//
	// FreeBytes is the space available to *this* user, which on a root-reserved ext4 is several
	// percent less than the raw free count. It is the honest number: the reserve is not space
	// the capture can use.
	TotalBytes int64 `json:"total_bytes"`
	UsedBytes  int64 `json:"used_bytes"`
	FreeBytes  int64 `json:"free_bytes"`

	// UsedPercent is of the filesystem, rounded to one decimal.
	UsedPercent float64 `json:"used_percent"`

	// EngagementBytes is what this engagement has written: the database, the hash files, the
	// projections and the raw archive.
	EngagementBytes int64 `json:"engagement_bytes"`

	// Level is the severity a frontend should render this at.
	Level DiskLevel `json:"level"`
}

// DiskLevel classifies how close the filesystem is to full.
type DiskLevel string

// Disk severity levels. The thresholds are deliberately not configurable: they are about the
// physics of a filling disk, not about a preference.
const (
	// DiskOK is under 75%.
	DiskOK DiskLevel = "ok"
	// DiskWatch is 75% and over - worth seeing, nothing to do yet.
	DiskWatch DiskLevel = "watch"
	// DiskWarn is 85% and over - a long capture from here will not finish.
	DiskWarn DiskLevel = "warn"
	// DiskCritical is 90% and over, and earns a banner on both frontends. Below the last few
	// percent, sqlite starts failing writes and the pcapng archive stops growing; a capture
	// that silently stopped is worse than one that never started, because nobody re-runs it.
	DiskCritical DiskLevel = "critical"
)

// levelFor classifies a percentage.
func levelFor(pct float64) DiskLevel {
	switch {
	case pct >= 90:
		return DiskCritical
	case pct >= 85:
		return DiskWarn
	case pct >= 75:
		return DiskWatch
	default:
		return DiskOK
	}
}

// Critical reports whether the frontends should show the banner.
func (u DiskUsage) Critical() bool { return u.Level == DiskCritical }

// diskCache holds the last directory walk.
//
// Statfs is a single cheap syscall and is taken fresh every time. Summing the engagement
// directory is a walk over files that can number in the thousands once the archive has been
// rotated, and both frontends poll once a second, so that half is recomputed on an interval
// instead. The number moves slowly enough that a few seconds of staleness means nothing.
type diskCache struct {
	mu      sync.Mutex
	bytes   int64
	taken   time.Time
	walking bool
}

const diskWalkInterval = 15 * time.Second

// Disk reports the state of the filesystem holding the workspace.
func (w *Workspace) Disk() (DiskUsage, error) {
	u := DiskUsage{Path: w.Dir}

	var st unix.Statfs_t
	if err := unix.Statfs(w.Dir, &st); err != nil {
		return u, fmt.Errorf("workspace: statfs %s: %w", w.Dir, err)
	}

	// Bsize is the filesystem's block size; Blocks, Bfree and Bavail are counts of it. Bavail
	// rather than Bfree: the difference is the root reserve, which the capture cannot use.
	bs := int64(st.Bsize)
	u.TotalBytes = int64(st.Blocks) * bs
	u.FreeBytes = int64(st.Bavail) * bs
	u.UsedBytes = u.TotalBytes - int64(st.Bfree)*bs

	// Against the space actually usable, not against the raw total: on a volume where the root
	// reserve is most of what is left, "88% used" understates how close capture is to stopping.
	usable := u.UsedBytes + u.FreeBytes
	if usable > 0 {
		u.UsedPercent = float64(u.UsedBytes) / float64(usable) * 100
		u.UsedPercent = float64(int64(u.UsedPercent*10+0.5)) / 10
	}
	u.Level = levelFor(u.UsedPercent)

	u.EngagementBytes = w.engagementBytes()
	return u, nil
}

// engagementBytes returns the size of the engagement directory, refreshing it in the
// background when the cached figure is stale.
//
// It never blocks the caller on the walk. Both frontends ask for this on their refresh tick,
// and a slow directory - a spinning disk, an SD card, an archive that has grown to thousands
// of files - would otherwise stall the dashboard once every interval.
func (w *Workspace) engagementBytes() int64 {
	w.disk.mu.Lock()
	first := w.disk.taken.IsZero()
	stale := time.Since(w.disk.taken) >= diskWalkInterval
	bytes := w.disk.bytes
	if (first || stale) && !w.disk.walking {
		w.disk.walking = true
		w.disk.mu.Unlock()
		if first {
			// The very first walk is synchronous so the first thing drawn on screen is a real
			// figure rather than a zero that corrects itself a second later.
			w.walkEngagement()
			w.disk.mu.Lock()
			bytes = w.disk.bytes
			w.disk.mu.Unlock()
			return bytes
		}
		go w.walkEngagement()
		return bytes
	}
	w.disk.mu.Unlock()
	return bytes
}

func (w *Workspace) walkEngagement() {
	var total int64
	// Errors are ignored per entry rather than abandoning the walk: a file removed underneath
	// us mid-capture is normal, and returning nothing because of one would blank the display.
	_ = filepath.WalkDir(w.Dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})

	w.disk.mu.Lock()
	w.disk.bytes = total
	w.disk.taken = time.Now()
	w.disk.walking = false
	w.disk.mu.Unlock()
}

// HumanBytes renders a byte count the way an operator reads one.
//
// Binary units, and one decimal place only below 100 so the width stays stable: a figure that
// changes from "9.8 GB" to "10.2 GB" to "104 GB" in a fixed-width column should not move the
// column.
func HumanBytes(n int64) string {
	if n < 0 {
		return "-"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	val := float64(n) / float64(div)
	suffix := [...]string{"KB", "MB", "GB", "TB", "PB"}[exp]
	if val >= 100 {
		return fmt.Sprintf("%.0f %s", val, suffix)
	}
	return fmt.Sprintf("%.1f %s", val, suffix)
}
