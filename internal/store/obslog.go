package store

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/waffl3ss/warp/internal/recon"
)

// ObservationLog appends observations to observations.csv as they are captured.
//
// Observations are the one projection that cannot be regenerated on a timer. Every other CSV
// holds one row per device - a few hundred rows on a large site, cheap to rebuild wholesale -
// but observations are one row per frame heard, millions of them over a multi-day run.
// Rewriting that file every few seconds would cost more disk I/O than the capture itself, and
// buffering it to write at the end is worse still: it holds the whole engagement in RAM and
// loses all of it to a SIGKILL, a flat battery or a box being unplugged.
//
// They are also append-only by nature. A signal reading at a timestamp is never revised and
// never duplicated, so there is nothing to deduplicate and no reason to rewrite what is
// already on disk. Appending is not merely the cheaper shape here, it is the correct one.
//
// One writer owns the file. Appends serialise on the mutex rather than through a dedicated
// goroutine because two paths flush observations - the interval timer and a full buffer - and
// two interleaved appends producing a half-written row is exactly the corruption the
// one-owner-per-file rule exists to prevent.
type ObservationLog struct {
	path string

	mu sync.Mutex
	f  *os.File
	w  *csv.Writer
}

var observationHeader = []string{
	"addr", "is_ap", "rssi", "freq", "channel", "ts", "radio_id", "frame_type",
}

// OpenObservationLog opens dir/observations.csv for appending, writing the header only if the
// file is new or empty.
//
// A resumed engagement appends to what is already there rather than truncating it or adding a
// second header line: the daemon restarting mid-engagement - after a crash, a reboot, or an
// operator moving the box - must not cost the observations captured before it.
func OpenObservationLog(dir string) (*ObservationLog, error) {
	path := filepath.Join(dir, ObservationsCSV)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: open observation log: %w", err)
	}

	l := &ObservationLog{path: path, f: f, w: csv.NewWriter(f)}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("store: stat observation log: %w", err)
	}
	if info.Size() == 0 {
		if err := l.w.Write(observationHeader); err != nil {
			f.Close()
			return nil, fmt.Errorf("store: write observation header: %w", err)
		}
		l.w.Flush()
		if err := l.w.Error(); err != nil {
			f.Close()
			return nil, fmt.Errorf("store: write observation header: %w", err)
		}
	}
	return l, nil
}

// Append writes a batch of observations and syncs them to disk.
//
// Synced on every batch rather than left to the page cache. A batch is at most a couple of
// seconds of capture, the cost is trivial against what the radios are already doing, and the
// whole point of writing incrementally is that the file is complete up to the instant the
// power went out.
func (l *ObservationLog) Append(obs []recon.Observation) error {
	if l == nil || len(obs) == 0 {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	for _, o := range obs {
		if err := l.w.Write([]string{
			o.Addr.String(), boolStr(o.IsAP), itoa(int(o.RSSI)), itoa(o.Freq), itoa(o.Channel),
			o.Timestamp.Format(timeFormat), o.RadioID, o.FrameType,
		}); err != nil {
			return fmt.Errorf("store: append observation: %w", err)
		}
	}

	l.w.Flush()
	if err := l.w.Error(); err != nil {
		return fmt.Errorf("store: append observations: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		return fmt.Errorf("store: sync observation log: %w", err)
	}
	return nil
}

// Size reports the observation log's size on disk, for the disk-usage display.
func (l *ObservationLog) Size() int64 {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	info, err := l.f.Stat()
	if err != nil {
		return 0
	}
	return info.Size()
}

// Path returns the file being appended to.
func (l *ObservationLog) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Close flushes and closes the log.
func (l *ObservationLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.w.Flush()
	flushErr := l.w.Error()
	if err := l.f.Close(); err != nil && flushErr == nil {
		flushErr = err
	}
	return flushErr
}
