package store

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/recon"
)

func obs(t *testing.T, addr string, rssi int8, at time.Time) recon.Observation {
	t.Helper()
	return recon.Observation{
		Addr: mac(t, addr), IsAP: true, RSSI: rssi, Freq: 2437, Channel: 6,
		Timestamp: at, RadioID: "phy1", FrameType: "beacon",
	}
}

// readObsCSV returns the rows on disk, excluding the header.
func readObsCSV(t *testing.T, dir string) [][]string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, ObservationsCSV))
	if err != nil {
		t.Fatalf("open %s: %v", ObservationsCSV, err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("%s is not valid CSV: %v", ObservationsCSV, err)
	}
	if len(records) == 0 {
		t.Fatalf("%s has no header", ObservationsCSV)
	}
	return records[1:]
}

// TestObservationsAreReadableBeforeAnythingIsClosed is the bug this exists for.
//
// The engagement directory used to be empty until the daemon exited — fifty access points on
// screen and a zero-byte observations.csv on disk, with nothing recoverable if the box lost
// power. Every append must be complete and parseable at the instant it returns, with no close
// and no final export involved.
func TestObservationsAreReadableBeforeAnythingIsClosed(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)

	log, err := OpenObservationLog(dir)
	if err != nil {
		t.Fatalf("OpenObservationLog: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	// A header exists from the moment the file does, so a reader never meets a zero-byte file.
	if rows := readObsCSV(t, dir); len(rows) != 0 {
		t.Fatalf("a freshly opened log has %d data rows, want 0", len(rows))
	}

	for i := 0; i < 3; i++ {
		if err := log.Append([]recon.Observation{obs(t, "a4:2b:8c:11:22:33", -55, now.Add(time.Duration(i)*time.Second))}); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		rows := readObsCSV(t, dir)
		if len(rows) != i+1 {
			t.Fatalf("after append %d the file holds %d rows, want %d", i, len(rows), i+1)
		}
	}

	rows := readObsCSV(t, dir)
	if got := rows[0][0]; got != "a4:2b:8c:11:22:33" {
		t.Errorf("addr = %q, want a4:2b:8c:11:22:33", got)
	}
	if got := rows[0][2]; got != "-55" {
		t.Errorf("rssi = %q, want -55", got)
	}
}

// TestObservationLogResumesWithoutASecondHeader.
//
// A daemon restarting mid-engagement — a crash, a reboot, the box being moved — must append to
// what is already there. Truncating would lose the capture so far; a second header line in the
// middle would break every tool that reads the file.
func TestObservationLogResumesWithoutASecondHeader(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)

	first, err := OpenObservationLog(dir)
	if err != nil {
		t.Fatalf("OpenObservationLog: %v", err)
	}
	if err := first.Append([]recon.Observation{obs(t, "a4:2b:8c:11:22:33", -55, now)}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := OpenObservationLog(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { second.Close() })
	if err := second.Append([]recon.Observation{obs(t, "a4:2b:8c:44:55:66", -70, now.Add(time.Minute))}); err != nil {
		t.Fatalf("Append after reopen: %v", err)
	}

	rows := readObsCSV(t, dir)
	if len(rows) != 2 {
		t.Fatalf("after a restart the file holds %d rows, want 2 (the earlier capture plus the new one)", len(rows))
	}
	if rows[0][0] == rows[1][0] {
		t.Errorf("both rows are %q; the reopened log overwrote rather than appended", rows[0][0])
	}
	for i, r := range rows {
		if r[0] == observationHeader[0] {
			t.Errorf("row %d is a second header line", i)
		}
	}
}

// TestConcurrentAppendsDoNotInterleave.
//
// Two paths flush observations — the interval timer and a full buffer — so appends really do
// race. A half-written row from an interleaved append is silent corruption that only surfaces
// when someone tries to parse the file days later.
func TestConcurrentAppendsDoNotInterleave(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)

	log, err := OpenObservationLog(dir)
	if err != nil {
		t.Fatalf("OpenObservationLog: %v", err)
	}
	t.Cleanup(func() { log.Close() })

	const writers, each = 8, 25
	done := make(chan error, writers)
	for w := 0; w < writers; w++ {
		go func(w int) {
			batch := make([]recon.Observation, 0, each)
			for i := 0; i < each; i++ {
				batch = append(batch, obs(t, "a4:2b:8c:11:22:33", -55, now.Add(time.Duration(i)*time.Second)))
			}
			done <- log.Append(batch)
		}(w)
	}
	for w := 0; w < writers; w++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Append: %v", err)
		}
	}

	rows := readObsCSV(t, dir)
	if len(rows) != writers*each {
		t.Fatalf("file holds %d rows, want %d", len(rows), writers*each)
	}
	for i, r := range rows {
		if len(r) != len(observationHeader) {
			t.Fatalf("row %d has %d fields, want %d: %v", i, len(r), len(observationHeader), r)
		}
	}
}
