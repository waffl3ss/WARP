package store

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// CSV projection filenames.
const (
	APsCSV          = "bssids.csv"
	StationsCSV     = "clients.csv"
	ObservationsCSV = "observations.csv"
	WalkthroughsCSV = "walkthroughs.csv"
	// FindingsCSV holds every finding - posture (WPS, WEP, 802.11w), decloaks, evil-twin
	// candidates, the lot. RoguesCSV is the narrow subset an operator means by "rogues": the
	// devices the classifier flagged as impersonating or answering for a network they should not
	// (evil-twin candidates and karma responders), not the whole findings table.
	FindingsCSV = "findings.csv"
	// FindingsInScopeCSV is the same table narrowed to findings on a scoped ESSID. On most
	// engagements the out-of-scope findings are noise the report never touches, so this file is
	// the one an operator hands to reporting: every row is a network the SoW actually covers.
	FindingsInScopeCSV = "findings-in-scope.csv"
	RoguesCSV          = "rogues.csv"
)

// rogueLabels are the finding labels that belong in rogues.csv - the classifier's "this device is
// not what it claims" verdicts. Kept as literals rather than importing internal/rogue, which
// imports this package. Mirrors rogue.LabelEvilTwinCandidate / rogue.LabelKarmaResponder.
var rogueLabels = map[string]bool{
	"evil twin candidate":      true,
	"karma responder":          true,
	"Potentially Rogue Device": true, // operator-marked; mirrors rogue.LabelPotentialRogue
}

// ExportCSV regenerates the state projections from the database.
//
// These files exist purely for interoperability with other tools. sqlite is authoritative and
// they are always rebuilt wholesale, never appended to incrementally - which is what makes
// concurrent-append corruption impossible rather than merely unlikely. The brief's rule is
// "one goroutine owns each file"; regenerating under the store's lock is a stronger version
// of the same guarantee.
//
// Rebuilding wholesale is only affordable because every file here holds *one row per device*:
// a few hundred rows on a large site, cheap enough to regenerate every few seconds so the
// engagement directory tracks what is on screen. Deduplication is therefore free - the
// database key is the identity, and the row is whatever is currently known about it.
//
// observations.csv is deliberately not in this set. It is one row per frame heard, it is
// append-only by nature, and it is written live by ObservationLog.
//
// Each file is written to a temporary path and renamed into place, so a reader never sees a
// half-written projection and an interrupted export cannot leave a truncated file behind.
func (s *Store) ExportCSV(ctx context.Context, dir string) error {
	type job struct {
		name string
		fn   func(context.Context, *csv.Writer) error
	}
	jobs := []job{
		{APsCSV, s.exportAPs},
		{StationsCSV, s.exportStations},
		{WalkthroughsCSV, s.exportWalkthroughs},
		{FindingsCSV, s.exportFindings},
		{FindingsInScopeCSV, s.exportFindingsInScope},
		{RoguesCSV, s.exportRogues},
	}

	for _, j := range jobs {
		if err := writeCSVAtomic(ctx, filepath.Join(dir, j.name), j.fn); err != nil {
			return err
		}
	}
	// The Kismet-style netxml projection rides the same tick: a survey-tool-importable view of the
	// same one-row-per-device data.
	if err := s.WriteNetXML(ctx, filepath.Join(dir, NetXMLFile)); err != nil {
		return err
	}
	return nil
}

// ExportObservationsCSV rebuilds observations.csv from the database.
//
// Only for rebuilding an engagement directory after the fact - from an archived warp.db, or
// after the file was deleted. It must never run while a daemon holds an ObservationLog over
// the same path: this renames a new file into place, and the appender would go on writing to
// the unlinked inode, silently losing everything captured afterwards.
func (s *Store) ExportObservationsCSV(ctx context.Context, dir string) error {
	return writeCSVAtomic(ctx, filepath.Join(dir, ObservationsCSV), s.exportObservations)
}

func writeCSVAtomic(ctx context.Context, path string, fn func(context.Context, *csv.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".warp-csv-*")
	if err != nil {
		return fmt.Errorf("store: create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed

	w := csv.NewWriter(tmp)
	if err := fn(ctx, w); err != nil {
		tmp.Close()
		return err
	}
	w.Flush()
	if err := w.Error(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write %s: %w", path, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("store: secure %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("store: rename into %s: %w", path, err)
	}
	return nil
}

func (s *Store) exportAPs(ctx context.Context, w *csv.Writer) error {
	rows, err := s.APs(ctx, "")
	if err != nil {
		return err
	}
	if err := w.Write([]string{
		"bssid", "essid", "hidden", "channel", "band", "security", "mfp", "wps",
		"ciphers", "akms", "transition_mode", "fingerprint_hash", "oui",
		"best_rssi", "best_rssi_radio", "first_seen", "last_seen", "beacons",
	}); err != nil {
		return err
	}
	for _, r := range rows {
		if err := w.Write([]string{
			r.BSSID, r.ESSID, boolStr(r.Hidden), itoa(r.Channel), r.Band,
			r.SecurityClass, r.MFP, boolStr(r.WPS), r.Ciphers, r.AKMs,
			boolStr(r.Transition), r.FingerprintHash, r.OUI,
			rssiStr(r.BestRSSI), r.BestRSSIRadio, r.FirstSeen, r.LastSeen,
			strconv.FormatInt(r.Beacons, 10),
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) exportStations(ctx context.Context, w *csv.Writer) error {
	rows, err := s.Stations(ctx)
	if err != nil {
		return err
	}
	if err := w.Write([]string{
		"mac", "bssid", "first_seen", "last_seen", "best_rssi",
		"randomised_mac", "oui", "frames", "probed_essids",
	}); err != nil {
		return err
	}
	for _, r := range rows {
		if err := w.Write([]string{
			r.MAC, r.BSSID, r.FirstSeen, r.LastSeen, rssiStr(r.BestRSSI),
			boolStr(r.Randomised), r.OUI, strconv.FormatInt(r.Frames, 10), r.ProbedESSIDs,
		}); err != nil {
			return err
		}
	}
	return nil
}

// exportObservations streams rather than loading every row: a multi-day run produces millions
// of observations and materialising them all would be a needless memory spike on a NUC.
func (s *Store) exportObservations(ctx context.Context, w *csv.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT addr, is_ap, rssi, freq, channel, ts, radio_id, frame_type
FROM observations ORDER BY ts`)
	if err != nil {
		return fmt.Errorf("store: query observations: %w", err)
	}
	defer rows.Close()

	if err := w.Write([]string{
		"addr", "is_ap", "rssi", "freq", "channel", "ts", "radio_id", "frame_type",
	}); err != nil {
		return err
	}

	for rows.Next() {
		var (
			addr, ts, radioID, frameType string
			isAP, rssi, freq, channel    int
		)
		if err := rows.Scan(&addr, &isAP, &rssi, &freq, &channel, &ts, &radioID, &frameType); err != nil {
			return err
		}
		if err := w.Write([]string{
			addr, boolStr(isAP != 0), itoa(rssi), itoa(freq), itoa(channel), ts, radioID, frameType,
		}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) exportWalkthroughs(ctx context.Context, w *csv.Writer) error {
	rows, err := s.ListWalkthroughs(ctx)
	if err != nil {
		return err
	}
	if err := w.Write([]string{
		"id", "name", "start_ts", "end_ts", "duration", "observations", "implicit", "notes",
	}); err != nil {
		return err
	}
	now := time.Now()
	for _, r := range rows {
		end := ""
		if r.EndTS != nil {
			end = r.EndTS.Format(timeFormat)
		}
		if err := w.Write([]string{
			strconv.FormatInt(r.ID, 10), r.Name, r.StartTS.Format(timeFormat), end,
			r.Duration(now).Round(time.Second).String(), itoa(r.Observations),
			boolStr(r.Implicit), r.Notes,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) exportFindings(ctx context.Context, w *csv.Writer) error {
	return s.writeFindings(ctx, w, nil)
}

// exportRogues writes only the classifier's rogue verdicts (evil-twin candidates, karma
// responders), so rogues.csv is the short list of suspicious devices rather than every finding.
func (s *Store) exportRogues(ctx context.Context, w *csv.Writer) error {
	return s.writeFindings(ctx, w, func(f Finding) bool { return rogueLabels[f.Label] })
}

// labelPotentialRogue mirrors rogue.LabelPotentialRogue. Kept as a literal because internal/rogue
// imports this package, so it cannot be imported back.
const labelPotentialRogue = "Potentially Rogue Device"

// exportFindingsInScope writes only the findings whose ESSID is in the engagement scope. A finding
// with no ESSID (a hidden or unnamed device) is out of scope by definition here - there is no name
// to match - which is the safe direction for the deliverable. The one exception is a manually-marked
// potential rogue: it is always part of the deliverable, because it is a finding about a device in
// the client's footprint that, being a suspected impostor, will not sit on a scoped ESSID.
func (s *Store) exportFindingsInScope(ctx context.Context, w *csv.Writer) error {
	inScope := s.scopeFilter()
	return s.writeFindings(ctx, w, func(f Finding) bool {
		if f.Label == labelPotentialRogue {
			return true
		}
		return f.ESSID != "" && inScope(f.ESSID)
	})
}

// writeFindings projects the findings table to CSV. keep, when non-nil, selects which findings to
// write; a nil keep writes every finding.
func (s *Store) writeFindings(ctx context.Context, w *csv.Writer, keep func(Finding) bool) error {
	rows, err := s.Findings(ctx, "")
	if err != nil {
		return err
	}
	if err := w.Write([]string{
		"bssid", "essid", "tier", "label", "rationale", "differences", "score",
		"first_seen", "last_seen",
	}); err != nil {
		return err
	}
	for _, r := range rows {
		if keep != nil && !keep(r) {
			continue
		}
		score := ""
		if r.Score != nil {
			score = strconv.FormatFloat(*r.Score, 'f', 3, 64)
		}
		diffs := ""
		for i, d := range r.Differences {
			if i > 0 {
				diffs += "; "
			}
			diffs += d
		}
		if err := w.Write([]string{
			r.BSSID, r.ESSID, string(r.Tier), r.Label, r.Rationale, diffs, score,
			r.FirstTS.Format(timeFormat), r.LastTS.Format(timeFormat),
		}); err != nil {
			return err
		}
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func itoa(v int) string { return strconv.Itoa(v) }

// rssiStr renders a missing signal as empty rather than 0, which would read as the strongest
// possible reading in any tool that imports the CSV.
func rssiStr(v *int) string {
	if v == nil {
		return ""
	}
	return strconv.Itoa(*v)
}
