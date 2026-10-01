package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Tier is the confidence tier of a finding.
//
// The tiers exist so a report never overstates what is known. "Determined" facts are
// deterministic and defensible; "evidence" findings are inferences with the supporting
// attributes attached; everything else stays "unclassified" and is listed with its
// observations and no label at all.
type Tier string

// Confidence tiers.
const (
	// TierDetermined is deterministic and defensible: an encryption fact, a configuration
	// fact, or a yes/no active test result.
	TierDetermined Tier = "determined"
	// TierEvidence is an inference from the observed population, always accompanied by the
	// specific attributes that differed.
	TierEvidence Tier = "evidence"
	// TierUnclassified is the default state of every observed device. It is not "neighbour":
	// concluding a device is a neighbour is a conclusion, and an unsupported one.
	TierUnclassified Tier = "unclassified"
	// TierControl is a positive result: a configuration that is correct, or an active test the
	// device passed. 802.11w required, WPS locked, and an AP that resisted Pixie Dust are all
	// controls - the tool tested for an exposure and did not find one. They are recorded (a
	// report that only lists what broke cannot tell what was tested from what was not, per the
	// brief) but they are not exposures, so they are kept out of the exposure list and shown as
	// passes.
	TierControl Tier = "control"
)

// Finding is a conclusion about a device.
//
// Findings live in their own table and never modify an AP's observed record. A report must be
// able to show the evidence independently of the label, and a reclassification must change
// nothing about what was seen.
type Finding struct {
	ID    int64  `json:"id"`
	BSSID string `json:"bssid"`
	ESSID string `json:"essid,omitempty"`
	Tier  Tier   `json:"tier"`
	// Label is the conclusion, e.g. "evil twin candidate" or "WPS enabled". Note the
	// deliberate hedge in the former: an outlier is a candidate, never a confirmed evil twin.
	Label string `json:"label"`
	// Rationale is the operator-facing explanation.
	Rationale string `json:"rationale,omitempty"`
	// Differences are the specific fingerprint attributes that diverged from the cluster, so
	// the report can cite facts rather than a score.
	Differences []string `json:"differences,omitempty"`
	// Score is the similarity value that produced an evidence-tier finding, if applicable.
	Score   *float64  `json:"score,omitempty"`
	FirstTS time.Time `json:"first_seen"`
	LastTS  time.Time `json:"last_seen"`
}

// UpsertFinding records or refreshes a conclusion.
//
// Keyed on (bssid, label), so re-running classification refreshes a finding rather than
// accumulating duplicates across a multi-day run.
func (s *Store) UpsertFinding(ctx context.Context, f Finding) error {
	diffs, err := json.Marshal(f.Differences)
	if err != nil {
		return fmt.Errorf("store: marshal finding differences: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var score any
	if f.Score != nil {
		score = *f.Score
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO findings (bssid, essid, tier, label, rationale, differences, score, first_ts, last_ts)
VALUES (?,?,?,?,?,?,?,?,?)
ON CONFLICT(bssid, label) DO UPDATE SET
    essid       = excluded.essid,
    tier        = excluded.tier,
    rationale   = excluded.rationale,
    differences = excluded.differences,
    score       = excluded.score,
    last_ts     = excluded.last_ts`,
		f.BSSID, f.ESSID, string(f.Tier), f.Label, f.Rationale, string(diffs), score,
		f.FirstTS.Format(timeFormat), f.LastTS.Format(timeFormat))
	if err != nil {
		return fmt.Errorf("store: upsert finding: %w", err)
	}
	return nil
}

// Findings returns recorded conclusions, optionally filtered by tier.
func (s *Store) Findings(ctx context.Context, tier Tier) ([]Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}

	q := `SELECT id, bssid, essid, tier, label, rationale, differences, score, first_ts, last_ts
          FROM findings`
	var args []any
	if tier != "" {
		q += ` WHERE tier = ?`
		args = append(args, string(tier))
	}
	// Determined findings first: they are the defensible ones and belong at the top of a
	// report. Controls (passes) come after the exposures, before anything else.
	q += ` ORDER BY CASE tier WHEN 'determined' THEN 0 WHEN 'evidence' THEN 1 ` +
		`WHEN 'control' THEN 2 ELSE 3 END, bssid`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query findings: %w", err)
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var (
			f           Finding
			tierStr     string
			diffs       string
			score       *float64
			first, last string
		)
		if err := rows.Scan(&f.ID, &f.BSSID, &f.ESSID, &tierStr, &f.Label,
			&f.Rationale, &diffs, &score, &first, &last); err != nil {
			return nil, err
		}
		f.Tier = Tier(tierStr)
		f.Score = score
		if diffs != "" {
			// A malformed differences blob must not drop the finding: the label and
			// rationale still stand on their own.
			_ = json.Unmarshal([]byte(diffs), &f.Differences)
		}
		if f.FirstTS, err = time.Parse(timeFormat, first); err != nil {
			return nil, fmt.Errorf("store: parse finding time: %w", err)
		}
		if f.LastTS, err = time.Parse(timeFormat, last); err != nil {
			return nil, fmt.Errorf("store: parse finding time: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// FindingsFor returns the conclusions recorded against one BSSID.
func (s *Store) FindingsFor(ctx context.Context, bssid string) ([]Finding, error) {
	all, err := s.Findings(ctx, "")
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, f := range all {
		if f.BSSID == bssid {
			out = append(out, f)
		}
	}
	return out, nil
}

// ClearFindings removes every conclusion, leaving all observations untouched.
//
// Used when classification is re-run from scratch. That this is safe - that no observed fact
// is lost by discarding every conclusion - is the point of keeping them in separate tables.
func (s *Store) ClearFindings(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.ExecContext(ctx, `DELETE FROM findings`); err != nil {
		return fmt.Errorf("store: clear findings: %w", err)
	}
	return nil
}

// ClearFindingsWithLabels removes only the findings carrying one of the given labels, leaving the
// rest. A re-classify uses this so it replaces the classifier's own conclusions without wiping
// findings recorded by the active attacks (a recovered WPS passphrase, say), which are results of
// work done rather than conclusions the classifier can re-derive.
func (s *Store) ClearFindingsWithLabels(ctx context.Context, labels []string) error {
	if len(labels) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	placeholders := make([]string, len(labels))
	args := make([]any, len(labels))
	for i, l := range labels {
		placeholders[i] = "?"
		args[i] = l
	}
	q := "DELETE FROM findings WHERE label IN (" + strings.Join(placeholders, ",") + ")"
	if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("store: clear classifier findings: %w", err)
	}
	return nil
}

// ClearFindingForBSSID removes the findings with the given labels recorded against one BSSID,
// leaving every other finding untouched. An active attack uses it to supersede a preliminary
// observation with its own result: once Pixie Dust has actually tested an AP, the "WPS enabled and
// unlocked" note the classifier derived from the beacon is stale and would otherwise sit alongside
// the definitive "resistant" or "recovered" finding for the same device.
func (s *Store) ClearFindingForBSSID(ctx context.Context, bssid string, labels ...string) error {
	if len(labels) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	placeholders := make([]string, len(labels))
	args := make([]any, 0, len(labels)+1)
	args = append(args, bssid)
	for i, l := range labels {
		placeholders[i] = "?"
		args = append(args, l)
	}
	q := "DELETE FROM findings WHERE bssid = ? AND label IN (" + strings.Join(placeholders, ",") + ")"
	if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("store: clear finding for bssid: %w", err)
	}
	return nil
}
