package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Walkthrough is an operator-declared location label covering a span of time.
//
// The label is free text and deliberately unstructured. No site/building/floor/zone schema:
// that structure is wrong or unknown often enough on a real engagement that it becomes
// friction, and an operator who cannot express where they are will stop labelling at all.
type Walkthrough struct {
	ID       int64      `json:"id"`
	Name     string     `json:"name"`
	StartTS  time.Time  `json:"start_ts"`
	EndTS    *time.Time `json:"end_ts,omitempty"`
	Notes    string     `json:"notes,omitempty"`
	Implicit bool       `json:"implicit,omitempty"`
	// PcapPath is the per-walkthrough raw archive, if one was written.
	PcapPath string `json:"pcap_path,omitempty"`

	// Observations, APs and Clients are populated by List, counted by time range rather than
	// stored - which is what keeps rename and split pure post-processing. APs and Clients are the
	// distinct access points and client stations heard while the walkthrough was open.
	Observations int `json:"observations"`
	APs          int `json:"aps"`
	Clients      int `json:"clients"`
}

// Duration returns how long the walkthrough ran, using now for one still open.
func (w Walkthrough) Duration(now time.Time) time.Duration {
	end := now
	if w.EndTS != nil {
		end = *w.EndTS
	}
	return end.Sub(w.StartTS)
}

// Open reports whether the walkthrough is still running.
func (w Walkthrough) Open() bool { return w.EndTS == nil }

// ErrNoWalkthrough is returned when a walkthrough ID does not exist.
var ErrNoWalkthrough = errors.New("store: no such walkthrough")

// StartWalkthrough closes any open walkthrough and opens a new one.
//
// Starting a new walkthrough ends the previous one - an operator moving to the next floor
// should not have to remember to close the last one.
func (s *Store) StartWalkthrough(ctx context.Context, name string, at time.Time, implicit bool) (*Walkthrough, error) {
	if name == "" {
		return nil, errors.New("store: walkthrough needs a name")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin walkthrough: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx,
		`UPDATE walkthroughs SET end_ts = ? WHERE end_ts IS NULL`,
		at.Format(timeFormat)); err != nil {
		return nil, fmt.Errorf("store: close open walkthroughs: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO walkthroughs (name, start_ts, implicit) VALUES (?,?,?)`,
		name, at.Format(timeFormat), boolInt(implicit))
	if err != nil {
		return nil, fmt.Errorf("store: insert walkthrough: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit walkthrough: %w", err)
	}

	return &Walkthrough{ID: id, Name: name, StartTS: at, Implicit: implicit}, nil
}

// EndWalkthrough closes the currently open walkthrough, if any.
func (s *Store) EndWalkthrough(ctx context.Context, at time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx,
		`UPDATE walkthroughs SET end_ts = ? WHERE end_ts IS NULL`, at.Format(timeFormat))
	if err != nil {
		return 0, fmt.Errorf("store: end walkthrough: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// CurrentWalkthrough returns the open walkthrough, or nil if none is open.
func (s *Store) CurrentWalkthrough(ctx context.Context) (*Walkthrough, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, start_ts, end_ts, notes, implicit, pcap_path
         FROM walkthroughs WHERE end_ts IS NULL ORDER BY start_ts DESC LIMIT 1`)

	w, err := scanWalkthrough(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return w, err
}

// ListWalkthroughs returns every walkthrough with its observation count.
//
// The count is derived by time range at query time rather than maintained as a column, which
// is what makes rename and split pure post-processing.
func (s *Store) ListWalkthroughs(ctx context.Context) ([]Walkthrough, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT w.id, w.name, w.start_ts, w.end_ts, w.notes, w.implicit, w.pcap_path,
       (SELECT COUNT(*) FROM observations o
        WHERE o.ts >= w.start_ts AND (w.end_ts IS NULL OR o.ts < w.end_ts)),
       (SELECT COUNT(DISTINCT o.addr) FROM observations o
        WHERE o.is_ap = 1 AND o.ts >= w.start_ts AND (w.end_ts IS NULL OR o.ts < w.end_ts)),
       (SELECT COUNT(DISTINCT o.addr) FROM observations o
        WHERE o.is_ap = 0 AND o.ts >= w.start_ts AND (w.end_ts IS NULL OR o.ts < w.end_ts))
FROM walkthroughs w
ORDER BY w.start_ts`)
	if err != nil {
		return nil, fmt.Errorf("store: list walkthroughs: %w", err)
	}
	defer rows.Close()

	var out []Walkthrough
	for rows.Next() {
		var (
			w        Walkthrough
			start    string
			end      sql.NullString
			implicit int
		)
		if err := rows.Scan(&w.ID, &w.Name, &start, &end, &w.Notes, &implicit, &w.PcapPath,
			&w.Observations, &w.APs, &w.Clients); err != nil {
			return nil, err
		}
		if w.StartTS, err = time.Parse(timeFormat, start); err != nil {
			return nil, fmt.Errorf("store: parse walkthrough start: %w", err)
		}
		if end.Valid {
			t, err := time.Parse(timeFormat, end.String)
			if err != nil {
				return nil, fmt.Errorf("store: parse walkthrough end: %w", err)
			}
			w.EndTS = &t
		}
		w.Implicit = implicit != 0
		out = append(out, w)
	}
	return out, rows.Err()
}

// RenameWalkthrough changes a walkthrough's label.
//
// This touches no observation data, because observations are associated by time range rather
// than by a copied label. The operator naming one sloppily on site is expected, and fixing it
// afterwards must be free.
func (s *Store) RenameWalkthrough(ctx context.Context, id int64, name string) error {
	if name == "" {
		return errors.New("store: walkthrough needs a name")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx, `UPDATE walkthroughs SET name = ? WHERE id = ?`, name, id)
	if err != nil {
		return fmt.Errorf("store: rename walkthrough: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %d", ErrNoWalkthrough, id)
	}
	return nil
}

// WalkthroughDevice is one device heard while a walkthrough was open, for the summary file and
// the overview's per-walkthrough table. APs carry their ESSID; clients carry the network they were
// associated with, if any.
type WalkthroughDevice struct {
	BSSID    string `json:"bssid"`
	ESSID    string `json:"essid,omitempty"`
	IsAP     bool   `json:"is_ap"`
	Channel  int    `json:"channel,omitempty"`
	Security string `json:"security,omitempty"`
}

// WalkthroughDevices returns the distinct devices observed during a walkthrough's time window:
// access points (with ESSID) first, then client stations (with the network they were on). This is
// derived by time range like the counts, so it stays correct after a rename or split.
func (s *Store) WalkthroughDevices(ctx context.Context, id int64) ([]WalkthroughDevice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}

	var (
		start string
		end   sql.NullString
	)
	if err := s.db.QueryRowContext(ctx,
		`SELECT start_ts, end_ts FROM walkthroughs WHERE id = ?`, id).Scan(&start, &end); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %d", ErrNoWalkthrough, id)
		}
		return nil, fmt.Errorf("store: look up walkthrough: %w", err)
	}
	endVal := ""
	if end.Valid {
		endVal = end.String
	}

	// Access points heard in the window, with whatever the aps table knows about them. Named
	// networks sort first (alphabetically), then hidden/unknown by address.
	rows, err := s.db.QueryContext(ctx, `
SELECT o.addr, COALESCE(a.essid,''), COALESCE(a.channel,0), COALESCE(a.security_class,'')
FROM (SELECT DISTINCT addr FROM observations
      WHERE is_ap = 1 AND ts >= ? AND (? = '' OR ts < ?)) o
LEFT JOIN aps a ON a.bssid = o.addr
ORDER BY COALESCE(a.essid,'') = '', COALESCE(a.essid,''), o.addr`,
		start, endVal, endVal)
	if err != nil {
		return nil, fmt.Errorf("store: walkthrough APs: %w", err)
	}
	defer rows.Close()

	var out []WalkthroughDevice
	for rows.Next() {
		d := WalkthroughDevice{IsAP: true}
		if err := rows.Scan(&d.BSSID, &d.ESSID, &d.Channel, &d.Security); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Client stations heard in the window, with the network they were associated with.
	crows, err := s.db.QueryContext(ctx, `
SELECT o.addr, COALESCE(a.essid,'')
FROM (SELECT DISTINCT addr FROM observations
      WHERE is_ap = 0 AND ts >= ? AND (? = '' OR ts < ?)) o
LEFT JOIN stations st ON st.mac = o.addr
LEFT JOIN aps a ON a.bssid = st.bssid
ORDER BY o.addr`,
		start, endVal, endVal)
	if err != nil {
		return nil, fmt.Errorf("store: walkthrough clients: %w", err)
	}
	defer crows.Close()

	for crows.Next() {
		var mac, essid string
		if err := crows.Scan(&mac, &essid); err != nil {
			return nil, err
		}
		out = append(out, WalkthroughDevice{BSSID: mac, ESSID: essid, IsAP: false})
	}
	return out, crows.Err()
}

// SetWalkthroughPcap records the per-walkthrough raw archive path for a walkthrough.
func (s *Store) SetWalkthroughPcap(ctx context.Context, id int64, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.ExecContext(ctx, `UPDATE walkthroughs SET pcap_path = ? WHERE id = ?`, path, id)
	if err != nil {
		return fmt.Errorf("store: set walkthrough pcap: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %d", ErrNoWalkthrough, id)
	}
	return nil
}

// DeleteWalkthrough removes a walkthrough record and returns its pcap path so the caller can
// delete the archive file. Observations are untouched - they are associated by time range, not
// owned by the walkthrough, and belong to the engagement regardless of how the operator labelled
// the pass. Deleting a walkthrough discards only the label and its dedicated capture.
func (s *Store) DeleteWalkthrough(ctx context.Context, id int64) (pcapPath string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.db.QueryRowContext(ctx,
		`SELECT pcap_path FROM walkthroughs WHERE id = ?`, id).Scan(&pcapPath); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%w: %d", ErrNoWalkthrough, id)
		}
		return "", fmt.Errorf("store: look up walkthrough: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM walkthroughs WHERE id = ?`, id); err != nil {
		return "", fmt.Errorf("store: delete walkthrough: %w", err)
	}
	return pcapPath, nil
}

// SplitWalkthrough divides a walkthrough at a timestamp, producing two records.
//
// Also pure post-processing: the original's end moves to at, and a new record covers the
// remainder. No observation row changes.
func (s *Store) SplitWalkthrough(ctx context.Context, id int64, at time.Time, newName string) (*Walkthrough, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin split: %w", err)
	}
	defer tx.Rollback()

	var (
		name  string
		start string
		end   sql.NullString
	)
	err = tx.QueryRowContext(ctx,
		`SELECT name, start_ts, end_ts FROM walkthroughs WHERE id = ?`, id).
		Scan(&name, &start, &end)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %d", ErrNoWalkthrough, id)
	}
	if err != nil {
		return nil, fmt.Errorf("store: read walkthrough: %w", err)
	}

	startTS, err := time.Parse(timeFormat, start)
	if err != nil {
		return nil, fmt.Errorf("store: parse walkthrough start: %w", err)
	}
	if !at.After(startTS) {
		return nil, fmt.Errorf("store: split point %s is not after the walkthrough start %s",
			at.Format(time.RFC3339), startTS.Format(time.RFC3339))
	}
	if end.Valid {
		endTS, err := time.Parse(timeFormat, end.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse walkthrough end: %w", err)
		}
		if !at.Before(endTS) {
			return nil, fmt.Errorf("store: split point %s is not before the walkthrough end %s",
				at.Format(time.RFC3339), endTS.Format(time.RFC3339))
		}
	}

	if newName == "" {
		newName = name + " (2)"
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE walkthroughs SET end_ts = ? WHERE id = ?`, at.Format(timeFormat), id); err != nil {
		return nil, fmt.Errorf("store: close first half: %w", err)
	}

	var endArg any
	if end.Valid {
		endArg = end.String
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO walkthroughs (name, start_ts, end_ts) VALUES (?,?,?)`,
		newName, at.Format(timeFormat), endArg)
	if err != nil {
		return nil, fmt.Errorf("store: insert second half: %w", err)
	}
	newID, _ := res.LastInsertId()

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit split: %w", err)
	}

	w := &Walkthrough{ID: newID, Name: newName, StartTS: at}
	if end.Valid {
		t, _ := time.Parse(timeFormat, end.String)
		w.EndTS = &t
	}
	return w, nil
}

func scanWalkthrough(row *sql.Row) (*Walkthrough, error) {
	var (
		w        Walkthrough
		start    string
		end      sql.NullString
		implicit int
	)
	if err := row.Scan(&w.ID, &w.Name, &start, &end, &w.Notes, &implicit, &w.PcapPath); err != nil {
		return nil, err
	}
	var err error
	if w.StartTS, err = time.Parse(timeFormat, start); err != nil {
		return nil, fmt.Errorf("store: parse walkthrough start: %w", err)
	}
	if end.Valid {
		t, err := time.Parse(timeFormat, end.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse walkthrough end: %w", err)
		}
		w.EndTS = &t
	}
	w.Implicit = implicit != 0
	return &w, nil
}

// LocationRank is one walkthrough's signal evidence for a device.
type LocationRank struct {
	WalkthroughID   int64     `json:"walkthrough_id"`
	WalkthroughName string    `json:"walkthrough"`
	MaxRSSI         int       `json:"max_rssi"`
	Observations    int       `json:"observations"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
}

// Localize returns the walkthroughs where a device was seen, ranked by strongest signal.
//
// This is deliberately "strongest walkthrough, ranked" and not trilateration. Indoor RSSI
// trilateration is fiction: it produces a coordinate that looks authoritative, cannot be
// defended in a report, and is wrong. A ranked list of the places a device was heard loudest
// is what actually sends someone to the right ceiling tile.
//
// radioID must be the pinned survey radio. RSSI is not comparable across chipsets or
// antennas, so mixing radios produces a ranking that looks correct and means nothing; the
// filter is mandatory rather than optional for exactly that reason.
func (s *Store) Localize(ctx context.Context, addr, radioID string) ([]LocationRank, error) {
	if radioID == "" {
		return nil, errors.New("store: localisation requires a radio_id - RSSI is not comparable across radios")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, `
SELECT w.id, w.name, MAX(o.rssi), COUNT(*), MIN(o.ts), MAX(o.ts)
FROM walkthroughs w
JOIN observations o
  ON o.ts >= w.start_ts AND (w.end_ts IS NULL OR o.ts < w.end_ts)
WHERE o.addr = ? AND o.radio_id = ?
GROUP BY w.id, w.name
ORDER BY MAX(o.rssi) DESC`, addr, radioID)
	if err != nil {
		return nil, fmt.Errorf("store: localize %s: %w", addr, err)
	}
	defer rows.Close()

	var out []LocationRank
	for rows.Next() {
		var (
			r           LocationRank
			first, last string
		)
		if err := rows.Scan(&r.WalkthroughID, &r.WalkthroughName, &r.MaxRSSI,
			&r.Observations, &first, &last); err != nil {
			return nil, err
		}
		if r.FirstSeen, err = time.Parse(timeFormat, first); err != nil {
			return nil, fmt.Errorf("store: parse observation time: %w", err)
		}
		if r.LastSeen, err = time.Parse(timeFormat, last); err != nil {
			return nil, fmt.Errorf("store: parse observation time: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
