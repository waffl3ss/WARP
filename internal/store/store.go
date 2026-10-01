package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver: no CGO, so the binary stays static

	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/recon"
)

// timeFormat is RFC3339 with nanoseconds, stored as TEXT so the database stays readable with
// the sqlite3 CLI on site.
const timeFormat = time.RFC3339Nano

// ErrClosed is returned by any operation that runs after Close.
//
// The engine's flush loop and its Close can race at shutdown: the daemon's context is cancelled,
// the flush loop wakes to write one last time, and the database is closed underneath it a moment
// later. Returning this - rather than dereferencing a nil handle and panicking, which is what
// used to happen and which invariant 8 forbids - turns that race into a logged line instead of a
// crash. Every method takes s.mu, and Close both sets db to nil and holds the same lock, so the
// check after the lock is authoritative.
var ErrClosed = errors.New("store: closed")

// Store is the engagement database.
//
// A single connection guarded by a mutex: sqlite serialises writers anyway, and one owner per
// file is the rule that keeps a multi-day capture from corrupting itself. Reads go through
// the same lock, which is ample - this is a few thousand rows per hour, not a web service.
type Store struct {
	mu sync.Mutex
	db *sql.DB

	path string

	// inScope reports whether an ESSID is in the engagement scope. It is used only to project the
	// scope-filtered findings file; the store is otherwise scope-agnostic. Nil means "nothing is
	// in scope", so a caller that never sets it gets an in-scope file with only a header - the
	// safe direction, the same one Result.InScope defaults to.
	inScope func(essid string) bool
}

// SetScopeFilter installs the predicate used to project the scope-filtered findings file. The
// daemon sets it once at startup from the engagement scope. Safe to call with nil to clear it.
func (s *Store) SetScopeFilter(fn func(essid string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inScope = fn
}

// scopeFilter returns the installed predicate, or a reject-all predicate when none is set.
func (s *Store) scopeFilter() func(string) bool {
	s.mu.Lock()
	fn := s.inScope
	s.mu.Unlock()
	if fn == nil {
		return func(string) bool { return false }
	}
	return fn
}

// Open opens (creating if needed) the engagement database and applies the schema.
func Open(path string) (*Store, error) {
	// _txlock=immediate avoids SQLITE_BUSY under the writer/reader mix during a projection
	// rebuild.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// One connection: see the type comment.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	return &Store{db: db, path: path}, nil
}

// migrate brings an engagement database created by an older build up to date.
//
// `CREATE TABLE IF NOT EXISTS` does nothing to a table that already exists, so a column added
// later needs an explicit ALTER. An engagement directory is evidence and runs for days - it
// has to survive a mid-engagement binary update rather than requiring a fresh workspace.
func migrate(db *sql.DB) error {
	// Each entry is idempotent: an ALTER that has already been applied reports a duplicate
	// column, which is the expected outcome on every start after the first.
	alters := []struct{ table, column, ddl string }{
		{"hashes", "in_scope", "ALTER TABLE hashes ADD COLUMN in_scope INTEGER NOT NULL DEFAULT 1"},
		{"walkthroughs", "pcap_path", "ALTER TABLE walkthroughs ADD COLUMN pcap_path TEXT NOT NULL DEFAULT ''"},
	}

	for _, a := range alters {
		has, err := columnExists(db, a.table, a.column)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := db.Exec(a.ddl); err != nil {
			return fmt.Errorf("store: add %s.%s: %w", a.table, a.column, err)
		}
	}
	return nil
}

func columnExists(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query("SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return false, fmt.Errorf("store: inspect %s: %w", table, err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

// Close closes the database.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	if err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

// Path returns the database file path.
func (s *Store) Path() string { return s.path }

// ---------------------------------------------------------------------------
// Observed facts
// ---------------------------------------------------------------------------

// UpsertAP writes an observed access point.
//
// Counters are taken from the tracker's running totals rather than incremented here, so a
// replayed or re-sent record cannot inflate them.
func (s *Store) UpsertAP(ctx context.Context, ap recon.AP) error {
	fp, err := json.Marshal(ap.Fingerprint)
	if err != nil {
		return fmt.Errorf("store: marshal fingerprint: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}

	_, err = s.db.ExecContext(ctx, `
INSERT INTO aps (
    bssid, essid, hidden, essid_source, channel, freq, band,
    security_class, mfp, wps, wps_locked, ciphers, akms, transition_mode,
    fingerprint_hash, fingerprint, oui, local_mac,
    best_rssi, best_rssi_radio, last_rssi, first_seen, last_seen,
    beacons, probe_responses, data_frames, radios_seen
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(bssid) DO UPDATE SET
    essid           = CASE WHEN excluded.essid != '' THEN excluded.essid ELSE aps.essid END,
    hidden          = excluded.hidden,
    essid_source    = CASE WHEN excluded.essid_source != '' THEN excluded.essid_source ELSE aps.essid_source END,
    channel         = excluded.channel,
    freq            = excluded.freq,
    band            = excluded.band,
    security_class  = excluded.security_class,
    mfp             = excluded.mfp,
    wps             = excluded.wps,
    wps_locked      = excluded.wps_locked,
    ciphers         = excluded.ciphers,
    akms            = excluded.akms,
    transition_mode = excluded.transition_mode,
    fingerprint_hash= excluded.fingerprint_hash,
    fingerprint     = excluded.fingerprint,
    best_rssi       = excluded.best_rssi,
    best_rssi_radio = excluded.best_rssi_radio,
    last_rssi       = excluded.last_rssi,
    last_seen       = excluded.last_seen,
    beacons         = excluded.beacons,
    probe_responses = excluded.probe_responses,
    data_frames     = excluded.data_frames,
    radios_seen     = excluded.radios_seen`,
		ap.BSSID.String(), ap.ESSID, boolInt(ap.Hidden), ap.ESSIDSource,
		ap.Channel, ap.Freq, ap.Band,
		string(ap.Security.Class), ap.Security.MFP.String(),
		boolInt(ap.Security.WPS), boolInt(ap.Security.WPSLocked),
		strings.Join(ap.Security.Ciphers, ","), strings.Join(ap.Security.AKMs, ","),
		boolInt(ap.Security.Transition),
		ap.Fingerprint.Hash(), string(fp), ap.OUI, boolInt(ap.LocalMAC),
		nullRSSI(ap.BestRSSI, ap.HasRSSI), ap.BestRSSIRadio, nullRSSI(ap.LastRSSI, ap.HasRSSI),
		ap.FirstSeen.Format(timeFormat), ap.LastSeen.Format(timeFormat),
		ap.Beacons, ap.ProbeResps, ap.DataFrames, strings.Join(ap.RadiosSeen, ","),
	)
	if err != nil {
		return fmt.Errorf("store: upsert ap %s: %w", ap.BSSID, err)
	}
	return nil
}

// UpsertStation writes an observed client station.
func (s *Store) UpsertStation(ctx context.Context, st recon.Station) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}

	bssid := ""
	if !st.BSSID.IsZero() {
		bssid = st.BSSID.String()
	}

	_, err := s.db.ExecContext(ctx, `
INSERT INTO stations (mac, bssid, first_seen, last_seen, best_rssi, last_rssi,
                      randomised, oui, frames, probed_essids)
VALUES (?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(mac) DO UPDATE SET
    bssid         = CASE WHEN excluded.bssid != '' THEN excluded.bssid ELSE stations.bssid END,
    last_seen     = excluded.last_seen,
    best_rssi     = excluded.best_rssi,
    last_rssi     = excluded.last_rssi,
    frames        = excluded.frames,
    probed_essids = excluded.probed_essids`,
		st.MAC.String(), bssid,
		st.FirstSeen.Format(timeFormat), st.LastSeen.Format(timeFormat),
		nullRSSI(st.BestRSSI, st.HasRSSI), nullRSSI(st.LastRSSI, st.HasRSSI),
		boolInt(st.Randomised), st.OUI, st.Frames,
		strings.Join(st.ProbedESSIDs, ","),
	)
	if err != nil {
		return fmt.Errorf("store: upsert station %s: %w", st.MAC, err)
	}
	return nil
}

// AddObservations writes a batch of signal readings in one transaction.
//
// Observations are the highest-volume table by far, so they are batched. Everything that
// matters for evidence - hashes, audit records - is written synchronously elsewhere; losing
// the last few seconds of RSSI samples to a power cut costs a little survey resolution, not
// a finding.
func (s *Store) AddObservations(ctx context.Context, obs []recon.Observation) error {
	if len(obs) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin observation batch: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO observations (addr, is_ap, rssi, freq, channel, ts, radio_id, frame_type)
VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		return fmt.Errorf("store: prepare observation insert: %w", err)
	}
	defer stmt.Close()

	for _, o := range obs {
		if o.RadioID == "" {
			// Refuse rather than store an unattributable reading: an observation whose radio
			// is unknown cannot be safely compared with any other.
			return fmt.Errorf("store: observation for %s has no radio_id", o.Addr)
		}
		if _, err := stmt.ExecContext(ctx,
			o.Addr.String(), boolInt(o.IsAP), o.RSSI, o.Freq, o.Channel,
			o.Timestamp.Format(timeFormat), o.RadioID, o.FrameType,
		); err != nil {
			return fmt.Errorf("store: insert observation: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit observation batch: %w", err)
	}
	return nil
}

// AddHash records an emitted hash line.
//
// The flat 22000 files are the deliverable; this row exists so counts can be reported and so
// a cracked result can be mapped back to a BSSID and ESSID for the report.
func (s *Store) AddHash(ctx context.Context, r handshake.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return ErrClosed
	}

	_, err := s.db.ExecContext(ctx, `
INSERT INTO hashes (kind, line, essid, ap, sta, channel, radio_id, detail, ts, in_scope)
VALUES (?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(line) DO NOTHING`,
		string(r.Kind), r.Line, r.ESSID, r.APString(), r.STAString(),
		r.Channel, r.RadioID, r.Detail, r.At.Format(timeFormat), r.InScope)
	if err != nil {
		return fmt.Errorf("store: record hash: %w", err)
	}
	return nil
}

// HashCounts returns how many hashes of each kind have been recorded.
// HashRecord is one captured hash as reported to a frontend.
//
// The Line itself is deliberately included. The whole point of the tool is the hash, and an
// operator who wants one out of the box before it is unracked should be able to see and copy
// it without going to the filesystem as root.
type HashRecord struct {
	Kind    string    `json:"kind"`
	Line    string    `json:"line"`
	ESSID   string    `json:"essid"`
	BSSID   string    `json:"bssid"`
	Station string    `json:"station,omitempty"`
	Channel int       `json:"channel,omitempty"`
	RadioID string    `json:"radio_id,omitempty"`
	Detail  string    `json:"detail,omitempty"`
	At      time.Time `json:"at"`
	// InScope reports whether the network was in scope when this was captured. Out-of-scope
	// material is incidental: WARP heard it, recorded it, and kept it out of the deliverable.
	InScope bool `json:"in_scope"`
}

// Hashes returns every captured hash, newest first.
func (s *Store) Hashes(ctx context.Context) ([]HashRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT kind, line, essid, ap, sta, channel, radio_id, detail, ts, in_scope
FROM hashes ORDER BY ts DESC`)
	if err != nil {
		return nil, fmt.Errorf("store: list hashes: %w", err)
	}
	defer rows.Close()

	var out []HashRecord
	for rows.Next() {
		var (
			r  HashRecord
			ts string
		)
		if err := rows.Scan(&r.Kind, &r.Line, &r.ESSID, &r.BSSID, &r.Station,
			&r.Channel, &r.RadioID, &r.Detail, &ts, &r.InScope); err != nil {
			return nil, fmt.Errorf("store: scan hash: %w", err)
		}
		r.At, _ = time.Parse(timeFormat, ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) HashCounts(ctx context.Context) (pmkid, eapol int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return 0, 0, ErrClosed
	}

	// Only in-scope material counts towards the engagement's totals. An incidental capture
	// from a neighbour is not a result, and inflating the count with it would misrepresent
	// what the engagement produced.
	rows, err := s.db.QueryContext(ctx,
		`SELECT kind, COUNT(*) FROM hashes WHERE in_scope = 1 GROUP BY kind`)
	if err != nil {
		return 0, 0, fmt.Errorf("store: count hashes: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var kind string
		var n int
		if err := rows.Scan(&kind, &n); err != nil {
			return 0, 0, err
		}
		switch handshake.Kind(kind) {
		case handshake.KindPMKID:
			pmkid = n
		case handshake.KindHandshake:
			eapol = n
		}
	}
	return pmkid, eapol, rows.Err()
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// APRow is one row of the aps table.
type APRow struct {
	BSSID           string `json:"bssid"`
	ESSID           string `json:"essid"`
	Hidden          bool   `json:"hidden"`
	Channel         int    `json:"channel"`
	Band            string `json:"band"`
	SecurityClass   string `json:"security_class"`
	MFP             string `json:"mfp"`
	WPS             bool   `json:"wps"`
	Ciphers         string `json:"ciphers,omitempty"`
	AKMs            string `json:"akms,omitempty"`
	Transition      bool   `json:"transition_mode,omitempty"`
	FingerprintHash string `json:"fingerprint_hash"`
	OUI             string `json:"oui"`
	BestRSSI        *int   `json:"best_rssi"`
	BestRSSIRadio   string `json:"best_rssi_radio,omitempty"`
	FirstSeen       string `json:"first_seen"`
	LastSeen        string `json:"last_seen"`
	Beacons         int64  `json:"beacons"`
}

// APs returns observed access points, optionally filtered by ESSID.
func (s *Store) APs(ctx context.Context, essid string) ([]APRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}

	q := `SELECT bssid, essid, hidden, channel, band, security_class, mfp, wps,
                 ciphers, akms, transition_mode, fingerprint_hash, oui,
                 best_rssi, best_rssi_radio, first_seen, last_seen, beacons
          FROM aps`
	var args []any
	if essid != "" {
		q += ` WHERE essid = ?`
		args = append(args, essid)
	}
	q += ` ORDER BY essid, bssid`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query aps: %w", err)
	}
	defer rows.Close()

	var out []APRow
	for rows.Next() {
		var r APRow
		var hidden, wps, transition int
		var bestRSSI sql.NullInt64
		if err := rows.Scan(&r.BSSID, &r.ESSID, &hidden, &r.Channel, &r.Band,
			&r.SecurityClass, &r.MFP, &wps, &r.Ciphers, &r.AKMs, &transition,
			&r.FingerprintHash, &r.OUI, &bestRSSI, &r.BestRSSIRadio,
			&r.FirstSeen, &r.LastSeen, &r.Beacons); err != nil {
			return nil, err
		}
		r.Hidden, r.WPS, r.Transition = hidden != 0, wps != 0, transition != 0
		if bestRSSI.Valid {
			v := int(bestRSSI.Int64)
			r.BestRSSI = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// StationRow is one row of the stations table.
type StationRow struct {
	MAC          string `json:"mac"`
	BSSID        string `json:"bssid,omitempty"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	BestRSSI     *int   `json:"best_rssi"`
	Randomised   bool   `json:"randomised_mac"`
	OUI          string `json:"oui"`
	Frames       int64  `json:"frames"`
	ProbedESSIDs string `json:"probed_essids,omitempty"`
}

// Stations returns observed client stations.
func (s *Store) Stations(ctx context.Context) ([]StationRow, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT mac, bssid, first_seen, last_seen, best_rssi, randomised, oui, frames, probed_essids
FROM stations ORDER BY mac`)
	if err != nil {
		return nil, fmt.Errorf("store: query stations: %w", err)
	}
	defer rows.Close()

	var out []StationRow
	for rows.Next() {
		var r StationRow
		var randomised int
		var bestRSSI sql.NullInt64
		if err := rows.Scan(&r.MAC, &r.BSSID, &r.FirstSeen, &r.LastSeen,
			&bestRSSI, &randomised, &r.OUI, &r.Frames, &r.ProbedESSIDs); err != nil {
			return nil, err
		}
		r.Randomised = randomised != 0
		if bestRSSI.Valid {
			v := int(bestRSSI.Int64)
			r.BestRSSI = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Counts returns row counts for the status header.
type Counts struct {
	APs          int `json:"aps"`
	Stations     int `json:"stations"`
	Observations int `json:"observations"`
	Hashes       int `json:"hashes"`
	Findings     int `json:"findings"`
	Walkthroughs int `json:"walkthroughs"`
}

// Counts returns how much has been recorded.
func (s *Store) Counts(ctx context.Context) (Counts, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return Counts{}, ErrClosed
	}

	var c Counts
	for _, q := range []struct {
		table string
		dst   *int
	}{
		{"aps", &c.APs},
		{"stations", &c.Stations},
		{"observations", &c.Observations},
		{"hashes", &c.Hashes},
		{"findings", &c.Findings},
		{"walkthroughs", &c.Walkthroughs},
	} {
		if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+q.table).Scan(q.dst); err != nil {
			return c, fmt.Errorf("store: count %s: %w", q.table, err)
		}
	}
	return c, nil
}

// ESSIDsInScopeSeen returns the distinct non-empty ESSIDs observed.
func (s *Store) ESSIDsSeen(ctx context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil, ErrClosed
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT essid FROM aps WHERE essid != '' ORDER BY essid`)
	if err != nil {
		return nil, fmt.Errorf("store: query essids: %w", err)
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// nullRSSI stores NULL rather than 0 when no signal was measured. Zero would read as the
// strongest possible signal and corrupt every ranking that touches it.
func nullRSSI(v int8, has bool) any {
	if !has {
		return nil
	}
	return int(v)
}
