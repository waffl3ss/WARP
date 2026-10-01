// Package audit implements the append-only engagement audit log (events.jsonl).
//
// This log is engagement evidence, not debug output. It must be complete enough to
// reconstruct exactly what WARP transmitted and when, and it is kept strictly separate
// from the structured operational log (log/slog).
//
// Durability: every record is written and fsync'd synchronously before Log returns.
// The brief's rule is "one goroutine owns each file"; the concern there is concurrent
// appends corrupting a file days into an engagement. A mutex-guarded single writer
// satisfies that, and doing it synchronously rather than through a buffered channel is
// strictly stronger for evidence - a SIGKILL cannot lose a decision that was already
// reported to the caller as logged. Authorization decisions are low-rate, so the fsync
// cost is irrelevant here. High-volume writers (observations, captures) must not use
// this package.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Outcome is the result of an authorization decision.
type Outcome string

const (
	// OutcomeAllow means the request was authorized and the module may transmit.
	OutcomeAllow Outcome = "allow"
	// OutcomeDeny means the request was refused and no frame was transmitted.
	OutcomeDeny Outcome = "deny"
	// OutcomeAck records a human accepting a documented residual risk.
	OutcomeAck Outcome = "ack"
	// OutcomeInfo records a material engagement event that is not itself a decision.
	OutcomeInfo Outcome = "info"
)

// Event kinds. These are stable identifiers - reports and downstream tooling key off them,
// so treat a rename as a breaking change.
const (
	KindAuthorize    = "authorize"     // a transmit authorization decision
	KindGenericESSID = "generic_essid" // operator acknowledged a generic/ambiguous ESSID
	KindScopeLoad    = "scope_load"    // scope.txt was loaded
	KindConfirm      = "scope_confirm" // optional operator sanity check at a BSSID
	KindReject       = "scope_reject"  // operator veto narrowing scope
	KindTransmit     = "transmit"      // frames actually put in the air
	KindRadio        = "radio"         // radio acquisition/release
	KindLifecycle    = "lifecycle"     // daemon start/stop
	// KindHarvest records a certificate read off the air. Its own kind rather than a transmit
	// record: what matters in evidence is that a certificate belonging to the client was
	// copied, when, and from which access point - the frames that carried it are already
	// logged separately.
	KindHarvest = "harvest"
	// KindAnnotate records an operator's judgement about a device that WARP did not derive itself -
	// marking or unmarking a BSSID as a potential rogue. It is not a transmission and not a scope
	// decision; it is context the operator added, kept in the evidence log alongside everything else.
	KindAnnotate = "annotate"
)

// Event is one line of events.jsonl.
//
// Field order in the struct is the field order in the emitted JSON, which keeps the log
// readable with plain `tail`. Empty optional fields are omitted so a grep for a BSSID does
// not match a run of empty strings.
type Event struct {
	TS      time.Time      `json:"ts"`
	Kind    string         `json:"kind"`
	Outcome Outcome        `json:"outcome"`
	Module  string         `json:"module"`
	BSSID   string         `json:"bssid,omitempty"`
	ESSID   string         `json:"essid,omitempty"`
	Channel int            `json:"channel,omitempty"`
	RadioID string         `json:"radio_id,omitempty"`
	Reason  string         `json:"reason,omitempty"`
	Detail  map[string]any `json:"detail,omitempty"`
}

// Logger records engagement events. It is satisfied by *File and by test doubles.
type Logger interface {
	Log(Event) error
}

// File is a Logger backed by an append-only JSONL file.
type File struct {
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
	now  func() time.Time // injectable for tests
	sync bool
}

// Open opens (creating if needed) the audit log at path for appending.
//
// The file is opened 0600: it records exactly what was transmitted at a client site and is
// not world-readable.
func Open(path string) (*File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	return newFile(f, true), nil
}

// NewWriter returns a Logger writing to w. Used for tests and for composing sinks; it does
// not fsync, so it is not suitable for the on-disk engagement log.
func NewWriter(w io.Writer) *File {
	return &File{enc: json.NewEncoder(w), now: time.Now}
}

func newFile(f *os.File, doSync bool) *File {
	return &File{f: f, enc: json.NewEncoder(f), now: time.Now, sync: doSync}
}

// Log appends e. TS is stamped here if the caller left it zero, so callers cannot
// accidentally emit an unstamped record.
func (l *File) Log(e Event) error {
	if l == nil {
		return nil
	}
	if e.TS.IsZero() {
		e.TS = l.now().UTC()
	} else {
		e.TS = e.TS.UTC()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.enc == nil {
		return fmt.Errorf("audit log is closed")
	}
	if err := l.enc.Encode(e); err != nil {
		return fmt.Errorf("write audit event: %w", err)
	}
	if l.sync && l.f != nil {
		if err := l.f.Sync(); err != nil {
			return fmt.Errorf("sync audit log: %w", err)
		}
	}
	return nil
}

// Close flushes and closes the underlying file.
func (l *File) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	l.enc = nil
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	if err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}
	return nil
}

// Discard is a Logger that drops events. It exists so tests and dry-run paths can construct
// a gate without a file; it must never be wired into a running engagement.
type Discard struct{}

// Log implements Logger.
func (Discard) Log(Event) error { return nil }
