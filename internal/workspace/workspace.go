// Package workspace manages the engagement directory.
//
// One engagement is one directory. Everything WARP learns lives inside it, and the directory
// is the deliverable that gets archived when the engagement closes.
package workspace

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/scope"
)

// Layout of an engagement directory. These names are stable - reports and downstream tooling
// depend on them.
const (
	ScopeFile = "scope.txt"
	// SiteWideFile records an engagement scoped to every network at a site rather than to a
	// list. Its presence is what makes the scope site-wide; its contents are the operator's
	// written justification. See scope.SiteWide.
	SiteWideFile = "site-wide-scope.txt"
	DBFile       = "warp.db"
	EventsFile   = "events.jsonl"
	CertsDir     = "certs"
	CredsDir     = "creds"
	CapturesDir  = "captures"
	// WalkthroughsDir holds one raw archive per walkthrough, so a single pass can be replayed
	// apart from the engagement-wide capture.
	WalkthroughsDir = "walkthroughs"

	PMKIDFile     = "pmkid.22000"
	HandshakeFile = "handshakes.22000"
)

// dirPerm is 0700 throughout: an engagement directory holds captured credential material and
// a record of everything transmitted at a client site.
const (
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600
)

// Workspace is an open engagement directory.
type Workspace struct {
	Dir   string
	Scope *scope.Set
	Gate  *scope.Gate

	audit *audit.File
	disk  diskCache
}

// Path returns an absolute path inside the workspace.
func (w *Workspace) Path(parts ...string) string {
	return filepath.Join(append([]string{w.Dir}, parts...)...)
}

// Audit returns the engagement audit log.
func (w *Workspace) Audit() audit.Logger { return w.audit }

// Init creates a new engagement directory from a client-supplied scope file.
//
// The scope file is copied in rather than referenced, so the engagement record is
// self-contained and the client's original cannot drift out from under it mid-engagement.
//
// Init does not complete the generic-ESSID acknowledgment: it returns the workspace with
// pending acknowledgments so the caller can surface the risk to a human and record their
// acceptance. Check Gate.PendingAcknowledgments before treating the workspace as ready.
func Init(dir, scopePath string) (*Workspace, []scope.Warning, error) {
	return InitSiteWide(dir, scopePath, "")
}

// InitSiteWide creates an engagement whose scope is every network at the site.
//
// justification is the operator's written authority for it and is required; scopePath is then
// ignored. See scope.SiteWide for why this exists and why it is an engagement property rather
// than a runtime flag. Pass an empty justification for an ordinary ESSID-list engagement.
func InitSiteWide(dir, scopePath, justification string) (*Workspace, []scope.Warning, error) {
	if dir == "" {
		return nil, nil, errors.New("workspace: no directory given")
	}

	// Refuse to initialise over an existing engagement. Re-running `warp init` against a live
	// directory would reset state that is evidence.
	if _, err := os.Stat(filepath.Join(dir, EventsFile)); err == nil {
		return nil, nil, fmt.Errorf("workspace: %s is already an engagement directory (%s exists) - use `warp daemon` to resume it", dir, EventsFile)
	}

	var (
		set   *scope.Set
		warns []scope.Warning
		err   error
	)
	if justification != "" {
		set, err = scope.SiteWide(justification)
	} else {
		set, warns, err = scope.Load(scopePath)
	}
	if err != nil {
		return nil, warns, err
	}

	for _, sub := range []string{"", CertsDir, CredsDir, CapturesDir, WalkthroughsDir} {
		if err := os.MkdirAll(filepath.Join(dir, sub), dirPerm); err != nil {
			return nil, warns, fmt.Errorf("workspace: create %s: %w", filepath.Join(dir, sub), err)
		}
	}

	if justification != "" {
		if err := os.WriteFile(filepath.Join(dir, SiteWideFile),
			[]byte(justification+"\n"), filePerm); err != nil {
			return nil, warns, fmt.Errorf("workspace: record the site-wide authorization: %w", err)
		}
	} else {
		dst := filepath.Join(dir, ScopeFile)
		if filepath.Clean(scopePath) != filepath.Clean(dst) {
			if err := copyFile(scopePath, dst); err != nil {
				return nil, warns, err
			}
		}
	}

	w, err := open(dir, set)
	if err != nil {
		return nil, warns, err
	}

	if err := w.audit.Log(audit.Event{
		Kind:    audit.KindScopeLoad,
		Outcome: audit.OutcomeInfo,
		Module:  "init",
		Reason:  "engagement initialised",
		Detail: map[string]any{
			"scope_essids":            set.List(),
			"generic_essids":          set.GenericEntries(),
			"directory":               dir,
			"site_wide_scope":         set.IsSiteWide(),
			"site_wide_justification": set.SiteWideNote(),
		},
	}); err != nil {
		w.Close()
		return nil, warns, err
	}

	return w, warns, nil
}

// Open resumes an existing engagement directory.
//
// Operator state - generic-ESSID acknowledgments, confirmations, vetoes - is replayed from
// events.jsonl. The audit log is the only source of truth for that state, so there is no
// second file that could disagree with the evidence, and a NUC rebooting mid-engagement comes
// back with the acknowledgments made before it shipped.
func Open(dir string) (*Workspace, error) {
	var (
		set *scope.Set
		err error
	)

	// A site-wide engagement is identified by the file `warp init --all-networks` wrote. It is
	// read back rather than re-decided, so resuming cannot quietly narrow or widen what the
	// engagement was authorized to do.
	if note, rerr := os.ReadFile(filepath.Join(dir, SiteWideFile)); rerr == nil {
		set, err = scope.SiteWide(strings.TrimSpace(string(note)))
	} else {
		set, _, err = scope.Load(filepath.Join(dir, ScopeFile))
	}
	if err != nil {
		return nil, err
	}

	w, err := open(dir, set)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(filepath.Join(dir, EventsFile))
	if err != nil {
		if os.IsNotExist(err) {
			return w, nil
		}
		w.Close()
		return nil, fmt.Errorf("workspace: open audit log for replay: %w", err)
	}
	defer f.Close()

	if _, err := w.Gate.Replay(f); err != nil {
		// A truncated final record from a SIGKILL is expected and must not block resuming.
		// Everything before it has already been applied.
		return w, nil
	}
	return w, nil
}

func open(dir string, set *scope.Set) (*Workspace, error) {
	log, err := audit.Open(filepath.Join(dir, EventsFile))
	if err != nil {
		return nil, err
	}
	gate, err := scope.NewGate(set, log)
	if err != nil {
		log.Close()
		return nil, err
	}
	return &Workspace{Dir: dir, Scope: set, Gate: gate, audit: log}, nil
}

// WriteScope persists the current scope back to scope.txt.
//
// Called after the operator widens scope on site. The file is the engagement record of what
// was authorized, so it has to match what the gate is enforcing - a daemon restart reading a
// stale file would silently narrow scope back and refuse work that had been approved.
//
// Written whole and renamed into place: a truncated scope.txt from a power cut mid-write
// would be worse than either version.
func (w *Workspace) WriteScope() error {
	if w == nil || w.Scope == nil {
		return errors.New("workspace: no scope to write")
	}
	if w.Scope.IsSiteWide() {
		return nil // the list is not what authorizes anything here
	}

	var b strings.Builder
	for _, e := range w.Scope.List() {
		b.WriteString(e)
		b.WriteByte('\n')
	}

	tmp := w.Path(ScopeFile + ".tmp")
	if err := os.WriteFile(tmp, []byte(b.String()), filePerm); err != nil {
		return fmt.Errorf("workspace: write scope: %w", err)
	}
	if err := os.Rename(tmp, w.Path(ScopeFile)); err != nil {
		return fmt.Errorf("workspace: replace scope file: %w", err)
	}
	return nil
}

// Close flushes and closes the workspace.
func (w *Workspace) Close() error {
	if w == nil {
		return nil
	}
	return w.audit.Close()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("workspace: open %s: %w", src, err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, filePerm)
	if err != nil {
		return fmt.Errorf("workspace: create %s: %w", dst, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("workspace: copy scope file: %w", err)
	}
	return out.Sync()
}
