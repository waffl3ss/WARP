package handshake

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Writer appends hash lines to the engagement's 22000 files.
//
// These files leave the engagement box for a separate cracking rig, which sets the
// requirements:
//
//   - Append the instant a tuple completes. The box may be powered off at any moment, and a
//     buffered hash is a lost hash that cannot be recaptured.
//   - Deduplicate on the *full hash line*. A multi-day run re-observes the same AP constantly;
//     deduplicating on BSSID instead would drop genuinely different handshakes, and not
//     deduplicating at all inflates the rig's workload with identical work.
//   - Keep PMKIDs and handshakes in separate files so the operator can prioritise PMKIDs,
//     which crack with no client involvement.
//   - Keep out-of-scope captures in files of their own. Capture is passive, so WARP hears
//     handshakes from networks the engagement has no authority over, and it records them -
//     a frame already received cannot be un-received, and quietly discarding evidence is
//     worse than holding it. But cracking one is unauthorized work, and a 22000 file has no
//     comment syntax to mark a line with, so the file *is* the label. The deliverable stays
//     exactly what the SoW covers, and submitting the wrong thing takes a deliberate act
//     rather than a wildcard.
//   - Every line is self-contained: ESSID and both MACs are in the line itself, so nothing
//     needed to crack it lives only in warp.db.
type Writer struct {
	mu sync.Mutex

	pmkid     *hashFile
	handshake *hashFile
	// Out-of-scope captures, kept apart from the deliverable.
	pmkidOut     *hashFile
	handshakeOut *hashFile
}

type hashFile struct {
	path string
	f    *os.File
	// seen holds the hash lines already written, for deduplication. Bounded in practice by
	// the number of distinct handshakes at a site, which is small.
	seen map[string]struct{}
}

// NewWriter opens (or creates) the hash files in dir.
//
// Existing files are read first so that deduplication survives a daemon restart: a NUC that
// reboots mid-engagement must not append a second copy of every hash it already has.
func NewWriter(dir, pmkidName, handshakeName string) (*Writer, error) {
	w := &Writer{}

	// The out-of-scope files are named from the in-scope ones so the pairing is obvious in a
	// directory listing, and so a shell glob for the deliverable cannot pick them up.
	for _, spec := range []struct {
		name string
		dst  **hashFile
	}{
		{pmkidName, &w.pmkid},
		{handshakeName, &w.handshake},
		{outOfScopeName(pmkidName), &w.pmkidOut},
		{outOfScopeName(handshakeName), &w.handshakeOut},
	} {
		hf, err := openHashFile(filepath.Join(dir, spec.name))
		if err != nil {
			w.Close()
			return nil, err
		}
		*spec.dst = hf
	}
	return w, nil
}

// outOfScopeName derives the out-of-scope filename from the deliverable's.
//
// The prefix rather than a suffix is deliberate: `*.22000` is what an operator types when
// collecting files for the rig, and a suffixed name would still match it.
func outOfScopeName(name string) string {
	return "out-of-scope-" + name
}

func openHashFile(path string) (*hashFile, error) {
	hf := &hashFile{path: path, seen: make(map[string]struct{})}

	// Load what is already there before opening for append.
	if existing, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(existing)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if line := sc.Text(); line != "" {
				hf.seen[line] = struct{}{}
			}
		}
		existing.Close()
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("handshake: read existing hashes from %s: %w", path, err)
	}

	// 0600: these are credential material.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("handshake: open %s: %w", path, err)
	}
	hf.f = f
	return hf, nil
}

// Write appends a result if its hash line has not been seen before.
//
// It reports whether the line was new. A false return is the normal case on a long run and is
// not an error.
func (w *Writer) Write(r Result) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var hf *hashFile
	switch {
	case r.Kind == KindPMKID && r.InScope:
		hf = w.pmkid
	case r.Kind == KindPMKID:
		hf = w.pmkidOut
	case r.Kind == KindHandshake && r.InScope:
		hf = w.handshake
	case r.Kind == KindHandshake:
		hf = w.handshakeOut
	default:
		return false, fmt.Errorf("handshake: unknown hash kind %q", r.Kind)
	}

	if _, dup := hf.seen[r.Line]; dup {
		return false, nil
	}

	if _, err := hf.f.WriteString(r.Line + "\n"); err != nil {
		return false, fmt.Errorf("handshake: append to %s: %w", hf.path, err)
	}
	// fsync per hash. These are low-rate and irreplaceable: the cost is irrelevant next to
	// losing one to a power cut.
	if err := hf.f.Sync(); err != nil {
		return false, fmt.Errorf("handshake: sync %s: %w", hf.path, err)
	}

	hf.seen[r.Line] = struct{}{}
	return true, nil
}

// Counts returns how many unique in-scope hashes of each kind have been written.
func (w *Writer) Counts() (pmkid, handshake int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.pmkid.seen), len(w.handshake.seen)
}

// OutOfScopeCounts returns the same for material captured from networks the engagement has no
// authority over.
func (w *Writer) OutOfScopeCounts() (pmkid, handshake int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.pmkidOut.seen), len(w.handshakeOut.seen)
}

// Paths returns the two deliverable hash file paths, for the handoff manifest.
func (w *Writer) Paths() (pmkid, handshake string) {
	return w.pmkid.path, w.handshake.path
}

// OutOfScopePaths returns the files holding incidental captures.
func (w *Writer) OutOfScopePaths() (pmkid, handshake string) {
	return w.pmkidOut.path, w.handshakeOut.path
}

// Close flushes and closes both files.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Every file is closed regardless of an earlier failure; the first error is reported.
	// Close also runs on a partially constructed Writer when NewWriter fails part-way.
	var firstErr error
	for _, hf := range []*hashFile{w.pmkid, w.handshake, w.pmkidOut, w.handshakeOut} {
		if hf == nil {
			continue
		}
		if err := hf.close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (h *hashFile) close() error {
	if h == nil || h.f == nil {
		return nil
	}
	err := h.f.Close()
	h.f = nil
	if err != nil {
		return fmt.Errorf("handshake: close %s: %w", h.path, err)
	}
	return nil
}
