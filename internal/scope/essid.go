// Package scope implements WARP's authorization model.
//
// Scope is defined by ESSID and only by ESSID. The client provides a list of ESSIDs in
// scope.txt; that list is the signed Statement of Work expressed as data, and ESSID match
// *is* the authorization. BSSIDs are always discovered, never configured - nothing in this
// package, or anywhere else, may accept a client-supplied BSSID list as scope input.
//
// See CLAUDE.md invariants 1 and 2.
package scope

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// MaxESSIDLen is the maximum length of an SSID in octets (IEEE 802.11 SSID element).
const MaxESSIDLen = 32

// Warning is a non-fatal observation about scope.txt that the operator should see.
//
// These are surfaced rather than silently corrected: quietly "fixing" a scope entry changes
// what the tool is authorized to transmit at, which is not a decision this package gets to
// make on its own.
type Warning struct {
	Line int
	Text string
}

func (w Warning) String() string { return fmt.Sprintf("scope.txt:%d: %s", w.Line, w.Text) }

// Set is an immutable ESSID scope.
//
// Matching is case-insensitive, and the reason is practical rather than theoretical. SSIDs are
// octet strings and are case-sensitive on the wire, but scope.txt is typed by a human from a
// signed document: an SoW that says "Acme-Corp" against a beacon that says "ACME-CORP" names
// the same network, and refusing to work there is a failure of the tool, not a finding.
//
// The exact bytes are not thrown away. Match reports whether the beacon matched byte-for-byte
// or only after folding, every authorization records which, and a network that matches only
// after folding is raised as a finding - an access point advertising "CORP-WIFI" beside the
// estate's "Corp-WiFi" is a classic impersonation, and it must not disappear into a
// case-insensitive lookup.
type Set struct {
	entries []string
	index   map[string]struct{}
	// folded maps the case-folded form back to the scope entry as the client wrote it, so a
	// refusal or a finding can quote the SoW rather than the beacon.
	folded map[string]string

	// siteWide authorizes every named network rather than a list. See SiteWide.
	siteWide bool
	// siteWideNote is the operator's recorded justification, quoted back in the audit log and
	// on screen so the widened scope can never be silently in force.
	siteWideNote string
}

// SiteWide returns a scope that authorizes every named network.
//
// Some Statements of Work are written that way - "all wireless at this facility" - and a
// warehouse or a single-tenant site has no meaningful ESSID list to enumerate. Refusing to
// express that would push the operator into faking a scope file, which is worse: the
// engagement record would then claim an authorization the SoW never described.
//
// It is an engagement-level decision recorded at `warp init`, not a runtime flag, and it does
// not add a second code path. The gate still evaluates one sequence; this set simply answers
// yes to every name. Two things are still refused, because they are refusals about knowledge
// rather than authorization: an unresolved hidden network has no name to authorize, and an
// operator veto still narrows scope.
//
// note is the operator's justification and is required. It is quoted in the audit log, in the
// report and on screen for the life of the engagement.
func SiteWide(note string) (*Set, error) {
	if strings.TrimSpace(note) == "" {
		return nil, errors.New("scope: a site-wide scope requires a written justification " +
			"naming the authority for it")
	}
	return &Set{
		index:        map[string]struct{}{},
		folded:       map[string]string{},
		siteWide:     true,
		siteWideNote: note,
	}, nil
}

// IsSiteWide reports whether every named network is in scope.
func (s *Set) IsSiteWide() bool { return s != nil && s.siteWide }

// SiteWideNote returns the recorded justification for a site-wide scope.
func (s *Set) SiteWideNote() string {
	if s == nil {
		return ""
	}
	return s.siteWideNote
}

// fold is the canonical form used for matching.
//
// Deliberately only case folding: no whitespace trimming, no Unicode normalisation, no
// confusable mapping. Those would fold genuinely different networks together - a homoglyph
// ESSID is an attack, not a typo, and it has to stay out of scope.
func fold(s string) string { return strings.ToLower(s) }

// Load reads scope.txt from path.
func Load(path string) (*Set, []Warning, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open scope file %s: %w", path, err)
	}
	defer f.Close()

	set, warns, err := Parse(f)
	if err != nil {
		return nil, warns, fmt.Errorf("parse scope file %s: %w", path, err)
	}
	return set, warns, nil
}

// Parse reads newline-delimited ESSIDs.
//
// Blank lines are skipped. A UTF-8 BOM on the first line and trailing CR are stripped -
// scope.txt routinely arrives from a client authored on Windows. Nothing else is trimmed:
// an SSID may legitimately contain leading or trailing spaces, so padded entries produce a
// warning and are kept verbatim rather than being silently altered.
//
// Comments are not supported. A line beginning with '#' is a valid SSID, and treating it as
// a comment would silently drop something the client put in scope.
func Parse(r io.Reader) (*Set, []Warning, error) {
	var (
		warns   []Warning
		entries []string
		index   = make(map[string]struct{})
		folded  = make(map[string]string)
	)

	sc := bufio.NewScanner(r)
	// SSIDs are at most 32 octets; the default 64KiB buffer is ample. A pathological line
	// still errors out below rather than being truncated into a different SSID.
	for line := 1; sc.Scan(); line++ {
		raw := sc.Text()
		if line == 1 {
			raw = strings.TrimPrefix(raw, "\ufeff")
		}
		raw = strings.TrimSuffix(raw, "\r")

		if raw == "" {
			continue
		}
		if len(raw) > MaxESSIDLen {
			return nil, warns, fmt.Errorf("line %d: ESSID is %d octets, maximum is %d: %q",
				line, len(raw), MaxESSIDLen, raw)
		}
		if strings.TrimSpace(raw) == "" {
			warns = append(warns, Warning{line, fmt.Sprintf("entry is only whitespace: %q - kept verbatim, verify this is intended", raw)})
		} else if raw != strings.TrimSpace(raw) {
			warns = append(warns, Warning{line, fmt.Sprintf("entry has leading or trailing whitespace: %q - kept verbatim, verify against the SoW", raw)})
		}
		if _, dup := index[raw]; dup {
			warns = append(warns, Warning{line, fmt.Sprintf("duplicate entry: %q", raw)})
			continue
		}
		// Two entries differing only in case now authorize the same thing. That is almost
		// always a transcription slip in the SoW, and it is worth saying so rather than
		// letting one entry silently shadow the other.
		if prev, clash := folded[fold(raw)]; clash {
			warns = append(warns, Warning{line, fmt.Sprintf(
				"%q differs from %q only in case; matching is case-insensitive, so both "+
					"authorize the same networks", raw, prev)})
		} else {
			folded[fold(raw)] = raw
		}

		index[raw] = struct{}{}
		entries = append(entries, raw)
	}
	if err := sc.Err(); err != nil {
		return nil, warns, fmt.Errorf("read scope: %w", err)
	}
	if len(entries) == 0 {
		return nil, warns, fmt.Errorf("scope is empty: at least one ESSID is required")
	}

	return &Set{entries: entries, index: index, folded: folded}, warns, nil
}

// NewSet builds a Set from an in-memory list. Used by tests and by RPC callers that already
// hold a validated list; file input still goes through Parse.
func NewSet(essids []string) (*Set, error) {
	var b strings.Builder
	for _, e := range essids {
		if strings.ContainsAny(e, "\r\n") {
			return nil, fmt.Errorf("ESSID contains a newline: %q", e)
		}
		b.WriteString(e)
		b.WriteByte('\n')
	}
	set, _, err := Parse(strings.NewReader(b.String()))
	return set, err
}

// Contains reports whether essid is in scope, ignoring case.
//
// A hidden SSID arrives as an empty or zero-filled SSID element and will not match. That is
// correct: an unresolved hidden network is passive-observation-only until a probe or
// association frame reveals its ESSID.
func (s *Set) Contains(essid string) bool {
	_, _, ok := s.Match(essid)
	return ok
}

// Match resolves an observed ESSID against the scope.
//
// It returns the scope entry as the client wrote it, whether the observed name matched it
// byte-for-byte, and whether it matched at all. Callers that record or report use the entry,
// so the audit log and the report quote the SoW; callers that judge use exact, because a
// name that matches only after folding is worth a finding.
func (s *Set) Match(essid string) (entry string, exact bool, ok bool) {
	if s == nil || essid == "" {
		return "", false, false
	}
	// A site-wide scope authorizes every named network. It still cannot authorize a network
	// with no name: an unresolved hidden SSID is passive-only until a probe or association
	// reveals what it is, because there is nothing to record against the transmission.
	if s.siteWide {
		return essid, true, true
	}
	if _, hit := s.index[essid]; hit {
		return essid, true, true
	}
	if e, hit := s.folded[fold(essid)]; hit {
		return e, false, true
	}
	return "", false, false
}

// Add extends the scope with an observed network name.
//
// Scope is normally the signed document expressed as data and does not change mid-engagement.
// This exists because it does, occasionally, in a defensible way: the client names a network
// on site that was missing from the list, or an estate turns out to use a name nobody wrote
// down. The operator makes that call, it is written back to scope.txt so the engagement record
// matches what was authorized, and the audit log records who added it and when.
//
// It only ever widens. Narrowing is `scope reject`, which is per-BSSID and advisory.
func (s *Set) Add(essid string) (bool, error) {
	if s == nil {
		return false, errors.New("scope: no scope set")
	}
	if s.siteWide {
		return false, nil // already authorizes everything
	}
	if essid == "" {
		return false, errors.New("scope: an empty ESSID cannot be added - a hidden network " +
			"has no name to authorize until one is recovered")
	}
	if len(essid) > MaxESSIDLen {
		return false, fmt.Errorf("scope: ESSID is %d octets, maximum is %d", len(essid), MaxESSIDLen)
	}
	if strings.ContainsAny(essid, "\r\n") {
		return false, fmt.Errorf("scope: ESSID contains a newline: %q", essid)
	}
	if s.Contains(essid) {
		return false, nil
	}

	s.entries = append(s.entries, essid)
	s.index[essid] = struct{}{}
	s.folded[fold(essid)] = essid
	return true, nil
}

// Remove deletes an ESSID from scope, case-insensitively (matching how it is added and matched).
// It reports whether anything was removed. Removing narrows scope, so it is always permitted; a
// site-wide scope is the exception, since there is no per-name list to take a name out of.
func (s *Set) Remove(essid string) (bool, error) {
	if s == nil {
		return false, errors.New("scope: no scope set")
	}
	if s.siteWide {
		return false, errors.New("scope: this engagement is site-wide (every named network is " +
			"authorized); there is no per-name list to remove from")
	}
	entry, ok := s.folded[fold(essid)]
	if !ok {
		return false, nil
	}
	delete(s.folded, fold(essid))
	delete(s.index, entry)
	for i, e := range s.entries {
		if e == entry {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			break
		}
	}
	return true, nil
}

// List returns the scoped ESSIDs in the order the client provided them.
func (s *Set) List() []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s.entries))
	copy(out, s.entries)
	return out
}

// Len returns the number of scoped ESSIDs.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}
