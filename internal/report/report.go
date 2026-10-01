// Package report renders an engagement into a document.
//
// The governing rule is the same one that shapes the schema: evidence and conclusions are
// presented separately, and nothing is claimed that cannot be defended. Every finding cites
// what was observed; every uncertain finding says so in its own words rather than behind a
// score; and the things WARP structurally cannot know - whether an unknown access point is on
// the client's wired network, where a device physically is - are stated as unknown rather than
// guessed at.
package report

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/waffl3ss/warp/internal/build"
	"github.com/waffl3ss/warp/internal/scope"
	"github.com/waffl3ss/warp/internal/store"
)

// Report is a rendered engagement.
type Report struct {
	Title     string
	Generated time.Time

	Scope    []scope.Entry
	Counts   store.Counts
	APs      []store.APRow
	Stations []store.StationRow
	// Findings are the deliverable: conclusions on scoped networks. OutOfScopeFindings are the
	// same kind of conclusion on networks the SoW does not cover - kept as context, filed
	// separately so they never enter the client-facing findings totals.
	Findings           []store.Finding
	OutOfScopeFindings []store.Finding
	Walkthroughs       []store.Walkthrough
	PMKIDHashes        int
	HandshakeHashes    int

	// Unclassified lists devices observed with no conclusion attached.
	Unclassified []string
}

// Options configures generation.
type Options struct {
	Title string
	// IncludeStations adds the client inventory, which can be long.
	IncludeStations bool
	// IncludeAllAPs includes every observed access point, not just the scoped ones.
	IncludeAllAPs bool
}

// Build assembles a report from the store.
func Build(ctx context.Context, st *store.Store, gate *scope.Gate, opts Options) (*Report, error) {
	if opts.Title == "" {
		opts.Title = "Wireless Assessment"
	}

	r := &Report{Title: opts.Title, Generated: time.Now()}

	var err error
	if r.Counts, err = st.Counts(ctx); err != nil {
		return nil, err
	}
	if r.APs, err = st.APs(ctx, ""); err != nil {
		return nil, err
	}
	allFindings, err := st.Findings(ctx, "")
	if err != nil {
		return nil, err
	}
	if r.Walkthroughs, err = st.ListWalkthroughs(ctx); err != nil {
		return nil, err
	}
	if r.PMKIDHashes, r.HandshakeHashes, err = st.HashCounts(ctx); err != nil {
		return nil, err
	}
	if opts.IncludeStations {
		if r.Stations, err = st.Stations(ctx); err != nil {
			return nil, err
		}
	}
	if gate != nil {
		r.Scope = gate.Snapshot()
	}

	// Split findings by scope: in-scope conclusions are the deliverable, out-of-scope ones are
	// context filed separately. A finding with no ESSID (a hidden device) has no name to match and
	// is treated as out of scope. With no gate, everything is treated as in scope (there is nothing
	// to file against).
	inScope := func(essid string) bool {
		if essid == "" {
			return false
		}
		if gate == nil {
			return true
		}
		return gate.Set().Contains(essid)
	}
	for _, f := range allFindings {
		if inScope(f.ESSID) {
			r.Findings = append(r.Findings, f)
		} else {
			r.OutOfScopeFindings = append(r.OutOfScopeFindings, f)
		}
	}

	// Unclassified is derived from every finding, in scope or not: a device with any conclusion
	// attached is not unclassified, wherever that conclusion is filed.
	labelled := make(map[string]bool, len(allFindings))
	for _, f := range allFindings {
		labelled[f.BSSID] = true
	}
	for _, ap := range r.APs {
		if !labelled[ap.BSSID] {
			r.Unclassified = append(r.Unclassified, ap.BSSID)
		}
	}
	sort.Strings(r.Unclassified)

	return r, nil
}

// WriteMarkdown renders the report.
func (r *Report) WriteMarkdown(w io.Writer) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "# %s\n\n", r.Title)
	// The tool and build that produced this, so a finding can be traced back to the code that
	// made it. The handle goes in the client deliverable too - this is a named tool, not an
	// anonymous script.
	fmt.Fprintf(b, "Generated %s by %s %s - %s\n\n",
		r.Generated.Format(time.RFC1123), build.Name, build.Release(), build.Author)

	r.writeScope(b)
	r.writeSummary(b)
	r.writeFindings(b)
	r.writeUnclassified(b)
	r.writeCoverage(b)
	r.writeCredentialMaterial(b)
	r.writeLimitations(b)

	_, err := io.WriteString(w, b.String())
	return err
}

func (r *Report) writeScope(b *strings.Builder) {
	b.WriteString("## Scope\n\n")
	b.WriteString("Testing was authorized by ESSID. Any access point broadcasting a listed " +
		"network name was in scope for active work; everything else was observed passively " +
		"only.\n\n")

	if len(r.Scope) == 0 {
		b.WriteString("_No scope recorded._\n\n")
		return
	}

	b.WriteString("| ESSID | Generic name | Active work |\n|---|---|---|\n")
	for _, e := range r.Scope {
		generic := "no"
		if e.Generic {
			generic = "**yes**"
		}
		active := "authorized"
		if !e.ActiveWorkReady {
			active = "blocked (unacknowledged)"
		}
		fmt.Fprintf(b, "| `%s` | %s | %s |\n", e.ESSID, generic, active)
	}
	b.WriteString("\n")

	for _, e := range r.Scope {
		if e.Generic && e.Acknowledged {
			fmt.Fprintf(b, "> `%s` is a common or vendor-default network name. A neighbouring "+
				"organisation could legitimately broadcast it, so active work at a matching "+
				"access point carried a residual risk of reaching a device outside this "+
				"engagement. This was acknowledged by %s before testing began and is recorded "+
				"in the audit log.\n\n", e.ESSID, orUnknown(e.AcknowledgedBy))
		}
	}
}

func (r *Report) writeSummary(b *strings.Builder) {
	b.WriteString("## Summary\n\n")

	var determined, evidence, control int
	for _, f := range r.Findings {
		switch f.Tier {
		case store.TierDetermined:
			determined++
		case store.TierEvidence:
			evidence++
		case store.TierControl:
			control++
		}
	}

	fmt.Fprintf(b, "- %d access points and %d client stations observed\n", r.Counts.APs, r.Counts.Stations)
	fmt.Fprintf(b, "- %d determined findings, %d evidence-based findings, %d controls (passes)\n",
		determined, evidence, control)
	fmt.Fprintf(b, "- %d devices observed with no conclusion available\n", len(r.Unclassified))
	fmt.Fprintf(b, "- %d PMKID and %d handshake hashes captured for offline analysis\n",
		r.PMKIDHashes, r.HandshakeHashes)
	fmt.Fprintf(b, "- %d signal observations across %d walkthroughs\n\n",
		r.Counts.Observations, len(r.Walkthroughs))
}

func (r *Report) writeFindings(b *strings.Builder) {
	b.WriteString("## Findings\n\n")

	if len(r.Findings) == 0 && len(r.OutOfScopeFindings) == 0 {
		b.WriteString("_No findings recorded._\n\n")
		return
	}
	if len(r.Findings) == 0 {
		b.WriteString("_No findings on a scoped network._\n\n")
	}

	byTier := map[store.Tier][]store.Finding{}
	for _, f := range r.Findings {
		byTier[f.Tier] = append(byTier[f.Tier], f)
	}

	if fs := byTier[store.TierDetermined]; len(fs) > 0 {
		b.WriteString("### Determined\n\n")
		b.WriteString("Deterministic and directly observable. Each of these is a fact read off " +
			"the air, not an inference.\n\n")
		for _, f := range fs {
			writeFinding(b, f)
		}
	}

	if fs := byTier[store.TierEvidence]; len(fs) > 0 {
		b.WriteString("### Evidence-based\n\n")
		b.WriteString("Inferences from the observed population, with the supporting evidence " +
			"attached. These warrant physical verification before action: an unusual but " +
			"legitimate access point produces the same signal as an impostor.\n\n")
		for _, f := range fs {
			writeFinding(b, f)
		}
	}

	if fs := byTier[store.TierControl]; len(fs) > 0 {
		b.WriteString("### Controls (passed)\n\n")
		b.WriteString("Configurations found to be correct and active tests the network passed - " +
			"802.11w required, WPS locked, an access point that resisted Pixie Dust. These are " +
			"recorded so the report shows what was tested, not only what was exposed.\n\n")
		for _, f := range fs {
			writeFinding(b, f)
		}
	}

	// Out-of-scope findings are context, not deliverable: conclusions about networks the SoW does
	// not cover, observed in the footprint and kept for completeness. They are not part of the
	// finding totals above and no active work was authorized against them.
	if len(r.OutOfScopeFindings) > 0 {
		b.WriteString("### Out of scope (context)\n\n")
		b.WriteString("Networks outside the engagement scope, observed in the footprint. These are " +
			"not the engagement's findings and no transmitting work was authorized against them; " +
			"they are listed only as context for the environment.\n\n")
		for _, f := range r.OutOfScopeFindings {
			writeFinding(b, f)
		}
	}
}

func writeFinding(b *strings.Builder, f store.Finding) {
	fmt.Fprintf(b, "#### %s - `%s`", f.Label, f.BSSID)
	if f.ESSID != "" {
		fmt.Fprintf(b, " (`%s`)", f.ESSID)
	}
	b.WriteString("\n\n")

	if f.Rationale != "" {
		fmt.Fprintf(b, "%s\n\n", f.Rationale)
	}
	if len(f.Differences) > 0 {
		b.WriteString("Differing attributes:\n\n")
		for _, d := range f.Differences {
			fmt.Fprintf(b, "- %s\n", d)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(b, "First observed %s, last %s.\n\n",
		f.FirstTS.Format(time.RFC3339), f.LastTS.Format(time.RFC3339))
}

func (r *Report) writeUnclassified(b *strings.Builder) {
	if len(r.Unclassified) == 0 {
		return
	}

	b.WriteString("### Unclassified\n\n")
	b.WriteString("These devices were observed in the footprint and no conclusion is available " +
		"about them. They are listed rather than omitted: the absence of a finding is not the " +
		"same as an absence of interest, and a reader should see everything that was on the " +
		"air.\n\n")

	for _, bssid := range r.Unclassified {
		fmt.Fprintf(b, "- `%s`\n", bssid)
	}
	b.WriteString("\n")
}

func (r *Report) writeCoverage(b *strings.Builder) {
	if len(r.Walkthroughs) == 0 {
		return
	}

	b.WriteString("## Coverage\n\n")
	b.WriteString("| Walkthrough | Started | Duration | Observations |\n|---|---|---|---|\n")

	now := time.Now()
	for _, w := range r.Walkthroughs {
		name := w.Name
		if w.Implicit {
			name += " _(unattended)_"
		}
		fmt.Fprintf(b, "| %s | %s | %s | %d |\n",
			name, w.StartTS.Format("2006-01-02 15:04"),
			w.Duration(now).Round(time.Minute), w.Observations)
	}
	b.WriteString("\n")
}

func (r *Report) writeCredentialMaterial(b *strings.Builder) {
	if r.PMKIDHashes+r.HandshakeHashes == 0 {
		return
	}

	b.WriteString("## Credential material\n\n")
	fmt.Fprintf(b, "%d PMKID and %d handshake hashes were captured and written to `pmkid.22000` "+
		"and `handshakes.22000`.\n\n", r.PMKIDHashes, r.HandshakeHashes)
	b.WriteString("These are hashes, not passphrases. Recovery is an offline exercise carried " +
		"out separately, and a hash that is not recovered is not evidence that the passphrase " +
		"is strong - only that it was not recovered within the effort applied.\n\n")
}

// writeLimitations states plainly what the assessment could not establish.
//
// This section is not boilerplate. Each item is something WARP is structurally incapable of
// determining, and saying so is what stops a reader inferring more from the findings than
// they support.
func (r *Report) writeLimitations(b *strings.Builder) {
	b.WriteString("## Limitations\n\n")

	b.WriteString("- **Wired connectivity was not determined.** Whether any unknown access " +
		"point is connected to the client's wired network cannot be established from radio " +
		"observation. It requires wired-side correlation. Devices are reported as present in " +
		"the footprint, and nothing more is claimed.\n")

	b.WriteString("- **Device locations are ranked, not measured.** Where a device was heard " +
		"loudest is reported as a ranked list of survey locations. No coordinate is given: " +
		"indoor signal-strength trilateration produces a position that looks authoritative " +
		"and cannot be defended.\n")

	b.WriteString("- **Evidence-based findings are candidates.** A fingerprint outlier is a " +
		"reason to investigate, not a confirmed rogue device. Verify physically before acting.\n")

	b.WriteString("- **Absence of a finding is not absence of exposure.** Coverage is bounded " +
		"by where the survey went, which channels were being watched when, and what was " +
		"transmitting at the time. A device that stayed quiet was not seen.\n")

	if len(r.Scope) > 0 {
		var generic []string
		for _, e := range r.Scope {
			if e.Generic {
				generic = append(generic, e.ESSID)
			}
		}
		if len(generic) > 0 {
			fmt.Fprintf(b, "- **Generic network names in scope.** %s %s common or vendor-default "+
				"name%s. Access points matching %s may belong to another organisation, and any "+
				"finding against them should be confirmed with the client before action.\n",
				quoteList(generic), plural(len(generic), "is a", "are"),
				plural(len(generic), "", "s"), plural(len(generic), "it", "them"))
		}
	}
	b.WriteString("\n")
}

func quoteList(items []string) string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = "`" + s + "`"
	}
	if len(out) == 1 {
		return out[0]
	}
	return strings.Join(out[:len(out)-1], ", ") + " and " + out[len(out)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func orUnknown(s string) string {
	if s == "" {
		return "an operator"
	}
	return s
}
