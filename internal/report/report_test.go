package report

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/scope"
	"github.com/waffl3ss/warp/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "warp.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func testGate(t *testing.T, essids ...string) *scope.Gate {
	t.Helper()
	set, err := scope.NewSet(essids)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	g, err := scope.NewGate(set, audit.Discard{})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return g
}

func mac(t *testing.T, s string) recon.MAC {
	t.Helper()
	m, err := recon.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	return m
}

func seed(t *testing.T, s *store.Store) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	for i, spec := range []struct {
		bssid, essid string
	}{
		{"a4:2b:8c:11:22:01", "CORP-WIFI"},
		{"a4:2b:8c:11:22:02", "CORP-WIFI"},
		{"de:ad:be:ef:00:01", "NEIGHBOUR"},
	} {
		ap := recon.AP{
			BSSID: mac(t, spec.bssid), ESSID: spec.essid, Channel: 6, Freq: 2437, Band: "2.4GHz",
			Security: recon.SecurityInfo{Class: recon.SecWPAPSK, MFP: recon.MFPAbsent},
			BestRSSI: int8(-50 - i), HasRSSI: true, BestRSSIRadio: "phy1",
			FirstSeen: now, LastSeen: now, Beacons: 10,
		}
		if err := s.UpsertAP(ctx, ap); err != nil {
			t.Fatalf("UpsertAP: %v", err)
		}
	}

	score := 0.31
	if err := s.UpsertFinding(ctx, store.Finding{
		BSSID: "a4:2b:8c:11:22:02", ESSID: "CORP-WIFI",
		Tier: store.TierEvidence, Label: "evil twin candidate",
		Rationale:   "radio fingerprint falls outside the dominant cluster on \"CORP-WIFI\".",
		Differences: []string{"vendor_ies: expected 004096:01, observed none"},
		Score:       &score, FirstTS: now, LastTS: now,
	}); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}
	if err := s.UpsertFinding(ctx, store.Finding{
		BSSID: "a4:2b:8c:11:22:01", ESSID: "CORP-WIFI",
		Tier: store.TierDetermined, Label: "no management frame protection",
		Rationale: "802.11w is neither required nor advertised.",
		FirstTS:   now, LastTS: now,
	}); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}

	if _, err := s.StartWalkthrough(ctx, "HQ_Floor_1", now, false); err != nil {
		t.Fatalf("StartWalkthrough: %v", err)
	}
}

func render(t *testing.T, s *store.Store, g *scope.Gate, opts Options) string {
	t.Helper()

	rep, err := Build(context.Background(), s, g, opts)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var buf bytes.Buffer
	if err := rep.WriteMarkdown(&buf); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	return buf.String()
}

func TestReportSeparatesEvidenceFromConclusions(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	out := render(t, s, testGate(t, "CORP-WIFI"), Options{Title: "Example Corp"})

	for _, want := range []string{
		"# Example Corp",
		"## Scope",
		"## Findings",
		"### Determined",
		"### Evidence-based",
		"## Limitations",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing section %q", want)
		}
	}

	// The evidence section must carry the differing attributes, not just a score.
	if !strings.Contains(out, "vendor_ies: expected 004096:01, observed none") {
		t.Error("the evidence finding does not cite its differing attributes")
	}
	// The hedge must survive into the document.
	if !strings.Contains(out, "evil twin candidate") {
		t.Error("the evil twin finding lost its hedge")
	}
	if strings.Contains(out, "confirmed evil twin") {
		t.Error("the report claims a confirmed evil twin")
	}
}

// TestLimitationsStateWhatCannotBeKnown is the section that stops a reader inferring more from
// the findings than they support. Each item is something WARP is structurally incapable of
// determining.
func TestLimitationsStateWhatCannotBeKnown(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	out := render(t, s, testGate(t, "CORP-WIFI"), Options{})

	required := map[string]string{
		"wired connectivity":   "Wired connectivity was not determined",
		"no trilateration":     "ranked, not measured",
		"candidates not proof": "candidates",
		"absence of evidence":  "Absence of a finding is not absence of exposure",
	}
	for name, phrase := range required {
		if !strings.Contains(out, phrase) {
			t.Errorf("limitations omit %s (looked for %q)", name, phrase)
		}
	}
}

// TestUnclassifiedDevicesAreListed: nothing is filtered out, and the absence of a finding is
// not the same as an absence of interest.
func TestUnclassifiedDevicesAreListed(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	out := render(t, s, testGate(t, "CORP-WIFI"), Options{})

	if !strings.Contains(out, "### Unclassified") {
		t.Fatal("the report has no unclassified section")
	}
	// The neighbour AP has no finding attached and must still appear.
	if !strings.Contains(out, "de:ad:be:ef:00:01") {
		t.Error("an observed device with no conclusion was omitted from the report")
	}
}

// TestGenericESSIDRiskIsCarriedIntoTheReport: the acknowledgment made at init is engagement
// context a reader needs.
func TestGenericESSIDRiskIsCarriedIntoTheReport(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	gate := testGate(t, "Guest", "CORP-WIFI")
	if err := gate.AcknowledgeGeneric("Guest", "operator@engagement"); err != nil {
		t.Fatalf("AcknowledgeGeneric: %v", err)
	}

	out := render(t, s, gate, Options{})

	if !strings.Contains(out, "common or vendor-default network name") {
		t.Error("the report does not explain the generic ESSID risk")
	}
	if !strings.Contains(out, "operator@engagement") {
		t.Error("the report does not name who accepted the residual risk")
	}
	if !strings.Contains(out, "Generic network names in scope") {
		t.Error("the limitations section does not carry the generic ESSID caveat")
	}
}

// TestHashesAreNotOverclaimed: an unrecovered hash is not evidence of a strong passphrase.
func TestHashesAreNotOverclaimed(t *testing.T) {
	s := testStore(t)
	seed(t, s)
	ctx := context.Background()

	if err := s.AddHash(ctx, handshakeResult("WPA*01*aa*bb*cc*dd***")); err != nil {
		t.Fatalf("AddHash: %v", err)
	}

	out := render(t, s, testGate(t, "CORP-WIFI"), Options{})

	if !strings.Contains(out, "## Credential material") {
		t.Fatal("captured hashes are not reported")
	}
	if !strings.Contains(out, "not evidence that the passphrase") {
		t.Error("the report does not caveat unrecovered hashes")
	}
	if !strings.Contains(out, "These are hashes, not passphrases") {
		t.Error("the report does not distinguish hashes from recovered passphrases")
	}
}

func TestEmptyEngagementStillRenders(t *testing.T) {
	s := testStore(t)

	out := render(t, s, testGate(t, "CORP-WIFI"), Options{})

	if !strings.Contains(out, "## Scope") || !strings.Contains(out, "## Limitations") {
		t.Error("an empty engagement did not render the standing sections")
	}
	if !strings.Contains(out, "_No findings recorded._") {
		t.Error("an empty findings section should say so explicitly")
	}
}

func TestCoverageSectionListsWalkthroughs(t *testing.T) {
	s := testStore(t)
	seed(t, s)

	out := render(t, s, testGate(t, "CORP-WIFI"), Options{})
	if !strings.Contains(out, "HQ_Floor_1") {
		t.Error("the coverage section does not list the walkthrough")
	}
}

// handshakeResult builds a minimal hash record for the credential-material section.
func handshakeResult(line string) handshake.Result {
	return handshake.Result{
		Kind: handshake.KindPMKID, Line: line, ESSID: "CORP-WIFI", At: time.Now().UTC(),
		InScope: true,
	}
}
