package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/waffl3ss/warp/internal/scope"
	"github.com/waffl3ss/warp/internal/store"
)

// TestBuildDataGroupsByNetworkAndFilesByScope: the JSON report groups BSSIDs and findings under
// their ESSID, the scoped variant drops out-of-scope networks, and captures are noted without any
// secret value.
func TestBuildDataGroupsByNetworkAndFilesByScope(t *testing.T) {
	r := &Report{
		Scope: []scope.Entry{{ESSID: "CORP-WIFI"}},
		APs: []store.APRow{
			{BSSID: "aa:aa:aa:aa:aa:01", ESSID: "CORP-WIFI", Channel: 6, SecurityClass: "wpa2"},
			{BSSID: "aa:aa:aa:aa:aa:02", ESSID: "CORP-WIFI", Channel: 11, SecurityClass: "wpa2"},
			{BSSID: "bb:bb:bb:bb:bb:01", ESSID: "NEIGHBOUR", Channel: 1, SecurityClass: "wep"},
		},
		Findings: []store.Finding{
			{BSSID: "aa:aa:aa:aa:aa:01", ESSID: "CORP-WIFI", Tier: store.TierDetermined,
				Label: "WPS enabled and unlocked", Differences: []string{"wps unlocked"}},
		},
		OutOfScopeFindings: []store.Finding{
			{BSSID: "bb:bb:bb:bb:bb:01", ESSID: "NEIGHBOUR", Tier: store.TierDetermined,
				Label: "WEP encryption"},
		},
	}
	inScope := func(e string) bool { return e == "CORP-WIFI" }
	caps := map[string]CaptureSummary{
		"CORP-WIFI": {PMKID: 1, WPSPassphrase: true},
	}
	tool := Tool{Name: "WARP", Version: "vtest"}

	// Scoped: only CORP-WIFI, with both its BSSIDs, its finding, and the capture note.
	scoped := BuildData(r, tool, inScope, caps, true)
	if len(scoped.Networks) != 1 || scoped.Networks[0].ESSID != "CORP-WIFI" {
		t.Fatalf("scoped networks = %+v, want just CORP-WIFI", scoped.Networks)
	}
	n := scoped.Networks[0]
	if !n.InScope || len(n.BSSIDs) != 2 {
		t.Errorf("network in_scope=%v bssids=%d, want true and 2", n.InScope, len(n.BSSIDs))
	}
	if n.Captured == nil || n.Captured.PMKID != 1 || !n.Captured.WPSPassphrase {
		t.Errorf("captured note wrong: %+v", n.Captured)
	}

	// Findings are a top-level section, grouped by title with their assets and evidence - not nested
	// under the networks.
	if len(scoped.Findings) != 1 {
		t.Fatalf("scoped findings = %d, want 1 (WEP is out of scope)", len(scoped.Findings))
	}
	fg := scoped.Findings[0]
	if fg.Title != "WPS enabled and unlocked" {
		t.Errorf("finding title = %q", fg.Title)
	}
	if len(fg.Assets) != 1 || fg.Assets[0].BSSID != "aa:aa:aa:aa:aa:01" {
		t.Errorf("finding assets = %+v", fg.Assets)
	}
	if fg.Evidence == nil || fg.Evidence.WPAVersion == "" {
		t.Errorf("finding evidence missing the parsed security: %+v", fg.Evidence)
	}

	// All: both networks and both findings, out-of-scope flagged.
	all := BuildData(r, tool, inScope, caps, false)
	if len(all.Networks) != 2 {
		t.Fatalf("all networks = %d, want 2", len(all.Networks))
	}
	if len(all.Findings) != 2 {
		t.Fatalf("all findings = %d, want 2", len(all.Findings))
	}

	// No secret *values* anywhere in the serialized document. The capture note carries booleans and
	// counts (wps_passphrase: true, pmkid: 1) - that is the point - but never a hash line, a
	// cleartext credential, or a recovered key/PIN value.
	blob := string(mustMarshal(t, all))
	for _, banned := range []string{"WPA*", "cleartext", "hash_line", "network_key"} {
		if strings.Contains(strings.ToLower(blob), strings.ToLower(banned)) {
			t.Errorf("report JSON contains %q - it must carry no secret value:\n%s", banned, blob)
		}
	}
}

// TestNetworkCarriesEncryptionDetail: each BSSID under a network carries the tshark-style encryption
// packet output as a field, ready to import into a reporting platform.
func TestNetworkCarriesEncryptionDetail(t *testing.T) {
	r := &Report{
		Scope: []scope.Entry{{ESSID: "CORP-WIFI"}},
		APs: []store.APRow{
			{BSSID: "aa:aa:aa:aa:aa:01", ESSID: "CORP-WIFI", Channel: 6, Band: "2.4 GHz",
				SecurityClass: "wpa_psk", Ciphers: "CCMP-128", AKMs: "PSK", MFP: "capable", WPS: true},
		},
	}
	inScope := func(e string) bool { return e == "CORP-WIFI" }
	d := BuildData(r, Tool{Name: "WARP", Version: "vtest"}, inScope, nil, false)
	if len(d.Networks) != 1 || len(d.Networks[0].BSSIDs) != 1 {
		t.Fatalf("networks = %+v", d.Networks)
	}
	det := d.Networks[0].BSSIDs[0].EncryptionDetail
	for _, want := range []string{"Detailed Encryption Information", "aa:aa:aa:aa:aa:01",
		"Pairwise Cipher Suite List", "AES (CCM)", "AKM", "WPS: enabled"} {
		if !strings.Contains(det, want) {
			t.Errorf("encryption_detail missing %q:\n%s", want, det)
		}
	}
}

// TestWeakEvidenceGetsReplaceablePlaceholder: a posture finding whose beacon record is not present
// (pruned, say) carries the stable placeholder token instead of an empty evidence field.
func TestWeakEvidenceGetsReplaceablePlaceholder(t *testing.T) {
	r := &Report{
		Scope: []scope.Entry{{ESSID: "CORP-WIFI"}},
		APs: []store.APRow{
			{BSSID: "aa:aa:aa:aa:aa:01", ESSID: "CORP-WIFI", SecurityClass: "wpa_psk"},
		},
		Findings: []store.Finding{
			// A posture finding whose BSSID is not among the observed APs: no beacon to show.
			{BSSID: "ff:ff:ff:ff:ff:ff", ESSID: "CORP-WIFI", Tier: store.TierDetermined,
				Label: "WEP encryption", Rationale: "uses WEP"},
		},
	}
	inScope := func(e string) bool { return e == "CORP-WIFI" }
	d := BuildData(r, Tool{Name: "WARP", Version: "vtest"}, inScope, nil, true)
	if len(d.Findings) != 1 || d.Findings[0].Evidence == nil {
		t.Fatalf("findings = %+v", d.Findings)
	}
	if got := d.Findings[0].Evidence.Placeholder; got != EvidencePlaceholder {
		t.Errorf("placeholder = %q, want %q", got, EvidencePlaceholder)
	}
}

// TestFindingsWithTheirOwnBasisDoNotGetTheManualPlaceholder: karma, decloak and evil-twin findings
// carry their own evidence, so they must never be tagged "no evidence, fill in manually" - the bug
// the manual-rogue evidence had. None of them dumps a cipher block either.
func TestFindingsWithTheirOwnBasisDoNotGetTheManualPlaceholder(t *testing.T) {
	sc := 0.3
	r := &Report{
		Scope: []scope.Entry{{ESSID: "CORP-WIFI"}},
		APs: []store.APRow{
			// evil-twin and decloak have a beacon record; karma answered a probe and never beaconed.
			{BSSID: "aa:aa:aa:aa:aa:01", ESSID: "CORP-WIFI", SecurityClass: "wpa_psk",
				Ciphers: "CCMP-128", AKMs: "PSK", Hidden: true},
			{BSSID: "aa:aa:aa:aa:aa:02", ESSID: "CORP-WIFI", SecurityClass: "wpa_psk",
				Ciphers: "CCMP-128", AKMs: "PSK"},
		},
		Findings: []store.Finding{
			{BSSID: "de:ad:be:ef:00:09", ESSID: "", Tier: store.TierDetermined,
				Label: "karma responder", Rationale: "answered an impossible probe"},
			{BSSID: "aa:aa:aa:aa:aa:01", ESSID: "CORP-WIFI", Tier: store.TierDetermined,
				Label: "hidden network name recovered", Rationale: "beacons an empty SSID"},
			{BSSID: "aa:aa:aa:aa:aa:02", ESSID: "CORP-WIFI", Tier: store.TierEvidence,
				Label: "evil twin candidate", Rationale: "fingerprint outlier",
				Differences: []string{"vendor OUI"}, Score: &sc},
		},
	}
	inScope := func(e string) bool { return e == "CORP-WIFI" }
	d := BuildData(r, Tool{Name: "WARP", Version: "vtest"}, inScope, nil, false)

	for _, fg := range d.Findings {
		ev := fg.Evidence
		if ev == nil {
			t.Fatalf("%q has no evidence", fg.Title)
		}
		if ev.Placeholder != "" {
			t.Errorf("%q wrongly tagged as no-evidence: %q", fg.Title, ev.Placeholder)
		}
		if ev.Ciphers != "" || ev.AKMs != "" || ev.WPAVersion != "" {
			t.Errorf("%q leaked a cipher block into a non-encryption finding: %+v", fg.Title, ev)
		}
	}
}

// TestPotentialRogueEvidenceIsManualAndSurvivesScopeFilter: a manually-marked potential rogue keeps
// its place under the in-scope filter (it is about a device in the footprint, not a scoped ESSID),
// its evidence is the manual placeholder rather than a beacon cipher dump, and the placeholder is in
// the evidence, not the description.
func TestPotentialRogueEvidenceIsManualAndSurvivesScopeFilter(t *testing.T) {
	r := &Report{
		Scope: []scope.Entry{{ESSID: "CORP-WIFI"}},
		APs: []store.APRow{
			{BSSID: "de:ad:be:ef:00:01", ESSID: "SOME-NEIGHBOUR", Channel: 6,
				SecurityClass: "wpa_psk", Ciphers: "CCMP-128", AKMs: "PSK"},
		},
		Findings: []store.Finding{
			{BSSID: "de:ad:be:ef:00:01", ESSID: "SOME-NEIGHBOUR", Tier: store.TierEvidence,
				Label:     "Potentially Rogue Device",
				Rationale: "Manually marked as a potential rogue device by the operator."},
		},
	}
	inScope := func(e string) bool { return e == "CORP-WIFI" }

	scoped := BuildData(r, Tool{Name: "WARP", Version: "vtest"}, inScope, nil, true)
	var fg *FindingGroup
	for i := range scoped.Findings {
		if scoped.Findings[i].Title == "Potentially Rogue Device" {
			fg = &scoped.Findings[i]
		}
	}
	if fg == nil {
		t.Fatalf("the potential-rogue finding was dropped by the in-scope filter: %+v", scoped.Findings)
	}
	if fg.Evidence == nil || fg.Evidence.Placeholder != EvidencePlaceholder {
		t.Errorf("evidence has no manual placeholder: %+v", fg.Evidence)
	}
	if fg.Evidence.WPAVersion != "" || fg.Evidence.Ciphers != "" || fg.Evidence.AKMs != "" {
		t.Errorf("rogue evidence leaked encryption detail: %+v", fg.Evidence)
	}
	if strings.Contains(fg.Rationale, EvidencePlaceholder) {
		t.Errorf("placeholder leaked into the description: %q", fg.Rationale)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
