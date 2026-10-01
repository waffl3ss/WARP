package scope

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/waffl3ss/warp/internal/audit"
)

// transmittingModules is every subsystem that can put a frame in the air, across all phases.
// Adding a transmitting module without adding it here is the mistake this list exists to
// catch, so keep it in sync as phases land.
var transmittingModules = []string{
	"solicit",  // PMKID solicitation — association requests at authorized BSSIDs
	"deauth",   // deauthentication
	"rogue-ap", // hostapd-backed rogue AP
	"harvest",  // 802.1X supplicant for certificate harvesting
	"karma",    // karma responder *detection* probes
	"inject",   // raw injection capability check
	// Decloaking is authorized by AuthorizeDecloak, on an operator confirmation at a BSSID
	// with no name. It is listed here anyway: if a decloak request ever reaches the ordinary
	// path — a mis-set flag, a refactor that loses the routing — it must be refused there like
	// anything else rather than sailing through on a module name.
	"decloak",
}

func newTestGate(t *testing.T, essids ...string) (*Gate, *bytes.Buffer) {
	t.Helper()
	set, err := NewSet(essids)
	if err != nil {
		t.Fatalf("NewSet(%q): %v", essids, err)
	}
	var buf bytes.Buffer
	g, err := NewGate(set, audit.NewWriter(&buf))
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return g, &buf
}

// TestEveryTransmittingModuleRefusesUnscopedESSID is the core scope-gate assertion: no
// module, under any circumstances, transmits at a BSSID whose ESSID is not in scope.txt.
func TestEveryTransmittingModuleRefusesUnscopedESSID(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI", "CORP-IOT")

	unscoped := []struct {
		name  string
		essid string
	}{
		{"neighbour network", "NEIGHBOR-NET"},
		{"trailing space", "CORP-WIFI "},   // not the same octet string
		{"substring", "CORP"},              // prefix of a scoped name is not in scope
		{"superstring", "CORP-WIFI-GUEST"}, // extension of a scoped name is not in scope
		{"hidden/unresolved", ""},          // an unresolved hidden SSID is passive-only
		// Cyrillic U+0421 in place of ASCII 'C'. Written as an escape because a literal
		// homoglyph in source is invisible to a reviewer — which is the whole point of it.
		{"unicode lookalike", "\u0421ORP-WIFI"},
		{"null padded", "CORP-WIFI\x00\x00"}, // zero-padded element is not the same SSID
	}

	for _, mod := range transmittingModules {
		for _, tc := range unscoped {
			t.Run(mod+"/"+tc.name, func(t *testing.T) {
				err := g.AuthorizeTransmit(context.Background(), Request{
					Module: mod,
					BSSID:  "a4:2b:8c:11:22:33",
					ESSID:  tc.essid,
				})
				if err == nil {
					t.Fatalf("module %q was authorized to transmit at unscoped ESSID %q", mod, tc.essid)
				}
				if !Denied(err) {
					t.Fatalf("expected a scope denial, got %T: %v", err, err)
				}
			})
		}
	}
}

// TestRogueAPRefusesUnscopedBeacon asserts the rogue AP may only beacon scoped ESSIDs.
// Beaconing anything else impersonates a network outside the SoW.
func TestRogueAPRefusesUnscopedBeacon(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI")

	for _, essid := range []string{"NEIGHBOR-NET", "", "Free WiFi", "attwifi", "CORP-WIFI-GUEST"} {
		if err := g.AuthorizeBeacon(context.Background(), "rogue-ap", essid, 6, "phy0"); err == nil {
			t.Fatalf("rogue AP was authorized to beacon unscoped ESSID %q", essid)
		}
	}

	if err := g.AuthorizeBeacon(context.Background(), "rogue-ap", "CORP-WIFI", 6, "phy0"); err != nil {
		t.Fatalf("rogue AP refused to beacon a scoped ESSID: %v", err)
	}
}

// TestCaseDifferencesAreInScopeAndRecorded.
//
// scope.txt is transcribed by a human from a signed document. "Acme-Corp" in the SoW against
// "ACME-CORP" on the wire names the same network, and refusing to work there is a failure of
// the tool. What must never happen is that the difference disappears: every authorization
// records that the match was case-insensitive and which scope entry it matched.
func TestCaseDifferencesAreInScopeAndRecorded(t *testing.T) {
	g, log := newTestGate(t, "Corp-WiFi")

	for _, observed := range []string{"Corp-WiFi", "CORP-WIFI", "corp-wifi", "cOrP-wIfI"} {
		if err := g.AuthorizeTransmit(context.Background(), Request{
			Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: observed,
		}); err != nil {
			t.Fatalf("refused %q against scope entry %q: %v", observed, "Corp-WiFi", err)
		}
	}

	out := log.String()
	if !strings.Contains(out, `"case_insensitive_match":true`) {
		t.Error("a case-insensitive authorization was not recorded as one")
	}
	if !strings.Contains(out, `"scope_entry":"Corp-WiFi"`) {
		t.Error("the audit record does not name the scope entry that was matched")
	}

	// The exact match must not be labelled as a folded one, or the record means nothing.
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if strings.Contains(lines[0], "case_insensitive_match") {
		t.Errorf("an exact match was recorded as case-insensitive:\n%s", lines[0])
	}
}

// TestFoldingDoesNotReachBeyondCase. Case folding is the only latitude given. Anything else —
// whitespace, homoglyphs, padding, substrings — stays out of scope, because those are attacks
// or different networks rather than transcription slips.
func TestFoldingDoesNotReachBeyondCase(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI")

	for _, essid := range []string{
		"CORP-WIFI ", " CORP-WIFI", "CORP_WIFI", "CORPWIFI", "CORP-WIFI\x00",
		"СORP-WIFI", // Cyrillic U+0421 for ASCII 'C'
		"CORP-WIFI-GUEST", "CORP",
	} {
		if err := g.AuthorizeTransmit(context.Background(), Request{
			Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: essid,
		}); err == nil {
			t.Errorf("folding reached past case and authorized %q", essid)
		}
	}
}

// TestAuthorizationSucceedsWithoutOperatorConfirmation is the assertion that rots first.
//
// `scope confirm` is a convenience for a human who happens to be present. A NUC in a wiring
// closet has nobody to confirm anything and must do identical work. If this test fails, a
// deployment-context branch has appeared in the attack path.
func TestAuthorizationSucceedsWithoutOperatorConfirmation(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI")

	if got := len(g.Confirmations()); got != 0 {
		t.Fatalf("precondition: expected zero confirmations, got %d", got)
	}

	for _, mod := range transmittingModules {
		err := g.AuthorizeTransmit(context.Background(), Request{
			Module: mod,
			BSSID:  "a4:2b:8c:11:22:33", // freshly discovered, never confirmed
			ESSID:  "CORP-WIFI",
		})
		if err != nil {
			t.Fatalf("module %q was refused at a scoped ESSID with no operator confirmation: %v", mod, err)
		}
	}
}

// TestConfirmationDoesNotChangeTheDecision asserts confirming is advisory: the same request
// is authorized identically before and after, so there is only one code path.
func TestConfirmationDoesNotChangeTheDecision(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI")
	req := Request{Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: "CORP-WIFI"}

	before := g.AuthorizeTransmit(context.Background(), req)
	if err := g.Confirm(req.BSSID, req.ESSID, "verified on the ceiling in room 214"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	after := g.AuthorizeTransmit(context.Background(), req)

	if (before == nil) != (after == nil) {
		t.Fatalf("confirmation changed the authorization outcome: before=%v after=%v", before, after)
	}
	if before != nil {
		t.Fatalf("scoped ESSID should have been authorized: %v", before)
	}
}

// TestOperatorVetoNarrowsScope asserts a rejection excludes a BSSID even though its ESSID
// matches — the neighbour-on-a-shared-name case.
func TestOperatorVetoNarrowsScope(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI")
	const neighbour = "de:ad:be:ef:00:01"

	if err := g.AuthorizeTransmit(context.Background(), Request{Module: "solicit", BSSID: neighbour, ESSID: "CORP-WIFI"}); err != nil {
		t.Fatalf("precondition: expected authorization before veto: %v", err)
	}
	if err := g.Reject(neighbour, "CORP-WIFI", "consumer OUI, signal peaks in the adjacent suite"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	err := g.AuthorizeTransmit(context.Background(), Request{Module: "solicit", BSSID: neighbour, ESSID: "CORP-WIFI"})
	if err == nil {
		t.Fatal("vetoed BSSID was still authorized")
	}
	if !strings.Contains(err.Error(), ReasonOperatorRejected) {
		t.Fatalf("expected veto reason, got: %v", err)
	}

	// The veto is per BSSID, not per ESSID: other APs on the scoped network are unaffected.
	if err := g.AuthorizeTransmit(context.Background(), Request{Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: "CORP-WIFI"}); err != nil {
		t.Fatalf("veto leaked to an unrelated BSSID: %v", err)
	}
}

// TestGenericESSIDRequiresAcknowledgment covers the neighbour-shares-the-name risk.
func TestGenericESSIDRequiresAcknowledgment(t *testing.T) {
	g, _ := newTestGate(t, "Guest", "CORP-WIFI")

	pending := g.PendingAcknowledgments()
	if len(pending) != 1 || pending[0] != "Guest" {
		t.Fatalf("expected Guest pending acknowledgment, got %q", pending)
	}

	req := Request{Module: "deauth", BSSID: "a4:2b:8c:11:22:33", ESSID: "Guest"}
	if err := g.AuthorizeTransmit(context.Background(), req); err == nil {
		t.Fatal("transmitted at an unacknowledged generic ESSID")
	}

	// A non-generic scoped ESSID is unaffected — the guard does not gate the whole engagement.
	if err := g.AuthorizeTransmit(context.Background(), Request{Module: "deauth", BSSID: "a4:2b:8c:11:22:33", ESSID: "CORP-WIFI"}); err != nil {
		t.Fatalf("non-generic ESSID was blocked by the generic guard: %v", err)
	}

	if err := g.AcknowledgeGeneric("Guest", "operator@engagement"); err != nil {
		t.Fatalf("AcknowledgeGeneric: %v", err)
	}
	if err := g.AuthorizeTransmit(context.Background(), req); err != nil {
		t.Fatalf("acknowledged generic ESSID still refused: %v", err)
	}
	if got := g.PendingAcknowledgments(); len(got) != 0 {
		t.Fatalf("expected no pending acknowledgments, got %q", got)
	}
}

// TestAcknowledgmentSurvivesRestart asserts a shipped box resumes with the acknowledgment
// made before it left. This is what keeps the generic guard from becoming an
// "operator present" requirement.
func TestAcknowledgmentSurvivesRestart(t *testing.T) {
	g1, log := newTestGate(t, "Guest")
	if err := g1.AcknowledgeGeneric("Guest", "operator@engagement"); err != nil {
		t.Fatalf("AcknowledgeGeneric: %v", err)
	}
	if err := g1.Confirm("a4:2b:8c:11:22:33", "Guest", "client AP, verified"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := g1.Reject("de:ad:be:ef:00:01", "Guest", "neighbour"); err != nil {
		t.Fatalf("Reject: %v", err)
	}

	// Simulate a daemon restart: new gate, replay the existing events.jsonl.
	g2, _ := newTestGate(t, "Guest")
	if _, err := g2.Replay(bytes.NewReader(log.Bytes())); err != nil {
		t.Fatalf("Replay: %v", err)
	}

	if got := g2.PendingAcknowledgments(); len(got) != 0 {
		t.Fatalf("acknowledgment did not survive restart, still pending: %q", got)
	}
	if err := g2.AuthorizeTransmit(context.Background(), Request{Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: "Guest"}); err != nil {
		t.Fatalf("authorized work refused after restart: %v", err)
	}
	if err := g2.AuthorizeTransmit(context.Background(), Request{Module: "solicit", BSSID: "de:ad:be:ef:00:01", ESSID: "Guest"}); err == nil {
		t.Fatal("veto did not survive restart")
	}
}

// TestReplayToleratesTruncatedLog asserts a SIGKILL mid-write does not prevent resuming.
func TestReplayToleratesTruncatedLog(t *testing.T) {
	g1, log := newTestGate(t, "Guest")
	if err := g1.AcknowledgeGeneric("Guest", "operator"); err != nil {
		t.Fatalf("AcknowledgeGeneric: %v", err)
	}
	truncated := append(log.Bytes(), []byte(`{"ts":"2026-01-01T00:00:00Z","kind":"scope_con`)...)

	g2, _ := newTestGate(t, "Guest")
	applied, err := g2.Replay(bytes.NewReader(truncated))
	if err == nil {
		t.Log("truncated record parsed cleanly; acceptable, but the acknowledgment must still apply")
	}
	if applied != 1 {
		t.Fatalf("expected the complete record before the truncation to apply, applied=%d err=%v", applied, err)
	}
	if got := g2.PendingAcknowledgments(); len(got) != 0 {
		t.Fatalf("acknowledgment lost to a truncated log: %q", got)
	}
}

// TestAuditLogRecordsEveryDecision asserts the evidence chain is complete — denials included.
// A silent refusal is a gap in the report.
func TestAuditLogRecordsEveryDecision(t *testing.T) {
	g, log := newTestGate(t, "CORP-WIFI")

	if err := g.AuthorizeTransmit(context.Background(), Request{
		Module: "solicit", BSSID: "A4:2B:8C:11:22:33", ESSID: "CORP-WIFI", Channel: 6, RadioID: "phy1",
	}); err != nil {
		t.Fatalf("expected allow: %v", err)
	}
	if err := g.AuthorizeTransmit(context.Background(), Request{
		Module: "deauth", BSSID: "de:ad:be:ef:00:01", ESSID: "NEIGHBOR-NET", Channel: 11, RadioID: "phy1",
	}); err == nil {
		t.Fatal("expected deny")
	}

	var events []audit.Event
	dec := json.NewDecoder(bytes.NewReader(log.Bytes()))
	for {
		var e audit.Event
		if err := dec.Decode(&e); err != nil {
			break
		}
		events = append(events, e)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 audit records (allow + deny), got %d", len(events))
	}

	allow, deny := events[0], events[1]
	if allow.Outcome != audit.OutcomeAllow || allow.Module != "solicit" || allow.ESSID != "CORP-WIFI" {
		t.Fatalf("allow record is wrong: %+v", allow)
	}
	if allow.BSSID != "a4:2b:8c:11:22:33" {
		t.Fatalf("BSSID was not normalised in the audit record: %q", allow.BSSID)
	}
	if allow.Channel != 6 || allow.RadioID != "phy1" {
		t.Fatalf("allow record lost channel/radio evidence: %+v", allow)
	}
	if allow.TS.IsZero() {
		t.Fatal("audit record has no timestamp")
	}
	if deny.Outcome != audit.OutcomeDeny || deny.Reason != ReasonESSIDNotInScope {
		t.Fatalf("deny record is wrong: %+v", deny)
	}
}

// TestTransmitRefusedWhenAuditFails asserts we do not transmit what we cannot record.
func TestTransmitRefusedWhenAuditFails(t *testing.T) {
	set, err := NewSet([]string{"CORP-WIFI"})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	g, err := NewGate(set, failingLogger{})
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}

	err = g.AuthorizeTransmit(context.Background(), Request{Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: "CORP-WIFI"})
	if err == nil {
		t.Fatal("authorized a transmission that could not be recorded in the audit log")
	}
	if Denied(err) {
		t.Fatalf("an audit failure should surface as an internal error, not a scope denial: %v", err)
	}
}

type failingLogger struct{}

func (failingLogger) Log(audit.Event) error { return errors.New("disk full") }

// TestGateRequiresScopeAndAudit asserts a Gate cannot be built in an unsafe configuration.
func TestGateRequiresScopeAndAudit(t *testing.T) {
	set, _ := NewSet([]string{"CORP-WIFI"})

	if _, err := NewGate(nil, audit.Discard{}); err == nil {
		t.Fatal("built a gate with no scope")
	}
	if _, err := NewGate(&Set{}, audit.Discard{}); err == nil {
		t.Fatal("built a gate with an empty scope")
	}
	if _, err := NewGate(set, nil); err == nil {
		t.Fatal("built a gate with no audit log")
	}
}

func TestContextCancellationIsHonoured(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := g.AuthorizeTransmit(ctx, Request{Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: "CORP-WIFI"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
