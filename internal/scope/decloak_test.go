package scope

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/waffl3ss/warp/internal/audit"
)

const hiddenBSSID = "a4:2b:8c:11:22:33"

// TestDecloakNeedsNoConfirmation.
//
// A hidden network may well be in scope, and there is no way to find out except by recovering
// the name. Requiring a confirmation first asked the operator to assert exactly the fact the
// tool was being asked to establish, and someone standing in the building looking at a
// nameless BSSID has no better information than WARP does. It made decloaking unusable for the
// case it exists for.
func TestDecloakNeedsNoConfirmation(t *testing.T) {
	g, buf := newTestGate(t, "CORP-WIFI")

	if err := g.AuthorizeDecloak(context.Background(), "decloak", hiddenBSSID, "", 6, "phy0"); err != nil {
		t.Fatalf("decloaking an unconfirmed BSSID was refused: %v", err)
	}

	// The evidence has to say *why* a nameless BSSID was transmitted at. Anyone reconstructing
	// the engagement from events.jsonl must not have to go and read the source.
	ev := lastAuthorizeEvent(t, buf)
	if ev.Outcome != audit.OutcomeAllow {
		t.Fatalf("audit outcome = %q, want allow", ev.Outcome)
	}
	if ev.Reason != ReasonDecloakNameless {
		t.Errorf("audit reason = %q, want %q", ev.Reason, ReasonDecloakNameless)
	}
	if ok, _ := ev.Detail["decloak"].(bool); !ok {
		t.Error("audit record is not marked as a decloak")
	}
	if ok, _ := ev.Detail["no_essid_to_authorize_against"].(bool); !ok {
		t.Error("audit record does not say there was no ESSID to decide on")
	}
	if ok, _ := ev.Detail["scope_resumes_once_named"].(bool); !ok {
		t.Error("audit record does not say scope resumes once the name is known")
	}
}

// TestAConfirmationIsRecordedButDecidesNothing: it is context in the evidence, the same as
// everywhere else in WARP.
func TestAConfirmationIsRecordedButDecidesNothing(t *testing.T) {
	g, buf := newTestGate(t, "CORP-WIFI")

	if err := g.Confirm(hiddenBSSID, "", "client pointed at the rack it is in"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := g.AuthorizeDecloak(context.Background(), "decloak", hiddenBSSID, "", 6, "phy0"); err != nil {
		t.Fatalf("AuthorizeDecloak: %v", err)
	}

	ev := lastAuthorizeEvent(t, buf)
	if ev.Reason != ReasonDecloakNameless {
		t.Errorf("audit reason = %q; a confirmation must not change the decision's reason",
			ev.Reason)
	}
	if ok, _ := ev.Detail["operator_confirmed"].(bool); !ok {
		t.Error("the confirmation is not recorded as context")
	}
	if note, _ := ev.Detail["operator_note"].(string); note == "" {
		t.Error("the operator's stated reason is not in the audit record")
	}
}

// TestDecloakHonoursAVeto: a veto only ever narrows scope, so it wins here as everywhere else.
func TestDecloakHonoursAVeto(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI")

	if err := g.Confirm(hiddenBSSID, "", "confirmed earlier"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if err := g.Reject(hiddenBSSID, "", "turned out to be the tenant upstairs"); err != nil {
		t.Fatalf("Reject: %v", err)
	}

	err := g.AuthorizeDecloak(context.Background(), "decloak", hiddenBSSID, "", 6, "phy0")
	if err == nil {
		t.Fatal("a vetoed BSSID was authorized for decloaking")
	}
	if !strings.Contains(err.Error(), ReasonOperatorRejected) {
		t.Errorf("denial reason = %q, want %q", err, ReasonOperatorRejected)
	}
}

// TestDecloakRefusesANamedNetwork.
//
// The decloak path exists only because there is no name to decide on. Letting a *named*
// network through it would launder an ordinary transmission past the ESSID check — the exact
// bypass this method is constructed to not be.
func TestDecloakRefusesANamedNetwork(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI")

	// Not merely an unscoped name: a scoped one is refused down this path too, because the
	// ordinary path is where a named network belongs.
	for _, essid := range []string{"NEIGHBOUR-WIFI", "CORP-WIFI"} {
		err := g.AuthorizeDecloak(context.Background(), "decloak", hiddenBSSID, essid, 6, "phy0")
		if err == nil {
			t.Fatalf("a network already broadcasting %q was authorized down the decloak path", essid)
		}
		if !strings.Contains(err.Error(), ReasonDecloakNamed) {
			t.Errorf("%s: denial reason = %q, want %q", essid, err, ReasonDecloakNamed)
		}
	}
}

// TestDecloakRefusesAnythingThatIsNotADiscoveredBSSID guards the "BSSIDs are always
// discovered, never configured" invariant at the gate itself.
func TestDecloakRefusesAnythingThatIsNotABSSID(t *testing.T) {
	g, _ := newTestGate(t, "CORP-WIFI")

	for _, bad := range []string{"", "not-a-mac", "CORP-WIFI", "a4:2b:8c:11:22"} {
		if err := g.AuthorizeDecloak(context.Background(), "decloak", bad, "", 6, "phy0"); err == nil {
			t.Errorf("AuthorizeDecloak(%q) was accepted", bad)
		}
	}
}

// lastAuthorizeEvent returns the final authorization record written to the log.
func lastAuthorizeEvent(t *testing.T, buf *bytes.Buffer) audit.Event {
	t.Helper()

	var last audit.Event
	found := false
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for {
		var e audit.Event
		if err := dec.Decode(&e); err != nil {
			break
		}
		if e.Kind == audit.KindAuthorize {
			last, found = e, true
		}
	}
	if !found {
		t.Fatalf("no authorization record in the audit log:\n%s", buf.String())
	}
	return last
}
