package daemon

import "testing"

// TestObservedBSSIDForValidatesSelection covers the Evil Twin BSSID selector's server-side guard:
// the operator may choose which observed access point the rogue mirrors, but only one WARP has
// actually seen broadcasting the scoped ESSID. An address not observed for that name - or typed by
// hand - is refused, which is what keeps the choice a selection among discovered addresses rather
// than configuration (invariant 1).
func TestObservedBSSIDForValidatesSelection(t *testing.T) {
	d, _ := startDaemon(t, "CORP-WIFI")
	observeBeacon(t, d, "a4:2b:8c:11:22:33", "CORP-WIFI", 6)
	observeBeacon(t, d, "a4:2b:8c:11:22:44", "CORP-WIFI", 6)
	observeBeacon(t, d, "b0:0b:1e:00:00:01", "NEIGHBOUR", 11)

	// An observed BSSID for the scoped name is accepted and returned in canonical form.
	if got := d.observedBSSIDFor("CORP-WIFI", "a4:2b:8c:11:22:44"); got != "a4:2b:8c:11:22:44" {
		t.Errorf("observedBSSIDFor accepted-case = %q, want a4:2b:8c:11:22:44", got)
	}
	// Case-insensitive, like the rest of the matching.
	if got := d.observedBSSIDFor("CORP-WIFI", "A4:2B:8C:11:22:33"); got != "a4:2b:8c:11:22:33" {
		t.Errorf("observedBSSIDFor upper-case = %q, want a4:2b:8c:11:22:33", got)
	}
	// An address observed only on a different network must not be accepted for this one.
	if got := d.observedBSSIDFor("CORP-WIFI", "b0:0b:1e:00:00:01"); got != "" {
		t.Errorf("observedBSSIDFor cross-network = %q, want empty", got)
	}
	// An address WARP never saw is refused - no hand-typed targets.
	if got := d.observedBSSIDFor("CORP-WIFI", "de:ad:be:ef:00:99"); got != "" {
		t.Errorf("observedBSSIDFor unobserved = %q, want empty", got)
	}
	// Empty selection means "no explicit choice" - the caller falls back to the strongest.
	if got := d.observedBSSIDFor("CORP-WIFI", ""); got != "" {
		t.Errorf("observedBSSIDFor empty = %q, want empty", got)
	}
}
