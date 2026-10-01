package daemon

import (
	"context"
	"strings"
	"testing"

	"github.com/waffl3ss/warp/internal/report"
	"github.com/waffl3ss/warp/internal/rogue"
)

// TestRogueMarkIsBSSIDSpecificAndToggles: marking a potential rogue records an evidence-tier finding
// on exactly that BSSID (not its ESSID siblings), colours only that row, points its evidence at
// manual evidence, and can be cleared again.
func TestRogueMarkIsBSSIDSpecificAndToggles(t *testing.T) {
	d, c := startDaemon(t, "CORP-WIFI")
	observeBeacon(t, d, "a4:2b:8c:11:22:01", "CORP-WIFI", 6)
	observeBeacon(t, d, "a4:2b:8c:11:22:02", "CORP-WIFI", 6)
	ctx := context.Background()

	if err := c.Call(ctx, "rogue.mark", map[string]any{"bssid": "a4:2b:8c:11:22:01"}, nil); err != nil {
		t.Fatalf("rogue.mark: %v", err)
	}

	// The finding lands on that BSSID, evidence tier, manual label. Its rationale is a clean
	// description - the "manual evidence required" placeholder belongs in the evidence field (the
	// report puts it there), never in the description.
	fs, err := d.store.FindingsFor(ctx, "a4:2b:8c:11:22:01")
	if err != nil {
		t.Fatalf("FindingsFor: %v", err)
	}
	var mark *string
	for i := range fs {
		if fs[i].Label == rogue.LabelPotentialRogue {
			mark = &fs[i].Rationale
			if fs[i].Tier != "evidence" {
				t.Errorf("tier = %q, want evidence", fs[i].Tier)
			}
		}
	}
	if mark == nil {
		t.Fatalf("no %q finding recorded: %+v", rogue.LabelPotentialRogue, fs)
	}
	if strings.Contains(*mark, report.EvidencePlaceholder) {
		t.Errorf("the placeholder leaked into the description; it belongs in the evidence: %q", *mark)
	}

	// The sibling BSSID on the same ESSID is untouched.
	sib, _ := d.store.FindingsFor(ctx, "a4:2b:8c:11:22:02")
	for _, f := range sib {
		if f.Label == rogue.LabelPotentialRogue {
			t.Errorf("marking one BSSID marked its ESSID sibling too: %+v", f)
		}
	}

	// aps.list colours only the marked BSSID (Rogue true on it, false elsewhere).
	var aps []APView
	if err := c.Call(ctx, "aps.list", nil, &aps); err != nil {
		t.Fatalf("aps.list: %v", err)
	}
	for _, ap := range aps {
		want := ap.BSSID.String() == "a4:2b:8c:11:22:01"
		if ap.Rogue != want {
			t.Errorf("%s Rogue = %v, want %v", ap.BSSID, ap.Rogue, want)
		}
	}

	// Unmark clears it.
	if err := c.Call(ctx, "rogue.unmark", map[string]any{"bssid": "a4:2b:8c:11:22:01"}, nil); err != nil {
		t.Fatalf("rogue.unmark: %v", err)
	}
	after, _ := d.store.FindingsFor(ctx, "a4:2b:8c:11:22:01")
	for _, f := range after {
		if f.Label == rogue.LabelPotentialRogue {
			t.Errorf("unmark left the mark in place: %+v", f)
		}
	}
}
