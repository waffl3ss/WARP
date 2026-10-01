package scope

import "testing"

// TestSetRemove: removing narrows scope, is case-insensitive (matching Add and Match), reports
// whether anything was removed, and can be reversed by adding the name back.
func TestSetRemove(t *testing.T) {
	set, err := NewSet([]string{"CORP-WIFI", "CORP-GUEST"})
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}

	// Case-insensitive removal: the SoW casing and the observed casing need not match.
	removed, err := set.Remove("corp-wifi")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !removed {
		t.Fatal("Remove reported nothing removed for a scoped name")
	}
	if set.Contains("CORP-WIFI") {
		t.Error("CORP-WIFI is still in scope after removal")
	}
	if !set.Contains("CORP-GUEST") {
		t.Error("removing one name removed another")
	}
	if set.Len() != 1 {
		t.Errorf("scope length is %d, want 1", set.Len())
	}

	// Removing a name that is not present is a no-op, not an error.
	removed, err = set.Remove("NOT-HERE")
	if err != nil {
		t.Fatalf("Remove(absent): %v", err)
	}
	if removed {
		t.Error("Remove reported a removal for a name that was not in scope")
	}

	// Reversible: adding it back restores authorization.
	added, err := set.Add("CORP-WIFI")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if !added || !set.Contains("CORP-WIFI") {
		t.Error("a removed name could not be added back")
	}
}

// TestSetRemoveSiteWideRefused: a site-wide scope has no per-name list to remove from.
func TestSetRemoveSiteWideRefused(t *testing.T) {
	set, err := SiteWide("SoW authorizes all wireless at the facility")
	if err != nil {
		t.Fatalf("SiteWide: %v", err)
	}
	if _, err := set.Remove("anything"); err == nil {
		t.Error("removing from a site-wide scope should be refused, not silently accepted")
	}
}
