package repl

import (
	"sort"
	"strings"

	"github.com/waffl3ss/warp/internal/store"
)

// findingGroup collapses the per-(BSSID, label) findings into one entry per finding name.
//
// The operator wants "here is a finding and everything it affects", not the same label
// repeated once per BSSID down the page - the same grouping the web interface's findings pane
// uses. Each group carries the finding name, a description (the first rationale seen), and the
// affected assets as BSSID + ESSID.
type findingGroup struct {
	Label  string
	Tier   store.Tier
	Desc   string          // first non-empty rationale for the group
	Assets []store.Finding // every finding carrying this label
}

// tierRank orders tiers most-severe first for grouping and sorting.
func tierRank(t store.Tier) int {
	switch t {
	case store.TierDetermined:
		return 0
	case store.TierEvidence:
		return 1
	case store.TierControl:
		// A control is a pass, not an exposure, so it sorts below the findings proper.
		return 2
	default:
		return 3
	}
}

// findingGroups groups m.data.findings by label. Assets keep the order they arrive in (already
// sorted by sortFindings); groups are ordered most-severe first, then by label, and the group
// header carries the most severe tier and the first non-empty rationale.
func (m *Model) findingGroups() []findingGroup {
	order := make([]string, 0)
	byLabel := make(map[string]*findingGroup)
	for _, f := range m.data.findings {
		g := byLabel[f.Label]
		if g == nil {
			g = &findingGroup{Label: f.Label, Tier: f.Tier, Desc: f.Rationale}
			byLabel[f.Label] = g
			order = append(order, f.Label)
		}
		if tierRank(f.Tier) < tierRank(g.Tier) {
			g.Tier = f.Tier
		}
		if g.Desc == "" {
			g.Desc = f.Rationale
		}
		g.Assets = append(g.Assets, f)
	}
	groups := make([]findingGroup, 0, len(order))
	for _, l := range order {
		groups = append(groups, *byLabel[l])
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if a, b := tierRank(groups[i].Tier), tierRank(groups[j].Tier); a != b {
			return a < b
		}
		return groups[i].Label < groups[j].Label
	})
	return groups
}

// selectedFindingGroup returns the group under the cursor on the findings tab, matched by the
// FINDING cell (the label). One row per group means the label identifies it uniquely.
func (m *Model) selectedFindingGroup() (findingGroup, bool) {
	label := strings.TrimSuffix(cellByTitle(m.findCols, m.findTable.SelectedRow(), "FINDING"), "…")
	if label == "" {
		return findingGroup{}, false
	}
	for _, g := range m.findingGroups() {
		if strings.HasPrefix(g.Label, label) {
			return g, true
		}
	}
	return findingGroup{}, false
}
