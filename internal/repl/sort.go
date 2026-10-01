package repl

import (
	"sort"
	"strings"
)

// Sorting the dashboard's tables.
//
// Sorting happens on the data, not on the rendered rows: a row cell is styled text with a
// signal bar in it, and sorting those as strings would order by escape sequence. It also has
// to survive a refresh - the tables repopulate every second, and a sort that reset each time
// would be useless on exactly the busy site where it matters.

// sortableColumns lists which columns each tab can sort by, in cycle order. The first is the
// default when the operator presses `s` on a tab for the first time.
var sortableColumns = map[View][]string{
	ViewAPs:      {"SIGNAL", "NETWORK", "CH", "CLI", "BSSID", "SECURITY", "PMF", "SCOPE", "BAND"},
	ViewStations: {"SIGNAL", "NETWORK", "CLIENT", "ASSOCIATED", "FRAMES", "BAND"},
	ViewFindings: {"TIER", "NETWORK", "BSSID", "FINDING"},
	ViewJobs:     {"#", "KIND", "STATE", "TARGET", "ELAPSED"},
}

// cycleSort advances the sort column for the current tab, or flips direction if the operator
// presses it again on the same column.
func (m *Model) cycleSort(reverse bool) {
	cols, ok := sortableColumns[m.view]
	if !ok || len(cols) == 0 {
		return
	}

	cur := m.sortKey[m.view]
	if cur == "" {
		m.sortKey[m.view] = cols[0]
		m.sortAsc[m.view] = defaultAscending(cols[0])
		m.populate()
		return
	}

	if reverse {
		m.sortAsc[m.view] = !m.sortAsc[m.view]
		m.populate()
		return
	}

	idx := 0
	for i, c := range cols {
		if c == cur {
			idx = i + 1
			break
		}
	}
	if idx >= len(cols) {
		// Round the cycle back to no sort at all, which is discovery order - the order things
		// were first heard, which is itself informative.
		delete(m.sortKey, m.view)
		delete(m.sortAsc, m.view)
		m.populate()
		return
	}
	m.sortKey[m.view] = cols[idx]
	m.sortAsc[m.view] = defaultAscending(cols[idx])
	m.populate()
}

// defaultAscending picks the direction that puts the interesting end first. Nobody sorting by
// signal wants the weakest access point at the top.
func defaultAscending(col string) bool {
	switch col {
	case "SIGNAL", "CLI", "FRAMES", "#", "ELAPSED":
		return false
	default:
		return true
	}
}

// sortLabel is what the footer shows.
func (m *Model) sortLabel() string {
	col := m.sortKey[m.view]
	if col == "" {
		return ""
	}
	arrow := "↓"
	if m.sortAsc[m.view] {
		arrow = "↑"
	}
	return col + arrow
}

// sortAPs orders the access point list.
func (m *Model) sortAPs() {
	col, asc := m.sortKey[ViewAPs], m.sortAsc[ViewAPs]
	if col == "" {
		return
	}
	sort.SliceStable(m.data.aps, func(i, j int) bool {
		a, b := m.data.aps[i], m.data.aps[j]
		var less bool
		switch col {
		case "SIGNAL":
			// An access point with no RSSI sorts last whichever way round it is: unknown is
			// not "very weak", and putting it at the strong end would be a lie.
			if a.HasRSSI != b.HasRSSI {
				return a.HasRSSI
			}
			less = a.LastRSSI < b.LastRSSI
		case "NETWORK":
			less = foldLess(a.ESSID, b.ESSID)
		case "CH":
			less = a.Channel < b.Channel
		case "BAND":
			less = a.Band < b.Band
		case "CLI":
			less = a.Clients < b.Clients
		case "SECURITY":
			less = string(a.Security.Class) < string(b.Security.Class)
		case "PMF":
			less = a.Security.MFP < b.Security.MFP
		case "SCOPE":
			if a.InScope != b.InScope {
				return a.InScope == asc
			}
			less = a.BSSID.String() < b.BSSID.String()
		default: // BSSID
			less = a.BSSID.String() < b.BSSID.String()
		}
		if asc {
			return less
		}
		return !less
	})
}

// sortStations orders the client list.
func (m *Model) sortStations() {
	col, asc := m.sortKey[ViewStations], m.sortAsc[ViewStations]
	if col == "" {
		return
	}
	sort.SliceStable(m.data.stations, func(i, j int) bool {
		a, b := m.data.stations[i], m.data.stations[j]
		var less bool
		switch col {
		case "SIGNAL":
			if a.HasRSSI != b.HasRSSI {
				return a.HasRSSI
			}
			less = a.LastRSSI < b.LastRSSI
		case "NETWORK":
			less = foldLess(a.ESSID, b.ESSID)
		case "ASSOCIATED":
			less = a.BSSID.String() < b.BSSID.String()
		case "FRAMES":
			less = a.Frames < b.Frames
		case "BAND":
			less = a.APBand < b.APBand
		default: // CLIENT
			less = a.MAC.String() < b.MAC.String()
		}
		if asc {
			return less
		}
		return !less
	})
}

// sortFindings orders the findings list.
func (m *Model) sortFindings() {
	col, asc := m.sortKey[ViewFindings], m.sortAsc[ViewFindings]
	if col == "" {
		return
	}
	rank := map[string]int{"determined": 0, "evidence": 1, "unclassified": 2}
	sort.SliceStable(m.data.findings, func(i, j int) bool {
		a, b := m.data.findings[i], m.data.findings[j]
		var less bool
		switch col {
		case "TIER":
			less = rank[string(a.Tier)] < rank[string(b.Tier)]
		case "NETWORK":
			less = foldLess(a.ESSID, b.ESSID)
		case "FINDING":
			less = a.Label < b.Label
		default: // BSSID
			less = a.BSSID < b.BSSID
		}
		if asc {
			return less
		}
		return !less
	})
}

// sortJobs orders the job list.
func (m *Model) sortJobs() {
	col, asc := m.sortKey[ViewJobs], m.sortAsc[ViewJobs]
	if col == "" {
		return
	}
	sort.SliceStable(m.data.jobs, func(i, j int) bool {
		a, b := m.data.jobs[i], m.data.jobs[j]
		var less bool
		switch col {
		case "KIND":
			less = a.Kind < b.Kind
		case "STATE":
			less = string(a.State) < string(b.State)
		case "TARGET":
			less = a.Target < b.Target
		case "ELAPSED":
			less = a.Started.Before(b.Started)
		default: // #
			less = a.Started.Before(b.Started)
		}
		if asc {
			return less
		}
		return !less
	})
}

// foldLess orders names the way a person reading them would, and puts the unnamed last rather
// than first - an empty ESSID at the top of an alphabetical list is just noise.
func foldLess(a, b string) bool {
	if (a == "") != (b == "") {
		return a != ""
	}
	return strings.ToLower(a) < strings.ToLower(b)
}
