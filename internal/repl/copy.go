package repl

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Copying data out of the dashboard.
//
// A full-screen bubbletea program owns the alternate screen buffer. Inside it the terminal's
// own selection either does nothing or selects the whole window - panel borders, signal bars
// and all - so a BSSID an operator wants in a ticket cannot be got out. Over SSH there is no
// system clipboard to fall back on either.
//
// `y` therefore suspends the program, prints the current tab as plain tab-separated text on
// the normal screen, and returns. The operator selects it with the mouse the way they would
// any other command output, and presses a key to go back. No styling, no borders, no bars:
// what is printed is the underlying values, which is what pastes usefully.

// copyOut prints the current tab as plain text outside the alternate screen.
func (m *Model) copyOut() tea.Cmd {
	text := m.plainTable()
	if text == "" {
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render("nothing on this tab to copy")}
		}
	}

	return tea.Sequence(
		tea.ExitAltScreen,
		tea.Printf("%s", text),
		tea.EnterAltScreen,
		func() tea.Msg {
			return flashMsg{text: "printed above - scroll back to select and copy"}
		},
	)
}

// plainTable renders the current tab as tab-separated values with no styling.
//
// Tab-separated rather than aligned: it pastes into a spreadsheet, a ticket or a report
// without carrying a column layout that will be wrong everywhere else.
func (m *Model) plainTable() string {
	var b strings.Builder

	switch m.view {
	case ViewAPs:
		fmt.Fprintln(&b, "bssid\tessid\tband\tchannel\trssi\tsecurity\tpmf\tclients\tin_scope\tfirst_seen\tlast_seen")
		for _, ap := range m.data.aps {
			fmt.Fprintf(&b, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%d\t%t\t%s\t%s\n",
				ap.BSSID, ap.ESSID, ap.Band, ap.Channel,
				plainRSSI(ap.LastRSSI, ap.HasRSSI), ap.Security.Class,
				plainPMF(ap.Security.MFP), ap.Clients, ap.InScope,
				ap.FirstSeen.Format("15:04:05"), ap.LastSeen.Format("15:04:05"))
		}

	case ViewStations:
		fmt.Fprintln(&b, "client\trandomised\tbssid\tessid\tband\tchannel\trssi\tframes\tprobed_for")
		for _, st := range m.data.stations {
			bssid := ""
			if !st.BSSID.IsZero() {
				bssid = st.BSSID.String()
			}
			fmt.Fprintf(&b, "%s\t%t\t%s\t%s\t%s\t%d\t%s\t%d\t%s\n",
				st.MAC, st.Randomised, bssid, st.ESSID, st.APBand, st.APChannel,
				plainRSSI(st.LastRSSI, st.HasRSSI), st.Frames,
				strings.Join(st.ProbedESSIDs, " "))
		}

	case ViewFindings:
		fmt.Fprintln(&b, "tier\tbssid\tessid\tfinding\trationale")
		for _, f := range m.data.findings {
			// Newlines in a rationale would break the row apart when pasted.
			rationale := strings.Join(strings.Fields(f.Rationale), " ")
			fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\n", f.Tier, f.BSSID, f.ESSID, f.Label, rationale)
		}
		for _, u := range m.data.unclass {
			fmt.Fprintf(&b, "unclassified\t%s\t\t\t\n", u)
		}

	case ViewJobs:
		fmt.Fprintln(&b, "id\tkind\ttarget\tstate\tstarted\tdetail")
		for _, j := range m.data.jobs {
			detail := j.Detail
			if j.Error != "" {
				detail = j.Error
			}
			fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%s\n",
				j.ID, j.Kind, j.Target, j.State,
				j.Started.Format("15:04:05"), strings.Join(strings.Fields(detail), " "))
		}

	case ViewLog:
		for _, line := range m.lines {
			fmt.Fprintln(&b, stripANSI(line))
		}

	default:
		return ""
	}

	return strings.TrimRight(b.String(), "\n")
}

// plainRSSI writes an unknown signal as empty rather than as a number, so a spreadsheet does
// not average a missing reading in with real ones.
func plainRSSI(rssi int8, has bool) string {
	if !has {
		return ""
	}
	return fmt.Sprintf("%d", rssi)
}

func plainPMF(m interface{ String() string }) string { return m.String() }
