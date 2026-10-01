package repl

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/waffl3ss/warp/internal/build"
	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/eap/certs"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/store"
	"github.com/waffl3ss/warp/internal/workspace"
)

// fixture builds a dashboard populated with a plausible engagement, so the layout can be
// exercised without a daemon.
//
// Rendering is worth testing on its own: a panic in View or a column that overruns the
// terminal width is invisible to every other test in the tree and is the first thing an
// operator would hit.
func fixture(t *testing.T, width, height int) *Model {
	t.Helper()

	m := New(context.Background(), nil, "/run/warp.sock")
	now := time.Now()

	mac := func(s string) recon.MAC {
		v, err := recon.ParseMAC(s)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", s, err)
		}
		return v
	}

	ap := func(bssid, essid string, ch int, rssi int8, sec recon.Security, inScope bool) daemon.APView {
		return daemon.APView{
			AP: recon.AP{
				BSSID: mac(bssid), ESSID: essid, Channel: ch, Freq: 2407 + 5*ch,
				Security: recon.SecurityInfo{Class: sec, MFP: recon.MFPAbsent},
				BestRSSI: rssi, HasRSSI: true, BestRSSIRadio: "phy1",
				FirstSeen: now.Add(-time.Hour), LastSeen: now, Beacons: 400,
			},
			InScope: inScope,
		}
	}

	score := 0.31
	m.data = snapshot{
		status: daemon.StatusResult{
			Workspace: "./engagement", Uptime: "14m22s", ScopeESSIDs: 3,
			Radios: 2, SurveyRadio: "phy1", PMKIDHashes: 4, HandshakeHashes: 2,
			RunningJobs: 1, Walkthrough: "HQ_Floor_1",
			Disk: workspace.DiskUsage{
				Path:       "./engagement",
				TotalBytes: 250 << 30, UsedBytes: 100 << 30, FreeBytes: 150 << 30,
				UsedPercent: 40, EngagementBytes: 3 << 30, Level: workspace.DiskOK,
			},
			Recon: daemon.EngineStats{
				Running: true, APs: 24, Stations: 61, SurveyRadio: "phy1",
				HeldRadios: []string{"phy1"},
				Radios: []daemon.RadioCaptureStats{
					{RadioID: "phy0", Ifname: "wlan0", Role: "recon", Channel: 6, Bands: "2.4/5GHz"},
					{RadioID: "phy1", Ifname: "wlan1", Role: "survey", Channel: 11, Bands: "2.4GHz", Locked: true},
				},
			},
			Capabilities: []radio.Capability{
				{Name: "passive recon", Available: true},
				{Name: "survey walkthroughs", Available: true},
				{Name: "PMKID solicitation / deauthentication", Available: true},
				{Name: "hunt (direction finding)", Available: true},
				{Name: "rogue AP / enterprise credential capture", Available: false,
					Reason: "no adapter supports AP mode"},
				{Name: "simultaneous capture and active work", Available: true},
			},
		},
		aps: []daemon.APView{
			ap("a4:2b:8c:11:22:01", "CORP-WIFI", 6, -42, recon.SecWPAPSK, true),
			ap("a4:2b:8c:11:22:02", "CORP-WIFI", 11, -58, recon.SecWPAPSK, true),
			ap("a4:2b:8c:11:22:03", "CORP-8021X", 36, -61, recon.SecWPAEnterprise, true),
			ap("de:ad:be:ef:00:01", "", 6, -77, recon.SecWPASAE, false),
			ap("11:22:33:44:55:66", "NEIGHBOUR-CAFE", 1, -84, recon.SecOpen, false),
		},
		stations: []daemon.StationView{
			{Station: recon.Station{
				MAC: mac("de:ad:be:ef:10:01"), BSSID: mac("a4:2b:8c:11:22:01"),
				BestRSSI: -55, HasRSSI: true, Frames: 1420, OUI: "Apple",
				ProbedESSIDs: []string{"CORP-WIFI", "HomeNet"}},
				ESSID: "CORP-WIFI", InScope: true, APBand: "2.4 GHz", APChannel: 6,
				MFP: recon.MFPAbsent},
			{Station: recon.Station{
				MAC: mac("da:a1:19:00:11:22"), BestRSSI: -70, HasRSSI: true, Frames: 12,
				Randomised: true, ProbedESSIDs: []string{"Starbucks"}}},
		},
		findings: []store.Finding{
			{Tier: store.TierDetermined, BSSID: "11:22:33:44:55:66", ESSID: "NEIGHBOUR-CAFE",
				Label: "open network on a scoped ESSID", FirstTS: now, LastTS: now},
			{Tier: store.TierEvidence, BSSID: "a4:2b:8c:11:22:02", ESSID: "CORP-WIFI",
				Label:       "evil twin candidate",
				Rationale:   "radio fingerprint falls outside the dominant cluster on CORP-WIFI.",
				Differences: []string{"vendor_ies: expected 004096:01, observed none"},
				Score:       &score, FirstTS: now, LastTS: now},
		},
		unclass: []string{"de:ad:be:ef:00:01"},
		hashes: daemon.HashesResult{
			PMKID: 1, Handshake: 1,
			Hashes: []store.HashRecord{
				{Kind: "pmkid", ESSID: "CORP-WIFI", BSSID: "a4:2b:8c:11:22:01", Channel: 6,
					Line: "WPA*01*aabb...*a42b8c112201*deadbeef1001*434f52502d57494649***", At: now},
				{Kind: "handshake", ESSID: "CORP-WIFI", BSSID: "a4:2b:8c:11:22:02",
					Station: "de:ad:be:ef:10:01", Channel: 11,
					Line: "WPA*02*ccdd...*a42b8c112202*deadbeef1001*434f52502d57494649*...", At: now},
			},
		},
		jobs: []daemon.Job{
			{ID: "3", Kind: "solicit", Target: "a4:2b:8c:11:22:01",
				State: daemon.JobRunning, Started: now.Add(-8 * time.Second)},
			{ID: "2", Kind: "karma-test", State: daemon.JobDone,
				Started: now.Add(-2 * time.Minute)},
		},
	}

	m.Update(tea.WindowSizeMsg{Width: width, Height: height})
	m.populate()
	return m
}

// TestEveryTabRenders is the guard against a panic or an overrun in the layout, which no other
// test in the tree would catch.
func TestEveryTabRenders(t *testing.T) {
	const width, height = 120, 32

	for v := ViewOverview; v <= ViewLog; v++ {
		t.Run(v.String(), func(t *testing.T) {
			m := fixture(t, width, height)
			m.view = v
			m.layout()

			out := m.View()
			if out == "" {
				t.Fatal("rendered nothing")
			}

			for i, line := range strings.Split(out, "\n") {
				if w := lipglossWidth(line); w > width {
					t.Errorf("line %d is %d columns wide, terminal is %d:\n%s", i, w, width, line)
				}
			}
		})
	}
}

// TestTheBuildCreditIsShown. Faint, right-aligned on the title line, and dropped rather than
// wrapped when the terminal is too narrow — the workspace and the clock own that line.
func TestTheBuildCreditIsShown(t *testing.T) {
	m := fixture(t, 140, 32)
	m.view = ViewOverview
	m.layout()

	out := stripANSI(m.View())
	if !strings.Contains(out, build.Author) {
		t.Errorf("the dashboard carries no attribution:\n%s", out)
	}

	// It must never push the header past the terminal width.
	for i, line := range strings.Split(m.headerView(), "\n") {
		if w := lipglossWidth(line); w > 140 {
			t.Errorf("header line %d is %d columns wide: %s", i, w, line)
		}
	}

	// On a narrow terminal the credit is dropped, not wrapped.
	narrow := fixture(t, 60, 20)
	narrow.view = ViewOverview
	narrow.layout()
	for i, line := range strings.Split(narrow.headerView(), "\n") {
		if w := lipglossWidth(line); w > 60 {
			t.Errorf("narrow header line %d is %d columns wide: %s", i, w, line)
		}
	}
}

// TestNarrowTerminalDoesNotPanic: an operator on a phone tether over SSH gets a small window.
func TestNarrowTerminalDoesNotPanic(t *testing.T) {
	for _, size := range [][2]int{{40, 10}, {60, 12}, {200, 60}} {
		m := fixture(t, size[0], size[1])
		for v := ViewOverview; v <= ViewLog; v++ {
			m.view = v
			m.layout()
			if m.View() == "" {
				t.Errorf("%dx%d %s rendered nothing", size[0], size[1], v)
			}
		}
	}
}

// TestSelectionSurvivesRefresh: the tables repopulate every second, and a cursor that jumped
// to the top each time would make the action keys unusable on a busy network.
func TestSelectionSurvivesRefresh(t *testing.T) {
	m := fixture(t, 120, 32)
	m.view = ViewAPs

	m.apTable.SetCursor(2)
	want := m.selectedBSSID()
	if want == "" {
		t.Fatal("no row selected")
	}

	for i := 0; i < 5; i++ {
		m.populate()
	}
	if got := m.selectedBSSID(); got != want {
		t.Errorf("selection moved across refreshes: %s → %s", want, got)
	}
}

// TestSelectionClampsWhenRowsDisappear covers an access point ageing out from under the
// cursor.
func TestSelectionClampsWhenRowsDisappear(t *testing.T) {
	m := fixture(t, 120, 32)
	m.view = ViewAPs
	m.apTable.SetCursor(4)

	m.data.aps = m.data.aps[:2]
	m.populate()

	if got := m.apTable.Cursor(); got > 1 {
		t.Errorf("cursor = %d with only 2 rows", got)
	}
	if m.selectedBSSID() == "" {
		t.Error("no row selected after the list shrank")
	}
}

// TestUnavailableCapabilityIsVisible: a capability the hardware cannot provide belongs on
// screen, not buried in a subcommand the operator would have to know to run.
func TestUnavailableCapabilityIsVisible(t *testing.T) {
	m := fixture(t, 120, 32)
	m.view = ViewOverview
	m.layout()

	out := m.View()
	if !strings.Contains(out, "no adapter supports AP mode") {
		t.Error("an unavailable capability is not shown on the overview")
	}
	if !strings.Contains(out, "rogue AP") {
		t.Error("the capability name is not shown")
	}
}

// TestEmptyStatesTellTheOperatorWhatToPress rather than showing a blank pane.
func TestEmptyStatesTellTheOperatorWhatToPress(t *testing.T) {
	m := fixture(t, 120, 32)
	m.data.aps = nil
	m.data.findings = nil
	m.populate()

	m.view = ViewAPs
	m.layout()
	if out := m.View(); !strings.Contains(out, "start capture") {
		t.Error("the empty access point tab does not say how to start capture")
	}

	m.view = ViewFindings
	m.layout()
	if out := m.View(); !strings.Contains(out, "classify") {
		t.Error("the empty findings tab does not say how to produce findings")
	}
}

// lipglossWidth measures a rendered line, ignoring ANSI escapes.
func lipglossWidth(s string) int {
	var (
		width int
		inEsc bool
	)
	for _, r := range s {
		switch {
		case r == '\x1b':
			inEsc = true
		case inEsc && r == 'm':
			inEsc = false
		case inEsc:
		default:
			width++
		}
	}
	return width
}

// TestDumpDashboard writes the rendered dashboard to stdout when asked.
//
// Not an assertion — a way to look at the thing. `go test -run TestDumpDashboard -v` with
// WARP_DUMP=1 prints every tab.
func TestDumpDashboard(t *testing.T) {
	if os.Getenv("WARP_DUMP") != "1" {
		t.Skip("set WARP_DUMP=1 to print the dashboard")
	}
	m := fixture(t, 118, 30)
	for v := ViewOverview; v <= ViewJobs; v++ {
		m.view = v
		m.layout()
		os.Stdout.WriteString("\n=== " + v.String() + " ===\n" + m.View() + "\n")
	}
}

// TestTableRowsDoNotWrap is the regression test for columns summing wider than their panel.
//
// A wrapped row does not overrun the terminal — the existing width check passes — it just
// spills each record across two lines and looks like a broken terminal. The symptom is
// visual, so the assertion has to be structural: the body must occupy exactly the height it
// was given, with no extra lines from wrapping.
func TestTableRowsDoNotWrap(t *testing.T) {
	for _, size := range [][2]int{{80, 24}, {100, 30}, {118, 30}, {160, 40}, {200, 50}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			m := fixture(t, size[0], size[1])

			for _, v := range []View{ViewAPs, ViewStations, ViewFindings, ViewJobs} {
				m.view = v
				m.layout()

				// The rounded border contributes the two outer lines, so a correctly fitted
				// panel is exactly bodyHeight tall. Anything more means a row wrapped.
				body := m.bodyView()
				got := len(strings.Split(body, "\n"))
				if got != m.bodyHeight {
					t.Errorf("%s body is %d lines, panel is %d — rows are wrapping",
						v, got, m.bodyHeight)
				}
			}
		})
	}
}

// TestResizingRepeatedlyDoesNotPanic drives one model through a sequence of window sizes,
// which is what a terminal actually does and what building a fresh model per size never
// exercises.
//
// Widening far enough to bring a dropped column back used to panic inside the table
// component: SetColumns re-renders immediately against rows that still carry the old cell
// count. It surfaced as a crash on resize with a stack trace and a dead dashboard.
func TestResizingRepeatedlyDoesNotPanic(t *testing.T) {
	m := fixture(t, 120, 32)

	// Down, up, and back through the widths where columns are shed and restored.
	widths := []int{120, 200, 62, 40, 200, 79, 118, 40, 160, 100, 30, 240}
	heights := []int{32, 60, 20, 10, 55, 24, 30, 8, 40, 28, 6, 70}

	for v := ViewOverview; v <= ViewLog; v++ {
		m.view = v
		for i, w := range widths {
			m.Update(tea.WindowSizeMsg{Width: w, Height: heights[i]})
			if out := m.View(); out == "" {
				t.Fatalf("%s at %dx%d rendered nothing", v, w, heights[i])
			}

			// Every table's rows must match its columns after each resize, which is the
			// invariant the component relies on and the one the panic came from.
			for name, pair := range map[string]struct {
				rows [][]string
				cols []string
			}{
				"aps":      {rowsOf(m.apTable.Rows()), m.apCols},
				"clients":  {rowsOf(m.staTable.Rows()), m.staCols},
				"findings": {rowsOf(m.findTable.Rows()), m.findCols},
				"jobs":     {rowsOf(m.jobTable.Rows()), m.jobCols},
			} {
				for _, row := range pair.rows {
					if len(row) != len(pair.cols) {
						t.Fatalf("%s at %d cols: row has %d cells, %d columns",
							name, w, len(row), len(pair.cols))
					}
				}
			}
		}
	}
}

// TestColouredCellsKeepTheirWidth.
//
// This is the bug that made SIGNAL, SECURITY and PMF look empty on a real terminal. The
// previous table measured cells with go-runewidth, which counts an SGR escape as printable:
// a seven-character coloured value measured nineteen columns, got truncated to nine, and what
// reached the screen was a fragment of the escape sequence and none of the value.
//
// Nothing in a test with no TTY reproduces it, because lipgloss suppresses colour when it
// cannot see one — so the escapes here are written out literally.
func TestColouredCellsKeepTheirWidth(t *testing.T) {
	green := func(s string) string { return "\x1b[38;5;48m" + s + "\x1b[0m" }

	tbl := &dataTable{}
	tbl.SetWidth(60)
	tbl.SetHeight(6)
	tbl.SetColumns([]column{
		{Title: "BSSID", Width: 17},
		{Title: "SIGNAL", Width: 9},
		{Title: "SECURITY", Width: 9},
	})
	tbl.SetRows([]row{
		{"a4:2b:8c:11:22:01", green("████░░ -42"), green("wpa_psk")},
		{"a4:2b:8c:11:22:02", "██░░░░ -71", "802.1X"},
	})

	for i, line := range strings.Split(tbl.View(), "\n") {
		if got := lipglossWidth(line); got > 60 {
			t.Errorf("line %d is %d columns wide, table is 60:\n%q", i, got, line)
		}
	}

	// The values themselves must survive rather than being cut to an escape fragment.
	plain := stripANSI(tbl.View())
	for _, want := range []string{"-42", "wpa_psk", "-71", "802.1X"} {
		if !strings.Contains(plain, want) {
			t.Errorf("%q was truncated out of the table:\n%s", want, plain)
		}
	}

	// And a coloured cell must occupy exactly the same width as an uncoloured one, or every
	// column to its right is pushed out of alignment.
	lines := strings.Split(tbl.View(), "\n")
	if len(lines) < 4 {
		t.Fatalf("expected a header, a rule and two rows, got %d lines", len(lines))
	}
	if a, b := lipglossWidth(lines[2]), lipglossWidth(lines[3]); a != b {
		t.Errorf("the coloured row is %d columns and the plain row is %d — they do not line up", a, b)
	}
}

// TestSelectedRowIsHighlightedWhole. The cursor has to be findable instantly on a screen with
// sixty access points on it, so the selected row is repainted as a block rather than left to
// each cell's own colour.
func TestSelectedRowIsHighlightedWhole(t *testing.T) {
	m := fixture(t, 140, 32)
	m.view = ViewAPs
	m.apTable.SetCursor(1)
	m.layout()

	lines := strings.Split(m.apTable.View(), "\n")
	if len(lines) < 4 {
		t.Fatalf("table rendered %d lines", len(lines))
	}
	// Row index 1 is the third line: header, rule, row 0, row 1.
	if !strings.Contains(lines[3], "\x1b[") && lipglossWidth(lines[3]) == 0 {
		t.Skip("no colour available in this environment")
	}
	if plain := stripANSI(lines[3]); !strings.Contains(plain, "a4:2b:8c:11:22:02") {
		t.Errorf("the selected row does not show its own content: %q", plain)
	}
}

// TestColumnsFillThePanel: leftover width is spent rather than left as a ragged gap between
// the last column and the border, which reads as a rendering fault.
func TestColumnsFillThePanel(t *testing.T) {
	for _, width := range []int{80, 100, 120, 160, 200, 240} {
		m := fixture(t, width, 40)

		for name, cols := range map[string][]column{
			"aps":      m.apTable.Columns(),
			"clients":  m.staTable.Columns(),
			"findings": m.findTable.Columns(),
			"jobs":     m.jobTable.Columns(),
		} {
			used := 0
			for _, c := range cols {
				used += c.Width + cellPadding
			}
			budget := m.apTable.Width()
			if used != budget {
				t.Errorf("%d cols: %s table uses %d of %d — %d columns of dead space",
					width, name, used, budget, budget-used)
			}
		}
	}
}

// TestTheTableFillsItsPanel.
//
// layout() sizes the table to the panel's content area and bodyView() then draws the panel.
// When the two disagreed — bodyView subtracted the border and padding a second time — the
// panel came out four columns narrower than the table inside it, and the last column was
// silently clipped against the border. On screen that reads as a column too narrow to hold
// its own values, with nothing to suggest the panel is at fault.
func TestTheTableFillsItsPanel(t *testing.T) {
	for _, width := range []int{80, 100, 118, 140, 200} {
		m := fixture(t, width, 30)
		m.view = ViewAPs
		m.layout()

		body := m.bodyView()
		lines := strings.Split(body, "\n")
		if len(lines) < 4 {
			t.Fatalf("%d cols: body rendered %d lines", width, len(lines))
		}

		// The whole body must be exactly the terminal width — no more (which wraps) and no
		// less (which leaves a gap beside the sidebar).
		for i, line := range lines {
			if got := lipglossWidth(line); got != width {
				t.Fatalf("%d cols: body line %d is %d wide:\n%s", width, i, got, line)
			}
		}

		// And the widest table row must survive into the panel intact rather than being cut.
		want := ""
		for _, r := range m.apTable.Rows() {
			if len(r) > 0 && strings.Contains(strings.Join(r, " "), "in scope") {
				want = "in scope"
			}
		}
		if want != "" && !strings.Contains(stripANSI(body), want) {
			t.Errorf("%d cols: the last column was clipped by the panel:\n%s", width, body)
		}
	}
}

// TestSecurityAndPMFSurviveAnEightyColumnTerminal.
//
// Whether management frames are protected decides whether deauthentication is worth
// attempting at all, and what the security is decides whether there is a handshake to
// capture. Both used to be shed on an 80-column terminal with the sidebar open, which is a
// completely ordinary size.
func TestSecurityAndPMFSurviveAnEightyColumnTerminal(t *testing.T) {
	for _, width := range []int{80, 100, 120, 160} {
		m := fixture(t, width, 30)
		m.view = ViewAPs
		m.layout()

		joined := strings.Join(m.apCols, ",")
		for _, want := range []string{"BSSID", "NETWORK", "SIGNAL", "SECURITY", "PMF"} {
			if !strings.Contains(joined, want) {
				t.Errorf("%d cols: %q was dropped (kept %s)", width, want, joined)
			}
		}
	}
}

func rowsOf(rows []row) [][]string {
	out := make([][]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r)
	}
	return out
}

// TestColumnsAreDroppedNotSqueezed: on a narrow terminal the layout sheds low-priority
// columns, and every row must then carry exactly the surviving cells or the table component
// panics.
func TestColumnsAreDroppedNotSqueezed(t *testing.T) {
	wide := fixture(t, 200, 40)
	wide.view = ViewAPs
	wide.layout()

	narrow := fixture(t, 62, 20)
	narrow.view = ViewAPs
	narrow.layout()

	if len(narrow.apCols) >= len(wide.apCols) {
		t.Errorf("narrow terminal kept %d columns, wide kept %d — nothing was shed",
			len(narrow.apCols), len(wide.apCols))
	}
	// The identifying columns survive whatever happens.
	joined := strings.Join(narrow.apCols, ",")
	for _, essential := range []string{"BSSID", "NETWORK"} {
		if !strings.Contains(joined, essential) {
			t.Errorf("column %q was dropped; it identifies the row", essential)
		}
	}
	// Rows must match the surviving columns exactly.
	for _, row := range narrow.apTable.Rows() {
		if len(row) != len(narrow.apCols) {
			t.Fatalf("row has %d cells but %d columns survived", len(row), len(narrow.apCols))
		}
	}
	// And selection still resolves by title rather than by position.
	if narrow.selectedBSSID() == "" {
		t.Error("selection broke after columns were dropped")
	}
}

// TestDiskUsageIsInTheHeaderAndTheBannerFiresAtNinety.
//
// A NUC in a closet that fills up stops capturing with nothing on screen to say so, and nobody
// re-runs a capture they believe already happened. Both figures stay in the header — how much
// this engagement has written, and how much room is left — and past 90% it becomes a line
// across the header rather than a colour on a number.
func TestDiskUsageIsInTheHeaderAndTheBannerFiresAtNinety(t *testing.T) {
	m := fixture(t, 120, 40)

	header := stripANSI(m.headerView())
	if !strings.Contains(header, "40%") {
		t.Errorf("the disk percentage is not in the header:\n%s", header)
	}
	if !strings.Contains(header, "3.0 GB") {
		t.Errorf("what this engagement has written is not in the header:\n%s", header)
	}
	if !strings.Contains(header, "150 GB") {
		t.Errorf("the space remaining is not in the header:\n%s", header)
	}
	if strings.Contains(header, "DISK") {
		t.Errorf("a healthy disk raised the banner:\n%s", header)
	}

	m.data.status.Disk = workspace.DiskUsage{
		Path:       "./engagement",
		TotalBytes: 250 << 30, UsedBytes: 231 << 30, FreeBytes: 19 << 30,
		UsedPercent: 92.4, EngagementBytes: 3 << 30, Level: workspace.DiskCritical,
	}

	header = stripANSI(m.headerView())
	if !strings.Contains(header, "DISK 92.4% FULL") {
		t.Errorf("the banner did not fire past 90%%:\n%s", header)
	}
	if !strings.Contains(header, "without an error") {
		t.Errorf("the banner does not say capture stops silently, which is the point:\n%s", header)
	}
}

// TestAMissingDiskFigureIsOmittedRatherThanShownAsZero: statfs can fail, and "0%" reads as an
// empty disk — the wrong direction to be wrong in.
func TestAMissingDiskFigureIsOmittedRatherThanShownAsZero(t *testing.T) {
	m := fixture(t, 120, 40)
	m.data.status.Disk = workspace.DiskUsage{}

	header := stripANSI(m.headerView())
	if strings.Contains(header, "disk") || strings.Contains(header, "DISK") {
		t.Errorf("a missing disk figure was rendered anyway:\n%s", header)
	}
}

// TestDetailValuesWrapRatherThanTruncate.
//
// In a 40-column pane "yes — name recovered from probe-response" used to be cut to
// "yes — name recovered from p". The cut fell exactly on the part carrying the information:
// *how* the name was recovered is the whole point of the line.
func TestDetailValuesWrapRatherThanTruncate(t *testing.T) {
	m := fixture(t, 120, 40)
	m.view = ViewAPs
	m.layout()

	// The fixture's hidden access point, decloaked.
	for i := range m.data.aps {
		if m.data.aps[i].ESSID == "" {
			m.data.aps[i].ESSID = "CORP-HIDDEN"
			m.data.aps[i].Cloaked = true
			m.data.aps[i].ESSIDSource = "probe-response"
			m.apTable.SetCursor(i)
			break
		}
	}
	m.populate()

	out := stripANSI(m.detailBody())
	if !strings.Contains(out, "probe-response") {
		t.Errorf("the recovery source was truncated away:\n%s", out)
	}
	if strings.Contains(out, "recovered from p\n") {
		t.Errorf("the value is still being cut mid-word:\n%s", out)
	}

	// Wrapping must not push a line past the pane.
	for i, line := range strings.Split(out, "\n") {
		if w := lipglossWidth(line); w > m.sidebarWidth-6 {
			t.Errorf("detail line %d is %d columns wide, pane content is %d: %q",
				i, w, m.sidebarWidth-6, line)
		}
	}
}

// TestWrapWordsHardBreaksAnOverlongToken: a 64-character hash has nowhere to break and must
// still not run off the panel.
func TestWrapWordsHardBreaksAnOverlongToken(t *testing.T) {
	long := strings.Repeat("a", 64)
	for _, line := range wrapWords("prefix "+long+" suffix", 20) {
		if lipglossWidth(line) > 20 {
			t.Errorf("wrapped line is %d columns wide, want <= 20: %q",
				lipglossWidth(line), line)
		}
	}
	joined := strings.Join(wrapWords("prefix "+long+" suffix", 20), "")
	if !strings.Contains(joined, long) {
		t.Error("the long token lost characters in the wrap")
	}
}

// TestTheNewTabsRender: Radios and Evil Twin both have to survive the empty state, which is
// what an operator sees first and the state most likely to be half-drawn.
func TestTheNewTabsRender(t *testing.T) {
	for _, v := range []View{ViewRadios, ViewEvilTwin} {
		t.Run(v.String(), func(t *testing.T) {
			m := fixture(t, 120, 32)
			m.view = v
			m.layout()

			if out := m.View(); out == "" {
				t.Fatal("rendered nothing")
			}
			// And with no data at all.
			m.data.radios = nil
			m.data.assigns = nil
			m.data.eap = daemon.EAPStatus{}
			m.layout()
			out := m.View()
			if out == "" {
				t.Fatal("the empty state rendered nothing")
			}
			for i, line := range strings.Split(out, "\n") {
				if w := lipglossWidth(line); w > 120 {
					t.Errorf("line %d is %d columns wide: %s", i, w, line)
				}
			}
		})
	}
}

// TestTheHelpOverlayNamesTheWalkthroughKey.
//
// The footer has room for the keys that apply to the current tab and no more, so `w` was
// discoverable by reading the source or by accident. It is one of the most useful keys here.
func TestTheHelpOverlayNamesTheWalkthroughKey(t *testing.T) {
	m := fixture(t, 120, 40)
	m.showHelp = true
	m.layout()

	out := stripANSI(m.View())
	for _, want := range []string{"walkthrough", "decloak", "Pixie Dust", "clone"} {
		if !strings.Contains(out, want) {
			t.Errorf("the key list does not mention %q", want)
		}
	}
	if !strings.Contains(stripANSI(m.footerView()), "keys") {
		t.Error("the footer does not advertise the key list")
	}
}

// TestTheEvilTwinTabShowsTheCertificateLibrary.
//
// The certificate is the pretext, so which one goes on the air is not a detail of starting the
// rogue — it is the decision that determines whether anything is captured at all.
func TestTheEvilTwinTabShowsTheCertificateLibrary(t *testing.T) {
	m := fixture(t, 140, 40)
	m.view = ViewEvilTwin
	m.data.certs = daemon.CertsListResult{
		Directory: "./engagement/certs",
		Networks: map[string][]certs.Entry{
			"CORP-8021X": {
				{
					ID: "a1b2c3d4e5f60718", ESSID: "CORP-8021X",
					Source: certs.SourceMimic, SourceDetail: certs.SourceMimic.Describe(),
					Subject: "CN=radius.corp.example ", Issuer: "CN=Corp Issuing CA",
					KeyAlgorithm: "RSA", KeyBits: 2048, Selected: true,
					NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
				},
				{
					ID: "0011223344556677", ESSID: "CORP-8021X",
					Source: certs.SourceSelfSigned, SourceDetail: certs.SourceSelfSigned.Describe(),
					Subject: "CN=radius.corp-8021x", Issuer: "CN=corp-8021x Root CA",
					KeyAlgorithm: "RSA", KeyBits: 2048,
					NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
				},
			},
		},
	}
	m.layout()

	out := stripANSI(m.View())
	for _, want := range []string{
		"Certificate library", "CORP-8021X", "a1b2c3d4e5f60718", "mimic", "self-signed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the tab does not show %q:\n%s", want, out)
		}
	}

	// The cursor moves, and the selection is a separate thing from where the cursor is.
	if r, ok := m.selectedCert(); !ok || r.entry.ID != "a1b2c3d4e5f60718" {
		t.Fatalf("cursor starts at %+v, want the first row", r)
	}
	m.certCursor = 1
	if r, _ := m.selectedCert(); r.entry.Selected {
		t.Error("the second row reports as selected; cursor and selection are different things")
	}

	// An empty library must say what to do about it rather than drawing nothing.
	m.data.certs = daemon.CertsListResult{}
	m.layout()
	out = stripANSI(m.View())
	if !strings.Contains(out, "Nothing prepared") {
		t.Errorf("an empty library renders:\n%s", out)
	}
	if !strings.Contains(out, "self-signed") {
		t.Errorf("the empty library does not say what would happen instead:\n%s", out)
	}
}
