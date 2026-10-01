package repl

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/lipgloss"

	"github.com/waffl3ss/warp/internal/build"
	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/eap/certs"
	"github.com/waffl3ss/warp/internal/eap/radius"
	"github.com/waffl3ss/warp/internal/hunt"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/store"
	"github.com/waffl3ss/warp/internal/workspace"
)

// Palette.
//
// 256-colour rather than truecolor: this runs over SSH into a wiring closet, and a NUC's
// serial console or a phone terminal will not always negotiate truecolor. Everything degrades
// legibly to 16 colours.
var (
	cText   = lipgloss.Color("252")
	cBright = lipgloss.Color("255")
	cMuted  = lipgloss.Color("244")
	cFaint  = lipgloss.Color("240")
	cLine   = lipgloss.Color("238")
	cPanel  = lipgloss.Color("235")

	cAccent = lipgloss.Color("48")  // in-scope, live, good
	cCyan   = lipgloss.Color("44")  // selection, headings
	cAmber  = lipgloss.Color("214") // degraded, warnings
	cRed    = lipgloss.Color("203") // failures, open networks
	cViolet = lipgloss.Color("141") // evidence tier
	cBlue   = lipgloss.Color("75")  // informational
)

var (
	sDim    = lipgloss.NewStyle().Foreground(cMuted)
	sFaint  = lipgloss.NewStyle().Foreground(cFaint)
	sText   = lipgloss.NewStyle().Foreground(cText)
	sBright = lipgloss.NewStyle().Foreground(cBright).Bold(true)
	sGood   = lipgloss.NewStyle().Foreground(cAccent)
	sWarn   = lipgloss.NewStyle().Foreground(cAmber)
	sErr    = lipgloss.NewStyle().Foreground(cRed)
	sKey    = lipgloss.NewStyle().Foreground(cCyan).Bold(true)
	sEcho   = lipgloss.NewStyle().Foreground(cBlue)
	sBlue   = lipgloss.NewStyle().Foreground(cBlue)
	sPrompt = lipgloss.NewStyle().Foreground(cAccent).Bold(true)

	sPanel = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(cLine).
		Padding(0, 1)

	sTableHead = lipgloss.NewStyle().Foreground(cFaint)
	// The selected row is painted as a block so the cursor is findable at a glance on a
	// screen with sixty access points on it.
	sTableSelected = lipgloss.NewStyle().
			Foreground(lipgloss.Color("232")).Background(cCyan).Bold(true)

	sTabActive = lipgloss.NewStyle().
			Foreground(lipgloss.Color("232")).Background(cCyan).Bold(true).Padding(0, 1)
	sTabIdle = lipgloss.NewStyle().Foreground(cMuted).Padding(0, 1)

	sFooter = lipgloss.NewStyle().Foreground(cMuted).Padding(0, 1)

	// Aliases kept so the command layer's existing styling keeps working.
	styleDim     = sDim
	styleGood    = sGood
	styleWarn    = sWarn
	styleErr     = sErr
	styleEcho    = sEcho
	stylePrompt  = sPrompt
	styleSection = sBright
	styleKey     = sKey
)

// layout sizes every component to the terminal.
func (m *Model) layout() {
	if m.width == 0 {
		return
	}

	headerH := lipgloss.Height(m.headerView())
	chrome := headerH + 1 /*tabs*/ + 1 /*footer*/ + 1 /*command*/
	bodyH := m.height - chrome
	if bodyH < 4 {
		bodyH = 4
	}
	m.bodyHeight = bodyH

	// The detail sidebar earns its width only once the table can still show every column
	// without it. Below that the table gets everything and detail goes to the log tab -
	// a sidebar bought by dropping SECURITY and PMF from the listing is a bad trade.
	m.sidebar = false
	tableW := m.width
	if !m.sidebarOff {
		// The sidebar takes a third, but it gives width back to the table before it gives up
		// entirely. A fixed one-third pane on a 120-column terminal left the table 76 columns
		// and pushed CH off the access-point list - and the channel is not something to trade
		// for a detail pane. Narrowed to 30 it fits both exactly.
		want := clamp(m.width/3, minSidebarWidth, 44)
		if avail := m.width - minTableWidth; want > avail {
			want = avail
		}
		if want >= minSidebarWidth {
			m.sidebar, m.sidebarWidth = true, want
			tableW = m.width - want
		}
	}

	// A panel's rendered width is Width()+2 for the border, and Width() itself includes the
	// two columns of padding. So content gets tableW-4.
	innerW, innerH := tableW-4, bodyH-2
	if innerW < 20 {
		innerW = 20
	}
	if innerH < 2 {
		innerH = 2
	}

	for _, t := range []*dataTable{
		&m.apTable, &m.staTable, &m.hashTable, &m.findTable, &m.jobTable,
	} {
		t.SetWidth(innerW)
		t.SetHeight(innerH)
	}
	m.fitColumns(innerW)

	if m.logView.Width == 0 {
		m.logView = viewport.New(m.width-4, bodyH-2)
	} else {
		m.logView.Width, m.logView.Height = m.width-4, bodyH-2
	}
	_ = innerH
	m.input.Width = m.width - 12
	m.refreshLog()

	// Rows are built from the surviving columns, so they must be rebuilt whenever the fit
	// changes - a resize that drops a column would otherwise leave mismatched rows behind.
	m.populate()
}

// cellPadding is what bubbles/table adds around every cell value.
const cellPadding = 2

// minTableWidth is the narrowest the access-point table can be and still carry every column.
//
// The sum of the minimum widths in fitColumns (68), plus cellPadding for each of the nine
// columns (18), plus the panel's border and padding (4). It was 79, which did not account for
// the per-cell padding at all, so the sidebar was granted its full width at terminal sizes
// where the table then had to start dropping columns to fit.
const minTableWidth = 90

// minSidebarWidth is the narrowest the detail pane is worth showing at. Below this a BSSID no
// longer fits on one line and the pane costs more than it gives.
const minSidebarWidth = 30

// fitColumns sizes each table to exactly the width available.
//
// The budget has to account for the per-cell padding the table component adds, or the columns
// sum wider than the panel and every row wraps onto a second line - which looks like a broken
// terminal rather than a layout bug. Low-priority columns are dropped entirely before any
// column is squeezed to uselessness.
func (m *Model) fitColumns(w int) {
	// Minimums are the narrowest width at which a column still says something. They are
	// deliberately tight: a column that gets dropped tells the operator nothing at all, which
	// is worse than one that is snug. PMF in particular used to fall off an 80-column table,
	// and whether management frames are protected decides whether deauthentication is even
	// worth attempting.
	m.apCols = m.setCols(&m.apTable, w, []flexColumn{
		{title: "BSSID", width: 17, priority: 0},
		{title: "NETWORK", width: 12, priority: 0, flex: true, max: 32},
		// Four columns for the band alone, twelve for "2.4 (ax/n/g)" when the terminal can
		// spare them. Fixed at twelve it pushed CH off an 80-column table, and the channel is
		// not something to trade away; fixed at four it clipped the generations off entirely,
		// which is the half saying whether this is a current radio or something that has been
		// on the wall since 2009. The cell renders to whichever width it got.
		{title: "BAND", width: 4, priority: 3, grow: true, max: 12},
		{title: "CH", width: 3, priority: 2},
		{title: "SIGNAL", width: 9, priority: 1, grow: true, max: 14},
		{title: "SECURITY", width: 9, priority: 1, grow: true, max: 14},
		{title: "PMF", width: 3, priority: 1},
		// Where the clients are is where the handshakes are, and an access point with none
		// has nothing to deauthenticate.
		{title: "CLI", width: 3, priority: 2},
		{title: "SCOPE", width: 8, priority: 2},
		// How recently it was heard. WARP keeps every AP it ever saw, so this is what tells a
		// live network apart from a stale entry - airodump's "still on the air" made explicit.
		{title: "SEEN", width: 5, priority: 1, grow: true, max: 9},
	})

	m.staCols = m.setCols(&m.staTable, w, []flexColumn{
		{title: "CLIENT", width: 17, priority: 0},
		{title: "ASSOCIATED", width: 17, priority: 2},
		// The name of the network it is on, joined by the daemon. A BSSID alone does not tell
		// the operator what they are looking at.
		{title: "NETWORK", width: 12, priority: 0, grow: true, max: 26},
		{title: "BAND", width: 4, priority: 3, grow: true, max: 12},
		{title: "SIGNAL", width: 9, priority: 1, grow: true, max: 14},
		{title: "PMF", width: 3, priority: 3},
		{title: "FRAMES", width: 6, priority: 3},
		{title: "PROBED FOR", width: 14, priority: 1, flex: true, max: 40},
	})

	// The hash line itself is the deliverable, so it gets the flexible column: an operator who
	// wants to eyeball or copy one should not have to go and read a root-owned file.
	m.hashCols = m.setCols(&m.hashTable, w, []flexColumn{
		{title: "KIND", width: 5, priority: 0},
		// Whether this belongs in the deliverable. Never dropped: an incidental capture that
		// reads as a result is how a neighbour's handshake ends up on the cracking rig.
		{title: "SCOPE", width: 5, priority: 0},
		{title: "NETWORK", width: 12, priority: 0, grow: true, max: 24},
		{title: "BSSID", width: 17, priority: 1},
		{title: "CLIENT", width: 17, priority: 3},
		{title: "CH", width: 3, priority: 3},
		{title: "AT", width: 8, priority: 2},
		{title: "SECRET", width: 16, priority: 2, flex: true, max: 64},
	})

	m.findCols = m.setCols(&m.findTable, w, []flexColumn{
		{title: "TIER", width: 9, priority: 0},
		{title: "FINDING", width: 18, priority: 0, flex: true, max: 60},
		{title: "ASSETS", width: 8, priority: 1},
	})

	m.jobCols = m.setCols(&m.jobTable, w, []flexColumn{
		{title: "#", width: 3, priority: 0},
		{title: "KIND", width: 9, priority: 0},
		{title: "TARGET", width: 17, priority: 1},
		{title: "STATE", width: 8, priority: 0},
		{title: "ELAPSED", width: 7, priority: 2},
		{title: "DETAIL", width: 16, priority: 2, flex: true, max: 56},
	})
}

// setCols applies a fitted column set to a table and returns the surviving titles.
//
// The titles are what rows are then built from: dropping a column without dropping the
// matching cell leaves the table with more values than columns, which panics inside the
// component rather than merely looking wrong.
func (m *Model) setCols(t *dataTable, w int, spec []flexColumn) []string {
	cols := fitTable(w, spec)

	// Remember what each column actually got. A cell that can render at more than one width -
	// BAND, which carries the 802.11 generations only when there is room - needs to know which
	// it is, and truncating a longer rendering leaves "2.4 (" on screen.
	if m.colWidth == nil {
		m.colWidth = map[string]int{}
	}
	for _, c := range cols {
		m.colWidth[c.Title] = c.Width
	}

	// Drop the rows before changing the columns. SetColumns re-renders the viewport
	// immediately, against rows that still have the old cell count - so widening the terminal
	// far enough to bring a dropped column back panics inside the component with an index out
	// of range. layout() repopulates from the new titles straight afterwards.
	t.SetRows(nil)
	t.SetColumns(cols)

	titles := make([]string, 0, len(cols))
	for _, c := range cols {
		titles = append(titles, c.Title)
	}
	return titles
}

// rowFor assembles a row containing exactly the columns that survived fitting.
func rowFor(titles []string, cells map[string]string) row {
	out := make(row, 0, len(titles))
	for _, t := range titles {
		out = append(out, cells[t])
	}
	return out
}

// flexColumn describes a column and how willing we are to lose it.
type flexColumn struct {
	title string
	// width is the column's minimum useful width.
	width int
	// priority 0 is essential; higher numbers are dropped first when space is short.
	priority int
	// flex marks the column that absorbs leftover width first - the one carrying the text
	// most likely to be cut off.
	flex bool
	// grow marks a column that will happily use spare width once the flex columns are capped,
	// rather than the surplus all landing on one column.
	grow bool
	// max caps a column so a very wide terminal does not leave one enormous column.
	max int
}

// fitTable turns column specs into concrete widths that fit the budget.
func fitTable(budget int, cols []flexColumn) []column {
	if budget < 10 {
		budget = 10
	}

	// Drop the least important columns until the minimums fit.
	keep := append([]flexColumn(nil), cols...)
	for {
		need := 0
		for _, c := range keep {
			need += c.width + cellPadding
		}
		if need <= budget || len(keep) <= 1 {
			break
		}

		worst, at := -1, -1
		for i, c := range keep {
			if c.flex {
				continue // never drop the column carrying the identifying text
			}
			if c.priority > worst {
				worst, at = c.priority, i
			}
		}
		if at < 0 {
			break
		}
		keep = append(keep[:at], keep[at+1:]...)
	}

	out := make([]column, 0, len(keep))
	for _, c := range keep {
		out = append(out, column{Title: c.title, Width: c.width})
	}

	// Spend the leftover width instead of leaving a ragged right edge beside a panel border.
	//
	// Flex columns take it first, up to their cap - they carry the text that actually gets cut
	// off. Whatever the caps leave over is then shared out among the growable columns, and the
	// last remainder goes to the final column so the table ends flush with the panel. A table
	// that stops two thirds of the way across reads as a rendering fault, not a design.
	used := func() int {
		n := 0
		for _, c := range out {
			n += c.Width + cellPadding
		}
		return n
	}

	for i, c := range keep {
		if !c.flex {
			continue
		}
		slack := budget - used()
		if slack <= 0 {
			break
		}
		want := out[i].Width + slack
		if c.max > 0 && want > c.max {
			want = c.max
		}
		out[i].Width = want
	}

	// Share the rest among the columns that benefit from room, a column at a time so the
	// growth is even rather than dumped on whichever happens to be first.
	growable := make([]int, 0, len(keep))
	for i, c := range keep {
		if c.grow || c.flex {
			growable = append(growable, i)
		}
	}
	for len(growable) > 0 && used() < budget {
		progressed := false
		for _, i := range growable {
			if used() >= budget {
				break
			}
			if keep[i].max > 0 && out[i].Width >= keep[i].max {
				continue
			}
			out[i].Width++
			progressed = true
		}
		if !progressed {
			break
		}
	}

	// Anything still unspent goes to the last column, so the right edge is flush.
	if slack := budget - used(); slack > 0 && len(out) > 0 {
		out[len(out)-1].Width += slack
	}
	return out
}

// View renders the whole dashboard.
func (m *Model) View() string {
	if !m.ready {
		return sDim.Render("  connecting to warpd…")
	}
	if m.quitting {
		return ""
	}
	return strings.Join([]string{
		m.headerView(),
		m.tabBar(),
		m.bodyView(),
		m.footerView(),
		m.commandView(),
	}, "\n")
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

func (m *Model) headerView() string {
	inner := m.width
	if inner < 24 {
		inner = 24
	}

	if m.data.err != nil {
		return sPanel.Width(inner - 2).BorderForeground(cRed).Render(
			sErr.Render("✖ warpd unreachable at "+m.socket) + "\n" +
				sDim.Render(truncate(m.data.err.Error(), inner-2)))
	}

	s := m.data.status

	// Which adapters are parked rather than sweeping.
	held := map[string]bool{}
	for _, id := range s.Recon.HeldRadios {
		held[id] = true
	}

	// One line per adapter, not one line for all of them.
	//
	// With two cards side by side on a single line there was no room for what each is
	// actually doing, and the operator's first question on a multi-adapter kit is exactly
	// that: which card is sweeping, which is transmitting, and what channel is each on.
	var cards []string
	for _, r := range s.Recon.Radios {
		ch := sFaint.Render("CH:  -")
		switch {
		case r.Channel != 0 && held[r.RadioID]:
			// Parked deliberately - during a deauthentication campaign, a solicitation or a
			// hunt. Distinguished from sweeping because "on ch6" means something different
			// when the radio is pinned there.
			ch = sWarn.Render(fmt.Sprintf("CH: %-3d", r.Channel)) + sFaint.Render(" locked")
		case r.Channel != 0:
			ch = sText.Render(fmt.Sprintf("CH: %-3d", r.Channel)) + sFaint.Render(" sweep")
		}

		// The interface name is the identity the operator tracks; the phy index is an internal
		// handle and is deliberately not shown.
		name := sBright.Render(pad(r.Ifname, 9))
		card := "  " + name + sDim.Render(pad(r.Role, 9)) + ch

		if r.Bands != "" {
			card += sFaint.Render("  " + r.Bands)
		}
		if spark := m.rateSpark(r.RadioID); spark != "" {
			card += "  " + sGood.Render(spark)
		}
		card += sFaint.Render("  " + humanCount(r.Capture.Frames) + " frames")
		if r.Capture.Dropped > 0 {
			card += sWarn.Render(fmt.Sprintf("  %s dropped", humanCount(r.Capture.Dropped)))
		}
		cards = append(cards, truncateToWidth(card, inner-2))
	}
	if len(cards) == 0 {
		cards = append(cards, "  "+sWarn.Render(
			"no radios assigned - press "+sKey.Render("r")+" to start capture"))
	}

	line1 := strings.Join(cards, "\n")

	// Line 2: the counters that matter, as labelled stats.
	stat := func(label string, v any, st lipgloss.Style) string {
		return st.Render(fmt.Sprint(v)) + " " + sFaint.Render(label)
	}
	walk := "walkthrough: " + s.Walkthrough
	if s.Walkthrough == "" {
		walk = sFaint.Render("walkthrough: none")
	}
	counters := []string{
		stat("APs", s.Recon.APs, sBright),
		stat("clients", s.Recon.Stations, sBright),
		stat("findings", len(m.data.findings), findingStyle(m.data.findings)),
		stat("pmkid", s.PMKIDHashes, hashStyle(s.PMKIDHashes)),
		stat("handshakes", s.HandshakeHashes, hashStyle(s.HandshakeHashes)),
		stat("jobs", s.RunningJobs, sBright),
	}
	// Disk sits with the counters because it is one: how much this engagement has produced,
	// and how much room is left to keep producing it.
	if disk := diskStat(s.Disk); disk != "" {
		counters = append(counters, disk)
	}
	line2 := strings.Join(counters, sFaint.Render("   ")) +
		sFaint.Render("   ▸ ") + sText.Render(walk)

	body := line1 + "\n" + line2

	// A running walkthrough gets its own prominent line, the way a live hunt does - an operator
	// needs to know a pass is being recorded and how to end it, from any tab. When none is running,
	// a dim line still says how to start one and how to list them, so the feature is discoverable.
	if s.Walkthrough != "" {
		body += "\n" + sBlue.Render("⦿ WALKTHROUGH "+s.Walkthrough) +
			sFaint.Render("  - press ") + sKey.Render("w") + sFaint.Render(" to stop, ") +
			sKey.Render(":walkthrough list") + sFaint.Render(" for the log")
	} else {
		body += "\n" + sFaint.Render("no walkthrough - press ") + sKey.Render("w") +
			sFaint.Render(" to start one, ") + sKey.Render(":walkthrough list") +
			sFaint.Render(" to see past passes")
	}

	// The banner. A NUC that fills up stops capturing without saying anything, and nobody goes
	// back for a capture they think already ran - so past 90% this is not a colour on a number,
	// it is a line across the header saying what is about to happen.
	if s.Disk.Critical() {
		body += "\n" + sErr.Render(truncate(fmt.Sprintf(
			"■ DISK %.1f%% FULL - %s left. Capture will stop without an error. Move %s of "+
				"engagement data off the box or free space now.",
			s.Disk.UsedPercent, workspace.HumanBytes(s.Disk.FreeBytes),
			workspace.HumanBytes(s.Disk.EngagementBytes)), inner-2))
	}

	if e := m.data.eap; e.Running && e.Session != nil {
		line := sErr.Render("◆ IMPERSONATING ") + sBright.Render(e.Session.ESSID) +
			sDim.Render(fmt.Sprintf("  ch%d %s  cert %s",
				e.Session.Channel, e.Session.Ifname, e.Session.CertSource))
		if n := len(e.Captured); n > 0 {
			line += sGood.Render(fmt.Sprintf("  %d captured", n))
		}
		if e.Stats.CertRefused > 0 {
			// The correct client behaviour. Shown so it is not mistaken for a fault.
			line += sFaint.Render(fmt.Sprintf("  %d refused the certificate",
				e.Stats.CertRefused))
		}
		body += "\n" + truncate(line, inner-2)
	}

	// A live hunt owns the header. Direction finding is done while walking, watching one
	// number - if the operator has to go and find it on another tab, the tool is not helping
	// with the thing they are actually doing.
	for _, h := range m.data.hunts {
		body += "\n" + m.huntLine(h, inner-2)
	}

	// A site-wide scope gets its own line rather than joining the warnings, because it is not
	// a degradation - it is what this engagement is authorized to do, and it has to be
	// impossible to be looking at this screen and not know it is in force.
	if s.SiteWide {
		body += "\n" + sErr.Render("■ SITE-WIDE SCOPE - every named network is authorized for "+
			"active work") + sDim.Render(truncate("  ("+s.SiteWideNote+")", inner-72))
	}

	// Anything blocking or degrading work goes on screen, not in a subcommand nobody runs.
	if w := m.warnings(); len(w) > 0 {
		body += "\n" + sWarn.Render("▲ "+truncate(strings.Join(w, "  ·  "), inner-2))
	}

	// The credit sits at the far right of the title line, faint. It should be findable if
	// someone looks for it and invisible while they are working - this line is read at a
	// glance for the workspace and the clock, and anything competing with those is in the way.
	// The status pill belongs on the title line beside the clock: "is it capturing" and "how
	// long has it been running" are one question, and the adapter lines below are the answer
	// to a different one.
	pill := sErr.Render("● IDLE")
	if s.Recon.Running {
		pill = sGood.Render("● CAPTURING")
	}
	title := sBright.Render(" "+build.Name+" ") + pill +
		sDim.Render("  "+s.Workspace+" · "+s.Uptime)
	credit := sFaint.Render(build.Credit())
	if gap := (inner - 4) - lipgloss.Width(title) - lipgloss.Width(credit); gap > 2 {
		title += strings.Repeat(" ", gap) + credit
	}

	return sPanel.Width(inner - 2).BorderForeground(cLine).Render(
		title + "\n" + body)
}

// diskStat renders the engagement size and remaining space as one header stat.
//
// Both numbers, because they answer different questions: how much this engagement has produced
// is what goes in a handover note and decides whether it fits on the drive it is being copied
// to; how much is left decides whether capture is about to stop. The percentage carries the
// colour, and it is the filesystem's, not WARP's share of it - a disk filled by something else
// stops the capture just as dead.
func diskStat(u workspace.DiskUsage) string {
	if u.TotalBytes == 0 {
		// statfs failed, or a status payload from a daemon that predates this. Better to show
		// nothing than a confident "0%" that means "unknown".
		return ""
	}

	st := sBright
	switch u.Level {
	case workspace.DiskCritical, workspace.DiskWarn:
		st = sErr
	case workspace.DiskWatch:
		st = sWarn
	}

	return st.Render(fmt.Sprintf("%.0f%%", u.UsedPercent)) +
		sFaint.Render(" disk ") +
		sText.Render(workspace.HumanBytes(u.EngagementBytes)) +
		sFaint.Render(" used · ") +
		sText.Render(workspace.HumanBytes(u.FreeBytes)) +
		sFaint.Render(" free")
}

// radiosBody is the adapter management view.
//
// The scheduler decides which card does what and the header shows the outcome one line at a
// time, but nothing said *why* - which adapter can do AP mode, which one injection was
// demonstrated on, which bands a card can even reach, what the survey pin costs. On a kit
// where one adapter is 2.4-only and the other is not, "the 5 GHz half of the estate is
// missing" and "that card cannot see it" are the same fact and neither was on screen.
func (m *Model) radiosBody() string {
	if len(m.data.radios) == 0 {
		return emptyBlock("No adapters.",
			"warpd found no wireless devices it can manage. Check "+
				sKey.Render("iw dev")+" and that warpd is running as root.")
	}

	// Which role each adapter is currently serving, and whether it is borrowed.
	assigned := map[string][]string{}
	for _, a := range m.data.assigns {
		label := string(a.Role)
		if a.Iftype != "" {
			label += " (" + a.Iftype + ")"
		}
		assigned[a.RadioID] = append(assigned[a.RadioID], label)
	}

	// Live capture counters, keyed by radio.
	live := map[string]daemon.RadioCaptureStats{}
	for _, r := range m.data.status.Recon.Radios {
		live[r.RadioID] = r
	}
	held := map[string]bool{}
	for _, id := range m.data.status.Recon.HeldRadios {
		held[id] = true
	}

	var b strings.Builder
	w := m.width - 8

	for i, r := range m.data.radios {
		point := "  "
		if i == m.radioCursor {
			point = sKey.Render("▸ ")
		}

		// Interface name is the identity shown; the phy index is an internal handle, omitted.
		head := point + sBright.Render(r.Ifname)
		if !r.Enabled {
			head += "  " + sWarn.Render("OFF")
		}
		if r.Driver != "" {
			head += sFaint.Render("  " + r.Driver)
		}
		if r.MAC != "" {
			head += sFaint.Render("  " + r.MAC)
		}
		if r.ID == m.data.status.SurveyRadio {
			// Worth saying: the survey radio is never lent, so it is the one adapter that
			// cannot be borrowed for a burst however busy the kit is.
			head += "  " + sBlue.Render("SURVEY - pinned for the engagement")
		}
		if r.PinnedChannel != 0 {
			head += "  " + sWarn.Render(fmt.Sprintf("PINNED ch%d", r.PinnedChannel))
		}
		b.WriteString("\n" + head + "\n")

		b.WriteString(kv("bands", strings.Join(r.Bands, ", "), w))
		b.WriteString(kv("channels", fmt.Sprintf("%d usable", r.Channels), w))
		b.WriteString(kvStyled("injection", r.Injection, w, injectionStyle(r.Injection)))
		b.WriteString(kv("modes", strings.Join(r.Iftypes, ", "), w))
		if r.APAndMonitor {
			b.WriteString(kv("concurrent", "AP and monitor at the same time", w))
		}

		if st, ok := live[r.ID]; ok {
			state := fmt.Sprintf("ch %d", st.Channel)
			switch {
			case st.Channel == 0:
				state = "no channel"
			case r.PinnedChannel != 0:
				state = fmt.Sprintf("ch %d - pinned by you, not sweeping", st.Channel)
			case held[r.ID] || st.Locked:
				state = fmt.Sprintf("ch %d - held for a campaign", st.Channel)
			default:
				state = fmt.Sprintf("ch %d sweeping", st.Channel)
			}
			b.WriteString(kv("now", state, w))
			b.WriteString(kv("captured", fmt.Sprintf("%s frames, %s dropped",
				humanCount(st.Capture.Frames), humanCount(st.Capture.Dropped)), w))
			if st.CycleFor != "" {
				b.WriteString(kv("sweep", st.CycleFor+" per full cycle", w))
			}
		}

		if roles, ok := assigned[r.ID]; ok {
			b.WriteString(kv("assigned", strings.Join(roles, ", "), w))
		} else {
			b.WriteString(kvStyled("assigned", "idle - not currently serving a role", w, sFaint))
		}

		// What this adapter can and cannot be asked to do, and why not.
		var can, cannot []string
		for _, rc := range r.Roles {
			if rc.Capable {
				can = append(can, string(rc.Role))
			} else {
				cannot = append(cannot, string(rc.Role)+": "+rc.Reason)
			}
		}
		if len(can) > 0 {
			b.WriteString(kv("can serve", strings.Join(can, ", "), w))
		}
		for _, c := range cannot {
			b.WriteString(kvStyled("unavailable", c, w, sFaint))
		}
	}

	b.WriteString("\n  " +
		sKey.Render("↑↓") + sDim.Render(" move  ") +
		sKey.Render("l") + sDim.Render(" pin to a channel  ") +
		sKey.Render("U") + sDim.Render(" back to the sweep") + "\n")
	return b.String()
}

func injectionStyle(state string) lipgloss.Style {
	switch {
	case strings.Contains(state, "verified"):
		return sGood
	case strings.Contains(state, "failed"):
		return sErr
	default:
		// Inconclusive. Not a failure: many drivers do not loop their own transmissions back,
		// and refusing to work on an adapter that injects fine is the worse outcome.
		return sWarn
	}
}

// section writes a heading and its body, indented consistently.
//
// The Evil Twin tab mixed kv() lines, which start at column 0, with hand-indented prose and
// list items that start at column 2 - so headings, values and notes each sat at a different
// margin and the eye had nothing to follow down the page. Everything under a heading is
// indented by two, including kv output.
func section(b *strings.Builder, title string, body string) {
	if title != "" {
		b.WriteString("\n" + sBright.Render(title) + "\n")
	}
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if line == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("  " + line + "\n")
	}
}

// evilTwinBody is the enterprise capture view: what is being impersonated, with what
// certificate, and what has come out of it.
func (m *Model) evilTwinBody() string {
	e := m.data.eap
	w := m.width - 8 // two columns of section indent on top of the panel's own

	var b strings.Builder

	if !e.Running || e.Session == nil {
		var idle strings.Builder
		for _, line := range wrapWords(
			"A rogue access point beacons a scoped network name with WARP's own RADIUS server "+
				"behind it, and records what supplicants are willing to send it. It wears the "+
				"target's BSSID as well as its name, because a client that has joined this "+
				"network before remembers both.", w) {
			idle.WriteString(sDim.Render(line) + "\n")
		}
		section(&b, "Not running", idle.String())

		var how strings.Builder
		how.WriteString(sKey.Render("S") + sDim.Render("  start it against the network under the cursor") + "\n")
		how.WriteString(sKey.Render("g") + sDim.Render("  build a certificate from fields you type") + "\n")
		how.WriteString(sKey.Render("C") + sDim.Render("  on the Access Points tab: clone the real certificate") + "\n")
		section(&b, "", how.String())

		b.WriteString(m.certLibrary(w))

		if len(e.Captured) > 0 {
			section(&b, "Captured earlier", m.credentialList(e, w))
		}
		return b.String()
	}

	s := e.Session

	var head strings.Builder
	head.WriteString(sErr.Render("◆ IMPERSONATING ") + sBright.Render(s.ESSID) + "\n\n")
	head.WriteString(kv("channel", fmt.Sprintf("%d", s.Channel), w))
	head.WriteString(kv("adapter", s.Ifname, w))
	if s.BSSID != "" {
		head.WriteString(kvStyled("bssid", s.BSSID+"  (cloned from the target)", w, sGood))
	} else {
		head.WriteString(kvStyled("bssid",
			"the adapter's own - a client that remembers the target's address sees a "+
				"different access point on a familiar name", w, sWarn))
	}
	head.WriteString(kv("running", time.Since(s.Started).Round(time.Second).String(), w))
	section(&b, "", head.String())

	var cert strings.Builder
	// Comparing rendered styles was the wrong test - lipgloss renders an empty string for an
	// empty input, so every source compared equal and a harvested mimic was reported as the
	// weak pretext it is not.
	weak := !strings.Contains(s.CertSource, "mimic") &&
		!strings.Contains(s.CertSource, "import") &&
		!strings.Contains(s.CertSource, "operator-supplied")
	certStyle := sGood
	if weak {
		certStyle = sWarn
	}
	cert.WriteString(kvStyled("source", s.CertSource, w, certStyle))
	if s.CertSubject != "" {
		cert.WriteString(kv("subject", s.CertSubject, w))
		cert.WriteString(kv("issuer", s.CertIssuer, w))
	}
	cert.WriteString(kv("sha256", s.Fingerprint, w))
	if weak {
		cert.WriteString("\n")
		for _, line := range wrapWords(
			"A self-signed certificate carrying none of the target's naming. Every client "+
				"that shows the user anything will refuse it. Clone the real one from the "+
				"Access Points tab, or press "+"g"+" to build one from what you know.", w) {
			cert.WriteString(sWarn.Render(line) + "\n")
		}
	}
	section(&b, "Certificate", cert.String())

	var rad strings.Builder
	rad.WriteString(kv("requests", fmt.Sprintf("%d", e.Stats.Requests), w))
	rad.WriteString(kv("challenges", fmt.Sprintf("%d", e.Stats.Challenges), w))
	rad.WriteString(kv("captured", fmt.Sprintf("%d", e.Stats.Captured), w))
	if e.Stats.CertRefused > 0 {
		// The correct client behaviour, and a finding in its own right. Said plainly so it is
		// never mistaken for a fault in the tool.
		rad.WriteString(kvStyled("refused",
			fmt.Sprintf("%d rejected the certificate - correct client behaviour, and a pass "+
				"for those devices", e.Stats.CertRefused), w, sGood))
	}
	section(&b, "RADIUS", rad.String())

	if len(e.Clients) > 0 {
		var cl strings.Builder
		for _, c := range e.Clients {
			cl.WriteString(sText.Render(c.MAC) +
				sFaint.Render("  since "+c.Since.Format("15:04:05")) + "\n")
		}
		section(&b, "Associated", cl.String())
	}

	section(&b, "Credentials", m.credentialList(e, w))

	b.WriteString(m.certLibrary(w))
	section(&b, "", sKey.Render("X")+sDim.Render(
		"  stop it. A running rogue keeps the certificate it started with.")+"\n")
	return b.String()
}

// credentialList renders what the RADIUS server has taken, unredacted.
func (m *Model) credentialList(e daemon.EAPStatus, w int) string {
	if len(e.Captured) == 0 {
		return sDim.Render("nothing yet - a supplicant has to try to join\n")
	}

	var b strings.Builder
	for _, o := range e.Captured {
		b.WriteString(sGood.Render(identityOfOutcome(o)))
		if o.OuterIdentity != "" && o.OuterIdentity != o.InnerIdentity {
			// Identity privacy: the outer name is what anyone listening sees, the inner one is
			// the account. The difference is itself worth reporting.
			b.WriteString(sFaint.Render("  outer: " + o.OuterIdentity))
		}
		b.WriteString(sFaint.Render("  " + o.Method.String()))
		b.WriteString("\n")
		if o.HashLine != "" {
			for _, line := range wrapWords(o.HashLine, w-2) {
				b.WriteString("  " + sText.Render(line) + "\n")
			}
		}
	}
	if e.CredsFile != "" {
		b.WriteString(sFaint.Render("→ " + e.CredsFile + "  (hashcat -m 5500)\n"))
	}
	return b.String()
}

// certFormBody renders the certificate wizard.
func (m *Model) certFormBody() string {
	var b strings.Builder
	w := m.width - 6

	b.WriteString("\n")
	for _, line := range wrapWords(
		"Only the common name is required - it is what a trust prompt shows. The issuing "+
			"authority matters nearly as much: most clients that prompt a human display it, "+
			"and a certificate issued by an authority with its own name reads as self-signed "+
			"in every viewer.", w-2) {
		b.WriteString("  " + sDim.Render(line) + "\n")
	}
	b.WriteString("\n")

	// The label column is sized to the longest label so the values line up. Ragged fields are
	// hard to read back, and reading them back is what the operator is doing before pressing
	// enter on something that goes on the air.
	labelW := 0
	for _, f := range m.form.fields {
		if n := lipgloss.Width(f.label); n > labelW {
			labelW = n
		}
	}

	for i, f := range m.form.fields {
		point, style := "  ", sText
		if i == m.form.cursor {
			point, style = sKey.Render("▸ "), sBright
		}

		label := f.label
		if f.required {
			label += " *"
		}

		value := f.value
		switch {
		case value == "" && i == m.form.cursor && f.placeholder != "":
			value = sFaint.Render(f.placeholder)
		case value == "" && f.placeholder != "":
			value = sFaint.Render(f.placeholder)
		case value == "":
			value = sFaint.Render("-")
		default:
			value = style.Render(value)
		}
		if i == m.form.cursor {
			value += sKey.Render("█")
		}

		b.WriteString(point + sFaint.Render(fmt.Sprintf("%-*s", labelW+2, label)) + value + "\n")
	}

	if m.form.err != "" {
		b.WriteString("\n")
		for _, line := range wrapWords(m.form.err, w-2) {
			b.WriteString("  " + sErr.Render(line) + "\n")
		}
	}

	b.WriteString("\n  " +
		sKey.Render("↑↓") + sDim.Render(" field  ") +
		sKey.Render("⏎") + sDim.Render(" next, submit on the last  ") +
		sKey.Render("ctrl+g") + sDim.Render(" submit now  ") +
		sKey.Render("ctrl+u") + sDim.Render(" clear  ") +
		sKey.Render("esc") + sDim.Render(" cancel") + "\n")
	return b.String()
}

// certRow is one line of the certificate library, flattened across networks so the cursor can
// walk it.
type certRow struct {
	essid string
	entry certs.Entry
}

// certRows flattens the library in the order it is displayed.
func (m *Model) certRows() []certRow {
	names := make([]string, 0, len(m.data.certs.Networks))
	for n := range m.data.certs.Networks {
		names = append(names, n)
	}
	sort.Strings(names)

	var out []certRow
	for _, n := range names {
		for _, e := range m.data.certs.Networks[n] {
			out = append(out, certRow{essid: n, entry: e})
		}
	}
	return out
}

// selectedCert returns the certificate under the cursor.
func (m *Model) selectedCert() (certRow, bool) {
	rows := m.certRows()
	if len(rows) == 0 {
		return certRow{}, false
	}
	if m.certCursor >= len(rows) {
		m.certCursor = len(rows) - 1
	}
	if m.certCursor < 0 {
		m.certCursor = 0
	}
	return rows[m.certCursor], true
}

// certLibrary renders every certificate the engagement could put on the air.
//
// The certificate is the pretext, so this is not a detail of starting the rogue - it is the
// decision that determines whether anything is captured at all. Which one is selected, where
// each came from and what a client will see are all on one screen.
func (m *Model) certLibrary(w int) string {
	var body strings.Builder

	rows := m.certRows()
	if len(rows) == 0 {
		for _, line := range wrapWords(
			"Nothing prepared. The rogue would generate a self-signed certificate, which "+
				"every client that shows the user anything will refuse.", w) {
			body.WriteString(sDim.Render(line) + "\n")
		}
		body.WriteString("\n")
		body.WriteString(sKey.Render("C") +
			sDim.Render("  on the Access Points tab: clone an enterprise network's real one") + "\n")
		body.WriteString(sKey.Render("g") +
			sDim.Render("  here: build one from fields you type") + "\n")

		var out strings.Builder
		section(&out, "Certificate library", body.String())
		return out.String()
	}

	lastESSID := ""
	for i, r := range rows {
		if r.essid != lastESSID {
			if lastESSID != "" {
				body.WriteString("\n")
			}
			body.WriteString(sText.Render(r.essid) + "\n")
			lastESSID = r.essid
		}

		// The cursor and the selection are different things and both have to be visible: one
		// is where you are, the other is what goes on the air.
		point := "  "
		if i == m.certCursor {
			point = sKey.Render("▸ ")
		}
		mark := sFaint.Render("·")
		if r.entry.Selected {
			mark = sGood.Render("●")
		}

		line := point + mark + " " + sFaint.Render(r.entry.ID) + " " +
			certSourceStyle(r.entry.Source).Render(pad(string(r.entry.Source), 12)) +
			sText.Render(truncate(r.entry.Subject, maxInt(w-42, 20)))
		if r.entry.Expired {
			line += sErr.Render("  EXPIRED")
		}
		body.WriteString(line + "\n")

		// Detail for the row under the cursor only, so a library of six does not fill the pane.
		if i == m.certCursor {
			d := w - 4
			body.WriteString("    " + strings.TrimRight(
				strings.ReplaceAll(kv("issuer", r.entry.Issuer, d), "\n", "\n    "), " "))
			if len(r.entry.SANs) > 0 {
				body.WriteString("    " + strings.TrimRight(
					strings.ReplaceAll(kv("sans", strings.Join(r.entry.SANs, ", "), d), "\n", "\n    "), " "))
			}
			body.WriteString("    " + strings.TrimRight(
				strings.ReplaceAll(kv("valid", r.entry.NotBefore.Format("2006-01-02")+" → "+
					r.entry.NotAfter.Format("2006-01-02"), d), "\n", "\n    "), " "))
			body.WriteString("    " + strings.TrimRight(
				strings.ReplaceAll(kv("key", fmt.Sprintf("%s-%d",
					r.entry.KeyAlgorithm, r.entry.KeyBits), d), "\n", "\n    "), " "))
		}
	}

	body.WriteString("\n" +
		sKey.Render("↑↓") + sDim.Render(" move  ") +
		sKey.Render("⏎") + sDim.Render(" use this one  ") +
		sKey.Render("g") + sDim.Render(" generate  ") +
		sKey.Render("S") + sDim.Render(" start  ") +
		sKey.Render("X") + sDim.Render(" stop") + "\n")

	var out strings.Builder
	section(&out, "Certificate library", body.String())
	return out.String()
}

func certSourceStyle(src certs.Source) lipgloss.Style {
	switch src {
	case certs.SourceMimic:
		return sGood
	case certs.SourceImported:
		return sBlue
	case certs.SourceGenerated:
		return sText
	default:
		return sWarn
	}
}

// helpBody lists every key, grouped by what it is for.
//
// The footer has room for the handful that apply to the current tab and no more, so everything
// else was discoverable only by reading the source or by accident. `w` to open a walkthrough is
// the clearest example: it is one of the most useful keys here and nothing on screen mentioned
// it.
func (m *Model) helpBody() string {
	type entry struct{ key, what string }
	groups := []struct {
		title   string
		entries []entry
	}{
		{"Moving around", []entry{
			{"1-9", "switch tab"},
			{"tab / shift+tab", "next / previous tab"},
			{"↑ ↓", "move the cursor"},
			{"enter", "full detail for the selected row, into the Log tab"},
			{"v", "hide the detail pane for a wider listing, and back"},
			{"o / O", "sort by the next column / reverse it"},
			{"p", "pause the display - capture keeps running"},
			{"y", "print the current tab as plain text, to select and copy"},
			{"?", "this list"},
		}},
		{"On an access point", []entry{
			{"s", "solicit a PMKID"},
			{"d", "deauthenticate every client on it"},
			{"u", "decloak - recover a hidden network's name"},
			{"P", "WPS Pixie Dust - one exchange, PIN recovered offline"},
			{"C", "clone the RADIUS certificate of an enterprise network"},
			{"a", "add this network's name to scope"},
			{"x", "exclude this BSSID from active work"},
			{"m", "mark / unmark this BSSID as a potential rogue"},
		}},
		{"On a client", []entry{
			{"d", "deauthenticate it from the access point it is on"},
			{"h", "hunt it"},
		}},
		{"On the Radios tab", []entry{
			{"↑ ↓", "move between adapters"},
			{"l", "pin this adapter to a channel instead of sweeping"},
			{"U", "hand it back to the channel plan"},
		}},
		{"On the Evil Twin tab", []entry{
			{"↑ ↓", "move through the certificate library"},
			{"enter", "use the certificate under the cursor"},
			{"g", "generate a certificate from fields you type"},
			{"S / X", "start / stop the rogue access point"},
		}},
		{"Anywhere", []entry{
			{"r", "start / stop recon"},
			{"h", "hunt the selected device, or stop hunting it"},
			{"H", "stop every hunt"},
			{"c", "re-run rogue classification"},
			{"w", "start a walkthrough - tags observations, resets the radios at the boundary"},
			{"e", "regenerate the CSV projections"},
			{"R", "write the engagement report (report.md)"},
			{"k", "kill the selected job (Jobs tab)"},
			{":", "command prompt, with completion over discovered addresses"},
			{"q", "detach - stops nothing, the daemon owns the radios"},
		}},
	}

	var b strings.Builder
	for _, g := range groups {
		b.WriteString("\n" + sBright.Render(g.title) + "\n")
		for _, e := range g.entries {
			b.WriteString("  " + sKey.Render(fmt.Sprintf("%-16s", e.key)) +
				sDim.Render(e.what) + "\n")
		}
	}
	return b.String()
}

// huntLine renders one live hunt: current signal, peak, and a trend bar to walk.
func (m *Model) huntLine(h hunt.State, w int) string {
	name := h.Target.Addr.String()
	if h.Target.ESSID != "" {
		name += " " + h.Target.ESSID
	}

	// The locked channel and radio confirm WARP is parked on the target rather than sweeping -
	// the whole point of a hunt is that it does not move off the target's channel.
	lock := ""
	if h.Target.Channel != 0 {
		lock = sFaint.Render(fmt.Sprintf("  ch%d", h.Target.Channel))
		if h.Target.RadioID != "" {
			lock += sFaint.Render("·" + m.ifnameFor(h.Target.RadioID))
		}
	}

	if !h.HasSignal {
		return sWarn.Render("◎ HUNTING "+name) + lock +
			sFaint.Render("  no frames yet - the target may have gone quiet, or be on another channel")
	}

	cur := sBright.Render(fmt.Sprintf("%4d dBm", h.Current))
	if h.Stale {
		cur = sFaint.Render(fmt.Sprintf("%4d dBm", h.Current)) + sWarn.Render(" stale")
	}

	line := sGood.Render("◎ HUNTING ") + sText.Render(name) + lock + "  " + cur +
		"  " + signalBar(h.Current, true, 16)

	if t := huntTrendWord(h.Sparkline); t != "" {
		line += "  " + t
	}
	if h.HasPeak {
		line += sFaint.Render(fmt.Sprintf("  peak %d dBm %s ago",
			h.Peak, h.PeakAge.Round(time.Second)))
	}
	if spark := sparkFromRSSI(h.Sparkline); spark != "" {
		line += "  " + sGood.Render(spark)
	}
	line += sFaint.Render(fmt.Sprintf("  %.0f/s", h.PacketsPerSec))
	return truncate(line, w)
}

// huntTrendWord reads the recent sparkline and says whether the operator is getting warmer,
// colder, or holding steady - the one thing they need while walking a gradient.
func huntTrendWord(spark []int8) string {
	if len(spark) < 6 {
		return ""
	}
	// Average the most recent few samples against the few before - smooths the several-dB jitter so
	// it does not flip constantly, but stays short enough to react to a walk. 3 dB deadband.
	win := len(spark) / 2
	if win > 5 {
		win = 5
	}
	avg := func(a []int8) float64 {
		var s int
		for _, v := range a {
			s += int(v)
		}
		return float64(s) / float64(len(a))
	}
	newer := avg(spark[len(spark)-win:])
	older := avg(spark[len(spark)-2*win : len(spark)-win])
	switch delta := newer - older; {
	case delta >= 3:
		return sGood.Render("▲ warmer")
	case delta <= -3:
		return sWarn.Render("▼ colder")
	default:
		return sFaint.Render("▬ steady")
	}
}

// sparkFromRSSI turns the hunt trend into a sparkline. Walking the gradient means watching
// this go up, which is easier to read at a glance than a number that jitters.
func sparkFromRSSI(vals []int8) string {
	if len(vals) < 2 {
		return ""
	}
	f := make([]float64, len(vals))
	for i, v := range vals {
		f[i] = float64(v)
	}
	return sparkline(f)
}

func (m *Model) warnings() []string {
	var out []string
	s := m.data.status

	if len(s.PendingAcks) > 0 {
		out = append(out, fmt.Sprintf("%d generic ESSID(s) unacknowledged - active work blocked",
			len(s.PendingAcks)))
	}
	if n := s.Recon.Handshake.PendingESSID; n > 0 {
		out = append(out, fmt.Sprintf("%d hash(es) held pending an ESSID", n))
	}
	for _, c := range s.Capabilities {
		if !c.Available && c.Reason != "" {
			out = append(out, c.Name+": "+c.Reason)
		}
	}
	return out
}

// sparkWidth bounds how many samples the header sparkline draws.
//
// Without a cap it grew one glyph per poll up to rateHistory, and every new glyph shoved the
// "N frames" counter further right until a byte-truncating header clipped it off entirely. A
// fixed width keeps the counter in the same place poll to poll.
const sparkWidth = 12

// rateSpark renders a sparkline of a radio's recent capture rate.
func (m *Model) rateSpark(radioID string) string {
	h := m.rate[radioID]
	if len(h) < 2 {
		return ""
	}
	if len(h) > sparkWidth {
		h = h[len(h)-sparkWidth:]
	}
	return sparkline(h)
}

// ---------------------------------------------------------------------------
// Tabs
// ---------------------------------------------------------------------------

// tabGlyphs must stay at least as long as viewNames; the fallback keeps a new tab from
// panicking the whole dashboard if it does not.
var tabGlyphs = []string{"①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨"}

func tabGlyph(i int) string {
	if i < len(tabGlyphs) {
		return tabGlyphs[i]
	}
	return fmt.Sprint(i + 1)
}

// viewShort is each tab's name when the full set will not fit. Same order as viewNames.
var viewShort = []string{
	"OVER", "APS", "CLI", "CREDS", "FIND", "JOBS", "RADIO", "TWIN", "LOG",
}

func (m *Model) tabBar() string {
	// Three tiers, narrowing rather than collapsing.
	//
	// It used to go straight from full names to bare circled numbers, which on a 110-column
	// terminal with nine tabs is what happened every time - and a row of ①②③ with no words on
	// it tells an operator nothing about where they are or what is on the other tabs. The
	// middle tier keeps a readable name, and even the narrowest keeps the *current* tab's
	// name, because that is the one fact the bar has to carry.
	build := func(label func(i int) string) string {
		var parts []string
		for i := range viewNames {
			if View(i) == m.view {
				parts = append(parts, sTabActive.Render(label(i)))
			} else {
				parts = append(parts, sTabIdle.Render(label(i)))
			}
		}
		return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
	}

	withCount := func(i int, name string) string {
		label := tabGlyph(i) + " " + name
		if n := m.tabCount(View(i)); n >= 0 {
			label += " " + fmt.Sprint(n)
		}
		return label
	}

	full := build(func(i int) string { return withCount(i, strings.ToUpper(viewNames[i])) })
	if lipgloss.Width(full) <= m.width {
		return full
	}

	short := build(func(i int) string { return withCount(i, viewShort[i]) })
	if lipgloss.Width(short) <= m.width {
		return short
	}

	return build(func(i int) string {
		if View(i) == m.view {
			return tabGlyph(i) + " " + viewShort[i]
		}
		return tabGlyph(i)
	})
}

func (m *Model) tabCount(v View) int {
	switch v {
	case ViewAPs:
		return len(m.data.aps)
	case ViewStations:
		return len(m.data.stations)
	case ViewCredentials:
		return len(m.data.hashes.Hashes) + len(m.data.eap.Captured) + len(m.data.hashes.WPSKeys)
	case ViewFindings:
		return len(m.data.findings)
	case ViewJobs:
		return len(m.data.jobs)
	default:
		return -1
	}
}

// ---------------------------------------------------------------------------
// Body
// ---------------------------------------------------------------------------

func (m *Model) bodyView() string {
	if m.showHelp {
		return m.panel("Keys - press ? or esc to close", m.helpBody(), m.width, m.bodyHeight)
	}
	if m.view == ViewOverview {
		return m.panel("Overview", m.overviewBody(), m.width, m.bodyHeight)
	}
	if m.view == ViewLog {
		return m.panel("Event log", m.logView.View(), m.width, m.bodyHeight)
	}
	if m.view == ViewRadios {
		return m.panel("Radios", m.radiosBody(), m.width, m.bodyHeight)
	}
	if m.view == ViewEvilTwin {
		if m.form.active {
			return m.panel("Generate a certificate for "+m.form.essid,
				m.certFormBody(), m.width, m.bodyHeight)
		}
		return m.panel("Evil twin", m.evilTwinBody(), m.width, m.bodyHeight)
	}

	var (
		title string
		inner string
		empty bool
	)
	switch m.view {
	case ViewAPs:
		title, inner, empty = "Access points", m.apTable.View(), len(m.data.aps) == 0
		if empty {
			inner = emptyBlock("Nothing on the air yet.",
				"Press "+sKey.Render("r")+" to start capture, then give it a few seconds.")
		}
	case ViewStations:
		title, inner, empty = "Client stations", m.staTable.View(), len(m.data.stations) == 0
		if empty {
			inner = emptyBlock("No client stations seen yet.",
				"Stations appear as they probe or associate.")
		}
	case ViewCredentials:
		title = "Credentials - PSK material (22000), enterprise (5500), WPS keys"
		inner, empty = m.hashTable.View(),
			len(m.data.hashes.Hashes)+len(m.data.eap.Captured)+len(m.data.hashes.WPSKeys) == 0
		if empty {
			hint := "Nothing captured yet."
			why := "PMKID needs an access point that offers one - press " +
				sKey.Render("s") + " on a scoped AP.\n" +
				"A handshake needs a client to join - press " + sKey.Render("d") +
				" on an AP to knock its clients off."
			if n := m.data.hashes.PendingESSID; n > 0 {
				hint = fmt.Sprintf("%d handshake(s) held, waiting for a network name.", n)
				why = "A 22000 line needs the ESSID. These are emitted the moment it is learned -\n" +
					"keep capturing, or press " + sKey.Render("d") + " to make a client reassociate."
			}
			inner = emptyBlock(hint, why)
		}

	case ViewFindings:
		title, inner, empty = "Findings", m.findTable.View(), len(m.data.findings) == 0
		if empty {
			inner = emptyBlock("No findings yet.",
				"Press "+sKey.Render("c")+" to classify what has been observed.")
		}
	case ViewJobs:
		title, inner, empty = "Background jobs", m.jobTable.View(), len(m.data.jobs) == 0
		if empty {
			inner = emptyBlock("No jobs.", "Attacks run in the background and appear here.")
		}
	}

	// panel takes a *total* width and subtracts its own border and padding. layout() already
	// sized the table to that content area, so subtracting the chrome again here made the
	// panel four columns narrower than the table inside it - and the last column was clipped
	// against the border, which looks exactly like a column that is too narrow.
	tableW := m.width
	if m.sidebar {
		tableW = m.width - m.sidebarWidth
	}
	left := m.panel(title, inner, tableW, m.bodyHeight)
	if !m.sidebar {
		return left
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, left,
		m.panel("Detail", m.detailBody(), m.sidebarWidth, m.bodyHeight))
}

// panel wraps content in a titled rounded box.
//
// w is the total rendered width. lipgloss adds the border outside Width() and counts padding
// inside it, so the style width is w-2 and the content area is w-4. Getting this wrong makes
// every table row wrap onto a second line, which reads as a broken terminal rather than a
// layout bug.
func (m *Model) panel(title, content string, w, h int) string {
	if w < 12 {
		w = 12
	}
	styleW := w - 2        // the border sits outside Width()
	contentW := styleW - 2 // Width() includes the two columns of padding

	inner := h - 2
	if inner < 1 {
		inner = 1
	}

	// Clamp every line to the content width, ANSI-aware. Callers build lines from styled
	// fragments whose byte length bears no relation to their rendered width, so the panel
	// enforces the bound itself rather than trusting each caller to have got it right.
	clamp := lipgloss.NewStyle().MaxWidth(contentW)

	lines := strings.Split(content, "\n")
	for i := range lines {
		lines[i] = clamp.Render(lines[i])
	}
	if len(lines) > inner-1 {
		lines = lines[:inner-1]
	}
	for len(lines) < inner-1 {
		lines = append(lines, "")
	}

	return sPanel.Width(styleW).Height(inner).Render(
		clamp.Render(sDim.Render(title)) + "\n" + strings.Join(lines, "\n"))
}

func emptyBlock(title, hint string) string {
	return "\n  " + sBright.Render(title) + "\n  " + sDim.Render(hint)
}

// detailBody renders the sidebar for the selected row.
//
// A sidebar rather than a modal: the operator is comparing rows, and a popup that has to be
// dismissed to move the cursor makes that impossible.
func (m *Model) detailBody() string {
	w := m.sidebarWidth - 6

	switch m.view {
	case ViewAPs:
		ap, ok := m.selectedAP()
		if !ok {
			return sDim.Render("\n  nothing selected")
		}
		return m.apDetail(ap, w)

	case ViewStations:
		st, ok := m.selectedStation()
		if !ok {
			return sDim.Render("\n  nothing selected")
		}
		return m.stationDetail(st, w)

	case ViewFindings:
		g, ok := m.selectedFindingGroup()
		if !ok {
			return sDim.Render("\n  nothing selected")
		}
		return m.findingDetail(g, w)

	case ViewJobs:
		if row := m.jobTable.SelectedRow(); len(row) > 3 {
			return "\n" + kv("job", row[0], w) + kv("kind", row[1], w) +
				kv("target", row[2], w) + kv("state", row[3], w)
		}
	}
	return ""
}

func (m *Model) apDetail(ap daemon.APView, w int) string {
	var b strings.Builder

	b.WriteString("\n" + sBright.Render(ap.BSSID.String()) + "\n")
	b.WriteString(networkStyle(ap).Render(orHidden(ap.ESSID)) + "\n\n")

	channel := fmt.Sprintf("%d", ap.Channel)
	if ap.Band != "" {
		channel += " · " + ap.Band
	}
	b.WriteString(kv("channel", channel, w))
	b.WriteString(kv("signal", rssiCell(ap.LastRSSI, ap.HasRSSI)+" dBm live", w))
	b.WriteString(sFaint.Render("           ") + signalBar(ap.LastRSSI, ap.HasRSSI, minInt(w-12, 16)) + "\n")
	if ap.HasRSSI {
		b.WriteString(kv("peak", rssiCell(ap.BestRSSI, ap.HasRSSI)+" dBm", w))
	}
	b.WriteString(kv("security", ap.Security.Describe(), w))
	b.WriteString(kv("pmf", pmfDetail(ap.Security.MFP), w))
	b.WriteString(kv("scope", scopeCell(ap), w))
	if ap.Cloaked && ap.ESSID != "" {
		b.WriteString(kvStyled("cloaked",
			"yes - name recovered from "+orDefault(ap.ESSIDSource, "observed traffic"),
			w, sWarn))
	}
	b.WriteString(kv("vendor", ap.OUI, w))
	b.WriteString(kv("beacons", humanCount(ap.Beacons), w))
	b.WriteString(kv("first seen", ap.FirstSeen.Format("15:04:05"), w))
	b.WriteString(kv("last seen", ap.LastSeen.Format("15:04:05"), w))

	// Findings on this device, so the evidence and the label sit side by side.
	var mine []store.Finding
	for _, f := range m.data.findings {
		if f.BSSID == ap.BSSID.String() {
			mine = append(mine, f)
		}
	}
	if len(mine) > 0 {
		b.WriteString("\n" + sDim.Render("findings") + "\n")
		for _, f := range mine {
			b.WriteString(tierStyle(f.Tier).Render("▪ "+truncate(f.Label, w)) + "\n")
		}
	}

	// Stations associated here.
	var stations []string
	for _, st := range m.data.stations {
		if st.BSSID == ap.BSSID {
			stations = append(stations, st.MAC.String())
		}
	}
	if len(stations) > 0 {
		b.WriteString("\n" + sDim.Render(fmt.Sprintf("stations (%d)", len(stations))) + "\n")
		for i, s := range stations {
			if i >= 5 {
				b.WriteString(sFaint.Render(fmt.Sprintf("  +%d more", len(stations)-5)) + "\n")
				break
			}
			b.WriteString(sText.Render("  "+s) + "\n")
		}
	}

	// What can be done to this access point, from here. Only what actually applies: a key
	// offered on every row is a key nobody remembers is there when it matters.
	//
	// Built as a list and wrapped, because the pane is around thirty columns and a single
	// joined line ran a long way past it - the hints at the end were simply not on screen.
	var keys []string
	if ap.InScope {
		keys = append(keys, sKey.Render("s")+" solicit", sKey.Render("d")+" deauth all")
	}
	// Hunting only listens, so it is offered at every access point. Tracking down a
	// transmitter nobody can account for is the reason hunt exists, and that device is
	// exactly the one that will never be in scope.
	keys = append(keys, sKey.Render("h")+" hunt")
	if ap.ESSID == "" {
		keys = append(keys, sKey.Render("u")+" decloak")
	}
	if ap.InScope && ap.Security.WPS {
		keys = append(keys, sKey.Render("P")+" pixie dust")
	}
	if ap.InScope && ap.Security.Class == recon.SecWPAEnterprise {
		keys = append(keys, sKey.Render("C")+" clone cert")
	}
	if !ap.InScope && ap.ESSID != "" {
		keys = append(keys, sKey.Render("a")+" +scope")
	}

	b.WriteString("\n")
	for _, line := range wrapStyled(keys, "  ", w) {
		b.WriteString(sDim.Render(line) + "\n")
	}
	if !ap.InScope {
		for _, line := range wrapWords("out of scope: nothing here transmits at it", w) {
			b.WriteString(sFaint.Render(line) + "\n")
		}
	}
	return b.String()
}

// identityOfOutcome picks the most specific name a supplicant gave. A client that sends
// "anonymous" outside the tunnel and its real account inside is using identity privacy, and
// the inner name is the one worth showing.
func identityOfOutcome(o radius.Outcome) string {
	switch {
	case o.InnerIdentity != "":
		return o.InnerIdentity
	case o.OuterIdentity != "":
		return o.OuterIdentity
	default:
		return "<no identity>"
	}
}

// pmfDetail spells out the Protected Management Frames posture for the detail pane, where
// there is room to say what it means for the next thing the operator does.
func pmfDetail(m recon.MFPState) string {
	switch m {
	case recon.MFPRequired:
		return sGood.Render("required") + sFaint.Render(" (no deauth)")
	case recon.MFPCapable:
		return sWarn.Render("optional") + sFaint.Render(" (deauth may work)")
	case recon.MFPAbsent:
		return sErr.Render("off") + sFaint.Render(" (deauth works)")
	default:
		return sFaint.Render("unknown")
	}
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func (m *Model) stationDetail(st daemon.StationView, w int) string {
	var b strings.Builder

	b.WriteString("\n" + sBright.Render(st.MAC.String()) + "\n")
	if st.Randomised {
		b.WriteString(sWarn.Render("randomised MAC") + "\n")
	} else if st.OUI != "" {
		b.WriteString(sDim.Render(truncate(st.OUI, w)) + "\n")
	}
	b.WriteString("\n")

	assoc := "-"
	if !st.BSSID.IsZero() {
		assoc = st.BSSID.String()
	}
	b.WriteString(kv("network", networkNameCell(st.ESSID, st.InScope), w))
	b.WriteString(kv("associated", assoc, w))
	if st.APChannel != 0 {
		b.WriteString(kv("channel", fmt.Sprintf("%d %s", st.APChannel, st.APBand), w))
	}
	b.WriteString(kv("signal", rssiCell(st.LastRSSI, st.HasRSSI)+" dBm live", w))
	b.WriteString(sFaint.Render("           ") + signalBar(st.LastRSSI, st.HasRSSI, minInt(w-12, 16)) + "\n")
	if st.HasRSSI {
		b.WriteString(kv("peak", rssiCell(st.BestRSSI, st.HasRSSI)+" dBm", w))
	}
	if !st.BSSID.IsZero() {
		b.WriteString(kv("pmf", pmfDetail(st.MFP), w))
	}
	b.WriteString(kv("frames", humanCount(st.Frames), w))
	b.WriteString(kv("first seen", st.FirstSeen.Format("15:04:05"), w))
	b.WriteString(kv("last seen", st.LastSeen.Format("15:04:05"), w))

	if len(st.ProbedESSIDs) > 0 {
		b.WriteString("\n" + sDim.Render("has looked for") + "\n")
		for _, e := range st.ProbedESSIDs {
			b.WriteString(sText.Render("  "+truncate(e, w)) + "\n")
		}
		b.WriteString(sFaint.Render("\nprobed names leak where this\ndevice has been before") + "\n")
	}

	// What can be done from here. Deauthenticating from the client list is the most targeted
	// form there is - a named client on a named BSSID - so it belongs on this pane, not only
	// on the access point's.
	b.WriteString("\n")
	switch {
	case st.BSSID.IsZero():
		b.WriteString(sFaint.Render("not associated - nothing to deauthenticate from"))
	case !st.InScope:
		b.WriteString(sDim.Render(sKey.Render("h") + " hunt"))
		b.WriteString(sFaint.Render("\nits network is out of scope, so\nnothing here transmits at it"))
	case st.MFP == recon.MFPRequired:
		b.WriteString(sDim.Render(sKey.Render("h") + " hunt"))
		b.WriteString(sWarn.Render("\n802.11w is required here -\ndeauthentication is refused"))
	default:
		b.WriteString(sDim.Render(sKey.Render("d") + " deauth this client  " +
			sKey.Render("h") + " hunt"))
	}
	b.WriteString("\n")
	return b.String()
}

// findingDetail renders a grouped finding: the name, the tier, a description, and every
// affected asset as BSSID + network, so the sidebar answers "what is this and what does it
// touch". Per-asset specifics (similarity score, differing attributes) hang under each asset.
func (m *Model) findingDetail(g findingGroup, w int) string {
	var b strings.Builder

	b.WriteString("\n" + tierStyle(g.Tier).Render(strings.ToUpper(string(g.Tier))) + "\n")
	b.WriteString(sBright.Render(wrapText(g.Label, w, "")) + "\n\n")

	if g.Desc != "" {
		b.WriteString(sDim.Render("why") + "\n")
		b.WriteString(sText.Render(wrapText(g.Desc, w, "")) + "\n\n")
	}

	b.WriteString(sDim.Render(fmt.Sprintf("affected assets (%d)", len(g.Assets))) + "\n")
	for _, f := range g.Assets {
		net := f.ESSID
		if net == "" {
			net = "(hidden)"
		}
		b.WriteString(sText.Render("• "+f.BSSID+"  "+net) + "\n")
		if f.Score != nil {
			b.WriteString(sFaint.Render(fmt.Sprintf("    similarity %.2f", *f.Score)) + "\n")
		}
		for _, d := range f.Differences {
			b.WriteString(sFaint.Render("    · "+wrapText(d, w-6, "      ")) + "\n")
		}
	}

	if g.Tier == store.TierEvidence {
		b.WriteString("\n" + sWarn.Render(wrapText(
			"Evidence, not proof. Verify physically before acting.", w, "")))
	}
	return b.String()
}

// kv renders a label/value line for the detail pane.
//
// The value is clamped with lipgloss rather than by byte length: values carry styled
// fragments such as signal bars, whose byte length is several times their rendered width.
// An empty value is skipped entirely rather than drawn as a dangling label.
// kvLabelWidth is the column the value starts at, and the indent continuation lines get.
const kvLabelWidth = 11

// kv renders one label/value line in the detail pane, wrapping rather than truncating.
//
// It used to truncate, and in a pane 40 columns wide that turned "yes - name recovered from
// probe-response" into "yes - name recovered from p". The cut fell exactly on the part that
// carried the information: *how* the name was recovered is the whole point of the line, and
// the operator was left with a sentence that stopped mid-word.
func kv(k, v string, w int) string { return kvStyled(k, v, w, sText) }

// kvStyled is kv with a colour for the value.
func kvStyled(k, v string, w int, style lipgloss.Style) string {
	if strings.TrimSpace(v) == "" {
		return ""
	}
	valueW := w - kvLabelWidth
	if valueW < 8 {
		valueW = 8
	}

	// A value that is already styled cannot be wrapped without cutting escape sequences in
	// half. Those are all short by construction - a signal reading, a PMF posture - so they
	// keep the old behaviour, and the wrapping applies to the long prose values that needed it.
	if strings.ContainsRune(v, 0x1b) {
		return sFaint.Render(fmt.Sprintf("%-*s", kvLabelWidth, k)) +
			lipgloss.NewStyle().MaxWidth(valueW).Render(v) + "\n"
	}

	var b strings.Builder

	// Below about sixteen columns of value there is no useful line left after an eleven-column
	// label - a hyphenated word starts breaking across lines and the pane becomes unreadable.
	// Stack instead: label on its own line, value indented under it with the full width.
	if valueW < 16 {
		b.WriteString(sFaint.Render(k) + "\n")
		for _, line := range wrapWords(v, w-2) {
			b.WriteString("  " + style.Render(line) + "\n")
		}
		return b.String()
	}

	for i, line := range wrapWords(v, valueW) {
		if i == 0 {
			b.WriteString(sFaint.Render(fmt.Sprintf("%-*s", kvLabelWidth, k)))
		} else {
			b.WriteString(strings.Repeat(" ", kvLabelWidth))
		}
		b.WriteString(style.Render(line) + "\n")
	}
	return b.String()
}

// wrapWords breaks plain text on spaces at width, hard-breaking any single word longer than
// the column - a 60-character hash with nowhere to break must still not run off the panel.
func wrapWords(s string, width int) []string {
	if width < 1 {
		width = 1
	}

	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			for lipgloss.Width(word) > width {
				// Longer than the whole column: take what fits and carry the rest.
				if line != "" {
					out = append(out, line)
					line = ""
				}
				cut := truncateToWidth(word, width)
				out = append(out, cut)
				word = word[len(cut):]
			}
			switch {
			case line == "":
				line = word
			case lipgloss.Width(line)+1+lipgloss.Width(word) <= width:
				line += " " + word
			default:
				out = append(out, line)
				line = word
			}
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return []string{""}
	}
	return out
}

// wrapStyled packs already-styled fragments onto lines no wider than width.
//
// Separate from wrapWords because these carry escape sequences: they cannot be split, only
// packed, and their width has to be measured with lipgloss rather than len.
func wrapStyled(parts []string, sep string, width int) []string {
	if width < 1 {
		width = 1
	}

	var out []string
	line := ""
	for _, p := range parts {
		switch {
		case line == "":
			line = p
		case lipgloss.Width(line)+lipgloss.Width(sep)+lipgloss.Width(p) <= width:
			line += sep + p
		default:
			out = append(out, line)
			line = p
		}
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

// truncateToWidth returns the longest prefix of s that fits in width display columns.
//
// Iterating to the last rune boundary that still fits, rather than returning at the first one
// that does not: `range` over a string never yields len(s), so a word exactly one column too
// wide fell out of the loop and came back untruncated - which put a 25-column line in a
// 24-column pane.
func truncateToWidth(s string, width int) string {
	if lipgloss.Width(s) <= width {
		return s
	}
	last := 0
	for i := range s {
		if lipgloss.Width(s[:i]) > width {
			break
		}
		last = i
	}
	if last == 0 {
		// A single rune wider than the whole column. Emit it anyway: dropping it silently
		// would lose characters, and one column of overflow beats missing data.
		for i := range s {
			if i > 0 {
				return s[:i]
			}
		}
		return s
	}
	return s[:last]
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

func (m *Model) overviewBody() string {
	s := m.data.status
	var b strings.Builder

	b.WriteString("\n" + sBright.Render("  ENGAGEMENT") + "\n")
	b.WriteString(sFaint.Render("  workspace   ") + sText.Render(s.Workspace) + "\n")
	b.WriteString(sFaint.Render("  in scope    ") +
		sText.Render(fmt.Sprintf("%d network name(s)", s.ScopeESSIDs)) + "\n")
	b.WriteString(sFaint.Render("  running     ") + sText.Render(s.Uptime) + "\n")
	b.WriteString(sFaint.Render("  build       ") +
		sDim.Render(build.Name+" "+build.Release()) +
		sFaint.Render("  "+build.Author+"  ·  "+build.URL) + "\n")

	b.WriteString("\n" + sBright.Render("  RESULTS") + "\n")
	b.WriteString(bigStat("access points", s.Recon.APs) + bigStat("clients", s.Recon.Stations) +
		bigStat("findings", len(m.data.findings)) + "\n")
	b.WriteString(bigStat("PMKID hashes", s.PMKIDHashes) + bigStat("handshakes", s.HandshakeHashes) +
		bigStat("unclassified", len(m.data.unclass)) + "\n")

	if e := m.data.eap; e.Running || len(e.Captured) > 0 {
		b.WriteString("\n" + sBright.Render("  ENTERPRISE") + "\n")
		if e.Running && e.Session != nil {
			b.WriteString(sFaint.Render("  impersonating") + " " +
				sErr.Render(e.Session.ESSID) +
				sFaint.Render(fmt.Sprintf("  ch%d  %s", e.Session.Channel, e.Session.Ifname)) + "\n")
			b.WriteString(sFaint.Render("  certificate ") +
				sDim.Render(e.Session.CertSource) + "\n")
			b.WriteString(sFaint.Render("  radius      ") +
				sDim.Render(fmt.Sprintf("%d requests, %d challenges",
					e.Stats.Requests, e.Stats.Challenges)) + "\n")
		}
		for _, o := range e.Captured {
			what := sDim.Render("no credential")
			switch {
			case o.Cleartext != "":
				what = sErr.Render("CLEARTEXT PASSWORD")
			case o.HashLine != "":
				what = sGood.Render("MSCHAPv2 → -m 5500")
			}
			b.WriteString("  " + sText.Render(pad(identityOfOutcome(o), 24)) + what + "\n")
		}
		if e.Running && len(e.Captured) == 0 {
			b.WriteString(sFaint.Render(
				"  nothing yet - a supplicant has to try to join") + "\n")
		}
	}

	b.WriteString("\n" + sBright.Render("  THIS HARDWARE") + "\n")

	// The name column is sized to the longest capability name rather than a fixed 40, because
	// a name that exactly fills the column leaves its reason butted straight up against it.
	nameW := 0
	for _, c := range s.Capabilities {
		if n := lipgloss.Width(c.Name); n > nameW {
			nameW = n
		}
	}
	nameW += 2

	// On a wide terminal the reason sits beside the capability; on a narrow one it wraps to
	// its own line rather than being cut to nothing.
	inline := m.width >= nameW+34
	for _, c := range s.Capabilities {
		mark, style := sGood.Render("✔"), sText
		switch {
		case !c.Available:
			mark, style = sErr.Render("✖"), sText
		case c.Degraded:
			mark, style = sWarn.Render("◐"), sText
		}

		if c.Reason == "" {
			b.WriteString("  " + mark + " " + style.Render(c.Name) + "\n")
			continue
		}
		if inline {
			b.WriteString("  " + mark + " " + style.Render(pad(c.Name, nameW)) +
				sFaint.Render(truncate(c.Reason, m.width-nameW-10)) + "\n")
			continue
		}
		b.WriteString("  " + mark + " " + style.Render(c.Name) + "\n")
		b.WriteString(sFaint.Render("    "+wrapText(c.Reason, maxInt(m.width-8, 20), "    ")) + "\n")
	}

	if !s.Recon.Running {
		b.WriteString("\n  " + sWarn.Render("Capture is not running. Press "+
			sKey.Render("r")+" to start it.") + "\n")
	}
	for _, e := range s.PendingAcks {
		b.WriteString("\n  " + sWarn.Render(fmt.Sprintf(
			"%q is a generic name and unacknowledged - active work there is refused.", e)) + "\n")
	}
	return b.String()
}

func bigStat(label string, v int) string {
	return "  " + sBright.Render(fmt.Sprintf("%-6d", v)) + sFaint.Render(pad(label, 18))
}

// ---------------------------------------------------------------------------
// Footer and command line
// ---------------------------------------------------------------------------

func (m *Model) footerView() string {
	if m.flash != "" && time.Now().Before(m.flashUntil) {
		return sFooter.Width(m.width).Render(m.flash)
	}

	k := func(key, desc string) string { return sKey.Render(key) + sDim.Render(" "+desc) }

	var hints []string
	switch m.view {
	case ViewAPs:
		hints = []string{k("↑↓", "move"), k("⏎", "detail"), k("s", "solicit"),
			k("d", "deauth"), k("h", "hunt"), k("a", "+scope"), k("x", "exclude"), k("m", "rogue")}
		// Only offered on a network that is actually hidden. A key that does nothing on
		// nineteen rows out of twenty is a key nobody remembers is there when it matters.
		if ap, ok := m.selectedAP(); ok {
			switch {
			case ap.ESSID == "":
				hints = append([]string{sWarn.Render("HIDDEN") + sDim.Render(" ") +
					k("u", "decloak")}, hints...)
			case ap.Security.Class == recon.SecWPAEnterprise && ap.InScope:
				hints = append([]string{sBlue.Render("ENTERPRISE") + sDim.Render(" ") +
					k("C", "clone cert")}, hints...)
			case ap.Security.WPS && ap.InScope:
				label := sWarn.Render("WPS")
				if ap.Security.WPSLocked {
					label = sFaint.Render("WPS LOCKED")
				}
				hints = append([]string{label + sDim.Render(" ") +
					k("P", "pixie dust")}, hints...)
			}
		}
	case ViewStations:
		hints = []string{k("↑↓", "move"), k("⏎", "detail"), k("d", "deauth"), k("h", "hunt")}
	case ViewFindings:
		hints = []string{k("↑↓", "move"), k("⏎", "detail"), k("c", "reclassify")}
	case ViewJobs:
		hints = []string{k("↑↓", "move"), k("k", "kill")}
	case ViewRadios:
		hints = []string{k("↑↓", "move"), k("t", "on/off"), k("l", "pin to channel"), k("U", "unpin")}
	case ViewEvilTwin:
		hints = []string{k("↑↓", "move"), k("⏎", "use cert"), k("g", "generate"),
			k("S", "start"), k("X", "stop")}
		if m.data.eap.Running {
			hints = append([]string{sErr.Render("IMPERSONATING")}, hints...)
		}
	default:
		hints = []string{k("↑↓", "scroll")}
	}

	// The sort column goes first when one is set, because otherwise the operator has no way
	// to tell whether they are looking at discovery order or something else.
	if len(m.data.hunts) > 0 {
		hints = append([]string{sWarn.Render("HUNTING") + sDim.Render(" ") +
			k("H", "stop")}, hints...)
	}
	if label := m.sortLabel(); label != "" {
		hints = append([]string{sKey.Render("o") + sDim.Render(" "+label)}, hints...)
	} else if _, sortable := sortableColumns[m.view]; sortable {
		hints = append(hints, k("o", "sort"))
	}
	if m.paused {
		hints = append([]string{sWarn.Render("PAUSED") + sDim.Render(" ") +
			k("p", "resume")}, hints...)
	} else {
		hints = append(hints, k("p", "pause"))
	}
	hints = append(hints, k("y", "copy"), k("w", "walkthrough"), k("R", "report"),
		k("r", "recon"), k("?", "keys"), k("q", "quit"))

	sep := sFaint.Render(" · ")
	line := strings.Join(hints, sep)
	for lipgloss.Width(line) > m.width-2 && len(hints) > 1 {
		hints = hints[:len(hints)-1]
		line = strings.Join(hints, sep)
	}
	return sFooter.Width(m.width).Render(line)
}

func (m *Model) commandView() string {
	if !m.cmdMode {
		return sFaint.Render("  " + sKey.Render(":") + " command  " +
			sKey.Render("tab") + " next tab")
	}
	return sPrompt.Render("  warp❯ ") + m.input.View()
}

// ---------------------------------------------------------------------------
// Cell rendering
// ---------------------------------------------------------------------------

// signalBar renders RSSI as a bar. Reading a column of numbers to find the strongest signal
// is exactly the work a display should be doing.
func signalBar(rssi int8, has bool, width int) string {
	if !has {
		// U+2500, not the double-dash U+254C that was here: the dashed variant is missing
		// from a lot of terminal fonts and renders as a replacement box, which looks like a
		// bug in the tool rather than an absence of signal.
		return sFaint.Render(strings.Repeat("─", width))
	}

	const weak, strong = -90.0, -35.0
	v := float64(rssi)
	if v < weak {
		v = weak
	}
	if v > strong {
		v = strong
	}
	frac := (v - weak) / (strong - weak)

	filled := int(frac*float64(width) + 0.5)
	if filled < 1 {
		filled = 1
	}
	if filled > width {
		filled = width
	}

	style := sErr
	switch {
	case rssi >= -55:
		style = sGood
	case rssi >= -72:
		style = sWarn
	}
	return style.Render(strings.Repeat("█", filled)) +
		sFaint.Render(strings.Repeat("░", width-filled))
}

// securityStyle colours a security class by how exposed it is.
func securityStyle(c recon.Security) lipgloss.Style {
	switch c {
	case recon.SecOpen, recon.SecWEP:
		return sErr
	case recon.SecWPASAE, recon.SecOWE, recon.SecWPA3Ent192:
		return sGood
	case recon.SecWPAEnterprise:
		return lipgloss.NewStyle().Foreground(cBlue)
	default:
		return sWarn
	}
}

func networkStyle(ap daemon.APView) lipgloss.Style {
	// A manual potential-rogue mark colours the name red and takes precedence over the in-scope
	// green: a rogue is the more urgent signal, and it is BSSID-specific.
	if ap.Rogue {
		return sErr
	}
	if ap.ESSID == "" {
		return sFaint
	}
	if ap.InScope {
		return sGood
	}
	return sText
}

func tierStyle(t store.Tier) lipgloss.Style {
	switch t {
	case store.TierDetermined:
		return sErr
	case store.TierEvidence:
		return lipgloss.NewStyle().Foreground(cViolet)
	case store.TierControl:
		// A control is a pass - render it green, not red like an exposure.
		return sGood
	default:
		return sDim
	}
}

func findingStyle(f []store.Finding) lipgloss.Style {
	if len(f) == 0 {
		return sBright
	}
	return sWarn
}

func hashStyle(n int) lipgloss.Style {
	if n == 0 {
		return sBright
	}
	return sGood
}

// sparkline renders a series as block characters, scaled to its own range.
// sparkBlocks is chosen once at startup. The Unicode block-element ramp needs a UTF-8 locale and
// a font that carries the glyphs; over SSH with LANG=C they render as replacement characters -
// the intermittent "question mark" an operator sees. When the locale is not UTF-8 we fall back to
// an ASCII ramp, which is uglier but always legible, rather than emitting glyphs the terminal
// cannot draw.
var sparkBlocks = pickSparkBlocks()

func pickSparkBlocks() []rune {
	for _, v := range []string{os.Getenv("LC_ALL"), os.Getenv("LC_CTYPE"), os.Getenv("LANG")} {
		if v == "" {
			continue
		}
		up := strings.ToUpper(v)
		if strings.Contains(up, "UTF-8") || strings.Contains(up, "UTF8") {
			return []rune("▁▂▃▄▅▆▇█")
		}
		// The first locale variable that is set decides it; an explicit non-UTF-8 locale means
		// the terminal will not draw the block glyphs.
		return []rune(".:-=+*#%")
	}
	// No locale set at all: assume the modern default rather than degrade every terminal.
	return []rune("▁▂▃▄▅▆▇█")
}

func sparkline(vals []float64) string {
	if len(vals) == 0 {
		return ""
	}
	blocks := sparkBlocks

	minV, maxV := vals[0], vals[0]
	for _, v := range vals {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}

	var b strings.Builder
	span := maxV - minV
	for _, v := range vals {
		idx := 0
		if span > 0 {
			idx = int((v - minV) / span * float64(len(blocks)-1))
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		b.WriteRune(blocks[idx])
	}
	return b.String()
}

// humanCount abbreviates large counters so a busy channel does not push the header around.
func humanCount(n uint64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1_000:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	default:
		return fmt.Sprint(n)
	}
}

func pad(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
