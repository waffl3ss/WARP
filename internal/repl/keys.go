package repl

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/recon"
)

// handleKey routes a keypress.
//
// The action keys work on the row under the cursor, so an operator never types a MAC address:
// point at the access point and press `s` to solicit it. That is the whole reason the
// dashboard exists rather than a bare prompt.
func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// The command line swallows everything except the keys that leave it.
	if m.cmdMode {
		return m.handleCommandKey(msg)
	}
	// So does the certificate wizard: while it is open every keystroke is text going into a
	// field, and a stray `d` must not deauthenticate something.
	if m.form.active {
		return m.handleFormKey(msg)
	}

	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	case ":", "/":
		m.cmdMode = true
		m.input.Focus()
		return m, nil

	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		idx := int(msg.String()[0] - '1')
		if idx < len(viewNames) {
			m.view = View(idx)
			m.layout()
		}
		return m, nil

	case "tab":
		m.view = View((int(m.view) + 1) % len(viewNames))
		m.layout()
		return m, nil

	case "shift+tab":
		m.view = View((int(m.view) - 1 + len(viewNames)) % len(viewNames))
		m.layout()
		return m, nil

	case "r":
		return m, m.toggleRecon()

	case "c":
		return m, m.runAction("rogue.classify", nil, "classification complete")

	case "w":
		// Context-aware: if a walkthrough is open, w ends it (matching the banner's stop control);
		// otherwise it drops into the command line with the verb typed, ready for a name. This is
		// the one action an operator most needs mid-walk and it should not require remembering the
		// command syntax.
		if m.data.status.Walkthrough != "" {
			return m, m.runAction("walkthrough.end", nil, "walkthrough ended")
		}
		m.cmdMode = true
		m.input.Focus()
		m.input.SetValue("walkthrough ")
		m.input.CursorEnd()
		return m, nil

	case "e":
		return m, m.runAction("export", nil, "projections regenerated")

	case "R":
		// Write the engagement report (report.md), the same as the web's "Write report".
		return m, m.runAction("report", nil, "report written to report.md")

	case "enter":
		if m.view == ViewEvilTwin {
			// Choose which certificate goes on the air.
			r, ok := m.selectedCert()
			if !ok {
				return m, nil
			}
			if r.entry.Selected {
				return m, func() tea.Msg {
					return flashMsg{text: styleDim.Render(
						r.entry.ID + " is already what the rogue will present")}
				}
			}
			return m, m.runAction("certs.select",
				daemon.CertSelectParams{ESSID: r.essid, ID: r.entry.ID},
				r.entry.ID+" selected for "+r.essid+" - restart the rogue to present it")
		}
		return m, m.showDetail()

	case "s":
		if b := m.selectedBSSID(); b != "" {
			return m, m.runAction("psk.solicit", daemon.SolicitParams{BSSID: b},
				"solicitation started against "+b)
		}
	case "d":
		// On the client list this is the most targeted form of deauthentication there is: a
		// named client on the access point it is actually associated to, no guessing.
		if m.view == ViewStations {
			return m, m.deauthSelectedClient()
		}
		if b := m.selectedBSSID(); b != "" {
			return m, m.deauthSelected(b)
		}
	case "h":
		if b := m.selectedBSSID(); b != "" {
			// Hunting the device already being hunted stops it. There was no way to stop one
			// at all, which on a one-adapter kit meant recon stayed pinned to a channel with
			// nothing the operator could do about it.
			for _, live := range m.data.hunts {
				if live.Target.Addr.String() == b {
					return m, m.runAction("hunt.stop", map[string]any{"addr": b},
						"stopped hunting "+b)
				}
			}
			return m, m.runAction("hunt.start",
				map[string]any{"addr": b, "audible": false}, "hunting "+b)
		}

	case "H":
		// Stop every hunt, from anywhere.
		if len(m.data.hunts) == 0 {
			return m, func() tea.Msg {
				return flashMsg{text: styleWarn.Render("no hunt is running")}
			}
		}
		addr := m.data.hunts[0].Target.Addr.String()
		return m, m.runAction("hunt.stop", map[string]any{"addr": addr},
			"stopped hunting "+addr)
	case "a":
		// Add the selected network's name to scope. The client naming a network on site that
		// was missing from the list is a real situation, and editing scope.txt and restarting
		// the daemon in the middle of a walkthrough is not a workable answer to it.
		if m.view == ViewAPs {
			ap, ok := m.selectedAP()
			switch {
			case !ok:
				return m, nil
			case ap.ESSID == "":
				return m, func() tea.Msg {
					return flashMsg{text: styleWarn.Render(
						"hidden network - no name to authorize until one is recovered")}
				}
			case ap.InScope:
				return m, func() tea.Msg {
					return flashMsg{text: styleDim.Render(ap.ESSID + " is already in scope")}
				}
			}
			return m, m.runAction("scope.add",
				map[string]string{"essid": ap.ESSID, "note": "added from the console"},
				ap.ESSID+" added to scope - active work is now authorized there")
		}

	case "g":
		// Build a certificate from typed fields.
		if m.view == ViewEvilTwin {
			essid := ""
			if r, ok := m.selectedCert(); ok {
				essid = r.essid
			} else if list := m.scopedEnterprise(); len(list) > 0 {
				essid = list[0]
			}
			if essid == "" {
				return m, func() tea.Msg {
					return flashMsg{text: styleWarn.Render(
						"no scoped enterprise network observed yet - a certificate is only " +
							"ever presented by the rogue's RADIUS server")}
				}
			}
			m.form = newCertForm(essid)
			m.layout()
			return m, nil
		}

	case "S":
		// Start the rogue. On the Evil Twin tab, against the selected network (wears the strongest
		// observed BSSID). On the Access Points tab, against the enterprise AP under the cursor -
		// wearing that specific BSSID, so the operator chooses which observed access point to mirror.
		if m.view == ViewEvilTwin {
			return m, m.startEvilTwin()
		}
		if m.view == ViewAPs {
			return m, m.startEvilTwinAP()
		}

	case "l":
		// Pin the adapter under the cursor to a channel. It needs a number, so it drops into
		// the command line with the radio already named.
		if m.view == ViewRadios {
			r, ok := m.selectedRadio()
			if !ok {
				return m, nil
			}
			m.cmdMode = true
			m.input.Focus()
			m.input.SetValue("radios lock " + r.ID + " ")
			m.input.CursorEnd()
			return m, nil
		}

	case "U":
		if m.view == ViewRadios {
			r, ok := m.selectedRadio()
			if !ok {
				return m, nil
			}
			if r.PinnedChannel == 0 {
				return m, func() tea.Msg {
					return flashMsg{text: styleDim.Render(
						r.ID + " is already following the channel plan")}
				}
			}
			return m, m.runAction("radios.unlock",
				daemon.RadioUnlockParams{RadioID: r.ID},
				r.ID+" back on the channel plan")
		}

	case "t":
		// Switch the adapter under the cursor on or off. Off releases it so another tool can use
		// it; on returns it to the pool. Distinct from pinning, which only stops it moving.
		if m.view == ViewRadios {
			r, ok := m.selectedRadio()
			if !ok {
				return m, nil
			}
			want := !r.Enabled
			state := "switched off - released for other use"
			if want {
				state = "switched on"
			}
			return m, m.runAction("radios.set-enabled",
				daemon.RadioEnableParams{RadioID: r.ID, Enabled: want},
				r.Ifname+" "+state)
		}

	case "X":
		if m.view == ViewEvilTwin {
			if !m.data.eap.Running {
				return m, func() tea.Msg {
					return flashMsg{text: styleDim.Render("no rogue access point is running")}
				}
			}
			return m, m.runAction("eap.stop", nil, "rogue access point stopped")
		}

	case "P":
		// Pixie Dust at the selected access point. One association and four messages, then
		// arithmetic - see internal/wps for why online PIN recovery is not offered.
		if m.view == ViewAPs {
			return m, m.pixieSelected()
		}

	case "C":
		// Clone the certificate of the selected enterprise network, so the rogue has something
		// worth presenting. Shifted because it associates to a production access point.
		if m.view == ViewAPs {
			return m, m.harvestSelected()
		}

	case "m":
		// Toggle a manual potential-rogue mark on the selected access point. It is the operator's
		// judgement about one BSSID (not the whole ESSID) and transmits nothing, so it is available
		// on any AP, in scope or not, named or hidden.
		if m.view == ViewAPs {
			ap, ok := m.selectedAP()
			if !ok {
				return m, nil
			}
			b := ap.BSSID.String()
			if ap.Rogue {
				return m, m.runAction("rogue.unmark", map[string]string{"bssid": b},
					b+" potential-rogue mark cleared")
			}
			return m, m.runAction("rogue.mark", map[string]string{"bssid": b},
				b+" marked as a potential rogue device")
		}

	case "u":
		// Uncloak the selected hidden network. `d` is deauthentication and this is a
		// deauthentication underneath, but they are different operator intents with different
		// authorization behind them, so they are different keys.
		if m.view == ViewAPs {
			return m, m.decloakSelected()
		}

	case "x":
		if b := m.selectedBSSID(); b != "" {
			return m, m.runAction("scope.reject",
				map[string]string{"bssid": b, "note": "excluded from the console"},
				b+" excluded from active work")
		}
	case "k":
		if m.view == ViewJobs {
			if row := m.jobTable.SelectedRow(); len(row) > 0 {
				return m, m.runAction("jobs.kill", map[string]string{"id": row[0]},
					"job "+row[0]+" killed")
			}
		}
	case "v":
		// Trade the detail pane for a wider listing, and back.
		m.sidebarOff = !m.sidebarOff
		m.layout()
		return m, nil

	case "o", "O":
		// Order the current tab. Repeat to cycle columns, shift to reverse.
		m.cycleSort(msg.String() == "O")
		return m, nil

	case "p":
		// Freeze the display. The daemon keeps capturing - this stops the screen moving so a
		// value can be read off it, which on a busy site is otherwise a race against the
		// next refresh.
		m.paused = !m.paused
		if m.paused {
			return m, func() tea.Msg {
				return flashMsg{text: styleWarn.Render(
					"paused - capture continues, press " + styleKey.Render("p") + " to resume")}
			}
		}
		return m, tea.Batch(m.refresh(), func() tea.Msg {
			return flashMsg{text: "resumed"}
		})

	case "?":
		// Every key, on screen. The footer only ever has room for the handful that apply to
		// the current tab, so the rest were discoverable by reading source or by accident -
		// `w` for a walkthrough is the one an operator most needs and least likely to find.
		m.showHelp = !m.showHelp
		m.layout()
		return m, nil

	case "esc":
		if m.showHelp {
			m.showHelp = false
			m.layout()
			return m, nil
		}

	case "y":
		// Leave the alternate screen and print the current tab as plain text, so the
		// terminal's own selection and clipboard work on it. Inside a full-screen program
		// there is no other way to get a BSSID out of here and into a ticket - mouse
		// selection either does nothing or selects the whole window including the borders.
		return m, m.copyOut()
	}

	// The Radios tab is not a table either.
	if m.view == ViewRadios {
		switch msg.String() {
		case "up", "k":
			if m.radioCursor > 0 {
				m.radioCursor--
			}
			return m, nil
		case "down", "j":
			if m.radioCursor < len(m.data.radios)-1 {
				m.radioCursor++
			}
			return m, nil
		}
	}

	// The Evil Twin tab is not a table, so it moves its own cursor.
	if m.view == ViewEvilTwin {
		switch msg.String() {
		case "up", "k":
			if m.certCursor > 0 {
				m.certCursor--
			}
			return m, nil
		case "down", "j":
			if m.certCursor < len(m.certRows())-1 {
				m.certCursor++
			}
			return m, nil
		}
	}

	// Anything else goes to the focused table or viewport.
	var cmd tea.Cmd
	switch m.view {
	case ViewAPs:
		_, cmd = m.apTable.Update(msg)
	case ViewStations:
		_, cmd = m.staTable.Update(msg)
	case ViewCredentials:
		_, cmd = m.hashTable.Update(msg)
	case ViewFindings:
		_, cmd = m.findTable.Update(msg)
	case ViewJobs:
		_, cmd = m.jobTable.Update(msg)
	case ViewLog:
		m.logView, cmd = m.logView.Update(msg)
	}
	return m, cmd
}

func (m *Model) handleCommandKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		m.cmdMode = false
		m.input.Blur()
		m.input.SetValue("")
		m.resetTab()
		return m, nil

	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit

	case tea.KeyEnter:
		line := strings.TrimSpace(m.input.Value())
		m.input.SetValue("")
		m.resetTab()
		m.cmdMode = false
		m.input.Blur()

		if line == "" {
			return m, nil
		}
		m.history = append(m.history, line)
		m.historyPos = -1
		m.appendLine(stylePrompt.Render("warp> ") + styleEcho.Render(line))

		if cmd, quit := m.dispatch(line); quit {
			m.quitting = true
			return m, tea.Quit
		} else if cmd != nil {
			return m, cmd
		}
		return m, nil

	case tea.KeyTab:
		m.completeNext()
		return m, nil

	case tea.KeyUp:
		m.recallHistory(-1)
		return m, nil

	case tea.KeyDown:
		m.recallHistory(1)
		return m, nil
	}

	m.resetTab()
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) recallHistory(delta int) {
	if len(m.history) == 0 {
		return
	}
	if m.historyPos == -1 {
		m.historyPos = len(m.history)
	}
	m.historyPos += delta
	if m.historyPos < 0 {
		m.historyPos = 0
	}
	if m.historyPos >= len(m.history) {
		m.historyPos = -1
		m.input.SetValue("")
		return
	}
	m.input.SetValue(m.history[m.historyPos])
	m.input.CursorEnd()
}

// runAction fires an RPC and flashes the result.
//
// Errors are shown rather than swallowed, and a scope denial reads as a decision rather than
// a malfunction - the gate refusing is the system working.
func (m *Model) runAction(method string, params any, success string) tea.Cmd {
	return func() tea.Msg {
		if err := m.call(method, params, nil); err != nil {
			m.appendLine(styleErr.Render("  " + err.Error()))
			return flashMsg{text: styleErr.Render("✗ " + truncate(err.Error(), 90))}
		}
		return flashMsg{text: "✓ " + success}
	}
}

// toggleRecon starts capture, or stops it if already running.
func (m *Model) toggleRecon() tea.Cmd {
	running := m.data.status.Recon.Running
	method, success := "recon.start", "recon started"
	if running {
		method, success = "recon.stop", "recon stopped, radios released"
	}
	return m.runAction(method, nil, success)
}

// deauthSelected disconnects the first observed station on the selected access point.
//
// Deauthentication is targeted by default because a broadcast takes every client off the
// network at once, which at a client site is an outage rather than a test. With no known
// station there is nothing to target, and the operator is told so.
// deauthSelected deauthenticates every client on the access point under the cursor.
//
// Broadcast, not targeted at whichever station happened to be first in the list. Acting on an
// access point means acting on the access point: it is what an operator means by "deauth this
// AP", it is what actually provokes a handshake, and picking one arbitrary client instead
// meant a network with clients WARP had not yet seen could not be deauthenticated at all.
// Targeting one device is what the Clients tab is for.
func (m *Model) deauthSelected(bssid string) tea.Cmd {
	return m.runAction("psk.deauth",
		daemon.DeauthParams{BSSID: bssid, Broadcast: true},
		"broadcast deauthentication against "+bssid)
}

// selectedRadio returns the adapter under the cursor on the Radios tab.
func (m *Model) selectedRadio() (daemon.RadioInfo, bool) {
	if len(m.data.radios) == 0 {
		return daemon.RadioInfo{}, false
	}
	if m.radioCursor >= len(m.data.radios) {
		m.radioCursor = len(m.data.radios) - 1
	}
	if m.radioCursor < 0 {
		m.radioCursor = 0
	}
	return m.data.radios[m.radioCursor], true
}

// scopedEnterprise names the in-scope enterprise networks WARP has observed.
func (m *Model) scopedEnterprise() []string {
	seen := map[string]bool{}
	var out []string
	for _, ap := range m.data.aps {
		if ap.Security.Class == recon.SecWPAEnterprise && ap.InScope && ap.ESSID != "" &&
			!seen[ap.ESSID] {
			seen[ap.ESSID] = true
			out = append(out, ap.ESSID)
		}
	}
	return out
}

// startEvilTwin brings up the rogue against the network the cursor is on.
func (m *Model) startEvilTwin() tea.Cmd {
	if m.data.eap.Running {
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render(
				"already impersonating " + m.data.eap.Session.ESSID + " - press " +
					styleKey.Render("X") + " to stop it first")}
		}
	}

	essid := ""
	if r, ok := m.selectedCert(); ok {
		essid = r.essid
	} else if list := m.scopedEnterprise(); len(list) > 0 {
		essid = list[0]
	}
	if essid == "" {
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render(
				"no scoped enterprise network observed yet - run recon, and add the network " +
					"to scope if it is not already there")}
		}
	}

	// Say which certificate is about to go on the air. A self-signed one is the weak pretext
	// and the operator should know before the beacon starts, not after a client refuses it.
	note := "impersonating " + essid
	for _, e := range m.data.certs.Networks[essid] {
		if e.Selected {
			note += " with " + e.SourceDetail
			break
		}
	}
	return m.runAction("eap.start", daemon.EAPStartParams{ESSID: essid}, note)
}

// startEvilTwinAP brings up the rogue against the specific enterprise access point under the cursor
// on the Access Points tab, so the operator chooses which observed BSSID the twin wears rather than
// always the strongest. The address is one WARP discovered broadcasting the scoped name; the daemon
// validates it again and refuses anything it has not seen (invariant 1).
func (m *Model) startEvilTwinAP() tea.Cmd {
	if m.data.eap.Running {
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render(
				"already impersonating " + m.data.eap.Session.ESSID + " - press " +
					styleKey.Render("X") + " on the Evil Twin tab to stop it first")}
		}
	}

	ap, ok := m.selectedAP()
	if !ok {
		return nil
	}
	switch {
	case ap.Security.Class != recon.SecWPAEnterprise && ap.Security.Class != recon.SecWPA3Ent192:
		return func() tea.Msg {
			return flashMsg{text: styleDim.Render(orHidden(ap.ESSID) + " is " +
				string(ap.Security.Class) + ", not enterprise - the evil twin impersonates a " +
				"RADIUS network, so there is nothing to capture here")}
		}
	case !ap.InScope:
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render(orHidden(ap.ESSID) +
				" is out of scope - press " + styleKey.Render("a") + " to add it to scope first")}
		}
	}

	note := "impersonating " + ap.ESSID + " as " + ap.BSSID.String()
	for _, e := range m.data.certs.Networks[ap.ESSID] {
		if e.Selected {
			note += " with " + e.SourceDetail
			break
		}
	}
	return m.runAction("eap.start",
		daemon.EAPStartParams{ESSID: ap.ESSID, Channel: ap.Channel, BSSID: ap.BSSID.String()}, note)
}

// pixieSelected runs Pixie Dust against the access point under the cursor.
func (m *Model) pixieSelected() tea.Cmd {
	ap, ok := m.selectedAP()
	if !ok {
		return nil
	}

	switch {
	case !ap.Security.WPS:
		return func() tea.Msg {
			return flashMsg{text: styleDim.Render(orHidden(ap.ESSID) +
				" advertises no WPS element - there is no registration protocol to run " +
				"against it. WPS being off is the good outcome; no finding is recorded for its absence")}
		}
	case !ap.InScope:
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render(orHidden(ap.ESSID) +
				" is out of scope, and Pixie Dust associates to the access point - press " +
				styleKey.Render("a") + " to add it to scope first")}
		}
	}

	note := "running one WPS exchange at " + ap.ESSID + " - the PIN is recovered offline"
	if ap.Security.WPSLocked {
		note = ap.ESSID + " advertises WPS as locked; trying anyway - a refusal is a pass"
	}
	return m.runAction("wps", daemon.WPSParams{BSSID: ap.BSSID.String()}, note)
}

// harvestSelected reads the RADIUS certificate of the enterprise network under the cursor.
//
// The refusals are explained here because everything they depend on is already on the screen
// the operator is looking at, and "denied" with no reason is what sends people back to SSH.
func (m *Model) harvestSelected() tea.Cmd {
	ap, ok := m.selectedAP()
	if !ok {
		return nil
	}

	switch {
	case ap.Security.Class != recon.SecWPAEnterprise:
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render(orHidden(ap.ESSID) +
				" is " + string(ap.Security.Class) + ", not enterprise - there is no RADIUS " +
				"server behind it and no certificate to clone")}
		}
	case !ap.InScope:
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render(orHidden(ap.ESSID) +
				" is out of scope, and the harvest associates to the access point - press " +
				styleKey.Render("a") + " to add it to scope first")}
		}
	}

	return m.runAction("harvest", daemon.HarvestParams{BSSID: ap.BSSID.String()},
		"harvesting the certificate at "+ap.ESSID+" - associating and running EAP-TLS")
}

// decloakSelected recovers the name of the hidden network under the cursor.
//
// The refusals are explained here rather than left to come back from the daemon, because
// everything they depend on is already on the screen the operator is looking at.
func (m *Model) decloakSelected() tea.Cmd {
	ap, ok := m.selectedAP()
	if !ok {
		return nil
	}

	switch {
	case ap.ESSID != "":
		return func() tea.Msg {
			return flashMsg{text: styleDim.Render(ap.BSSID.String() +
				" already broadcasts " + ap.ESSID + " - there is nothing to decloak")}
		}
	case ap.Security.MFP == recon.MFPRequired:
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render("802.11w is required on " +
				ap.BSSID.String() + " - its clients would ignore the deauthentication, " +
				"so the name cannot be recovered this way")}
		}
	}

	return m.runAction("decloak", daemon.DecloakParams{BSSID: ap.BSSID.String()},
		"decloaking "+ap.BSSID.String()+" - waiting for a client to name it")
}

// deauthSelectedClient deauthenticates the client under the cursor from the access point it
// is associated to.
//
// Everything the request needs is already on screen, so the refusals that would otherwise
// come back from the daemon are explained here instead: an unassociated client has nothing to
// be knocked off, and 802.11w means the frame would be ignored even if it were sent.
func (m *Model) deauthSelectedClient() tea.Cmd {
	st, ok := m.selectedStation()
	if !ok {
		return nil
	}

	switch {
	case st.BSSID.IsZero():
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render(st.MAC.String() +
				" is not associated to anything - there is nothing to deauthenticate it from")}
		}
	case st.MFP == recon.MFPRequired:
		return func() tea.Msg {
			return flashMsg{text: styleWarn.Render("802.11w is required on " +
				orHidden(st.ESSID) + " - an unprotected deauthentication would be ignored")}
		}
	}

	return m.runAction("psk.deauth",
		daemon.DeauthParams{BSSID: st.BSSID.String(), Station: st.MAC.String()},
		"deauthenticating "+st.MAC.String()+" from "+orHidden(st.ESSID))
}

// showDetail prints the selected row's full record into the log tab.
func (m *Model) showDetail() tea.Cmd {
	if m.view == ViewFindings {
		g, ok := m.selectedFindingGroup()
		if !ok {
			return nil
		}
		return func() tea.Msg {
			lines := []string{
				styleSection.Render(fmt.Sprintf("  [%s] %s - %d affected",
					g.Tier, g.Label, len(g.Assets))),
			}
			if g.Desc != "" {
				lines = append(lines, "  "+wrapText(g.Desc, 100, "  "))
			}
			for _, f := range g.Assets {
				lines = append(lines, styleDim.Render(fmt.Sprintf("    · %s  %s",
					f.BSSID, orHidden(f.ESSID))))
				for _, d := range f.Differences {
					lines = append(lines, styleDim.Render("        · "+d))
				}
			}
			return outputMsg{lines: lines}
		}
	}

	bssid := m.selectedBSSID()
	if bssid == "" {
		return nil
	}

	return func() tea.Msg {
		var res daemon.APDetailResult
		if err := m.call("aps.detail", map[string]string{"bssid": bssid}, &res); err != nil {
			return outputMsg{lines: []string{styleErr.Render("  " + err.Error())}}
		}

		ap := res.AP
		lines := []string{
			styleSection.Render(fmt.Sprintf("  %s  %s", ap.BSSID, orHidden(ap.ESSID))),
			fmt.Sprintf("    channel     %d (%d MHz, %s)", ap.Channel, ap.Freq, ap.Band),
			fmt.Sprintf("    security    %s", ap.Security.Describe()),
			fmt.Sprintf("    signal      %s dBm live · %s dBm peak%s",
				rssiCell(ap.LastRSSI, ap.HasRSSI), rssiCell(ap.BestRSSI, ap.HasRSSI),
				func() string {
					if ap.BestRSSIRadio != "" {
						return " (" + m.ifnameFor(ap.BestRSSIRadio) + ")"
					}
					return ""
				}()),
			fmt.Sprintf("    seen        %s → %s (%d beacons)",
				ap.FirstSeen.Format("15:04:05"), ap.LastSeen.Format("15:04:05"), ap.Beacons),
			fmt.Sprintf("    scope       %s", scopeCell(ap)),
		}
		if len(res.Stations) > 0 {
			lines = append(lines, styleDim.Render("    stations"))
			for _, st := range res.Stations {
				lines = append(lines, fmt.Sprintf("      %s  %s dBm",
					st.MAC, rssiCell(st.LastRSSI, st.HasRSSI)))
			}
		}
		for _, f := range res.Findings {
			lines = append(lines, fmt.Sprintf("    [%s] %s", f.Tier, f.Label))
		}
		if len(res.Locations) > 0 {
			lines = append(lines, styleDim.Render("    heard loudest in"))
			for i, l := range res.Locations {
				lines = append(lines, fmt.Sprintf("      %d. %-24s %d dBm",
					i+1, l.WalkthroughName, l.MaxRSSI))
			}
		}
		return outputMsg{lines: lines}
	}
}

// populate refreshes every table from the current snapshot, preserving cursor position.
func (m *Model) populate() {
	// Ordering is applied to the data before rows are built. A rendered cell is styled text
	// with a signal bar in it, so sorting rows as strings would order by escape sequence.
	m.sortAPs()
	m.sortStations()
	m.sortFindings()
	m.sortJobs()

	apRows := make([]row, 0, len(m.data.aps))
	for _, ap := range m.data.aps {
		apRows = append(apRows, rowFor(m.apCols, map[string]string{
			"BSSID":   ap.BSSID.String(),
			"NETWORK": networkCell(ap),
			"BAND":    bandCell(ap.Band, ap.PHY, m.colWidth["BAND"]),
			"CH":      fmt.Sprintf("%d", ap.Channel),
			// Live (last-heard) reading, not peak-ever: a peak that only climbs latches to max and
			// never falls. Staleness is carried by the SEEN column beside it.
			"SIGNAL":   signalBar(ap.LastRSSI, ap.HasRSSI, 6) + " " + rssiCell(ap.LastRSSI, ap.HasRSSI),
			"SECURITY": securityStyle(ap.Security.Class).Render(truncate(securityShort(ap), 12)),
			"PMF":      mfpCell(ap.Security.MFP),
			"CLI":      clientCountCell(ap.Clients),
			"SCOPE":    scopeCell(ap),
			"SEEN":     seenCell(ap.Active, ap.LastSeenSecs),
		}))
	}
	setRows(&m.apTable, apRows)

	staRows := make([]row, 0, len(m.data.stations))
	for _, st := range m.data.stations {
		bssid := st.BSSID.String()
		if st.BSSID.IsZero() {
			bssid = "-"
		}
		mark := ""
		if st.Randomised {
			mark = "*"
		}
		staRows = append(staRows, rowFor(m.staCols, map[string]string{
			"CLIENT":     st.MAC.String() + mark,
			"ASSOCIATED": bssid,
			"NETWORK":    networkNameCell(st.ESSID, st.InScope),
			"BAND":       bandCell(st.APBand, st.APPHY, m.colWidth["BAND"]),
			"SIGNAL":     signalBar(st.LastRSSI, st.HasRSSI, 6) + " " + rssiCell(st.LastRSSI, st.HasRSSI),
			"PMF":        mfpCell(st.MFP),
			"FRAMES":     humanCount(st.Frames),
			"PROBED FOR": truncate(strings.Join(st.ProbedESSIDs, ", "), 40),
		}))
	}
	setRows(&m.staTable, staRows)

	// Enterprise credentials first: they are the freshest and, when a cleartext password
	// comes back, the most serious thing on the screen.
	hashRows := make([]row, 0, len(m.data.hashes.Hashes)+len(m.data.eap.Captured)+len(m.data.hashes.WPSKeys))

	// WPS-recovered keys are already-cracked credentials - the passphrase, read out of M7 - so
	// they belong at the top of the credentials tab with the enterprise creds, not filed with the
	// hashes still headed for the rig.
	for _, c := range m.data.hashes.WPSKeys {
		val := c.PSK
		if val == "" {
			val = "PIN " + c.PIN + " (run again to read the passphrase from M7)"
		}
		hashRows = append(hashRows, rowFor(m.hashCols, map[string]string{
			"KIND":    sGood.Render("WPS KEY"),
			"SCOPE":   sGood.Render("yes"),
			"NETWORK": networkNameCell(c.ESSID, true),
			"BSSID":   c.BSSID,
			"CLIENT":  "",
			"CH":      "",
			"AT":      c.At.Format("15:04:05"),
			"SECRET":  sBright.Render(val),
		}))
	}

	for _, o := range m.data.eap.Captured {
		kind, line := sBlue.Render("MSCHAPv2"), o.HashLine
		if o.Cleartext != "" {
			// No cracking step at all. Shown in full - nothing here is redacted, the operator
			// needs the actual value for the report and the client needs to see it.
			kind, line = sErr.Render("CLEARTEXT"), o.Cleartext
		}
		if line == "" {
			kind, line = sDim.Render("attempt"), "no credential - "+o.Method.String()
		}
		hashRows = append(hashRows, rowFor(m.hashCols, map[string]string{
			"KIND":    kind,
			"SCOPE":   sGood.Render("yes"),
			"NETWORK": networkNameCell(o.ESSID, true),
			"BSSID":   identityOfOutcome(o),
			"CLIENT":  o.CallingStation,
			"CH":      "",
			"AT":      o.At.Format("15:04:05"),
			"SECRET":  sFaint.Render(line),
		}))
	}

	// A PMKID or handshake overheard from a WPA-Enterprise (802.1X) network is kept as evidence,
	// but its pairwise key comes from the RADIUS exchange, not a passphrase - no 22000 wordlist can
	// recover it. Mark those rows so they never read as crackable PSK material headed for the rig
	// (the same honesty the web credentials tab enforces). Keyed off the observed AP's security.
	entBSSID := map[string]bool{}
	for _, ap := range m.data.aps {
		if ap.Security.Class == recon.SecWPAEnterprise || ap.Security.Class == recon.SecWPA3Ent192 {
			entBSSID[strings.ToLower(ap.BSSID.String())] = true
		}
	}

	for _, h := range m.data.hashes.Hashes {
		kind := sGood.Render("PMKID")
		if h.Kind == "handshake" {
			kind = sWarn.Render("HSHAKE")
		}
		// An incidental capture is marked on its own row. It is real material and it is kept,
		// but it is not part of the deliverable and must never read as if it were.
		scope := sGood.Render("yes")
		if !h.InScope {
			scope = sErr.Render("no")
			kind = sFaint.Render(stripANSI(kind))
		}
		secret := sFaint.Render(h.Line)
		if entBSSID[strings.ToLower(h.BSSID)] {
			// 802.1X capture: kept, but not crackable. Say so plainly, in place of the hash line.
			kind = sFaint.Render("802.1X")
			secret = sWarn.Render("not crackable - 802.1X key is from RADIUS, not a passphrase")
		}
		hashRows = append(hashRows, rowFor(m.hashCols, map[string]string{
			"KIND":    kind,
			"SCOPE":   scope,
			"NETWORK": networkNameCell(h.ESSID, h.InScope),
			"BSSID":   h.BSSID,
			"CLIENT":  h.Station,
			"CH":      fmt.Sprintf("%d", h.Channel),
			"AT":      h.At.Format("15:04:05"),
			"SECRET":  secret,
		}))
	}
	setRows(&m.hashTable, hashRows)

	// One row per finding *name*, not per (BSSID, finding): the group carries the tier, the
	// label and a count of affected assets, and the detail pane lists the assets themselves.
	groups := m.findingGroups()
	findRows := make([]row, 0, len(groups))
	for _, g := range groups {
		findRows = append(findRows, rowFor(m.findCols, map[string]string{
			"TIER":    tierStyle(g.Tier).Render(string(g.Tier)),
			"FINDING": truncate(g.Label, 46),
			"ASSETS":  fmt.Sprintf("%d", len(g.Assets)),
		}))
	}
	setRows(&m.findTable, findRows)

	now := time.Now()
	jobRows := make([]row, 0, len(m.data.jobs))
	for _, j := range m.data.jobs {
		detail := j.Detail
		if j.Error != "" {
			detail = j.Error
		}
		jobRows = append(jobRows, rowFor(m.jobCols, map[string]string{
			"#":       j.ID,
			"KIND":    j.Kind,
			"TARGET":  truncate(j.Target, 18),
			"STATE":   jobStateStyle(j.State).Render(string(j.State)),
			"ELAPSED": j.Elapsed(now).Round(time.Second).String(),
			"DETAIL":  truncate(detail, 44),
		}))
	}
	setRows(&m.jobTable, jobRows)
}

// setRows replaces a table's contents while keeping the cursor where it was.
//
// Without this the selection would jump to the top on every one-second refresh, which makes
// the action keys unusable on a busy network.
func setRows(t *dataTable, rows []row) {
	cursor := t.Cursor()
	t.SetRows(rows)

	if cursor >= len(rows) {
		cursor = len(rows) - 1
	}
	if cursor < 0 {
		cursor = 0
	}
	t.SetCursor(cursor)
}

func orHidden(essid string) string {
	if essid == "" {
		return "<hidden>"
	}
	return essid
}

// bandCell abbreviates a band for a narrow column. The band matters as much as the channel:
// a 5 GHz network will not be heard from the other end of the floor, and an adapter parked on
// 2.4 GHz will never see it at all.
// bandCell renders the band with the 802.11 generations in parentheses: "2.4 (ax/n/g)".
//
// The two together are what an operator actually wants from one column. The band says where
// the access point is; the generations say what it is, and "2.4 (g)" - a radio with no HT at
// all, still on the floor - is a finding on sight. The parentheses are dropped first when the
// column is tight, because the band is the part that cannot be inferred.
func bandCell(band, phy string, width int) string {
	var label string
	switch {
	case strings.HasPrefix(band, "2.4"):
		label = "2.4"
	case strings.HasPrefix(band, "5"):
		label = "5"
	case strings.HasPrefix(band, "6"):
		label = "6"
	case band == "":
		return sFaint.Render("-")
	default:
		label = truncate(band, 4)
	}

	// The generations need "2.4 (ax/n/g)" worth of room. Below that the band alone is the
	// part that cannot be inferred from anything else on the row.
	if phy == "" || width < len(label)+len(phy)+3 {
		return sDim.Render(label)
	}
	// An old radio is worth noticing rather than reading past.
	style := sFaint
	if phy == "g" || phy == "b" || phy == "a" {
		style = sWarn
	}
	return sDim.Render(label) + style.Render(" ("+phy+")")
}

// clientCountCell shows how many clients are on an access point. Zero is dimmed rather than
// hidden: "no clients" is the answer to "why did that deauthentication do nothing".
func clientCountCell(n int) string {
	if n == 0 {
		return sFaint.Render("0")
	}
	return sGood.Render(fmt.Sprintf("%d", n))
}

// seenCell renders how recently an access point was heard: a bright age for one still on the air,
// a faint age for one that has dropped off. WARP keeps every AP it has ever seen, so this is what
// separates the live picture from the history - the "currently visible" airodump shows.
func seenCell(active bool, secs int) string {
	if secs < 0 {
		secs = 0
	}
	var age string
	switch {
	case secs < 60:
		age = fmt.Sprintf("%ds", secs)
	case secs < 3600:
		age = fmt.Sprintf("%dm", secs/60)
	default:
		age = fmt.Sprintf("%dh", secs/3600)
	}
	if active {
		return sGood.Render("●" + age)
	}
	return sFaint.Render(age)
}

// networkNameCell renders a network name for the client listing.
func networkNameCell(essid string, inScope bool) string {
	if essid == "" {
		return sFaint.Render("-")
	}
	if inScope {
		return sGood.Render(truncate(essid, 26))
	}
	return sText.Render(truncate(essid, 26))
}

// networkCell renders an access point's name for the listing.
//
// A network that cloaked its SSID and whose name WARP recovered anyway is marked with a small
// eye. That is worth seeing at a glance: the client believes that network is not advertising
// itself, and it is - which is a finding on its own, quite apart from anything else about it.
func networkCell(ap daemon.APView) string {
	name := networkStyle(ap).Render(truncate(orHidden(ap.ESSID), 30))
	if ap.Rogue {
		name += sErr.Render("⚑") // operator-marked potential rogue
	}
	if ap.Cloaked && ap.ESSID != "" {
		name += sWarn.Render("◉")
	}
	return name
}

// wrapText reflows text, indenting continuation lines.
func wrapText(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if lineLen > 0 && lineLen+1+len(w) > width {
			b.WriteString("\n" + indent)
			lineLen = 0
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}

// securityShort abbreviates a security class for the table column.
func securityShort(ap daemon.APView) string {
	s := string(ap.Security.Class)
	s = strings.TrimPrefix(s, "wpa_")
	switch s {
	case "enterprise":
		s = "802.1X"
	case "psk", "sae", "open", "wep", "owe":
	}
	if ap.Security.WPS {
		s += "+wps"
	}
	return s
}

// mfpCell renders the 802.11w posture, which decides whether deauthentication is worth trying.
// mfpCell renders the Protected Management Frames posture.
//
// "off" rather than a dash: an em dash reads as "not applicable", and PMF being absent is a
// finding rather than a blank. It is also the single fact that decides whether a targeted
// deauthentication is worth attempting at this access point.
func mfpCell(m recon.MFPState) string {
	switch m {
	case recon.MFPRequired:
		return sGood.Render("req")
	case recon.MFPCapable:
		return sWarn.Render("opt")
	case recon.MFPAbsent:
		return sErr.Render("off")
	default:
		return sFaint.Render("?")
	}
}

func jobStateStyle(s daemon.JobState) lipgloss.Style {
	switch s {
	case daemon.JobRunning:
		return sWarn
	case daemon.JobDone:
		return sGood
	case daemon.JobFailed, daemon.JobDenied:
		return sErr
	default:
		return sDim
	}
}

// cellByTitle reads a row's value for a named column, tolerating a column that was dropped
// because the terminal is narrow.
func cellByTitle(titles []string, row row, want string) string {
	for i, t := range titles {
		if t == want && i < len(row) {
			return row[i]
		}
	}
	return ""
}

// handleFormKey drives the certificate wizard.
//
// Every key belongs to the form while it is open. The alternative - leaving the tab's action
// keys live underneath - means typing an organisation name starts a Pixie Dust attempt at the
// letter P.
func (m *Model) handleFormKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	f := &m.form

	switch msg.Type {
	case tea.KeyEsc:
		m.form = certForm{}
		m.layout()
		return m, func() tea.Msg {
			return flashMsg{text: styleDim.Render("certificate wizard cancelled")}
		}

	case tea.KeyCtrlC:
		m.quitting = true
		return m, tea.Quit

	case tea.KeyUp, tea.KeyShiftTab:
		if f.cursor > 0 {
			f.cursor--
		}
		return m, nil

	case tea.KeyDown, tea.KeyTab:
		if f.cursor < len(f.fields)-1 {
			f.cursor++
		}
		return m, nil

	case tea.KeyEnter:
		// Enter moves on, and submits from the last field - the way a form behaves. Ctrl-G
		// submits from anywhere, so an operator who filled in only the common name does not
		// have to press enter nine more times.
		if f.cursor < len(f.fields)-1 {
			f.cursor++
			return m, nil
		}
		return m, m.submitCertForm()

	case tea.KeyCtrlG:
		return m, m.submitCertForm()

	case tea.KeyBackspace:
		fl := &f.fields[f.cursor]
		if n := len(fl.value); n > 0 {
			fl.value = fl.value[:n-1]
		}
		return m, nil

	case tea.KeyCtrlU:
		f.fields[f.cursor].value = ""
		return m, nil

	case tea.KeySpace:
		f.fields[f.cursor].value += " "
		return m, nil

	case tea.KeyRunes:
		f.fields[f.cursor].value += string(msg.Runes)
		return m, nil
	}
	return m, nil
}

// submitCertForm validates and sends the wizard.
func (m *Model) submitCertForm() tea.Cmd {
	if m.form.value("cn") == "" {
		// Checked here rather than only at the daemon: it is what a trust prompt shows, and a
		// round trip to be told so is a round trip that did not need to happen.
		m.form.err = "A common name is required - it is what a supplicant's trust prompt shows."
		for i, fl := range m.form.fields {
			if fl.key == "cn" {
				m.form.cursor = i
				break
			}
		}
		return nil
	}

	params := m.form.params()
	essid := m.form.essid
	m.form = certForm{}
	m.layout()

	return m.runAction("certs.generate", params,
		"certificate generated for "+essid+" - it is now what the rogue will present")
}
