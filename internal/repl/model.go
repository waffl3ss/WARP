// Package repl implements WARP's interactive dashboard.
//
// It is a thin RPC client, exactly like the one-shot subcommands: the daemon owns the radios
// and every running job, so the console can be closed, killed or disconnected at any moment
// without affecting the engagement. Nothing here is console-only - every action maps onto the
// same RPC surface `warp <subcommand>` uses.
//
// The layout is a fixed status header, a tab bar, a live table, and a key hint line. The
// intent is that an operator who has never read the documentation can open it and see what is
// on the air, because on site nobody is reading documentation.
package repl

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/eap/certs"
	"github.com/waffl3ss/warp/internal/hunt"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/store"
)

// Refresh intervals.
const (
	// refreshInterval is how often the dashboard repolls. Fast enough that counters feel
	// live, slow enough not to flood the daemon.
	refreshInterval = time.Second
	// maxScrollback bounds retained log lines.
	maxScrollback = 5000
)

// View is one dashboard tab.
type View int

// Tabs, in the order they appear.
const (
	ViewOverview View = iota
	ViewAPs
	ViewStations
	ViewCredentials
	ViewFindings
	ViewJobs
	ViewRadios
	ViewEvilTwin
	ViewLog
)

var viewNames = []string{
	"Overview", "Access Points", "Clients", "Credentials", "Findings", "Jobs",
	"Radios", "Evil Twin", "Log",
}

func (v View) String() string {
	if int(v) < len(viewNames) {
		return viewNames[v]
	}
	return "?"
}

// snapshot is everything the dashboard displays, refreshed as a set.
//
// Polled together so the panes never disagree with each other - a findings count in the
// header that does not match the findings tab is the kind of thing that makes an operator
// stop trusting the display.
type snapshot struct {
	status   daemon.StatusResult
	aps      []daemon.APView
	stations []daemon.StationView
	findings []store.Finding
	unclass  []string
	jobs     []daemon.Job
	hashes   daemon.HashesResult
	hunts    []hunt.State
	eap      daemon.EAPStatus
	radios   []daemon.RadioInfo
	assigns  []radio.Assignment
	certs    daemon.CertsListResult
	err      error
}

// Model is the dashboard.
type Model struct {
	client *rpc.Client
	ctx    context.Context
	socket string

	view View
	data snapshot

	apTable   dataTable
	staTable  dataTable
	hashTable dataTable
	findTable dataTable
	jobTable  dataTable

	// Column titles that survived fitting, per table. Rows are built from these.
	apCols   []string
	staCols  []string
	hashCols []string
	findCols []string
	jobCols  []string
	logView  viewport.Model
	input    textinput.Model

	// cmdMode is true while the command line has focus.
	cmdMode bool

	lines      []string
	history    []string
	historyPos int

	tabCandidates []string
	tabIndex      int
	tabPrefix     string
	completions   completionCache

	width, height int
	bodyHeight    int
	// sidebar is on when the terminal is wide enough for a detail pane beside the table.
	sidebar      bool
	sidebarWidth int
	// sidebarOff is the operator's veto, toggled with `v`. Some people want the widest
	// possible listing even on a wide screen.
	sidebarOff bool

	// paused freezes the display. The daemon keeps capturing - this only stops the dashboard
	// redrawing, so a row can be read, copied or photographed without it moving.
	paused bool
	// copyMode drops the alternate screen and prints the current table as plain text, so the
	// terminal's own selection and clipboard work on it. Over SSH that is the only way to get
	// a BSSID out of here and into a ticket.
	copyMode bool

	// sort is the column each table is sorted by, and the direction.
	// showHelp overlays the full key list.
	showHelp bool

	// certCursor and radioCursor are the cursors on the two tabs that are not tables.
	certCursor  int
	radioCursor int

	// form is the certificate wizard, when it is open. The Evil Twin tab renders it instead
	// of the library while it is active and swallows every keystroke into it.
	form certForm

	// colWidth is the width each column was actually fitted to, so a cell that can render at
	// more than one width knows which one it got.
	colWidth map[string]int

	sortKey map[View]string
	sortAsc map[View]bool

	// rate holds a short history of capture rate per radio, for the header sparkline.
	rate      map[string][]float64
	lastFrame map[string]uint64
	lastRate  time.Time

	ready    bool
	quitting bool
	// flash is a transient message shown in the hint line.
	flash      string
	flashUntil time.Time
}

// Messages.
type (
	snapshotMsg   struct{ snap snapshot }
	eventMsg      struct{ event rpc.Event }
	eventsDone    struct{}
	completionMsg struct{ cache completionCache }
	outputMsg     struct{ lines []string }
	flashMsg      struct{ text string }
	tickMsg       time.Time
)

// New builds the dashboard.
func New(ctx context.Context, client *rpc.Client, socket string) *Model {
	in := textinput.New()
	in.Prompt = ""
	in.Placeholder = "command (try `help`)"
	in.CharLimit = 512

	m := &Model{
		client:     client,
		ctx:        ctx,
		socket:     socket,
		input:      in,
		historyPos: -1,
		rate:       make(map[string][]float64),
		lastFrame:  make(map[string]uint64),
		sortKey:    make(map[View]string),
		sortAsc:    make(map[View]bool),
	}

	// Initial columns only: layout() refits them to the terminal on the first window-size
	// message, before anything is drawn.
	m.apTable.SetColumns([]column{{Title: "BSSID", Width: 17}, {Title: "NETWORK", Width: 20}})
	m.staTable.SetColumns([]column{{Title: "CLIENT", Width: 17}, {Title: "ASSOCIATED", Width: 17}})
	m.hashTable.SetColumns([]column{{Title: "KIND", Width: 6}, {Title: "NETWORK", Width: 20}})
	m.findTable.SetColumns([]column{{Title: "TIER", Width: 9}, {Title: "BSSID", Width: 17}})
	m.jobTable.SetColumns([]column{{Title: "#", Width: 3}, {Title: "KIND", Width: 9}})

	return m
}

// Init starts the pollers.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		m.refresh(),
		m.fetchCompletions(),
		m.waitForEvent(),
		tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) }),
	)
}

// waitForEvent blocks on the daemon's event stream.
//
// Asynchronous events land in the log tab as they happen - a PMKID captured while the
// operator is reading the findings tab must not be silently dropped.
func (m *Model) waitForEvent() tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-m.client.Events()
		if !ok {
			return eventsDone{}
		}
		return eventMsg{event: ev}
	}
}

// refresh polls every pane's data in one round.
func (m *Model) refresh() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 4*time.Second)
		defer cancel()

		var snap snapshot
		if err := m.client.Call(ctx, "status", nil, &snap.status); err != nil {
			snap.err = err
			return snapshotMsg{snap: snap}
		}
		m.client.Call(ctx, "aps.list", nil, &snap.aps)
		m.client.Call(ctx, "stations.list", nil, &snap.stations)
		m.client.Call(ctx, "jobs.list", nil, &snap.jobs)
		m.client.Call(ctx, "hashes.list", nil, &snap.hashes)
		m.client.Call(ctx, "hunt.state", nil, &snap.hunts)
		m.client.Call(ctx, "eap.status", nil, &snap.eap)
		m.client.Call(ctx, "radios.list", nil, &snap.radios)
		m.client.Call(ctx, "radios.assignments", nil, &snap.assigns)
		m.client.Call(ctx, "certs.list", nil, &snap.certs)

		var findings struct {
			Findings     []store.Finding `json:"findings"`
			Unclassified []string        `json:"unclassified"`
		}
		if err := m.client.Call(ctx, "rogue.list", nil, &findings); err == nil {
			snap.findings = findings.Findings
			snap.unclass = findings.Unclassified
		}

		return snapshotMsg{snap: snap}
	}
}

// Update handles one message.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()
		m.ready = true
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tickMsg:
		// The ticker keeps running while paused so resuming is immediate; only the poll is
		// skipped. The daemon is unaffected either way - it owns the capture, and nothing
		// here can stop it.
		if !m.paused {
			cmds = append(cmds, m.refresh())
		}
		cmds = append(cmds, tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) }))

	case snapshotMsg:
		if m.paused {
			// A poll already in flight when the operator pressed pause must not redraw
			// underneath them.
			break
		}
		m.data = msg.snap
		m.recordRates()
		m.populate()

	case completionMsg:
		m.completions = msg.cache

	case eventMsg:
		m.appendEvent(msg.event)
		cmds = append(cmds, m.waitForEvent())

	case eventsDone:
		m.appendLine(styleErr.Render("[!] connection to warpd closed - the engagement is " +
			"unaffected; reattach with `warp console`"))

	case outputMsg:
		for _, l := range msg.lines {
			m.appendLine(l)
		}
		// Command output goes to the log tab, so switch there to show it.
		if len(msg.lines) > 0 && m.view != ViewLog {
			m.view = ViewLog
			m.layout()
		}

	case flashMsg:
		m.flash = msg.text
		m.flashUntil = time.Now().Add(4 * time.Second)
	}

	// Route input to whichever component has focus.
	var cmd tea.Cmd
	if m.cmdMode {
		m.input, cmd = m.input.Update(msg)
	} else {
		switch m.view {
		case ViewAPs:
			_, cmd = m.apTable.Update(msg)
		case ViewStations:
			_, cmd = m.staTable.Update(msg)
		case ViewFindings:
			_, cmd = m.findTable.Update(msg)
		case ViewJobs:
			_, cmd = m.jobTable.Update(msg)
		case ViewLog:
			m.logView, cmd = m.logView.Update(msg)
		}
	}
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// selectedBSSID returns the BSSID under the cursor on the current tab, if any.
//
// This is what makes the action keys work without typing a MAC address: the operator points
// at a row and presses a key. Nobody types MAC addresses by hand.
func (m *Model) selectedBSSID() string {
	switch m.view {
	case ViewAPs:
		if row := m.apTable.SelectedRow(); len(row) > 0 {
			return row[0]
		}
	case ViewFindings:
		// Findings are grouped by name now, so a row is a group, not a single BSSID. Resolve to
		// the first affected asset so an action key still has a concrete target to act on.
		if g, ok := m.selectedFindingGroup(); ok && len(g.Assets) > 0 {
			return g.Assets[0].BSSID
		}
	case ViewStations:
		if row := m.staTable.SelectedRow(); len(row) > 0 {
			return row[0]
		}
	}
	return ""
}

func (m *Model) appendLine(s string) {
	m.lines = append(m.lines, s)
	if len(m.lines) > maxScrollback {
		m.lines = m.lines[len(m.lines)-maxScrollback:]
	}
	m.refreshLog()
}

func (m *Model) refreshLog() {
	if m.logView.Width == 0 {
		return
	}
	m.logView.SetContent(strings.Join(m.lines, "\n"))
	m.logView.GotoBottom()
}

func (m *Model) appendEvent(ev rpc.Event) {
	style := styleDim
	switch ev.Level {
	case rpc.LevelGood:
		style = styleGood
	case rpc.LevelWarn:
		style = styleWarn
	}
	stamp := styleDim.Render(time.Now().Format("15:04:05") + " ")
	m.appendLine(stamp + style.Render(ev.Text))
}

// View renders the dashboard.

// rateHistory is how many samples the header sparkline keeps.
const rateHistory = 24

// recordRates turns cumulative frame counters into a per-radio rate series.
//
// The counters are monotonic totals, so the sparkline needs the delta between polls. A radio
// that vanishes keeps its history rather than being dropped, so a brief RPC failure does not
// blank the graph.
func (m *Model) recordRates() {
	now := time.Now()
	elapsed := now.Sub(m.lastRate).Seconds()
	m.lastRate = now

	for _, r := range m.data.status.Recon.Radios {
		prev, seen := m.lastFrame[r.RadioID]
		m.lastFrame[r.RadioID] = r.Capture.Frames

		if !seen || elapsed <= 0 || r.Capture.Frames < prev {
			continue
		}
		rate := float64(r.Capture.Frames-prev) / elapsed

		h := append(m.rate[r.RadioID], rate)
		if len(h) > rateHistory {
			h = h[len(h)-rateHistory:]
		}
		m.rate[r.RadioID] = h
	}
}

// selectedAP returns the access point under the cursor.
func (m *Model) selectedAP() (daemon.APView, bool) {
	want := cellByTitle(m.apCols, m.apTable.SelectedRow(), "BSSID")
	if want == "" {
		return daemon.APView{}, false
	}
	for _, ap := range m.data.aps {
		if ap.BSSID.String() == want {
			return ap, true
		}
	}
	return daemon.APView{}, false
}

// selectedStation returns the station under the cursor.
func (m *Model) selectedStation() (daemon.StationView, bool) {
	want := strings.TrimSuffix(
		cellByTitle(m.staCols, m.staTable.SelectedRow(), "CLIENT"), "*")
	if want == "" {
		return daemon.StationView{}, false
	}
	for _, st := range m.data.stations {
		if st.MAC.String() == want {
			return st, true
		}
	}
	return daemon.StationView{}, false
}

// The findings tab groups by finding name; selection resolves through selectedFindingGroup
// (internal/repl/findings.go) rather than a single (BSSID, label) pair.

// ifnameFor maps a radio id (phyNNN) to its interface name (wlanN) for display - phyNNN is an
// internal handle and must never reach the operator. Falls back to the id if unknown.
func (m *Model) ifnameFor(id string) string {
	if id == "" {
		return ""
	}
	for _, r := range m.data.radios {
		if r.ID == id {
			if r.Ifname != "" {
				return r.Ifname
			}
			return id
		}
	}
	return id
}

// certForm is the console's certificate wizard.
//
// A form rather than a prefilled command line. Dropping into the prompt with
// `eap cert generate <essid> --common-name ` looked like it would work and did not: the
// console's command set does not carry the subcommand or its dozen flags, so pressing enter
// closed the prompt and nothing happened. Typing a dozen flags on one line is also not what
// the browser does, and these two are supposed to be the same tool.
type certForm struct {
	active bool
	essid  string
	fields []certField
	cursor int
	err    string
}

// certField is one line of the wizard.
type certField struct {
	key         string
	label       string
	placeholder string
	value       string
	required    bool
}

// newCertForm builds the wizard for a network.
func newCertForm(essid string) certForm {
	return certForm{
		active: true,
		essid:  essid,
		fields: []certField{
			{key: "cn", label: "Common name", placeholder: "radius.acme-corp.internal", required: true},
			{key: "o", label: "Organization", placeholder: "ACME Corporation"},
			{key: "ou", label: "Organizational unit", placeholder: "IT Infrastructure"},
			{key: "c", label: "Country", placeholder: "US"},
			{key: "st", label: "State"},
			{key: "l", label: "Locality"},
			{key: "email", label: "Email"},
			{key: "icn", label: "Issuer common name", placeholder: "ACME Corporate Issuing CA"},
			{key: "io", label: "Issuer organization", placeholder: "ACME Corporation"},
			{key: "dns", label: "DNS names", placeholder: "comma separated"},
			{key: "days", label: "Validity in days", placeholder: "825"},
			{key: "bits", label: "RSA key bits", placeholder: "2048"},
		},
	}
}

// value returns a field's contents by key.
func (f certForm) value(key string) string {
	for _, fl := range f.fields {
		if fl.key == key {
			return strings.TrimSpace(fl.value)
		}
	}
	return ""
}

// params builds the RPC request from what was typed.
func (f certForm) params() daemon.CertGenerateParams {
	atoi := func(s string) int {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0
		}
		return n
	}

	var dns []string
	for _, part := range strings.Split(f.value("dns"), ",") {
		if p := strings.TrimSpace(part); p != "" {
			dns = append(dns, p)
		}
	}

	return daemon.CertGenerateParams{
		ESSID: f.essid,
		Fields: certs.Fields{
			CommonName:         f.value("cn"),
			Organization:       f.value("o"),
			OrganizationalUnit: f.value("ou"),
			Country:            f.value("c"),
			Province:           f.value("st"),
			Locality:           f.value("l"),
			Email:              f.value("email"),
			IssuerCommonName:   f.value("icn"),
			IssuerOrganization: f.value("io"),
			DNSNames:           dns,
			ValidityDays:       atoi(f.value("days")),
			KeyBits:            atoi(f.value("bits")),
			Note:               "generated from the console",
		},
	}
}
