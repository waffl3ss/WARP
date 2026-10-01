package repl

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/store"
)

// command is one console verb.
//
// Every command maps onto the same RPC surface the one-shot subcommands use. Nothing is
// REPL-only, so anything an operator can do interactively can be scripted.
type command struct {
	name    string
	aliases []string
	usage   string
	summary string
	// run executes the command and returns lines to append to scrollback.
	run func(m *Model, args []string) ([]string, error)
}

var commands []command

// commandNames returns every verb and alias, for completion.
func commandNames() []string {
	var out []string
	for _, c := range commands {
		out = append(out, c.name)
		out = append(out, c.aliases...)
	}
	sort.Strings(out)
	return out
}

func lookupCommand(name string) (command, bool) {
	for _, c := range commands {
		if c.name == name {
			return c, true
		}
		for _, a := range c.aliases {
			if a == name {
				return c, true
			}
		}
	}
	return command{}, false
}

// dispatch runs a line. The bool reports whether the console should exit.
func (m *Model) dispatch(line string) (tea.Cmd, bool) {
	fields := strings.Fields(line)
	name, args := fields[0], fields[1:]

	if name == "exit" || name == "quit" {
		return nil, true
	}

	cmd, ok := lookupCommand(name)
	if !ok {
		m.appendLine(styleErr.Render(fmt.Sprintf("unknown command %q - try `help`", name)))
		return nil, false
	}

	// Commands run off the UI goroutine so a slow RPC never freezes the prompt. Attacks are
	// background jobs on the daemon anyway; this covers the round trip.
	return func() tea.Msg {
		lines, err := cmd.run(m, args)
		if err != nil {
			return outputMsg{lines: []string{styleErr.Render("  " + err.Error())}}
		}
		return outputMsg{lines: lines}
	}, false
}

// call is a short-timeout RPC helper for console commands.
func (m *Model) call(method string, params, out any) error {
	ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
	defer cancel()
	return m.client.Call(ctx, method, params, out)
}

func init() {
	commands = []command{
		{
			name: "help", summary: "list commands",
			run: func(m *Model, args []string) ([]string, error) {
				var out []string
				out = append(out, styleDim.Render("  commands (every one maps to the same RPC the subcommands use):"))
				for _, c := range commands {
					usage := c.usage
					if usage == "" {
						usage = c.name
					}
					out = append(out, fmt.Sprintf("  %-34s %s", usage, styleDim.Render(c.summary)))
				}
				out = append(out, fmt.Sprintf("  %-34s %s", "exit", styleDim.Render("leave the console; the engagement keeps running")))
				return out, nil
			},
		},
		{
			name: "recon", usage: "recon start|stop|status",
			summary: "control the capture engine",
			run: func(m *Model, args []string) ([]string, error) {
				action := "status"
				if len(args) > 0 {
					action = args[0]
				}
				switch action {
				case "start", "stop", "status":
				default:
					return nil, fmt.Errorf("recon start|stop|status")
				}
				var raw json.RawMessage
				if err := m.call("recon."+action, nil, &raw); err != nil {
					return nil, err
				}
				if action == "stop" {
					return []string{styleGood.Render("  recon stopped; radios released")}, nil
				}
				var st daemon.EngineStats
				if err := json.Unmarshal(raw, &st); err != nil {
					return nil, err
				}
				return reconLines(st), nil
			},
		},
		{
			name: "aps", aliases: []string{"bssids"}, usage: "aps [essid]",
			summary: "list observed access points",
			run: func(m *Model, args []string) ([]string, error) {
				params := daemon.APsListParams{}
				if len(args) > 0 {
					params.ESSID = args[0]
				}
				var aps []daemon.APView
				if err := m.call("aps.list", params, &aps); err != nil {
					return nil, err
				}
				if len(aps) == 0 {
					return []string{styleDim.Render("  nothing observed yet")}, nil
				}
				out := []string{styleDim.Render(fmt.Sprintf(
					"  %-17s %-24s %3s %5s %-22s %s", "BSSID", "ESSID", "CH", "RSSI", "SECURITY", "SCOPE"))}
				for _, ap := range aps {
					essid := ap.ESSID
					if essid == "" {
						essid = "<hidden>"
					}
					line := fmt.Sprintf("  %-17s %-24s %3d %5s %-22s %s",
						ap.BSSID, truncate(essid, 24), ap.Channel,
						rssiCell(ap.LastRSSI, ap.HasRSSI),
						truncate(ap.Security.Describe(), 22), scopeCell(ap))
					if ap.InScope {
						line = styleGood.Render(line)
					}
					out = append(out, line)
				}
				return out, nil
			},
		},
		{
			name: "stations", aliases: []string{"clients"},
			summary: "list observed client devices",
			run: func(m *Model, args []string) ([]string, error) {
				var sts []daemon.StationView
				if err := m.call("stations.list", nil, &sts); err != nil {
					return nil, err
				}
				if len(sts) == 0 {
					return []string{styleDim.Render("  no client devices observed")}, nil
				}
				out := []string{styleDim.Render(fmt.Sprintf(
					"  %-18s %-17s %5s %7s %s", "MAC", "BSSID", "RSSI", "FRAMES", "PROBED"))}
				for _, st := range sts {
					bssid := st.BSSID.String()
					if st.BSSID.IsZero() {
						bssid = "-"
					}
					mark := " "
					if st.Randomised {
						mark = "*"
					}
					out = append(out, fmt.Sprintf("  %-17s%s %-17s %5s %7d %s",
						st.MAC, mark, bssid, rssiCell(st.LastRSSI, st.HasRSSI), st.Frames,
						truncate(strings.Join(st.ProbedESSIDs, ","), 30)))
				}
				out = append(out, styleDim.Render("  * randomised MAC - may be one device seen repeatedly"))
				return out, nil
			},
		},
		{
			name: "scope", usage: "scope list|confirm <bssid>|reject <bssid>|acknowledge <essid>|add <essid>|remove <essid>",
			summary: "inspect and edit the ESSID scope",
			run:     runScope,
		},
		{
			name: "walkthrough", aliases: []string{"walk"}, usage: "walkthrough [name|end|list|delete <id>|rename <id> <name>|split <id> <ts> [name]|devices <id>]",
			summary: "tag observations with where you are",
			run:     runWalkthrough,
		},
		{
			name: "localize", aliases: []string{"locate"}, usage: "localize <bssid|mac>",
			summary: "rank where a device was heard loudest",
			run:     runLocalize,
		},
		{
			name: "psk", usage: "psk <bssid> [--deauth <station>] [--count <frames>] [--seconds <dur>]",
			summary: "solicit a PMKID, or deauthenticate to force a handshake",
			run:     runPSK,
		},
		{
			name: "rogue", usage: "rogue classify|list|karma-test",
			summary: "population clustering and classification",
			run:     runRogue,
		},
		{
			name: "hunt", usage: "hunt <bssid|mac>",
			summary: "direction-find a device",
			run:     runHunt,
		},
		{
			name: "jobs", summary: "list background jobs",
			run: func(m *Model, args []string) ([]string, error) {
				var jobs []daemon.Job
				if err := m.call("jobs.list", nil, &jobs); err != nil {
					return nil, err
				}
				if len(jobs) == 0 {
					return []string{styleDim.Render("  no jobs")}, nil
				}
				now := time.Now()
				var out []string
				for _, j := range jobs {
					detail := j.Detail
					if j.Error != "" {
						detail = j.Error
					}
					line := fmt.Sprintf("  %-4s %-12s %-18s %-8s %8s  %s",
						j.ID, j.Kind, j.Target, j.State,
						j.Elapsed(now).Round(time.Second), truncate(detail, 40))
					switch j.State {
					case daemon.JobFailed, daemon.JobDenied:
						line = styleWarn.Render(line)
					case daemon.JobDone:
						line = styleGood.Render(line)
					}
					out = append(out, line)
				}
				return out, nil
			},
		},
		{
			name: "kill", usage: "kill <job-id>",
			summary: "cancel a running job",
			run: func(m *Model, args []string) ([]string, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("kill <job-id>")
				}
				if err := m.call("jobs.kill", map[string]string{"id": args[0]}, nil); err != nil {
					return nil, err
				}
				return []string{styleGood.Render("  job " + args[0] + " killed")}, nil
			},
		},
		{
			name: "radios", usage: "radios [list|assignments|lock <radio> <ch>|unlock [radio]|reset <radio>|regdomain [cc]|channels <radio> [1,6,11] [no5ghz] [random]]",
			summary: "show adapters, pin one to a channel, or USB-reset a wedged one",
			run: func(m *Model, args []string) ([]string, error) {
				if len(args) > 0 && args[0] == "reset" {
					if len(args) != 2 {
						return nil, fmt.Errorf("usage: radios reset <radio> (stop capture first)")
					}
					var out map[string]any
					if err := m.call("radios.reset", daemon.RadioResetParams{RadioID: args[1]}, &out); err != nil {
						return nil, err
					}
					return []string{
						styleGood.Render(fmt.Sprintf("  %v (%v) reset and back online", out["radio_id"], out["ifname"])),
						styleDim.Render(fmt.Sprintf("  %v", out["note"])),
					}, nil
				}
				if len(args) > 0 && args[0] == "lock" {
					if len(args) != 3 {
						return nil, fmt.Errorf("usage: radios lock <radio> <channel>")
					}
					ch, err := strconv.Atoi(args[2])
					if err != nil {
						return nil, fmt.Errorf("channel must be a number: %q", args[2])
					}
					var out map[string]any
					if err := m.call("radios.lock", daemon.RadioLockParams{
						RadioID: args[1], Channel: ch,
					}, &out); err != nil {
						return nil, err
					}
					return []string{
						styleGood.Render(fmt.Sprintf("  %v pinned to channel %v", out["radio_id"], out["channel"])),
						styleDim.Render(fmt.Sprintf("  %v", out["note"])),
					}, nil
				}
				if len(args) > 0 && args[0] == "unlock" {
					var p daemon.RadioUnlockParams
					if len(args) > 1 {
						p.RadioID = args[1]
					}
					var out map[string]any
					if err := m.call("radios.unlock", p, &out); err != nil {
						return nil, err
					}
					released, _ := out["released"].([]any)
					if len(released) == 0 {
						return []string{styleDim.Render("  nothing was pinned")}, nil
					}
					var lines []string
					for _, id := range released {
						lines = append(lines, styleGood.Render(
							fmt.Sprintf("  %v back on the channel plan", id)))
					}
					return lines, nil
				}
				if len(args) > 0 && args[0] == "assignments" {
					var as []struct {
						Role, RadioID, Ifname, Iftype string
					}
					if err := m.call("radios.assignments", nil, &as); err != nil {
						return nil, err
					}
					var out []string
					for _, a := range as {
						out = append(out, fmt.Sprintf("  %-8s %-10s %s",
							a.Role, a.Ifname, a.Iftype))
					}
					if len(out) == 0 {
						out = []string{styleDim.Render("  no radios assigned")}
					}
					return out, nil
				}
				if len(args) > 0 && args[0] == "regdomain" {
					if len(args) > 1 {
						var r daemon.RegDomainResult
						if err := m.call("radios.set-regdomain", map[string]any{"cc": args[1]}, &r); err != nil {
							return nil, err
						}
						return []string{styleGood.Render("  regulatory domain set to " + r.CC)}, nil
					}
					var r daemon.RegDomainResult
					if err := m.call("radios.regdomain", nil, &r); err != nil {
						return nil, err
					}
					cc := r.CC
					if cc == "" {
						cc = "00"
					}
					note := ""
					if r.IsWorld {
						note = styleDim.Render("  (world default - 5/6 GHz receive-only; set a country to transmit)")
					}
					return []string{"  regulatory domain: " + cc + note}, nil
				}
				if len(args) > 0 && args[0] == "channels" {
					// radios channels <radio> [1,6,11] [no5ghz] [random]. No channel list clears the
					// override and returns the adapter to a full ascending sweep.
					if len(args) < 2 {
						return nil, fmt.Errorf("usage: radios channels <radio> [1,6,11] [no5ghz] [random]")
					}
					p := daemon.RadioChannelsParams{RadioID: args[1]}
					for _, a := range args[2:] {
						switch a {
						case "no5ghz", "no5", "no-5ghz":
							p.Disable5GHz = true
						case "random", "rand":
							p.Random = true
						default:
							for _, part := range strings.Split(a, ",") {
								if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n > 0 {
									p.Channels = append(p.Channels, n)
								}
							}
						}
					}
					var res map[string]any
					if err := m.call("radios.channels", p, &res); err != nil {
						return nil, err
					}
					return []string{styleGood.Render(fmt.Sprintf("  %v sweeping %v channel(s)%s%s",
						res["radio_id"], res["usable_channels"],
						map[bool]string{true: ", 5 GHz off"}[p.Disable5GHz],
						map[bool]string{true: ", random hop"}[p.Random]))}, nil
				}

				var radios []daemon.RadioInfo
				if err := m.call("radios.list", nil, &radios); err != nil {
					return nil, err
				}
				var out []string
				// Show the regulatory domain at the top - it decides whether the upper bands are
				// transmit-usable, and there is nowhere else in the TUI it is visible.
				var reg daemon.RegDomainResult
				if err := m.call("radios.regdomain", nil, &reg); err == nil {
					cc := reg.CC
					if cc == "" {
						cc = "00"
					}
					line := "  regulatory domain: " + cc
					if reg.IsWorld {
						line += styleDim.Render("  (world - 5/6 GHz rx-only; `radios regdomain US` to transmit)")
					}
					out = append(out, line, "")
				}
				for _, r := range radios {
					// Interface name, not the phy index - phyNNN is an internal handle.
					line := fmt.Sprintf("  %-10s %-12s bands=%-22s injection=%s",
						r.Ifname, r.Driver, strings.Join(r.Bands, "/"), r.Injection)
					if r.APAndMonitor {
						line += "  ap+monitor"
					}
					out = append(out, line)
				}
				return out, nil
			},
		},
		{
			name: "precheck", usage: "precheck [fix <check>]",
			summary: "check the host is ready to capture (rfkill, NetworkManager, wpa_supplicant), and fix issues",
			run:     runPrecheck,
		},
		{
			name: "certs", usage: "certs list|delete <essid> <id>|import <essid> <cert.pem> <key.pem>",
			summary: "manage the certificate library the rogue presents",
			run:     runCerts,
		},
		{
			name: "report", usage: "report [json [all]]", summary: "write the engagement report (md, or json for the machine-readable one)",
			run: func(m *Model, args []string) ([]string, error) {
				// Bare `report` writes report.md (same as the R key). `report json` / `report json all`
				// write the machine-readable report.json + report-in-scope.json.
				if len(args) >= 1 && (args[0] == "json" || args[0] == "export") {
					scoped := !(len(args) >= 2 && args[1] == "all")
					var r struct {
						Path string `json:"path"`
					}
					if err := m.call("report.export", map[string]bool{"scoped": scoped}, &r); err != nil {
						return nil, err
					}
					return []string{styleGood.Render(
						"  wrote report.json and report-in-scope.json to the workspace")}, nil
				}
				var r struct {
					Path     string `json:"path"`
					Findings int    `json:"findings"`
				}
				if err := m.call("report", nil, &r); err != nil {
					return nil, err
				}
				return []string{styleGood.Render(fmt.Sprintf("  report written to %s (%d findings)", r.Path, r.Findings))}, nil
			},
		},
		{
			name: "export", summary: "regenerate the flat-file projections",
			run: func(m *Model, args []string) ([]string, error) {
				var r struct {
					Directory       string   `json:"directory"`
					PMKIDHashes     int      `json:"pmkid_hashes"`
					HandshakeHashes int      `json:"handshake_hashes"`
					Files           []string `json:"files"`
				}
				if err := m.call("export", nil, &r); err != nil {
					return nil, err
				}
				return []string{
					styleGood.Render("  exported to " + r.Directory),
					styleDim.Render(fmt.Sprintf("  %d PMKID and %d handshake hashes ready for the cracking rig",
						r.PMKIDHashes, r.HandshakeHashes)),
				}, nil
			},
		},
		{
			name: "status", summary: "show the full daemon status",
			run: func(m *Model, args []string) ([]string, error) {
				var st daemon.StatusResult
				if err := m.call("status", nil, &st); err != nil {
					return nil, err
				}
				out := []string{
					fmt.Sprintf("  workspace   %s", st.Workspace),
					fmt.Sprintf("  uptime      %s", st.Uptime),
					fmt.Sprintf("  scope       %d ESSIDs", st.ScopeESSIDs),
					fmt.Sprintf("  radios      %d (survey pinned to %s)", st.Radios, orDash(st.SurveyRadio)),
					fmt.Sprintf("  observed    %d aps, %d stations, %d observations",
						st.Counts.APs, st.Counts.Stations, st.Counts.Observations),
					fmt.Sprintf("  hashes      %d pmkid, %d handshake", st.PMKIDHashes, st.HandshakeHashes),
				}
				for _, e := range st.PendingAcks {
					out = append(out, styleWarn.Render(
						fmt.Sprintf("  ! %q is generic and unacknowledged - active work blocked there", e)))
				}
				return out, nil
			},
		},
		{
			name: "clear", summary: "clear the scrollback",
			run: func(m *Model, args []string) ([]string, error) {
				m.lines = nil
				m.refreshLog()
				return nil, nil
			},
		},
	}
}

func runPrecheck(m *Model, args []string) ([]string, error) {
	if len(args) > 0 && args[0] == "fix" {
		if len(args) < 2 {
			return nil, fmt.Errorf("precheck fix <check> (a name from `precheck`)")
		}
		var checks []daemon.PrecheckView
		if err := m.call("precheck.fix", daemon.PrecheckFixParams{Name: strings.Join(args[1:], " ")}, &checks); err != nil {
			return nil, err
		}
		return precheckLines(checks, "fix applied - "), nil
	}
	var checks []daemon.PrecheckView
	if err := m.call("precheck.list", nil, &checks); err != nil {
		return nil, err
	}
	return precheckLines(checks, ""), nil
}

func precheckLines(checks []daemon.PrecheckView, prefix string) []string {
	if len(checks) == 0 {
		return []string{styleGood.Render("  " + prefix + "host looks ready")}
	}
	var out []string
	for _, c := range checks {
		style := styleGood
		switch c.Level {
		case "warn", "fixable":
			style = styleWarn
		case "fail":
			style = styleErr
		case "info":
			style = styleDim
		}
		line := fmt.Sprintf("  %-6s %-14s %s", c.Level, c.Name, c.Detail)
		if c.Fixable {
			line += styleDim.Render("   (precheck fix " + c.Name + ")")
		}
		out = append(out, style.Render(line))
	}
	return out
}

func runCerts(m *Model, args []string) ([]string, error) {
	action := "list"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "list":
		var r struct {
			Networks map[string][]struct {
				ID, Subject, Issuer string
				Expired, Selected   bool
			} `json:"networks"`
		}
		if err := m.call("certs.list", nil, &r); err != nil {
			return nil, err
		}
		var out []string
		for essid, list := range r.Networks {
			out = append(out, styleSection.Render("  "+essid))
			for _, c := range list {
				mark := " "
				if c.Selected {
					mark = "*"
				}
				status := c.Subject
				if c.Expired {
					status = styleErr.Render("EXPIRED ") + status
				}
				out = append(out, fmt.Sprintf("   %s %-10s %s", mark, c.ID, status))
			}
		}
		if len(out) == 0 {
			out = []string{styleDim.Render("  no certificates in the library")}
		}
		return out, nil

	case "delete", "rm":
		if len(args) < 3 {
			return nil, fmt.Errorf("certs delete <essid> <id>")
		}
		if err := m.call("certs.delete", daemon.CertDeleteParams{ESSID: args[1], ID: args[2]}, nil); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  certificate removed")}, nil

	case "import":
		if len(args) < 4 {
			return nil, fmt.Errorf("certs import <essid> <cert.pem path> <key.pem path>")
		}
		if err := m.call("certs.import", daemon.CertImportParams{
			ESSID: args[1], CertPath: args[2], KeyPath: args[3], Note: "imported from the console",
		}, nil); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  certificate imported - select it on the Evil Twin tab to present it")}, nil
	}
	return nil, fmt.Errorf("certs list|delete <essid> <id>|import <essid> <cert.pem> <key.pem>")
}

func runScope(m *Model, args []string) ([]string, error) {
	action := "list"
	if len(args) > 0 {
		action = args[0]
	}

	switch action {
	case "list":
		var r struct {
			ESSIDs        []store.Finding   `json:"-"`
			Entries       []scopeEntry      `json:"essids"`
			Confirmations map[string]string `json:"confirmations"`
			Rejections    map[string]string `json:"rejections"`
		}
		if err := m.call("scope.list", nil, &r); err != nil {
			return nil, err
		}
		var out []string
		for _, e := range r.Entries {
			line := fmt.Sprintf("  %-28s", e.ESSID)
			if e.Generic {
				line += " generic"
			}
			if !e.ActiveWorkReady {
				out = append(out, styleWarn.Render(line+"  BLOCKED - needs acknowledgment"))
				continue
			}
			out = append(out, styleGood.Render(line+"  authorized for active work"))
		}
		for b, note := range r.Rejections {
			out = append(out, styleDim.Render(fmt.Sprintf("  vetoed %s %s", b, note)))
		}
		return out, nil

	case "confirm", "reject":
		if len(args) < 2 {
			return nil, fmt.Errorf("scope %s <bssid> [note]", action)
		}
		params := map[string]string{"bssid": args[1]}
		if len(args) > 2 {
			params["note"] = strings.Join(args[2:], " ")
		}
		var res map[string]string
		if err := m.call("scope."+action, params, &res); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  " + res["bssid"] + " - " + res["note"])}, nil

	case "acknowledge", "ack":
		// Accept the residual risk of a generic scoped ESSID (Guest, attwifi, ...) so active work
		// is authorized there. Recorded in the audit log as engagement evidence.
		if len(args) < 2 {
			return nil, fmt.Errorf("scope acknowledge <essid>")
		}
		if err := m.call("scope.acknowledge", map[string]string{"essid": strings.Join(args[1:], " ")}, nil); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  acknowledged - active work authorized (recorded in the audit log)")}, nil

	case "add", "remove", "rm":
		// add widens scope to an observed name; remove/rm takes one back out. Both persist to
		// scope.txt and are recorded in the audit log; removing only narrows scope.
		if len(args) < 2 {
			return nil, fmt.Errorf("scope %s <essid>", action)
		}
		method, verb, flag := "scope.add", "added to", "added"
		if action != "add" {
			method, verb, flag = "scope.remove", "removed from", "removed"
		}
		essid := strings.Join(args[1:], " ")
		var out map[string]any
		if err := m.call(method, map[string]string{"essid": essid, "note": "from the dashboard"}, &out); err != nil {
			return nil, err
		}
		// Only claim a change (and an audit-log entry) when one actually happened - adding a name
		// already in scope, or removing one that was not, is a no-op the daemon does not record.
		if changed, _ := out[flag].(bool); !changed {
			if action == "add" {
				return []string{styleDim.Render(fmt.Sprintf("  %q was already in scope", essid))}, nil
			}
			return []string{styleDim.Render(fmt.Sprintf("  %q was not in scope", essid))}, nil
		}
		return []string{styleGood.Render(fmt.Sprintf("  %q %s scope (recorded in the audit log)", essid, verb))}, nil
	}
	return nil, fmt.Errorf("scope list|confirm <bssid>|reject <bssid>|acknowledge <essid>|add <essid>|remove <essid>")
}

type scopeEntry struct {
	ESSID           string `json:"essid"`
	Generic         bool   `json:"generic"`
	Acknowledged    bool   `json:"acknowledged"`
	ActiveWorkReady bool   `json:"active_work_ready"`
}

func runWalkthrough(m *Model, args []string) ([]string, error) {
	if len(args) == 0 {
		var cur *store.Walkthrough
		if err := m.call("walkthrough.current", nil, &cur); err != nil {
			return nil, err
		}
		if cur == nil {
			return []string{styleDim.Render("  no walkthrough open")}, nil
		}
		return []string{fmt.Sprintf("  current: %s (%s ago)",
			cur.Name, time.Since(cur.StartTS).Round(time.Second))}, nil
	}

	switch args[0] {
	case "end":
		if err := m.call("walkthrough.end", nil, nil); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  walkthrough ended")}, nil

	case "list":
		var wts []store.Walkthrough
		if err := m.call("walkthrough.list", nil, &wts); err != nil {
			return nil, err
		}
		now := time.Now()
		var out []string
		for _, w := range wts {
			name := w.Name
			if w.Implicit {
				name += " (implicit)"
			}
			if w.Open() {
				name += " [open]"
			}
			line := fmt.Sprintf("  %-3d %-28s %8s  %d APs  %d clients  %d obs",
				w.ID, name, w.Duration(now).Round(time.Second), w.APs, w.Clients, w.Observations)
			if w.PcapPath != "" {
				line += "  " + styleDim.Render(w.PcapPath)
			}
			out = append(out, line)
		}
		return out, nil

	case "delete", "rm":
		if len(args) < 2 {
			return nil, fmt.Errorf("walkthrough delete <id>")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a walkthrough id", args[1])
		}
		if err := m.call("walkthrough.delete", map[string]any{"id": id}, nil); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  deleted (observations are kept)")}, nil

	case "rename":
		if len(args) < 3 {
			return nil, fmt.Errorf("walkthrough rename <id> <name>")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a walkthrough id", args[1])
		}
		params := map[string]any{"id": id, "name": strings.Join(args[2:], " ")}
		if err := m.call("walkthrough.rename", params, nil); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  renamed (no observation data was touched)")}, nil

	case "split":
		if len(args) < 3 {
			return nil, fmt.Errorf("walkthrough split <id> <timestamp RFC3339> [new-name]")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a walkthrough id", args[1])
		}
		params := map[string]any{"id": id, "at": args[2]}
		if len(args) > 3 {
			params["name"] = strings.Join(args[3:], " ")
		}
		if err := m.call("walkthrough.split", params, nil); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  split (observations associate by time range; none were touched)")}, nil

	case "devices":
		if len(args) < 2 {
			return nil, fmt.Errorf("walkthrough devices <id>")
		}
		id, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%q is not a walkthrough id", args[1])
		}
		var devs []store.WalkthroughDevice
		if err := m.call("walkthrough.devices", map[string]any{"id": id}, &devs); err != nil {
			return nil, err
		}
		if len(devs) == 0 {
			return []string{styleDim.Render("  nothing heard during this walkthrough")}, nil
		}
		var out []string
		for _, d := range devs {
			kind := "client"
			if d.IsAP {
				kind = "AP"
			}
			essid := d.ESSID
			if essid == "" {
				essid = styleDim.Render("(hidden/unknown)")
			}
			out = append(out, fmt.Sprintf("  %-17s %-7s %s", d.BSSID, kind, essid))
		}
		return out, nil
	}

	// Anything else is a name: start a walkthrough.
	name := strings.Join(args, " ")
	var w store.Walkthrough
	if err := m.call("walkthrough.start", map[string]string{"name": name}, &w); err != nil {
		return nil, err
	}
	return nil, nil // the daemon broadcasts the confirmation
}

func runLocalize(m *Model, args []string) ([]string, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("localize <bssid|mac>")
	}
	var r daemon.LocalizeResult
	if err := m.call("localize", map[string]string{"addr": args[0]}, &r); err != nil {
		return nil, err
	}
	if len(r.Ranks) == 0 {
		return []string{styleDim.Render("  not observed on the survey radio")}, nil
	}

	out := []string{styleDim.Render(fmt.Sprintf("  ranked by strongest observation (survey radio %s):", m.ifnameFor(r.RadioID)))}
	for i, l := range r.Ranks {
		out = append(out, fmt.Sprintf("  %d. %-28s %4d dBm  (%d observations)",
			i+1, l.WalkthroughName, l.MaxRSSI, l.Observations))
	}
	out = append(out, styleDim.Render("  not trilateration - no coordinate is emitted"))
	return out, nil
}

func runPSK(m *Model, args []string) ([]string, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("psk <bssid> [--deauth <station>]")
	}
	bssid := args[0]

	deauth := false
	station := ""
	count, seconds := 0, 0
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--deauth":
			deauth = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
				station = args[i+1]
				i++
			}
		case "--count":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--count needs a number (frames per burst)")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("--count must be a number: %q", args[i+1])
			}
			count = n
			i++
		case "--seconds":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--seconds needs a number (campaign duration, capped at 60)")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return nil, fmt.Errorf("--seconds must be a number: %q", args[i+1])
			}
			seconds = n
			i++
		default:
			return nil, fmt.Errorf("unknown option %q", args[i])
		}
	}

	if deauth {
		if station == "" {
			return nil, fmt.Errorf("--deauth needs a station; broadcast deauthentication " +
				"disconnects every client at once and must be asked for explicitly")
		}
		params := daemon.DeauthParams{BSSID: bssid, Station: station, Count: count, Seconds: seconds}
		var job daemon.Job
		if err := m.call("psk.deauth", params, &job); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  job " + job.ID + " started (deauth)")}, nil
	}

	var job daemon.Job
	if err := m.call("psk.solicit", daemon.SolicitParams{BSSID: bssid}, &job); err != nil {
		return nil, err
	}
	return []string{styleGood.Render("  job " + job.ID + " started (PMKID solicitation)")}, nil
}

func runRogue(m *Model, args []string) ([]string, error) {
	action := "list"
	if len(args) > 0 {
		action = args[0]
	}

	switch action {
	case "classify":
		var r struct {
			Findings     int `json:"findings"`
			Unclassified int `json:"unclassified"`
		}
		if err := m.call("rogue.classify", nil, &r); err != nil {
			return nil, err
		}
		return []string{styleGood.Render(fmt.Sprintf(
			"  %d finding(s); %d device(s) left unclassified", r.Findings, r.Unclassified))}, nil

	case "karma-test":
		var job daemon.Job
		if err := m.call("rogue.karma-test", nil, &job); err != nil {
			return nil, err
		}
		return []string{styleGood.Render("  job " + job.ID + " started (karma responder probe)")}, nil

	case "list":
		params := daemon.RogueListParams{}
		if len(args) > 1 {
			params.Tier = args[1]
		}
		var r struct {
			Findings     []store.Finding `json:"findings"`
			Unclassified []string        `json:"unclassified"`
		}
		if err := m.call("rogue.list", params, &r); err != nil {
			return nil, err
		}
		var out []string
		for _, f := range r.Findings {
			line := fmt.Sprintf("  [%-11s] %-17s %-20s %s",
				f.Tier, f.BSSID, truncate(f.ESSID, 20), f.Label)
			if f.Tier == store.TierEvidence {
				line = styleWarn.Render(line)
			}
			out = append(out, line)
		}
		if len(r.Unclassified) > 0 {
			out = append(out, styleDim.Render(fmt.Sprintf(
				"  %d device(s) observed with no conclusion available", len(r.Unclassified))))
		}
		if len(out) == 0 {
			out = []string{styleDim.Render("  nothing recorded - run `rogue classify`")}
		}
		return out, nil
	}
	return nil, fmt.Errorf("rogue classify|list [tier]|karma-test")
}

func runHunt(m *Model, args []string) ([]string, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("hunt <bssid|mac>")
	}
	var res struct {
		Job daemon.Job `json:"job"`
	}
	params := map[string]any{"addr": args[0], "audible": false}
	if err := m.call("hunt.start", params, &res); err != nil {
		return nil, err
	}
	return []string{
		styleGood.Render("  hunting " + args[0] + " (job " + res.Job.ID + ")"),
		styleDim.Render("  switch to a directional antenna and walk the gradient"),
	}, nil
}

// ---------------------------------------------------------------------------
// Shared rendering
// ---------------------------------------------------------------------------

func reconLines(st daemon.EngineStats) []string {
	out := []string{
		fmt.Sprintf("  running %v, %d aps, %d stations", st.Running, st.APs, st.Stations),
	}
	for _, r := range st.Radios {
		out = append(out, fmt.Sprintf("  %-6s %-10s %-8s frames=%d bad_fcs=%d dropped=%d sweep=%s",
			r.RadioID, r.Ifname, r.Role,
			r.Capture.Frames, r.Capture.BadFCS, r.Capture.Dropped, r.CycleFor))
	}
	if n := st.Handshake.PendingESSID; n > 0 {
		out = append(out, styleWarn.Render(fmt.Sprintf(
			"  %d hash(es) held pending an ESSID - the name is the PBKDF2 salt", n)))
	}
	return out
}

func rssiCell(rssi int8, has bool) string {
	if !has {
		return "-"
	}
	return strconv.Itoa(int(rssi))
}

func scopeCell(ap daemon.APView) string {
	switch {
	case ap.Rejected:
		return "vetoed"
	case ap.InScope:
		return "in scope"
	default:
		return "passive"
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// truncate shortens a string to n columns.
//
// Defensive against a non-positive n: callers derive widths by subtracting fixed layout costs
// from the terminal width, and on a 40-column phone terminal that arithmetic goes negative.
// A rendering helper must never be the thing that panics.
func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return s[:n-1] + "…"
}

var _ = rpc.LevelInfo
