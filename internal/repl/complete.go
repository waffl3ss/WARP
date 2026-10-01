package repl

import (
	"context"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/waffl3ss/warp/internal/daemon"
)

// completionCache holds the identifiers worth completing.
//
// Nobody is typing MAC addresses by hand. Completion covers BSSIDs, ESSIDs and client MACs,
// refreshed from the daemon as recon discovers more.
type completionCache struct {
	bssids   []string
	essids   []string
	stations []string
	// jobs holds the IDs of running jobs, for `kill`.
	jobs []string
	// radios holds the adapter IDs, for `radios lock` and `radios unlock`. Nobody should be
	// typing "phy1" from memory when the tool knows what is plugged in.
	radios []string
}

func (m *Model) fetchCompletions() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(m.ctx, 3*time.Second)
		defer cancel()

		var cache completionCache

		var aps []daemon.APView
		if err := m.client.Call(ctx, "aps.list", nil, &aps); err == nil {
			seenESSID := map[string]struct{}{}
			for _, ap := range aps {
				cache.bssids = append(cache.bssids, ap.BSSID.String())
				if ap.ESSID != "" {
					if _, dup := seenESSID[ap.ESSID]; !dup {
						seenESSID[ap.ESSID] = struct{}{}
						cache.essids = append(cache.essids, ap.ESSID)
					}
				}
			}
		}

		var stations []daemon.StationView
		if err := m.client.Call(ctx, "stations.list", nil, &stations); err == nil {
			for _, st := range stations {
				cache.stations = append(cache.stations, st.MAC.String())
			}
		}

		var jobs []daemon.Job
		if err := m.client.Call(ctx, "jobs.list", nil, &jobs); err == nil {
			for _, j := range jobs {
				if !j.State.Terminal() {
					cache.jobs = append(cache.jobs, j.ID)
				}
			}
		}

		var radios []daemon.RadioInfo
		if err := m.client.Call(ctx, "radios.list", nil, &radios); err == nil {
			for _, r := range radios {
				cache.radios = append(cache.radios, r.ID)
			}
		}

		sort.Strings(cache.bssids)
		sort.Strings(cache.essids)
		sort.Strings(cache.stations)
		sort.Strings(cache.jobs)
		sort.Strings(cache.radios)

		return completionMsg{cache: cache}
	}
}

func (m *Model) resetTab() {
	m.tabCandidates = nil
	m.tabIndex = 0
	m.tabPrefix = ""
}

// completeNext cycles through the candidates for the word under the cursor.
//
// Pressing tab repeatedly walks the list rather than requiring a longer prefix, because on
// site the operator often knows roughly which device they want and not its exact address.
func (m *Model) completeNext() {
	value := m.input.Value()

	if m.tabCandidates == nil {
		prefix, candidates := m.candidatesFor(value)
		if len(candidates) == 0 {
			return
		}
		m.tabPrefix = prefix
		m.tabCandidates = candidates
		m.tabIndex = 0
	} else {
		m.tabIndex = (m.tabIndex + 1) % len(m.tabCandidates)
	}

	m.input.SetValue(m.tabPrefix + m.tabCandidates[m.tabIndex])
	m.input.CursorEnd()

	// With several matches, show them once so the operator can see what they are cycling
	// through rather than tabbing blind.
	if len(m.tabCandidates) > 1 && m.tabIndex == 0 {
		m.appendLine(styleDim.Render("  " + strings.Join(truncateList(m.tabCandidates, 12), "  ")))
	}
}

// candidatesFor returns the unchanged prefix of the line and the completions for its last
// word.
func (m *Model) candidatesFor(line string) (string, []string) {
	fields := strings.Fields(line)

	// Completing the command itself.
	if len(fields) == 0 || (len(fields) == 1 && !strings.HasSuffix(line, " ")) {
		word := ""
		if len(fields) == 1 {
			word = fields[0]
		}
		return "", matching(commandNames(), word)
	}

	cmd := fields[0]
	word := ""
	if !strings.HasSuffix(line, " ") {
		word = fields[len(fields)-1]
	}
	prefix := line[:len(line)-len(word)]

	return prefix, matching(m.argumentsFor(cmd, len(fields), strings.HasSuffix(line, " ")), word)
}

// argumentsFor returns the candidate set for a command's argument position.
func (m *Model) argumentsFor(cmd string, fieldCount int, trailingSpace bool) []string {
	// Position of the argument being completed, 1-based.
	pos := fieldCount - 1
	if trailingSpace {
		pos = fieldCount
	}

	switch cmd {
	case "psk", "solicit", "deauth", "detail", "confirm", "reject":
		if pos == 1 {
			return m.completions.bssids
		}
		// A deauth target is a station, not another access point.
		return m.completions.stations

	case "hunt", "localize", "locate":
		// Hunt works on any observed device, access point or station alike.
		return append(append([]string{}, m.completions.bssids...), m.completions.stations...)

	case "aps", "bssids":
		return m.completions.essids

	case "kill":
		return m.completions.jobs

	case "rogue":
		if pos == 1 {
			return []string{"classify", "list", "detail", "karma-test"}
		}
		return m.completions.bssids

	case "walkthrough", "walk":
		if pos == 1 {
			return []string{"end", "list", "rename", "split"}
		}
		return nil

	case "recon":
		if pos == 1 {
			return []string{"start", "stop", "status"}
		}
		return nil

	case "scope":
		if pos == 1 {
			return []string{"list", "confirm", "reject"}
		}
		return m.completions.bssids

	case "radios":
		if pos == 1 {
			return []string{"list", "assignments", "lock", "unlock"}
		}
		// `lock` and `unlock` are the only subcommands taking a second argument, and both take
		// an adapter. Nobody should be typing "phy1" from memory when the tool knows what is
		// plugged in.
		if pos == 2 {
			return m.completions.radios
		}
		return nil
	}
	return nil
}

func matching(candidates []string, word string) []string {
	if word == "" {
		return candidates
	}
	lower := strings.ToLower(word)

	var out []string
	for _, c := range candidates {
		if strings.HasPrefix(strings.ToLower(c), lower) {
			out = append(out, c)
		}
	}
	// A MAC address is often recalled by its tail rather than its OUI, so fall back to a
	// substring match when nothing matches the prefix.
	if len(out) == 0 {
		for _, c := range candidates {
			if strings.Contains(strings.ToLower(c), lower) {
				out = append(out, c)
			}
		}
	}
	return out
}

func truncateList(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	out := append([]string{}, items[:n]...)
	return append(out, "…")
}
