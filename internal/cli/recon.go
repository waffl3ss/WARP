package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/store"
)

func reconCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Control the capture and reconnaissance engine",
	}

	start := &cobra.Command{
		Use:   "start",
		Short: "Acquire radios and begin capture",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "recon.start", nil, func(w io.Writer, s daemon.EngineStats) error {
				fprintf(w, "recon started on %d radio(s)\n", len(s.Radios))
				return renderEngineStats(w, s)
			})
		},
	}

	stop := &cobra.Command{
		Use:   "stop",
		Short: "Stop capture and release the radios",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "recon.stop", nil, func(w io.Writer, _ map[string]any) error {
				fprintf(w, "recon stopped; radios released\n")
				return nil
			})
		},
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show capture counters per radio",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "recon.status", nil, renderEngineStats)
		},
	}

	cmd.AddCommand(start, stop, status)
	return cmd
}

func renderEngineStats(w io.Writer, s daemon.EngineStats) error {
	fprintf(w, "running:      %v\n", s.Running)
	if s.SurveyRadio != "" {
		fprintf(w, "survey radio: %s (pinned)\n", s.SurveyRadio)
	}
	fprintf(w, "tracked:      %d access points, %d stations\n", s.APs, s.Stations)
	fprintf(w, "handshakes:   %d session(s) in flight\n", s.Handshake.Sessions)

	// Held handshakes are directly actionable: a probe or an association will reveal the
	// cloaked name and unlock the hash.
	if n := s.Handshake.PendingESSID; n > 0 {
		fprintf(w, "held:         %d hash(es) waiting on an ESSID - the name is the PBKDF2 salt\n", n)
		for _, b := range s.PendingESSID {
			fprintf(w, "                %s\n", b)
		}
	}

	if len(s.Radios) == 0 {
		return nil
	}
	fprintf(w, "\n")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IFACE\tROLE\tFRAMES\tBAD FCS\tDROPPED\tSWEEP")
	for _, r := range s.Radios {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%s\n",
			r.Ifname, r.Role,
			r.Capture.Frames, r.Capture.BadFCS, r.Capture.Dropped, r.CycleFor)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	// A rising drop count means the channel is busier than the capture path can keep up
	// with. The operator needs to know that before concluding a network is quiet.
	for _, r := range s.Radios {
		if r.Capture.Dropped > 0 {
			fprintf(w, "\nnote: %s has dropped %d frame(s); the channel is busier than capture "+
				"can sustain, so absence of a result is not evidence of absence\n",
				r.RadioID, r.Capture.Dropped)
		}
	}
	return nil
}

func apsCmd() *cobra.Command {
	var (
		essid      string
		scopedOnly bool
	)

	cmd := &cobra.Command{
		Use:     "aps",
		Aliases: []string{"bssids"},
		Short:   "List observed access points",
		Long: `Lists every access point WARP has observed.

Nothing is filtered out by default, including neighbours and other tenants: the default state
of an observed device is unclassified, and deciding a device is somebody else's is a
conclusion. Use ` + "`warp rogue list`" + ` for the conclusions.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			params := daemon.APsListParams{ESSID: essid, ScopedOnly: scopedOnly}
			return callAndRender(cmd, "aps.list", params, func(w io.Writer, aps []daemon.APView) error {
				if len(aps) == 0 {
					fprintf(w, "no access points observed\n")
					return nil
				}
				tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "BSSID\tESSID\tBAND\tCH\tRSSI\tSECURITY\tPMF\tCLIENTS\tSCOPE\tSEEN")
				for _, ap := range aps {
					band := ap.Band
					if band == "" {
						band = "-"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\t%s\t%d\t%s\t%s\n",
						ap.BSSID, displayESSID(ap.ESSID, ap.Hidden), band, ap.Channel,
						rssiCell(ap.BestRSSI, ap.HasRSSI),
						securityCell(ap), pmfShort(ap.Security.MFP), ap.Clients,
						scopeCell(ap), seenCell(ap.Active, ap.LastSeenSecs))
				}
				return tw.Flush()
			})
		},
	}

	cmd.Flags().StringVar(&essid, "essid", "", "only show access points broadcasting this ESSID")
	cmd.Flags().BoolVar(&scopedOnly, "scoped", false, "only show access points on scoped ESSIDs")

	detail := &cobra.Command{
		Use:   "detail <bssid>",
		Short: "Show everything observed and concluded about one access point",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := map[string]string{"bssid": args[0]}
			return callAndRender(cmd, "aps.detail", params, func(w io.Writer, r daemon.APDetailResult) error {
				ap := r.AP
				fprintf(w, "%s  %s\n", ap.BSSID, displayESSID(ap.ESSID, ap.Hidden))
				fprintf(w, "  channel:    %d (%d MHz, %s)\n", ap.Channel, ap.Freq, ap.Band)
				fprintf(w, "  security:   %s\n", ap.Security.Describe())
				fprintf(w, "  signal:     %s (best, on %s)\n",
					rssiCell(ap.BestRSSI, ap.HasRSSI), ap.BestRSSIRadio)
				fprintf(w, "  seen:       %s → %s (%d beacons)\n",
					ap.FirstSeen.Format(time.RFC3339), ap.LastSeen.Format(time.RFC3339), ap.Beacons)
				fprintf(w, "  scope:      %s\n", scopeCell(ap))
				if ap.ESSIDSource != "" {
					fprintf(w, "  essid from: %s\n", ap.ESSIDSource)
				}
				fprintf(w, "  fingerprint: %s\n", ap.Fingerprint.Hash())

				if len(r.Stations) > 0 {
					fprintf(w, "\n  associated stations:\n")
					for _, st := range r.Stations {
						fprintf(w, "    %s%s  %s\n", st.MAC,
							randomisedMark(st.Randomised), rssiCell(st.BestRSSI, st.HasRSSI))
					}
				}

				// Observations and conclusions are shown in separate sections, because they
				// are separate things.
				if len(r.Findings) > 0 {
					fprintf(w, "\n  findings (conclusions, separate from the observations above):\n")
					for _, f := range r.Findings {
						fprintf(w, "    [%s] %s\n", f.Tier, f.Label)
						if f.Rationale != "" {
							fprintf(w, "        %s\n", wrap(f.Rationale, 72, "        "))
						}
						for _, d := range f.Differences {
							fprintf(w, "        - %s\n", d)
						}
					}
				}

				if len(r.Locations) > 0 {
					fprintf(w, "\n  strongest walkthroughs (ranked, not a coordinate):\n")
					for _, l := range r.Locations {
						fprintf(w, "    %-24s %4d dBm  (%d observations)\n",
							l.WalkthroughName, l.MaxRSSI, l.Observations)
					}
				}
				return nil
			})
		},
	}

	cmd.AddCommand(detail)
	return cmd
}

func stationsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "clients",
		Aliases: []string{"stations"},
		Short:   "List observed client devices",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "stations.list", nil, func(w io.Writer, sts []daemon.StationView) error {
				if len(sts) == 0 {
					fprintf(w, "no client devices observed\n")
					return nil
				}
				tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "CLIENT\tASSOCIATED\tNETWORK\tBAND\tCH\tPMF\tRSSI\tFRAMES\tHAS LOOKED FOR")
				for _, st := range sts {
					bssid, essid, band, ch := "-", "-", "-", "-"
					if !st.BSSID.IsZero() {
						bssid = st.BSSID.String()
					}
					if st.ESSID != "" {
						essid = st.ESSID
					}
					if st.APBand != "" {
						band = st.APBand
					}
					if st.APChannel != 0 {
						ch = fmt.Sprintf("%d", st.APChannel)
					}
					fmt.Fprintf(tw, "%s%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
						st.MAC, randomisedMark(st.Randomised), bssid, essid, band, ch,
						pmfShort(st.MFP), rssiCell(st.BestRSSI, st.HasRSSI), st.Frames,
						strings.Join(st.ProbedESSIDs, ", "))
				}
				if err := tw.Flush(); err != nil {
					return err
				}
				fprintf(w, "\n* = randomised (locally administered) MAC; these may be the same "+
					"device appearing repeatedly\n")
				return nil
			})
		},
	}
}

// pmfShort abbreviates the Protected Management Frames posture.
//
// The same three words the dashboard and the browser use. "off" rather than a dash, because
// absent 802.11w is a finding and it is what decides whether a deauthentication does anything.
func pmfShort(m recon.MFPState) string {
	switch m {
	case recon.MFPRequired:
		return "req"
	case recon.MFPCapable:
		return "opt"
	case recon.MFPAbsent:
		return "off"
	default:
		return "?"
	}
}

// ---------------------------------------------------------------------------
// Rendering helpers
// ---------------------------------------------------------------------------

func displayESSID(essid string, hidden bool) string {
	if essid != "" {
		return essid
	}
	if hidden {
		return "<hidden>"
	}
	return "<unknown>"
}

// rssiCell renders a signal reading, or a dash when none was measured.
//
// Never 0: that would read as the strongest possible signal.
func rssiCell(rssi int8, has bool) string {
	if !has {
		return "-"
	}
	return fmt.Sprintf("%d", rssi)
}

// seenCell renders how recently an access point was heard, airodump-style: a compact age, with a
// leading dot for one still visible now and "(gone)" for one that has dropped off the air. WARP
// keeps every AP it ever saw, so this is what separates the live picture from the history.
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
		return "• " + age
	}
	return age + " (gone)"
}

func securityCell(ap daemon.APView) string {
	s := string(ap.Security.Class)
	if ap.Security.WPS {
		s += "+WPS"
	}
	if ap.Security.Transition {
		s += "+transition"
	}
	return s
}

func scopeCell(ap daemon.APView) string {
	switch {
	case ap.Rejected:
		return "vetoed"
	case ap.InScope && ap.Confirmed:
		return "in scope (confirmed)"
	case ap.InScope:
		return "in scope"
	default:
		return "passive only"
	}
}

func randomisedMark(randomised bool) string {
	if randomised {
		return "*"
	}
	return ""
}

// wrap reflows text to width, indenting continuation lines.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}

	var b strings.Builder
	lineLen := 0
	for i, word := range words {
		if lineLen > 0 && lineLen+1+len(word) > width {
			b.WriteString("\n" + indent)
			lineLen = 0
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(word)
		lineLen += len(word)
	}
	return b.String()
}

func tierLabel(t store.Tier) string {
	switch t {
	case store.TierDetermined:
		return "determined"
	case store.TierEvidence:
		return "evidence"
	default:
		return "unclassified"
	}
}
