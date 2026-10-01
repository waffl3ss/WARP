package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/store"
)

func pskCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "psk <bssid>",
		Short: "PSK capture: solicit a PMKID, or deauthenticate to force a handshake",
		Long: `Active PSK capture at an authorized access point.

By default this solicits a PMKID: WARP associates from a made-up station and reads the M1 the
access point sends back. That needs no client involvement and disrupts nothing, and it is the
largest single time saver available - it turns "wait for a client to reassociate" into "walk
past the AP".

--deauth additionally disconnects clients so they reauthenticate and a full handshake can be
captured. Naming a --station targets one device; without one it is a broadcast against the
access point, which moves every client and is the better way to provoke a handshake.

A deauthentication is a campaign, not a single burst. It holds every capture radio on the
access point's channel - the handshake arrives there a second or two later, and a radio that
has resumed sweeping will be elsewhere when it does - transmits in rounds for up to --seconds,
and stops the moment a handshake for that access point lands.

Both are refused unless the access point broadcasts a scoped ESSID.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			bssid := args[0]

			deauth, _ := cmd.Flags().GetBool("deauth")
			station, _ := cmd.Flags().GetString("station")
			broadcast, _ := cmd.Flags().GetBool("broadcast")
			count, _ := cmd.Flags().GetInt("count")
			seconds, _ := cmd.Flags().GetInt("seconds")

			if deauth {
				params := daemon.DeauthParams{
					BSSID: bssid, Station: station, Broadcast: broadcast,
					Count: count, Seconds: seconds,
				}
				return callAndRender(cmd, "psk.deauth", params, renderJobStart)
			}
			return callAndRender(cmd, "psk.solicit", daemon.SolicitParams{BSSID: bssid}, renderJobStart)
		},
	}

	cmd.Flags().Bool("pmkid", true, "solicit a PMKID (default)")
	cmd.Flags().Bool("deauth", false, "deauthenticate a client to force a full handshake")
	cmd.Flags().String("station", "", "station to deauthenticate; omit it to broadcast against every client on the AP")
	cmd.Flags().Bool("broadcast", false,
		"deauthenticate every client at once. This is the default when no --station is named: "+
			"acting on an access point means every client, which is what provokes a handshake")
	cmd.Flags().Int("count", 0, "frames per burst (default 8)")
	cmd.Flags().Int("seconds", 0,
		"how long the campaign runs, in seconds (default 20, capped at 60). It stops early the "+
			"moment a handshake for this access point is captured")
	return cmd
}

func wpsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "wps <bssid>",
		Aliases: []string{"pixie", "pixiedust"},
		Short:   "Recover a WPS PIN offline (Pixie Dust)",
		Long: `Run one WPS registration exchange and recover the PIN offline.

WPS protects the PIN with two commitments the access point sends in M3, keyed on two secret
nonces. A great many access points generate those nonces badly - some set them to zero, some
reuse the enrollee nonce they already sent in the clear, some seed a linear congruential
generator with the clock. In any of those cases the nonces are recoverable, and the PIN then
falls to a 10,000-candidate search in well under a second.

WARP associates, runs four WSC messages, and disconnects. It stops at M3: registration never
completes, nothing joins the network, and no configuration is written to the access point.
Everything after the exchange is arithmetic on this box.

Online PIN brute force is deliberately not implemented. It needs thousands of round trips over
hours, it only works while it can keep talking to the access point, and on an engagement there
is often no route off the box anyway. It also locks WPS on production hardware and fills the
client's logs, which is disruption nobody bought.

An access point whose nonces are sound is a **pass**, and it is recorded as a finding saying
so - a report that only lists what broke leaves the reader unable to tell what was tested from
what was not.

Refused unless the access point broadcasts a scoped ESSID: associating is transmission.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			seconds, _ := cmd.Flags().GetInt("seconds")
			return callAndRender(cmd, "wps",
				daemon.WPSParams{BSSID: args[0], Seconds: seconds}, renderJobStart)
		},
	}
	cmd.Flags().Int("seconds", 0,
		"how long the exchange may take, in seconds (default 20, capped at 60)")
	return cmd
}

func decloakCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decloak <bssid>",
		Short: "Recover the network name of a hidden access point",
		Long: `Recover the ESSID of a cloaked network.

A hidden network is only hidden in its beacons. The name travels in clear text in every probe
response and every association request, so knocking the associated clients off and watching
them come back names it. WARP holds every capture radio on the access point's channel,
broadcasts deauthentication in rounds, and stops the instant the name arrives.

Passive capture already recovers hidden names on its own, given a client that happens to
reassociate while WARP is listening on the right channel. This is the on-demand version for
when you cannot wait, and it is the only reason to use it.

Authorization works differently here, and this is one of only two places in WARP that it does.
Every other transmission is decided by matching the beaconed ESSID against scope.txt, and a
cloaked network has no name to match. That is not merely awkward: the network **may well be in
scope**, and there is no way to find out except by recovering the name. An ESSID check here
would refuse to establish the very fact it needs.

So the name is recovered first and scope resumes immediately afterwards. Nothing else is
unlocked: the moment the name is known every subsequent decision is back on the ordinary path,
and if it turns out not to be in scope, nothing further will transmit at it.

Each attempt is recorded in the audit log stating plainly that there was no ESSID to decide on.
An operator veto (warp scope reject) still refuses, because a veto only ever narrows scope.

It will not run against an access point that requires 802.11w - protected clients ignore
unprotected deauthentication, so they cannot be made to reassociate.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			seconds, _ := cmd.Flags().GetInt("seconds")
			return callAndRender(cmd, "decloak",
				daemon.DecloakParams{BSSID: args[0], Seconds: seconds}, renderJobStart)
		},
	}
	cmd.Flags().Int("seconds", 0,
		"how long the campaign runs, in seconds (default 20, capped at 60). It stops early the "+
			"moment the name is recovered")
	return cmd
}

func renderJobStart(w io.Writer, j daemon.Job) error {
	fprintf(w, "job %s started (%s %s)\n", j.ID, j.Kind, j.Target)
	fprintf(w, "watch it with:  warp jobs\n")
	return nil
}

func rogueCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rogue",
		Short: "Rogue detection: population clustering and classification",
		Long: `Derives a baseline from the observed population and classifies against it.

There is no client AP inventory, so the baseline is derived: every BSSID broadcasting a scoped
ESSID is clustered by radio fingerprint, and the dominant cluster is taken to be the client's
infrastructure. An impostor falls outside the cluster it is pretending to belong to - which
also catches an impostor that spoofed a legitimate BSSID.

Findings are tiered. "determined" is deterministic and defensible. "evidence" is an inference
with the specific differing attributes attached. Everything else stays unclassified and is
listed with no label.`,
	}

	classify := &cobra.Command{
		Use:   "classify",
		Short: "Re-run classification over everything observed so far",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "rogue.classify", nil, func(w io.Writer, r struct {
				Findings     int               `json:"findings"`
				Unclassified int               `json:"unclassified"`
				Analyses     []analysisSummary `json:"analyses"`
			}) error {
				fprintf(w, "%d finding(s), %d device(s) left unclassified\n\n",
					r.Findings, r.Unclassified)
				for _, a := range r.Analyses {
					if a.Inconclusive {
						fprintf(w, "%s (%d APs): inconclusive\n  %s\n\n",
							a.ESSID, a.Population, wrap(a.Reason, 74, "  "))
						continue
					}
					fprintf(w, "%s (%d APs): %d outlier(s)\n", a.ESSID, a.Population, len(a.Outliers))
					for _, o := range a.Outliers {
						fprintf(w, "  %s  similarity %.2f\n", o.AP.BSSID, o.Score)
						for _, d := range o.Differences {
							fprintf(w, "    %s: expected %s, observed %s\n",
								d.Attribute, truncate(d.Expected, 40), truncate(d.Observed, 40))
						}
					}
					fprintf(w, "\n")
				}
				return nil
			})
		},
	}

	var tier string
	list := &cobra.Command{
		Use:   "list",
		Short: "List findings",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			params := daemon.RogueListParams{Tier: tier}
			return callAndRender(cmd, "rogue.list", params, func(w io.Writer, r struct {
				Findings     []store.Finding `json:"findings"`
				Unclassified []string        `json:"unclassified"`
			}) error {
				if len(r.Findings) == 0 && len(r.Unclassified) == 0 {
					fprintf(w, "nothing recorded - run `warp rogue classify` first\n")
					return nil
				}

				if len(r.Findings) > 0 {
					tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
					fmt.Fprintln(tw, "TIER\tBSSID\tESSID\tFINDING")
					for _, f := range r.Findings {
						fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
							tierLabel(f.Tier), f.BSSID, f.ESSID, f.Label)
					}
					if err := tw.Flush(); err != nil {
						return err
					}
				}

				// Unclassified devices are listed, not hidden: nothing is filtered out, and
				// the absence of a label is itself the honest answer.
				if len(r.Unclassified) > 0 {
					fprintf(w, "\nunclassified (%d) - observed, no conclusion available:\n", len(r.Unclassified))
					for _, b := range r.Unclassified {
						fprintf(w, "  %s\n", b)
					}
				}
				return nil
			})
		},
	}
	list.Flags().StringVar(&tier, "tier", "", "filter by tier: determined, evidence, unclassified")

	detail := &cobra.Command{
		Use:   "detail <bssid>",
		Short: "Show a device's findings alongside the population they came from",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd.Context(), "rogue.detail", map[string]string{"bssid": args[0]}, nil)
		},
	}

	karma := &cobra.Command{
		Use:   "karma-test",
		Short: "Probe for a network that cannot exist and record what answers",
		Long: `Transmits probe requests for a randomly generated 20-character ESSID.

No such network exists, so anything that answers is responding to arbitrary probes - the
behaviour of a Wi-Fi Pineapple or equivalent attacker device. The result is a deterministic
yes/no, and nothing passive will ever find it.

The generated name is different every run, so a device that has already seen one cannot learn
to decline.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			channels, _ := cmd.Flags().GetIntSlice("channels")
			params := daemon.KarmaTestParams{Channels: channels}
			return callAndRender(cmd, "rogue.karma-test", params, renderJobStart)
		},
	}
	karma.Flags().IntSlice("channels", nil, "channels to sweep (default: channels hosting scoped ESSIDs)")

	mark := &cobra.Command{
		Use:   "mark <bssid>",
		Short: "Mark one BSSID as a potential rogue device (operator judgement)",
		Long: `Records your judgement that one specific BSSID is a potential rogue.

It marks only the BSSID you name, not every access point on its ESSID. It transmits nothing and does
not consult scope - judging a device you can see is not transmitting at it. It adds an evidence-tier
finding whose evidence points at manual evidence you supply, and colours the device red in the
dashboards. Clear it again with 'warp rogue unmark <bssid>'.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "rogue.mark", map[string]string{"bssid": args[0]},
				func(w io.Writer, r struct {
					BSSID string `json:"bssid"`
					ESSID string `json:"essid"`
				}) error {
					fprintf(w, "%s marked as a potential rogue device", r.BSSID)
					if r.ESSID != "" {
						fprintf(w, " (on %q)", r.ESSID)
					}
					fprintf(w, "\n")
					return nil
				})
		},
	}

	unmark := &cobra.Command{
		Use:   "unmark <bssid>",
		Short: "Remove the potential-rogue mark from a BSSID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "rogue.unmark", map[string]string{"bssid": args[0]},
				func(w io.Writer, r struct {
					BSSID string `json:"bssid"`
				}) error {
					fprintf(w, "%s potential-rogue mark cleared\n", r.BSSID)
					return nil
				})
		},
	}

	cmd.AddCommand(classify, list, detail, karma, mark, unmark)
	return cmd
}

// analysisSummary mirrors the clustering result for rendering.
type analysisSummary struct {
	ESSID        string `json:"essid"`
	Population   int    `json:"population"`
	Inconclusive bool   `json:"inconclusive"`
	Reason       string `json:"reason"`
	Outliers     []struct {
		AP struct {
			BSSID string `json:"bssid"`
		} `json:"ap"`
		Score       float64 `json:"score"`
		Differences []struct {
			Attribute string `json:"attribute"`
			Expected  string `json:"expected"`
			Observed  string `json:"observed"`
		} `json:"differences"`
	} `json:"outliers"`
}

func huntCmd() *cobra.Command {
	var (
		audible bool
		watch   bool
	)

	cmd := &cobra.Command{
		Use:   "hunt <bssid|mac>",
		Short: "Direction-find a single device",
		Long: `Locks a radio to the target's channel and reports live signal strength.

Works on any BSSID or client MAC WARP has observed, not just on rogues: locating an unknown
access point, a broadcasting printer, or an unauthorized station are all ordinary uses.

The intended workflow is to switch to a directional antenna and walk the signal gradient. The
peak-hold marker tells you whether you are getting warmer or have already walked past it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr := args[0]
			params := map[string]any{"addr": addr, "audible": audible}

			var started struct {
				Job daemon.Job `json:"job"`
			}
			if err := call(cmd.Context(), "hunt.start", params, &started); err != nil {
				return err
			}
			if g.jsonOut {
				return emitJSON(cmd.OutOrStdout(), started)
			}

			w := cmd.OutOrStdout()
			fprintf(w, "hunting %s (job %s)\n", addr, started.Job.ID)
			if !watch {
				fprintf(w, "poll with:  warp hunt-state %s\n", addr)
				return nil
			}
			return watchHunt(cmd, addr)
		},
	}

	cmd.Flags().BoolVar(&audible, "audible", false,
		"audible cue: the beep rate rises with signal strength, so you can watch the antenna")
	cmd.Flags().BoolVar(&watch, "watch", true, "stream the readout until interrupted")

	state := &cobra.Command{
		Use:   "hunt-state [addr]",
		Short: "Show the current state of a hunt",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := map[string]any{}
			if len(args) == 1 {
				params["addr"] = args[0]
			}
			return call(cmd.Context(), "hunt.state", params, nil)
		},
	}

	stop := &cobra.Command{
		Use:   "hunt-stop <addr>",
		Short: "Stop a hunt and release its radio",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd.Context(), "hunt.stop", map[string]string{"addr": args[0]}, nil)
		},
	}

	cmd.AddCommand(state, stop)
	return cmd
}

// watchHunt polls the hunt state and redraws a single line.
//
// A full-screen display belongs in the REPL; this is the one-shot client, and a single
// rewritten line is what stays readable over SSH on a phone tether.
func watchHunt(cmd *cobra.Command, addr string) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	w := cmd.OutOrStdout()
	var lastBeep time.Time
	for {
		select {
		case <-cmd.Context().Done():
			fprintf(w, "\n")
			return nil
		case <-ticker.C:
			var st huntState
			if err := call(cmd.Context(), "hunt.state", map[string]string{"addr": addr}, &st); err != nil {
				fprintf(w, "\n")
				return err
			}
			fprintf(w, "\r\033[K%s", st.line())
			// The audible cue (--audible): the daemon sets a beep interval that shortens as the
			// signal strengthens, and zero when silent. Sound the terminal bell no faster than the
			// 250ms poll, so the rate rises with signal as the flag promises. Emit only when the
			// interval has elapsed to avoid a continuous tone.
			if st.BeepInterval > 0 && time.Since(lastBeep) >= time.Duration(st.BeepInterval) {
				fprintf(w, "\a")
				lastBeep = time.Now()
			}
		}
	}
}

// huntState mirrors the hunt snapshot for rendering.
type huntState struct {
	Current       int8    `json:"current_rssi"`
	HasSignal     bool    `json:"has_signal"`
	Peak          int8    `json:"peak_rssi"`
	PeakAge       int64   `json:"peak_age"`
	HasPeak       bool    `json:"has_peak"`
	PacketsPerSec float64 `json:"packets_per_sec"`
	Sparkline     []int8  `json:"sparkline"`
	Stale         bool    `json:"stale"`
	Packets       uint64  `json:"packets"`
	// BeepInterval is how often the audible cue should sound, in nanoseconds. Zero means silent
	// (the hunt was not started with --audible, or there is no signal yet).
	BeepInterval int64 `json:"beep_interval"`
}

func (s huntState) line() string {
	if s.Stale {
		return "target lost - no packets recently"
	}
	if !s.HasSignal {
		return "waiting for the first packet…"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%4d dBm  %s  %5.1f pkt/s",
		s.Current, bar(s.Current, 24), s.PacketsPerSec)
	if s.HasPeak {
		fmt.Fprintf(&b, "  peak %d dBm %s ago",
			s.Peak, time.Duration(s.PeakAge).Round(time.Second))
	}
	return b.String()
}

func bar(rssi int8, width int) string {
	const weak, strong = -90.0, -30.0
	v := float64(rssi)
	if v < weak {
		v = weak
	}
	if v > strong {
		v = strong
	}
	filled := int((v - weak) / (strong - weak) * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func jobsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "jobs",
		Short: "List background jobs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "jobs.list", nil, func(w io.Writer, jobs []daemon.Job) error {
				if len(jobs) == 0 {
					fprintf(w, "no jobs\n")
					return nil
				}
				now := time.Now()
				tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "ID\tKIND\tTARGET\tSTATE\tELAPSED\tDETAIL")
				for _, j := range jobs {
					detail := j.Detail
					if j.Error != "" {
						detail = j.Error
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
						j.ID, j.Kind, j.Target, j.State,
						j.Elapsed(now).Round(time.Second), truncate(detail, 50))
				}
				return tw.Flush()
			})
		},
	}

	kill := &cobra.Command{
		Use:   "kill <id>",
		Short: "Cancel a running job",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return call(cmd.Context(), "jobs.kill", map[string]string{"id": args[0]}, nil)
		},
	}

	cmd.AddCommand(kill)
	return cmd
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
