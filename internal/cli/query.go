package cli

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/scope"
	"github.com/waffl3ss/warp/internal/workspace"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon and engagement status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "status", nil, func(w io.Writer, s daemon.StatusResult) error {
				fprintf(w, "workspace:    %s\n", s.Workspace)
				fprintf(w, "uptime:       %s\n", s.Uptime)
				fprintf(w, "scope:        %d ESSIDs\n", s.ScopeESSIDs)
				fprintf(w, "radios:       %d\n", s.Radios)
				if s.SurveyRadio != "" {
					fprintf(w, "survey radio: %s (pinned for the engagement)\n", s.SurveyRadio)
				}
				if d := s.Disk; d.TotalBytes > 0 {
					fprintf(w, "disk:         %s written, %s free (%.1f%% of the volume used)\n",
						workspace.HumanBytes(d.EngagementBytes),
						workspace.HumanBytes(d.FreeBytes), d.UsedPercent)
					if d.Critical() {
						// Loud in a subcommand too. Somebody checking status over SSH before
						// leaving site is exactly who needs to know the box is about to stop.
						fprintf(w, "              *** the volume is %.1f%% full - capture will "+
							"stop without an error ***\n", d.UsedPercent)
					}
				}

				if len(s.PendingAcks) > 0 {
					fprintf(w, "\ngeneric ESSIDs awaiting acknowledgment (excluded from active work):\n")
					for _, e := range s.PendingAcks {
						fprintf(w, "  %s\n", e)
					}
				}

				if len(s.Assignments) == 0 {
					fprintf(w, "\nno radios assigned\n")
					return nil
				}
				fprintf(w, "\nassignments:\n")
				tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "  ROLE\tINTERFACE\tMODE\tCHANNEL")
				for _, a := range s.Assignments {
					ch := "independent"
					if a.SharedChannel {
						ch = "shared"
					}
					fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", a.Role, a.Ifname, a.Iftype, ch)
				}
				return tw.Flush()
			})
		},
	}
}

func radiosCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "radios",
		Short: "Inspect wireless adapters",
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List adapters under the daemon's management and their role capabilities",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "radios.list", nil, func(w io.Writer, radios []daemon.RadioInfo) error {
				if len(radios) == 0 {
					fprintf(w, "no radios\n")
					return nil
				}
				for _, r := range radios {
					fprintf(w, "%s  %s", r.ID, r.Ifname)
					if r.Driver != "" {
						fprintf(w, "  driver=%s", r.Driver)
					}
					fprintf(w, "\n")
					fprintf(w, "  bands:      %s\n", strings.Join(r.Bands, ", "))
					fprintf(w, "  modes:      %s\n", strings.Join(r.Iftypes, ", "))
					fprintf(w, "  channels:   %d usable for transmit\n", r.Channels)
					fprintf(w, "  injection:  %s\n", r.Injection)
					if r.APAndMonitor {
						fprintf(w, "  concurrent AP + monitor supported\n")
					}

					var can, cannot []string
					for _, rc := range r.Roles {
						if rc.Capable {
							can = append(can, string(rc.Role))
						} else {
							cannot = append(cannot, fmt.Sprintf("%s (%s)", rc.Role, rc.Reason))
						}
					}
					fprintf(w, "  roles:      %s\n", strings.Join(can, ", "))
					if len(cannot) > 0 {
						fprintf(w, "  unavailable:\n")
						for _, c := range cannot {
							fprintf(w, "    %s\n", c)
						}
					}
					fprintf(w, "\n")
				}
				return nil
			})
		},
	}

	assignments := &cobra.Command{
		Use:   "assignments",
		Short: "Show which role each adapter is currently serving",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "radios.assignments", nil, func(w io.Writer, as []radio.Assignment) error {
				if len(as) == 0 {
					fprintf(w, "no radios assigned\n")
					return nil
				}
				tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "ROLE\tINTERFACE\tMODE")
				for _, a := range as {
					fmt.Fprintf(tw, "%s\t%s\t%s\n", a.Role, a.Ifname, a.Iftype)
				}
				return tw.Flush()
			})
		},
	}

	lock := &cobra.Command{
		Use:   "lock <radio> <channel>",
		Short: "Pin an adapter to a channel instead of letting it sweep",
		Long: `Stop one adapter following the channel plan and park it on a channel.

The plan sweeps, which is right for finding things and wrong for watching one. Pinning a card
to the target's channel while the other keeps sweeping means a handshake, a probe response or a
reassociation on that channel is never missed because the radio was three channels away.

Locking does not stop the adapter capturing; it stops it moving. An attack that needs a
different channel still borrows it for the length of the burst and puts it back.

Refused if the adapter cannot reach that channel - a 2.4 GHz-only card asked for channel 36
says so rather than tuning nowhere.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ch, err := strconv.Atoi(args[1])
			if err != nil {
				return fmt.Errorf("channel must be a number: %q", args[1])
			}
			return callAndRender(cmd, "radios.lock",
				daemon.RadioLockParams{RadioID: args[0], Channel: ch},
				func(w io.Writer, r map[string]any) error {
					fprintf(w, "%v pinned to channel %v (%v MHz)\n",
						r["radio_id"], r["channel"], r["freq"])
					fprintf(w, "%v\n", r["note"])
					return nil
				})
		},
	}

	unlock := &cobra.Command{
		Use:   "unlock [radio]",
		Short: "Hand an adapter back to the channel plan (all of them if none is named)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var p daemon.RadioUnlockParams
			if len(args) == 1 {
				p.RadioID = args[0]
			}
			return callAndRender(cmd, "radios.unlock", p,
				func(w io.Writer, r map[string]any) error {
					released, _ := r["released"].([]any)
					if len(released) == 0 {
						fprintf(w, "nothing was pinned\n")
						return nil
					}
					for _, id := range released {
						fprintf(w, "%v back on the channel plan\n", id)
					}
					return nil
				})
		},
	}

	setEnabled := func(use, short string, on bool) *cobra.Command {
		return &cobra.Command{
			Use:   use,
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return callAndRender(cmd, "radios.set-enabled",
					daemon.RadioEnableParams{RadioID: args[0], Enabled: on},
					func(w io.Writer, r map[string]any) error {
						state := "disabled - released for other use"
						if on {
							state = "enabled"
						}
						fprintf(w, "%v %s\n", r["radio_id"], state)
						return nil
					})
			},
		}
	}
	enable := setEnabled("enable <radio>", "Switch an adapter on so WARP uses it", true)
	disable := setEnabled("disable <radio>",
		"Switch an adapter off - WARP releases it and leaves it for another tool", false)

	var (
		chOnly   []int
		chNo5    bool
		chRandom bool
	)
	channels := &cobra.Command{
		Use:   "channels <radio>",
		Short: "Set which channels an adapter sweeps, 5 GHz on/off, and hop order",
		Long: `Control an adapter's channel sweep, Kismet-style.

--only restricts the sweep to a set of channels (a beacon-poor site where the target is on a
known channel wastes dwell hopping the rest). --no-5ghz drops the 5 GHz band for a 2.4-only
engagement. --random shuffles the hop order so a device that beacons rarely is less likely to be
missed by a predictable sweep landing elsewhere at the same phase every cycle.

Applied live: a sweeping radio changes without restarting recon. Passing none of the flags
clears the overrides and returns the adapter to a full ascending sweep.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "radios.channels",
				daemon.RadioChannelsParams{
					RadioID: args[0], Channels: chOnly, Disable5GHz: chNo5, Random: chRandom,
				},
				func(w io.Writer, r map[string]any) error {
					fprintf(w, "%v sweeping %v channel(s)", r["radio_id"], r["usable_channels"])
					if chNo5 {
						fprintf(w, ", 5 GHz off")
					}
					if chRandom {
						fprintf(w, ", random hop")
					}
					fprintf(w, "\n")
					return nil
				})
		},
	}
	channels.Flags().IntSliceVar(&chOnly, "only", nil,
		"restrict the sweep to these channels, e.g. --only 1,6,11 (default: all usable)")
	channels.Flags().BoolVar(&chNo5, "no-5ghz", false, "skip the 5 GHz band")
	channels.Flags().BoolVar(&chRandom, "random", false, "hop channels randomly instead of in order")

	regdomain := &cobra.Command{
		Use:   "regdomain [country-code]",
		Short: "Show or set the regulatory domain (transmit rules for 5/6 GHz)",
		Long: `With no argument, prints the current regulatory domain. With a two-letter ISO country
code, sets it - which unlocks transmitting on the 5/6 GHz bands (under the world default "00" the
kernel marks them receive-only). warpd already sets a default at startup; this changes it live.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return callAndRender(cmd, "radios.regdomain", nil,
					func(w io.Writer, r daemon.RegDomainResult) error {
						cc := r.CC
						if cc == "" {
							cc = "00"
						}
						fprintf(w, "regulatory domain: %s%s\n", cc,
							map[bool]string{true: " (world default - 5/6 GHz receive-only; set a country to transmit)"}[r.IsWorld])
						return nil
					})
			}
			return callAndRender(cmd, "radios.set-regdomain", map[string]any{"cc": args[0]},
				func(w io.Writer, r daemon.RegDomainResult) error {
					fprintf(w, "regulatory domain set to %s\n", r.CC)
					return nil
				})
		},
	}

	cmd.AddCommand(list, assignments, lock, unlock, enable, disable, channels, regdomain, probeCmd(), resetCmd())
	return cmd
}

// scopeListResult mirrors the scope.list RPC response.
type scopeListResult struct {
	ESSIDs        []scope.Entry     `json:"essids"`
	Confirmations map[string]string `json:"confirmations"`
	Rejections    map[string]string `json:"rejections"`
}

func scopeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Inspect and annotate the ESSID scope",
		Long: `Scope is defined by ESSID and only by ESSID.

` + "`confirm`" + ` records an optional operator sanity check at a discovered BSSID. It is a
convenience for a human who happens to be on site and is never a precondition: authorization
follows from ESSID match either way, because the ESSID list is what was signed.

` + "`reject`" + ` excludes a specific discovered BSSID from active work - the case where a
neighbour is broadcasting a name that is also in scope. A rejection only ever narrows scope.`,
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List scoped ESSIDs and operator annotations",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "scope.list", nil, func(w io.Writer, r scopeListResult) error {
				tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
				fmt.Fprintln(tw, "ESSID\tGENERIC\tACKNOWLEDGED\tACTIVE WORK")
				for _, e := range r.ESSIDs {
					active := "authorized"
					if !e.ActiveWorkReady {
						active = "blocked - needs acknowledgment"
					}
					ack := "-"
					if e.Acknowledged {
						ack = "yes"
						if e.AcknowledgedBy != "" {
							ack = e.AcknowledgedBy
						}
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.ESSID, yesNo(e.Generic), ack, active)
				}
				if err := tw.Flush(); err != nil {
					return err
				}

				renderAnnotations(w, "operator confirmations (advisory only)", r.Confirmations)
				renderAnnotations(w, "operator rejections (excluded from active work)", r.Rejections)
				return nil
			})
		},
	}

	var note string

	confirm := &cobra.Command{
		Use:   "confirm <bssid>",
		Short: "Record an operator sanity check at a discovered BSSID (advisory only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]string
			if err := call(cmd.Context(), "scope.confirm", map[string]string{
				"bssid": args[0], "note": note,
			}, &out); err != nil {
				return err
			}
			if g.jsonOut {
				return emitJSON(cmd.OutOrStdout(), out)
			}
			fprintf(cmd.OutOrStdout(), "confirmed %s - %s\n", out["bssid"], out["note"])
			return nil
		},
	}

	reject := &cobra.Command{
		Use:   "reject <bssid>",
		Short: "Exclude a discovered BSSID from active work",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]string
			if err := call(cmd.Context(), "scope.reject", map[string]string{
				"bssid": args[0], "note": note,
			}, &out); err != nil {
				return err
			}
			if g.jsonOut {
				return emitJSON(cmd.OutOrStdout(), out)
			}
			fprintf(cmd.OutOrStdout(), "rejected %s - %s\n", out["bssid"], out["note"])
			return nil
		},
	}

	add := &cobra.Command{
		Use:   "add <essid>",
		Short: "Widen scope to an observed network name",
		Long: `Add an ESSID to scope, authorizing active work at every access point broadcasting it.

Only names WARP has actually observed can be added: scope names things off the air, it does not
invent them. Persisted to scope.txt and recorded in the audit log.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := call(cmd.Context(), "scope.add", map[string]string{
				"essid": strings.Join(args, " "), "note": note,
			}, &out); err != nil {
				return err
			}
			if g.jsonOut {
				return emitJSON(cmd.OutOrStdout(), out)
			}
			if added, _ := out["added"].(bool); !added {
				fprintf(cmd.OutOrStdout(), "%v was already in scope\n", out["essid"])
				return nil
			}
			fprintf(cmd.OutOrStdout(), "%v added to scope\n", out["essid"])
			return nil
		},
	}

	remove := &cobra.Command{
		Use:     "remove <essid>",
		Aliases: []string{"rm"},
		Short:   "Take a network name back out of scope",
		Long: `Remove an ESSID from scope. Active work there stops being authorized and its posture
findings become out-of-scope context. Removing only narrows scope; add it back at any time with
'scope add'. Persisted to scope.txt and recorded in the audit log.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]any
			if err := call(cmd.Context(), "scope.remove", map[string]string{
				"essid": strings.Join(args, " "), "note": note,
			}, &out); err != nil {
				return err
			}
			if g.jsonOut {
				return emitJSON(cmd.OutOrStdout(), out)
			}
			if removed, _ := out["removed"].(bool); !removed {
				fprintf(cmd.OutOrStdout(), "%v was not in scope\n", out["essid"])
				return nil
			}
			fprintf(cmd.OutOrStdout(), "%v removed from scope\n", out["essid"])
			return nil
		},
	}

	for _, c := range []*cobra.Command{confirm, reject, add, remove} {
		c.Flags().StringVar(&note, "note", "", "reason, recorded in the audit log")
	}

	cmd.AddCommand(list, confirm, reject, add, remove)
	return cmd
}

func renderAnnotations(w io.Writer, title string, m map[string]string) {
	if len(m) == 0 {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fprintf(w, "\n%s:\n", title)
	for _, k := range keys {
		if m[k] == "" {
			fprintf(w, "  %s\n", k)
		} else {
			fprintf(w, "  %s - %s\n", k, m[k])
		}
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}
