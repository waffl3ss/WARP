package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/waffl3ss/warp/internal/daemon"
	"github.com/waffl3ss/warp/internal/store"
)

func walkthroughCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "walkthrough [name]",
		Aliases: []string{"walk"},
		Short:   "Tag observations with where you are",
		Long: `Starts a walkthrough, tagging subsequent observations with a location label.

The label is free text and deliberately unstructured - no site/building/floor/zone schema,
because that structure is wrong or unknown often enough on a real engagement that it becomes
friction, and an operator who cannot express where they are stops labelling at all.

Starting a new walkthrough ends the previous one. Observations are associated by time range
rather than by copying the label onto each row, so renaming and splitting afterwards are free
and never touch observation data.

The daemon opens an implicit walkthrough at startup, so every observation always has one
whether or not anyone declares any. A box running unattended simply keeps that one.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return callAndRender(cmd, "walkthrough.current", nil,
					func(w io.Writer, cur *store.Walkthrough) error {
						if cur == nil {
							fprintf(w, "no walkthrough open\n")
							return nil
						}
						fprintf(w, "current: %s (started %s, %s ago)\n",
							cur.Name, cur.StartTS.Format("15:04:05"),
							time.Since(cur.StartTS).Round(time.Second))
						return nil
					})
			}

			params := map[string]string{"name": args[0]}
			return callAndRender(cmd, "walkthrough.start", params,
				func(w io.Writer, wt store.Walkthrough) error {
					fprintf(w, "[+] walkthrough started - observations tagging to %s\n", wt.Name)
					return nil
				})
		},
	}

	end := &cobra.Command{
		Use:   "end",
		Short: "Close the current walkthrough without starting another",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "walkthrough.end", nil,
				func(w io.Writer, r map[string]any) error {
					fprintf(w, "walkthrough ended\n")
					return nil
				})
		},
	}

	list := &cobra.Command{
		Use:   "list",
		Short: "List walkthroughs with durations and observation counts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "walkthrough.list", nil,
				func(w io.Writer, wts []store.Walkthrough) error {
					if len(wts) == 0 {
						fprintf(w, "no walkthroughs\n")
						return nil
					}
					now := time.Now()
					tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
					fmt.Fprintln(tw, "ID\tNAME\tSTARTED\tDURATION\tAPS\tCLIENTS\tOBSERVATIONS\tPCAP\t")
					for _, wt := range wts {
						name := wt.Name
						if wt.Implicit {
							name += " (implicit)"
						}
						if wt.Open() {
							name += " [open]"
						}
						pcap := wt.PcapPath
						if pcap == "" {
							pcap = "-"
						}
						fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t\n",
							wt.ID, name, wt.StartTS.Format("2006-01-02 15:04:05"),
							wt.Duration(now).Round(time.Second), wt.APs, wt.Clients,
							wt.Observations, pcap)
					}
					return tw.Flush()
				})
		},
	}

	rename := &cobra.Command{
		Use:   "rename <id> <name>",
		Short: "Rename a walkthrough (touches no observation data)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a walkthrough id", args[0])
			}
			return call(cmd.Context(), "walkthrough.rename",
				map[string]any{"id": id, "name": args[1]}, nil)
		},
	}

	split := &cobra.Command{
		Use:   "split <id> <timestamp> [new-name]",
		Short: "Split a walkthrough in two at a timestamp",
		Long: `Divides a walkthrough at a point in time, producing two records.

Like rename, this is pure post-processing: observations associate by time range, so no
observation row is touched. The timestamp is RFC3339, e.g. 2026-03-01T14:30:00Z.`,
		Args: cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a walkthrough id", args[0])
			}
			params := map[string]any{"id": id, "at": args[1]}
			if len(args) == 3 {
				params["name"] = args[2]
			}
			return call(cmd.Context(), "walkthrough.split", params, nil)
		},
	}

	del := &cobra.Command{
		Use:     "delete <id>",
		Aliases: []string{"rm"},
		Short:   "Delete a walkthrough label and its archive (observations are kept)",
		Long: `Removes a mislabelled or failed walkthrough and its dedicated pcap.

Observations are NOT deleted: they belong to the engagement and are associated by time range,
not owned by the walkthrough. This discards only the label and the pass's own capture file.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("%q is not a walkthrough id", args[0])
			}
			return call(cmd.Context(), "walkthrough.delete", map[string]any{"id": id}, nil)
		},
	}

	cmd.AddCommand(end, list, rename, split, del)
	return cmd
}

func localizeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "localize <bssid|mac>",
		Aliases: []string{"locate"},
		Short:   "Rank the walkthroughs where a device was heard loudest",
		Long: `Reports where a device was heard, ranked by strongest signal per walkthrough.

This is deliberately not trilateration and emits no coordinate. Indoor RSSI trilateration
produces a position that looks authoritative, cannot be defended in a report, and is wrong.
A ranked list of the places a device was heard loudest is what sends someone to the right
ceiling tile.

Only observations from the pinned survey radio are used: RSSI is not comparable across
chipsets or antennas, so mixing radios would produce a ranking that looks correct and means
nothing.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := map[string]string{"addr": args[0]}
			return callAndRender(cmd, "localize", params,
				func(w io.Writer, r daemon.LocalizeResult) error {
					if len(r.Ranks) == 0 {
						fprintf(w, "%s was not observed on the survey radio (%s)\n", r.Addr, r.RadioID)
						return nil
					}
					fprintf(w, "%s - ranked by strongest observation (survey radio %s)\n\n",
						r.Addr, r.RadioID)

					tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
					fmt.Fprintln(tw, "RANK\tWALKTHROUGH\tMAX RSSI\tOBSERVATIONS\tFIRST\tLAST")
					for i, l := range r.Ranks {
						fmt.Fprintf(tw, "%d\t%s\t%d\t%d\t%s\t%s\n",
							i+1, l.WalkthroughName, l.MaxRSSI, l.Observations,
							l.FirstSeen.Format("15:04:05"), l.LastSeen.Format("15:04:05"))
					}
					if err := tw.Flush(); err != nil {
						return err
					}

					fprintf(w, "\n%s\n", wrap(r.Note, 76, ""))
					return nil
				})
		},
	}
}

// hashesCmd lists what has been captured for the cracking rig.
//
// WARP does not crack. This is the deliverable, and an operator needs to be able to see it
// without reading a root-owned file on the engagement box.
func hashesCmd() *cobra.Command {
	var linesOnly bool

	cmd := &cobra.Command{
		Use:     "hashes",
		Aliases: []string{"handshakes"},
		Short:   "List captured PMKID and handshake hashes",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "hashes.list", nil,
				func(w io.Writer, res daemon.HashesResult) error {
					// --lines emits nothing but the hash lines, so it pipes straight into a
					// file or an scp on the way to the rig.
					if linesOnly {
						// The deliverable only. An incidental capture reaching the rig would
						// be unauthorized work on someone else's credentials, and a pipe is
						// exactly where that mistake gets made.
						for _, h := range res.Hashes {
							if h.InScope {
								fprintf(w, "%s\n", h.Line)
							}
						}
						return nil
					}

					// WPS-recovered credentials are already cracked, so they head the credentials
					// view rather than the material bound for the rig. --lines never emits them.
					if len(res.WPSKeys) > 0 {
						fprintf(w, "WPS recovered keys:\n")
						wt := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
						fmt.Fprintln(wt, "NETWORK\tBSSID\tPASSPHRASE\tWPS PIN\tGENERATOR\tRECOVERED")
						for _, c := range res.WPSKeys {
							psk := c.PSK
							if psk == "" {
								psk = "(PIN only - re-run to read the passphrase)"
							}
							fmt.Fprintf(wt, "%s\t%s\t%s\t%s\t%s\t%s\n",
								displayESSID(c.ESSID, false), c.BSSID, psk, c.PIN,
								string(c.Generator), c.At.Format("15:04:05"))
						}
						if err := wt.Flush(); err != nil {
							return err
						}
						fprintf(w, "\n")
					}

					if len(res.Hashes) == 0 {
						if len(res.WPSKeys) == 0 {
							fprintf(w, "nothing captured yet\n")
						}
						if res.PendingESSID > 0 {
							fprintf(w, "\n%d handshake(s) are held waiting for a network name. "+
								"A 22000 line needs the ESSID;\nthey are written the moment it is "+
								"learned, so keep capturing or deauthenticate a client\nso it "+
								"reassociates and names the network.\n", res.PendingESSID)
						}
						return nil
					}

					tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
					fmt.Fprintln(tw, "KIND\tSCOPE\tNETWORK\tBSSID\tCLIENT\tCH\tCAPTURED")
					for _, h := range res.Hashes {
						kind := "PMKID"
						if h.Kind == "handshake" {
							kind = "HANDSHAKE"
						}
						sta := h.Station
						if sta == "" {
							sta = "-"
						}
						scope := "in scope"
						if !h.InScope {
							scope = "INCIDENTAL"
						}
						fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
							kind, scope, displayESSID(h.ESSID, false), h.BSSID, sta,
							h.Channel, h.At.Format("15:04:05"))
					}
					if err := tw.Flush(); err != nil {
						return err
					}

					fprintf(w, "\n%d PMKID, %d handshake(s)\n", res.PMKID, res.Handshake)
					if res.PendingESSID > 0 {
						fprintf(w, "%d more held pending an ESSID\n", res.PendingESSID)
					}
					fprintf(w, "\nWARP does not crack. Transfer these to the cracking rig:\n")
					for _, f := range res.Files {
						fprintf(w, "  %s\n", f)
					}
					fprintf(w, "\n  warp hashes --lines > handshakes.22000\n")

					if res.OutOfScope > 0 {
						fprintf(w, "\n%d handshake(s) were overheard from networks outside the "+
							"scope.\nCapture is passive, so WARP records what it hears rather than "+
							"discarding\nevidence - but cracking one would be unauthorized work. "+
							"They are kept\nseparately and are excluded from --lines:\n",
							res.OutOfScope)
						for _, f := range res.OutOfScopeFiles {
							fprintf(w, "  %s\n", f)
						}
					}
					return nil
				})
		},
	}

	cmd.Flags().BoolVar(&linesOnly, "lines", false,
		"print only the hash lines, for piping to a file or the cracking rig")
	return cmd
}

func exportCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "export",
		Short: "Regenerate the flat-file projections from the database",
		Long: `Rebuilds the CSV projections in the engagement directory.

sqlite is authoritative; the CSVs exist for interoperability with other tools and are always
regenerated wholesale rather than appended to, which is what makes concurrent-append
corruption impossible.

The 22000 hash files are not touched: they are append-only and already current. Carry them to
the cracking rig as they are - each line is self-contained.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return callAndRender(cmd, "export", nil, func(w io.Writer, r struct {
				Directory       string       `json:"directory"`
				Counts          store.Counts `json:"counts"`
				PMKIDHashes     int          `json:"pmkid_hashes"`
				HandshakeHashes int          `json:"handshake_hashes"`
				Files           []string     `json:"files"`
			}) error {
				fprintf(w, "exported to %s\n", r.Directory)
				for _, f := range r.Files {
					fprintf(w, "  %s\n", f)
				}
				fprintf(w, "\n%d access points, %d stations, %d observations, %d findings\n",
					r.Counts.APs, r.Counts.Stations, r.Counts.Observations, r.Counts.Findings)
				fprintf(w, "%d PMKID and %d handshake hashes ready for the cracking rig\n",
					r.PMKIDHashes, r.HandshakeHashes)
				if r.PMKIDHashes+r.HandshakeHashes > 0 {
					fprintf(w, "  %s\n  %s\n", "pmkid.22000", "handshakes.22000")
				}
				return nil
			})
		},
	}
}

func reportCmd() *cobra.Command {
	var (
		title    string
		stations bool
		stdout   bool
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate the engagement report",
		Long: `Renders the engagement into report.md in the workspace.

Evidence and conclusions are presented separately, and the report states plainly what the
assessment could not establish - wired connectivity, physical position, and the difference
between "not found" and "not present". Those limitations are not boilerplate: each one is
something WARP is structurally incapable of determining, and saying so is what stops a reader
inferring more from the findings than they support.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			params := daemon.ReportParams{Title: title, IncludeStations: stations}

			var res struct {
				Path     string `json:"path"`
				Bytes    int    `json:"bytes"`
				Findings int    `json:"findings"`
				Markdown string `json:"markdown"`
			}
			if err := call(cmd.Context(), "report", params, &res); err != nil {
				return err
			}
			if g.jsonOut {
				return emitJSON(cmd.OutOrStdout(), res)
			}
			if stdout {
				fprintf(cmd.OutOrStdout(), "%s", res.Markdown)
				return nil
			}
			fprintf(cmd.OutOrStdout(), "report written to %s (%d bytes, %d findings)\n",
				res.Path, res.Bytes, res.Findings)
			return nil
		},
	}

	cmd.Flags().StringVar(&title, "title", "", "report title")
	cmd.Flags().BoolVar(&stations, "stations", false, "include the client station inventory")
	cmd.Flags().BoolVar(&stdout, "stdout", false, "print the report instead of only writing it")

	cmd.AddCommand(reportExportCmd())
	return cmd
}

// reportExportCmd is the machine-readable (JSON) report: every BSSID under each ESSID, the findings
// and their assets, the evidence, and what was captured - no secret material.
func reportExportCmd() *cobra.Command {
	var scoped bool
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the machine-readable (JSON) report for the deliverable",
		Long: `Writes report.json (everything observed) and report-in-scope.json (scoped networks
only) into the workspace. Both files are written every time. The JSON groups by network - every
BSSID under each ESSID, the findings and the assets they affect, the evidence, and a note of what
was captured for which ESSID. It carries no secret material: no passphrases, PINs, MSCHAPv2 hashes
or cleartext.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			var res struct {
				Scoped bool            `json:"scoped"`
				Path   string          `json:"path"`
				Report json.RawMessage `json:"report"`
			}
			if err := call(cmd.Context(), "report.export",
				daemon.ReportExportParams{Scoped: scoped}, &res); err != nil {
				return err
			}
			if g.jsonOut {
				return emitJSON(cmd.OutOrStdout(), res.Report)
			}
			fprintf(cmd.OutOrStdout(),
				"wrote report.json and report-in-scope.json to the workspace (%s selected)\n",
				res.Path)
			return nil
		},
	}
	cmd.Flags().BoolVar(&scoped, "scoped", false,
		"select the in-scope-only variant for --json output (both files are written regardless)")
	return cmd
}
