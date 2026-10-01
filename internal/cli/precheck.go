package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/waffl3ss/warp/internal/precheck"
)

// precheckCmd runs the host pre-flight: rfkill, NetworkManager, stray supplicants, adapters. It is
// a standalone command - it runs before any daemon exists, the same category as `warp radios
// probe` - and it changes nothing without the operator confirming each fix.
func precheckCmd() *cobra.Command {
	var (
		assumeYes bool
		checkOnly bool
	)
	cmd := &cobra.Command{
		Use:   "precheck",
		Short: "Check the host is ready to capture - radios, rfkill, NetworkManager, supplicants",
		Long: `Run after a reboot, before starting warpd, to make sure nothing on the host will
fight WARP for the radios.

It checks that the adapters are present, that none are rfkill-blocked, that NetworkManager is not
going to reclaim the interfaces mid-capture, and that no stray wpa_supplicant is holding a card.
Every check is read-only. For the problems WARP can fix - a soft rfkill block, NetworkManager
managing the Wi-Fi interfaces, a running wpa_supplicant - it shows the fix and asks you to confirm
before doing anything. Nothing is changed without a yes.

Most fixes need root, so run this with sudo:
  sudo warp precheck

Skip the prompts with --yes (applies every offered fix), or --check-only to just report.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			checks := precheck.Run(cmd.Context())

			if g.jsonOut {
				return emitJSON(cmd.OutOrStdout(), precheckJSONFrom(checks))
			}

			out := cmd.OutOrStdout()
			fprintf(out, "\n  WARP pre-flight\n\n")

			var fixable []int
			var failed bool
			for i := range checks {
				c := &checks[i]
				fprintf(out, "  %s  %-16s %s\n", symbol(c.Level), c.Name, c.Detail)
				if c.Level == precheck.Fail {
					failed = true
				}
				if c.Fixable() {
					fprintf(out, "        └─ fix: %s\n", c.Fix)
					fixable = append(fixable, i)
				}
			}
			fprintf(out, "\n")

			// Apply fixes, each verified by the operator unless --yes.
			applied, remaining := 0, 0
			if !checkOnly {
				for _, i := range fixable {
					c := &checks[i]
					if !assumeYes && !confirm(cmd.InOrStdin(), out,
						fmt.Sprintf("Apply fix for %q - %s?", c.Name, c.Fix)) {
						remaining++
						continue
					}
					if err := c.Apply(cmd.Context()); err != nil {
						fprintf(out, "  %s  %-16s fix failed: %v\n", symbol(precheck.Warn), c.Name, err)
						remaining++
						continue
					}
					fprintf(out, "  %s  %-16s fixed\n", symbol(precheck.OK), c.Name)
					applied++
				}
				if applied > 0 || remaining > 0 {
					fprintf(out, "\n")
				}
			} else {
				remaining = len(fixable)
			}

			// The bottom line: can they start, or is something still in the way.
			switch {
			case failed:
				fprintf(out, "  NOT READY - a blocker above must be resolved first.\n\n")
				return fmt.Errorf("pre-flight found a blocker")
			case remaining > 0:
				fprintf(out, "  NOT READY - %d item(s) still need attention (declined, or --check-only).\n\n", remaining)
				return nil
			default:
				fprintf(out, "  READY - start the daemon:\n    sudo warpd --workspace ./eng\n\n")
				return nil
			}
		},
	}
	cmd.Flags().BoolVarP(&assumeYes, "yes", "y", false, "apply every offered fix without prompting")
	cmd.Flags().BoolVar(&checkOnly, "check-only", false, "report only; never offer to fix anything")
	return cmd
}

// symbol is the status glyph for a check level, with ASCII that survives any terminal.
func symbol(l precheck.Level) string {
	switch l {
	case precheck.OK:
		return "[ok]"
	case precheck.Info:
		return "[--]"
	case precheck.Warn:
		return "[!!]"
	case precheck.Fixable:
		return "[fix]"
	case precheck.Fail:
		return "[XX]"
	default:
		return "[??]"
	}
}

// confirm asks a yes/no question and returns true only on an explicit yes. The default is no: a
// pre-flight that changes the host on a stray keypress is worse than one that makes the operator
// type y.
func confirm(in io.Reader, out io.Writer, question string) bool {
	fprintf(out, "  %s [y/N] ", question)
	sc := bufio.NewScanner(in)
	if !sc.Scan() {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(sc.Text()))
	return answer == "y" || answer == "yes"
}

// precheckJSON is the machine-readable shape for --json.
type precheckJSON []precheckItem

type precheckItem struct {
	Name    string `json:"name"`
	Level   string `json:"level"`
	Detail  string `json:"detail"`
	Fix     string `json:"fix,omitempty"`
	Fixable bool   `json:"fixable"`
}

func precheckJSONFrom(checks []precheck.Check) precheckJSON {
	out := make(precheckJSON, 0, len(checks))
	for i := range checks {
		c := &checks[i]
		out = append(out, precheckItem{
			Name: c.Name, Level: c.Level.String(), Detail: c.Detail,
			Fix: c.Fix, Fixable: c.Fixable(),
		})
	}
	return out
}
