// Package cli implements the warp command line.
//
// Every subcommand other than `init` and `daemon` is a thin RPC client. Both frontends - the
// one-shot subcommands here and the REPL that lands in Phase 2 - hit the same RPC surface, so
// anything reachable interactively is scriptable.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/waffl3ss/warp/internal/build"
	"github.com/waffl3ss/warp/internal/repl"
	"github.com/waffl3ss/warp/internal/rpc"
)

// DefaultSocket is where warpd listens unless told otherwise.
const DefaultSocket = "/run/warp.sock"

// globals are the flags shared by every subcommand.
type globals struct {
	socket  string
	jsonOut bool
	verbose bool
}

var g globals

// Root builds the command tree.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:     "warp",
		Short:   build.Name + " - " + build.Tagline,
		Version: build.Version,
		Long: build.Name + ` performs authorized wireless security assessments.

Scope is defined by ESSID and only by ESSID: the client provides a list of network names
and any BSSID broadcasting one of them is authorized for active work. BSSIDs are always
discovered off the air, never configured.

` + build.Author + `  ·  ` + build.URL,
		SilenceUsage:  true,
		SilenceErrors: true,

		// With no arguments, open the dashboard if a daemon is running. Discovering the tool
		// should not require reading the help first - on site nobody is reading help.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := rpc.Dial(g.socket)
			if err != nil {
				// Say what is wrong and what to do, rather than dumping the help text and
				// leaving the operator to work out that the daemon is not running.
				fprintf(cmd.ErrOrStderr(), "No daemon is listening on %s.\n\n", g.socket)

				// A daemon started on a different path is the likeliest cause, and the
				// operator has no way to tell that apart from "not running" - both look
				// identical from here. Say which one is actually there.
				if found := findLiveSockets(g.socket); len(found) > 0 {
					fprintf(cmd.ErrOrStderr(),
						"A daemon does appear to be listening elsewhere. Point at it with:\n")
					for _, s := range found {
						fprintf(cmd.ErrOrStderr(), "  warp --socket %s\n", s)
					}
					return fmt.Errorf("wrong socket path")
				}

				fprintf(cmd.ErrOrStderr(),
					"Start one, then run `warp` again:\n"+
						"  warp init ./engagement --scope <your-essid-list>\n"+
						"  sudo warp precheck        # after a reboot: radios, rfkill, NetworkManager\n"+
						"  sudo warpd --workspace ./engagement --socket %s\n\n"+
						"Run `warp --help` for the full command list, or `warp radios probe`\n"+
						"to check your adapters without a daemon.\n", g.socket)
				return fmt.Errorf("warpd is not running")
			}
			c.Close()
			return repl.Run(cmd.Context(), g.socket)
		},
	}

	// Version output carries the same credit line the dashboard and browser interface show,
	// so `warp --version` in a report appendix says who wrote it and which build ran.
	root.SetVersionTemplate(build.Name + " " + build.Release() + "\n" +
		build.Tagline + "\n" + build.Author + "  ·  " + build.URL + "\n")

	root.PersistentFlags().StringVar(&g.socket, "socket", DefaultSocket, "path to the warpd control socket")
	root.PersistentFlags().BoolVar(&g.jsonOut, "json", false, "emit JSON instead of human-readable output")
	root.PersistentFlags().BoolVarP(&g.verbose, "verbose", "v", false, "verbose logging")

	root.AddCommand(
		initCmd(),
		precheckCmd(),
		daemonCmd(),
		radiosCmd(),
		scopeCmd(),
		statusCmd(),
		consoleCmd(),
		webCmd(),
		reconCmd(),
		apsCmd(),
		stationsCmd(), // registered as `clients`, with `stations` as an alias
		walkthroughCmd(),
		localizeCmd(),
		rogueCmd(),
		pskCmd(),
		decloakCmd(),
		wpsCmd(),
		huntCmd(),
		eapCmd(),
		jobsCmd(),
		hashesCmd(),
		exportCmd(),
		reportCmd(),
	)
	return root
}

// findLiveSockets looks for a daemon listening somewhere other than where we were told.
//
// A mistyped socket path - /run/warp.socket against the default /run/warp.sock - is
// indistinguishable from "no daemon" at the call site, and the operator ends up restarting a
// daemon that was already running. Checking costs one directory read.
func findLiveSockets(exclude string) []string {
	var out []string
	for _, dir := range []string{"/run", "/var/run", "/tmp"} {
		matches, err := filepath.Glob(filepath.Join(dir, "warp*.sock*"))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if m == exclude {
				continue
			}
			// Only report one something is actually listening on: a socket left behind by a
			// killed daemon would send the operator down a dead end.
			c, err := net.DialTimeout("unix", m, 200*time.Millisecond)
			if err != nil {
				continue
			}
			c.Close()
			out = append(out, m)
		}
	}
	return out
}

// logger builds the structured operational logger. It is deliberately separate from the
// engagement audit log: events.jsonl is evidence, this is debug output.
func logger() *slog.Logger {
	level := slog.LevelInfo
	if g.verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// dial connects to the running daemon.
func dial() (*rpc.Client, error) { return rpc.Dial(g.socket) }

// call is the common path for a one-shot subcommand: connect, invoke, decode.
func call(ctx context.Context, method string, params, out any) error {
	c, err := dial()
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Call(ctx, method, params, out)
}

// emitJSON writes v as indented JSON.
func emitJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// callAndRender invokes method and either dumps JSON or hands the decoded value to render.
//
// Keeping both output shapes on one path is what stops the JSON surface from drifting away
// from the human one as commands are added.
func callAndRender[T any](cmd *cobra.Command, method string, params any, render func(io.Writer, T) error) error {
	var out T
	if err := call(cmd.Context(), method, params, &out); err != nil {
		return err
	}
	if g.jsonOut {
		return emitJSON(cmd.OutOrStdout(), out)
	}
	return render(cmd.OutOrStdout(), out)
}

func fprintf(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, format, args...)
}

// consoleCmd attaches the interactive console.
func consoleCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "console",
		Aliases: []string{"repl"},
		Short:   "Attach an interactive console to a running daemon",
		Long: `Attaches the msfconsole-style console to warpd.

The console is a thin client and holds no engagement state. Detaching, losing the SSH session
it runs in, or killing it outright changes nothing - the daemon owns the radios and every
running job. Every console command maps onto the same RPC surface the subcommands use, so
nothing here is console-only.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return repl.Run(cmd.Context(), g.socket)
		},
	}
}
