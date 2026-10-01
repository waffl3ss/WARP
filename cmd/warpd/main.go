// Command warpd is the WARP daemon.
//
// It is the same binary surface as `warp daemon`, shipped separately so a systemd unit on a
// NUC in a wiring closet has a stable entry point that does not depend on subcommand parsing.
package main

import (
	"fmt"
	"os"

	"github.com/waffl3ss/warp/internal/cli"
)

func main() {
	root := cli.Root()

	// Rewrite argv so `warpd --workspace ...` behaves as `warp daemon --workspace ...`.
	os.Args = append([]string{os.Args[0], "daemon"}, os.Args[1:]...)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
