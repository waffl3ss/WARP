// Command warp is the WARP client and daemon launcher.
//
// Subcommands are thin RPC clients speaking to warpd over a Unix socket, except `init`
// (which creates an engagement directory) and `daemon` (which is warpd itself).
package main

import (
	"fmt"
	"os"

	"github.com/waffl3ss/warp/internal/cli"
)

func main() {
	// No fatal calls in library code: main is the only place that decides to exit.
	if err := cli.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
