// Package build holds the identity stamped on the binary.
//
// One place, so the dashboard, the browser interface, `--version`, the daemon banner and the
// engagement report cannot disagree about what is running.
package build

// Version is the release this source tree represents.
//
// Edited by hand when the version is bumped, and tagged in git to match. It is *not* derived
// from git: a plain `go build ./...` with no Makefile and no repository must still produce a
// binary that knows what it is, because that is how it gets built on a machine that only has
// the source.
const Version = "v0.24.0"

// Commit is the git revision the binary was built from, set at link time by the Makefile with
// -X github.com/waffl3ss/warp/internal/build.Commit=<sha>. Empty for a build outside the
// Makefile or outside a repository.
//
// Version says which release; Commit says which build of it. A client asking which code
// produced a finding needs the second one, and a version alone cannot answer it.
var Commit = ""

// Identity.
const (
	// Name is the tool.
	Name = "WARP"
	// Tagline expands the acronym, for the places with room for it.
	Tagline = "Wireless Assessment & Rogue Platform"
	// Author is the handle this is published under.
	Author = "@waffl3ss"
	// URL is where it lives.
	URL = "github.com/waffl3ss/warp"
)

// Release is the version, with the commit when one is known: "v0.5.0" or "v0.5.0 (a1b2c3d)".
func Release() string {
	if Commit == "" {
		return Version
	}
	return Version + " (" + Commit + ")"
}

// Credit is the compact attribution shown alongside live engagement data. Deliberately short:
// it shares a line with the workspace and the clock and must not compete with them.
func Credit() string { return Version + " " + Author }
