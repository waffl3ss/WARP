package build

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The version is declared in three places that must agree: this package, the changelog, and the
// README's header line. Two of those are prose and drift silently — a release note describing
// v0.5.0 while the binary reports v0.4.1 is worse than no release note, because the reader has
// no reason to doubt it.

var semver = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

func TestVersionIsSemver(t *testing.T) {
	if !semver.MatchString(Version) {
		t.Fatalf("Version = %q, want a semver tag like v0.5.0", Version)
	}
}

// TestTheChangelogDocumentsThisVersion. A version bump without a changelog entry leaves the
// operator no way to know what changed between two binaries.
func TestTheChangelogDocumentsThisVersion(t *testing.T) {
	body, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	if !strings.Contains(string(body), "## ["+Version+"]") {
		t.Errorf("CHANGELOG.md has no entry for %s", Version)
	}
}

// TestTheReadmeStatesThisVersion.
func TestTheReadmeStatesThisVersion(t *testing.T) {
	body, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	if !strings.Contains(string(body), "**"+Version+"**") {
		t.Errorf("README.md does not state %s in its header", Version)
	}
}

// TestReleaseCarriesTheCommitWhenThereIsOne. Version says which release; Commit says which
// build of it, and that is what traces a finding in a report back to code.
func TestReleaseCarriesTheCommitWhenThereIsOne(t *testing.T) {
	saved := Commit
	defer func() { Commit = saved }()

	Commit = ""
	if got := Release(); got != Version {
		t.Errorf("Release() with no commit = %q, want %q", got, Version)
	}

	Commit = "a1b2c3d"
	got := Release()
	if !strings.Contains(got, Version) || !strings.Contains(got, "a1b2c3d") {
		t.Errorf("Release() = %q, want both the version and the commit", got)
	}
}

// TestCreditIsShortEnoughForAHeaderLine. It shares the dashboard's title line with the
// workspace path and the clock, and a long credit pushes those off a narrow terminal.
func TestCreditIsShortEnoughForAHeaderLine(t *testing.T) {
	if n := len(Credit()); n > 24 {
		t.Errorf("Credit() is %d characters (%q); it shares a line with live data", n, Credit())
	}
	if !strings.Contains(Credit(), Author) {
		t.Errorf("Credit() = %q, carries no attribution", Credit())
	}
}
