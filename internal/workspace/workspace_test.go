package workspace

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/waffl3ss/warp/internal/scope"
)

func writeScope(t *testing.T, dir string, lines ...string) string {
	t.Helper()
	path := filepath.Join(dir, "client-scope.txt")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write scope file: %v", err)
	}
	return path
}

func TestInitCreatesEngagementDirectory(t *testing.T) {
	tmp := t.TempDir()
	scopePath := writeScope(t, tmp, "CORP-WIFI", "CORP-IOT")
	dir := filepath.Join(tmp, "engagement")

	ws, warns, err := Init(dir, scopePath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer ws.Close()

	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	if ws.Scope.Len() != 2 {
		t.Errorf("scope has %d entries, want 2", ws.Scope.Len())
	}

	for _, sub := range []string{ScopeFile, EventsFile, CertsDir, CredsDir, CapturesDir} {
		if _, err := os.Stat(filepath.Join(dir, sub)); err != nil {
			t.Errorf("missing %s: %v", sub, err)
		}
	}

	// The scope file is copied in, not referenced: the engagement record must be
	// self-contained and the client's original must not be able to drift under it.
	if err := os.Remove(scopePath); err != nil {
		t.Fatalf("remove original scope file: %v", err)
	}
	ws.Close()
	if _, err := Open(dir); err != nil {
		t.Fatalf("workspace does not survive deletion of the client's original scope file: %v", err)
	}
}

// TestSiteWideEngagementInitialisesAndResumes walks the whole path, because the pieces were
// each correct on their own and the combination was not: a site-wide scope has no entries,
// and the gate refused to build over an empty one. `warp init --all-networks` created the
// directory and then failed, which no unit test touched.
func TestSiteWideEngagementInitialisesAndResumes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "engagement")
	const why = "SoW 2026-114, all wireless at the Reno DC"

	ws, _, err := InitSiteWide(dir, "", why)
	if err != nil {
		t.Fatalf("InitSiteWide: %v", err)
	}
	if !ws.Scope.IsSiteWide() {
		t.Fatal("the scope is not site-wide")
	}
	if ws.Gate == nil {
		t.Fatal("no gate was built over a site-wide scope")
	}

	// Every named network is authorized; an unresolved hidden one still is not, because there
	// is no name to record the transmission against.
	for _, essid := range []string{"ANYTHING", "a neighbour's network", "linksys"} {
		if err := ws.Gate.AuthorizeTransmit(context.Background(), scope.Request{
			Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: essid,
		}); err != nil {
			t.Errorf("site-wide scope refused %q: %v", essid, err)
		}
	}
	if err := ws.Gate.AuthorizeTransmit(context.Background(), scope.Request{
		Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: "",
	}); err == nil {
		t.Error("a network with no name was authorized under a site-wide scope")
	}
	ws.Close()

	// Resuming must read the authorization back rather than re-deciding it, or a restart
	// could silently narrow or widen what the engagement is allowed to do.
	again, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer again.Close()

	if !again.Scope.IsSiteWide() {
		t.Fatal("resuming lost the site-wide authorization")
	}
	if again.Scope.SiteWideNote() != why {
		t.Errorf("the recorded justification came back as %q", again.Scope.SiteWideNote())
	}
}

// TestSiteWideRequiresAWrittenJustification. It is the widest authorization WARP has, and a
// bare flag is not a record of why anyone was allowed to use it.
func TestSiteWideRequiresAWrittenJustification(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "engagement")
	if _, _, err := InitSiteWide(dir, "", "   "); err == nil {
		t.Fatal("a site-wide scope was accepted with no justification")
	}
}

func TestInitRefusesToOverwriteAnExistingEngagement(t *testing.T) {
	tmp := t.TempDir()
	scopePath := writeScope(t, tmp, "CORP-WIFI")
	dir := filepath.Join(tmp, "engagement")

	ws, _, err := Init(dir, scopePath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	ws.Close()

	// Re-running init would reset state that is evidence.
	if _, _, err := Init(dir, scopePath); err == nil {
		t.Fatal("Init overwrote an existing engagement directory")
	}
}

func TestDirectoryPermissionsAreRestrictive(t *testing.T) {
	tmp := t.TempDir()
	scopePath := writeScope(t, tmp, "CORP-WIFI")
	dir := filepath.Join(tmp, "engagement")

	ws, _, err := Init(dir, scopePath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer ws.Close()

	// The directory holds captured credential material and a record of everything
	// transmitted at a client site.
	for _, p := range []string{dir, filepath.Join(dir, CredsDir), filepath.Join(dir, CertsDir)} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %04o; group/other access must be denied", p, perm)
		}
	}

	fi, err := os.Stat(filepath.Join(dir, EventsFile))
	if err != nil {
		t.Fatalf("stat audit log: %v", err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("audit log has mode %04o; it must not be world-readable", perm)
	}
}

// TestOpenReplaysOperatorState is the shipped-NUC case: a reboot mid-engagement must come
// back with the acknowledgments and vetoes already in place, with nobody present.
func TestOpenReplaysOperatorState(t *testing.T) {
	tmp := t.TempDir()
	scopePath := writeScope(t, tmp, "Guest", "CORP-WIFI")
	dir := filepath.Join(tmp, "engagement")

	ws, _, err := Init(dir, scopePath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	if pending := ws.Gate.PendingAcknowledgments(); len(pending) != 1 || pending[0] != "Guest" {
		t.Fatalf("expected Guest pending, got %v", pending)
	}
	if err := ws.Gate.AcknowledgeGeneric("Guest", "operator"); err != nil {
		t.Fatalf("AcknowledgeGeneric: %v", err)
	}
	if err := ws.Gate.Reject("de:ad:be:ef:00:01", "Guest", "neighbour"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	ws.Close()

	reopened, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer reopened.Close()

	if pending := reopened.Gate.PendingAcknowledgments(); len(pending) != 0 {
		t.Errorf("acknowledgment did not survive a restart: %v", pending)
	}
	if _, vetoed := reopened.Gate.Rejections()["de:ad:be:ef:00:01"]; !vetoed {
		t.Error("veto did not survive a restart")
	}

	// Active work at the acknowledged ESSID proceeds with nobody present to confirm anything.
	err = reopened.Gate.AuthorizeTransmit(context.Background(), scope.Request{
		Module: "solicit", BSSID: "a4:2b:8c:11:22:33", ESSID: "Guest",
	})
	if err != nil {
		t.Errorf("authorized work refused after restart with no operator present: %v", err)
	}
}

func TestOpenRejectsMissingScope(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil {
		t.Fatal("Open succeeded on a directory with no scope.txt")
	}
}

func TestInitRejectsEmptyScope(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "empty.txt")
	if err := os.WriteFile(path, []byte("\n\n\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := Init(filepath.Join(tmp, "e"), path); err == nil {
		t.Fatal("Init accepted an empty scope file")
	}
}

// TestInitSurfacesScopeWarnings covers a client-supplied file with whitespace-padded or
// duplicated entries — kept verbatim, but reported.
func TestInitSurfacesScopeWarnings(t *testing.T) {
	tmp := t.TempDir()
	scopePath := writeScope(t, tmp, "CORP-WIFI ", "CORP-IOT", "CORP-IOT")
	dir := filepath.Join(tmp, "engagement")

	ws, warns, err := Init(dir, scopePath)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer ws.Close()

	if len(warns) != 2 {
		t.Fatalf("expected warnings for the padded and duplicate entries, got %d: %v", len(warns), warns)
	}
	// The padded entry is kept exactly as the client wrote it.
	if !ws.Scope.Contains("CORP-WIFI ") {
		t.Error("padded ESSID was silently trimmed, changing what is in scope")
	}
	if ws.Scope.Contains("CORP-WIFI") {
		t.Error("trimmed form was added to scope, widening it beyond the client's file")
	}
}
