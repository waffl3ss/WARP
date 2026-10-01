package scope

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The brief requires an assertion that no code path accepts a BSSID list as scope input, and
// that no deployment-context branch exists anywhere in the attack path. Those are properties
// of the whole tree, not of one package, so they are enforced by parsing the source rather
// than by exercising an API — an API test can only cover the code paths someone remembered to
// wire up, and the failure being guarded against is precisely someone adding a new one.
//
// This duplicates .claude/hooks/constraint-guard.sh on purpose. The hook catches the mistake
// while it is being made; this catches it in CI, where it also runs for changes that never
// passed through the hook.

var (
	// A BSSID (or MAC) being accepted as scope, allowlist, inventory or target input.
	// BSSIDs are always discovered off the air, never configured.
	// The character class includes '-' so CLI flag names (--bssid-list) are caught too, not
	// just Go identifiers.
	bssidScopeInput = regexp.MustCompile(`(?i)(bssid[-_a-z]*(scope|allow|list|inventory|file|input)|(scope|allow|target|authorized)[-_a-z]*bssids?)`)

	// A branch on which deployment context WARP is running in. On-site and closet run
	// identical code; there is no mode flag gating any transmitting behaviour.
	deploymentBranch = regexp.MustCompile(`(?i)\b(onsite|on_site|closet_?mode|mode_?closet|deployment_?mode|operator_?present|is_?unattended|unattended_?mode|attended_?mode)\b`)

	// Constructs that would *implement* impersonation.
	//
	// The bare word "karma" is deliberately not banned. WARP uses it throughout for karma
	// responder *detection* — probing for a name that cannot exist and recording what answers
	// — which is the exact inverse of the behaviour being prohibited. Banning the word forced
	// an ever-growing allowlist (internal/rogue, the gate that authorizes the probe, the
	// injector that sends it), and a guard with three exemptions is a guard nobody trusts.
	//
	// What is actually forbidden is answering arbitrary probes and beaconing names that were
	// never scoped, so the patterns name those shapes directly. The behavioural guarantee is
	// enforced separately and more strongly by TestRogueAPRefusesUnscopedBeacon.
	// The karma alternation deliberately excludes "respond*": "karmaResponder" is a *noun*
	// naming a device WARP detected, and banning it would forbid describing our own findings.
	// The behaviour-shaped patterns below it — respond_to_any, answer_any_probe,
	// probe_response_any — catch an actual implementation regardless of what it is called.
	impersonationConstruct = regexp.MustCompile(`(?i)\b(` +
		`known_?beacons?|mana_?attack|` +
		`respond_?to_?any|probe_?response_?any|answer_?any_?probe|` +
		`karma_?(mode|enabled|reply|ap|beacon)` +
		`)\b`)
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %s has no go.mod: %v", root, err)
	}
	return root
}

// sourceFile is one non-test Go file with its parsed AST.
type sourceFile struct {
	rel  string
	fset *token.FileSet
	file *ast.File
}

func loadSources(t *testing.T) []sourceFile {
	t.Helper()
	root := repoRoot(t)

	var out []sourceFile
	for _, dir := range []string{"internal", "cmd"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, path)
			out = append(out, sourceFile{rel: filepath.ToSlash(rel), fset: fset, file: f})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}
	if len(out) == 0 {
		t.Fatal("no source files found — the adversarial audit would vacuously pass")
	}
	return out
}

// declaredNames returns every identifier a file *declares* — struct fields, parameters,
// results, functions, types, consts and vars — plus every string literal.
//
// Comments are deliberately excluded: CLAUDE.md and the package docs describe these
// constraints in prose ("no karma, no known-beacon"), and a scanner that cannot tell
// documentation from implementation would force the constraints to go undocumented.
func declaredNames(sf sourceFile) []struct {
	name string
	pos  token.Pos
} {
	var out []struct {
		name string
		pos  token.Pos
	}
	add := func(n string, p token.Pos) {
		if n != "" && n != "_" {
			out = append(out, struct {
				name string
				pos  token.Pos
			}{n, p})
		}
	}
	addFields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				add(n.Name, n.Pos())
			}
		}
	}

	ast.Inspect(sf.file, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncDecl:
			add(v.Name.Name, v.Name.Pos())
			if v.Type != nil {
				addFields(v.Type.Params)
				addFields(v.Type.Results)
			}
			if v.Recv != nil {
				addFields(v.Recv)
			}
		case *ast.StructType:
			addFields(v.Fields)
		case *ast.InterfaceType:
			addFields(v.Methods)
		case *ast.TypeSpec:
			add(v.Name.Name, v.Name.Pos())
		case *ast.ValueSpec:
			for _, n := range v.Names {
				add(n.Name, n.Pos())
			}
		case *ast.AssignStmt:
			if v.Tok == token.DEFINE {
				for _, lhs := range v.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						add(id.Name, id.Pos())
					}
				}
			}
		case *ast.BasicLit:
			// String literals catch the CLI/config surface: cobra flag names, struct tags,
			// config keys. A flag named --bssid-list is scope input even though no Go
			// identifier spells it that way.
			if v.Kind == token.STRING {
				if s, err := strconv.Unquote(v.Value); err == nil {
					add(s, v.Pos())
				}
			}
		}
		return true
	})
	return out
}

// TestNoCodePathAcceptsBSSIDScopeInput asserts scope.txt (ESSIDs) is the only scope input.
func TestNoCodePathAcceptsBSSIDScopeInput(t *testing.T) {
	for _, sf := range loadSources(t) {
		for _, d := range declaredNames(sf) {
			if bssidScopeInput.MatchString(d.name) {
				t.Errorf("%s:%d: %q accepts a BSSID as scope input.\n"+
					"BSSIDs are always discovered, never configured — scope.txt (ESSIDs) is the only scope input. See CLAUDE.md invariant 1.",
					sf.rel, sf.fset.Position(d.pos).Line, d.name)
			}
		}
	}
}

// TestNoDeploymentContextBranch asserts on-site and closet deployments run identical code.
func TestNoDeploymentContextBranch(t *testing.T) {
	for _, sf := range loadSources(t) {
		for _, d := range declaredNames(sf) {
			if deploymentBranch.MatchString(d.name) {
				t.Errorf("%s:%d: %q branches on deployment context.\n"+
					"There is exactly one attack path, exercised identically whether or not an operator is present. See CLAUDE.md invariant 2.",
					sf.rel, sf.fset.Position(d.pos).Line, d.name)
			}
		}
	}
}

// TestNoImpersonationConstructOutsideRogueDetection asserts the rogue AP can only beacon
// scoped ESSIDs — no karma, no known-beacon, no probe-response to arbitrary probes.
func TestNoImpersonationConstructOutsideRogueDetection(t *testing.T) {
	for _, sf := range loadSources(t) {
		// internal/rogue may say "karma": it runs the karma *responder detection* test,
		// probing for a random impossible ESSID to see what answers. That is detection.
		if strings.HasPrefix(sf.rel, "internal/rogue/") {
			continue
		}
		for _, d := range declaredNames(sf) {
			if impersonationConstruct.MatchString(d.name) {
				t.Errorf("%s:%d: %q is an impersonation construct.\n"+
					"The rogue AP may only beacon ESSIDs present in scope.txt; responding to arbitrary probes impersonates networks outside the SoW. See CLAUDE.md invariant 3.",
					sf.rel, sf.fset.Position(d.pos).Line, d.name)
			}
		}
	}
}

// TestNoFatalsInLibraryCode asserts internal/ returns errors and lets main decide. A panic
// during teardown can leave three adapters stranded in monitor mode.
func TestNoFatalsInLibraryCode(t *testing.T) {
	fatal := regexp.MustCompile(`^(log\.Fatal|log\.Panic|os\.Exit|panic)`)

	for _, sf := range loadSources(t) {
		if !strings.HasPrefix(sf.rel, "internal/") {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name string
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				if x, ok := fn.X.(*ast.Ident); ok {
					name = x.Name + "." + fn.Sel.Name
				}
			}
			if fatal.MatchString(name) {
				t.Errorf("%s:%d: %s() in library code — return an error and let main decide. See CLAUDE.md invariant 8.",
					sf.rel, sf.fset.Position(call.Pos()).Line, name)
			}
			return true
		})
	}
}

// TestNoHardcodedInterfaceNamesOutsideRadio asserts modules request a role from the
// scheduler rather than naming an interface.
func TestNoHardcodedInterfaceNamesOutsideRadio(t *testing.T) {
	ifname := regexp.MustCompile(`^(wlan|wlp|wlx|mon)[0-9]`)

	for _, sf := range loadSources(t) {
		if !strings.HasPrefix(sf.rel, "internal/") || strings.HasPrefix(sf.rel, "internal/radio/") {
			continue
		}
		ast.Inspect(sf.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if ifname.MatchString(s) {
				t.Errorf("%s:%d: hardcoded interface name %q outside internal/radio — request a role from the scheduler instead.",
					sf.rel, sf.fset.Position(lit.Pos()).Line, s)
			}
			return true
		})
	}
}

// TestAuditScannerActuallyMatches guards the guard: if the patterns stopped matching, every
// audit above would pass vacuously and nobody would notice.
func TestAuditScannerActuallyMatches(t *testing.T) {
	cases := []struct {
		re   *regexp.Regexp
		want []string
	}{
		{bssidScopeInput, []string{"BSSIDScope", "bssid_allowlist", "ScopeBSSIDs", "AuthorizedBSSIDs", "--bssid-list", "bssidInventory"}},
		{deploymentBranch, []string{"onsite", "IsUnattended", "deploymentMode", "operatorPresent", "ClosetMode"}},
		{impersonationConstruct, []string{
			"KnownBeacons", "known_beacon", "respondToAny", "respond_to_any",
			"manaAttack", "karmaMode", "karma_enabled", "karmaBeacon", "karmaReply",
			"answerAnyProbe", "probeResponseAny",
		}},
	}
	for _, c := range cases {
		for _, s := range c.want {
			if !c.re.MatchString(s) {
				t.Errorf("pattern %v no longer matches %q — the adversarial audit has gone blind", c.re, s)
			}
		}
	}

	// And must not fire on ordinary, correct code — including WARP's own karma *detection*
	// vocabulary, which is the whole reason the pattern is shaped the way it is.
	for _, ok := range []string{
		"BSSID", "bssid", "DiscoveredBSSIDs", "ESSIDScope", "scopeFile", "Mode",
		"beaconInterval", "Present",
		"karma", "KarmaProbe", "AuthorizeKarmaProbe", "karma-probe", "karmaDetection",
		"KarmaProbeESSIDLen", "karma responder detection",
		// Nouns naming what WARP *detected*, not an implementation of it.
		"karmaResponder", "karmaResponders", "LabelKarmaResponder", "detectedResponders",
	} {
		for _, c := range cases {
			if c.re.MatchString(ok) {
				t.Errorf("pattern %v false-positives on %q", c.re, ok)
			}
		}
	}
}
