package report

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestNoUserFacingEAPOLInOutputLayers enforces invariant 3a-ii beyond the web assets: the word
// "EAPOL" is hashcat's name for mode 22000 and the frame type, but to an operator it reads as
// WPA-Enterprise (uncrackable), so it must never appear in what WARP shows or writes. The web has its
// own guard (TestNothingUserFacingSaysEAPOL); this one covers the other output layers - the report,
// the console, and the subcommands - by scanning their string literals. The word stays legal in the
// parser (ParseEAPOLKey and friends are identifiers, not string literals), which is where it belongs.
func TestNoUserFacingEAPOLInOutputLayers(t *testing.T) {
	// Relative to this test's package directory (internal/report).
	dirs := []string{".", "../repl", "../cli"}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				if strings.Contains(strings.ToLower(val), "eapol") {
					t.Errorf("%s shows EAPOL to the operator in a string literal: %q\n"+
						"(invariant 3a-ii: say HANDSHAKE, write handshakes.22000)", path, val)
				}
				return true
			})
		}
	}
}
