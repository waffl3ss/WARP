package web

import (
	"regexp"
	"strings"
	"testing"

	"github.com/dop251/goja/parser"
)

// The frontend is plain JavaScript with no build step, which means nothing but a browser
// would otherwise notice a syntax error — and the symptom is a blank page with a working API
// behind it, on an engagement box the operator may only be able to reach over WireGuard.
//
// goja is a test-only dependency and never enters the shipped binary; it is here purely to
// parse the file the same way a browser would.
func TestAppScriptParses(t *testing.T) {
	src, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatalf("read app.js: %v", err)
	}
	if _, err := parser.ParseFile(nil, "app.js", string(src), 0); err != nil {
		t.Fatalf("app.js does not parse, so the interface would render as a blank page:\n%v", err)
	}
}

// TestEveryFetchTargetIsARealRoute catches the other way the page silently half-works: a
// button wired to a path the server does not serve returns 404 and the operator sees a
// failure toast with no explanation.
func TestEveryFetchTargetIsARealRoute(t *testing.T) {
	src, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}

	// Every server path in the script is a single-quoted literal beginning with a slash —
	// some passed to api() directly, most through act(). /static/ is served by the file
	// server rather than the route table.
	re := regexp.MustCompile(`'(/(?:api|login|logout)[^']*)'`)
	known := map[string]bool{"/login": true, "/logout": true, "/api/events": true}
	for p := range routeTable {
		known[p] = true
	}

	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		p := m[1]
		seen[p] = true
		if !known[p] {
			t.Errorf("app.js calls %s, which no route serves", p)
		}
	}
	if len(seen) < 10 {
		// If the regex stops matching after a refactor this test would pass vacuously.
		t.Fatalf("only found %d fetch targets in app.js; the extraction is broken", len(seen))
	}
}

// TestMutatingCallsUsePOST: a route that changes state or transmits refuses GET, so a
// frontend call that forgot the method would fail at runtime with a 405.
func TestMutatingCallsUsePOST(t *testing.T) {
	src, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	for p, rt := range routeTable {
		if !rt.mutating {
			continue
		}
		for _, idx := range regexp.MustCompile(regexp.QuoteMeta("'"+p+"'")).FindAllStringIndex(text, -1) {
			// act() posts by definition; a direct api() call has to say so itself.
			line := lineAround(text, idx[0])
			if strings.Contains(line, "act(") || strings.Contains(line, "method: 'POST'") {
				continue
			}
			t.Errorf("%s is mutating but is called without POST:\n  %s", p, strings.TrimSpace(line))
		}
	}
}

func lineAround(s string, i int) string {
	start := strings.LastIndexByte(s[:i], '\n') + 1
	end := strings.IndexByte(s[i:], '\n')
	if end < 0 {
		return s[start:]
	}
	return s[start : i+end]
}

// TestIndexReferencesTheAssetsItNeeds guards against a rename that leaves the page loading a
// script that is not there.
func TestIndexReferencesTheAssetsItNeeds(t *testing.T) {
	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}

	for _, ref := range regexp.MustCompile(`(?:src|href)="(/static/[^"]+)"`).
		FindAllStringSubmatch(string(index), -1) {
		name := "assets/" + strings.TrimPrefix(ref[1], "/static/")
		if _, err := assets.ReadFile(name); err != nil {
			t.Errorf("index.html references %s, which is not embedded", ref[1])
		}
	}
}

// TestEveryClassTheScriptEmitsIsStyled.
//
// An unstyled class is invisible: the markup is right, the page looks broken, and nothing
// anywhere reports an error. This is the only check that catches a rename on one side only.
func TestEveryClassTheScriptEmitsIsStyled(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	// Classes chosen at runtime by the helpers rather than written as literals.
	tokens := map[string]bool{
		"good": true, "warn": true, "bad": true, "info": true, "evid": true, "muted": true,
		"live": true, "idle": true, "on": true, "split": true, "sel": true,
		"ok": true, "err": true, "deny": true,
		"determined": true, "evidence": true, "unclassified": true,
	}

	re := regexp.MustCompile("class(?::| =) *[`']([^`']*)[`']")
	for _, m := range re.FindAllStringSubmatch(string(script), -1) {
		for _, tok := range strings.Fields(m[1]) {
			if strings.Contains(tok, "$") || tok == "" {
				continue // an interpolated fragment, covered by the map above
			}
			tokens[tok] = true
		}
	}
	if len(tokens) < 25 {
		t.Fatalf("only found %d classes; the extraction is broken", len(tokens))
	}

	styled := string(css)
	for tok := range tokens {
		if !regexp.MustCompile(`\.` + regexp.QuoteMeta(tok) + `\b`).MatchString(styled) {
			t.Errorf("app.js emits class %q, which style.css never styles", tok)
		}
	}
}

// TestEveryCSSVariableTheScriptUsesIsDefined. The script sets a few inline styles — the
// signal bar's colour, mostly — and an undefined custom property resolves to nothing, which
// on a dark background means invisible rather than wrong.
func TestEveryCSSVariableTheScriptUsesIsDefined(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := assets.ReadFile("assets/style.css")
	if err != nil {
		t.Fatal(err)
	}

	found := 0
	for _, m := range regexp.MustCompile(`var\((--[a-z0-9-]+)\)`).
		FindAllStringSubmatch(string(script), -1) {
		found++
		if !strings.Contains(string(css), m[1]+":") {
			t.Errorf("app.js uses %s, which style.css does not define", m[1])
		}
	}
	if found == 0 {
		t.Fatal("no custom properties found in app.js; the extraction is broken")
	}
}

// TestNoInlineStyleAttributes.
//
// The CSP is `style-src 'self'`, which blocks style attributes. A `setAttribute('style', …)`
// therefore does nothing at all — the signal bars rendered zero-width — and the only symptom
// is a console warning, on a box whose operator has no reason to have the console open.
// Styles set through the CSSOM are not inline styles as far as CSP is concerned.
func TestNoInlineStyleAttributes(t *testing.T) {
	for _, name := range []string{"assets/app.js", "assets/index.html"} {
		src, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if m := regexp.MustCompile(`setAttribute\(\s*['"]style['"]`).
			FindString(string(src)); m != "" {
			t.Errorf("%s sets a style attribute, which the CSP blocks: %s", name, m)
		}
		if strings.Contains(name, ".html") {
			if m := regexp.MustCompile(`\sstyle="`).FindString(string(src)); m != "" {
				t.Errorf("%s carries a style attribute, which the CSP blocks", name)
			}
		}
	}

	// And the helper that builds every element must route styles through the CSSOM.
	src, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "style.cssText") {
		t.Error("app.js does not apply styles through the CSSOM; the CSP will drop them")
	}
}

// TestNothingUserFacingSaysEAPOL.
//
// EAPOL-Key is the frame type a WPA-Personal four-way handshake arrives in, and "EAPOL" is
// hashcat's own name for mode 22000 — but it is also the transport WPA-Enterprise carries EAP
// over. An operator reading it in a column concludes the file holds enterprise captures and is
// therefore uncrackable, and stops looking at the thing the whole tool exists to produce.
//
// The word stays in the parser, where it names the actual protocol. It does not appear on
// screen.
func TestNothingUserFacingSaysEAPOL(t *testing.T) {
	for _, name := range []string{"assets/app.js", "assets/index.html", "assets/style.css"} {
		src, err := assets.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			// Comments may explain why the word is avoided.
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") ||
				strings.HasPrefix(trimmed, "/*") {
				continue
			}
			if strings.Contains(strings.ToLower(line), "eapol") {
				t.Errorf("%s shows EAPOL to the operator: %s", name, trimmed)
			}
		}
	}
}

// TestEveryElementIDTheScriptNeedsExists. The script reaches for a fixed set of IDs; a
// missing one throws on the first render and the page stays blank.
func TestEveryElementIDTheScriptNeedsExists(t *testing.T) {
	script, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}

	// IDs the script creates itself rather than looking up in the document.
	created := map[string]bool{"log": true}

	ids := map[string]bool{}
	for _, m := range regexp.MustCompile(`\$\('#([A-Za-z0-9_-]+)'\)`).
		FindAllStringSubmatch(string(script), -1) {
		ids[m[1]] = true
	}
	if len(ids) < 8 {
		t.Fatalf("only found %d element lookups; the extraction is broken", len(ids))
	}

	html := string(index)
	for id := range ids {
		if created[id] {
			continue
		}
		if !strings.Contains(html, `id="`+id+`"`) {
			t.Errorf("app.js looks up #%s, which index.html does not define", id)
		}
	}
}
