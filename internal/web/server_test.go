package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/rpc"
)

// fakeDispatcher records what the web server asked the RPC surface to do.
type fakeDispatcher struct {
	calls  []string
	params []string
	result any
	err    error

	events chan rpc.Event
	recent []rpc.Event
}

func (f *fakeDispatcher) Dispatch(_ context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	f.calls = append(f.calls, method)
	f.params = append(f.params, string(params))
	if f.err != nil {
		return nil, f.err
	}
	res := f.result
	if res == nil {
		res = map[string]any{"ok": true}
	}
	return json.Marshal(res)
}

func (f *fakeDispatcher) SubscribeWithRecent(int) ([]rpc.Event, <-chan rpc.Event, func()) {
	if f.events == nil {
		f.events = make(chan rpc.Event, 8)
	}
	return f.recent, f.events, func() {}
}

func newTestServer(t *testing.T) (*Server, *fakeDispatcher, http.Handler) {
	t.Helper()
	d := &fakeDispatcher{}
	s, err := New(Config{Addr: "127.0.0.1:0", Token: "test-token", Dispatcher: d})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, d, s.routes()
}

// authed returns a request carrying the bearer token.
func authed(method, path string, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer test-token")
	return r
}

// TestEveryAPIRouteRequiresAuthentication is the one that matters most here.
//
// This interface starts captures and transmits. A route added without authentication would
// hand anyone who can reach the port the ability to make a licensed radio transmit, so the
// test walks the whole table rather than sampling it.
func TestEveryAPIRouteRequiresAuthentication(t *testing.T) {
	_, _, h := newTestServer(t)

	paths := make([]string, 0, len(routeTable)+1)
	for p := range routeTable {
		paths = append(paths, p)
	}
	paths = append(paths, "/api/events")

	for _, p := range paths {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(m, p, nil))
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s: got %d without a token, want 401", m, p, w.Code)
			}
		}
	}
}

// TestMutatingRoutesRefuseGET pins the CSRF property: a transmitting action cannot be
// triggered by an <img> tag or a link someone clicks.
func TestMutatingRoutesRefuseGET(t *testing.T) {
	_, d, h := newTestServer(t)

	for p, rt := range routeTable {
		if !rt.mutating {
			continue
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, authed(http.MethodGet, p, ""))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: got %d, want 405", p, w.Code)
		}
	}
	if len(d.calls) != 0 {
		t.Errorf("a rejected GET still dispatched %v", d.calls)
	}
}

func TestRouteDispatchesToItsRPCMethod(t *testing.T) {
	_, d, h := newTestServer(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(http.MethodPost, "/api/psk/solicit", `{"bssid":"aa:bb:cc:dd:ee:ff"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}
	if len(d.calls) != 1 || d.calls[0] != "psk.solicit" {
		t.Fatalf("dispatched %v, want [psk.solicit]", d.calls)
	}
	if d.params[0] != `{"bssid":"aa:bb:cc:dd:ee:ff"}` {
		t.Fatalf("params reached the handler as %q", d.params[0])
	}
}

// TestScopeDenialIsForbiddenNotAnError separates refusal from malfunction. The operator has
// to be able to tell "the gate said no" from "something broke", because only one of those is
// worth investigating.
func TestScopeDenialIsForbiddenNotAnError(t *testing.T) {
	_, d, h := newTestServer(t)
	d.err = &rpc.Error{Code: rpc.CodeScopeDenied, Message: "ESSID not in scope"}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(http.MethodPost, "/api/psk/deauth", `{}`))

	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", w.Code)
	}
	var body struct {
		Error  string `json:"error"`
		Denied bool   `json:"denied"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !body.Denied {
		t.Error("a scope refusal was not flagged as a denial, so the interface will render it as a crash")
	}
	if !strings.Contains(body.Error, "not in scope") {
		t.Errorf("the reason was lost: %q", body.Error)
	}
}

func TestLoginIssuesASessionAndRejectsABadToken(t *testing.T) {
	s, _, h := newTestServer(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(`{"token":"wrong"}`)))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("bad token got %d, want 401", w.Code)
	}
	if len(s.sessions) != 0 {
		t.Fatal("a rejected login created a session")
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(`{"token":"test-token"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("good token got %d, want 200", w.Code)
	}

	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie was set")
	}
	if !cookie.HttpOnly {
		t.Error("the session cookie is readable from JavaScript")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Error("the session cookie is not SameSite=Strict, so it rides along on cross-site requests")
	}

	// The cookie now authenticates.
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("session cookie got %d, want 200", w.Code)
	}
}

func TestExpiredSessionStopsWorking(t *testing.T) {
	s, _, h := newTestServer(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(`{"token":"test-token"}`)))
	cookie := w.Result().Cookies()[0]

	s.mu.Lock()
	s.sessions[cookie.Value] = time.Now().Add(-time.Minute)
	s.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("an expired session got %d, want 401", w.Code)
	}
}

func TestLogoutInvalidatesTheSession(t *testing.T) {
	_, _, h := newTestServer(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader(`{"token":"test-token"}`)))
	cookie := w.Result().Cookies()[0]

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)
	h.ServeHTTP(httptest.NewRecorder(), req)

	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a logged-out session got %d, want 401", w.Code)
	}
}

// TestQueryParamsBecomeTypedRPCParams covers the read routes that take arguments: `?id=3`
// has to reach the handler as a number, because that is what the socket clients send.
func TestQueryParamsBecomeTypedRPCParams(t *testing.T) {
	_, d, h := newTestServer(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(http.MethodGet, "/api/findings?tier=%22evidence%22", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body.String())
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(d.params[0]), &got); err != nil {
		t.Fatalf("params were not an object: %q", d.params[0])
	}
	if got["tier"] != "evidence" {
		t.Fatalf("tier reached the handler as %#v", got["tier"])
	}
}

// TestTokenIsNotEchoedIntoRPCParams: the login link carries ?token=…, and that must not be
// forwarded into a handler where it could be written to the audit log.
func TestTokenIsNotEchoedIntoRPCParams(t *testing.T) {
	_, d, h := newTestServer(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(http.MethodGet, "/api/status?token=test-token", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	if strings.Contains(d.params[0], "test-token") {
		t.Fatalf("the access token was forwarded to the RPC handler: %q", d.params[0])
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	_, _, h := newTestServer(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP is missing %q: %s", want, csp)
		}
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff is not set")
	}
}

// TestIndexAndAssetsAreServed proves the embed actually contains the interface. A binary
// that serves a working API and a blank page is worse than one that fails to build.
func TestIndexAndAssetsAreServed(t *testing.T) {
	_, _, h := newTestServer(t)

	for path, want := range map[string]string{
		"/":                 "<title>WARP</title>",
		"/static/app.js":    "EventSource",
		"/static/style.css": "--accent",
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: got %d", path, w.Code)
			continue
		}
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s does not contain %q", path, want)
		}
	}
}

// TestIndexIsNotAuthenticated: the login form has to be reachable without a session, or
// there is no way to get one.
func TestIndexIsNotAuthenticated(t *testing.T) {
	_, _, h := newTestServer(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("the login page got %d", w.Code)
	}
}

func TestEventStreamDeliversEvents(t *testing.T) {
	s, d, _ := newTestServer(t)
	_ = s

	d.events = make(chan rpc.Event, 4)
	d.events <- rpc.Event{Kind: "pmkid", Level: rpc.LevelGood, Text: "[+] PMKID captured"}

	ctx, cancel := context.WithCancel(context.Background())
	req := authed(http.MethodGet, "/api/events", "").WithContext(ctx)
	w := httptest.NewRecorder()

	// The stream is a long-lived response: the handler goes on writing while this goroutine
	// polls for the event. An httptest.ResponseRecorder is not safe for that, so the body is
	// mirrored through a lock — otherwise the test itself is the data race, not the code.
	rec := &syncRecorder{ResponseRecorder: w}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.routes().ServeHTTP(rec, req)
	}()

	deadline := time.After(2 * time.Second)
	for {
		if strings.Contains(rec.body(), "PMKID captured") {
			break
		}
		select {
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("the event never reached the stream: %q", rec.body())
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	<-done

	if ct := w.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type is %q, want text/event-stream", ct)
	}
}

// TestRemoteBindNeedsAnExplicitOptIn. This interface transmits; putting it on a routable
// address should never be something that happens by accident or by copying a config.
func TestRemoteBindNeedsAnExplicitOptIn(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8443", "192.168.1.10:8443", ":8443", "example.internal:8443"} {
		if _, err := New(Config{Addr: addr, Dispatcher: &fakeDispatcher{}}); err == nil {
			t.Errorf("%s was accepted without --web-allow-remote", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0", "localhost:0"} {
		if _, err := New(Config{Addr: addr, Dispatcher: &fakeDispatcher{}}); err != nil {
			t.Errorf("loopback %s was rejected: %v", addr, err)
		}
	}
	if _, err := New(Config{Addr: "0.0.0.0:0", AllowRemote: true, Dispatcher: &fakeDispatcher{}}); err != nil {
		t.Errorf("an explicit remote bind was still refused: %v", err)
	}
}

func TestGeneratedTokenIsNotGuessable(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		s, err := New(Config{Addr: "127.0.0.1:0", Dispatcher: &fakeDispatcher{}})
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Token()) < 30 {
			t.Fatalf("token %q is too short to resist guessing", s.Token())
		}
		if seen[s.Token()] {
			t.Fatal("two servers generated the same token")
		}
		seen[s.Token()] = true
	}
}

// TestServeBeforeListenIsAnErrorNotAPanic — the daemon binds first so a taken port fails
// startup loudly; this pins the other order as a clean error.
func TestServeBeforeListenIsAnErrorNotAPanic(t *testing.T) {
	s, _, _ := newTestServer(t)
	if err := s.Serve(context.Background()); err == nil {
		t.Fatal("Serve without Listen returned nil")
	}
}

func TestListenReportsTheBoundAddress(t *testing.T) {
	s, _, _ := newTestServer(t)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer s.ln.Close()

	if strings.HasSuffix(s.Addr(), ":0") {
		t.Fatalf("Addr still reports the requested port: %s", s.Addr())
	}
	if !strings.Contains(s.URL(), s.Token()) {
		t.Errorf("the URL does not carry the token: %s", s.URL())
	}
}

// TestUnknownRPCErrorsAreNotDenials guards the inverse of the scope-denial test: an internal
// failure must not be presented to the operator as a refusal they can argue with.
func TestUnknownRPCErrorsAreNotDenials(t *testing.T) {
	_, d, h := newTestServer(t)
	d.err = errors.New("the radio went away")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(http.MethodPost, "/api/recon/start", `{}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500", w.Code)
	}
	if strings.Contains(w.Body.String(), `"denied":true`) {
		t.Error("an internal failure was reported as a scope denial")
	}
}

func TestMalformedJSONBodyIsRejectedBeforeDispatch(t *testing.T) {
	_, d, h := newTestServer(t)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(http.MethodPost, "/api/recon/start", `{not json`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", w.Code)
	}
	if len(d.calls) != 0 {
		t.Errorf("a malformed body still reached %v", d.calls)
	}
}

func TestBodyIsSizeLimited(t *testing.T) {
	_, _, h := newTestServer(t)

	// Two megabytes of valid JSON: the read is capped at one, so what arrives is truncated
	// and no longer parses. The point is that it is refused rather than buffered whole.
	big := `{"x":"` + strings.Repeat("a", 2<<20) + `"}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, authed(http.MethodPost, "/api/recon/start", big))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", w.Code)
	}
}

func TestMethodsCoversTheRouteTable(t *testing.T) {
	got := Methods()
	if len(got) != len(routeTable) {
		t.Fatalf("Methods returned %d entries for %d routes", len(got), len(routeTable))
	}
}

func TestSelfSignedCertificateIsUsable(t *testing.T) {
	cert, err := selfSignedCert()
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		t.Fatal("the certificate is incomplete")
	}

	// Regenerated per start, so two calls must not produce the same key material.
	other, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if string(cert.Certificate[0]) == string(other.Certificate[0]) {
		t.Error("two starts produced the same certificate")
	}
}

// TestEndToEndOverTLS runs a real client against a real listener, which is the only way to
// know the TLS wrapping, the routing and the embedded assets work together.
func TestEndToEndOverTLS(t *testing.T) {
	d := &fakeDispatcher{result: map[string]any{"workspace": "/tmp/eng"}}
	s, err := New(Config{Addr: "127.0.0.1:0", Token: "e2e-token", TLS: true, Dispatcher: d})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Listen(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx)

	client := &http.Client{Transport: &http.Transport{
		// The certificate is self-signed and regenerated at every start, so there is nothing
		// to pin. Verification is not what protects this interface — the token is; TLS is
		// here to keep that token and the engagement data off the wire.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
	}}

	req, _ := http.NewRequest(http.MethodGet, "https://"+s.Addr()+"/api/status", nil)
	req.Header.Set("Authorization", "Bearer e2e-token")

	var resp *http.Response
	for i := 0; i < 50; i++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "/tmp/eng") {
		t.Fatalf("the RPC result did not come back: %s", body)
	}
}

// syncRecorder makes an httptest.ResponseRecorder safe to read while the handler is still
// writing to it, which is what a streaming response requires.
type syncRecorder struct {
	*httptest.ResponseRecorder

	mu  sync.Mutex
	buf strings.Builder
}

func (r *syncRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(p)
	r.mu.Unlock()
	return len(p), nil
}

func (r *syncRecorder) Flush() {}

func (r *syncRecorder) body() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}
