// Package web serves WARP's browser interface.
//
// It is a client of the same RPC surface the console and the subcommands use: every HTTP
// route maps onto an RPC method and dispatches through the same handlers. There is no second
// implementation of anything, so the web UI cannot drift away from what the other two
// frontends do.
//
// The interface is fully capable, not read-only. It starts and stops capture, solicits,
// deauthenticates, hunts, classifies and exports - because a browser on a laptop beside the
// rack is often the most convenient way to drive an engagement, and a read-only view would
// just send the operator back to SSH for anything that matters.
//
// That capability is exactly why it is authenticated, bound to localhost by default, and
// served over TLS.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waffl3ss/warp/internal/rpc"
)

//go:embed assets
var assets embed.FS

// Defaults.
const (
	// DefaultAddr binds to loopback. The web interface can start and stop transmissions, so
	// it is not exposed on the network unless the operator explicitly asks - reach it over
	// the WireGuard tunnel or an SSH port-forward instead.
	DefaultAddr = "127.0.0.1:8443"

	// sessionTTL is how long a browser session lasts before the token must be entered again.
	sessionTTL = 12 * time.Hour

	// tokenChars is the length of a generated alphanumeric token (~190 bits over [A-Za-z0-9]).
	tokenChars = 32
)

// Config configures the web server.
type Config struct {
	// Addr to listen on.
	Addr string
	// Token is the access token. Generated if empty.
	Token string
	// TLS enables HTTPS with a self-signed certificate generated at startup.
	TLS bool
	// AllowRemote permits binding to a non-loopback address.
	//
	// Required as an explicit acknowledgment: this interface transmits, and putting it on a
	// routable address without one would be too easy to do by accident.
	AllowRemote bool

	Dispatcher Dispatcher
	Log        *slog.Logger
}

// Dispatcher is the RPC surface the web server calls into.
type Dispatcher interface {
	Dispatch(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error)
	// SubscribeWithRecent registers an event stream and returns the recent event backlog alongside
	// it, so a browser connecting during a quiet stretch sees the log so far rather than an empty
	// pane. The backlog and the live channel are consistent - nothing between them is lost.
	SubscribeWithRecent(buffer int) (recent []rpc.Event, ch <-chan rpc.Event, stop func())
}

// Server is the HTTP interface.
type Server struct {
	cfg   Config
	log   *slog.Logger
	token string

	mu       sync.Mutex
	sessions map[string]time.Time

	srv *http.Server
	ln  net.Listener // the raw TCP listener, for reporting the bound address
	acc net.Listener // what Serve accepts on: ln, or ln wrapped in TLS
}

// New builds the web server.
func New(cfg Config) (*Server, error) {
	if cfg.Dispatcher == nil {
		return nil, errors.New("web: no dispatcher")
	}
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	if !cfg.AllowRemote {
		if err := requireLoopback(cfg.Addr); err != nil {
			return nil, err
		}
	}

	token := cfg.Token
	if token == "" {
		t, err := alphanumericToken(tokenChars)
		if err != nil {
			return nil, fmt.Errorf("web: generate access token: %w", err)
		}
		token = t
	}

	s := &Server{
		cfg:      cfg,
		log:      cfg.Log,
		token:    token,
		sessions: make(map[string]time.Time),
	}
	s.srv = &http.Server{
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: the event stream is a long-lived response.
		IdleTimeout: 120 * time.Second,
	}
	return s, nil
}

// requireLoopback refuses a non-loopback bind without an explicit opt-in.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("web: parse listen address %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("web: %q binds every interface; pass --web-allow-remote to accept "+
			"that this interface can transmit and should be reachable from the network", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if host == "localhost" {
			return nil
		}
		return fmt.Errorf("web: %q is not a loopback address; pass --web-allow-remote to "+
			"accept that this interface can transmit and should be reachable from the network", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("web: %s is not a loopback address; pass --web-allow-remote to "+
			"accept that this interface can transmit and should be reachable from the network", host)
	}
	return nil
}

// Token returns the access token, so the daemon can print it.
func (s *Server) Token() string { return s.token }

// alphanumericToken returns a token of n characters drawn uniformly from [A-Za-z0-9]. No dashes,
// underscores or other punctuation, so it copies and types cleanly and survives being pasted into a
// URL or a chat without escaping. Rejection sampling keeps the distribution uniform.
func alphanumericToken(n int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, n)
	buf := make([]byte, 1)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= 256-(256%len(alphabet)) {
			continue // avoid modulo bias
		}
		out[i] = alphabet[int(buf[0])%len(alphabet)]
		i++
	}
	return string(out), nil
}

// Addr is the bound address once Listen has run, and the requested one before that.
//
// Guarded because the daemon calls Listen on its own goroutine while whatever asked for the
// web interface is printing the URL: with :0 for the port, "the requested address" and "the
// bound address" are genuinely different answers, and reading the listener without the lock
// is a race on the value that decides which one comes back.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		return s.ln.Addr().String()
	}
	return s.cfg.Addr
}

// TLSEnabled reports whether the interface is served over HTTPS.
func (s *Server) TLSEnabled() bool { return s.cfg.TLS }

// URL returns the address to open.
func (s *Server) URL() string {
	scheme := "http"
	if s.cfg.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/?token=%s", scheme, s.Addr(), s.token)
}

// Listen binds the socket.
//
// Binding is separate from serving so the daemon can fail loudly at startup if the port is
// taken - an operator who asked for the web interface and silently did not get it would go
// looking for a dashboard that never existed - and so the URL is known before Serve runs.
func (s *Server) Listen() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.ln != nil {
		return errors.New("web: already listening")
	}

	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("web: listen on %s: %w", s.cfg.Addr, err)
	}
	s.ln = ln
	s.acc = ln

	if s.cfg.TLS {
		cert, err := selfSignedCert()
		if err != nil {
			ln.Close()
			s.ln, s.acc = nil, nil
			return err
		}
		s.acc = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
	}
	return nil
}

// acceptor returns what Serve should accept on.
func (s *Server) acceptor() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acc
}

// Serve runs until ctx is cancelled. Listen must have been called.
func (s *Server) Serve(ctx context.Context) error {
	acc := s.acceptor()
	if acc == nil {
		return errors.New("web: Serve called before Listen")
	}

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.srv.Shutdown(shutdown)
	}()
	go s.expireSessions(ctx)

	s.log.Info("web interface listening", "addr", s.Addr(), "tls", s.cfg.TLS)

	err := s.srv.Serve(acc)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

// ListenAndServe binds and then serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve(ctx)
}

func (s *Server) expireSessions(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			for id, exp := range s.sessions {
				if now.After(exp) {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

// route maps an HTTP path onto an RPC method.
type route struct {
	method string // RPC method
	// mutating marks a route that changes state or transmits; those require POST so a
	// cross-origin GET cannot trigger them.
	mutating bool
}

// routeTable is the whole web API.
//
// Every entry names an RPC method. Adding a capability to the daemon makes it available here
// by listing it, which is what keeps the three frontends in step.
var routeTable = map[string]route{
	"/api/status":              {method: "status"},
	"/api/radios":              {method: "radios.list"},
	"/api/assignments":         {method: "radios.assignments"},
	"/api/scope":               {method: "scope.list"},
	"/api/aps":                 {method: "aps.list"},
	"/api/ap":                  {method: "aps.detail"},
	"/api/stations":            {method: "stations.list"},
	"/api/findings":            {method: "rogue.list"},
	"/api/finding":             {method: "rogue.detail"},
	"/api/jobs":                {method: "jobs.list"},
	"/api/walkthroughs":        {method: "walkthrough.list"},
	"/api/walkthrough":         {method: "walkthrough.current"},
	"/api/walkthrough/devices": {method: "walkthrough.devices"},
	"/api/localize":            {method: "localize"},
	"/api/hunt/state":          {method: "hunt.state"},
	"/api/recon/status":        {method: "recon.status"},
	"/api/hashes":              {method: "hashes.list"},
	"/api/eap":                 {method: "eap.status"},
	"/api/certs":               {method: "certs.list"},

	// Mutating: state changes and transmissions.
	"/api/recon/start":          {method: "recon.start", mutating: true},
	"/api/recon/stop":           {method: "recon.stop", mutating: true},
	"/api/psk/solicit":          {method: "psk.solicit", mutating: true},
	"/api/psk/deauth":           {method: "psk.deauth", mutating: true},
	"/api/decloak":              {method: "decloak", mutating: true},
	"/api/harvest":              {method: "harvest", mutating: true},
	"/api/wps":                  {method: "wps", mutating: true},
	"/api/hunt/start":           {method: "hunt.start", mutating: true},
	"/api/hunt/stop":            {method: "hunt.stop", mutating: true},
	"/api/rogue/classify":       {method: "rogue.classify", mutating: true},
	"/api/rogue/karma-test":     {method: "rogue.karma-test", mutating: true},
	"/api/rogue/mark":           {method: "rogue.mark", mutating: true},
	"/api/rogue/unmark":         {method: "rogue.unmark", mutating: true},
	"/api/eap/start":            {method: "eap.start", mutating: true},
	"/api/eap/stop":             {method: "eap.stop", mutating: true},
	"/api/certs/generate":       {method: "certs.generate", mutating: true},
	"/api/certs/import":         {method: "certs.import", mutating: true},
	"/api/certs/select":         {method: "certs.select", mutating: true},
	"/api/certs/delete":         {method: "certs.delete", mutating: true},
	"/api/radios/lock":          {method: "radios.lock", mutating: true},
	"/api/radios/unlock":        {method: "radios.unlock", mutating: true},
	"/api/radios/set-enabled":   {method: "radios.set-enabled", mutating: true},
	"/api/radios/reset":         {method: "radios.reset", mutating: true},
	"/api/radios/channels":      {method: "radios.channels", mutating: true},
	"/api/radios/regdomain":     {method: "radios.regdomain"},
	"/api/radios/set-regdomain": {method: "radios.set-regdomain", mutating: true},
	"/api/precheck":             {method: "precheck.list"},
	"/api/precheck/fix":         {method: "precheck.fix", mutating: true},
	"/api/scope/confirm":        {method: "scope.confirm", mutating: true},
	"/api/scope/reject":         {method: "scope.reject", mutating: true},
	"/api/scope/acknowledge":    {method: "scope.acknowledge", mutating: true},
	"/api/scope/add":            {method: "scope.add", mutating: true},
	"/api/scope/remove":         {method: "scope.remove", mutating: true},
	"/api/walkthrough/start":    {method: "walkthrough.start", mutating: true},
	"/api/walkthrough/end":      {method: "walkthrough.end", mutating: true},
	"/api/walkthrough/rename":   {method: "walkthrough.rename", mutating: true},
	"/api/walkthrough/split":    {method: "walkthrough.split", mutating: true},
	"/api/walkthrough/delete":   {method: "walkthrough.delete", mutating: true},
	"/api/jobs/kill":            {method: "jobs.kill", mutating: true},
	"/api/export":               {method: "export", mutating: true},
	"/api/export/bundle":        {method: "export.bundle", mutating: true},
	"/api/report":               {method: "report", mutating: true},
	"/api/report/export":        {method: "report.export", mutating: true},
}

// Methods returns the RPC methods the web interface exposes.
//
// The daemon's tests use this to assert that the browser can reach everything the socket can:
// a capability that exists only over the Unix socket is a capability the web operator silently
// does not have, and that divergence is exactly what this package exists to prevent.
func Methods() []string {
	out := make([]string, 0, len(routeTable))
	for _, r := range routeTable {
		out = append(out, r.method)
	}
	return out
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	static, err := fs.Sub(assets, "assets")
	if err != nil {
		// The assets are embedded at build time; a failure here is a build problem, and the
		// server is more useful serving the API than refusing to start.
		s.log.Error("web: embedded assets unavailable", "err", err)
	} else {
		// no-cache (not no-store) so the browser revalidates the embedded assets on every load
		// rather than serving a stale app.js after an upgrade. Embedded files carry a zero modtime,
		// so without this the browser's heuristic caching keeps an old build's JavaScript - which
		// looks exactly like "the new feature doesn't work" when in fact the new code never loaded.
		fileServer := http.StripPrefix("/static/", http.FileServer(http.FS(static)))
		mux.Handle("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-cache")
			fileServer.ServeHTTP(w, r)
		}))
	}

	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/api/events", s.requireAuth(s.handleEvents))

	for path, r := range routeTable {
		mux.HandleFunc(path, s.requireAuth(s.rpcHandler(r)))
	}

	return s.securityHeaders(mux)
}

// securityHeaders sets a restrictive policy on every response.
//
// The page loads only its own embedded assets, so the CSP can forbid everything else outright.
// That matters more than usual here: the interface can make the tool transmit, so a script
// injected into it would be able to do the same.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; "+
				"connect-src 'self'; img-src 'self' data:; font-src 'self'; "+
				"form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if s.cfg.TLS {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

const sessionCookie = "warp_session"

// requireAuth rejects unauthenticated requests.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			writeError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		next(w, r)
	}
}

func (s *Server) authenticated(r *http.Request) bool {
	// A bearer token, for scripting against the same API.
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if s.validToken(strings.TrimPrefix(h, "Bearer ")) {
			return true
		}
	}

	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	exp, ok := s.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(s.sessions, c.Value)
		return false
	}
	return true
}

// validToken compares in constant time so a token cannot be recovered by timing.
func (s *Server) validToken(got string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request")
		return
	}
	if !s.validToken(strings.TrimSpace(body.Token)) {
		// Deliberately slow and vague: this is the only guess-able surface on the interface.
		time.Sleep(500 * time.Millisecond)
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		writeError(w, http.StatusInternalServerError, "could not create a session")
		return
	}
	sid := base64.RawURLEncoding.EncodeToString(id)

	s.mu.Lock()
	s.sessions[sid] = time.Now().Add(sessionTTL)
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLS,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.TLS, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := assets.ReadFile("assets/index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "interface unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// rpcHandler turns an HTTP request into an RPC dispatch.
func (s *Server) rpcHandler(rt route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if rt.mutating && r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed,
				"this action changes state or transmits; POST required")
			return
		}

		params, err := requestParams(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		result, err := s.cfg.Dispatcher.Dispatch(ctx, rt.method, params)
		if err != nil {
			var rerr *rpc.Error
			if errors.As(err, &rerr) {
				writeJSON(w, httpStatusFor(rerr.Code), map[string]any{
					"error": rerr.Message,
					"code":  rerr.Code,
					// A scope refusal is a correct outcome, not a malfunction, and the
					// interface renders it differently.
					"denied": rerr.Code == rpc.CodeScopeDenied,
				})
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if len(result) == 0 {
			result = []byte("null")
		}
		w.Write(result)
	}
}

// requestParams reads RPC params from the query string or the JSON body.
func requestParams(r *http.Request) (json.RawMessage, error) {
	if r.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
		if len(body) == 0 {
			return nil, nil
		}
		if !json.Valid(body) {
			return nil, errors.New("request body is not valid JSON")
		}
		return body, nil
	}

	q := r.URL.Query()
	if len(q) == 0 {
		return nil, nil
	}
	// Query parameters become a flat JSON object. Values that parse as JSON are kept as
	// such so `?id=3` reaches the handler as a number rather than a string.
	obj := make(map[string]any, len(q))
	for k, v := range q {
		if len(v) == 0 || k == "token" {
			continue
		}
		var parsed any
		if err := json.Unmarshal([]byte(v[0]), &parsed); err == nil {
			obj[k] = parsed
			continue
		}
		obj[k] = v[0]
	}
	if len(obj) == 0 {
		return nil, nil
	}
	return json.Marshal(obj)
}

// handleEvents streams daemon events to the browser.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	recent, events, stop := s.cfg.Dispatcher.SubscribeWithRecent(256)
	defer stop()

	// Replay the backlog first, so a tab opened during a quiet stretch shows the log so far rather
	// than an empty pane, then fall through to the live stream.
	for _, ev := range recent {
		if payload, err := json.Marshal(ev); err == nil {
			fmt.Fprintf(w, "data: %s\n\n", payload)
		}
	}
	flusher.Flush()

	// A keepalive so an idle stream is not culled by an intermediate proxy.
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case ev, ok := <-events:
			if !ok {
				return
			}
			payload, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()

		case <-ping.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func httpStatusFor(code int) int {
	switch code {
	case rpc.CodeMethodNotFound, rpc.CodeNotFound:
		return http.StatusNotFound
	case rpc.CodeInvalidParams, rpc.CodeInvalidRequest, rpc.CodeParse:
		return http.StatusBadRequest
	case rpc.CodeScopeDenied:
		// The request was understood and refused on authorization grounds.
		return http.StatusForbidden
	case rpc.CodeUnsatisfiable:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
