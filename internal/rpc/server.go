package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// Handler serves one RPC method.
type Handler func(ctx context.Context, params json.RawMessage) (any, error)

// StatusError lets a handler choose the JSON-RPC error code a failure surfaces as.
type StatusError struct {
	Code int
	Err  error
}

func (e *StatusError) Error() string { return e.Err.Error() }
func (e *StatusError) Unwrap() error { return e.Err }

// Errorf builds a StatusError.
func Errorf(code int, format string, args ...any) error {
	return &StatusError{Code: code, Err: fmt.Errorf(format, args...)}
}

// Server is the daemon's RPC endpoint.
type Server struct {
	log *slog.Logger

	mu       sync.RWMutex
	handlers map[string]Handler

	connMu sync.Mutex
	conns  map[*serverConn]struct{}

	// subs are in-process listeners, currently the web server's event stream. recent is a small
	// ring of the most recent events, replayed to a new subscriber so a client that connects during
	// a quiet stretch still sees the log so far rather than an empty pane. Guarded by subMu.
	subMu  sync.Mutex
	subs   map[chan Event]struct{}
	recent []Event

	ln       net.Listener
	sockPath string
}

// NewServer builds an RPC server with no methods registered.
func NewServer(log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		log:      log,
		handlers: make(map[string]Handler),
		conns:    make(map[*serverConn]struct{}),
	}
}

// Register adds a method. Registering the same method twice is a programming error and is
// reported rather than silently overwriting.
func (s *Server) Register(method string, h Handler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, dup := s.handlers[method]; dup {
		return fmt.Errorf("rpc: method %q is already registered", method)
	}
	s.handlers[method] = h
	return nil
}

// Methods returns the registered method names.
func (s *Server) Methods() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]string, 0, len(s.handlers))
	for m := range s.handlers {
		out = append(out, m)
	}
	return out
}

// Listen binds the Unix socket.
//
// The socket is created 0600. Anyone who can write to it can make WARP transmit, so it is
// owned by the user running the daemon (root, in practice) and readable by nobody else.
func (s *Server) Listen(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("rpc: create socket directory: %w", err)
	}

	// A socket left behind by a killed daemon would otherwise block startup - which, on a
	// box in a wiring closet reached only over WireGuard, means an engagement that cannot be
	// resumed remotely. Only remove it if nothing is listening.
	if _, err := os.Stat(path); err == nil {
		if c, derr := net.Dial("unix", path); derr == nil {
			c.Close()
			return fmt.Errorf("rpc: a daemon is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("rpc: remove stale socket %s: %w", path, err)
		}
	}

	// Create with a restrictive umask so there is no window where the socket is world-writable.
	old := syscallUmask(0o177)
	ln, err := net.Listen("unix", path)
	syscallUmask(old)
	if err != nil {
		return fmt.Errorf("rpc: listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("rpc: secure socket %s: %w", path, err)
	}

	s.ln = ln
	s.sockPath = path
	return nil
}

// Serve accepts connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	if s.ln == nil {
		return errors.New("rpc: Serve called before Listen")
	}

	go func() {
		<-ctx.Done()
		s.ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		c, err := s.ln.Accept()
		if err != nil {
			wg.Wait()
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("rpc: accept: %w", err)
		}

		sc := &serverConn{c: c, enc: json.NewEncoder(c)}
		s.connMu.Lock()
		s.conns[sc] = struct{}{}
		s.connMu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, sc)
		}()
	}
}

// Close shuts the listener and removes the socket.
func (s *Server) Close() error {
	if s.ln == nil {
		return nil
	}
	err := s.ln.Close()
	if s.sockPath != "" {
		os.Remove(s.sockPath)
	}
	return err
}

// Dispatch invokes a registered method directly, without a socket.
//
// The web server uses this so that HTTP and the Unix socket run the same handlers rather than
// two implementations that drift apart. There is one RPC surface, and everything is a client
// of it - including the parts of WARP that live in the same process.
func (s *Server) Dispatch(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	s.mu.RLock()
	h, ok := s.handlers[method]
	s.mu.RUnlock()

	if !ok {
		return nil, &Error{Code: CodeMethodNotFound, Message: "unknown method: " + method}
	}

	result, err := h(ctx, params)
	if err != nil {
		code := CodeInternal
		var se *StatusError
		if errors.As(err, &se) {
			code = se.Code
		}
		return nil, &Error{Code: code, Message: err.Error()}
	}

	raw, err := json.Marshal(result)
	if err != nil {
		return nil, &Error{Code: CodeInternal, Message: "marshal result: " + err.Error()}
	}
	return raw, nil
}

// recentEvents is how many past events are replayed to a new subscriber.
const recentEvents = 256

// Subscribe returns a channel of asynchronous events plus a function to stop listening.
//
// Used by the web server's event stream. Subscribers that fall behind lose events rather than
// stalling the daemon: a browser tab left open on a sleeping laptop must not block a capture.
func (s *Server) Subscribe(buffer int) (<-chan Event, func()) {
	_, ch, stop := s.SubscribeWithRecent(buffer)
	return ch, stop
}

// SubscribeWithRecent is Subscribe plus the recent-event backlog, returned atomically with the
// subscription so a client sees the log so far and then every event after it, with nothing missed
// or duplicated in between (the snapshot and the registration happen under the same lock Broadcast
// takes). It is what keeps the web log tab from opening empty during a quiet stretch.
func (s *Server) SubscribeWithRecent(buffer int) ([]Event, <-chan Event, func()) {
	if buffer <= 0 {
		buffer = eventBuffer
	}
	ch := make(chan Event, buffer)

	s.subMu.Lock()
	if s.subs == nil {
		s.subs = make(map[chan Event]struct{})
	}
	s.subs[ch] = struct{}{}
	recent := append([]Event(nil), s.recent...)
	s.subMu.Unlock()

	var once sync.Once
	return recent, ch, func() {
		once.Do(func() {
			s.subMu.Lock()
			delete(s.subs, ch)
			s.subMu.Unlock()
			close(ch)
		})
	}
}

// Broadcast pushes an asynchronous event to every connected client.
//
// A client that has fallen behind is dropped rather than allowed to block the daemon: an
// operator's laptop going to sleep must not stall a capture.
func (s *Server) Broadcast(ev Event) {
	params, err := json.Marshal(ev)
	if err != nil {
		s.log.Error("rpc: marshal event", "err", err)
		return
	}
	note := Request{JSONRPC: Version, Method: EventMethod, Params: params}

	s.connMu.Lock()
	conns := make([]*serverConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.connMu.Unlock()

	for _, c := range conns {
		if err := c.write(note); err != nil {
			s.log.Debug("rpc: dropping event for client", "err", err)
		}
	}

	s.subMu.Lock()
	// Keep the recent-event ring current for the next subscriber's backlog.
	s.recent = append(s.recent, ev)
	if len(s.recent) > recentEvents {
		s.recent = s.recent[len(s.recent)-recentEvents:]
	}
	for ch := range s.subs {
		select {
		case ch <- ev:
		default: // subscriber is behind; drop rather than stall the daemon
		}
	}
	s.subMu.Unlock()
}

// serverConn is one client connection. Writes are serialised because responses and
// asynchronous events share the socket.
type serverConn struct {
	c   net.Conn
	mu  sync.Mutex
	enc *json.Encoder
}

func (sc *serverConn) write(v any) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.enc.Encode(v)
}

func (s *Server) handleConn(ctx context.Context, sc *serverConn) {
	defer func() {
		s.connMu.Lock()
		delete(s.conns, sc)
		s.connMu.Unlock()
		sc.c.Close()
	}()

	// A dropped client must never end the engagement: the operator is SSH'd into a NUC in a
	// wiring closet and the session will drop. Connection scope is deliberately separate from
	// the daemon's context, and jobs keep running.
	scanner := bufio.NewScanner(sc.c)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			sc.write(Response{JSONRPC: Version, Error: &Error{Code: CodeParse, Message: "invalid JSON"}})
			continue
		}

		// Each request is handled on its own goroutine so a long call does not block the
		// connection. Attacks are background jobs and return a job ID immediately, but a slow
		// query must not stall the prompt either.
		go s.dispatch(ctx, sc, req)
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		s.log.Debug("rpc: client read error", "err", err)
	}
}

func (s *Server) dispatch(ctx context.Context, sc *serverConn, req Request) {
	isNotification := len(req.ID) == 0

	respond := func(resp Response) {
		if isNotification {
			return
		}
		resp.JSONRPC = Version
		resp.ID = req.ID
		if err := sc.write(resp); err != nil {
			s.log.Debug("rpc: write response", "method", req.Method, "err", err)
		}
	}

	s.mu.RLock()
	h, ok := s.handlers[req.Method]
	s.mu.RUnlock()

	if !ok {
		respond(Response{Error: &Error{Code: CodeMethodNotFound, Message: "unknown method: " + req.Method}})
		return
	}

	result, err := h(ctx, req.Params)
	if err != nil {
		code := CodeInternal
		var se *StatusError
		if errors.As(err, &se) {
			code = se.Code
		}
		s.log.Debug("rpc: handler error", "method", req.Method, "code", code, "err", err)
		respond(Response{Error: &Error{Code: code, Message: err.Error()}})
		return
	}

	raw, err := json.Marshal(result)
	if err != nil {
		respond(Response{Error: &Error{Code: CodeInternal, Message: "marshal result: " + err.Error()}})
		return
	}
	respond(Response{Result: raw})
}
