package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// newTestServer starts a server on a temp socket and returns it with a connected client.
func newTestServer(t *testing.T, register func(*Server)) (*Server, *Client) {
	t.Helper()

	// Unix socket paths are limited to ~108 bytes, and t.TempDir() under a long test name can
	// exceed that.
	dir, err := os.MkdirTemp("", "warprpc")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "warp.sock")

	s := NewServer(quietLogger())
	register(s)
	if err := s.Listen(sock); err != nil {
		t.Fatalf("Listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		s.Close()
		<-done
	})

	c, err := Dial(sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return s, c
}

func TestCallAndResult(t *testing.T) {
	_, c := newTestServer(t, func(s *Server) {
		s.Register("echo", func(ctx context.Context, params json.RawMessage) (any, error) {
			var in struct {
				Msg string `json:"msg"`
			}
			if err := json.Unmarshal(params, &in); err != nil {
				return nil, Errorf(CodeInvalidParams, "bad params: %v", err)
			}
			return map[string]string{"msg": in.Msg}, nil
		})
	})

	var out struct {
		Msg string `json:"msg"`
	}
	if err := c.Call(context.Background(), "echo", map[string]string{"msg": "hello"}, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if out.Msg != "hello" {
		t.Fatalf("got %q, want %q", out.Msg, "hello")
	}
}

func TestUnknownMethod(t *testing.T) {
	_, c := newTestServer(t, func(s *Server) {})

	err := c.Call(context.Background(), "nope", nil, nil)
	if err == nil {
		t.Fatal("expected an error for an unknown method")
	}
	var rerr *Error
	if !errors.As(err, &rerr) || rerr.Code != CodeMethodNotFound {
		t.Fatalf("expected CodeMethodNotFound, got %v", err)
	}
}

// TestScopeDenialHasItsOwnCode asserts a scope refusal is distinguishable from a failure. A
// denial is a correct outcome and clients must be able to render it as one.
func TestScopeDenialHasItsOwnCode(t *testing.T) {
	_, c := newTestServer(t, func(s *Server) {
		s.Register("psk", func(ctx context.Context, params json.RawMessage) (any, error) {
			return nil, Errorf(CodeScopeDenied, "essid not in scope")
		})
	})

	err := c.Call(context.Background(), "psk", nil, nil)
	var rerr *Error
	if !errors.As(err, &rerr) {
		t.Fatalf("expected an *Error, got %T: %v", err, err)
	}
	if rerr.Code != CodeScopeDenied {
		t.Fatalf("scope denial surfaced as code %d, want %d", rerr.Code, CodeScopeDenied)
	}
	if rerr.Code == CodeInternal {
		t.Fatal("a scope denial must not be indistinguishable from an internal error")
	}
}

func TestDuplicateRegistrationIsRejected(t *testing.T) {
	s := NewServer(quietLogger())
	if err := s.Register("m", func(context.Context, json.RawMessage) (any, error) { return nil, nil }); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := s.Register("m", func(context.Context, json.RawMessage) (any, error) { return nil, nil }); err == nil {
		t.Fatal("duplicate registration was accepted, silently replacing the handler")
	}
}

// TestConcurrentCallsDoNotBlockEachOther asserts a slow call does not stall the prompt.
func TestConcurrentCallsDoNotBlockEachOther(t *testing.T) {
	release := make(chan struct{})
	_, c := newTestServer(t, func(s *Server) {
		s.Register("slow", func(ctx context.Context, _ json.RawMessage) (any, error) {
			<-release
			return "slow done", nil
		})
		s.Register("fast", func(ctx context.Context, _ json.RawMessage) (any, error) {
			return "fast done", nil
		})
	})

	slowDone := make(chan error, 1)
	go func() {
		slowDone <- c.Call(context.Background(), "slow", nil, nil)
	}()

	// The fast call must complete while the slow one is still in flight.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var out string
	if err := c.Call(ctx, "fast", nil, &out); err != nil {
		t.Fatalf("fast call blocked behind a slow one: %v", err)
	}
	if out != "fast done" {
		t.Fatalf("got %q", out)
	}

	close(release)
	if err := <-slowDone; err != nil {
		t.Fatalf("slow call: %v", err)
	}
}

// TestSubscribeWithRecentReplaysBacklog: a subscriber that connects after events have been
// broadcast still receives them as the recent backlog, so the web log tab is never empty during a
// quiet stretch.
func TestSubscribeWithRecentReplaysBacklog(t *testing.T) {
	s := NewServer(quietLogger())

	s.Broadcast(Event{Kind: "recon", Text: "one"})
	s.Broadcast(Event{Kind: "recon", Text: "two"})

	recent, ch, stop := s.SubscribeWithRecent(8)
	defer stop()

	if len(recent) != 2 || recent[0].Text != "one" || recent[1].Text != "two" {
		t.Fatalf("backlog = %+v, want the two prior events in order", recent)
	}

	// And a subsequent event arrives live on the channel.
	s.Broadcast(Event{Kind: "recon", Text: "three"})
	select {
	case got := <-ch:
		if got.Text != "three" {
			t.Errorf("live event = %q, want three", got.Text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no live event after subscribing")
	}
}

func TestEventBroadcast(t *testing.T) {
	s, c := newTestServer(t, func(s *Server) {
		s.Register("ping", func(context.Context, json.RawMessage) (any, error) { return "pong", nil })
	})

	// Round-trip a call first so the connection is definitely established server-side.
	if err := c.Call(context.Background(), "ping", nil, nil); err != nil {
		t.Fatalf("ping: %v", err)
	}

	want := Event{
		Kind:   "pmkid",
		Level:  LevelGood,
		Text:   "[+] PMKID  CORP-WIFI  a4:2b:8c:11:22:1f  ch6  → pmkid.22000",
		Fields: map[string]any{"essid": "CORP-WIFI", "channel": float64(6)},
	}
	s.Broadcast(want)

	select {
	case got := <-c.Events():
		if got.Kind != want.Kind || got.Text != want.Text || got.Level != want.Level {
			t.Fatalf("event mismatch:\n got %+v\nwant %+v", got, want)
		}
		if got.Fields["essid"] != "CORP-WIFI" {
			t.Errorf("structured fields lost: %+v", got.Fields)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no event received")
	}
}

// TestEventsAndResponsesShareTheSocket asserts the client demuxes correctly — an event
// arriving mid-call must not be mistaken for the response.
func TestEventsAndResponsesShareTheSocket(t *testing.T) {
	s, c := newTestServer(t, func(s *Server) {
		s.Register("work", func(ctx context.Context, _ json.RawMessage) (any, error) {
			return "result", nil
		})
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			s.Broadcast(Event{Kind: "noise", Text: "background"})
		}
	}()

	for i := 0; i < 50; i++ {
		var out string
		if err := c.Call(context.Background(), "work", nil, &out); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if out != "result" {
			t.Fatalf("call %d returned %q — an event was decoded as a response", i, out)
		}
	}
	wg.Wait()
}

// TestClientDisconnectDoesNotEndTheEngagement is the wiring-closet requirement: the operator
// is SSH'd into a NUC and the session will drop.
func TestClientDisconnectDoesNotEndTheEngagement(t *testing.T) {
	var calls int
	var mu sync.Mutex
	s, c := newTestServer(t, func(s *Server) {
		s.Register("count", func(context.Context, json.RawMessage) (any, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			return calls, nil
		})
	})

	if err := c.Call(context.Background(), "count", nil, nil); err != nil {
		t.Fatalf("first call: %v", err)
	}
	c.Close()

	// The daemon must still be serving. Broadcasting to a dead connection must not panic.
	s.Broadcast(Event{Kind: "test", Text: "after disconnect"})

	c2, err := Dial(s.sockPath)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer c2.Close()

	var n int
	if err := c2.Call(context.Background(), "count", nil, &n); err != nil {
		t.Fatalf("call after reconnect: %v", err)
	}
	if n != 2 {
		t.Fatalf("daemon state did not survive a client disconnect: count=%d, want 2", n)
	}
}

func TestCallHonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	_, c := newTestServer(t, func(s *Server) {
		s.Register("hang", func(ctx context.Context, _ json.RawMessage) (any, error) {
			<-release
			return nil, nil
		})
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.Call(ctx, "hang", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestSocketIsNotWorldAccessible(t *testing.T) {
	s, _ := newTestServer(t, func(s *Server) {})

	fi, err := os.Stat(s.sockPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	// Anyone who can write to this socket can make WARP transmit.
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("socket permissions are %04o; group/other access must be denied", perm)
	}
}

func TestListenRefusesWhenDaemonAlreadyRunning(t *testing.T) {
	s, _ := newTestServer(t, func(s *Server) {})

	second := NewServer(quietLogger())
	if err := second.Listen(s.sockPath); err == nil {
		second.Close()
		t.Fatal("a second daemon bound a socket already in use")
	}
}

// TestListenClearsStaleSocket covers a killed daemon: a leftover socket must not make the
// engagement unresumable on a box reachable only over WireGuard.
func TestListenClearsStaleSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "warprpc")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "warp.sock")

	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatalf("create stale socket file: %v", err)
	}

	s := NewServer(quietLogger())
	if err := s.Listen(sock); err != nil {
		t.Fatalf("Listen over a stale socket: %v", err)
	}
	s.Close()
}
