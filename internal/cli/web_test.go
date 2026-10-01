package cli

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/web"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// startRPC brings up a real RPC server on a real Unix socket and returns a connected client.
func startRPC(t *testing.T, methods map[string]rpc.Handler) (*rpc.Server, *rpc.Client) {
	t.Helper()

	// Unix socket paths are limited to about 108 bytes and t.TempDir() under a long test name
	// overruns it.
	dir, err := os.MkdirTemp("", "warpweb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	srv := rpc.NewServer(quiet())
	for name, h := range methods {
		if err := srv.Register(name, h); err != nil {
			t.Fatal(err)
		}
	}

	sock := filepath.Join(dir, "warp.sock")
	if err := srv.Listen(sock); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); srv.Serve(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	c, err := rpc.Dial(sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return srv, c
}

// TestWebOverTheSocketReachesTheDaemon is the whole `warp web` path end to end: a browser
// request crosses HTTP, the dispatcher, the Unix socket and lands in a real handler.
func TestWebOverTheSocketReachesTheDaemon(t *testing.T) {
	var gotParams string
	_, client := startRPC(t, map[string]rpc.Handler{
		"status": func(context.Context, json.RawMessage) (any, error) {
			return map[string]any{"workspace": "/opt/eng/acme"}, nil
		},
		"psk.solicit": func(_ context.Context, p json.RawMessage) (any, error) {
			gotParams = string(p)
			return map[string]any{"job": "7"}, nil
		},
	})

	d := newSocketDispatcher(client)
	srv, err := web.New(web.Config{
		Addr: "127.0.0.1:0", Token: "sock-token", Dispatcher: d, Log: quiet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	base := "http://" + srv.Addr()
	do := func(method, path, body string) (*http.Response, string) {
		t.Helper()
		var r io.Reader
		if body != "" {
			r = jsonReader(body)
		}
		req, err := http.NewRequest(method, base+path, r)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer sock-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}

	resp, body := do(http.MethodGet, "/api/status", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d %s", resp.StatusCode, body)
	}
	if want := `"workspace":"/opt/eng/acme"`; !contains(body, want) {
		t.Fatalf("the daemon's result did not come back: %s", body)
	}

	resp, body = do(http.MethodPost, "/api/psk/solicit", `{"bssid":"aa:bb:cc:dd:ee:ff"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solicit: %d %s", resp.StatusCode, body)
	}
	if gotParams != `{"bssid":"aa:bb:cc:dd:ee:ff"}` {
		t.Fatalf("params arrived at the handler as %q", gotParams)
	}
}

// TestScopeRefusalSurvivesTheSocket. The gate's refusal has to reach the browser as a
// refusal — a 403 with the reason — not as a generic failure the operator goes debugging.
func TestScopeRefusalSurvivesTheSocket(t *testing.T) {
	_, client := startRPC(t, map[string]rpc.Handler{
		"psk.deauth": func(context.Context, json.RawMessage) (any, error) {
			return nil, rpc.Errorf(rpc.CodeScopeDenied,
				`ESSID "NEIGHBOUR-NET" is not in scope`)
		},
	})

	d := newSocketDispatcher(client)
	srv, _ := web.New(web.Config{
		Addr: "127.0.0.1:0", Token: "t", Dispatcher: d, Log: quiet(),
	})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	req, _ := http.NewRequest(http.MethodPost, "http://"+srv.Addr()+"/api/psk/deauth",
		jsonReader(`{}`))
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a scope refusal came back as %d: %s", resp.StatusCode, body)
	}
	if !contains(string(body), `"denied":true`) {
		t.Errorf("the refusal was not flagged as one: %s", body)
	}
	if !contains(string(body), "NEIGHBOUR-NET") {
		t.Errorf("the reason was lost: %s", body)
	}
}

// TestEveryBrowserTabGetsEveryEvent. The socket delivers one stream; each open tab needs its
// own copy, and a tab that has stopped reading must not stall the others.
func TestEveryBrowserTabGetsEveryEvent(t *testing.T) {
	srv, client := startRPC(t, map[string]rpc.Handler{
		"status": func(context.Context, json.RawMessage) (any, error) { return nil, nil },
	})

	d := newSocketDispatcher(client)

	// Dial returns as soon as the socket connects; the server registers the connection when
	// it accepts. A round trip guarantees that has happened before anything is broadcast.
	if _, err := d.Dispatch(context.Background(), "status", nil); err != nil {
		t.Fatalf("priming call: %v", err)
	}

	_, a, stopA := d.SubscribeWithRecent(8)
	_, b, stopB := d.SubscribeWithRecent(8)
	defer stopA()
	defer stopB()

	// A third subscriber that never reads: its buffer fills and it starts losing events,
	// which must not affect the two that are keeping up.
	_, stalled, stopStalled := d.SubscribeWithRecent(1)
	defer stopStalled()
	_ = stalled

	for i := 0; i < 4; i++ {
		srv.Broadcast(rpc.Event{Kind: "pmkid", Level: rpc.LevelGood, Text: "[+] PMKID"})
	}

	for name, ch := range map[string]<-chan rpc.Event{"first tab": a, "second tab": b} {
		for i := 0; i < 4; i++ {
			select {
			case ev := <-ch:
				if ev.Text != "[+] PMKID" {
					t.Errorf("%s got %q", name, ev.Text)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s received only %d of 4 events", name, i)
			}
		}
	}
}

// TestStreamsCloseWhenTheDaemonGoesAway, so the browser reconnects rather than sitting on a
// dead socket showing stale data as if it were live.
func TestStreamsCloseWhenTheDaemonGoesAway(t *testing.T) {
	_, client := startRPC(t, map[string]rpc.Handler{
		"status": func(context.Context, json.RawMessage) (any, error) { return nil, nil },
	})

	d := newSocketDispatcher(client)
	_, ch, stop := d.SubscribeWithRecent(4)
	defer stop()

	client.Close()

	select {
	case _, ok := <-ch:
		if ok {
			t.Error("the stream delivered an event after the connection dropped")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the event stream stayed open after the daemon went away")
	}

	// A subscription taken out after the drop is closed immediately rather than hanging.
	_, late, stopLate := d.SubscribeWithRecent(1)
	defer stopLate()
	select {
	case _, ok := <-late:
		if ok {
			t.Error("a late subscriber received an event from a dead connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a late subscriber hung on a dead connection")
	}
}

// TestUnsubscribingTwiceIsSafe — the SSE handler defers its stop, and a dropped connection
// during shutdown can reach it by both paths.
func TestUnsubscribingTwiceIsSafe(t *testing.T) {
	_, client := startRPC(t, map[string]rpc.Handler{
		"status": func(context.Context, json.RawMessage) (any, error) { return nil, nil },
	})
	d := newSocketDispatcher(client)

	_, _, stop := d.SubscribeWithRecent(1)
	stop()
	stop()
}

// TestDispatchReportsAnUnknownMethod rather than hanging or returning an empty result.
func TestDispatchReportsAnUnknownMethod(t *testing.T) {
	_, client := startRPC(t, map[string]rpc.Handler{
		"status": func(context.Context, json.RawMessage) (any, error) { return nil, nil },
	})
	d := newSocketDispatcher(client)

	_, err := d.Dispatch(context.Background(), "no.such.method", nil)
	if err == nil {
		t.Fatal("an unknown method returned no error")
	}
	var rerr *rpc.Error
	if !errors.As(err, &rerr) || rerr.Code != rpc.CodeMethodNotFound {
		t.Fatalf("got %v, want a method-not-found RPC error", err)
	}
}

func jsonReader(s string) io.Reader { return strings.NewReader(s) }

func contains(haystack, needle string) bool { return strings.Contains(haystack, needle) }
