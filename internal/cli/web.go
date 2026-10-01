package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/spf13/cobra"

	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/web"
)

// webCmd serves the browser interface against an already-running daemon.
//
// `warpd --web` is the usual way in, but an operator who started the daemon without it should
// not have to restart - restarting releases the radios and kills every running job, which on
// site means walking the floor again. This is a client of the same socket the console uses,
// so it can be started, stopped and restarted freely while the engagement continues.
func webCmd() *cobra.Command {
	var (
		listen      string
		token       string
		noTLS       bool
		allowRemote bool
	)

	cmd := &cobra.Command{
		Use:   "web",
		Short: "Serve the browser interface against a running daemon",
		Long: `Serves the WARP web interface, connecting to warpd over its control socket.

The interface is fully capable: it starts and stops capture, solicits, deauthenticates,
hunts, classifies and exports. That is why it is bound to loopback, served over TLS with a
certificate generated at startup, and gated behind an access token printed below.

Reach it over an SSH port-forward or the engagement's WireGuard tunnel rather than exposing
the port. Nothing here bypasses the scope gate: a refusal over HTTP is the same refusal the
console gets.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := dial()
			if err != nil {
				return err
			}
			defer c.Close()

			d := newSocketDispatcher(c)
			defer d.stop()

			srv, err := web.New(web.Config{
				Addr:        listen,
				Token:       token,
				TLS:         !noTLS,
				AllowRemote: allowRemote,
				Dispatcher:  d,
				Log:         logger(),
			})
			if err != nil {
				return err
			}
			if err := srv.Listen(); err != nil {
				return err
			}

			fprintf(cmd.ErrOrStderr(),
				"\nweb interface:  %s\naccess token:   %s\n\n"+
					"The link above logs in on its own. The token is new for this run;\n"+
					"stop this command to invalidate it.\n",
				srv.URL(), srv.Token())

			// Write the URL, token and address to web-access.txt in the current directory, so they
			// are retrievable without watching this console. 0600: whoever can read it can drive the
			// interface, which transmits.
			access := fmt.Sprintf("web interface:  %s\naccess token:   %s\nlisten address: %s\n",
				srv.URL(), srv.Token(), srv.Addr())
			if err := os.WriteFile(webAccessFile, []byte(access), 0o600); err != nil {
				fprintf(cmd.ErrOrStderr(), "warning: could not write %s: %v\n", webAccessFile, err)
			} else {
				fprintf(cmd.ErrOrStderr(), "Also written to ./%s (0600).\n\n", webAccessFile)
			}
			if !noTLS {
				fprintf(cmd.ErrOrStderr(),
					"The certificate is self-signed and generated at startup, so the browser will\n"+
						"warn once. Nothing on this box identifies itself with a real certificate.\n\n")
			}

			return srv.Serve(cmd.Context())
		},
	}

	cmd.Flags().StringVar(&listen, "listen", web.DefaultAddr, "address to serve on")
	cmd.Flags().StringVar(&token, "token", "", "access token (default: generated and printed at startup)")
	cmd.Flags().BoolVar(&noTLS, "no-tls", false,
		"serve over plain HTTP (only sane behind an SSH port-forward)")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote", false,
		"allow binding a non-loopback address - this interface can transmit, so this is deliberate")
	return cmd
}

// socketDispatcher adapts an RPC client to the interface the web server expects.
//
// The daemon's own Server can be dispatched against directly; over a socket it takes this
// thin shim. Either way the web server is talking to the same handlers, which is what keeps
// the console, the subcommands and the browser from drifting apart.
type socketDispatcher struct {
	c *rpc.Client

	mu     sync.Mutex
	subs   map[chan rpc.Event]struct{}
	recent []rpc.Event
	closed bool
	done   chan struct{}
}

func newSocketDispatcher(c *rpc.Client) *socketDispatcher {
	d := &socketDispatcher{
		c:    c,
		subs: make(map[chan rpc.Event]struct{}),
		done: make(chan struct{}),
	}
	go d.fanOut()
	return d
}

func (d *socketDispatcher) Dispatch(ctx context.Context, method string, params json.RawMessage) (json.RawMessage, error) {
	var p any
	if len(params) > 0 {
		p = params
	}
	var out json.RawMessage
	if err := d.c.Call(ctx, method, p, &out); err != nil {
		// A *rpc.Error passes through unwrapped so the web server can map its code onto an
		// HTTP status - a scope refusal has to arrive at the browser as a refusal.
		return nil, err
	}
	return out, nil
}

// SubscribeWithRecent registers a browser stream and returns the events seen since this `warp web`
// process started, so a tab that connects during a quiet stretch still shows the log so far. (A
// standalone `warp web` cannot replay events from before it attached; the embedded daemon can.)
func (d *socketDispatcher) SubscribeWithRecent(buffer int) ([]rpc.Event, <-chan rpc.Event, func()) {
	if buffer <= 0 {
		buffer = 256
	}
	ch := make(chan rpc.Event, buffer)

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		close(ch)
		return nil, ch, func() {}
	}
	d.subs[ch] = struct{}{}
	recent := append([]rpc.Event(nil), d.recent...)
	d.mu.Unlock()

	var once sync.Once
	return recent, ch, func() {
		once.Do(func() {
			d.mu.Lock()
			if _, ok := d.subs[ch]; ok {
				delete(d.subs, ch)
				close(ch)
			}
			d.mu.Unlock()
		})
	}
}

// fanOut copies the single client event channel to every browser tab.
//
// A subscriber that has fallen behind loses events rather than stalling the others: a tab
// left open on a sleeping laptop must not hold up the operator watching the live one.
func (d *socketDispatcher) fanOut() {
	defer close(d.done)

	for ev := range d.c.Events() {
		d.mu.Lock()
		d.recent = append(d.recent, ev)
		if len(d.recent) > 256 {
			d.recent = d.recent[len(d.recent)-256:]
		}
		for ch := range d.subs {
			select {
			case ch <- ev:
			default:
			}
		}
		d.mu.Unlock()
	}

	// The daemon went away. Close every stream so the browser's EventSource reconnects
	// instead of sitting silently on a dead socket.
	d.mu.Lock()
	d.closed = true
	for ch := range d.subs {
		delete(d.subs, ch)
		close(ch)
	}
	d.mu.Unlock()
}

func (d *socketDispatcher) stop() {
	d.c.Close()
	<-d.done
}
