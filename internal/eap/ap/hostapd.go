package ap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// eventBuffer bounds the event channel. A slow consumer drops events rather than stalling
// hostapd's output pipe, which would eventually block the subprocess itself.
const eventBuffer = 256

// Hostapd runs hostapd as a managed subprocess.
//
// hostapd handles beaconing, association and EAPOL, and relays every EAP message to WARP's
// RADIUS server untouched. Nothing is patched: this is stock hostapd driven by a generated
// configuration file, which is the whole reason WARP does not carry a forked C tree.
type Hostapd struct {
	// Binary is the hostapd executable. Resolved from PATH when empty.
	Binary string
	// WorkDir is where the generated configuration is written.
	WorkDir string
	Log     *slog.Logger

	mu      sync.Mutex
	cmd     *exec.Cmd
	cfgPath string
	running bool
	cfg     Config

	clients map[string]*Client
	events  chan Event

	done chan struct{}
}

// NewHostapd builds a hostapd-backed controller.
func NewHostapd(workDir string, log *slog.Logger) *Hostapd {
	if log == nil {
		log = slog.Default()
	}
	return &Hostapd{
		WorkDir: workDir,
		Log:     log,
		clients: make(map[string]*Client),
		events:  make(chan Event, eventBuffer),
	}
}

// ErrHostapdMissing is returned when the binary cannot be found.
//
// This is the one external runtime dependency WARP has, so the error names it explicitly
// rather than surfacing a bare exec failure.
var ErrHostapdMissing = errors.New(
	"ap: hostapd not found in PATH - it is WARP's one external runtime dependency " +
		"(apt install hostapd); everything else is built in")

// Start brings the access point up.
func (h *Hostapd) Start(ctx context.Context, cfg Config) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return errors.New("ap: hostapd is already running")
	}
	if cfg.ESSID == "" {
		return errors.New("ap: refusing to start an access point with no ESSID")
	}
	if cfg.Interface == "" {
		return errors.New("ap: no interface given; request one from the radio scheduler")
	}

	binary := h.Binary
	if binary == "" {
		found, err := exec.LookPath("hostapd")
		if err != nil {
			return ErrHostapdMissing
		}
		binary = found
	}

	conf, err := RenderConfig(cfg)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(h.WorkDir, 0o700); err != nil {
		return fmt.Errorf("ap: create work directory: %w", err)
	}
	// 0600: the file contains the RADIUS shared secret.
	path := filepath.Join(h.WorkDir, "hostapd.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		return fmt.Errorf("ap: write hostapd config: %w", err)
	}

	cmd := exec.CommandContext(ctx, binary, path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("ap: attach to hostapd stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("ap: attach to hostapd stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("ap: start hostapd: %w", err)
	}

	h.cmd = cmd
	h.cfgPath = path
	h.cfg = cfg
	h.running = true
	h.done = make(chan struct{})

	go h.readOutput(stdout, "stdout")
	go h.readOutput(stderr, "stderr")
	go h.wait()

	h.emit(Event{Kind: EventStarted, At: time.Now(),
		Text: fmt.Sprintf("hostapd started on %s beaconing %q ch%d",
			cfg.Interface, cfg.ESSID, cfg.Channel)})

	return nil
}

// wait reaps the subprocess.
func (h *Hostapd) wait() {
	err := h.cmd.Wait()

	h.mu.Lock()
	h.running = false
	done := h.done
	h.mu.Unlock()

	text := "hostapd exited"
	if err != nil {
		text = fmt.Sprintf("hostapd exited: %v", err)
	}
	h.emit(Event{Kind: EventStopped, Text: text, At: time.Now()})

	if done != nil {
		close(done)
	}
}

// readOutput parses hostapd's log lines into events.
//
// hostapd's stdout is the only interface it offers without a control socket, and the lines
// worth acting on - a station associating, an EAP exchange starting - are stable across
// versions.
func (h *Hostapd) readOutput(r io.Reader, stream string) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)

	for sc.Scan() {
		line := sc.Text()
		h.Log.Debug("hostapd", "stream", stream, "line", line)

		if ev, ok := parseHostapdLine(line); ok {
			h.applyEvent(ev)
			h.emit(ev)
		}
	}
}

// parseHostapdLine turns a hostapd log line into an event.
func parseHostapdLine(line string) (Event, bool) {
	now := time.Now()

	switch {
	case strings.Contains(line, "AP-STA-CONNECTED"):
		return Event{Kind: EventClientJoin, MAC: lastField(line), Text: line, At: now}, true

	case strings.Contains(line, "AP-STA-DISCONNECTED"):
		return Event{Kind: EventClientLeave, MAC: lastField(line), Text: line, At: now}, true

	case strings.Contains(line, "associated") && strings.Contains(line, "STA"):
		return Event{Kind: EventClientJoin, MAC: extractMAC(line), Text: line, At: now}, true

	case strings.Contains(line, "EAP-Request") || strings.Contains(line, "CTRL-EVENT-EAP-STARTED"):
		return Event{Kind: EventEAPStarted, MAC: extractMAC(line), Text: line, At: now}, true

	case strings.Contains(line, "Could not") ||
		strings.Contains(line, "Failed to") ||
		strings.Contains(line, "error"):
		return Event{Kind: EventError, Text: line, At: now}, true
	}
	return Event{}, false
}

func lastField(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[len(fields)-1]
}

// extractMAC pulls the first colon-separated hardware address out of a log line.
func extractMAC(line string) string {
	for _, f := range strings.Fields(line) {
		if strings.Count(f, ":") == 5 && len(f) == 17 {
			return f
		}
	}
	return ""
}

func (h *Hostapd) applyEvent(ev Event) {
	if ev.MAC == "" {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	switch ev.Kind {
	case EventClientJoin:
		if c, ok := h.clients[ev.MAC]; ok {
			c.LastSeen = ev.At
			return
		}
		h.clients[ev.MAC] = &Client{MAC: ev.MAC, Since: ev.At, LastSeen: ev.At}

	case EventClientLeave:
		delete(h.clients, ev.MAC)

	case EventEAPStarted:
		if c, ok := h.clients[ev.MAC]; ok {
			c.LastSeen = ev.At
		}
	}
}

func (h *Hostapd) emit(ev Event) {
	select {
	case h.events <- ev:
	default:
		// A slow consumer must not block hostapd's output pipe, which would eventually stall
		// the subprocess itself.
	}
}

// Stop tears the access point down.
func (h *Hostapd) Stop(ctx context.Context) error {
	h.mu.Lock()
	if !h.running || h.cmd == nil || h.cmd.Process == nil {
		h.mu.Unlock()
		return nil
	}
	cmd := h.cmd
	done := h.done
	cfgPath := h.cfgPath
	h.mu.Unlock()

	// SIGTERM first: hostapd deauthenticates its clients and restores the interface on a
	// clean shutdown, which SIGKILL skips entirely.
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		h.Log.Debug("could not signal hostapd", "err", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		h.Log.Warn("hostapd did not exit on SIGTERM; killing it")
		cmd.Process.Kill()
		<-done
	case <-ctx.Done():
		cmd.Process.Kill()
	}

	h.mu.Lock()
	h.clients = make(map[string]*Client)
	h.mu.Unlock()

	// The config file holds the RADIUS shared secret; it does not outlive the run.
	if cfgPath != "" {
		os.Remove(cfgPath)
	}
	return nil
}

// Clients returns the currently associated stations.
func (h *Hostapd) Clients() []Client {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]Client, 0, len(h.clients))
	for _, c := range h.clients {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// Events streams what the access point reports.
func (h *Hostapd) Events() <-chan Event { return h.events }

// Running reports whether hostapd is up.
func (h *Hostapd) Running() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.running
}

// Verify that Hostapd satisfies the interface a native nl80211 backend will also satisfy.
var _ APController = (*Hostapd)(nil)
