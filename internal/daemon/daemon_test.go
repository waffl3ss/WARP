package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/store"
	"github.com/waffl3ss/warp/internal/web"
	"github.com/waffl3ss/warp/internal/workspace"
)

// This is the Phase 1 spine end to end: an engagement directory, a radio scheduler, the scope
// gate and the RPC surface, exercised through a real client over a real socket. It uses
// synthetic adapters because the development machine has no radios; the nl80211 layer beneath
// it is validated separately against real hardware (see the hw-probe skill).

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func fakeDevice(id string, index uint32, iftypes []nl80211.Iftype, inj radio.InjectionStatus) *radio.Device {
	return &radio.Device{
		ID:      id,
		Ifname:  "if-" + id,
		Ifindex: index + 1,
		Driver:  "testdrv",
		Phy: &nl80211.Wiphy{
			Index:            index,
			Name:             id,
			SupportedIftypes: iftypes,
			Combinations: []nl80211.IfaceCombination{{
				Limits:        []nl80211.IfaceLimit{{Max: 1, Types: iftypes}},
				MaxInterfaces: 1,
				NumChannels:   1,
			}},
			Bands: []nl80211.BandInfo{{
				Band:  nl80211.Band2GHz,
				Name:  nl80211.Band2GHz.String(),
				Freqs: []nl80211.Frequency{{MHz: 2412, Channel: 1}, {MHz: 2437, Channel: 6}},
			}},
		},
		Injection: inj,
	}
}

// startDaemon brings up a full daemon over a temp workspace and returns a connected client.
func startDaemon(t *testing.T, essids ...string) (*Daemon, *rpc.Client) {
	t.Helper()
	return startDaemonCfg(t, nil, essids...)
}

// startDaemonCfg is startDaemon with the web interface optionally wired in.
func startDaemonCfg(t *testing.T, webCfg *web.Config, essids ...string) (*Daemon, *rpc.Client) {
	t.Helper()

	// Keep the socket path short: Unix sockets are limited to ~108 bytes and t.TempDir()
	// under a long test name overruns it.
	tmp, err := os.MkdirTemp("", "warpd")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	scopePath := filepath.Join(tmp, "scope.txt")
	var content string
	for _, e := range essids {
		content += e + "\n"
	}
	if err := os.WriteFile(scopePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write scope: %v", err)
	}

	ws, _, err := workspace.Init(filepath.Join(tmp, "engagement"), scopePath)
	if err != nil {
		t.Fatalf("workspace.Init: %v", err)
	}
	t.Cleanup(func() { ws.Close() })

	monitorOnly := []nl80211.Iftype{nl80211.IftypeStation, nl80211.IftypeMonitor}
	withAP := []nl80211.Iftype{nl80211.IftypeStation, nl80211.IftypeMonitor, nl80211.IftypeAP}
	sched, err := radio.NewScheduler([]*radio.Device{
		fakeDevice("phy0", 0, monitorOnly, radio.InjectionVerified),
		fakeDevice("phy1", 1, withAP, radio.InjectionUnverified),
	}, quietLogger())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	db, err := store.Open(filepath.Join(tmp, "warp.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	d, err := New(Deps{
		Workspace: ws,
		Scheduler: sched,
		Store:     db,
		Acquirer:  &stubAcquirer{},
		Log:       quietLogger(),
		Web:       webCfg,
	})
	if err != nil {
		t.Fatalf("daemon.New: %v", err)
	}

	sock := filepath.Join(tmp, "warp.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx, sock) }()
	t.Cleanup(func() { cancel(); <-done })

	// Wait for the listener rather than sleeping a fixed interval.
	var c *rpc.Client
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err = rpc.Dial(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c == nil {
		t.Fatalf("daemon never started listening: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	return d, c
}

func TestDaemonStatus(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI", "CORP-IOT")

	var st StatusResult
	if err := c.Call(context.Background(), "status", nil, &st); err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.ScopeESSIDs != 2 {
		t.Errorf("ScopeESSIDs = %d, want 2", st.ScopeESSIDs)
	}
	if st.Radios != 2 {
		t.Errorf("Radios = %d, want 2", st.Radios)
	}
	if len(st.PendingAcks) != 0 {
		t.Errorf("unexpected pending acknowledgments: %v", st.PendingAcks)
	}
}

func TestDaemonReportsPendingAcknowledgments(t *testing.T) {
	_, c := startDaemon(t, "Guest", "CORP-WIFI")

	var st StatusResult
	if err := c.Call(context.Background(), "status", nil, &st); err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(st.PendingAcks) != 1 || st.PendingAcks[0] != "Guest" {
		t.Fatalf("PendingAcks = %v, want [Guest]", st.PendingAcks)
	}

	// Acknowledging over RPC clears it — a shipped box can be set up remotely.
	var ack struct {
		ESSID   string   `json:"essid"`
		Pending []string `json:"pending"`
	}
	if err := c.Call(context.Background(), "scope.acknowledge", map[string]string{
		"essid": "Guest", "operator": "tester",
	}, &ack); err != nil {
		t.Fatalf("scope.acknowledge: %v", err)
	}
	if len(ack.Pending) != 0 {
		t.Errorf("Pending = %v after acknowledgment, want empty", ack.Pending)
	}
}

func TestRadiosListReportsCapabilitiesAndRefusalReasons(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI")

	var radios []RadioInfo
	if err := c.Call(context.Background(), "radios.list", nil, &radios); err != nil {
		t.Fatalf("radios.list: %v", err)
	}
	if len(radios) != 2 {
		t.Fatalf("expected 2 radios, got %d", len(radios))
	}

	byID := map[string]RadioInfo{}
	for _, r := range radios {
		byID[r.ID] = r
	}

	// phy1 has no verified injection, so transmitting roles must be reported unavailable
	// with a reason — not silently omitted.
	phy1 := byID["phy1"]
	var solicit *radio.RoleCapability
	for i := range phy1.Roles {
		if phy1.Roles[i].Role == radio.RoleSolicit {
			solicit = &phy1.Roles[i]
		}
	}
	if solicit == nil {
		t.Fatal("solicit role missing from the capability table")
	}
	if solicit.Capable {
		t.Error("solicit reported capable on an adapter with unverified injection")
	}
	if solicit.Reason == "" {
		t.Error("capability refusal has no reason attached")
	}

	// phy0 has verified injection and monitor mode.
	phy0 := byID["phy0"]
	if phy0.Injection != "verified" {
		t.Errorf("phy0 injection = %q, want verified", phy0.Injection)
	}
}

// TestScopeAnnotationsRoundTrip covers confirm and reject over RPC, and asserts a
// confirmation is recorded as advisory rather than as a precondition.
func TestScopeAnnotationsRoundTrip(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI")
	ctx := context.Background()

	var confirmed map[string]string
	if err := c.Call(ctx, "scope.confirm", map[string]string{
		"bssid": "A4:2B:8C:11:22:33", "essid": "CORP-WIFI", "note": "ceiling, room 214",
	}, &confirmed); err != nil {
		t.Fatalf("scope.confirm: %v", err)
	}
	if confirmed["bssid"] != "a4:2b:8c:11:22:33" {
		t.Errorf("BSSID not normalised: %q", confirmed["bssid"])
	}

	if err := c.Call(ctx, "scope.reject", map[string]string{
		"bssid": "de:ad:be:ef:00:01", "essid": "CORP-WIFI", "note": "neighbouring tenant",
	}, nil); err != nil {
		t.Fatalf("scope.reject: %v", err)
	}

	var listed struct {
		Confirmations map[string]string `json:"confirmations"`
		Rejections    map[string]string `json:"rejections"`
	}
	if err := c.Call(ctx, "scope.list", nil, &listed); err != nil {
		t.Fatalf("scope.list: %v", err)
	}
	if listed.Confirmations["a4:2b:8c:11:22:33"] != "ceiling, room 214" {
		t.Errorf("confirmation not recorded: %+v", listed.Confirmations)
	}
	if listed.Rejections["de:ad:be:ef:00:01"] != "neighbouring tenant" {
		t.Errorf("rejection not recorded: %+v", listed.Rejections)
	}
}

func TestInvalidBSSIDIsRejected(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI")

	err := c.Call(context.Background(), "scope.confirm", map[string]string{"bssid": "not-a-mac"}, nil)
	if err == nil {
		t.Fatal("an invalid BSSID was accepted")
	}
	var rerr *rpc.Error
	if !errors.As(err, &rerr) || rerr.Code != rpc.CodeInvalidParams {
		t.Fatalf("expected CodeInvalidParams, got %v", err)
	}
}

// TestAuditLogRecordsTheEngagement asserts events.jsonl accumulates the evidence chain
// through the RPC surface, not just through direct gate calls.
func TestAuditLogRecordsTheEngagement(t *testing.T) {
	d, c := startDaemon(t, "CORP-WIFI")
	ctx := context.Background()

	if err := c.Call(ctx, "scope.confirm", map[string]string{
		"bssid": "a4:2b:8c:11:22:33", "essid": "CORP-WIFI",
	}, nil); err != nil {
		t.Fatalf("scope.confirm: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(d.ws.Dir, workspace.EventsFile))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	log := string(data)

	for _, want := range []string{"scope_load", "lifecycle", "scope_confirm", "a4:2b:8c:11:22:33"} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log is missing %q:\n%s", want, log)
		}
	}
}

func TestEveryRegisteredMethodIsReachable(t *testing.T) {
	d, c := startDaemon(t, "CORP-WIFI")

	// No functionality is REPL-only: everything the daemon exposes must be callable by a
	// one-shot client too.
	for _, m := range d.srv.Methods() {
		err := c.Call(context.Background(), m, map[string]string{}, nil)
		var rerr *rpc.Error
		if errors.As(err, &rerr) && rerr.Code == rpc.CodeMethodNotFound {
			t.Errorf("registered method %q is not reachable", m)
		}
	}
}

// TestTheWebInterfaceReachesEveryMethod holds the three frontends in step.
//
// The console, the subcommands and the browser are all clients of the same RPC surface. A
// method that exists but is not routed is a capability the web operator silently does not
// have — they would go looking for a button that was never wired, and reach for SSH. This
// fails when a handler is registered without a route, which is the direction that actually
// happens.
func TestTheWebInterfaceReachesEveryMethod(t *testing.T) {
	d, _ := startDaemon(t, "CORP-WIFI")

	routed := map[string]bool{}
	for _, m := range web.Methods() {
		routed[m] = true
	}

	for _, m := range d.srv.Methods() {
		if !routed[m] {
			t.Errorf("RPC method %q has no web route; add it to routeTable in internal/web", m)
		}
	}

	// And the inverse: a route naming a method nobody registered is a dead button.
	registered := map[string]bool{}
	for _, m := range d.srv.Methods() {
		registered[m] = true
	}
	for m := range routed {
		if !registered[m] {
			t.Errorf("web route names %q, which the daemon does not register", m)
		}
	}
}

// TestTheWebInterfaceStartsWithTheDaemon covers the wiring: asking for it must produce a
// server with a token, not a nil field and a silent absence.
func TestTheWebInterfaceStartsWithTheDaemon(t *testing.T) {
	d, _ := startDaemon(t, "CORP-WIFI")
	if d.Web() != nil {
		t.Fatal("the web interface started without being asked for")
	}

	withWeb, _ := startDaemonCfg(t, &web.Config{Addr: "127.0.0.1:0"}, "CORP-WIFI")
	w := withWeb.Web()
	if w == nil {
		t.Fatal("--web produced no server")
	}
	if w.Token() == "" {
		t.Error("the web interface has no access token")
	}
	if !strings.Contains(w.URL(), w.Token()) {
		t.Errorf("the printed URL does not log the operator in: %s", w.URL())
	}
}

// TestPassiveHandshakeCaptureIsNeverScopeGated.
//
// WARP listens for handshakes continuously and records every one it hears, including from
// networks the engagement has no authority over. Two things must both hold and they pull in
// opposite directions:
//
//   - Nothing is discarded. A handshake is heard once; a frame dropped because of a scope
//     check is gone, and the operator never learns it existed.
//   - Nothing incidental reaches the deliverable. Cracking a neighbour's handshake is
//     unauthorized work, and `cat *.22000` must not be able to sweep one up.
//
// This drives the daemon's own capture path rather than the writer in isolation, because the
// scope decision is made there and a future refactor could quietly drop it.
func TestPassiveHandshakeCaptureIsNeverScopeGated(t *testing.T) {
	d, c := startDaemon(t, "CORP-WIFI")

	scoped := handshake.Result{
		Kind: handshake.KindPMKID, ESSID: "CORP-WIFI",
		Line: "WPA*01*1111111111111111111111111111111f*a42b8c112201*deadbeef1001*434f52502d57494649***",
		At:   time.Now(),
	}
	unscoped := handshake.Result{
		Kind: handshake.KindPMKID, ESSID: "NEIGHBOUR-NET",
		Line: "WPA*01*2222222222222222222222222222222f*b42b8c112202*deadbeef1002*4e454947484230***",
		At:   time.Now(),
	}

	d.engine.emitHash(scoped)
	d.engine.emitHash(unscoped)

	var res HashesResult
	if err := c.Call(context.Background(), "hashes.list", nil, &res); err != nil {
		t.Fatalf("hashes.list: %v", err)
	}

	got := map[string]bool{}
	for _, h := range res.Hashes {
		got[h.ESSID] = h.InScope
	}

	if _, ok := got["NEIGHBOUR-NET"]; !ok {
		t.Fatal("an out-of-scope handshake was dropped instead of recorded; " +
			"passive capture must never be gated on scope")
	}
	if got["NEIGHBOUR-NET"] {
		t.Error("an out-of-scope capture is labelled as in scope")
	}
	if _, ok := got["CORP-WIFI"]; !ok {
		t.Fatal("the in-scope handshake was not recorded")
	}
	if !got["CORP-WIFI"] {
		t.Error("an in-scope capture is labelled as incidental")
	}

	// The engagement's counters report the deliverable, not everything overheard.
	if res.PMKID != 1 {
		t.Errorf("PMKID count = %d, want 1 — incidental captures must not inflate the total", res.PMKID)
	}
}

// TestTheRogueAPRefusesAnUnscopedESSID.
//
// CLAUDE.md invariant 3, exercised through the RPC surface an operator actually reaches
// rather than against the gate in isolation. Beaconing a name the SoW never covered
// impersonates someone else's network, and until the enterprise path was wired there was no
// code path to assert it on — the invariant was true only because nothing could reach it.
//
// The refusal must happen before any radio is acquired and before hostapd is configured, so
// this also passes on a machine with no adapters: reaching a hardware error would mean the
// gate was consulted too late.
func TestTheRogueAPRefusesAnUnscopedESSID(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI")
	ctx := context.Background()

	for _, essid := range []string{
		"NEIGHBOUR-NET",   // someone else's network
		"CORP-WIFI-GUEST", // an extension of a scoped name
		"CORP",            // a prefix of one
		"CORP-WIFI ",      // trailing space: a different octet string
		"\u0421ORP-WIFI",  // Cyrillic homoglyph
		"",                // no name at all
	} {
		err := c.Call(ctx, "eap.start", map[string]any{"essid": essid}, nil)
		if err == nil {
			t.Fatalf("the rogue AP was authorized to beacon %q", essid)
		}

		var rerr *rpc.Error
		if !errors.As(err, &rerr) {
			t.Fatalf("%q: got %T, want an RPC error", essid, err)
		}
		// A scope refusal, not a hardware failure. Reaching the radio layer would mean the
		// gate was consulted after something had already been configured.
		if essid != "" && rerr.Code != rpc.CodeScopeDenied {
			t.Errorf("%q: refused with code %d (%s), want a scope denial — the gate must be "+
				"consulted before any radio is touched", essid, rerr.Code, rerr.Message)
		}
	}
}

// TestEnterpriseCaptureIsReachableAndReportsItsState. The capability the dashboard advertises
// has to be invocable: for a long time it was reported available with no command behind it.
func TestEnterpriseCaptureIsReachableAndReportsItsState(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI")
	ctx := context.Background()

	var st EAPStatus
	if err := c.Call(ctx, "eap.status", nil, &st); err != nil {
		t.Fatalf("eap.status: %v", err)
	}
	if st.Running {
		t.Error("a fresh daemon reports an enterprise capture running")
	}
	if st.CredsFile == "" {
		t.Error("status does not say where captured credentials are written")
	}

	// Stopping when nothing is running is a clear refusal, not a panic or a silent success.
	if err := c.Call(ctx, "eap.stop", nil, nil); err == nil {
		t.Error("eap.stop succeeded with nothing running")
	}
}

// TestDeauthenticatingAnAccessPointIsABroadcast.
//
// Naming no station means the operator is acting on the access point, and at that level the
// useful action moves every client rather than one — that is what provokes a handshake. It
// used to be refused outright with "no station given", which made the access point list's
// deauth key do nothing at all.
func TestDeauthenticatingAnAccessPointIsABroadcast(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI")

	// Nothing has been observed, so this fails at the lookup rather than at the parameters —
	// which is the point: it must not be refused for want of a station.
	err := c.Call(context.Background(), "psk.deauth",
		map[string]any{"bssid": "a4:2b:8c:11:22:33"}, nil)
	if err == nil {
		t.Fatal("deauthenticating an unobserved BSSID succeeded")
	}
	if strings.Contains(err.Error(), "no station given") {
		t.Errorf("an access-point-level deauthentication was refused for want of a station: %v", err)
	}
	var rerr *rpc.Error
	if !errors.As(err, &rerr) || rerr.Code != rpc.CodeNotFound {
		t.Errorf("got %v, want a not-found error for an unobserved BSSID", err)
	}
}

// TestScopeOnlyWidensFromWhatWasHeard.
//
// Adding a network to scope by name is how a BSSID list could sneak in through the back door,
// and invariant 1 forbids that: scope names things WARP observed off the air, it does not
// accept them typed in.
func TestScopeOnlyWidensFromWhatWasHeard(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI")
	ctx := context.Background()

	err := c.Call(ctx, "scope.add", map[string]any{"essid": "NEVER-OBSERVED"}, nil)
	if err == nil {
		t.Fatal("a network that was never observed was added to scope")
	}
	var rerr *rpc.Error
	if !errors.As(err, &rerr) || rerr.Code != rpc.CodeNotFound {
		t.Errorf("got %v, want a not-found refusal", err)
	}

	// An empty name is refused too: a hidden network has nothing to authorize.
	if err := c.Call(ctx, "scope.add", map[string]any{"essid": ""}, nil); err == nil {
		t.Error("an empty ESSID was added to scope")
	}
}

// stubAcquirer stands in for real hardware. The daemon tests exercise the RPC surface and the
// wiring, not the radio layer, which is validated against real adapters separately.
type stubAcquirer struct{}

func (stubAcquirer) Acquire(context.Context, *radio.Device, nl80211.Iftype) (*radio.Acquisition, error) {
	return nil, errors.New("stub acquirer: no hardware in tests")
}
func (stubAcquirer) AcquireActiveMonitor(context.Context, *radio.Device, net.HardwareAddr) (*radio.Acquisition, error) {
	return nil, errors.New("stub acquirer: no hardware in tests")
}
func (stubAcquirer) AcquireStation(context.Context, *radio.Device, nl80211.ConnectParams) (*radio.Acquisition, error) {
	return nil, errors.New("stub acquirer: no hardware in tests")
}
func (stubAcquirer) Release(context.Context, *radio.Acquisition) error { return nil }
func (stubAcquirer) SetChannel(context.Context, *radio.Device, int) error {
	return errors.New("stub acquirer: no hardware in tests")
}
func (stubAcquirer) CurrentFreq(context.Context, *radio.Device) (int, error) { return 0, nil }
