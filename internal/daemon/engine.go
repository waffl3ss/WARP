package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/waffl3ss/warp/internal/capture"
	"github.com/waffl3ss/warp/internal/eap/harvest"
	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/store"
)

// Engine tuning.
const (
	// observationFlush is how often buffered signal readings are written. Observations are
	// the highest-volume table by far, so they are batched; everything that matters for
	// evidence is written synchronously elsewhere.
	observationFlush = 2 * time.Second

	// observationBuffer bounds the in-memory batch. On a busy channel this fills well before
	// the flush interval.
	observationBuffer = 2048

	// stateFlush is how often tracker state is persisted to the store and the state
	// projections regenerated behind it.
	//
	// The projections used to be written only at shutdown and on an explicit `warp export`,
	// which meant the engagement directory showed an empty bssids.csv while fifty access points
	// sat on screen - and a SIGKILL, a power cut or a box being unplugged left them that way
	// permanently. sqlite still had everything, but the flat files are what an operator reads
	// and what gets archived. A few hundred rows every five seconds costs nothing; the file
	// that genuinely could not be rebuilt on this cadence, observations.csv, is appended live
	// instead (store.ObservationLog).
	stateFlush = 5 * time.Second

	// pcapngFlush is how often the raw archive is pushed to disk.
	pcapngFlush = 5 * time.Second
)

// Engine runs the capture and recon pipeline across every assigned radio.
//
// It owns the flow from radio to disk: a capture source per radio, frames parsed into the
// tracker, handshakes extracted, hashes appended, observations batched to the store, and the
// raw archive written continuously alongside so that a parser bug does not lose an
// engagement's data.
type Engine struct {
	sched     *radio.Scheduler
	acquirer  radio.Acquirer
	store     *store.Store
	tracker   *recon.Tracker
	machine   *handshake.Machine
	hashes    *handshake.Writer
	log       *slog.Logger
	broadcast func(rpc.Event)

	// capturesDir is where each recon session's raw archive is written. pcapng is the archive for
	// the currently running session, or nil when recon is stopped: a fresh timestamped file is
	// opened on Start and closed on Stop, so each start/stop pair is its own capture. It is read on
	// the hot capture path once per frame, so it is an atomic pointer rather than a mutex-guarded
	// field - consume() must never block on the RPC goroutine that rotates it.
	capturesDir string
	pcapng      atomic.Pointer[capture.PcapngWriter]
	// pcapngPath is the path of the current session archive, for writing the netxml snapshot beside
	// it on Stop. Guarded by mu.
	pcapngPath string

	// walkPcap is the raw archive for the currently open walkthrough, or nil when none is open.
	// It is read on the hot capture path once per frame, so it is an atomic pointer rather than a
	// mutex-guarded field: consume() must never block on the RPC goroutine that swaps it.
	walkPcap atomic.Pointer[walkCapture]

	// inScope reports whether an ESSID is in scope. Used only to label and file captured
	// hashes - never to decide whether to capture one, which is passive and ungated.
	inScope func(essid string) bool

	// workspaceDir is where the CSV projections are written.
	workspaceDir string

	// obsLog appends observations.csv as they are captured. The other projections are
	// regenerated wholesale on the state tick; this one is far too large for that.
	obsLog *store.ObservationLog

	// watchers are campaigns waiting for a handshake from a particular access point;
	// essidWatchers are decloaking campaigns waiting for one to be named.
	watchMu       sync.Mutex
	watchers      map[chan handshake.Result]recon.MAC
	essidWatchers map[chan<- string]recon.MAC
	// huntWatchers are direction-finding sessions reading signal readings for one target off a
	// specific radio's frames. A hunt on a borrowed capture radio consumes the engine's existing
	// capture through this rather than opening a second AF_PACKET socket on the same interface -
	// two sockets on one netdev are unreliable on some drivers (mt76 after mode-cycling), which
	// left a hunt seeing no frames while recon on the very same card saw them fine.
	huntWatchers map[chan huntObservation]huntFilter
	// huntWatcherN guards the capture hot path: notifyHunt takes the lock only when a hunt is
	// actually registered, so an ordinary run pays nothing per frame.
	huntWatcherN atomic.Int32
	// eapolWatchers are certificate harvests waiting on 802.1X traffic addressed to the
	// station they associated from.
	eapolWatchers map[chan []byte]recon.MAC
	// mgmtWatchers are association attempts waiting for the access point's answer.
	mgmtWatchers map[chan MgmtReply]recon.MAC

	// certWatchers are passive certificate harvests waiting for a server certificate to be
	// reassembled from any client's EAP-TLS exchange with a particular access point.
	certWatchers map[chan CertObservation]recon.MAC
	// certAssemblers reassemble the server certificate per client exchange, keyed by
	// [bssid, station]. Populated only while a certWatcher for that access point is present, so
	// the map stays bounded - it is not a standing per-network cache.
	certAssemblers map[[2]recon.MAC]*harvest.Assembler

	// onESSID is called whenever a BSSID's network name becomes known. The karma responder
	// test uses it: it probes for a name that cannot exist, so anything that turns up
	// broadcasting that name answered an arbitrary probe.
	onESSID func(bssid recon.MAC, essid string)

	mu       sync.Mutex
	running  bool
	radios   []*radioRunner
	obsBuf   []recon.Observation
	obsMu    sync.Mutex
	surveyID string
	// reconCtx is the context recon was started with, kept so a radio switched on from the
	// radios tab after startup can have a capture runner spun up under the same lifetime.
	reconCtx context.Context
	// chanPolicy holds per-radio channel-management overrides (allowed channels, 5 GHz on/off,
	// random hop) set from the radios tab. Applied when a plan is built and re-applied live to a
	// running radio. Guarded by mu.
	chanPolicy map[string]radio.PlanOptions

	// suspended marks radios a borrow is deliberately reconfiguring (active monitor for WPS),
	// keyed by radio ID. While a radio is here, its capture loop waits for the borrow to finish
	// rather than racing to reopen the socket against a half-configured interface. Guarded by mu.
	suspended map[string]chan struct{}

	stopped chan struct{}
}

// radioRunner is one radio's capture loop and the state it owns.
type radioRunner struct {
	handle  *radio.Handle
	acq     *radio.Acquisition
	plan    *radio.ChannelPlan
	ifaceID uint32
	// role is what this runner is capturing for, so a reconcile after a radio toggle knows which
	// roles are already covered.
	role radio.Role
	// cancel stops this one runner's capture and hop loops without touching the others, so a
	// single adapter can be switched off from the radios tab while the rest keep running. done
	// is closed when runRadio has fully returned, so a disable can wait for a clean stop. rctx is
	// the runner's own context, cancelled by cancel.
	rctx   context.Context
	cancel context.CancelFunc
	done   chan struct{}

	// mu guards source and carried, which the capture goroutine swaps on a reopen while Stats
	// reads them from the RPC goroutine.
	mu sync.Mutex
	// source is the current capture handle. It is replaced when the interface is reopened after a
	// borrow downs it, so it must not be read without the lock.
	source *capture.Source
	// carried accumulates the frame/byte/error counters from every source that has been closed
	// and reopened on this radio. Each reopen creates a fresh Source whose counters start at
	// zero; without carrying the old ones forward, a card's frame count appears to reset to 0
	// every time it is borrowed - which reads as "this radio stopped capturing" when it did not.
	carried capture.Stats
}

// stats returns this radio's cumulative capture counters across every reopen.
func (r *radioRunner) stats() capture.Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return addStats(r.carried, r.source.Stats())
}

// reopened swaps in a fresh source, folding the old source's counters into the carried total so
// the reported frame count keeps climbing across the reopen instead of resetting.
func (r *radioRunner) reopened(old, next *capture.Source) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old != nil {
		r.carried = addStats(r.carried, old.Stats())
	}
	r.source = next
}

// currentSource returns the live source under the lock, for the capture loop.
func (r *radioRunner) currentSource() *capture.Source {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.source
}

// addStats sums two capture stat snapshots.
func addStats(a, b capture.Stats) capture.Stats {
	return capture.Stats{
		Frames:     a.Frames + b.Frames,
		Bytes:      a.Bytes + b.Bytes,
		BadFCS:     a.BadFCS + b.BadFCS,
		ParseError: a.ParseError + b.ParseError,
		Dropped:    a.Dropped + b.Dropped,
	}
}

// EngineOptions wires the engine's collaborators.
type EngineOptions struct {
	Scheduler *radio.Scheduler
	Acquirer  radio.Acquirer
	Store     *store.Store
	Hashes    *handshake.Writer
	Log       *slog.Logger
	Broadcast func(rpc.Event)
	// InScope labels captured hashes. Capture itself is never gated on it.
	InScope func(essid string) bool
	// WorkspaceDir is where the CSV projections are regenerated. Empty disables them.
	WorkspaceDir string
	// CapturesDir is where each recon session's raw pcapng archive is written. Empty disables the
	// raw archive.
	CapturesDir string
}

// NewEngine builds the recon engine.
func NewEngine(o EngineOptions) (*Engine, error) {
	if o.Scheduler == nil || o.Store == nil {
		return nil, errors.New("daemon: engine needs a scheduler and a store")
	}
	if o.Acquirer == nil {
		return nil, errors.New("daemon: engine needs a radio acquirer")
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.InScope == nil {
		// With no scope function every capture is filed as incidental, which is the
		// conservative default: nothing lands in the deliverable unless something said it
		// belonged there.
		o.InScope = func(string) bool { return false }
	}
	if o.Broadcast == nil {
		o.Broadcast = func(rpc.Event) {}
	}

	e := &Engine{
		sched:        o.Scheduler,
		acquirer:     o.Acquirer,
		store:        o.Store,
		hashes:       o.Hashes,
		capturesDir:  o.CapturesDir,
		log:          o.Log,
		broadcast:    o.Broadcast,
		inScope:      o.InScope,
		workspaceDir: o.WorkspaceDir,
		stopped:      make(chan struct{}),
	}
	e.tracker = recon.NewTracker(e.recordObservation)

	// The observation log is opened here rather than lazily on the first flush so that a
	// permissions or disk problem surfaces at startup, where an operator is still watching,
	// instead of silently dropping every observation an hour into a capture.
	if o.WorkspaceDir != "" {
		obsLog, err := store.OpenObservationLog(o.WorkspaceDir)
		if err != nil {
			return nil, err
		}
		e.obsLog = obsLog
	}

	// The handshake machine resolves ESSIDs from the live tracker. A handshake captured on a
	// cloaked network is held rather than discarded: the ESSID is the PBKDF2 salt and cannot
	// be recovered later, but the handshake stays good once the name is learned.
	e.machine = handshake.NewMachine(func(ap [6]byte) (string, bool) {
		rec, ok := e.tracker.AP(recon.MAC(ap))
		if !ok || rec.ESSID == "" {
			return "", false
		}
		return rec.ESSID, true
	}, handshake.Options{})

	return e, nil
}

// Tracker exposes the live picture for RPC queries.
func (e *Engine) Tracker() *recon.Tracker { return e.tracker }

// SetESSIDObserver registers a callback fired when a BSSID's network name becomes known.
func (e *Engine) SetESSIDObserver(fn func(bssid recon.MAC, essid string)) {
	e.mu.Lock()
	e.onESSID = fn
	e.mu.Unlock()
}

func (e *Engine) notifyESSID(bssid recon.MAC, essid string) {
	if essid == "" {
		return
	}
	e.mu.Lock()
	fn := e.onESSID
	e.mu.Unlock()
	if fn != nil {
		fn(bssid, essid)
	}
}

// Running reports whether recon is active.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// SurveyRadioID returns the pinned survey radio, or "" if survey was never acquired.
func (e *Engine) SurveyRadioID() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.surveyID
}

// SurveyRadioName returns the survey radio's interface name (wlanN) for display, or "" if survey
// was never acquired. The phyNNN id is an internal handle and must never reach the operator.
func (e *Engine) SurveyRadioName() string {
	id := e.SurveyRadioID()
	if id == "" {
		return ""
	}
	if dev := e.deviceForID(id); dev != nil && dev.Ifname != "" {
		return dev.Ifname
	}
	return id
}

// Start acquires radios and begins capture.
//
// Roles are requested in priority order and a role that cannot be satisfied is a warning, not
// a failure: a two-radio laptop cannot host every role at once, and refusing to start would
// be worse than starting with what the hardware allows. The exception is recon itself -
// without it there is no engagement.
func (e *Engine) Start(ctx context.Context) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("daemon: recon is already running")
	}
	e.running = true
	e.reconCtx = ctx
	e.mu.Unlock()

	// Open a fresh raw archive for this session. Each recon start/stop is its own timestamped
	// capture, so a run is never appended to a previous one, and each closes with a netxml snapshot
	// beside it. Opened before any role starts, since startRole registers its interface in it.
	e.openArchive()

	// Survey first: it is pinned for the engagement and must get its adapter before anything
	// else competes for one.
	//
	// With a single adapter there is nothing to pin it apart from - survey and recon are the
	// same capture, and RSSI is trivially comparable because there is only one radio. Asking
	// for both would take the only interface for survey and leave recon with nothing, so the
	// one radio serves both and is recorded as the survey radio.
	roles := []radio.Role{radio.RoleSurvey, radio.RoleRecon}
	soleRadio := len(e.sched.Devices()) < radio.RecommendedRadios
	if soleRadio {
		roles = []radio.Role{radio.RoleRecon}
	}

	var started []*radioRunner
	for _, role := range roles {
		runner, err := e.startRole(ctx, role)
		if err != nil {
			if role == radio.RoleRecon && len(started) == 0 {
				e.stopRunners(ctx, started)
				e.closeArchive(ctx)
				e.mu.Lock()
				e.running = false
				e.mu.Unlock()
				return fmt.Errorf("daemon: cannot start recon: %w", err)
			}
			e.log.Warn("role not started", "role", role, "err", err)
			e.broadcast(rpc.Event{
				Kind: "radio", Level: rpc.LevelWarn,
				Text: fmt.Sprintf("[!] role %s unavailable: %v", role, err),
			})
			continue
		}
		started = append(started, runner)

		if role == radio.RoleSurvey || soleRadio {
			e.mu.Lock()
			e.surveyID = runner.handle.Device.ID
			e.mu.Unlock()
		}
	}

	e.mu.Lock()
	e.radios = started
	e.mu.Unlock()

	for _, r := range started {
		go e.runRadio(r.rctx, r)
	}
	go e.flushLoop(ctx)

	text := fmt.Sprintf("[+] recon started on %d radio(s)", len(started))
	if soleRadio {
		text += " - one adapter, so survey shares it and active work pauses capture briefly"
	}
	e.broadcast(rpc.Event{Kind: "recon", Level: rpc.LevelGood, Text: text})
	return nil
}

// HoldChannel parks every capture radio on one frequency and returns a function that releases
// them.
//
// This is what makes active work actually produce a capture. A deauthentication is only half
// the job: the handshake it provokes arrives milliseconds later on the access point's channel,
// and a radio that is still sweeping will be somewhere else when it does. Locking only the
// transmitting radio is not enough either - on a two-adapter kit the transmitter and the
// listener are different cards, and it is the *listener* that has to be on the right channel.
//
// So every capture radio is pinned, not just the one being borrowed. What that costs is
// coverage elsewhere for the length of the burst, which is the correct trade: the operator
// asked for a handshake at this access point.
func (e *Engine) HoldChannel(mhz int) func() {
	e.mu.Lock()
	radios := append([]*radioRunner(nil), e.radios...)
	e.mu.Unlock()

	var released []func()
	for _, r := range radios {
		if !r.plan.Lock(mhz) {
			// This adapter cannot reach that frequency - a 2.4 GHz-only card asked to hold a
			// 5 GHz channel. Leave it sweeping rather than parking it somewhere useless.
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		e.acquirer.SetChannel(ctx, r.handle.Device, mhz)
		cancel()

		plan := r.plan
		released = append(released, func() { plan.Unlock() })
	}

	return func() {
		for _, f := range released {
			f()
		}
	}
}

// HoldingRadios reports which capture radios are parked on a frequency, for the operator's
// benefit: a dashboard that shows a radio "on ch6" while it is really sweeping is lying.
func (e *Engine) HoldingRadios() []string {
	e.mu.Lock()
	defer e.mu.Unlock()

	var out []string
	for _, r := range e.radios {
		if r.plan.Locked() != 0 {
			out = append(out, r.handle.Device.ID)
		}
	}
	return out
}

// PauseHopping stops a radio's channel plan so a borrowed transmit lands on the intended
// channel. It reports whether the radio was actually parked there: false means the adapter's
// channel plan does not include that frequency (a 2.4 GHz-only card asked for a 5 GHz channel, or
// a sweep the operator restricted to a channel subset that excludes it), so the caller can say so
// rather than proceeding as if the radio were locked when it is still sweeping.
//
// Without this a burst would go out mid-hop: the plan would retune the adapter partway through
// a solicitation and the frames would leave on whatever channel came next.
func (e *Engine) PauseHopping(radioID string, mhz int) (resume func(), locked bool) {
	e.mu.Lock()
	radios := append([]*radioRunner(nil), e.radios...)
	e.mu.Unlock()

	for _, r := range radios {
		if r.handle.Device.ID != radioID {
			continue
		}
		if !r.plan.Lock(mhz) {
			return func() {}, false
		}
		// Park the adapter on the target channel now; the hop loop honours the lock from its
		// next iteration.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		e.acquirer.SetChannel(ctx, r.handle.Device, mhz)
		cancel()

		return func() { r.plan.Unlock() }, true
	}
	return func() {}, false
}

// startRole acquires one radio for a role and prepares its capture source.
func (e *Engine) startRole(ctx context.Context, role radio.Role) (*radioRunner, error) {
	handle, err := e.sched.Acquire(ctx, role)
	if err != nil {
		return nil, err
	}

	acq, err := acquireReconciling(ctx, e.sched, e.acquirer, handle.Device, nl80211.IftypeMonitor)
	if err != nil {
		handle.Release()
		return nil, err
	}

	source, err := capture.Open(handle.Device.Ifname, int(handle.Device.Ifindex), handle.Device.ID)
	if err != nil {
		e.acquirer.Release(ctx, acq)
		handle.Release()
		return nil, err
	}

	plan, err := radio.NewChannelPlanForDevice(handle.Device, e.channelPolicyFor(handle.Device.ID))
	if err != nil {
		source.Close()
		e.acquirer.Release(ctx, acq)
		handle.Release()
		return nil, err
	}

	rctx, rcancel := context.WithCancel(ctx)
	runner := &radioRunner{
		handle: handle, acq: acq, source: source, plan: plan, role: role,
		rctx: rctx, cancel: rcancel, done: make(chan struct{}),
	}

	if p := e.pcapng.Load(); p != nil {
		id, err := p.AddInterface(handle.Device.Ifname,
			fmt.Sprintf("%s (%s)", handle.Device.ID, role))
		if err != nil {
			e.log.Warn("could not register capture interface in the archive", "err", err)
		}
		runner.ifaceID = id
	}

	return runner, nil
}

// channelPolicyFor returns the operator's channel-management overrides for an adapter, or the
// zero value (full sweep, ascending) when none is set.
func (e *Engine) channelPolicyFor(id string) radio.PlanOptions {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.chanPolicy[id]
}

// ChannelPolicyFor returns the operator-facing channel policy currently in effect for an adapter.
func (e *Engine) ChannelPolicyFor(id string) ChannelPolicy {
	opts := e.channelPolicyFor(id)
	return ChannelPolicy{
		Channels: opts.OnlyChannels, Disable5GHz: opts.Disable5GHz, Random: opts.Random,
	}
}

// ChannelPolicy is the operator's channel-management choice for one adapter.
type ChannelPolicy struct {
	// Channels restricts the sweep to these IEEE channel numbers; empty means every usable one.
	Channels []int `json:"channels,omitempty"`
	// Disable5GHz drops the 5/6 GHz bands from the sweep.
	Disable5GHz bool `json:"disable_5ghz,omitempty"`
	// Random hops in a shuffled order rather than ascending frequency.
	Random bool `json:"random,omitempty"`
}

// SetChannelPolicy records an adapter's channel-management choice and, if it is currently
// sweeping, reconfigures its live plan so the change takes effect without a restart. Returns the
// resulting usable-channel count, or an error if the selection leaves the adapter nothing to sweep.
func (e *Engine) SetChannelPolicy(id string, pol ChannelPolicy) (int, error) {
	dev := e.deviceForID(id)
	if dev == nil {
		return 0, fmt.Errorf("daemon: no radio %q under management", id)
	}
	opts := radio.PlanOptions{
		OnlyChannels: pol.Channels,
		Disable5GHz:  pol.Disable5GHz,
		Random:       pol.Random,
	}

	// Build a plan with the policy first, so a selection that filters everything out is refused
	// before it is stored - the operator keeps the working sweep rather than a dead one.
	fresh, err := radio.NewChannelPlanForDevice(dev, opts)
	if err != nil {
		return 0, err
	}

	e.mu.Lock()
	if e.chanPolicy == nil {
		e.chanPolicy = make(map[string]radio.PlanOptions)
	}
	e.chanPolicy[id] = opts
	var running *radioRunner
	for _, r := range e.radios {
		if r.handle.Device.ID == id {
			running = r
			break
		}
	}
	e.mu.Unlock()

	if running != nil {
		running.plan.Adopt(fresh)
	}
	return len(fresh.Channels()), nil
}

// deviceForID returns the managed device with this ID, or nil.
func (e *Engine) deviceForID(id string) *radio.Device {
	for _, dev := range e.sched.Devices() {
		if dev.ID == id {
			return dev
		}
	}
	return nil
}

// RestartCapture stops every capture runner and starts them again, so the radios are re-acquired
// from a clean slate and the per-radio frame counters reset. It is what a walkthrough boundary
// runs: the operator wants each walkthrough isolated, with the cards reset between them (this is
// the deliberate revision of invariant 5 - RSSI is comparable *within* a walkthrough, not across
// the reset). A no-op when recon is not running.
func (e *Engine) RestartCapture() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	ctx := e.reconCtx
	runners := append([]*radioRunner(nil), e.radios...)
	e.radios = nil
	e.running = false
	e.surveyID = ""
	e.mu.Unlock()

	for _, r := range runners {
		if r.cancel != nil {
			r.cancel()
		}
		if r.done != nil {
			select {
			case <-r.done:
			case <-time.After(3 * time.Second):
			}
		}
	}
	// Teardown uses a fresh short-lived context: the recon context may already be the one being
	// cancelled, and release must run regardless to restore the interfaces.
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = e.stopRunners(stopCtx, runners)
	cancel()

	if ctx == nil || ctx.Err() != nil {
		return nil
	}
	return e.Start(ctx)
}

// SetRadioEnabled switches an adapter on or off from the radios tab.
//
// Off frees the interface for another tool: any capture runner on it is stopped and the adapter
// released, and it is never assigned again until switched back on. On returns it to the pool and,
// when recon is running and a capture role is now uncovered, spins a runner back up. Disabling the
// survey adapter un-pins survey (in the scheduler), so it can move to another card.
func (e *Engine) SetRadioEnabled(id string, on bool) error {
	if !e.sched.SetEnabled(id, on) {
		return fmt.Errorf("daemon: no radio %q under management", id)
	}
	e.mu.Lock()
	ctx, running := e.reconCtx, e.running
	e.mu.Unlock()
	if running && ctx != nil {
		e.reconcileRadios(ctx)
	}
	if on {
		e.broadcast(rpc.Event{Kind: "radio", Level: rpc.LevelInfo,
			Text: fmt.Sprintf("[*] %s switched on", id)})
	} else {
		e.broadcast(rpc.Event{Kind: "radio", Level: rpc.LevelInfo,
			Text: fmt.Sprintf("[*] %s switched off - released for other use", id)})
	}
	return nil
}

// reconcileRadios brings the running capture runners in line with the enabled adapters: it stops
// runners on adapters that are now off, and starts a runner for any capture role left uncovered on
// a still-enabled adapter. It is idempotent, so both directions of a toggle call the same code.
func (e *Engine) reconcileRadios(ctx context.Context) {
	// Stop runners on adapters that are now disabled.
	e.mu.Lock()
	var keep, stop []*radioRunner
	for _, r := range e.radios {
		if e.sched.IsEnabled(r.handle.Device.ID) {
			keep = append(keep, r)
		} else {
			stop = append(stop, r)
		}
	}
	e.radios = keep
	e.mu.Unlock()

	for _, r := range stop {
		if r.cancel != nil {
			r.cancel()
		}
		if r.done != nil {
			select {
			case <-r.done:
			case <-time.After(3 * time.Second):
			}
		}
		_ = e.stopRunners(ctx, []*radioRunner{r})
	}

	// Start any capture role that is now uncovered on a still-enabled adapter.
	enabled := 0
	for _, dev := range e.sched.Devices() {
		if e.sched.IsEnabled(dev.ID) {
			enabled++
		}
	}
	var want []radio.Role
	switch {
	case enabled >= radio.RecommendedRadios:
		want = []radio.Role{radio.RoleSurvey, radio.RoleRecon}
	case enabled >= 1:
		want = []radio.Role{radio.RoleRecon}
	}

	e.mu.Lock()
	have := map[radio.Role]bool{}
	for _, r := range e.radios {
		have[r.role] = true
	}
	e.mu.Unlock()

	for _, role := range want {
		if have[role] {
			continue
		}
		runner, err := e.startRole(ctx, role)
		if err != nil {
			e.log.Warn("could not bring a role back after a radio toggle", "role", role, "err", err)
			continue
		}
		e.mu.Lock()
		e.radios = append(e.radios, runner)
		e.mu.Unlock()
		go e.runRadio(runner.rctx, runner)
		e.broadcast(rpc.Event{Kind: "radio", Level: rpc.LevelGood,
			Text: fmt.Sprintf("[+] %s now covering %s", runner.handle.Device.ID, role)})
	}

	// Recompute which adapter is survey: an explicit survey runner, or the sole recon radio when
	// there is only one, or none. Keeps the status header and observations' radio_id honest.
	e.mu.Lock()
	e.surveyID = ""
	for _, r := range e.radios {
		if r.role == radio.RoleSurvey {
			e.surveyID = r.handle.Device.ID
		}
	}
	if e.surveyID == "" && enabled <= 1 {
		for _, r := range e.radios {
			if r.role == radio.RoleRecon {
				e.surveyID = r.handle.Device.ID
			}
		}
	}
	e.mu.Unlock()
}

// SuspendCapture marks a radio as being deliberately reconfigured by a borrow, so its capture
// loop waits for the card to be handed back instead of racing to reopen the socket against a
// half-configured interface. Returns a function that ends the suspension.
//
// The active-monitor borrow (WPS) changes the interface's mode and MAC, which downs it and drops
// the capture socket. Without this the reopen loop would succeed against the interface mid-change
// and be torn down again on the next step, thrashing every few hundred milliseconds for the
// length of the job - which is exactly the regression this fixes. Held until after the borrow's
// acquisition is released and the interface restored, so capture resumes on a settled card.
//
// Passive borrows (deauth, decloak, the passive harvest) do not down the interface - they only
// pause hopping - so they neither need nor use this.
func (e *Engine) SuspendCapture(radioID string) func() {
	done := make(chan struct{})
	e.mu.Lock()
	if e.suspended == nil {
		e.suspended = make(map[string]chan struct{})
	}
	e.suspended[radioID] = done
	e.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			e.mu.Lock()
			if e.suspended[radioID] == done {
				delete(e.suspended, radioID)
			}
			e.mu.Unlock()
			close(done)
		})
	}
}

// waitWhileSuspended blocks while radioID is under a SuspendCapture, so the capture loop does not
// reopen while a borrow is still reconfiguring the card.
func (e *Engine) waitWhileSuspended(ctx context.Context, radioID string) {
	for {
		e.mu.Lock()
		done := e.suspended[radioID]
		e.mu.Unlock()
		if done == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-done:
			// Re-check: a second borrow may have started while this one was ending.
		}
	}
}

// runRadio drives one radio's channel plan and capture loop.
//
// The capture is reopened rather than abandoned when it dies. The usual cause is not a real
// failure: an active-monitor borrow (WPS) briefly downs the interface to change its mode and MAC,
// which drops the AF_PACKET socket with "network is down". Before, that killed the capture
// goroutine for the rest of the engagement - so recon went dead the first time anything borrowed
// the card, and deauth, which used to only pause hopping, appeared to break. Now the loop waits
// for the borrow to finish (SuspendCapture) and for the interface to come back, then resumes.
func (e *Engine) runRadio(ctx context.Context, r *radioRunner) {
	if r.done != nil {
		defer close(r.done)
	}
	go e.hopChannels(ctx, r)

	for {
		src := r.currentSource()
		err := src.Run(ctx, func(frame *capture.Frame) error {
			e.consume(frame, r)
			return nil
		})
		if ctx.Err() != nil || err == nil {
			return
		}

		e.log.Warn("capture interrupted; reopening when the interface returns",
			"radio_id", r.handle.Device.ID, "err", err)
		src.Close()

		// If a borrow is deliberately reconfiguring this card, wait for it to finish before
		// reopening - reopening mid-reconfiguration is what caused the capture to thrash.
		e.waitWhileSuspended(ctx, r.handle.Device.ID)

		next, rerr := e.reopenCapture(ctx, r)
		if rerr != nil {
			if ctx.Err() == nil {
				e.log.Error("capture stopped and could not be reopened",
					"radio_id", r.handle.Device.ID, "err", rerr)
				e.broadcast(rpc.Event{
					Kind: "radio", Level: rpc.LevelWarn,
					Text: fmt.Sprintf("[!] capture stopped on %s: %v", r.handle.Device.ID, rerr),
				})
			}
			return
		}
		// Carry the closed source's counters forward so the frame count keeps climbing across the
		// reopen rather than resetting to zero (which read as "this radio stopped capturing").
		r.reopened(src, next)
	}
}

// reopenCapture waits for a downed interface to come back and reopens the capture source on it.
//
// A borrow that reconfigures the card downs it for a second or two; capture.Open fails while it
// is down and succeeds once it is back, so retrying with a short backoff is the whole
// mechanism. Bounded so a genuinely dead adapter - unplugged mid-engagement - does not spin
// forever.
func (e *Engine) reopenCapture(ctx context.Context, r *radioRunner) (*capture.Source, error) {
	const (
		retryEvery = 500 * time.Millisecond
		giveUp     = 30 * time.Second
	)
	deadline := time.Now().Add(giveUp)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryEvery):
		}

		// The interface may have re-enumerated while capture was down (a USB drop on a flaky bus),
		// giving it a new index that the cached one no longer matches - which is exactly the ENODEV
		// "bind: no such device" that used to strand the radio for the whole 30s. Re-resolve it by
		// name each attempt (best-effort; it will simply fail while the interface is still absent) so
		// that as soon as the card comes back, the next Open uses the fresh index.
		if _, rerr := e.sched.ReprobeDeviceByIfname(ctx, r.handle.Device.Ifname); rerr == nil {
			// Device fields (including Ifindex) were refreshed in place on the handle's device.
		}

		src, err := capture.Open(r.handle.Device.Ifname, int(r.handle.Device.Ifindex),
			r.handle.Device.ID)
		if err == nil {
			e.log.Info("capture reopened", "radio_id", r.handle.Device.ID)
			return src, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("interface did not return within %s: %w", giveUp, err)
		}
	}
}

// hopChannels walks the radio's dwell plan.
//
// A handle marked SharedChannel co-exists with another role on the same phy where the
// hardware supports only one channel, so it must follow rather than tune independently -
// retuning would drag the other role's channel out from under it.
func (e *Engine) hopChannels(ctx context.Context, r *radioRunner) {
	if r.handle.SharedChannel {
		return
	}

	for {
		dwell, ok := r.plan.Next()
		if !ok {
			return
		}
		// Re-read the lock immediately before tuning. Next() returns the locked channel while a
		// lock is held, but a lock taken *between* Next() and here (a hunt or pin starting) would
		// otherwise be stomped by this stale pre-lock dwell for a whole dwell period - long enough
		// for a hunt to report "no frames, may be on another channel" on its first read. Honour the
		// lock now so the radio parks at once.
		mhz := dwell.MHz
		if locked := r.plan.Locked(); locked != 0 {
			mhz = locked
		}
		if err := e.acquirer.SetChannel(ctx, r.handle.Device, mhz); err != nil {
			if ctx.Err() != nil {
				return
			}
			e.log.Debug("channel set failed", "radio_id", r.handle.Device.ID,
				"mhz", mhz, "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(dwell.Duration):
		}
	}
}

// walkCapture is the raw archive for one walkthrough: a pcapng writer plus the path it lives at.
// The writer maps interfaces by name internally and is safe for concurrent use, so consume() can
// resolve and write per frame without any extra locking here.
type walkCapture struct {
	w    *capture.PcapngWriter
	path string
}

// StartWalkthroughCapture opens a dedicated raw archive for a walkthrough. Frames are teed into it
// from consume() until StopWalkthroughCapture is called. Safe to call while capture is running.
func (e *Engine) StartWalkthroughCapture(path string) error {
	w, err := capture.NewPcapngWriter(path, "warp walkthrough")
	if err != nil {
		return err
	}
	if old := e.walkPcap.Swap(&walkCapture{w: w, path: path}); old != nil {
		_ = old.w.Close()
	}
	return nil
}

// StopWalkthroughCapture closes the current walkthrough archive and returns how many frames it
// captured and where it lives. A no-op (0, "", nil) when none is open.
func (e *Engine) StopWalkthroughCapture() (frames uint64, path string, err error) {
	wc := e.walkPcap.Swap(nil)
	if wc == nil {
		return 0, "", nil
	}
	frames, _ = wc.w.Stats()
	return frames, wc.path, wc.w.Close()
}

// consume folds one captured frame into every consumer.
func (e *Engine) consume(frame *capture.Frame, r *radioRunner) {
	// The raw archive is written first and unconditionally, before any parsing. A parser bug
	// must not be able to lose an engagement's data.
	if p := e.pcapng.Load(); p != nil {
		if err := p.WriteFrame(r.ifaceID, frame.At, frame.Raw); err != nil {
			e.log.Debug("pcapng write failed", "err", err)
		}
	}

	// Tee into the walkthrough archive when one is open. The interface is registered lazily by
	// name (idempotent), so this works regardless of whether the runner existed before the
	// walkthrough started or was spun up by the boundary reset afterwards.
	if wc := e.walkPcap.Load(); wc != nil {
		if id, err := wc.w.AddInterface(r.handle.Device.Ifname, string(r.role)); err == nil {
			if err := wc.w.WriteFrame(id, frame.At, frame.Raw); err != nil {
				e.log.Debug("walkthrough pcapng write failed", "err", err)
			}
		}
	}

	parsed, err := recon.ParseFrame(frame.Body)
	if err != nil {
		return
	}

	meta := recon.RadiotapMeta{
		RSSI:    frame.Radiotap.SignalDBM,
		HasRSSI: frame.Radiotap.HasSignal,
		Freq:    frame.Radiotap.Freq,
	}
	if frame.Radiotap.Freq != 0 {
		meta.Channel, _ = nl80211.ChannelForFrequencyAuto(frame.Radiotap.Freq)
	}

	for _, ev := range e.tracker.Observe(parsed, meta, frame.RadioID, frame.At) {
		e.broadcastTrackerEvent(ev)
	}

	// Feed any direction-finding session reading this radio - the borrowed-hunt path taps the
	// capture here instead of opening its own socket.
	e.notifyHunt(parsed, frame.RadioID, frame.Radiotap.SignalDBM, frame.Radiotap.HasSignal, frame.At)

	e.consumeEAPOL(parsed, meta, frame)
	e.consumeMgmtReply(parsed)
}

// consumeEAPOL extracts handshake material from a data frame.
func (e *Engine) consumeEAPOL(f *recon.Frame, meta recon.RadiotapMeta, frame *capture.Frame) {
	if f.Type != recon.TypeData || len(f.Body) == 0 {
		return
	}

	payload, err := handshake.ExtractEAPOL(f.Body)
	if err != nil {
		return
	}

	// Before the EAPOL-Key filter: a certificate harvest is carried by EAP-Packet frames,
	// which ParseEAPOLKey rejects by design.
	//
	// The legacy active harvest (WatchEAPOL) is delivered by destination, so it only ever sees
	// traffic addressed to the station it associated from. The passive harvest (feedCert)
	// reassembles the server certificate out of any client's exchange with an access point it is
	// watching - no association, keyed per [bssid, station] so concurrent clients do not
	// corrupt each other's stream.
	if dst, ok := f.Destination(); ok {
		e.notifyEAPOL(dst, payload)
	}
	if bssid, ok := f.BSSID(); ok {
		if sta, ok := f.StationAddr(); ok {
			e.feedCert(bssid, sta, payload)
		}
	}

	key, err := handshake.ParseEAPOLKey(payload)
	if err != nil {
		return
	}

	bssid, ok := f.BSSID()
	if !ok {
		return
	}
	sta, ok := f.StationAddr()
	if !ok {
		return
	}

	for _, res := range e.machine.Consume([6]byte(bssid), [6]byte(sta), key,
		meta.Channel, frame.RadioID, frame.At) {
		e.emitHash(res)
	}
}

// emitHash appends a completed hash and tells the operator.
// WatchESSID reports the moment a BSSID's network name becomes known.
//
// A decloaking campaign uses this to stop as soon as it has the name, rather than continuing
// to knock clients off a network that has already told us what it is called.
func (e *Engine) WatchESSID(ap recon.MAC, out chan<- string) func() {
	e.watchMu.Lock()
	if e.essidWatchers == nil {
		e.essidWatchers = make(map[chan<- string]recon.MAC)
	}
	e.essidWatchers[out] = ap
	e.watchMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			e.watchMu.Lock()
			delete(e.essidWatchers, out)
			e.watchMu.Unlock()
		})
	}
}

// notifyESSIDWatchers wakes anything waiting for this BSSID to be named.
func (e *Engine) notifyESSIDWatchers(bssid recon.MAC, essid string) {
	if essid == "" {
		return
	}
	e.watchMu.Lock()
	defer e.watchMu.Unlock()

	for ch, want := range e.essidWatchers {
		if want != bssid {
			continue
		}
		select {
		case ch <- essid:
		default:
		}
	}
}

// MgmtReply is an access point's answer to an authentication or association request.
type MgmtReply struct {
	// Subtype is recon.SubtypeAuth or recon.SubtypeAssocResp.
	Subtype recon.FrameSubtype
	// Status is the 802.11 status code. Zero is success.
	Status uint16
}

// WatchMgmt delivers authentication and association responses addressed to one station.
//
// Without this an association was transmitted blind: the frames went out, nothing came back
// through any path the daemon could see, and every failure - a refused AKM suite, a busy
// access point, an adapter on the wrong channel, injection not working at all - arrived as the
// same silence. The access point does answer, and it says why in a status code; this is what
// picks that answer up off the capture radio and hands it to the code that asked.
func (e *Engine) WatchMgmt(sta recon.MAC) (<-chan MgmtReply, func()) {
	ch := make(chan MgmtReply, 8)

	e.watchMu.Lock()
	if e.mgmtWatchers == nil {
		e.mgmtWatchers = make(map[chan MgmtReply]recon.MAC)
	}
	e.mgmtWatchers[ch] = sta
	e.watchMu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			e.watchMu.Lock()
			delete(e.mgmtWatchers, ch)
			e.watchMu.Unlock()
			close(ch)
		})
	}
}

// consumeMgmtReply forwards an access point's answer to whoever is associating.
func (e *Engine) consumeMgmtReply(f *recon.Frame) {
	if f.Type != recon.TypeManagement {
		return
	}
	switch f.Subtype {
	case recon.SubtypeAuth, recon.SubtypeAssocResp, recon.SubtypeReassocResp:
	default:
		return
	}

	dst, ok := f.Destination()
	if !ok {
		return
	}
	status, ok := f.StatusCode()
	if !ok {
		return
	}

	e.watchMu.Lock()
	defer e.watchMu.Unlock()

	for ch, want := range e.mgmtWatchers {
		if want != dst {
			continue
		}
		select {
		case ch <- MgmtReply{Subtype: f.Subtype, Status: status}:
		default:
		}
	}
}

// WatchEAPOL delivers 802.1X payloads addressed to one station until stop is called.
//
// The receive half of certificate harvesting. WARP associates from a station of its own and
// the access point answers over EAPOL - but those replies arrive on the capture radio like
// every other frame, not on the socket that sent the association. This is what joins the two
// halves back together.
//
// Only frames *to* the station are delivered, so the peer state machine never sees its own
// transmissions echoed back by a driver that loops them.
func (e *Engine) WatchEAPOL(sta recon.MAC) (<-chan []byte, func()) {
	// Buffered generously: a fragmented certificate chain arrives as a burst, and a peer that
	// is briefly busy assembling one must not lose the next fragment.
	ch := make(chan []byte, 32)

	e.watchMu.Lock()
	if e.eapolWatchers == nil {
		e.eapolWatchers = make(map[chan []byte]recon.MAC)
	}
	e.eapolWatchers[ch] = sta
	e.watchMu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			e.watchMu.Lock()
			delete(e.eapolWatchers, ch)
			e.watchMu.Unlock()
			close(ch)
		})
	}
}

// huntObservation is one signal reading for a hunted target, taken off the engine's capture.
type huntObservation struct {
	signalDBM int8
	hasSignal bool
	at        time.Time
}

// huntFilter selects which frames feed a hunt watcher: frames involving the target, seen on the
// one radio the hunt locked. Restricting to that radio keeps the RSSI comparable - a reading from
// the survey card on a different channel and chipset must never mix into the gradient (invariant 5).
type huntFilter struct {
	addr    recon.MAC
	radioID string
}

// WatchHunt delivers signal readings for a target seen on one radio, until stop is called. It lets
// a hunt on a borrowed capture radio read the engine's existing capture instead of opening a second
// socket on the same interface. The channel dropped a lock rather than never taken is fine here: a
// reading missed is one the walker will see on the next frame.
func (e *Engine) WatchHunt(addr recon.MAC, radioID string) (<-chan huntObservation, func()) {
	// Buffered so a burst of the target's frames does not block the capture path; readings are
	// cheap and losing one under load costs nothing but a slightly staler gradient.
	ch := make(chan huntObservation, 64)

	e.watchMu.Lock()
	if e.huntWatchers == nil {
		e.huntWatchers = make(map[chan huntObservation]huntFilter)
	}
	e.huntWatchers[ch] = huntFilter{addr: addr, radioID: radioID}
	e.watchMu.Unlock()
	e.huntWatcherN.Add(1)

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			e.watchMu.Lock()
			delete(e.huntWatchers, ch)
			e.watchMu.Unlock()
			e.huntWatcherN.Add(-1)
			close(ch)
		})
	}
}

// notifyHunt feeds a parsed frame's signal reading to any hunt watching that target on this radio.
// Called from the capture hot path, so it does nothing at all when no hunt is registered.
func (e *Engine) notifyHunt(f *recon.Frame, radioID string, signalDBM int8, hasSignal bool, at time.Time) {
	if e.huntWatcherN.Load() == 0 {
		return
	}
	e.watchMu.Lock()
	defer e.watchMu.Unlock()

	for ch, filt := range e.huntWatchers {
		if filt.radioID != radioID || !frameInvolves(f, filt.addr) {
			continue
		}
		select {
		case ch <- huntObservation{signalDBM: signalDBM, hasSignal: hasSignal, at: at}:
		default:
			// A hunt briefly behind on reads drops this sample rather than stalling capture.
		}
	}
}

// notifyEAPOL delivers an 802.1X payload to anything harvesting at that station.
func (e *Engine) notifyEAPOL(dst recon.MAC, payload []byte) {
	e.watchMu.Lock()
	defer e.watchMu.Unlock()

	for ch, want := range e.eapolWatchers {
		if want != dst {
			continue
		}
		// Copied: payload points into the capture buffer, which is reused for the next frame.
		out := make([]byte, len(payload))
		copy(out, payload)
		select {
		case ch <- out:
		default:
			// A harvest that has stopped reading is skipped rather than stalling the capture
			// path. Losing a fragment fails that one harvest; blocking here would stop
			// recording the entire engagement.
		}
	}
}

// CertObservation is a server certificate chain reassembled passively from a client's EAP-TLS
// exchange with an access point.
type CertObservation struct {
	// BSSID is the access point whose RADIUS server presented the certificate.
	BSSID recon.MAC
	// STA is the client whose authentication carried it - the exchange WARP overheard, never
	// one it associated. Reported so the operator can see whose traffic yielded the certificate.
	STA recon.MAC
	// DERs is the certificate chain, leaf first, exactly as it arrived on the wire.
	DERs [][]byte
}

// WatchCert delivers a server certificate the moment one is reassembled from any client's
// EAP-TLS exchange with the given access point, until stop is called.
//
// This is the passive certificate harvest: it reads the certificate a RADIUS server presents in
// the clear, out of an authentication WARP merely overhears. It associates nothing and injects
// nothing - a broadcast deauthentication provokes a client to reconnect, and the certificate
// arrives on that reconnect like any other frame on the capture radio. The assembler for this
// access point is created here and torn down on stop, so nothing accumulates when no harvest is
// running.
func (e *Engine) WatchCert(bssid recon.MAC) (<-chan CertObservation, func()) {
	ch := make(chan CertObservation, 4)

	e.watchMu.Lock()
	if e.certWatchers == nil {
		e.certWatchers = make(map[chan CertObservation]recon.MAC)
	}
	e.certWatchers[ch] = bssid
	e.watchMu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			e.watchMu.Lock()
			delete(e.certWatchers, ch)
			// Drop any assemblers for this access point once nothing is watching it, so a busy
			// enterprise network does not leave half-built streams behind after the job ends.
			if len(e.certWatchers) == 0 {
				e.certAssemblers = nil
			} else {
				for key := range e.certAssemblers {
					if key[0] == bssid {
						delete(e.certAssemblers, key)
					}
				}
			}
			e.watchMu.Unlock()
			close(ch)
		})
	}
}

// feedCert assembles the server certificate from an EAP-TLS fragment and notifies any harvest
// watching this access point when the chain completes.
//
// It runs only while a certWatcher for the BSSID is present: without one there is nobody to
// receive the certificate and no reason to spend memory reassembling it. The assembler is keyed
// per client exchange so two clients authenticating at once do not corrupt each other's stream.
func (e *Engine) feedCert(bssid, sta recon.MAC, payload []byte) {
	e.watchMu.Lock()
	watching := false
	for _, want := range e.certWatchers {
		if want == bssid {
			watching = true
			break
		}
	}
	if !watching {
		e.watchMu.Unlock()
		return
	}

	eap, ok := harvest.EAPFromEAPOL(payload)
	if !ok {
		e.watchMu.Unlock()
		return
	}

	key := [2]recon.MAC{bssid, sta}
	if e.certAssemblers == nil {
		e.certAssemblers = make(map[[2]recon.MAC]*harvest.Assembler)
	}
	a := e.certAssemblers[key]
	if a == nil {
		a = &harvest.Assembler{}
		e.certAssemblers[key] = a
	}
	ders, done := a.Feed(eap)
	if done {
		delete(e.certAssemblers, key)
	}
	e.watchMu.Unlock()

	if !done {
		return
	}
	e.notifyCert(CertObservation{BSSID: bssid, STA: sta, DERs: ders})
}

// notifyCert wakes any harvest waiting for a certificate from this access point.
func (e *Engine) notifyCert(obs CertObservation) {
	e.watchMu.Lock()
	defer e.watchMu.Unlock()

	for ch, want := range e.certWatchers {
		if want != obs.BSSID {
			continue
		}
		select {
		case ch <- obs:
		default:
			// A harvest that has already finished is skipped rather than stalling the capture
			// path - the same rule as every other watcher.
		}
	}
}

// SubmitEAPOLKey folds an EAPOL-Key frame read off a station association's control port into the
// same handshake machine passive captures use, emitting any PMKID (or four-way handshake) it
// completes exactly as an overheard frame would - deduplicated, filed by scope, written to the hash
// file and recorded in the store.
//
// This is the reception half of PMKID solicitation. Rather than injecting an association in active
// monitor and hoping to overhear the M1 the access point sends back - the path whose replies a
// non-ACKing driver never delivers - WARP associates with a real kernel connection (withStation)
// and the access point's M1 arrives on the control port. Feeding it here means a solicited PMKID
// and an overheard one travel identical code from the frame onward. It returns the completed
// results (empty if the frame was not an M1, or carried no PMKID) so the caller can tell whether
// the solicitation succeeded.
func (e *Engine) SubmitEAPOLKey(bssid, sta recon.MAC, payload []byte, channel int, radioID string, at time.Time) []handshake.Result {
	key, err := handshake.ParseEAPOLKey(payload)
	if err != nil {
		return nil
	}
	results := e.machine.Consume([6]byte(bssid), [6]byte(sta), key, channel, radioID, at)
	for _, res := range results {
		e.emitHash(res)
	}
	return results
}

// WatchHandshakes reports completed captures for one access point until stop is called.
//
// A deauthentication campaign uses this to finish the moment it has what it came for, rather
// than transmitting for the full window at a network that already gave up a handshake. Every
// extra burst after that is airtime at a client site for nothing.
func (e *Engine) WatchHandshakes(ap recon.MAC) (<-chan handshake.Result, func()) {
	ch := make(chan handshake.Result, 4)

	e.watchMu.Lock()
	if e.watchers == nil {
		e.watchers = make(map[chan handshake.Result]recon.MAC)
	}
	e.watchers[ch] = ap
	e.watchMu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			e.watchMu.Lock()
			delete(e.watchers, ch)
			e.watchMu.Unlock()
			close(ch)
		})
	}
}

// notifyHandshake wakes anything waiting on a capture from this access point.
//
// A watcher that has stopped reading is skipped rather than blocking: the capture path must
// never stall behind a consumer, and a campaign that has already finished does not care.
func (e *Engine) notifyHandshake(res handshake.Result) {
	e.watchMu.Lock()
	defer e.watchMu.Unlock()

	for ch, want := range e.watchers {
		if want != recon.MAC(res.AP) {
			continue
		}
		select {
		case ch <- res:
		default:
		}
	}
}

func (e *Engine) emitHash(res handshake.Result) {
	// Capture is passive and is never gated on scope: a handshake heard from a neighbour's
	// network is evidence WARP already has, and throwing it away silently would be worse than
	// keeping it. What scope decides is where it goes - out-of-scope material is written to
	// its own file so it cannot end up in a job on the cracking rig, which would be
	// unauthorized work on someone else's credentials.
	res.InScope = res.ESSID != "" && e.inScope != nil && e.inScope(res.ESSID)

	if e.hashes != nil {
		fresh, err := e.hashes.Write(res)
		if err != nil {
			e.log.Error("hash write failed", "err", err)
			return
		}
		if !fresh {
			// Already have this exact hash. Normal on a long run.
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.store.AddHash(ctx, res); err != nil {
		e.log.Error("hash record failed", "err", err)
	}

	file := "pmkid.22000"
	label := "PMKID"
	if res.Kind == handshake.KindHandshake {
		// "handshake", not "EAPOL". EAPOL is the frame type it arrived in and is hashcat's own
		// name for mode 22000, but it also names the transport WPA-Enterprise carries EAP
		// over, so it reads as enterprise capture and invites the wrong conclusion.
		file, label = "handshakes.22000", "HANDSHAKE"
	}

	// An out-of-scope capture is announced as one, on the same line, so it is impossible to
	// read the log and think it belongs in the deliverable.
	level, scopeNote := rpc.LevelGood, ""
	if !res.InScope {
		level = rpc.LevelWarn
		file = "out-of-scope-" + file
		scopeNote = "  [OUT OF SCOPE - incidental capture, not part of the deliverable]"
	}

	// A PMKID or four-way handshake from a WPA-Enterprise (802.1X) network is real evidence and
	// is kept, but its pairwise key is derived from the RADIUS exchange, not a passphrase - no
	// hashcat 22000 wordlist can recover anything from it. So it is never announced as a win:
	// drop it to an informational line (no tray toast) and say plainly it is not crackable, so
	// nobody transfers it to the cracking rig expecting a result. The enterprise credential
	// worth having is the MSCHAPv2 exchange from the evil-twin RADIUS server (mode 5500).
	enterprise := false
	if e.tracker != nil {
		if rec, ok := e.tracker.AP(recon.MAC(res.AP)); ok {
			switch rec.Security.Class {
			case recon.SecWPAEnterprise, recon.SecWPA3Ent192:
				enterprise = true
			}
		}
	}
	if enterprise {
		if level == rpc.LevelGood {
			level = rpc.LevelInfo
		}
		scopeNote += "  [802.1X - not crackable, kept as evidence]"
	}

	e.notifyHandshake(res)

	e.broadcast(rpc.Event{
		Kind:  string(res.Kind),
		Level: level,
		Text: fmt.Sprintf("[+] %-5s %-20s %s  ch%-3d → %s%s",
			label, displayESSID(res.ESSID), res.APString(), res.Channel, file, scopeNote),
		Fields: map[string]any{
			"essid": res.ESSID, "bssid": res.APString(), "sta": res.STAString(),
			"channel": res.Channel, "radio_id": res.RadioID, "detail": res.Detail,
			"in_scope": res.InScope, "file": file, "enterprise": enterprise,
		},
	})
}

func (e *Engine) broadcastTrackerEvent(ev recon.Event) {
	switch ev.Kind {
	case recon.EventNewAP:
		e.notifyESSID(ev.BSSID, ev.ESSID)
		text := fmt.Sprintf("[+] AP    %-20s %s  ch%-3d %4d dBm  %s",
			displayESSID(ev.ESSID), ev.BSSID, ev.Channel, ev.RSSI, ev.Detail)
		e.broadcast(rpc.Event{
			Kind: "bssid", Level: rpc.LevelInfo, Text: text,
			Fields: map[string]any{
				"bssid": ev.BSSID.String(), "essid": ev.ESSID, "channel": ev.Channel,
			},
		})

	case recon.EventESSIDRevealed:
		e.notifyESSID(ev.BSSID, ev.ESSID)
		e.notifyESSIDWatchers(ev.BSSID, ev.ESSID)
		e.broadcast(rpc.Event{
			Kind: "essid", Level: rpc.LevelGood,
			Text:   fmt.Sprintf("[+] ESSID %-20s %s  (%s)", ev.ESSID, ev.BSSID, ev.Detail),
			Fields: map[string]any{"bssid": ev.BSSID.String(), "essid": ev.ESSID},
		})
		// A newly revealed name may unlock handshakes captured before it was known.
		for _, res := range e.machine.ResolvePending() {
			e.emitHash(res)
		}
	}
}

// bandLabel summarises which bands an adapter can use, compactly enough for a status line.
func bandLabel(dev *radio.Device) string {
	var has24, has5, has6 bool
	for _, b := range dev.Bands() {
		switch {
		case strings.HasPrefix(b, "2.4"):
			has24 = true
		case strings.HasPrefix(b, "5"):
			has5 = true
		case strings.HasPrefix(b, "6"):
			has6 = true
		}
	}
	var parts []string
	if has24 {
		parts = append(parts, "2.4")
	}
	if has5 {
		parts = append(parts, "5")
	}
	if has6 {
		parts = append(parts, "6")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "/") + "GHz"
}

func displayESSID(s string) string {
	if s == "" {
		return "<hidden>"
	}
	return s
}

// recordObservation buffers a signal reading.
func (e *Engine) recordObservation(o recon.Observation) {
	e.obsMu.Lock()
	e.obsBuf = append(e.obsBuf, o)
	full := len(e.obsBuf) >= observationBuffer
	e.obsMu.Unlock()

	if full {
		e.flushObservations()
	}
}

func (e *Engine) flushObservations() {
	e.obsMu.Lock()
	if len(e.obsBuf) == 0 {
		e.obsMu.Unlock()
		return
	}
	batch := e.obsBuf
	e.obsBuf = make([]recon.Observation, 0, observationBuffer)
	e.obsMu.Unlock()

	// The flat file first, then the database. If sqlite is wedged - a full disk, a locked
	// file, a corrupt page - the operator still ends up with the readings on disk in the
	// format they can actually read, which is the outcome that matters at 2am in a wiring
	// closet. The reverse ordering would lose them to the same failure.
	if err := e.obsLog.Append(batch); err != nil {
		e.log.Error("observation log append failed", "count", len(batch), "err", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := e.store.AddObservations(ctx, batch); err != nil {
		e.log.Error("observation flush failed", "count", len(batch), "err", err)
	}
}

// flushLoop periodically persists tracker state, observations and the raw archive.
func (e *Engine) flushLoop(ctx context.Context) {
	obs := time.NewTicker(observationFlush)
	state := time.NewTicker(stateFlush)
	arch := time.NewTicker(pcapngFlush)
	defer obs.Stop()
	defer state.Stop()
	defer arch.Stop()

	for {
		select {
		case <-ctx.Done():
			// A final flush on the way out: everything buffered is still recoverable here,
			// and this is the last chance.
			e.flushObservations()
			e.persistState()
			e.exportProjections()
			if p := e.pcapng.Load(); p != nil {
				p.Flush()
			}
			return

		case <-obs.C:
			e.flushObservations()

		case <-state.C:
			e.persistState()
			// Immediately after, and never on a ticker of its own: exporting before the
			// tracker's current picture has reached the database projects stale rows, and two
			// independent tickers would drift into doing exactly that.
			e.exportProjections()
			e.machine.Expire(time.Now())

		case <-arch.C:
			if p := e.pcapng.Load(); p != nil {
				if err := p.Flush(); err != nil {
					e.log.Error("pcapng flush failed", "err", err)
				}
			}
		}
	}
}

// exportProjections regenerates the flat-file CSVs from the database.
//
// Ordered after persistState in the shutdown path deliberately: exporting before the tracker's
// current picture has been written would produce projections of stale rows.
func (e *Engine) exportProjections() {
	if e.workspaceDir == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := e.store.ExportCSV(ctx, e.workspaceDir); err != nil {
		if errors.Is(err, store.ErrClosed) {
			return
		}
		e.log.Error("projection export failed", "err", err)
	}
}

// persistState writes the tracker's current picture to the store.
//
// A store closed underneath a final flush (the shutdown race) is reported once and abandoned, not
// logged per row: a few hundred "store: closed" lines for a database that is simply gone is noise
// that buries whatever actually went wrong.
func (e *Engine) persistState() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, ap := range e.tracker.APs() {
		if err := e.store.UpsertAP(ctx, ap); err != nil {
			if errors.Is(err, store.ErrClosed) {
				return
			}
			e.log.Error("ap upsert failed", "bssid", ap.BSSID, "err", err)
		}
	}
	for _, st := range e.tracker.Stations() {
		if err := e.store.UpsertStation(ctx, st); err != nil {
			if errors.Is(err, store.ErrClosed) {
				return
			}
			e.log.Error("station upsert failed", "mac", st.MAC, "err", err)
		}
	}
}

// PrioritiseScopedChannels concentrates dwell time on the channels hosting scoped ESSIDs.
//
// Called as the picture of where scoped networks live changes during an engagement. A uniform
// sweep spends as long on an empty channel as on the one the client's APs are actually using,
// which is how a survey misses a handshake it was sitting next to.
func (e *Engine) PrioritiseScopedChannels(scoped map[string]bool) {
	freqs := map[int]struct{}{}
	for _, ap := range e.tracker.APs() {
		if ap.Freq != 0 && scoped[ap.ESSID] {
			freqs[ap.Freq] = struct{}{}
		}
	}
	list := make([]int, 0, len(freqs))
	for f := range freqs {
		list = append(list, f)
	}

	e.mu.Lock()
	radios := append([]*radioRunner(nil), e.radios...)
	e.mu.Unlock()

	for _, r := range radios {
		r.plan.PrioritiseChannels(list)
	}
}

// Stop tears down capture and restores every radio.
func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = false
	runners := e.radios
	e.radios = nil
	e.mu.Unlock()

	e.flushObservations()
	e.persistState()
	e.exportProjections()

	err := e.stopRunners(ctx, runners)
	// Close this session's archive after the runners have stopped writing to it, and drop a netxml
	// snapshot beside it.
	e.closeArchive(ctx)
	return err
}

// openArchive opens a fresh timestamped pcapng for the recon session that is starting.
func (e *Engine) openArchive() {
	if e.capturesDir == "" {
		return
	}
	name := fmt.Sprintf("capture-%s.pcapng", time.Now().UTC().Format("20060102-150405"))
	path := filepath.Join(e.capturesDir, name)
	w, err := capture.NewPcapngWriter(path, "warp")
	if err != nil {
		e.log.Error("could not open the capture archive", "err", err, "path", path)
		return
	}
	e.pcapng.Store(w)
	e.mu.Lock()
	e.pcapngPath = path
	e.mu.Unlock()
	e.broadcast(rpc.Event{Kind: "recon", Level: rpc.LevelInfo, Text: "[*] capturing to " + name})
}

// closeArchive closes the current session's pcapng and writes a Kismet netxml snapshot beside it,
// named to match. A no-op when no archive is open.
func (e *Engine) closeArchive(ctx context.Context) {
	w := e.pcapng.Swap(nil)
	if w == nil {
		return
	}
	e.mu.Lock()
	path := e.pcapngPath
	e.pcapngPath = ""
	e.mu.Unlock()

	if err := w.Close(); err != nil {
		e.log.Error("could not close the capture archive", "err", err)
	}
	if path != "" {
		netpath := strings.TrimSuffix(path, ".pcapng") + ".netxml"
		if err := e.store.WriteNetXML(ctx, netpath); err != nil {
			e.log.Warn("could not write the capture netxml", "err", err, "path", netpath)
		}
	}
}

// FlushNow pushes everything buffered to disk without waiting for the next tick. Called by
// `warp export`, which an operator runs precisely because they want the files current now.
func (e *Engine) FlushNow() {
	e.flushObservations()
	e.persistState()
	if p := e.pcapng.Load(); p != nil {
		if err := p.Flush(); err != nil {
			e.log.Error("pcapng flush failed", "err", err)
		}
	}
}

// Close releases the engine's files. Separate from Stop because recon can be stopped and
// started again within one engagement - the observation log spans all of it, and closing it
// with the radios would leave the second run appending to a closed file.
func (e *Engine) Close() error { return e.obsLog.Close() }

// stopRunners releases every radio, best-effort.
//
// Every runner is torn down even if an earlier one failed: a partial restore still beats
// leaving a card in monitor mode, and an engagement that ends with three stranded adapters is
// the failure this ordering exists to avoid.
func (e *Engine) stopRunners(ctx context.Context, runners []*radioRunner) error {
	var errs []error
	for _, r := range runners {
		if src := r.currentSource(); src != nil {
			if err := src.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if r.acq != nil {
			if err := e.acquirer.Release(ctx, r.acq); err != nil {
				errs = append(errs, err)
			}
		}
		if r.handle != nil {
			r.handle.Release()
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// EngineStats summarises capture activity for the status header.
type EngineStats struct {
	Running     bool                `json:"running"`
	SurveyRadio string              `json:"survey_radio,omitempty"`
	APs         int                 `json:"aps"`
	Stations    int                 `json:"stations"`
	Radios      []RadioCaptureStats `json:"radios"`
	// HeldRadios are parked on one channel rather than sweeping - during a deauthentication
	// campaign, a solicitation or a hunt. "on ch6" means something different when a radio is
	// pinned there, so the frontends say which.
	HeldRadios   []string        `json:"held_radios,omitempty"`
	Handshake    handshake.Stats `json:"handshake"`
	PendingESSID []string        `json:"pending_essid,omitempty"`
}

// RadioCaptureStats is one radio's capture counters.
type RadioCaptureStats struct {
	RadioID string `json:"radio_id"`
	Ifname  string `json:"ifname"`
	// Bands this adapter can actually use: "2.4", "5", or "2.4/5". A 2.4-only card will never
	// see the 5 GHz half of an estate, and an operator staring at an empty listing needs to
	// know that before concluding the network is not there.
	Bands    string        `json:"bands,omitempty"`
	Locked   bool          `json:"locked,omitempty"`
	Role     string        `json:"role"`
	Channel  int           `json:"channel"`
	Capture  capture.Stats `json:"capture"`
	CycleFor string        `json:"sweep_cycle,omitempty"`
}

// Stats returns the engine's current counters.
func (e *Engine) Stats() EngineStats {
	e.mu.Lock()
	runners := append([]*radioRunner(nil), e.radios...)
	running := e.running
	surveyID := e.surveyID
	e.mu.Unlock()

	// Resolve the survey radio to its interface name for display; phyNNN is an internal handle.
	surveyName := surveyID
	if surveyID != "" {
		if dev := e.deviceForID(surveyID); dev != nil && dev.Ifname != "" {
			surveyName = dev.Ifname
		}
	}

	aps, stations := e.tracker.Counts()
	st := EngineStats{
		Running:      running,
		SurveyRadio:  surveyName,
		APs:          aps,
		Stations:     stations,
		Handshake:    e.machine.Stats(),
		PendingESSID: e.machine.PendingBSSIDs(),
	}

	for _, r := range runners {
		rs := RadioCaptureStats{
			RadioID: r.handle.Device.ID,
			Ifname:  r.handle.Device.Ifname,
			Role:    string(r.handle.Role),
			Capture: r.stats(),
		}
		if locked := r.plan.Locked(); locked != 0 {
			rs.Channel, _ = nl80211.ChannelForFrequencyAuto(locked)
			rs.Locked = true
			st.HeldRadios = append(st.HeldRadios, rs.RadioID)
		} else if cur := r.plan.Current(); cur != 0 {
			// Where the adapter is right now, mid-sweep. Without this the channel column is
			// blank whenever a radio is doing its ordinary job, which is most of the time.
			rs.Channel, _ = nl80211.ChannelForFrequencyAuto(cur)
		}
		rs.Bands = bandLabel(r.handle.Device)
		rs.CycleFor = r.plan.CycleDuration().Round(time.Second).String()
		st.Radios = append(st.Radios, rs)
	}
	return st
}
