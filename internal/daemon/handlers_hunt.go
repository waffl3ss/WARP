package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/waffl3ss/warp/internal/capture"
	"github.com/waffl3ss/warp/internal/hunt"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/rpc"
)

// huntSession pairs a direction-finding session with the radio it locked.
type huntSession struct {
	session *hunt.Session
	handle  *radio.Handle
	acq     *radio.Acquisition
	cancel  context.CancelFunc
	jobID   string
}

// HuntStartParams asks to hunt a target.
type HuntStartParams struct {
	// Addr is any BSSID or client MAC that has been observed. Hunt is not restricted to
	// rogues: locating an unknown AP, a broadcasting printer, or an unauthorized station are
	// all ordinary uses.
	Addr string `json:"addr"`
	// Audible enables the signal cue.
	Audible bool `json:"audible,omitempty"`
}

func (d *Daemon) handleHuntStart(ctx context.Context, params json.RawMessage) (any, error) {
	var p HuntStartParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	addr, err := recon.ParseMAC(p.Addr)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}

	target, err := d.resolveHuntTarget(addr)
	if err != nil {
		return nil, err
	}

	d.huntMu.Lock()
	if _, exists := d.hunts[addr]; exists {
		d.huntMu.Unlock()
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "already hunting %s", addr)
	}
	d.huntMu.Unlock()

	// Hunt is a job like every other attack, so it returns immediately and the operator can
	// keep using the prompt while walking.
	job := d.jobs.Start(d.ctx, "hunt", addr.String(), func(jctx context.Context) (any, error) {
		return d.runHunt(jctx, addr, target, p.Audible)
	})

	return map[string]any{"job": job, "target": target}, nil
}

// resolveHuntTarget finds an observed device and the channel to lock to.
func (d *Daemon) resolveHuntTarget(addr recon.MAC) (hunt.Target, error) {
	tracker := d.engine.Tracker()

	if ap, ok := tracker.AP(addr); ok {
		return hunt.Target{
			Addr: addr, IsAP: true, ESSID: ap.ESSID,
			Channel: ap.Channel, Freq: ap.Freq,
		}, nil
	}

	if st, ok := tracker.Station(addr); ok {
		t := hunt.Target{Addr: addr}
		// A station is hunted on its access point's channel: that is where its traffic is.
		if !st.BSSID.IsZero() {
			if ap, ok := tracker.AP(st.BSSID); ok {
				t.Channel, t.Freq, t.ESSID = ap.Channel, ap.Freq, ap.ESSID
			}
		}
		if t.Freq == 0 {
			return t, rpc.Errorf(rpc.CodeInvalidParams,
				"%s has been seen but its channel is not known; wait for it to associate, "+
					"or hunt its access point instead", addr)
		}
		return t, nil
	}

	return hunt.Target{}, rpc.Errorf(rpc.CodeNotFound,
		"%s has not been observed; hunt works on any BSSID or station WARP has seen, so run "+
			"recon until it appears", addr)
}

// runHunt locks a radio to the target's channel and feeds the session.
func (d *Daemon) runHunt(ctx context.Context, addr recon.MAC, target hunt.Target, audible bool) (any, error) {
	handle, err := d.sched.Acquire(ctx, radio.RoleHunt)
	if err != nil {
		return nil, err
	}
	defer handle.Release()

	target.RadioID = handle.Device.ID

	session := hunt.NewSession(target, audible)

	hctx, cancel := context.WithCancel(ctx)
	defer cancel()

	d.huntMu.Lock()
	d.hunts[addr] = &huntSession{session: session, handle: handle, cancel: cancel}
	d.huntMu.Unlock()

	defer func() {
		d.huntMu.Lock()
		delete(d.hunts, addr)
		d.huntMu.Unlock()
	}()

	if handle.Borrowed {
		return d.runHuntBorrowed(hctx, addr, target, session, handle)
	}
	return d.runHuntDedicated(hctx, addr, target, session, handle)
}

// runHuntBorrowed hunts on a radio shared with recon. It parks that radio on the target's channel
// and reads the engine's *existing* capture through a tap, rather than opening a second AF_PACKET
// socket on the same interface: two sockets on one netdev are unreliable on some drivers (mt76
// after mode-cycling), which left a hunt reporting "no frames" while recon on the same card saw
// them. Reconfiguring the interface is not an option either - it would down the netdev and kill the
// capture its owner depends on.
func (d *Daemon) runHuntBorrowed(ctx context.Context, addr recon.MAC, target hunt.Target,
	session *hunt.Session, handle *radio.Handle) (any, error) {

	resume, parked := d.engine.PauseHopping(handle.Device.ID, target.Freq)
	defer resume()

	if !parked {
		// The radio is still sweeping: its channel plan does not include the target's channel (a
		// channel subset set on the radios tab, or a band the sweep skips). Say so plainly rather
		// than letting the operator walk a gradient that only updates when the sweep happens to
		// pass the target - which reads as the hunt being broken.
		d.Broadcast(rpc.Event{
			Kind: "hunt", Level: rpc.LevelWarn,
			Text: fmt.Sprintf("[!] cannot park %s on ch%d for the hunt - the sweep plan excludes "+
				"that channel. Widen the channel selection on the radios tab (or clear it), or "+
				"give hunting its own adapter.", handle.Device.ID, target.Channel),
			Fields: map[string]any{"addr": addr.String(), "channel": target.Channel},
		})
	} else {
		d.Broadcast(rpc.Event{
			Kind: "hunt", Level: rpc.LevelGood,
			Text: fmt.Sprintf("[+] hunting %s on ch%d (radio %s) - switch to a directional antenna "+
				"and walk the gradient", addr, target.Channel, target.RadioID),
			Fields: map[string]any{"addr": addr.String(), "channel": target.Channel},
		})
		// Verify the card actually moved. The recon hop loop re-asserts the locked channel every
		// dwell, so this is a detector, not another attempt: an mt76 that wedged after mode-cycling
		// accepts SetChannel and ignores it, which the hunt experiences as "locked but no frames".
		go d.verifyHuntChannel(ctx, handle, target, addr)
	}

	obs, stop := d.engine.WatchHunt(addr, handle.Device.ID)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			return session.Snapshot(), nil
		case o := <-obs:
			session.Observe(o.signalDBM, o.hasSignal, o.at)
		}
	}
}

// verifyHuntChannel confirms the adapter actually tuned to the hunt's channel, warning clearly if
// it did not. Some USB drivers (mt76 especially) stop honouring a channel change after being
// mode-cycled by earlier attacks - they accept the netlink command and the plan reports the radio
// locked, but the hardware stays put, so the operator sees "locked to the channel" and no frames.
// Best-effort: when the driver does not report its frequency (freq 0), no conclusion is drawn.
func (d *Daemon) verifyHuntChannel(ctx context.Context, handle *radio.Handle, target hunt.Target, addr recon.MAC) {
	if target.Freq == 0 {
		return
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}

		got, err := d.acquirer.CurrentFreq(ctx, handle.Device)
		if err != nil || got == 0 {
			return // cannot read it back on this driver: do not raise a false alarm
		}
		if got == target.Freq {
			return // tuned correctly
		}
		if time.Now().After(deadline) {
			d.Broadcast(rpc.Event{
				Kind: "hunt", Level: rpc.LevelWarn,
				Text: fmt.Sprintf("[!] %s is not honouring the channel change: the hunt wants ch%d "+
					"but the adapter reports %d MHz, so no target frames arrive. This is the mt76 "+
					"wedge after mode-cycling - stop the hunt; if it persists, stop warpd and run "+
					"`sudo warp radios reset` (or unplug/replug the adapter), then start again.",
					handle.Device.ID, target.Channel, got),
				Fields: map[string]any{
					"addr": addr.String(), "channel": target.Channel,
					"wanted_freq": target.Freq, "actual_freq": got,
				},
			})
			return
		}
	}
}

// runHuntDedicated hunts on an adapter of its own: it acquires the interface in monitor mode, locks
// its channel plan to the target, and reads its own capture socket - the only one on that netdev.
func (d *Daemon) runHuntDedicated(ctx context.Context, addr recon.MAC, target hunt.Target,
	session *hunt.Session, handle *radio.Handle) (any, error) {

	acq, err := acquireReconciling(ctx, d.sched, d.acquirer, handle.Device, nl80211.IftypeMonitor)
	if err != nil {
		return nil, err
	}
	defer d.acquirer.Release(ctx, acq)

	// Follow/lock is the ordinary channel plan restricted to one channel - the same code path as
	// hopping, not a parallel one.
	plan, err := radio.NewChannelPlanForDevice(handle.Device, radio.PlanOptions{})
	if err != nil {
		return nil, err
	}
	if !plan.Lock(target.Freq) {
		return nil, fmt.Errorf("daemon: adapter %s cannot tune to %d MHz",
			handle.Device.ID, target.Freq)
	}
	if err := d.acquirer.SetChannel(ctx, handle.Device, target.Freq); err != nil {
		return nil, err
	}

	d.Broadcast(rpc.Event{
		Kind: "hunt", Level: rpc.LevelGood,
		Text: fmt.Sprintf("[+] hunting %s on ch%d (radio %s) - switch to a directional antenna "+
			"and walk the gradient", addr, target.Channel, target.RadioID),
		Fields: map[string]any{"addr": addr.String(), "channel": target.Channel},
	})

	source, err := capture.Open(handle.Device.Ifname, int(handle.Device.Ifindex), handle.Device.ID)
	if err != nil {
		return nil, err
	}
	defer source.Close()

	err = source.Run(ctx, func(frame *capture.Frame) error {
		f, err := recon.ParseFrame(frame.Body)
		if err != nil {
			return nil
		}
		if !frameInvolves(f, addr) {
			return nil
		}
		session.Observe(frame.Radiotap.SignalDBM, frame.Radiotap.HasSignal, frame.At)
		return nil
	})
	if err != nil && ctx.Err() == nil {
		return session.Snapshot(), err
	}

	return session.Snapshot(), nil
}

// frameInvolves reports whether a frame was transmitted by or addressed to the target.
//
// Both directions count: a station's own frames give the best gradient, but frames addressed
// to it from the AP still prove it is present and keep the packet rate meaningful.
func frameInvolves(f *recon.Frame, addr recon.MAC) bool {
	if f.Addr2 == addr || f.Addr1 == addr {
		return true
	}
	if f.Type != recon.TypeControl && f.Addr3 == addr {
		return true
	}
	return false
}

func (d *Daemon) handleHuntStop(_ context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	addr, err := recon.ParseMAC(p.Addr)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}

	d.huntMu.Lock()
	h, ok := d.hunts[addr]
	d.huntMu.Unlock()

	if !ok {
		return nil, rpc.Errorf(rpc.CodeNotFound, "not hunting %s", addr)
	}
	h.cancel()
	return map[string]string{"addr": addr.String(), "state": "stopped"}, nil
}

func (d *Daemon) handleHuntState(_ context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Addr string `json:"addr,omitempty"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
		}
	}

	d.huntMu.RLock()
	defer d.huntMu.RUnlock()

	if p.Addr != "" {
		addr, err := recon.ParseMAC(p.Addr)
		if err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
		}
		h, ok := d.hunts[addr]
		if !ok {
			return nil, rpc.Errorf(rpc.CodeNotFound, "not hunting %s", addr)
		}
		return h.session.Snapshot(), nil
	}

	out := make([]hunt.State, 0, len(d.hunts))
	for _, h := range d.hunts {
		out = append(out, h.session.Snapshot())
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Target.Addr.String() < out[j].Target.Addr.String()
	})
	return out, nil
}

// ---------------------------------------------------------------------------
// Karma responder tracking
// ---------------------------------------------------------------------------

// The probed ESSID and the set of responders live on the Daemon, guarded by karmaMu.

func (d *Daemon) setKarmaProbe(essid string) {
	d.karmaMu.Lock()
	d.karmaProbeESSID = essid
	d.karmaMu.Unlock()
}

func (d *Daemon) clearKarmaProbe() {
	d.karmaMu.Lock()
	d.karmaProbeESSID = ""
	d.karmaMu.Unlock()
}

// NoteKarmaResponse records a device that answered a probe for the generated ESSID.
//
// Called from the capture path when a probe response or beacon carries the impossible name.
// This is a deterministic yes/no: the network does not exist, so anything claiming to be it
// is answering arbitrary probes.
func (d *Daemon) NoteKarmaResponse(bssid recon.MAC, essid string) bool {
	d.karmaMu.Lock()
	defer d.karmaMu.Unlock()

	if d.karmaProbeESSID == "" || essid != d.karmaProbeESSID {
		return false
	}
	if _, known := d.karmaResponders[bssid]; known {
		return false
	}
	d.karmaResponders[bssid] = essid
	return true
}

func (d *Daemon) karmaResponderList() []string {
	d.karmaMu.RLock()
	defer d.karmaMu.RUnlock()

	out := make([]string, 0, len(d.karmaResponders))
	for k := range d.karmaResponders {
		out = append(out, k.String())
	}
	sort.Strings(out)
	return out
}
