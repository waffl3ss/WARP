package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/rpc"
)

// Manual radio control.
//
// The channel plan owns the capture radios and sweeps them, which is right for finding things
// and wrong for watching one. An operator who knows the target is on channel 36 and wants a
// card to sit there - while the other one keeps sweeping - had no way to say so: every hold in
// the tool was a side effect of running an attack, and ended when the attack did.
//
// So a radio can be pinned by hand. It is a lock on the channel plan, the same mechanism a
// campaign uses, held until it is released rather than for the length of a burst. Locking a
// radio does not stop it capturing; it stops it *moving*.
//
// What this is not: a way to reassign roles or to hot-unplug a card. Roles are the scheduler's
// and are decided by what each adapter can do - invariant 4a - and pulling a radio out from
// under a running capture is what the borrow rules exist to prevent.

// radioLocks records the operator's manual channel holds, so they survive the RPC call that
// created them and can be listed and released.
type radioLocks struct {
	mu   sync.Mutex
	held map[string]*radioLock
}

type radioLock struct {
	mhz     int
	channel int
	release func()
}

// RadioLockParams pins one adapter to a channel.
type RadioLockParams struct {
	// RadioID is the adapter, e.g. "phy0".
	RadioID string `json:"radio_id"`
	// Channel is the IEEE channel number. Frequency is derived from the adapter's own bands,
	// so channel 36 is unambiguous even though the number alone is not.
	Channel int `json:"channel"`
}

func (d *Daemon) handleRadioLock(ctx context.Context, params json.RawMessage) (any, error) {
	var p RadioLockParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if p.Channel == 0 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"a channel is required; use radios.unlock to hand the adapter back to the sweep")
	}

	dev := d.deviceByID(p.RadioID)
	if dev == nil {
		return nil, rpc.Errorf(rpc.CodeNotFound,
			"no adapter %q; `warp radios list` names the ones warpd is managing", p.RadioID)
	}
	if !d.engine.Running() {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"recon is not running, so no adapter is on a channel to be pinned to one. "+
				"Start it first: warp recon start")
	}

	// Resolve the channel against what this adapter actually reaches, from the phy's own
	// frequency list rather than by assuming a band. A 2.4-only card asked for channel 36
	// should be told so, not silently tuned nowhere - and channel 6 exists in both 2.4 GHz and
	// 6 GHz, so the number alone does not identify a frequency.
	//
	// Disabled channels are refused; NoIR ones are not. NoIR forbids *transmitting* until a
	// beacon is heard, and pinning a capture radio is listening - which is exactly what an
	// operator wants on a DFS channel they suspect something is hiding on.
	mhz := 0
	if dev.Phy != nil {
		for _, band := range dev.Phy.Bands {
			for _, f := range band.Freqs {
				if f.Channel == p.Channel && !f.Disabled {
					mhz = f.MHz
					break
				}
			}
			if mhz != 0 {
				break
			}
		}
	}
	if mhz == 0 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s cannot use channel %d. It reaches %v - a 2.4 GHz-only adapter asked for a "+
				"5 GHz channel is the usual cause, and a channel disabled by the regulatory "+
				"domain is the other",
			p.RadioID, p.Channel, dev.Bands())
	}

	d.locks.mu.Lock()
	if prev, ok := d.locks.held[p.RadioID]; ok {
		// Re-pinning replaces the previous hold rather than stacking a second one, which would
		// leak a release function and leave the radio pinned after an unlock.
		prev.release()
		delete(d.locks.held, p.RadioID)
	}
	release, parked := d.engine.PauseHopping(p.RadioID, mhz)
	if d.locks.held == nil {
		d.locks.held = map[string]*radioLock{}
	}
	d.locks.held[p.RadioID] = &radioLock{mhz: mhz, channel: p.Channel, release: release}
	d.locks.mu.Unlock()

	if !parked {
		// The adapter can reach the channel (checked above) but the running sweep plan does not
		// include it - a channel subset set on the radios tab. Say so rather than leaving it
		// silently sweeping while the pane claims it is pinned.
		release()
		d.locks.mu.Lock()
		delete(d.locks.held, p.RadioID)
		d.locks.mu.Unlock()
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s reaches channel %d but the current sweep plan excludes it; widen the channel "+
				"selection on the radios tab (or clear it) before pinning there",
			p.RadioID, p.Channel)
	}

	d.logEvent(audit.KindRadio, audit.OutcomeInfo, "adapter pinned to a channel by the operator",
		map[string]any{"radio_id": p.RadioID, "channel": p.Channel, "freq": mhz})
	d.Broadcast(rpc.Event{
		Kind: "radio", Level: rpc.LevelInfo,
		Text: fmt.Sprintf("[*] %s pinned to channel %d - it will not sweep until released",
			p.RadioID, p.Channel),
		Fields: map[string]any{"radio_id": p.RadioID, "channel": p.Channel},
	})

	return map[string]any{
		"radio_id": p.RadioID,
		"channel":  p.Channel,
		"freq":     mhz,
		"note": "This adapter no longer sweeps. It still captures, and an attack that needs " +
			"another channel will move it for the length of the burst and put it back.",
	}, nil
}

// RadioUnlockParams hands an adapter back to the channel plan.
type RadioUnlockParams struct {
	// RadioID names one adapter. Empty releases every manual hold.
	RadioID string `json:"radio_id,omitempty"`
}

func (d *Daemon) handleRadioUnlock(ctx context.Context, params json.RawMessage) (any, error) {
	var p RadioUnlockParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
		}
	}

	d.locks.mu.Lock()
	var released []string
	for id, lock := range d.locks.held {
		if p.RadioID != "" && id != p.RadioID {
			continue
		}
		lock.release()
		delete(d.locks.held, id)
		released = append(released, id)
	}
	d.locks.mu.Unlock()

	if len(released) == 0 {
		if p.RadioID != "" {
			return nil, rpc.Errorf(rpc.CodeInvalidParams,
				"%s is not pinned; it is already following the channel plan", p.RadioID)
		}
		return map[string]any{"released": []string{}, "note": "nothing was pinned"}, nil
	}

	for _, id := range released {
		d.logEvent(audit.KindRadio, audit.OutcomeInfo, "adapter released back to the channel plan",
			map[string]any{"radio_id": id})
	}
	d.Broadcast(rpc.Event{
		Kind: "radio", Level: rpc.LevelInfo,
		Text:   fmt.Sprintf("[*] %v back on the channel plan", released),
		Fields: map[string]any{"released": released},
	})

	return map[string]any{"released": released}, nil
}

// pinnedChannels reports the operator's manual holds, for the radio listing.
func (d *Daemon) pinnedChannels() map[string]int {
	d.locks.mu.Lock()
	defer d.locks.mu.Unlock()

	out := make(map[string]int, len(d.locks.held))
	for id, lock := range d.locks.held {
		out[id] = lock.channel
	}
	return out
}

// releaseAllLocks drops every manual hold. Called at shutdown so a pinned adapter does not
// keep a lock on a channel plan that is being torn down.
func (d *Daemon) releaseAllLocks() {
	d.locks.mu.Lock()
	defer d.locks.mu.Unlock()

	for id, lock := range d.locks.held {
		lock.release()
		delete(d.locks.held, id)
	}
}

func (d *Daemon) deviceByID(id string) *radio.Device {
	for _, dev := range d.sched.Devices() {
		if dev.ID == id {
			return dev
		}
	}
	return nil
}

// deviceByIDOrIfname resolves an adapter by its radio ID (phyN) or its interface name (wlanN), so a
// caller that has one or the other - the web sends the ID, an operator at the CLI may type either -
// can name the radio the natural way.
func (d *Daemon) deviceByIDOrIfname(name string) *radio.Device {
	for _, dev := range d.sched.Devices() {
		if dev.ID == name || dev.Ifname == name {
			return dev
		}
	}
	return nil
}

// RadioEnableParams switches an adapter on or off.
type RadioEnableParams struct {
	RadioID string `json:"radio_id"`
	Enabled bool   `json:"enabled"`
}

// handleRadioSetEnabled switches an adapter on or off from the radios tab. Off releases the
// adapter and leaves it alone so another tool can use it; on returns it to the pool and brings a
// capture role back if one is uncovered. This is deliberate operator control over which of several
// plugged-in cards WARP uses - distinct from role assignment, which stays the scheduler's.
func (d *Daemon) handleRadioSetEnabled(_ context.Context, params json.RawMessage) (any, error) {
	var p RadioEnableParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if d.deviceByID(p.RadioID) == nil {
		return nil, rpc.Errorf(rpc.CodeNotFound,
			"no adapter %q; `warp radios list` names the ones warpd is managing", p.RadioID)
	}
	if err := d.engine.SetRadioEnabled(p.RadioID, p.Enabled); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	state := "disabled"
	if p.Enabled {
		state = "enabled"
	}
	d.logEvent(audit.KindLifecycle, audit.OutcomeInfo, "radio "+state,
		map[string]any{"radio_id": p.RadioID})
	return map[string]any{"radio_id": p.RadioID, "enabled": p.Enabled}, nil
}

// RadioResetParams names the adapter to power-cycle.
type RadioResetParams struct {
	RadioID string `json:"radio_id"`
}

// handleRadioReset USB-resets one adapter live, without restarting the daemon. A USBDEVFS_RESET
// clears the wedged firmware state that stops mt76 (and similar) parts capturing after heavy
// mode-cycling - the "did not associate" that a card reset fixes. It re-enumerates the device, so the
// phy is re-created under a new index: the daemon waits for the interface to come back, then rebinds
// the managed radio to the fresh phy by its (preserved) interface name.
//
// It is gated on capture being fully stopped and no jobs running, so nothing holds the interface
// while it is power-cycled. The gate is enforced here, not just in the frontends, so no client can
// pull a radio out from under a live capture.
func (d *Daemon) handleRadioReset(ctx context.Context, params json.RawMessage) (any, error) {
	var p RadioResetParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	dev := d.deviceByIDOrIfname(p.RadioID)
	if dev == nil {
		return nil, rpc.Errorf(rpc.CodeNotFound,
			"no adapter %q; `warp radios list` names the ones warpd is managing", p.RadioID)
	}
	if d.engine.Running() {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"stop capture before resetting a radio - a reset power-cycles the adapter, which cannot "+
				"happen while it is capturing. Stop recon (warp recon stop), then reset.")
	}
	if n := d.jobs.RunningCount(); n > 0 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%d background job(s) still running; a radio can only be reset when nothing is using it. "+
				"Wait for them to finish or kill them (warp jobs), then reset.", n)
	}
	if !radio.IsUSBAdapter(dev.Ifname) {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s (%s) is not a USB adapter, so it cannot be USB-reset. A built-in PCIe/SDIO card is "+
				"reset by reloading its driver or rebooting.", dev.ID, dev.Ifname)
	}

	ifname := dev.Ifname
	oldIfindex := dev.Ifindex
	d.Broadcast(rpc.Event{
		Kind: "radio", Level: rpc.LevelInfo,
		Text:   fmt.Sprintf("[*] resetting %s (%s) - it will drop off and re-enumerate", dev.ID, ifname),
		Fields: map[string]any{"radio_id": dev.ID, "ifname": ifname},
	})

	if err := radio.ResetUSBAdapter(ifname); err != nil {
		return nil, rpc.Errorf(rpc.CodeInternal, "%v", err)
	}

	// The netdev drops during re-enumeration; wait for it to come back with a new kernel index
	// before touching it again.
	if err := radio.WaitForReenumeration(ctx, ifname, oldIfindex, 25*time.Second); err != nil {
		return nil, rpc.Errorf(rpc.CodeInternal, "%v", err)
	}
	// A short settle so the phy's bands are fully published before we read them.
	select {
	case <-time.After(500 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	fresh, err := d.sched.ReprobeDeviceByIfname(ctx, ifname)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInternal,
			"%s came back but WARP could not rebind it (%v); a daemon restart will pick it up", ifname, err)
	}

	d.logEvent(audit.KindRadio, audit.OutcomeInfo, "adapter USB-reset by the operator",
		map[string]any{"radio_id": fresh.ID, "ifname": ifname, "prior_id": p.RadioID})
	d.Broadcast(rpc.Event{
		Kind: "radio", Level: rpc.LevelInfo,
		Text:   fmt.Sprintf("[*] %s (%s) reset and back online", fresh.ID, ifname),
		Fields: map[string]any{"radio_id": fresh.ID, "ifname": ifname},
	})

	return map[string]any{
		"radio_id": fresh.ID,
		"ifname":   ifname,
		"note":     "adapter power-cycled and rebound; start capture again with `warp recon start`",
	}, nil
}

// RadioChannelsParams sets an adapter's channel-management policy - which channels it sweeps,
// whether it sweeps 5 GHz, and whether it hops randomly.
type RadioChannelsParams struct {
	RadioID     string `json:"radio_id"`
	Channels    []int  `json:"channels,omitempty"`
	Disable5GHz bool   `json:"disable_5ghz,omitempty"`
	Random      bool   `json:"random,omitempty"`
}

// handleRadioChannels sets an adapter's channel selection, 5 GHz on/off and hop order. Applied
// live to a sweeping radio, so the operator sees the effect without restarting recon.
func (d *Daemon) handleRadioChannels(_ context.Context, params json.RawMessage) (any, error) {
	var p RadioChannelsParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if d.deviceByID(p.RadioID) == nil {
		return nil, rpc.Errorf(rpc.CodeNotFound,
			"no adapter %q; `warp radios list` names the ones warpd is managing", p.RadioID)
	}
	n, err := d.engine.SetChannelPolicy(p.RadioID, ChannelPolicy{
		Channels: p.Channels, Disable5GHz: p.Disable5GHz, Random: p.Random,
	})
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	d.logEvent(audit.KindLifecycle, audit.OutcomeInfo, "radio channel policy set",
		map[string]any{"radio_id": p.RadioID, "channels": p.Channels,
			"disable_5ghz": p.Disable5GHz, "random": p.Random})
	return map[string]any{"radio_id": p.RadioID, "usable_channels": n,
		"disable_5ghz": p.Disable5GHz, "random": p.Random}, nil
}

// RegDomainResult is the current regulatory domain plus whether it is the world/unset default,
// which is what leaves the upper bands receive-only.
type RegDomainResult struct {
	CC      string `json:"cc"`
	IsWorld bool   `json:"is_world"`
}

// handleRegDomainGet reports the kernel's current regulatory domain.
func (d *Daemon) handleRegDomainGet(_ context.Context, _ json.RawMessage) (any, error) {
	cc, err := radio.GetRegDomain()
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInternal, "%v", err)
	}
	return RegDomainResult{CC: cc, IsWorld: cc == "" || cc == "00"}, nil
}

// handleRegDomainSet changes the regulatory domain, then re-probes so the band flags (and WARP's
// own transmit gating) reflect the new rules - a 5 GHz band that was NoIR under the world default
// becomes transmit-usable once a country is set.
func (d *Daemon) handleRegDomainSet(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		CC string `json:"cc"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if len(p.CC) != 2 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"a two-letter ISO country code is required (e.g. US), got %q", p.CC)
	}
	if err := radio.SetRegDomain(p.CC); err != nil {
		return nil, rpc.Errorf(rpc.CodeInternal, "%v", err)
	}
	// The kernel applies the change asynchronously; give it a moment before re-probing so the
	// refreshed band flags reflect the new domain rather than the old one.
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := d.sched.RefreshRegulatory(ctx); err != nil {
		d.log.Warn("could not re-probe phys after a regulatory change", "err", err)
	}
	cc, _ := radio.GetRegDomain()
	d.logEvent(audit.KindLifecycle, audit.OutcomeInfo, "regulatory domain set",
		map[string]any{"cc": cc, "requested": p.CC})
	d.Broadcast(rpc.Event{
		Kind: "radio", Level: rpc.LevelInfo,
		Text:   fmt.Sprintf("[*] regulatory domain set to %s", cc),
		Fields: map[string]any{"cc": cc},
	})
	return RegDomainResult{CC: cc, IsWorld: cc == "" || cc == "00"}, nil
}
