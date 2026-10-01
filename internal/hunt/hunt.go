// Package hunt implements direction finding for a single target.
//
// It works on any BSSID or client MAC that has been observed, not just on rogues: the common
// cases are locating an unknown access point, a broadcasting printer, or an unauthorized
// station. The intended workflow is to switch to a directional antenna and walk the signal
// gradient, which means the operator is watching the antenna, not the screen - so the display
// is built around a large readout, a peak-hold marker, and an optional audible cue.
package hunt

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/waffl3ss/warp/internal/recon"
)

// Tuning.
const (
	// SparklineLen is how many samples the rolling display holds.
	SparklineLen = 60

	// rateWindow is the interval over which packets-per-second is averaged. Short enough to
	// react as the operator sweeps the antenna, long enough not to flicker.
	rateWindow = 2 * time.Second

	// StaleAfter is how long without a packet before the target is reported lost. Walking
	// behind a wall can easily cause this, so it is reported rather than treated as an end.
	StaleAfter = 5 * time.Second

	// Audible cue bounds. Pitch is not available without an audio stack, so the cue is a
	// terminal bell whose *rate* tracks signal strength - the Geiger-counter idiom. Faster is
	// stronger.
	minBeepInterval = 60 * time.Millisecond
	maxBeepInterval = 1500 * time.Millisecond

	// RSSI range used to map signal onto the beep rate.
	weakRSSI   = -90
	strongRSSI = -30
)

// Target is what is being hunted.
type Target struct {
	Addr recon.MAC `json:"addr"`
	// IsAP records whether the target was observed as an access point, purely for display.
	IsAP    bool   `json:"is_ap"`
	ESSID   string `json:"essid,omitempty"`
	Channel int    `json:"channel"`
	Freq    int    `json:"freq"`
	// RadioID is the adapter locked to the target. RSSI is not comparable across radios, so a
	// hunt that changed adapters mid-walk would produce a gradient that means nothing.
	RadioID string `json:"radio_id"`
}

// State is a snapshot of the hunt for display.
type State struct {
	Target Target `json:"target"`

	// Current is the most recent signal reading.
	Current int8 `json:"current_rssi"`
	// HasSignal is false before the first packet arrives, or once the target goes stale.
	HasSignal bool `json:"has_signal"`

	// Peak is the strongest reading seen, with how long ago it was. The peak-hold marker is
	// what tells an operator whether they are getting warmer or have walked past it.
	Peak    int8          `json:"peak_rssi"`
	PeakAge time.Duration `json:"peak_age"`
	HasPeak bool          `json:"has_peak"`

	// PacketsPerSec confirms the target is still being heard at all. A falling rate with a
	// steady RSSI usually means the target stopped transmitting, not that it moved.
	PacketsPerSec float64 `json:"packets_per_sec"`

	// Sparkline is the recent signal history, oldest first.
	Sparkline []int8 `json:"sparkline"`

	// Stale is set when nothing has been heard for StaleAfter.
	Stale bool `json:"stale"`
	// LastSeen is when the target was last heard.
	LastSeen time.Time `json:"last_seen"`

	// BeepInterval is how often the audible cue should sound. Zero means silent.
	BeepInterval time.Duration `json:"beep_interval"`

	Started time.Time `json:"started"`
	Packets uint64    `json:"packets"`
}

// Session accumulates observations for one hunt.
type Session struct {
	mu     sync.RWMutex
	target Target

	samples []int8
	current int8
	hasSig  bool

	peak    int8
	peakAt  time.Time
	hasPeak bool

	lastSeen time.Time
	started  time.Time
	packets  uint64

	// rate tracks packet arrivals in the current window.
	windowStart time.Time
	windowCount int
	rate        float64

	audible bool
	now     func() time.Time
}

// NewSession starts a hunt for a target.
func NewSession(t Target, audible bool) *Session {
	now := time.Now()
	return &Session{
		target:      t,
		samples:     make([]int8, 0, SparklineLen),
		started:     now,
		windowStart: now,
		audible:     audible,
		now:         time.Now,
	}
}

// Target returns what is being hunted.
func (s *Session) Target() Target {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.target
}

// Observe records one signal reading for the target.
//
// Readings with no RSSI are counted as packets but do not move the gradient: a driver that
// reported no signal must not register as 0 dBm, which would read as the strongest possible
// reading and send the operator in exactly the wrong direction.
func (s *Session) Observe(rssi int8, hasRSSI bool, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.packets++
	s.lastSeen = at

	// Packets-per-second over a rolling window.
	s.windowCount++
	if elapsed := at.Sub(s.windowStart); elapsed >= rateWindow {
		s.rate = float64(s.windowCount) / elapsed.Seconds()
		s.windowStart = at
		s.windowCount = 0
	}

	if !hasRSSI {
		return
	}

	s.current = rssi
	s.hasSig = true

	if !s.hasPeak || rssi > s.peak {
		s.peak = rssi
		s.peakAt = at
		s.hasPeak = true
	}

	s.samples = append(s.samples, rssi)
	if len(s.samples) > SparklineLen {
		s.samples = s.samples[len(s.samples)-SparklineLen:]
	}
}

// ResetPeak clears the peak-hold marker.
//
// Used when the operator moves to a new area and wants the gradient measured from where they
// now stand, rather than against a peak recorded two rooms ago.
func (s *Session) ResetPeak() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hasPeak = false
	s.peak = 0
}

// Snapshot returns the current display state.
func (s *Session) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := s.now()
	stale := !s.lastSeen.IsZero() && now.Sub(s.lastSeen) > StaleAfter

	st := State{
		Target:        s.target,
		Current:       s.current,
		HasSignal:     s.hasSig && !stale,
		Peak:          s.peak,
		HasPeak:       s.hasPeak,
		PacketsPerSec: s.rate,
		Sparkline:     append([]int8(nil), s.samples...),
		Stale:         stale,
		LastSeen:      s.lastSeen,
		Started:       s.started,
		Packets:       s.packets,
	}
	if s.hasPeak {
		st.PeakAge = now.Sub(s.peakAt)
	}
	if s.audible && st.HasSignal {
		st.BeepInterval = beepInterval(s.current)
	}
	return st
}

// beepInterval maps signal strength onto an audible cue rate.
//
// Pitch would be preferable and is what the brief describes, but generating a tone needs an
// audio stack that WARP cannot take on: ALSA bindings mean CGO, and shelling out to a player
// means a runtime dependency. Rate is the honest alternative - it is the Geiger-counter idiom,
// it works over SSH on any terminal, and it leaves the operator free to watch the antenna
// rather than the screen, which is the actual requirement.
func beepInterval(rssi int8) time.Duration {
	v := float64(rssi)
	if v < weakRSSI {
		v = weakRSSI
	}
	if v > strongRSSI {
		v = strongRSSI
	}
	// 0 at the weakest, 1 at the strongest.
	frac := (v - weakRSSI) / (strongRSSI - weakRSSI)

	span := float64(maxBeepInterval - minBeepInterval)
	return maxBeepInterval - time.Duration(frac*span)
}

// Sparkline renders the signal history as block characters.
//
// Scaled to the observed range rather than to a fixed one: the operator cares about the
// gradient as they move, and a fixed -90..-30 scale flattens the last few metres of a walk
// into a single row of identical blocks, which is exactly when the detail matters most.
func Sparkline(samples []int8) string {
	if len(samples) == 0 {
		return ""
	}
	blocks := []rune("▁▂▃▄▅▆▇█")

	minV, maxV := samples[0], samples[0]
	for _, s := range samples {
		if s < minV {
			minV = s
		}
		if s > maxV {
			maxV = s
		}
	}

	var b strings.Builder
	span := float64(maxV - minV)
	for _, s := range samples {
		idx := 0
		if span > 0 {
			idx = int(float64(s-minV) / span * float64(len(blocks)-1))
		} else {
			idx = len(blocks) / 2
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(blocks) {
			idx = len(blocks) - 1
		}
		b.WriteRune(blocks[idx])
	}
	return b.String()
}

// Bar renders a horizontal signal meter of the given width.
func Bar(rssi int8, width int) string {
	if width <= 0 {
		return ""
	}
	v := float64(rssi)
	if v < weakRSSI {
		v = weakRSSI
	}
	if v > strongRSSI {
		v = strongRSSI
	}
	frac := (v - weakRSSI) / (strongRSSI - weakRSSI)

	filled := int(frac * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

// Describe renders a one-line summary, for non-interactive clients.
func (s State) Describe() string {
	if !s.HasSignal {
		if s.Stale {
			return fmt.Sprintf("%s: no packets for %s - target lost or stopped transmitting",
				s.Target.Addr, time.Since(s.LastSeen).Round(time.Second))
		}
		return fmt.Sprintf("%s: waiting for the first packet", s.Target.Addr)
	}

	out := fmt.Sprintf("%s  %4d dBm  %s  %.1f pkt/s",
		s.Target.Addr, s.Current, Bar(s.Current, 20), s.PacketsPerSec)
	if s.HasPeak {
		out += fmt.Sprintf("  peak %d dBm %s ago", s.Peak, s.PeakAge.Round(time.Second))
	}
	return out
}
