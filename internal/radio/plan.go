package radio

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// Default dwell parameters. A quarter second is roughly two beacon intervals at the usual
// 100 TU, so a base dwell reliably catches a beacon from every AP on the channel.
const (
	DefaultBaseDwell = 250 * time.Millisecond
	DefaultMinDwell  = 50 * time.Millisecond
	DefaultMaxDwell  = 5 * time.Second

	// ScopedChannelWeight is applied to channels hosting a scoped ESSID. Those channels are
	// where the engagement actually is; the rest get short sweeps purely to catch a new BSSID
	// appearing.
	ScopedChannelWeight = 4.0
	// SweepChannelWeight is the baseline for channels with nothing scoped on them.
	SweepChannelWeight = 1.0
)

// Dwell is one scheduled visit to a channel.
type Dwell struct {
	MHz      int           `json:"mhz"`
	Channel  int           `json:"channel"`
	Band     nl80211.Band  `json:"band"`
	Duration time.Duration `json:"duration"`
	// TransmitAllowed is false on channels where the regulatory domain forbids initiating
	// radiation. Listening is fine; soliciting or injecting there is not.
	TransmitAllowed bool `json:"transmit_allowed"`
}

func (d Dwell) String() string {
	return fmt.Sprintf("ch%d (%d MHz) %v", d.Channel, d.MHz, d.Duration)
}

type planEntry struct {
	freq   nl80211.Frequency
	band   nl80211.Band
	weight float64
}

// ChannelPlan produces the channel-hopping schedule for a radio.
//
// Dwell is weighted rather than uniform: a uniform round-robin spends as much time on an
// empty channel as on the one the client's APs are actually using, which is how a survey
// misses a handshake it was sitting next to. Channels hosting scoped ESSIDs get long dwells;
// everything else gets a short sweep to catch new BSSIDs.
//
// Follow/lock is not a separate mechanism - Lock is the same code path restricted to a
// single channel at weight 1.0, so hunt mode and ordinary hopping share all the logic below.
type ChannelPlan struct {
	mu      sync.Mutex
	entries []planEntry
	cursor  int
	// random hops in a shuffled order instead of ascending frequency.
	random bool

	// locked, when non-zero, restricts the plan to that frequency.
	locked int

	base time.Duration
	min  time.Duration
	max  time.Duration
}

// PlanOptions tunes dwell durations.
type PlanOptions struct {
	BaseDwell time.Duration
	MinDwell  time.Duration
	MaxDwell  time.Duration

	// OnlyChannels, when non-empty, restricts the sweep to these IEEE channel numbers - the
	// Kismet-style "only hop these channels". A number the adapter cannot reach is simply
	// dropped; an empty list means every usable channel.
	OnlyChannels []int
	// Disable5GHz drops the 5 and 6 GHz bands from the sweep, for when an engagement is 2.4-only
	// and sweeping the (much larger) 5 GHz channel list is wasted dwell.
	Disable5GHz bool
	// Random hops the channels in a shuffled order rather than ascending frequency, so a device
	// that only beacons occasionally is less likely to be repeatedly missed by a predictable
	// sweep landing elsewhere at the same phase every cycle.
	Random bool
}

func (o PlanOptions) withDefaults() PlanOptions {
	if o.BaseDwell <= 0 {
		o.BaseDwell = DefaultBaseDwell
	}
	if o.MinDwell <= 0 {
		o.MinDwell = DefaultMinDwell
	}
	if o.MaxDwell <= 0 {
		o.MaxDwell = DefaultMaxDwell
	}
	return o
}

// NewChannelPlan builds a plan over the given channels.
//
// Channels disabled by the regulatory domain are excluded outright. No-IR channels are kept
// - we can still listen on them, and a rogue AP sitting on a DFS channel is exactly the kind
// of thing worth finding - but they are marked so transmitting roles skip them.
func NewChannelPlan(freqs []nl80211.Frequency, band nl80211.Band, opts PlanOptions) *ChannelPlan {
	opts = opts.withDefaults()

	p := &ChannelPlan{base: opts.BaseDwell, min: opts.MinDwell, max: opts.MaxDwell, random: opts.Random}
	for _, f := range freqs {
		if f.Disabled {
			continue
		}
		p.entries = append(p.entries, planEntry{freq: f, band: band, weight: SweepChannelWeight})
	}
	p.sortLocked()
	return p
}

// NewChannelPlanForDevice builds a plan across every band the device supports.
func NewChannelPlanForDevice(dev *Device, opts PlanOptions) (*ChannelPlan, error) {
	if dev == nil || dev.Phy == nil {
		return nil, fmt.Errorf("radio: cannot build a channel plan without adapter capabilities")
	}
	opts = opts.withDefaults()

	only := make(map[int]bool, len(opts.OnlyChannels))
	for _, ch := range opts.OnlyChannels {
		only[ch] = true
	}

	p := &ChannelPlan{base: opts.BaseDwell, min: opts.MinDwell, max: opts.MaxDwell, random: opts.Random}
	for _, b := range dev.Phy.Bands {
		if opts.Disable5GHz && b.Band != nl80211.Band2GHz {
			continue
		}
		for _, f := range b.Freqs {
			if f.Disabled {
				continue
			}
			if len(only) > 0 && !only[f.Channel] {
				continue
			}
			p.entries = append(p.entries, planEntry{freq: f, band: b.Band, weight: SweepChannelWeight})
		}
	}
	if len(p.entries) == 0 {
		return nil, fmt.Errorf("radio: adapter %s has no usable channels under the current "+
			"channel selection (all filtered out?)", dev.ID)
	}
	p.sortLocked()
	return p, nil
}

// Adopt replaces this plan's channel set and hop mode with another's, in place, so a running
// radio's plan can be reconfigured without swapping the pointer the hop loop reads. Scoped-channel
// weighting is reset to the sweep weight - recon re-applies it on its next tick.
func (p *ChannelPlan) Adopt(other *ChannelPlan) {
	other.mu.Lock()
	entries := append([]planEntry(nil), other.entries...)
	random := other.random
	other.mu.Unlock()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.entries = entries
	p.random = random
	p.cursor = 0
	p.locked = 0
}

func (p *ChannelPlan) sortLocked() {
	sort.Slice(p.entries, func(i, j int) bool { return p.entries[i].freq.MHz < p.entries[j].freq.MHz })
}

// SetWeight sets the dwell weight for a frequency. Returns false if the plan has no such
// channel.
func (p *ChannelPlan) SetWeight(mhz int, weight float64) bool {
	if weight <= 0 {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	for i := range p.entries {
		if p.entries[i].freq.MHz == mhz {
			p.entries[i].weight = weight
			return true
		}
	}
	return false
}

// PrioritiseChannels marks the channels hosting scoped ESSIDs, giving them long dwells.
//
// Everything not listed is reset to the sweep weight, so this is the whole priority state
// rather than an accumulating set - recon calls it as the picture of where scoped networks
// live changes during an engagement.
func (p *ChannelPlan) PrioritiseChannels(mhz []int) {
	scoped := make(map[int]struct{}, len(mhz))
	for _, f := range mhz {
		scoped[f] = struct{}{}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.entries {
		if _, ok := scoped[p.entries[i].freq.MHz]; ok {
			p.entries[i].weight = ScopedChannelWeight
		} else {
			p.entries[i].weight = SweepChannelWeight
		}
	}
}

// Lock restricts the plan to a single frequency - follow-BSSID and hunt mode.
//
// This is deliberately the same mechanism as ordinary hopping, not a parallel one: Next()
// keeps returning dwells, they just all name the same channel. Returns false if the plan does
// not contain that frequency.
func (p *ChannelPlan) Lock(mhz int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, e := range p.entries {
		if e.freq.MHz == mhz {
			p.locked = mhz
			return true
		}
	}
	return false
}

// Unlock resumes hopping.
func (p *ChannelPlan) Unlock() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.locked = 0
}

// Locked returns the locked frequency, or 0 when hopping.
func (p *ChannelPlan) Locked() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.locked
}

// Current is the frequency the plan last handed out, or the locked one.
//
// Where the adapter actually is right now. Without it a status display can only show a channel
// while a radio is pinned, which is the rarest case - an operator watching a sweep wants to
// see it move.
func (p *ChannelPlan) Current() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.locked != 0 {
		return p.locked
	}
	if len(p.entries) == 0 {
		return 0
	}
	// cursor points at the *next* entry, so the one just visited is behind it.
	i := (p.cursor - 1 + len(p.entries)) % len(p.entries)
	return p.entries[i].freq.MHz
}

// Next returns the next channel to visit and how long to stay.
//
// It advances a cursor rather than consulting the clock, so the sequence is deterministic
// and testable.
func (p *ChannelPlan) Next() (Dwell, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.entries) == 0 {
		return Dwell{}, false
	}

	if p.locked != 0 {
		for _, e := range p.entries {
			if e.freq.MHz == p.locked {
				// Weight 1.0: a locked channel is held continuously, so a long dwell only
				// delays noticing that the plan changed.
				return p.dwellLocked(e, SweepChannelWeight), true
			}
		}
		// The locked channel vanished (regulatory change, adapter swap). Fall through to
		// hopping rather than stalling.
		p.locked = 0
	}

	if p.random && len(p.entries) > 1 {
		// A shuffled hop: pick a random channel, avoiding an immediate repeat so a run of the
		// same channel does not read as a stuck sweep.
		i := rand.Intn(len(p.entries))
		if i == p.cursor {
			i = (i + 1) % len(p.entries)
		}
		p.cursor = i
		return p.dwellLocked(p.entries[i], p.entries[i].weight), true
	}

	e := p.entries[p.cursor%len(p.entries)]
	p.cursor = (p.cursor + 1) % len(p.entries)
	return p.dwellLocked(e, e.weight), true
}

func (p *ChannelPlan) dwellLocked(e planEntry, weight float64) Dwell {
	d := time.Duration(float64(p.base) * weight)
	if d < p.min {
		d = p.min
	}
	if d > p.max {
		d = p.max
	}
	return Dwell{
		MHz:             e.freq.MHz,
		Channel:         e.freq.Channel,
		Band:            e.band,
		Duration:        d,
		TransmitAllowed: e.freq.Usable(),
	}
}

// Channels returns the plan's channels in frequency order, for the status header.
func (p *ChannelPlan) Channels() []Dwell {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]Dwell, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, p.dwellLocked(e, e.weight))
	}
	return out
}

// CycleDuration is how long one full sweep takes at the current weights - what the operator
// needs to answer "how long until this radio comes back to channel 6".
func (p *ChannelPlan) CycleDuration() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	var total time.Duration
	for _, e := range p.entries {
		total += p.dwellLocked(e, e.weight).Duration
	}
	return total
}
