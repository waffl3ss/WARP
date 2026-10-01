package radio

import (
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

func testFreqs() []nl80211.Frequency {
	return []nl80211.Frequency{
		{MHz: 2412, Channel: 1},
		{MHz: 2437, Channel: 6},
		{MHz: 2462, Channel: 11},
		{MHz: 2467, Channel: 12, NoIR: true},     // listen only
		{MHz: 2472, Channel: 13, Disabled: true}, // excluded entirely
	}
}

func newTestPlan() *ChannelPlan {
	return NewChannelPlan(testFreqs(), nl80211.Band2GHz, PlanOptions{BaseDwell: 100 * time.Millisecond})
}

func TestPlanExcludesDisabledButKeepsNoIR(t *testing.T) {
	p := newTestPlan()
	chans := p.Channels()

	if len(chans) != 4 {
		t.Fatalf("expected 4 channels (disabled excluded), got %d: %+v", len(chans), chans)
	}
	for _, c := range chans {
		if c.Channel == 13 {
			t.Error("a regulatory-disabled channel is in the plan")
		}
		if c.Channel == 12 {
			// No-IR channels stay in the plan — we can listen there, and a rogue AP parked on
			// one is worth finding — but must be marked unusable for transmitting roles.
			if c.TransmitAllowed {
				t.Error("a no-IR channel is marked transmit-allowed")
			}
		}
	}
}

// TestWeightedDwellNotUniformRoundRobin is the point of the whole file: a uniform sweep
// spends as long on an empty channel as on the one the client's APs are on.
func TestWeightedDwellNotUniform(t *testing.T) {
	p := newTestPlan()
	p.PrioritiseChannels([]int{2437}) // channel 6 hosts a scoped ESSID

	dwells := map[int]time.Duration{}
	for i := 0; i < 4; i++ {
		d, ok := p.Next()
		if !ok {
			t.Fatal("plan exhausted")
		}
		dwells[d.Channel] = d.Duration
	}

	scoped, sweep := dwells[6], dwells[1]
	if scoped <= sweep {
		t.Fatalf("scoped channel did not get a longer dwell: ch6=%v ch1=%v", scoped, sweep)
	}
	if want := time.Duration(float64(100*time.Millisecond) * ScopedChannelWeight); scoped != want {
		t.Errorf("scoped dwell = %v, want %v", scoped, want)
	}
}

func TestPrioritiseChannelsReplacesRatherThanAccumulates(t *testing.T) {
	p := newTestPlan()
	p.PrioritiseChannels([]int{2412})
	p.PrioritiseChannels([]int{2437}) // the picture changed; 2412 is no longer scoped

	for _, c := range p.Channels() {
		switch c.Channel {
		case 6:
			if c.Duration != time.Duration(float64(100*time.Millisecond)*ScopedChannelWeight) {
				t.Errorf("channel 6 should be prioritised, got %v", c.Duration)
			}
		case 1:
			if c.Duration != 100*time.Millisecond {
				t.Errorf("channel 1 should have reverted to the sweep weight, got %v", c.Duration)
			}
		}
	}
}

func TestPlanCyclesThroughEveryChannel(t *testing.T) {
	p := newTestPlan()
	total := len(p.Channels())

	seen := map[int]int{}
	for i := 0; i < total*3; i++ {
		d, ok := p.Next()
		if !ok {
			t.Fatal("plan exhausted mid-cycle")
		}
		seen[d.Channel]++
	}
	if len(seen) != total {
		t.Fatalf("expected every channel visited, saw %d of %d", len(seen), total)
	}
	for ch, n := range seen {
		if n != 3 {
			t.Errorf("channel %d visited %d times in three cycles, want 3", ch, n)
		}
	}
}

// TestLockIsTheSameCodePath asserts follow/lock is the hopping mechanism restricted to one
// channel, not a parallel implementation.
func TestLockIsTheSameCodePath(t *testing.T) {
	p := newTestPlan()
	p.PrioritiseChannels([]int{2437})

	if p.Lock(9999) {
		t.Fatal("locked to a frequency not in the plan")
	}
	if !p.Lock(2462) {
		t.Fatal("failed to lock to channel 11")
	}
	if p.Locked() != 2462 {
		t.Fatalf("Locked() = %d, want 2462", p.Locked())
	}

	for i := 0; i < 10; i++ {
		d, ok := p.Next()
		if !ok {
			t.Fatal("plan exhausted while locked")
		}
		if d.Channel != 11 {
			t.Fatalf("locked plan returned channel %d", d.Channel)
		}
		// A locked channel is held continuously, so its dwell is the base unit — a long
		// dwell would only delay noticing that the lock was released.
		if d.Duration != 100*time.Millisecond {
			t.Fatalf("locked dwell = %v, want the base dwell", d.Duration)
		}
	}

	p.Unlock()
	if p.Locked() != 0 {
		t.Fatal("Unlock did not clear the lock")
	}

	seen := map[int]bool{}
	for i := 0; i < len(p.Channels()); i++ {
		d, _ := p.Next()
		seen[d.Channel] = true
	}
	if len(seen) < 2 {
		t.Fatal("hopping did not resume after unlock")
	}
}

// TestLockedChannelDisappearing covers a regulatory change or adapter swap removing the
// locked channel: the plan must resume hopping rather than stall.
func TestLockedChannelDisappearing(t *testing.T) {
	p := NewChannelPlan([]nl80211.Frequency{{MHz: 2437, Channel: 6}}, nl80211.Band2GHz, PlanOptions{})
	if !p.Lock(2437) {
		t.Fatal("lock failed")
	}

	// Rebuild the plan without the locked channel, as a re-probe would.
	p.mu.Lock()
	p.entries = []planEntry{{freq: nl80211.Frequency{MHz: 2412, Channel: 1}, band: nl80211.Band2GHz, weight: SweepChannelWeight}}
	p.mu.Unlock()

	d, ok := p.Next()
	if !ok {
		t.Fatal("plan stalled after the locked channel vanished")
	}
	if d.Channel != 1 {
		t.Fatalf("expected to fall back to hopping, got channel %d", d.Channel)
	}
	if p.Locked() != 0 {
		t.Error("stale lock was not cleared")
	}
}

func TestDwellClamping(t *testing.T) {
	p := NewChannelPlan(testFreqs(), nl80211.Band2GHz, PlanOptions{
		BaseDwell: time.Second,
		MinDwell:  10 * time.Millisecond,
		MaxDwell:  1500 * time.Millisecond,
	})

	if !p.SetWeight(2437, 100) { // would be 100s unclamped
		t.Fatal("SetWeight failed")
	}
	if !p.SetWeight(2412, 0.0001) {
		t.Fatal("SetWeight failed")
	}
	if p.SetWeight(2437, 0) {
		t.Error("a non-positive weight should be rejected")
	}
	if p.SetWeight(9999, 2) {
		t.Error("SetWeight accepted a frequency not in the plan")
	}

	for _, c := range p.Channels() {
		if c.Duration > 1500*time.Millisecond {
			t.Errorf("channel %d dwell %v exceeds the maximum", c.Channel, c.Duration)
		}
		if c.Duration < 10*time.Millisecond {
			t.Errorf("channel %d dwell %v is below the minimum", c.Channel, c.Duration)
		}
	}
}

func TestCycleDuration(t *testing.T) {
	p := newTestPlan()
	p.PrioritiseChannels([]int{2437})

	// 3 sweep channels at 100ms + 1 scoped at 400ms.
	want := 3*100*time.Millisecond + time.Duration(float64(100*time.Millisecond)*ScopedChannelWeight)
	if got := p.CycleDuration(); got != want {
		t.Fatalf("CycleDuration = %v, want %v", got, want)
	}
}

func TestNewChannelPlanForDevice(t *testing.T) {
	dev := testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency,
		nl80211.Band2GHz, nl80211.Band5GHz)

	p, err := NewChannelPlanForDevice(dev, PlanOptions{})
	if err != nil {
		t.Fatalf("NewChannelPlanForDevice: %v", err)
	}
	if len(p.Channels()) != 2 {
		t.Fatalf("expected one channel per band, got %d", len(p.Channels()))
	}

	if _, err := NewChannelPlanForDevice(nil, PlanOptions{}); err == nil {
		t.Error("expected an error for a nil device")
	}
	empty := &Device{ID: "phy9", Phy: &nl80211.Wiphy{}}
	if _, err := NewChannelPlanForDevice(empty, PlanOptions{}); err == nil {
		t.Error("expected an error for an adapter with no usable channels")
	}
}

func TestChannelPolicyFiltersAndRandomises(t *testing.T) {
	dev := &Device{ID: "phy0", Phy: &nl80211.Wiphy{Bands: []nl80211.BandInfo{
		{Band: nl80211.Band2GHz, Freqs: []nl80211.Frequency{
			{MHz: 2412, Channel: 1}, {MHz: 2437, Channel: 6}, {MHz: 2462, Channel: 11},
		}},
		{Band: nl80211.Band5GHz, Freqs: []nl80211.Frequency{
			{MHz: 5180, Channel: 36}, {MHz: 5745, Channel: 149},
		}},
	}}}

	// Disable5GHz drops the 5 GHz channels.
	no5, err := NewChannelPlanForDevice(dev, PlanOptions{Disable5GHz: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(no5.Channels()); got != 3 {
		t.Errorf("5 GHz-off plan has %d channels, want the three 2.4 GHz ones", got)
	}

	// OnlyChannels restricts the sweep to a subset, across bands.
	only, err := NewChannelPlanForDevice(dev, PlanOptions{OnlyChannels: []int{1, 36}})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(only.Channels()); got != 2 {
		t.Errorf("only-{1,36} plan has %d channels, want 2", got)
	}

	// A selection that filters everything out is refused rather than leaving a dead sweep.
	if _, err := NewChannelPlanForDevice(dev, PlanOptions{OnlyChannels: []int{999}}); err == nil {
		t.Error("a plan selecting only an unreachable channel should be refused")
	}

	// Random still visits every channel over enough draws, and Adopt swaps a live plan's set.
	rnd, err := NewChannelPlanForDevice(dev, PlanOptions{Random: true})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]bool{}
	for i := 0; i < 200; i++ {
		d, ok := rnd.Next()
		if !ok {
			t.Fatal("random plan exhausted")
		}
		seen[d.Channel] = true
	}
	if len(seen) != 5 {
		t.Errorf("random hop visited %d of 5 channels over 200 draws", len(seen))
	}

	rnd.Adopt(only)
	if got := len(rnd.Channels()); got != 2 {
		t.Errorf("after Adopt the plan has %d channels, want the 2 it adopted", got)
	}
}

func TestEmptyPlanReportsExhaustion(t *testing.T) {
	p := NewChannelPlan(nil, nl80211.Band2GHz, PlanOptions{})
	if _, ok := p.Next(); ok {
		t.Fatal("an empty plan returned a dwell")
	}
}
