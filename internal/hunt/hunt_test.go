package hunt

import (
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/recon"
)

func testTarget(t *testing.T) Target {
	t.Helper()
	m, err := recon.ParseMAC("a4:2b:8c:11:22:33")
	if err != nil {
		t.Fatalf("ParseMAC: %v", err)
	}
	return Target{Addr: m, Channel: 6, Freq: 2437, RadioID: "phy1"}
}

func TestTracksCurrentAndPeak(t *testing.T) {
	s := NewSession(testTarget(t), false)
	now := time.Now()

	// Walking towards the target, then past it.
	for i, rssi := range []int8{-80, -70, -55, -42, -50, -65} {
		s.Observe(rssi, true, now.Add(time.Duration(i)*time.Second))
	}

	st := s.Snapshot()
	if st.Current != -65 {
		t.Errorf("Current = %d, want -65", st.Current)
	}
	if !st.HasPeak || st.Peak != -42 {
		t.Errorf("Peak = %d (has=%v), want -42", st.Peak, st.HasPeak)
	}
	if st.Packets != 6 {
		t.Errorf("Packets = %d, want 6", st.Packets)
	}
	if len(st.Sparkline) != 6 {
		t.Errorf("Sparkline has %d samples, want 6", len(st.Sparkline))
	}
}

// TestPeakAgeTellsTheOperatorTheyWalkedPast is the point of peak-hold: a falling current
// reading with an old peak means "you have gone too far".
func TestPeakAgeTellsTheOperatorTheyWalkedPast(t *testing.T) {
	s := NewSession(testTarget(t), false)
	base := time.Now()
	s.now = func() time.Time { return base.Add(30 * time.Second) }

	s.Observe(-42, true, base)
	s.Observe(-70, true, base.Add(20*time.Second))

	st := s.Snapshot()
	if st.Peak != -42 {
		t.Fatalf("Peak = %d, want -42", st.Peak)
	}
	if st.PeakAge < 29*time.Second {
		t.Errorf("PeakAge = %v, want about 30s", st.PeakAge)
	}
	if st.Current >= st.Peak {
		t.Error("current reading should be below the peak after walking past")
	}
}

// TestMissingRSSIDoesNotMoveTheGradient: a reading with no signal must not register as 0 dBm,
// which would read as the strongest possible value and send the operator the wrong way.
func TestMissingRSSIDoesNotMoveTheGradient(t *testing.T) {
	s := NewSession(testTarget(t), false)
	now := time.Now()

	s.Observe(-70, true, now)
	s.Observe(0, false, now.Add(time.Second)) // driver reported no signal

	st := s.Snapshot()
	if st.Current != -70 {
		t.Errorf("Current = %d, want -70; a signal-less reading was recorded", st.Current)
	}
	if st.Peak != -70 {
		t.Errorf("Peak = %d, want -70; a signal-less reading became the peak", st.Peak)
	}
	// It still counts as a packet: the target is demonstrably present.
	if st.Packets != 2 {
		t.Errorf("Packets = %d, want 2", st.Packets)
	}
	if len(st.Sparkline) != 1 {
		t.Errorf("Sparkline has %d samples, want 1", len(st.Sparkline))
	}
}

func TestResetPeak(t *testing.T) {
	s := NewSession(testTarget(t), false)
	now := time.Now()

	s.Observe(-42, true, now)
	if !s.Snapshot().HasPeak {
		t.Fatal("peak not recorded")
	}

	// Moving to a new area: the gradient should be measured from here, not against a peak
	// recorded two rooms ago.
	s.ResetPeak()
	if s.Snapshot().HasPeak {
		t.Error("peak survived a reset")
	}

	s.Observe(-75, true, now.Add(time.Second))
	if got := s.Snapshot().Peak; got != -75 {
		t.Errorf("Peak = %d, want -75 after reset", got)
	}
}

// TestStaleTargetIsReportedNotHidden: walking behind a wall stops the packets, and the
// operator needs to be told rather than shown a frozen reading.
func TestStaleTargetIsReportedNotHidden(t *testing.T) {
	s := NewSession(testTarget(t), false)
	base := time.Now()

	s.Observe(-50, true, base)

	s.now = func() time.Time { return base.Add(time.Second) }
	if st := s.Snapshot(); st.Stale || !st.HasSignal {
		t.Error("target reported stale too early")
	}

	s.now = func() time.Time { return base.Add(StaleAfter + time.Second) }
	st := s.Snapshot()
	if !st.Stale {
		t.Error("target not reported stale after the timeout")
	}
	if st.HasSignal {
		t.Error("a stale target should not report a live signal")
	}
	if !strings.Contains(st.Describe(), "lost or stopped") {
		t.Errorf("Describe should say the target was lost: %q", st.Describe())
	}
}

func TestPacketsPerSecond(t *testing.T) {
	s := NewSession(testTarget(t), false)
	base := time.Now()

	// Twenty packets over four seconds: two full rate windows.
	for i := 0; i < 20; i++ {
		s.Observe(-60, true, base.Add(time.Duration(i)*200*time.Millisecond))
	}

	st := s.Snapshot()
	if st.PacketsPerSec <= 0 {
		t.Fatalf("PacketsPerSec = %v, want a positive rate", st.PacketsPerSec)
	}
	if st.PacketsPerSec < 3 || st.PacketsPerSec > 8 {
		t.Errorf("PacketsPerSec = %.1f, want roughly 5", st.PacketsPerSec)
	}
}

func TestSparklineIsBounded(t *testing.T) {
	s := NewSession(testTarget(t), false)
	now := time.Now()

	for i := 0; i < SparklineLen*3; i++ {
		s.Observe(int8(-90+i%40), true, now.Add(time.Duration(i)*time.Millisecond))
	}

	if got := len(s.Snapshot().Sparkline); got != SparklineLen {
		t.Errorf("Sparkline length = %d, want %d", got, SparklineLen)
	}
}

// TestBeepRateTracksSignal: faster is stronger, so the operator can walk the gradient without
// looking at the screen.
func TestBeepRateTracksSignal(t *testing.T) {
	weak := beepInterval(-85)
	mid := beepInterval(-60)
	strong := beepInterval(-35)

	if !(weak > mid && mid > strong) {
		t.Errorf("beep interval should shorten as signal strengthens: %v, %v, %v", weak, mid, strong)
	}
	if strong < minBeepInterval || weak > maxBeepInterval {
		t.Errorf("beep interval out of bounds: %v..%v", strong, weak)
	}

	// Values beyond the mapped range clamp rather than run away.
	if got := beepInterval(-127); got != maxBeepInterval {
		t.Errorf("beepInterval(-127) = %v, want the maximum", got)
	}
	if got := beepInterval(0); got != minBeepInterval {
		t.Errorf("beepInterval(0) = %v, want the minimum", got)
	}
}

func TestAudibleCueOnlyWhenEnabled(t *testing.T) {
	silent := NewSession(testTarget(t), false)
	silent.Observe(-50, true, time.Now())
	if silent.Snapshot().BeepInterval != 0 {
		t.Error("silent session produced a beep interval")
	}

	loud := NewSession(testTarget(t), true)
	loud.Observe(-50, true, time.Now())
	if loud.Snapshot().BeepInterval == 0 {
		t.Error("audible session produced no beep interval")
	}
}

func TestSparklineRendering(t *testing.T) {
	if got := Sparkline(nil); got != "" {
		t.Errorf("empty sparkline = %q", got)
	}

	rendered := Sparkline([]int8{-90, -70, -50, -30})
	if len([]rune(rendered)) != 4 {
		t.Fatalf("rendered %d runes, want 4: %q", len([]rune(rendered)), rendered)
	}
	// Scaled to the observed range, so the weakest is the lowest block and the strongest the
	// highest.
	runes := []rune(rendered)
	if runes[0] != '▁' || runes[3] != '█' {
		t.Errorf("sparkline = %q, want it to span the full block range", rendered)
	}

	// A flat series must not divide by zero.
	if got := Sparkline([]int8{-60, -60, -60}); len([]rune(got)) != 3 {
		t.Errorf("flat sparkline = %q", got)
	}
}

func TestBarRendering(t *testing.T) {
	if got := Bar(-90, 10); got != strings.Repeat("░", 10) {
		t.Errorf("weakest bar = %q", got)
	}
	if got := Bar(-30, 10); got != strings.Repeat("█", 10) {
		t.Errorf("strongest bar = %q", got)
	}
	if got := len([]rune(Bar(-60, 10))); got != 10 {
		t.Errorf("bar width = %d, want 10", got)
	}
	if got := Bar(-60, 0); got != "" {
		t.Errorf("zero-width bar = %q", got)
	}
}

func TestDescribeBeforeFirstPacket(t *testing.T) {
	s := NewSession(testTarget(t), false)
	if !strings.Contains(s.Snapshot().Describe(), "waiting") {
		t.Errorf("Describe = %q, want it to say it is waiting", s.Snapshot().Describe())
	}
}
