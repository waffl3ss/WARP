package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// countingAcquirer fails its first failN Acquire calls, then succeeds, counting every call.
type countingAcquirer struct {
	stubAcquirer
	calls int
	failN int
}

func (c *countingAcquirer) Acquire(_ context.Context, dev *radio.Device, ift nl80211.Iftype) (*radio.Acquisition, error) {
	c.calls++
	if c.calls <= c.failN {
		return nil, errors.New("stub: set monitor mode: no such device")
	}
	return &radio.Acquisition{Device: dev, Iftype: ift}, nil
}

func testScheduler(t *testing.T) *radio.Scheduler {
	t.Helper()
	s, err := radio.NewScheduler([]*radio.Device{
		fakeDevice("phy0", 0, []nl80211.Iftype{nl80211.IftypeStation, nl80211.IftypeMonitor}, radio.InjectionVerified),
	}, quietLogger())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	return s
}

// TestAcquireReconcilingPassesThroughOnSuccess: no failure means one Acquire and no reconcile.
func TestAcquireReconcilingPassesThroughOnSuccess(t *testing.T) {
	sched := testScheduler(t)
	acq := &countingAcquirer{}
	dev := sched.Devices()[0]

	a, err := acquireReconciling(context.Background(), sched, acq, dev, nl80211.IftypeMonitor)
	if err != nil || a == nil {
		t.Fatalf("acquireReconciling = %v, %v; want success", a, err)
	}
	if acq.calls != 1 {
		t.Errorf("Acquire called %d times, want 1 (no reconcile on success)", acq.calls)
	}
}

// TestAcquireReconcilingSurfacesErrorWithoutReenumeration: when the adapter has not re-enumerated
// (the interface index is unchanged, or cannot be re-resolved), the original error stands and the
// acquirer is not retried - a failure that is not a re-enumeration must not be masked or looped.
func TestAcquireReconcilingSurfacesErrorWithoutReenumeration(t *testing.T) {
	sched := testScheduler(t)
	acq := &countingAcquirer{failN: 1}
	dev := sched.Devices()[0]

	_, err := acquireReconciling(context.Background(), sched, acq, dev, nl80211.IftypeMonitor)
	if err == nil {
		t.Fatal("acquireReconciling succeeded; want the original error surfaced")
	}
	if acq.calls != 1 {
		t.Errorf("Acquire called %d times, want 1 (no retry without a proven re-enumeration)", acq.calls)
	}
}
