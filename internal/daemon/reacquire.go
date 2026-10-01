package daemon

import (
	"context"

	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// Auto-reconcile on a re-enumerated adapter.
//
// A USB Wi-Fi adapter on a flaky bus (a hub, or USB passthrough into a VM - both common in the field)
// can drop off and come back on its own. The kernel destroys the old netdev and builds a fresh one:
// the interface *name* usually returns (so `iwconfig` shows it), but it has a new interface index and
// a new phy. Every low-level call WARP makes is by the cached index, so once a card re-enumerates,
// binding the capture socket and setting the interface mode both fail with ENODEV ("no such device")
// against an index that no longer exists - and retrying the same dead index never recovers.
//
// The fix is to notice a re-enumeration and rebind: re-resolve the interface by its (stable) name to
// the current index and phy, then retry once. We gate the retry on the index having actually changed
// rather than on matching a specific errno, which is both robust to how the netlink layer wraps the
// error and precise: if nothing re-enumerated, the original failure (rfkill, a real refusal) is
// surfaced unchanged instead of being masked by a pointless retry.

// acquireReconciling acquires an adapter into iftype, and if that fails because the adapter has
// re-enumerated (its interface index moved), rebinds to the fresh phy and retries once.
func acquireReconciling(ctx context.Context, sched *radio.Scheduler, acq radio.Acquirer,
	dev *radio.Device, iftype nl80211.Iftype) (*radio.Acquisition, error) {
	a, err := acq.Acquire(ctx, dev, iftype)
	if err == nil {
		return a, nil
	}
	if reenumerated(ctx, sched, dev) {
		return acq.Acquire(ctx, dev, iftype)
	}
	return a, err
}

// acquireStationReconciling is acquireReconciling for the kernel-driven association path (PMKID
// solicitation, certificate harvest, WPS).
func acquireStationReconciling(ctx context.Context, sched *radio.Scheduler, acq radio.Acquirer,
	dev *radio.Device, params nl80211.ConnectParams) (*radio.Acquisition, error) {
	a, err := acq.AcquireStation(ctx, dev, params)
	if err == nil {
		return a, nil
	}
	if reenumerated(ctx, sched, dev) {
		return acq.AcquireStation(ctx, dev, params)
	}
	return a, err
}

// reenumerated rebinds dev to the interface it names and reports whether that changed the interface
// index - the proof the adapter dropped and came back. On a rebind failure (the interface is still
// absent mid-re-enumeration) it reports false, leaving the caller's original error to stand.
func reenumerated(ctx context.Context, sched *radio.Scheduler, dev *radio.Device) bool {
	old := dev.Ifindex
	if _, err := sched.ReprobeDeviceByIfname(ctx, dev.Ifname); err != nil {
		return false
	}
	return dev.Ifindex != old
}
