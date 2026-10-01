package daemon

import (
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/recon"
)

// TestWatchHuntFiltersByRadioAndTarget: the borrowed-hunt tap must deliver only frames involving
// the hunted target and seen on the radio the hunt locked. A frame on another radio (survey, on a
// different channel and chipset) or involving another device must not reach the session - mixing
// them would corrupt the gradient (invariant 5).
func TestWatchHuntFiltersByRadioAndTarget(t *testing.T) {
	e := &Engine{}

	target := mustMAC(t, "aa:bb:cc:dd:ee:ff")
	other := mustMAC(t, "11:22:33:44:55:66")
	now := time.Now()

	obs, stop := e.WatchHunt(target, "phy1")
	defer stop()

	// Matching: target frame on the hunt radio.
	e.notifyHunt(&recon.Frame{Addr1: target}, "phy1", -50, true, now)
	// Wrong radio: same target, but on the survey card.
	e.notifyHunt(&recon.Frame{Addr1: target}, "phy2", -30, true, now)
	// Wrong target: another device on the hunt radio.
	e.notifyHunt(&recon.Frame{Addr1: other}, "phy1", -40, true, now)
	// Matching again, target as the transmitter (Addr2).
	e.notifyHunt(&recon.Frame{Addr2: target}, "phy1", -55, true, now)

	got := drain(obs)
	if len(got) != 2 {
		t.Fatalf("got %d readings, want 2 (only the target on the hunt radio)", len(got))
	}
	if got[0].signalDBM != -50 || got[1].signalDBM != -55 {
		t.Errorf("delivered the wrong readings: %+v", got)
	}
}

// TestWatchHuntStopEndsDelivery: after stop, no further readings are delivered and the hot-path
// guard returns to zero so an ordinary run pays nothing.
func TestWatchHuntStopEndsDelivery(t *testing.T) {
	e := &Engine{}
	target := mustMAC(t, "aa:bb:cc:dd:ee:ff")

	obs, stop := e.WatchHunt(target, "phy1")
	e.notifyHunt(&recon.Frame{Addr1: target}, "phy1", -50, true, time.Now())
	stop()

	if e.huntWatcherN.Load() != 0 {
		t.Errorf("the hunt-watcher guard is %d after stop, want 0", e.huntWatcherN.Load())
	}
	// Delivering after stop is a no-op (the guard short-circuits before any locking).
	e.notifyHunt(&recon.Frame{Addr1: target}, "phy1", -60, true, time.Now())

	got := drain(obs)
	if len(got) != 1 || got[0].signalDBM != -50 {
		t.Errorf("readings after stop leaked or the pre-stop reading was lost: %+v", got)
	}
}

func drain(ch <-chan huntObservation) []huntObservation {
	var out []huntObservation
	for {
		select {
		case o, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, o)
		default:
			return out
		}
	}
}

func mustMAC(t *testing.T, s string) recon.MAC {
	t.Helper()
	m, err := recon.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return m
}
