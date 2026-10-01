package radio

import (
	"context"
	"fmt"
	"time"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// WaitForReenumeration blocks until the interface named ifname has come back after a USB reset, or
// the timeout elapses. A USBDEVFS_RESET drops the netdev and re-creates it, so "the interface is
// present" is not enough on its own - right after the reset the *old* netdev may still be visible for
// a moment. Re-enumeration reassigns the kernel interface index, so this waits for an interface named
// ifname whose index differs from oldIfindex, which is the proof the cycle actually happened.
func WaitForReenumeration(ctx context.Context, ifname string, oldIfindex uint32, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if idx, ok := currentIfindex(ifname); ok && idx != oldIfindex {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("radio: %s did not re-enumerate within %s after the reset "+
				"(still absent or unchanged)", ifname, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// currentIfindex reads the kernel index of the interface named ifname over nl80211, or ok=false if
// no such interface is present.
func currentIfindex(ifname string) (uint32, bool) {
	conn, err := nl80211.Dial()
	if err != nil {
		return 0, false
	}
	defer conn.Close()
	ifaces, err := conn.Interfaces()
	if err != nil {
		return 0, false
	}
	for _, f := range ifaces {
		if f.Name == ifname {
			return f.Index, true
		}
	}
	return 0, false
}

// ReprobeDeviceByIfname rebinds the managed device currently backing ifname to the phy that now
// carries it, in place. A USB reset (or a spontaneous re-enumeration on a flaky bus) re-creates the
// phy under a new index and name while preserving the interface name, so the device is located by
// ifname (the stable anchor) and its ID, Phy, Ifindex and MAC are refreshed from a fresh enumeration.
// Any ID-keyed scheduler state (the enabled flag, the survey pin, and any live handles) is migrated to
// the new ID, so the card keeps its settings and a running capture's handle stays consistent.
//
// The device pointer is preserved, so every holder of it - including a live capture runner's handle -
// picks up the refreshed fields; this is what lets a transient USB drop self-heal rather than
// stranding the radio on a dead interface index. Injection status is left as it was: the same silicon
// injects the same way after a power-cycle, and re-testing it is a separate action.
func (s *Scheduler) ReprobeDeviceByIfname(ctx context.Context, ifname string) (*Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := nl80211.Dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	phys, err := conn.Wiphys()
	if err != nil {
		return nil, err
	}
	ifaces, err := conn.Interfaces()
	if err != nil {
		return nil, err
	}

	var iface *nl80211.Interface
	for _, f := range ifaces {
		if f.Name == ifname {
			iface = f
			break
		}
	}
	if iface == nil {
		return nil, fmt.Errorf("radio: interface %q is not present after the reset", ifname)
	}
	var phy *nl80211.Wiphy
	for _, p := range phys {
		if p.Index == iface.Wiphy {
			phy = p
			break
		}
	}
	if phy == nil {
		return nil, fmt.Errorf("radio: no phy backs interface %q after the reset", ifname)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var dev *Device
	for _, d := range s.devices {
		if d.Ifname == ifname {
			dev = d
			break
		}
	}
	if dev == nil {
		return nil, fmt.Errorf("radio: no managed adapter is on interface %q", ifname)
	}

	oldID := dev.ID
	newID := phy.Name

	dev.ID = newID
	dev.Phy = phy
	dev.Ifindex = iface.Index
	if iface.MAC != nil {
		dev.MAC = iface.MAC.String()
	}
	dev.Driver = driverName(newID)

	if oldID != newID {
		if s.disabled[oldID] {
			delete(s.disabled, oldID)
			s.disabled[newID] = true
		}
		if s.surveyDevice == oldID {
			s.surveyDevice = newID
		}
		if h, ok := s.assigned[oldID]; ok { // a live capture's handle moves with the rebind
			s.assigned[newID] = h
			delete(s.assigned, oldID)
		}
	}
	sortDevices(s.devices)
	return dev, nil
}
