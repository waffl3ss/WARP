package radio

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// sysfsIEEE80211 is where the kernel exposes per-phy attributes not available over nl80211,
// notably the driver name and rfkill state.
const sysfsIEEE80211 = "/sys/class/ieee80211"

// DiscoverOptions controls adapter selection.
type DiscoverOptions struct {
	// Only restricts discovery to these interface names (`--radios wlan0,wlan1`). Empty means
	// every capable adapter.
	Only []string
	// RequireMonitor skips adapters that cannot enter monitor mode. On by default in practice:
	// an adapter that cannot monitor is useless for every role except the rogue AP.
	RequireMonitor bool
}

// RFKillState is the rfkill status of an adapter.
type RFKillState struct {
	// Soft is a software block, clearable with `rfkill unblock`.
	Soft bool `json:"soft"`
	// Hard is a physical switch or firmware block, which WARP cannot clear.
	Hard bool `json:"hard"`
	// Known is false when no rfkill node was found for the adapter.
	Known bool `json:"known"`
}

// Blocked reports whether the adapter is currently unusable.
func (r RFKillState) Blocked() bool { return r.Soft || r.Hard }

func (r RFKillState) String() string {
	switch {
	case !r.Known:
		return "unknown"
	case r.Hard:
		return "hard-blocked"
	case r.Soft:
		return "soft-blocked"
	default:
		return "unblocked"
	}
}

// Discovery is the full result of a capability probe, including adapters that were rejected.
//
// Rejected adapters are reported rather than dropped: "WARP only sees one radio" is a
// question the operator will ask on site, and the answer needs to be in the output.
type Discovery struct {
	Devices  []*Device        `json:"devices"`
	Excluded []ExcludedDevice `json:"excluded,omitempty"`
}

// ExcludedDevice is an adapter that was found but not used, and why.
type ExcludedDevice struct {
	ID     string `json:"id"`
	Ifname string `json:"ifname,omitempty"`
	Reason string `json:"reason"`
}

// Discover enumerates wireless adapters and probes their capabilities.
//
// This is the Phase 1 gate: nothing above this package is trustworthy until a real phy
// enumerates here with correct bands, interface modes and interface combinations. It does not
// require privileges - enumeration is readable by any user - so the probe can be run and its
// output compared against `iw list` before anything is reconfigured.
//
// Injection is deliberately left Unverified. The capability bitmap lies on several common
// chipsets, so the only honest answer before an empirical test is "not yet demonstrated".
func Discover(ctx context.Context, opts DiscoverOptions) (*Discovery, error) {
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

	// Pick one netdev per phy. Prefer a managed interface, which is what the distro brings up
	// by default and therefore what the operator names on the command line.
	primary := make(map[uint32]*nl80211.Interface)
	for _, iface := range ifaces {
		cur, ok := primary[iface.Wiphy]
		if !ok || (cur.Iftype != nl80211.IftypeStation && iface.Iftype == nl80211.IftypeStation) {
			primary[iface.Wiphy] = iface
		}
	}

	only := make(map[string]struct{}, len(opts.Only))
	for _, name := range opts.Only {
		if name = strings.TrimSpace(name); name != "" {
			only[name] = struct{}{}
		}
	}

	out := &Discovery{}
	for _, phy := range phys {
		dev := &Device{
			ID:        phy.Name,
			Phy:       phy,
			Injection: InjectionUnverified,
			Driver:    driverName(phy.Name),
		}
		if iface, ok := primary[phy.Index]; ok {
			dev.Ifname = iface.Name
			dev.Ifindex = iface.Index
			if iface.MAC != nil {
				dev.MAC = iface.MAC.String()
			}
		}

		if len(only) > 0 {
			if _, selected := only[dev.Ifname]; !selected {
				if _, selected := only[dev.ID]; !selected {
					out.Excluded = append(out.Excluded, ExcludedDevice{
						ID: dev.ID, Ifname: dev.Ifname, Reason: "not listed in --radios",
					})
					continue
				}
			}
		}
		if opts.RequireMonitor && !phy.SupportsIftype(nl80211.IftypeMonitor) {
			out.Excluded = append(out.Excluded, ExcludedDevice{
				ID: dev.ID, Ifname: dev.Ifname, Reason: "adapter does not support monitor mode",
			})
			continue
		}
		if rf := RFKill(phy.Name); rf.Blocked() {
			out.Excluded = append(out.Excluded, ExcludedDevice{
				ID: dev.ID, Ifname: dev.Ifname,
				Reason: fmt.Sprintf("adapter is %s (see `rfkill list`)", rf),
			})
			continue
		}

		out.Devices = append(out.Devices, dev)
	}

	// A name in --radios that matched nothing is almost certainly a typo, and silently
	// operating with fewer radios than the operator asked for is exactly the kind of thing
	// nobody notices until the data is thin.
	for name := range only {
		found := false
		for _, d := range out.Devices {
			if d.Ifname == name || d.ID == name {
				found = true
				break
			}
		}
		if !found {
			var present []string
			for _, d := range out.Devices {
				present = append(present, d.Ifname)
			}
			for _, e := range out.Excluded {
				if e.Ifname != "" {
					present = append(present, e.Ifname)
				}
			}
			return out, fmt.Errorf("radio: --radios named %q, which is not a wireless interface on this host (found: %s)",
				name, strings.Join(present, ", "))
		}
	}

	sortDevices(out.Devices)
	return out, nil
}

// driverName reads the kernel driver backing a phy, e.g. "mt76x2u" or "ath9k_htc".
//
// Capability varies enormously by chipset, so a hardware validation record is close to
// meaningless without it. Returns "" when it cannot be determined.
func driverName(phyName string) string {
	link, err := os.Readlink(filepath.Join(sysfsIEEE80211, phyName, "device", "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

// RFKill reports the rfkill state of a phy.
//
// Read from sysfs rather than /dev/rfkill: it needs no privileges and no ioctls, and a
// soft-blocked adapter that silently captures nothing is a genuinely confusing failure to
// debug on site.
func RFKill(phyName string) RFKillState {
	matches, err := filepath.Glob(filepath.Join(sysfsIEEE80211, phyName, "rfkill*"))
	if err != nil || len(matches) == 0 {
		return RFKillState{}
	}

	state := RFKillState{Known: true}
	for _, dir := range matches {
		if readSysfsFlag(filepath.Join(dir, "soft")) {
			state.Soft = true
		}
		if readSysfsFlag(filepath.Join(dir, "hard")) {
			state.Hard = true
		}
	}
	return state
}

func readSysfsFlag(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}
