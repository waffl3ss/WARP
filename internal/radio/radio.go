// Package radio owns every wireless adapter WARP touches.
//
// Modules never name an interface. They request a *role* from the Scheduler and receive a
// Handle. This is what makes the tool work unchanged across a two-adapter laptop and a
// six-adapter NUC, and it is why no interface name appears anywhere outside this package.
package radio

import (
	"fmt"
	"sort"
	"strings"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// Role is what a module needs a radio *for*. Roles are requested; interfaces are assigned.
type Role string

// Roles. Each maps to an interface type and a set of capability requirements.
const (
	// RoleSurvey is pinned to one adapter for the entire engagement. RSSI is not comparable
	// across chipsets or antennas, so a survey that hops adapters produces a coverage picture
	// that looks correct and means nothing.
	RoleSurvey Role = "survey"
	// RoleRecon passively parses beacons, probes and data frames.
	RoleRecon Role = "recon"
	// RoleSolicit injects association requests to elicit PMKIDs.
	RoleSolicit Role = "solicit"
	// RoleRogue runs the rogue AP.
	RoleRogue Role = "rogue"
	// RoleClient is an 802.1X supplicant used for certificate harvesting.
	RoleClient Role = "client"
	// RoleDeauth transmits deauthentication frames.
	RoleDeauth Role = "deauth"
	// RoleHunt locks to one channel for direction finding.
	RoleHunt Role = "hunt"
)

// AllRoles is every role, in a stable order for display.
var AllRoles = []Role{RoleSurvey, RoleRecon, RoleSolicit, RoleRogue, RoleClient, RoleDeauth, RoleHunt}

// RoleSpec describes what a role needs from hardware.
type RoleSpec struct {
	// Iftype is the interface type the adapter must be placed in.
	Iftype nl80211.Iftype
	// NeedsInjection means the role transmits raw frames, so the adapter's injection
	// capability must have been *empirically* verified - the capability bitmap lies on
	// several common chipsets.
	NeedsInjection bool
	// Pinned means the assignment is held for the whole engagement and never reassigned.
	Pinned bool
	// ChannelLocked means the role holds one channel rather than hopping, so the scheduler
	// must not also run a hopping role on the same device.
	ChannelLocked bool

	// Borrowable means the role can run on an interface another role already owns, when no
	// adapter is free. Short bursts qualify; anything that holds a radio for minutes does not.
	//
	// This is what keeps a single-adapter kit fully capable: soliciting a PMKID borrows the
	// capture radio for a second rather than being refused.
	Borrowable bool
	// Lendable means this role's interface may be borrowed by a Borrowable role.
	//
	// Survey is deliberately not lendable: it is pinned for the engagement so its observations
	// stay comparable, and interrupting it would put gaps in the coverage picture at exactly
	// the moments the operator was doing something worth recording.
	Lendable bool

	// Description is operator-facing.
	Description string
}

// roleSpecs is the single source of truth for role requirements.
var roleSpecs = map[Role]RoleSpec{
	RoleSurvey: {
		Iftype:      nl80211.IftypeMonitor,
		Pinned:      true,
		Description: "walkthrough RSSI observations - pinned to one adapter for the engagement",
	},
	RoleRecon: {
		Iftype: nl80211.IftypeMonitor,
		// Recon is the natural lender: it hops channels continuously, so pausing it for the
		// length of a burst costs a fraction of one dwell.
		Lendable:    true,
		Description: "passive beacon/probe/data frame parsing",
	},
	RoleSolicit: {
		Iftype:         nl80211.IftypeMonitor,
		NeedsInjection: true,
		Borrowable:     true,
		Description:    "PMKID solicitation via association requests",
	},
	RoleDeauth: {
		Iftype:         nl80211.IftypeMonitor,
		NeedsInjection: true,
		Borrowable:     true,
		Description:    "targeted deauthentication",
	},
	RoleHunt: {
		Iftype:        nl80211.IftypeMonitor,
		ChannelLocked: true,
		// Hunt can borrow, but doing so stops recon for as long as the operator is walking
		// the gradient. That is the right trade on one adapter - direction finding is the
		// task in hand - and the operator is told it is happening.
		Borrowable:  true,
		Description: "direction finding - locks to the target's channel",
	},
	RoleRogue: {
		Iftype:        nl80211.IftypeAP,
		ChannelLocked: true,
		Description:   "rogue AP (scoped ESSIDs only)",
	},
	RoleClient: {
		Iftype:        nl80211.IftypeStation,
		ChannelLocked: true,
		Description:   "802.1X supplicant for certificate harvesting",
	},
}

// Spec returns the hardware requirements for a role.
func (r Role) Spec() (RoleSpec, bool) {
	s, ok := roleSpecs[r]
	return s, ok
}

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	_, ok := roleSpecs[r]
	return ok
}

// InjectionStatus records what we actually know about an adapter's ability to inject.
//
// The brief is explicit that injection must be verified empirically rather than read from
// the capability bitmap, which lies on several common chipsets. "Unverified" is therefore a
// distinct state from "capable".
//
// The four states are not three plus a shrug. There is a real difference between *the driver
// refused the write* and *the driver accepted the write but we never saw the frame come
// back*, and treating them the same refuses to transmit on adapters that inject perfectly
// well - plenty of drivers simply do not loop transmitted frames to their own monitor
// socket. The second case is inconclusive, not a failure, and is allowed to transmit with
// the uncertainty recorded rather than being locked out.
type InjectionStatus int

// Injection statuses.
const (
	// InjectionUnverified means no empirical test has been run. Not the same as capable.
	InjectionUnverified InjectionStatus = iota
	// InjectionVerified means a frame was injected and observed coming back.
	InjectionVerified
	// InjectionFailed means the driver rejected the frame. This adapter cannot inject.
	InjectionFailed
	// InjectionInconclusive means the driver accepted the frame but it was never observed.
	// The adapter probably injects; the loopback observation is what is missing.
	InjectionInconclusive
)

func (s InjectionStatus) String() string {
	switch s {
	case InjectionVerified:
		return "verified"
	case InjectionFailed:
		return "failed"
	case InjectionInconclusive:
		return "inconclusive"
	default:
		return "untested"
	}
}

// CanTransmit reports whether a transmitting role may be assigned to this status.
//
// Inconclusive counts: the kernel took the frame, which is most of the evidence. What is
// missing is only the loopback confirmation, and refusing to work on that basis makes WARP
// useless on a large fraction of otherwise fine adapters.
func (s InjectionStatus) CanTransmit() bool {
	return s == InjectionVerified || s == InjectionInconclusive
}

// MarshalJSON renders the status as its name so operator-facing JSON is self-explaining.
func (s InjectionStatus) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// Device is one physical wireless adapter (an nl80211 wiphy) plus what WARP has learned
// about it.
type Device struct {
	// ID is the stable identifier stamped on every observation, so that a mixed-radio
	// coverage picture is detectable at query time rather than being silently averaged.
	ID string `json:"id"`
	// Phy is the parsed capability set.
	Phy *nl80211.Wiphy `json:"phy"`
	// Ifname is the netdev currently backing this device.
	Ifname string `json:"ifname"`
	// Ifindex is the kernel index of that netdev.
	Ifindex uint32 `json:"ifindex"`
	// MAC is the adapter's hardware address.
	MAC string `json:"mac,omitempty"`
	// Driver is the kernel driver name, where it could be determined.
	Driver string `json:"driver,omitempty"`
	// Injection is what the empirical probe found.
	Injection InjectionStatus `json:"injection"`
	// InjectionNote records how the conclusion was reached, for the hardware validation
	// record.
	InjectionNote string `json:"injection_note,omitempty"`
}

// SupportsRole reports whether the device could host the role in isolation, and why not if
// it cannot. The returned reason is operator-facing.
func (d *Device) SupportsRole(r Role) (bool, string) {
	spec, ok := roleSpecs[r]
	if !ok {
		return false, fmt.Sprintf("unknown role %q", r)
	}
	if d.Phy == nil {
		return false, "no capability information for this adapter"
	}
	if !d.Phy.SupportsIftype(spec.Iftype) {
		return false, fmt.Sprintf("adapter does not support %s mode", spec.Iftype)
	}
	if spec.NeedsInjection && !d.Injection.CanTransmit() {
		switch d.Injection {
		case InjectionFailed:
			return false, "the driver rejected an injected frame on this adapter: " + d.InjectionNote
		default:
			return false, "injection has not been tested on this adapter - start warpd " +
				"without --skip-injection-test, or pass --assume-injection if you have " +
				"confirmed it elsewhere"
		}
	}
	return true, ""
}

// Bands returns the band names the device supports, whether or not it may currently transmit on
// them. A band that is present but has no transmit-usable channel (every channel NoIR - the
// country-00 / world regulatory domain case) is suffixed " (no-tx: set reg domain)" so it is clear
// the card *reaches* the band and can still listen there; it just cannot transmit until a
// regulatory domain is set (`iw reg set <cc>`). This is not a limit of the adapter - injection is
// reported separately and is verified on 2.4 GHz - it is the regulatory domain forbidding it.
func (d *Device) Bands() []string {
	if d.Phy == nil {
		return nil
	}
	var out []string
	for _, b := range []nl80211.Band{nl80211.Band2GHz, nl80211.Band5GHz, nl80211.Band6GHz, nl80211.Band60GHz} {
		if !d.Phy.SupportsBand(b) {
			continue
		}
		label := b.String()
		if d.Phy.ReceiveOnlyBand(b) {
			label += " (no-tx: set reg domain)"
		}
		out = append(out, label)
	}
	return out
}

// Summary is a one-line operator-facing description, for `warp radios list`.
func (d *Device) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%s)", d.ID, d.Ifname)
	if d.Driver != "" {
		fmt.Fprintf(&b, " %s", d.Driver)
	}
	if bands := d.Bands(); len(bands) > 0 {
		fmt.Fprintf(&b, " bands=%s", strings.Join(bands, "/"))
	}
	fmt.Fprintf(&b, " injection=%s", d.Injection)
	if d.Phy != nil && d.Phy.SupportsAPMonitorConcurrent() {
		b.WriteString(" ap+monitor")
	}
	return b.String()
}

// RoleCapability reports, per role, whether this device could serve it.
type RoleCapability struct {
	Role      Role   `json:"role"`
	Capable   bool   `json:"capable"`
	Reason    string `json:"reason,omitempty"`
	Iftype    string `json:"iftype"`
	Pinned    bool   `json:"pinned,omitempty"`
	Describes string `json:"description"`
}

// Capabilities returns the per-role capability table for this device.
func (d *Device) Capabilities() []RoleCapability {
	out := make([]RoleCapability, 0, len(AllRoles))
	for _, r := range AllRoles {
		spec, _ := r.Spec()
		ok, reason := d.SupportsRole(r)
		out = append(out, RoleCapability{
			Role:      r,
			Capable:   ok,
			Reason:    reason,
			Iftype:    spec.Iftype.String(),
			Pinned:    spec.Pinned,
			Describes: spec.Description,
		})
	}
	return out
}

// sortDevices orders devices by phy index so output is stable across runs. Operators compare
// `warp radios list` against `iw list` by eye; unstable ordering makes that miserable.
func sortDevices(devs []*Device) {
	sort.Slice(devs, func(i, j int) bool {
		if devs[i].Phy == nil || devs[j].Phy == nil {
			return devs[i].ID < devs[j].ID
		}
		return devs[i].Phy.Index < devs[j].Phy.Index
	})
}
