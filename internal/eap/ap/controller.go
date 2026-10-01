// Package ap controls the rogue access point.
//
// hostapd is the one permitted external dependency, and it sits behind the APController
// interface so a native nl80211 implementation can replace it without touching a single
// caller. Do not attempt native AP mode before Phase 4: it requires beacon construction,
// probe/auth/assoc response handling and management-frame registration over nl80211 -
// roughly what hostapd already does - and attempting it early stalls the project.
package ap

import (
	"context"
	"time"
)

// Event is something the access point reports.
type Event struct {
	Kind string    `json:"kind"`
	Text string    `json:"text"`
	MAC  string    `json:"mac,omitempty"`
	At   time.Time `json:"at"`
}

// Event kinds.
const (
	EventStarted     = "started"
	EventStopped     = "stopped"
	EventClientJoin  = "client-join"
	EventClientLeave = "client-leave"
	EventEAPStarted  = "eap-started"
	EventError       = "error"
)

// Client is a station associated with the rogue access point.
type Client struct {
	MAC      string    `json:"mac"`
	Since    time.Time `json:"since"`
	AuthOK   bool      `json:"authenticated"`
	LastSeen time.Time `json:"last_seen"`
}

// Config describes the access point to bring up.
//
// There is deliberately no field for an arbitrary ESSID list, no karma toggle and no
// known-beacon list. The rogue AP beacons exactly one ESSID, and the scope gate must have
// authorized it: responding to arbitrary probes would impersonate networks outside the SoW.
type Config struct {
	// Interface to run the access point on. Supplied by the radio scheduler.
	Interface string
	// ESSID to beacon. Must be present in scope.txt - the caller is responsible for having
	// cleared it with the scope gate, and the gate refuses anything else.
	ESSID string
	// Channel to operate on.
	Channel int
	// BSSID overrides the adapter's own address, when set.
	BSSID string

	// RADIUSAddr and RADIUSPort point hostapd at WARP's own RADIUS server.
	RADIUSAddr string
	RADIUSPort int
	// RADIUSSecret is shared with that server.
	RADIUSSecret string

	// CountryCode sets the regulatory domain.
	CountryCode string
	// HWMode is hostapd's mode letter: g for 2.4 GHz, a for 5 GHz.
	HWMode string
}

// APController is the interface every access point backend satisfies.
//
// Keeping this narrow is what makes the hostapd dependency replaceable: a native nl80211
// implementation needs to provide exactly these four operations and nothing else.
type APController interface {
	// Start brings the access point up.
	Start(ctx context.Context, cfg Config) error
	// Stop tears it down and restores the interface.
	Stop(ctx context.Context) error
	// Clients returns the currently associated stations.
	Clients() []Client
	// Events streams what the access point reports.
	Events() <-chan Event
}
