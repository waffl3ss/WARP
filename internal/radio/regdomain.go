package radio

import (
	"context"
	"fmt"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// GetRegDomain returns the kernel's current regulatory domain as an ISO 3166-1 alpha-2 country
// code. "00" is the world/unset domain, under which the upper bands are receive-only (NoIR).
func GetRegDomain() (string, error) {
	conn, err := nl80211.Dial()
	if err != nil {
		return "", err
	}
	defer conn.Close()
	return conn.GetRegDomain()
}

// SetRegDomain requests a regulatory-domain change. The kernel applies it asynchronously; callers
// that need the new channel flags should re-probe (see Scheduler.RefreshRegulatory) after a moment.
// Requires CAP_NET_ADMIN.
func SetRegDomain(cc string) error {
	conn, err := nl80211.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.SetRegDomain(cc)
}

// RefreshRegulatory re-reads the phys and swaps each managed device's capability set for the fresh
// one, so a regulatory-domain change is reflected in the band flags (a band that was NoIR before a
// country was set becomes transmit-usable). Capability facts that do not depend on the regulatory
// domain - interface modes, combinations - come back identical; only the per-channel flags move.
// Injection status and the netdev binding live on Device, not on Phy, so they are preserved.
func (s *Scheduler) RefreshRegulatory(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := nl80211.Dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	phys, err := conn.Wiphys()
	if err != nil {
		return err
	}
	byIndex := make(map[uint32]*nl80211.Wiphy, len(phys))
	for _, p := range phys {
		byIndex[p.Index] = p
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, dev := range s.devices {
		if dev.Phy == nil {
			continue
		}
		if fresh, ok := byIndex[dev.Phy.Index]; ok {
			dev.Phy = fresh
		}
	}
	return nil
}

// DefaultRegDomain is what warpd sets on startup when the kernel is still on the world/unset
// domain, so the upper bands are transmit-usable out of the box rather than requiring the operator
// to remember an `iw reg set`. US is a safe, permissive default for the bands a pentester uses; an
// operator elsewhere overrides it (startup flag, the radios tab, or `warp radios regdomain`).
const DefaultRegDomain = "US"

// EnsureRegDomain sets the regulatory domain to cc when the kernel is currently on the world/unset
// domain ("00" or empty). It never overrides a domain an operator or the system has already set -
// only fills in the unset default. Returns the domain in effect after the call.
func EnsureRegDomain(cc string) (string, error) {
	cur, err := GetRegDomain()
	if err != nil {
		return "", err
	}
	if cur != "" && cur != "00" {
		return cur, nil // already set by the system or the operator; leave it alone
	}
	if err := SetRegDomain(cc); err != nil {
		return cur, fmt.Errorf("radio: set default regulatory domain %q: %w", cc, err)
	}
	return cc, nil
}
