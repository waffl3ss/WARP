package inject

import (
	"context"
	"fmt"
	"time"

	"github.com/waffl3ss/warp/internal/recon"
)

// DeauthOptions describes a deauthentication run.
type DeauthOptions struct {
	// BSSID is the discovered access point.
	BSSID recon.MAC
	// ESSID is the observed network name. Authorization is decided on this.
	ESSID string
	// Target is the station to deauthenticate. Zero means broadcast.
	Target recon.MAC
	// Channel the AP is on, recorded as evidence.
	Channel int
	// MFP is the access point's management frame protection posture.
	MFP recon.MFPState
	// Reason is the 802.11 reason code.
	Reason uint16
	// Count and Interval control one burst.
	Count    int
	Interval time.Duration
	// Cooldown is enforced between runs against the same AP.
	Cooldown time.Duration
	// AllowBroadcast must be set explicitly to deauthenticate every client at once.
	AllowBroadcast bool
	// BypassESSIDMatch authorizes on the operator's recorded BSSID confirmation instead of an
	// ESSID match.
	//
	// Exactly one caller sets it: decloaking a hidden network, which by definition has no name
	// to match against scope.txt. Requiring one would make decloaking impossible by
	// construction. The authorization has not gone away - it has moved to a confirmation the
	// operator recorded in the audit log saying the network is the client's - but this is the
	// only place in WARP where transmission is not gated on an ESSID, and it must stay that
	// way.
	BypassESSIDMatch bool
}

// DeauthResult reports what a run did.
type DeauthResult struct {
	Frames  int    `json:"frames"`
	Target  string `json:"target"`
	Skipped bool   `json:"skipped"`
	Reason  string `json:"reason,omitempty"`
}

// ErrMFPRequired is returned when 802.11w makes deauthentication pointless.
var ErrMFPRequired = fmt.Errorf("inject: 802.11w management frame protection is required at this AP")

// Deauth transmits deauthentication frames at an authorized access point.
//
// Two guards beyond the scope gate:
//
// MFP-awareness. Where 802.11w is required, associated clients ignore unprotected
// deauthentication entirely. Transmitting anyway wastes airtime at a client site and produces
// a false negative in the report - "we deauthenticated and nothing happened" reads as a
// resilient network when it is actually a correctly configured one. The skip is returned and
// logged so it appears as the finding it is.
//
// Targeted by default. Broadcast deauthentication takes down every client on the network at
// once, which at a client site is an outage rather than a test, so it requires an explicit
// opt-in.
func Deauth(ctx context.Context, inj *Injector, o DeauthOptions) (DeauthResult, error) {
	if o.MFP == recon.MFPRequired {
		return DeauthResult{
			Skipped: true,
			Target:  o.Target.String(),
			Reason:  "802.11w required: associated clients will ignore unprotected deauthentication",
		}, ErrMFPRequired
	}

	target := o.Target
	if target.IsZero() {
		if !o.AllowBroadcast {
			return DeauthResult{}, fmt.Errorf(
				"inject: no target station given; broadcast deauthentication disconnects every " +
					"client at once and must be requested explicitly")
		}
		target = recon.Broadcast
	}

	reason := o.Reason
	if reason == 0 {
		reason = ReasonClass3FromNonAssoc
	}

	req := Request{
		Module:  "deauth",
		BSSID:   o.BSSID,
		ESSID:   o.ESSID,
		Channel: o.Channel,
		Decloak: o.BypassESSIDMatch,
	}
	if o.BypassESSIDMatch {
		// Named for what it is in the evidence log. A reader reconstructing the engagement must
		// be able to see at a glance which frames went out under the ordinary ESSID
		// authorization and which went out under a confirmation at a nameless BSSID.
		req.Module = "decloak"
	}
	opts := BurstOptions{Count: o.Count, Interval: o.Interval}

	// A deauthentication is only effective when both ends are told: the station stops using
	// the association, and the AP tears down its side. Alternating the two directions per
	// frame is what makes a client actually reconnect rather than sit on a stale association.
	sent, err := inj.Burst(ctx, req, opts, func(seq uint16) []byte {
		if seq%2 == 0 {
			return DeauthFrame(o.BSSID, target, reason, seq)
		}
		// From the station to the AP: addresses reverse.
		return DeauthFrame(target, o.BSSID, reason, seq)
	})
	if err != nil {
		return DeauthResult{Frames: sent, Target: target.String()}, err
	}

	return DeauthResult{Frames: sent, Target: target.String()}, nil
}

// KarmaProbe transmits probe requests for an ESSID that cannot exist.
//
// This is *detection*, not impersonation: WARP asks for a network that does not exist and
// records what answers. Anything that responds is a karma responder - a Pineapple or
// equivalent attacker device - and that is a deterministic yes/no, which is why it belongs in
// the determined confidence tier. Nothing passive will ever find it.
//
// The ESSID is regenerated per test rather than reused, so a device that has already seen it
// cannot learn to decline.
func KarmaProbe(ctx context.Context, inj *Injector, sta recon.MAC, essid string, channel int, count int) (int, error) {
	if essid == "" {
		return 0, fmt.Errorf("inject: karma probe needs a generated ESSID")
	}

	// The probe names a network that does not exist, so there is no BSSID and no scoped
	// ESSID to decide on. It still goes through the gate - via the one method that handles
	// this case - so the transmission is authorized and audited exactly like any other, and
	// there is no bypass path in the injector for a later module to reach for.
	if err := inj.gate.AuthorizeKarmaProbe(ctx, "karma-probe", essid, channel, inj.radioID); err != nil {
		return 0, err
	}

	if count <= 0 {
		count = 3
	}
	sent := 0
	for n := 0; n < count; n++ {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		frame, err := ProbeRequestFrame(sta, essid, inj.NextSeq())
		if err != nil {
			return sent, err
		}
		if err := inj.sendUnauthorized(frame); err != nil {
			return sent, err
		}
		sent++

		select {
		case <-ctx.Done():
			return sent, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return sent, nil
}
