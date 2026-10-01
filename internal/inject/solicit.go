package inject

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/waffl3ss/warp/internal/recon"
)

// Solicitation defaults.
const (
	// DefaultSolicitCooldown is the minimum gap between solicitation attempts at the same AP.
	//
	// Rate limiting is per-AP and not optional. Hammering association requests at a
	// production access point degrades service for real users at a client site, which is an
	// outage the SoW did not buy.
	DefaultSolicitCooldown = 30 * time.Second

	// DefaultSolicitTimeout is how long to wait for the AP's M1 before giving up.
	DefaultSolicitTimeout = 3 * time.Second

	// DefaultSolicitRetries is how many auth/assoc rounds to try before moving on.
	DefaultSolicitRetries = 2
)

// SolicitOptions describes a PMKID solicitation attempt.
type SolicitOptions struct {
	// BSSID is the discovered access point.
	BSSID recon.MAC
	// ESSID is the observed network name. Authorization is decided on this.
	ESSID string
	// Channel the AP is on.
	Channel int
	// RSN, when set, mirrors the AP's advertised RSN element. Offering a suite the AP does
	// not support gets the association rejected, and the rejection looks like a tool bug.
	RSN []byte
	// STA is the source address to associate from. Generated if zero.
	STA recon.MAC
	// Retries and Timeout bound one attempt.
	Retries int
	Timeout time.Duration
}

// SolicitResult reports what an attempt did.
type SolicitResult struct {
	BSSID    string        `json:"bssid"`
	ESSID    string        `json:"essid"`
	STA      string        `json:"sta"`
	Attempts int           `json:"attempts"`
	Frames   int           `json:"frames"`
	Elapsed  time.Duration `json:"elapsed"`
	// Skipped is set when the cooldown suppressed the attempt.
	Skipped bool   `json:"skipped"`
	Reason  string `json:"reason,omitempty"`
}

// Solicitor drives PMKID solicitation and enforces per-AP rate limits.
//
// Soliciting is the largest single time saver on an engagement: it converts "wait for a
// client to reassociate" into "walk past the AP". A single association request from a made-up
// station is often enough to make the AP volunteer an M1 carrying a PMKID, with no client
// involvement and nothing disrupted.
//
// The PMKID itself is not extracted here. This module transmits; the capture path parses the
// M1 that comes back, and internal/handshake decides whether it is usable. Keeping
// transmission and parsing apart means a solicitation is still useful when the reply arrives
// on a different radio.
type Solicitor struct {
	mu       sync.Mutex
	lastTry  map[recon.MAC]time.Time
	cooldown time.Duration
	now      func() time.Time
}

// NewSolicitor builds a solicitor. A zero cooldown uses DefaultSolicitCooldown; it cannot be
// disabled.
func NewSolicitor(cooldown time.Duration) *Solicitor {
	if cooldown <= 0 {
		cooldown = DefaultSolicitCooldown
	}
	return &Solicitor{
		lastTry:  make(map[recon.MAC]time.Time),
		cooldown: cooldown,
		now:      time.Now,
	}
}

// Mark records an attempt against the cooldown.
//
// Called once at the start of a campaign, before transmitting rather than after: if the
// campaign fails partway through we must still not immediately retry against a production
// access point.
func (s *Solicitor) Mark(bssid recon.MAC) { s.mark(bssid) }

func (s *Solicitor) mark(bssid recon.MAC) {
	s.mu.Lock()
	s.lastTry[bssid] = s.now()
	s.mu.Unlock()
}

// Ready reports whether the cooldown has elapsed for an AP, and how long remains if not.
func (s *Solicitor) Ready(bssid recon.MAC) (bool, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	last, seen := s.lastTry[bssid]
	if !seen {
		return true, 0
	}
	elapsed := s.now().Sub(last)
	if elapsed >= s.cooldown {
		return true, 0
	}
	return false, s.cooldown - elapsed
}

// Solicit performs one authentication and association round at an authorized AP.
//
// The sequence is: open-system authentication, then an association request carrying an RSN
// element. A cooperative AP replies with EAPOL M1, and on many models that M1 carries a
// PMKID. Everything after transmission is the capture path's job.
func (s *Solicitor) Solicit(ctx context.Context, inj *Injector, o SolicitOptions) (SolicitResult, error) {
	if ready, remaining := s.Ready(o.BSSID); !ready {
		return SolicitResult{
			BSSID: o.BSSID.String(), ESSID: o.ESSID, Skipped: true,
			Reason: fmt.Sprintf(
				"rate limited: %s remaining before this AP may be solicited again",
				remaining.Round(time.Second)),
		}, nil
	}
	s.mark(o.BSSID)
	return s.Attempt(ctx, inj, o)
}

// Attempt performs one authentication and association round with no rate limiting.
//
// The cooldown exists to stop an operator hammering a production access point with repeated
// *actions*. A campaign is one action: it retries in rounds because a single association is
// regularly dropped by a busy access point, and applying the per-AP cooldown inside it meant
// round one transmitted and every round after it was skipped with "cannot solicit again for
// 12s" - which looked like a double-click and was actually the campaign refusing itself.
//
// So the caller marks the cooldown once, at the start of the campaign, and drives this.
func (s *Solicitor) Attempt(ctx context.Context, inj *Injector, o SolicitOptions) (SolicitResult, error) {
	res := SolicitResult{
		BSSID: o.BSSID.String(),
		ESSID: o.ESSID,
	}

	sta := o.STA
	if sta.IsZero() {
		var err error
		if sta, err = RandomMAC(); err != nil {
			return res, err
		}
	}
	res.STA = sta.String()

	rsn := o.RSN
	if len(rsn) == 0 {
		rsn = DefaultRSN()
	}
	retries := o.Retries
	if retries <= 0 {
		retries = DefaultSolicitRetries
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultSolicitTimeout
	}

	assoc, err := AssocRequestFrame(AssocRequestOptions{
		BSSID: o.BSSID, STA: sta, ESSID: o.ESSID, RSN: rsn,
	})
	if err != nil {
		return res, err
	}

	req := Request{Module: "solicit", BSSID: o.BSSID, ESSID: o.ESSID, Channel: o.Channel}
	start := time.Now()

	for attempt := 0; attempt < retries; attempt++ {
		if err := ctx.Err(); err != nil {
			res.Elapsed = time.Since(start)
			return res, err
		}
		res.Attempts++

		// Authentication first: APs reject an association from a station they have not
		// authenticated, and the rejection carries no PMKID.
		sent, err := inj.Burst(ctx, req, BurstOptions{Count: 1}, func(seq uint16) []byte {
			return AuthFrame(o.BSSID, sta, seq)
		})
		res.Frames += sent
		if err != nil {
			res.Elapsed = time.Since(start)
			return res, err
		}

		// Give the AP time to answer the authentication before associating.
		if !sleepCtx(ctx, 100*time.Millisecond) {
			res.Elapsed = time.Since(start)
			return res, ctx.Err()
		}

		sent, err = inj.Burst(ctx, req, BurstOptions{Count: 1}, func(seq uint16) []byte {
			// The sequence number is rewritten per transmission; the rest of the frame is
			// fixed, so it is built once.
			return withSeq(assoc, seq)
		})
		res.Frames += sent
		if err != nil {
			res.Elapsed = time.Since(start)
			return res, err
		}

		// Wait for the M1 to arrive on the capture path.
		if !sleepCtx(ctx, timeout) {
			res.Elapsed = time.Since(start)
			return res, ctx.Err()
		}
	}

	res.Elapsed = time.Since(start)
	return res, nil
}

// withSeq rewrites the sequence control field of a prebuilt frame.
//
// The frame carries a radiotap header, so the 802.11 header starts after it and the sequence
// control field is the last two bytes of the 24-byte MAC header.
func withSeq(frame []byte, seq uint16) []byte {
	// Derived from the header rather than written as a magic number, so changing the
	// radiotap transmit header cannot silently corrupt every frame's sequence field.
	seqOffset := len(radiotapTX) + 22

	out := make([]byte, len(frame))
	copy(out, frame)
	if len(out) >= seqOffset+2 {
		binary.LittleEndian.PutUint16(out[seqOffset:seqOffset+2], seq<<4)
	}
	return out
}

// sleepCtx waits for d, returning false if the context was cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
