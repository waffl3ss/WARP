package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/rpc"
)

// Deauthentication and solicitation as campaigns rather than single bursts.
//
// The original shape of this was: borrow a radio, send four frames over eighty milliseconds,
// give the radio back. That is not how a handshake is captured, for two reasons.
//
// A client does not always leave on the first frame. It may be mid-transmit, the frame may be
// lost to a collision, or the driver may simply ignore it. One short burst produces a false
// negative that reads as a resilient network.
//
// And the handshake arrives *after* the client comes back - a second or two later, on the
// access point's channel. A capture radio that has resumed sweeping by then is somewhere else
// when it happens. On a two-adapter kit the transmitter and the listener are different cards,
// so pinning only the transmitter changes nothing at all; the *listener* is the one that has
// to be parked.
//
// So a campaign holds every capture radio on the target's channel, transmits in rounds across
// a window, and stops the instant a handshake for that access point lands.

// Campaign timing.
const (
	// DefaultCampaignWindow is how long a campaign runs when the caller does not say.
	DefaultCampaignWindow = 20 * time.Second
	// MaxCampaignWindow bounds it. Beyond a minute this stops being a test and becomes a
	// sustained denial of service at a client site.
	MaxCampaignWindow = 60 * time.Second
	// campaignRound is the gap between bursts. Long enough for a client to notice it has been
	// disconnected and start reassociating, short enough to catch one that ignored the last.
	campaignRound = 2 * time.Second
	// campaignListenTail keeps the radios on the channel, listening, after the last frame is
	// transmitted. A client knocked off at the end of the transmit window reconnects a few
	// seconds *later*, and the handshake it produces then would be missed if the campaign shut
	// down the moment it stopped transmitting. Transmission stops at the window; capture runs
	// for this much longer.
	campaignListenTail = 12 * time.Second
	// settleAfterCapture lets the fourth message of a handshake arrive after the first has
	// been recognised, rather than tearing the radio away mid-exchange.
	settleAfterCapture = 1500 * time.Millisecond
)

// CampaignResult is what a run achieved.
type CampaignResult struct {
	BSSID   string `json:"bssid"`
	ESSID   string `json:"essid"`
	Channel int    `json:"channel"`
	Target  string `json:"target"`
	// Rounds is how many bursts were transmitted.
	Rounds int `json:"rounds"`
	Frames int `json:"frames"`
	// Captured names what the campaign produced, empty if nothing.
	Captured []string `json:"captured,omitempty"`
	// Elapsed is how long it ran.
	Elapsed string `json:"elapsed"`
	// Outcome is the operator-facing summary.
	Outcome string `json:"outcome"`
	// HeldRadios are the capture radios that were parked on the target's channel. Reported
	// because "nothing was captured" means something very different when the answer is that
	// no radio could reach the channel.
	HeldRadios []string `json:"held_radios,omitempty"`
}

// Summary implements Summariser: what the campaign actually produced.
func (r CampaignResult) Summary() string { return r.Outcome }

// campaignWindow clamps a caller-supplied duration.
func campaignWindow(seconds int) time.Duration {
	if seconds <= 0 {
		return DefaultCampaignWindow
	}
	d := time.Duration(seconds) * time.Second
	if d > MaxCampaignWindow {
		return MaxCampaignWindow
	}
	return d
}

// runCampaign holds the channel, runs burst rounds, and stops on the first capture.
//
// burst is called once per round and reports how many frames it sent. It is expected to have
// been authorized by the scope gate already - the gate is consulted per burst inside the
// injector, so a campaign cannot outlive an authorization.
func (d *Daemon) runCampaign(ctx context.Context, ap recon.AP, target string,
	window time.Duration, burst func(context.Context) (int, error)) (CampaignResult, error) {

	res := CampaignResult{
		BSSID: ap.BSSID.String(), ESSID: ap.ESSID,
		Channel: ap.Channel, Target: target,
	}

	// Park every capture radio on the access point's channel before the first frame goes out.
	// Without this the handshake lands while the listener is three channels away.
	release := d.engine.HoldChannel(ap.Freq)
	defer release()
	res.HeldRadios = d.engine.HoldingRadios()

	if len(res.HeldRadios) == 0 {
		// Worth saying out loud. Transmitting with nothing listening on the right channel is
		// airtime spent at a client site for a result that cannot arrive.
		d.Broadcast(rpc.Event{
			Kind: "deauth", Level: rpc.LevelWarn,
			Text: fmt.Sprintf("[!] no capture radio is on ch%d - start recon first, or a "+
				"handshake will be provoked and missed", ap.Channel),
		})
	}

	captures, stop := d.engine.WatchHandshakes(ap.BSSID)
	defer stop()

	started := time.Now()
	// Two deadlines: stop transmitting at the window, but keep the channel held and keep
	// listening for the reconnect handshake through the tail.
	stopTransmit := time.After(window)
	stopListening := time.After(window + campaignListenTail)
	ticker := time.NewTicker(campaignRound)
	defer ticker.Stop()
	transmitting := true

	send := func() error {
		n, err := burst(ctx)
		res.Frames += n
		if n > 0 {
			res.Rounds++
		}
		return err
	}

	if err := send(); err != nil {
		return res, err
	}

	for {
		select {
		case <-ctx.Done():
			res.Elapsed = time.Since(started).Round(time.Millisecond).String()
			res.Outcome = summariseCampaign(res, "cancelled")
			return res, nil

		case r := <-captures:
			// Give the rest of the exchange a moment to arrive before the radios resume
			// sweeping - the first message is not the whole handshake.
			select {
			case <-time.After(settleAfterCapture):
			case <-ctx.Done():
			}
			res.Captured = append(res.Captured, describeCapture(r))
			drainCaptures(captures, &res)

			res.Elapsed = time.Since(started).Round(time.Millisecond).String()
			res.Outcome = summariseCampaign(res, "captured")
			return res, nil

		case <-stopTransmit:
			// Stop sending, keep listening. Clients reconnect in the seconds after the frames
			// stop, and their handshake is the whole point of the exercise.
			transmitting = false

		case <-stopListening:
			res.Elapsed = time.Since(started).Round(time.Millisecond).String()
			res.Outcome = summariseCampaign(res, "window elapsed")
			return res, nil

		case <-ticker.C:
			if !transmitting {
				continue
			}
			if err := send(); err != nil {
				return res, err
			}
		}
	}
}

// drainCaptures collects anything else that arrived in the same exchange.
func drainCaptures(ch <-chan handshake.Result, res *CampaignResult) {
	for {
		select {
		case r := <-ch:
			res.Captured = append(res.Captured, describeCapture(r))
		default:
			return
		}
	}
}

func describeCapture(r handshake.Result) string {
	kind := "handshake"
	if r.Kind == handshake.KindPMKID {
		kind = "PMKID"
	}
	if r.STAString() != "00:00:00:00:00:00" {
		return fmt.Sprintf("%s from %s", kind, r.STAString())
	}
	return kind
}

// summariseCampaign writes the sentence the operator reads.
//
// It says what happened *and* what to do next, because "0 captured" on its own is
// indistinguishable from a dozen different causes.
func summariseCampaign(res CampaignResult, why string) string {
	switch {
	case len(res.Captured) > 0:
		return fmt.Sprintf("%d frame(s) over %d round(s) in %s - captured %v",
			res.Frames, res.Rounds, res.Elapsed, res.Captured)

	case len(res.HeldRadios) == 0:
		return fmt.Sprintf("%d frame(s) over %d round(s) in %s, but no capture radio was on "+
			"ch%d - start recon so something is listening",
			res.Frames, res.Rounds, res.Elapsed, res.Channel)

	case res.Target == "" || res.Target == "broadcast":
		return fmt.Sprintf("%d frame(s) over %d round(s) in %s (%s), nothing captured - the "+
			"network may have no associated clients right now",
			res.Frames, res.Rounds, res.Elapsed, why)

	default:
		return fmt.Sprintf("%d frame(s) over %d round(s) in %s (%s), nothing captured - %s may "+
			"have roamed, gone idle, or be ignoring unprotected deauthentication",
			res.Frames, res.Rounds, res.Elapsed, why, res.Target)
	}
}
