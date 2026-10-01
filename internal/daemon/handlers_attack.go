package daemon

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/waffl3ss/warp/internal/build"
	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/inject"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/report"
	"github.com/waffl3ss/warp/internal/rogue"
	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/store"
)

// crackableCheck explains, before any airtime is spent, when a network's handshake is not
// worth capturing.
//
// WPA3-SAE is the case that matters. Its pairwise master key comes out of the dragonfly
// exchange, not from PBKDF2 over a passphrase, so a captured four-way handshake carries nothing
// a wordlist can attack - hashcat mode 22000 is WPA-PBKDF2-PMKID+EAPOL and that is exactly the
// part SAE removes. Its PMKID is derived from the SAE PMK and is no better. SAE also mandates
// 802.11w, so the deauthentication that would provoke a handshake is ignored anyway.
//
// Transition mode is different and is the useful case: a BSS advertising both SAE and PSK still
// has clients on the PSK side, and those handshakes crack normally. That is itself the finding.
//
// This is reported rather than refused. An operator may want the capture for evidence that the
// exchange happened, and refusing work on a correct assumption is how a tool becomes something
// people route around.
func crackableCheck(ap recon.AP) string {
	switch ap.Security.Class {
	case recon.SecWPASAE:
		if ap.Security.Transition {
			return "" // the PSK half is attackable; nothing to warn about
		}
		return "WPA3-SAE: a captured handshake here is not crackable. The key comes from the " +
			"SAE exchange rather than from the passphrase, so there is no PBKDF2 to attack - " +
			"hashcat 22000 covers the part SAE removes. SAE also requires 802.11w, so clients " +
			"ignore unprotected deauthentication. This is a pass for the network, and it is " +
			"worth recording as one."

	case recon.SecOpen, recon.SecOWE:
		return "This network has no passphrase, so there is no handshake to capture and " +
			"nothing to crack."

	case recon.SecWPAEnterprise, recon.SecWPA3Ent192:
		return "WPA-Enterprise: credentials come from the RADIUS exchange, not from a " +
			"passphrase. There is no PSK handshake to capture - use `warp eap` instead."

	case recon.SecWEP:
		return "WEP: the four-way handshake does not exist here. This is already a finding on " +
			"its own."
	}
	return ""
}

// withInjector acquires a transmitting role, prepares an injector, runs fn, and releases
// everything.
//
// Every transmitting module funnels through here, which is what keeps radio acquisition and
// release symmetrical: there is one place that can leave an adapter stranded, and it always
// releases.
func (d *Daemon) withInjector(ctx context.Context, role radio.Role, channelMHz int, fn func(*inject.Injector) error) error {
	handle, err := d.sched.Acquire(ctx, role)
	if err != nil {
		var unsat *radio.UnsatisfiableError
		if errors.As(err, &unsat) {
			return rpc.Errorf(rpc.CodeUnsatisfiable, "%v", err)
		}
		return err
	}
	defer handle.Release()

	// A borrowed handle reuses an interface the capture engine already owns and has already
	// put into monitor mode. Reconfiguring it would tear the capture out from under its owner
	// - all that is needed is to stop the channel plan hopping for the length of the burst.
	if handle.Borrowed {
		resume, _ := d.engine.PauseHopping(handle.Device.ID, channelMHz)
		defer resume()

		inj, err := inject.Open(handle.Device.Ifname, int(handle.Device.Ifindex),
			handle.Device.ID, d.ws.Gate)
		if err != nil {
			return err
		}
		defer inj.Close()

		return fn(inj)
	}

	acq, err := acquireReconciling(ctx, d.sched, d.acquirer, handle.Device, nl80211.IftypeMonitor)
	if err != nil {
		return err
	}
	defer d.acquirer.Release(ctx, acq)

	// A dedicated transmitter needs putting on the target's channel explicitly. Nothing else
	// does it: the channel plan belongs to the capture radios, and this adapter is not one of
	// them - on a two-card kit it has just been taken out of managed mode and is wherever the
	// driver left it.
	if channelMHz != 0 {
		if err := d.acquirer.SetChannel(ctx, handle.Device, channelMHz); err != nil {
			return fmt.Errorf("daemon: tune %s to %d MHz: %w",
				handle.Device.Ifname, channelMHz, err)
		}
	}

	inj, err := inject.Open(handle.Device.Ifname, int(handle.Device.Ifindex),
		handle.Device.ID, d.ws.Gate)
	if err != nil {
		return err
	}
	defer inj.Close()

	return fn(inj)
}

// eapolTransport is the 802.1X exchange over a completed association: send our EAPOL, receive the
// access point's. Satisfied by *nl80211.StationConn (control port over nl80211).
type eapolTransport interface {
	Send(ctx context.Context, eapol []byte) error
	Receive(ctx context.Context) ([]byte, error)
}

// withStation borrows an adapter, puts it in managed mode, drives a real kernel association to the
// network in params - the firmware acknowledging the access point the way it does for
// wpa_supplicant - and runs fn with the station MAC the card wears and the EAPOL transport for the
// association's 802.1X control port.
//
// This is the robust path for the two-way exchanges active-monitor injection could never reliably
// complete on hardware whose driver does not ACK injected frames. The association is the kernel's,
// not a forged one, and the EAPOL exchange rides the nl80211 control port on the socket that owns
// it - the data-path packet socket does not carry EAPOL on many drivers. The card is suspended
// from capture for the duration and disconnected and restored on release, same discipline as
// active monitor.
func (d *Daemon) withStation(ctx context.Context, role radio.Role, params nl80211.ConnectParams,
	fn func(sta recon.MAC, radioID string, eapol eapolTransport) error) error {

	handle, err := d.sched.Acquire(ctx, role)
	if err != nil {
		var unsat *radio.UnsatisfiableError
		if errors.As(err, &unsat) {
			return rpc.Errorf(rpc.CodeUnsatisfiable, "%v", err)
		}
		return err
	}
	defer handle.Release()

	// Managed mode downs and reconfigures the interface; hold its capture loop so it does not
	// race to reopen mid-reconfiguration, exactly as for active monitor.
	resumeCapture := d.engine.SuspendCapture(handle.Device.ID)
	defer resumeCapture()

	if handle.Borrowed {
		resume, _ := d.engine.PauseHopping(handle.Device.ID, params.FreqMHz)
		defer resume()
	}

	// What we are about to offer the access point. When an association is refused with a bare
	// status code, the mismatch (or the fact that nothing was mismatched and the link is simply
	// too weak for the AP to answer) is only visible here - there is no second capture radio on
	// the exchange. Every station-based attack funnels through here, so one log covers them all.
	d.log.Info("station connect offer",
		"role", string(role), "ifname", handle.Device.Ifname,
		"ssid", string(params.SSID), "freq", params.FreqMHz,
		"wpa_versions", params.WPAVersions,
		"group", fmt.Sprintf("0x%08x", params.Group),
		"pairwise", suitesHex(params.Pairwise),
		"akms", suitesHex(params.AKMs),
		"mfp", params.MFP,
	)

	acq, err := acquireStationReconciling(ctx, d.sched, d.acquirer, handle.Device, params)
	if err != nil {
		return err
	}
	defer d.acquirer.Release(ctx, acq)

	station := acq.Station()
	if station == nil {
		return fmt.Errorf("daemon: station association produced no control-port transport")
	}
	sta, err := recon.ParseMAC(acq.StationMAC.String())
	if err != nil {
		return fmt.Errorf("daemon: station association produced no usable MAC: %w", err)
	}
	return fn(sta, handle.Device.ID, station)
}

// DecloakParams targets a hidden network.
type DecloakParams struct {
	BSSID string `json:"bssid"`
	// Seconds bounds the campaign, same limits as a deauthentication.
	Seconds int `json:"seconds,omitempty"`
}

// handleDecloak recovers the name of a cloaked network.
//
// A hidden network is only hidden in its beacons. The name is in every probe response and
// every association request, so knocking the associated clients off and watching them come
// back reveals it - the reassociation names the network in the clear.
//
// This is one of the two places WARP transmits at something it cannot authorize by name, and
// it is deliberate. A cloaked network has no ESSID to match against scope.txt, so requiring a
// match would make decloaking impossible by construction - and the reason that matters is
// sharper than "the check cannot run": **the network may well be in scope, and there is no way
// to find out except by decloaking it.** Refusing until someone confirms it inverts the
// question, because the confirmation is asking the operator to assert exactly the fact the
// tool is being asked to establish.
//
// So the name is recovered first and authorization resumes immediately afterwards. Nothing
// else is unlocked by this: the moment the name is known every subsequent decision is back on
// the ordinary ESSID path, and if the name turns out not to be in scope, nothing further will
// transmit at it. The gate still refuses a vetoed BSSID here, because a veto only narrows.
//
// What it costs is one broadcast deauthentication at a network that may not be the client's.
// That is a real cost and it is why the audit record is explicit about it, but it is smaller
// than the alternative - which is an unidentified hidden network inside the client's footprint
// that nobody ever names.
func (d *Daemon) handleDecloak(ctx context.Context, params json.RawMessage) (any, error) {
	var p DecloakParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	ap, err := d.lookupAP(p.BSSID)
	if err != nil {
		return nil, err
	}

	if ap.ESSID != "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s already broadcasts %q - there is nothing to decloak", ap.BSSID, ap.ESSID)
	}

	if ap.Security.MFP == recon.MFPRequired {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s requires 802.11w; its clients will ignore unprotected deauthentication, so they "+
				"cannot be made to reassociate. The name cannot be recovered this way",
			ap.BSSID)
	}

	window := campaignWindow(p.Seconds)

	job := d.jobs.Start(d.ctx, "decloak", ap.BSSID.String(), func(jctx context.Context) (any, error) {
		// Watch for the name arriving while the campaign runs. The tracker learns it from the
		// reassociation and the engine already emits an event; this is the same signal.
		revealed := make(chan string, 1)
		stop := d.engine.WatchESSID(ap.BSSID, revealed)
		defer stop()

		var res CampaignResult
		err := d.withInjector(jctx, radio.RoleDeauth, ap.Freq, func(inj *inject.Injector) error {
			cctx, cancel := context.WithCancel(jctx)
			defer cancel()

			// Finish the moment the name is known rather than transmitting for the full
			// window at a network that has already given it up.
			go func() {
				select {
				case <-revealed:
					cancel()
				case <-cctx.Done():
				}
			}()

			var cerr error
			res, cerr = d.runCampaign(cctx, ap, "broadcast", window,
				func(bctx context.Context) (int, error) {
					out, err := inject.Deauth(bctx, inj, inject.DeauthOptions{
						BSSID:          ap.BSSID,
						ESSID:          ap.ESSID,
						Channel:        ap.Channel,
						MFP:            ap.Security.MFP,
						AllowBroadcast: true,
						// Authorization here is the operator's confirmation, recorded above,
						// not an ESSID match there is no name for.
						BypassESSIDMatch: true,
					})
					return out.Frames, err
				})
			return cerr
		})
		if err != nil {
			return res, scopeRPCError(err)
		}

		// Did it work?
		if now, ok := d.engine.Tracker().AP(ap.BSSID); ok && now.ESSID != "" {
			res.Outcome = fmt.Sprintf("decloaked: %s broadcasts %q, recovered from %s",
				ap.BSSID, now.ESSID, orDefaultSource(now.ESSIDSource))
			d.Broadcast(rpc.Event{
				Kind: "decloak", Level: rpc.LevelGood,
				Text: fmt.Sprintf("[+] DECLOAKED %s - %q (%s)",
					ap.BSSID, now.ESSID, orDefaultSource(now.ESSIDSource)),
				Fields: map[string]any{"bssid": ap.BSSID.String(), "essid": now.ESSID},
			})
			return res, nil
		}

		res.Outcome = fmt.Sprintf("%d frame(s) over %d round(s) in %s - the name was not "+
			"recovered. Nothing reassociated: the network may have no clients right now, or "+
			"they may be out of range of this adapter",
			res.Frames, res.Rounds, res.Elapsed)
		return res, nil
	})

	return job, nil
}

func orDefaultSource(s string) string {
	if s == "" {
		return "observed traffic"
	}
	return s
}

// lookupAP resolves a BSSID to its observed record.
//
// Active work always starts from something WARP saw on the air. There is no path that accepts
// a BSSID the tool has not observed, which is the practical expression of "BSSIDs are always
// discovered, never configured".
func (d *Daemon) lookupAP(bssid string) (recon.AP, error) {
	addr, err := recon.ParseMAC(bssid)
	if err != nil {
		return recon.AP{}, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	ap, ok := d.engine.Tracker().AP(addr)
	if !ok {
		return recon.AP{}, rpc.Errorf(rpc.CodeNotFound,
			"no access point has been observed at %s; run recon first - WARP only acts on "+
				"BSSIDs it discovered off the air", addr)
	}
	return ap, nil
}

// SolicitParams asks for PMKID solicitation at a discovered AP.
type SolicitParams struct {
	BSSID string `json:"bssid"`
	// Seconds bounds the campaign. Default 20, capped at 60, the same as every other.
	Seconds int `json:"seconds,omitempty"`
}

func (d *Daemon) handleSolicit(ctx context.Context, params json.RawMessage) (any, error) {
	var p SolicitParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	ap, err := d.lookupAP(p.BSSID)
	if err != nil {
		return nil, err
	}

	// Fail fast on an unscoped target so the operator gets an immediate refusal rather than a
	// job that dies a moment later. The gate still decides at transmit time - this is a
	// courtesy, not the authorization.
	if !d.ws.Scope.Contains(ap.ESSID) {
		return nil, rpc.Errorf(rpc.CodeScopeDenied,
			"%s broadcasts %q, which is not in scope; passive observation only",
			ap.BSSID, ap.ESSID)
	}

	if why := crackableCheck(ap); why != "" {
		d.Broadcast(rpc.Event{
			Kind: "solicit", Level: rpc.LevelWarn,
			Text:   "[!] " + ap.BSSID.String() + " - " + why,
			Fields: map[string]any{"bssid": ap.BSSID.String(), "essid": ap.ESSID},
		})
	}

	// The cooldown is per access point and per *action*, checked once here. It is not optional:
	// repeated associations at a production access point degrade service for real users.
	if ready, remaining := d.solicitor.Ready(ap.BSSID); !ready {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s was solicited recently; %s remaining. The limit is per access point and is "+
				"not optional - repeated association requests at a production access point "+
				"degrade service for real users",
			ap.BSSID, remaining.Round(time.Second))
	}
	d.solicitor.Mark(ap.BSSID)

	// The association mirrors the access point's advertised RSN, exactly as the harvest does - a
	// guessed CCMP+PSK is refused by anything running the wrong crypto. A WPA3 transition BSS is
	// the exception connectParamsForAP handles: it associates on the PSK side (PSK AKM only), which
	// is where the crackable PMKID lives; pure SAE is still refused (no crackable material).
	cp, ok := connectParamsForAP(ap)
	if !ok || cp.WPAVersions == 0 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s (%s) is not a network WARP can solicit a PMKID from - there is no WPA-PSK "+
				"association to drive", ap.BSSID, ap.Security.Class)
	}

	window := campaignWindow(p.Seconds)

	job := d.jobs.Start(d.ctx, "solicit", ap.BSSID.String(), func(jctx context.Context) (any, error) {
		jctx, cancel := context.WithTimeout(jctx, window)
		defer cancel()

		res := CampaignResult{
			BSSID: ap.BSSID.String(), ESSID: ap.ESSID,
			Channel: ap.Channel, Target: ap.BSSID.String(),
		}
		started := time.Now()

		// The PMKID lives in the first message of the four-way handshake (M1), which a PSK access
		// point sends the instant a station associates - before the station has to prove it knows
		// the passphrase. So WARP associates with a real, kernel-driven connection the firmware
		// acknowledges the way it does for wpa_supplicant (the active-monitor injection path could
		// never reliably get that ACK, which is why solicitation used to come back empty on drivers
		// that do not loop injected frames), reads M1 off the association's 802.1X control port, and
		// takes the PMKID from it. WARP never answers M1 - it has no passphrase and needs none - so
		// nothing joins the network.
		var (
			associated bool
			gotM1      bool
			assocErr   error
		)

		for attempt := 0; attempt < solicitMaxAttempts && jctx.Err() == nil && len(res.Captured) == 0; attempt++ {
			err := d.withStation(jctx, radio.RoleSolicit, cp, func(sta recon.MAC, radioID string, eapol eapolTransport) error {
				associated = true
				res.Rounds++

				// Give the access point a moment after the association completes to bring the
				// station's control port up on its side before M1.
				select {
				case <-time.After(assocSettle):
				case <-jctx.Done():
					return jctx.Err()
				}

				// Read control-port frames until the M1 carrying a PMKID arrives, or the read
				// window elapses. The access point retransmits M1 while WARP stays silent, so
				// there are several chances at it; the first one with a PMKID wins.
				rctx, rcancel := context.WithTimeout(jctx, solicitReadWindow)
				defer rcancel()
				for {
					payload, rerr := eapol.Receive(rctx)
					if rerr != nil {
						return nil // read window elapsed: the AP had its chance to volunteer a PMKID
					}
					if key, kerr := handshake.ParseEAPOLKey(payload); kerr == nil {
						d.log.Info("solicit control-port frame",
							"bssid", ap.BSSID.String(), "message", key.Message.String(),
							"key_data_len", len(key.KeyData), "key_data", fmt.Sprintf("%x", key.KeyData))
						if key.Message == handshake.M1 {
							gotM1 = true
						}
					} else {
						d.log.Info("solicit control-port frame (not EAPOL-Key)",
							"bssid", ap.BSSID.String(), "len", len(payload), "raw", fmt.Sprintf("%x", payload))
					}
					for _, r := range d.engine.SubmitEAPOLKey(ap.BSSID, sta, payload, ap.Channel, radioID, time.Now()) {
						if r.Kind == handshake.KindPMKID {
							res.Captured = append(res.Captured, describeCapture(r))
						}
					}
					if len(res.Captured) > 0 {
						return nil
					}
					// An M1 with no PMKID is a definitive answer: this AP does not cache one for
					// an unassociated station. No point reading further or retrying.
					if gotM1 {
						return nil
					}
				}
			})
			if err != nil {
				assocErr = err
				if len(res.Captured) > 0 {
					break
				}
				// A refused or failed association is worth one retry - a busy AP drops the odd
				// request - but a completed association that simply carried no PMKID is not.
				if associated {
					break
				}
				select {
				case <-time.After(campaignRound):
				case <-jctx.Done():
				}
				continue
			}
			// Associated (with or without a PMKID); no reason to hammer it again.
			break
		}

		res.Elapsed = time.Since(started).Round(time.Millisecond).String()
		if len(res.Captured) > 0 {
			res.Outcome = fmt.Sprintf("associated and read the PMKID from M1 in %s - %v",
				res.Elapsed, res.Captured)
			return res, nil
		}
		res.Outcome = solicitOutcome(ap, res, associated, gotM1, assocErr)
		return res, nil
	})

	return job, nil
}

// solicitation tuning.
const (
	// solicitMaxAttempts bounds how many times a *failed* association is retried within the
	// window. A completed association is never retried - its answer, PMKID or not, is definitive.
	solicitMaxAttempts = 3
	// solicitReadWindow is how long to read control-port frames for M1 after an association
	// completes. M1 normally arrives within a few hundred milliseconds and the AP retransmits it.
	solicitReadWindow = 6 * time.Second
)

// solicitOutcome writes the honest sentence for a solicitation that returned no PMKID, over the
// kernel-connect path.
//
// The determining fact is whether the association completed. If it did and the access point sent
// its M1 without a PMKID, that is the genuine "does not cache a PMKID" finding. If it did but no M1
// arrived, the control port is not delivering EAPOL on this driver - not a caching finding. If the
// association was refused, the status says why. Invariant 7a: report what was established, never a
// conclusion the evidence does not support.
// rssiNote reports the strongest signal WARP heard from an access point, as a parenthetical, so a
// refusal message can say how far away the AP looked. Empty when no RSSI was observed.
func rssiNote(ap recon.AP) string {
	if !ap.HasRSSI {
		return ""
	}
	return fmt.Sprintf(" (strongest signal seen %d dBm)", ap.BestRSSI)
}

func solicitOutcome(ap recon.AP, res CampaignResult, associated, gotM1 bool, assocErr error) string {
	switch {
	case associated && gotM1:
		return fmt.Sprintf(
			"%d association(s) over %s: the access point completed the association and sent its "+
				"M1, but it carried no PMKID. This one does not cache a PMKID for an unassociated "+
				"station - a real result, worth recording. Force a full handshake instead: "+
				"warp psk --deauth %s",
			res.Rounds, res.Elapsed, ap.BSSID)

	case associated:
		return fmt.Sprintf(
			"%d association(s) over %s: the association completed but no M1 arrived on the control "+
				"port within the read window. That is unusual for a PSK network - the AP may defer "+
				"the four-way, or this driver is not delivering EAPOL over the control port. Not a "+
				"caching finding. Try a full handshake: warp psk --deauth %s",
			res.Rounds, res.Elapsed, ap.BSSID)

	case assocErr != nil:
		return fmt.Sprintf(
			"%d attempt(s) over %s: the association was not completed (%v)%s. The request mirrored "+
				"the AP's advertised RSN, so this is not an offer mismatch WARP can fix by changing "+
				"the crypto. 802.11 status 1 is \"unspecified failure\" - a catch-all the kernel also "+
				"reports when the auth/assoc simply times out, so on a distant AP it usually means the "+
				"link is too weak or asymmetric for the AP to complete the exchange (the AP hears the "+
				"station worse than the station hears it). Other causes: MAC filtering, or 802.11w / a "+
				"policy the beacon did not advertise. Move closer, or force a full handshake from a "+
				"real client instead: warp psk --deauth %s",
			res.Rounds, res.Elapsed, assocErr, rssiNote(ap), ap.BSSID)

	default:
		return fmt.Sprintf("%d attempt(s) over %s: no PMKID. Try a full handshake: warp psk --deauth %s",
			res.Rounds, res.Elapsed, ap.BSSID)
	}
}

// DeauthParams asks for targeted deauthentication.
type DeauthParams struct {
	BSSID string `json:"bssid"`
	// Station is the client to disconnect. Required unless Broadcast is set.
	Station string `json:"station,omitempty"`
	// Broadcast takes every client off the network at once.
	//
	// Deauthenticating an *access point* without naming a client means broadcast - that is
	// what the operator asked for, and it is the better way to provoke a handshake because it
	// moves every client rather than one. Naming a station is the targeted form and is what
	// the client list offers.
	Broadcast bool `json:"broadcast,omitempty"`
	// Count is frames per burst. The campaign sends several bursts.
	Count int `json:"count,omitempty"`
	// Seconds bounds the campaign. Default 20, capped at 60 - beyond that this stops being a
	// test and becomes a sustained denial of service at a client site.
	Seconds int `json:"seconds,omitempty"`
}

func (d *Daemon) handleDeauth(ctx context.Context, params json.RawMessage) (any, error) {
	var p DeauthParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	ap, err := d.lookupAP(p.BSSID)
	if err != nil {
		return nil, err
	}
	if !d.ws.Scope.Contains(ap.ESSID) {
		return nil, rpc.Errorf(rpc.CodeScopeDenied,
			"%s broadcasts %q, which is not in scope; passive observation only",
			ap.BSSID, ap.ESSID)
	}

	if why := crackableCheck(ap); why != "" {
		d.Broadcast(rpc.Event{
			Kind: "deauth", Level: rpc.LevelWarn,
			Text:   "[!] " + ap.BSSID.String() + " - " + why,
			Fields: map[string]any{"bssid": ap.BSSID.String(), "essid": ap.ESSID},
		})
	}

	// No station named means the operator is acting on the access point, and at that level
	// the useful action is a broadcast: it moves every client rather than one, which is what
	// provokes a handshake. Naming a station is the targeted form, offered from the client
	// list where a specific device is already under the cursor.
	var target recon.MAC
	broadcast := p.Broadcast
	if p.Station != "" {
		if target, err = recon.ParseMAC(p.Station); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
		}
		broadcast = false
	} else {
		broadcast = true
	}

	// Refuse early where 802.11w is required. Transmitting anyway wastes airtime and produces
	// a false negative: "we deauthenticated and nothing happened" reads as resilience.
	if ap.Security.MFP == recon.MFPRequired {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s requires 802.11w management frame protection; associated clients ignore "+
				"unprotected deauthentication, so they cannot be forced off. That is a hardening "+
				"control on the network, not an exposure this attack can create - classification "+
				"notes it as a control (802.11w required)",
			ap.BSSID)
	}

	who := p.Station
	if broadcast {
		who = "broadcast"
	}
	window := campaignWindow(p.Seconds)

	job := d.jobs.Start(d.ctx, "deauth", ap.BSSID.String(), func(jctx context.Context) (any, error) {
		var res CampaignResult

		// The injector is held for the whole campaign rather than reacquired per round: a
		// radio handed back and retaken between bursts would be retuned each time, and the
		// channel hold would be pointless.
		err := d.withInjector(jctx, radio.RoleDeauth, ap.Freq, func(inj *inject.Injector) error {
			var cerr error
			res, cerr = d.runCampaign(jctx, ap, who, window, func(bctx context.Context) (int, error) {
				out, err := inject.Deauth(bctx, inj, inject.DeauthOptions{
					BSSID:          ap.BSSID,
					ESSID:          ap.ESSID,
					Target:         target,
					Channel:        ap.Channel,
					MFP:            ap.Security.MFP,
					Count:          p.Count,
					AllowBroadcast: broadcast,
				})
				return out.Frames, err
			})
			return cerr
		})
		if err != nil {
			return res, scopeRPCError(err)
		}

		level := rpc.LevelWarn
		if len(res.Captured) > 0 {
			level = rpc.LevelGood
		}
		d.Broadcast(rpc.Event{
			Kind: "deauth", Level: level,
			Text:   fmt.Sprintf("[*] deauth %s %s - %s", ap.BSSID, who, res.Outcome),
			Fields: map[string]any{"bssid": ap.BSSID.String(), "target": who},
		})
		return res, nil
	})

	return job, nil
}

// KarmaTestParams asks for a karma responder detection sweep.
type KarmaTestParams struct {
	// Channels to sweep. Empty means every channel a scoped AP was seen on.
	Channels []int `json:"channels,omitempty"`
}

// KarmaTestResult reports what answered.
type KarmaTestResult struct {
	ESSIDProbed string   `json:"essid_probed"`
	Channels    []int    `json:"channels"`
	Frames      int      `json:"frames"`
	Responders  []string `json:"responders"`
	Note        string   `json:"note"`
}

// channelToMHz converts an IEEE channel number to its centre frequency, picking the band from the
// channel number: 1-14 are 2.4 GHz, everything above is 5 GHz.
func channelToMHz(ch int) int {
	band := nl80211.Band5GHz
	if ch <= 14 {
		band = nl80211.Band2GHz
	}
	return nl80211.FrequencyForChannel(ch, band)
}

func (d *Daemon) handleKarmaTest(ctx context.Context, params json.RawMessage) (any, error) {
	var p KarmaTestParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
		}
	}

	channels := p.Channels
	if len(channels) == 0 {
		seen := map[int]struct{}{}
		for _, ap := range d.engine.Tracker().APs() {
			if ap.Channel != 0 && d.ws.Scope.Contains(ap.ESSID) {
				seen[ap.Channel] = struct{}{}
			}
		}
		for ch := range seen {
			channels = append(channels, ch)
		}
		if len(channels) == 0 {
			// Nothing scoped has been seen yet; sweep the common 2.4 GHz channels so the test
			// is still useful early in an engagement.
			channels = []int{1, 6, 11}
		}
	}

	job := d.jobs.Start(d.ctx, "karma-test", "", func(jctx context.Context) (any, error) {
		essid, err := inject.RandomESSID()
		if err != nil {
			return nil, err
		}
		sta, err := inject.RandomMAC()
		if err != nil {
			return nil, err
		}

		res := KarmaTestResult{
			ESSIDProbed: essid,
			Channels:    channels,
			Note: "Probed for a randomly generated ESSID that cannot exist. Anything that " +
				"answered is responding to arbitrary probes, which is characteristic of a " +
				"Wi-Fi Pineapple or equivalent attacker device. Nothing passive will find this.",
		}

		// Record the probed name before transmitting, so the capture path can recognise a
		// response to it.
		d.setKarmaProbe(essid)
		defer d.clearKarmaProbe()

		// One withInjector burst per channel, each tuned to that channel: the probe is
		// transmitted there and the same (borrowed) radio captures the response on the same
		// channel. Passing the channel is what actually retunes the adapter - a single burst with
		// channel 0 would send every probe on whatever channel the radio happened to be on and
		// silently test only that one.
		for _, ch := range channels {
			if err := jctx.Err(); err != nil {
				return res, err
			}
			mhz := channelToMHz(ch)
			err := d.withInjector(jctx, radio.RoleSolicit, mhz, func(inj *inject.Injector) error {
				sent, perr := inject.KarmaProbe(jctx, inj, sta, essid, ch, 3)
				res.Frames += sent
				if perr != nil {
					return perr
				}
				// Give any responder time to answer before moving to the next channel.
				select {
				case <-jctx.Done():
					return jctx.Err()
				case <-time.After(500 * time.Millisecond):
				}
				return nil
			})
			if err != nil {
				return res, scopeRPCError(err)
			}
		}

		res.Responders = d.karmaResponderList()
		if len(res.Responders) > 0 {
			d.Broadcast(rpc.Event{
				Kind: "karma", Level: rpc.LevelWarn,
				Text: fmt.Sprintf("[!] KARMA RESPONDER: %d device(s) answered a probe for a "+
					"network that does not exist: %v", len(res.Responders), res.Responders),
			})
		}
		return res, nil
	})

	return job, nil
}

// ---------------------------------------------------------------------------
// Rogue detection
// ---------------------------------------------------------------------------

func (d *Daemon) handleRogueClassify(ctx context.Context, _ json.RawMessage) (any, error) {
	aps := d.engine.Tracker().APs()

	d.karmaMu.RLock()
	responders := make(map[recon.MAC]string, len(d.karmaResponders))
	for k, v := range d.karmaResponders {
		responders[k] = v
	}
	d.karmaMu.RUnlock()

	res := d.classifier.Classify(aps, responders, time.Now())

	// The classifier's own conclusions are replaced on each pass, but findings recorded by the
	// active attacks (a WPS PIN recovered by Pixie Dust, a harvested certificate) are results of
	// work done - not conclusions re-derivable from a passive re-classify - so they are preserved.
	if err := d.store.ClearFindingsWithLabels(ctx, rogue.ClassifierLabels); err != nil {
		return nil, err
	}
	for _, f := range res.Findings {
		if err := d.store.UpsertFinding(ctx, f); err != nil {
			return nil, err
		}
	}

	// A BSSID that has already been tested by Pixie Dust keeps its definitive result across a
	// re-classify (those labels are not in ClassifierLabels). The classifier, however, re-derives
	// "WPS enabled and unlocked" from the beacon every pass, which would re-introduce the
	// preliminary note the active result already superseded - so drop it again for any tested AP.
	all, err := d.store.Findings(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, f := range all {
		if f.Label == LabelWPSResistant || f.Label == LabelWPSRecovered {
			if err := d.store.ClearFindingForBSSID(ctx, f.BSSID, rogue.LabelWPSUnlocked); err != nil {
				return nil, err
			}
		}
	}

	return map[string]any{
		"findings":     len(res.Findings),
		"unclassified": len(res.Unclassified),
		"analyses":     res.Analyses,
	}, nil
}

// RogueListParams filters the findings listing.
type RogueListParams struct {
	Tier string `json:"tier,omitempty"`
}

func (d *Daemon) handleRogueList(ctx context.Context, params json.RawMessage) (any, error) {
	var p RogueListParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
		}
	}

	tier := store.Tier(p.Tier)
	switch tier {
	case "", store.TierDetermined, store.TierEvidence, store.TierControl, store.TierUnclassified:
	default:
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"unknown tier %q (determined, evidence, control, unclassified)", p.Tier)
	}

	findings, err := d.store.Findings(ctx, tier)
	if err != nil {
		return nil, err
	}
	out := d.annotateFindings(findings)

	// The unclassified tier is not stored as findings - it is, by definition, the absence of
	// a conclusion - so it is derived here from what has no finding attached.
	if tier == store.TierUnclassified || tier == "" {
		labelled := map[string]bool{}
		all, err := d.store.Findings(ctx, "")
		if err != nil {
			return nil, err
		}
		for _, f := range all {
			labelled[f.BSSID] = true
		}
		var unclassified []string
		for _, ap := range d.engine.Tracker().APs() {
			if !labelled[ap.BSSID.String()] {
				unclassified = append(unclassified, ap.BSSID.String())
			}
		}
		return map[string]any{"findings": out, "unclassified": unclassified}, nil
	}

	return map[string]any{"findings": out}, nil
}

// findingOut is a finding decorated with whether its network is in the engagement scope, so the
// frontends can offer an "in scope only" filter without re-deriving scope membership themselves.
type findingOut struct {
	store.Finding
	InScope bool `json:"in_scope"`
}

// annotateFindings tags each finding with its scope membership. A finding with no ESSID (a hidden
// or unnamed device) has no name to match and is out of scope by definition here.
func (d *Daemon) annotateFindings(findings []store.Finding) []findingOut {
	out := make([]findingOut, 0, len(findings))
	for _, f := range findings {
		out = append(out, findingOut{
			Finding: f,
			InScope: findingInScope(f, d.ws.Scope.Contains),
		})
	}
	return out
}

// findingInScope reports whether a finding belongs in the in-scope view. Normally that is scope
// membership of its ESSID, but a manually-marked potential rogue is always in-scope-relevant: it is
// a finding about a device in the client's footprint that, being a suspected impostor, will not sit
// on a scoped ESSID. Filtering it out with the neighbours would hide the finding the operator
// deliberately raised.
func findingInScope(f store.Finding, inScope func(string) bool) bool {
	if f.Label == rogue.LabelPotentialRogue {
		return true
	}
	return f.ESSID != "" && inScope(f.ESSID)
}

func (d *Daemon) handleRogueDetail(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		BSSID string `json:"bssid"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	ap, err := d.lookupAP(p.BSSID)
	if err != nil {
		return nil, err
	}

	findings, err := d.store.FindingsFor(ctx, ap.BSSID.String())
	if err != nil {
		return nil, err
	}

	// Re-run the analysis for this ESSID so the operator can see the population the
	// conclusion came from, not just the conclusion.
	var analysis *rogue.Analysis
	if ap.ESSID != "" && d.ws.Scope.Contains(ap.ESSID) {
		a := rogue.AnalyseESSID(ap.ESSID, d.engine.Tracker().APsForESSID(ap.ESSID), rogue.Config{})
		analysis = &a
	}

	return map[string]any{
		"ap":       ap,
		"findings": findings,
		"analysis": analysis,
	}, nil
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

func (d *Daemon) handleJobsList(context.Context, json.RawMessage) (any, error) {
	return d.jobs.List(), nil
}

func (d *Daemon) handleJobsKill(_ context.Context, params json.RawMessage) (any, error) {
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if err := d.jobs.Kill(p.ID); err != nil {
		if errors.Is(err, ErrNoJob) {
			return nil, rpc.Errorf(rpc.CodeNotFound, "%v", err)
		}
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	return map[string]string{"id": p.ID, "state": string(JobKilled)}, nil
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

// ReportParams configures report generation.
type ReportParams struct {
	Title           string `json:"title,omitempty"`
	IncludeStations bool   `json:"include_stations,omitempty"`
}

func (d *Daemon) handleReport(ctx context.Context, params json.RawMessage) (any, error) {
	var p ReportParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
		}
	}

	rep, err := report.Build(ctx, d.store, d.ws.Gate, report.Options{
		Title:           p.Title,
		IncludeStations: p.IncludeStations,
	})
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := rep.WriteMarkdown(&buf); err != nil {
		return nil, err
	}

	path := d.ws.Path("report.md")
	// 0600: the report names the client and everything found at their site.
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("daemon: write report: %w", err)
	}

	return map[string]any{
		"path":     path,
		"bytes":    buf.Len(),
		"findings": len(rep.Findings),
		"markdown": buf.String(),
	}, nil
}

// ReportExportParams selects which machine-readable report to return for download.
type ReportExportParams struct {
	// Scoped returns the in-scope-only deliverable; false returns everything observed.
	Scoped bool `json:"scoped,omitempty"`
}

// handleReportExport builds the machine-readable (JSON) engagement report. It writes both the
// in-scope-only and the full document to the engagement directory each time (so both files are
// always current), and returns the one the caller asked for so a frontend can offer it as a
// download. No secret material is included - only what was captured for which network.
func (d *Daemon) handleReportExport(ctx context.Context, params json.RawMessage) (any, error) {
	var p ReportExportParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
		}
	}

	rep, err := report.Build(ctx, d.store, d.ws.Gate, report.Options{})
	if err != nil {
		return nil, err
	}
	caps, err := d.captureSummary(ctx)
	if err != nil {
		return nil, err
	}
	tool := report.Tool{Name: build.Name, Version: build.Version, Commit: build.Commit}

	// Write both variants so the engagement directory always has both files.
	var chosen report.Data
	for _, scoped := range []bool{false, true} {
		data := report.BuildData(rep, tool, d.ws.Scope.Contains, caps, scoped)
		name := "report.json"
		if scoped {
			name = "report-in-scope.json"
		}
		buf, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("daemon: marshal report json: %w", err)
		}
		if err := os.WriteFile(d.ws.Path(name), buf, 0o600); err != nil {
			return nil, fmt.Errorf("daemon: write %s: %w", name, err)
		}
		if scoped == p.Scoped {
			chosen = data
		}
	}

	return map[string]any{
		"scoped": p.Scoped,
		"path":   d.ws.Path(map[bool]string{false: "report.json", true: "report-in-scope.json"}[p.Scoped]),
		"report": chosen,
	}, nil
}

// captureSummary rolls up what was recovered per ESSID, with no secret values: PMKID/handshake
// counts from the store, and WPS/enterprise presence from the daemon's own credential state.
func (d *Daemon) captureSummary(ctx context.Context) (map[string]report.CaptureSummary, error) {
	caps := map[string]report.CaptureSummary{}

	hashes, err := d.store.Hashes(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range hashes {
		c := caps[h.ESSID]
		switch h.Kind {
		case "pmkid":
			c.PMKID++
		case "handshake":
			c.Handshake++
		}
		caps[h.ESSID] = c
	}

	d.wpsMu.Lock()
	for _, k := range d.wpsKeys {
		c := caps[k.ESSID]
		if k.PSK != "" {
			c.WPSPassphrase = true
		}
		if k.PIN != "" {
			c.WPSPin = true
		}
		caps[k.ESSID] = c
	}
	d.wpsMu.Unlock()

	d.eap.mu.RLock()
	for _, o := range d.eap.captured {
		c := caps[o.ESSID]
		c.EnterpriseMSCHAPv2++
		caps[o.ESSID] = c
	}
	d.eap.mu.RUnlock()

	return caps, nil
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

func (d *Daemon) handleExport(ctx context.Context, _ json.RawMessage) (any, error) {
	// Everything below is already current to within a few seconds - the projections are
	// regenerated on the state tick and observations.csv is appended live. `export` exists to
	// pull the last couple of seconds forward on demand, not to produce the files for the first
	// time, so it flushes the engine's buffers and then rebuilds.
	//
	// It deliberately does not rebuild observations.csv: the engine holds an open append handle
	// on that path, and renaming a fresh file over it would leave the daemon writing to an
	// unlinked inode with no error anywhere.
	d.engine.FlushNow()
	if err := d.store.ExportCSV(ctx, d.ws.Dir); err != nil {
		return nil, err
	}
	counts, err := d.store.Counts(ctx)
	if err != nil {
		return nil, err
	}
	pmkid, handshakes, _ := d.store.HashCounts(ctx)

	return map[string]any{
		"directory":        d.ws.Dir,
		"counts":           counts,
		"pmkid_hashes":     pmkid,
		"handshake_hashes": handshakes,
		"files": []string{
			store.APsCSV, store.StationsCSV, store.ObservationsCSV,
			store.WalkthroughsCSV, store.FindingsCSV, store.RoguesCSV,
		},
	}, nil
}

// handleExportBundle regenerates the flat-file projections and returns them as a single zip
// (base64), so a frontend can offer one download. The zip is built in memory and never written to
// disk - only the individual projection files persist in the engagement directory. observations.csv
// is left out on purpose: it is the append-only frame log and can be enormous.
func (d *Daemon) handleExportBundle(ctx context.Context, _ json.RawMessage) (any, error) {
	d.engine.FlushNow()
	if err := d.store.ExportCSV(ctx, d.ws.Dir); err != nil {
		return nil, err
	}

	bundle := []string{
		store.APsCSV, store.StationsCSV, store.RoguesCSV, store.WalkthroughsCSV,
		store.FindingsCSV, store.FindingsInScopeCSV, store.NetXMLFile,
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	included := 0
	for _, name := range bundle {
		data, err := os.ReadFile(d.ws.Path(name))
		if err != nil {
			continue // a projection with nothing to write yet is simply skipped
		}
		w, err := zw.Create(name)
		if err != nil {
			return nil, fmt.Errorf("daemon: zip %s: %w", name, err)
		}
		if _, err := w.Write(data); err != nil {
			return nil, fmt.Errorf("daemon: zip write %s: %w", name, err)
		}
		included++
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("daemon: close zip: %w", err)
	}

	return map[string]any{
		"filename":   fmt.Sprintf("warp-projections-%s.zip", time.Now().UTC().Format("20060102-150405")),
		"files":      included,
		"zip_base64": base64.StdEncoding.EncodeToString(buf.Bytes()),
	}, nil
}
