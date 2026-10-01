package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/rogue"
	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/store"
	"github.com/waffl3ss/warp/internal/wps"
)

// WPS Pixie Dust.
//
// One association, the WSC registrar exchange, disconnect - then arithmetic. Pixie Dust recovers
// the PIN offline from M3; when it does, the exchange goes on to complete registration with that
// PIN and read the access point's own passphrase out of M7. It stops at M7 and never sends M8, so
// no configuration is written back and nothing joins the network - reading a credential, not using
// WPS. Online PIN *brute force* is still deliberately not implemented: it needs thousands of round
// trips over hours, locks WPS on production hardware, and fills the client's logs. This is one
// exchange with a PIN already recovered offline.

// WPS finding labels. These are stable strings - they appear in reports and in findings.csv.
const (
	// LabelWPSResistant is a pass: WPS was reachable, WARP ran one offline Pixie Dust exchange, and
	// the AP's nonces held. It is a control, not an exposure.
	LabelWPSResistant = "WPS enabled and resistant to offline PIN recovery"
	// LabelWPSRecovered is the exposure: the PIN fell to Pixie Dust and the passphrase was read.
	LabelWPSRecovered = "WPS PIN recovered offline (Pixie Dust)"
)

// WPSParams asks for a Pixie Dust attempt at a discovered access point.
type WPSParams struct {
	BSSID string `json:"bssid"`
	// Seconds bounds the exchange. Default 20, capped at 60 like every other campaign.
	Seconds int `json:"seconds,omitempty"`
}

// WPSResult is what an attempt reports.
type WPSResult struct {
	BSSID   string     `json:"bssid"`
	ESSID   string     `json:"essid"`
	Station string     `json:"station"`
	Device  wps.Device `json:"device"`

	Recovered bool            `json:"recovered"`
	PIN       string          `json:"pin,omitempty"`
	PSK       string          `json:"psk,omitempty"`
	Generator wps.Generator   `json:"generator,omitempty"`
	Elapsed   string          `json:"recovery_time,omitempty"`
	RuledOut  []wps.Generator `json:"generators_ruled_out,omitempty"`

	Outcome string `json:"outcome"`
}

// Summary implements Summariser.
func (r WPSResult) Summary() string { return r.Outcome }

// WPSCredential is a recovered WPS credential, surfaced in the Credentials view. The PIN is always
// present when recovered; PSK carries the network passphrase when the exchange went on to read it
// from M7.
type WPSCredential struct {
	BSSID     string        `json:"bssid"`
	ESSID     string        `json:"essid"`
	PIN       string        `json:"pin"`
	PSK       string        `json:"psk,omitempty"`
	Generator wps.Generator `json:"generator,omitempty"`
	At        time.Time     `json:"at"`
}

// recordWPSCredential keeps a recovered credential for the Credentials view.
func (d *Daemon) recordWPSCredential(c WPSCredential) {
	d.wpsMu.Lock()
	// De-duplicate on BSSID: a re-run of the same access point updates rather than piles up.
	replaced := false
	for i, existing := range d.wpsKeys {
		if existing.BSSID == c.BSSID {
			d.wpsKeys[i] = c
			replaced = true
			break
		}
	}
	if !replaced {
		d.wpsKeys = append(d.wpsKeys, c)
	}
	d.wpsMu.Unlock()

	// Write a durable deliverable, mirroring the MSCHAPv2 creds file. The in-memory list drives
	// the credentials tab for the live session; this file is what survives to the report, since a
	// recovered passphrase is the whole point of the exchange. Best-effort - the finding and the
	// audit log already record it regardless.
	if c.PSK != "" {
		if err := d.appendWPSKey(c); err != nil {
			d.log.Warn("could not write the WPS key file", "err", err)
		}
	}

	// Refresh the consolidated, always-current credentials summary.
	d.writeCredentialsFile()
}

// WPSKeyFile is where recovered WPS passphrases are appended, inside the workspace's creds/.
const WPSKeyFile = "wps-keys.txt"

// loadWPSKeys reads any previously-recovered WPS keys from creds/wps-keys.txt back into memory on
// startup, so a recovered passphrase keeps showing in the credentials tab across a daemon restart.
// Best-effort: a missing or malformed file just means nothing to reload.
func (d *Daemon) loadWPSKeys() {
	data, err := os.ReadFile(filepath.Join(d.ws.Path("creds"), WPSKeyFile))
	if err != nil {
		return
	}
	d.wpsMu.Lock()
	defer d.wpsMu.Unlock()
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue // essid, bssid, psk, pin are the minimum
		}
		c := WPSCredential{ESSID: f[0], BSSID: f[1], PSK: f[2], PIN: f[3]}
		if len(f) > 4 {
			c.Generator = wps.Generator(f[4])
		}
		if len(f) > 5 {
			c.At, _ = time.Parse(time.RFC3339, f[5])
		}
		// De-duplicate on BSSID, newest line wins (the file is append-only, so a re-run appends).
		replaced := false
		for i, existing := range d.wpsKeys {
			if existing.BSSID == c.BSSID {
				d.wpsKeys[i] = c
				replaced = true
				break
			}
		}
		if !replaced {
			d.wpsKeys = append(d.wpsKeys, c)
		}
	}
}

// appendWPSKey writes one recovered WPS credential to creds/wps-keys.txt as a durable artifact.
func (d *Daemon) appendWPSKey(c WPSCredential) error {
	dir := d.ws.Path("creds")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("daemon: create creds directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(dir, WPSKeyFile),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("daemon: open WPS key file: %w", err)
	}
	defer f.Close()
	// essid<TAB>bssid<TAB>passphrase<TAB>pin<TAB>generator<TAB>timestamp
	line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n",
		c.ESSID, c.BSSID, c.PSK, c.PIN, c.Generator, c.At.Format(time.RFC3339))
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("daemon: append WPS key: %w", err)
	}
	return f.Sync()
}

// wpsCredentials returns a copy of the recovered WPS credentials, newest first.
func (d *Daemon) wpsCredentials() []WPSCredential {
	d.wpsMu.RLock()
	defer d.wpsMu.RUnlock()
	out := make([]WPSCredential, len(d.wpsKeys))
	for i, c := range d.wpsKeys {
		out[len(d.wpsKeys)-1-i] = c
	}
	return out
}

func (d *Daemon) handleWPS(ctx context.Context, params json.RawMessage) (any, error) {
	var p WPSParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}

	ap, err := d.lookupAP(p.BSSID)
	if err != nil {
		return nil, err
	}

	// Refused here as well as at the gate so the operator gets a refusal that names the
	// network rather than one that names a frame. The gate still decides - every frame goes
	// through it - and this is not a second authorization path.
	if ap.ESSID == "" {
		return nil, rpc.Errorf(rpc.CodeScopeDenied,
			"%s broadcasts no network name, so there is nothing to authorize against scope. "+
				"Recover it first: warp decloak %s", ap.BSSID, ap.BSSID)
	}
	if _, _, ok := d.ws.Scope.Match(ap.ESSID); !ok {
		return nil, rpc.Errorf(rpc.CodeScopeDenied,
			"%q is not in scope, and Pixie Dust associates to the access point - that is "+
				"transmission, and it is authorized by ESSID like everything else", ap.ESSID)
	}
	if !ap.Security.WPS {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s advertises no WPS element, so there is no registration protocol to run "+
				"against it. That absence is itself the finding", ap.BSSID)
	}
	if ap.Security.WPSLocked {
		// Not refused: locked state is advertised in the beacon and access points do lie about
		// it, or unlock on a timer. The operator is told what to expect and the attempt runs.
		d.Broadcast(rpc.Event{
			Kind: "wps", Level: rpc.LevelWarn,
			Text: fmt.Sprintf("[!] %s advertises WPS as locked - the exchange will probably be "+
				"refused, which is itself the correct configuration", ap.BSSID),
		})
	}

	// The registrar exchange runs over a real, kernel-driven association - the firmware ACKs the
	// access point the way it does for wpa_supplicant. The active-monitor injection path could
	// never reliably get that ACK on drivers that do not loop injected frames, so the WSC exchange
	// died silently. Unlike PMKID/harvest, this association is *open* and carries a WSC element
	// (wpsConnectParams), which is what makes the AP run EAP-WSC rather than the WPA four-way.
	cp, ok := wpsConnectParams(ap)
	if !ok {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s (%s) is not a network WARP can associate to for a WPS exchange", ap.BSSID, ap.Security.Class)
	}

	window := campaignWindow(p.Seconds)

	job := d.jobs.Start(d.ctx, "wps", ap.BSSID.String(), func(jctx context.Context) (any, error) {
		jctx, cancel := context.WithTimeout(jctx, window)
		defer cancel()

		var (
			dev     wps.Device
			res     wps.Result
			staUsed recon.MAC
		)
		// A kernel-driven association, then the WSC registrar exchange over its 802.1X control
		// port (carried over nl80211, the same transport the certificate harvest uses). The WSC
		// messages arrive on the socket that owns the association, not on a capture radio, so no
		// channel hold is needed. The exchange recovers the PIN at M3 and, when it does, completes
		// registration to M7 to read the passphrase - it never sends M8, so nothing is reconfigured
		// and nothing joins the network.
		err = d.withStation(jctx, radio.RoleDeauth, cp, func(sta recon.MAC, _ string, eapol eapolTransport) error {
			staUsed = sta

			// Give the association a moment to settle before the first 802.1X frame. An access
			// point that receives EAPOL-Start before the station's entry exists discards it.
			select {
			case <-time.After(assocSettle):
			case <-jctx.Done():
				return jctx.Err()
			}

			var xerr error
			_, dev, res, xerr = wps.Exchange(jctx, eapol, wps.ExchangeOptions{
				Log: func(format string, args ...any) {
					d.log.Info("wps exchange", "step", fmt.Sprintf(format, args...), "bssid", ap.BSSID.String())
				},
			})
			return xerr
		})

		out := WPSResult{
			BSSID: ap.BSSID.String(), ESSID: ap.ESSID,
			Station: staUsed.String(), Device: dev,
		}

		switch {
		case errors.Is(err, wps.ErrLocked):
			// A pass, and a real one. Say so rather than reporting a failure the reader cannot
			// distinguish from a broken tool.
			out.Outcome = "the access point refused the registration - WPS is locked. That is " +
				"the correct configuration and is recorded as a pass."
			d.recordWPSFinding(jctx, ap, out)
			return out, nil

		case errors.Is(err, wps.ErrNoWPS):
			out.Outcome = fmt.Sprintf(
				"%s: the open+WSC association completed, but no EAP-WSC registration exchange "+
					"started. This means WPS is disabled in software while still being beaconed - a "+
					"real, reportable finding - rather than proof the AP is unreachable.",
				ap.BSSID)
			return out, nil

		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			out.Outcome = fmt.Sprintf(
				"%s: the association or WSC exchange was still in progress when the window "+
					"elapsed. The access point may be slow to answer or out of range - try again, "+
					"or give it longer with --seconds.", ap.BSSID)
			return out, nil

		case err != nil:
			// The association was refused or could not be completed, so the WSC exchange never
			// started. The kernel returns the 802.11 status in the error text. Status 1 is
			// "unspecified failure" - a catch-all that also covers an auth/assoc that timed out on
			// a weak or asymmetric link, which is the usual cause on a distant AP; MAC filtering or
			// an undisclosed 802.11w policy are the others. The request mirrored the AP's advertised
			// RSN, so it is not an offer mismatch WARP can fix by changing the crypto.
			out.Outcome = fmt.Sprintf(
				"%s did not complete the association%s, so no WPS exchange could start: %v. Move "+
					"closer or retry; if it keeps refusing, the AP is declining an unknown station "+
					"rather than WPS being absent.",
				ap.BSSID, rssiNote(ap), err)
			return out, nil
		}

		// The exchange has already run the offline recovery (and, when it succeeded, gone on to
		// read the passphrase from M7); res carries both.
		out.Recovered = res.Recovered
		out.PIN = res.PIN
		out.PSK = res.NetworkKey
		out.Generator = res.Generator
		out.Elapsed = res.Elapsed.Round(time.Millisecond).String()
		out.RuledOut = res.Tried
		out.Outcome = res.Describe()

		if res.Recovered {
			d.recordWPSCredential(WPSCredential{
				BSSID: ap.BSSID.String(), ESSID: ap.ESSID,
				PIN: res.PIN, PSK: res.NetworkKey, Generator: res.Generator, At: time.Now(),
			})
			text := fmt.Sprintf("[+] WPS PIN %s recovered at %s (%s) - %s",
				res.PIN, ap.ESSID, ap.BSSID, res.Generator)
			if res.NetworkKey != "" {
				text = fmt.Sprintf("[+] WPS PIN %s → WPA passphrase %q at %s (%s) - %s",
					res.PIN, res.NetworkKey, ap.ESSID, ap.BSSID, res.Generator)
			}
			fields := map[string]any{
				"bssid": ap.BSSID.String(), "essid": ap.ESSID,
				"pin": res.PIN, "generator": string(res.Generator),
			}
			if res.NetworkKey != "" {
				fields["psk"] = res.NetworkKey
			}
			d.Broadcast(rpc.Event{Kind: "wps", Level: rpc.LevelGood, Text: text, Fields: fields})
			d.logEvent(audit.KindHarvest, audit.OutcomeInfo,
				"WPS PIN recovered offline from one registration exchange",
				map[string]any{
					"bssid": ap.BSSID.String(), "essid": ap.ESSID,
					"station": staUsed.String(), "generator": string(res.Generator),
					"device": dev.ModelName, "passphrase_recovered": res.NetworkKey != "",
				})
		}
		d.recordWPSFinding(jctx, ap, out)

		return out, nil
	})

	return job, nil
}

// recordWPSFinding writes the result into the findings table so it reaches the report.
//
// Both outcomes are recorded. A device that resisted Pixie Dust is a pass - a control, not an
// exposure - and belongs in the report as one: a report that only lists what broke leaves the
// reader unable to tell what was tested from what was not. A recovered PIN is a real exposure and
// is filed as a determined finding.
//
// Either way the active result supersedes the classifier's preliminary "WPS enabled and unlocked"
// note for this device: that note means only that the beacon advertised WPS unlocked (reachable),
// and once the exchange has actually run, the definitive result replaces it rather than sitting
// beside it.
func (d *Daemon) recordWPSFinding(ctx context.Context, ap recon.AP, res WPSResult) {
	label := LabelWPSResistant
	tier := store.TierControl
	// The finding describes the exposure; the recovered secret itself (PIN, passphrase) is a
	// credential and lives on the credentials tab and in creds/wps-keys.txt, not embedded in a
	// finding's prose. res.Outcome carries the passphrase, so it is not used as the rationale for
	// a successful recovery.
	rationale := res.Outcome
	if res.Recovered {
		label = LabelWPSRecovered
		tier = store.TierDetermined
		rationale = "WPS is enabled and the access point's registration nonces are weak, so the " +
			"PIN was recovered offline from a single Pixie Dust exchange and used to read the WPA " +
			"passphrase out of M7 (the exchange stopped at M7 and never wrote M8, so nothing was " +
			"reconfigured). The recovered PIN and passphrase are on the Credentials tab and in " +
			"creds/wps-keys.txt."
	}

	// Supersede the classifier's beacon-derived "unlocked" note now that the AP has actually been
	// tested. rogue.LabelWPSUnlocked is the exposure the active result replaces.
	if err := d.store.ClearFindingForBSSID(ctx, ap.BSSID.String(), rogue.LabelWPSUnlocked); err != nil {
		d.log.Error("could not supersede the WPS unlocked finding", "bssid", ap.BSSID, "err", err)
	}

	f := store.Finding{
		BSSID:     ap.BSSID.String(),
		ESSID:     ap.ESSID,
		Tier:      tier,
		Label:     label,
		Rationale: rationale,
		FirstTS:   time.Now(),
		LastTS:    time.Now(),
	}
	if res.Device.ModelName != "" || res.Device.Manufacturer != "" {
		f.Differences = append(f.Differences,
			fmt.Sprintf("device: %s %s", res.Device.Manufacturer, res.Device.ModelName))
	}
	if res.Recovered {
		// The nonce generator is the demonstrable technical fact (which weak generator produced
		// the recoverable nonces); the PIN/passphrase are the credential and are not repeated here.
		f.Differences = append(f.Differences,
			fmt.Sprintf("nonce generator: %s", res.Generator))
	}

	if err := d.store.UpsertFinding(ctx, f); err != nil {
		d.log.Error("could not record the WPS finding", "bssid", ap.BSSID, "err", err)
	}
}
