package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/eap/harvest"
	"github.com/waffl3ss/warp/internal/eap/mimic"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/rpc"
)

// Certificate harvesting.
//
// # Why this exists
//
// A rogue AP that presents a self-signed certificate with none of the target's naming on it is
// refused by every client that shows the user anything at all. The mimic has to be built from
// the real certificate - and the real certificate is available to anyone who starts a
// connection, because the RADIUS server presents it before it knows who is asking.
//
// It has always been possible to get by hand: capture an authentication in Wireshark, filter
// for the TLS Certificate record (`tls.handshake.type == 11`), export it. That is tedious
// enough that people skip it and ship a self-signed certificate that fools nobody. This does
// the same thing in one command.
//
// # What it does
//
// WARP associates to the access point itself and runs its own EAP-TLS client over the
// association, exactly as `wpa_supplicant` does - minus the passphrase. The association is a real,
// kernel-driven one (radio.AcquireStation → nl80211 CMD_CONNECT), so the firmware acknowledges the
// access point the way it does for any client; the active-monitor injection path could never
// reliably get that ACK, which is why associations died silently on some drivers. The RADIUS
// server presents its certificate in the clear at the very start of EAP-TLS, before it knows who
// is asking, so the certificate arrives and the exchange is abandoned - WARP has no credentials
// and needs none. EAPOL rides the nl80211 control port on the socket that owns the association
// (radio.AcquireStation → nl80211.StationConn), which is what carries EAPOL on drivers where the
// data-path packet socket does not.
//
// This does not deauthenticate anyone and does not wait for a client: WARP *is* the client,
// generating the exchange that carries the certificate. It still associates, which is
// transmission, so it is authorized by ESSID like everything else.

// HarvestParams asks for a certificate harvest at a discovered enterprise access point.
type HarvestParams struct {
	BSSID string `json:"bssid"`
	// Seconds bounds the whole exchange. Default 20, capped at 60 like every other campaign.
	Seconds int `json:"seconds,omitempty"`
}

// HarvestResult is what a completed harvest reports.
type HarvestResult struct {
	ESSID       string   `json:"essid"`
	BSSID       string   `json:"bssid"`
	Station     string   `json:"station"`
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	SANs        []string `json:"sans,omitempty"`
	NotAfter    string   `json:"not_after"`
	KeyBits     int      `json:"key_bits"`
	Fingerprint string   `json:"fingerprint_sha256"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	ChainLength int      `json:"chain_length"`
	PEMPath     string   `json:"pem_path"`
	JSONPath    string   `json:"json_path"`
	Notes       []string `json:"notes,omitempty"`
	// MimicSubject is what the rogue will claim if this harvest is used. Shown because it is
	// deliberately not identical to Subject - see mimic.Distinguish.
	MimicSubject string `json:"mimic_subject"`
	// CertID names the mimic filed in the engagement's certificate library, and Selected says
	// whether the rogue will now present it.
	CertID   string `json:"certificate_id,omitempty"`
	Selected bool   `json:"selected,omitempty"`

	Outcome string `json:"outcome"`
}

// Summary implements Summariser.
func (r HarvestResult) Summary() string { return r.Outcome }

func (d *Daemon) handleHarvest(ctx context.Context, params json.RawMessage) (any, error) {
	var p HarvestParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}

	ap, err := d.lookupAP(p.BSSID)
	if err != nil {
		return nil, err
	}

	// Scope is checked here as well as at the gate, so the operator gets a refusal that names
	// the network instead of one that names a frame. The gate still decides - every frame this
	// sends goes through it - and this is not a second authorization path.
	if ap.ESSID == "" {
		return nil, rpc.Errorf(rpc.CodeScopeDenied,
			"%s broadcasts no network name, so there is nothing to authorize against scope. "+
				"Recover it first: warp decloak %s", ap.BSSID, ap.BSSID)
	}
	if _, _, ok := d.ws.Scope.Match(ap.ESSID); !ok {
		return nil, rpc.Errorf(rpc.CodeScopeDenied,
			"%q is not in scope, and harvesting associates to the access point - that is "+
				"transmission, and it is authorized by ESSID like everything else", ap.ESSID)
	}
	if ap.Security.Class != recon.SecWPAEnterprise {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s is %s, not WPA-Enterprise. There is no RADIUS server behind it and no "+
				"certificate to harvest", ap.BSSID, ap.Security.Class)
	}

	window := campaignWindow(p.Seconds)

	cp, ok := connectParamsForAP(ap)
	if !ok {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"%s (%s) is not a network WARP can associate to for harvesting", ap.ESSID, ap.Security.Class)
	}

	// What we are about to offer versus what the access point advertised. When an association is
	// refused with a bare status 1, the mismatch is somewhere in here - a cipher or AKM the AP does
	// not run, or an 802.11w posture it disagrees with - and this is the only way to see it without
	// a second capture radio on the exchange.
	d.log.Info("harvest connect offer",
		"essid", ap.ESSID,
		"ap_class", string(ap.Security.Class),
		"ap_ciphers", strings.Join(ap.Security.Ciphers, ","),
		"ap_akms", strings.Join(ap.Security.AKMs, ","),
		"ap_mfp", ap.Security.MFP.String(),
		"ap_rsn_bytes", len(ap.Security.RSNElement),
		"offer_wpa_versions", cp.WPAVersions,
		"offer_group", fmt.Sprintf("0x%08x", cp.Group),
		"offer_pairwise", suitesHex(cp.Pairwise),
		"offer_akms", suitesHex(cp.AKMs),
		"offer_mfp", cp.MFP,
	)

	job := d.jobs.Start(d.ctx, "harvest", ap.BSSID.String(), func(jctx context.Context) (any, error) {
		jctx, cancel := context.WithTimeout(jctx, window)
		defer cancel()

		var (
			res           *harvest.Result
			sta           recon.MAC
			eapolSent     uint64
			eapolReceived uint64
		)

		// WARP associates to the access point itself - a real, kernel-driven association the
		// firmware acknowledges the way it does for wpa_supplicant - and runs its own EAP-TLS
		// client over it. The RADIUS server presents its certificate at the very start of the
		// exchange, before authentication, so the certificate arrives and the exchange is then
		// abandoned: WARP has no credentials and needs none. This does not deauthenticate anyone
		// and does not wait for a client - WARP *is* the client, generating the exchange that
		// carries the certificate.
		err := d.withStation(jctx, radio.RoleDeauth, cp, func(staMAC recon.MAC, _ string, eapol eapolTransport) error {
			sta = staMAC

			// Give the access point a moment after the association completes to bring the station's
			// control port up on its side before the first EAPOL frame.
			select {
			case <-time.After(assocSettle):
			case <-jctx.Done():
				return jctx.Err()
			}

			var herr error
			res, herr = harvest.Harvest(jctx, eapol, harvest.PeerOptions{
				ESSID: ap.ESSID, BSSID: ap.BSSID.String(),
			})
			if c, ok := eapol.(interface {
				Sent() uint64
				Received() uint64
			}); ok {
				eapolSent, eapolReceived = c.Sent(), c.Received()
			}
			return herr
		})

		// The EAPOL frame counts are the diagnosis when nothing comes back: they say whether our
		// frames left the socket and whether the access point answered at all.
		d.log.Info("harvest EAPOL exchange",
			"essid", ap.ESSID, "bssid", ap.BSSID.String(), "station", sta.String(),
			"eapol_sent", eapolSent, "eapol_received", eapolReceived, "err", err)

		if err != nil {
			return nil, harvestConnectDiagnosis(ap, sta, eapolSent, eapolReceived, err)
		}
		if res == nil {
			return nil, harvestConnectDiagnosis(ap, sta, eapolSent, eapolReceived, harvest.ErrNoEnterpriseExchange)
		}

		pemPath, jsonPath, err := res.Save(d.ws.Path("certs"))
		if err != nil {
			return nil, err
		}

		// Build the mimic now and file it in the certificate library, rather than at the
		// moment the rogue starts. Two reasons: the operator gets to see exactly what will go
		// on the air while they are still standing next to the access point, and a harvest
		// that produces an unusable mimic - a key size the generator cannot match, a validity
		// window already in the past - fails here rather than an hour later when the rogue
		// refuses to come up.
		out := harvestView(res, sta, pemPath, jsonPath)
		if h, mErr := res.MimicSource(); mErr == nil {
			if chain, gErr := mimic.Generate(h, mimic.Options{}); gErr == nil {
				if entry, aErr := d.certs().AddMimic(ap.ESSID,
					"mimicked from the certificate harvested at "+ap.BSSID.String(),
					chain); aErr == nil {
					out.CertID = entry.ID
					out.MimicSubject = entry.Subject
					out.Selected = entry.Selected
				} else {
					d.log.Warn("could not file the mimic", "essid", ap.ESSID, "err", aErr)
				}
			}
		}
		d.Broadcast(rpc.Event{
			Kind: "harvest", Level: rpc.LevelGood,
			Text: fmt.Sprintf("[+] HARVESTED %s - %s (%s)", ap.ESSID, out.Subject, out.Issuer),
			Fields: map[string]any{
				"essid": ap.ESSID, "bssid": ap.BSSID.String(),
				"subject": out.Subject, "fingerprint": out.Fingerprint,
			},
		})
		d.logEvent(audit.KindHarvest, audit.OutcomeInfo,
			"certificate harvested by associating to the access point and running an EAP-TLS "+
				"client; the exchange was abandoned before authentication",
			map[string]any{
				"essid": ap.ESSID, "bssid": ap.BSSID.String(),
				"station": sta.String(), "subject": out.Subject,
				"fingerprint": out.Fingerprint, "pem": pemPath,
			})

		return out, nil
	})

	return job, nil
}

// assocSettle is how long to wait after the association completes before sending the first EAPOL
// frame, giving the access point a moment to bring the station's control port up on its side.
const assocSettle = 1500 * time.Millisecond

// harvestConnectDiagnosis turns a harvest that got no certificate into something an operator can
// act on.
//
// The harvest now drives a real kernel association, so the failure modes are a supplicant's, not a
// passive listener's: the association was refused, or it completed but the access point never
// started EAP, or our EAP-TLS client and the server could not agree. It reports what actually
// happened rather than guessing.
func harvestConnectDiagnosis(ap recon.AP, sta recon.MAC, eapolSent, eapolReceived uint64, err error) error {
	// A cancelled or timed-out job is not a diagnosis.
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return rpc.Errorf(rpc.CodeInternal,
			"%s (%s): the association or EAP exchange was still in progress when the window "+
				"elapsed - the access point may be out of range or slow to answer. Try again, or "+
				"give it longer with `--seconds`.", ap.ESSID, ap.BSSID)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "No certificate harvested from %s (%s) on channel %d.\n\n",
		ap.ESSID, ap.BSSID, ap.Channel)
	fmt.Fprintf(&b, "  associated as     %s\n", sta)
	fmt.Fprintf(&b, "  EAPOL frames sent %d, received %d\n", eapolSent, eapolReceived)
	fmt.Fprintf(&b, "  underlying error  %v\n\n", err)

	switch {
	case errors.Is(err, harvest.ErrNoEnterpriseExchange) && eapolReceived == 0:
		// The association completed (the kernel confirmed it) but not one EAPOL frame came back.
		// The frame counts localise the fault to the control port: our EAPOL either did not reach
		// the access point, or its reply did not reach our packet socket.
		b.WriteString(
			"The association completed but no EAPOL frame came back from the access point - the " +
				"802.1X control port is not carrying traffic. This is not a scope or range issue " +
				"and, since the kernel confirmed the association, not an association failure " +
				"either. On some drivers the control port only works over nl80211 rather than the " +
				"data path WARP is using; on others hostapd must be configured to answer. To see " +
				"which half is stuck, watch EAPOL on the associating (managed) interface during a " +
				"harvest from another terminal:\n" +
				"    sudo tcpdump -i <that-iface> -e -n ether proto 0x888e\n" +
				"If our EAPOL-Start goes out but nothing returns, the access point is not " +
				"answering; if nothing goes out at all, the send path is the problem.")
	case errors.Is(err, harvest.ErrNoEnterpriseExchange):
		b.WriteString(
			"The access point answered EAPOL but never sent an EAP request that started the " +
				"certificate exchange. The network may not be running 802.1X on this BSS, or it is " +
				"waiting on something our anonymous identity did not provide.")
	default:
		b.WriteString(
			"WARP associated and EAPOL was exchanged, but the handshake did not yield a " +
				"certificate. The underlying error above is the specific cause - an EAP method the " +
				"server would not start, a TLS alert, or the association dropping mid-exchange.")
	}

	return rpc.Errorf(rpc.CodeInternal, "%s", b.String())
}

// harvestView flattens a harvest for the RPC response.
func harvestView(res *harvest.Result, sta recon.MAC, pemPath, jsonPath string) HarvestResult {
	out := HarvestResult{
		ESSID:       res.ESSID,
		BSSID:       res.BSSID,
		Station:     sta.String(),
		TLSVersion:  res.TLSVersion,
		ChainLength: len(res.Chain),
		PEMPath:     pemPath,
		JSONPath:    jsonPath,
		Notes:       res.Notes,
	}

	leaf, ok := res.Leaf()
	if !ok {
		out.Outcome = "the exchange completed but no leaf certificate was recorded"
		return out
	}

	out.Subject = leaf.Subject
	out.Issuer = leaf.Issuer
	out.SANs = leaf.SANs
	out.NotAfter = leaf.NotAfter.Format(time.RFC3339)
	out.KeyBits = leaf.KeyBits
	out.Fingerprint = leaf.Fingerprint

	if h, err := res.MimicSource(); err == nil {
		out.MimicSubject = mimic.Distinguish(h.Subject).String()
	}

	out.Outcome = fmt.Sprintf(
		"harvested %s from %s. The rogue will present a certificate mirroring it, with a "+
			"trailing space in the common name so the artefact is provably not the client's own.",
		leaf.Subject, res.BSSID)
	return out
}
