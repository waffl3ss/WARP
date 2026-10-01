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
	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/store"
	"github.com/waffl3ss/warp/internal/workspace"
)

func (d *Daemon) handleReconStart(ctx context.Context, _ json.RawMessage) (any, error) {
	if d.engine.Running() {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "recon is already running")
	}
	// The engine's lifetime is the daemon's, not this RPC call's: a client disconnecting must
	// not stop the capture.
	if err := d.engine.Start(d.ctx); err != nil {
		return nil, err
	}
	// The operator started capture deliberately, so it is not the walkthrough's to stop later.
	d.walkAutoRecon = false
	return d.engine.Stats(), nil
}

func (d *Daemon) handleReconStop(ctx context.Context, _ json.RawMessage) (any, error) {
	if err := d.engine.Stop(ctx); err != nil {
		return nil, err
	}
	d.walkAutoRecon = false
	return map[string]any{"running": false}, nil
}

func (d *Daemon) handleReconStatus(context.Context, json.RawMessage) (any, error) {
	return d.engine.Stats(), nil
}

// APsListParams filters the access point listing.
type APsListParams struct {
	ESSID string `json:"essid,omitempty"`
	// ScopedOnly restricts the listing to scoped networks. Off by default: every observed
	// device is listed, including neighbours and other tenants, and nothing is filtered out.
	ScopedOnly bool `json:"scoped_only,omitempty"`
}

// APView is one access point as reported to clients.
//
// Every field here is observed. Findings - the conclusions - are a separate call, so a client
// can always show the evidence independently of the label.
type APView struct {
	recon.AP
	// InScope reports whether the ESSID is in scope, which determines whether active work is
	// authorized at this BSSID.
	InScope bool `json:"in_scope"`
	// Confirmed and Rejected are the operator's advisory annotations.
	Confirmed bool `json:"operator_confirmed,omitempty"`
	Rejected  bool `json:"operator_rejected,omitempty"`
	// Rogue is set when the operator has marked this specific BSSID as a potential rogue. It is
	// BSSID-specific: other access points on the same ESSID are not marked by association.
	Rogue bool `json:"rogue,omitempty"`
	// Clients is how many client devices have been seen associated here. It decides whether
	// a deauthentication has anything to target, and an access point with clients on it is
	// where a handshake is going to come from.
	Clients int `json:"clients"`
	// Active reports whether the access point was heard recently enough to still be on the air
	// from WARP's vantage point - the equivalent of what airodump shows as currently visible.
	// WARP never drops an AP it has seen (nothing is filtered), so this is how a client tells a
	// live network from a stale entry: a device that has left, or a beacon a sweep caught once on
	// a channel it rarely revisits. LastSeenSecs is the age of the last frame heard, in seconds.
	Active       bool `json:"active"`
	LastSeenSecs int  `json:"last_seen_secs"`
}

// ActiveWindow is how recently an access point must have been heard to count as still visible.
//
// Recon sweeps every channel, so a live AP is only heard when a radio is parked on its channel -
// once per sweep cycle at best. The window is generous enough to survive a couple of full cycles
// (so a real AP on a rarely-revisited channel is not flapped to "gone"), and short enough that a
// device that has actually left drops out within a reasonable time.
const ActiveWindow = 90 * time.Second

func (d *Daemon) handleAPsList(_ context.Context, params json.RawMessage) (any, error) {
	var p APsListParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
		}
	}

	confirmed := d.ws.Gate.Confirmations()
	rejected := d.ws.Gate.Rejections()

	// Count clients per BSSID once rather than per row.
	clients := map[recon.MAC]int{}
	for _, st := range d.engine.Tracker().Stations() {
		if !st.BSSID.IsZero() {
			clients[st.BSSID]++
		}
	}

	now := time.Now()
	var out []APView
	for _, ap := range d.engine.Tracker().APs() {
		if p.ESSID != "" && ap.ESSID != p.ESSID {
			continue
		}
		inScope := ap.ESSID != "" && d.ws.Scope.Contains(ap.ESSID)
		if p.ScopedOnly && !inScope {
			continue
		}
		key := ap.BSSID.String()
		_, isConfirmed := confirmed[key]
		_, isRejected := rejected[key]
		age := now.Sub(ap.LastSeen)
		out = append(out, APView{
			AP: ap, InScope: inScope, Confirmed: isConfirmed, Rejected: isRejected,
			Rogue:        d.isRogueMarked(key),
			Clients:      clients[ap.BSSID],
			Active:       age <= ActiveWindow,
			LastSeenSecs: int(age.Seconds()),
		})
	}
	return out, nil
}

// APDetailResult is everything known about one BSSID: the observations and, separately, the
// conclusions.
type APDetailResult struct {
	AP        APView               `json:"ap"`
	Findings  []store.Finding      `json:"findings"`
	Locations []store.LocationRank `json:"locations,omitempty"`
	Stations  []recon.Station      `json:"stations,omitempty"`
}

func (d *Daemon) handleAPDetail(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		BSSID string `json:"bssid"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	addr, err := recon.ParseMAC(p.BSSID)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}

	ap, ok := d.engine.Tracker().AP(addr)
	if !ok {
		return nil, rpc.Errorf(rpc.CodeNotFound, "no access point observed at %s", addr)
	}

	res := APDetailResult{
		AP: APView{
			AP:      ap,
			InScope: ap.ESSID != "" && d.ws.Scope.Contains(ap.ESSID),
			Rogue:   d.isRogueMarked(ap.BSSID.String()),
		},
	}
	if f, err := d.store.FindingsFor(ctx, addr.String()); err == nil {
		res.Findings = f
	}
	// Localisation is only meaningful on the pinned survey radio.
	if surveyID := d.sched.SurveyRadioID(); surveyID != "" {
		if locs, err := d.store.Localize(ctx, addr.String(), surveyID); err == nil {
			res.Locations = locs
		}
	}
	for _, st := range d.engine.Tracker().Stations() {
		if st.BSSID == addr {
			res.Stations = append(res.Stations, st)
		}
	}
	return res, nil
}

// StationView is one client device as reported to clients.
//
// The network name is joined on here rather than left to each frontend. A BSSID on its own
// does not tell the operator which network a device is on, and three frontends each doing the
// lookup differently is three chances to disagree about it.
type StationView struct {
	recon.Station
	// ESSID is the network the associated BSSID broadcasts, "" if unknown or unassociated.
	ESSID string `json:"essid,omitempty"`
	// InScope reports whether that network is in scope, which is what decides whether this
	// client can be deauthenticated.
	InScope bool `json:"in_scope"`
	// APBand and APChannel come from the associated access point, so the client list can be
	// read without cross-referencing the AP tab.
	APBand    string `json:"ap_band,omitempty"`
	APChannel int    `json:"ap_channel,omitempty"`
	// APPHY is the 802.11 generations that access point advertises, e.g. "ax/n/g".
	APPHY string `json:"ap_phy,omitempty"`
	// MFP is the associated network's Protected Management Frames posture. A client on an
	// mfp=required network cannot be deauthenticated, and the operator should see that
	// before trying rather than after.
	MFP recon.MFPState `json:"mfp,omitempty"`
	// Active and LastSeenSecs mirror the AP view: whether the client was heard recently enough
	// to still be present, and the age of the last frame heard, so the live signal reading can be
	// shown as stale rather than as a current measurement that never decays.
	Active       bool `json:"active"`
	LastSeenSecs int  `json:"last_seen_secs"`
}

func (d *Daemon) handleStationsList(context.Context, json.RawMessage) (any, error) {
	tracker := d.engine.Tracker()

	// One pass over the access points, so a busy site does not turn this into a quadratic
	// lookup every time a frontend polls.
	type apInfo struct {
		essid   string
		band    string
		phy     string
		channel int
		mfp     recon.MFPState
		inScope bool
	}
	aps := map[recon.MAC]apInfo{}
	for _, ap := range tracker.APs() {
		aps[ap.BSSID] = apInfo{
			essid: ap.ESSID, band: ap.Band, phy: ap.PHY,
			channel: ap.Channel, mfp: ap.Security.MFP,
			inScope: ap.ESSID != "" && d.ws.Scope.Contains(ap.ESSID),
		}
	}

	now := time.Now()
	stations := tracker.Stations()
	out := make([]StationView, 0, len(stations))
	for _, st := range stations {
		age := now.Sub(st.LastSeen)
		v := StationView{Station: st, Active: age <= ActiveWindow, LastSeenSecs: int(age.Seconds())}
		if info, ok := aps[st.BSSID]; ok && !st.BSSID.IsZero() {
			v.ESSID, v.APBand, v.APChannel = info.essid, info.band, info.channel
			v.APPHY = info.phy
			v.MFP, v.InScope = info.mfp, info.inScope
		}
		// A client counts as in scope if it is associated to a scoped network (above) or has probed
		// for one by name: a device asking for a scoped ESSID is relevant to the engagement even
		// before it associates, and it is exactly the client an evil twin would answer.
		if !v.InScope {
			for _, pe := range st.ProbedESSIDs {
				if pe != "" && d.ws.Scope.Contains(pe) {
					v.InScope = true
					break
				}
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// handleScopeAdd puts an observed network name into scope.
//
// Scope is the signed document expressed as data and does not normally change mid-engagement.
// This exists because occasionally it legitimately does: the client names a network on site
// that was missing from the list. The operator makes that call from the access point list
// rather than editing a file and restarting the daemon, it is written back to scope.txt so
// the engagement record matches what was authorized, and the audit log records it.
//
// It only ever widens. Narrowing is `scope reject`, which is per-BSSID and advisory.
func (d *Daemon) handleScopeAdd(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		ESSID string `json:"essid"`
		Note  string `json:"note,omitempty"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if p.ESSID == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"an ESSID is required. A hidden network has no name to authorize until one is "+
				"recovered - decloak it first")
	}

	// Only names WARP has actually heard. Typing a network into scope that was never observed
	// is how a BSSID list gets in through the back door, and it is exactly what invariant 1
	// forbids: scope names things off the air, it does not invent them.
	seen := false
	for _, ap := range d.engine.Tracker().APs() {
		if ap.ESSID == p.ESSID {
			seen = true
			break
		}
	}
	if !seen {
		return nil, rpc.Errorf(rpc.CodeNotFound,
			"%q has not been observed. Scope is added from what is on the air, not typed in - "+
				"run recon until it appears", p.ESSID)
	}

	added, err := d.ws.Scope.Add(p.ESSID)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	if !added {
		return map[string]any{"essid": p.ESSID, "added": false,
			"scope": d.ws.Scope.List()}, nil
	}

	// Persist, so a daemon restart does not silently narrow scope back.
	if err := d.ws.WriteScope(); err != nil {
		return nil, err
	}

	d.logEvent(audit.KindScopeLoad, audit.OutcomeInfo, "ESSID added to scope by the operator",
		map[string]any{"essid": p.ESSID, "note": p.Note, "scope": d.ws.Scope.List()})

	d.Broadcast(rpc.Event{
		Kind: "scope", Level: rpc.LevelWarn,
		Text: fmt.Sprintf("[!] %q added to scope - active work is now authorized there",
			p.ESSID),
		Fields: map[string]any{"essid": p.ESSID},
	})

	return map[string]any{"essid": p.ESSID, "added": true, "scope": d.ws.Scope.List()}, nil
}

// handleScopeRemove takes an ESSID back out of scope. Removing narrows scope - active work at that
// network is no longer authorized, and its posture findings become out-of-scope context rather than
// deliverable - and it is the reverse of scope.add: the operator can add the name back at any time.
func (d *Daemon) handleScopeRemove(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		ESSID string `json:"essid"`
		Note  string `json:"note,omitempty"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if p.ESSID == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "an ESSID is required")
	}

	removed, err := d.ws.Scope.Remove(p.ESSID)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	if !removed {
		return map[string]any{"essid": p.ESSID, "removed": false, "scope": d.ws.Scope.List()}, nil
	}

	// Persist, so a daemon restart does not silently widen scope back to include it again.
	if err := d.ws.WriteScope(); err != nil {
		return nil, err
	}

	d.logEvent(audit.KindScopeLoad, audit.OutcomeInfo, "ESSID removed from scope by the operator",
		map[string]any{"essid": p.ESSID, "note": p.Note, "scope": d.ws.Scope.List()})

	d.Broadcast(rpc.Event{
		Kind: "scope", Level: rpc.LevelWarn,
		Text: fmt.Sprintf("[!] %q removed from scope - active work there is no longer authorized",
			p.ESSID),
		Fields: map[string]any{"essid": p.ESSID},
	})

	return map[string]any{"essid": p.ESSID, "removed": true, "scope": d.ws.Scope.List()}, nil
}

// HashesResult is everything WARP has captured for the cracking rig.
type HashesResult struct {
	Hashes []store.HashRecord `json:"hashes"`
	// PMKID and Handshake count the deliverable - material from networks the engagement is
	// authorized against.
	PMKID     int `json:"pmkid"`
	Handshake int `json:"handshake"`
	// OutOfScope counts handshakes overheard from networks the engagement has no authority
	// over. They are kept, and kept separate: cracking one would be unauthorized work, so
	// they never enter the totals above or the files that go to the rig.
	OutOfScope int `json:"out_of_scope"`
	// PendingESSID is how many handshakes are held back waiting for a network name. They are
	// not lost - a 22000 line needs the ESSID, so they are emitted the moment it is learned -
	// but an operator staring at a zero needs to know that is why.
	PendingESSID int `json:"pending_essid"`
	// Files names where the lines are written, because the operator has to transfer them off
	// this box by hand.
	Files []string `json:"files"`
	// OutOfScopeFiles hold the incidental captures. Named separately and prefixed rather than
	// suffixed, so a `*.22000` glob collecting the deliverable cannot pick them up.
	OutOfScopeFiles []string `json:"out_of_scope_files"`
	// WPSKeys are WPS credentials recovered this run - the PIN, and the passphrase when it was
	// read from M7. Unlike the hashes these are already cracked, so they belong with the
	// credentials rather than the material headed for the rig.
	WPSKeys []WPSCredential `json:"wps_keys,omitempty"`
}

// handleHashesList reports the captured hashes.
//
// This is the deliverable. Everything else WARP does exists to produce these lines, and until
// now there was no way to see one without reading a root-owned file on the engagement box.
func (d *Daemon) handleHashesList(ctx context.Context, _ json.RawMessage) (any, error) {
	hashes, err := d.store.Hashes(ctx)
	if err != nil {
		return nil, err
	}

	res := HashesResult{
		Hashes:       hashes,
		WPSKeys:      d.wpsCredentials(),
		PendingESSID: d.engine.Stats().Handshake.PendingESSID,
		Files: []string{
			d.ws.Path(workspace.PMKIDFile),
			d.ws.Path(workspace.HandshakeFile),
		},
		OutOfScopeFiles: []string{
			d.ws.Path("out-of-scope-" + workspace.PMKIDFile),
			d.ws.Path("out-of-scope-" + workspace.HandshakeFile),
		},
	}
	for _, h := range hashes {
		if !h.InScope {
			res.OutOfScope++
			continue
		}
		if h.Kind == string(handshake.KindHandshake) {
			res.Handshake++
		} else {
			res.PMKID++
		}
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Survey
// ---------------------------------------------------------------------------

func (d *Daemon) handleWalkthroughStart(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if p.Name == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "a walkthrough needs a name")
	}

	// A walkthrough is a capture: if recon is not already running, start it, otherwise the pass's
	// pcap opens but no radio is capturing and nothing lands in it. Remember that we started it so
	// ending the last walkthrough puts the radios back to idle; if the operator already had recon
	// running, leave that flag alone so ending returns to capturing. The engine's lifetime is the
	// daemon's, not this call's.
	if !d.engine.Running() {
		if err := d.engine.Start(d.ctx); err != nil {
			return nil, rpc.Errorf(rpc.CodeInternal,
				"could not start capture for the walkthrough: %v", err)
		}
		d.walkAutoRecon = true
	}

	// Starting a new walkthrough ends the previous one: an operator moving to the next floor
	// should not have to remember to close the last one. Close its dedicated archive first, and
	// note it so its device summary can be written once the store has closed it.
	prev, _ := d.store.CurrentWalkthrough(ctx)
	if frames, path, err := d.engine.StopWalkthroughCapture(); err != nil {
		d.log.Warn("could not close the previous walkthrough archive", "err", err)
	} else if path != "" {
		d.log.Info("previous walkthrough archive closed", "frames", frames, "path", path)
	}

	w, err := d.store.StartWalkthrough(ctx, p.Name, time.Now(), false)
	if err != nil {
		return nil, err
	}

	// Open a dedicated raw archive for this walkthrough, so the pass can be replayed apart from the
	// engagement-wide capture. Best-effort: a capture that cannot be opened must not undo the
	// walkthrough, which is already recorded - it just goes without its own pcap.
	pcapPath := filepath.Join(d.ws.Dir, workspace.WalkthroughsDir,
		d.walkthroughBasename(walkthroughSlug(w.Name), w.ID)+".pcapng")
	if err := d.engine.StartWalkthroughCapture(pcapPath); err != nil {
		d.log.Warn("could not open a walkthrough archive", "err", err, "path", pcapPath)
	} else if err := d.store.SetWalkthroughPcap(ctx, w.ID, pcapPath); err != nil {
		d.log.Warn("could not record the walkthrough archive path", "err", err)
	} else {
		w.PcapPath = pcapPath
	}

	// The previous walkthrough is now closed in the store, so write its device summary file.
	if prev != nil {
		d.writeWalkthroughSummary(ctx, prev)
	}

	// Reset the radios at the boundary so each walkthrough is captured from a clean slate (the
	// operator's choice - see the invariant-5 note). Best-effort: a reset failure must not undo the
	// walkthrough that is already recorded.
	if err := d.engine.RestartCapture(); err != nil {
		d.log.Warn("could not reset the radios at the walkthrough boundary", "err", err)
	}

	d.Broadcast(rpc.Event{
		Kind: "walkthrough", Level: rpc.LevelGood,
		Text:   fmt.Sprintf("[+] walkthrough %q started - radios reset, observations tagging to it", w.Name),
		Fields: map[string]any{"id": w.ID, "name": w.Name},
	})
	return w, nil
}

// walkthroughBasename is the file basename for a walkthrough's artifacts (pcap, netxml, summary).
// It is the slug of the name alone - matching what the operator called the pass - and only falls
// back to slug-id when a file with that name already exists, so two passes that share a name do not
// overwrite each other.
func (d *Daemon) walkthroughBasename(slug string, id int64) string {
	dir := filepath.Join(d.ws.Dir, workspace.WalkthroughsDir)
	if _, err := os.Stat(filepath.Join(dir, slug+".pcapng")); os.IsNotExist(err) {
		return slug
	}
	return fmt.Sprintf("%s-%d", slug, id)
}

// walkthroughSlug turns a free-text walkthrough name into a filesystem-safe archive basename.
// The database keeps the real name; this is only for the file on disk.
func walkthroughSlug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '/':
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		return "walkthrough"
	}
	if len(s) > 48 {
		s = strings.Trim(s[:48], "-")
	}
	return s
}

func (d *Daemon) handleWalkthroughEnd(ctx context.Context, _ json.RawMessage) (any, error) {
	// Capture which walkthrough is open before closing it, so its device summary can be written.
	cur, _ := d.store.CurrentWalkthrough(ctx)
	n, err := d.store.EndWalkthrough(ctx, time.Now())
	if err != nil {
		return nil, err
	}
	if n > 0 {
		// Close the dedicated archive before the boundary reset, so the pass's pcap holds exactly
		// the span it was open for and nothing after it.
		if frames, path, err := d.engine.StopWalkthroughCapture(); err != nil {
			d.log.Warn("could not close the walkthrough archive", "err", err)
		} else if path != "" {
			d.log.Info("walkthrough archive closed", "frames", frames, "path", path)
		}
		if cur != nil {
			d.writeWalkthroughSummary(ctx, cur)
		}

		// Put the radios back the way they were before the walkthrough. If the walkthrough itself
		// started capture (recon was idle), stop it again so the cards return to idle; otherwise
		// reset at the boundary so post-walkthrough capture is not mixed into the pass but recon
		// keeps running.
		msg := "[*] walkthrough ended - radios reset"
		if d.walkAutoRecon {
			d.walkAutoRecon = false
			if err := d.engine.Stop(d.ctx); err != nil {
				d.log.Warn("could not stop capture after the walkthrough", "err", err)
			}
			msg = "[*] walkthrough ended - capture returned to idle"
		} else if err := d.engine.RestartCapture(); err != nil {
			d.log.Warn("could not reset the radios at the walkthrough boundary", "err", err)
		}
		d.Broadcast(rpc.Event{Kind: "walkthrough", Level: rpc.LevelInfo, Text: msg})
	}
	return map[string]any{"closed": n}, nil
}

// handleWalkthroughDelete removes a walkthrough label and its dedicated archive. Observations are
// left untouched: they belong to the engagement and are associated by time range, not owned by the
// walkthrough. This is for discarding a mislabelled or failed pass, not for erasing evidence.
func (d *Daemon) handleWalkthroughDelete(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if p.ID == 0 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "a walkthrough id is required")
	}

	// If the pass being deleted is the one still capturing, stop its archive first so the file is
	// closed before it is removed.
	if cur, err := d.store.CurrentWalkthrough(ctx); err == nil && cur != nil && cur.ID == p.ID {
		if _, _, err := d.engine.StopWalkthroughCapture(); err != nil {
			d.log.Warn("could not close the walkthrough archive before deleting", "err", err)
		}
		if _, err := d.store.EndWalkthrough(ctx, time.Now()); err != nil {
			d.log.Warn("could not close the walkthrough before deleting", "err", err)
		}
	}

	pcapPath, err := d.store.DeleteWalkthrough(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if pcapPath != "" {
		if err := os.Remove(pcapPath); err != nil && !os.IsNotExist(err) {
			d.log.Warn("could not remove the walkthrough archive", "err", err, "path", pcapPath)
		}
		// The device summary sits beside the pcap with the same basename and a .txt extension.
		summary := strings.TrimSuffix(pcapPath, filepath.Ext(pcapPath)) + ".txt"
		if err := os.Remove(summary); err != nil && !os.IsNotExist(err) {
			d.log.Warn("could not remove the walkthrough summary", "err", err, "path", summary)
		}
	}
	d.Broadcast(rpc.Event{
		Kind: "walkthrough", Level: rpc.LevelInfo,
		Text:   fmt.Sprintf("[*] walkthrough %d deleted", p.ID),
		Fields: map[string]any{"id": p.ID},
	})
	return map[string]any{"deleted": p.ID}, nil
}

func (d *Daemon) handleWalkthroughList(ctx context.Context, _ json.RawMessage) (any, error) {
	return d.store.ListWalkthroughs(ctx)
}

func (d *Daemon) handleWalkthroughDevices(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	if p.ID == 0 {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "a walkthrough id is required")
	}
	return d.store.WalkthroughDevices(ctx, p.ID)
}

// writeWalkthroughSummary writes a plain-text roll of the BSSID/ESSIDs heard during a walkthrough,
// named for the walkthrough so an operator can see at a glance what a given pass covered. Called
// when a walkthrough closes; best-effort, since it is a convenience projection of data the store
// already holds authoritatively.
func (d *Daemon) writeWalkthroughSummary(ctx context.Context, w *store.Walkthrough) {
	if w == nil {
		return
	}
	id, name := w.ID, w.Name
	devices, err := d.store.WalkthroughDevices(ctx, id)
	if err != nil {
		d.log.Warn("could not read walkthrough devices for the summary", "err", err, "id", id)
		return
	}
	// Derive the summary/netxml basename from the pass's actual pcap path, so all three files share
	// one basename (the clean name, or name-id on collision) rather than recomputing and diverging.
	base := fmt.Sprintf("%s-%d", walkthroughSlug(name), id)
	if w.PcapPath != "" {
		base = strings.TrimSuffix(filepath.Base(w.PcapPath), ".pcapng")
	}
	dir := filepath.Join(d.ws.Dir, workspace.WalkthroughsDir)
	path := filepath.Join(dir, base+".txt")

	var b strings.Builder
	fmt.Fprintf(&b, "# walkthrough: %s\n", name)
	fmt.Fprintf(&b, "# generated: %s\n\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "%-19s  %-6s  %-8s  %s\n", "BSSID/MAC", "TYPE", "CHANNEL", "NETWORK")
	for _, dev := range devices {
		kind := "client"
		ch := ""
		if dev.IsAP {
			kind = "AP"
			if dev.Channel != 0 {
				ch = fmt.Sprintf("%d", dev.Channel)
			}
		}
		essid := dev.ESSID
		if essid == "" {
			essid = "(hidden/unknown)"
		}
		fmt.Fprintf(&b, "%-19s  %-6s  %-8s  %s\n", dev.BSSID, kind, ch, essid)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		d.log.Warn("could not write the walkthrough summary", "err", err, "path", path)
	}

	// A Kismet netxml beside the pass's pcap, holding only the networks seen during this
	// walkthrough, named to match.
	netpath := filepath.Join(dir, base+".netxml")
	if err := d.store.WriteNetXMLForWalkthrough(ctx, netpath, id); err != nil {
		d.log.Warn("could not write the walkthrough netxml", "err", err, "path", netpath)
	}
}

func (d *Daemon) handleWalkthroughCurrent(ctx context.Context, _ json.RawMessage) (any, error) {
	return d.store.CurrentWalkthrough(ctx)
}

func (d *Daemon) handleWalkthroughRename(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	// Renaming touches no observation data: observations associate by time range, so the
	// operator naming one sloppily on site costs nothing to fix.
	if err := d.store.RenameWalkthrough(ctx, p.ID, p.Name); err != nil {
		if errors.Is(err, store.ErrNoWalkthrough) {
			return nil, rpc.Errorf(rpc.CodeNotFound, "%v", err)
		}
		return nil, err
	}
	return map[string]any{"id": p.ID, "name": p.Name}, nil
}

func (d *Daemon) handleWalkthroughSplit(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		ID   int64  `json:"id"`
		At   string `json:"at"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	at, err := time.Parse(time.RFC3339, p.At)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"split point %q is not an RFC3339 timestamp: %v", p.At, err)
	}

	w, err := d.store.SplitWalkthrough(ctx, p.ID, at, p.Name)
	if err != nil {
		if errors.Is(err, store.ErrNoWalkthrough) {
			return nil, rpc.Errorf(rpc.CodeNotFound, "%v", err)
		}
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}
	return w, nil
}

// LocalizeResult is the "strongest walkthrough, ranked" output.
type LocalizeResult struct {
	Addr    string               `json:"addr"`
	RadioID string               `json:"radio_id"`
	Ranks   []store.LocationRank `json:"ranks"`
	// Note is shown to the operator alongside the ranking.
	Note string `json:"note"`
}

func (d *Daemon) handleLocalize(ctx context.Context, params json.RawMessage) (any, error) {
	var p struct {
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "bad params: %v", err)
	}
	addr, err := recon.ParseMAC(p.Addr)
	if err != nil {
		return nil, rpc.Errorf(rpc.CodeInvalidParams, "%v", err)
	}

	surveyID := d.sched.SurveyRadioID()
	if surveyID == "" {
		return nil, rpc.Errorf(rpc.CodeInvalidParams,
			"no survey radio is pinned; localisation needs one adapter's observations because "+
				"RSSI is not comparable across radios")
	}

	ranks, err := d.store.Localize(ctx, addr.String(), surveyID)
	if err != nil {
		return nil, err
	}

	return LocalizeResult{
		Addr: addr.String(),
		// The query used the phy id above; the result carries the interface name for display.
		RadioID: d.engine.SurveyRadioName(),
		Ranks:   ranks,
		Note: "Ranked by strongest observation per walkthrough, measured on the pinned survey " +
			"radio. This is not trilateration and deliberately emits no coordinate: indoor RSSI " +
			"trilateration produces a position that looks authoritative and cannot be defended.",
	}, nil
}
