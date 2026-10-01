package daemon

import (
	"context"
	"encoding/json"
	"time"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/rogue"
	"github.com/waffl3ss/warp/internal/rpc"
	"github.com/waffl3ss/warp/internal/store"
)

// loadRogueMarks hydrates the in-memory rogue-mark index from the findings table at startup, so a
// device an operator marked in an earlier run comes back marked. The store is authoritative; a
// failure here leaves the index empty and is logged, never fatal (invariant 8: library code returns
// errors, main decides - but this is the daemon deciding to carry on with an empty index rather than
// refuse to start over a cosmetic annotation).
func (d *Daemon) loadRogueMarks() {
	findings, err := d.store.Findings(context.Background(), "")
	if err != nil {
		d.log.Warn("could not reload rogue marks", "err", err)
		return
	}
	d.rogueMu.Lock()
	defer d.rogueMu.Unlock()
	for _, f := range findings {
		if f.Label == rogue.LabelPotentialRogue {
			d.rogueBSSIDs[f.BSSID] = true
		}
	}
}

// isRogueMarked reports whether a BSSID carries an operator's potential-rogue mark.
func (d *Daemon) isRogueMarked(bssid string) bool {
	d.rogueMu.RLock()
	defer d.rogueMu.RUnlock()
	return d.rogueBSSIDs[bssid]
}

// handleRogueMark records an operator's judgement that a specific BSSID is a potential rogue. It is
// BSSID/ESSID specific by construction: the finding is keyed on this one BSSID, so other access
// points broadcasting the same ESSID are untouched. There is no packet-level basis - the operator
// supplies the evidence - so the finding says exactly that, and a JSON export fills its evidence with
// the replaceable placeholder. Marking is never a transmission and never consults scope: judging a
// device you can see is not transmitting at it.
func (d *Daemon) handleRogueMark(ctx context.Context, params json.RawMessage) (any, error) {
	p, err := decodeBSSIDParams(params)
	if err != nil {
		return nil, err
	}
	// Resolve the ESSID from the observed record so the finding is filed against the network the
	// device claims, but do not require the AP to be present - an operator may mark a device that
	// has just dropped off the air.
	essid := ""
	if ap, err := d.lookupAP(p.BSSID); err == nil {
		essid = ap.ESSID
	}

	now := time.Now()
	f := store.Finding{
		BSSID: p.BSSID, ESSID: essid,
		Tier:  store.TierEvidence,
		Label: rogue.LabelPotentialRogue,
		// The description stays clean: it says what the finding is, not what the evidence is. The
		// "manual evidence required" placeholder belongs in the evidence field (the report fills it
		// there), never in the rationale.
		Rationale: "Manually marked as a potential rogue device by the operator.",
		FirstTS:   now, LastTS: now,
	}
	if err := d.store.UpsertFinding(ctx, f); err != nil {
		return nil, err
	}

	d.rogueMu.Lock()
	d.rogueBSSIDs[p.BSSID] = true
	d.rogueMu.Unlock()

	d.logEvent(audit.KindAnnotate, audit.OutcomeInfo, "operator marked a potential rogue device",
		map[string]any{"bssid": p.BSSID, "essid": essid})
	d.Broadcast(rpc.Event{
		Kind: "rogue-mark", Level: rpc.LevelWarn,
		Text:   "[!] " + p.BSSID + " marked as a potential rogue device",
		Fields: map[string]any{"bssid": p.BSSID, "essid": essid},
	})

	// Keep the projections current so rogues.csv reflects the mark immediately (invariant 6).
	if err := d.store.ExportCSV(ctx, d.ws.Dir); err != nil {
		d.log.Warn("could not regenerate projections after rogue mark", "err", err)
	}
	return map[string]any{"bssid": p.BSSID, "essid": essid, "rogue": true}, nil
}

// handleRogueUnmark removes an operator's potential-rogue mark from one BSSID.
func (d *Daemon) handleRogueUnmark(ctx context.Context, params json.RawMessage) (any, error) {
	p, err := decodeBSSIDParams(params)
	if err != nil {
		return nil, err
	}
	if err := d.store.ClearFindingForBSSID(ctx, p.BSSID, rogue.LabelPotentialRogue); err != nil {
		return nil, err
	}

	d.rogueMu.Lock()
	delete(d.rogueBSSIDs, p.BSSID)
	d.rogueMu.Unlock()

	d.logEvent(audit.KindAnnotate, audit.OutcomeInfo, "operator cleared a potential-rogue mark",
		map[string]any{"bssid": p.BSSID})
	d.Broadcast(rpc.Event{
		Kind: "rogue-mark", Level: rpc.LevelInfo,
		Text:   p.BSSID + " potential-rogue mark cleared",
		Fields: map[string]any{"bssid": p.BSSID},
	})

	if err := d.store.ExportCSV(ctx, d.ws.Dir); err != nil {
		d.log.Warn("could not regenerate projections after rogue unmark", "err", err)
	}
	return map[string]any{"bssid": p.BSSID, "rogue": false}, nil
}
