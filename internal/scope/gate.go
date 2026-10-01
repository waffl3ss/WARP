package scope

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/waffl3ss/warp/internal/audit"
)

// Gate is the single authorization point for every frame WARP puts in the air.
//
// There is exactly one authorization path and it is exercised identically in every
// deployment. An unattended box in a wiring closet has nobody to confirm anything and must
// still work: authorization follows from ESSID match, because the ESSID list is what was
// signed. Nothing here branches on whether an operator is present.
type Gate struct {
	set *Set
	log audit.Logger

	mu sync.RWMutex
	// confirmed records optional operator sanity checks. It is informational: it is attached
	// to the audit record and never consulted when deciding.
	confirmed map[string]string
	// rejected records operator vetoes. A veto only ever narrows scope, so honouring it
	// without a confirmation requirement is always the safe direction.
	rejected map[string]string
	// ackedGeneric records human acceptance of the residual risk of a generic ESSID. This is
	// workspace state established once at `warp init`, not a runtime prompt - a shipped NUC
	// carries the acknowledgment made before it left.
	ackedGeneric map[string]string
}

// DenialError is returned by AuthorizeTransmit when a request is refused.
//
// AuthorizeTransmit returns an error rather than a bool specifically so that a caller who
// forgets to check the result cannot transmit. Ignoring an error is a vet-detectable
// mistake; ignoring a bool is invisible.
type DenialError struct {
	Module string
	BSSID  string
	ESSID  string
	Reason string
}

func (e *DenialError) Error() string {
	target := e.BSSID
	if target == "" {
		target = "(no bssid)"
	}
	return fmt.Sprintf("scope: %s refused at %s essid=%q: %s", e.Module, target, e.ESSID, e.Reason)
}

// Denied reports whether err is a scope denial (as opposed to an internal failure).
func Denied(err error) bool {
	var d *DenialError
	return errors.As(err, &d)
}

// Denial reasons. Stable strings - they land in events.jsonl and in reports.
const (
	ReasonESSIDInScope     = "essid in scope"
	ReasonESSIDNotInScope  = "essid not in scope"
	ReasonESSIDEmpty       = "essid unknown (hidden or unresolved) - passive observation only"
	ReasonOperatorRejected = "bssid vetoed by operator"
	ReasonGenericUnacked   = "generic essid has no recorded operator acknowledgment"

	ReasonDecloakNameless = "hidden network: no essid exists to decide on until it is recovered"
	ReasonDecloakNamed    = "network is not hidden; its name decides authorization in the usual way"
)

// Request describes a proposed transmission.
//
// There is no field here for a client-supplied BSSID list, and there must never be one. The
// BSSID in a Request is a BSSID WARP discovered off the air, carried so the decision can be
// recorded against it.
type Request struct {
	// Module is the requesting subsystem, e.g. "solicit", "deauth", "rogue-ap", "harvest".
	Module string
	// BSSID is the discovered target, if the transmission is aimed at one. Empty when the
	// request is to beacon an ESSID rather than to transmit at a specific AP.
	BSSID string
	// ESSID is the network name observed at BSSID, or the name to be beaconed.
	ESSID string
	// Channel and RadioID are recorded as evidence.
	Channel int
	RadioID string
}

// NewGate builds a Gate over set, recording every decision to log.
func NewGate(set *Set, log audit.Logger) (*Gate, error) {
	// An empty scope authorizes nothing and is almost always a misread scope.txt, so it is
	// refused rather than quietly producing a gate that says no to everything. A site-wide
	// scope is also empty of entries, and is the one case where that is deliberate.
	if set == nil || (set.Len() == 0 && !set.IsSiteWide()) {
		return nil, errors.New("scope: refusing to build a gate with an empty scope")
	}
	if log == nil {
		return nil, errors.New("scope: refusing to build a gate with no audit log")
	}
	return &Gate{
		set:          set,
		log:          log,
		confirmed:    make(map[string]string),
		rejected:     make(map[string]string),
		ackedGeneric: make(map[string]string),
	}, nil
}

// AuthorizeTransmit decides whether req may put a frame in the air.
//
// It returns nil if authorized, a *DenialError if refused, and any other error if the
// decision could not be recorded. A caller that cannot write the audit record must not
// transmit: the log is engagement evidence, and an unlogged transmission is indefensible in
// a report.
func (g *Gate) AuthorizeTransmit(ctx context.Context, req Request) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.Module == "" {
		return errors.New("scope: authorization request has no requesting module")
	}

	bssid := NormalizeBSSID(req.BSSID)

	g.mu.RLock()
	vetoNote, vetoed := g.rejected[bssid]
	_, acked := g.ackedGeneric[req.ESSID]
	confirmNote, confirmed := g.confirmed[bssid]
	g.mu.RUnlock()

	scopeEntry, exactCase, inScope := g.set.Match(req.ESSID)

	// One decision path, evaluated in order of how strongly it constrains us. Operator veto
	// first because it only ever narrows scope.
	outcome, reason := audit.OutcomeAllow, ReasonESSIDInScope
	switch {
	case bssid != "" && vetoed:
		outcome, reason = audit.OutcomeDeny, ReasonOperatorRejected
	case req.ESSID == "":
		outcome, reason = audit.OutcomeDeny, ReasonESSIDEmpty
	case !inScope:
		outcome, reason = audit.OutcomeDeny, ReasonESSIDNotInScope
	case IsGeneric(req.ESSID) && !acked && !g.set.IsSiteWide():
		// The acknowledgment is required at `warp init` and persisted, so reaching this in a
		// properly initialised workspace means the scope was changed underneath us. Refusing
		// is the conservative reading: a generic ESSID does not uniquely identify the
		// client's equipment, so transmitting could reach a neighbour.
		outcome, reason = audit.OutcomeDeny, ReasonGenericUnacked
	}

	detail := map[string]any{"generic_essid": IsGeneric(req.ESSID)}
	if g.set.IsSiteWide() {
		// Every transmission under a site-wide scope carries the justification with it, so
		// nobody reading events.jsonl afterwards has to go looking for why this was allowed.
		detail["site_wide_scope"] = true
		detail["site_wide_justification"] = g.set.SiteWideNote()
	}
	if inScope && !exactCase {
		// Authorized, but the beacon and the SoW disagree on case. Recorded on every single
		// transmission so a report can show exactly what was matched against what, and so
		// this can never be mistaken for an exact match after the fact.
		detail["scope_entry"] = scopeEntry
		detail["case_insensitive_match"] = true
	}
	if confirmed {
		// Recorded as context only. Confirmation is a convenience for a human who happens to
		// be present and is never a precondition - see CLAUDE.md invariant 1.
		detail["operator_confirmed"] = true
		if confirmNote != "" {
			detail["operator_note"] = confirmNote
		}
	}
	if vetoed && vetoNote != "" {
		detail["veto_reason"] = vetoNote
	}

	if err := g.log.Log(audit.Event{
		Kind:    audit.KindAuthorize,
		Outcome: outcome,
		Module:  req.Module,
		BSSID:   bssid,
		ESSID:   req.ESSID,
		Channel: req.Channel,
		RadioID: req.RadioID,
		Reason:  reason,
		Detail:  detail,
	}); err != nil {
		return fmt.Errorf("scope: refusing to transmit, audit record failed: %w", err)
	}

	if outcome == audit.OutcomeDeny {
		return &DenialError{Module: req.Module, BSSID: bssid, ESSID: req.ESSID, Reason: reason}
	}
	return nil
}

// AuthorizeBeacon decides whether the rogue AP may beacon essid.
//
// It is the same code path as AuthorizeTransmit with no BSSID. The rogue AP may only beacon
// ESSIDs present in scope.txt - no karma, no known-beacon, no probe-response to arbitrary
// probes - because responding to an arbitrary probe impersonates a network outside the SoW.
func (g *Gate) AuthorizeBeacon(ctx context.Context, module, essid string, channel int, radioID string) error {
	return g.AuthorizeTransmit(ctx, Request{
		Module:  module,
		ESSID:   essid,
		Channel: channel,
		RadioID: radioID,
	})
}

// KarmaProbeESSIDLen is the length of the generated ESSID used for karma responder
// detection. It is fixed so the gate can verify that what it is being asked to transmit
// really is a generated name and not a real network.
const KarmaProbeESSIDLen = 20

// AuthorizeKarmaProbe authorizes a probe request for a randomly generated ESSID that cannot
// exist.
//
// This is the one transmission that is not decided by ESSID match, and it is handled here
// rather than by a bypass in the injector so that there remains exactly one authorization
// surface and one place that writes the audit log.
//
// Why it is inside the SoW: the frame asks whether any device will answer for a network that
// does not exist. It names no client network, targets no BSSID, and impersonates nothing - it
// is the exact inverse of the karma behaviour WARP refuses to implement, which is *answering*
// arbitrary probes. Anything that replies is a karma responder, which is a deterministic
// finding nothing passive will ever surface.
//
// The guards below exist because "transmit an ESSID that is not in scope" is precisely the
// shape of the mistake the scope gate is here to prevent. The ESSID must look generated, and
// must not be a network anyone actually scoped.
func (g *Gate) AuthorizeKarmaProbe(ctx context.Context, module, essid string, channel int, radioID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if module == "" {
		return errors.New("scope: karma probe request has no requesting module")
	}

	reason := "karma responder detection: probe for a generated ESSID that cannot exist"
	outcome := audit.OutcomeAllow

	switch {
	case len(essid) != KarmaProbeESSIDLen:
		outcome = audit.OutcomeDeny
		reason = fmt.Sprintf("karma probe ESSID must be %d generated characters, got %d",
			KarmaProbeESSIDLen, len(essid))
	case !isGeneratedESSID(essid):
		outcome = audit.OutcomeDeny
		reason = "karma probe ESSID is not a generated random name"
	case !g.set.IsSiteWide() && g.set.Contains(essid):
		// Astronomically unlikely, and a sign something is very wrong. Probing for a real
		// scoped network under the karma path would sidestep the ordinary decision.
		//
		// Skipped under a site-wide scope, where every name is in scope by definition and this
		// check would refuse every probe: the two guards above already establish that the name
		// is generated and therefore cannot be a network anyone runs.
		outcome = audit.OutcomeDeny
		reason = "karma probe ESSID collides with a scoped network"
	}

	if err := g.log.Log(audit.Event{
		Kind:    audit.KindAuthorize,
		Outcome: outcome,
		Module:  module,
		ESSID:   essid,
		Channel: channel,
		RadioID: radioID,
		Reason:  reason,
		Detail:  map[string]any{"karma_detection": true},
	}); err != nil {
		return fmt.Errorf("scope: refusing to transmit, audit record failed: %w", err)
	}

	if outcome == audit.OutcomeDeny {
		return &DenialError{Module: module, ESSID: essid, Reason: reason}
	}
	return nil
}

// AuthorizeDecloak authorizes the broadcast deauthentication that recovers a hidden network's
// name.
//
// This is the second and last transmission not decided by ESSID match, and like the karma
// probe it lives here rather than as a bypass inside the injector, so there remains exactly one
// authorization surface and one writer of the audit log.
//
// Why it cannot be decided the usual way, precisely: a cloaked network broadcasts no name, and
// **it may well be in scope** - there is no way to find out except by recovering the name. An
// ESSID check here would not be protecting anything, it would be refusing to establish the
// fact the check needs. That is not a gap in the scope model; it is the one question the scope
// model cannot answer from the outside.
//
// Requiring an operator confirmation instead was worse, and it was wrong for the same reason:
// it asks a human to assert exactly what the tool is being asked to determine. Someone
// standing in a building looking at a nameless BSSID has no better information than WARP does.
// A confirmation is still recorded when one exists, as context - it is evidence, not a gate.
//
// What this authorizes is narrow and self-limiting:
//
//   - One broadcast deauthentication. Nothing is impersonated, no name is beaconed, and no
//     credential is solicited.
//   - It provokes a reassociation whose probe and association requests carry the network's
//     name in clear text - which is the entire objective.
//   - The instant the name is known, every subsequent decision reverts to the ordinary ESSID
//     path, including refusing everything else if it turns out not to be in scope.
//
// An operator veto still refuses, because a veto only ever narrows scope. And a network that
// already has a name is refused down this path: letting one through would launder an ordinary
// transmission past the ESSID check, which is the exact bypass this method is built not to be.
func (g *Gate) AuthorizeDecloak(ctx context.Context, module, bssid, observedESSID string, channel int, radioID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if module == "" {
		return errors.New("scope: decloak request has no requesting module")
	}

	b := NormalizeBSSID(bssid)
	if b == "" {
		return fmt.Errorf("scope: decloak: %q is not a MAC address", bssid)
	}

	g.mu.RLock()
	vetoNote, vetoed := g.rejected[b]
	confirmNote, confirmed := g.confirmed[b]
	g.mu.RUnlock()

	outcome, reason := audit.OutcomeAllow, ReasonDecloakNameless
	switch {
	case vetoed:
		outcome, reason = audit.OutcomeDeny, ReasonOperatorRejected
	case observedESSID != "":
		// Not hidden after all - the name arrived between the operator asking and the request
		// reaching the gate. It goes down the ordinary path or not at all.
		outcome, reason = audit.OutcomeDeny, ReasonDecloakNamed
	}

	detail := map[string]any{
		"decloak": true,
		// Spelled out on every record. A reader reconstructing the engagement has to be able
		// to see that this frame went out at a BSSID with no name attached, and why that was
		// allowed, without going and reading the source.
		"no_essid_to_authorize_against": outcome == audit.OutcomeAllow,
		"scope_resumes_once_named":      true,
	}
	if confirmed {
		// Context only. It carries no authorization weight here and never did - see above.
		detail["operator_confirmed"] = true
		if confirmNote != "" {
			detail["operator_note"] = confirmNote
		}
	}
	if vetoed && vetoNote != "" {
		detail["veto_reason"] = vetoNote
	}

	if err := g.log.Log(audit.Event{
		Kind:    audit.KindAuthorize,
		Outcome: outcome,
		Module:  module,
		BSSID:   b,
		Channel: channel,
		RadioID: radioID,
		Reason:  reason,
		Detail:  detail,
	}); err != nil {
		return fmt.Errorf("scope: refusing to transmit, audit record failed: %w", err)
	}

	if outcome == audit.OutcomeDeny {
		return &DenialError{Module: module, BSSID: b, ESSID: observedESSID, Reason: reason}
	}
	return nil
}

// isGeneratedESSID reports whether s looks like one of our generated probe names: only
// unreserved alphanumerics, which is what RandomESSID produces.
func isGeneratedESSID(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return len(s) > 0
}

// Confirm records an optional operator sanity check at a discovered BSSID.
//
// This changes nothing about authorization. It exists so a human who is standing in the
// building can note "yes, that is the client's AP" and have it appear in the evidence.
func (g *Gate) Confirm(bssid, essid, note string) error {
	b := NormalizeBSSID(bssid)
	if b == "" {
		return fmt.Errorf("scope: confirm: %q is not a MAC address", bssid)
	}
	g.mu.Lock()
	g.confirmed[b] = note
	delete(g.rejected, b)
	g.mu.Unlock()

	return g.log.Log(audit.Event{
		Kind:    audit.KindConfirm,
		Outcome: audit.OutcomeInfo,
		Module:  "operator",
		BSSID:   b,
		ESSID:   essid,
		Reason:  "operator sanity check - advisory only, not a precondition",
		Detail:  detailNote(note),
	})
}

// Reject records an operator veto at a BSSID, excluding it from active work.
//
// A veto only narrows scope - for example a neighbouring tenant who happens to broadcast a
// generic name that is also in scope - so it takes effect immediately.
func (g *Gate) Reject(bssid, essid, reason string) error {
	b := NormalizeBSSID(bssid)
	if b == "" {
		return fmt.Errorf("scope: reject: %q is not a MAC address", bssid)
	}
	g.mu.Lock()
	g.rejected[b] = reason
	delete(g.confirmed, b)
	g.mu.Unlock()

	return g.log.Log(audit.Event{
		Kind:    audit.KindReject,
		Outcome: audit.OutcomeInfo,
		Module:  "operator",
		BSSID:   b,
		ESSID:   essid,
		Reason:  "operator veto - excluded from active work",
		Detail:  detailNote(reason),
	})
}

// AcknowledgeGeneric records that a human accepted the residual risk of a generic ESSID.
//
// Called from `warp init`. The acknowledgment is persisted as an audit record and replayed at
// daemon startup, so a box shipped to a closet carries the acknowledgment made before it left
// rather than needing someone on site.
func (g *Gate) AcknowledgeGeneric(essid, operator string) error {
	if !g.set.Contains(essid) {
		return fmt.Errorf("scope: cannot acknowledge %q: not in scope", essid)
	}
	if !IsGeneric(essid) {
		return fmt.Errorf("scope: %q is not a generic ESSID and needs no acknowledgment", essid)
	}
	g.mu.Lock()
	g.ackedGeneric[essid] = operator
	g.mu.Unlock()

	return g.log.Log(audit.Event{
		Kind:    audit.KindGenericESSID,
		Outcome: audit.OutcomeAck,
		Module:  "operator",
		ESSID:   essid,
		Reason:  "operator accepted residual risk: a neighbour may legitimately broadcast this ESSID",
		Detail:  map[string]any{"operator": operator},
	})
}

// PendingAcknowledgments returns scoped ESSIDs that are generic and not yet acknowledged.
// `warp init` must not complete while this is non-empty.
func (g *Gate) PendingAcknowledgments() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var out []string
	for _, e := range g.set.GenericEntries() {
		if _, ok := g.ackedGeneric[e]; !ok {
			out = append(out, e)
		}
	}
	return out
}

// Entry is the reportable state of one scoped ESSID.
type Entry struct {
	ESSID           string `json:"essid"`
	Generic         bool   `json:"generic"`
	Acknowledged    bool   `json:"acknowledged"`
	AcknowledgedBy  string `json:"acknowledged_by,omitempty"`
	ActiveWorkReady bool   `json:"active_work_ready"`
}

// Snapshot returns the current scope state for RPC and reporting.
func (g *Gate) Snapshot() []Entry {
	g.mu.RLock()
	defer g.mu.RUnlock()

	out := make([]Entry, 0, g.set.Len())
	for _, e := range g.set.List() {
		by, acked := g.ackedGeneric[e]
		generic := IsGeneric(e)
		out = append(out, Entry{
			ESSID:           e,
			Generic:         generic,
			Acknowledged:    acked,
			AcknowledgedBy:  by,
			ActiveWorkReady: !generic || acked,
		})
	}
	return out
}

// Confirmations returns operator confirmations by BSSID.
func (g *Gate) Confirmations() map[string]string { return g.copyMap(g.confirmed) }

// Rejections returns operator vetoes by BSSID.
func (g *Gate) Rejections() map[string]string { return g.copyMap(g.rejected) }

func (g *Gate) copyMap(m map[string]string) map[string]string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Set returns the underlying ESSID scope.
func (g *Gate) Set() *Set { return g.set }

// Replay rebuilds operator state (acknowledgments, confirmations, vetoes) from an existing
// events.jsonl.
//
// The audit log is the source of truth for this state - there is no second state file that
// could disagree with the evidence. Replaying it at daemon startup is what lets a shipped
// NUC come back from a reboot mid-engagement with the acknowledgments already in place.
//
// Malformed lines are skipped rather than failing the load: a truncated final record from a
// SIGKILL must not prevent the engagement from resuming.
func (g *Gate) Replay(r io.Reader) (int, error) {
	dec := json.NewDecoder(r)
	applied := 0
	for {
		var e audit.Event
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				return applied, nil
			}
			if _, ok := err.(*json.SyntaxError); ok {
				return applied, fmt.Errorf("replay audit log: %w", err)
			}
			return applied, fmt.Errorf("replay audit log: %w", err)
		}

		g.mu.Lock()
		switch e.Kind {
		case audit.KindGenericESSID:
			if e.Outcome == audit.OutcomeAck && g.set.Contains(e.ESSID) {
				op, _ := e.Detail["operator"].(string)
				g.ackedGeneric[e.ESSID] = op
				applied++
			}
		case audit.KindConfirm:
			if b := NormalizeBSSID(e.BSSID); b != "" {
				note, _ := e.Detail["note"].(string)
				g.confirmed[b] = note
				delete(g.rejected, b)
				applied++
			}
		case audit.KindReject:
			if b := NormalizeBSSID(e.BSSID); b != "" {
				note, _ := e.Detail["note"].(string)
				g.rejected[b] = note
				delete(g.confirmed, b)
				applied++
			}
		}
		g.mu.Unlock()
	}
}

func detailNote(note string) map[string]any {
	if note == "" {
		return nil
	}
	return map[string]any{"note": note}
}

// NormalizeBSSID canonicalises a MAC address to lowercase colon-separated form.
//
// Returns "" if s is not a MAC address, so callers can reject bad input without a second
// validation step.
func NormalizeBSSID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	hw, err := net.ParseMAC(s)
	if err != nil || len(hw) != 6 {
		return ""
	}
	return strings.ToLower(hw.String())
}
