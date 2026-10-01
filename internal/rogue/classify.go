package rogue

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/store"
)

// Labels applied to findings. These are stable strings - they appear in reports.
const (
	LabelOpenNetwork        = "open network on a scoped ESSID"
	LabelWEP                = "WEP encryption"
	LabelTKIP               = "TKIP (WPA1) cipher"
	LabelWPSEnabled         = "WPS enabled"
	LabelWPSUnlocked        = "WPS enabled and unlocked"
	LabelPSKAmongEnterprise = "PSK access point on an otherwise enterprise ESSID"
	LabelMFPAbsent          = "protected management frames not enabled (802.11w)"
	LabelMFPOptional        = "protected management frames optional, not enforced (802.11w)"
	LabelMFPRequired        = "protected management frames required (802.11w)"

	// LabelDecloaked is a hidden network whose name WARP recovered anyway. Worth reporting
	// because the client believes that network is not advertising itself.
	LabelDecloaked      = "hidden network name recovered"
	LabelTransitionMode = "WPA2/WPA3 transition mode"
	LabelKarmaResponder = "karma responder"

	// LabelEvilTwinCandidate is deliberately hedged. A fingerprint outlier is evidence, not
	// proof: it is a candidate for investigation, and calling it a confirmed evil twin in a
	// report is a claim that cannot be defended from the air alone.
	LabelEvilTwinCandidate = "evil twin candidate"

	// LabelPotentialRogue is applied only by an operator, never by the classifier. Someone
	// standing in the building decides a specific BSSID/ESSID warrants investigation and marks it;
	// WARP records the mark as an evidence-tier finding with no automatic basis, so the evidence
	// field points at manual evidence the operator supplies. It is deliberately out of
	// ClassifierLabels so a re-classify never invents it and never wipes a mark. Note what it does
	// not claim: it does not assert the device is on the client's wired network - that requires
	// wired-side correlation and cannot be obtained from the air.
	LabelPotentialRogue = "Potentially Rogue Device"
)

// ClassifierLabels is every label the classifier can produce. A re-classify replaces only these,
// leaving findings recorded by the active attacks (a WPS PIN recovered by Pixie Dust, say) and by
// the operator (a manually marked potential rogue) in place - those are results of work done or of
// an operator's judgement, not conclusions re-derivable from passive observation, and must not be
// wiped by re-running the classifier. LabelPotentialRogue is intentionally absent for this reason.
var ClassifierLabels = []string{
	LabelOpenNetwork, LabelWEP, LabelTKIP, LabelWPSEnabled, LabelWPSUnlocked,
	LabelPSKAmongEnterprise, LabelMFPAbsent, LabelMFPOptional, LabelMFPRequired,
	LabelDecloaked, LabelTransitionMode, LabelKarmaResponder, LabelEvilTwinCandidate,
}

// Classifier turns observations into tiered findings.
//
// The separation the brief insists on is preserved throughout: nothing here modifies an AP's
// observed record. Findings are written to their own table, so a report can always show the
// evidence independently of the label, and a reclassification changes nothing about what was
// seen.
type Classifier struct {
	cfg Config
	// match resolves an observed ESSID against the scope, returning the scope entry as the
	// client wrote it, whether the observed name matched byte-for-byte, and whether it
	// matched at all.
	match ScopeMatcher
}

// ScopeMatcher resolves an observed ESSID against the engagement scope.
type ScopeMatcher func(essid string) (entry string, exact bool, ok bool)

// NewClassifier builds a classifier. match must not be nil.
func NewClassifier(cfg Config, match ScopeMatcher) *Classifier {
	if match == nil {
		match = func(string) (string, bool, bool) { return "", false, false }
	}
	return &Classifier{cfg: cfg.withDefaults(), match: match}
}

// scoped is the yes/no form, for the many places that do not care about case.
func (c *Classifier) scoped(essid string) bool {
	_, _, ok := c.match(essid)
	return ok
}

// Result is a full classification pass.
type Result struct {
	Findings []store.Finding `json:"findings"`
	Analyses []Analysis      `json:"analyses"`
	// Unclassified lists devices that were observed and deliberately not labelled.
	Unclassified []string `json:"unclassified,omitempty"`
}

// Classify runs a full pass over the observed population.
//
// The determined tier comes first and is derived per-AP from deterministic facts. The
// evidence tier comes from population clustering per scoped ESSID. Everything else stays
// unclassified and is listed with its observations attached and no label applied.
func (c *Classifier) Classify(aps []recon.AP, karmaResponders map[recon.MAC]string, now time.Time) Result {
	var res Result

	// ---------------------------------------------------------------------
	// Determined tier: deterministic and defensible.
	// ---------------------------------------------------------------------
	byESSID := map[string][]recon.AP{}
	for _, ap := range aps {
		if ap.ESSID != "" {
			byESSID[ap.ESSID] = append(byESSID[ap.ESSID], ap)
		}
		res.Findings = append(res.Findings, c.determinedFindings(ap, now)...)
	}

	// A PSK access point sharing an ESSID that is otherwise served by enterprise (802.1X) access
	// points is an anomaly: a legitimate enterprise deployment does not usually hand out the same
	// name over a pre-shared key, and a PSK BSS on that name is the shape of a misconfiguration or
	// an impostor an ordinary client would still trust. It is a population fact, not a per-AP one -
	// it needs the ESSID's other BSSIDs to see it - so it is derived here rather than in
	// determinedFindings.
	res.Findings = append(res.Findings, enterpriseMixFindings(byESSID, now)...)

	// A karma responder is a yes/no result from an active test: we probed for a network that
	// cannot exist and this device answered. Nothing passive would ever find it.
	for bssid, essid := range karmaResponders {
		res.Findings = append(res.Findings, store.Finding{
			BSSID: bssid.String(), ESSID: essid,
			Tier:  store.TierDetermined,
			Label: LabelKarmaResponder,
			Rationale: "responded to a probe request for a randomly generated ESSID that cannot " +
				"exist; this device answers arbitrary probes, which is characteristic of a " +
				"Wi-Fi Pineapple or equivalent attacker device",
			FirstTS: now, LastTS: now,
		})
	}

	// ---------------------------------------------------------------------
	// Evidence tier: fingerprint outliers within a scoped ESSID's population.
	// ---------------------------------------------------------------------
	essids := make([]string, 0, len(byESSID))
	for e := range byESSID {
		essids = append(essids, e)
	}
	sort.Strings(essids)

	for _, essid := range essids {
		// Clustering only runs on scoped networks. An impostor is defined relative to the
		// network it is impersonating, and WARP has no standing to judge which of a
		// neighbour's access points is legitimate.
		if !c.scoped(essid) {
			continue
		}

		analysis := AnalyseESSID(essid, byESSID[essid], c.cfg)
		res.Analyses = append(res.Analyses, analysis)
		if analysis.Inconclusive {
			continue
		}

		for _, out := range analysis.Outliers {
			res.Findings = append(res.Findings, evilTwinFinding(analysis, out, now))
		}
	}

	// ---------------------------------------------------------------------
	// Unclassified: everything else, listed and unlabelled.
	// ---------------------------------------------------------------------
	labelled := map[string]bool{}
	for _, f := range res.Findings {
		labelled[f.BSSID] = true
	}
	for _, ap := range aps {
		if !labelled[ap.BSSID.String()] {
			res.Unclassified = append(res.Unclassified, ap.BSSID.String())
		}
	}
	sort.Strings(res.Unclassified)

	return res
}

// determinedFindings derives the deterministic, defensible facts about one AP.
func (c *Classifier) determinedFindings(ap recon.AP, now time.Time) []store.Finding {
	var out []store.Finding

	add := func(label, rationale string) {
		out = append(out, store.Finding{
			BSSID: ap.BSSID.String(), ESSID: ap.ESSID,
			Tier: store.TierDetermined, Label: label, Rationale: rationale,
			FirstTS: ap.FirstSeen, LastTS: ap.LastSeen,
		})
	}
	// ctrl records a positive result - a correct configuration, or a defence the network has in
	// place. It is a pass, not an exposure, so it is filed under the control tier and shown apart
	// from the findings that are actually exposures.
	ctrl := func(label, rationale string) {
		out = append(out, store.Finding{
			BSSID: ap.BSSID.String(), ESSID: ap.ESSID,
			Tier: store.TierControl, Label: label, Rationale: rationale,
			FirstTS: ap.FirstSeen, LastTS: ap.LastSeen,
		})
	}

	// A cloaked network whose name was recovered anyway. SSID cloaking is not a security
	// control, but it is frequently deployed as though it were, so the client is usually
	// unaware their "hidden" network announces itself the moment a client associates.
	if ap.Cloaked && ap.ESSID != "" {
		source := ap.ESSIDSource
		if source == "" {
			source = "observed traffic"
		}
		add(LabelDecloaked, fmt.Sprintf(
			"beacons an empty SSID element, but the name %q was recovered from %s. SSID "+
				"cloaking hides the network from a casual scan and from nothing else - any "+
				"client joining it broadcasts the name in the clear", ap.ESSID, source))
	}

	// Posture findings are recorded for every observed network, in scope or not, and each one's
	// scope membership is filed separately (Finding.ESSID against the scope: findings-in-scope.csv,
	// the report's deliverable section, the findings-tab "in scope only" toggle). This follows the
	// same "capture everything; file it by scope" rule the capture path uses - throwing away a
	// neighbour's exposure at classification time discards context the operator may need, and the
	// scope separation keeps it out of the client deliverable without losing it. Transmitting work
	// is still gated on scope everywhere else; observing a posture is not transmitting.
	switch ap.Security.Class {
	case recon.SecOpen:
		add(LabelOpenNetwork,
			"broadcasts with no encryption; any client associating here transmits in the clear")
	case recon.SecWEP:
		add(LabelWEP,
			"uses WEP, which is trivially recoverable and has been deprecated since 2004")
	}

	// TKIP is the WPA1-era cipher: deprecated since 2012, disallowed alongside 802.11n/ac
	// rates, and vulnerable to the Beck-Tews/Ohigashi class of attacks. Its presence - a pure
	// WPA1 BSS, or a WPA2 BSS still offering TKIP for backward compatibility - is a posture
	// finding.
	for _, c := range ap.Security.Ciphers {
		if c == "TKIP" {
			add(LabelTKIP,
				"advertises the TKIP cipher (WPA1), deprecated since 2012 and weaker than "+
					"CCMP; an AP still offering it for backward compatibility widens the attack "+
					"surface")
			break
		}
	}

	if ap.Security.WPS {
		if ap.Security.WPSLocked {
			ctrl(LabelWPSEnabled,
				"WPS is enabled but the AP reports setup as locked, which blocks the "+
					"registrar exchange while it remains locked - the correct configuration")
		} else {
			add(LabelWPSUnlocked,
				"WPS is enabled and not locked. WARP runs one offline Pixie Dust exchange: if "+
					"the AP's registration nonces are weak it recovers the PIN offline and reads "+
					"the WPA passphrase out of M7, regardless of passphrase strength. No online "+
					"PIN brute force is performed")
		}
	}

	if ap.Security.Transition {
		add(LabelTransitionMode,
			"advertises WPA3-SAE and WPA2-PSK on one BSS. WPA3's own SAE handshake has no "+
				"offline-crackable material, but the legacy PSK side does: associating while "+
				"offering only the PSK AKM downgrades to WPA2 and the AP returns a crackable PMKID "+
				"in its first message - no client and no passphrase needed. Where the AP does not "+
				"volunteer a PMKID, deauthenticating a client forces a WPA2 four-way handshake that "+
				"is equally crackable. The WPA3 upgrade buys nothing while the WPA2 path is offered.")
	}

	// Protected Management Frames (802.11w) posture is a finding in all three states.
	// Required is good practice worth recording; optional and absent are both exposures, and
	// all three determine whether deauthentication will work at all.
	//
	// "Capable" is not "protected": a client that does not negotiate PMF is deauthenticatable
	// on an AP that merely offers it, so it is reported as an exposure rather than folded in
	// with required.
	if ap.Security.Class != recon.SecOpen && ap.Security.Class != recon.SecWEP {
		switch ap.Security.MFP {
		case recon.MFPRequired:
			ctrl(LabelMFPRequired,
				"802.11w is required, so management frames are authenticated: associated "+
					"clients cannot be deauthenticated and a handshake cannot be forced")
		case recon.MFPCapable:
			add(LabelMFPOptional,
				"802.11w is advertised but not required. Clients that negotiate it are "+
					"protected; clients that do not can still be deauthenticated, so the "+
					"protection depends on the client rather than the network")
		case recon.MFPAbsent:
			add(LabelMFPAbsent,
				"802.11w is neither required nor advertised, so management frames are "+
					"unauthenticated: any associated client can be deauthenticated at will, "+
					"which forces a handshake and enables a denial of service")
		}
	}

	return out
}

// enterpriseMixFindings flags every PSK access point that shares an ESSID with one or more
// enterprise (802.1X) access points. The enterprise BSSIDs are the norm on that name; the PSK one
// is the anomaly, so the finding lands on the PSK BSSID. It is evidence-tier: the PSK class is a
// hard fact, but "otherwise enterprise" is an inference from the observed population, and a
// deployment that deliberately runs a PSK BSS beside an enterprise one on the same name (unusual,
// but not impossible) would trip it, so it is reported as something to verify, not as a verdict.
func enterpriseMixFindings(byESSID map[string][]recon.AP, now time.Time) []store.Finding {
	isEnterprise := func(s recon.Security) bool {
		return s == recon.SecWPAEnterprise || s == recon.SecWPA3Ent192
	}
	isPSK := func(s recon.Security) bool {
		return s == recon.SecWPAPSK || s == recon.SecWPASAE
	}

	essids := make([]string, 0, len(byESSID))
	for e := range byESSID {
		essids = append(essids, e)
	}
	sort.Strings(essids)

	var out []store.Finding
	for _, essid := range essids {
		aps := byESSID[essid]
		enterprise := 0
		for _, ap := range aps {
			if isEnterprise(ap.Security.Class) {
				enterprise++
			}
		}
		if enterprise == 0 {
			continue // nothing enterprise on this name, so no PSK BSS is out of place
		}
		for _, ap := range aps {
			if !isPSK(ap.Security.Class) {
				continue
			}
			out = append(out, store.Finding{
				BSSID: ap.BSSID.String(), ESSID: ap.ESSID,
				Tier:  store.TierEvidence,
				Label: LabelPSKAmongEnterprise,
				Rationale: fmt.Sprintf(
					"advertises a pre-shared key (%s) on %q, while %d access point(s) on the same "+
						"name serve it over 802.1X enterprise authentication. An enterprise network "+
						"does not usually also hand out the same name over a PSK, so this BSSID is "+
						"either a misconfiguration or an impostor a client would still trust. Verify "+
						"physically before acting.",
					ap.Security.Class, essid, enterprise),
				FirstTS: ap.FirstSeen, LastTS: ap.LastSeen,
			})
		}
	}
	return out
}

// evilTwinFinding builds the evidence-tier finding for a fingerprint outlier.
func evilTwinFinding(a Analysis, out Outlier, now time.Time) store.Finding {
	diffs := make([]string, 0, len(out.Differences))
	for _, d := range out.Differences {
		diffs = append(diffs, d.String())
	}

	score := out.Score
	rationale := fmt.Sprintf(
		"radio fingerprint falls outside the dominant cluster on %q. %d of %d access points "+
			"broadcasting this ESSID share one fingerprint; this one does not (similarity %.2f). "+
			"An impostor cannot easily reproduce the firmware-specific elements a real fleet "+
			"member emits. Verify physically before acting: an unusual but legitimate access "+
			"point produces the same signal.",
		a.ESSID, a.Dominant.Size(), a.Population, out.Score)

	return store.Finding{
		BSSID:       out.AP.BSSID.String(),
		ESSID:       out.AP.ESSID,
		Tier:        store.TierEvidence,
		Label:       LabelEvilTwinCandidate,
		Rationale:   rationale,
		Differences: diffs,
		Score:       &score,
		FirstTS:     out.AP.FirstSeen,
		LastTS:      out.AP.LastSeen,
	}
}

// Summary renders an analysis for operator-facing output.
func (a Analysis) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d access point(s)", a.ESSID, a.Population)

	if a.Inconclusive {
		fmt.Fprintf(&b, " - inconclusive: %s", a.Reason)
		return b.String()
	}
	fmt.Fprintf(&b, ", dominant cluster %d", a.Dominant.Size())
	if len(a.Outliers) == 0 {
		b.WriteString(", no outliers")
		return b.String()
	}
	fmt.Fprintf(&b, ", %d outlier(s):", len(a.Outliers))
	for _, o := range a.Outliers {
		fmt.Fprintf(&b, "\n    %s (similarity %.2f)", o.AP.BSSID, o.Score)
		for _, d := range o.Differences {
			fmt.Fprintf(&b, "\n      %s", d)
		}
	}
	return b.String()
}
