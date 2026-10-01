package report

import (
	"sort"
	"time"

	"github.com/waffl3ss/warp/internal/rogue"
	"github.com/waffl3ss/warp/internal/store"
)

// Data is the machine-readable engagement report. It is laid out for reporting in two parts: the
// networks section is the BSSID-to-ESSID map (each ESSID and every BSSID under it), and the findings
// section is one entry per finding - its title, the evidence behind it, and the assets it affects.
// It carries no secret material: no passphrases, PINs, MSCHAPv2 hashes or cleartext. Those stay in
// the creds/ and .22000 files; this says *what* was recovered for which network, not the value.
type Data struct {
	Generated   time.Time      `json:"generated"`
	Tool        Tool           `json:"tool"`
	Scope       ScopeInfo      `json:"scope"`
	InScopeOnly bool           `json:"in_scope_only"`
	Networks    []Network      `json:"networks"`
	Findings    []FindingGroup `json:"findings,omitempty"`
	// Unclassified are observed devices with no conclusion attached.
	Unclassified []Device `json:"unclassified,omitempty"`
}

// Tool identifies the build that produced the report, so a finding traces back to the code.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
}

// ScopeInfo is the engagement scope.
type ScopeInfo struct {
	ESSIDs   []string `json:"essids"`
	SiteWide bool     `json:"site_wide"`
}

// Network is one ESSID and every access point broadcasting it - the BSSID-to-ESSID map. An empty
// ESSID is the bucket for hidden or unnamed access points. Findings are not nested here; they live in
// the top-level findings section, grouped by finding rather than by device.
type Network struct {
	ESSID    string    `json:"essid"`
	InScope  bool      `json:"in_scope"`
	BSSIDs   []AP      `json:"bssids"`
	Captured *Captured `json:"captured,omitempty"`
}

// AP is one observed access point.
type AP struct {
	BSSID       string `json:"bssid"`
	Channel     int    `json:"channel,omitempty"`
	Band        string `json:"band,omitempty"`
	Security    string `json:"security,omitempty"`
	Ciphers     string `json:"ciphers,omitempty"`
	AKMs        string `json:"akms,omitempty"`
	MFP         string `json:"mfp,omitempty"`
	WPS         bool   `json:"wps"`
	Transition  bool   `json:"transition_mode,omitempty"`
	Hidden      bool   `json:"hidden,omitempty"`
	Fingerprint string `json:"fingerprint_hash,omitempty"`
	OUI         string `json:"oui,omitempty"`
	BestRSSI    *int   `json:"best_rssi,omitempty"`
	FirstSeen   string `json:"first_seen,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`
	Beacons     int64  `json:"beacons,omitempty"`
	// EncryptionDetail is the parsed beacon security laid out like a `tshark -V` dump - the same
	// packet-detail evidence the web "Encryption Packet" popup shows - so a reporting platform can
	// import it verbatim as one field.
	EncryptionDetail string `json:"encryption_detail,omitempty"`
}

// FindingGroup is one finding: its title, the evidence behind it, and the assets it affects. This is
// the reporting shape - grouped by finding, not repeated per device.
type FindingGroup struct {
	Title     string    `json:"title"`
	Tier      string    `json:"tier"`
	Rationale string    `json:"rationale,omitempty"`
	Evidence  *Evidence `json:"evidence,omitempty"`
	Assets    []Device  `json:"assets"`
}

// EvidencePlaceholder is written into a finding's evidence when there was no packet-level basis to
// record (no beacon/probe-response record joined and no cited fingerprint differences). It is a
// single, stable, obviously-not-real string so an import into a reporting platform has one token to
// find-and-replace with the manually gathered evidence, rather than a silently empty field.
const EvidencePlaceholder = "REPLACE: no packet-level evidence was captured for this finding - fill in manually"

// Evidence is the observed basis for a finding: a one-line pointer to what it rests on, and, for a
// representative affected access point, the parsed beacon facts (never a secret). When there is no
// packet-level basis to show, Placeholder carries a replaceable token instead.
type Evidence struct {
	// Note says what to look at - the finding stated plainly.
	Note string `json:"note,omitempty"`
	// Placeholder is set (to EvidencePlaceholder) only when no packet-level evidence was captured,
	// so a downstream import always has a field present to fill in.
	Placeholder string `json:"placeholder,omitempty"`
	// WPAVersion, GroupCipher, Ciphers, AKMs, MFP, WPS, Hidden are the representative asset's parsed
	// beacon security, so a reader can see the encryption posture the conclusion came from.
	BSSID       string   `json:"bssid,omitempty"`
	ESSID       string   `json:"essid,omitempty"`
	WPAVersion  string   `json:"wpa_version,omitempty"`
	Ciphers     string   `json:"ciphers,omitempty"`
	AKMs        string   `json:"akms,omitempty"`
	MFP         string   `json:"mfp,omitempty"`
	WPS         string   `json:"wps,omitempty"`
	Hidden      bool     `json:"hidden,omitempty"`
	Differences []string `json:"differences,omitempty"`
}

// Captured notes what was recovered for a network, never the value.
type Captured struct {
	PMKID              int  `json:"pmkid,omitempty"`
	Handshake          int  `json:"handshake,omitempty"`
	WPSPassphrase      bool `json:"wps_passphrase,omitempty"`
	WPSPin             bool `json:"wps_pin,omitempty"`
	EnterpriseMSCHAPv2 int  `json:"enterprise_mschapv2,omitempty"`
}

// Device is a bare BSSID/ESSID pair, for asset lists and the unclassified section.
type Device struct {
	BSSID string `json:"bssid"`
	ESSID string `json:"essid,omitempty"`
}

// CaptureSummary is what was recovered for one ESSID, supplied by the daemon (which owns the WPS and
// enterprise credential state); the store supplies the hash counts.
type CaptureSummary struct {
	PMKID              int
	Handshake          int
	WPSPassphrase      bool
	WPSPin             bool
	EnterpriseMSCHAPv2 int
}

// BuildData assembles the machine-readable report. networks is the BSSID-to-ESSID map; findings is
// grouped by finding with evidence and affected assets. inScope reports scope membership; caps is the
// per-ESSID capture summary; scoped drops out-of-scope networks and findings entirely.
func BuildData(r *Report, tool Tool, inScope func(string) bool, caps map[string]CaptureSummary, scoped bool) Data {
	d := Data{Generated: time.Now(), Tool: tool, InScopeOnly: scoped}
	for _, e := range r.Scope {
		d.Scope.ESSIDs = append(d.Scope.ESSIDs, e.ESSID)
	}

	apByBSSID := map[string]store.APRow{}
	byESSID := map[string][]store.APRow{}
	order := []string{}
	for _, ap := range r.APs {
		apByBSSID[ap.BSSID] = ap
		if _, ok := byESSID[ap.ESSID]; !ok {
			order = append(order, ap.ESSID)
		}
		byESSID[ap.ESSID] = append(byESSID[ap.ESSID], ap)
	}
	netInScope := func(essid string) bool { return essid != "" && inScope(essid) }

	// networks: one entry per ESSID with its BSSIDs.
	sort.Strings(order)
	for _, essid := range order {
		if scoped && !netInScope(essid) {
			continue
		}
		n := Network{ESSID: essid, InScope: netInScope(essid)}
		for _, ap := range byESSID[essid] {
			n.BSSIDs = append(n.BSSIDs, apOf(ap))
		}
		if c, ok := caps[essid]; ok && (c.PMKID > 0 || c.Handshake > 0 || c.WPSPassphrase ||
			c.WPSPin || c.EnterpriseMSCHAPv2 > 0) {
			n.Captured = &Captured{
				PMKID: c.PMKID, Handshake: c.Handshake, WPSPassphrase: c.WPSPassphrase,
				WPSPin: c.WPSPin, EnterpriseMSCHAPv2: c.EnterpriseMSCHAPv2,
			}
		}
		d.Networks = append(d.Networks, n)
	}

	// findings: grouped by title, each with its assets and the evidence behind it.
	groups := map[string]*FindingGroup{}
	sampledInScope := map[string]bool{} // whether a group's evidence sample is an in-scope asset
	var labels []string
	for _, f := range append(append([]store.Finding{}, r.Findings...), r.OutOfScopeFindings...) {
		// A manually-marked potential rogue is always part of the deliverable, even under the
		// in-scope filter: it is a finding about a device in the client's footprint that is, by its
		// nature, not on a scoped ESSID. Filtering it out with the out-of-scope neighbours would
		// discard exactly the finding the operator went out of their way to record.
		if scoped && !netInScope(f.ESSID) && f.Label != rogue.LabelPotentialRogue {
			continue
		}
		g := groups[f.Label]
		if g == nil {
			g = &FindingGroup{Title: f.Label, Tier: string(f.Tier)}
			groups[f.Label] = g
			labels = append(labels, f.Label)
		}
		if g.Rationale == "" {
			g.Rationale = f.Rationale
		}
		g.Assets = append(g.Assets, Device{BSSID: f.BSSID, ESSID: f.ESSID})
		// Prefer an in-scope asset for the evidence sample; take the first otherwise.
		if g.Evidence == nil || (netInScope(f.ESSID) && !sampledInScope[f.Label]) {
			g.Evidence = evidenceFor(f, apByBSSID[f.BSSID])
			sampledInScope[f.Label] = netInScope(f.ESSID)
		}
	}
	for _, l := range labels {
		d.Findings = append(d.Findings, *groups[l])
	}

	// unclassified devices.
	essidOf := map[string]string{}
	for _, ap := range r.APs {
		essidOf[ap.BSSID] = ap.ESSID
	}
	for _, bssid := range r.Unclassified {
		essid := essidOf[bssid]
		if scoped && !netInScope(essid) {
			continue
		}
		d.Unclassified = append(d.Unclassified, Device{BSSID: bssid, ESSID: essid})
	}
	return d
}

// evidenceFor builds the evidence for a finding, chosen by finding type so the JSON matches the web:
// the beacon cipher parse is the evidence only for a posture/encryption finding. A finding whose
// basis is something else carries that instead, and the "fill in manually" placeholder is used only
// when there genuinely is no captured basis - never for a finding that has its own (a karma probe
// response, a recovered hidden name, a cited fingerprint difference).
func evidenceFor(f store.Finding, ap store.APRow) *Evidence {
	e := &Evidence{Note: f.Rationale, BSSID: f.BSSID, ESSID: f.ESSID}

	switch f.Label {
	case rogue.LabelPotentialRogue:
		// Operator judgement, no packet-level basis: the evidence is the manual placeholder, and the
		// description (Note) is not the placeholder.
		e.Note = "Manual evidence required."
		e.Placeholder = EvidencePlaceholder
		return e

	case rogue.LabelKarmaResponder:
		// The basis is the active karma detection stated in the rationale, not a beacon. Never a
		// cipher dump, and never the "no evidence" placeholder - WARP captured the probe response.
		return e

	case rogue.LabelEvilTwinCandidate:
		// The basis is the diverging fingerprint attributes, carried as differences.
		e.Differences = f.Differences
		return e

	case rogue.LabelDecloaked:
		// The basis is that it beacons an empty SSID and the name was recovered anyway - the
		// cloaking, not the encryption.
		e.Hidden = true
		return e
	}

	// Everything else is a posture/encryption finding: the parsed beacon security is the evidence.
	if ap.BSSID != "" {
		e.WPAVersion = wpaVersionOf(ap.SecurityClass, ap.Transition, ap.WPS)
		e.Ciphers = ap.Ciphers
		e.AKMs = ap.AKMs
		e.MFP = ap.MFP
		e.Hidden = ap.Hidden
		if ap.WPS {
			e.WPS = "enabled"
		}
		return e
	}
	// A posture finding whose beacon record was not found (pruned, say) has nothing to show. Leave a
	// single, obvious, find-and-replaceable token so a downstream import has a slot to fill in rather
	// than a silently empty field.
	e.Placeholder = EvidencePlaceholder
	return e
}

// wpaVersionOf turns a stored security class into a human WPA-version string.
func wpaVersionOf(class string, transition, wps bool) string {
	base := ""
	switch class {
	case "open":
		base = "open (no encryption)"
	case "owe":
		base = "OWE"
	case "wep":
		base = "WEP"
	case "wpa_sae":
		base = "WPA3-SAE"
	case "wpa_enterprise":
		base = "WPA2-Enterprise (802.1X)"
	case "wpa3_enterprise_192":
		base = "WPA3-Enterprise 192-bit"
	case "wpa_psk":
		base = "WPA2-PSK"
	default:
		base = class
	}
	if transition {
		base += " (WPA2/WPA3 transition)"
	}
	return base
}

func apOf(r store.APRow) AP {
	return AP{
		BSSID: r.BSSID, Channel: r.Channel, Band: r.Band, Security: r.SecurityClass,
		Ciphers: r.Ciphers, AKMs: r.AKMs, MFP: r.MFP, WPS: r.WPS, Transition: r.Transition,
		Hidden: r.Hidden, Fingerprint: r.FingerprintHash, OUI: r.OUI, BestRSSI: r.BestRSSI,
		FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, Beacons: r.Beacons,
		EncryptionDetail: encryptionDetail(r),
	}
}
