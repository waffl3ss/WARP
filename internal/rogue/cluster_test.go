package rogue

import (
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/store"
)

// Synthetic populations, as the brief requires: a homogeneous cluster with a planted outlier
// (must detect), and a genuinely mixed-vendor tenant environment (must NOT false-positive).

var (
	ouiCisco  = [3]byte{0x00, 0x40, 0x96}
	ouiAruba  = [3]byte{0x00, 0x0b, 0x86}
	ouiRuckus = [3]byte{0x00, 0x1d, 0x2e}
	ouiMS     = [3]byte{0x00, 0x50, 0xf2}
)

func ie(id uint8, data ...byte) []byte {
	return append([]byte{id, byte(len(data))}, data...)
}

func vendorIE(oui [3]byte, subtype uint8, data ...byte) []byte {
	body := append([]byte{oui[0], oui[1], oui[2], subtype}, data...)
	return ie(221, body...)
}

func htCapIE(caps uint16) []byte {
	body := make([]byte, 26)
	body[0], body[1] = byte(caps), byte(caps>>8)
	return ie(45, body...)
}

func rsnIE(caps uint16) []byte {
	body := []byte{0x01, 0x00}
	body = append(body, 0x00, 0x0F, 0xAC, 0x04)
	body = append(body, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04)
	body = append(body, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x01)
	body = append(body, byte(caps), byte(caps>>8))
	return ie(48, body...)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func mac(t *testing.T, s string) recon.MAC {
	t.Helper()
	m, err := recon.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return m
}

// vendorProfile is how one vendor's firmware presents on the air.
//
// Real APs from different vendors differ in far more than an OUI byte: rate sets, HT
// capability bits, RSN capabilities, beacon interval and the order they emit elements in are
// all firmware decisions. Fixtures that vary only the OUI are not a mixed environment — they
// are one environment with a cosmetic difference, and they would let a genuinely broken
// clustering implementation pass.
type vendorProfile struct {
	oui            [3]byte
	rates          []byte
	htCaps         uint16
	rsnCaps        uint16
	beaconInterval uint16
	// vendorSubtypes is how many vendor elements the firmware emits.
	vendorSubtypes []uint8
	// dsBeforeRates reflects a different element ordering.
	dsBeforeRates bool
}

var (
	profileCisco = vendorProfile{
		oui:    ouiCisco,
		rates:  []byte{0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24},
		htCaps: 0x016e, rsnCaps: 0x0080, beaconInterval: 100,
		vendorSubtypes: []uint8{0x01, 0x03},
	}
	profileAruba = vendorProfile{
		oui:    ouiAruba,
		rates:  []byte{0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c},
		htCaps: 0x19ef, rsnCaps: 0x000c, beaconInterval: 100,
		vendorSubtypes: []uint8{0x01},
		dsBeforeRates:  true,
	}
	profileRuckus = vendorProfile{
		oui:    ouiRuckus,
		rates:  []byte{0x82, 0x84, 0x8b, 0x96},
		htCaps: 0x107e, rsnCaps: 0x0000, beaconInterval: 200,
		vendorSubtypes: []uint8{0x01, 0x02, 0x04},
	}
)

func (p vendorProfile) elements(essid string) []byte {
	var parts [][]byte
	parts = append(parts, ie(0, []byte(essid)...))
	if p.dsBeforeRates {
		parts = append(parts, ie(3, 6), ie(1, p.rates...))
	} else {
		parts = append(parts, ie(1, p.rates...), ie(3, 6))
	}
	parts = append(parts, rsnIE(p.rsnCaps), htCapIE(p.htCaps))
	for _, st := range p.vendorSubtypes {
		parts = append(parts, vendorIE(p.oui, st, 0x01, 0x02))
	}
	parts = append(parts, vendorIE(ouiMS, 0x02, 0x01, 0x01))
	return concat(parts...)
}

// fleetAP builds a member of a homogeneous vendor fleet.
func fleetAP(t *testing.T, bssid, essid string, p vendorProfile, beacons uint64) recon.AP {
	t.Helper()
	ies, err := recon.ParseIEs(p.elements(essid))
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	now := time.Now()
	return recon.AP{
		BSSID: mac(t, bssid), ESSID: essid, Channel: 6, Freq: 2437,
		Security:    recon.ClassifySecurity(ies, recon.CapESS|recon.CapPrivacy),
		Fingerprint: recon.FingerprintFrom(ies, recon.CapESS|recon.CapPrivacy, p.beaconInterval),
		FirstSeen:   now, LastSeen: now, Beacons: beacons,
	}
}

// impostorAP builds what an evil twin actually looks like: hostapd on a laptop or Pineapple,
// advertising almost no vendor elements.
func impostorAP(t *testing.T, bssid, essid string) recon.AP {
	t.Helper()
	ies, err := recon.ParseIEs(concat(
		ie(0, []byte(essid)...),
		ie(1, 0x82, 0x84, 0x8b, 0x96),
		ie(3, 6),
		rsnIE(0x0000),
		vendorIE(ouiMS, 0x02, 0x01, 0x01),
	))
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	now := time.Now()
	return recon.AP{
		BSSID: mac(t, bssid), ESSID: essid, Channel: 6, Freq: 2437,
		Security:    recon.ClassifySecurity(ies, recon.CapESS|recon.CapPrivacy),
		Fingerprint: recon.FingerprintFrom(ies, recon.CapESS|recon.CapPrivacy, 100),
		FirstSeen:   now, LastSeen: now, Beacons: 5,
	}
}

// TestHomogeneousFleetWithPlantedOutlier is the detection case.
func TestHomogeneousFleetWithPlantedOutlier(t *testing.T) {
	aps := []recon.AP{
		fleetAP(t, "a4:2b:8c:11:22:01", "CORP-WIFI", profileCisco, 100),
		fleetAP(t, "a4:2b:8c:11:22:02", "CORP-WIFI", profileCisco, 90),
		fleetAP(t, "a4:2b:8c:11:22:03", "CORP-WIFI", profileCisco, 80),
		fleetAP(t, "a4:2b:8c:11:22:04", "CORP-WIFI", profileCisco, 70),
		impostorAP(t, "de:ad:be:ef:00:01", "CORP-WIFI"),
	}

	a := AnalyseESSID("CORP-WIFI", aps, Config{})

	if a.Inconclusive {
		t.Fatalf("analysis was inconclusive on a clearly homogeneous fleet: %s", a.Reason)
	}
	if a.Dominant == nil {
		t.Fatal("no dominant cluster identified")
	}
	if a.Dominant.Size() != 4 {
		t.Errorf("dominant cluster size = %d, want 4", a.Dominant.Size())
	}
	if len(a.Outliers) != 1 {
		t.Fatalf("got %d outliers, want 1: %+v", len(a.Outliers), a.Outliers)
	}

	out := a.Outliers[0]
	if out.AP.BSSID.String() != "de:ad:be:ef:00:01" {
		t.Errorf("flagged the wrong AP: %s", out.AP.BSSID)
	}
	if len(out.Differences) == 0 {
		t.Fatal("no differences attached; the report needs specific attributes, not a score")
	}

	var attrs []string
	for _, d := range out.Differences {
		attrs = append(attrs, d.Attribute)
	}
	if !strings.Contains(strings.Join(attrs, ","), "vendor_ies") {
		t.Errorf("expected a vendor element difference, got %v", attrs)
	}
}

// TestMixedVendorEnvironmentIsInconclusive is the false-positive guard the brief is most
// insistent about. A multi-tenant floor with three vendors on one shared ESSID must produce
// nothing: flagging the least common vendor would send someone to tear down a legitimate AP.
func TestMixedVendorEnvironmentIsInconclusive(t *testing.T) {
	aps := []recon.AP{
		fleetAP(t, "a4:2b:8c:11:22:01", "SHARED-GUEST", profileCisco, 100),
		fleetAP(t, "a4:2b:8c:11:22:02", "SHARED-GUEST", profileCisco, 90),
		fleetAP(t, "b4:2b:8c:11:22:03", "SHARED-GUEST", profileAruba, 95),
		fleetAP(t, "b4:2b:8c:11:22:04", "SHARED-GUEST", profileAruba, 85),
		fleetAP(t, "c4:2b:8c:11:22:05", "SHARED-GUEST", profileRuckus, 88),
		fleetAP(t, "c4:2b:8c:11:22:06", "SHARED-GUEST", profileRuckus, 82),
	}

	a := AnalyseESSID("SHARED-GUEST", aps, Config{})

	if !a.Inconclusive {
		t.Fatalf("a genuinely mixed environment produced %d outlier(s); "+
			"this is the false positive that sends someone to tear down a legitimate AP:\n%s",
			len(a.Outliers), a.Summary())
	}
	if len(a.Outliers) != 0 {
		t.Errorf("inconclusive analysis still reported outliers: %+v", a.Outliers)
	}
	if !strings.Contains(a.Reason, "mixed") {
		t.Errorf("reason should explain the environment is mixed: %q", a.Reason)
	}
}

// TestSmallPopulationIsInconclusive: with two APs there is no way to tell which is the
// impostor, and flagging either is a guess dressed up as a finding.
func TestSmallPopulationIsInconclusive(t *testing.T) {
	for _, n := range []int{1, 2} {
		aps := []recon.AP{
			fleetAP(t, "a4:2b:8c:11:22:01", "CORP-WIFI", profileCisco, 100),
			impostorAP(t, "de:ad:be:ef:00:01", "CORP-WIFI"),
		}[:n]

		a := AnalyseESSID("CORP-WIFI", aps, Config{})
		if !a.Inconclusive {
			t.Errorf("population of %d produced a conclusion: %s", n, a.Summary())
		}
		if len(a.Outliers) != 0 {
			t.Errorf("population of %d produced outliers", n)
		}
	}
}

// TestSameVendorModelVariantsStayInCluster: a fleet is rarely perfectly uniform, and a second
// AP model from the same vendor must not be flagged.
func TestSameVendorModelVariantsStayInCluster(t *testing.T) {
	variant := fleetAP(t, "a4:2b:8c:11:22:09", "CORP-WIFI", profileCisco, 60)
	// Same vendor and configuration, slightly different PHY capabilities.
	ies, _ := recon.ParseIEs(concat(
		ie(0, []byte("CORP-WIFI")...),
		ie(1, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24),
		ie(3, 6),
		rsnIE(0x0080),
		htCapIE(0x11ee), // different HT capability bits
		vendorIE(ouiCisco, 0x01, 0x01, 0x02),
		vendorIE(ouiCisco, 0x03, 0x00),
		vendorIE(ouiMS, 0x02, 0x01, 0x01),
	))
	variant.Fingerprint = recon.FingerprintFrom(ies, recon.CapESS|recon.CapPrivacy, 100)

	aps := []recon.AP{
		fleetAP(t, "a4:2b:8c:11:22:01", "CORP-WIFI", profileCisco, 100),
		fleetAP(t, "a4:2b:8c:11:22:02", "CORP-WIFI", profileCisco, 90),
		fleetAP(t, "a4:2b:8c:11:22:03", "CORP-WIFI", profileCisco, 80),
		variant,
	}

	a := AnalyseESSID("CORP-WIFI", aps, Config{})
	if a.Inconclusive {
		t.Fatalf("inconclusive on a same-vendor fleet: %s", a.Reason)
	}
	if len(a.Outliers) != 0 {
		t.Errorf("a same-vendor model variant was flagged as an outlier: %s", a.Summary())
	}
}

// TestSpoofedBSSIDStillCaught is the advantage over an inventory lookup: an impostor that
// copied a legitimate BSSID still fails the fingerprint comparison.
func TestSpoofedBSSIDStillCaught(t *testing.T) {
	// The impostor uses a BSSID from the client's own OUI range.
	spoofed := impostorAP(t, "a4:2b:8c:11:22:99", "CORP-WIFI")

	aps := []recon.AP{
		fleetAP(t, "a4:2b:8c:11:22:01", "CORP-WIFI", profileCisco, 100),
		fleetAP(t, "a4:2b:8c:11:22:02", "CORP-WIFI", profileCisco, 90),
		fleetAP(t, "a4:2b:8c:11:22:03", "CORP-WIFI", profileCisco, 80),
		spoofed,
	}

	a := AnalyseESSID("CORP-WIFI", aps, Config{})
	if len(a.Outliers) != 1 {
		t.Fatalf("an impostor with a plausible BSSID was not flagged: %s", a.Summary())
	}
	if a.Outliers[0].AP.BSSID.String() != "a4:2b:8c:11:22:99" {
		t.Errorf("flagged %s", a.Outliers[0].AP.BSSID)
	}
}

func TestAPsWithoutFingerprintsAreSkipped(t *testing.T) {
	// An AP seen only via a truncated frame carries no fingerprint. Including it would make
	// it look like an outlier when the only difference is how much we heard.
	bare := recon.AP{BSSID: mac(t, "11:22:33:44:55:66"), ESSID: "CORP-WIFI"}

	aps := []recon.AP{
		fleetAP(t, "a4:2b:8c:11:22:01", "CORP-WIFI", profileCisco, 100),
		fleetAP(t, "a4:2b:8c:11:22:02", "CORP-WIFI", profileCisco, 90),
		fleetAP(t, "a4:2b:8c:11:22:03", "CORP-WIFI", profileCisco, 80),
		bare,
	}

	a := AnalyseESSID("CORP-WIFI", aps, Config{})
	for _, o := range a.Outliers {
		if o.AP.BSSID == bare.BSSID {
			t.Error("an AP with no usable fingerprint was flagged as an outlier")
		}
	}
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

func scopedOnly(essids ...string) ScopeMatcher {
	set := map[string]string{}
	for _, e := range essids {
		set[strings.ToLower(e)] = e
	}
	return func(e string) (string, bool, bool) {
		entry, ok := set[strings.ToLower(e)]
		return entry, ok && entry == e, ok
	}
}

func TestClassifyProducesTieredFindings(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-WIFI"))
	now := time.Now()

	aps := []recon.AP{
		fleetAP(t, "a4:2b:8c:11:22:01", "CORP-WIFI", profileCisco, 100),
		fleetAP(t, "a4:2b:8c:11:22:02", "CORP-WIFI", profileCisco, 90),
		fleetAP(t, "a4:2b:8c:11:22:03", "CORP-WIFI", profileCisco, 80),
		impostorAP(t, "de:ad:be:ef:00:01", "CORP-WIFI"),
	}

	res := c.Classify(aps, nil, now)

	var determined, evidence int
	var evilTwin *store.Finding
	for i, f := range res.Findings {
		switch f.Tier {
		case store.TierDetermined:
			determined++
		case store.TierEvidence:
			evidence++
			if f.Label == LabelEvilTwinCandidate {
				evilTwin = &res.Findings[i]
			}
		}
	}
	if determined == 0 {
		t.Error("no determined-tier findings produced")
	}
	if evilTwin == nil {
		t.Fatalf("no evil twin candidate produced: %+v", res.Findings)
	}

	// The hedge is deliberate and must survive: an outlier is a candidate for investigation,
	// not a confirmed evil twin.
	if strings.Contains(evilTwin.Label, "confirmed") || evilTwin.Label != LabelEvilTwinCandidate {
		t.Errorf("label = %q; it must stay hedged", evilTwin.Label)
	}
	if len(evilTwin.Differences) == 0 {
		t.Error("evil twin finding carries no differences; the report needs the attributes")
	}
	if !strings.Contains(evilTwin.Rationale, "Verify physically") {
		t.Errorf("rationale should tell the operator to verify before acting: %q", evilTwin.Rationale)
	}
}

// TestNeverInfersWiredConnectivity: whether an unknown AP is on the client's wired LAN cannot
// be known from the air, so no finding may claim it.
func TestNeverInfersWiredConnectivity(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-WIFI"))

	aps := []recon.AP{
		fleetAP(t, "a4:2b:8c:11:22:01", "CORP-WIFI", profileCisco, 100),
		fleetAP(t, "a4:2b:8c:11:22:02", "CORP-WIFI", profileCisco, 90),
		fleetAP(t, "a4:2b:8c:11:22:03", "CORP-WIFI", profileCisco, 80),
		impostorAP(t, "de:ad:be:ef:00:01", "CORP-WIFI"),
	}

	res := c.Classify(aps, nil, time.Now())
	for _, f := range res.Findings {
		text := strings.ToLower(f.Label + " " + f.Rationale)
		for _, forbidden := range []string{"wired", "plugged into", "on the lan", "connected to the network"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("finding %q claims wired connectivity, which cannot be known from the air: %q",
					f.Label, f.Rationale)
			}
		}
	}
}

// TestProtectedManagementFramesArePostureNotJustAbsence. All three 802.11w states change what
// the operator can do next, so all three are reported. "Capable" in particular is not
// protection: a client that does not negotiate it is still deauthenticatable.
func TestProtectedManagementFramesArePostureNotJustAbsence(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-WIFI"))

	withMFP := func(bssid string, state recon.MFPState) recon.AP {
		ap := fleetAP(t, bssid, "CORP-WIFI", profileCisco, 100)
		ap.Security.MFP = state
		return ap
	}

	want := map[string]string{
		"a4:2b:8c:11:22:01": LabelMFPAbsent,
		"a4:2b:8c:11:22:02": LabelMFPOptional,
		"a4:2b:8c:11:22:03": LabelMFPRequired,
	}

	res := c.Classify([]recon.AP{
		withMFP("a4:2b:8c:11:22:01", recon.MFPAbsent),
		withMFP("a4:2b:8c:11:22:02", recon.MFPCapable),
		withMFP("a4:2b:8c:11:22:03", recon.MFPRequired),
	}, nil, time.Now())

	got := map[string]string{}
	for _, f := range res.Findings {
		switch f.Label {
		case LabelMFPAbsent, LabelMFPOptional, LabelMFPRequired:
			got[f.BSSID] = f.Label
			// The label has to be readable by someone who does not already know what 802.11w
			// is, since that is most of the people who read the report.
			if !strings.Contains(f.Label, "protected management frames") {
				t.Errorf("label %q is jargon with no expansion", f.Label)
			}
		}
	}

	for bssid, label := range want {
		if got[bssid] != label {
			t.Errorf("%s: got %q, want %q", bssid, got[bssid], label)
		}
	}
}

// TestUnscopedESSIDsAreNotClustered: an impostor is defined relative to the network it
// impersonates, and WARP has no standing to judge a neighbour's access points.
func TestUnscopedESSIDsAreNotClustered(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-WIFI"))

	aps := []recon.AP{
		fleetAP(t, "a4:2b:8c:11:22:01", "NEIGHBOUR-NET", profileCisco, 100),
		fleetAP(t, "a4:2b:8c:11:22:02", "NEIGHBOUR-NET", profileCisco, 90),
		fleetAP(t, "a4:2b:8c:11:22:03", "NEIGHBOUR-NET", profileCisco, 80),
		impostorAP(t, "de:ad:be:ef:00:01", "NEIGHBOUR-NET"),
	}

	res := c.Classify(aps, nil, time.Now())
	if len(res.Analyses) != 0 {
		t.Errorf("clustering ran on an unscoped ESSID: %+v", res.Analyses)
	}
	for _, f := range res.Findings {
		if f.Label == LabelEvilTwinCandidate {
			t.Error("an evil twin candidate was raised on a neighbour's network")
		}
	}
}

// TestUnclassifiedIsTheDefault: a device with no derivable conclusion is listed with no label.
//
// Posture findings are now recorded for every network, in scope or not, so "unclassified" is what
// remains when there is genuinely nothing to conclude - here a network whose security element could
// not be read (MFP unknown, class undetermined), which is the honest "no conclusion" case.
func TestUnclassifiedIsTheDefault(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-WIFI"))

	now := time.Now()
	unknown := recon.AP{
		BSSID: mac(t, "de:ad:be:ef:00:99"), ESSID: "SomeoneElsesNetwork", Channel: 6, Freq: 2437,
		// No readable security posture: nothing to conclude, and no scope to file it under.
		Security:  recon.SecurityInfo{Class: "", MFP: recon.MFPUnknown},
		FirstSeen: now, LastSeen: now, Beacons: 50,
	}

	res := c.Classify([]recon.AP{unknown}, nil, now)

	for _, f := range res.Findings {
		if f.BSSID == unknown.BSSID.String() {
			t.Errorf("a device with no derivable posture was labelled %q; the default state is "+
				"unclassified, not 'neighbour' and not anything else", f.Label)
		}
	}
	if len(res.Unclassified) != 1 || res.Unclassified[0] != unknown.BSSID.String() {
		t.Errorf("device not listed as unclassified: %v", res.Unclassified)
	}
}

func TestKarmaResponderIsDetermined(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-WIFI"))
	pineapple := mac(t, "de:ad:be:ef:00:01")

	res := c.Classify(nil, map[recon.MAC]string{pineapple: "xKcMqRtVbNjHgFdSaPwZ"}, time.Now())

	if len(res.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.Tier != store.TierDetermined {
		t.Errorf("tier = %q; a karma responder is a yes/no active test result", f.Tier)
	}
	if f.Label != LabelKarmaResponder {
		t.Errorf("label = %q", f.Label)
	}
	if !strings.Contains(f.Rationale, "cannot exist") {
		t.Errorf("rationale should explain the probe was for an impossible network: %q", f.Rationale)
	}
}

func TestDeterminedFindingsForWeakConfiguration(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-GUEST"))
	now := time.Now()

	open := recon.AP{
		BSSID: mac(t, "a4:2b:8c:11:22:01"), ESSID: "CORP-GUEST",
		Security:  recon.SecurityInfo{Class: recon.SecOpen, MFP: recon.MFPAbsent},
		FirstSeen: now, LastSeen: now,
	}
	wps := recon.AP{
		BSSID: mac(t, "a4:2b:8c:11:22:02"), ESSID: "CORP-GUEST",
		Security: recon.SecurityInfo{
			Class: recon.SecWPAPSK, MFP: recon.MFPAbsent, WPS: true, WPSLocked: false,
		},
		FirstSeen: now, LastSeen: now,
	}
	wep := recon.AP{
		BSSID: mac(t, "a4:2b:8c:11:22:03"), ESSID: "CORP-GUEST",
		Security:  recon.SecurityInfo{Class: recon.SecWEP, MFP: recon.MFPAbsent},
		FirstSeen: now, LastSeen: now,
	}

	res := c.Classify([]recon.AP{open, wps, wep}, nil, now)

	labels := map[string]bool{}
	for _, f := range res.Findings {
		labels[f.Label] = true
		if f.Tier != store.TierDetermined {
			t.Errorf("finding %q is tier %q, want determined", f.Label, f.Tier)
		}
	}
	for _, want := range []string{LabelOpenNetwork, LabelWPSUnlocked, LabelWEP} {
		if !labels[want] {
			t.Errorf("missing determined finding %q; got %v", want, labels)
		}
	}
}

func TestMFPIsAFindingEitherWay(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-WIFI"))
	now := time.Now()

	required := recon.AP{
		BSSID: mac(t, "a4:2b:8c:11:22:01"), ESSID: "CORP-WIFI",
		Security:  recon.SecurityInfo{Class: recon.SecWPASAE, MFP: recon.MFPRequired},
		FirstSeen: now, LastSeen: now,
	}
	absent := recon.AP{
		BSSID: mac(t, "a4:2b:8c:11:22:02"), ESSID: "CORP-WIFI",
		Security:  recon.SecurityInfo{Class: recon.SecWPAPSK, MFP: recon.MFPAbsent},
		FirstSeen: now, LastSeen: now,
	}

	res := c.Classify([]recon.AP{required, absent}, nil, now)

	labels := map[string]bool{}
	for _, f := range res.Findings {
		labels[f.Label] = true
	}
	if !labels[LabelMFPRequired] {
		t.Error("MFP required was not recorded; it is good practice worth reporting")
	}
	if !labels[LabelMFPAbsent] {
		t.Error("MFP absent was not recorded; it determines whether deauth will work")
	}
}

// TestPassesAreControlsNotExposures: a correct configuration is filed under the control tier so a
// report can present it as a pass, not mixed in with the exposures. WPS locked and 802.11w required
// are the two the classifier can determine passively.
func TestPassesAreControlsNotExposures(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-WIFI"))
	now := time.Now()

	wpsLocked := recon.AP{
		BSSID: mac(t, "a4:2b:8c:11:22:01"), ESSID: "CORP-WIFI",
		Security: recon.SecurityInfo{
			Class: recon.SecWPAPSK, MFP: recon.MFPRequired, WPS: true, WPSLocked: true,
		},
		FirstSeen: now, LastSeen: now,
	}

	res := c.Classify([]recon.AP{wpsLocked}, nil, now)

	tierOf := map[string]store.Tier{}
	for _, f := range res.Findings {
		tierOf[f.Label] = f.Tier
	}
	for _, label := range []string{LabelWPSEnabled, LabelMFPRequired} {
		tier, ok := tierOf[label]
		if !ok {
			t.Errorf("pass %q was not recorded at all", label)
			continue
		}
		if tier != store.TierControl {
			t.Errorf("pass %q is tier %q, want control (it is not an exposure)", label, tier)
		}
	}
}

// TestPSKAmongEnterpriseFlaggedOnlyWhenMixed: a PSK access point sharing an ESSID with enterprise
// access points is flagged (that one BSSID, evidence tier); an all-enterprise ESSID is not.
func TestPSKAmongEnterpriseFlaggedOnlyWhenMixed(t *testing.T) {
	c := NewClassifier(Config{}, scopedOnly("CORP-WIFI"))
	now := time.Now()

	ent := func(b string) recon.AP {
		return recon.AP{BSSID: mac(t, b), ESSID: "CORP-WIFI",
			Security: recon.SecurityInfo{Class: recon.SecWPAEnterprise}}
	}
	psk := func(b string) recon.AP {
		return recon.AP{BSSID: mac(t, b), ESSID: "CORP-WIFI",
			Security: recon.SecurityInfo{Class: recon.SecWPAPSK}}
	}

	mixed := c.Classify([]recon.AP{
		ent("aa:aa:aa:aa:aa:01"), ent("aa:aa:aa:aa:aa:02"), psk("aa:aa:aa:aa:aa:03"),
	}, nil, now)
	var flagged []store.Finding
	for _, f := range mixed.Findings {
		if f.Label == LabelPSKAmongEnterprise {
			flagged = append(flagged, f)
		}
	}
	if len(flagged) != 1 || flagged[0].BSSID != "aa:aa:aa:aa:aa:03" {
		t.Fatalf("want only the PSK BSSID flagged, got %+v", flagged)
	}
	if flagged[0].Tier != store.TierEvidence {
		t.Errorf("tier = %q, want evidence (it is a population inference)", flagged[0].Tier)
	}

	uniform := c.Classify([]recon.AP{ent("bb:bb:bb:bb:bb:01"), ent("bb:bb:bb:bb:bb:02")}, nil, now)
	for _, f := range uniform.Findings {
		if f.Label == LabelPSKAmongEnterprise {
			t.Errorf("PSK-among-enterprise fired on an all-enterprise ESSID: %+v", f)
		}
	}
}

// TestManualRogueLabelIsNotClassifierDerived: the manual potential-rogue label must never be in
// ClassifierLabels, or a re-classify would wipe an operator's marks.
func TestManualRogueLabelIsNotClassifierDerived(t *testing.T) {
	for _, l := range ClassifierLabels {
		if l == LabelPotentialRogue {
			t.Fatalf("%q is in ClassifierLabels; a re-classify would wipe manual marks", l)
		}
	}
}
