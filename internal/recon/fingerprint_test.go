package recon

import (
	"strings"
	"testing"
)

var (
	ouiCisco = [3]byte{0x00, 0x40, 0x96}
	ouiAruba = [3]byte{0x00, 0x0b, 0x86}
)

// ciscoAP is the shape of a homogeneous enterprise fleet member: several vendor elements,
// full PHY capability set, standard configuration.
func ciscoAP(essid string) Fingerprint {
	ies, _ := ParseIEs(concat([][]byte{
		ssidIE(essid),
		ratesIE(0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24),
		dsIE(6),
		rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKM8021X}, rsnCapMFPC, true),
		htCapIE(0x016e),
		vhtCapIE(0x0f815932),
		vendorIE(ouiCisco, 0x01, 0x01, 0x02),
		vendorIE(ouiCisco, 0x03, 0x00),
		vendorIE(OUIMicrosoft, msSubtypeWMM, 0x01, 0x01),
	}))
	return FingerprintFrom(ies, CapESS|CapPrivacy, 100)
}

// hostapdImpostor is what an evil twin actually looks like: a laptop or Pineapple running
// hostapd, advertising almost no vendor elements and a different element order.
func hostapdImpostor(essid string) Fingerprint {
	ies, _ := ParseIEs(concat([][]byte{
		ssidIE(essid),
		ratesIE(0x82, 0x84, 0x8b, 0x96),
		dsIE(6),
		rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKM8021X}, 0, true),
		vendorIE(OUIMicrosoft, msSubtypeWMM, 0x01, 0x01),
	}))
	return FingerprintFrom(ies, CapESS|CapPrivacy, 100)
}

func TestIdenticalFingerprintsScoreOne(t *testing.T) {
	a := ciscoAP("CORP-WIFI")
	b := ciscoAP("CORP-WIFI")

	score, diffs := Similarity(a, b)
	if score != 1.0 {
		t.Fatalf("identical fingerprints scored %.3f, want 1.0 (diffs: %v)", score, diffs)
	}
	if len(diffs) != 0 {
		t.Errorf("identical fingerprints reported differences: %v", diffs)
	}
	if a.Hash() != b.Hash() {
		t.Error("identical fingerprints hashed differently")
	}
}

// TestImpostorIsAnOutlier is the core rogue-detection signal.
func TestImpostorIsAnOutlier(t *testing.T) {
	legit := ciscoAP("CORP-WIFI")
	fake := hostapdImpostor("CORP-WIFI")

	score, diffs := Similarity(legit, fake)
	if score > 0.6 {
		t.Fatalf("impostor scored %.3f against the fleet fingerprint; too similar to flag", score)
	}
	if len(diffs) == 0 {
		t.Fatal("no differences reported for an obvious impostor")
	}

	// The differences must be specific enough to write into a report. "Outlier score 0.42"
	// is not a defensible sentence; "advertises no Cisco vendor elements" is.
	var attrs []string
	for _, d := range diffs {
		attrs = append(attrs, d.Attribute)
	}
	joined := strings.Join(attrs, ",")
	for _, want := range []string{"vendor_ies", "ie_order"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected a %q difference, got %v", want, attrs)
		}
	}

	for _, d := range diffs {
		if d.Attribute == "vendor_ies" {
			if !strings.Contains(d.Expected, "004096") {
				t.Errorf("expected side should list the Cisco elements, got %q", d.Expected)
			}
			if strings.Contains(d.Observed, "004096") {
				t.Errorf("observed side should not list Cisco elements, got %q", d.Observed)
			}
		}
	}
}

// TestMixedVendorEnvironmentDoesNotFalsePositive is the requirement the brief is most
// insistent about. A genuinely mixed environment must not manufacture evil-twin candidates:
// a false positive sends someone to tear down a legitimate AP.
func TestMixedVendorEnvironmentDoesNotFalsePositive(t *testing.T) {
	// Two APs from different vendors, both legitimately on their own networks. They are very
	// different — which is correct and expected — so what this asserts is that *difference
	// alone* is not the finding. Clustering must require a shared ESSID and a dominant
	// cluster before anything is flagged; that logic lives in the rogue package and is tested
	// there. Here we only assert the metric behaves monotonically and does not saturate.
	cisco := ciscoAP("CORP-WIFI")

	arubaIEs, _ := ParseIEs(concat([][]byte{
		ssidIE("TENANT-NET"),
		ratesIE(0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24),
		dsIE(11),
		rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKM8021X}, rsnCapMFPC, true),
		htCapIE(0x016e),
		vhtCapIE(0x0f815932),
		vendorIE(ouiAruba, 0x01, 0x01),
		vendorIE(OUIMicrosoft, msSubtypeWMM, 0x01, 0x01),
	}))
	aruba := FingerprintFrom(arubaIEs, CapESS|CapPrivacy, 100)

	score, _ := Similarity(cisco, aruba)

	// Different vendors score below identical but well above an impostor: they share rates,
	// PHY capabilities, beacon interval and RSN configuration.
	if score >= 1.0 {
		t.Errorf("two different vendors scored %.3f; the metric is saturating", score)
	}
	impostorScore, _ := Similarity(cisco, hostapdImpostor("CORP-WIFI"))
	if score <= impostorScore {
		t.Errorf("a legitimate different-vendor AP (%.3f) scored no better than an impostor (%.3f); "+
			"the metric cannot separate them", score, impostorScore)
	}
}

// TestSameVendorDifferentModelStaysClose: a fleet is rarely perfectly uniform, and a
// second AP model from the same vendor must not be flagged.
func TestSameVendorDifferentModelStaysClose(t *testing.T) {
	base := ciscoAP("CORP-WIFI")

	// Same vendor elements and configuration, slightly different PHY capabilities.
	variantIEs, _ := ParseIEs(concat([][]byte{
		ssidIE("CORP-WIFI"),
		ratesIE(0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24),
		dsIE(6),
		rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKM8021X}, rsnCapMFPC, true),
		htCapIE(0x016e),
		vhtCapIE(0x0f814032), // different VHT capability bits
		vendorIE(ouiCisco, 0x01, 0x01, 0x02),
		vendorIE(ouiCisco, 0x03, 0x00),
		vendorIE(OUIMicrosoft, msSubtypeWMM, 0x01, 0x01),
	}))
	variant := FingerprintFrom(variantIEs, CapESS|CapPrivacy, 100)

	score, diffs := Similarity(base, variant)
	if score < 0.9 {
		t.Errorf("same-vendor variant scored %.3f; too low, this would be a false positive.\ndiffs: %v",
			score, diffs)
	}
}

// TestElementOrderMatters: two APs advertising exactly the same elements in different orders
// are different firmware, and the metric must notice.
func TestElementOrderMatters(t *testing.T) {
	forward, _ := ParseIEs(concat([][]byte{
		ssidIE("N"), ratesIE(0x82, 0x84), dsIE(6), htCapIE(0x016e),
		vendorIE(ouiCisco, 0x01), vendorIE(OUIMicrosoft, msSubtypeWMM),
	}))
	shuffled, _ := ParseIEs(concat([][]byte{
		ssidIE("N"), dsIE(6), ratesIE(0x82, 0x84),
		vendorIE(OUIMicrosoft, msSubtypeWMM), vendorIE(ouiCisco, 0x01), htCapIE(0x016e),
	}))

	a := FingerprintFrom(forward, CapESS, 100)
	b := FingerprintFrom(shuffled, CapESS, 100)

	if a.Hash() == b.Hash() {
		t.Fatal("reordered elements produced the same hash; order is not being captured")
	}
	score, diffs := Similarity(a, b)
	if score >= 1.0 {
		t.Errorf("reordered elements scored %.3f, want < 1.0", score)
	}

	var found bool
	for _, d := range diffs {
		if d.Attribute == "ie_order" {
			found = true
		}
	}
	if !found {
		t.Errorf("no ie_order difference reported: %v", diffs)
	}

	// The vendor element *set* is unchanged, so that component must not report a difference.
	for _, d := range diffs {
		if d.Attribute == "vendor_ies" {
			t.Errorf("vendor set is identical but was reported as differing: %+v", d)
		}
	}
}

func TestBeaconIntervalDifference(t *testing.T) {
	ies, _ := ParseIEs(concat([][]byte{ssidIE("N"), ratesIE(0x82)}))
	a := FingerprintFrom(ies, CapESS, 100)
	b := FingerprintFrom(ies, CapESS, 250)

	score, diffs := Similarity(a, b)
	if score >= 1.0 {
		t.Error("a differing beacon interval was not penalised")
	}
	var found bool
	for _, d := range diffs {
		if d.Attribute == "beacon_interval" {
			found = true
			if !strings.Contains(d.Expected, "100") || !strings.Contains(d.Observed, "250") {
				t.Errorf("beacon interval difference is not reportable: %+v", d)
			}
		}
	}
	if !found {
		t.Errorf("no beacon_interval difference reported: %v", diffs)
	}
}

func TestEmptyFingerprint(t *testing.T) {
	var empty Fingerprint
	if !empty.Empty() {
		t.Error("a zero fingerprint should report Empty")
	}
	if ciscoAP("N").Empty() {
		t.Error("a populated fingerprint reported Empty")
	}

	// Two empty fingerprints are trivially identical; clustering must skip them rather than
	// treat that as evidence of anything.
	score, _ := Similarity(empty, Fingerprint{})
	if score != 1.0 {
		t.Errorf("two empty fingerprints scored %.3f", score)
	}
}

func TestSimilarityIsSymmetric(t *testing.T) {
	a := ciscoAP("CORP-WIFI")
	b := hostapdImpostor("CORP-WIFI")

	ab, _ := Similarity(a, b)
	ba, _ := Similarity(b, a)
	if ab != ba {
		t.Errorf("Similarity is not symmetric: a→b %.4f, b→a %.4f", ab, ba)
	}
}

func TestJaccard(t *testing.T) {
	tests := []struct {
		a, b []string
		want float64
	}{
		{nil, nil, 1.0},
		{[]string{"x"}, []string{"x"}, 1.0},
		{[]string{"x"}, nil, 0.0},
		{[]string{"x", "y"}, []string{"x"}, 0.5},
		{[]string{"x", "y"}, []string{"y", "x"}, 1.0}, // order-insensitive by design
	}
	for _, tc := range tests {
		if got := jaccard(tc.a, tc.b); got != tc.want {
			t.Errorf("jaccard(%v, %v) = %.3f, want %.3f", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestSequenceSimilarity(t *testing.T) {
	tests := []struct {
		name string
		a, b []string
		want float64
	}{
		{"identical", []string{"0", "1", "3"}, []string{"0", "1", "3"}, 1.0},
		{"both empty", nil, nil, 1.0},
		{"one empty", []string{"0"}, nil, 0.0},
		{"one substitution", []string{"0", "1", "3"}, []string{"0", "2", "3"}, 2.0 / 3.0},
		{"one insertion", []string{"0", "1"}, []string{"0", "1", "3"}, 2.0 / 3.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sequenceSimilarity(tc.a, tc.b)
			if diff := got - tc.want; diff > 1e-9 || diff < -1e-9 {
				t.Errorf("got %.4f, want %.4f", got, tc.want)
			}
		})
	}
}

func TestFormatRatesMarksBasic(t *testing.T) {
	// 0x82 = basic 1 Mbps, 0x0c = non-basic 6 Mbps.
	got := formatRates([]byte{0x82, 0x0c})
	if got != "1*,6" {
		t.Errorf("formatRates = %q, want %q", got, "1*,6")
	}
	if formatRates(nil) != "none" {
		t.Errorf("empty rate set should render as 'none'")
	}
}
