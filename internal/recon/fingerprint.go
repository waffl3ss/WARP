package recon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Fingerprint is the observable radio signature of an access point.
//
// Its purpose is population clustering: no client AP inventory exists, so the baseline is
// derived by clustering every BSSID broadcasting a given scoped ESSID and treating the
// dominant cluster as the client's infrastructure. Client fleets are homogeneous - same
// vendor, same firmware, same configuration - so an impostor falls outside the cluster it is
// pretending to belong to. That is a stronger signal than an inventory lookup, because it
// also catches an impostor that spoofed a legitimate BSSID.
//
// Everything here is *observed*, never concluded. The conclusion lives in the rogue package
// and is stored in a separate column.
type Fingerprint struct {
	// VendorIEs is the sorted set of vendor element keys (OUI:subtype).
	//
	// The strongest single component. A Cisco AP advertises Cisco elements, an Aruba AP
	// advertises Aruba ones, and a laptop running hostapd advertises almost none.
	VendorIEs []string `json:"vendor_ies,omitempty"`

	// IEOrder is the element ID sequence exactly as the AP emitted it. Firmware emits
	// elements in a fixed order, so the sequence is characteristic even when every
	// individual element matches.
	IEOrder []string `json:"ie_order,omitempty"`

	// BeaconInterval in TU. Almost always the 100 TU default, so a deviation is loud.
	BeaconInterval uint16 `json:"beacon_interval,omitempty"`

	// Rates is the supported and extended rate set, with the basic-rate flag preserved:
	// which rates an AP marks basic is a configuration choice.
	Rates []byte `json:"rates,omitempty"`

	// Capability is the raw capability information field.
	Capability uint16 `json:"capability"`

	// RSNCaps is the RSN capabilities field.
	RSNCaps    uint16 `json:"rsn_caps,omitempty"`
	HasRSNCaps bool   `json:"has_rsn_caps"`

	// HT/VHT/HE capability layout.
	HTCaps  uint16 `json:"ht_caps,omitempty"`
	HasHT   bool   `json:"has_ht"`
	VHTCaps uint32 `json:"vht_caps,omitempty"`
	HasVHT  bool   `json:"has_vht"`
	HasHE   bool   `json:"has_he"`

	// ExtCaps is the extended capabilities element, which encodes a long tail of
	// firmware-specific feature flags.
	ExtCaps []byte `json:"ext_caps,omitempty"`
}

// FingerprintFrom builds a fingerprint from a beacon or probe response.
func FingerprintFrom(ies IEs, capability, beaconInterval uint16) Fingerprint {
	fp := Fingerprint{
		BeaconInterval: beaconInterval,
		Capability:     capability,
		IEOrder:        ies.IDs(),
		Rates:          ies.SupportedRates(),
	}

	for _, v := range ies.VendorIEs() {
		fp.VendorIEs = append(fp.VendorIEs, v.Key())
	}
	sort.Strings(fp.VendorIEs)

	if ht, ok := ies.HTCapabilities(); ok {
		fp.HTCaps, fp.HasHT = ht, true
	}
	if vht, ok := ies.VHTCapabilities(); ok {
		fp.VHTCaps, fp.HasVHT = vht, true
	}
	fp.HasHE = ies.HasHE()

	if rsn := extractRSN(ies); rsn != nil && rsn.HasCaps {
		fp.RSNCaps, fp.HasRSNCaps = rsn.Capabilities, true
	}
	if ie, ok := ies.Find(IEExtendedCapabilities); ok {
		fp.ExtCaps = append([]byte(nil), ie.Data...)
	}

	return fp
}

// Hash is a stable identifier for exactly this fingerprint, for cheap grouping of identical
// APs before the more expensive similarity comparison runs.
func (f Fingerprint) Hash() string {
	h := sha256.New()
	fmt.Fprintf(h, "v=%s|o=%s|bi=%d|r=%x|cap=%04x|rsn=%v:%04x|ht=%v:%04x|vht=%v:%08x|he=%v|ext=%x",
		strings.Join(f.VendorIEs, ","), strings.Join(f.IEOrder, ","),
		f.BeaconInterval, f.Rates, f.Capability,
		f.HasRSNCaps, f.RSNCaps, f.HasHT, f.HTCaps, f.HasVHT, f.VHTCaps, f.HasHE, f.ExtCaps)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Empty reports whether the fingerprint carries no usable signal, which happens when only a
// truncated or heavily minimal frame was seen. Clustering must skip these rather than treat
// them as outliers.
func (f Fingerprint) Empty() bool {
	return len(f.VendorIEs) == 0 && len(f.IEOrder) == 0 && len(f.Rates) == 0 && !f.HasHT && !f.HasVHT
}

// Attribute weights for the similarity metric. They sum to 1.0.
//
// Vendor elements and element order dominate because they reflect firmware identity, which an
// impostor cannot easily copy without running the same firmware. Beacon interval and rates
// are cheap for an impostor to match, so they contribute less on their own but still catch
// the careless case.
const (
	weightVendorIEs = 0.30
	weightIEOrder   = 0.25
	weightRates     = 0.10
	weightBeaconInt = 0.10
	weightRSNCaps   = 0.10
	weightPHYCaps   = 0.15
)

// Difference is one attribute on which two fingerprints disagree.
//
// These are attached to a finding so the report writes itself: "this BSSID advertises no
// vendor elements where every other AP on this ESSID advertises three Cisco elements" is a
// defensible sentence; "outlier score 0.42" is not.
type Difference struct {
	Attribute string `json:"attribute"`
	Expected  string `json:"expected"`
	Observed  string `json:"observed"`
}

func (d Difference) String() string {
	return fmt.Sprintf("%s: expected %s, observed %s", d.Attribute, d.Expected, d.Observed)
}

// Similarity scores two fingerprints in [0,1] and reports the attributes that differ.
//
// 1.0 is identical. The differences are returned regardless of the score so a caller can show
// the evidence whether or not it crossed the threshold.
func Similarity(a, b Fingerprint) (float64, []Difference) {
	var score float64
	var diffs []Difference

	// Vendor element set: Jaccard index.
	vs := jaccard(a.VendorIEs, b.VendorIEs)
	score += weightVendorIEs * vs
	if vs < 1.0 {
		diffs = append(diffs, Difference{
			Attribute: "vendor_ies",
			Expected:  describeSet(a.VendorIEs),
			Observed:  describeSet(b.VendorIEs),
		})
	}

	// Element order: normalised edit distance over the ID sequence.
	os := sequenceSimilarity(a.IEOrder, b.IEOrder)
	score += weightIEOrder * os
	if os < 1.0 {
		diffs = append(diffs, Difference{
			Attribute: "ie_order",
			Expected:  strings.Join(a.IEOrder, ","),
			Observed:  strings.Join(b.IEOrder, ","),
		})
	}

	// Rate set: exact match.
	if string(a.Rates) == string(b.Rates) {
		score += weightRates
	} else {
		diffs = append(diffs, Difference{
			Attribute: "rates",
			Expected:  formatRates(a.Rates),
			Observed:  formatRates(b.Rates),
		})
	}

	// Beacon interval: exact match.
	if a.BeaconInterval == b.BeaconInterval {
		score += weightBeaconInt
	} else {
		diffs = append(diffs, Difference{
			Attribute: "beacon_interval",
			Expected:  fmt.Sprintf("%d TU", a.BeaconInterval),
			Observed:  fmt.Sprintf("%d TU", b.BeaconInterval),
		})
	}

	// RSN capabilities: exact match, including whether the field is present at all.
	if a.HasRSNCaps == b.HasRSNCaps && a.RSNCaps == b.RSNCaps {
		score += weightRSNCaps
	} else {
		diffs = append(diffs, Difference{
			Attribute: "rsn_caps",
			Expected:  formatCaps(a.HasRSNCaps, uint32(a.RSNCaps)),
			Observed:  formatCaps(b.HasRSNCaps, uint32(b.RSNCaps)),
		})
	}

	// PHY capability layout: HT, VHT and HE together.
	phy := 0.0
	if a.HasHT == b.HasHT && a.HTCaps == b.HTCaps {
		phy += 1.0 / 3.0
	} else {
		diffs = append(diffs, Difference{
			Attribute: "ht_caps",
			Expected:  formatCaps(a.HasHT, uint32(a.HTCaps)),
			Observed:  formatCaps(b.HasHT, uint32(b.HTCaps)),
		})
	}
	if a.HasVHT == b.HasVHT && a.VHTCaps == b.VHTCaps {
		phy += 1.0 / 3.0
	} else {
		diffs = append(diffs, Difference{
			Attribute: "vht_caps",
			Expected:  formatCaps(a.HasVHT, a.VHTCaps),
			Observed:  formatCaps(b.HasVHT, b.VHTCaps),
		})
	}
	if a.HasHE == b.HasHE {
		phy += 1.0 / 3.0
	} else {
		diffs = append(diffs, Difference{
			Attribute: "he",
			Expected:  fmt.Sprintf("%v", a.HasHE),
			Observed:  fmt.Sprintf("%v", b.HasHE),
		})
	}
	score += weightPHYCaps * phy

	// Floating-point accumulation can land a hair above 1.0 on identical inputs.
	if score > 1.0 {
		score = 1.0
	}
	return score, diffs
}

// jaccard is the intersection-over-union of two string sets. Two empty sets are identical.
func jaccard(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	set := make(map[string]int, len(a)+len(b))
	for _, s := range a {
		set[s] |= 1
	}
	for _, s := range b {
		set[s] |= 2
	}

	var inter, union int
	for _, v := range set {
		union++
		if v == 3 {
			inter++
		}
	}
	if union == 0 {
		return 1.0
	}
	return float64(inter) / float64(union)
}

// sequenceSimilarity is 1 minus the normalised Levenshtein distance between two sequences.
//
// Edit distance rather than set comparison because *order* is the signal: two APs can
// advertise exactly the same elements in different orders and be different firmware.
func sequenceSimilarity(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	longest := len(a)
	if len(b) > longest {
		longest = len(b)
	}
	if longest == 0 {
		return 1.0
	}

	// Two rolling rows rather than a full matrix: sequences are short, but this is called
	// pairwise across every BSSID on an ESSID.
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}

	dist := prev[len(b)]
	return 1.0 - float64(dist)/float64(longest)
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func describeSet(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ",")
}

func formatCaps(present bool, v uint32) string {
	if !present {
		return "absent"
	}
	return fmt.Sprintf("%#x", v)
}

// formatRates renders a rate set in Mbps, marking basic rates with a trailing asterisk the
// way `iw` does.
func formatRates(rates []byte) string {
	if len(rates) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(rates))
	for _, r := range rates {
		basic := r&0x80 != 0
		mbps := float64(r&0x7f) / 2
		s := strings.TrimSuffix(fmt.Sprintf("%.1f", mbps), ".0")
		if basic {
			s += "*"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}
