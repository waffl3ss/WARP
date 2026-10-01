package recon

import (
	"strings"
	"testing"
)

// TestClassifySecurity is the table the report depends on. Misclassifying enterprise as PSK
// sends the operator down the wrong attack path for a whole engagement.
func TestClassifySecurity(t *testing.T) {
	tests := []struct {
		name       string
		capability uint16
		ies        [][]byte
		want       Security
		wantMFP    MFPState
	}{
		{
			name:       "open network",
			capability: CapESS,
			ies:        [][]byte{ssidIE("GUEST-OPEN"), ratesIE(0x82, 0x84)},
			want:       SecOpen,
			wantMFP:    MFPAbsent,
		},
		{
			// Privacy set with no key-management element is the only reliable WEP signal:
			// WPA sets the same capability bit.
			name:       "WEP: privacy with no RSN or WPA element",
			capability: CapESS | CapPrivacy,
			ies:        [][]byte{ssidIE("OLD-NET"), ratesIE(0x82)},
			want:       SecWEP,
			wantMFP:    MFPAbsent,
		},
		{
			name:       "WPA2-PSK",
			capability: CapESS | CapPrivacy,
			ies: [][]byte{ssidIE("CORP-WIFI"),
				rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKMPSK}, 0, true)},
			want:    SecWPAPSK,
			wantMFP: MFPAbsent,
		},
		{
			name:       "WPA2-Enterprise",
			capability: CapESS | CapPrivacy,
			ies: [][]byte{ssidIE("CORP-8021X"),
				rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKM8021X}, 0, true)},
			want:    SecWPAEnterprise,
			wantMFP: MFPAbsent,
		},
		{
			name:       "WPA3-SAE with MFP required",
			capability: CapESS | CapPrivacy,
			ies: [][]byte{ssidIE("CORP-WPA3"),
				rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKMSAE}, rsnCapMFPR|rsnCapMFPC, true)},
			want:    SecWPASAE,
			wantMFP: MFPRequired,
		},
		{
			name:       "OWE",
			capability: CapESS | CapPrivacy,
			ies: [][]byte{ssidIE("OPEN-ENHANCED"),
				rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKMOWE}, rsnCapMFPR|rsnCapMFPC, true)},
			want:    SecOWE,
			wantMFP: MFPRequired,
		},
		{
			name:       "WPA3-Enterprise 192-bit",
			capability: CapESS | CapPrivacy,
			ies: [][]byte{ssidIE("CORP-SUITEB"),
				rsnIE(CipherGCMP256, []uint8{CipherGCMP256}, []uint8{AKM8021XSuiteB192}, rsnCapMFPR|rsnCapMFPC, true)},
			want:    SecWPA3Ent192,
			wantMFP: MFPRequired,
		},
		{
			name:       "WPA1 only",
			capability: CapESS | CapPrivacy,
			ies: [][]byte{ssidIE("LEGACY"),
				wpaIE(CipherTKIP, []uint8{CipherTKIP}, []uint8{AKMPSK})},
			want:    SecWPAPSK,
			wantMFP: MFPAbsent,
		},
		{
			name:       "MFP capable but not required",
			capability: CapESS | CapPrivacy,
			ies: [][]byte{ssidIE("CORP-WIFI"),
				rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKMPSK}, rsnCapMFPC, true)},
			want:    SecWPAPSK,
			wantMFP: MFPCapable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ies, err := ParseIEs(concat(tc.ies))
			if err != nil {
				t.Fatalf("ParseIEs: %v", err)
			}
			got := ClassifySecurity(ies, tc.capability)
			if got.Class != tc.want {
				t.Errorf("Class = %q, want %q (%s)", got.Class, tc.want, got.Describe())
			}
			if got.MFP != tc.wantMFP {
				t.Errorf("MFP = %s, want %s", got.MFP, tc.wantMFP)
			}
		})
	}
}

// TestMFPDrivesDeauthViability: 802.11w required means deauthentication will be ignored, and
// transmitting anyway wastes airtime at a client site.
func TestMFPDrivesDeauthViability(t *testing.T) {
	tests := []struct {
		state MFPState
		want  bool
	}{
		{MFPAbsent, true},
		{MFPCapable, true}, // clients that did not negotiate it remain deauthenticatable
		{MFPRequired, false},
		{MFPUnknown, true},
	}
	for _, tc := range tests {
		if got := tc.state.DeauthViable(); got != tc.want {
			t.Errorf("%s.DeauthViable() = %v, want %v", tc.state, got, tc.want)
		}
	}
}

// TestTransitionModeIsFlagged covers WPA2/WPA3 mixed mode, where a client can be pushed onto
// the weaker AKM. That is a finding, and it must not be hidden behind the WPA3 label.
func TestTransitionModeIsFlagged(t *testing.T) {
	ies, _ := ParseIEs(concat([][]byte{
		ssidIE("CORP-WPA3"),
		rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKMSAE, AKMPSK}, rsnCapMFPC, true),
	}))

	got := ClassifySecurity(ies, CapESS|CapPrivacy)
	if got.Class != SecWPASAE {
		t.Errorf("Class = %q, want %q", got.Class, SecWPASAE)
	}
	if !got.Transition {
		t.Error("WPA2/WPA3 transition mode was not flagged; the PSK path is still attackable")
	}
	if !strings.Contains(got.Describe(), "transition") {
		t.Errorf("Describe() should mention transition mode: %q", got.Describe())
	}
}

func TestWPAAndRSNTogetherIsTransition(t *testing.T) {
	ies, _ := ParseIEs(concat([][]byte{
		ssidIE("MIXED"),
		wpaIE(CipherTKIP, []uint8{CipherTKIP}, []uint8{AKMPSK}),
		rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKMPSK}, 0, true),
	}))
	got := ClassifySecurity(ies, CapESS|CapPrivacy)
	if !got.Transition {
		t.Error("WPA1+WPA2 mixed mode was not flagged as a downgrade case")
	}
}

func TestWPSDetection(t *testing.T) {
	unlocked, _ := ParseIEs(concat([][]byte{ssidIE("N"), wpsIE(false)}))
	got := ClassifySecurity(unlocked, CapESS|CapPrivacy)
	if !got.WPS {
		t.Fatal("WPS element not detected")
	}
	if got.WPSLocked {
		t.Error("unlocked WPS reported as locked")
	}

	locked, _ := ParseIEs(concat([][]byte{ssidIE("N"), wpsIE(true)}))
	got = ClassifySecurity(locked, CapESS|CapPrivacy)
	if !got.WPS || !got.WPSLocked {
		t.Errorf("locked WPS not detected: wps=%v locked=%v", got.WPS, got.WPSLocked)
	}
}

// TestRSNWithoutCapabilities: a beacon that omits the optional capabilities field is legal.
// Refusing to parse it would drop the AP entirely.
func TestRSNWithoutCapabilities(t *testing.T) {
	ies, _ := ParseIEs(concat([][]byte{
		ssidIE("CORP-WIFI"),
		rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKMPSK}, 0, false),
	}))
	got := ClassifySecurity(ies, CapESS|CapPrivacy)
	if got.Class != SecWPAPSK {
		t.Errorf("Class = %q, want %q", got.Class, SecWPAPSK)
	}
	if got.MFP != MFPAbsent {
		t.Errorf("MFP = %s, want absent when the capabilities field is not present", got.MFP)
	}
}

// TestTruncatedRSNDoesNotPanic feeds every prefix of a valid element. Real captures are
// clipped mid-element and the parser must degrade rather than fail.
func TestTruncatedRSNDoesNotPanic(t *testing.T) {
	full := rsnIE(CipherCCMP128, []uint8{CipherCCMP128, CipherTKIP}, []uint8{AKM8021X, AKMPSK}, rsnCapMFPC, true)
	body := full[2:] // strip the element header

	for n := 0; n <= len(body); n++ {
		info, err := ParseRSN(body[:n])
		if n < 2 {
			if err == nil {
				t.Errorf("prefix of %d bytes should not parse", n)
			}
			continue
		}
		if err != nil {
			t.Errorf("prefix of %d bytes: %v", n, err)
			continue
		}
		// Whatever parsed must be self-consistent: no partial suite may be reported.
		if info == nil {
			t.Errorf("prefix of %d bytes returned nil without an error", n)
		}
	}
}

func TestRSNPMKIDExtraction(t *testing.T) {
	pmkid := make([]byte, 16)
	for i := range pmkid {
		pmkid[i] = byte(i + 1)
	}

	ies, err := ParseIEs(rsnIEWithPMKID(pmkid))
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	got := RSNPMKIDs(ies)
	if len(got) != 1 {
		t.Fatalf("got %d PMKIDs, want 1", len(got))
	}
	if string(got[0]) != string(pmkid) {
		t.Errorf("PMKID = % x, want % x", got[0], pmkid)
	}

	// Duplicates are collapsed.
	ies, _ = ParseIEs(rsnIEWithPMKID(pmkid, pmkid))
	if got := RSNPMKIDs(ies); len(got) != 1 {
		t.Errorf("duplicate PMKIDs were not collapsed: got %d", len(got))
	}
}

func TestSuiteNames(t *testing.T) {
	ies, _ := ParseIEs(rsnIE(CipherCCMP128, []uint8{CipherCCMP128, CipherTKIP}, []uint8{AKM8021X}, 0, true))
	info := extractRSN(ies)
	if info == nil {
		t.Fatal("RSN element not found")
	}

	ciphers := strings.Join(info.CipherNames(), ",")
	if ciphers != "CCMP-128,TKIP" {
		t.Errorf("CipherNames = %q", ciphers)
	}
	if akms := strings.Join(info.AKMNames(), ","); akms != "802.1X" {
		t.Errorf("AKMNames = %q", akms)
	}
	if !info.Enterprise() {
		t.Error("Enterprise() should be true for the 802.1X AKM")
	}
	if info.PSKBased() {
		t.Error("PSKBased() should be false for the 802.1X AKM")
	}
}

// TestVendorSuiteIsNotMisreadAsStandard: a genuinely vendor-specific selector must not be
// interpreted against the IEEE table, which would report a misleading standard name.
func TestVendorSuiteIsNotMisreadAsStandard(t *testing.T) {
	cisco := Suite{OUI: [3]byte{0x00, 0x40, 0x96}, Type: 1}
	rsn := &RSNInfo{AKM: []Suite{cisco, {OUI: OUIIEEE, Type: AKM8021X}}}

	names := rsn.AKMNames()
	if len(names) != 2 {
		t.Fatalf("got %d AKM names, want 2", len(names))
	}
	if !strings.Contains(names[0], "00:40:96") {
		t.Errorf("vendor AKM rendered as %q; it should name the OUI", names[0])
	}
	if names[1] != "802.1X" {
		t.Errorf("standard AKM rendered as %q, want 802.1X", names[1])
	}
	// With only the vendor selector present, the IEEE type table must not match it. (The
	// fixture above deliberately also carries a real IEEE type-1 selector, so HasAKM there
	// would match for the right reason.)
	vendorOnly := &RSNInfo{AKM: []Suite{cisco}}
	if vendorOnly.HasAKM(AKM8021X) {
		t.Error("a Cisco selector of type 1 was matched against the IEEE 802.1X type")
	}
	if vendorOnly.Enterprise() {
		t.Error("a vendor selector was classified as 802.1X enterprise")
	}
}

// TestWPA1SelectorsUseMicrosoftOUI is the regression test for classifying every WPA1 network
// as unknown: WPA1 defines its selectors under 00:50:F2, not the IEEE 00:0F:AC.
func TestWPA1SelectorsUseMicrosoftOUI(t *testing.T) {
	ies, err := ParseIEs(wpaIE(CipherTKIP, []uint8{CipherTKIP}, []uint8{AKMPSK}))
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	wpa := extractWPA(ies)
	if wpa == nil {
		t.Fatal("WPA1 element not found")
	}
	if !wpa.WPA1 {
		t.Error("WPA1 flag not set")
	}
	if !wpa.PSKBased() {
		t.Error("WPA1 PSK AKM not recognised — selectors are under 00:50:F2")
	}
	if !wpa.HasCipher(CipherTKIP) {
		t.Error("WPA1 TKIP cipher not recognised")
	}
	if names := wpa.AKMNames(); len(names) != 1 || names[0] != "PSK" {
		t.Errorf("AKMNames = %v, want [PSK]", names)
	}
}

func concat(parts [][]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
