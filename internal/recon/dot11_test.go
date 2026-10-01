package recon

import (
	"errors"
	"testing"
)

func TestParseBeacon(t *testing.T) {
	bssid := mac("a4:2b:8c:11:22:33")
	raw := buildBeacon(beaconOpts{
		bssid:      bssid,
		capability: CapESS | CapPrivacy,
		ies:        [][]byte{ssidIE("CORP-WIFI"), ratesIE(0x82, 0x84), dsIE(6)},
	})

	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if f.Type != TypeManagement || f.Subtype != SubtypeBeacon {
		t.Fatalf("type/subtype = %v/%v", f.Type, f.Subtype)
	}
	if got, ok := f.BSSID(); !ok || got != bssid {
		t.Errorf("BSSID = %v (ok=%v), want %v", got, ok, bssid)
	}
	if f.HeaderLen != 24 {
		t.Errorf("HeaderLen = %d, want 24", f.HeaderLen)
	}

	cap, ok := f.Capability()
	if !ok || cap&CapPrivacy == 0 {
		t.Errorf("Capability = %#x (ok=%v), privacy bit missing", cap, ok)
	}
	if bi, ok := f.BeaconInterval(); !ok || bi != 100 {
		t.Errorf("BeaconInterval = %d (ok=%v), want 100", bi, ok)
	}

	_, ies, ok := f.ManagementBody()
	if !ok {
		t.Fatal("ManagementBody returned false for a beacon")
	}
	parsed, err := ParseIEs(ies)
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	if essid, ok := parsed.SSID(); !ok || essid != "CORP-WIFI" {
		t.Errorf("SSID = %q (ok=%v)", essid, ok)
	}
	if ch, ok := parsed.Channel(); !ok || ch != 6 {
		t.Errorf("Channel = %d (ok=%v), want 6", ch, ok)
	}
}

// TestBSSIDDependsOnDSBits is the correctness case that matters most: reading the wrong
// address invents BSSIDs that were never on the air, which then appear in the report as
// unknown devices in the client's footprint.
func TestBSSIDDependsOnDSBits(t *testing.T) {
	ap := mac("a4:2b:8c:11:22:33")
	sta := mac("de:ad:be:ef:00:01")
	other := mac("11:22:33:44:55:66")

	tests := []struct {
		name          string
		toDS, fromDS  bool
		a1, a2, a3    MAC
		wantBSSID     MAC
		wantOK        bool
		wantStation   MAC
		wantStationOK bool
	}{
		{
			name: "to AP (toDS)", toDS: true, fromDS: false,
			a1: ap, a2: sta, a3: other,
			wantBSSID: ap, wantOK: true, wantStation: sta, wantStationOK: true,
		},
		{
			name: "from AP (fromDS)", toDS: false, fromDS: true,
			a1: sta, a2: ap, a3: other,
			wantBSSID: ap, wantOK: true, wantStation: sta, wantStationOK: true,
		},
		{
			name: "IBSS (neither)", toDS: false, fromDS: false,
			a1: sta, a2: other, a3: ap,
			wantBSSID: ap, wantOK: true, wantStationOK: false,
		},
		{
			// WDS has no single BSSID, and inventing one from Addr1 would be a fabrication.
			name: "WDS (both)", toDS: true, fromDS: true,
			a1: ap, a2: other, a3: sta,
			wantOK: false, wantStationOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildDataFrame(tc.toDS, tc.fromDS, tc.a1, tc.a2, tc.a3)
			if tc.toDS && tc.fromDS {
				raw = append(raw[:24], append(other[:], raw[24:]...)...) // fourth address
			}
			f, err := ParseFrame(raw)
			if err != nil {
				t.Fatalf("ParseFrame: %v", err)
			}

			got, ok := f.BSSID()
			if ok != tc.wantOK {
				t.Fatalf("BSSID ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.wantBSSID {
				t.Errorf("BSSID = %v, want %v", got, tc.wantBSSID)
			}

			sta, ok := f.StationAddr()
			if ok != tc.wantStationOK {
				t.Fatalf("StationAddr ok = %v, want %v", ok, tc.wantStationOK)
			}
			if ok && sta != tc.wantStation {
				t.Errorf("StationAddr = %v, want %v", sta, tc.wantStation)
			}
		})
	}
}

// TestBroadcastIsNotAStation: a beacon is addressed to broadcast, and recording that as a
// client would put ff:ff:ff:ff:ff:ff in the device inventory.
func TestBroadcastIsNotAStation(t *testing.T) {
	raw := buildBeacon(beaconOpts{bssid: mac("a4:2b:8c:11:22:33"), ies: [][]byte{ssidIE("N")}})
	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if sta, ok := f.StationAddr(); ok {
		t.Errorf("a beacon yielded a station address: %v", sta)
	}
}

func TestQoSDataHeaderLength(t *testing.T) {
	ap := mac("a4:2b:8c:11:22:33")
	sta := mac("de:ad:be:ef:00:01")

	raw := buildDataFrame(true, false, ap, sta, ap)
	raw[0] = 0x88 // QoS data subtype
	// Splice the two-byte QoS control field in after the sequence control field.
	raw = append(raw[:24], append([]byte{0x06, 0x00}, raw[24:]...)...)

	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if !f.HasQoS {
		t.Fatal("QoS control field not detected")
	}
	if f.HeaderLen != 26 {
		t.Errorf("HeaderLen = %d, want 26 for QoS data", f.HeaderLen)
	}
	if f.QoSTID != 6 {
		t.Errorf("QoSTID = %d, want 6", f.QoSTID)
	}
}

// TestControlFrameDoesNotOverread: an ACK is 10 bytes and carries only Addr1. Reading a
// second or third address would manufacture MACs from whatever followed in the buffer.
func TestControlFrameDoesNotOverread(t *testing.T) {
	ack := []byte{0xD4, 0x00, 0x00, 0x00, 0xa4, 0x2b, 0x8c, 0x11, 0x22, 0x33}

	f, err := ParseFrame(ack)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if f.Type != TypeControl {
		t.Fatalf("Type = %v, want control", f.Type)
	}
	if !f.Addr2.IsZero() {
		t.Errorf("Addr2 = %v; an ACK carries only one address", f.Addr2)
	}
	if _, ok := f.BSSID(); ok {
		t.Error("a control frame yielded a BSSID")
	}
}

func TestShortAndMalformedFrames(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, ErrShortFrame},
		{"below control minimum", []byte{0x80, 0x00, 0x00}, ErrShortFrame},
		{"management below 24 bytes", append([]byte{0x80, 0x00}, make([]byte, 15)...), ErrShortFrame},
		{"bad protocol version", append([]byte{0x81, 0x00}, make([]byte, 30)...), ErrBadVersion},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseFrame(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDeauthReasonCode(t *testing.T) {
	ap := mac("a4:2b:8c:11:22:33")
	sta := mac("de:ad:be:ef:00:01")

	raw := []byte{0xC0, 0x00, 0x00, 0x00}
	raw = append(raw, sta[:]...)
	raw = append(raw, ap[:]...)
	raw = append(raw, ap[:]...)
	raw = append(raw, 0x00, 0x00)
	raw = append(raw, 0x07, 0x00) // reason 7: class 3 frame from nonassociated STA

	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if f.Subtype != SubtypeDeauth {
		t.Fatalf("Subtype = %v, want deauth", f.Subtype)
	}
	code, ok := f.ReasonCode()
	if !ok || code != 7 {
		t.Errorf("ReasonCode = %d (ok=%v), want 7", code, ok)
	}
	if got, ok := f.StationAddr(); !ok || got != sta {
		t.Errorf("StationAddr = %v (ok=%v), want %v", got, ok, sta)
	}
}

func TestMACHelpers(t *testing.T) {
	m := mac("a4:2b:8c:11:22:33")
	if m.String() != "a4:2b:8c:11:22:33" {
		t.Errorf("String = %q", m.String())
	}
	if m.OUIString() != "a4:2b:8c" {
		t.Errorf("OUIString = %q", m.OUIString())
	}
	if m.IsMulticast() || m.IsRandomised() {
		t.Error("a4:2b:8c is neither multicast nor locally administered")
	}
	if !Broadcast.IsBroadcast() || !Broadcast.IsMulticast() {
		t.Error("broadcast address helpers are wrong")
	}

	// A randomised phone MAC has the locally-administered bit set.
	if r := mac("da:a1:19:00:11:22"); !r.IsRandomised() {
		t.Error("locally administered address not detected as randomised")
	}

	if _, err := ParseMAC("not-a-mac"); err == nil {
		t.Error("ParseMAC accepted a non-MAC")
	}
	if _, err := ParseMAC("a4:2b:8c:11:22"); err == nil {
		t.Error("ParseMAC accepted a five-octet address")
	}
	// Hyphen-separated and uppercase forms round-trip to the canonical form.
	if got, err := ParseMAC("A4-2B-8C-11-22-33"); err != nil || got != m {
		t.Errorf("ParseMAC(hyphenated) = %v, %v", got, err)
	}
}

func TestMACJSONRoundTrip(t *testing.T) {
	m := mac("a4:2b:8c:11:22:33")
	text, err := m.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(text) != "a4:2b:8c:11:22:33" {
		t.Fatalf("MarshalText = %q", text)
	}
	var back MAC
	if err := back.UnmarshalText(text); err != nil || back != m {
		t.Errorf("round trip failed: %v, %v", back, err)
	}
}

// TestHiddenSSIDVariants: both a zero-length and a NUL-padded SSID are cloaked, and both must
// report absent so the network cannot match a scoped ESSID until it is resolved.
func TestHiddenSSIDVariants(t *testing.T) {
	for _, tc := range []struct {
		name string
		ie   []byte
	}{
		{"zero length", ssidIE("")},
		{"NUL padded", hiddenSSIDIE(9)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ies, err := ParseIEs(tc.ie)
			if err != nil {
				t.Fatalf("ParseIEs: %v", err)
			}
			if essid, ok := ies.SSID(); ok {
				t.Errorf("cloaked SSID reported as present: %q", essid)
			}
		})
	}
}

func TestTruncatedIEsYieldWhatParsed(t *testing.T) {
	// A valid SSID element followed by an element claiming more bytes than remain.
	raw := append(ssidIE("CORP-WIFI"), IESupportedRates, 0x10, 0x82, 0x84)

	ies, err := ParseIEs(raw)
	if !errors.Is(err, ErrTruncatedIE) {
		t.Fatalf("err = %v, want ErrTruncatedIE", err)
	}
	// The elements before the truncation are still usable: a clipped capture should still
	// yield a BSSID record rather than nothing.
	if essid, ok := ies.SSID(); !ok || essid != "CORP-WIFI" {
		t.Errorf("SSID = %q (ok=%v); elements before the truncation were discarded", essid, ok)
	}
}

func TestIEOrderPreserved(t *testing.T) {
	ies, err := ParseIEs(concat([][]byte{
		ssidIE("N"), ratesIE(0x82), dsIE(6), htCapIE(0), heCapIE(),
	}))
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	got := ies.IDs()
	want := []string{"0", "1", "3", "45", "255.35"}
	if len(got) != len(want) {
		t.Fatalf("IDs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("IDs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if !ies.HasHE() {
		t.Error("HE capability element not detected")
	}
}
