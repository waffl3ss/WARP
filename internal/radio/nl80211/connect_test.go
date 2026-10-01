package nl80211

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/mdlayher/netlink"
)

// decodeAttrs decodes an encoder's output into a map of attribute type → raw bytes, so a test can
// assert exactly which attributes CMD_CONNECT carries and what they hold.
func decodeAttrs(t *testing.T, ae *netlink.AttributeEncoder) map[uint16][]byte {
	t.Helper()
	raw, err := ae.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	ad, err := netlink.NewAttributeDecoder(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := map[uint16][]byte{}
	for ad.Next() {
		// Copy: the decoder reuses its buffer across Next calls.
		out[ad.Type()] = append([]byte(nil), ad.Bytes()...)
	}
	if err := ad.Err(); err != nil {
		t.Fatalf("decode walk: %v", err)
	}
	return out
}

func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// TestConnectEncodesAnEnterpriseAssociation checks the exact attributes a WPA-Enterprise connect
// puts on the wire: the frequency, the SSID, the pinned BSSID, open-system auth, WPA2, the AP's
// advertised suites, and the control-port-over-nl80211 flags that route EAPOL back to us. A wrong
// attribute number or integer width here is a bug that would only ever show up as a silent
// non-association against real hardware, which is exactly what cannot be caught on this box.
func TestConnectEncodesAnEnterpriseAssociation(t *testing.T) {
	bssid := []byte{0x9c, 0xef, 0xd5, 0xfd, 0x0f, 0x42}
	ae, err := connectAttrs(7, ConnectParams{
		SSID:        []byte("Waffles-Corp"),
		BSSID:       bssid,
		FreqMHz:     2437,
		AuthType:    AuthTypeOpenSystem,
		WPAVersions: WPAVersion2,
		Pairwise:    []uint32{CipherCCMP128},
		Group:       CipherCCMP128,
		AKMs:        []uint32{AKM8021X},

		ControlPort: true,
	})
	if err != nil {
		t.Fatalf("connectAttrs: %v", err)
	}
	attrs := decodeAttrs(t, ae)

	if got := u32(attrs[AttrIfindex]); got != 7 {
		t.Errorf("ifindex = %d, want 7", got)
	}
	if got := u32(attrs[AttrWiphyFreq]); got != 2437 {
		t.Errorf("freq = %d, want 2437", got)
	}
	if got := string(attrs[AttrSSID]); got != "Waffles-Corp" {
		t.Errorf("ssid = %q, want Waffles-Corp", got)
	}
	if !bytes.Equal(attrs[AttrMAC], bssid) {
		t.Errorf("bssid = %x, want %x", attrs[AttrMAC], bssid)
	}
	if got := u32(attrs[AttrAuthType]); got != AuthTypeOpenSystem {
		t.Errorf("auth type = %d, want open system", got)
	}
	if got := u32(attrs[AttrWPAVersions]); got != WPAVersion2 {
		t.Errorf("wpa versions = %d, want %d", got, WPAVersion2)
	}
	if _, ok := attrs[AttrPrivacy]; !ok {
		t.Error("the privacy flag is missing; the kernel would build an open-network association")
	}
	if got := u32(attrs[AttrCipherSuitesPairwise]); got != CipherCCMP128 {
		t.Errorf("pairwise = %08x, want CCMP", got)
	}
	if got := u32(attrs[AttrCipherSuiteGroup]); got != CipherCCMP128 {
		t.Errorf("group = %08x, want CCMP", got)
	}
	if got := u32(attrs[AttrAKMSuites]); got != AKM8021X {
		t.Errorf("akm = %08x, want 802.1X", got)
	}
	// Control port on the netdev: the flag and the EAPOL ethertype must be present so the kernel
	// hands EAPOL to a packet socket, but NOT the over-nl80211/socket-owner flags — those belong
	// to the alternate single-socket path.
	if got := binary.LittleEndian.Uint16(attrs[AttrControlPortEthertype]); got != EtherTypeEAPOL {
		t.Errorf("control port ethertype = %04x, want EAPOL %04x", got, EtherTypeEAPOL)
	}
	if _, ok := attrs[AttrControlPort]; !ok {
		t.Error("the control-port flag is missing; the kernel would swallow EAPOL")
	}
	for _, a := range []uint16{AttrControlPortOverNL80211, AttrSocketOwner} {
		if _, ok := attrs[a]; ok {
			t.Errorf("attr %d should be absent for the packet-socket control-port path", a)
		}
	}
}

// TestConnectOverNL80211SetsSocketOwner: the alternate routing keeps the socket-owner semantics.
func TestConnectOverNL80211SetsSocketOwner(t *testing.T) {
	ae, err := connectAttrs(1, ConnectParams{
		SSID: []byte("x"), FreqMHz: 2437, AuthType: AuthTypeOpenSystem,
		ControlPortOverNL80211: true,
	})
	if err != nil {
		t.Fatalf("connectAttrs: %v", err)
	}
	attrs := decodeAttrs(t, ae)
	for _, a := range []uint16{AttrControlPort, AttrControlPortOverNL80211, AttrSocketOwner} {
		if _, ok := attrs[a]; !ok {
			t.Errorf("control-port-over-nl80211 flag attr %d is missing", a)
		}
	}
}

// TestRSNElementMatchesWhatWorks pins the RSN element WARP puts in the association request to the
// exact bytes wpa_supplicant sends and that the access point accepts (captured off the air). The
// kernel does not build this element from the crypto attributes on several drivers, so it has to
// be supplied via NL80211_ATTR_IE — and if it is even slightly wrong the association is refused
// with 802.11 status 40.
func TestRSNElementMatchesWhatWorks(t *testing.T) {
	// WPA2-Enterprise, CCMP, 802.1X, no MFP — the Waffles-Corp case.
	p := ConnectParams{
		WPAVersions: WPAVersion2,
		Group:       CipherCCMP128,
		Pairwise:    []uint32{CipherCCMP128},
		AKMs:        []uint32{AKM8021X},
	}
	got := rsnIE(p)
	want := []byte{
		0x30, 0x14, // RSN element, length 20
		0x01, 0x00, // version 1
		0x00, 0x0f, 0xac, 0x04, // group CCMP
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // 1 pairwise: CCMP
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x01, // 1 AKM: 802.1X
		0x00, 0x00, // RSN capabilities
	}
	if !bytes.Equal(got, want) {
		t.Errorf("RSN element\n got % x\nwant % x", got, want)
	}

	// An open network has no RSN element.
	if ie := rsnIE(ConnectParams{}); ie != nil {
		t.Errorf("open network should have no RSN element, got % x", ie)
	}

	// MFP-required adds the capability bits, a zero PMKID count, and the group management cipher.
	mfp := rsnIE(ConnectParams{
		WPAVersions: WPAVersion2, Group: CipherCCMP128,
		Pairwise: []uint32{CipherCCMP128}, AKMs: []uint32{AKM8021X}, MFP: MFPRequired,
	})
	// caps 0x00c0 (MFPC|MFPR), then 00 00 PMKID count, then 00 0f ac 06 (BIP-CMAC-128).
	tail := []byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xac, 0x06}
	if !bytes.HasSuffix(mfp, tail) {
		t.Errorf("MFP RSN element should end with caps+pmkid+group-mgmt % x, got % x", tail, mfp)
	}
}

// TestConnectIncludesRSNElement checks the encoded connect actually carries the element.
func TestConnectIncludesRSNElement(t *testing.T) {
	ae, err := connectAttrs(7, ConnectParams{
		SSID: []byte("Waffles-Corp"), BSSID: []byte{1, 2, 3, 4, 5, 6}, FreqMHz: 2437,
		AuthType: AuthTypeOpenSystem, WPAVersions: WPAVersion2,
		Group: CipherCCMP128, Pairwise: []uint32{CipherCCMP128}, AKMs: []uint32{AKM8021X},
	})
	if err != nil {
		t.Fatalf("connectAttrs: %v", err)
	}
	attrs := decodeAttrs(t, ae)
	ie, ok := attrs[AttrIE]
	if !ok {
		t.Fatal("connect request carries no NL80211_ATTR_IE — the AP will refuse with status 40")
	}
	if len(ie) < 2 || ie[0] != 48 {
		t.Errorf("ATTR_IE is not an RSN element: % x", ie)
	}
}

// TestConnectOmitsCryptoForAnOpenNetwork: an open network carries no WPA/privacy/cipher
// attributes, or the kernel refuses the association for offering encryption the AP does not run.
func TestConnectOmitsCryptoForAnOpenNetwork(t *testing.T) {
	ae, err := connectAttrs(3, ConnectParams{
		SSID: []byte("GuestWiFi"), FreqMHz: 5180, AuthType: AuthTypeOpenSystem,
	})
	if err != nil {
		t.Fatalf("connectAttrs: %v", err)
	}
	attrs := decodeAttrs(t, ae)
	for _, a := range []uint16{AttrPrivacy, AttrWPAVersions, AttrCipherSuitesPairwise, AttrAKMSuites} {
		if _, ok := attrs[a]; ok {
			t.Errorf("open-network connect should not carry attr %d", a)
		}
	}
}

// TestConnectValidatesInput: the encoder refuses a request that would fail obscurely on the wire.
func TestConnectValidatesInput(t *testing.T) {
	cases := []struct {
		name string
		p    ConnectParams
	}{
		{"no ssid", ConnectParams{FreqMHz: 2437}},
		{"no freq", ConnectParams{SSID: []byte("x")}},
		{"short bssid", ConnectParams{SSID: []byte("x"), FreqMHz: 2437, BSSID: []byte{1, 2, 3}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := connectAttrs(1, tc.p); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestSuiteBytesAreLittleEndianU32: RSN selectors go on the wire as an array of little-endian
// u32, and a byte-order slip would offer the AP a cipher it never advertised.
func TestSuiteBytesAreLittleEndianU32(t *testing.T) {
	got := suiteBytes([]uint32{CipherCCMP128, AKMPSK})
	want := []byte{0x04, 0xac, 0x0f, 0x00, 0x02, 0xac, 0x0f, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("suiteBytes = % x, want % x", got, want)
	}
}
