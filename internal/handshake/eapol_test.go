package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// EAPOL-Key builders. Real handshake bytes are unreadable in a test, so the fixtures state
// which message they are and the builder sets the corresponding Key Information bits.

type keyOpts struct {
	keyInfo       uint16
	replayCounter uint64
	nonce         []byte
	mic           []byte
	keyData       []byte
}

func buildEAPOLKey(o keyOpts) []byte {
	keyData := o.keyData
	body := make([]byte, offKeyData+len(keyData))

	body[offEAPOLVersion] = 2
	body[offEAPOLType] = eapolTypeKey
	// The 802.1X length field counts everything after the 4-byte 802.1X header.
	binary.BigEndian.PutUint16(body[offEAPOLLength:], uint16(len(body)-offDescriptor))
	body[offDescriptor] = descriptorRSN

	binary.BigEndian.PutUint16(body[offKeyInfo:], o.keyInfo)
	binary.BigEndian.PutUint16(body[offKeyLength:], 16)
	binary.BigEndian.PutUint64(body[offReplayCounter:], o.replayCounter)

	if len(o.nonce) > 0 {
		copy(body[offNonce:offNonce+nonceLen], o.nonce)
	}
	if len(o.mic) > 0 {
		copy(body[offKeyMIC:offKeyMIC+micLen], o.mic)
	}
	binary.BigEndian.PutUint16(body[offKeyDataLength:], uint16(len(keyData)))
	copy(body[offKeyData:], keyData)

	return body
}

func fill(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

var (
	anonce = fill(nonceLen, 0xA1)
	snonce = fill(nonceLen, 0x52)
	micVal = fill(micLen, 0x9C)
)

// pmkidKDE builds the RSN PMKID key data element carried in M1.
func pmkidKDE(pmkid []byte) []byte {
	body := []byte{0x00, 0x0F, 0xAC, 0x04}
	body = append(body, pmkid...)
	return append([]byte{0xDD, byte(len(body))}, body...)
}

func m1Frame(rc uint64, keyData []byte) []byte {
	return buildEAPOLKey(keyOpts{
		keyInfo:       keyInfoKeyType | keyInfoACK | 0x0002,
		replayCounter: rc, nonce: anonce, keyData: keyData,
	})
}

func m2Frame(rc uint64) []byte {
	return buildEAPOLKey(keyOpts{
		keyInfo:       keyInfoKeyType | keyInfoMIC | 0x0002,
		replayCounter: rc, nonce: snonce, mic: micVal,
		keyData: []byte{0x30, 0x14}, // a stub RSN element, so this is not mistaken for M4
	})
}

func m3Frame(rc uint64) []byte {
	return buildEAPOLKey(keyOpts{
		keyInfo:       keyInfoKeyType | keyInfoACK | keyInfoMIC | keyInfoSecure | keyInfoInstall | 0x0002,
		replayCounter: rc, nonce: anonce, mic: micVal,
		keyData: []byte{0x30, 0x14},
	})
}

// m4Frame builds M4. Some supplicants echo the SNonce; most send zeroes.
func m4Frame(rc uint64, withSNonce bool) []byte {
	n := make([]byte, nonceLen)
	if withSNonce {
		copy(n, snonce)
	}
	return buildEAPOLKey(keyOpts{
		keyInfo:       keyInfoKeyType | keyInfoMIC | keyInfoSecure | 0x0002,
		replayCounter: rc, nonce: n, mic: fill(micLen, 0x4D),
	})
}

func TestClassifyHandshakeMessages(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want MessageNumber
	}{
		{"M1: ACK, no MIC", m1Frame(1, nil), M1},
		{"M2: MIC, no ACK, has key data", m2Frame(1), M2},
		{"M3: ACK and MIC", m3Frame(2), M3},
		{"M4: MIC, no key data", m4Frame(2, false), M4},
		{"M4 with echoed SNonce", m4Frame(2, true), M4},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k, err := ParseEAPOLKey(tc.raw)
			if err != nil {
				t.Fatalf("ParseEAPOLKey: %v", err)
			}
			if k.Message != tc.want {
				t.Errorf("Message = %v, want %v (keyinfo %#04x)", k.Message, tc.want, k.KeyInfo)
			}
		})
	}
}

// TestGroupKeyIsNotAHandshake: group rekey traffic uses EAPOL-Key too, and treating it as a
// 4-way handshake would produce hashes from frames that have nothing to do with the PSK.
func TestGroupKeyIsNotAHandshake(t *testing.T) {
	groupKey := buildEAPOLKey(keyOpts{
		keyInfo:       keyInfoACK | keyInfoMIC | keyInfoSecure | 0x0002, // Key Type clear
		replayCounter: 5, nonce: anonce, mic: micVal,
	})
	k, err := ParseEAPOLKey(groupKey)
	if err != nil {
		t.Fatalf("ParseEAPOLKey: %v", err)
	}
	if k.Pairwise() {
		t.Fatal("group key reported as pairwise")
	}
	if k.Message != MessageUnknown {
		t.Errorf("Message = %v, want unknown for a group key", k.Message)
	}
}

func TestExtractEAPOLFromDataFrame(t *testing.T) {
	payload := m1Frame(1, nil)
	body := append(append([]byte{}, llcSNAPEAPOL...), payload...)

	got, err := ExtractEAPOL(body)
	if err != nil {
		t.Fatalf("ExtractEAPOL: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Error("extracted payload does not match")
	}

	// A non-EAPOL SNAP payload (IPv4) must be rejected.
	ip := append([]byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00}, 0x45, 0x00)
	if _, err := ExtractEAPOL(ip); !errors.Is(err, ErrNotEAPOL) {
		t.Errorf("IPv4 payload: got %v, want ErrNotEAPOL", err)
	}
	if _, err := ExtractEAPOL([]byte{0xAA}); !errors.Is(err, ErrNotEAPOL) {
		t.Errorf("short payload: got %v, want ErrNotEAPOL", err)
	}
}

func TestPMKIDExtraction(t *testing.T) {
	pmkid := fill(16, 0x77)
	k, err := ParseEAPOLKey(m1Frame(1, pmkidKDE(pmkid)))
	if err != nil {
		t.Fatalf("ParseEAPOLKey: %v", err)
	}

	got, ok := k.PMKID()
	if !ok {
		t.Fatal("PMKID not extracted from M1")
	}
	if !bytes.Equal(got, pmkid) {
		t.Errorf("PMKID = % x, want % x", got, pmkid)
	}
}

// TestZeroPMKIDIsRejected: some APs pad the KDE with zeroes rather than omitting it, and a
// zero PMKID is not crackable. Emitting it sends the cracking rig on an impossible errand.
func TestZeroPMKIDIsRejected(t *testing.T) {
	k, err := ParseEAPOLKey(m1Frame(1, pmkidKDE(make([]byte, 16))))
	if err != nil {
		t.Fatalf("ParseEAPOLKey: %v", err)
	}
	if _, ok := k.PMKID(); ok {
		t.Fatal("a zero PMKID was accepted; it can never crack")
	}
}

func TestNoPMKIDWhenAbsent(t *testing.T) {
	k, _ := ParseEAPOLKey(m1Frame(1, nil))
	if _, ok := k.PMKID(); ok {
		t.Error("PMKID reported for an M1 with no key data")
	}

	// A key data element that is not the PMKID KDE must be ignored.
	otherKDE := append([]byte{0xDD, 0x06, 0x00, 0x0F, 0xAC, 0x01}, 0x00, 0x00)
	k, _ = ParseEAPOLKey(m1Frame(1, otherKDE))
	if _, ok := k.PMKID(); ok {
		t.Error("a non-PMKID KDE was read as a PMKID")
	}
}

// TestZeroMIC is the most expensive mistake available in this package: an un-zeroed MIC
// produces a hash hashcat accepts and can never crack, and the failure only surfaces at the
// cracking rig.
func TestZeroMIC(t *testing.T) {
	k, err := ParseEAPOLKey(m2Frame(1))
	if err != nil {
		t.Fatalf("ParseEAPOLKey: %v", err)
	}

	if !bytes.Equal(k.MIC[:], micVal) {
		t.Fatalf("MIC = % x, want % x", k.MIC, micVal)
	}

	zeroed := k.ZeroMIC()
	if len(zeroed) != len(k.Raw) {
		t.Fatalf("zeroed frame is %d bytes, raw is %d", len(zeroed), len(k.Raw))
	}
	if !allZero(zeroed[offKeyMIC : offKeyMIC+micLen]) {
		t.Error("MIC field was not zeroed")
	}
	// Everything outside the MIC field must be untouched: hashcat computes over the whole
	// frame.
	if !bytes.Equal(zeroed[:offKeyMIC], k.Raw[:offKeyMIC]) {
		t.Error("bytes before the MIC were modified")
	}
	if !bytes.Equal(zeroed[offKeyMIC+micLen:], k.Raw[offKeyMIC+micLen:]) {
		t.Error("bytes after the MIC were modified")
	}
	// The original must not be mutated — it is still needed for the MIC field of the hash.
	if allZero(k.MIC[:]) {
		t.Error("ZeroMIC mutated the parsed key's MIC")
	}
}

// TestRawExcludesDriverPadding: the 802.1X length field bounds the frame. Trailing padding
// would be included in hashcat's MIC computation and make every hash fail.
func TestRawExcludesDriverPadding(t *testing.T) {
	frame := m2Frame(1)
	padded := append(append([]byte{}, frame...), 0xFF, 0xFF, 0xFF, 0xFF)

	k, err := ParseEAPOLKey(padded)
	if err != nil {
		t.Fatalf("ParseEAPOLKey: %v", err)
	}
	if len(k.Raw) != len(frame) {
		t.Errorf("Raw is %d bytes, want %d — driver padding was included", len(k.Raw), len(frame))
	}
	if bytes.Contains(k.Raw, []byte{0xFF, 0xFF, 0xFF, 0xFF}) {
		t.Error("padding bytes appear in the raw frame")
	}
}

func TestMalformedEAPOL(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want error
	}{
		{"empty", nil, ErrShortEAPOL},
		{"not a key frame", []byte{2, eapolTypeStart, 0, 0}, ErrNotEAPOLKey},
		// EAPOL type 0 is EAP-Packet: the transport WPA-Enterprise carries PEAP, TTLS and
		// friends over. It is not a 4-way handshake and has no PMK behind it, so it must never
		// reach the 22000 path. Enterprise credentials come from the RADIUS server in
		// internal/eap and are emitted as MSCHAPv2 (hashcat -m 5500), not as 22000.
		{"enterprise EAP packet", []byte{1, eapolTypeEAPPacket, 0, 0}, ErrNotEAPOLKey},
		{"truncated key body", append([]byte{2, eapolTypeKey, 0, 0}, make([]byte, 20)...), ErrShortEAPOL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseEAPOLKey(tc.raw); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	// A key data length claiming more than the frame holds must be refused, not read past.
	bad := m2Frame(1)
	binary.BigEndian.PutUint16(bad[offKeyDataLength:], 0xFFFF)
	if _, err := ParseEAPOLKey(bad); !errors.Is(err, ErrBadKeyData) {
		t.Errorf("oversized key data: got %v, want ErrBadKeyData", err)
	}
}

func TestReplayCounterParsed(t *testing.T) {
	k, err := ParseEAPOLKey(m1Frame(0x0102030405060708, nil))
	if err != nil {
		t.Fatalf("ParseEAPOLKey: %v", err)
	}
	if k.ReplayCounter != 0x0102030405060708 {
		t.Errorf("ReplayCounter = %#x", k.ReplayCounter)
	}
}
