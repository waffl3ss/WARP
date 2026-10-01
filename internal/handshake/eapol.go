// Package handshake extracts PMKIDs and EAPOL 4-way handshakes and emits hashcat 22000
// lines natively.
//
// WARP does not run hashcat. These files are carried to a separate cracking rig, which makes
// correctness here unusually expensive to get wrong: a malformed MESSAGEPAIR or an
// un-zeroed MIC produces a file that looks fine, travels, and only fails to crack hours later
// when the engagement box may already be unracked. There is no second chance to recapture.
//
// Everything is therefore emitted from first principles rather than by shelling out to
// cap2hccapx or hcxpcapngtool, and validated against real hashcat in CI with known
// passphrases (see the hashcat-validate skill).
package handshake

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// LLC/SNAP header preceding an EAPOL payload in an 802.11 data frame.
var llcSNAPEAPOL = []byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E}

// EAPOL packet types.
const (
	eapolTypeEAPPacket = 0
	eapolTypeStart     = 1
	eapolTypeLogoff    = 2
	eapolTypeKey       = 3
)

// EAPOL-Key descriptor types.
const (
	descriptorRSN = 2
	descriptorWPA = 254
)

// Key Information bits (IEEE 802.11-2020 figure 12-34), big-endian.
const (
	keyInfoDescVersion = 0x0007
	keyInfoKeyType     = 0x0008 // 1 = pairwise, 0 = group
	keyInfoInstall     = 0x0040
	keyInfoACK         = 0x0080
	keyInfoMIC         = 0x0100
	keyInfoSecure      = 0x0200
	keyInfoError       = 0x0400
	keyInfoRequest     = 0x0800
	keyInfoEncrypted   = 0x1000
	keyInfoSMK         = 0x2000
)

// Offsets within the EAPOL-Key body, from the start of the 802.1X header.
const (
	offEAPOLVersion  = 0
	offEAPOLType     = 1
	offEAPOLLength   = 2
	offDescriptor    = 4
	offKeyInfo       = 5
	offKeyLength     = 7
	offReplayCounter = 9
	offNonce         = 17
	offKeyIV         = 49
	offKeyRSC        = 65
	offKeyID         = 73
	offKeyMIC        = 81
	offKeyDataLength = 97
	offKeyData       = 99

	// minEAPOLKeyLen is the fixed portion through the key-data-length field.
	minEAPOLKeyLen = offKeyData
	micLen         = 16
	nonceLen       = 32
)

// MessageNumber identifies which of the four handshake messages a frame is.
type MessageNumber int

// Handshake message numbers. MessageUnknown covers group-key and other EAPOL-Key traffic
// that is not part of a pairwise 4-way handshake.
const (
	MessageUnknown MessageNumber = 0
	M1             MessageNumber = 1
	M2             MessageNumber = 2
	M3             MessageNumber = 3
	M4             MessageNumber = 4
)

func (m MessageNumber) String() string {
	if m == MessageUnknown {
		return "M?"
	}
	return fmt.Sprintf("M%d", int(m))
}

// EAPOLKey is a parsed EAPOL-Key frame.
type EAPOLKey struct {
	Version    uint8
	Descriptor uint8
	KeyInfo    uint16
	KeyLength  uint16
	// ReplayCounter is tracked so that messages from different handshake attempts are not
	// combined. Mixing them produces a hash that is internally consistent and will never
	// crack.
	ReplayCounter uint64
	Nonce         [nonceLen]byte
	MIC           [micLen]byte
	KeyData       []byte

	// Raw is the complete 802.1X frame as transmitted, from the version byte through the end
	// of the key data. This is what goes into the 22000 EAPOL field.
	Raw []byte

	Message MessageNumber
}

// Descriptor version bits, which determine the MIC algorithm.
func (k *EAPOLKey) descriptorVersion() uint16 { return k.KeyInfo & keyInfoDescVersion }

// Pairwise reports whether the Key Type bit marks this as a pairwise (not group) key.
func (k *EAPOLKey) Pairwise() bool { return k.KeyInfo&keyInfoKeyType != 0 }

// HasMIC reports whether the Key MIC bit is set.
func (k *EAPOLKey) HasMIC() bool { return k.KeyInfo&keyInfoMIC != 0 }

// Errors returned when parsing EAPOL.
var (
	ErrNotEAPOL    = errors.New("handshake: not an EAPOL frame")
	ErrNotEAPOLKey = errors.New("handshake: not an EAPOL-Key frame")
	ErrShortEAPOL  = errors.New("handshake: EAPOL frame too short")
	ErrBadKeyData  = errors.New("handshake: key data length exceeds the frame")
)

// ExtractEAPOL returns the 802.1X payload from an 802.11 data frame body, which begins with
// an LLC/SNAP header.
func ExtractEAPOL(body []byte) ([]byte, error) {
	if len(body) < len(llcSNAPEAPOL) {
		return nil, ErrNotEAPOL
	}
	for i, b := range llcSNAPEAPOL {
		if body[i] != b {
			return nil, ErrNotEAPOL
		}
	}
	return body[len(llcSNAPEAPOL):], nil
}

// ParseEAPOLKey decodes an 802.1X EAPOL-Key frame and classifies which handshake message it
// is.
func ParseEAPOLKey(b []byte) (*EAPOLKey, error) {
	if len(b) < 4 {
		return nil, ErrShortEAPOL
	}
	if b[offEAPOLType] != eapolTypeKey {
		return nil, ErrNotEAPOLKey
	}
	if len(b) < minEAPOLKeyLen {
		return nil, ErrShortEAPOL
	}

	k := &EAPOLKey{
		Version:       b[offEAPOLVersion],
		Descriptor:    b[offDescriptor],
		KeyInfo:       binary.BigEndian.Uint16(b[offKeyInfo : offKeyInfo+2]),
		KeyLength:     binary.BigEndian.Uint16(b[offKeyLength : offKeyLength+2]),
		ReplayCounter: binary.BigEndian.Uint64(b[offReplayCounter : offReplayCounter+8]),
	}
	copy(k.Nonce[:], b[offNonce:offNonce+nonceLen])
	copy(k.MIC[:], b[offKeyMIC:offKeyMIC+micLen])

	keyDataLen := int(binary.BigEndian.Uint16(b[offKeyDataLength : offKeyDataLength+2]))
	if offKeyData+keyDataLen > len(b) {
		return nil, ErrBadKeyData
	}
	k.KeyData = b[offKeyData : offKeyData+keyDataLen]

	// The 802.1X length field is authoritative for where the frame ends. Trailing padding
	// from the driver must not be included: hashcat computes the MIC over exactly this range,
	// so extra bytes make every hash fail to crack.
	end := offDescriptor + int(binary.BigEndian.Uint16(b[offEAPOLLength:offEAPOLLength+2]))
	if end > len(b) || end < minEAPOLKeyLen {
		end = offKeyData + keyDataLen
	}
	k.Raw = b[:end]

	k.Message = classify(k)
	return k, nil
}

// classify determines which handshake message an EAPOL-Key frame is.
//
// The distinguishing bits:
//
//	M1: ACK set, MIC clear      - from the AP, carries the ANonce and possibly a PMKID
//	M2: ACK clear, MIC set      - from the station, carries the SNonce and a MIC
//	M3: ACK set, MIC set        - from the AP, carries the ANonce again
//	M4: ACK clear, MIC set, no key data - from the station, confirms installation
//
// M2 and M4 are separated by whether key data is present: M2 carries the station's RSN
// element, M4 normally carries nothing. Getting this backwards pairs the wrong EAPOL frame
// with the ANonce and yields a hash that never cracks.
func classify(k *EAPOLKey) MessageNumber {
	if !k.Pairwise() || k.KeyInfo&keyInfoRequest != 0 || k.KeyInfo&keyInfoSMK != 0 {
		return MessageUnknown
	}

	ack := k.KeyInfo&keyInfoACK != 0
	mic := k.HasMIC()
	secure := k.KeyInfo&keyInfoSecure != 0

	switch {
	case ack && !mic:
		return M1
	case ack && mic:
		// Only M3 is sent by the AP with a MIC. Install and Secure are normally set too, but
		// neither is needed to distinguish it: M1 is the only other AP-sent message and it
		// carries no MIC.
		return M3
	case !ack && mic:
		// A zero SNonce with no key data is M4. Some supplicants send a non-empty M4, so
		// the Secure bit is the tiebreaker: M2 is sent before the PTK is confirmed.
		if len(k.KeyData) == 0 {
			return M4
		}
		if secure {
			return M4
		}
		return M2
	default:
		return MessageUnknown
	}
}

// PMKID extracts the PMKID from an M1's key data, if present.
//
// The PMKID arrives inside an RSN PMKID KDE: a vendor-specific key data element with the
// IEEE OUI and data type 4.
//
// A zero PMKID is explicitly rejected. Some APs pad the KDE with zeroes rather than omitting
// it, and a zero PMKID is not crackable - emitting it wastes rig time on a hash that can
// never produce a result.
func (k *EAPOLKey) PMKID() ([]byte, bool) {
	const (
		kdeTypeVendor    = 0xDD
		kdeDataTypePMKID = 4
	)
	oui := [3]byte{0x00, 0x0F, 0xAC}

	data := k.KeyData
	for off := 0; off+2 <= len(data); {
		id, length := data[off], int(data[off+1])
		off += 2
		if off+length > len(data) {
			return nil, false
		}
		body := data[off : off+length]
		off += length

		if id != kdeTypeVendor || len(body) < 4 {
			continue
		}
		if body[0] != oui[0] || body[1] != oui[1] || body[2] != oui[2] {
			continue
		}
		if body[3] != kdeDataTypePMKID || len(body) < 4+16 {
			continue
		}

		pmkid := body[4 : 4+16]
		if allZero(pmkid) {
			return nil, false
		}
		return append([]byte(nil), pmkid...), true
	}
	return nil, false
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ZeroMIC returns a copy of the raw 802.1X frame with the MIC field zeroed.
//
// hashcat recomputes the MIC over the EAPOL frame and compares it against the MIC field of
// the hash line, so the frame it computes over must have that field zeroed. Leaving the real
// MIC in place produces a hash that hashcat accepts and can never crack - the single most
// expensive mistake available here, because it is invisible until the rig has run.
func (k *EAPOLKey) ZeroMIC() []byte {
	out := make([]byte, len(k.Raw))
	copy(out, k.Raw)
	if len(out) >= offKeyMIC+micLen {
		for i := offKeyMIC; i < offKeyMIC+micLen; i++ {
			out[i] = 0
		}
	}
	return out
}

// NonceIsZero reports whether the nonce is all zeroes, which marks an M4 that carries no
// usable SNonce.
func (k *EAPOLKey) NonceIsZero() bool { return allZero(k.Nonce[:]) }
