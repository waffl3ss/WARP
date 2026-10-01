// Package recon parses 802.11 frames and maintains the picture of what is on the air:
// BSSIDs, their encryption configuration, their radio fingerprints, and the client stations
// associated with them.
//
// The parser is hand-rolled rather than delegated to gopacket for three reasons. Radio
// fingerprinting needs the *exact* information elements in the *exact* order the AP sent
// them, which a normalising parser discards. The capture path is hot enough that per-frame
// allocation matters. And WARP ships as a single static binary with CGO disabled, so a
// dependency that pulls in a capture stack is unwelcome. The brief explicitly permits this.
package recon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// MAC is an 802.11 hardware address.
//
// A fixed-size array rather than a slice: it is comparable, usable directly as a map key, and
// carries no allocation. Client tracking keys off it for the whole engagement.
type MAC [6]byte

// Broadcast is the all-ones address.
var Broadcast = MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// ParseMAC converts a colon- or hyphen-separated address.
func ParseMAC(s string) (MAC, error) {
	var m MAC
	s = strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(s), "-", ""), ":", "")
	if len(s) != 12 {
		return m, fmt.Errorf("recon: %q is not a MAC address", s)
	}
	for i := 0; i < 6; i++ {
		var b byte
		for j := 0; j < 2; j++ {
			c := s[i*2+j]
			var v byte
			switch {
			case c >= '0' && c <= '9':
				v = c - '0'
			case c >= 'a' && c <= 'f':
				v = c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = c - 'A' + 10
			default:
				return m, fmt.Errorf("recon: %q is not a MAC address", s)
			}
			b = b<<4 | v
		}
		m[i] = b
	}
	return m, nil
}

// MACFromBytes reads a MAC from the first six bytes of b.
func MACFromBytes(b []byte) MAC {
	var m MAC
	copy(m[:], b)
	return m
}

const hexDigits = "0123456789abcdef"

// String renders the lowercase colon-separated form used everywhere in WARP's output.
func (m MAC) String() string {
	buf := make([]byte, 0, 17)
	for i, b := range m {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(buf)
}

// MarshalText makes MAC render as a string in JSON rather than as an array of numbers.
func (m MAC) MarshalText() ([]byte, error) { return []byte(m.String()), nil }

// UnmarshalText parses the string form.
func (m *MAC) UnmarshalText(b []byte) error {
	v, err := ParseMAC(string(b))
	if err != nil {
		return err
	}
	*m = v
	return nil
}

// IsZero reports whether the address is all zeroes.
func (m MAC) IsZero() bool { return m == MAC{} }

// IsBroadcast reports whether the address is the broadcast address.
func (m MAC) IsBroadcast() bool { return m == Broadcast }

// IsMulticast reports whether the group bit is set.
func (m MAC) IsMulticast() bool { return m[0]&0x01 != 0 }

// IsLocallyAdministered reports whether the local bit is set.
//
// Modern phones randomise their MAC when probing, and a randomised address is locally
// administered. Client counts that ignore this wildly overcount devices, so it is surfaced
// rather than hidden.
func (m MAC) IsLocallyAdministered() bool { return m[0]&0x02 != 0 }

// IsRandomised is a synonym for IsLocallyAdministered, named for how it is used.
func (m MAC) IsRandomised() bool { return m.IsLocallyAdministered() }

// OUI returns the 24-bit organisationally unique identifier.
func (m MAC) OUI() [3]byte { return [3]byte{m[0], m[1], m[2]} }

// OUIString renders the OUI in the canonical colon form.
func (m MAC) OUIString() string { return m.String()[:8] }

// FrameType is the 802.11 frame type field.
type FrameType uint8

// Frame types.
const (
	TypeManagement FrameType = 0
	TypeControl    FrameType = 1
	TypeData       FrameType = 2
	TypeExtension  FrameType = 3
)

func (t FrameType) String() string {
	switch t {
	case TypeManagement:
		return "mgmt"
	case TypeControl:
		return "ctrl"
	case TypeData:
		return "data"
	case TypeExtension:
		return "ext"
	default:
		return "type?"
	}
}

// FrameSubtype is the 802.11 subtype field, interpreted within a FrameType.
type FrameSubtype uint8

// Management subtypes.
const (
	SubtypeAssocReq    FrameSubtype = 0
	SubtypeAssocResp   FrameSubtype = 1
	SubtypeReassocReq  FrameSubtype = 2
	SubtypeReassocResp FrameSubtype = 3
	SubtypeProbeReq    FrameSubtype = 4
	SubtypeProbeResp   FrameSubtype = 5
	SubtypeTimingAdv   FrameSubtype = 6
	SubtypeBeacon      FrameSubtype = 8
	SubtypeATIM        FrameSubtype = 9
	SubtypeDisassoc    FrameSubtype = 10
	SubtypeAuth        FrameSubtype = 11
	SubtypeDeauth      FrameSubtype = 12
	SubtypeAction      FrameSubtype = 13
	SubtypeActionNoAck FrameSubtype = 14
)

// Data subtypes.
const (
	SubtypeData     FrameSubtype = 0
	SubtypeNullData FrameSubtype = 4
	SubtypeQoSData  FrameSubtype = 8
	SubtypeQoSNull  FrameSubtype = 12
)

// ManagementName returns an operator-facing name for a management subtype.
func (s FrameSubtype) ManagementName() string {
	switch s {
	case SubtypeAssocReq:
		return "assoc-req"
	case SubtypeAssocResp:
		return "assoc-resp"
	case SubtypeReassocReq:
		return "reassoc-req"
	case SubtypeReassocResp:
		return "reassoc-resp"
	case SubtypeProbeReq:
		return "probe-req"
	case SubtypeProbeResp:
		return "probe-resp"
	case SubtypeBeacon:
		return "beacon"
	case SubtypeDisassoc:
		return "disassoc"
	case SubtypeAuth:
		return "auth"
	case SubtypeDeauth:
		return "deauth"
	case SubtypeAction:
		return "action"
	default:
		return fmt.Sprintf("mgmt-%d", uint8(s))
	}
}

// Frame is a parsed 802.11 MAC header plus the body that follows it.
type Frame struct {
	Type    FrameType
	Subtype FrameSubtype

	ToDS      bool
	FromDS    bool
	MoreFrag  bool
	Retry     bool
	PwrMgmt   bool
	MoreData  bool
	Protected bool
	Order     bool

	Addr1 MAC
	Addr2 MAC
	Addr3 MAC
	Addr4 MAC

	SeqNum  uint16
	FragNum uint8

	HasQoS bool
	QoSTID uint8

	// HeaderLen is the length of the MAC header, i.e. the offset of Body within the frame.
	HeaderLen int
	// Body is the frame body: the management fixed fields and IEs, or the data payload.
	Body []byte
}

// Errors returned by ParseFrame.
var (
	ErrShortFrame = errors.New("recon: frame shorter than an 802.11 header")
	ErrBadVersion = errors.New("recon: unsupported 802.11 protocol version")
)

// Minimum header sizes.
const (
	frameControlLen = 2
	minHeaderLen    = 10 // FC + duration + one address (control frames such as ACK)
	fullHeaderLen   = 24 // FC + duration + three addresses + sequence control
)

// ParseFrame decodes an 802.11 MAC header.
//
// Control frames are parsed as far as they go - most carry only one or two addresses - so
// that a control frame never produces a spurious BSSID from whatever bytes followed.
func ParseFrame(b []byte) (*Frame, error) {
	if len(b) < minHeaderLen {
		return nil, ErrShortFrame
	}
	if b[0]&0x03 != 0 {
		return nil, fmt.Errorf("%w: %d", ErrBadVersion, b[0]&0x03)
	}

	f := &Frame{
		Type:    FrameType((b[0] >> 2) & 0x03),
		Subtype: FrameSubtype((b[0] >> 4) & 0x0f),

		ToDS:      b[1]&0x01 != 0,
		FromDS:    b[1]&0x02 != 0,
		MoreFrag:  b[1]&0x04 != 0,
		Retry:     b[1]&0x08 != 0,
		PwrMgmt:   b[1]&0x10 != 0,
		MoreData:  b[1]&0x20 != 0,
		Protected: b[1]&0x40 != 0,
		Order:     b[1]&0x80 != 0,
	}

	f.Addr1 = MACFromBytes(b[4:10])

	// Control frames are short and irregular: an ACK or CTS carries only Addr1. Stop here
	// rather than reading past the frame into whatever the driver left in the buffer.
	if f.Type == TypeControl {
		f.HeaderLen = len(b)
		if len(b) >= 16 {
			f.Addr2 = MACFromBytes(b[10:16])
			f.HeaderLen = 16
		}
		return f, nil
	}

	if len(b) < fullHeaderLen {
		return nil, ErrShortFrame
	}
	f.Addr2 = MACFromBytes(b[10:16])
	f.Addr3 = MACFromBytes(b[16:22])

	seq := binary.LittleEndian.Uint16(b[22:24])
	f.FragNum = uint8(seq & 0x0f)
	f.SeqNum = seq >> 4

	off := fullHeaderLen

	// A fourth address is present only in the WDS case.
	if f.ToDS && f.FromDS {
		if len(b) < off+6 {
			return nil, ErrShortFrame
		}
		f.Addr4 = MACFromBytes(b[off : off+6])
		off += 6
	}

	if f.Type == TypeData && f.Subtype&0x08 != 0 {
		if len(b) < off+2 {
			return nil, ErrShortFrame
		}
		f.HasQoS = true
		f.QoSTID = b[off] & 0x0f
		off += 2
	}

	// The HT Control field is present when the Order bit is set on a QoS frame.
	if f.Order && f.HasQoS {
		if len(b) < off+4 {
			return nil, ErrShortFrame
		}
		off += 4
	}

	f.HeaderLen = off
	f.Body = b[off:]
	return f, nil
}

// HasAddr4 reports whether the frame carried a fourth address.
func (f *Frame) HasAddr4() bool { return f.ToDS && f.FromDS }

// BSSID returns the BSSID the frame belongs to, and whether one could be determined.
//
// Which address holds the BSSID depends on the DS bits. Reading the wrong one invents BSSIDs
// that were never on the air, which then appear in the report as unknown devices.
func (f *Frame) BSSID() (MAC, bool) {
	switch f.Type {
	case TypeManagement:
		// In management frames Addr3 is the BSSID.
		return f.Addr3, !f.Addr3.IsZero()

	case TypeData:
		switch {
		case !f.ToDS && !f.FromDS:
			return f.Addr3, !f.Addr3.IsZero() // IBSS
		case !f.ToDS && f.FromDS:
			return f.Addr2, !f.Addr2.IsZero() // from AP
		case f.ToDS && !f.FromDS:
			return f.Addr1, !f.Addr1.IsZero() // to AP
		default:
			return MAC{}, false // WDS: no single BSSID
		}

	default:
		return MAC{}, false
	}
}

// Source returns the frame's source address.
func (f *Frame) Source() (MAC, bool) {
	switch {
	case f.Type == TypeControl:
		return f.Addr2, !f.Addr2.IsZero()
	case f.ToDS && f.FromDS:
		return f.Addr4, !f.Addr4.IsZero()
	case !f.ToDS && f.FromDS:
		return f.Addr3, !f.Addr3.IsZero()
	default:
		return f.Addr2, !f.Addr2.IsZero()
	}
}

// Destination returns the frame's destination address.
func (f *Frame) Destination() (MAC, bool) {
	switch {
	case f.ToDS && !f.FromDS:
		return f.Addr3, !f.Addr3.IsZero()
	default:
		return f.Addr1, !f.Addr1.IsZero()
	}
}

// StationAddr returns the client station involved in the frame, if the frame identifies one.
//
// For a frame from an AP this is the destination; for a frame to an AP it is the source. It
// returns false for frames where no station can be attributed, so that a broadcast beacon is
// never recorded as a client.
func (f *Frame) StationAddr() (MAC, bool) {
	bssid, ok := f.BSSID()
	if !ok {
		return MAC{}, false
	}

	switch f.Type {
	case TypeManagement:
		switch f.Subtype {
		case SubtypeProbeReq, SubtypeAssocReq, SubtypeReassocReq:
			return f.Addr2, !f.Addr2.IsZero() && f.Addr2 != bssid
		case SubtypeProbeResp, SubtypeAssocResp, SubtypeReassocResp:
			if f.Addr1.IsMulticast() {
				return MAC{}, false
			}
			return f.Addr1, !f.Addr1.IsZero()
		case SubtypeAuth, SubtypeDeauth, SubtypeDisassoc:
			// Either direction; the non-BSSID party is the station.
			if f.Addr2 != bssid && !f.Addr2.IsZero() {
				return f.Addr2, true
			}
			if !f.Addr1.IsMulticast() && f.Addr1 != bssid && !f.Addr1.IsZero() {
				return f.Addr1, true
			}
			return MAC{}, false
		}
		return MAC{}, false

	case TypeData:
		if f.ToDS && !f.FromDS {
			return f.Addr2, !f.Addr2.IsZero()
		}
		if !f.ToDS && f.FromDS {
			if f.Addr1.IsMulticast() {
				return MAC{}, false
			}
			return f.Addr1, !f.Addr1.IsZero()
		}
		return MAC{}, false

	default:
		return MAC{}, false
	}
}

// Management fixed-field lengths, in bytes, preceding the information elements.
const (
	fixedBeacon     = 12 // timestamp(8) + beacon interval(2) + capability(2)
	fixedAssocReq   = 4  // capability(2) + listen interval(2)
	fixedAssocResp  = 6  // capability(2) + status(2) + AID(2)
	fixedReassocReq = 10 // capability(2) + listen interval(2) + current AP(6)
	fixedAuth       = 6  // algorithm(2) + sequence(2) + status(2)
)

// ManagementBody splits a management frame body into its fixed fields and its information
// elements. Returns false if the subtype carries no IEs or the body is too short.
func (f *Frame) ManagementBody() (fixed, ies []byte, ok bool) {
	if f.Type != TypeManagement {
		return nil, nil, false
	}

	var n int
	switch f.Subtype {
	case SubtypeBeacon, SubtypeProbeResp:
		n = fixedBeacon
	case SubtypeProbeReq:
		n = 0
	case SubtypeAssocReq:
		n = fixedAssocReq
	case SubtypeAssocResp, SubtypeReassocResp:
		n = fixedAssocResp
	case SubtypeReassocReq:
		n = fixedReassocReq
	case SubtypeAuth:
		n = fixedAuth
	default:
		return nil, nil, false
	}

	if len(f.Body) < n {
		return nil, nil, false
	}
	return f.Body[:n], f.Body[n:], true
}

// Capability returns the capability information field of a beacon, probe response or
// association frame.
func (f *Frame) Capability() (uint16, bool) {
	fixed, _, ok := f.ManagementBody()
	if !ok {
		return 0, false
	}
	switch f.Subtype {
	case SubtypeBeacon, SubtypeProbeResp:
		return binary.LittleEndian.Uint16(fixed[10:12]), true
	case SubtypeAssocReq, SubtypeAssocResp, SubtypeReassocReq, SubtypeReassocResp:
		return binary.LittleEndian.Uint16(fixed[0:2]), true
	}
	return 0, false
}

// BeaconInterval returns the beacon interval in time units (1 TU = 1024 µs).
//
// It is part of the radio fingerprint: a homogeneous fleet of client APs is configured
// identically, so an impostor that left the default is visibly different.
func (f *Frame) BeaconInterval() (uint16, bool) {
	if f.Subtype != SubtypeBeacon && f.Subtype != SubtypeProbeResp {
		return 0, false
	}
	fixed, _, ok := f.ManagementBody()
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint16(fixed[8:10]), true
}

// Timestamp returns the AP's TSF timestamp from a beacon or probe response.
func (f *Frame) Timestamp() (uint64, bool) {
	if f.Subtype != SubtypeBeacon && f.Subtype != SubtypeProbeResp {
		return 0, false
	}
	fixed, _, ok := f.ManagementBody()
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint64(fixed[0:8]), true
}

// Capability information bits.
const (
	CapESS         = 0x0001
	CapIBSS        = 0x0002
	CapPrivacy     = 0x0010
	CapShortPre    = 0x0020
	CapPBCC        = 0x0040
	CapChanAgility = 0x0080
	CapShortSlot   = 0x0400
	CapRadioMeas   = 0x1000
)

// ReasonCode returns the reason code from a deauthentication or disassociation frame.
func (f *Frame) ReasonCode() (uint16, bool) {
	if f.Subtype != SubtypeDeauth && f.Subtype != SubtypeDisassoc {
		return 0, false
	}
	if len(f.Body) < 2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(f.Body[0:2]), true
}

// StatusCode returns the status field of an authentication or association response.
//
// Zero is success; anything else is the access point saying why it refused, and that number is
// the difference between "the association did not land" and a diagnosis. 43 is an invalid
// AKMP - the suite offered is not one the access point runs - and 40/41/42 are the cipher and
// key-management variants of the same mistake.
func (f *Frame) StatusCode() (uint16, bool) {
	fixed, _, ok := f.ManagementBody()
	if !ok {
		return 0, false
	}
	switch f.Subtype {
	case SubtypeAssocResp, SubtypeReassocResp:
		// capability(2) status(2) aid(2)
		if len(fixed) < 4 {
			return 0, false
		}
		return binary.LittleEndian.Uint16(fixed[2:4]), true
	case SubtypeAuth:
		// algorithm(2) sequence(2) status(2)
		if len(fixed) < 6 {
			return 0, false
		}
		return binary.LittleEndian.Uint16(fixed[4:6]), true
	}
	return 0, false
}

// StatusReason names an 802.11 status code (IEEE 802.11-2020 Table 9-50), for the codes that
// actually come back at a station trying to associate. Anything else is reported by number.
func StatusReason(code uint16) string {
	switch code {
	case 0:
		return "success"
	case 1:
		return "unspecified failure"
	case 10:
		return "capabilities in the request are unsupported"
	case 12:
		return "association denied for a reason outside the standard"
	case 13:
		return "authentication algorithm unsupported"
	case 14:
		return "authentication sequence out of order"
	case 15:
		return "authentication challenge failed"
	case 16:
		return "authentication timed out"
	case 17:
		return "the access point is at capacity"
	case 18:
		return "the basic rate set is unsupported"
	case 30:
		return "try again later - the access point is busy"
	case 31:
		return "management frame protection policy violation"
	case 33:
		return "insufficient bandwidth"
	case 40:
		return "invalid information element"
	case 41:
		return "invalid group cipher"
	case 42:
		return "invalid pairwise cipher"
	case 43:
		return "invalid AKMP - the key management suite offered is not one this access point runs"
	case 44:
		return "unsupported RSN version"
	case 45:
		return "invalid RSN capabilities"
	case 46:
		return "cipher suite rejected by policy"
	case 53:
		return "invalid PMKID"
	default:
		return fmt.Sprintf("status %d", code)
	}
}
