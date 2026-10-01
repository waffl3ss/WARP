package method

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// EAP codes (RFC 3748 section 4).
const (
	CodeRequest  = 1
	CodeResponse = 2
	CodeSuccess  = 3
	CodeFailure  = 4
)

// Type is an EAP method type.
type Type uint8

// EAP method types.
const (
	TypeIdentity     Type = 1
	TypeNotification Type = 2
	TypeNak          Type = 3
	TypeMD5Challenge Type = 4
	TypeGTC          Type = 6
	TypeTLS          Type = 13
	TypeTTLS         Type = 21
	TypePEAP         Type = 25
	TypeMSCHAPv2     Type = 26
	TypeExpanded     Type = 254
)

// String names the method for logs and findings.
func (t Type) String() string {
	switch t {
	case TypeIdentity:
		return "Identity"
	case TypeNotification:
		return "Notification"
	case TypeNak:
		return "Nak"
	case TypeMD5Challenge:
		return "MD5-Challenge"
	case TypeGTC:
		return "GTC"
	case TypeTLS:
		return "EAP-TLS"
	case TypeTTLS:
		return "EAP-TTLS"
	case TypePEAP:
		return "PEAP"
	case TypeMSCHAPv2:
		return "EAP-MSCHAPv2"
	case TypeExpanded:
		return "Expanded"
	default:
		return fmt.Sprintf("EAP-type-%d", uint8(t))
	}
}

// Packet is an EAP packet.
type Packet struct {
	Code       uint8
	Identifier uint8
	// Type and Data are meaningful for Request and Response only.
	Type Type
	Data []byte
}

// Errors returned when parsing EAP.
var (
	ErrShortEAP  = errors.New("method: EAP packet too short")
	ErrEAPLength = errors.New("method: EAP length field disagrees with the packet")
)

// eapHeaderLen is code(1) + identifier(1) + length(2).
const eapHeaderLen = 4

// ParsePacket decodes an EAP packet.
func ParsePacket(b []byte) (*Packet, error) {
	if len(b) < eapHeaderLen {
		return nil, ErrShortEAP
	}

	length := int(binary.BigEndian.Uint16(b[2:4]))
	if length < eapHeaderLen || length > len(b) {
		return nil, fmt.Errorf("%w: says %d, have %d", ErrEAPLength, length, len(b))
	}
	b = b[:length]

	p := &Packet{Code: b[0], Identifier: b[1]}
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		return p, nil
	}
	if length < eapHeaderLen+1 {
		return nil, ErrShortEAP
	}
	p.Type = Type(b[4])
	p.Data = b[5:]
	return p, nil
}

// Marshal encodes an EAP packet.
func (p *Packet) Marshal() []byte {
	if p.Code == CodeSuccess || p.Code == CodeFailure {
		out := make([]byte, eapHeaderLen)
		out[0], out[1] = p.Code, p.Identifier
		binary.BigEndian.PutUint16(out[2:4], eapHeaderLen)
		return out
	}

	out := make([]byte, eapHeaderLen+1+len(p.Data))
	out[0], out[1] = p.Code, p.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[4] = byte(p.Type)
	copy(out[5:], p.Data)
	return out
}

// Request builds an EAP Request.
func Request(id uint8, t Type, data []byte) *Packet {
	return &Packet{Code: CodeRequest, Identifier: id, Type: t, Data: data}
}

// Success builds an EAP Success.
func Success(id uint8) *Packet { return &Packet{Code: CodeSuccess, Identifier: id} }

// Failure builds an EAP Failure.
func Failure(id uint8) *Packet { return &Packet{Code: CodeFailure, Identifier: id} }

// NakTypes returns the method types a supplicant offered in a legacy Nak.
//
// A Nak is a refusal that names what the client would accept instead, so it is the single most
// informative packet in a negotiation: it enumerates exactly which methods the supplicant is
// configured for. Which methods a client accepts or rejects is itself a finding.
func NakTypes(p *Packet) []Type {
	if p == nil || p.Type != TypeNak {
		return nil
	}
	out := make([]Type, 0, len(p.Data))
	for _, b := range p.Data {
		if b != 0 {
			out = append(out, Type(b))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// TLS-based method framing (EAP-TLS, PEAP, EAP-TTLS)
// ---------------------------------------------------------------------------

// TLS method flag bits (RFC 5216 section 3.1).
const (
	// FlagLengthIncluded marks a packet carrying the total TLS message length.
	FlagLengthIncluded = 0x80
	// FlagMoreFragments marks a fragment that is not the last.
	FlagMoreFragments = 0x40
	// FlagStart begins the method.
	FlagStart = 0x20
	// FlagVersionMask holds the PEAP version in the low three bits.
	FlagVersionMask = 0x07
)

// PEAPVersion0 is the version essentially every supplicant speaks.
const PEAPVersion0 = 0

// TLSMessage is one parsed TLS-method packet.
type TLSMessage struct {
	Flags uint8
	// TotalLength is meaningful only when FlagLengthIncluded is set.
	TotalLength uint32
	Data        []byte
}

// LengthIncluded reports whether the total-length field was present.
func (m TLSMessage) LengthIncluded() bool { return m.Flags&FlagLengthIncluded != 0 }

// MoreFragments reports whether more fragments follow.
func (m TLSMessage) MoreFragments() bool { return m.Flags&FlagMoreFragments != 0 }

// Start reports whether this begins the method.
func (m TLSMessage) Start() bool { return m.Flags&FlagStart != 0 }

// Version returns the PEAP version from the flag byte.
func (m TLSMessage) Version() uint8 { return m.Flags & FlagVersionMask }

// IsACK reports whether this is a bare acknowledgment: no flags and no data.
//
// A peer sends one to acknowledge a fragment, and it carries no TLS bytes. Feeding an ACK's
// empty payload into the TLS state machine is a common way to corrupt a handshake.
func (m TLSMessage) IsACK() bool {
	return len(m.Data) == 0 && m.Flags&(FlagLengthIncluded|FlagMoreFragments|FlagStart) == 0
}

// ParseTLSMessage decodes the flags and payload of a TLS-method packet.
func ParseTLSMessage(data []byte) (TLSMessage, error) {
	if len(data) < 1 {
		return TLSMessage{}, errors.New("method: TLS method packet has no flag byte")
	}

	m := TLSMessage{Flags: data[0]}
	rest := data[1:]

	if m.LengthIncluded() {
		if len(rest) < 4 {
			return m, errors.New("method: TLS method packet claims a length field but is too short")
		}
		m.TotalLength = binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
	}
	m.Data = rest
	return m, nil
}

// BuildTLSMessage encodes a TLS-method payload.
func BuildTLSMessage(flags uint8, totalLength uint32, data []byte) []byte {
	out := make([]byte, 0, 5+len(data))
	out = append(out, flags)
	if flags&FlagLengthIncluded != 0 {
		out = binary.BigEndian.AppendUint32(out, totalLength)
	}
	return append(out, data...)
}

// Fragmenter splits an outbound TLS byte stream into EAP-sized fragments and reassembles
// inbound ones.
//
// The fragmentation protocol is where TLS-based EAP methods usually break: the first fragment
// carries the total length, every fragment but the last sets the more-fragments bit, and the
// peer acknowledges each one with an empty packet. A certificate chain is several kilobytes,
// so this path runs on every single authentication and cannot be skipped in testing.
type Fragmenter struct {
	// MaxFragment is the largest TLS payload per EAP packet. RADIUS attributes cap an
	// EAP-Message at 253 bytes each and a packet at 4096, so a conservative fragment size
	// keeps the assembled RADIUS packet well inside that.
	MaxFragment int

	pending   []byte
	sentTotal bool

	inbound     []byte
	inboundWant uint32
}

// DefaultMaxFragment is a conservative payload size that survives RADIUS attribute packing.
const DefaultMaxFragment = 1000

// NewFragmenter builds a fragmenter.
func NewFragmenter(max int) *Fragmenter {
	if max <= 0 {
		max = DefaultMaxFragment
	}
	return &Fragmenter{MaxFragment: max}
}

// Queue sets the outbound TLS bytes to be fragmented.
func (f *Fragmenter) Queue(b []byte) {
	f.pending = b
	f.sentTotal = false
}

// Pending reports whether outbound bytes remain.
func (f *Fragmenter) Pending() bool { return len(f.pending) > 0 }

// Next returns the next outbound fragment payload, ready to be wrapped in an EAP packet.
func (f *Fragmenter) Next(version uint8) []byte {
	if len(f.pending) == 0 {
		return nil
	}

	total := len(f.pending)
	chunk := f.pending
	more := false
	if len(chunk) > f.MaxFragment {
		chunk = chunk[:f.MaxFragment]
		more = true
	}
	f.pending = f.pending[len(chunk):]

	flags := version & FlagVersionMask
	if more {
		flags |= FlagMoreFragments
	}
	// The total length is sent once, on the first fragment of a message, and only when the
	// message is actually fragmented - sending it on an unfragmented message is legal but
	// upsets a few supplicants.
	if !f.sentTotal && more {
		flags |= FlagLengthIncluded
		f.sentTotal = true
		return BuildTLSMessage(flags, uint32(total), chunk)
	}
	return BuildTLSMessage(flags, 0, chunk)
}

// Accept folds an inbound message into the reassembly buffer.
//
// It returns the complete TLS byte stream once the final fragment arrives, and nil while more
// are expected.
func (f *Fragmenter) Accept(m TLSMessage) ([]byte, bool) {
	if m.LengthIncluded() {
		f.inboundWant = m.TotalLength
		f.inbound = f.inbound[:0]
	}
	f.inbound = append(f.inbound, m.Data...)

	if m.MoreFragments() {
		return nil, false
	}

	out := f.inbound
	f.inbound = nil
	f.inboundWant = 0
	return out, true
}

// NeedsACK reports whether an inbound fragment should be acknowledged with an empty packet.
func NeedsACK(m TLSMessage) bool { return m.MoreFragments() }

// ACK builds the empty acknowledgment for a fragment.
func ACK(version uint8) []byte { return BuildTLSMessage(version&FlagVersionMask, 0, nil) }
