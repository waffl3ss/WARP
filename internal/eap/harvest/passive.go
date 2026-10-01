package harvest

import (
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"github.com/waffl3ss/warp/internal/eap/method"
)

// Passive certificate harvesting: reading the server certificate out of an EAP-TLS exchange
// WARP merely *overhears*, rather than one it associates to provoke.
//
// # Why this is the right way to do it
//
// The certificate a RADIUS server presents is sent in the clear, in the first flight of the
// TLS handshake, before any tunnel exists. It is identical whether WARP asks for it or a real
// client does - so if any client on the network authenticates while WARP is listening on the
// right channel, the certificate is right there in the capture. No association, no injected
// frames, no dependency on the adapter acknowledging anything: exactly what makes it work when
// injecting an association does not.
//
// This is what an operator does by hand in Wireshark - filter for `tls.handshake.type == 11`,
// export the certificate - and it is what this does automatically on the capture path. When
// there is no client to wait for, a broadcast deauthentication provokes one to reconnect and
// re-authenticate, and the certificate arrives on the reconnect.
//
// # The reassembly
//
// The server's half of the handshake is fragmented twice over. TLS itself splits a large
// Certificate message across records; EAP-TLS then splits those bytes across EAP-Request
// packets, each carrying a fragment with more-fragments and length flags. So the path is:
//
//	EAP-Request (server) → TLS-method fragment → concatenate → TLS record stream
//	→ reassemble handshake messages → find Certificate (handshake type 11) → DER chain
//
// Only the server's fragments (EAP-Request, code 1) carry the certificate; the client's
// (EAP-Response, code 2) are its ClientHello and key exchange and are ignored.

// certAssembler reassembles one station's view of a server's TLS handshake and yields the
// certificate chain the moment the Certificate message is complete.
// Assembler reassembles one access point's server certificate from the EAP-TLS fragments seen
// passively on the capture path. Zero value is ready.
type Assembler struct {
	// stream is the concatenated TLS record bytes from the server's EAP-TLS fragments.
	stream []byte
	// done is set once a certificate chain has been extracted, so later fragments of the same
	// exchange are ignored rather than reparsed.
	done bool
}

// feed adds one server EAP packet and returns the DER chain once the Certificate message has
// been fully reassembled.
//
// eap is the parsed EAP packet; it must be an EAP-Request (from the access point) of a
// TLS-based method (PEAP, TTLS or EAP-TLS). Anything else is ignored.
// Feed adds one EAP packet observed on the wire and returns the DER chain once the server's
// Certificate message has been fully reassembled.
func (a *Assembler) Feed(eap *method.Packet) ([][]byte, bool) {
	if a.done || eap == nil || eap.Code != method.CodeRequest {
		return nil, false
	}
	switch eap.Type {
	case method.TypePEAP, method.TypeTTLS, method.TypeTLS:
	default:
		return nil, false
	}

	msg, err := method.ParseTLSMessage(eap.Data)
	if err != nil || msg.IsACK() {
		return nil, false
	}
	// A Start packet carries no TLS bytes; it only signals the method beginning.
	if len(msg.Data) == 0 {
		return nil, false
	}

	a.stream = append(a.stream, msg.Data...)

	// Try to extract after every fragment rather than waiting for a length that a malformed or
	// truncated capture may never complete: the Certificate message often lands before the
	// whole handshake does, and getting it early is the point.
	ders, ok := certificatesFromTLSStream(a.stream)
	if ok {
		a.done = true
		return ders, true
	}
	return nil, false
}

// TLS record and handshake constants.
const (
	tlsRecordHandshake  = 22
	tlsHandshakeCert    = 11
	tlsRecordHeaderLen  = 5
	tlsHandshakeHdrLen  = 4
	maxReasonableCert   = 1 << 20 // 1 MiB: a certificate larger than this is a parser going wrong
	maxReasonableStream = 1 << 22 // stop accumulating a stream that is clearly not a handshake
)

// certificatesFromTLSStream walks a reassembled TLS record stream, concatenates the handshake
// messages, and returns the DER chain from the first Certificate message.
//
// It reassembles handshake messages across record boundaries - a Certificate message routinely
// spans several TLS records - and stops at the first complete Certificate. Returns ok=false
// while the Certificate message has not yet fully arrived, so the caller keeps feeding.
func certificatesFromTLSStream(stream []byte) ([][]byte, bool) {
	if len(stream) > maxReasonableStream {
		return nil, false
	}

	// Concatenate the payloads of every handshake record. A ChangeCipherSpec or Alert record
	// in between would end the cleartext handshake, but the Certificate arrives before either.
	var handshake []byte
	for off := 0; off+tlsRecordHeaderLen <= len(stream); {
		typ := stream[off]
		length := int(binary.BigEndian.Uint16(stream[off+3 : off+5]))
		end := off + tlsRecordHeaderLen + length
		if length == 0 || end > len(stream) {
			break // record truncated in the capture; use what came before
		}
		if typ == tlsRecordHandshake {
			handshake = append(handshake, stream[off+tlsRecordHeaderLen:end]...)
		}
		off = end
	}

	// Walk the reassembled handshake messages looking for Certificate.
	for off := 0; off+tlsHandshakeHdrLen <= len(handshake); {
		msgType := handshake[off]
		msgLen := int(handshake[off+1])<<16 | int(handshake[off+2])<<8 | int(handshake[off+3])
		end := off + tlsHandshakeHdrLen + msgLen
		if end > len(handshake) {
			return nil, false // the message is still arriving
		}
		if msgType == tlsHandshakeCert {
			return parseCertificateMessage(handshake[off+tlsHandshakeHdrLen : end])
		}
		off = end
	}
	return nil, false
}

// parseCertificateMessage extracts the DER certificates from a TLS Certificate handshake body.
//
// Layout: a 3-byte total length, then for each certificate a 3-byte length and that many DER
// bytes, leaf first.
func parseCertificateMessage(body []byte) ([][]byte, bool) {
	if len(body) < 3 {
		return nil, false
	}
	total := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	body = body[3:]
	if total > len(body) {
		return nil, false // still arriving
	}
	body = body[:total]

	var ders [][]byte
	for len(body) >= 3 {
		clen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
		body = body[3:]
		if clen == 0 || clen > maxReasonableCert || clen > len(body) {
			break
		}
		ders = append(ders, append([]byte(nil), body[:clen]...))
		body = body[clen:]
	}
	if len(ders) == 0 {
		return nil, false
	}
	return ders, true
}

// FromCapturedCertificates builds a Result from DER certificates lifted off the wire.
//
// The counterpart to FromConnectionState for the passive path, where there is no
// tls.ConnectionState - only the raw certificate bytes reassembled from the capture. The same
// per-certificate extraction runs, so a passively-harvested certificate and a live-harvested
// one produce identical records.
func FromCapturedCertificates(essid, bssid string, ders [][]byte) (*Result, error) {
	if len(ders) == 0 {
		return nil, ErrNoCertificate
	}

	certs := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			// Keep the ones that parse: a trailing malformed entry must not discard the leaf.
			continue
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("harvest: %d certificate(s) captured but none parsed", len(ders))
	}

	res := resultFromCerts(essid, bssid, certs)
	res.Notes = append(res.Notes,
		"captured passively from a client's authentication - no association, no injected frames")
	return res, nil
}

// EAPFromEAPOL extracts the EAP packet from an 802.1X payload, or reports that the payload is
// not an EAP-Packet.
//
// The 802.1X payload is version(1), type(1), length(2), body. Type 0 is EAP-Packet, the only
// one that carries the certificate; EAPOL-Key (type 3, the WPA handshake) and the rest are not
// this path's concern.
func EAPFromEAPOL(payload []byte) (*method.Packet, bool) {
	if len(payload) < 4 || payload[1] != 0x00 {
		return nil, false
	}
	n := int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if n > 0 && n <= len(body) {
		body = body[:n]
	}
	eap, err := method.ParsePacket(body)
	if err != nil {
		return nil, false
	}
	return eap, true
}
