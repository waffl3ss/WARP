package method

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// RFC 2759 section 9.2 worked example. These exact values are the reason to trust this
// implementation: they are the only independent check available that the challenge derivation
// and the response computation are right.
var rfc2759 = struct {
	username               string
	password               string
	authenticatorChallenge string
	peerChallenge          string
	derivedChallenge       string
	ntResponse             string
}{
	username:               "User",
	password:               "clientPass",
	authenticatorChallenge: "5B5D7C7D7B3F2F3E3C2C602132262628",
	peerChallenge:          "21402324255E262A28295F2B3A337C7E",
	derivedChallenge:       "D02E4386BCE91226",
	ntResponse:             "82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF",
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

// TestChallengeHashRFC2759 is the vector that matters. Emitting the raw 16-byte authenticator
// challenge instead of this derived 8-byte value produces a hash hashcat accepts and can never
// crack.
func TestChallengeHashRFC2759(t *testing.T) {
	var peer [PeerChallengeLen]byte
	var auth [AuthenticatorChallengeLen]byte
	copy(peer[:], mustHex(t, rfc2759.peerChallenge))
	copy(auth[:], mustHex(t, rfc2759.authenticatorChallenge))

	got := ChallengeHash(peer, auth, rfc2759.username)
	want := mustHex(t, rfc2759.derivedChallenge)

	if !bytes.Equal(got[:], want) {
		t.Fatalf("ChallengeHash = %X, want %s (RFC 2759 §9.2)", got, rfc2759.derivedChallenge)
	}
}

func TestNTPasswordHashRFC2759(t *testing.T) {
	// RFC 2759 §9.2: NtPasswordHash("clientPass")
	const want = "44EBBA8D5312B8D611474411F56989AE"

	got := NTPasswordHash(rfc2759.password)
	if hex.EncodeToString(got[:]) != strings.ToLower(want) {
		t.Fatalf("NTPasswordHash = %X, want %s", got, want)
	}
}

func TestGenerateNTResponseRFC2759(t *testing.T) {
	var peer [PeerChallengeLen]byte
	var auth [AuthenticatorChallengeLen]byte
	copy(peer[:], mustHex(t, rfc2759.peerChallenge))
	copy(auth[:], mustHex(t, rfc2759.authenticatorChallenge))

	got := GenerateNTResponse(auth, peer, rfc2759.username, rfc2759.password)

	want := mustHex(t, rfc2759.ntResponse)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("GenerateNTResponse = %X\n                want %X", got, want)
	}
}

// TestHashcatLineFormat pins the -m 5500 layout.
func TestHashcatLineFormat(t *testing.T) {
	var peer [PeerChallengeLen]byte
	var auth [AuthenticatorChallengeLen]byte
	copy(peer[:], mustHex(t, rfc2759.peerChallenge))
	copy(auth[:], mustHex(t, rfc2759.authenticatorChallenge))

	var ntr [NTResponseLen]byte
	copy(ntr[:], mustHex(t, rfc2759.ntResponse))

	c := Credential{
		Username:               rfc2759.username,
		AuthenticatorChallenge: auth,
		PeerChallenge:          peer,
		NTResponse:             ntr,
	}

	line, err := c.HashcatLine()
	if err != nil {
		t.Fatalf("HashcatLine: %v", err)
	}

	// `username::::response:challenge` carries five colons, so six fields: the name, three
	// empty ones, the response and the challenge.
	parts := strings.Split(line, ":")
	if len(parts) != 6 {
		t.Fatalf("got %d colon-separated fields, want 6: %q", len(parts), line)
	}
	if parts[0] != "User" {
		t.Errorf("username field = %q", parts[0])
	}
	for i := 1; i <= 3; i++ {
		if parts[i] != "" {
			t.Errorf("field %d should be empty, got %q", i, parts[i])
		}
	}
	if got := strings.ToUpper(parts[4]); got != rfc2759.ntResponse {
		t.Errorf("response field = %s, want %s", got, rfc2759.ntResponse)
	}
	// The challenge field must be the DERIVED 8-byte value, not the 16-byte authenticator
	// challenge. This is the assertion that stops uncrackable hashes reaching the rig.
	if got := strings.ToUpper(parts[5]); got != rfc2759.derivedChallenge {
		t.Errorf("challenge field = %s, want the derived %s", got, rfc2759.derivedChallenge)
	}
	if len(parts[5]) != DerivedChallengeLen*2 {
		t.Errorf("challenge field is %d hex chars, want %d — the raw authenticator challenge "+
			"was emitted instead of the derived one", len(parts[5]), DerivedChallengeLen*2)
	}
}

func TestHashcatLineRejectsBadCredentials(t *testing.T) {
	var ntr [NTResponseLen]byte
	copy(ntr[:], mustHex(t, rfc2759.ntResponse))

	tests := []struct {
		name string
		c    Credential
	}{
		{"no username", Credential{NTResponse: ntr}},
		{"zero NT response", Credential{Username: "alice"}},
		{"username contains the separator", Credential{Username: "co:rp", NTResponse: ntr}},
		{"username contains a newline", Credential{Username: "a\nb", NTResponse: ntr}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.c.HashcatLine(); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestDomainPrefixIsStrippedForTheHash: RFC 2759 hashes the bare account name. Hashing
// "CORP\alice" produces a challenge that will not crack.
func TestDomainPrefixIsStrippedForTheHash(t *testing.T) {
	var peer [PeerChallengeLen]byte
	var auth [AuthenticatorChallengeLen]byte
	copy(peer[:], mustHex(t, rfc2759.peerChallenge))
	copy(auth[:], mustHex(t, rfc2759.authenticatorChallenge))

	bare := ChallengeHash(peer, auth, "User")
	qualified := ChallengeHash(peer, auth, `CORP\User`)

	if !bytes.Equal(bare[:], qualified[:]) {
		t.Errorf("domain prefix changed the challenge: %X vs %X — the prefix must be stripped",
			bare, qualified)
	}

	// A different account name must still produce a different challenge.
	other := ChallengeHash(peer, auth, "Other")
	if bytes.Equal(bare[:], other[:]) {
		t.Error("different usernames produced the same challenge")
	}
}

// TestRoundTripDerivation: build a response from a known password, then confirm the derived
// challenge in the emitted line is the one that response was computed against. This is the
// self-consistency half of the proof; the other half is cracking it with real hashcat in CI.
func TestRoundTripDerivation(t *testing.T) {
	var peer [PeerChallengeLen]byte
	var auth [AuthenticatorChallengeLen]byte
	copy(peer[:], mustHex(t, "0102030405060708090A0B0C0D0E0F10"))
	copy(auth[:], mustHex(t, "101112131415161718191A1B1C1D1E1F"))

	const username, password = "alice", "Winter2026!"

	c := Credential{
		Username:               username,
		AuthenticatorChallenge: auth,
		PeerChallenge:          peer,
		NTResponse:             GenerateNTResponse(auth, peer, username, password),
	}

	line, err := c.HashcatLine()
	if err != nil {
		t.Fatalf("HashcatLine: %v", err)
	}
	parts := strings.Split(line, ":")

	wantChallenge := ChallengeHash(peer, auth, username)
	gotChallenge := mustHex(t, parts[5])
	if !bytes.Equal(gotChallenge, wantChallenge[:]) {
		t.Fatal("the emitted challenge is not the one the response was computed against")
	}

	// And the response recomputes from that challenge and the password hash.
	recomputed := challengeResponse(wantChallenge, NTPasswordHash(password))
	if !bytes.Equal(recomputed[:], c.NTResponse[:]) {
		t.Fatal("response does not recompute from the derived challenge")
	}
}

// ---------------------------------------------------------------------------
// Packet parsing
// ---------------------------------------------------------------------------

func TestBuildAndParseChallenge(t *testing.T) {
	var auth [AuthenticatorChallengeLen]byte
	copy(auth[:], mustHex(t, rfc2759.authenticatorChallenge))

	packet := BuildChallenge(7, auth, "warp")
	if packet[0] != OpChallenge {
		t.Fatalf("opcode = %d, want %d", packet[0], OpChallenge)
	}

	id, got, name, err := ParseChallenge(packet[1:])
	if err != nil {
		t.Fatalf("ParseChallenge: %v", err)
	}
	if id != 7 {
		t.Errorf("id = %d, want 7", id)
	}
	if !bytes.Equal(got[:], auth[:]) {
		t.Errorf("challenge = %X", got)
	}
	if name != "warp" {
		t.Errorf("name = %q", name)
	}
}

func TestParseResponse(t *testing.T) {
	var peer [PeerChallengeLen]byte
	var ntr [NTResponseLen]byte
	copy(peer[:], mustHex(t, rfc2759.peerChallenge))
	copy(ntr[:], mustHex(t, rfc2759.ntResponse))

	// identifier(1) length(2) value-size(1) peer(16) reserved(8) response(24) flags(1) name
	body := []byte{0x09, 0x00, 0x00, 49}
	body = append(body, peer[:]...)
	body = append(body, make([]byte, 8)...)
	body = append(body, ntr[:]...)
	body = append(body, 0x00)
	body = append(body, "alice"...)

	c, err := ParseResponse(body)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if c.Username != "alice" {
		t.Errorf("Username = %q", c.Username)
	}
	if !bytes.Equal(c.PeerChallenge[:], peer[:]) {
		t.Errorf("PeerChallenge = %X", c.PeerChallenge)
	}
	if !bytes.Equal(c.NTResponse[:], ntr[:]) {
		t.Errorf("NTResponse = %X", c.NTResponse)
	}
}

func TestParseResponseRejectsMalformed(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"empty", nil},
		{"too short", []byte{1, 2, 3}},
		{"wrong value size", append([]byte{0x09, 0, 0, 20}, make([]byte, 60)...)},
		{"truncated value", []byte{0x09, 0, 0, 49, 0x01, 0x02}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseResponse(tc.body); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestBuildFailure(t *testing.T) {
	packet := BuildFailure(3, "")
	if packet[0] != OpFailure {
		t.Fatalf("opcode = %d, want %d", packet[0], OpFailure)
	}
	if packet[1] != 3 {
		t.Errorf("id = %d, want 3", packet[1])
	}
	// R=0 tells the client not to retry, so it gives up cleanly instead of looping.
	if !strings.Contains(string(packet), "R=0") {
		t.Errorf("failure message should set R=0: %q", packet[4:])
	}
}

// TestDESKeyExpansion checks the structural properties of the 7→8 byte expansion.
//
// There is deliberately no hardcoded expected key here: RFC 2759 does not publish a worked
// example for this step, and inventing one would test the fixture rather than the code. The
// expansion's correctness is established end-to-end by TestGenerateNTResponseRFC2759 — the
// RFC's NT-Response cannot be reproduced unless all three DES keys are derived correctly.
func TestDESKeyExpansion(t *testing.T) {
	got := desKeyFromBytes(mustHex(t, "FC156AF7EDCD6C"))

	// The low bit of every byte is the parity slot, vacated by the final left shift.
	for i, b := range got {
		if b&0x01 != 0 {
			t.Errorf("byte %d = %#02x has its parity bit set", i, b)
		}
	}

	// The expansion must be injective over the inputs it sees: two different 7-byte chunks
	// producing the same DES key would silently collapse distinct password hashes.
	other := desKeyFromBytes(mustHex(t, "FC156AF7EDCD6D"))
	if bytes.Equal(got[:], other[:]) {
		t.Error("two different 7-byte inputs produced the same DES key")
	}

	// A run of zero bytes expands to a zero key, which is the one case where an off-by-one in
	// the bit packing would go unnoticed by the injectivity check above.
	if zero := desKeyFromBytes(make([]byte, 7)); !bytes.Equal(zero[:], make([]byte, 8)) {
		t.Errorf("zero input expanded to %X, want a zero key", zero)
	}
}
