package method

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildAVP assembles one Diameter AVP the way a supplicant does, so the parser is tested against the
// bytes it will actually see (header, optional vendor id, 4-byte padding).
func buildAVP(vendor, code uint32, data []byte) []byte {
	hdr := 8
	var flags byte
	if vendor != 0 {
		flags = 0x80
		hdr = 12
	}
	length := hdr + len(data)
	b := make([]byte, length)
	binary.BigEndian.PutUint32(b[0:4], code)
	b[4] = flags
	b[5], b[6], b[7] = byte(length>>16), byte(length>>8), byte(length)
	if vendor != 0 {
		binary.BigEndian.PutUint32(b[8:12], vendor)
	}
	copy(b[hdr:], data)
	if pad := (4 - length%4) % 4; pad > 0 {
		b = append(b, make([]byte, pad)...)
	}
	return b
}

// TestParseAVPsPAP: a TTLS-PAP Phase-2 payload yields the username and the cleartext password, with
// the NUL padding TTLS applies stripped.
func TestParseAVPsPAP(t *testing.T) {
	pw := append([]byte("s3cret!"), make([]byte, 9)...) // padded to a 16-byte boundary
	payload := append(buildAVP(0, avpUserName, []byte("alice")), buildAVP(0, avpUserPassword, pw)...)

	avps := parseAVPs(payload)
	if got := string(findAVP(avps, 0, avpUserName)); got != "alice" {
		t.Errorf("User-Name = %q, want alice", got)
	}
	if got := string(trimTrailingNUL(findAVP(avps, 0, avpUserPassword))); got != "s3cret!" {
		t.Errorf("User-Password = %q, want s3cret!", got)
	}
}

// TestParseAVPsVendorIsolation: a vendor AVP is matched only by a vendor-qualified lookup, never by a
// bare code lookup (so an MS-CHAP AVP is never mistaken for a standard attribute of the same number).
func TestParseAVPsVendor(t *testing.T) {
	resp := make([]byte, mschap2ResponseLen)
	for i := range resp {
		resp[i] = byte(i + 1)
	}
	avps := parseAVPs(buildAVP(vendorMicrosoft, avpMSCHAP2Response, resp))

	if got := findAVP(avps, vendorMicrosoft, avpMSCHAP2Response); len(got) != mschap2ResponseLen {
		t.Fatalf("MS-CHAP2-Response len = %d, want %d", len(got), mschap2ResponseLen)
	}
	if findAVP(avps, 0, avpMSCHAP2Response) != nil {
		t.Error("a vendor AVP was matched by a non-vendor lookup")
	}
}

// TestParseAVPsStopsOnMalformed: a bogus length halts the walk without panicking, keeping what was
// read before it (invariant: a partial parse keeps the good part, discards nothing valid).
func TestParseAVPsStopsOnMalformed(t *testing.T) {
	good := buildAVP(0, avpUserName, []byte("bob"))
	bad := []byte{0, 0, 0, 2, 0, 0xff, 0xff, 0xff} // length far past the buffer
	avps := parseAVPs(append(good, bad...))
	if got := string(findAVP(avps, 0, avpUserName)); got != "bob" {
		t.Errorf("User-Name = %q, want bob (the good AVP before the malformed one)", got)
	}
}

// TestTTLSMSCHAPv2Line: the MS-CHAP AVPs map onto a hashcat -m 5500 line, and bad inputs refuse
// rather than emit a line that can never crack.
func TestTTLSMSCHAPv2Line(t *testing.T) {
	chal := make([]byte, AuthenticatorChallengeLen)
	for i := range chal {
		chal[i] = byte(i)
	}
	resp := make([]byte, mschap2ResponseLen)
	for i := 26; i < 50; i++ { // a non-zero NT-Response (HashcatLine refuses an all-zero one)
		resp[i] = byte(i)
	}

	line, ok := ttlsMSCHAPv2Line("alice", chal, resp)
	if !ok {
		t.Fatal("expected a 5500 line from valid MS-CHAP AVPs")
	}
	if !strings.HasPrefix(line, "alice::::") {
		t.Errorf("line = %q, want it to start alice::::", line)
	}
	if _, ok := ttlsMSCHAPv2Line("alice", chal[:8], resp); ok {
		t.Error("a short challenge should not emit a line")
	}
	if _, ok := ttlsMSCHAPv2Line("", chal, resp); ok {
		t.Error("an empty username should not emit a line")
	}
	if _, ok := ttlsMSCHAPv2Line("alice", chal, make([]byte, mschap2ResponseLen)); ok {
		t.Error("an all-zero NT-Response should not emit a line")
	}
}
