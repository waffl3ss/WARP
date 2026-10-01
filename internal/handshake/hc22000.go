package handshake

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// hashcat 22000 line formats:
//
//	WPA*01*PMKID*MAC_AP*MAC_STA*ESSID_HEX***
//	WPA*02*MIC*MAC_AP*MAC_STA*ESSID_HEX*ANONCE*EAPOL_FRAME*MESSAGEPAIR
//
// Fields are lowercase hex with no separators. The ESSID is hex-encoded because it is an
// octet string that may contain any byte, including the asterisk used as the field separator.

// Hash type prefixes.
const (
	typePMKID = "01"
	typeEAPOL = "02"
)

// MessagePair encodes which handshake messages produced a hash and where the EAPOL frame came
// from. hashcat uses it to decide how to verify, so a wrong value yields a hash that either
// fails to crack or is rejected outright.
//
// The naming is hcxtools': MxyEz means messages x and y were used and the EAPOL frame was
// taken from message z.
type MessagePair uint8

// Message pair base values.
const (
	// PairM12E2 is the common case: ANonce from M1, EAPOL and MIC from M2.
	PairM12E2 MessagePair = 0
	// PairM14E4 uses M1 for the ANonce and M4 for the EAPOL frame.
	PairM14E4 MessagePair = 1
	// PairM32E2 uses M3 for the ANonce and M2 for the EAPOL frame.
	PairM32E2 MessagePair = 2
	// PairM32E3 uses M3 for both the ANonce and the EAPOL frame.
	PairM32E3 MessagePair = 3
	// PairM34E3 uses M3 and M4, EAPOL from M3.
	PairM34E3 MessagePair = 4
	// PairM34E4 uses M3 and M4, EAPOL from M4.
	PairM34E4 MessagePair = 5
)

// Message pair flag bits, OR'd onto the base value.
const (
	// PairFlagAPLess marks a handshake obtained without a real AP present.
	PairFlagAPLess MessagePair = 0x10
	// PairFlagLE and PairFlagBE record an endianness assumption made about the nonce.
	PairFlagLE MessagePair = 0x20
	PairFlagBE MessagePair = 0x40
	// PairFlagNC tells hashcat that nonce correction may be required, because the messages
	// paired here did not share a replay counter and the nonce may have advanced.
	PairFlagNC MessagePair = 0x80
)

// String renders the message pair as the two hex digits the format expects.
func (m MessagePair) String() string { return fmt.Sprintf("%02x", uint8(m)) }

// Base returns the message pair without its flag bits.
func (m MessagePair) Base() MessagePair { return m & 0x0f }

// NonceCorrection reports whether the nonce-correction flag is set.
func (m MessagePair) NonceCorrection() bool { return m&PairFlagNC != 0 }

// Describe renders the pair for operator-facing output.
func (m MessagePair) Describe() string {
	var b strings.Builder
	switch m.Base() {
	case PairM12E2:
		b.WriteString("M1+M2")
	case PairM14E4:
		b.WriteString("M1+M4")
	case PairM32E2:
		b.WriteString("M3+M2")
	case PairM32E3:
		b.WriteString("M3+M2(e3)")
	case PairM34E3:
		b.WriteString("M3+M4(e3)")
	case PairM34E4:
		b.WriteString("M3+M4")
	default:
		fmt.Fprintf(&b, "pair-%d", uint8(m.Base()))
	}
	if m&PairFlagNC != 0 {
		b.WriteString("+nc")
	}
	if m&PairFlagAPLess != 0 {
		b.WriteString("+apless")
	}
	return b.String()
}

// PMKIDLine builds a WPA*01 hash line.
//
// It returns an error rather than a line for a zero PMKID: some APs pad the KDE with zeroes,
// and a zero PMKID cannot be cracked. Emitting it would send the rig on an impossible errand.
func PMKIDLine(pmkid []byte, ap, sta [6]byte, essid string) (string, error) {
	if len(pmkid) != 16 {
		return "", fmt.Errorf("handshake: PMKID must be 16 bytes, got %d", len(pmkid))
	}
	if allZero(pmkid) {
		return "", fmt.Errorf("handshake: refusing to emit a zero PMKID (not crackable)")
	}
	if err := validateESSID(essid); err != nil {
		return "", err
	}

	return strings.Join([]string{
		"WPA", typePMKID,
		hex.EncodeToString(pmkid),
		hex.EncodeToString(ap[:]),
		hex.EncodeToString(sta[:]),
		hex.EncodeToString([]byte(essid)),
		"", "", "",
	}, "*"), nil
}

// EAPOLLine builds a WPA*02 hash line.
//
// eapolFrame must already have its MIC field zeroed - see EAPOLKey.ZeroMIC. That is checked
// here rather than trusted, because an un-zeroed MIC produces a hash that hashcat accepts and
// can never crack, and the failure is invisible until the cracking rig has already run.
func EAPOLLine(mic []byte, ap, sta [6]byte, essid string, anonce, eapolFrame []byte, pair MessagePair) (string, error) {
	if len(mic) != micLen {
		return "", fmt.Errorf("handshake: MIC must be %d bytes, got %d", micLen, len(mic))
	}
	if len(anonce) != nonceLen {
		return "", fmt.Errorf("handshake: ANonce must be %d bytes, got %d", nonceLen, len(anonce))
	}
	if len(eapolFrame) < minEAPOLKeyLen {
		return "", fmt.Errorf("handshake: EAPOL frame is %d bytes, minimum is %d", len(eapolFrame), minEAPOLKeyLen)
	}
	if allZero(mic) {
		return "", fmt.Errorf("handshake: refusing to emit a zero MIC")
	}
	if allZero(anonce) {
		return "", fmt.Errorf("handshake: refusing to emit a zero ANonce")
	}
	if !allZero(eapolFrame[offKeyMIC : offKeyMIC+micLen]) {
		return "", fmt.Errorf("handshake: EAPOL frame still carries its MIC; it must be zeroed " +
			"or the resulting hash will never crack")
	}
	if err := validateESSID(essid); err != nil {
		return "", err
	}

	return strings.Join([]string{
		"WPA", typeEAPOL,
		hex.EncodeToString(mic),
		hex.EncodeToString(ap[:]),
		hex.EncodeToString(sta[:]),
		hex.EncodeToString([]byte(essid)),
		hex.EncodeToString(anonce),
		hex.EncodeToString(eapolFrame),
		pair.String(),
	}, "*"), nil
}

// maxESSIDLen is the 802.11 SSID element maximum.
const maxESSIDLen = 32

func validateESSID(essid string) error {
	if essid == "" {
		// A hash with no ESSID cannot be cracked: the ESSID is the PBKDF2 salt.
		return fmt.Errorf("handshake: refusing to emit a hash with no ESSID (it is the PBKDF2 salt)")
	}
	if len(essid) > maxESSIDLen {
		return fmt.Errorf("handshake: ESSID is %d octets, maximum is %d", len(essid), maxESSIDLen)
	}
	return nil
}

// ParseLine splits a 22000 line into its fields, for tests and for verifying files written
// earlier in an engagement.
func ParseLine(line string) (fields []string, err error) {
	f := strings.Split(strings.TrimSpace(line), "*")
	if len(f) != 9 {
		return nil, fmt.Errorf("handshake: expected 9 fields, got %d", len(f))
	}
	if f[0] != "WPA" {
		return nil, fmt.Errorf("handshake: line does not start with WPA")
	}
	if f[1] != typePMKID && f[1] != typeEAPOL {
		return nil, fmt.Errorf("handshake: unknown hash type %q", f[1])
	}
	return f, nil
}
