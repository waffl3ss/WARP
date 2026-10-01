// Package inject builds and transmits 802.11 frames.
//
// Everything in this package puts energy in the air, so every transmit path is gated on
// internal/scope. There is no unguarded send: the injector itself refuses to construct a
// session without a gate, so a new attack module cannot accidentally skip authorization.
package inject

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/waffl3ss/warp/internal/recon"
)

// Radiotap transmit header.
//
// A bare 8-byte header with an empty present bitmap tells the driver "use your defaults",
// which is what we want: rate and power selection belong to the driver, and overriding them
// is a common source of injection that silently does not leave the card.
var radiotapTX = []byte{
	0x00,       // version
	0x00,       // pad
	0x08, 0x00, // length = 8, little-endian
	0x00, 0x00, 0x00, 0x00, // present bitmap: no fields
}

// Frame control subtypes used here, pre-shifted into the first frame-control octet.
const (
	fcAssocReq byte = 0x00
	fcProbeReq byte = 0x40
	fcAuth     byte = 0xB0
	fcDeauth   byte = 0xC0
	fcDisassoc byte = 0xA0
	// fcData is a plain data frame, subtype 0. It carries the 802.1X exchange.
	fcData byte = 0x08
)

// 802.1X (EAPOL) header fields.
const (
	// eapolVersion 1 rather than 2: it is what every deployed supplicant sends, and some
	// access points are stricter about the version than the standard requires.
	eapolVersion    byte = 0x01
	eapolTypeEAP    byte = 0x00
	eapolTypeStart  byte = 0x01
	eapolTypeLogoff byte = 0x02
)

// Reason codes (IEEE 802.11-2020 Table 9-49).
const (
	// ReasonUnspecified is the least informative and most widely honoured reason.
	ReasonUnspecified uint16 = 1
	// ReasonLeavingESS is sent by a station that is disassociating deliberately.
	ReasonLeavingESS uint16 = 3
	// ReasonClass3FromNonAssoc is what an AP sends to a station it does not recognise, and is
	// the most reliable trigger for a client to reauthenticate.
	ReasonClass3FromNonAssoc uint16 = 7
)

// Authentication algorithms.
const (
	authOpenSystem uint16 = 0
)

// buildHeader assembles a 24-byte management frame header.
func buildHeader(subtype byte, addr1, addr2, addr3 recon.MAC, seq uint16) []byte {
	h := make([]byte, 0, 24)
	h = append(h, subtype, 0x00) // frame control
	h = append(h, 0x00, 0x00)    // duration
	h = append(h, addr1[:]...)   // destination / receiver
	h = append(h, addr2[:]...)   // source / transmitter
	h = append(h, addr3[:]...)   // BSSID
	h = binary.LittleEndian.AppendUint16(h, seq<<4)
	return h
}

func appendIE(b []byte, id uint8, data []byte) []byte {
	b = append(b, id, byte(len(data)))
	return append(b, data...)
}

// defaultRates is a conservative 2.4 GHz rate set. Advertising rates an AP does not support
// gets an association rejected for reasons that look like a bug in the tool.
var defaultRates = []byte{0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24}

var extendedRates = []byte{0x30, 0x48, 0x60, 0x6c}

// AuthFrame builds an open-system authentication request.
//
// Open system authentication is a formality that predates any real security, but APs still
// require it before they will accept an association, and PMKID solicitation needs an
// association.
func AuthFrame(bssid, sta recon.MAC, seq uint16) []byte {
	f := buildHeader(fcAuth, bssid, sta, bssid, seq)
	f = binary.LittleEndian.AppendUint16(f, authOpenSystem)
	f = binary.LittleEndian.AppendUint16(f, 1) // transaction sequence 1
	f = binary.LittleEndian.AppendUint16(f, 0) // status: success
	return withRadiotap(f)
}

// AssocRequestOptions describes the association request to build.
type AssocRequestOptions struct {
	BSSID recon.MAC
	STA   recon.MAC
	ESSID string
	Seq   uint16
	// RSN is the RSN element body to advertise, without the element header. It should mirror
	// what the AP advertises: an association offering a cipher suite the AP does not support
	// is rejected, and the rejection looks like a tool bug rather than a configuration
	// mismatch.
	RSN []byte
}

// AssocRequestFrame builds an association request.
//
// This is what elicits the EAPOL M1 carrying a PMKID - the single largest time saver
// available, because it converts "wait for a client to reassociate" into "walk past the AP".
func AssocRequestFrame(o AssocRequestOptions) ([]byte, error) {
	if o.ESSID == "" {
		return nil, fmt.Errorf("inject: association request needs an ESSID")
	}
	if len(o.ESSID) > 32 {
		return nil, fmt.Errorf("inject: ESSID is %d octets, maximum is 32", len(o.ESSID))
	}

	f := buildHeader(fcAssocReq, o.BSSID, o.STA, o.BSSID, o.Seq)

	// Capability: ESS, privacy, short preamble, short slot time.
	f = binary.LittleEndian.AppendUint16(f, 0x0431)
	f = binary.LittleEndian.AppendUint16(f, 3) // listen interval

	f = appendIE(f, recon.IESSID, []byte(o.ESSID))
	f = appendIE(f, recon.IESupportedRates, defaultRates)
	f = appendIE(f, recon.IEExtendedRates, extendedRates)
	if len(o.RSN) > 0 {
		f = appendIE(f, recon.IERSN, o.RSN)
	}

	return withRadiotap(f), nil
}

// DefaultRSN is a minimal RSN element body advertising CCMP-128 with PSK, which is what the
// overwhelming majority of PSK networks run.
func DefaultRSN() []byte {
	b := []byte{0x01, 0x00}                         // version 1
	b = append(b, 0x00, 0x0F, 0xAC, 0x04)           // group cipher: CCMP-128
	b = binary.LittleEndian.AppendUint16(b, 1)      // pairwise count
	b = append(b, 0x00, 0x0F, 0xAC, 0x04)           // pairwise: CCMP-128
	b = binary.LittleEndian.AppendUint16(b, 1)      // AKM count
	b = append(b, 0x00, 0x0F, 0xAC, 0x02)           // AKM: PSK
	b = binary.LittleEndian.AppendUint16(b, 0x0000) // capabilities
	return b
}

// EnterpriseRSN is an RSN element body advertising CCMP-128 with 802.1X.
//
// The enterprise counterpart to DefaultRSN. Associating to a WPA-Enterprise access point with
// a PSK AKM in the request gets the association rejected with an invalid-AKMP status, which
// looks like a bug in the tool rather than the mismatch it is.
func EnterpriseRSN() []byte {
	b := []byte{0x01, 0x00}                         // version 1
	b = append(b, 0x00, 0x0F, 0xAC, 0x04)           // group cipher: CCMP-128
	b = binary.LittleEndian.AppendUint16(b, 1)      // pairwise count
	b = append(b, 0x00, 0x0F, 0xAC, 0x04)           // pairwise: CCMP-128
	b = binary.LittleEndian.AppendUint16(b, 1)      // AKM count
	b = append(b, 0x00, 0x0F, 0xAC, 0x01)           // AKM: 802.1X
	b = binary.LittleEndian.AppendUint16(b, 0x0000) // capabilities
	return b
}

// llcSNAPEAPOL is the LLC/SNAP header that precedes an 802.1X payload in a data frame. It
// mirrors the constant the capture path matches on, from the transmitting side.
var llcSNAPEAPOL = []byte{0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E}

// EAPOLFrame builds a data frame carrying an 802.1X payload from a station to its access
// point.
//
// This is the transmit half of the exchange the capture path has always been able to read.
// It is what makes certificate harvesting possible without a supplicant: WARP associates from
// a station of its own, answers the access point's EAP identity request, and reads the
// certificate the RADIUS server presents - then drops the exchange before anything is
// authenticated.
//
// ToDS is set and FromDS clear, which is an uplink frame: addr1 is the BSSID, addr2 the
// station, addr3 the destination. Unprotected: the exchange happens before any key is
// installed, which is exactly why the certificate is readable at all.
func EAPOLFrame(bssid, sta recon.MAC, payload []byte, seq uint16) []byte {
	f := make([]byte, 0, 24+len(llcSNAPEAPOL)+len(payload))
	f = append(f, fcData, 0x01) // frame control: data, ToDS
	f = append(f, 0x00, 0x00)   // duration
	f = append(f, bssid[:]...)  // addr1: receiver (the AP)
	f = append(f, sta[:]...)    // addr2: transmitter (us)
	f = append(f, bssid[:]...)  // addr3: destination
	f = binary.LittleEndian.AppendUint16(f, seq<<4)

	f = append(f, llcSNAPEAPOL...)
	f = append(f, payload...)
	return withRadiotap(f)
}

// EAPOLStart builds the 802.1X EAPOL-Start payload.
//
// Most access points send EAP-Request/Identity unprompted on association, but not all do, and
// one that is waiting will wait indefinitely. Sending Start costs one frame and removes a
// failure mode that looks identical to "the network is not enterprise".
func EAPOLStart() []byte {
	return []byte{eapolVersion, eapolTypeStart, 0x00, 0x00}
}

// EAPOLLogoff builds the 802.1X EAPOL-Logoff payload.
//
// Sent when a harvest finishes. The certificate has been read and nothing else is wanted, so
// the exchange is ended explicitly rather than left for the access point's session timer to
// clean up - a dangling half-authenticated session on a production RADIUS server is noise the
// client's own team has to explain later.
func EAPOLLogoff() []byte {
	return []byte{eapolVersion, eapolTypeLogoff, 0x00, 0x00}
}

// EAPOLPacket wraps an EAP packet in an 802.1X EAP-Packet frame.
func EAPOLPacket(eap []byte) []byte {
	p := make([]byte, 0, 4+len(eap))
	p = append(p, eapolVersion, eapolTypeEAP)
	p = binary.BigEndian.AppendUint16(p, uint16(len(eap)))
	return append(p, eap...)
}

// DeauthFrame builds a deauthentication frame.
//
// Targeting a specific station is the default: broadcast deauthentication takes down every
// client on the network at once, which at a client site is an outage rather than a test.
func DeauthFrame(bssid, target recon.MAC, reason uint16, seq uint16) []byte {
	f := buildHeader(fcDeauth, target, bssid, bssid, seq)
	f = binary.LittleEndian.AppendUint16(f, reason)
	return withRadiotap(f)
}

// DisassocFrame builds a disassociation frame.
func DisassocFrame(bssid, target recon.MAC, reason uint16, seq uint16) []byte {
	f := buildHeader(fcDisassoc, target, bssid, bssid, seq)
	f = binary.LittleEndian.AppendUint16(f, reason)
	return withRadiotap(f)
}

// ProbeRequestFrame builds a probe request for a named network.
//
// Used by the karma responder detection test, which probes for a randomly generated ESSID
// that cannot exist. Anything that answers is a karma responder.
func ProbeRequestFrame(sta recon.MAC, essid string, seq uint16) ([]byte, error) {
	if len(essid) > 32 {
		return nil, fmt.Errorf("inject: ESSID is %d octets, maximum is 32", len(essid))
	}

	f := buildHeader(fcProbeReq, recon.Broadcast, sta, recon.Broadcast, seq)
	f = appendIE(f, recon.IESSID, []byte(essid))
	f = appendIE(f, recon.IESupportedRates, defaultRates)
	f = appendIE(f, recon.IEExtendedRates, extendedRates)
	return withRadiotap(f), nil
}

func withRadiotap(frame []byte) []byte {
	out := make([]byte, 0, len(radiotapTX)+len(frame))
	out = append(out, radiotapTX...)
	return append(out, frame...)
}

// RandomMAC generates a locally administered unicast address.
//
// Used as the source address for solicitation and probing. It is deliberately locally
// administered - the local bit marks the address as not globally assigned, so it cannot
// collide with a real device's burned-in address.
func RandomMAC() (recon.MAC, error) {
	var m recon.MAC
	if _, err := rand.Read(m[:]); err != nil {
		return m, fmt.Errorf("inject: generate MAC: %w", err)
	}
	m[0] &^= 0x01 // unicast
	m[0] |= 0x02  // locally administered
	return m, nil
}

// impossibleESSIDLen is the length of the random ESSID used for karma detection. Twenty
// characters of random alphanumerics has no realistic chance of matching a network that
// exists, so anything that answers is responding to arbitrary probes by design.
const impossibleESSIDLen = 20

const essidAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// RandomESSID generates an ESSID that cannot exist, for the karma responder detection test.
//
// It is regenerated per test rather than reused: a fixed string would eventually be
// recognisable, and a device that has already seen it could decline to answer.
func RandomESSID() (string, error) {
	buf := make([]byte, impossibleESSIDLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("inject: generate probe ESSID: %w", err)
	}
	for i, b := range buf {
		buf[i] = essidAlphabet[int(b)%len(essidAlphabet)]
	}
	return string(buf), nil
}
