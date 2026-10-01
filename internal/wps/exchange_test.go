package wps

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// vulnerableAP is an access point with the WPS implementation this attack exists to find: it
// generates its secret nonces badly.
//
// It speaks the real protocol — real Diffie-Hellman, real key derivation, real commitments —
// so the exchange driver is tested against something that would reject a malformed M2 the way
// a real device does.
type vulnerableAP struct {
	t   *testing.T
	pin string
	// es picks the secret nonces from the enrollee nonce, modelling one vendor's mistake.
	es func(nonce []byte) (es1, es2 []byte)

	kp     *DHKeypair
	nonce  []byte
	rawM1  []byte
	toPeer chan []byte
	id     byte

	// networkKey is the passphrase this access point will reveal in M7 once the registrar proves
	// the PIN — the thing the PSK-retrieval half of the attack exists to read.
	networkKey string

	// State carried across the registration once M2 keys the session.
	keys Keys
	pkr  []byte

	// sawM8 records whether the registrar tried to *complete* registration (write a new config).
	// It must not: reading the AP's settings from M7 is the goal; M8 would reconfigure it.
	sawM8 bool
	// authenticatorChecked records that M2 carried a valid authenticator.
	authenticatorOK bool
}

func newVulnerableAP(t *testing.T, pin string, es func([]byte) ([]byte, []byte)) *vulnerableAP {
	t.Helper()

	kp, err := NewDHKeypair()
	if err != nil {
		t.Fatalf("access point keypair: %v", err)
	}
	nonce := make([]byte, NonceLen)
	rand.Read(nonce)

	a := &vulnerableAP{t: t, pin: pin, es: es, kp: kp, nonce: nonce,
		toPeer: make(chan []byte, 16)}

	// The identity request the access point sends on association.
	a.id++
	a.queueEAP(buildEAP(eapCodeRequest, a.id, eapTypeIdentity, nil))
	return a
}

func (a *vulnerableAP) queueEAP(eap []byte) { a.toPeer <- eapolPacket(eap) }

func (a *vulnerableAP) queueWSC(op byte, msg []byte) {
	a.id++
	body := make([]byte, 0, 9+len(msg))
	body = append(body, wfaVendor[0], wfaVendor[1], wfaVendor[2])
	body = binary.BigEndian.AppendUint32(body, wscVendorType)
	body = append(body, op, 0x00)
	body = append(body, msg...)
	a.queueEAP(buildEAP(eapCodeRequest, a.id, eapTypeExpanded, body))
}

func (a *vulnerableAP) Send(ctx context.Context, eapol []byte) error {
	if len(eapol) < 4 {
		a.t.Fatalf("registrar sent a %d-byte 802.1X frame", len(eapol))
	}
	switch eapol[1] {
	case 0x01, 0x02: // EAPOL-Start, EAPOL-Logoff
		return nil
	}

	code, _, typ, body, err := parseEAP(eapol)
	if err != nil {
		a.t.Fatalf("registrar sent something unparseable: %v", err)
	}
	if code != eapCodeResponse {
		a.t.Fatalf("registrar sent EAP code %d; a peer only sends responses", code)
	}

	switch typ {
	case eapTypeIdentity:
		if got := string(body); got != registrarIdentity {
			a.t.Errorf("identity = %q, want %q — the access point uses it to pick its role",
				got, registrarIdentity)
		}
		a.queueWSC(opWSCStart, nil)

	case eapTypeExpanded:
		op, msg, err := parseExpanded(body)
		if err != nil {
			a.t.Fatalf("registrar sent a malformed expanded payload: %v", err)
		}
		switch op {
		case opWSCACK:
			a.sendM1()
		case opWSCNACK:
			// Expected: the registrar ends the exchange after M3.
		case opWSCMsg:
			a.handleMessage(msg)
		}
	}
	return nil
}

func (a *vulnerableAP) sendM1() {
	var b []byte
	b = appendTLV8(b, attrVersion, 0x10)
	b = appendTLV8(b, attrMessageType, msgM1)
	b = appendTLV(b, attrUUIDE, make([]byte, 16))
	b = appendTLV(b, attrMACAddress, []byte{0xa4, 0x2b, 0x8c, 0x11, 0x22, 0x33})
	b = appendTLV(b, attrEnrolleeNonce, a.nonce)
	b = appendTLV(b, attrPublicKey, a.kp.Public)
	b = appendTLV(b, attrManufacturer, []byte("Ralink Technology, Corp."))
	b = appendTLV(b, attrModelName, []byte("RT2860"))
	b = appendTLV(b, attrModelNumber, []byte("1.0"))
	b = appendTLV(b, attrSerialNumber, []byte("12345678"))
	b = appendTLV(b, attrDeviceName, []byte("RalinkAPS"))

	a.rawM1 = b
	a.queueWSC(opWSCMsg, b)
}

func (a *vulnerableAP) handleMessage(msg []byte) {
	t := parseTLVs(msg)
	mt, ok := t[attrMessageType]
	if !ok || len(mt) != 1 {
		a.t.Fatalf("registrar sent a WSC message with no message type")
	}

	switch mt[0] {
	case msgM2:
		pkr := t[attrPublicKey]
		n2 := t[attrRegistrarNonce]
		// Pin the registrar nonce to its literal WSC tag rather than trusting the package's own
		// constant, so a wrong attrRegistrarNonce cannot pass by agreeing with itself. The WSC
		// spec puts the Registrar Nonce at 0x1039; 0x101C is ATTR_IDENTITY. A real WSC 2.0 access
		// point looks for 0x1039, finds nothing when it is mis-tagged, and NACKs M2 with config
		// error 0 before it ever checks the authenticator — which is exactly how this shipped
		// broken once and looked like a crypto bug.
		if _, ok := t[0x1039]; !ok {
			a.t.Fatalf("M2 has no Registrar Nonce at WSC tag 0x1039; a WSC 2.0 AP NACKs at M2")
		}
		if _, ok := t[0x101c]; ok {
			a.t.Errorf("M2 carries a 0x101C (ATTR_IDENTITY) attribute; the registrar nonce must " +
				"be tagged 0x1039, not 0x101C")
		}
		if len(pkr) != dhKeyLen {
			a.t.Fatalf("M2 public key is %d octets, want %d", len(pkr), dhKeyLen)
		}
		if len(n2) != NonceLen {
			a.t.Fatalf("M2 registrar nonce is %d octets, want %d", len(n2), NonceLen)
		}
		if got := t[attrEnrolleeNonce]; string(got) != string(a.nonce) {
			a.t.Error("M2 did not echo the enrollee nonce; a real access point stops here")
		}

		shared, err := a.kp.Shared(pkr)
		if err != nil {
			a.t.Fatalf("shared secret: %v", err)
		}
		keys, err := DeriveKeys(shared, a.nonce,
			[]byte{0xa4, 0x2b, 0x8c, 0x11, 0x22, 0x33}, n2)
		if err != nil {
			a.t.Fatalf("DeriveKeys: %v", err)
		}

		// Verify the authenticator the way a real access point does. Getting this wrong is the
		// classic way an exchange dies silently at M2.
		if auth, ok := t[attrAuthenticator]; ok && len(auth) == 8 {
			// The authenticator covers everything in M2 except itself, which is the last
			// attribute: 12 bytes of TLV header plus value.
			want := authenticator(keys.AuthKey, a.rawM1, msg[:len(msg)-12])
			a.authenticatorOK = string(want) == string(auth)
		}

		a.keys = keys
		a.pkr = pkr

		es1, es2 := a.es(a.nonce)
		var b []byte
		b = appendTLV8(b, attrVersion, 0x10)
		b = appendTLV8(b, attrMessageType, msgM3)
		b = appendTLV(b, attrRegistrarNonce, n2)
		b = appendTLV(b, attrEHash1,
			hashHalf(keys.AuthKey, es1, pskHalf(keys.AuthKey, a.pin[:4]), a.kp.Public, pkr))
		b = appendTLV(b, attrEHash2,
			hashHalf(keys.AuthKey, es2, pskHalf(keys.AuthKey, a.pin[4:]), a.kp.Public, pkr))
		a.queueWSC(opWSCMsg, b)

	case msgM4:
		// The registrar has proven it holds the PIN by binding its secret nonces to the PIN halves.
		// Verify R-Hash1 the way a real enrollee does, then reveal E-S1 in M5.
		rs := a.openSettings(t, attrRSNonce1)
		psk1 := pskHalf(a.keys.AuthKey, a.pin[:len(a.pin)/2])
		wantRHash1 := hashHalf(a.keys.AuthKey, rs, psk1, a.kp.Public, a.pkr)
		if string(t[attrRHash1]) != string(wantRHash1) {
			a.t.Error("M4 R-Hash1 did not verify; the registrar built it wrong or has the wrong PIN")
		}
		es1, _ := a.es(a.nonce)
		var plain []byte
		plain = appendTLV(plain, attrESNonce1, es1)
		plain = appendTLV(plain, attrKeyWrapAuth, keyWrapAuth(a.keys.AuthKey, plain))
		encr, err := encryptSettings(a.keys.KeyWrapKey, plain)
		if err != nil {
			a.t.Fatalf("encrypt M5: %v", err)
		}
		var b []byte
		b = appendTLV8(b, attrVersion, 0x10)
		b = appendTLV8(b, attrMessageType, msgM5)
		b = appendTLV(b, attrEnrolleeNonce, a.nonce)
		b = appendTLV(b, attrEncrSettings, encr)
		a.queueWSC(opWSCMsg, b)

	case msgM6:
		// The registrar revealed R-S2; the enrollee now hands over E-S2 and, crucially, its own
		// configuration — including the network key — in M7's encrypted settings.
		_ = a.openSettings(t, attrRSNonce2)
		_, es2 := a.es(a.nonce)
		var plain []byte
		plain = appendTLV(plain, attrESNonce2, es2)
		plain = appendTLV(plain, attrSSID, []byte("WPS-LAB"))
		plain = appendTLV16(plain, attrAuthType, 0x0020)
		plain = appendTLV16(plain, attrEncrType, 0x0008)
		plain = appendTLV(plain, attrNetworkKey, []byte(a.networkKey))
		plain = appendTLV(plain, attrMACAddress, []byte{0xa4, 0x2b, 0x8c, 0x11, 0x22, 0x33})
		plain = appendTLV(plain, attrKeyWrapAuth, keyWrapAuth(a.keys.AuthKey, plain))
		encr, err := encryptSettings(a.keys.KeyWrapKey, plain)
		if err != nil {
			a.t.Fatalf("encrypt M7: %v", err)
		}
		var b []byte
		b = appendTLV8(b, attrVersion, 0x10)
		b = appendTLV8(b, attrMessageType, msgM7)
		b = appendTLV(b, attrEnrolleeNonce, a.nonce)
		b = appendTLV(b, attrEncrSettings, encr)
		a.queueWSC(opWSCMsg, b)

	default:
		// The registrar must stop at M7. Sending M8 would write a new configuration to the access
		// point — using WPS rather than reading a credential out of it.
		a.sawM8 = true
		a.t.Errorf("the registrar sent WSC message type 0x%02x; it must stop at M7 and never send M8",
			mt[0])
	}
}

// openSettings decrypts an M4/M6 encrypted-settings blob under the KeyWrapKey and returns one
// attribute from the plaintext — the enrollee's side of the same crypto the registrar just ran.
func (a *vulnerableAP) openSettings(t tlvs, attr uint16) []byte {
	plain, err := decryptSettings(a.keys.KeyWrapKey, t[attrEncrSettings])
	if err != nil {
		a.t.Fatalf("decrypt registrar settings: %v", err)
	}
	return parseTLVs(plain)[attr]
}

func (a *vulnerableAP) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-a.toPeer:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func zeroNonces([]byte) ([]byte, []byte) {
	return make([]byte, NonceLen), make([]byte, NonceLen)
}

// TestTheExchangeRecoversAPINEndToEnd.
//
// Association aside, this is the whole attack: four WSC messages against a device with a weak
// nonce generator, then arithmetic. Everything except the 802.11 frames is exercised here.
func TestTheExchangeRecoversAPINEndToEnd(t *testing.T) {
	const pin = "12345670"
	const passphrase = "l4b-secret-pass"
	ap := newVulnerableAP(t, pin, zeroNonces)
	ap.networkKey = passphrase

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, dev, res, err := Exchange(ctx, ap, ExchangeOptions{})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if !ap.authenticatorOK {
		t.Error("M2's authenticator did not verify; a real access point would stop at M2 and " +
			"the exchange would yield nothing")
	}
	if ap.sawM8 {
		t.Error("registration was completed past M7 (M8 was sent), reconfiguring the access point")
	}

	// The device details go in the report: the model is what tells whoever has to fix this
	// which firmware they are looking for.
	if dev.Manufacturer != "Ralink Technology, Corp." {
		t.Errorf("manufacturer = %q, want the value from M1", dev.Manufacturer)
	}
	if dev.ModelName != "RT2860" {
		t.Errorf("model = %q, want the value from M1", dev.ModelName)
	}

	if !res.Recovered {
		t.Fatalf("the exchange succeeded but the PIN was not recovered: %s", res.Describe())
	}
	if res.PIN != pin {
		t.Errorf("recovered %q, want %q", res.PIN, pin)
	}
	// The whole point of going past M3: the exchange reads the passphrase out of M7.
	if res.NetworkKey != passphrase {
		t.Errorf("recovered passphrase %q, want %q", res.NetworkKey, passphrase)
	}
}

// TestASecureAccessPointYieldsAPass — the exchange still works, the recovery correctly fails,
// and that is a reportable result rather than an error.
func TestASecureAccessPointYieldsAPass(t *testing.T) {
	const pin = "12345670"
	ap := newVulnerableAP(t, pin, func([]byte) ([]byte, []byte) {
		es1, es2 := make([]byte, NonceLen), make([]byte, NonceLen)
		rand.Read(es1)
		rand.Read(es2)
		return es1, es2
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, res, err := Exchange(ctx, ap, ExchangeOptions{})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	if res.Recovered {
		t.Fatalf("a PIN was 'recovered' from a properly implemented access point: %q", res.PIN)
	}
	if res.NetworkKey != "" {
		t.Errorf("a passphrase was read from a secure AP that should have stopped at M3: %q", res.NetworkKey)
	}
	if !strings.Contains(res.Describe(), "pass") {
		t.Errorf("the result does not read as a pass: %s", res.Describe())
	}
}

// TestSilenceIsReportedAsWPSNotRunning: a network with WPS disabled never starts the
// conversation, and the operator has to be told that rather than watching a job time out.
func TestSilenceIsReportedAsWPSNotRunning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, _, _, err := Exchange(ctx, silent{}, ExchangeOptions{Timeout: 100 * time.Millisecond})
	if !errors.Is(err, ErrNoWPS) {
		t.Fatalf("got %v, want ErrNoWPS", err)
	}
}

type silent struct{}

func (silent) Send(context.Context, []byte) error { return nil }
func (silent) Receive(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
