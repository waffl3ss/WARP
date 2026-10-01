package wps

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// synthesise builds the exchange a vulnerable access point would produce for a known PIN.
//
// This is the only honest way to test an offline attack without hardware: generate the same
// values the firmware would, from the same PIN, and require the recovery to find it. If the
// derivation here is wrong in the same way the recovery is wrong, both agree and the test
// proves nothing — which is why the derivation lives in the package under test and this
// function only assembles the message contents an access point would send.
func synthesise(t *testing.T, pin string, es1, es2 []byte) (Observation, Keys) {
	t.Helper()

	if !ValidPIN(pin) {
		t.Fatalf("test PIN %q has a bad check digit; a real access point would never use it", pin)
	}

	enrollee, err := NewDHKeypair() // the access point
	if err != nil {
		t.Fatalf("enrollee keypair: %v", err)
	}
	registrar, err := NewDHKeypair() // us
	if err != nil {
		t.Fatalf("registrar keypair: %v", err)
	}

	shared, err := enrollee.Shared(registrar.Public)
	if err != nil {
		t.Fatalf("shared secret: %v", err)
	}
	// Both sides must arrive at the same secret, or nothing below means anything.
	check, err := registrar.Shared(enrollee.Public)
	if err != nil {
		t.Fatalf("shared secret: %v", err)
	}
	if string(shared) != string(check) {
		t.Fatal("the two sides derived different shared secrets")
	}

	n1 := make([]byte, NonceLen)
	n2 := make([]byte, NonceLen)
	rand.Read(n1)
	rand.Read(n2)
	apMAC := []byte{0xa4, 0x2b, 0x8c, 0x11, 0x22, 0x33}

	keys, err := DeriveKeys(shared, n1, apMAC, n2)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	psk1 := pskHalf(keys.AuthKey, pin[:4])
	psk2 := pskHalf(keys.AuthKey, pin[4:])

	return Observation{
		PKE:     enrollee.Public,
		PKR:     registrar.Public,
		AuthKey: keys.AuthKey,
		EHash1:  hashHalf(keys.AuthKey, es1, psk1, enrollee.Public, registrar.Public),
		EHash2:  hashHalf(keys.AuthKey, es2, psk2, enrollee.Public, registrar.Public),
		ENonce:  n1,
		At:      time.Now(),
	}, keys
}

// TestRecoversAPINFromZeroNonces — the single most common case in the field: Ralink, MediaTek
// and Realtek firmwares that never filled the nonce buffer in at all.
func TestRecoversAPINFromZeroNonces(t *testing.T) {
	const pin = "12345670"
	zero := make([]byte, NonceLen)

	obs, _ := synthesise(t, pin, zero, zero)

	res, err := Recover(obs)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !res.Recovered {
		t.Fatalf("the PIN was not recovered from zero nonces: %s", res.Describe())
	}
	if res.PIN != pin {
		t.Errorf("recovered %q, want %q", res.PIN, pin)
	}
	if res.Generator != GeneratorZero {
		t.Errorf("generator = %q, want %q", res.Generator, GeneratorZero)
	}
	if !strings.Contains(res.Describe(), pin) {
		t.Errorf("the description does not carry the PIN: %s", res.Describe())
	}
}

// TestRecoversAPINWhenTheSecretNoncesReuseThePublicOne — Broadcom and some Realtek builds draw
// all three nonces from one call and end up sending the secret ones in the clear in M1.
func TestRecoversAPINWhenTheSecretNoncesReuseThePublicOne(t *testing.T) {
	const pin = "80516378"

	// Built with a placeholder, then rebuilt once the nonce is known: the enrollee nonce is
	// generated inside synthesise, and this case needs the secrets to equal it.
	seed, _ := synthesise(t, pin, make([]byte, NonceLen), make([]byte, NonceLen))
	obs := synthesiseWithNonce(t, pin, seed.ENonce)

	res, err := Recover(obs)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !res.Recovered {
		t.Fatalf("the PIN was not recovered: %s", res.Describe())
	}
	if res.PIN != pin {
		t.Errorf("recovered %q, want %q", res.PIN, pin)
	}
	if res.Generator != GeneratorENonce {
		t.Errorf("generator = %q, want %q", res.Generator, GeneratorENonce)
	}
}

// synthesiseWithNonce builds an exchange whose secret nonces both equal the public one.
func synthesiseWithNonce(t *testing.T, pin string, nonce []byte) Observation {
	t.Helper()

	enrollee, _ := NewDHKeypair()
	registrar, _ := NewDHKeypair()
	shared, _ := enrollee.Shared(registrar.Public)

	n2 := make([]byte, NonceLen)
	rand.Read(n2)
	apMAC := []byte{0xa4, 0x2b, 0x8c, 0x11, 0x22, 0x33}

	keys, err := DeriveKeys(shared, nonce, apMAC, n2)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	return Observation{
		PKE:     enrollee.Public,
		PKR:     registrar.Public,
		AuthKey: keys.AuthKey,
		EHash1:  hashHalf(keys.AuthKey, nonce, pskHalf(keys.AuthKey, pin[:4]), enrollee.Public, registrar.Public),
		EHash2:  hashHalf(keys.AuthKey, nonce, pskHalf(keys.AuthKey, pin[4:]), enrollee.Public, registrar.Public),
		ENonce:  nonce,
		At:      time.Now(),
	}
}

// TestRecoversAPINFromAClockSeededGenerator — Ralink's PRNG, drawing the public nonce and both
// secrets in sequence from a seed that is just the clock.
func TestRecoversAPINFromAClockSeededGenerator(t *testing.T) {
	const pin = "80516378"

	// The access point seeded its generator 90 seconds before we observed the exchange: a box
	// whose clock is off, which is the normal case rather than the exception.
	seed := uint32(time.Now().Unix()) - 90
	s := lcgState(seed)
	n1 := s.draw()
	es1 := s.draw()
	es2 := s.draw()

	enrollee, _ := NewDHKeypair()
	registrar, _ := NewDHKeypair()
	shared, _ := enrollee.Shared(registrar.Public)
	n2 := make([]byte, NonceLen)
	rand.Read(n2)

	keys, err := DeriveKeys(shared, n1, []byte{0xa4, 0x2b, 0x8c, 0x11, 0x22, 0x33}, n2)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}

	obs := Observation{
		PKE:     enrollee.Public,
		PKR:     registrar.Public,
		AuthKey: keys.AuthKey,
		EHash1:  hashHalf(keys.AuthKey, es1, pskHalf(keys.AuthKey, pin[:4]), enrollee.Public, registrar.Public),
		EHash2:  hashHalf(keys.AuthKey, es2, pskHalf(keys.AuthKey, pin[4:]), enrollee.Public, registrar.Public),
		ENonce:  n1,
		At:      time.Now(),
	}

	res, err := Recover(obs)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if !res.Recovered {
		t.Fatalf("the PIN was not recovered from a clock-seeded generator: %s", res.Describe())
	}
	if res.PIN != pin {
		t.Errorf("recovered %q, want %q", res.PIN, pin)
	}
	if res.Generator != GeneratorLCG {
		t.Errorf("generator = %q, want %q", res.Generator, GeneratorLCG)
	}
	if res.Seed != seed {
		t.Errorf("recovered seed %d, want %d", res.Seed, seed)
	}
}

// TestAWellBehavedAccessPointIsAPass.
//
// An access point that generates its nonces properly is not vulnerable, and the tool must say
// so as the finding it is rather than as an absence. Reporting "attack failed" would leave a
// reader unable to tell a secure device from a tool that did not work.
func TestAWellBehavedAccessPointIsAPass(t *testing.T) {
	const pin = "12345670"

	es1 := make([]byte, NonceLen)
	es2 := make([]byte, NonceLen)
	rand.Read(es1)
	rand.Read(es2)

	obs, _ := synthesise(t, pin, es1, es2)

	res, err := Recover(obs)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if res.Recovered {
		t.Fatalf("a PIN was 'recovered' from properly random nonces: %q", res.PIN)
	}
	if len(res.Tried) != 3 {
		t.Errorf("ruled out %d generators, want all 3 named so the pass is reportable: %v",
			len(res.Tried), res.Tried)
	}

	desc := res.Describe()
	if !strings.Contains(desc, "pass") {
		t.Errorf("a negative result does not read as a pass: %s", desc)
	}
}

// TestPINChecksum against the values in the specification.
func TestPINChecksum(t *testing.T) {
	cases := []struct {
		pin   string
		valid bool
	}{
		{"12345670", true},
		{"12345678", false},
		{"80516378", true},
		{"00000000", true},
		{"1234567", false},   // too short
		{"123456700", false}, // too long
		{"1234567a", false},
	}
	for _, c := range cases {
		if got := ValidPIN(c.pin); got != c.valid {
			t.Errorf("ValidPIN(%q) = %t, want %t", c.pin, got, c.valid)
		}
	}
}

// TestDiffieHellmanKeysAreAlwaysFullLength.
//
// A public value with a leading zero byte happens roughly once in 256 exchanges. Trimming it
// changes every derived key, and the failure looks like a broken access point rather than a
// padding bug — the kind of thing that gets diagnosed on site at 1am.
func TestDiffieHellmanKeysAreAlwaysFullLength(t *testing.T) {
	for i := 0; i < 64; i++ {
		k, err := NewDHKeypair()
		if err != nil {
			t.Fatalf("NewDHKeypair: %v", err)
		}
		if len(k.Public) != dhKeyLen {
			t.Fatalf("public key is %d octets, want %d", len(k.Public), dhKeyLen)
		}

		peer, _ := NewDHKeypair()
		shared, err := k.Shared(peer.Public)
		if err != nil {
			t.Fatalf("Shared: %v", err)
		}
		if len(shared) != dhKeyLen {
			t.Fatalf("shared secret is %d octets, want %d", len(shared), dhKeyLen)
		}
	}
}

// TestDegeneratePublicKeysAreRefused: an access point does not send these, but something
// pretending to be one might, and a shared secret with no entropy would produce a "recovered"
// PIN that is meaningless.
func TestDegeneratePublicKeysAreRefused(t *testing.T) {
	k, err := NewDHKeypair()
	if err != nil {
		t.Fatalf("NewDHKeypair: %v", err)
	}

	zero := make([]byte, dhKeyLen)
	one := make([]byte, dhKeyLen)
	one[dhKeyLen-1] = 1

	for name, bad := range map[string][]byte{"zero": zero, "one": one} {
		if _, err := k.Shared(bad); err == nil {
			t.Errorf("a %s public key was accepted", name)
		}
	}

	short := make([]byte, 32)
	if _, err := k.Shared(short); err == nil {
		t.Error("a short public key was accepted")
	}
}

// TestKDFProducesTheRightLengths — the three keys come out of one derivation and a length
// mistake would silently misalign all of them.
func TestKDFProducesTheRightLengths(t *testing.T) {
	shared := make([]byte, dhKeyLen)
	n1 := make([]byte, NonceLen)
	n2 := make([]byte, NonceLen)
	binary.BigEndian.PutUint32(shared, 0xdeadbeef)

	keys, err := DeriveKeys(shared, n1, []byte{1, 2, 3, 4, 5, 6}, n2)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	if len(keys.AuthKey) != 32 {
		t.Errorf("AuthKey is %d octets, want 32", len(keys.AuthKey))
	}
	if len(keys.KeyWrapKey) != 16 {
		t.Errorf("KeyWrapKey is %d octets, want 16", len(keys.KeyWrapKey))
	}
	if len(keys.EMSK) != 32 {
		t.Errorf("EMSK is %d octets, want 32", len(keys.EMSK))
	}

	// Wrong-sized inputs must be refused rather than producing keys that verify against
	// nothing and take an evening to diagnose.
	if _, err := DeriveKeys(shared, n1[:8], []byte{1, 2, 3, 4, 5, 6}, n2); err == nil {
		t.Error("a short nonce was accepted")
	}
	if _, err := DeriveKeys(shared, n1, []byte{1, 2, 3}, n2); err == nil {
		t.Error("a short enrollee MAC was accepted")
	}
}
