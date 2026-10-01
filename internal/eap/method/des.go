package method

import "crypto/des" //nolint:staticcheck // DES is what MSCHAPv2 specifies

// desKeyFromBytes expands a 7-byte key into the 8-byte parity-adjusted form DES expects
// (RFC 2759 section 8.6).
//
// MSCHAPv2 packs its 21-byte padded password hash into three 7-byte keys; DES keys are 8
// bytes with the low bit of each byte reserved for parity, so each 7-byte chunk is spread
// across 8 bytes.
func desKeyFromBytes(key []byte) [8]byte {
	var out [8]byte

	out[0] = key[0] >> 1
	out[1] = ((key[0] & 0x01) << 6) | (key[1] >> 2)
	out[2] = ((key[1] & 0x03) << 5) | (key[2] >> 3)
	out[3] = ((key[2] & 0x07) << 4) | (key[3] >> 4)
	out[4] = ((key[3] & 0x0F) << 3) | (key[4] >> 5)
	out[5] = ((key[4] & 0x1F) << 2) | (key[5] >> 6)
	out[6] = ((key[5] & 0x3F) << 1) | (key[6] >> 7)
	out[7] = key[6] & 0x7F

	// Shift left one bit; the vacated low bit is the (ignored) parity bit.
	for i := range out {
		out[i] <<= 1
	}
	return out
}

// desEncryptECB encrypts one 8-byte block.
//
// Returns a zero block if the key or input is malformed. That cannot happen with input from
// desKeyFromBytes, and returning an error here would push a nil check into every caller of a
// function that is arithmetically incapable of failing.
func desEncryptECB(key [8]byte, plaintext []byte) []byte {
	out := make([]byte, des.BlockSize)
	if len(plaintext) < des.BlockSize {
		return out
	}

	block, err := des.NewCipher(key[:])
	if err != nil {
		return out
	}
	block.Encrypt(out, plaintext[:des.BlockSize])
	return out
}
