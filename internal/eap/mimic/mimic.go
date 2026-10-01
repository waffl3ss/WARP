// Package mimic generates a certificate chain mirroring a harvested one.
//
// # What this actually achieves
//
// Be precise about this, because overstating it leads to bad findings. Supplicant certificate
// validation is chain-based, not string comparison: a mimic signed by our own CA fails on any
// client that properly pins the real CA, no matter how exactly the subject matches. Mirroring
// the fields does not defeat correct validation and is not meant to.
//
// What field mirroring is actually for:
//
//   - Trust-on-first-use clients (Android and iOS in their default enterprise flows) show the
//     user the issuer and common name and ask them to accept. A plausible subject raises
//     click-through substantially, and click-through is the finding.
//   - Clients configured with a permissive or empty CA list, or with server-name validation
//     disabled. That is a misconfiguration, and demonstrating it is the point.
//   - Report screenshots, where a certificate that visibly claims to be the client's own
//     RADIUS server makes the exposure legible to a non-technical reader.
//
// A client that rejects the mimic is a **pass**. It must be recorded as such: this module
// measures supplicant configuration hygiene, and negative results are report content.
package mimic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// Harvested describes the certificate WARP observed, as captured by the harvest package.
type Harvested struct {
	Subject      pkix.Name
	Issuer       pkix.Name
	DNSNames     []string
	IPAddresses  []net.IP
	EmailA       []string
	URIs         []string
	NotBefore    time.Time
	NotAfter     time.Time
	SerialNumber *big.Int
	// PublicKeyAlgorithm and KeyBits describe the key to match.
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	KeyBits            int
	SignatureAlgorithm x509.SignatureAlgorithm
}

// Chain is a generated CA and leaf.
type Chain struct {
	CACert  *x509.Certificate
	CAKey   any
	CAPEM   []byte
	LeafPEM []byte
	KeyPEM  []byte

	// TLS is the ready-to-serve certificate.
	TLS tls.Certificate

	// Fingerprint is the leaf's SHA-256 fingerprint.
	Fingerprint string
}

// Options tunes generation.
type Options struct {
	// Validity overrides the harvested validity window. Zero mirrors the original.
	Validity time.Duration
	// KeyBits overrides the RSA modulus size. Zero mirrors the original.
	KeyBits int
	// ExactSubject disables the distinguishing mark described at Distinguish. Off by default,
	// and there is no reason to set it on an engagement.
	ExactSubject bool
}

// distinguishingMark is appended to the mimic's common name: a single trailing space.
//
// # Why the mimic is never an exact copy
//
// A certificate that is byte-for-byte indistinguishable from the client's own, in their own
// naming, sitting in an engagement directory, is a liability. If it leaks, or is recovered
// from a decommissioned box, or turns up in a report attachment, there is no way for anyone -
// including us - to tell it apart from the real thing by looking at it. "That is not ours" is
// not a defensible claim about an artefact that is identical to theirs.
//
// So every mimic carries a mark that makes it provably not the original, and the mark is
// chosen to be the smallest thing that satisfies two requirements at once:
//
//   - **Invisible where it matters.** A supplicant's trust prompt renders the common name as
//     text. A trailing space does not change a single visible glyph, so click-through - the
//     thing being measured - is unaffected. Changing "Corporation" to "Corporatlon" would be
//     noticed; a trailing space is not.
//   - **Unambiguous where it matters.** In a hex dump, a diff, an openssl dump or a court
//     exhibit, the subject differs. The fingerprint differs regardless, but a fingerprint only
//     proves a difference to someone who has the original to compare against; the mark is in
//     the artefact itself.
//
// It goes on the leaf's common name only. Not the issuer, not the SANs: the SANs are what a
// client performing server-name validation matches on, and marking those would break the
// mimic against exactly the better-configured clients the test most wants to reach.
const distinguishingMark = " "

// Distinguish returns name with the distinguishing mark applied to its common name.
//
// Exported so a caller can show the operator precisely what the mimic will claim, and so the
// mark is testable as the deliberate thing it is rather than as a stray byte someone will
// "fix" later.
func Distinguish(name pkix.Name) pkix.Name {
	if name.CommonName == "" {
		return name
	}
	out := name
	out.CommonName = name.CommonName + distinguishingMark
	return out
}

// IsDistinguished reports whether a common name carries the mark.
func IsDistinguished(commonName string) bool {
	return strings.HasSuffix(commonName, distinguishingMark)
}

// Generate builds a CA and a leaf mirroring the harvested certificate.
//
// The CA's subject is set to the harvested *issuer*, so a client that displays the issuing
// authority sees the name it expects. This is cosmetic by design - see the package comment.
func Generate(h Harvested, opts Options) (*Chain, error) {
	notBefore, notAfter := h.NotBefore, h.NotAfter
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-24 * time.Hour)
	}
	if notAfter.IsZero() || !notAfter.After(notBefore) {
		notAfter = notBefore.Add(365 * 24 * time.Hour)
	}
	if opts.Validity > 0 {
		notAfter = notBefore.Add(opts.Validity)
	}
	// A certificate that has already expired is rejected before any name is even displayed,
	// which would waste the engagement's one chance at a click-through.
	if notAfter.Before(time.Now()) {
		shift := time.Until(notAfter)
		notBefore = notBefore.Add(-shift).Add(-time.Hour)
		notAfter = time.Now().Add(365 * 24 * time.Hour)
	}

	caKey, err := generateKey(h, opts)
	if err != nil {
		return nil, err
	}
	leafKey, err := generateKey(h, opts)
	if err != nil {
		return nil, err
	}

	caSerial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          caSerial,
		Subject:               h.Issuer,
		Issuer:                h.Issuer,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate,
		publicKey(caKey), caKey)
	if err != nil {
		return nil, fmt.Errorf("mimic: create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("mimic: parse generated CA: %w", err)
	}

	// The leaf keeps the harvested serial where there is one, so a screenshot of the mimic
	// matches the real certificate field for field.
	leafSerial := h.SerialNumber
	if leafSerial == nil || leafSerial.Sign() <= 0 {
		if leafSerial, err = randomSerial(); err != nil {
			return nil, err
		}
	}

	// Every field mirrors the original except the common name, which carries the mark that
	// makes this provably not the client's certificate. See Distinguish.
	subject := h.Subject
	if !opts.ExactSubject {
		subject = Distinguish(subject)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// ExtKeyUsageServerAuth is required: a supplicant that checks EKU rejects a
		// certificate without it before ever showing the user a name.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              h.DNSNames,
		IPAddresses:           h.IPAddresses,
		EmailAddresses:        h.EmailA,
		BasicConstraintsValid: true,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert,
		publicKey(leafKey), caKey)
	if err != nil {
		return nil, fmt.Errorf("mimic: create leaf certificate: %w", err)
	}

	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("mimic: marshal leaf key: %w", err)
	}

	chain := &Chain{
		CACert:  caCert,
		CAKey:   caKey,
		CAPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		LeafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}),
	}

	sum := sha256.Sum256(leafDER)
	chain.Fingerprint = hex.EncodeToString(sum[:])

	// The chain sent to the supplicant is leaf then CA, which is what a real server presents.
	chain.TLS = tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
	}
	return chain, nil
}

// generateKey produces a key matching the harvested algorithm and size.
//
// Matching matters because a supplicant that displays certificate details shows the key
// algorithm, and because some clients refuse algorithms they were not configured for - a
// mismatch fails before the name is ever shown.
func generateKey(h Harvested, opts Options) (any, error) {
	bits := h.KeyBits
	if opts.KeyBits > 0 {
		bits = opts.KeyBits
	}

	switch h.PublicKeyAlgorithm {
	case x509.ECDSA:
		curve := elliptic.P256()
		switch bits {
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("mimic: generate ECDSA key: %w", err)
		}
		return key, nil

	default:
		// RSA is the overwhelming default for enterprise RADIUS.
		if bits < 2048 {
			// Below 2048 modern clients reject outright, so mirroring a weak key would only
			// guarantee failure. Note the deviation rather than silently matching.
			bits = 2048
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("mimic: generate RSA key: %w", err)
		}
		return key, nil
	}
}

func publicKey(key any) any {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("mimic: generate serial: %w", err)
	}
	return serial, nil
}

// SelfSigned generates a plausible standalone certificate for an ESSID, used when nothing has
// been harvested yet.
//
// It is deliberately generic. Without a harvested certificate to mirror there is nothing to
// impersonate, and inventing a specific-looking organisation name would put a fabricated
// identity on the air.
func SelfSigned(essid string, opts Options) (*Chain, error) {
	name := pkix.Name{CommonName: fmt.Sprintf("radius.%s", sanitise(essid))}
	return Generate(Harvested{
		Subject:            name,
		Issuer:             pkix.Name{CommonName: fmt.Sprintf("%s Root CA", sanitise(essid))},
		DNSNames:           []string{name.CommonName},
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		PublicKeyAlgorithm: x509.RSA,
		KeyBits:            2048,
	}, opts)
}

// sanitise reduces an ESSID to something usable in a DNS name.
func sanitise(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
		case r == ' ' || r == '_' || r == '.':
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "network"
	}
	return string(out)
}

// Describe summarises what was generated and, importantly, what it does and does not achieve.
func (c *Chain) Describe() string {
	leaf, err := x509.ParseCertificate(c.TLS.Certificate[0])
	if err != nil {
		return "mimic certificate (unparseable)"
	}
	return fmt.Sprintf(
		"mimic leaf CN=%q issuer CN=%q serial=%s valid %s→%s fingerprint=%s\n"+
			"  Signed by a WARP-generated CA. A supplicant that validates the chain against the "+
			"real CA will reject this, which is the correct outcome and is recorded as a pass. "+
			"It is effective only against trust-on-first-use prompts and clients with validation "+
			"disabled or misconfigured.",
		leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.SerialNumber,
		leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02"),
		c.Fingerprint[:16])
}
