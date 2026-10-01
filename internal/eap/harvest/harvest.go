// Package harvest captures the certificate chain an enterprise network presents.
//
// It implements the client half of an 802.1X exchange: authenticate against an authorized
// enterprise BSSID with no CA validation, complete the TLS phase, record the presented chain,
// and abort before inner authentication.
//
// **No credentials are ever sent.** The supplicant deliberately has none: there is nothing to
// leak even if the exchange ran to completion, and it does not. Harvesting reads what the
// server volunteers during the handshake and stops there.
package harvest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/waffl3ss/warp/internal/eap/mimic"
)

// Certificate is one harvested certificate, flattened for the report.
type Certificate struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	SANs      []string  `json:"sans,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Serial    string    `json:"serial"`

	KeyAlgorithm string `json:"key_algorithm"`
	KeyBits      int    `json:"key_bits"`
	SigAlgorithm string `json:"signature_algorithm"`

	// Fingerprint is the SHA-256 of the DER encoding.
	Fingerprint string `json:"fingerprint_sha256"`

	// IsCA marks an intermediate or root in the chain.
	IsCA bool `json:"is_ca"`
	// SelfSigned marks a certificate that issued itself.
	SelfSigned bool `json:"self_signed"`
	// Expired and NotYetValid are recorded because either is a finding on its own.
	Expired     bool `json:"expired"`
	NotYetValid bool `json:"not_yet_valid"`
}

// Result is a completed harvest.
type Result struct {
	ESSID string `json:"essid"`
	BSSID string `json:"bssid,omitempty"`
	// Chain is the presented certificates, leaf first.
	Chain []Certificate `json:"chain"`
	// TLSVersion and CipherSuite record what the server negotiated. A server that will
	// negotiate TLS 1.0 is a finding in itself.
	TLSVersion  string    `json:"tls_version"`
	CipherSuite string    `json:"cipher_suite"`
	At          time.Time `json:"at"`

	// PEM is the full chain in PEM form.
	PEM []byte `json:"-"`

	// Notes carries observations worth reporting that are not per-certificate.
	Notes []string `json:"notes,omitempty"`
}

// Leaf returns the server certificate.
func (r *Result) Leaf() (Certificate, bool) {
	if len(r.Chain) == 0 {
		return Certificate{}, false
	}
	return r.Chain[0], true
}

// ErrNoCertificate is returned when the server presented nothing.
var ErrNoCertificate = errors.New("harvest: the server presented no certificate")

// FromConnectionState extracts everything reportable from a completed TLS handshake.
//
// This is deliberately separate from the network path so it can be tested against synthetic
// chains without a radio, and so the same extraction runs whether the chain came from a live
// harvest or from a capture replayed later.
func FromConnectionState(essid, bssid string, state tls.ConnectionState) (*Result, error) {
	if len(state.PeerCertificates) == 0 {
		return nil, ErrNoCertificate
	}

	res := resultFromCerts(essid, bssid, state.PeerCertificates)
	res.TLSVersion = tlsVersionName(state.Version)
	res.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	res.Notes = observations(res, state)
	return res, nil
}

// resultFromCerts flattens a certificate chain into a Result, filling everything derivable from
// the certificates alone. The live path adds the negotiated TLS version and cipher on top; the
// passive path (FromCapturedCertificates) has only the certificates, and that is enough for the
// mimic.
func resultFromCerts(essid, bssid string, certs []*x509.Certificate) *Result {
	res := &Result{ESSID: essid, BSSID: bssid, At: time.Now()}

	var pemBuf strings.Builder
	now := time.Now()

	for _, cert := range certs {
		sum := sha256.Sum256(cert.Raw)
		bits, algo := keyDetails(cert)

		res.Chain = append(res.Chain, Certificate{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SANs:         collectSANs(cert),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			Serial:       cert.SerialNumber.String(),
			KeyAlgorithm: algo,
			KeyBits:      bits,
			SigAlgorithm: cert.SignatureAlgorithm.String(),
			Fingerprint:  hex.EncodeToString(sum[:]),
			IsCA:         cert.IsCA,
			SelfSigned:   cert.Subject.String() == cert.Issuer.String(),
			Expired:      now.After(cert.NotAfter),
			NotYetValid:  now.Before(cert.NotBefore),
		})
		pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}
	res.PEM = []byte(pemBuf.String())
	return res
}

// observations records reportable facts about the chain that are not per-certificate.
func observations(r *Result, state tls.ConnectionState) []string {
	var notes []string

	if state.Version < tls.VersionTLS12 {
		notes = append(notes, fmt.Sprintf(
			"the RADIUS server negotiated %s; TLS 1.0 and 1.1 are deprecated and this is a "+
				"finding independent of anything else here", tlsVersionName(state.Version)))
	}

	leaf, ok := r.Leaf()
	if !ok {
		return notes
	}

	if leaf.SelfSigned {
		notes = append(notes, "the server certificate is self-signed; supplicants configured "+
			"to validate a CA chain cannot be validating this one")
	}
	if leaf.Expired {
		notes = append(notes, "the server certificate has expired; clients that still connect "+
			"are ignoring certificate validity entirely")
	}
	if len(leaf.SANs) == 0 {
		notes = append(notes, "the server certificate carries no subject alternative names; "+
			"supplicants that check the server name cannot match it")
	}
	if leaf.KeyAlgorithm == "RSA" && leaf.KeyBits > 0 && leaf.KeyBits < 2048 {
		notes = append(notes, fmt.Sprintf(
			"the server key is RSA-%d, below the 2048-bit minimum", leaf.KeyBits))
	}
	if len(r.Chain) == 1 && !leaf.SelfSigned {
		notes = append(notes, "the server sent only its leaf certificate with no intermediates; "+
			"clients without the issuing CA cached cannot build a chain")
	}

	return notes
}

func collectSANs(c *x509.Certificate) []string {
	var out []string
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, c.EmailAddresses...)
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	sort.Strings(out)
	return out
}

func keyDetails(c *x509.Certificate) (bits int, algo string) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen(), "RSA"
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize, "ECDSA"
	case ed25519.PublicKey:
		return 256, "Ed25519"
	default:
		return 0, c.PublicKeyAlgorithm.String()
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (%#04x)", v)
	}
}

// ClientConfig builds the TLS configuration the harvesting supplicant uses.
//
// InsecureSkipVerify is set deliberately and is the entire point: WARP is *recording* what the
// server presents, not deciding whether to trust it. Verification would abort the handshake
// before the chain could be captured, which is the opposite of what is wanted here.
//
// Nothing is sent in return: this configuration carries no client certificate, and the
// exchange is abandoned before inner authentication begins.
func ClientConfig(serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // harvesting requires seeing an untrusted chain
		ServerName:         serverName,
		// Offer everything so a legacy server still completes far enough to present its
		// chain. A server that will only do TLS 1.0 is itself a finding, and refusing to talk
		// to it would mean never learning that.
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS13,
	}
}

// Save writes the harvested chain and its JSON sidecar into the engagement directory.
//
// Layout is certs/<essid>/harvested.pem plus harvested.json, as the workspace specifies.
func (r *Result) Save(certsDir string) (pemPath, jsonPath string, err error) {
	dir := filepath.Join(certsDir, sanitise(r.ESSID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("harvest: create %s: %w", dir, err)
	}

	pemPath = filepath.Join(dir, "harvested.pem")
	if err := os.WriteFile(pemPath, r.PEM, 0o600); err != nil {
		return "", "", fmt.Errorf("harvest: write %s: %w", pemPath, err)
	}

	sidecar, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("harvest: marshal certificate metadata: %w", err)
	}
	jsonPath = filepath.Join(dir, "harvested.json")
	if err := os.WriteFile(jsonPath, append(sidecar, '\n'), 0o600); err != nil {
		return "", "", fmt.Errorf("harvest: write %s: %w", jsonPath, err)
	}

	return pemPath, jsonPath, nil
}

// ToMimic converts a harvested leaf into the description the mimic generator needs.
func (r *Result) ToMimic(state tls.ConnectionState) (mimic.Harvested, error) {
	if len(state.PeerCertificates) == 0 {
		return mimic.Harvested{}, ErrNoCertificate
	}
	leaf := state.PeerCertificates[0]

	bits, _ := keyDetails(leaf)
	return mimic.Harvested{
		Subject:            leaf.Subject,
		Issuer:             leaf.Issuer,
		DNSNames:           leaf.DNSNames,
		IPAddresses:        leaf.IPAddresses,
		EmailA:             leaf.EmailAddresses,
		NotBefore:          leaf.NotBefore,
		NotAfter:           leaf.NotAfter,
		SerialNumber:       leaf.SerialNumber,
		PublicKeyAlgorithm: leaf.PublicKeyAlgorithm,
		KeyBits:            bits,
		SignatureAlgorithm: leaf.SignatureAlgorithm,
	}, nil
}

// MimicSource derives the mimic generator's input from a saved harvest.
//
// ToMimic needs a live tls.ConnectionState and so only works at the moment of harvesting.
// This works from the PEM, which means a mimic can be regenerated from certs/<essid>/ hours
// later, on a different run of the daemon, without going back to the air. That matters: the
// harvest costs an association at a production access point and should happen once.
func (r *Result) MimicSource() (mimic.Harvested, error) {
	block, _ := pem.Decode(r.PEM)
	if block == nil {
		return mimic.Harvested{}, ErrNoCertificate
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return mimic.Harvested{}, fmt.Errorf("harvest: parse saved leaf certificate: %w", err)
	}

	bits, _ := keyDetails(leaf)
	return mimic.Harvested{
		Subject:            leaf.Subject,
		Issuer:             leaf.Issuer,
		DNSNames:           leaf.DNSNames,
		IPAddresses:        leaf.IPAddresses,
		EmailA:             leaf.EmailAddresses,
		NotBefore:          leaf.NotBefore,
		NotAfter:           leaf.NotAfter,
		SerialNumber:       leaf.SerialNumber,
		PublicKeyAlgorithm: leaf.PublicKeyAlgorithm,
		KeyBits:            bits,
		SignatureAlgorithm: leaf.SignatureAlgorithm,
	}, nil
}

// Load reads a harvest previously written by Save.
//
// The JSON sidecar carries the metadata and the PEM carries the chain; both are needed, and
// the PEM is authoritative - the sidecar is a rendering of it for people and for reports.
func Load(certsDir, essid string) (*Result, error) {
	dir := filepath.Join(certsDir, sanitise(essid))

	pemBytes, err := os.ReadFile(filepath.Join(dir, "harvested.pem"))
	if err != nil {
		return nil, fmt.Errorf("harvest: read harvested certificate: %w", err)
	}

	res := &Result{}
	sidecar, err := os.ReadFile(filepath.Join(dir, "harvested.json"))
	if err == nil {
		// A missing or unreadable sidecar is survivable: everything that matters for building
		// a mimic is in the PEM, and refusing to use a good certificate because its metadata
		// file was lost would be the wrong trade on site.
		_ = json.Unmarshal(sidecar, res)
	}
	res.PEM = pemBytes
	if res.ESSID == "" {
		res.ESSID = essid
	}
	return res, nil
}

// Describe renders the harvest for operator-facing output.
func (r *Result) Describe() string {
	var b strings.Builder

	fmt.Fprintf(&b, "%s - %s, %s\n", r.ESSID, r.TLSVersion, r.CipherSuite)
	for i, c := range r.Chain {
		role := "leaf"
		if c.IsCA {
			role = "CA"
		}
		fmt.Fprintf(&b, "  [%d] %s  %s\n", i, role, c.Subject)
		fmt.Fprintf(&b, "      issuer   %s\n", c.Issuer)
		fmt.Fprintf(&b, "      valid    %s → %s", c.NotBefore.Format("2006-01-02"),
			c.NotAfter.Format("2006-01-02"))
		if c.Expired {
			b.WriteString("  EXPIRED")
		}
		b.WriteString("\n")
		fmt.Fprintf(&b, "      key      %s-%d, %s\n", c.KeyAlgorithm, c.KeyBits, c.SigAlgorithm)
		if len(c.SANs) > 0 {
			fmt.Fprintf(&b, "      sans     %s\n", strings.Join(c.SANs, ", "))
		}
		fmt.Fprintf(&b, "      sha256   %s\n", c.Fingerprint)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "  ! %s\n", n)
	}
	return b.String()
}

// sanitise reduces an ESSID to a directory name.
func sanitise(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}
