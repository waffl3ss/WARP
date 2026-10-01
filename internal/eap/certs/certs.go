// Package certs is the engagement's certificate library: everything the rogue access point
// could present, and which one it will.
//
// # Why this is not just "generate a self-signed one"
//
// The certificate is the pretext. A supplicant deciding whether to hand over its credentials
// is, in almost every real case, deciding whether the certificate looks like the one it
// expects - either by validating a chain, or by showing a human a name and a prompt. A
// self-signed certificate carrying none of the target's naming loses that decision every
// single time against any client that shows the user anything, which makes it useful only
// against clients that check nothing at all.
//
// So there are four ways a certificate gets here, in descending order of how convincing it is:
//
//   - **Mimicked** from a certificate harvested off the air. The strongest, because every field
//     a client displays came from the real thing. Carries a distinguishing mark - see
//     mimic.Distinguish.
//   - **Generated** from fields the operator typed. For when the target cannot be harvested
//     (out of range, not yet observed, or an engagement that starts before the site visit) but
//     the naming is known from a scoping call or a previous report.
//   - **Imported**: a certificate and key produced elsewhere. A client with a real internal CA
//     may have issued one for the test, or the operator may have a prepared chain.
//   - **Self-signed**, generated from the ESSID alone. The fallback, and the weakest - it
//     invents nothing, which is correct, and convinces nobody, which is the cost.
//
// Which one is selected is engagement state, not a runtime flag: it is recorded on disk so a
// daemon restart presents the same certificate, and so a report can say what was on the air.
package certs

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/waffl3ss/warp/internal/eap/mimic"
)

// Source says where a certificate came from. It is reported on the session and in the report,
// because "a supplicant accepted the certificate" means very different things depending on
// which of these it accepted.
type Source string

// The four sources.
const (
	SourceMimic      Source = "mimic"
	SourceGenerated  Source = "generated"
	SourceImported   Source = "imported"
	SourceSelfSigned Source = "self-signed"
)

// Describe renders a source for an operator.
func (s Source) Describe() string {
	switch s {
	case SourceMimic:
		return "mimicked from a harvested certificate"
	case SourceGenerated:
		return "generated from operator-supplied fields"
	case SourceImported:
		return "imported"
	default:
		return "self-signed"
	}
}

// Strength ranks sources so the strongest available is selected by default. Higher is better.
func (s Source) Strength() int {
	switch s {
	case SourceMimic:
		return 3
	case SourceImported:
		return 2
	case SourceGenerated:
		return 1
	default:
		return 0
	}
}

// Entry is one certificate in the library.
type Entry struct {
	ID     string `json:"id"`
	ESSID  string `json:"essid"`
	Source Source `json:"source"`
	// SourceDetail is the human sentence for Source.
	SourceDetail string `json:"source_detail"`

	Subject string   `json:"subject"`
	Issuer  string   `json:"issuer"`
	SANs    []string `json:"sans,omitempty"`

	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Expired   bool      `json:"expired,omitempty"`

	KeyAlgorithm string `json:"key_algorithm"`
	KeyBits      int    `json:"key_bits,omitempty"`
	Fingerprint  string `json:"fingerprint_sha256"`

	Created  time.Time `json:"created"`
	Selected bool      `json:"selected"`

	// Note carries whatever the operator said about it.
	Note string `json:"note,omitempty"`

	// CertPath and KeyPath are absolute paths inside the engagement.
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

// Store is the certificate library for one engagement.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Open returns the library rooted at dir (the engagement's certs/ directory).
func Open(dir string) *Store { return &Store{dir: dir} }

// Fields describes a certificate to generate.
//
// The eaphammer certwizard equivalent, and the reason it exists: a self-signed certificate
// with a generated name is refused by anything that looks at it, and an operator who knows the
// client runs `radius.acme-corp.internal` issued by `ACME Corporate Issuing CA` can say so
// without needing to be in range of the access point first.
type Fields struct {
	// CommonName is the only required field. It is what a trust prompt shows.
	CommonName string `json:"common_name"`

	Organization       string `json:"organization,omitempty"`
	OrganizationalUnit string `json:"organizational_unit,omitempty"`
	Country            string `json:"country,omitempty"`
	Province           string `json:"province,omitempty"`
	Locality           string `json:"locality,omitempty"`
	// Email is the emailAddress RDN. eaphammer's certwizard prompts for it, and some
	// enterprise CAs put it in the subject DN, so mirroring one that does matters - a client
	// displaying the full subject shows a different string without it.
	Email string `json:"email,omitempty"`

	// IssuerCommonName and IssuerOrganization name the CA. A client that displays the issuing
	// authority - which is most of the ones that prompt - shows this, so it matters as much as
	// the subject.
	IssuerCommonName   string `json:"issuer_common_name,omitempty"`
	IssuerOrganization string `json:"issuer_organization,omitempty"`

	// DNSNames are the subject alternative names. A supplicant configured with
	// domain_suffix_match checks these and nothing else.
	DNSNames []string `json:"dns_names,omitempty"`
	// IPAddresses is rarely wanted and occasionally decisive.
	IPAddresses []string `json:"ip_addresses,omitempty"`

	// ValidityDays defaults to 825 - the longest a public CA may issue for, so it looks
	// unremarkable next to a real certificate.
	ValidityDays int `json:"validity_days,omitempty"`
	// KeyBits defaults to 2048. A client that displays key details shows this.
	KeyBits int `json:"key_bits,omitempty"`

	// Note is recorded with the certificate.
	Note string `json:"note,omitempty"`
}

// oidEmailAddress is PKCS#9 emailAddress (1.2.840.113549.1.9.1), the OID a subject DN uses to
// carry an email address.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// Errors.
var (
	ErrNoCommonName = errors.New("certs: a certificate needs at least a common name")
	ErrNotFound     = errors.New("certs: no such certificate")
)

// Generate builds a certificate from operator-supplied fields and files it under essid.
//
// The fields are used verbatim. Unlike a mimic, which always carries a distinguishing mark
// because it is a copy of somebody's real certificate, this is what the operator typed - and
// silently mutating typed input would be worse than the risk it guards against. What the
// subject will be is reported back before it goes anywhere near the air.
func (s *Store) Generate(essid string, f Fields) (Entry, error) {
	if strings.TrimSpace(f.CommonName) == "" {
		return Entry{}, ErrNoCommonName
	}

	days := f.ValidityDays
	if days <= 0 {
		days = 825
	}
	bits := f.KeyBits
	if bits <= 0 {
		bits = 2048
	}

	issuer := pkix.Name{
		CommonName: f.IssuerCommonName,
	}
	if issuer.CommonName == "" {
		// A leaf issued by an authority with the same name as itself reads as self-signed in
		// every viewer, which is the one thing a hand-authored certificate should not do.
		issuer.CommonName = f.CommonName + " Issuing CA"
	}
	if f.IssuerOrganization != "" {
		issuer.Organization = []string{f.IssuerOrganization}
	} else if f.Organization != "" {
		issuer.Organization = []string{f.Organization}
	}

	subject := pkix.Name{CommonName: f.CommonName}
	appendIf(&subject.Organization, f.Organization)
	appendIf(&subject.OrganizationalUnit, f.OrganizationalUnit)
	appendIf(&subject.Country, f.Country)
	appendIf(&subject.Province, f.Province)
	appendIf(&subject.Locality, f.Locality)
	if e := strings.TrimSpace(f.Email); e != "" {
		// emailAddress has no field in pkix.Name; it goes in as an ExtraName under its OID
		// (1.2.840.113549.1.9.1), which is how a CA that carries it in the DN encodes it.
		subject.ExtraNames = append(subject.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  oidEmailAddress,
			Value: e,
		})
	}

	dns := f.DNSNames
	if len(dns) == 0 && looksLikeHostname(f.CommonName) {
		// A supplicant checking the server name matches on the SANs, not the common name.
		// A certificate whose CN is a hostname and which carries no SAN at all is refused by
		// anything modern before a human ever sees it.
		dns = []string{f.CommonName}
	}

	var ips []net.IP
	for _, raw := range f.IPAddresses {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			ips = append(ips, ip)
		}
	}

	chain, err := mimic.Generate(mimic.Harvested{
		Subject:            subject,
		Issuer:             issuer,
		DNSNames:           dns,
		IPAddresses:        ips,
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(time.Duration(days) * 24 * time.Hour),
		PublicKeyAlgorithm: x509.RSA,
		KeyBits:            bits,
	}, mimic.Options{ExactSubject: true})
	if err != nil {
		return Entry{}, err
	}

	return s.add(essid, SourceGenerated, f.Note, chain)
}

func appendIf(dst *[]string, v string) {
	if strings.TrimSpace(v) != "" {
		*dst = append(*dst, v)
	}
}

// looksLikeHostname reports whether a common name is a DNS name rather than a descriptive
// string like "ACME RADIUS".
func looksLikeHostname(s string) bool {
	return strings.Contains(s, ".") && !strings.Contains(s, " ")
}

// AddMimic files a certificate mimicking a harvested one.
func (s *Store) AddMimic(essid, note string, chain *mimic.Chain) (Entry, error) {
	return s.add(essid, SourceMimic, note, chain)
}

// AddSelfSigned files the generic fallback.
func (s *Store) AddSelfSigned(essid string) (Entry, error) {
	chain, err := mimic.SelfSigned(essid, mimic.Options{})
	if err != nil {
		return Entry{}, err
	}
	return s.add(essid, SourceSelfSigned, "", chain)
}

// Import files a certificate and key produced elsewhere.
//
// The pair is validated by loading it as a TLS certificate before anything is written: an
// imported certificate whose key does not match is a failure that would otherwise surface as
// the rogue access point refusing to start, halfway through an engagement.
func (s *Store) Import(essid, note string, certPEM, keyPEM []byte) (Entry, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return Entry{}, fmt.Errorf("certs: the certificate and key do not form a usable pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return Entry{}, errors.New("certs: no certificate in the supplied PEM")
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return Entry{}, fmt.Errorf("certs: parse imported certificate: %w", err)
	}

	// Any certificates after the leaf are the chain and are presented with it.
	var caPEM []byte
	for _, der := range pair.Certificate[1:] {
		caPEM = append(caPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}

	sum := sha256.Sum256(leaf.Raw)
	return s.write(essid, SourceGenerated, note, entryFrom(leaf, SourceImported),
		certPEM, keyPEM, caPEM, hex.EncodeToString(sum[:]), SourceImported)
}

// add files a generated chain.
func (s *Store) add(essid string, src Source, note string, chain *mimic.Chain) (Entry, error) {
	leaf, err := x509.ParseCertificate(chain.TLS.Certificate[0])
	if err != nil {
		return Entry{}, fmt.Errorf("certs: parse generated certificate: %w", err)
	}
	// Leaf then CA, which is what a real server presents.
	certPEM := append(append([]byte{}, chain.LeafPEM...), chain.CAPEM...)
	return s.write(essid, src, note, entryFrom(leaf, src),
		certPEM, chain.KeyPEM, chain.CAPEM, chain.Fingerprint, src)
}

func (s *Store) write(essid string, _ Source, note string, e Entry,
	certPEM, keyPEM, caPEM []byte, fingerprint string, src Source) (Entry, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	e.ESSID = essid
	e.Source = src
	e.SourceDetail = src.Describe()
	e.Fingerprint = fingerprint
	e.Created = time.Now()
	e.Note = note
	// The fingerprint's first sixteen characters: short enough to type, long enough that two
	// certificates in one engagement cannot collide.
	e.ID = fingerprint[:16]

	dir := filepath.Join(s.dir, sanitise(essid), e.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Entry{}, fmt.Errorf("certs: create %s: %w", dir, err)
	}

	e.CertPath = filepath.Join(dir, "cert.pem")
	e.KeyPath = filepath.Join(dir, "key.pem")

	// 0600 throughout: this directory holds private keys.
	if err := os.WriteFile(e.CertPath, certPEM, 0o600); err != nil {
		return Entry{}, fmt.Errorf("certs: write certificate: %w", err)
	}
	if err := os.WriteFile(e.KeyPath, keyPEM, 0o600); err != nil {
		return Entry{}, fmt.Errorf("certs: write key: %w", err)
	}
	if len(caPEM) > 0 {
		// Written out separately so it can be handed to a supplicant that is being configured
		// to *validate* - the control case that proves a correctly configured client refuses.
		if err := os.WriteFile(filepath.Join(dir, "ca.pem"), caPEM, 0o600); err != nil {
			return Entry{}, fmt.Errorf("certs: write CA: %w", err)
		}
	}

	meta, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return Entry{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), append(meta, '\n'), 0o600); err != nil {
		return Entry{}, fmt.Errorf("certs: write metadata: %w", err)
	}

	// A new certificate is selected when it is at least as convincing as whatever is selected
	// now. Harvesting one and then having the rogue go on presenting a self-signed certificate
	// because nobody pressed a second button is exactly the trap this avoids.
	if cur, ok := s.selectedLocked(essid); !ok || src.Strength() >= cur.Source.Strength() {
		if err := s.selectLocked(essid, e.ID); err != nil {
			return Entry{}, err
		}
		e.Selected = true
	}
	return e, nil
}

// subjectString renders a subject the way an operator reads one, resolving the emailAddress
// OID that pkix.Name.String() leaves as raw hex.
//
// The value is in the certificate correctly either way; this is so the library listing and the
// report show "emailAddress=noc@acme.example" rather than "1.2.840.113549.1.9.1=#0c10…".
func subjectString(name pkix.Name) string {
	base := name.String()
	for _, atv := range name.Names {
		if atv.Type.Equal(oidEmailAddress) {
			if v, ok := atv.Value.(string); ok {
				base += ",emailAddress=" + v
			}
		}
	}
	return base
}

// entryFrom flattens an x509 certificate into the reportable fields.
func entryFrom(c *x509.Certificate, src Source) Entry {
	e := Entry{
		Source:       src,
		SourceDetail: src.Describe(),
		Subject:      subjectString(c.Subject),
		Issuer:       c.Issuer.String(),
		NotBefore:    c.NotBefore,
		NotAfter:     c.NotAfter,
		Expired:      time.Now().After(c.NotAfter),
		KeyAlgorithm: c.PublicKeyAlgorithm.String(),
	}
	e.SANs = append(e.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		e.SANs = append(e.SANs, ip.String())
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		e.KeyBits = k.N.BitLen()
	case *ecdsa.PublicKey:
		e.KeyBits = k.Curve.Params().BitSize
	case ed25519.PublicKey:
		e.KeyBits = 256
	}
	return e
}

// List returns the certificates filed for an ESSID, strongest first.
func (s *Store) List(essid string) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listLocked(essid)
}

func (s *Store) listLocked(essid string) ([]Entry, error) {
	dir := filepath.Join(s.dir, sanitise(essid))
	items, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("certs: read %s: %w", dir, err)
	}

	selected := s.readSelection(essid)

	var out []Entry
	for _, it := range items {
		if !it.IsDir() {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, it.Name(), "meta.json"))
		if err != nil {
			continue
		}
		var e Entry
		if err := json.Unmarshal(body, &e); err != nil {
			continue
		}
		e.Expired = time.Now().After(e.NotAfter)
		e.Selected = e.ID == selected
		out = append(out, e)
	}

	// Strongest first, then newest. The list is read top-down by someone deciding what to put
	// on the air, and the best answer should be the first line.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Selected != out[j].Selected {
			return out[i].Selected
		}
		if a, b := out[i].Source.Strength(), out[j].Source.Strength(); a != b {
			return a > b
		}
		return out[i].Created.After(out[j].Created)
	})
	return out, nil
}

// Select records which certificate the rogue will present.
func (s *Store) Select(essid, id string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	list, err := s.listLocked(essid)
	if err != nil {
		return Entry{}, err
	}
	for _, e := range list {
		if e.ID != id {
			continue
		}
		if err := s.selectLocked(essid, id); err != nil {
			return Entry{}, err
		}
		e.Selected = true
		return e, nil
	}
	return Entry{}, fmt.Errorf("%w: %q for %q", ErrNotFound, id, essid)
}

func (s *Store) selectLocked(essid, id string) error {
	dir := filepath.Join(s.dir, sanitise(essid))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "selected"), []byte(id+"\n"), 0o600)
}

func (s *Store) readSelection(essid string) string {
	body, err := os.ReadFile(filepath.Join(s.dir, sanitise(essid), "selected"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// Selected returns the certificate the rogue should present, and the loaded pair.
//
// Returns ok=false when the library holds nothing for this ESSID; the caller then generates a
// self-signed fallback rather than refusing to start. A rogue that will not come up because
// nobody prepared a certificate is worse than one that comes up with a weak pretext and says
// so plainly.
func (s *Store) Selected(essid string) (Entry, tls.Certificate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selectedPairLocked(essid)
}

func (s *Store) selectedLocked(essid string) (Entry, bool) {
	e, _, ok := s.selectedPairLocked(essid)
	return e, ok
}

func (s *Store) selectedPairLocked(essid string) (Entry, tls.Certificate, bool) {
	list, err := s.listLocked(essid)
	if err != nil || len(list) == 0 {
		return Entry{}, tls.Certificate{}, false
	}

	want := s.readSelection(essid)
	chosen := list[0] // strongest, as a fallback if the selection is stale
	for _, e := range list {
		if e.ID == want {
			chosen = e
			break
		}
	}

	pair, err := tls.LoadX509KeyPair(chosen.CertPath, chosen.KeyPath)
	if err != nil {
		return Entry{}, tls.Certificate{}, false
	}
	chosen.Selected = true
	return chosen, pair, true
}

// Delete removes a certificate from the library.
func (s *Store) Delete(essid, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Join(s.dir, sanitise(essid), id)
	if _, err := os.Stat(dir); err != nil {
		return fmt.Errorf("%w: %q", ErrNotFound, id)
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("certs: remove %s: %w", dir, err)
	}
	if s.readSelection(essid) == id {
		// Leave nothing selected rather than a dangling id; Selected falls back to the
		// strongest remaining certificate.
		_ = os.Remove(filepath.Join(s.dir, sanitise(essid), "selected"))
	}
	return nil
}

// sanitise reduces an ESSID to a directory name. A network name is attacker-controlled text
// off the air and may contain slashes, dots or control characters.
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
		return "unnamed"
	}
	return string(out)
}
