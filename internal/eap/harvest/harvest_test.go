package harvest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildCert makes a certificate for a synthetic chain.
func buildCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, signerKey := parent, parentKey
	if signer == nil {
		signer, signerKey = tmpl, key // self-signed
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

func realisticChain(t *testing.T) []*x509.Certificate {
	t.Helper()
	now := time.Now()

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Example Corp Issuing CA", Organization: []string{"Example Corp"}},
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	ca, caKey := buildCert(t, caTmpl, nil, nil)

	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(4096),
		Subject:               pkix.Name{CommonName: "radius.corp.example", Organization: []string{"Example Corp"}},
		NotBefore:             now.Add(-30 * 24 * time.Hour),
		NotAfter:              now.Add(300 * 24 * time.Hour),
		DNSNames:              []string{"radius.corp.example", "radius2.corp.example"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	leaf, _ := buildCert(t, leafTmpl, ca, caKey)

	return []*x509.Certificate{leaf, ca}
}

func TestHarvestExtractsEverythingReportable(t *testing.T) {
	state := tls.ConnectionState{
		Version:          tls.VersionTLS12,
		CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		PeerCertificates: realisticChain(t),
	}

	res, err := FromConnectionState("CORP-8021X", "a4:2b:8c:11:22:33", state)
	if err != nil {
		t.Fatalf("FromConnectionState: %v", err)
	}

	if len(res.Chain) != 2 {
		t.Fatalf("captured %d certificates, want the full chain of 2", len(res.Chain))
	}

	leaf, ok := res.Leaf()
	if !ok {
		t.Fatal("no leaf")
	}

	// Everything the brief requires: subject DN, issuer DN, SANs, validity, serial, key
	// algorithm and size, signature algorithm, fingerprint.
	if !strings.Contains(leaf.Subject, "radius.corp.example") {
		t.Errorf("Subject = %q", leaf.Subject)
	}
	if !strings.Contains(leaf.Issuer, "Example Corp Issuing CA") {
		t.Errorf("Issuer = %q", leaf.Issuer)
	}
	if len(leaf.SANs) != 2 {
		t.Errorf("SANs = %v, want both", leaf.SANs)
	}
	if leaf.Serial != "4096" {
		t.Errorf("Serial = %q", leaf.Serial)
	}
	if leaf.KeyAlgorithm != "RSA" || leaf.KeyBits != 2048 {
		t.Errorf("key = %s-%d, want RSA-2048", leaf.KeyAlgorithm, leaf.KeyBits)
	}
	if leaf.SigAlgorithm == "" {
		t.Error("signature algorithm not recorded")
	}
	if len(leaf.Fingerprint) != 64 {
		t.Errorf("fingerprint = %q, want a SHA-256 hex digest", leaf.Fingerprint)
	}
	if leaf.IsCA {
		t.Error("the leaf was marked as a CA")
	}
	if !res.Chain[1].IsCA {
		t.Error("the issuing CA was not marked as one")
	}

	// The PEM must contain the whole chain, so the file stands alone.
	if n := strings.Count(string(res.PEM), "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("PEM holds %d certificates, want 2", n)
	}

	// A healthy chain produces no alarming notes.
	for _, note := range res.Notes {
		if strings.Contains(note, "expired") || strings.Contains(note, "self-signed") {
			t.Errorf("unexpected note on a healthy chain: %q", note)
		}
	}
}

// TestWeakChainProducesFindings: the notes are report content, so each weakness must surface.
func TestWeakChainProducesFindings(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		build    func(t *testing.T) tls.ConnectionState
		wantNote string
	}{
		{
			name:     "self-signed server certificate",
			wantNote: "self-signed",
			build: func(t *testing.T) tls.ConnectionState {
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(7),
					Subject:      pkix.Name{CommonName: "radius.corp.example"},
					NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
					DNSNames:              []string{"radius.corp.example"},
					BasicConstraintsValid: true,
				}
				cert, _ := buildCert(t, tmpl, nil, nil)
				return tls.ConnectionState{Version: tls.VersionTLS12,
					PeerCertificates: []*x509.Certificate{cert}}
			},
		},
		{
			name:     "expired server certificate",
			wantNote: "expired",
			build: func(t *testing.T) tls.ConnectionState {
				tmpl := &x509.Certificate{
					SerialNumber:          big.NewInt(8),
					Subject:               pkix.Name{CommonName: "old.corp.example"},
					NotBefore:             now.Add(-800 * 24 * time.Hour),
					NotAfter:              now.Add(-400 * 24 * time.Hour),
					DNSNames:              []string{"old.corp.example"},
					BasicConstraintsValid: true,
				}
				cert, _ := buildCert(t, tmpl, nil, nil)
				return tls.ConnectionState{Version: tls.VersionTLS12,
					PeerCertificates: []*x509.Certificate{cert}}
			},
		},
		{
			name:     "no subject alternative names",
			wantNote: "subject alternative names",
			build: func(t *testing.T) tls.ConnectionState {
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(9),
					Subject:      pkix.Name{CommonName: "radius.corp.example"},
					NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
					BasicConstraintsValid: true,
				}
				cert, _ := buildCert(t, tmpl, nil, nil)
				return tls.ConnectionState{Version: tls.VersionTLS12,
					PeerCertificates: []*x509.Certificate{cert}}
			},
		},
		{
			name:     "obsolete TLS version",
			wantNote: "TLS 1.0",
			build: func(t *testing.T) tls.ConnectionState {
				return tls.ConnectionState{Version: tls.VersionTLS10,
					PeerCertificates: realisticChain(t)}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := FromConnectionState("CORP-8021X", "", tc.build(t))
			if err != nil {
				t.Fatalf("FromConnectionState: %v", err)
			}
			joined := strings.Join(res.Notes, " | ")
			if !strings.Contains(joined, tc.wantNote) {
				t.Errorf("notes do not mention %q: %s", tc.wantNote, joined)
			}
		})
	}
}

func TestNoCertificateIsAnError(t *testing.T) {
	_, err := FromConnectionState("CORP", "", tls.ConnectionState{Version: tls.VersionTLS12})
	if !errors.Is(err, ErrNoCertificate) {
		t.Fatalf("got %v, want ErrNoCertificate", err)
	}
}

// TestClientConfigSendsNoCredentials is the safety property: the harvesting supplicant has
// nothing to leak, by construction.
func TestClientConfigSendsNoCredentials(t *testing.T) {
	cfg := ClientConfig("radius.corp.example")

	if len(cfg.Certificates) != 0 {
		t.Error("the harvesting client carries a certificate; it must present nothing")
	}
	if cfg.GetClientCertificate != nil {
		t.Error("the harvesting client can supply a certificate on request")
	}
	// Verification is skipped deliberately: the whole point is to record an untrusted chain,
	// and verifying would abort before it could be captured.
	if !cfg.InsecureSkipVerify {
		t.Error("verification is enabled; the handshake would abort before the chain is captured")
	}
	if cfg.ServerName != "radius.corp.example" {
		t.Errorf("ServerName = %q", cfg.ServerName)
	}
}

func TestSaveWritesChainAndSidecar(t *testing.T) {
	state := tls.ConnectionState{
		Version:          tls.VersionTLS12,
		CipherSuite:      tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		PeerCertificates: realisticChain(t),
	}
	res, err := FromConnectionState("CORP 8021X/test", "a4:2b:8c:11:22:33", state)
	if err != nil {
		t.Fatalf("FromConnectionState: %v", err)
	}

	dir := t.TempDir()
	pemPath, jsonPath, err := res.Save(dir)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	// The ESSID contained a slash; the directory name must not have escaped.
	rel, err := filepath.Rel(dir, pemPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("harvest escaped the certs directory: %s", pemPath)
	}

	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("read PEM: %v", err)
	}
	if n := strings.Count(string(pemData), "BEGIN CERTIFICATE"); n != 2 {
		t.Errorf("PEM file holds %d certificates, want 2", n)
	}

	sidecar, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	var back Result
	if err := json.Unmarshal(sidecar, &back); err != nil {
		t.Fatalf("sidecar is not valid JSON: %v", err)
	}
	if back.ESSID != res.ESSID || len(back.Chain) != 2 {
		t.Errorf("sidecar round trip lost data: %+v", back)
	}

	for _, p := range []string{pemPath, jsonPath} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s has mode %04o; group/other access must be denied", p, perm)
		}
	}
}

// TestToMimicCarriesTheFieldsWorthMirroring checks the handoff into mimic generation.
func TestToMimicCarriesTheFieldsWorthMirroring(t *testing.T) {
	chain := realisticChain(t)
	state := tls.ConnectionState{Version: tls.VersionTLS12, PeerCertificates: chain}

	res, err := FromConnectionState("CORP-8021X", "", state)
	if err != nil {
		t.Fatalf("FromConnectionState: %v", err)
	}

	h, err := res.ToMimic(state)
	if err != nil {
		t.Fatalf("ToMimic: %v", err)
	}

	if h.Subject.CommonName != "radius.corp.example" {
		t.Errorf("subject CN = %q", h.Subject.CommonName)
	}
	// The issuer is what a trust-on-first-use prompt shows the user, so it must survive.
	if h.Issuer.CommonName != "Example Corp Issuing CA" {
		t.Errorf("issuer CN = %q", h.Issuer.CommonName)
	}
	if len(h.DNSNames) != 2 {
		t.Errorf("SANs = %v", h.DNSNames)
	}
	if h.KeyBits != 2048 || h.PublicKeyAlgorithm != x509.RSA {
		t.Errorf("key = %v-%d", h.PublicKeyAlgorithm, h.KeyBits)
	}
	if h.SerialNumber == nil || h.SerialNumber.String() != "4096" {
		t.Errorf("serial = %v", h.SerialNumber)
	}
}

func TestSanitiseESSIDForDirectory(t *testing.T) {
	tests := map[string]string{
		"CORP-WIFI": "CORP-WIFI",
		"CORP WIFI": "CORP_WIFI",
		"../escape": ".._escape",
		"a/b":       "a_b",
		"":          "unknown",
	}
	for in, want := range tests {
		if got := sanitise(in); got != want {
			t.Errorf("sanitise(%q) = %q, want %q", in, got, want)
		}
	}
}
