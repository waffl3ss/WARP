package mimic

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func harvested() Harvested {
	return Harvested{
		Subject: pkix.Name{
			CommonName:   "radius.acme-corp.example",
			Organization: []string{"ACME Corporation"},
		},
		Issuer: pkix.Name{
			CommonName:   "ACME Corporation Internal Issuing CA 2",
			Organization: []string{"ACME Corporation"},
		},
		DNSNames:     []string{"radius.acme-corp.example"},
		IPAddresses:  []net.IP{net.ParseIP("10.20.30.40")},
		NotBefore:    time.Now().Add(-90 * 24 * time.Hour),
		NotAfter:     time.Now().Add(275 * 24 * time.Hour),
		SerialNumber: big.NewInt(0x5eaf00d),
		KeyBits:      2048,
	}
}

func leafOf(t *testing.T, c *Chain) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.TLS.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated leaf: %v", err)
	}
	return leaf
}

// TestTheMimicIsNeverAnExactCopy.
//
// A certificate byte-identical to the client's own, carrying their naming, sitting in an
// engagement directory, is a liability: if it leaks or is recovered from a decommissioned box
// there is nothing in the artefact itself that distinguishes it from theirs. Every mimic
// carries a mark, and the mark is in the subject where it is visible to a diff.
func TestTheMimicIsNeverAnExactCopy(t *testing.T) {
	h := harvested()
	chain, err := Generate(h, Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	leaf := leafOf(t, chain)

	if leaf.Subject.CommonName == h.Subject.CommonName {
		t.Fatal("the mimic's common name is byte-identical to the harvested one; there is " +
			"nothing in the certificate itself that distinguishes it from the client's")
	}
	if !IsDistinguished(leaf.Subject.CommonName) {
		t.Errorf("common name %q does not carry the distinguishing mark",
			leaf.Subject.CommonName)
	}
}

// TestTheMarkChangesNoVisibleGlyph.
//
// The mark exists to be findable in a diff, not to be seen by a user at a trust prompt.
// Click-through is what the whole enterprise module measures, and a mimic that looks visibly
// wrong measures nothing.
func TestTheMarkChangesNoVisibleGlyph(t *testing.T) {
	h := harvested()
	chain, err := Generate(h, Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	leaf := leafOf(t, chain)

	if got, want := strings.TrimSpace(leaf.Subject.CommonName), h.Subject.CommonName; got != want {
		t.Errorf("rendered common name = %q, want %q — the mark must be whitespace only, so a "+
			"trust prompt shows exactly the name the user expects", got, want)
	}
	if !strings.EqualFold(strings.Join(leaf.Subject.Organization, ","),
		strings.Join(h.Subject.Organization, ",")) {
		t.Errorf("organization = %v, want %v; only the common name is marked",
			leaf.Subject.Organization, h.Subject.Organization)
	}
}

// TestTheSANsAreNotMarked.
//
// Server-name validation matches on the SANs. Marking those would break the mimic against
// exactly the better-configured clients the test most wants to reach, turning a real finding
// into a false pass.
func TestTheSANsAreNotMarked(t *testing.T) {
	h := harvested()
	chain, err := Generate(h, Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	leaf := leafOf(t, chain)

	if len(leaf.DNSNames) != len(h.DNSNames) {
		t.Fatalf("DNS names = %v, want %v", leaf.DNSNames, h.DNSNames)
	}
	for i, name := range leaf.DNSNames {
		if name != h.DNSNames[i] {
			t.Errorf("SAN %d = %q, want %q exactly — this is what a validating client matches on",
				i, name, h.DNSNames[i])
		}
	}
	if len(leaf.IPAddresses) != len(h.IPAddresses) {
		t.Errorf("IP SANs = %v, want %v", leaf.IPAddresses, h.IPAddresses)
	}
}

// TestTheIssuerIsMirroredExactly: a client that displays the issuing authority must see the
// name it expects, and the CA is ours regardless — the mark on the leaf is what proves origin.
func TestTheIssuerIsMirroredExactly(t *testing.T) {
	h := harvested()
	chain, err := Generate(h, Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	leaf := leafOf(t, chain)

	if leaf.Issuer.CommonName != h.Issuer.CommonName {
		t.Errorf("issuer CN = %q, want %q", leaf.Issuer.CommonName, h.Issuer.CommonName)
	}
}

// TestEverythingElseIsMirrored — the fields that make a mimic plausible in a client that shows
// certificate details, and in a report screenshot.
func TestEverythingElseIsMirrored(t *testing.T) {
	h := harvested()
	chain, err := Generate(h, Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	leaf := leafOf(t, chain)

	if leaf.SerialNumber.Cmp(h.SerialNumber) != 0 {
		t.Errorf("serial = %s, want %s", leaf.SerialNumber, h.SerialNumber)
	}
	if !leaf.NotBefore.Equal(h.NotBefore.Truncate(time.Second)) &&
		leaf.NotBefore.Sub(h.NotBefore).Abs() > time.Second {
		t.Errorf("not-before = %s, want %s", leaf.NotBefore, h.NotBefore)
	}
	var serverAuth bool
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		t.Error("no ServerAuth EKU: a supplicant that checks it rejects the certificate " +
			"before showing the user a name")
	}
}

// TestSelfSignedIsGenericOnPurpose: with nothing harvested there is nothing to impersonate,
// and inventing a specific-looking organisation would put a fabricated identity on the air.
func TestSelfSignedIsGenericOnPurpose(t *testing.T) {
	chain, err := SelfSigned("ACME-CORP", Options{})
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	leaf := leafOf(t, chain)

	if len(leaf.Subject.Organization) != 0 {
		t.Errorf("a self-signed fallback claims organisation %v; it must invent nothing",
			leaf.Subject.Organization)
	}
	if !strings.Contains(leaf.Subject.CommonName, "acme-corp") {
		t.Errorf("common name %q does not derive from the ESSID", leaf.Subject.CommonName)
	}
}
