package certs

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/eap/mimic"
)

func store(t *testing.T) *Store {
	t.Helper()
	return Open(t.TempDir())
}

// TestGenerateUsesTheOperatorsFieldsVerbatim.
//
// A mimic always carries a distinguishing mark because it is a copy of somebody's real
// certificate. This is not a copy — it is what the operator typed — and silently mutating
// typed input would be worse than the risk it guards against.
func TestGenerateUsesTheOperatorsFieldsVerbatim(t *testing.T) {
	s := store(t)

	e, err := s.Generate("ACME-CORP", Fields{
		CommonName:         "radius.acme-corp.internal",
		Organization:       "ACME Corporation",
		OrganizationalUnit: "IT Infrastructure",
		Country:            "US",
		IssuerCommonName:   "ACME Corporate Issuing CA",
		IssuerOrganization: "ACME Corporation",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if !strings.Contains(e.Subject, "CN=radius.acme-corp.internal") {
		t.Errorf("subject = %q, want the common name exactly as typed", e.Subject)
	}
	if strings.Contains(e.Subject, "internal ") {
		t.Error("the typed common name was mutated; only a mimic carries the mark")
	}
	if !strings.Contains(e.Issuer, "ACME Corporate Issuing CA") {
		t.Errorf("issuer = %q, want the issuing authority as typed", e.Issuer)
	}
	if !strings.Contains(e.Subject, "IT Infrastructure") {
		t.Errorf("subject = %q, missing the organizational unit", e.Subject)
	}
}

// TestAHostnameCommonNameGetsASAN.
//
// A supplicant checking the server name matches on the SANs, not the common name. A
// certificate whose CN is a hostname and which carries no SAN is refused by anything modern
// before a human ever sees it — so an operator who typed only a CN gets one anyway.
func TestAHostnameCommonNameGetsASAN(t *testing.T) {
	s := store(t)

	e, err := s.Generate("ACME-CORP", Fields{CommonName: "radius.acme-corp.internal"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(e.SANs) == 0 || e.SANs[0] != "radius.acme-corp.internal" {
		t.Errorf("SANs = %v, want the common name mirrored", e.SANs)
	}

	// A descriptive name is not a hostname and must not become one.
	e, err = s.Generate("ACME-CORP", Fields{CommonName: "ACME RADIUS Server"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(e.SANs) != 0 {
		t.Errorf("SANs = %v, want none for a descriptive common name", e.SANs)
	}
}

// TestTheIssuerNeverMatchesTheSubjectByAccident: a leaf issued by an authority with its own
// name reads as self-signed in every viewer, which is the one thing a hand-authored
// certificate should not do.
func TestTheIssuerNeverMatchesTheSubjectByAccident(t *testing.T) {
	s := store(t)

	e, err := s.Generate("ACME-CORP", Fields{CommonName: "radius.acme.example"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if e.Issuer == e.Subject {
		t.Errorf("issuer and subject are identical (%q); it reads as self-signed", e.Subject)
	}
	if !strings.Contains(e.Issuer, "Issuing CA") {
		t.Errorf("issuer = %q, want a derived authority name", e.Issuer)
	}
}

func TestGenerateNeedsACommonName(t *testing.T) {
	if _, err := store(t).Generate("ACME-CORP", Fields{}); err == nil {
		t.Fatal("a certificate with no common name was generated")
	}
}

// TestImportValidatesThePairBeforeWritingAnything.
//
// A certificate whose key does not match would otherwise surface as the rogue access point
// refusing to start, halfway through an engagement.
func TestImportValidatesThePairBeforeWritingAnything(t *testing.T) {
	s := store(t)

	a, err := mimic.SelfSigned("ACME-CORP", mimic.Options{})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	b, err := mimic.SelfSigned("OTHER-NET", mimic.Options{})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	if _, err := s.Import("ACME-CORP", "", a.LeafPEM, b.KeyPEM); err == nil {
		t.Fatal("a mismatched certificate and key were imported")
	}
	if list, _ := s.List("ACME-CORP"); len(list) != 0 {
		t.Errorf("a failed import left %d entries behind", len(list))
	}

	e, err := s.Import("ACME-CORP", "from the client's own CA", a.LeafPEM, a.KeyPEM)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if e.Source != SourceImported {
		t.Errorf("source = %q, want %q", e.Source, SourceImported)
	}
	if e.Note == "" {
		t.Error("the operator's note was not kept")
	}
}

// TestTheStrongestCertificateIsSelectedAutomatically.
//
// Harvesting a certificate and then having the rogue go on presenting a self-signed one
// because nobody pressed a second button is exactly the trap this avoids.
func TestTheStrongestCertificateIsSelectedAutomatically(t *testing.T) {
	s := store(t)

	if _, err := s.AddSelfSigned("ACME-CORP"); err != nil {
		t.Fatalf("AddSelfSigned: %v", err)
	}
	sel, _, ok := s.Selected("ACME-CORP")
	if !ok || sel.Source != SourceSelfSigned {
		t.Fatalf("selected = %q, want the only certificate there is", sel.Source)
	}

	// A generated one is better than self-signed.
	if _, err := s.Generate("ACME-CORP", Fields{CommonName: "radius.acme.example"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if sel, _, _ = s.Selected("ACME-CORP"); sel.Source != SourceGenerated {
		t.Errorf("selected = %q, want %q", sel.Source, SourceGenerated)
	}

	// And a mimic is better than that.
	chain, err := mimic.Generate(mimic.Harvested{
		Subject: pkixName("radius.acme-corp.internal"),
		Issuer:  pkixName("ACME Corporate Issuing CA"),
		KeyBits: 2048,
	}, mimic.Options{})
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, err := s.AddMimic("ACME-CORP", "harvested at a4:2b:8c:11:22:33", chain); err != nil {
		t.Fatalf("AddMimic: %v", err)
	}
	if sel, _, _ = s.Selected("ACME-CORP"); sel.Source != SourceMimic {
		t.Errorf("selected = %q, want %q — a harvested mimic outranks everything", sel.Source, SourceMimic)
	}

	// The strongest is first in the listing, because that list is read by someone deciding
	// what to put on the air.
	list, err := s.List("ACME-CORP")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("listed %d certificates, want 3", len(list))
	}
	if list[0].Source != SourceMimic || !list[0].Selected {
		t.Errorf("first entry is %q selected=%t; want the selected mimic",
			list[0].Source, list[0].Selected)
	}
}

// TestSelectingIsRememberedAcrossRestart: which certificate goes on the air is engagement
// state, not a runtime flag, so a daemon restart presents the same one.
func TestSelectingIsRememberedAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)

	weak, err := s.AddSelfSigned("ACME-CORP")
	if err != nil {
		t.Fatalf("AddSelfSigned: %v", err)
	}
	if _, err := s.Generate("ACME-CORP", Fields{CommonName: "radius.acme.example"}); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// Deliberately pick the weaker one — an operator may want the control case.
	if _, err := s.Select("ACME-CORP", weak.ID); err != nil {
		t.Fatalf("Select: %v", err)
	}

	reopened := Open(dir)
	sel, pair, ok := reopened.Selected("ACME-CORP")
	if !ok {
		t.Fatal("nothing selected after reopening")
	}
	if sel.ID != weak.ID {
		t.Errorf("selected %q after restart, want the operator's choice %q", sel.ID, weak.ID)
	}
	if len(pair.Certificate) == 0 {
		t.Error("the selected certificate did not load as a usable pair")
	}
}

func TestSelectingSomethingThatIsNotThereFails(t *testing.T) {
	s := store(t)
	if _, err := s.Select("ACME-CORP", "deadbeef"); err == nil {
		t.Fatal("selecting an unknown certificate succeeded")
	}
}

// TestDeletingTheSelectedCertificateFallsBack: nothing dangling, and the rogue still starts.
func TestDeletingTheSelectedCertificateFallsBack(t *testing.T) {
	s := store(t)

	if _, err := s.AddSelfSigned("ACME-CORP"); err != nil {
		t.Fatalf("AddSelfSigned: %v", err)
	}
	gen, err := s.Generate("ACME-CORP", Fields{CommonName: "radius.acme.example"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	if err := s.Delete("ACME-CORP", gen.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	sel, _, ok := s.Selected("ACME-CORP")
	if !ok {
		t.Fatal("deleting the selected certificate left nothing usable")
	}
	if sel.Source != SourceSelfSigned {
		t.Errorf("fell back to %q, want the remaining certificate", sel.Source)
	}
}

// TestKeysAreNotWorldReadable: this directory holds private keys.
func TestKeysAreNotWorldReadable(t *testing.T) {
	s := store(t)
	e, err := s.Generate("ACME-CORP", Fields{CommonName: "radius.acme.example"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, p := range []string{e.CertPath, e.KeyPath} {
		info, err := osStat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s is mode %04o; group and other access must be denied", p, perm)
		}
	}
}

// TestExpiryIsReported: an expired certificate is rejected before a name is ever displayed,
// which would waste the engagement's one chance at a click-through.
func TestExpiryIsReported(t *testing.T) {
	s := store(t)
	e, err := s.Generate("ACME-CORP", Fields{
		CommonName: "radius.acme.example", ValidityDays: 1,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if e.Expired {
		t.Error("a freshly generated certificate reports as expired")
	}
	if e.NotAfter.Before(time.Now()) {
		t.Error("a freshly generated certificate has already expired")
	}
	if e.KeyBits != 2048 {
		t.Errorf("key bits = %d, want the 2048 default", e.KeyBits)
	}
	if e.KeyAlgorithm != x509.RSA.String() {
		t.Errorf("key algorithm = %q, want RSA", e.KeyAlgorithm)
	}
}

func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

func osStat(p string) (os.FileInfo, error) { return os.Stat(p) }

// TestEmailLandsInTheSubject.
//
// eaphammer's certwizard prompts for an email, and some enterprise CAs carry emailAddress in
// the subject DN. A mimic of one that does must reproduce it, or a client displaying the full
// subject shows a visibly different string.
func TestEmailLandsInTheSubject(t *testing.T) {
	s := store(t)
	e, err := s.Generate("ACME-CORP", Fields{
		CommonName: "radius.acme.example",
		Email:      "noc@acme.example",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(e.Subject, "noc@acme.example") {
		t.Errorf("subject %q does not carry the email address", e.Subject)
	}
}
