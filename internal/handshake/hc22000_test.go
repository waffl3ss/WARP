package handshake

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	apMAC  = [6]byte{0xa4, 0x2b, 0x8c, 0x11, 0x22, 0x33}
	staMAC = [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
)

// TestPMKIDLineFormat pins the exact wire format. The line goes to a separate cracking rig,
// so nothing here can be validated by the tool that produced it.
func TestPMKIDLineFormat(t *testing.T) {
	pmkid := fill(16, 0xAB)

	line, err := PMKIDLine(pmkid, apMAC, staMAC, "CORP-WIFI")
	if err != nil {
		t.Fatalf("PMKIDLine: %v", err)
	}

	fields, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if fields[1] != "01" {
		t.Errorf("hash type = %q, want 01", fields[1])
	}
	if fields[2] != strings.Repeat("ab", 16) {
		t.Errorf("PMKID field = %q", fields[2])
	}
	if fields[3] != "a42b8c112233" {
		t.Errorf("AP MAC = %q, want a42b8c112233 (lowercase, no separators)", fields[3])
	}
	if fields[4] != "deadbeef0001" {
		t.Errorf("STA MAC = %q", fields[4])
	}
	// The ESSID is hex-encoded because it is an octet string that may contain the separator.
	if want := hex.EncodeToString([]byte("CORP-WIFI")); fields[5] != want {
		t.Errorf("ESSID = %q, want %q", fields[5], want)
	}
	for i := 6; i < 9; i++ {
		if fields[i] != "" {
			t.Errorf("field %d should be empty for a PMKID line, got %q", i, fields[i])
		}
	}
	if !strings.HasSuffix(line, "***") {
		t.Errorf("PMKID line should end in three separators: %q", line)
	}
}

func TestPMKIDLineRejectsBadInput(t *testing.T) {
	tests := []struct {
		name  string
		pmkid []byte
		essid string
	}{
		{"zero PMKID is not crackable", make([]byte, 16), "CORP-WIFI"},
		{"short PMKID", fill(8, 0xAB), "CORP-WIFI"},
		{"long PMKID", fill(20, 0xAB), "CORP-WIFI"},
		{"no ESSID (it is the PBKDF2 salt)", fill(16, 0xAB), ""},
		{"oversized ESSID", fill(16, 0xAB), strings.Repeat("x", 33)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PMKIDLine(tc.pmkid, apMAC, staMAC, tc.essid); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestEAPOLLineFormat(t *testing.T) {
	k, _ := ParseEAPOLKey(m2Frame(1))
	zeroed := k.ZeroMIC()

	line, err := EAPOLLine(k.MIC[:], apMAC, staMAC, "CORP-WIFI", anonce, zeroed, PairM12E2)
	if err != nil {
		t.Fatalf("EAPOLLine: %v", err)
	}

	fields, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine: %v", err)
	}
	if fields[1] != "02" {
		t.Errorf("hash type = %q, want 02", fields[1])
	}
	if fields[2] != strings.Repeat("9c", 16) {
		t.Errorf("MIC = %q", fields[2])
	}
	if fields[6] != hex.EncodeToString(anonce) {
		t.Errorf("ANonce = %q", fields[6])
	}
	if fields[7] != hex.EncodeToString(zeroed) {
		t.Errorf("EAPOL frame field does not match the zeroed frame")
	}
	if fields[8] != "00" {
		t.Errorf("MESSAGEPAIR = %q, want 00 for M1+M2", fields[8])
	}
}

// TestEAPOLLineRefusesUnzeroedMIC is the guard on the mistake that is invisible until the
// cracking rig has already run.
func TestEAPOLLineRefusesUnzeroedMIC(t *testing.T) {
	k, _ := ParseEAPOLKey(m2Frame(1))

	_, err := EAPOLLine(k.MIC[:], apMAC, staMAC, "CORP-WIFI", anonce, k.Raw, PairM12E2)
	if err == nil {
		t.Fatal("an EAPOL frame with its MIC still in place was accepted; the hash could never crack")
	}
	if !strings.Contains(err.Error(), "zeroed") {
		t.Errorf("error should explain the MIC must be zeroed: %v", err)
	}
}

func TestEAPOLLineRejectsBadInput(t *testing.T) {
	k, _ := ParseEAPOLKey(m2Frame(1))
	zeroed := k.ZeroMIC()

	tests := []struct {
		name   string
		mic    []byte
		anonce []byte
		eapol  []byte
		essid  string
	}{
		{"short MIC", fill(8, 1), anonce, zeroed, "CORP-WIFI"},
		{"zero MIC", make([]byte, micLen), anonce, zeroed, "CORP-WIFI"},
		{"short ANonce", k.MIC[:], fill(16, 1), zeroed, "CORP-WIFI"},
		{"zero ANonce", k.MIC[:], make([]byte, nonceLen), zeroed, "CORP-WIFI"},
		{"truncated EAPOL frame", k.MIC[:], anonce, zeroed[:20], "CORP-WIFI"},
		{"no ESSID", k.MIC[:], anonce, zeroed, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := EAPOLLine(tc.mic, apMAC, staMAC, tc.essid, tc.anonce, tc.eapol, PairM12E2); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestMessagePairEncoding pins the values hashcat expects. A wrong MESSAGEPAIR yields a hash
// that either fails to crack or is rejected outright.
func TestMessagePairEncoding(t *testing.T) {
	tests := []struct {
		pair MessagePair
		want string
	}{
		{PairM12E2, "00"},
		{PairM14E4, "01"},
		{PairM32E2, "02"},
		{PairM32E3, "03"},
		{PairM34E3, "04"},
		{PairM34E4, "05"},
		{PairM12E2 | PairFlagNC, "80"},
		{PairM34E4 | PairFlagNC, "85"},
		{PairM12E2 | PairFlagAPLess, "10"},
	}
	for _, tc := range tests {
		if got := tc.pair.String(); got != tc.want {
			t.Errorf("MessagePair(%d).String() = %q, want %q", uint8(tc.pair), got, tc.want)
		}
	}

	// Flags must not corrupt the base value.
	if got := (PairM34E4 | PairFlagNC).Base(); got != PairM34E4 {
		t.Errorf("Base() with NC set = %d, want %d", uint8(got), uint8(PairM34E4))
	}
	if !(PairM12E2 | PairFlagNC).NonceCorrection() {
		t.Error("NonceCorrection() false with the NC flag set")
	}
	if (PairM12E2).NonceCorrection() {
		t.Error("NonceCorrection() true with no flag set")
	}
}

func TestParseLineRejectsMalformed(t *testing.T) {
	tests := []string{
		"",
		"WPA*02*aa*bb*cc",              // too few fields
		"NOTWPA*01*a*b*c*d***",         // wrong prefix
		"WPA*99*a*b*c*d***",            // unknown type
		"WPA*01*a*b*c*d***" + "*extra", // too many fields
	}
	for _, line := range tests {
		if _, err := ParseLine(line); err == nil {
			t.Errorf("ParseLine(%q) should have failed", line)
		}
	}
}

// TestESSIDWithSeparatorSurvivesHexEncoding: an ESSID may legally contain an asterisk, which
// is the field separator. Hex encoding is what makes that safe.
func TestESSIDWithSeparatorSurvivesHexEncoding(t *testing.T) {
	essid := "CORP*WIFI"

	line, err := PMKIDLine(fill(16, 1), apMAC, staMAC, essid)
	if err != nil {
		t.Fatalf("PMKIDLine: %v", err)
	}
	fields, err := ParseLine(line)
	if err != nil {
		t.Fatalf("ParseLine: %v — the separator inside the ESSID broke the line", err)
	}
	decoded, err := hex.DecodeString(fields[5])
	if err != nil {
		t.Fatalf("decode ESSID: %v", err)
	}
	if string(decoded) != essid {
		t.Errorf("ESSID round trip = %q, want %q", decoded, essid)
	}
}

// TestNonUTF8ESSIDIsPreserved: SSIDs are octet strings, not text.
func TestNonUTF8ESSIDIsPreserved(t *testing.T) {
	essid := string([]byte{0xFF, 0xFE, 0x00, 0x41})

	line, err := PMKIDLine(fill(16, 1), apMAC, staMAC, essid)
	if err != nil {
		t.Fatalf("PMKIDLine: %v", err)
	}
	fields, _ := ParseLine(line)
	decoded, _ := hex.DecodeString(fields[5])
	if string(decoded) != essid {
		t.Errorf("non-UTF-8 ESSID was mangled: % x, want % x", decoded, []byte(essid))
	}
}

// ---------------------------------------------------------------------------
// Writer
// ---------------------------------------------------------------------------

func TestWriterDeduplicatesOnFullLine(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, "pmkid.22000", "handshakes.22000")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	line, _ := PMKIDLine(fill(16, 0xAB), apMAC, staMAC, "CORP-WIFI")
	r := Result{Kind: KindPMKID, Line: line, AP: apMAC, STA: staMAC, ESSID: "CORP-WIFI", At: time.Now(), InScope: true}

	for i := 0; i < 5; i++ {
		wrote, err := w.Write(r)
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if i == 0 && !wrote {
			t.Fatal("first write reported a duplicate")
		}
		if i > 0 && wrote {
			t.Fatalf("write %d was not deduplicated", i)
		}
	}

	// A genuinely different handshake at the same BSSID must still be written: deduplicating
	// on BSSID would drop real captures.
	other, _ := PMKIDLine(fill(16, 0xCD), apMAC, staMAC, "CORP-WIFI")
	wrote, err := w.Write(Result{Kind: KindPMKID, Line: other, ESSID: "CORP-WIFI", InScope: true})
	if err != nil || !wrote {
		t.Fatalf("a different PMKID at the same BSSID was suppressed (wrote=%v err=%v)", wrote, err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "pmkid.22000"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if n := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; n != 2 {
		t.Errorf("file has %d lines, want 2:\n%s", n, data)
	}
}

// TestWriterSeparatesKinds: PMKIDs and EAPOL hashes go to separate files so the operator can
// prioritise PMKIDs on the rig.
func TestWriterSeparatesKinds(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir, "pmkid.22000", "handshakes.22000")
	defer w.Close()

	pmkidLine, _ := PMKIDLine(fill(16, 0xAB), apMAC, staMAC, "CORP-WIFI")
	k, _ := ParseEAPOLKey(m2Frame(1))
	eapolLine, _ := EAPOLLine(k.MIC[:], apMAC, staMAC, "CORP-WIFI", anonce, k.ZeroMIC(), PairM12E2)

	if _, err := w.Write(Result{Kind: KindPMKID, Line: pmkidLine, InScope: true}); err != nil {
		t.Fatalf("write PMKID: %v", err)
	}
	if _, err := w.Write(Result{Kind: KindHandshake, Line: eapolLine, InScope: true}); err != nil {
		t.Fatalf("write EAPOL: %v", err)
	}

	p, _ := os.ReadFile(filepath.Join(dir, "pmkid.22000"))
	e, _ := os.ReadFile(filepath.Join(dir, "handshakes.22000"))
	if !strings.Contains(string(p), "WPA*01") || strings.Contains(string(p), "WPA*02") {
		t.Errorf("pmkid file has the wrong contents:\n%s", p)
	}
	if !strings.Contains(string(e), "WPA*02") || strings.Contains(string(e), "WPA*01") {
		t.Errorf("handshake file has the wrong contents:\n%s", e)
	}

	pc, ec := w.Counts()
	if pc != 1 || ec != 1 {
		t.Errorf("counts = (%d, %d), want (1, 1)", pc, ec)
	}
}

// TestWriterDedupSurvivesRestart: a NUC rebooting mid-engagement must not append a second
// copy of every hash it already holds.
func TestWriterDedupSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	line, _ := PMKIDLine(fill(16, 0xAB), apMAC, staMAC, "CORP-WIFI")

	w1, _ := NewWriter(dir, "pmkid.22000", "handshakes.22000")
	if wrote, _ := w1.Write(Result{Kind: KindPMKID, Line: line, InScope: true}); !wrote {
		t.Fatal("first write was suppressed")
	}
	w1.Close()

	w2, err := NewWriter(dir, "pmkid.22000", "handshakes.22000")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()

	if wrote, _ := w2.Write(Result{Kind: KindPMKID, Line: line, InScope: true}); wrote {
		t.Fatal("a hash already on disk was appended again after restart")
	}
	if pc, _ := w2.Counts(); pc != 1 {
		t.Errorf("count after restart = %d, want 1", pc)
	}
}

// TestWriterFileIsValidAtEveryInstant: the box may be powered off at any moment, so a hash
// must be complete on disk the moment Write returns.
func TestWriterFileIsValidAtEveryInstant(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir, "pmkid.22000", "handshakes.22000")
	defer w.Close()

	for i := 0; i < 3; i++ {
		line, _ := PMKIDLine(fill(16, byte(i+1)), apMAC, staMAC, "CORP-WIFI")
		if _, err := w.Write(Result{Kind: KindPMKID, Line: line, InScope: true}); err != nil {
			t.Fatalf("Write: %v", err)
		}

		// Read the file back immediately, as a separate reader would after a power cut.
		data, err := os.ReadFile(filepath.Join(dir, "pmkid.22000"))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != i+1 {
			t.Fatalf("after %d writes the file holds %d lines", i+1, len(lines))
		}
		for _, l := range lines {
			if _, err := ParseLine(l); err != nil {
				t.Fatalf("line on disk is not parseable: %v", err)
			}
		}
	}
}

func TestWriterPermissions(t *testing.T) {
	dir := t.TempDir()
	w, _ := NewWriter(dir, "pmkid.22000", "handshakes.22000")
	defer w.Close()

	line, _ := PMKIDLine(fill(16, 1), apMAC, staMAC, "CORP-WIFI")
	w.Write(Result{Kind: KindPMKID, Line: line, InScope: true})

	fi, err := os.Stat(filepath.Join(dir, "pmkid.22000"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// These are credential material.
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("hash file mode is %04o; group/other access must be denied", perm)
	}
}

// TestIncidentalCapturesAreKeptOutOfTheDeliverable.
//
// Capture is passive, so WARP hears handshakes from networks the engagement has no authority
// over, and it keeps them — a frame already received cannot be un-received, and quietly
// discarding evidence is worse than holding it. But cracking one is unauthorized work on
// someone else's credentials, and a 22000 file has no comment syntax, so the file is the
// only place the distinction can live.
//
// The failure this prevents is quiet and expensive: `cat *.22000 | ssh rig` picks up a
// neighbour's handshake along with the client's, and nobody notices until it is cracked.
func TestIncidentalCapturesAreKeptOutOfTheDeliverable(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, "pmkid.22000", "handshakes.22000")
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	defer w.Close()

	const (
		scoped   = "WPA*01*1111111111111111111111111111111f*a42b8c112201*deadbeef1001*434f52502d57494649***"
		unscoped = "WPA*01*2222222222222222222222222222222f*b42b8c112202*deadbeef1002*4e4549474842***"
	)

	if _, err := w.Write(Result{Kind: KindPMKID, Line: scoped, ESSID: "CORP-WIFI", InScope: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(Result{Kind: KindPMKID, Line: unscoped, ESSID: "NEIGHB", InScope: false}); err != nil {
		t.Fatal(err)
	}

	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}

	deliverable := read("pmkid.22000")
	if !strings.Contains(deliverable, scoped) {
		t.Error("the in-scope capture is missing from the deliverable")
	}
	if strings.Contains(deliverable, unscoped) {
		t.Fatal("an out-of-scope capture landed in the deliverable; it could be cracked by accident")
	}

	incidental := read("out-of-scope-pmkid.22000")
	if !strings.Contains(incidental, unscoped) {
		t.Error("the out-of-scope capture was not kept at all — evidence was discarded")
	}

	// The engagement's totals count the deliverable, not the incidental material.
	if p, e := w.Counts(); p != 1 || e != 0 {
		t.Errorf("Counts() = (%d, %d), want (1, 0)", p, e)
	}
	if p, e := w.OutOfScopeCounts(); p != 1 || e != 0 {
		t.Errorf("OutOfScopeCounts() = (%d, %d), want (1, 0)", p, e)
	}

	// A glob for the deliverable must not sweep the incidental file up with it.
	matches, err := filepath.Glob(filepath.Join(dir, "*.22000"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range matches {
		if strings.HasPrefix(filepath.Base(m), "out-of-scope-") {
			continue
		}
		if body, _ := os.ReadFile(m); strings.Contains(string(body), unscoped) {
			t.Errorf("%s is picked up by *.22000 and contains out-of-scope material", m)
		}
	}
}

// TestAnUnlabelledCaptureIsTreatedAsIncidental. The zero value has to be the safe one: a
// caller that forgets to set InScope must not silently add material to the deliverable.
func TestAnUnlabelledCaptureIsTreatedAsIncidental(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir, "pmkid.22000", "handshakes.22000")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	const line = "WPA*01*3333333333333333333333333333333f*c42b8c112203*deadbeef1003*54455354***"
	if _, err := w.Write(Result{Kind: KindPMKID, Line: line}); err != nil {
		t.Fatal(err)
	}

	if b, _ := os.ReadFile(filepath.Join(dir, "pmkid.22000")); strings.Contains(string(b), line) {
		t.Error("an unlabelled capture was added to the deliverable")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "out-of-scope-pmkid.22000")); !strings.Contains(string(b), line) {
		t.Error("an unlabelled capture was lost entirely")
	}
}
