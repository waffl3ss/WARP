package inject

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/audit"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/scope"
)

func mac(t *testing.T, s string) recon.MAC {
	t.Helper()
	m, err := recon.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return m
}

func testGate(t *testing.T, essids ...string) (*scope.Gate, *bytes.Buffer) {
	t.Helper()
	set, err := scope.NewSet(essids)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	var log bytes.Buffer
	g, err := scope.NewGate(set, audit.NewWriter(&log))
	if err != nil {
		t.Fatalf("NewGate: %v", err)
	}
	return g, &log
}

// ---------------------------------------------------------------------------
// Frame construction
// ---------------------------------------------------------------------------

// stripRadiotap removes the transmit radiotap header so the 802.11 frame can be checked with
// the ordinary parser — which is the strongest available assertion that what we build is what
// a receiver will read.
func stripRadiotap(t *testing.T, frame []byte) []byte {
	t.Helper()
	if len(frame) < len(radiotapTX) {
		t.Fatalf("frame is shorter than the radiotap header")
	}
	if !bytes.Equal(frame[:len(radiotapTX)], radiotapTX) {
		t.Errorf("radiotap header = % x, want % x", frame[:len(radiotapTX)], radiotapTX)
	}
	return frame[len(radiotapTX):]
}

func TestDeauthFrameRoundTripsThroughTheParser(t *testing.T) {
	bssid := mac(t, "a4:2b:8c:11:22:33")
	target := mac(t, "de:ad:be:ef:00:01")

	raw := stripRadiotap(t, DeauthFrame(bssid, target, ReasonClass3FromNonAssoc, 7))

	f, err := recon.ParseFrame(raw)
	if err != nil {
		t.Fatalf("our own deauth frame does not parse: %v", err)
	}
	if f.Type != recon.TypeManagement || f.Subtype != recon.SubtypeDeauth {
		t.Fatalf("type/subtype = %v/%v, want mgmt/deauth", f.Type, f.Subtype)
	}
	if f.Addr1 != target {
		t.Errorf("Addr1 (destination) = %v, want the target station %v", f.Addr1, target)
	}
	if f.Addr2 != bssid || f.Addr3 != bssid {
		t.Errorf("Addr2/Addr3 = %v/%v, want the BSSID %v", f.Addr2, f.Addr3, bssid)
	}
	if got, ok := f.ReasonCode(); !ok || got != ReasonClass3FromNonAssoc {
		t.Errorf("ReasonCode = %d (ok=%v), want %d", got, ok, ReasonClass3FromNonAssoc)
	}
	if f.SeqNum != 7 {
		t.Errorf("SeqNum = %d, want 7", f.SeqNum)
	}
}

func TestAssocRequestFrameRoundTrips(t *testing.T) {
	bssid := mac(t, "a4:2b:8c:11:22:33")
	sta := mac(t, "02:11:22:33:44:55")

	frame, err := AssocRequestFrame(AssocRequestOptions{
		BSSID: bssid, STA: sta, ESSID: "CORP-WIFI", Seq: 1, RSN: DefaultRSN(),
	})
	if err != nil {
		t.Fatalf("AssocRequestFrame: %v", err)
	}

	f, err := recon.ParseFrame(stripRadiotap(t, frame))
	if err != nil {
		t.Fatalf("our own association request does not parse: %v", err)
	}
	if f.Subtype != recon.SubtypeAssocReq {
		t.Fatalf("Subtype = %v, want assoc-req", f.Subtype)
	}
	if f.Addr1 != bssid || f.Addr2 != sta {
		t.Errorf("addresses = %v/%v, want %v/%v", f.Addr1, f.Addr2, bssid, sta)
	}

	_, ies, ok := f.ManagementBody()
	if !ok {
		t.Fatal("ManagementBody returned false")
	}
	parsed, err := recon.ParseIEs(ies)
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	if essid, ok := parsed.SSID(); !ok || essid != "CORP-WIFI" {
		t.Errorf("SSID = %q (ok=%v)", essid, ok)
	}
	// The RSN element must survive, or the AP has no reason to send a PMKID.
	if !parsed.Has(recon.IERSN) {
		t.Error("RSN element missing from the association request")
	}
}

func TestAssocRequestRejectsBadESSID(t *testing.T) {
	bssid := mac(t, "a4:2b:8c:11:22:33")
	sta := mac(t, "02:11:22:33:44:55")

	if _, err := AssocRequestFrame(AssocRequestOptions{BSSID: bssid, STA: sta, ESSID: ""}); err == nil {
		t.Error("an association request with no ESSID was built")
	}
	long := make([]byte, 33)
	for i := range long {
		long[i] = 'x'
	}
	if _, err := AssocRequestFrame(AssocRequestOptions{BSSID: bssid, STA: sta, ESSID: string(long)}); err == nil {
		t.Error("an association request with a 33-octet ESSID was built")
	}
}

func TestAuthFrameRoundTrips(t *testing.T) {
	bssid := mac(t, "a4:2b:8c:11:22:33")
	sta := mac(t, "02:11:22:33:44:55")

	f, err := recon.ParseFrame(stripRadiotap(t, AuthFrame(bssid, sta, 1)))
	if err != nil {
		t.Fatalf("our own auth frame does not parse: %v", err)
	}
	if f.Subtype != recon.SubtypeAuth {
		t.Fatalf("Subtype = %v, want auth", f.Subtype)
	}
	fixed, _, ok := f.ManagementBody()
	if !ok || len(fixed) < 6 {
		t.Fatal("auth fixed fields missing")
	}
	if alg := binary.LittleEndian.Uint16(fixed[0:2]); alg != authOpenSystem {
		t.Errorf("auth algorithm = %d, want open system", alg)
	}
	if seq := binary.LittleEndian.Uint16(fixed[2:4]); seq != 1 {
		t.Errorf("transaction sequence = %d, want 1", seq)
	}
}

func TestProbeRequestFrameRoundTrips(t *testing.T) {
	sta := mac(t, "02:11:22:33:44:55")

	frame, err := ProbeRequestFrame(sta, "aBcDeFgHiJkLmNoPqRsT", 3)
	if err != nil {
		t.Fatalf("ProbeRequestFrame: %v", err)
	}
	f, err := recon.ParseFrame(stripRadiotap(t, frame))
	if err != nil {
		t.Fatalf("our own probe request does not parse: %v", err)
	}
	if f.Subtype != recon.SubtypeProbeReq {
		t.Fatalf("Subtype = %v, want probe-req", f.Subtype)
	}
	if !f.Addr1.IsBroadcast() {
		t.Errorf("Addr1 = %v, want broadcast", f.Addr1)
	}
}

func TestWithSeqRewritesOnlyTheSequenceField(t *testing.T) {
	bssid := mac(t, "a4:2b:8c:11:22:33")
	sta := mac(t, "02:11:22:33:44:55")

	original, err := AssocRequestFrame(AssocRequestOptions{
		BSSID: bssid, STA: sta, ESSID: "CORP-WIFI", Seq: 0, RSN: DefaultRSN(),
	})
	if err != nil {
		t.Fatalf("AssocRequestFrame: %v", err)
	}

	modified := withSeq(original, 42)
	if len(modified) != len(original) {
		t.Fatalf("length changed: %d → %d", len(original), len(modified))
	}

	f, err := recon.ParseFrame(stripRadiotap(t, modified))
	if err != nil {
		t.Fatalf("reseq'd frame does not parse: %v", err)
	}
	if f.SeqNum != 42 {
		t.Errorf("SeqNum = %d, want 42", f.SeqNum)
	}

	// Everything except the two sequence-control bytes must be identical.
	seqOffset := len(radiotapTX) + 22
	if !bytes.Equal(original[:seqOffset], modified[:seqOffset]) {
		t.Error("bytes before the sequence field were modified")
	}
	if !bytes.Equal(original[seqOffset+2:], modified[seqOffset+2:]) {
		t.Error("bytes after the sequence field were modified")
	}

	// The original must not be mutated: it is reused across retries.
	if orig, _ := recon.ParseFrame(stripRadiotap(t, original)); orig.SeqNum != 0 {
		t.Error("withSeq mutated its input")
	}
}

func TestRandomMACIsLocallyAdministeredUnicast(t *testing.T) {
	seen := make(map[recon.MAC]struct{})
	for i := 0; i < 50; i++ {
		m, err := RandomMAC()
		if err != nil {
			t.Fatalf("RandomMAC: %v", err)
		}
		if m.IsMulticast() {
			t.Fatalf("%v has the group bit set", m)
		}
		if !m.IsLocallyAdministered() {
			t.Fatalf("%v is not locally administered; it could collide with a real device", m)
		}
		seen[m] = struct{}{}
	}
	if len(seen) < 45 {
		t.Errorf("only %d distinct addresses in 50 draws", len(seen))
	}
}

func TestRandomESSIDIsGeneratedAndUnique(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 50; i++ {
		e, err := RandomESSID()
		if err != nil {
			t.Fatalf("RandomESSID: %v", err)
		}
		if len(e) != scope.KarmaProbeESSIDLen {
			t.Fatalf("length = %d, want %d", len(e), scope.KarmaProbeESSIDLen)
		}
		seen[e] = struct{}{}
	}
	// Regenerated per test so a device that has already seen one cannot learn to decline.
	if len(seen) != 50 {
		t.Errorf("only %d distinct ESSIDs in 50 draws", len(seen))
	}
}

// ---------------------------------------------------------------------------
// Scope enforcement
// ---------------------------------------------------------------------------

// TestInjectorRequiresAGate: an injector cannot be built without one, so a future attack
// module physically cannot skip authorization by forgetting to call it.
func TestInjectorRequiresAGate(t *testing.T) {
	if _, err := Open("mon0", 1, "phy0", nil); err == nil {
		t.Fatal("an injector was built with no scope gate")
	}
}

// TestKarmaProbeIsGatedAndAudited: the one transmission not decided by ESSID match still goes
// through the gate and still lands in the audit log.
func TestKarmaProbeIsGatedAndAudited(t *testing.T) {
	g, log := testGate(t, "CORP-WIFI")
	ctx := context.Background()

	essid, err := RandomESSID()
	if err != nil {
		t.Fatalf("RandomESSID: %v", err)
	}
	if err := g.AuthorizeKarmaProbe(ctx, "karma-probe", essid, 6, "phy1"); err != nil {
		t.Fatalf("a generated karma probe ESSID was refused: %v", err)
	}
	if !bytes.Contains(log.Bytes(), []byte("karma_detection")) {
		t.Errorf("karma probe was not recorded in the audit log:\n%s", log.String())
	}
	if !bytes.Contains(log.Bytes(), []byte(essid)) {
		t.Error("the probed ESSID is not in the audit record")
	}
}

// TestKarmaProbePathCannotSmuggleARealNetwork is the guard on the one authorization path that
// does not decide on ESSID match. Without it, "transmit an unscoped ESSID" would have an open
// door.
func TestKarmaProbePathCannotSmuggleARealNetwork(t *testing.T) {
	g, _ := testGate(t, "CORP-WIFI")
	ctx := context.Background()

	tests := []struct {
		name  string
		essid string
	}{
		{"a real neighbouring network", "NEIGHBOR-NET"},
		{"a scoped network", "CORP-WIFI"},
		{"empty", ""},
		{"too short to be generated", "abc"},
		{"right length but not generated", "corp-wifi-guest-1234"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := g.AuthorizeKarmaProbe(ctx, "karma-probe", tc.essid, 6, "phy1")
			if err == nil {
				t.Fatalf("karma probe path accepted %q", tc.essid)
			}
			if !scope.Denied(err) {
				t.Fatalf("expected a scope denial, got %T: %v", err, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Deauthentication guards
// ---------------------------------------------------------------------------

// TestDeauthSkippedWhenMFPRequired: 802.11w means associated clients ignore unprotected
// deauthentication. Transmitting anyway wastes airtime and produces a false negative in the
// report — "we deauthenticated and nothing happened" reads as resilience.
func TestDeauthSkippedWhenMFPRequired(t *testing.T) {
	res, err := Deauth(context.Background(), nil, DeauthOptions{
		BSSID:  mac(t, "a4:2b:8c:11:22:33"),
		ESSID:  "CORP-WIFI",
		Target: mac(t, "de:ad:be:ef:00:01"),
		MFP:    recon.MFPRequired,
	})
	if err != ErrMFPRequired {
		t.Fatalf("err = %v, want ErrMFPRequired", err)
	}
	if !res.Skipped {
		t.Error("result does not record the skip")
	}
	if res.Reason == "" {
		t.Error("skip has no reason; it must appear in the report as the finding it is")
	}
	if res.Frames != 0 {
		t.Errorf("transmitted %d frames despite MFP being required", res.Frames)
	}
}

// TestBroadcastDeauthRequiresExplicitOptIn: taking every client off a network at once is an
// outage, not a test.
func TestBroadcastDeauthRequiresExplicitOptIn(t *testing.T) {
	_, err := Deauth(context.Background(), nil, DeauthOptions{
		BSSID: mac(t, "a4:2b:8c:11:22:33"),
		ESSID: "CORP-WIFI",
		// No target and no AllowBroadcast.
	})
	if err == nil {
		t.Fatal("broadcast deauthentication was allowed without an explicit opt-in")
	}
}

// ---------------------------------------------------------------------------
// Solicitation rate limiting
// ---------------------------------------------------------------------------

// TestSolicitCooldownIsEnforced: hammering association requests at a production AP degrades
// service for real users, which the SoW did not buy.
func TestSolicitCooldownIsEnforced(t *testing.T) {
	s := NewSolicitor(30 * time.Second)
	now := time.Now()
	s.now = func() time.Time { return now }

	bssid := mac(t, "a4:2b:8c:11:22:33")

	if ready, _ := s.Ready(bssid); !ready {
		t.Fatal("a never-solicited AP is not ready")
	}

	s.mu.Lock()
	s.lastTry[bssid] = now
	s.mu.Unlock()

	ready, remaining := s.Ready(bssid)
	if ready {
		t.Fatal("cooldown not enforced immediately after an attempt")
	}
	if remaining <= 0 || remaining > 30*time.Second {
		t.Errorf("remaining = %v, want within the cooldown", remaining)
	}

	// A different AP is unaffected — the limit is per-AP.
	if ready, _ := s.Ready(mac(t, "de:ad:be:ef:00:01")); !ready {
		t.Error("the cooldown leaked to an unrelated AP")
	}

	now = now.Add(31 * time.Second)
	if ready, _ := s.Ready(bssid); !ready {
		t.Error("cooldown did not expire")
	}
}

// TestSolicitCooldownCannotBeDisabled: a zero or negative value falls back to the default
// rather than removing the limit.
func TestSolicitCooldownCannotBeDisabled(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		s := NewSolicitor(d)
		if s.cooldown != DefaultSolicitCooldown {
			t.Errorf("NewSolicitor(%v) cooldown = %v, want the default", d, s.cooldown)
		}
	}
}
