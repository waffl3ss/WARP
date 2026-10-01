package handshake

import (
	"strings"
	"testing"
	"time"
)

func staticResolver(essid string) ESSIDResolver {
	return func([6]byte) (string, bool) { return essid, essid != "" }
}

func mustParse(t *testing.T, raw []byte) *EAPOLKey {
	t.Helper()
	k, err := ParseEAPOLKey(raw)
	if err != nil {
		t.Fatalf("ParseEAPOLKey: %v", err)
	}
	return k
}

func TestFullHandshakeProducesAHandshakeHash(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})
	now := time.Now()

	var got []Result
	got = append(got, m.Consume(apMAC, staMAC, mustParse(t, m1Frame(1, nil)), 6, "phy1", now)...)
	got = append(got, m.Consume(apMAC, staMAC, mustParse(t, m2Frame(1)), 6, "phy1", now.Add(time.Millisecond))...)

	if len(got) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(got), got)
	}
	r := got[0]
	if r.Kind != KindHandshake {
		t.Errorf("Kind = %q, want handshake", r.Kind)
	}
	if r.Pair != PairM12E2 {
		t.Errorf("Pair = %s, want M1+M2 with no flags", r.Pair.Describe())
	}
	if r.ESSID != "CORP-WIFI" {
		t.Errorf("ESSID = %q", r.ESSID)
	}
	if r.Channel != 6 || r.RadioID != "phy1" {
		t.Errorf("evidence lost: channel=%d radio=%q", r.Channel, r.RadioID)
	}
	if _, err := ParseLine(r.Line); err != nil {
		t.Errorf("emitted line does not parse: %v", err)
	}
}

func TestPMKIDEmittedFromM1Alone(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})

	// A single frame from the AP, no client involvement — this is what makes solicitation
	// the largest time saver on an engagement.
	got := m.Consume(apMAC, staMAC, mustParse(t, m1Frame(1, pmkidKDE(fill(16, 0x77)))), 6, "phy1", time.Now())

	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	if got[0].Kind != KindPMKID {
		t.Errorf("Kind = %q, want pmkid", got[0].Kind)
	}
	if !strings.HasPrefix(got[0].Line, "WPA*01*") {
		t.Errorf("line = %q, want a WPA*01 PMKID line", got[0].Line)
	}
}

func TestZeroPMKIDProducesNothing(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})
	got := m.Consume(apMAC, staMAC, mustParse(t, m1Frame(1, pmkidKDE(make([]byte, 16)))), 6, "phy1", time.Now())

	for _, r := range got {
		if r.Kind == KindPMKID {
			t.Fatal("a zero PMKID was emitted; it can never crack")
		}
	}
}

// TestM3M2Pairing covers a missed M1: M3 repeats the ANonce and substitutes for it.
func TestM3M2Pairing(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})
	now := time.Now()

	m.Consume(apMAC, staMAC, mustParse(t, m2Frame(1)), 6, "phy1", now)
	got := m.Consume(apMAC, staMAC, mustParse(t, m3Frame(2)), 6, "phy1", now.Add(time.Millisecond))

	if len(got) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(got), got)
	}
	if got[0].Pair.Base() != PairM32E2 {
		t.Errorf("Pair = %s, want M3+M2", got[0].Pair.Describe())
	}
	if got[0].Pair.NonceCorrection() {
		t.Error("nonce correction flagged for consecutive replay counters")
	}
}

// TestM4WithoutSNonceIsNotEmitted is the deliberate conservatism in this package.
//
// hashcat reads the SNonce out of the EAPOL frame in the hash line. Most supplicants send a
// zero nonce in M4, so shipping that frame yields a hash that is structurally uncrackable.
// Emitting fewer, correct hashes beats burning rig time on a result that can never come.
func TestM4WithoutSNonceIsNotEmitted(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})
	now := time.Now()

	m.Consume(apMAC, staMAC, mustParse(t, m3Frame(2)), 6, "phy1", now)
	got := m.Consume(apMAC, staMAC, mustParse(t, m4Frame(2, false)), 6, "phy1", now.Add(time.Millisecond))

	if len(got) != 0 {
		t.Fatalf("emitted a hash from an M4 with a zero SNonce: %+v", got)
	}
}

// TestM4WithSNonceIsEmitted: supplicants that do echo the SNonce give a usable M3+M4.
func TestM4WithSNonceIsEmitted(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})
	now := time.Now()

	m.Consume(apMAC, staMAC, mustParse(t, m3Frame(2)), 6, "phy1", now)
	got := m.Consume(apMAC, staMAC, mustParse(t, m4Frame(2, true)), 6, "phy1", now.Add(time.Millisecond))

	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	if got[0].Pair.Base() != PairM34E4 {
		t.Errorf("Pair = %s, want M3+M4", got[0].Pair.Describe())
	}
}

// TestMismatchedReplayCounterSetsNonceCorrection: paired messages from different exchange
// steps may need hashcat's nonce correction, and it must be told.
func TestMismatchedReplayCounterSetsNonceCorrection(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})
	now := time.Now()

	m.Consume(apMAC, staMAC, mustParse(t, m1Frame(1, nil)), 6, "phy1", now)
	got := m.Consume(apMAC, staMAC, mustParse(t, m2Frame(9)), 6, "phy1", now.Add(time.Millisecond))

	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	if !got[0].Pair.NonceCorrection() {
		t.Errorf("Pair = %s; mismatched replay counters must set the NC flag", got[0].Pair.Describe())
	}
	if got[0].Pair.Base() != PairM12E2 {
		t.Errorf("base pair = %s, want M1+M2", got[0].Pair.Describe())
	}
}

// TestDifferentStationsAreSeparateSessions: mixing messages from two stations at the same AP
// produces a hash that is internally consistent and can never crack.
func TestDifferentStationsAreSeparateSessions(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})
	now := time.Now()
	staB := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x02}

	// M1 to station A, M2 from station B. These must not pair.
	m.Consume(apMAC, staMAC, mustParse(t, m1Frame(1, nil)), 6, "phy1", now)
	got := m.Consume(apMAC, staB, mustParse(t, m2Frame(1)), 6, "phy1", now.Add(time.Millisecond))

	if len(got) != 0 {
		t.Fatalf("messages from two stations were paired: %+v", got)
	}

	// Completing station B's own handshake works normally. B's M2 was already delivered
	// above, so the pair completes the moment its M1 arrives — and the retransmitted M2
	// after that must not produce a second copy.
	var all []Result
	all = append(all, m.Consume(apMAC, staB, mustParse(t, m1Frame(1, nil)), 6, "phy1", now.Add(2*time.Millisecond))...)
	all = append(all, m.Consume(apMAC, staB, mustParse(t, m2Frame(1)), 6, "phy1", now.Add(3*time.Millisecond))...)

	if len(all) != 1 {
		t.Fatalf("station B's handshake produced %d hashes, want 1: %+v", len(all), all)
	}
	if all[0].STA != staB {
		t.Errorf("STA = %v, want %v", all[0].STA, staB)
	}
}

// TestNewAttemptDiscardsStaleMessages: a fresh M1 with a new replay counter starts a new
// exchange, and the old partial messages must not be carried into it.
func TestNewAttemptDiscardsStaleMessages(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})
	now := time.Now()

	m.Consume(apMAC, staMAC, mustParse(t, m1Frame(1, nil)), 6, "phy1", now)
	m.Consume(apMAC, staMAC, mustParse(t, m3Frame(2)), 6, "phy1", now.Add(time.Millisecond))

	// A new attempt begins.
	m.Consume(apMAC, staMAC, mustParse(t, m1Frame(10, nil)), 6, "phy1", now.Add(time.Second))
	got := m.Consume(apMAC, staMAC, mustParse(t, m2Frame(10)), 6, "phy1", now.Add(time.Second+time.Millisecond))

	// The M2 must pair with the new M1, and the stale M3 must not produce a second hash.
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(got), got)
	}
	if got[0].Pair != PairM12E2 {
		t.Errorf("Pair = %s, want a clean M1+M2 from the new attempt", got[0].Pair.Describe())
	}
}

// TestRetransmissionDoesNotDuplicate: APs retransmit constantly on a busy network.
func TestRetransmissionDoesNotDuplicate(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})
	now := time.Now()

	m.Consume(apMAC, staMAC, mustParse(t, m1Frame(1, nil)), 6, "phy1", now)

	var total int
	for i := 0; i < 5; i++ {
		total += len(m.Consume(apMAC, staMAC, mustParse(t, m2Frame(1)), 6, "phy1",
			now.Add(time.Duration(i)*time.Millisecond)))
	}
	if total != 1 {
		t.Errorf("five retransmitted M2s produced %d hashes, want 1", total)
	}
}

// TestHandshakeHeldUntilESSIDKnown is the cloaked-network case. The ESSID is the PBKDF2 salt
// and cannot be recovered later, but the handshake is still good once the name is learned.
func TestHandshakeHeldUntilESSIDKnown(t *testing.T) {
	var essid string
	m := NewMachine(func([6]byte) (string, bool) { return essid, essid != "" }, Options{})
	now := time.Now()

	m.Consume(apMAC, staMAC, mustParse(t, m1Frame(1, pmkidKDE(fill(16, 0x77)))), 6, "phy1", now)
	got := m.Consume(apMAC, staMAC, mustParse(t, m2Frame(1)), 6, "phy1", now.Add(time.Millisecond))

	if len(got) != 0 {
		t.Fatalf("emitted a hash with no ESSID: %+v", got)
	}
	if stats := m.Stats(); stats.PendingESSID != 2 {
		t.Errorf("PendingESSID = %d, want 2 (the PMKID and the handshake)", stats.PendingESSID)
	}
	if pending := m.PendingBSSIDs(); len(pending) != 1 || pending[0] != "a4:2b:8c:11:22:33" {
		t.Errorf("PendingBSSIDs = %v", pending)
	}

	// A probe response reveals the name.
	essid = "HIDDEN-CORP"
	resolved := m.ResolvePending()

	if len(resolved) != 2 {
		t.Fatalf("resolved %d hashes, want 2: %+v", len(resolved), resolved)
	}
	var kinds []string
	for _, r := range resolved {
		kinds = append(kinds, string(r.Kind))
		if r.ESSID != "HIDDEN-CORP" {
			t.Errorf("ESSID = %q", r.ESSID)
		}
		if _, err := ParseLine(r.Line); err != nil {
			t.Errorf("resolved line does not parse: %v", err)
		}
	}
	if m.Stats().PendingESSID != 0 {
		t.Error("pending queue not drained")
	}
	t.Logf("resolved kinds: %v", kinds)
}

func TestExpiry(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{Timeout: time.Minute})
	now := time.Now()

	m.Consume(apMAC, staMAC, mustParse(t, m1Frame(1, nil)), 6, "phy1", now)
	if m.Stats().Sessions != 1 {
		t.Fatal("session not created")
	}

	if n := m.Expire(now.Add(30 * time.Second)); n != 0 {
		t.Errorf("expired %d sessions early", n)
	}
	if n := m.Expire(now.Add(2 * time.Minute)); n != 1 {
		t.Errorf("expired %d sessions, want 1", n)
	}
	if m.Stats().Sessions != 0 {
		t.Error("session table not cleared")
	}
}

// TestSessionTableIsBounded: a multi-day run in a busy environment must not grow without
// limit.
func TestSessionTableIsBounded(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{MaxSessions: 4})
	now := time.Now()

	for i := 0; i < 20; i++ {
		sta := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, byte(i)}
		m.Consume(apMAC, sta, mustParse(t, m1Frame(1, nil)), 6, "phy1", now.Add(time.Duration(i)*time.Second))
	}
	if n := m.Stats().Sessions; n > 4 {
		t.Errorf("session table grew to %d, cap is 4", n)
	}
}

func TestUnknownMessagesAreIgnored(t *testing.T) {
	m := NewMachine(staticResolver("CORP-WIFI"), Options{})

	if got := m.Consume(apMAC, staMAC, nil, 6, "phy1", time.Now()); got != nil {
		t.Error("a nil key produced results")
	}

	groupKey := buildEAPOLKey(keyOpts{
		keyInfo: keyInfoACK | keyInfoMIC | 0x0002, replayCounter: 5, nonce: anonce, mic: micVal,
	})
	if got := m.Consume(apMAC, staMAC, mustParse(t, groupKey), 6, "phy1", time.Now()); len(got) != 0 {
		t.Errorf("group key traffic produced hashes: %+v", got)
	}
	if m.Stats().Sessions != 0 {
		t.Error("a session was created for group key traffic")
	}
}

func TestResultMACRendering(t *testing.T) {
	r := Result{AP: apMAC, STA: staMAC}
	if r.APString() != "a4:2b:8c:11:22:33" {
		t.Errorf("APString = %q", r.APString())
	}
	if r.STAString() != "de:ad:be:ef:00:01" {
		t.Errorf("STAString = %q", r.STAString())
	}
}
