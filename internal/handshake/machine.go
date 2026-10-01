package handshake

import (
	"sort"
	"sync"
	"time"
)

// Defaults for the handshake state machine.
const (
	// DefaultTimeout is how long an incomplete handshake is held. A 4-way exchange completes
	// in milliseconds, but retransmissions and roaming stretch it, and holding a partial
	// exchange costs almost nothing.
	DefaultTimeout = 2 * time.Minute

	// DefaultMaxSessions bounds memory on a multi-day unattended run in a busy environment.
	// Oldest sessions are evicted first.
	DefaultMaxSessions = 8192
)

// Kind distinguishes the two hash products.
type Kind string

// Hash kinds. They are written to separate files so the operator can prioritise PMKIDs on the
// cracking rig.
const (
	KindPMKID Kind = "pmkid"
	// KindHandshake is a WPA/WPA2/WPA3-Personal four-way handshake, captured from EAPOL-Key
	// frames (802.1X packet type 3) and emitted as hashcat 22000 WPA*02.
	//
	// Named "handshake" everywhere it is visible - the constant, the wire value, the file, the
	// columns. EAPOL is the frame type it arrives in, and is hashcat's own name for mode 22000
	// ("WPA-PBKDF2-PMKID+EAPOL"), but it also names the transport WPA-Enterprise carries EAP
	// over. Operators read it as enterprise capture and conclude the file is uncrackable, and
	// stop looking at the thing the tool exists to produce.
	//
	// Enterprise authentication never reaches this path: it is EAPOL packet type 0,
	// ParseEAPOLKey rejects it outright, and those credentials come from the RADIUS server in
	// internal/eap as MSCHAPv2 for hashcat -m 5500.
	KindHandshake Kind = "handshake"
)

// Result is one completed, emittable hash.
type Result struct {
	Kind  Kind        `json:"kind"`
	Line  string      `json:"line"`
	AP    [6]byte     `json:"-"`
	STA   [6]byte     `json:"-"`
	ESSID string      `json:"essid"`
	Pair  MessagePair `json:"-"`
	// Channel and RadioID are evidence, not part of the hash.
	Channel int       `json:"channel,omitempty"`
	RadioID string    `json:"radio_id,omitempty"`
	At      time.Time `json:"at"`
	// Detail is an operator-facing description, e.g. "M1+M2".
	Detail string `json:"detail,omitempty"`
	// InScope reports whether the ESSID was in scope when this was captured.
	//
	// Capture is passive: WARP records every handshake it happens to hear, whether or not the
	// engagement has any authority over that network, because a frame already received cannot
	// be un-received and discarding evidence silently is worse than holding it. What the flag
	// controls is where it goes - out-of-scope material is kept apart from the deliverable, so
	// a neighbour's handshake cannot end up in a job on the cracking rig by accident.
	//
	// It is set by the caller from the scope gate, not decided here.
	InScope bool `json:"in_scope"`
}

// APString renders the AP MAC in colon form.
func (r Result) APString() string { return macString(r.AP) }

// STAString renders the station MAC in colon form.
func (r Result) STAString() string { return macString(r.STA) }

func macString(m [6]byte) string {
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 0, 17)
	for i, b := range m {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(buf)
}

// sessionKey identifies one AP/station pairing. Handshakes from different stations at the
// same AP are entirely separate exchanges and must never be combined: mixing them produces a
// hash that is internally consistent and will never crack.
type sessionKey struct {
	ap  [6]byte
	sta [6]byte
}

// session accumulates the messages of one 4-way handshake.
type session struct {
	m1, m2, m3, m4 *EAPOLKey
	firstSeen      time.Time
	lastSeen       time.Time
	channel        int
	radioID        string

	// emitted records which pairings have already been produced so a retransmitted message
	// does not generate the same hash repeatedly.
	emitted map[MessagePair]bool
	// pmkidDone marks that this session's PMKID has been emitted.
	pmkidDone bool
}

// ESSIDResolver returns the network name for a BSSID.
//
// The ESSID is the PBKDF2 salt, so a hash without it cannot be cracked. When the name is not
// yet known - a cloaked network, or a handshake captured before any beacon was parsed - the
// session is held rather than discarded, and retried as names are learned.
type ESSIDResolver func(ap [6]byte) (string, bool)

// Machine tracks in-flight handshakes and produces hashes.
type Machine struct {
	mu       sync.Mutex
	sessions map[sessionKey]*session

	resolve     ESSIDResolver
	timeout     time.Duration
	maxSessions int

	// pendingESSID holds sessions that produced a hash but had no ESSID at the time.
	pending []pendingResult
}

// pendingResult is a completed handshake awaiting an ESSID.
type pendingResult struct {
	key     sessionKey
	kind    Kind
	pmkid   []byte
	mic     []byte
	anonce  []byte
	eapol   []byte
	pair    MessagePair
	channel int
	radioID string
	at      time.Time
}

// Options configures a Machine.
type Options struct {
	Timeout     time.Duration
	MaxSessions int
}

// NewMachine builds a handshake state machine. resolve may be nil, in which case no hash can
// be completed until one is supplied.
func NewMachine(resolve ESSIDResolver, opts Options) *Machine {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.MaxSessions <= 0 {
		opts.MaxSessions = DefaultMaxSessions
	}
	return &Machine{
		sessions:    make(map[sessionKey]*session),
		resolve:     resolve,
		timeout:     opts.Timeout,
		maxSessions: opts.MaxSessions,
	}
}

// Consume folds one EAPOL-Key frame into the machine and returns any hashes it completed.
func (m *Machine) Consume(ap, sta [6]byte, k *EAPOLKey, channel int, radioID string, at time.Time) []Result {
	if k == nil || k.Message == MessageUnknown {
		return nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := sessionKey{ap: ap, sta: sta}
	s, ok := m.sessions[key]
	if !ok {
		m.evictIfFullLocked()
		s = &session{firstSeen: at, emitted: make(map[MessagePair]bool)}
		m.sessions[key] = s
	}
	s.lastSeen = at
	if channel != 0 {
		s.channel = channel
	}
	if radioID != "" {
		s.radioID = radioID
	}

	// A new M1 with a different replay counter is a fresh handshake attempt at the same
	// station. Keeping the old M2/M3/M4 would let messages from two attempts be paired.
	if k.Message == M1 && s.m1 != nil && s.m1.ReplayCounter != k.ReplayCounter {
		s.m2, s.m3, s.m4 = nil, nil, nil
	}

	switch k.Message {
	case M1:
		s.m1 = k
	case M2:
		s.m2 = k
	case M3:
		s.m3 = k
	case M4:
		s.m4 = k
	}

	var results []Result
	if r, ok := m.tryPMKIDLocked(key, s, at); ok {
		results = append(results, r)
	}
	results = append(results, m.tryPairsLocked(key, s, at)...)
	return results
}

// tryPMKIDLocked emits a PMKID hash if M1 carries one.
//
// This is the cheapest possible capture: a single frame from the AP, no client involvement at
// all, which is what makes PMKID solicitation the largest time saver on an engagement.
func (m *Machine) tryPMKIDLocked(key sessionKey, s *session, at time.Time) (Result, bool) {
	if s.pmkidDone || s.m1 == nil {
		return Result{}, false
	}
	pmkid, ok := s.m1.PMKID()
	if !ok {
		// Either no PMKID KDE, or a zero one - some APs pad the KDE with zeroes and a zero
		// PMKID is not crackable. Either way there is nothing to emit.
		s.pmkidDone = true
		return Result{}, false
	}
	s.pmkidDone = true

	essid, known := m.essidLocked(key.ap)
	if !known {
		m.pending = append(m.pending, pendingResult{
			key: key, kind: KindPMKID, pmkid: pmkid,
			channel: s.channel, radioID: s.radioID, at: at,
		})
		return Result{}, false
	}

	line, err := PMKIDLine(pmkid, key.ap, key.sta, essid)
	if err != nil {
		return Result{}, false
	}
	return Result{
		Kind: KindPMKID, Line: line, AP: key.ap, STA: key.sta, ESSID: essid,
		Channel: s.channel, RadioID: s.radioID, At: at, Detail: "PMKID from M1",
	}, true
}

// tryPairsLocked emits every valid message pairing not already produced.
//
// Only pairings whose EAPOL frame actually carries the SNonce are emitted. hashcat derives
// the PTK from the ANonce (a separate field) and the SNonce (read out of the EAPOL frame), so
// shipping an EAPOL frame with a zero nonce yields a hash that is structurally uncrackable.
// Some supplicants do echo the SNonce in M4 and those are emitted; the ones that send a zero
// nonce in M4 are not. Emitting fewer, correct hashes is the right trade when the alternative
// is burning time on the cracking rig for a result that can never come.
func (m *Machine) tryPairsLocked(key sessionKey, s *session, at time.Time) []Result {
	var out []Result

	emit := func(pair MessagePair, anonceSrc, eapolSrc *EAPOLKey, detail string) {
		if anonceSrc == nil || eapolSrc == nil {
			return
		}
		// Nonce correction: the paired messages did not share the replay counter they should
		// have, so the nonce may have advanced between them.
		if !replayCountersConsistent(pair, anonceSrc, eapolSrc) {
			pair |= PairFlagNC
		}
		if s.emitted[pair] {
			return
		}
		s.emitted[pair] = true

		essid, known := m.essidLocked(key.ap)
		zeroed := eapolSrc.ZeroMIC()
		if !known {
			m.pending = append(m.pending, pendingResult{
				key: key, kind: KindHandshake,
				mic:    append([]byte(nil), eapolSrc.MIC[:]...),
				anonce: append([]byte(nil), anonceSrc.Nonce[:]...),
				eapol:  zeroed, pair: pair,
				channel: s.channel, radioID: s.radioID, at: at,
			})
			return
		}

		line, err := EAPOLLine(eapolSrc.MIC[:], key.ap, key.sta, essid,
			anonceSrc.Nonce[:], zeroed, pair)
		if err != nil {
			return
		}
		out = append(out, Result{
			Kind: KindHandshake, Line: line, AP: key.ap, STA: key.sta, ESSID: essid,
			Pair: pair, Channel: s.channel, RadioID: s.radioID, At: at,
			Detail: detail + " (" + pair.Describe() + ")",
		})
	}

	// M1 + M2: the standard case. ANonce from M1, EAPOL and MIC from M2, which carries the
	// SNonce.
	if s.m1 != nil && s.m2 != nil {
		emit(PairM12E2, s.m1, s.m2, "EAPOL")
	}

	// M3 + M2: M3 repeats the ANonce, so it substitutes for a missed M1.
	if s.m3 != nil && s.m2 != nil {
		emit(PairM32E2, s.m3, s.m2, "EAPOL")
	}

	// M1/M3 + M4, only where the supplicant echoed the SNonce in M4.
	if s.m4 != nil && !s.m4.NonceIsZero() {
		if s.m1 != nil {
			emit(PairM14E4, s.m1, s.m4, "EAPOL")
		}
		if s.m3 != nil {
			emit(PairM34E4, s.m3, s.m4, "EAPOL")
		}
	}

	return out
}

// replayCountersConsistent reports whether the two messages belong to the same exchange step
// as expected for the pairing.
func replayCountersConsistent(pair MessagePair, anonceSrc, eapolSrc *EAPOLKey) bool {
	switch pair.Base() {
	case PairM12E2:
		// M2 answers M1 with the same replay counter.
		return eapolSrc.ReplayCounter == anonceSrc.ReplayCounter
	case PairM32E2:
		// M3 is the next step after M2.
		return anonceSrc.ReplayCounter == eapolSrc.ReplayCounter+1
	case PairM14E4:
		return eapolSrc.ReplayCounter >= anonceSrc.ReplayCounter
	case PairM34E4:
		// M4 answers M3 with the same replay counter.
		return eapolSrc.ReplayCounter == anonceSrc.ReplayCounter
	default:
		return true
	}
}

// essidLocked resolves the ESSID for a BSSID.
func (m *Machine) essidLocked(ap [6]byte) (string, bool) {
	if m.resolve == nil {
		return "", false
	}
	essid, ok := m.resolve(ap)
	if !ok || essid == "" {
		return "", false
	}
	return essid, true
}

// ResolvePending retries hashes that completed before their network name was known.
//
// A handshake captured on a cloaked network, or before the first beacon was parsed, is held
// rather than discarded: the ESSID is the PBKDF2 salt and cannot be recovered later, but the
// handshake itself is still good once the name is learned.
func (m *Machine) ResolvePending() []Result {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.pending) == 0 {
		return nil
	}

	var out []Result
	remaining := m.pending[:0]

	for _, p := range m.pending {
		essid, known := m.essidLocked(p.key.ap)
		if !known {
			remaining = append(remaining, p)
			continue
		}

		var (
			line string
			err  error
		)
		switch p.kind {
		case KindPMKID:
			line, err = PMKIDLine(p.pmkid, p.key.ap, p.key.sta, essid)
		case KindHandshake:
			line, err = EAPOLLine(p.mic, p.key.ap, p.key.sta, essid, p.anonce, p.eapol, p.pair)
		}
		if err != nil {
			continue
		}
		out = append(out, Result{
			Kind: p.kind, Line: line, AP: p.key.ap, STA: p.key.sta, ESSID: essid,
			Pair: p.pair, Channel: p.channel, RadioID: p.radioID, At: p.at,
			Detail: "resolved after ESSID became known",
		})
	}
	m.pending = remaining
	return out
}

// Expire drops sessions that have gone quiet, and returns how many were removed.
func (m *Machine) Expire(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	n := 0
	for k, s := range m.sessions {
		if now.Sub(s.lastSeen) > m.timeout {
			delete(m.sessions, k)
			n++
		}
	}
	return n
}

// evictIfFullLocked removes the oldest session when the table is at capacity.
func (m *Machine) evictIfFullLocked() {
	if len(m.sessions) < m.maxSessions {
		return
	}
	var (
		oldestKey sessionKey
		oldest    time.Time
		found     bool
	)
	for k, s := range m.sessions {
		if !found || s.lastSeen.Before(oldest) {
			oldestKey, oldest, found = k, s.lastSeen, true
		}
	}
	if found {
		delete(m.sessions, oldestKey)
	}
}

// Stats reports the machine's state for the status header.
type Stats struct {
	Sessions     int `json:"sessions"`
	PendingESSID int `json:"pending_essid"`
}

// Stats returns current counts.
func (m *Machine) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Stats{Sessions: len(m.sessions), PendingESSID: len(m.pending)}
}

// PendingBSSIDs lists the BSSIDs holding hashes that cannot be emitted for want of an ESSID.
//
// Surfaced to the operator because it is directly actionable: a probe or a client association
// will reveal a cloaked name and unlock the hash.
func (m *Machine) PendingBSSIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[string]struct{}, len(m.pending))
	for _, p := range m.pending {
		seen[macString(p.key.ap)] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
