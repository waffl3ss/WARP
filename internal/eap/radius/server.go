// Package radius implements the RADIUS server hostapd relays EAP messages to.
//
// This is the architectural decision the brief is emphatic about: WARP does not port
// eaphammer, and does not embed a patched FreeRADIUS the way hostapd-wpe does. Stock hostapd
// already supports an external RADIUS backend, so with ieee8021x=1, wpa_key_mgmt=WPA-EAP and
// auth_server_addr pointing at localhost, hostapd handles beaconing, association and EAPOL and
// relays every EAP message here untouched.
//
// The result is that all the interesting logic - certificate presentation, method negotiation,
// credential capture, downgrade - lives in Go, with no patched C anywhere in the tool.
package radius

import (
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // RADIUS specifies MD5 for the Message-Authenticator
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2869"

	"github.com/waffl3ss/warp/internal/eap/method"
)

// DefaultPort is the RADIUS authentication port.
const DefaultPort = 1812

// Handler is called with each completed authentication outcome.
type Handler func(Outcome)

// Outcome is one authentication attempt, with the RADIUS-level context attached.
type Outcome struct {
	method.Outcome
	// ESSID being impersonated.
	ESSID string `json:"essid"`
	// CallingStation is the supplicant's MAC, as hostapd reports it.
	CallingStation string `json:"calling_station,omitempty"`
	// CalledStation is the access point's BSSID and SSID, as hostapd reports it.
	CalledStation string    `json:"called_station,omitempty"`
	At            time.Time `json:"at"`
}

// Config configures the RADIUS server.
type Config struct {
	// Addr to listen on. Defaults to localhost only - the server exists for hostapd on the
	// same box, and exposing it on the wire would let anything on the network feed it EAP.
	Addr string
	// Secret shared with hostapd.
	Secret []byte
	// ESSID being impersonated.
	ESSID string
	// EAP is the method server configuration.
	EAP method.ServerConfig
	// OnOutcome receives each completed authentication.
	OnOutcome Handler
	Log       *slog.Logger
}

// Server is the RADIUS listener.
type Server struct {
	cfg    Config
	eap    *method.Server
	log    *slog.Logger
	packet *radius.PacketServer

	mu    sync.Mutex
	stats Stats
}

// Stats counts what the server has seen.
type Stats struct {
	Requests    int `json:"requests"`
	Challenges  int `json:"challenges"`
	Accepts     int `json:"accepts"`
	Rejects     int `json:"rejects"`
	Captured    int `json:"captured"`
	CertRefused int `json:"certificate_refused"`
	BadAuth     int `json:"bad_message_authenticator"`
}

// New builds a RADIUS server.
func New(cfg Config) (*Server, error) {
	if len(cfg.Secret) == 0 {
		return nil, errors.New("radius: a shared secret is required")
	}
	if cfg.Addr == "" {
		// Localhost only by default. hostapd runs on the same box, and a RADIUS server
		// reachable from the network would accept EAP from anything that could route to it.
		cfg.Addr = fmt.Sprintf("127.0.0.1:%d", DefaultPort)
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	eapServer, err := method.NewServer(cfg.EAP)
	if err != nil {
		return nil, err
	}

	s := &Server{cfg: cfg, eap: eapServer, log: cfg.Log}
	s.packet = &radius.PacketServer{
		Addr:         cfg.Addr,
		SecretSource: radius.StaticSecretSource(cfg.Secret),
		Handler:      radius.HandlerFunc(s.serve),
	}
	return s, nil
}

// ListenAndServe runs until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.packet.Shutdown(shutdownCtx)
	}()

	// Expire half-finished authentications so a supplicant that walks away does not pin a
	// TLS session forever.
	go s.expireLoop(ctx)

	s.log.Info("RADIUS server listening", "addr", s.cfg.Addr, "essid", s.cfg.ESSID)

	err := s.packet.ListenAndServe()
	if errors.Is(err, radius.ErrServerShutdown) || ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) expireLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := s.eap.Expire(time.Now()); n > 0 {
				s.log.Debug("expired stale EAP sessions", "count", n)
			}
		}
	}
}

// serve handles one Access-Request.
func (s *Server) serve(w radius.ResponseWriter, r *radius.Request) {
	s.bump(func(st *Stats) { st.Requests++ })

	if r.Code != radius.CodeAccessRequest {
		s.log.Debug("ignoring non-Access-Request", "code", r.Code)
		return
	}

	// Validate the Message-Authenticator. Without this check anything that can reach the
	// socket could inject EAP on hostapd's behalf, and the credentials recorded would not be
	// attributable to a real supplicant - which would make them useless as evidence.
	if !s.validateMessageAuthenticator(r) {
		s.bump(func(st *Stats) { st.BadAuth++ })
		s.log.Warn("dropping a RADIUS packet with a bad Message-Authenticator",
			"from", r.RemoteAddr)
		return
	}

	eapData := concatEAPMessages(r.Packet)
	if len(eapData) == 0 {
		s.log.Debug("Access-Request carried no EAP-Message")
		s.reject(w, r)
		return
	}

	pkt, err := method.ParsePacket(eapData)
	if err != nil {
		s.log.Debug("malformed EAP payload", "err", err)
		s.reject(w, r)
		return
	}

	sessionID := sessionKey(r)
	res, err := s.eap.Handle(sessionID, pkt)
	if err != nil {
		s.log.Debug("EAP handling failed", "err", err, "session", sessionID)
		s.reject(w, r)
		return
	}

	// Fragment-level trace of the EAP-TLS exchange: what the supplicant sent and what we reply,
	// with the TLS flags/length so a stalled certificate flight is visible.
	s.log.Info("eap round", "in", eapDesc(pkt), "out", eapDesc(res.Packet),
		"done", res.Done, "accept", res.Accept,
		"state", string(res.Outcome.State), "note", res.Outcome.Note)

	if res.Done {
		s.recordOutcome(r, res.Outcome)
	}

	switch {
	case res.Done && res.Accept:
		s.bump(func(st *Stats) { st.Accepts++ })
		s.respond(w, r, radius.CodeAccessAccept, res.Packet)
	case res.Done:
		s.bump(func(st *Stats) { st.Rejects++ })
		s.respond(w, r, radius.CodeAccessReject, res.Packet)
	default:
		s.bump(func(st *Stats) { st.Challenges++ })
		s.respond(w, r, radius.CodeAccessChallenge, res.Packet)
	}
}

// eapDesc renders an EAP packet compactly for the fragment trace: the method, and for a TLS-based
// method the flags, declared total length, and this fragment's data size.
func eapDesc(p *method.Packet) string {
	if p == nil {
		return "nil"
	}
	base := fmt.Sprintf("%s/%s#%d", codeName(p.Code), p.Type, p.Identifier)
	switch p.Type {
	case method.TypePEAP, method.TypeTTLS, method.TypeTLS:
		msg, err := method.ParseTLSMessage(p.Data)
		if err != nil {
			return base + " (bad-tls)"
		}
		var f []string
		if msg.Flags&method.FlagLengthIncluded != 0 {
			f = append(f, "L")
		}
		if msg.Flags&method.FlagMoreFragments != 0 {
			f = append(f, "M")
		}
		if msg.Flags&method.FlagStart != 0 {
			f = append(f, "S")
		}
		if msg.IsACK() {
			f = append(f, "ACK")
		}
		return fmt.Sprintf("%s flags=[%s] total=%d frag=%dB", base, strings.Join(f, ""), msg.TotalLength, len(msg.Data))
	}
	return base + fmt.Sprintf(" data=%dB", len(p.Data))
}

// codeName is a short name for an EAP code.
func codeName(c uint8) string {
	switch c {
	case method.CodeRequest:
		return "Req"
	case method.CodeResponse:
		return "Resp"
	case method.CodeSuccess:
		return "Success"
	case method.CodeFailure:
		return "Failure"
	default:
		return "?"
	}
}

// respond builds and sends a RADIUS reply carrying an EAP packet.
func (s *Server) respond(w radius.ResponseWriter, r *radius.Request, code radius.Code, eapPkt *method.Packet) {
	resp := r.Response(code)

	if eapPkt != nil {
		if err := appendEAPMessages(resp, eapPkt.Marshal()); err != nil {
			s.log.Error("could not attach the EAP payload", "err", err)
			return
		}
	}
	// An Access-Challenge carries State so the next request is matched to this session.
	if code == radius.CodeAccessChallenge {
		if state := rfc2865.State_Get(r.Packet); len(state) > 0 {
			rfc2865.State_Set(resp, state)
		} else {
			rfc2865.State_Set(resp, []byte(sessionKey(r)))
		}
	}

	// The Message-Authenticator must be present and is computed over the finished packet, so
	// it is added last with a zeroed placeholder.
	if err := setMessageAuthenticator(resp, s.cfg.Secret, r.Authenticator[:]); err != nil {
		s.log.Error("could not sign the RADIUS response", "err", err)
		return
	}

	if err := w.Write(resp); err != nil {
		s.log.Debug("could not write the RADIUS response", "err", err)
	}
}

func (s *Server) reject(w radius.ResponseWriter, r *radius.Request) {
	s.bump(func(st *Stats) { st.Rejects++ })
	s.respond(w, r, radius.CodeAccessReject, nil)
}

// recordOutcome hands a completed authentication to the caller.
func (s *Server) recordOutcome(r *radius.Request, o method.Outcome) {
	out := Outcome{
		Outcome:        o,
		ESSID:          s.cfg.ESSID,
		CallingStation: rfc2865.CallingStationID_GetString(r.Packet),
		CalledStation:  rfc2865.CalledStationID_GetString(r.Packet),
		At:             time.Now(),
	}

	s.bump(func(st *Stats) {
		if o.HashLine != "" || o.Cleartext != "" {
			st.Captured++
		}
		if o.CertificateRejected() {
			st.CertRefused++
		}
	})

	if s.cfg.OnOutcome != nil {
		s.cfg.OnOutcome(out)
	}
}

// Stats returns the server's counters.
func (s *Server) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	return st
}

func (s *Server) bump(fn func(*Stats)) {
	s.mu.Lock()
	fn(&s.stats)
	s.mu.Unlock()
}

// sessionKey identifies one supplicant's authentication across RADIUS round trips.
//
// The State attribute is the RADIUS-native way to do this; where hostapd does not send one,
// the calling station plus the peer address is stable enough for a single AP.
func sessionKey(r *radius.Request) string {
	if state := rfc2865.State_Get(r.Packet); len(state) > 0 {
		return string(state)
	}
	if id := rfc2865.CallingStationID_GetString(r.Packet); id != "" {
		return id
	}
	return r.RemoteAddr.String()
}

// ---------------------------------------------------------------------------
// EAP-Message attribute handling
// ---------------------------------------------------------------------------

// maxAttrValue is the largest value a single RADIUS attribute can carry.
const maxAttrValue = 253

// concatEAPMessages joins the EAP-Message attributes in order.
//
// An EAP payload longer than 253 bytes - which every certificate fragment is - is split across
// multiple EAP-Message attributes that must be concatenated in the order they appear.
// Reading only the first attribute yields a truncated packet that parses as valid and fails
// mysteriously later.
func concatEAPMessages(p *radius.Packet) []byte {
	var out []byte
	for _, avp := range p.Attributes {
		if avp.Type == rfc2869.EAPMessage_Type {
			out = append(out, radius.Bytes(avp.Attribute)...)
		}
	}
	return out
}

// appendEAPMessages splits an EAP payload across as many EAP-Message attributes as needed.
func appendEAPMessages(p *radius.Packet, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	for len(data) > 0 {
		chunk := data
		if len(chunk) > maxAttrValue {
			chunk = chunk[:maxAttrValue]
		}
		data = data[len(chunk):]

		// Add, not Set: a payload longer than 253 bytes needs several EAP-Message attributes
		// and Set would replace the previous one, silently truncating every fragment to its
		// last 253 bytes.
		attr, err := radius.NewBytes(chunk)
		if err != nil {
			return fmt.Errorf("radius: encode EAP-Message chunk: %w", err)
		}
		p.Attributes.Add(rfc2869.EAPMessage_Type, attr)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Message-Authenticator
// ---------------------------------------------------------------------------

// messageAuthenticatorLen is the HMAC-MD5 output size.
const messageAuthenticatorLen = 16

// validateMessageAuthenticator checks the attribute on an inbound request.
//
// RFC 3579 requires it on any packet carrying EAP-Message. A packet without one, or with a
// wrong one, did not come from our hostapd - accepting it would mean recording credentials
// that cannot be attributed to a real supplicant.
func (s *Server) validateMessageAuthenticator(r *radius.Request) bool {
	got := rfc2869.MessageAuthenticator_Get(r.Packet)
	if len(got) != messageAuthenticatorLen {
		return false
	}

	// The HMAC is computed over the packet with the Message-Authenticator zeroed.
	encoded, err := r.Packet.Encode()
	if err != nil {
		return false
	}
	zeroed := zeroMessageAuthenticator(encoded)
	if zeroed == nil {
		return false
	}

	mac := hmac.New(md5.New, s.cfg.Secret)
	mac.Write(zeroed)
	return hmac.Equal(mac.Sum(nil), got)
}

// setMessageAuthenticator computes and sets the attribute on an outbound response.
func setMessageAuthenticator(p *radius.Packet, secret, requestAuthenticator []byte) error {
	// Add a zeroed placeholder so the attribute is present at its final offset before the
	// HMAC is computed over the encoded packet.
	if err := rfc2869.MessageAuthenticator_Set(p, make([]byte, messageAuthenticatorLen)); err != nil {
		return fmt.Errorf("radius: reserve Message-Authenticator: %w", err)
	}

	encoded, err := p.Encode()
	if err != nil {
		return fmt.Errorf("radius: encode response: %w", err)
	}
	// For a response, the HMAC covers the packet with the *request's* authenticator in place
	// of the response's own.
	if len(encoded) >= 20 && len(requestAuthenticator) == 16 {
		copy(encoded[4:20], requestAuthenticator)
	}

	mac := hmac.New(md5.New, secret)
	mac.Write(encoded)

	if err := rfc2869.MessageAuthenticator_Set(p, mac.Sum(nil)); err != nil {
		return fmt.Errorf("radius: set Message-Authenticator: %w", err)
	}
	return nil
}

// zeroMessageAuthenticator returns a copy of an encoded packet with the Message-Authenticator
// attribute value zeroed, which is what the HMAC is computed over.
func zeroMessageAuthenticator(encoded []byte) []byte {
	const (
		headerLen = 20
		attrType  = 80 // Message-Authenticator
	)
	if len(encoded) < headerLen {
		return nil
	}

	out := make([]byte, len(encoded))
	copy(out, encoded)

	for off := headerLen; off+2 <= len(out); {
		typ := out[off]
		length := int(out[off+1])
		if length < 2 || off+length > len(out) {
			return nil
		}
		if typ == attrType && length == 2+messageAuthenticatorLen {
			for i := off + 2; i < off+length; i++ {
				out[i] = 0
			}
		}
		off += length
	}
	return out
}

// LocalAddr reports where the server is listening, for the generated hostapd config.
func (s *Server) LocalAddr() string { return s.cfg.Addr }

// SplitHostPort separates the configured listen address.
func SplitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("radius: parse listen address %q: %w", addr, err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return "", 0, fmt.Errorf("radius: parse port %q: %w", portStr, err)
	}
	return host, port, nil
}
