package harvest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/waffl3ss/warp/internal/eap/method"
)

// The harvesting peer.
//
// # What this does, and where it stops
//
// A WPA-Enterprise access point will hand its RADIUS server's certificate to anyone who asks.
// That is not a flaw: the certificate is public, and presenting it is the first thing the
// server does, before it has any idea who is connecting. Everything needed to build a
// convincing mimic - subject, issuer, SANs, validity, key algorithm, serial - is in it.
//
// So the harvest is exactly the beginning of a connection and nothing more:
//
//	associate → EAPOL-Start → EAP-Response/Identity → PEAP/TLS Start
//	→ ClientHello → **ServerHello + Certificate** → stop
//
// It stops there deliberately, and the stop is enforced by TLS itself rather than by
// remembering to break out of a loop: the client configuration carries a VerifyPeerCertificate
// callback that records the chain and then returns an error, so the standard library aborts
// the handshake the instant the certificate arrives. Nothing after that point is ever sent -
// no key exchange, no tunnel, no inner method, no identity beyond the anonymous outer one.
//
// The alternative - capturing an association in Wireshark and digging the chain out of a pcap
// by hand - is what this replaces. It is the same bytes; getting them out of a capture is just
// tedious enough that people skip it and ship a self-signed certificate instead, which no
// client has ever accepted.
//
// # Why this is not credential theft
//
// The harvesting supplicant has no credentials to send. Not "does not send them" - does not
// have them. There is nothing to leak even if the exchange ran to completion, and it does not
// run to completion.

// Transport is how the peer exchanges 802.1X payloads with the access point.
//
// An interface rather than a concrete radio, so the state machine is testable end to end
// against an in-process RADIUS server on a machine with no wireless hardware at all - which is
// most of the machines this gets developed on.
type Transport interface {
	// Send transmits one 802.1X payload (an EAPOL frame body) to the access point.
	Send(ctx context.Context, eapol []byte) error
	// Receive returns the next 802.1X payload addressed to our station, or an error if none
	// arrives before ctx is done.
	Receive(ctx context.Context) ([]byte, error)
}

// PeerOptions configures one harvest.
type PeerOptions struct {
	// ESSID is the network being harvested. Recorded on the result; also the TLS SNI, which
	// some RADIUS servers use to select which certificate to present.
	ESSID string
	// BSSID is the discovered access point, for the record.
	BSSID string
	// Identity is the outer identity sent in the EAP identity response.
	//
	// Anonymous by default and deliberately: the outer identity is visible in clear text to
	// anything listening, it ends up in the client's RADIUS logs, and a harvest has no reason
	// to claim to be a person. "anonymous" is what a correctly configured supplicant sends
	// anyway, so it is also the least conspicuous thing to send.
	Identity string
	// Timeout bounds one request/response round.
	Timeout time.Duration
	// Rounds bounds the whole exchange, so a server that fragments endlessly cannot hold a
	// radio forever.
	Rounds int
}

func (o PeerOptions) withDefaults() PeerOptions {
	if o.Identity == "" {
		o.Identity = "anonymous"
	}
	if o.Timeout <= 0 {
		o.Timeout = 3 * time.Second
	}
	if o.Rounds <= 0 {
		// Generous: a 4 KB chain at 1000-byte fragments is five rounds, plus identity and
		// start. Forty leaves room for a long chain on a slow link and still terminates.
		o.Rounds = 40
	}
	return o
}

// errCertificateHarvested is returned from the verify callback to stop the handshake.
//
// It is not a failure. It is the success condition: the certificate arrived, it has been
// recorded, and there is no reason to complete a handshake we are about to abandon anyway.
var errCertificateHarvested = errors.New("harvest: certificate captured, handshake abandoned")

// ErrNoEnterpriseExchange is returned when the access point never started an EAP conversation.
var ErrNoEnterpriseExchange = errors.New(
	"harvest: the access point sent no EAP request; it may not be WPA-Enterprise")

// Harvest runs the peer exchange and returns the certificate chain the network presented.
//
// The returned Result is complete enough to generate a mimic from without going back to the
// air, which matters: the harvest costs an association at a production access point and should
// happen once.
func Harvest(ctx context.Context, t Transport, o PeerOptions) (*Result, error) {
	o = o.withDefaults()

	var (
		captured []*x509.Certificate
		state    tls.ConnectionState
	)

	cfg := ClientConfig(o.ESSID)
	cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		// Parsed here rather than trusting the library to have done it: with
		// InsecureSkipVerify set, verifiedChains is empty and rawCerts is what there is.
		for _, der := range rawCerts {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				// A chain we cannot parse is still worth reporting as far as it got, so the
				// loop keeps whatever parsed rather than discarding the lot.
				continue
			}
			captured = append(captured, c)
		}
		// Stop here. Everything wanted has arrived, and going further would mean completing a
		// handshake in order to immediately throw it away.
		return errCertificateHarvested
	}

	sess := method.NewTLSClient(cfg)
	defer sess.Close()

	frag := method.NewFragmenter(method.DefaultMaxFragment)
	peapVersion := uint8(method.PEAPVersion0)
	var innerType method.Type
	started := false

	// EAPOL-Start. Most access points send EAP-Request/Identity unprompted on association, but
	// one that is waiting for a Start will wait forever, and that failure is indistinguishable
	// from "this network is not enterprise".
	if err := t.Send(ctx, eapolStart()); err != nil {
		return nil, fmt.Errorf("harvest: send EAPOL-Start: %w", err)
	}

	sawEAP := false
	// EAPOL-Start is resent while nothing has come back yet. An access point that expects a Start
	// waits forever without one, and a Start sent in the instant the association came up can be
	// lost - so a single Start followed by one timeout used to read as "not enterprise" when the
	// exchange had simply not been kicked off. Each retry costs one Timeout; the budget keeps the
	// whole thing inside the job window.
	const maxStarts = 4
	startsSent := 1
	for round := 0; round < o.Rounds; round++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		rctx, cancel := context.WithTimeout(ctx, o.Timeout)
		payload, err := t.Receive(rctx)
		cancel()
		if err != nil {
			if len(captured) > 0 {
				break // we already have what we came for
			}
			if !sawEAP {
				if startsSent < maxStarts && ctx.Err() == nil {
					if serr := t.Send(ctx, eapolStart()); serr == nil {
						startsSent++
						continue
					}
				}
				return nil, ErrNoEnterpriseExchange
			}
			return nil, fmt.Errorf("harvest: waiting for the next EAP request: %w", err)
		}

		pkt, err := parseEAPOL(payload)
		if err != nil {
			continue // not an EAP packet; the access point sends other 802.1X traffic too
		}
		sawEAP = true

		switch {
		case pkt.Code == method.CodeSuccess || pkt.Code == method.CodeFailure:
			// Either ends the conversation. A Failure here is entirely expected - we never
			// authenticated - and is not an error if the certificate already arrived.
			if len(captured) > 0 {
				return buildResult(o, captured, state, sess)
			}
			return nil, fmt.Errorf(
				"harvest: the access point ended the exchange (EAP %s) before presenting a "+
					"certificate", codeName(pkt.Code))

		case pkt.Code != method.CodeRequest:
			continue
		}

		switch pkt.Type {
		case method.TypeIdentity:
			out := &method.Packet{
				Code: method.CodeResponse, Identifier: pkt.Identifier,
				Type: method.TypeIdentity, Data: []byte(o.Identity),
			}
			if err := t.Send(ctx, eapolPacket(out.Marshal())); err != nil {
				return nil, fmt.Errorf("harvest: send identity: %w", err)
			}

		case method.TypePEAP, method.TypeTTLS, method.TypeTLS:
			if innerType == 0 {
				innerType = pkt.Type
			}
			if pkt.Type != innerType {
				// The server switched methods mid-exchange. Follow it: which tunnel type it
				// offers is itself worth recording, and the certificate is the same either way.
				innerType = pkt.Type
			}

			msg, err := method.ParseTLSMessage(pkt.Data)
			if err != nil {
				return nil, fmt.Errorf("harvest: malformed %s packet: %w", pkt.Type, err)
			}
			if v := msg.Version(); v != 0 {
				peapVersion = v
			}

			var send []byte
			switch {
			case msg.Start() && !started:
				// The Start packet carries no TLS bytes: it is the server saying "begin". The
				// ClientHello is ours to produce.
				started = true
				out, err := sess.Exchange(nil, o.Timeout)
				if err != nil && len(out) == 0 {
					return nil, fmt.Errorf("harvest: producing the client hello: %w", err)
				}
				frag.Queue(out)
				send = frag.Next(peapVersion)

			case frag.Pending():
				// Mid-transmission: the server is acknowledging our fragments.
				send = frag.Next(peapVersion)

			default:
				assembled, complete := frag.Accept(msg)
				if !complete {
					send = method.ACK(peapVersion)
					break
				}

				out, err := sess.Exchange(assembled, o.Timeout)
				if len(captured) > 0 {
					// The verify callback fired: the chain is in hand and the handshake has
					// been aborted on purpose. Say goodbye and stop.
					_ = t.Send(ctx, eapolLogoff())
					return buildResult(o, captured, sess.ConnectionState(), sess)
				}
				if err != nil && len(out) == 0 {
					return nil, fmt.Errorf("harvest: TLS exchange: %w", err)
				}
				frag.Queue(out)
				send = frag.Next(peapVersion)
			}

			resp := &method.Packet{
				Code: method.CodeResponse, Identifier: pkt.Identifier,
				Type: pkt.Type, Data: send,
			}
			if err := t.Send(ctx, eapolPacket(resp.Marshal())); err != nil {
				return nil, fmt.Errorf("harvest: send %s: %w", pkt.Type, err)
			}

		default:
			// Something other than a TLS-based method: MD5-Challenge, GTC, or a vendor type.
			// Nak it back to PEAP, which is what the certificate lives behind.
			nak := &method.Packet{
				Code: method.CodeResponse, Identifier: pkt.Identifier,
				Type: method.TypeNak, Data: []byte{byte(method.TypePEAP)},
			}
			if err := t.Send(ctx, eapolPacket(nak.Marshal())); err != nil {
				return nil, fmt.Errorf("harvest: send Nak: %w", err)
			}
		}
	}

	if len(captured) > 0 {
		_ = t.Send(ctx, eapolLogoff())
		return buildResult(o, captured, state, sess)
	}
	return nil, fmt.Errorf("harvest: no certificate after %d rounds", o.Rounds)
}

// buildResult turns the captured chain into a Result, reusing the same extraction the offline
// path uses so a harvested certificate and a replayed one produce identical records.
func buildResult(o PeerOptions, chain []*x509.Certificate, state tls.ConnectionState,
	sess *method.TLSSession) (*Result, error) {

	if len(chain) == 0 {
		return nil, ErrNoCertificate
	}

	// The handshake was abandoned before it completed, so the negotiated version and cipher
	// are whatever TLS had settled on at the point the certificate arrived. That is still the
	// server's choice and is worth recording - a server that will negotiate TLS 1.0 is a
	// finding on its own.
	if state.Version == 0 {
		state = sess.ConnectionState()
	}
	state.PeerCertificates = chain

	res, err := FromConnectionState(o.ESSID, o.BSSID, state)
	if err != nil {
		return nil, err
	}
	res.Notes = append(res.Notes,
		"harvested from the air: the exchange was abandoned as soon as the certificate "+
			"arrived, before any key exchange and before any inner authentication")
	return res, nil
}

// EAPOL framing helpers. These mirror internal/inject's transmit-side constants; they are
// duplicated rather than imported because harvest must not depend on the injector - the
// transport is an interface precisely so this package can be exercised without a radio.
const (
	eapolVersion    = 0x01
	eapolTypeEAP    = 0x00
	eapolTypeStart  = 0x01
	eapolTypeLogoff = 0x02
)

func eapolStart() []byte  { return []byte{eapolVersion, eapolTypeStart, 0, 0} }
func eapolLogoff() []byte { return []byte{eapolVersion, eapolTypeLogoff, 0, 0} }

func eapolPacket(eap []byte) []byte {
	p := []byte{eapolVersion, eapolTypeEAP, byte(len(eap) >> 8), byte(len(eap))}
	return append(p, eap...)
}

// parseEAPOL unwraps an 802.1X frame and returns the EAP packet inside it.
func parseEAPOL(b []byte) (*method.Packet, error) {
	if len(b) < 4 {
		return nil, errors.New("harvest: short 802.1X frame")
	}
	if b[1] != eapolTypeEAP {
		return nil, errors.New("harvest: 802.1X frame is not an EAP-Packet")
	}
	length := int(b[2])<<8 | int(b[3])
	body := b[4:]
	// Trust the header only as far as the frame actually goes: a truncated capture with a
	// header claiming more must not slice out of range.
	if length > 0 && length <= len(body) {
		body = body[:length]
	}
	return method.ParsePacket(body)
}

func codeName(c uint8) string {
	switch c {
	case method.CodeSuccess:
		return "Success"
	case method.CodeFailure:
		return "Failure"
	default:
		return fmt.Sprintf("code %d", c)
	}
}
