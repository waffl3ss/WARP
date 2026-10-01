package method

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/eap/mimic"
)

func testChain(t *testing.T) *mimic.Chain {
	t.Helper()
	chain, err := mimic.SelfSigned("CORP-8021X", mimic.Options{})
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	return chain
}

// TestTLSOverEAPTransport drives a full TLS handshake through the EAP transport against a
// real crypto/tls client.
//
// This is the assertion that the in-memory pipe actually works as a net.Conn: if the shuttling
// were wrong the handshake would deadlock or produce a protocol error, and no amount of unit
// testing the fragmenter would catch it.
func TestTLSOverEAPTransport(t *testing.T) {
	chain := testChain(t)

	session := NewTLSServer(&tls.Config{
		Certificates: []tls.Certificate{chain.TLS},
		MinVersion:   tls.VersionTLS12,
	})
	defer session.Close()

	// The client end is an ordinary crypto/tls client over a real socket pair, so the bytes
	// crossing the EAP transport are exactly what a supplicant would send.
	clientConn, serverSide := net.Pipe()
	defer clientConn.Close()
	defer serverSide.Close()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(chain.CAPEM) {
		t.Fatal("could not load the generated CA")
	}

	var (
		wg        sync.WaitGroup
		clientErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		c := tls.Client(clientConn, &tls.Config{
			RootCAs:    pool,
			ServerName: "radius.corp-8021x",
			MinVersion: tls.VersionTLS12,
		})
		clientErr = c.Handshake()
		c.Close()
	}()

	// Shuttle bytes between the socket and the EAP transport, exactly as the RADIUS server
	// does with EAP-TLS fragments.
	//
	// Read first, then exchange: a TLS server never speaks before it has seen a ClientHello,
	// so calling Exchange with nothing to feed it would simply time out.
	done := make(chan struct{})
	go func() {
		defer close(done)
		shuttle(serverSide, session, 40, 2*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("handshake did not complete")
	}
	wg.Wait()

	if clientErr != nil {
		t.Fatalf("client handshake failed: %v", clientErr)
	}
	if !session.HandshakeComplete() {
		t.Fatalf("server handshake did not complete: %v", session.HandshakeError())
	}

	state := session.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		t.Errorf("negotiated TLS version %#x", state.Version)
	}
}

// TestClientRejectingTheMimicIsRecorded is the pass case.
//
// A supplicant that validates the chain against the real CA refuses the mimic. That is
// correct client behaviour and a good result for the client — the module measures
// configuration hygiene, so the rejection must surface as a recordable outcome rather than
// as a tool malfunction.
func TestClientRejectingTheMimicIsRecorded(t *testing.T) {
	chain := testChain(t)

	session := NewTLSServer(&tls.Config{
		Certificates: []tls.Certificate{chain.TLS},
		MinVersion:   tls.VersionTLS12,
	})
	defer session.Close()

	clientConn, serverSide := net.Pipe()
	defer clientConn.Close()
	defer serverSide.Close()

	var (
		wg        sync.WaitGroup
		clientErr error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// An empty root pool: the client trusts nothing, which is what a properly pinned
		// supplicant looks like from our side.
		c := tls.Client(clientConn, &tls.Config{
			RootCAs:    x509.NewCertPool(),
			ServerName: "radius.corp-8021x",
			MinVersion: tls.VersionTLS12,
		})
		clientErr = c.Handshake()
		c.Close()
	}()

	go shuttle(serverSide, session, 20, time.Second)

	wg.Wait()

	if clientErr == nil {
		t.Fatal("a client with an empty trust store accepted the mimic; the chain check is not working")
	}
	// The rejection is the finding. It must be distinguishable from a broken transport.
	if !strings.Contains(clientErr.Error(), "certificate") {
		t.Errorf("client error should name the certificate: %v", clientErr)
	}
	t.Logf("client correctly rejected the mimic: %v (this is a PASS for the client)", clientErr)
}

func TestExchangeTimesOutRatherThanHanging(t *testing.T) {
	chain := testChain(t)
	session := NewTLSServer(&tls.Config{Certificates: []tls.Certificate{chain.TLS}})
	defer session.Close()

	// Feeding nothing: TLS is waiting for a ClientHello that never comes.
	start := time.Now()
	_, err := session.Exchange(nil, 200*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout")
	}
	if !errors.Is(err, ErrHandshakeTimeout) {
		t.Errorf("err = %v, want ErrHandshakeTimeout", err)
	}
	if elapsed > 3*time.Second {
		t.Errorf("Exchange blocked for %v; it must not hang", elapsed)
	}
}

func TestApplicationDataBeforeHandshakeIsRefused(t *testing.T) {
	chain := testChain(t)
	session := NewTLSServer(&tls.Config{Certificates: []tls.Certificate{chain.TLS}})
	defer session.Close()

	if _, err := session.WriteApplication([]byte("inner"), time.Second); err == nil {
		t.Error("wrote application data before the handshake completed")
	}
	if _, err := session.ReadApplication(nil, time.Second); err == nil {
		t.Error("read application data before the handshake completed")
	}
	if _, err := session.ExportKeyingMaterial("test", 64); err == nil {
		t.Error("exported keying material before the handshake completed")
	}
}

// ---------------------------------------------------------------------------
// Fragmentation
// ---------------------------------------------------------------------------

// TestFragmentationRoundTrip: a certificate chain is several kilobytes, so this path runs on
// every authentication.
func TestFragmentationRoundTrip(t *testing.T) {
	payload := make([]byte, 3500)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	sender := NewFragmenter(1000)
	sender.Queue(payload)

	receiver := NewFragmenter(1000)

	var (
		fragments int
		assembled []byte
		acks      int
	)
	for sender.Pending() {
		raw := sender.Next(PEAPVersion0)
		fragments++

		msg, err := ParseTLSMessage(raw)
		if err != nil {
			t.Fatalf("fragment %d does not parse: %v", fragments, err)
		}

		// The first fragment of a fragmented message carries the total length.
		if fragments == 1 {
			if !msg.LengthIncluded() {
				t.Error("first fragment does not carry the total length")
			}
			if msg.TotalLength != uint32(len(payload)) {
				t.Errorf("total length = %d, want %d", msg.TotalLength, len(payload))
			}
		} else if msg.LengthIncluded() {
			t.Errorf("fragment %d repeats the total length", fragments)
		}

		if NeedsACK(msg) {
			acks++
		}

		out, complete := receiver.Accept(msg)
		if complete {
			assembled = out
		}
	}

	if fragments != 4 {
		t.Errorf("produced %d fragments for %d bytes at 1000 per fragment, want 4",
			fragments, len(payload))
	}
	if acks != fragments-1 {
		t.Errorf("%d fragments needed an ACK, want %d (every fragment but the last)",
			acks, fragments-1)
	}
	if len(assembled) != len(payload) {
		t.Fatalf("assembled %d bytes, want %d", len(assembled), len(payload))
	}
	for i := range payload {
		if assembled[i] != payload[i] {
			t.Fatalf("assembled payload differs at byte %d", i)
		}
	}
}

// TestUnfragmentedMessageOmitsTotalLength: sending it on a message that fits in one packet is
// legal but upsets some supplicants.
func TestUnfragmentedMessageOmitsTotalLength(t *testing.T) {
	f := NewFragmenter(1000)
	f.Queue(make([]byte, 100))

	msg, err := ParseTLSMessage(f.Next(PEAPVersion0))
	if err != nil {
		t.Fatalf("ParseTLSMessage: %v", err)
	}
	if msg.LengthIncluded() {
		t.Error("an unfragmented message carried a total-length field")
	}
	if msg.MoreFragments() {
		t.Error("an unfragmented message set the more-fragments bit")
	}
	if f.Pending() {
		t.Error("bytes remain after a single unfragmented message")
	}
}

// TestACKIsRecognised: feeding an acknowledgment's empty payload into the TLS state machine
// corrupts the handshake.
func TestACKIsRecognised(t *testing.T) {
	msg, err := ParseTLSMessage(ACK(PEAPVersion0))
	if err != nil {
		t.Fatalf("ParseTLSMessage: %v", err)
	}
	if !msg.IsACK() {
		t.Fatalf("an ACK was not recognised: flags=%#02x data=%d", msg.Flags, len(msg.Data))
	}

	// A start packet is not an ACK even though it carries no data.
	start, _ := ParseTLSMessage(BuildTLSMessage(FlagStart|PEAPVersion0, 0, nil))
	if start.IsACK() {
		t.Error("a start packet was treated as an ACK")
	}
	// Nor is a packet with data.
	withData, _ := ParseTLSMessage(BuildTLSMessage(PEAPVersion0, 0, []byte{1, 2, 3}))
	if withData.IsACK() {
		t.Error("a packet carrying data was treated as an ACK")
	}
}

func TestParseTLSMessageRejectsMalformed(t *testing.T) {
	if _, err := ParseTLSMessage(nil); err == nil {
		t.Error("empty packet accepted")
	}
	// Length-included flag set but no room for the length field.
	if _, err := ParseTLSMessage([]byte{FlagLengthIncluded, 0x00}); err == nil {
		t.Error("truncated length field accepted")
	}
}

// ---------------------------------------------------------------------------
// EAP packets
// ---------------------------------------------------------------------------

func TestEAPPacketRoundTrip(t *testing.T) {
	p := Request(7, TypePEAP, []byte{FlagStart | PEAPVersion0})
	raw := p.Marshal()

	got, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if got.Code != CodeRequest || got.Identifier != 7 || got.Type != TypePEAP {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	if len(got.Data) != 1 || got.Data[0] != FlagStart {
		t.Errorf("data = % x", got.Data)
	}

	// Success and Failure carry no type or data.
	for _, p := range []*Packet{Success(3), Failure(4)} {
		back, err := ParsePacket(p.Marshal())
		if err != nil {
			t.Fatalf("ParsePacket: %v", err)
		}
		if len(back.Data) != 0 {
			t.Errorf("code %d carried data", back.Code)
		}
	}
}

func TestEAPPacketRejectsBadLength(t *testing.T) {
	// Length field claims more than the buffer holds.
	if _, err := ParsePacket([]byte{CodeRequest, 1, 0xFF, 0xFF, 1}); !errors.Is(err, ErrEAPLength) {
		t.Errorf("got %v, want ErrEAPLength", err)
	}
	if _, err := ParsePacket([]byte{1, 2}); !errors.Is(err, ErrShortEAP) {
		t.Errorf("got %v, want ErrShortEAP", err)
	}
}

// TestNakEnumeratesAcceptableMethods: a Nak names what the supplicant would accept instead,
// which is itself a finding.
func TestNakEnumeratesAcceptableMethods(t *testing.T) {
	nak := &Packet{Code: CodeResponse, Identifier: 2, Type: TypeNak,
		Data: []byte{byte(TypePEAP), byte(TypeTTLS), 0}}

	types := NakTypes(nak)
	if len(types) != 2 {
		t.Fatalf("got %d types, want 2 (zero padding must be ignored)", len(types))
	}
	if types[0] != TypePEAP || types[1] != TypeTTLS {
		t.Errorf("types = %v", types)
	}
	if NakTypes(Request(1, TypeIdentity, nil)) != nil {
		t.Error("NakTypes returned values for a non-Nak packet")
	}
}

func TestMimicMirrorsHarvestedFields(t *testing.T) {
	h := mimic.Harvested{
		Subject:            pkix.Name{CommonName: "radius.corp.example", Organization: []string{"Example Corp"}},
		Issuer:             pkix.Name{CommonName: "Example Corp Issuing CA"},
		DNSNames:           []string{"radius.corp.example", "radius2.corp.example"},
		NotBefore:          time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:           time.Now().Add(300 * 24 * time.Hour),
		PublicKeyAlgorithm: x509.RSA,
		KeyBits:            2048,
	}

	chain, err := mimic.Generate(h, mimic.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	leaf, err := x509.ParseCertificate(chain.TLS.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	// Trimmed: the mimic marks the common name with a trailing space so the artefact is
	// provably not the client's own certificate. It changes no visible glyph, which is the
	// point — see mimic.Distinguish.
	if got := strings.TrimSpace(leaf.Subject.CommonName); got != h.Subject.CommonName {
		t.Errorf("subject CN = %q, want %q", got, h.Subject.CommonName)
	}
	if !mimic.IsDistinguished(leaf.Subject.CommonName) {
		t.Errorf("subject CN %q carries no distinguishing mark", leaf.Subject.CommonName)
	}
	if leaf.Issuer.CommonName != h.Issuer.CommonName {
		t.Errorf("issuer CN = %q, want %q — a TOFU prompt shows this", leaf.Issuer.CommonName, h.Issuer.CommonName)
	}
	if len(leaf.DNSNames) != 2 {
		t.Errorf("SANs = %v, want both mirrored", leaf.DNSNames)
	}

	// Server auth EKU is required or a checking supplicant rejects before showing a name.
	var hasServerAuth bool
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("leaf lacks the server-auth EKU")
	}

	// And the chain really is ours, not the client's: it must not validate against anything
	// but the generated CA.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(chain.CAPEM) {
		t.Fatal("could not load the generated CA")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "radius.corp.example"}); err != nil {
		t.Errorf("leaf does not verify against its own CA: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: x509.NewCertPool()}); err == nil {
		t.Error("leaf verified against an empty trust store")
	}
}

// TestMimicRefusesToShipAnExpiredCertificate: an expired certificate is rejected before any
// name is displayed, wasting the one chance at a click-through.
func TestMimicRefusesToShipAnExpiredCertificate(t *testing.T) {
	h := mimic.Harvested{
		Subject:            pkix.Name{CommonName: "old.corp.example"},
		Issuer:             pkix.Name{CommonName: "Old CA"},
		NotBefore:          time.Now().Add(-800 * 24 * time.Hour),
		NotAfter:           time.Now().Add(-400 * 24 * time.Hour), // long expired
		PublicKeyAlgorithm: x509.RSA,
		KeyBits:            2048,
	}

	chain, err := mimic.Generate(h, mimic.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	leaf, _ := x509.ParseCertificate(chain.TLS.Certificate[0])

	if leaf.NotAfter.Before(time.Now()) {
		t.Error("generated an already-expired mimic; it would be rejected before the name is shown")
	}
	if leaf.NotBefore.After(time.Now()) {
		t.Error("generated a not-yet-valid mimic")
	}
}

// shuttle moves bytes between a socket and an EAP TLS transport, mimicking what the RADIUS
// server does with EAP-TLS fragments.
//
// The order matters and is the same as the real protocol: a TLS server produces nothing until
// it has received something, so every round reads first and only then asks the transport what
// to send back.
func shuttle(conn net.Conn, session *TLSSession, rounds int, timeout time.Duration) {
	buf := make([]byte, 8192)

	for i := 0; i < rounds; i++ {
		conn.SetReadDeadline(time.Now().Add(timeout))
		n, rerr := conn.Read(buf)

		var in []byte
		if n > 0 {
			in = append([]byte(nil), buf[:n]...)
		}

		out, xerr := session.Exchange(in, timeout)
		if len(out) > 0 {
			conn.SetWriteDeadline(time.Now().Add(timeout))
			if _, werr := conn.Write(out); werr != nil {
				return
			}
		}

		if session.HandshakeComplete() || xerr != nil || rerr != nil {
			return
		}
	}
}
