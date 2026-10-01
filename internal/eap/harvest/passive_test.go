package harvest

import (
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/eap/method"
	"github.com/waffl3ss/warp/internal/eap/mimic"
)

// tlsRecord wraps a payload in a TLS record header of the given content type.
func tlsRecord(typ byte, payload []byte) []byte {
	rec := []byte{typ, 0x03, 0x03}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(payload)))
	return append(rec, payload...)
}

// handshakeMsg wraps a body in a TLS handshake-message header of the given type.
func handshakeMsg(typ byte, body []byte) []byte {
	msg := []byte{typ, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// certificateBody builds a TLS Certificate handshake body from DER chains.
func certificateBody(ders [][]byte) []byte {
	var certs []byte
	for _, der := range ders {
		certs = append(certs, byte(len(der)>>16), byte(len(der)>>8), byte(len(der)))
		certs = append(certs, der...)
	}
	body := []byte{byte(len(certs) >> 16), byte(len(certs) >> 8), byte(len(certs))}
	return append(body, certs...)
}

// fixtureCert returns a realistic RADIUS server certificate's DER.
func fixtureCert(t *testing.T) []byte {
	t.Helper()
	chain, err := mimic.Generate(mimic.Harvested{
		Subject:     pkix.Name{CommonName: "radius.acme-corp.example", Organization: []string{"ACME"}},
		Issuer:      pkix.Name{CommonName: "ACME Internal Issuing CA"},
		DNSNames:    []string{"radius.acme-corp.example"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		SerialNumber: big.NewInt(0x1234), KeyBits: 2048,
	}, mimic.Options{ExactSubject: true})
	if err != nil {
		t.Fatalf("fixture cert: %v", err)
	}
	return chain.TLS.Certificate[0]
}

// TestCertificateIsExtractedFromASplitTLSStream.
//
// The server's Certificate message spans several TLS records and arrives as a run of EAP-TLS
// fragments. This is the whole passive-harvest path: reassemble, find handshake type 11, parse
// the DER. Splitting the stream across records and across EAP fragments is exactly what a real
// capture does and is where a naive parser breaks.
func TestCertificateIsExtractedFromASplitTLSStream(t *testing.T) {
	der := fixtureCert(t)

	// The server's flight: ServerHello, then a Certificate message big enough to span records.
	serverHello := handshakeMsg(2, make([]byte, 40))
	certMsg := handshakeMsg(11, certificateBody([][]byte{der}))
	flight := append(serverHello, certMsg...)

	// Split the handshake bytes across TLS records of 512 bytes.
	var stream []byte
	for off := 0; off < len(flight); off += 512 {
		end := off + 512
		if end > len(flight) {
			end = len(flight)
		}
		stream = append(stream, tlsRecord(tlsRecordHandshake, flight[off:end])...)
	}

	// Now split the TLS record stream across EAP-TLS fragments and feed them as EAP-Requests.
	var a Assembler
	var got [][]byte
	for off := 0; off < len(stream); off += 300 {
		end := off + 300
		more := true
		if end >= len(stream) {
			end = len(stream)
			more = false
		}
		flags := uint8(0)
		if more {
			flags |= method.FlagMoreFragments
		}
		payload := method.BuildTLSMessage(flags, 0, stream[off:end])
		eap := &method.Packet{Code: method.CodeRequest, Identifier: 1, Type: method.TypePEAP, Data: payload}

		if ders, ok := a.Feed(eap); ok {
			got = ders
			break
		}
	}

	if len(got) != 1 {
		t.Fatalf("extracted %d certificates, want 1", len(got))
	}

	res, err := FromCapturedCertificates("ACME-CORP", "a4:2b:8c:11:22:33", got)
	if err != nil {
		t.Fatalf("FromCapturedCertificates: %v", err)
	}
	leaf, ok := res.Leaf()
	if !ok {
		t.Fatal("no leaf in the result")
	}
	if leaf.Subject == "" || leaf.Fingerprint == "" {
		t.Errorf("leaf not populated: %+v", leaf)
	}
	// It must be usable to build a mimic — the whole point.
	if _, err := res.MimicSource(); err != nil {
		t.Errorf("harvested certificate cannot seed a mimic: %v", err)
	}
}

// TestClientFragmentsAreIgnored: only the server (EAP-Request) carries the certificate; a
// client's EAP-Response fragments must not be fed into the reassembly.
func TestClientFragmentsAreIgnored(t *testing.T) {
	var a Assembler
	// A client response carrying a plausible-looking but irrelevant payload.
	resp := &method.Packet{
		Code: method.CodeResponse, Identifier: 1, Type: method.TypePEAP,
		Data: method.BuildTLSMessage(0, 0, tlsRecord(tlsRecordHandshake, make([]byte, 100))),
	}
	if _, ok := a.Feed(resp); ok {
		t.Error("a client EAP-Response was accepted into the certificate reassembly")
	}
	if len(a.stream) != 0 {
		t.Error("a client response added bytes to the server stream")
	}
}

// TestPartialCertificateWaitsForMore: an incomplete Certificate message must not yield a
// truncated certificate; the assembler keeps waiting.
func TestPartialCertificateWaitsForMore(t *testing.T) {
	der := fixtureCert(t)
	certMsg := handshakeMsg(11, certificateBody([][]byte{der}))
	stream := tlsRecord(tlsRecordHandshake, certMsg)

	var a Assembler
	// Feed only the first half.
	half := len(stream) / 2
	eap := &method.Packet{
		Code: method.CodeRequest, Type: method.TypePEAP,
		Data: method.BuildTLSMessage(method.FlagMoreFragments, 0, stream[:half]),
	}
	if _, ok := a.Feed(eap); ok {
		t.Fatal("a half-received certificate was returned")
	}
	// The rest completes it.
	eap.Data = method.BuildTLSMessage(0, 0, stream[half:])
	ders, ok := a.Feed(eap)
	if !ok || len(ders) != 1 {
		t.Fatalf("certificate not completed after the second fragment: ok=%v n=%d", ok, len(ders))
	}
}
