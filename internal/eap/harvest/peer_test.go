package harvest

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/eap/method"
	"github.com/waffl3ss/warp/internal/eap/mimic"
)

// A fake enterprise access point, in process.
//
// The point of the Transport interface is that the whole harvest — association aside — can be
// exercised on a machine with no radios, which is most of the machines this is developed on.
// This server speaks real EAP over real TLS; only the 802.11 frames are missing.
type fakeAP struct {
	t    *testing.T
	tls  *method.TLSSession
	frag *method.Fragmenter

	toPeer  chan []byte
	fromAP  chan []byte
	stage   string
	id      uint8
	started bool
}

func newFakeAP(t *testing.T, cert tls.Certificate) *fakeAP {
	t.Helper()
	return &fakeAP{
		t:      t,
		tls:    method.NewTLSServer(&tls.Config{Certificates: []tls.Certificate{cert}}),
		frag:   method.NewFragmenter(method.DefaultMaxFragment),
		toPeer: make(chan []byte, 16),
		fromAP: make(chan []byte, 16),
		stage:  "await-start",
	}
}

// Send is the peer's transmit path: the AP receives here and queues its reply.
func (a *fakeAP) Send(ctx context.Context, eapol []byte) error {
	if len(eapol) < 4 {
		a.t.Fatalf("peer sent a %d-byte 802.1X frame", len(eapol))
	}

	switch eapol[1] {
	case 0x01: // EAPOL-Start
		a.id++
		a.queue(&method.Packet{
			Code: method.CodeRequest, Identifier: a.id, Type: method.TypeIdentity,
		})
		return nil
	case 0x02: // EAPOL-Logoff
		return nil
	}

	pkt, err := parseEAPOL(eapol)
	if err != nil {
		a.t.Fatalf("the peer sent something that is not an EAP packet: %v", err)
	}
	if pkt.Code != method.CodeResponse {
		a.t.Fatalf("the peer sent EAP code %d; a peer only ever sends responses", pkt.Code)
	}

	switch pkt.Type {
	case method.TypeIdentity:
		if got := string(pkt.Data); got != "anonymous" {
			a.t.Errorf("outer identity = %q, want anonymous — a harvest has no reason to claim "+
				"to be a person, and the outer identity is in the clear", got)
		}
		a.id++
		a.queue(&method.Packet{
			Code: method.CodeRequest, Identifier: a.id, Type: method.TypePEAP,
			Data: []byte{method.FlagStart | method.PEAPVersion0},
		})
		a.started = true

	case method.TypePEAP:
		msg, err := method.ParseTLSMessage(pkt.Data)
		if err != nil {
			a.t.Fatalf("peer sent a malformed PEAP packet: %v", err)
		}

		if a.frag.Pending() {
			a.id++
			a.queuePEAP(a.frag.Next(method.PEAPVersion0))
			return nil
		}

		assembled, complete := a.frag.Accept(msg)
		if !complete {
			a.id++
			a.queuePEAP(method.ACK(method.PEAPVersion0))
			return nil
		}

		out, err := a.tls.Exchange(assembled, 2*time.Second)
		if err != nil && len(out) == 0 {
			// The peer aborting after the certificate is the expected end of this test, not a
			// failure: it is the harvest declining to complete a handshake it has no use for.
			return nil
		}
		a.frag.Queue(out)
		a.id++
		a.queuePEAP(a.frag.Next(method.PEAPVersion0))

	default:
		a.t.Fatalf("peer sent unexpected EAP type %s", pkt.Type)
	}
	return nil
}

func (a *fakeAP) queue(p *method.Packet) {
	a.toPeer <- eapolPacket(p.Marshal())
}

func (a *fakeAP) queuePEAP(data []byte) {
	a.queue(&method.Packet{
		Code: method.CodeRequest, Identifier: a.id, Type: method.TypePEAP, Data: data,
	})
}

func (a *fakeAP) Receive(ctx context.Context) ([]byte, error) {
	select {
	case b := <-a.toPeer:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// testCertificate builds a certificate that looks like a real corporate RADIUS server's, so
// the test can assert the harvest recovered the fields a mimic is built from.
func testCertificate(t *testing.T) (tls.Certificate, *mimic.Chain) {
	t.Helper()

	chain, err := mimic.Generate(mimic.Harvested{
		Subject: pkix.Name{
			CommonName:   "radius.acme-corp.example",
			Organization: []string{"ACME Corporation"},
		},
		Issuer: pkix.Name{
			CommonName:   "ACME Corporation Internal Issuing CA 2",
			Organization: []string{"ACME Corporation"},
		},
		DNSNames:     []string{"radius.acme-corp.example", "radius2.acme-corp.example"},
		IPAddresses:  []net.IP{net.ParseIP("10.20.30.40")},
		NotBefore:    time.Now().Add(-90 * 24 * time.Hour),
		NotAfter:     time.Now().Add(275 * 24 * time.Hour),
		SerialNumber: big.NewInt(0x5eaf00d),
		KeyBits:      2048,
	}, mimic.Options{})
	if err != nil {
		t.Fatalf("building the fixture certificate: %v", err)
	}
	return chain.TLS, chain
}

// TestHarvestReadsTheCertificateWithoutAuthenticating.
//
// The whole enterprise pretext depends on this. A self-signed certificate with none of the
// target's naming on it is refused by every client that shows the user anything, so the mimic
// has to be built from the real one — and the real one is available to anyone who starts a
// connection, because the server presents it before it knows who is asking.
func TestHarvestReadsTheCertificateWithoutAuthenticating(t *testing.T) {
	cert, _ := testCertificate(t)
	ap := newFakeAP(t, cert)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := Harvest(ctx, ap, PeerOptions{
		ESSID: "ACME-CORP", BSSID: "a4:2b:8c:11:22:33",
	})
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}

	leaf, ok := res.Leaf()
	if !ok {
		t.Fatal("the harvest produced no leaf certificate")
	}

	// Every field a convincing mimic is built from.
	for _, want := range []string{"radius.acme-corp.example", "ACME Corporation"} {
		if !strings.Contains(leaf.Subject, want) {
			t.Errorf("leaf subject %q does not carry %q", leaf.Subject, want)
		}
	}
	if !strings.Contains(leaf.Issuer, "Internal Issuing CA") {
		t.Errorf("leaf issuer %q does not carry the issuing authority's name", leaf.Issuer)
	}
	if len(leaf.SANs) == 0 {
		t.Error("no SANs were harvested; a client checking the server name has nothing to match")
	}
	if leaf.KeyBits != 2048 {
		t.Errorf("key bits = %d, want 2048 — a mimic with a different key size is visibly "+
			"different in any client that shows certificate details", leaf.KeyBits)
	}
	if leaf.Fingerprint == "" {
		t.Error("no fingerprint recorded; there is nothing to prove the mimic came from this cert")
	}
	if len(res.PEM) == 0 {
		t.Error("no PEM was recorded, so the harvest cannot be re-read later")
	}

	// And the thing that makes it safe to run at a client site.
	joined := strings.Join(res.Notes, " ")
	if !strings.Contains(joined, "abandoned") {
		t.Errorf("the record does not say the exchange was abandoned early: %v", res.Notes)
	}
}

// TestHarvestBuildsAMimicFromWhatItRead — the harvest is only worth doing if what comes out
// of it can be turned into the certificate the rogue presents.
func TestHarvestBuildsAMimicFromWhatItRead(t *testing.T) {
	cert, _ := testCertificate(t)
	ap := newFakeAP(t, cert)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, err := Harvest(ctx, ap, PeerOptions{ESSID: "ACME-CORP"})
	if err != nil {
		t.Fatalf("Harvest: %v", err)
	}

	h, err := res.MimicSource()
	if err != nil {
		t.Fatalf("MimicSource: %v", err)
	}
	chain, err := mimic.Generate(h, mimic.Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(chain.TLS.Certificate) == 0 {
		t.Fatal("the generated chain has no certificate to present")
	}
}

// TestHarvestSaysSoWhenTheNetworkIsNotEnterprise.
//
// A PSK network never starts an EAP conversation, and the operator needs to be told that
// rather than watching a job time out with nothing to show for it.
func TestHarvestSaysSoWhenTheNetworkIsNotEnterprise(t *testing.T) {
	silent := silentAP{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Harvest(ctx, silent, PeerOptions{ESSID: "ACME-CORP", Timeout: 200 * time.Millisecond})
	if err == nil {
		t.Fatal("harvesting a silent access point succeeded")
	}
	if !strings.Contains(err.Error(), "WPA-Enterprise") {
		t.Errorf("error %q does not tell the operator the network may not be enterprise", err)
	}
}

type silentAP struct{}

func (silentAP) Send(context.Context, []byte) error { return nil }
func (silentAP) Receive(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
