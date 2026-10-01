package method

import (
	"bytes"
	"testing"
)

// The PEAPv0 inner EAP framing is the one part of the module that could only be pinned against a
// real supplicant (the eap-validate gate). These tests encode exactly what wpa_supplicant v2.10 put
// on the wire during a validated over-the-air capture, so the framing can never silently regress to
// the shape that stalled every authentication after the tunnel came up.
//
// The wire truth: inside the tunnel PEAPv0 carries only [Type][Type-Data]. The Code and Identifier
// come from the outer PEAP EAP-Request/Response; the Length is implied by the TLS record boundary.

func TestMarshalInnerIsBarePEAPv0Framing(t *testing.T) {
	// An inner EAP-Request/Identity is a single byte: the Identity type, no data. Not [Code][Id]
	// [Type] — sending those three bytes is what made the supplicant read the wrong Type on the
	// MSCHAPv2 round (it survived the identity round only because Code Request 1 == Type Identity 1).
	got := marshalInner(&Packet{Code: CodeRequest, Identifier: 0xA4, Type: TypeIdentity})
	if want := []byte{byte(TypeIdentity)}; !bytes.Equal(got, want) {
		t.Fatalf("inner identity request = %x, want %x (Code/Identifier must not be on the wire)", got, want)
	}

	// An inner MSCHAPv2 request is [Type=26][mschapv2 payload]. The Identifier lives inside the
	// MSCHAPv2 payload (MS-CHAP-ID), never in an EAP header here.
	payload := []byte{0x01, 0x2a, 0x00, 0x10, 0xde, 0xad}
	got = marshalInner(&Packet{Code: CodeRequest, Identifier: 0x2a, Type: TypeMSCHAPv2, Data: payload})
	want := append([]byte{byte(TypeMSCHAPv2)}, payload...)
	if !bytes.Equal(got, want) {
		t.Fatalf("inner mschapv2 request = %x, want %x", got, want)
	}
}

func TestUnmarshalInnerBareIdentityResponse(t *testing.T) {
	// The exact bytes wpa_supplicant sent for its inner EAP-Response/Identity with identity
	// "CORP\jdoe": [Type=Identity][identity]. No Code, no Identifier, no Length.
	wire := []byte{0x01, 0x43, 0x4f, 0x52, 0x50, 0x5c, 0x6a, 0x64, 0x6f, 0x65}
	pkt, err := unmarshalInner(wire)
	if err != nil {
		t.Fatalf("unmarshalInner: %v", err)
	}
	if pkt.Type != TypeIdentity {
		t.Fatalf("type = %v (%d), want Identity", pkt.Type, pkt.Type)
	}
	if got := string(pkt.Data); got != `CORP\jdoe` {
		t.Fatalf("identity = %q, want %q", got, `CORP\jdoe`)
	}
}

func TestUnmarshalInnerBareMSCHAPv2Response(t *testing.T) {
	// A bare inner MSCHAPv2 response: [Type=26][OpResponse ...]. The leading byte is 26, which is
	// not a valid EAP Code, so the full-header fallback must not misfire on it.
	wire := []byte{byte(TypeMSCHAPv2), OpResponse, 0x2a, 0x00, 0x3a}
	pkt, err := unmarshalInner(wire)
	if err != nil {
		t.Fatalf("unmarshalInner: %v", err)
	}
	if pkt.Type != TypeMSCHAPv2 {
		t.Fatalf("type = %v, want MSCHAPv2", pkt.Type)
	}
	if len(pkt.Data) == 0 || pkt.Data[0] != OpResponse {
		t.Fatalf("data = %x, want it to begin with OpResponse", pkt.Data)
	}
}

func TestInnerRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  Type
		data []byte
	}{
		{"identity", TypeIdentity, nil},
		{"mschapv2", TypeMSCHAPv2, []byte{0x02, 0x2a, 0x00, 0x04}},
		{"gtc", TypeGTC, []byte("secret")},
		{"nak", TypeNak, []byte{byte(TypeMSCHAPv2)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := marshalInner(&Packet{Code: CodeResponse, Identifier: 7, Type: tc.typ, Data: tc.data})
			back, err := unmarshalInner(wire)
			if err != nil {
				t.Fatalf("unmarshalInner: %v", err)
			}
			if back.Type != tc.typ {
				t.Fatalf("type = %v, want %v", back.Type, tc.typ)
			}
			if !bytes.Equal(back.Data, tc.data) && !(len(back.Data) == 0 && len(tc.data) == 0) {
				t.Fatalf("data = %x, want %x", back.Data, tc.data)
			}
		})
	}
}

func TestUnmarshalInnerAcceptsFullHeaderFallback(t *testing.T) {
	// A supplicant that sends a full inner EAP header (Code, Id, Length, Type, Data) is still
	// understood: Code is a valid EAP Code and the Length matches the buffer.
	wire := []byte{CodeResponse, 0x10, 0x00, 0x0e, byte(TypeIdentity), 'C', 'O', 'R', 'P', '\\', 'j', 'd', 'o', 'e'}
	pkt, err := unmarshalInner(wire)
	if err != nil {
		t.Fatalf("unmarshalInner: %v", err)
	}
	if pkt.Type != TypeIdentity {
		t.Fatalf("type = %v, want Identity", pkt.Type)
	}
	if got := string(pkt.Data); got != `CORP\jdoe` {
		t.Fatalf("identity = %q, want %q", got, `CORP\jdoe`)
	}
}
