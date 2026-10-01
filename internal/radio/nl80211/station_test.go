package nl80211

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestControlPortFrameEncoding checks the exact attributes of a CMD_CONTROL_PORT_FRAME send. This
// is the EAPOL transmit path for the certificate harvest on drivers where the data-path packet
// socket does not carry EAPOL; a wrong attribute number, a missing no-encrypt flag, or the payload
// in the wrong attribute all produce a send the kernel silently drops, which is exactly what
// cannot be caught without hardware.
func TestControlPortFrameEncoding(t *testing.T) {
	bssid := []byte{0x9c, 0xef, 0xd5, 0xfd, 0x0f, 0x42}
	eapol := []byte{0x01, 0x01, 0x00, 0x00} // an EAPOL-Start PDU
	ae := controlPortFrameAttrs(9, bssid, eapol)
	attrs := decodeAttrs(t, ae)

	if got := binary.LittleEndian.Uint32(attrs[AttrIfindex]); got != 9 {
		t.Errorf("ifindex = %d, want 9", got)
	}
	if !bytes.Equal(attrs[AttrMAC], bssid) {
		t.Errorf("dst MAC = %x, want the BSSID %x", attrs[AttrMAC], bssid)
	}
	if got := binary.LittleEndian.Uint16(attrs[AttrControlPortEthertype]); got != EtherTypeEAPOL {
		t.Errorf("ethertype = %04x, want EAPOL %04x", got, EtherTypeEAPOL)
	}
	if _, ok := attrs[AttrControlPortNoEncrypt]; !ok {
		t.Error("the no-encrypt flag is missing; pre-key EAPOL would be dropped")
	}
	if !bytes.Equal(attrs[AttrFrame], eapol) {
		t.Errorf("frame payload = %x, want the EAPOL PDU %x", attrs[AttrFrame], eapol)
	}
}

// TestParseControlPortFrame round-trips a notification's attributes back to the ifindex and EAPOL
// payload the receive path pulls out.
func TestParseControlPortFrame(t *testing.T) {
	eapol := []byte{0x02, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}
	ae := controlPortFrameAttrs(12, []byte{1, 2, 3, 4, 5, 6}, eapol)
	data, err := ae.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	ifi, frame := parseControlPortFrame(data)
	if ifi != 12 {
		t.Errorf("ifindex = %d, want 12", ifi)
	}
	if !bytes.Equal(frame, eapol) {
		t.Errorf("frame = %x, want %x", frame, eapol)
	}
}
