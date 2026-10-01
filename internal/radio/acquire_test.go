package radio

import "testing"

// TestRandomStationMACIsLocallyAdministeredUnicast.
//
// The address the active-monitor interface wears has to be one a real client could not own and
// that no access point will treat as a group address:
//
//   - locally administered (bit 1 of the first octet set) — cannot collide with a real
//     manufacturer OUI, so it will never be mistaken for an actual device on the network.
//   - unicast (bit 0 of the first octet clear) — a multicast source address is malformed and
//     an access point may drop the frame, which would break the very ACK behaviour this MAC
//     exists to enable.
func TestRandomStationMACIsLocallyAdministeredUnicast(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 256; i++ {
		mac, err := randomStationMAC()
		if err != nil {
			t.Fatalf("randomStationMAC: %v", err)
		}
		if len(mac) != 6 {
			t.Fatalf("MAC is %d octets, want 6", len(mac))
		}
		if mac[0]&0x02 == 0 {
			t.Errorf("%s is not locally administered (bit 1 of the first octet must be set)", mac)
		}
		if mac[0]&0x01 != 0 {
			t.Errorf("%s is multicast (bit 0 of the first octet must be clear)", mac)
		}
		seen[mac.String()] = true
	}
	// Not a randomness test, just a sanity check that it is not returning a constant.
	if len(seen) < 200 {
		t.Errorf("only %d distinct MACs in 256 draws; generation looks stuck", len(seen))
	}
}
