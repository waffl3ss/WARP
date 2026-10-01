package daemon

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/radio"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/store"
)

// TestSolicitedPMKIDReachesTheDeliverable proves the daemon glue the over-the-air PMKID
// solicitation depends on. The association that reads message 1 off the control port needs radios
// and is validated on hardware; everything from the received M1 onward is exercised here with the
// real handshake machine, the real 22000 writer and the real store, so a solicited PMKID and a
// passively-overheard one travel identical code and both land a crackable line in pmkid.22000.
//
// This is the piece that was only ever asserted before: that when an access point *does* put a
// PMKID in M1, WARP writes the deliverable. (Whether a given AP volunteers one is the AP's choice —
// modern hostapd sends a bare M1 — which is why this is proved against a constructed M1 rather than
// against whatever AP happens to be in range.)
func TestSolicitedPMKIDReachesTheDeliverable(t *testing.T) {
	dir := t.TempDir()

	db, err := store.Open(filepath.Join(dir, "warp.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	hashes, err := handshake.NewWriter(dir, "pmkid.22000", "handshakes.22000")
	if err != nil {
		t.Fatalf("handshake.NewWriter: %v", err)
	}

	const essid = "CORP-IOT"
	sched, err := radio.NewScheduler([]*radio.Device{
		fakeDevice("phy0", 0, []nl80211.Iftype{nl80211.IftypeStation, nl80211.IftypeMonitor}, radio.InjectionVerified),
	}, quietLogger())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	eng, err := NewEngine(EngineOptions{
		Scheduler:    sched,
		Acquirer:     &stubAcquirer{},
		Store:        db,
		Hashes:       hashes,
		Log:          quietLogger(),
		InScope:      func(name string) bool { return name == essid },
		WorkspaceDir: dir,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	bssid := recon.MAC{0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	sta := recon.MAC{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}

	// Seed the tracker with a beacon so the machine can resolve the BSSID's ESSID — without a name
	// the PMKID is held pending, exactly as in the live engine.
	beacon, err := recon.ParseFrame(buildBeaconFrame(bssid, essid))
	if err != nil {
		t.Fatalf("ParseFrame(beacon): %v", err)
	}
	eng.Tracker().Observe(beacon, recon.RadiotapMeta{Channel: 6, Freq: 2437, RSSI: -40, HasRSSI: true}, "phy0", time.Now())
	if ap, ok := eng.Tracker().AP(bssid); !ok || ap.ESSID != essid {
		t.Fatalf("tracker did not learn the AP: ok=%v essid=%q", ok, ap.ESSID)
	}

	// The frame the solicitation reads off the control port: M1 carrying a PMKID KDE.
	pmkid := make([]byte, 16)
	for i := range pmkid {
		pmkid[i] = 0xA0 + byte(i)
	}
	results := eng.SubmitEAPOLKey(bssid, sta, buildM1WithPMKID(pmkid), 6, "phy0", time.Now())

	// 1. The pipeline emitted a PMKID result.
	var got *handshake.Result
	for i := range results {
		if results[i].Kind == handshake.KindPMKID {
			got = &results[i]
		}
	}
	if got == nil {
		t.Fatalf("SubmitEAPOLKey emitted no PMKID (results=%d)", len(results))
	}
	if got.ESSID != essid {
		t.Errorf("PMKID ESSID = %q, want %q", got.ESSID, essid)
	}

	// 2. The deliverable file holds a crackable 22000 line for this PMKID/BSSID/STA/ESSID.
	line := readOneLine(t, filepath.Join(dir, "pmkid.22000"))
	fields := strings.Split(line, "*")
	if len(fields) < 6 || fields[0] != "WPA" || fields[1] != "01" {
		t.Fatalf("pmkid.22000 line is not a PMKID hash line: %q", line)
	}
	if !strings.EqualFold(fields[2], hex.EncodeToString(pmkid)) {
		t.Errorf("hash line PMKID = %s, want %s", fields[2], hex.EncodeToString(pmkid))
	}
	if !strings.EqualFold(fields[3], hex.EncodeToString(bssid[:])) {
		t.Errorf("hash line AP MAC = %s, want %s", fields[3], hex.EncodeToString(bssid[:]))
	}
	if !strings.EqualFold(fields[5], hex.EncodeToString([]byte(essid))) {
		t.Errorf("hash line ESSID = %s, want %s (hex of %q)", fields[5], hex.EncodeToString([]byte(essid)), essid)
	}

	// 3. The store recorded it, in scope, as a PMKID.
	pmkidCount, _, err := db.HashCounts(context.Background())
	if err != nil {
		t.Fatalf("HashCounts: %v", err)
	}
	if pmkidCount != 1 {
		t.Errorf("store PMKID count = %d, want 1", pmkidCount)
	}
}

func readOneLine(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	line := strings.TrimSpace(string(b))
	if line == "" {
		t.Fatalf("%s is empty — no hash was written", path)
	}
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return line
}

// buildBeaconFrame assembles a minimal 802.11 beacon advertising essid, enough for the tracker to
// learn the BSSID→ESSID mapping.
func buildBeaconFrame(bssid recon.MAC, essid string) []byte {
	f := []byte{0x80, 0x00, 0x00, 0x00} // beacon, no flags, duration 0
	f = append(f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	f = append(f, bssid[:]...) // transmitter
	f = append(f, bssid[:]...) // BSSID
	f = append(f, 0x00, 0x00)  // sequence
	f = append(f, make([]byte, 8)...)
	f = binary.LittleEndian.AppendUint16(f, 100)    // beacon interval
	f = binary.LittleEndian.AppendUint16(f, 0x0011) // capability: ESS + Privacy
	f = append(f, 0x00, byte(len(essid)))           // SSID element
	f = append(f, []byte(essid)...)
	f = append(f, 0x01, 0x02, 0x82, 0x84) // supported rates, so the frame is well-formed
	return f
}

// buildM1WithPMKID assembles message 1 of a WPA2 four-way handshake carrying a PMKID KDE — the
// frame an access point that caches a PMKID puts on the air, and what the solicitation reads off
// the control port. Standard EAPOL-Key layout; key data begins at offset 99.
func buildM1WithPMKID(pmkid []byte) []byte {
	kde := append([]byte{0xDD, byte(4 + len(pmkid)), 0x00, 0x0F, 0xAC, 0x04}, pmkid...)

	const keyDataOffset = 99
	b := make([]byte, keyDataOffset+len(kde))
	b[0] = 2 // 802.1X version
	b[1] = 3 // 802.1X type: EAPOL-Key
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)-4))
	b[4] = 2                                  // descriptor: RSN
	binary.BigEndian.PutUint16(b[5:], 0x008A) // key info: pairwise | ACK | version 2
	binary.BigEndian.PutUint16(b[7:], 16)     // key length
	binary.BigEndian.PutUint64(b[9:], 1)      // replay counter
	for i := 17; i < 49; i++ {                // ANonce (non-zero)
		b[i] = 0x22
	}
	binary.BigEndian.PutUint16(b[97:], uint16(len(kde))) // key data length
	copy(b[keyDataOffset:], kde)
	return b
}
