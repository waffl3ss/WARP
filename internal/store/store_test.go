package store

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/handshake"
	"github.com/waffl3ss/warp/internal/recon"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "warp.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// TestClosedStoreReturnsErrorNotPanic guards the shutdown crash: the engine's flush loop and the
// store's Close race at shutdown, and a write that lands after Close used to dereference a nil
// *sql.DB and panic (SIGSEGV in persistState → UpsertStation), which invariant 8 forbids. Every
// method must now return ErrClosed instead.
func TestClosedStoreReturnsErrorNotPanic(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "warp.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	ctx := context.Background()
	now := time.Now()

	// Each of these is on the concurrent shutdown path (persistState, flushObservations,
	// exportProjections, emitHash). None may panic; all must report ErrClosed.
	checks := []struct {
		name string
		run  func() error
	}{
		{"UpsertAP", func() error { return s.UpsertAP(ctx, testAP(t, "aa:bb:cc:dd:ee:ff", "X", now)) }},
		{"UpsertStation", func() error {
			return s.UpsertStation(ctx, recon.Station{MAC: mac(t, "11:22:33:44:55:66"), FirstSeen: now, LastSeen: now})
		}},
		{"AddObservations", func() error {
			return s.AddObservations(ctx, []recon.Observation{{Addr: mac(t, "11:22:33:44:55:66"), RadioID: "phy1", Timestamp: now}})
		}},
		{"AddHash", func() error { return s.AddHash(ctx, handshake.Result{Kind: handshake.KindPMKID, Line: "x", At: now}) }},
		{"APs", func() error { _, err := s.APs(ctx, ""); return err }},
		{"Stations", func() error { _, err := s.Stations(ctx); return err }},
		{"ExportCSV", func() error { return s.ExportCSV(ctx, t.TempDir()) }},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if err := c.run(); !errors.Is(err, ErrClosed) {
				t.Fatalf("%s on a closed store returned %v, want ErrClosed", c.name, err)
			}
		})
	}
}

func mac(t *testing.T, s string) recon.MAC {
	t.Helper()
	m, err := recon.ParseMAC(s)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", s, err)
	}
	return m
}

func testAP(t *testing.T, bssid, essid string, seen time.Time) recon.AP {
	t.Helper()
	return recon.AP{
		BSSID: mac(t, bssid), ESSID: essid, Channel: 6, Freq: 2437, Band: "2.4GHz",
		Security: recon.SecurityInfo{
			Class: recon.SecWPAEnterprise, MFP: recon.MFPRequired,
			Ciphers: []string{"CCMP-128"}, AKMs: []string{"802.1X"},
		},
		BestRSSI: -55, LastRSSI: -60, HasRSSI: true, BestRSSIRadio: "phy1",
		FirstSeen: seen, LastSeen: seen, Beacons: 10,
		OUI: bssid[:8], RadiosSeen: []string{"phy1"},
	}
}

// TestWriteNetXML: the netxml projection renders each AP as a wireless-network with its SSID,
// encryption and associated clients, and parses as well-formed XML.
func TestWriteNetXML(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	s.UpsertAP(ctx, testAP(t, "a4:2b:8c:11:22:33", "CORP-WIFI", now))
	s.UpsertStation(ctx, recon.Station{
		MAC: mac(t, "3c:22:fb:aa:bb:cc"), BSSID: mac(t, "a4:2b:8c:11:22:33"),
		FirstSeen: now, LastSeen: now, OUI: "3c:22:fb", Frames: 9,
	})

	path := filepath.Join(t.TempDir(), "networks.netxml")
	if err := s.WriteNetXML(ctx, path); err != nil {
		t.Fatalf("WriteNetXML: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read netxml: %v", err)
	}

	// Well-formed XML, and it carries the network, its name, its encryption and the client.
	var doc struct {
		Networks []struct {
			BSSID string `xml:"BSSID"`
			SSID  struct {
				Essid      string   `xml:"essid"`
				Encryption []string `xml:"encryption"`
			} `xml:"SSID"`
			Clients []struct {
				MAC string `xml:"client-mac"`
			} `xml:"wireless-client"`
		} `xml:"wireless-network"`
	}
	if err := xml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("netxml is not well-formed XML: %v", err)
	}
	if len(doc.Networks) != 1 {
		t.Fatalf("got %d networks, want 1", len(doc.Networks))
	}
	n := doc.Networks[0]
	if n.BSSID != "a4:2b:8c:11:22:33" {
		t.Errorf("BSSID = %q", n.BSSID)
	}
	if n.SSID.Essid != "CORP-WIFI" {
		t.Errorf("essid = %q", n.SSID.Essid)
	}
	if len(n.SSID.Encryption) == 0 || !strings.Contains(strings.Join(n.SSID.Encryption, ","), "WPA+EAP") {
		t.Errorf("encryption tags = %v, want WPA+EAP for an enterprise AP", n.SSID.Encryption)
	}
	if len(n.Clients) != 1 || n.Clients[0].MAC != "3c:22:fb:aa:bb:cc" {
		t.Errorf("associated client missing: %+v", n.Clients)
	}
}

func TestUpsertAndQueryAP(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)

	ap := testAP(t, "a4:2b:8c:11:22:33", "CORP-WIFI", now)
	if err := s.UpsertAP(ctx, ap); err != nil {
		t.Fatalf("UpsertAP: %v", err)
	}

	rows, err := s.APs(ctx, "")
	if err != nil {
		t.Fatalf("APs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	r := rows[0]
	if r.BSSID != "a4:2b:8c:11:22:33" || r.ESSID != "CORP-WIFI" {
		t.Errorf("row = %+v", r)
	}
	if r.SecurityClass != string(recon.SecWPAEnterprise) || r.MFP != "required" {
		t.Errorf("security = %q/%q", r.SecurityClass, r.MFP)
	}
	if r.BestRSSI == nil || *r.BestRSSI != -55 {
		t.Errorf("BestRSSI = %v, want -55", r.BestRSSI)
	}

	// Re-upserting updates rather than duplicating.
	ap.Beacons = 20
	ap.LastSeen = now.Add(time.Minute)
	if err := s.UpsertAP(ctx, ap); err != nil {
		t.Fatalf("second UpsertAP: %v", err)
	}
	rows, _ = s.APs(ctx, "")
	if len(rows) != 1 {
		t.Fatalf("upsert duplicated the row: %d rows", len(rows))
	}
	if rows[0].Beacons != 20 {
		t.Errorf("Beacons = %d, want 20", rows[0].Beacons)
	}
}

// TestESSIDIsNotClearedByALaterHiddenBeacon: an AP whose name was resolved must not lose it
// when a subsequent cloaked beacon arrives.
func TestESSIDIsNotClearedByALaterHiddenBeacon(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	ap := testAP(t, "a4:2b:8c:11:22:33", "HIDDEN-CORP", now)
	ap.ESSIDSource = "probe-resp"
	if err := s.UpsertAP(ctx, ap); err != nil {
		t.Fatalf("UpsertAP: %v", err)
	}

	ap.ESSID = ""
	ap.ESSIDSource = ""
	ap.LastSeen = now.Add(time.Minute)
	if err := s.UpsertAP(ctx, ap); err != nil {
		t.Fatalf("second UpsertAP: %v", err)
	}

	rows, _ := s.APs(ctx, "")
	if rows[0].ESSID != "HIDDEN-CORP" {
		t.Errorf("ESSID = %q; a resolved name was lost to a later cloaked beacon", rows[0].ESSID)
	}
}

// TestMissingRSSIStoresNull: zero would read as the strongest possible signal in any query
// that ranks by RSSI.
func TestMissingRSSIStoresNull(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	ap := testAP(t, "a4:2b:8c:11:22:33", "CORP-WIFI", time.Now().UTC())
	ap.HasRSSI = false
	ap.BestRSSI, ap.LastRSSI = 0, 0
	if err := s.UpsertAP(ctx, ap); err != nil {
		t.Fatalf("UpsertAP: %v", err)
	}

	rows, _ := s.APs(ctx, "")
	if rows[0].BestRSSI != nil {
		t.Errorf("BestRSSI = %v, want NULL when no signal was measured", *rows[0].BestRSSI)
	}
}

// TestObservationRequiresRadioID: an observation whose radio is unknown cannot be safely
// compared with any other, so it is refused rather than stored.
func TestObservationRequiresRadioID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	err := s.AddObservations(ctx, []recon.Observation{{
		Addr: mac(t, "a4:2b:8c:11:22:33"), RSSI: -60, Timestamp: time.Now(), RadioID: "",
	}})
	if err == nil {
		t.Fatal("an observation with no radio_id was accepted")
	}
	if !strings.Contains(err.Error(), "radio_id") {
		t.Errorf("error should name the missing field: %v", err)
	}

	c, _ := s.Counts(ctx)
	if c.Observations != 0 {
		t.Errorf("the rejected batch was partially written: %d observations", c.Observations)
	}
}

func TestHashRecording(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	r := handshake.Result{
		Kind: handshake.KindPMKID, Line: "WPA*01*aa*bb*cc*dd***",
		ESSID: "CORP-WIFI", Channel: 6, RadioID: "phy1", At: time.Now().UTC(),
		InScope: true,
	}
	if err := s.AddHash(ctx, r); err != nil {
		t.Fatalf("AddHash: %v", err)
	}
	// The same line twice must not duplicate.
	if err := s.AddHash(ctx, r); err != nil {
		t.Fatalf("second AddHash: %v", err)
	}

	pmkid, eapol, err := s.HashCounts(ctx)
	if err != nil {
		t.Fatalf("HashCounts: %v", err)
	}
	if pmkid != 1 || eapol != 0 {
		t.Errorf("counts = (%d, %d), want (1, 0)", pmkid, eapol)
	}
}

// ---------------------------------------------------------------------------
// Walkthroughs
// ---------------------------------------------------------------------------

func TestWalkthroughLifecycle(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)

	// The daemon opens an implicit walkthrough at startup so every observation always has
	// one, whether or not an operator ever declares any.
	implicit, err := s.StartWalkthrough(ctx, "unattended", t0, true)
	if err != nil {
		t.Fatalf("StartWalkthrough: %v", err)
	}
	if !implicit.Implicit {
		t.Error("implicit flag not stored")
	}

	cur, err := s.CurrentWalkthrough(ctx)
	if err != nil || cur == nil {
		t.Fatalf("CurrentWalkthrough = %v, %v", cur, err)
	}
	if cur.ID != implicit.ID {
		t.Errorf("current = %d, want %d", cur.ID, implicit.ID)
	}

	// Starting a new one closes the previous.
	floor1, err := s.StartWalkthrough(ctx, "HQ_Floor_1", t0.Add(time.Minute), false)
	if err != nil {
		t.Fatalf("StartWalkthrough: %v", err)
	}

	list, err := s.ListWalkthroughs(ctx)
	if err != nil {
		t.Fatalf("ListWalkthroughs: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("got %d walkthroughs, want 2", len(list))
	}
	if list[0].Open() {
		t.Error("the first walkthrough was not closed when the second started")
	}
	if !list[1].Open() {
		t.Error("the second walkthrough should still be open")
	}

	if _, err := s.EndWalkthrough(ctx, t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("EndWalkthrough: %v", err)
	}
	cur, _ = s.CurrentWalkthrough(ctx)
	if cur != nil {
		t.Errorf("a walkthrough is still open after end: %+v", cur)
	}
	_ = floor1
}

// TestRenameDoesNotTouchObservations is the schema decision the brief is emphatic about: the
// operator will name one sloppily on site, and fixing it must be free.
func TestRenameDoesNotTouchObservations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)

	w, _ := s.StartWalkthrough(ctx, "flor 1 typo", t0, false)

	addr := mac(t, "a4:2b:8c:11:22:33")
	obs := []recon.Observation{
		{Addr: addr, RSSI: -50, Timestamp: t0.Add(time.Second), RadioID: "phy1", FrameType: "beacon"},
		{Addr: addr, RSSI: -55, Timestamp: t0.Add(2 * time.Second), RadioID: "phy1", FrameType: "beacon"},
	}
	if err := s.AddObservations(ctx, obs); err != nil {
		t.Fatalf("AddObservations: %v", err)
	}

	before, _ := s.Counts(ctx)

	if err := s.RenameWalkthrough(ctx, w.ID, "HQ_Floor_1"); err != nil {
		t.Fatalf("RenameWalkthrough: %v", err)
	}

	after, _ := s.Counts(ctx)
	if before.Observations != after.Observations {
		t.Errorf("rename changed the observation count: %d → %d", before.Observations, after.Observations)
	}

	list, _ := s.ListWalkthroughs(ctx)
	if list[0].Name != "HQ_Floor_1" {
		t.Errorf("name = %q", list[0].Name)
	}
	// The observations are still associated, by time range.
	if list[0].Observations != 2 {
		t.Errorf("observations associated = %d, want 2", list[0].Observations)
	}

	if err := s.RenameWalkthrough(ctx, 9999, "nope"); !errors.Is(err, ErrNoWalkthrough) {
		t.Errorf("renaming a missing walkthrough: got %v, want ErrNoWalkthrough", err)
	}
}

// TestWalkthroughCountsAndPcap covers the overview card's data: distinct AP/client counts within
// the walkthrough's time range, the recorded pcap path, and that deleting a walkthrough discards
// the label but never the observations (they belong to the engagement, associated by time range).
func TestWalkthroughCountsAndPcap(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)

	w, err := s.StartWalkthrough(ctx, "HQ Floor 3", t0, false)
	if err != nil {
		t.Fatalf("StartWalkthrough: %v", err)
	}

	// Two distinct APs and one client, each heard twice, all within the walkthrough window.
	ap1, ap2 := mac(t, "a4:2b:8c:00:00:01"), mac(t, "a4:2b:8c:00:00:02")
	cli := mac(t, "3c:22:fb:00:00:aa")
	obs := []recon.Observation{
		{Addr: ap1, IsAP: true, RSSI: -50, Timestamp: t0.Add(1 * time.Second), RadioID: "phy1", FrameType: "beacon"},
		{Addr: ap1, IsAP: true, RSSI: -52, Timestamp: t0.Add(2 * time.Second), RadioID: "phy1", FrameType: "beacon"},
		{Addr: ap2, IsAP: true, RSSI: -60, Timestamp: t0.Add(3 * time.Second), RadioID: "phy1", FrameType: "beacon"},
		{Addr: cli, IsAP: false, RSSI: -55, Timestamp: t0.Add(4 * time.Second), RadioID: "phy1", FrameType: "data"},
		{Addr: cli, IsAP: false, RSSI: -57, Timestamp: t0.Add(5 * time.Second), RadioID: "phy1", FrameType: "data"},
	}
	if err := s.AddObservations(ctx, obs); err != nil {
		t.Fatalf("AddObservations: %v", err)
	}

	if err := s.SetWalkthroughPcap(ctx, w.ID, "/eng/walkthroughs/hq-floor-3-1.pcapng"); err != nil {
		t.Fatalf("SetWalkthroughPcap: %v", err)
	}

	list, err := s.ListWalkthroughs(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListWalkthroughs = %v (len %d), %v", list, len(list), err)
	}
	got := list[0]
	if got.APs != 2 {
		t.Errorf("distinct APs = %d, want 2", got.APs)
	}
	if got.Clients != 1 {
		t.Errorf("distinct clients = %d, want 1", got.Clients)
	}
	if got.Observations != 5 {
		t.Errorf("observations = %d, want 5", got.Observations)
	}
	if got.PcapPath != "/eng/walkthroughs/hq-floor-3-1.pcapng" {
		t.Errorf("pcap path = %q", got.PcapPath)
	}

	// The device roll lists the distinct APs and clients heard in the window.
	devs, err := s.WalkthroughDevices(ctx, w.ID)
	if err != nil {
		t.Fatalf("WalkthroughDevices: %v", err)
	}
	var aps, clients int
	for _, d := range devs {
		if d.IsAP {
			aps++
		} else {
			clients++
		}
	}
	if aps != 2 || clients != 1 {
		t.Errorf("device roll = %d APs, %d clients; want 2, 1 (%+v)", aps, clients, devs)
	}

	// Deleting returns the pcap path (so the caller can remove the file) and keeps observations.
	before, _ := s.Counts(ctx)
	path, err := s.DeleteWalkthrough(ctx, w.ID)
	if err != nil {
		t.Fatalf("DeleteWalkthrough: %v", err)
	}
	if path != "/eng/walkthroughs/hq-floor-3-1.pcapng" {
		t.Errorf("delete returned pcap path %q", path)
	}
	if list, _ := s.ListWalkthroughs(ctx); len(list) != 0 {
		t.Errorf("walkthrough still present after delete: %+v", list)
	}
	after, _ := s.Counts(ctx)
	if before.Observations != after.Observations {
		t.Errorf("delete changed observation count: %d → %d", before.Observations, after.Observations)
	}

	if _, err := s.DeleteWalkthrough(ctx, 9999); !errors.Is(err, ErrNoWalkthrough) {
		t.Errorf("deleting a missing walkthrough: got %v, want ErrNoWalkthrough", err)
	}
}

func TestSplitWalkthrough(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)

	w, _ := s.StartWalkthrough(ctx, "whole floor", t0, false)
	s.EndWalkthrough(ctx, t0.Add(10*time.Minute))

	addr := mac(t, "a4:2b:8c:11:22:33")
	var obs []recon.Observation
	for i := 0; i < 10; i++ {
		obs = append(obs, recon.Observation{
			Addr: addr, RSSI: int8(-40 - i), Timestamp: t0.Add(time.Duration(i) * time.Minute),
			RadioID: "phy1", FrameType: "beacon",
		})
	}
	if err := s.AddObservations(ctx, obs); err != nil {
		t.Fatalf("AddObservations: %v", err)
	}

	before, _ := s.Counts(ctx)

	second, err := s.SplitWalkthrough(ctx, w.ID, t0.Add(5*time.Minute), "east wing")
	if err != nil {
		t.Fatalf("SplitWalkthrough: %v", err)
	}

	after, _ := s.Counts(ctx)
	if before.Observations != after.Observations {
		t.Error("split modified observation data")
	}

	list, _ := s.ListWalkthroughs(ctx)
	if len(list) != 2 {
		t.Fatalf("got %d walkthroughs after split, want 2", len(list))
	}
	// Five observations either side of the split point.
	if list[0].Observations != 5 || list[1].Observations != 5 {
		t.Errorf("observations split %d/%d, want 5/5", list[0].Observations, list[1].Observations)
	}
	if list[1].Name != "east wing" {
		t.Errorf("second half name = %q", list[1].Name)
	}
	_ = second

	// A split point outside the walkthrough is refused rather than silently producing an
	// empty record.
	if _, err := s.SplitWalkthrough(ctx, w.ID, t0.Add(-time.Hour), "x"); err == nil {
		t.Error("a split point before the start was accepted")
	}
}

// TestLocalizeRanksNotTriangulates: the output is a ranked list of places the device was
// heard loudest, which is defensible; a coordinate would not be.
func TestLocalizeRanksNotTriangulates(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)
	addr := mac(t, "a4:2b:8c:11:22:33")

	type step struct {
		name string
		rssi []int8
	}
	steps := []step{
		{"HQ_Floor_1", []int8{-70, -68}},
		{"HQ_Floor_2", []int8{-45, -42}}, // strongest
		{"HQ_Basement", []int8{-80}},
	}

	at := t0
	for _, st := range steps {
		if _, err := s.StartWalkthrough(ctx, st.name, at, false); err != nil {
			t.Fatalf("StartWalkthrough: %v", err)
		}
		var obs []recon.Observation
		for _, r := range st.rssi {
			at = at.Add(time.Second)
			obs = append(obs, recon.Observation{
				Addr: addr, RSSI: r, Timestamp: at, RadioID: "phy1", FrameType: "beacon",
			})
		}
		if err := s.AddObservations(ctx, obs); err != nil {
			t.Fatalf("AddObservations: %v", err)
		}
		at = at.Add(time.Minute)
	}

	ranks, err := s.Localize(ctx, addr.String(), "phy1")
	if err != nil {
		t.Fatalf("Localize: %v", err)
	}
	if len(ranks) != 3 {
		t.Fatalf("got %d ranked locations, want 3", len(ranks))
	}
	if ranks[0].WalkthroughName != "HQ_Floor_2" {
		t.Errorf("strongest location = %q, want HQ_Floor_2", ranks[0].WalkthroughName)
	}
	if ranks[0].MaxRSSI != -42 {
		t.Errorf("max RSSI = %d, want -42", ranks[0].MaxRSSI)
	}
	// Descending by signal strength.
	for i := 1; i < len(ranks); i++ {
		if ranks[i].MaxRSSI > ranks[i-1].MaxRSSI {
			t.Errorf("ranking is not descending: %+v", ranks)
		}
	}
}

// TestLocalizeRequiresARadio: mixing radios produces a ranking that looks correct and means
// nothing, so the filter is mandatory.
func TestLocalizeRequiresARadio(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Localize(context.Background(), "a4:2b:8c:11:22:33", ""); err == nil {
		t.Fatal("localisation without a radio filter was allowed")
	}
}

// TestLocalizeExcludesOtherRadios: an observation from a different adapter must not pollute
// the ranking, however strong it is.
func TestLocalizeExcludesOtherRadios(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Second)
	addr := mac(t, "a4:2b:8c:11:22:33")

	s.StartWalkthrough(ctx, "HQ_Floor_1", t0, false)
	err := s.AddObservations(ctx, []recon.Observation{
		{Addr: addr, RSSI: -70, Timestamp: t0.Add(time.Second), RadioID: "phy1", FrameType: "beacon"},
		// A different adapter with a high-gain antenna reads far hotter. Including it would
		// move the device to the wrong floor.
		{Addr: addr, RSSI: -30, Timestamp: t0.Add(2 * time.Second), RadioID: "phy2", FrameType: "beacon"},
	})
	if err != nil {
		t.Fatalf("AddObservations: %v", err)
	}

	ranks, err := s.Localize(ctx, addr.String(), "phy1")
	if err != nil {
		t.Fatalf("Localize: %v", err)
	}
	if len(ranks) != 1 {
		t.Fatalf("got %d ranks, want 1", len(ranks))
	}
	if ranks[0].MaxRSSI != -70 {
		t.Errorf("max RSSI = %d, want -70 — another radio's reading leaked in", ranks[0].MaxRSSI)
	}
	if ranks[0].Observations != 1 {
		t.Errorf("observations = %d, want 1", ranks[0].Observations)
	}
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// TestFindingsAreSeparateFromObservations is the schema guarantee that lets a report show
// evidence independently of a label.
func TestFindingsAreSeparateFromObservations(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if err := s.UpsertAP(ctx, testAP(t, "a4:2b:8c:11:22:33", "CORP-WIFI", now)); err != nil {
		t.Fatalf("UpsertAP: %v", err)
	}

	score := 0.42
	f := Finding{
		BSSID: "a4:2b:8c:11:22:33", ESSID: "CORP-WIFI",
		Tier:        TierEvidence,
		Label:       "evil twin candidate", // note: candidate, never a confirmed evil twin
		Rationale:   "fingerprint outlier within the CORP-WIFI cluster",
		Differences: []string{"vendor_ies: expected 004096:01, observed none"},
		Score:       &score,
		FirstTS:     now, LastTS: now,
	}
	if err := s.UpsertFinding(ctx, f); err != nil {
		t.Fatalf("UpsertFinding: %v", err)
	}

	got, err := s.Findings(ctx, "")
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Label != "evil twin candidate" {
		t.Errorf("label = %q", got[0].Label)
	}
	if len(got[0].Differences) != 1 {
		t.Errorf("differences lost: %v — the report needs the specific attributes", got[0].Differences)
	}
	if got[0].Score == nil || *got[0].Score != score {
		t.Errorf("score = %v", got[0].Score)
	}

	// Discarding every conclusion must leave the observed record untouched.
	if err := s.ClearFindings(ctx); err != nil {
		t.Fatalf("ClearFindings: %v", err)
	}
	c, _ := s.Counts(ctx)
	if c.Findings != 0 {
		t.Errorf("findings = %d after clear", c.Findings)
	}
	if c.APs != 1 {
		t.Errorf("clearing conclusions destroyed observed data: %d APs remain", c.APs)
	}
}

func TestFindingUpsertRefreshesRatherThanDuplicates(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	f := Finding{
		BSSID: "a4:2b:8c:11:22:33", Tier: TierDetermined, Label: "WPS enabled",
		FirstTS: now, LastTS: now,
	}
	for i := 0; i < 3; i++ {
		f.LastTS = now.Add(time.Duration(i) * time.Hour)
		if err := s.UpsertFinding(ctx, f); err != nil {
			t.Fatalf("UpsertFinding: %v", err)
		}
	}

	got, _ := s.Findings(ctx, "")
	if len(got) != 1 {
		t.Fatalf("re-running classification duplicated findings: %d rows", len(got))
	}
	if !got[0].LastTS.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("LastTS = %v, want the most recent", got[0].LastTS)
	}
}

func TestFindingsOrderedByTier(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for _, f := range []Finding{
		{BSSID: "aa:aa:aa:aa:aa:aa", Tier: TierUnclassified, Label: "unknown device", FirstTS: now, LastTS: now},
		{BSSID: "bb:bb:bb:bb:bb:bb", Tier: TierDetermined, Label: "open network", FirstTS: now, LastTS: now},
		{BSSID: "cc:cc:cc:cc:cc:cc", Tier: TierEvidence, Label: "evil twin candidate", FirstTS: now, LastTS: now},
	} {
		if err := s.UpsertFinding(ctx, f); err != nil {
			t.Fatalf("UpsertFinding: %v", err)
		}
	}

	got, _ := s.Findings(ctx, "")
	want := []Tier{TierDetermined, TierEvidence, TierUnclassified}
	for i, w := range want {
		if got[i].Tier != w {
			t.Errorf("finding %d tier = %q, want %q", i, got[i].Tier, w)
		}
	}

	// Filtering works.
	determined, _ := s.Findings(ctx, TierDetermined)
	if len(determined) != 1 || determined[0].Tier != TierDetermined {
		t.Errorf("tier filter returned %+v", determined)
	}
}

// ---------------------------------------------------------------------------
// CSV projections
// ---------------------------------------------------------------------------

func TestExportCSV(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)

	s.UpsertAP(ctx, testAP(t, "a4:2b:8c:11:22:33", "CORP-WIFI", now))
	s.UpsertStation(ctx, recon.Station{
		MAC: mac(t, "de:ad:be:ef:00:01"), BSSID: mac(t, "a4:2b:8c:11:22:33"),
		FirstSeen: now, LastSeen: now, BestRSSI: -62, HasRSSI: true,
		Randomised: true, OUI: "de:ad:be", Frames: 5,
		ProbedESSIDs: []string{"HOME", "CORP-WIFI"},
	})
	s.StartWalkthrough(ctx, "HQ_Floor_1", now, false)
	s.AddObservations(ctx, []recon.Observation{
		{Addr: mac(t, "a4:2b:8c:11:22:33"), IsAP: true, RSSI: -55,
			Freq: 2437, Channel: 6, Timestamp: now.Add(time.Second), RadioID: "phy1", FrameType: "beacon"},
	})
	s.UpsertFinding(ctx, Finding{
		BSSID: "a4:2b:8c:11:22:33", Tier: TierDetermined, Label: "MFP required",
		FirstTS: now, LastTS: now,
	})
	// A rogue-class finding, so rogues.csv has content and the findings/rogues split is exercised:
	// rogues.csv must carry this one and not the posture finding above.
	s.UpsertFinding(ctx, Finding{
		BSSID: "de:ad:be:ef:00:01", ESSID: "ACME-CORP", Tier: TierEvidence,
		Label: "evil twin candidate", FirstTS: now, LastTS: now,
	})

	if err := s.ExportCSV(ctx, dir); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	// rogues.csv is the rogue subset: the evil-twin candidate, not the MFP posture finding.
	rf, err := os.Open(filepath.Join(dir, RoguesCSV))
	if err != nil {
		t.Fatalf("open rogues.csv: %v", err)
	}
	rogueRows, err := csv.NewReader(rf).ReadAll()
	rf.Close()
	if err != nil {
		t.Fatalf("read rogues.csv: %v", err)
	}
	if len(rogueRows) != 2 { // header + the one rogue
		t.Errorf("rogues.csv has %d rows, want header + the single rogue finding", len(rogueRows))
	}
	for _, row := range rogueRows[1:] {
		if row[3] == "MFP required" {
			t.Errorf("rogues.csv leaked a posture finding: %v", row)
		}
	}
	// observations.csv is appended live by ObservationLog during an engagement and is not part
	// of the wholesale rebuild; this is the after-the-fact reconstruction path.
	if err := s.ExportObservationsCSV(ctx, dir); err != nil {
		t.Fatalf("ExportObservationsCSV: %v", err)
	}

	for _, name := range []string{APsCSV, StationsCSV, ObservationsCSV, WalkthroughsCSV, FindingsCSV, RoguesCSV} {
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			t.Errorf("open %s: %v", name, err)
			continue
		}
		records, err := csv.NewReader(f).ReadAll()
		f.Close()
		if err != nil {
			t.Errorf("%s is not valid CSV: %v", name, err)
			continue
		}
		if len(records) < 2 {
			t.Errorf("%s has no data rows: %v", name, records)
		}

		fi, _ := os.Stat(path)
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s mode is %04o; group/other access must be denied", name, perm)
		}
	}

	// No temporary files left behind: the export writes to a temp path and renames.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".warp-csv-") {
			t.Errorf("temporary export file left behind: %s", e.Name())
		}
	}
}

// TestFindingsInScopeCSV: the scope-filtered projection carries only findings on a scoped ESSID,
// while findings.csv carries every finding. A finding with no ESSID is out of scope by definition.
func TestFindingsInScopeCSV(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)

	// Only CORP-WIFI is in scope.
	s.SetScopeFilter(func(essid string) bool { return essid == "CORP-WIFI" })

	s.UpsertFinding(ctx, Finding{
		BSSID: "a4:2b:8c:11:22:33", ESSID: "CORP-WIFI", Tier: TierDetermined,
		Label: "WPS enabled and unlocked", FirstTS: now, LastTS: now,
	})
	s.UpsertFinding(ctx, Finding{
		BSSID: "de:ad:be:ef:00:02", ESSID: "NEIGHBOUR-NET", Tier: TierDetermined,
		Label: "WEP encryption", FirstTS: now, LastTS: now,
	})
	s.UpsertFinding(ctx, Finding{ // no ESSID: out of scope here
		BSSID: "de:ad:be:ef:00:03", Tier: TierDetermined,
		Label: "karma responder", FirstTS: now, LastTS: now,
	})

	if err := s.ExportCSV(ctx, dir); err != nil {
		t.Fatalf("ExportCSV: %v", err)
	}

	readLabels := func(name string) []string {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		defer f.Close()
		rows, err := csv.NewReader(f).ReadAll()
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		var labels []string
		for _, r := range rows[1:] {
			labels = append(labels, r[3])
		}
		return labels
	}

	if all := readLabels(FindingsCSV); len(all) != 3 {
		t.Errorf("findings.csv has %d findings, want all 3: %v", len(all), all)
	}
	inScope := readLabels(FindingsInScopeCSV)
	if len(inScope) != 1 || inScope[0] != "WPS enabled and unlocked" {
		t.Errorf("findings-in-scope.csv = %v, want only the CORP-WIFI finding", inScope)
	}
}

// TestClearFindingForBSSID: an attack supersedes a preliminary note on one device without touching
// findings on other devices or other labels on the same device.
func TestClearFindingForBSSID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	s.UpsertFinding(ctx, Finding{BSSID: "aa:aa:aa:aa:aa:aa", ESSID: "CORP-WIFI",
		Tier: TierDetermined, Label: "WPS enabled and unlocked", FirstTS: now, LastTS: now})
	s.UpsertFinding(ctx, Finding{BSSID: "aa:aa:aa:aa:aa:aa", ESSID: "CORP-WIFI",
		Tier: TierDetermined, Label: "WEP encryption", FirstTS: now, LastTS: now})
	s.UpsertFinding(ctx, Finding{BSSID: "bb:bb:bb:bb:bb:bb", ESSID: "OTHER",
		Tier: TierDetermined, Label: "WPS enabled and unlocked", FirstTS: now, LastTS: now})

	if err := s.ClearFindingForBSSID(ctx, "aa:aa:aa:aa:aa:aa", "WPS enabled and unlocked"); err != nil {
		t.Fatalf("ClearFindingForBSSID: %v", err)
	}

	got, _ := s.Findings(ctx, "")
	var haveA, haveAWEP, haveB bool
	for _, f := range got {
		switch {
		case f.BSSID == "aa:aa:aa:aa:aa:aa" && f.Label == "WPS enabled and unlocked":
			haveA = true
		case f.BSSID == "aa:aa:aa:aa:aa:aa" && f.Label == "WEP encryption":
			haveAWEP = true
		case f.BSSID == "bb:bb:bb:bb:bb:bb" && f.Label == "WPS enabled and unlocked":
			haveB = true
		}
	}
	if haveA {
		t.Error("the superseded finding survived on the tested device")
	}
	if !haveAWEP {
		t.Error("clearing one label removed an unrelated finding on the same device")
	}
	if !haveB {
		t.Error("clearing a label on one device removed it from another")
	}
}

// TestExportCSVIsIdempotent: regenerating wholesale is what makes concurrent-append
// corruption impossible.
func TestExportCSVIsIdempotent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Now().UTC()

	s.UpsertAP(ctx, testAP(t, "a4:2b:8c:11:22:33", "CORP-WIFI", now))

	var first []byte
	for i := 0; i < 3; i++ {
		if err := s.ExportCSV(ctx, dir); err != nil {
			t.Fatalf("ExportCSV: %v", err)
		}
		data, _ := os.ReadFile(filepath.Join(dir, APsCSV))
		if i == 0 {
			first = data
			continue
		}
		if string(data) != string(first) {
			t.Fatalf("export %d differs from the first; projections must be regenerated, not appended", i)
		}
	}
}

// TestIncidentalCapturesAreRecordedButNotCounted.
//
// Passive capture is never scope-gated, so the store holds handshakes from networks the
// engagement has no authority over. They must be retrievable — they are evidence, and an
// engagement report may need to say they were heard — without inflating the counters that
// describe what the engagement produced.
func TestIncidentalCapturesAreRecordedButNotCounted(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	scoped := handshake.Result{
		Kind: handshake.KindPMKID, Line: "WPA*01*11*aa*bb*434f5250***",
		ESSID: "CORP-WIFI", At: time.Now().UTC(), InScope: true,
	}
	incidental := handshake.Result{
		Kind: handshake.KindHandshake, Line: "WPA*02*22*cc*dd*4e454947***",
		ESSID: "NEIGHBOUR-NET", At: time.Now().UTC(), InScope: false,
	}
	for _, r := range []handshake.Result{scoped, incidental} {
		if err := s.AddHash(ctx, r); err != nil {
			t.Fatalf("AddHash: %v", err)
		}
	}

	hashes, err := s.Hashes(ctx)
	if err != nil {
		t.Fatalf("Hashes: %v", err)
	}
	if len(hashes) != 2 {
		t.Fatalf("got %d hashes, want 2 — an incidental capture was discarded", len(hashes))
	}

	byESSID := map[string]bool{}
	for _, h := range hashes {
		byESSID[h.ESSID] = h.InScope
	}
	if !byESSID["CORP-WIFI"] {
		t.Error("the in-scope capture came back labelled incidental")
	}
	if byESSID["NEIGHBOUR-NET"] {
		t.Error("the incidental capture came back labelled in scope")
	}

	// Counts describe the deliverable.
	p, e, err := s.HashCounts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p != 1 || e != 0 {
		t.Errorf("HashCounts = (%d, %d), want (1, 0) — incidental material inflated the totals", p, e)
	}
}

// TestOpeningAnOlderEngagementDatabaseStillWorks.
//
// An engagement directory runs for days and is evidence. Updating the binary mid-engagement
// must not require a fresh workspace, so a column added after the fact has to be applied by
// migration rather than by CREATE TABLE IF NOT EXISTS, which does nothing to a table that
// already exists.
func TestOpeningAnOlderEngagementDatabaseStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "warp.db")

	// Build the hashes table as an earlier version wrote it: no in_scope column.
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`
CREATE TABLE hashes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL, line TEXT NOT NULL UNIQUE, essid TEXT NOT NULL,
    ap TEXT NOT NULL, sta TEXT NOT NULL, channel INTEGER NOT NULL DEFAULT 0,
    radio_id TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '', ts TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`
INSERT INTO hashes (kind, line, essid, ap, sta, ts)
VALUES ('pmkid', 'WPA*01*old*aa*bb*cc***', 'CORP-WIFI', 'aa:bb:cc:dd:ee:ff', '', ?)`,
		time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on an older database: %v", err)
	}
	defer s.Close()

	hashes, err := s.Hashes(context.Background())
	if err != nil {
		t.Fatalf("Hashes after migration: %v", err)
	}
	if len(hashes) != 1 {
		t.Fatalf("got %d hashes, want 1 — existing evidence was lost", len(hashes))
	}
	// Rows captured before the column existed default to in-scope: they were written when
	// only scoped material was recorded at all.
	if !hashes[0].InScope {
		t.Error("a pre-existing hash was relabelled as incidental by the migration")
	}
}

// TestClearFindingsWithLabelsPreservesOthers covers the re-classify path: clearing the classifier's
// own labels must leave attack-recorded findings (a recovered WPS passphrase) in place.
func TestClearFindingsWithLabelsPreservesOthers(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	classifier := Finding{BSSID: "aa:bb:cc:00:00:01", ESSID: "CORP", Tier: TierDetermined,
		Label: "WPS enabled and unlocked", Rationale: "from the beacon"}
	attack := Finding{BSSID: "aa:bb:cc:00:00:01", ESSID: "CORP", Tier: TierDetermined,
		Label: "WPS PIN recovered offline (Pixie Dust)", Rationale: "recovered"}
	for _, f := range []Finding{classifier, attack} {
		if err := s.UpsertFinding(ctx, f); err != nil {
			t.Fatalf("UpsertFinding: %v", err)
		}
	}

	if err := s.ClearFindingsWithLabels(ctx, []string{"WPS enabled and unlocked"}); err != nil {
		t.Fatalf("ClearFindingsWithLabels: %v", err)
	}

	got, err := s.FindingsFor(ctx, "aa:bb:cc:00:00:01")
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(got) != 1 || got[0].Label != "WPS PIN recovered offline (Pixie Dust)" {
		t.Fatalf("re-classify did not preserve the attack finding: %+v", got)
	}
}
