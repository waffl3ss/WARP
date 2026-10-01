package recon

import (
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

func observe(t *testing.T, tr *Tracker, raw []byte, meta RadiotapMeta, radioID string, at time.Time) []Event {
	t.Helper()
	f, err := ParseFrame(raw)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	return tr.Observe(f, meta, radioID, at)
}

func TestTrackerRecordsAP(t *testing.T) {
	tr := NewTracker(nil)
	bssid := mac("a4:2b:8c:11:22:33")
	now := time.Now()

	raw := buildBeacon(beaconOpts{
		bssid:      bssid,
		capability: CapESS | CapPrivacy,
		ies: [][]byte{
			ssidIE("CORP-WIFI"), ratesIE(0x82, 0x84), dsIE(6),
			rsnIE(CipherCCMP128, []uint8{CipherCCMP128}, []uint8{AKM8021X}, rsnCapMFPR|rsnCapMFPC, true),
		},
	})

	events := observe(t, tr, raw, rssi(-55, 6), "phy1", now)
	if len(events) != 1 || events[0].Kind != EventNewAP {
		t.Fatalf("expected one new_ap event, got %+v", events)
	}

	ap, ok := tr.AP(bssid)
	if !ok {
		t.Fatal("AP not recorded")
	}
	if ap.ESSID != "CORP-WIFI" {
		t.Errorf("ESSID = %q", ap.ESSID)
	}
	if ap.Channel != 6 {
		t.Errorf("Channel = %d, want 6", ap.Channel)
	}
	if ap.Security.Class != SecWPAEnterprise {
		t.Errorf("Security = %q, want enterprise", ap.Security.Class)
	}
	if ap.Security.MFP != MFPRequired {
		t.Errorf("MFP = %s, want required", ap.Security.MFP)
	}
	if ap.BestRSSI != -55 || ap.BestRSSIRadio != "phy1" {
		t.Errorf("BestRSSI = %d on %q, want -55 on phy1", ap.BestRSSI, ap.BestRSSIRadio)
	}
	if ap.Beacons != 1 {
		t.Errorf("Beacons = %d, want 1", ap.Beacons)
	}

	// A second beacon is not a new AP.
	events = observe(t, tr, raw, rssi(-60, 6), "phy1", now.Add(time.Second))
	if len(events) != 0 {
		t.Errorf("re-observing an AP produced events: %+v", events)
	}
	ap, _ = tr.AP(bssid)
	if ap.BestRSSI != -55 {
		t.Errorf("BestRSSI regressed to %d; it should keep the strongest reading", ap.BestRSSI)
	}
	if ap.LastRSSI != -60 {
		t.Errorf("LastRSSI = %d, want -60", ap.LastRSSI)
	}
}

// TestMissingRSSIIsNotRecordedAsZero: a driver reporting no signal must not produce 0 dBm,
// which would read as the strongest possible signal and dominate the localisation ranking.
func TestMissingRSSIIsNotRecordedAsZero(t *testing.T) {
	tr := NewTracker(nil)
	bssid := mac("a4:2b:8c:11:22:33")
	now := time.Now()

	raw := buildBeacon(beaconOpts{bssid: bssid, ies: [][]byte{ssidIE("N"), dsIE(6)}})

	observe(t, tr, raw, rssi(-70, 6), "phy1", now)
	observe(t, tr, raw, noRSSI(6), "phy1", now.Add(time.Second))

	ap, _ := tr.AP(bssid)
	if !ap.HasRSSI {
		t.Fatal("HasRSSI cleared by a reading with no signal")
	}
	if ap.BestRSSI != -70 {
		t.Errorf("BestRSSI = %d, want -70; a missing signal was recorded as 0 dBm", ap.BestRSSI)
	}
	if ap.LastRSSI != -70 {
		t.Errorf("LastRSSI = %d, want -70", ap.LastRSSI)
	}
}

// TestHiddenSSIDResolvedByProbeResponse: a cloaked network stays passive-only until its name
// is learned, then becomes eligible for scope matching.
func TestHiddenSSIDResolvedByProbeResponse(t *testing.T) {
	tr := NewTracker(nil)
	bssid := mac("a4:2b:8c:11:22:33")
	sta := mac("de:ad:be:ef:00:01")
	now := time.Now()

	// A cloaked beacon.
	observe(t, tr, buildBeacon(beaconOpts{
		bssid: bssid,
		ies:   [][]byte{hiddenSSIDIE(9), ratesIE(0x82), dsIE(6)},
	}), rssi(-50, 6), "phy1", now)

	ap, _ := tr.AP(bssid)
	if !ap.Hidden {
		t.Fatal("cloaked SSID not marked hidden")
	}
	if ap.ESSID != "" {
		t.Fatalf("ESSID = %q, want empty for a cloaked network", ap.ESSID)
	}

	// A probe response reveals the name.
	events := observe(t, tr, buildProbeResp(bssid, sta, "HIDDEN-CORP", dsIE(6)),
		rssi(-52, 6), "phy1", now.Add(time.Second))

	var revealed bool
	for _, e := range events {
		if e.Kind == EventESSIDRevealed && e.ESSID == "HIDDEN-CORP" {
			revealed = true
		}
	}
	if !revealed {
		t.Fatalf("no essid_revealed event: %+v", events)
	}

	ap, _ = tr.AP(bssid)
	if ap.ESSID != "HIDDEN-CORP" || ap.Hidden {
		t.Errorf("ESSID = %q hidden=%v, want HIDDEN-CORP and not hidden", ap.ESSID, ap.Hidden)
	}
	if ap.ESSIDSource == "" {
		t.Error("ESSIDSource not recorded; the report needs to say how the name was learned")
	}
	// The name is now known, but the network is still one that was not advertising itself.
	// Losing that would turn a decloaking into an ordinary observation.
	if !ap.Cloaked {
		t.Error("Cloaked was cleared when the name was recovered; the decloaking is no longer visible")
	}
}

// TestAnOrdinaryNetworkIsNotMarkedCloaked. The decloaked flag is only worth showing if it
// means something, so it must not latch on a network that beacons its name normally.
func TestAnOrdinaryNetworkIsNotMarkedCloaked(t *testing.T) {
	tr := NewTracker(nil)
	bssid := mac("a4:2b:8c:11:22:44")
	now := time.Now()

	observe(t, tr, buildBeacon(beaconOpts{
		bssid: bssid,
		ies:   [][]byte{ssidIE("CORP-WIFI"), ratesIE(0x82), dsIE(6)},
	}), rssi(-50, 6), "phy1", now)

	ap, _ := tr.AP(bssid)
	if ap.Cloaked {
		t.Error("a network that beacons its own name was marked cloaked")
	}
	if ap.Hidden {
		t.Error("a network that beacons its own name was marked hidden")
	}
}

func TestHiddenSSIDResolvedByAssociationRequest(t *testing.T) {
	tr := NewTracker(nil)
	bssid := mac("a4:2b:8c:11:22:33")
	sta := mac("de:ad:be:ef:00:01")
	now := time.Now()

	observe(t, tr, buildBeacon(beaconOpts{
		bssid: bssid, ies: [][]byte{hiddenSSIDIE(4), dsIE(6)},
	}), rssi(-50, 6), "phy1", now)

	observe(t, tr, buildAssocReq(bssid, sta, "HIDDEN-CORP"), rssi(-58, 6), "phy1", now.Add(time.Second))

	ap, _ := tr.AP(bssid)
	if ap.ESSID != "HIDDEN-CORP" {
		t.Errorf("ESSID = %q, want HIDDEN-CORP", ap.ESSID)
	}

	st, ok := tr.Station(sta)
	if !ok {
		t.Fatal("station not recorded")
	}
	if st.BSSID != bssid {
		t.Errorf("station BSSID = %v, want %v", st.BSSID, bssid)
	}
}

// TestProbeRequestsRecordDeviceHistory: the ESSIDs a device asks for leak where it has been
// and are directly useful for targeting.
func TestProbeRequestsRecordDeviceHistory(t *testing.T) {
	tr := NewTracker(nil)
	sta := mac("da:a1:19:00:11:22") // randomised address
	now := time.Now()

	for i, essid := range []string{"HOME-NET", "CORP-WIFI", "Starbucks", "CORP-WIFI"} {
		observe(t, tr, buildProbeReq(sta, essid), rssi(-65, 6), "phy1",
			now.Add(time.Duration(i)*time.Second))
	}

	st, ok := tr.Station(sta)
	if !ok {
		t.Fatal("station not recorded")
	}
	if len(st.ProbedESSIDs) != 3 {
		t.Errorf("ProbedESSIDs = %v, want 3 unique entries", st.ProbedESSIDs)
	}
	if !st.Randomised {
		t.Error("locally administered address not flagged as randomised")
	}
	if st.Frames != 4 {
		t.Errorf("Frames = %d, want 4", st.Frames)
	}
}

func TestObservationsAreEmittedWithRadioID(t *testing.T) {
	var got []Observation
	tr := NewTracker(func(o Observation) { got = append(got, o) })

	bssid := mac("a4:2b:8c:11:22:33")
	now := time.Now()
	observe(t, tr, buildBeacon(beaconOpts{
		bssid: bssid, ies: [][]byte{ssidIE("CORP-WIFI"), dsIE(6)},
	}), rssi(-55, 6), "phy1", now)

	if len(got) != 1 {
		t.Fatalf("got %d observations, want 1", len(got))
	}
	o := got[0]
	if o.Addr != bssid || !o.IsAP {
		t.Errorf("observation addr = %v isAP=%v", o.Addr, o.IsAP)
	}
	if o.RadioID != "phy1" {
		t.Errorf("RadioID = %q; RSSI is meaningless without knowing which radio heard it", o.RadioID)
	}
	if o.RSSI != -55 || o.Channel != 6 {
		t.Errorf("observation = %+v", o)
	}
	if o.FrameType != "beacon" {
		t.Errorf("FrameType = %q, want beacon", o.FrameType)
	}
}

func TestNoObservationWithoutSignal(t *testing.T) {
	var got []Observation
	tr := NewTracker(func(o Observation) { got = append(got, o) })

	observe(t, tr, buildBeacon(beaconOpts{
		bssid: mac("a4:2b:8c:11:22:33"), ies: [][]byte{ssidIE("N"), dsIE(6)},
	}), noRSSI(6), "phy1", time.Now())

	if len(got) != 0 {
		t.Errorf("emitted %d observations with no signal reading: %+v", len(got), got)
	}
}

// TestFirstSeenLastSeen is what a multi-day unattended run surfaces that a walk cannot:
// devices that only appear at 0200.
func TestFirstSeenLastSeen(t *testing.T) {
	tr := NewTracker(nil)
	bssid := mac("a4:2b:8c:11:22:33")
	start := time.Date(2026, 3, 1, 2, 0, 0, 0, time.UTC)

	raw := buildBeacon(beaconOpts{bssid: bssid, ies: [][]byte{ssidIE("CONTRACTOR-HOTSPOT"), dsIE(6)}})
	observe(t, tr, raw, rssi(-70, 6), "phy1", start)
	observe(t, tr, raw, rssi(-68, 6), "phy1", start.Add(3*time.Hour))

	ap, _ := tr.AP(bssid)
	if !ap.FirstSeen.Equal(start) {
		t.Errorf("FirstSeen = %v, want %v", ap.FirstSeen, start)
	}
	if !ap.LastSeen.Equal(start.Add(3 * time.Hour)) {
		t.Errorf("LastSeen = %v", ap.LastSeen)
	}
}

// TestNothingIsFilteredOut: every observed device is recorded, including obvious neighbours.
// The default state is unclassified, not "neighbour", and that call is not the tracker's.
func TestNothingIsFilteredOut(t *testing.T) {
	tr := NewTracker(nil)
	now := time.Now()

	for _, spec := range []struct {
		bssid string
		essid string
	}{
		{"a4:2b:8c:11:22:33", "CORP-WIFI"},
		{"de:ad:be:ef:00:01", "NEIGHBOUR-COFFEE"},
		{"11:22:33:44:55:66", "SomeoneElsesPrinter"},
	} {
		observe(t, tr, buildBeacon(beaconOpts{
			bssid: mac(spec.bssid), ies: [][]byte{ssidIE(spec.essid), dsIE(6)},
		}), rssi(-70, 6), "phy1", now)
	}

	aps, stations := tr.Counts()
	if aps != 3 {
		t.Errorf("tracked %d APs, want 3 — nothing may be filtered out", aps)
	}
	if stations != 0 {
		t.Errorf("tracked %d stations, want 0", stations)
	}
}

func TestAPsForESSIDGroupsThePopulation(t *testing.T) {
	tr := NewTracker(nil)
	now := time.Now()

	for _, b := range []string{"a4:2b:8c:11:22:33", "a4:2b:8c:11:22:44", "a4:2b:8c:11:22:55"} {
		observe(t, tr, buildBeacon(beaconOpts{
			bssid: mac(b), ies: [][]byte{ssidIE("CORP-WIFI"), dsIE(6)},
		}), rssi(-60, 6), "phy1", now)
	}
	observe(t, tr, buildBeacon(beaconOpts{
		bssid: mac("de:ad:be:ef:00:01"), ies: [][]byte{ssidIE("OTHER"), dsIE(6)},
	}), rssi(-60, 6), "phy1", now)

	group := tr.APsForESSID("CORP-WIFI")
	if len(group) != 3 {
		t.Fatalf("APsForESSID returned %d, want 3", len(group))
	}
	for _, ap := range group {
		if ap.ESSID != "CORP-WIFI" {
			t.Errorf("wrong ESSID in group: %q", ap.ESSID)
		}
	}
}

func TestDataFrameTracksAssociation(t *testing.T) {
	tr := NewTracker(nil)
	ap := mac("a4:2b:8c:11:22:33")
	sta := mac("de:ad:be:ef:00:01")
	now := time.Now()

	// Frame from the station to the AP.
	observe(t, tr, buildDataFrame(true, false, ap, sta, mac("11:22:33:44:55:66")),
		rssi(-62, 6), "phy1", now)

	st, ok := tr.Station(sta)
	if !ok {
		t.Fatal("station not recorded from a data frame")
	}
	if st.BSSID != ap {
		t.Errorf("station BSSID = %v, want %v", st.BSSID, ap)
	}

	rec, ok := tr.AP(ap)
	if !ok {
		t.Fatal("AP not recorded from a data frame")
	}
	if rec.DataFrames != 1 {
		t.Errorf("DataFrames = %d, want 1", rec.DataFrames)
	}
}

func TestConcurrentObservationsAreSafe(t *testing.T) {
	tr := NewTracker(func(Observation) {})
	now := time.Now()

	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			b := MAC{0xa4, 0x2b, 0x8c, 0x11, 0x22, byte(n)}
			raw := buildBeacon(beaconOpts{bssid: b, ies: [][]byte{ssidIE("CORP-WIFI"), dsIE(6)}})
			for j := 0; j < 100; j++ {
				f, err := ParseFrame(raw)
				if err != nil {
					return
				}
				tr.Observe(f, rssi(-60, 6), "phy1", now)
			}
			tr.APs()
			tr.Counts()
		}(i)
	}
	for i := 0; i < 4; i++ {
		<-done
	}

	if aps, _ := tr.Counts(); aps != 4 {
		t.Errorf("tracked %d APs, want 4", aps)
	}
}

// TestTheAPsChannelComesFromItsBeaconNotFromOurReceiver.
//
// This is the bug that broke every transmitting attack in the tool.
//
// Radiotap reports the frequency the *receiving* card was tuned to. 2.4 GHz channels overlap
// by 20 MHz of a 22 MHz-wide signal, so a beacon transmitted on channel 1 is comfortably
// audible while sweeping channel 2. Taking the frequency from radiotap recorded the sweep's
// channel rather than the access point's: an AP on 1 was filed as 2, one on 6 as 7, one on 10
// as 11. Every campaign then parked the radios one channel off and transmitted where nothing
// was listening — no PMKID ever came back, deauthentication worked at one network and not its
// neighbour, and the enterprise harvest never saw an EAP request.
//
// The DS Parameter Set is the access point stating its own channel in its own beacon. It wins.
func TestTheAPsChannelComesFromItsBeaconNotFromOurReceiver(t *testing.T) {
	cases := []struct {
		name        string
		beaconCh    uint8
		heardAtFreq int
		wantCh      int
		wantFreq    int
	}{
		// The three the operator actually hit.
		{"channel 1 heard while sweeping 2", 1, 2417, 1, 2412},
		{"channel 6 heard while sweeping 7", 6, 2442, 6, 2437},
		{"channel 10 heard while sweeping 11", 10, 2462, 10, 2457},

		// Heard on its own channel: unchanged, which is the case that used to work and made
		// the bug look intermittent.
		{"channel 6 heard on 6", 6, 2437, 6, 2437},

		// 5 GHz: the band has to come from the receiver, because the channel number alone
		// cannot distinguish 5 GHz channel 36 from anything else numbered 36.
		{"5 GHz channel 36", 36, 5200, 36, 5180},
		{"5 GHz channel 44", 44, 5180, 44, 5220},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := NewTracker(nil)
			bssid := mac("a4:2b:8c:11:22:33")

			raw := buildBeacon(beaconOpts{
				bssid: bssid,
				ies:   [][]byte{ssidIE("CORP-WIFI"), ratesIE(0x82, 0x84), dsIE(c.beaconCh)},
			})
			heardCh, _ := nl80211ChannelForTest(c.heardAtFreq)
			observe(t, tr, raw, RadiotapMeta{
				RSSI: -50, HasRSSI: true, Freq: c.heardAtFreq, Channel: heardCh,
			}, "phy0", time.Now())

			ap, ok := tr.AP(bssid)
			if !ok {
				t.Fatal("the access point was not recorded at all")
			}
			if ap.Channel != c.wantCh {
				t.Errorf("channel = %d, want %d (the beacon says %d; we heard it at %d MHz)",
					ap.Channel, c.wantCh, c.beaconCh, c.heardAtFreq)
			}
			if ap.Freq != c.wantFreq {
				t.Errorf("freq = %d MHz, want %d — every campaign holds the radios on this "+
					"frequency, so being off by one channel means transmitting where nothing "+
					"is listening", ap.Freq, c.wantFreq)
			}
		})
	}
}

// TestChannelFallsBackToRadiotapWithoutAChannelElement.
//
// Some beacons carry no DS Parameter Set, and a probe response from a hidden network
// sometimes does not either. Being one channel out beats having no channel at all.
func TestChannelFallsBackToRadiotapWithoutAChannelElement(t *testing.T) {
	tr := NewTracker(nil)
	bssid := mac("a4:2b:8c:11:22:33")

	raw := buildBeacon(beaconOpts{
		bssid: bssid,
		ies:   [][]byte{ssidIE("CORP-WIFI"), ratesIE(0x82, 0x84)}, // no DS element
	})
	observe(t, tr, raw, RadiotapMeta{
		RSSI: -50, HasRSSI: true, Freq: 2437, Channel: 6,
	}, "phy0", time.Now())

	ap, _ := tr.AP(bssid)
	if ap.Channel != 6 || ap.Freq != 2437 {
		t.Errorf("channel/freq = %d/%d, want 6/2437 from radiotap", ap.Channel, ap.Freq)
	}
}

// TestTheBandSurvivesTheChannelCorrection: the band label is derived from the corrected
// frequency, so a 5 GHz access point must not come out labelled 2.4 GHz.
func TestTheBandSurvivesTheChannelCorrection(t *testing.T) {
	tr := NewTracker(nil)
	bssid := mac("a4:2b:8c:11:22:33")

	raw := buildBeacon(beaconOpts{
		bssid: bssid,
		ies:   [][]byte{ssidIE("CORP-5G"), ratesIE(0x8c, 0x98), dsIE(36)},
	})
	observe(t, tr, raw, RadiotapMeta{
		RSSI: -60, HasRSSI: true, Freq: 5200, Channel: 40,
	}, "phy0", time.Now())

	ap, _ := tr.AP(bssid)
	if ap.Band != "5GHz" {
		t.Errorf("band = %q, want %q", ap.Band, "5GHz")
	}
}

// nl80211ChannelForTest mirrors what a capture source fills into RadiotapMeta.Channel.
func nl80211ChannelForTest(freq int) (int, string) {
	ch, band := nl80211.ChannelForFrequencyAuto(freq)
	return ch, band.String()
}

// TestPHYModesAreReported.
//
// Next to the band because they answer different questions: the band is where the access point
// is, the PHY is what it is. An 802.11g-only radio still on the floor is a finding on its own —
// old radios carry old firmware, and that is where the weak WPS and the absent 802.11w live.
func TestPHYModesAreReported(t *testing.T) {
	ofdm := ratesIE(0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24)
	dsssOnly := ratesIE(0x82, 0x84, 0x8b, 0x96)

	cases := []struct {
		name    string
		channel uint8
		freq    int
		ies     [][]byte
		want    string
	}{
		{
			name: "modern 2.4 GHz", channel: 6, freq: 2437,
			ies:  [][]byte{ofdm, htCapIE(0x012c), heCapIE()},
			want: "ax/n/g",
		},
		{
			name: "typical 5 GHz", channel: 36, freq: 5180,
			ies:  [][]byte{ratesIE(0x8c, 0x98, 0xb0), htCapIE(0x012c), vhtCapIE(0x0f815832)},
			want: "ac/n/a",
		},
		{
			name: "2.4 GHz with no HT — an old access point", channel: 1, freq: 2412,
			ies:  [][]byte{ofdm},
			want: "g",
		},
		{
			name: "DSSS rates only — genuinely ancient", channel: 1, freq: 2412,
			ies:  [][]byte{dsssOnly},
			want: "b",
		},
		{
			name: "5 GHz with no HT", channel: 40, freq: 5200,
			ies:  [][]byte{ratesIE(0x8c, 0x98)},
			want: "a",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := NewTracker(nil)
			bssid := mac("a4:2b:8c:11:22:33")

			ies := append([][]byte{ssidIE("CORP-WIFI"), dsIE(c.channel)}, c.ies...)
			raw := buildBeacon(beaconOpts{bssid: bssid, ies: ies})
			observe(t, tr, raw, RadiotapMeta{
				RSSI: -50, HasRSSI: true, Freq: c.freq, Channel: int(c.channel),
			}, "phy0", time.Now())

			ap, _ := tr.AP(bssid)
			if ap.PHY != c.want {
				t.Errorf("PHY = %q, want %q", ap.PHY, c.want)
			}
		})
	}
}
