package nl80211

import "testing"

// Combinations transcribed from real `iw list` output. The whole point of parsing interface
// combinations is to know when a phy gives us a free extra logical radio, so the fixtures are
// real capability sets rather than invented ones.

// mt76 (MediaTek USB, e.g. mt7612u — a common pentest adapter): AP and monitor concurrently.
//
//	#{ AP, mesh point } <= 8, #{ managed } <= 8, #{ monitor } <= 1, total <= 8, #channels <= 1
var combMT76 = IfaceCombination{
	Limits: []IfaceLimit{
		{Max: 8, Types: []Iftype{IftypeAP, IftypeMeshPoint}},
		{Max: 8, Types: []Iftype{IftypeStation}},
		{Max: 1, Types: []Iftype{IftypeMonitor}},
	},
	MaxInterfaces: 8,
	NumChannels:   1,
}

// ath9k_htc (e.g. TL-WN722N v1): managed/AP/monitor, single channel.
var combATH9K = IfaceCombination{
	Limits: []IfaceLimit{
		{Max: 2048, Types: []Iftype{IftypeStation, IftypeWDS, IftypeP2PClient}},
		{Max: 8, Types: []Iftype{IftypeAdhoc, IftypeAP, IftypeMeshPoint, IftypeP2PGo}},
		{Max: 1, Types: []Iftype{IftypeMonitor}},
	},
	MaxInterfaces: 2048,
	NumChannels:   1,
}

// A restrictive part that cannot do anything concurrently.
var combSingle = IfaceCombination{
	Limits: []IfaceLimit{
		{Max: 1, Types: []Iftype{IftypeStation}},
		{Max: 1, Types: []Iftype{IftypeAP}},
	},
	MaxInterfaces: 1,
	NumChannels:   1,
}

func TestIfaceCombinationSupports(t *testing.T) {
	tests := []struct {
		name     string
		comb     IfaceCombination
		want     map[Iftype]uint32
		channels uint32
		expect   bool
	}{
		{"mt76 AP+monitor is the free extra radio", combMT76, map[Iftype]uint32{IftypeAP: 1, IftypeMonitor: 1}, 1, true},
		{"mt76 two monitors exceeds the monitor clause", combMT76, map[Iftype]uint32{IftypeMonitor: 2}, 1, false},
		{"mt76 AP+monitor on two channels", combMT76, map[Iftype]uint32{IftypeAP: 1, IftypeMonitor: 1}, 2, false},
		{"mt76 managed+monitor", combMT76, map[Iftype]uint32{IftypeStation: 1, IftypeMonitor: 1}, 1, true},

		{"ath9k AP+monitor", combATH9K, map[Iftype]uint32{IftypeAP: 1, IftypeMonitor: 1}, 1, true},
		{"ath9k monitor alone", combATH9K, map[Iftype]uint32{IftypeMonitor: 1}, 1, true},

		{"single-interface part cannot do AP+monitor", combSingle, map[Iftype]uint32{IftypeAP: 1, IftypeMonitor: 1}, 1, false},
		{"single-interface part does not list monitor at all", combSingle, map[Iftype]uint32{IftypeMonitor: 1}, 1, false},
		{"single-interface part managed alone", combSingle, map[Iftype]uint32{IftypeStation: 1}, 1, true},

		{"empty request", combMT76, map[Iftype]uint32{}, 1, false},
		{"zero counts are not a request", combMT76, map[Iftype]uint32{IftypeAP: 0}, 1, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.comb.Supports(tc.want, tc.channels); got != tc.expect {
				t.Errorf("Supports(%v, %d) = %v, want %v", tc.want, tc.channels, got, tc.expect)
			}
		})
	}
}

// TestSupportsIsNotOrderDependent is the regression test for the assignment problem.
//
// A type may appear in several clauses. Charging demand to clauses greedily in the order the
// driver happens to list them can exhaust a clause a later type needed, reporting infeasible
// when a valid assignment exists — costing us a concurrency the hardware really has. The two
// combinations below are identical except for clause order and must give identical answers.
func TestSupportsIsNotOrderDependent(t *testing.T) {
	forward := IfaceCombination{
		Limits: []IfaceLimit{
			{Max: 1, Types: []Iftype{IftypeAP, IftypeMonitor}},
			{Max: 1, Types: []Iftype{IftypeAP}},
		},
		MaxInterfaces: 2,
		NumChannels:   1,
	}
	reversed := IfaceCombination{
		Limits: []IfaceLimit{
			{Max: 1, Types: []Iftype{IftypeAP}},
			{Max: 1, Types: []Iftype{IftypeAP, IftypeMonitor}},
		},
		MaxInterfaces: 2,
		NumChannels:   1,
	}

	want := map[Iftype]uint32{IftypeAP: 1, IftypeMonitor: 1}

	// AP charges to the AP-only clause, monitor to the shared clause. Feasible either way.
	if !forward.Supports(want, 1) {
		t.Error("forward clause order reported infeasible; a valid assignment exists (AP→clause 2, monitor→clause 1)")
	}
	if !reversed.Supports(want, 1) {
		t.Error("reversed clause order reported infeasible; a valid assignment exists (AP→clause 1, monitor→clause 2)")
	}

	// And the genuinely infeasible case stays infeasible: one shared clause of size 1.
	tight := IfaceCombination{
		Limits:        []IfaceLimit{{Max: 1, Types: []Iftype{IftypeAP, IftypeMonitor}}},
		MaxInterfaces: 2,
		NumChannels:   1,
	}
	if tight.Supports(want, 1) {
		t.Error("a single shared clause of size 1 cannot host both AP and monitor")
	}
}

func TestWiphyCapabilityHelpers(t *testing.T) {
	w := &Wiphy{
		Index:            0,
		Name:             "phy0",
		SupportedIftypes: []Iftype{IftypeStation, IftypeAP, IftypeMonitor},
		Combinations:     []IfaceCombination{combMT76},
		Bands: []BandInfo{
			{Band: Band2GHz, Freqs: []Frequency{
				{MHz: 2412, Channel: 1},
				{MHz: 2437, Channel: 6},
			}},
			{Band: Band5GHz, Freqs: []Frequency{
				{MHz: 5180, Channel: 36},
				{MHz: 5260, Channel: 52, NoIR: true, Radar: true},
				{MHz: 5320, Channel: 64, Disabled: true},
			}},
		},
	}

	if !w.SupportsIftype(IftypeMonitor) {
		t.Error("monitor should be supported")
	}
	if w.SupportsIftype(IftypeNAN) {
		t.Error("NAN should not be supported")
	}
	if !w.SupportsAPMonitorConcurrent() {
		t.Error("mt76 combination should permit concurrent AP + monitor")
	}
	if !w.HasBand(Band2GHz) || !w.HasBand(Band5GHz) {
		t.Error("both bands should be present")
	}
	if w.HasBand(Band6GHz) {
		t.Error("6 GHz should not be reported")
	}

	// Disabled and no-IR channels must not appear as usable: transmitting on them fails in
	// ways that look like driver bugs, and counting them inflates the channel plan.
	usable := w.UsableChannels()
	if len(usable) != 3 {
		t.Fatalf("expected 3 usable channels (2412, 2437, 5180), got %d: %+v", len(usable), usable)
	}
	for _, f := range usable {
		if f.NoIR || f.Disabled {
			t.Errorf("unusable channel %d MHz reported as usable", f.MHz)
		}
	}
}

// TestHasBandIgnoresUnusableChannels guards against reporting a band we cannot transmit on.
func TestHasBandIgnoresUnusableChannels(t *testing.T) {
	w := &Wiphy{Bands: []BandInfo{
		{Band: Band6GHz, Freqs: []Frequency{
			{MHz: 5955, Channel: 1, Disabled: true},
			{MHz: 5975, Channel: 5, NoIR: true},
		}},
	}}
	if w.HasBand(Band6GHz) {
		t.Error("a band with no usable channels must not be reported as present")
	}
}

// TestMergeSplitWiphyDump covers the split-dump merge. The kernel spreads one phy across
// several messages and can split a single band's frequency list, so bands must merge by
// band ID. Appending instead yields a phy that appears to support only the channels in the
// last message — which reads as a regulatory restriction, not a bug.
func TestMergeSplitWiphyDump(t *testing.T) {
	acc := &Wiphy{Index: 0}

	acc.merge(&Wiphy{
		Index:            0,
		Name:             "phy0",
		SupportedIftypes: []Iftype{IftypeStation, IftypeAP},
		Bands: []BandInfo{{Band: Band2GHz, Freqs: []Frequency{
			{MHz: 2412, Channel: 1},
			{MHz: 2437, Channel: 6},
		}}},
	})

	// Second message: the rest of the 2.4 GHz channels, a new band, and the combinations.
	acc.merge(&Wiphy{
		Index:            0,
		SupportedIftypes: []Iftype{IftypeMonitor},
		Bands: []BandInfo{
			{Band: Band2GHz, Freqs: []Frequency{{MHz: 2462, Channel: 11}}, HTCapa: 0x016e},
			{Band: Band5GHz, Freqs: []Frequency{{MHz: 5180, Channel: 36}}},
		},
		Combinations: []IfaceCombination{combMT76},
	})

	if acc.Name != "phy0" {
		t.Errorf("name lost across merge: %q", acc.Name)
	}
	if len(acc.Bands) != 2 {
		t.Fatalf("expected 2 bands after merge, got %d", len(acc.Bands))
	}

	var band24 *BandInfo
	for i := range acc.Bands {
		if acc.Bands[i].Band == Band2GHz {
			band24 = &acc.Bands[i]
		}
	}
	if band24 == nil {
		t.Fatal("2.4 GHz band missing after merge")
	}
	if len(band24.Freqs) != 3 {
		t.Errorf("2.4 GHz frequencies split across messages were not merged: got %d, want 3", len(band24.Freqs))
	}
	if band24.HTCapa != 0x016e {
		t.Errorf("HT capability from the later message was lost: %#x", band24.HTCapa)
	}

	// Iftypes union rather than overwrite: monitor arrived in the second message.
	if !acc.SupportsIftype(IftypeStation) || !acc.SupportsIftype(IftypeAP) || !acc.SupportsIftype(IftypeMonitor) {
		t.Errorf("iftypes did not union across messages: %v", acc.SupportedIftypes)
	}
	if !acc.SupportsAPMonitorConcurrent() {
		t.Error("combinations from the later message were lost")
	}
}

// TestSoftwareIftypesAreAlwaysAddable is the regression test for a real mt76x2u.
//
// That adapter advertises `#{ IBSS } <= 1, #{ managed, AP, mesh point, P2P-client, P2P-GO }
// <= 2, total <= 2` — monitor appears in no clause at all — while separately listing monitor
// under "software interface modes (can always be added)". Checking the combinations alone
// reports AP+monitor as unsupported and throws away a free extra radio.
func TestSoftwareIftypesAreAlwaysAddable(t *testing.T) {
	// Transcribed from `iw list` on an mt76x2u.
	mt76x2u := &Wiphy{
		SupportedIftypes: []Iftype{
			IftypeAdhoc, IftypeStation, IftypeAP, IftypeAPVLAN,
			IftypeMonitor, IftypeMeshPoint, IftypeP2PClient, IftypeP2PGo,
		},
		SoftwareIftypes: []Iftype{IftypeAPVLAN, IftypeMonitor},
		Combinations: []IfaceCombination{{
			Limits: []IfaceLimit{
				{Max: 1, Types: []Iftype{IftypeAdhoc}},
				{Max: 2, Types: []Iftype{IftypeStation, IftypeAP, IftypeMeshPoint,
					IftypeP2PClient, IftypeP2PGo}},
			},
			MaxInterfaces: 2,
			NumChannels:   1,
		}},
	}

	if !mt76x2u.SupportsAPMonitorConcurrent() {
		t.Error("AP+monitor reported unsupported; monitor is a software iftype and can " +
			"always be added, which is why it appears in no combination clause")
	}
	if !mt76x2u.SupportsConcurrent(map[Iftype]uint32{IftypeMonitor: 1}, 1) {
		t.Error("monitor alone reported unsupported")
	}
	if !mt76x2u.SupportsConcurrent(map[Iftype]uint32{IftypeStation: 1, IftypeMonitor: 1}, 1) {
		t.Error("managed+monitor reported unsupported")
	}

	// A type the adapter does not support at all is still refused, software list or not.
	if mt76x2u.SupportsConcurrent(map[Iftype]uint32{IftypeNAN: 1}, 1) {
		t.Error("an unsupported interface type was accepted")
	}
	// And a hardware type still has to fit the combinations.
	if mt76x2u.SupportsConcurrent(map[Iftype]uint32{IftypeAP: 3}, 1) {
		t.Error("three APs accepted where the combination allows two")
	}
}
