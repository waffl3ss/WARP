package nl80211

import "testing"

func TestChannelForFrequency(t *testing.T) {
	tests := []struct {
		name string
		mhz  int
		band Band
		want int
	}{
		// 2.4 GHz
		{"2g ch1", 2412, Band2GHz, 1},
		{"2g ch6", 2437, Band2GHz, 6},
		{"2g ch11", 2462, Band2GHz, 11},
		{"2g ch13", 2472, Band2GHz, 13},
		{"2g ch14 is out of sequence", 2484, Band2GHz, 14},
		{"2g off-grid frequency", 2415, Band2GHz, 0},
		{"2g out of band", 2500, Band2GHz, 0},

		// 5 GHz
		{"5g ch36", 5180, Band5GHz, 36},
		{"5g ch40", 5200, Band5GHz, 40},
		{"5g ch48", 5240, Band5GHz, 48},
		{"5g ch100 (DFS)", 5500, Band5GHz, 100},
		{"5g ch149", 5745, Band5GHz, 149},
		{"5g ch165", 5825, Band5GHz, 165},
		{"4.9g public safety", 4940, Band5GHz, 188},

		// 6 GHz — numbering restarts at 1
		{"6g ch1", 5955, Band6GHz, 1},
		{"6g ch5", 5975, Band6GHz, 5},
		{"6g ch33", 6115, Band6GHz, 33},
		{"6g ch233 (top)", 7115, Band6GHz, 233},
		{"6g ch2 is out of sequence", 5935, Band6GHz, 2},
		{"6g below band", 5950, Band6GHz, 0},
		{"6g above band", 7120, Band6GHz, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ChannelForFrequency(tc.mhz, tc.band); got != tc.want {
				t.Errorf("ChannelForFrequency(%d, %v) = %d, want %d", tc.mhz, tc.band, got, tc.want)
			}
		})
	}
}

// TestSixGHzIsNotMisreadAsFiveGHz is the specific failure this mapping exists to prevent:
// applying the 5 GHz formula to a 6 GHz frequency yields a plausible wrong channel rather
// than an error, and a wrong channel number in a report sends someone to the wrong radio.
func TestSixGHzIsNotMisreadAsFiveGHz(t *testing.T) {
	const sixGHzCh1 = 5955

	if got := ChannelForFrequency(sixGHzCh1, Band6GHz); got != 1 {
		t.Fatalf("6 GHz channel 1 read as %d", got)
	}
	if got := ChannelForFrequency(sixGHzCh1, Band5GHz); got == 1 {
		t.Fatal("5 GHz mapping produced channel 1 for a 6 GHz frequency — the band qualifier is not being honoured")
	}
	if got, band := ChannelForFrequencyAuto(sixGHzCh1); got != 1 || band != Band6GHz {
		t.Fatalf("ChannelForFrequencyAuto(%d) = (%d, %v), want (1, 6GHz)", sixGHzCh1, got, band)
	}
}

func TestFrequencyChannelRoundTrip(t *testing.T) {
	bands := map[Band][]int{
		Band2GHz: {1, 6, 11, 13, 14},
		Band5GHz: {36, 40, 48, 100, 149, 165},
		Band6GHz: {1, 2, 5, 33, 97, 233},
	}

	for band, channels := range bands {
		for _, ch := range channels {
			mhz := FrequencyForChannel(ch, band)
			if mhz == 0 {
				t.Errorf("FrequencyForChannel(%d, %v) = 0", ch, band)
				continue
			}
			if got := ChannelForFrequency(mhz, band); got != ch {
				t.Errorf("round trip failed for %v channel %d: %d MHz mapped back to channel %d", band, ch, mhz, got)
			}
		}
	}
}

func TestBandForFrequency(t *testing.T) {
	tests := []struct {
		mhz  int
		want Band
	}{
		{2412, Band2GHz},
		{2484, Band2GHz},
		{5180, Band5GHz},
		{5825, Band5GHz},
		{5935, Band6GHz}, // out-of-sequence 6 GHz channel 2
		{5955, Band6GHz},
		{7115, Band6GHz},
		{58320, Band60GHz},
	}
	for _, tc := range tests {
		if got := BandForFrequency(tc.mhz); got != tc.want {
			t.Errorf("BandForFrequency(%d) = %v, want %v", tc.mhz, got, tc.want)
		}
	}
}

func TestFrequencyUsable(t *testing.T) {
	tests := []struct {
		name string
		f    Frequency
		want bool
	}{
		{"plain channel", Frequency{MHz: 2437}, true},
		{"disabled by regulatory domain", Frequency{MHz: 2437, Disabled: true}, false},
		{"no initiating radiation", Frequency{MHz: 5260, NoIR: true}, false},
		{"radar channel is still usable once cleared", Frequency{MHz: 5260, Radar: true}, true},
		{"radar and no-IR", Frequency{MHz: 5260, Radar: true, NoIR: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.Usable(); got != tc.want {
				t.Errorf("Usable() = %v, want %v", got, tc.want)
			}
		})
	}
}
