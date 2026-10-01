package nl80211

// Frequency/channel conversion per IEEE 802.11-2020 Annex E.
//
// The band matters. 6 GHz channel numbering restarts at 1 and its frequencies (5955-7115 MHz)
// sit above the 5 GHz formula's domain, so applying the 5 GHz mapping to a 6 GHz frequency
// yields a plausible-looking wrong channel - 5955 MHz would read as channel 191 instead of
// channel 1. Every conversion here is therefore band-qualified, and the band-inferring
// helpers exist only for callers that genuinely do not have it.

// Frequency boundaries, in MHz.
const (
	freq24Ch1  = 2412
	freq24Ch13 = 2472
	freq24Ch14 = 2484

	freq6Ch2    = 5935 // the one out-of-sequence 6 GHz channel
	freq6Base   = 5950
	freq6First  = 5955
	freq6Last   = 7115
	freq5Lowest = 5000
	freq49Base  = 4000
)

// ChannelForFrequency converts a centre frequency in MHz to an IEEE channel number for the
// given band. It returns 0 if the frequency is not a valid channel in that band.
func ChannelForFrequency(mhz int, band Band) int {
	switch band {
	case Band2GHz:
		switch {
		case mhz == freq24Ch14:
			return 14
		case mhz >= freq24Ch1 && mhz <= freq24Ch13 && (mhz-freq24Ch1)%5 == 0:
			return (mhz - 2407) / 5
		}
		return 0

	case Band5GHz:
		switch {
		case mhz >= freq5Lowest && mhz%5 == 0:
			return (mhz - freq5Lowest) / 5
		// 4.9 GHz public-safety allocation, still reported as the 5 GHz band.
		case mhz >= 4000 && mhz < freq5Lowest && mhz%5 == 0:
			return (mhz - freq49Base) / 5
		}
		return 0

	case Band6GHz:
		switch {
		case mhz == freq6Ch2:
			return 2
		case mhz >= freq6First && mhz <= freq6Last && (mhz-freq6Base)%5 == 0:
			return (mhz - freq6Base) / 5
		}
		return 0

	case Band60GHz:
		if mhz >= 56160 && mhz <= 70200 && (mhz-56160)%2160 == 0 {
			return (mhz-56160)/2160 + 1
		}
		return 0
	}
	return 0
}

// FrequencyForChannel converts an IEEE channel number to a centre frequency in MHz for the
// given band. It returns 0 if the channel is not valid in that band.
func FrequencyForChannel(ch int, band Band) int {
	switch band {
	case Band2GHz:
		switch {
		case ch == 14:
			return freq24Ch14
		case ch >= 1 && ch <= 13:
			return 2407 + 5*ch
		}
		return 0

	case Band5GHz:
		if ch >= 1 && ch <= 200 {
			return freq5Lowest + 5*ch
		}
		return 0

	case Band6GHz:
		switch {
		case ch == 2:
			return freq6Ch2
		case ch >= 1 && ch <= 233:
			return freq6Base + 5*ch
		}
		return 0

	case Band60GHz:
		if ch >= 1 && ch <= 7 {
			return 56160 + 2160*(ch-1)
		}
		return 0
	}
	return 0
}

// BandForFrequency infers the band from a centre frequency.
//
// Prefer the band the kernel reported. This is for callers holding only a frequency - for
// example a radiotap header on a captured frame, which carries frequency but not band.
func BandForFrequency(mhz int) Band {
	switch {
	case mhz >= 2400 && mhz <= 2500:
		return Band2GHz
	case mhz == freq6Ch2 || (mhz >= freq6First && mhz <= freq6Last):
		return Band6GHz
	case mhz >= 4000 && mhz < freq6First:
		return Band5GHz
	case mhz >= 56160:
		return Band60GHz
	default:
		return Band2GHz
	}
}

// ChannelForFrequencyAuto converts a frequency to a channel, inferring the band. It returns
// the channel and the inferred band.
func ChannelForFrequencyAuto(mhz int) (int, Band) {
	b := BandForFrequency(mhz)
	return ChannelForFrequency(mhz, b), b
}
