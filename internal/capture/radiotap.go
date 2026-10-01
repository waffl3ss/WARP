// Package capture ingests 802.11 frames from a monitor-mode interface.
//
// Radiotap parsing lives here because it is the layer that carries RSSI, and RSSI is what the
// survey depends on. A silent bug here does not crash anything - it produces a coverage
// picture that looks entirely plausible and points at the wrong ceiling tile.
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Radiotap header constants.
const (
	radiotapVersion   = 0
	radiotapMinHeader = 8 // version + pad + len + one present bitmap
)

// Radiotap present-bitmap bits (ieee80211_radiotap_presence).
const (
	bitTSFT            = 0
	bitFlags           = 1
	bitRate            = 2
	bitChannel         = 3
	bitFHSS            = 4
	bitDBMAntSignal    = 5
	bitDBMAntNoise     = 6
	bitLockQuality     = 7
	bitTXAttenuation   = 8
	bitDBTXAttenuation = 9
	bitDBMTXPower      = 10
	bitAntenna         = 11
	bitDBAntSignal     = 12
	bitDBAntNoise      = 13
	bitRXFlags         = 14
	bitTXFlags         = 15
	bitRTSRetries      = 16
	bitDataRetries     = 17
	bitXChannel        = 18
	bitMCS             = 19
	bitAMPDUStatus     = 20
	bitVHT             = 21
	bitTimestamp       = 22
	bitHE              = 23
	bitHEMU            = 24
	bitHEMUOtherUser   = 25
	bitZeroLenPSDU     = 26
	bitLSIG            = 27
	bitTLV             = 28
	bitRadiotapNS      = 29
	bitVendorNS        = 30
	bitExt             = 31
)

// Radiotap FLAGS field bits.
const (
	flagCFP      = 0x01
	flagShortPre = 0x02
	flagWEP      = 0x04
	flagFrag     = 0x08
	flagFCS      = 0x10 // frame includes a trailing 4-byte FCS
	flagDataPad  = 0x20 // 802.11 header is padded to a 32-bit boundary
	flagBadFCS   = 0x40
	flagShortGI  = 0x80
)

// Radiotap CHANNEL flags.
const (
	chanTurbo   = 0x0010
	chanCCK     = 0x0020
	chanOFDM    = 0x0040
	chan2GHz    = 0x0080
	chan5GHz    = 0x0100
	chanPassive = 0x0200
	chanDynCCK  = 0x0400
	chanGFSK    = 0x0800
)

// fieldLayout is the alignment and size of one radiotap field.
//
// Every field is aligned to its natural boundary *relative to the start of the radiotap
// header*, and fields appear in ascending bit order. Getting an alignment wrong shifts every
// subsequent field, which typically shows up as an RSSI of -128 or a nonsense frequency
// rather than as a parse error - so the table is transcribed directly from
// ieee80211_radiotap.h and must not be "tidied".
var fieldLayout = map[int]struct{ align, size int }{
	bitTSFT:            {8, 8},
	bitFlags:           {1, 1},
	bitRate:            {1, 1},
	bitChannel:         {2, 4}, // u16 freq + u16 flags
	bitFHSS:            {1, 2},
	bitDBMAntSignal:    {1, 1},
	bitDBMAntNoise:     {1, 1},
	bitLockQuality:     {2, 2},
	bitTXAttenuation:   {2, 2},
	bitDBTXAttenuation: {2, 2},
	bitDBMTXPower:      {1, 1},
	bitAntenna:         {1, 1},
	bitDBAntSignal:     {1, 1},
	bitDBAntNoise:      {1, 1},
	bitRXFlags:         {2, 2},
	bitTXFlags:         {2, 2},
	bitRTSRetries:      {1, 1},
	bitDataRetries:     {1, 1},
	bitXChannel:        {4, 8}, // u32 flags + u16 freq + u8 channel + u8 maxpower
	bitMCS:             {1, 3},
	bitAMPDUStatus:     {4, 8},
	bitVHT:             {2, 12},
	bitTimestamp:       {8, 12},
	bitHE:              {2, 12},
	bitHEMU:            {2, 12},
	bitHEMUOtherUser:   {2, 6},
	bitZeroLenPSDU:     {1, 1},
	bitLSIG:            {2, 4},
	bitTLV:             {4, 0}, // variable; handled specially
}

// RadiotapInfo is what WARP needs from a radiotap header.
type RadiotapInfo struct {
	// Length is the radiotap header length, i.e. the offset of the 802.11 frame.
	Length int
	// Freq is the channel centre frequency in MHz, 0 if not reported.
	Freq int
	// ChannelFlags is the raw radiotap channel flag word.
	ChannelFlags uint16
	// SignalDBM is the antenna signal in dBm. Valid only if HasSignal.
	SignalDBM int8
	// HasSignal reports whether the driver supplied an antenna signal.
	//
	// This is not decoration. An observation with no RSSI must not be recorded as 0 dBm,
	// which would read as an extremely strong signal and put a device in the wrong room.
	HasSignal bool
	// NoiseDBM is the antenna noise in dBm, valid only if HasNoise.
	NoiseDBM int8
	HasNoise bool
	// Antenna index, valid only if HasAntenna.
	Antenna    uint8
	HasAntenna bool
	// Flags is the raw radiotap FLAGS field.
	Flags uint8
	// HasFCS reports that the frame carries a trailing 4-byte FCS to be stripped.
	HasFCS bool
	// BadFCS reports that the driver flagged the frame as failing its checksum.
	BadFCS bool
	// DataPad reports that the 802.11 header is padded to a 32-bit boundary.
	DataPad bool
	// RateKbps is the legacy bitrate in kbps, 0 if not reported or not legacy.
	RateKbps int
	// MCS index, valid only if HasMCS.
	MCS    uint8
	HasMCS bool
	// TSFT is the driver's MAC timestamp, valid only if HasTSFT.
	TSFT    uint64
	HasTSFT bool
	// Partial reports that the walk stopped early at a field WARP has no layout for.
	//
	// Everything decoded before that point is still correct - fields appear in ascending bit
	// order at deterministic offsets - so what was read is kept. Only fields after the stop
	// are missing.
	Partial bool
}

// Band2GHz reports whether the radiotap channel flags indicate the 2.4 GHz band.
func (r RadiotapInfo) Band2GHz() bool { return r.ChannelFlags&chan2GHz != 0 }

// Band5GHz reports whether the radiotap channel flags indicate the 5 GHz band.
func (r RadiotapInfo) Band5GHz() bool { return r.ChannelFlags&chan5GHz != 0 }

// Errors returned by ParseRadiotap.
var (
	ErrShortRadiotap   = errors.New("capture: buffer shorter than a radiotap header")
	ErrRadiotapVersion = errors.New("capture: unsupported radiotap version")
	ErrRadiotapLength  = errors.New("capture: radiotap length exceeds the buffer")
)

// ParseRadiotap decodes a radiotap header.
//
// It returns the parsed info and the 802.11 frame body with any trailing FCS removed. Fields
// WARP does not use are skipped by alignment rather than decoded, so an unfamiliar field from
// a newer driver costs nothing and does not desynchronise the walk.
func ParseRadiotap(buf []byte) (RadiotapInfo, []byte, error) {
	var info RadiotapInfo

	if len(buf) < radiotapMinHeader {
		return info, nil, ErrShortRadiotap
	}
	if buf[0] != radiotapVersion {
		return info, nil, fmt.Errorf("%w: %d", ErrRadiotapVersion, buf[0])
	}

	hdrLen := int(binary.LittleEndian.Uint16(buf[2:4]))
	if hdrLen < radiotapMinHeader || hdrLen > len(buf) {
		return info, nil, fmt.Errorf("%w: header says %d, buffer is %d", ErrRadiotapLength, hdrLen, len(buf))
	}
	info.Length = hdrLen

	// Collect the present bitmaps. Bit 31 of a word means another word follows.
	var bitmaps []uint32
	off := 4
	for {
		if off+4 > hdrLen {
			return info, nil, fmt.Errorf("capture: radiotap present bitmap runs past the header")
		}
		word := binary.LittleEndian.Uint32(buf[off : off+4])
		bitmaps = append(bitmaps, word)
		off += 4
		if word&(1<<bitExt) == 0 {
			break
		}
		// A malformed header could otherwise chain bitmaps indefinitely.
		if len(bitmaps) > 8 {
			return info, nil, fmt.Errorf("capture: radiotap present bitmap chain too long")
		}
	}

	// Field data begins after the bitmaps. Alignment is relative to the start of the header,
	// which is offset 0 of buf, so the running offset is used directly.
	if err := walkFields(buf, hdrLen, off, bitmaps, &info); err != nil {
		// A field we cannot walk means everything *after* it is untrustworthy, because its
		// size is unknown and every later offset would be wrong. Everything before it was
		// decoded at a correct offset and is kept.
		//
		// This used to discard the antenna signal as well. That was wrong and it was
		// expensive: signal is bit 5 and is decoded long before the fields that stop the walk
		// (HE, TLV, an extended bitmap, a vendor namespace), so on any driver emitting one of
		// those every frame arrived with no RSSI. The signal column read empty, hunt had no
		// gradient to follow, and localisation had nothing to rank - with no error anywhere,
		// because a walk that stops early is not a parse failure.
		info.Partial = true
	}

	body := buf[hdrLen:]

	// Strip the FCS before anything tries to parse the frame. Leaving it on makes the last
	// information element of a beacon look corrupt.
	if info.HasFCS && len(body) >= 4 {
		body = body[:len(body)-4]
	}

	return info, body, nil
}

func walkFields(buf []byte, hdrLen, off int, bitmaps []uint32, info *RadiotapInfo) error {
	// Namespace handling: a vendor namespace suppresses interpretation of subsequent bits
	// until the next radiotap-namespace marker. WARP does not consume vendor data, so it is
	// skipped, but the walk must still track it or the offsets drift.
	inVendorNS := false

	for word, bm := range bitmaps {
		for bit := 0; bit < 32; bit++ {
			if bm&(1<<uint(bit)) == 0 {
				continue
			}

			switch bit {
			case bitExt:
				continue
			case bitRadiotapNS:
				inVendorNS = false
				continue
			case bitVendorNS:
				// OUI(3) + sub-namespace(1) + skip length(2), aligned to 2.
				var err error
				off, err = align(off, 2)
				if err != nil {
					return err
				}
				if off+6 > hdrLen {
					return fmt.Errorf("capture: vendor namespace runs past the header")
				}
				skip := int(binary.LittleEndian.Uint16(buf[off+4 : off+6]))
				off += 6 + skip
				if off > hdrLen {
					return fmt.Errorf("capture: vendor namespace skip runs past the header")
				}
				inVendorNS = true
				continue
			}

			// Bits in a vendor namespace, and bits past the first word that WARP has no
			// layout for, cannot be walked: their sizes are unknown, so any field after them
			// would be misaligned. Stop rather than decode garbage.
			layout, known := fieldLayout[bit]
			if inVendorNS || !known || word > 0 {
				return fmt.Errorf("capture: cannot walk radiotap bit %d (word %d)", bit, word)
			}

			var err error
			off, err = align(off, layout.align)
			if err != nil {
				return err
			}
			if off+layout.size > hdrLen {
				return fmt.Errorf("capture: radiotap field %d runs past the header", bit)
			}

			decodeField(bit, buf[off:off+layout.size], info)
			off += layout.size
		}
	}
	return nil
}

func decodeField(bit int, b []byte, info *RadiotapInfo) {
	switch bit {
	case bitTSFT:
		info.TSFT = binary.LittleEndian.Uint64(b)
		info.HasTSFT = true

	case bitFlags:
		info.Flags = b[0]
		info.HasFCS = b[0]&flagFCS != 0
		info.BadFCS = b[0]&flagBadFCS != 0
		info.DataPad = b[0]&flagDataPad != 0

	case bitRate:
		// Reported in 500 kbps units.
		info.RateKbps = int(b[0]) * 500

	case bitChannel:
		info.Freq = int(binary.LittleEndian.Uint16(b[0:2]))
		info.ChannelFlags = binary.LittleEndian.Uint16(b[2:4])

	case bitDBMAntSignal:
		info.SignalDBM = int8(b[0])
		info.HasSignal = true

	case bitDBMAntNoise:
		info.NoiseDBM = int8(b[0])
		info.HasNoise = true

	case bitAntenna:
		info.Antenna = b[0]
		info.HasAntenna = true

	case bitXChannel:
		// XCHANNEL repeats the frequency with a wider flag word. Prefer it only when the
		// standard CHANNEL field was absent.
		if info.Freq == 0 {
			info.Freq = int(binary.LittleEndian.Uint16(b[4:6]))
		}

	case bitMCS:
		known, mcs := b[0], b[2]
		if known&0x02 != 0 { // MCS index is known
			info.MCS = mcs
			info.HasMCS = true
		}
	}
}

// align advances off to the next multiple of a.
func align(off, a int) (int, error) {
	if a <= 0 {
		return off, fmt.Errorf("capture: invalid radiotap alignment %d", a)
	}
	if rem := off % a; rem != 0 {
		off += a - rem
	}
	return off, nil
}

// StripDataPad removes the padding some drivers insert to align the 802.11 payload to a
// 32-bit boundary. hdrLen is the length of the 802.11 MAC header.
func StripDataPad(frame []byte, hdrLen int, padded bool) []byte {
	if !padded {
		return frame
	}
	pad := (4 - hdrLen%4) % 4
	if pad == 0 || len(frame) < hdrLen+pad {
		return frame
	}
	// Splice the padding out from between the header and the body.
	out := make([]byte, 0, len(frame)-pad)
	out = append(out, frame[:hdrLen]...)
	out = append(out, frame[hdrLen+pad:]...)
	return out
}
