package capture

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// radiotapBuilder assembles a radiotap header field by field, honouring alignment, so tests
// state what they mean rather than carrying hand-computed byte offsets.
type radiotapBuilder struct {
	present uint32
	fields  []byte
}

func (b *radiotapBuilder) add(bit int, align int, data []byte) *radiotapBuilder {
	b.present |= 1 << uint(bit)
	// Alignment is relative to the start of the header: 8 bytes of preamble precede fields.
	for (8+len(b.fields))%align != 0 {
		b.fields = append(b.fields, 0)
	}
	b.fields = append(b.fields, data...)
	return b
}

func (b *radiotapBuilder) build(body []byte) []byte {
	hdrLen := 8 + len(b.fields)
	out := make([]byte, 8, hdrLen+len(body))
	out[0] = radiotapVersion
	binary.LittleEndian.PutUint16(out[2:4], uint16(hdrLen))
	binary.LittleEndian.PutUint32(out[4:8], b.present)
	out = append(out, b.fields...)
	return append(out, body...)
}

func u16le(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func TestParseRadiotapTypicalBeacon(t *testing.T) {
	body := []byte{0x80, 0x00, 0x00, 0x00} // beacon frame control + duration
	var b radiotapBuilder
	b.add(bitTSFT, 8, make([]byte, 8)).
		add(bitFlags, 1, []byte{0x00}).
		add(bitRate, 1, []byte{0x02}). // 1 Mbps
		add(bitChannel, 2, append(u16le(2437), u16le(chan2GHz|chanCCK)...)).
		add(bitDBMAntSignal, 1, []byte{0xC5}). // -59 dBm
		add(bitAntenna, 1, []byte{0x01})

	info, frame, err := ParseRadiotap(b.build(body))
	if err != nil {
		t.Fatalf("ParseRadiotap: %v", err)
	}

	if !info.HasSignal {
		t.Fatal("signal not reported")
	}
	if info.SignalDBM != -59 {
		t.Errorf("SignalDBM = %d, want -59", info.SignalDBM)
	}
	if info.Freq != 2437 {
		t.Errorf("Freq = %d, want 2437", info.Freq)
	}
	if !info.Band2GHz() || info.Band5GHz() {
		t.Errorf("band flags wrong: %#x", info.ChannelFlags)
	}
	if info.RateKbps != 1000 {
		t.Errorf("RateKbps = %d, want 1000", info.RateKbps)
	}
	if !info.HasTSFT {
		t.Error("TSFT not reported")
	}
	if string(frame) != string(body) {
		t.Errorf("frame body = % x, want % x", frame, body)
	}
}

// TestFCSIsStripped covers the bug that makes the last information element of every beacon
// look corrupt.
func TestFCSIsStripped(t *testing.T) {
	body := []byte{0x80, 0x00, 0xAA, 0xBB}
	fcs := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	var b radiotapBuilder
	b.add(bitFlags, 1, []byte{flagFCS}).
		add(bitDBMAntSignal, 1, []byte{0xC5})

	info, frame, err := ParseRadiotap(b.build(append(append([]byte{}, body...), fcs...)))
	if err != nil {
		t.Fatalf("ParseRadiotap: %v", err)
	}
	if !info.HasFCS {
		t.Fatal("HasFCS not set")
	}
	if len(frame) != len(body) {
		t.Fatalf("frame is %d bytes, want %d — FCS was not stripped", len(frame), len(body))
	}
	if string(frame) != string(body) {
		t.Errorf("frame = % x, want % x", frame, body)
	}
}

func TestBadFCSIsFlagged(t *testing.T) {
	var b radiotapBuilder
	b.add(bitFlags, 1, []byte{flagFCS | flagBadFCS})

	info, _, err := ParseRadiotap(b.build([]byte{0x80, 0x00, 0x00, 0x00, 0, 0, 0, 0}))
	if err != nil {
		t.Fatalf("ParseRadiotap: %v", err)
	}
	if !info.BadFCS {
		t.Error("BadFCS not reported; a corrupt frame would be parsed as real")
	}
}

// TestMissingSignalIsNotZero is the survey-correctness case: a driver that reports no signal
// must not yield 0 dBm, which reads as an extremely strong signal.
func TestMissingSignalIsNotZero(t *testing.T) {
	var b radiotapBuilder
	b.add(bitChannel, 2, append(u16le(5180), u16le(chan5GHz|chanOFDM)...))

	info, _, err := ParseRadiotap(b.build([]byte{0x80, 0x00}))
	if err != nil {
		t.Fatalf("ParseRadiotap: %v", err)
	}
	if info.HasSignal {
		t.Fatal("HasSignal set when the driver reported no antenna signal")
	}
	if !info.Band5GHz() {
		t.Errorf("5 GHz flag not set: %#x", info.ChannelFlags)
	}
}

// TestAlignmentIsHonoured is the regression test for the failure mode this parser exists to
// avoid: a misaligned field shifts everything after it, and the symptom is a plausible-looking
// wrong RSSI rather than an error.
func TestAlignmentIsHonoured(t *testing.T) {
	// FLAGS (1 byte, align 1) then TSFT (align 8) forces seven pad bytes, then CHANNEL
	// (align 2) and the signal after it. If alignment is ignored the signal reads as noise.
	var b radiotapBuilder
	b.add(bitTSFT, 8, []byte{1, 2, 3, 4, 5, 6, 7, 8}).
		add(bitFlags, 1, []byte{0x00}).
		add(bitChannel, 2, append(u16le(2412), u16le(chan2GHz)...)).
		add(bitDBMAntSignal, 1, []byte{0xB0}) // -80 dBm

	info, _, err := ParseRadiotap(b.build([]byte{0x80, 0x00}))
	if err != nil {
		t.Fatalf("ParseRadiotap: %v", err)
	}
	if info.TSFT != 0x0807060504030201 {
		t.Errorf("TSFT = %#x, misaligned", info.TSFT)
	}
	if info.Freq != 2412 {
		t.Errorf("Freq = %d, want 2412 — fields are misaligned", info.Freq)
	}
	if info.SignalDBM != -80 {
		t.Errorf("SignalDBM = %d, want -80 — fields are misaligned", info.SignalDBM)
	}
}

func TestMCSField(t *testing.T) {
	var b radiotapBuilder
	b.add(bitDBMAntSignal, 1, []byte{0xC5}).
		add(bitMCS, 1, []byte{0x02, 0x00, 0x07}) // known=MCS index, mcs=7

	info, _, err := ParseRadiotap(b.build([]byte{0x80, 0x00}))
	if err != nil {
		t.Fatalf("ParseRadiotap: %v", err)
	}
	if !info.HasMCS || info.MCS != 7 {
		t.Errorf("MCS = %d (has=%v), want 7", info.MCS, info.HasMCS)
	}
}

// TestAnUnwalkableFieldKeepsWhatCameBeforeIt.
//
// This is the shape of header a real driver emits: an extended present bitmap whose second
// word sets bits nothing has a layout for. The walk cannot continue past that — the sizes are
// unknown, so every later offset would be wrong — but the fields decoded before it were read
// at correct offsets and are valid.
//
// Discarding the signal here was a silent, total failure of RSSI on any adapter emitting an
// extended bitmap: no error, no log line, just an empty signal column, a hunt with no gradient
// to walk, and localisation with nothing to rank. Signal is bit 5 and is always decoded long
// before whatever stops the walk.
func TestAnUnwalkableFieldKeepsWhatCameBeforeIt(t *testing.T) {
	// Word 0: FLAGS, CHANNEL, dBm ANTSIGNAL, ANTENNA, RX_FLAGS, plus the ext bit.
	// Word 1: an undefined bit, which is where the walk has to stop.
	const hdrLen = 22
	buf := make([]byte, hdrLen+4)
	buf[0] = radiotapVersion
	binary.LittleEndian.PutUint16(buf[2:4], hdrLen)
	binary.LittleEndian.PutUint32(buf[4:8],
		(1<<bitFlags)|(1<<bitChannel)|(1<<bitDBMAntSignal)|
			(1<<bitAntenna)|(1<<bitRXFlags)|(1<<bitExt))
	binary.LittleEndian.PutUint32(buf[8:12], 1<<0) // undefined bit in word 1

	buf[12] = 0x00                                    // FLAGS
	binary.LittleEndian.PutUint16(buf[14:16], 2437)   // CHANNEL freq (aligned to 2)
	binary.LittleEndian.PutUint16(buf[16:18], 0x00a0) // CHANNEL flags: 2 GHz + OFDM
	buf[18] = byte(0xCC)                              // dBm ANTSIGNAL: int8(-52)
	buf[19] = 0x01                                    // ANTENNA
	binary.LittleEndian.PutUint16(buf[20:22], 0)      // RX_FLAGS
	copy(buf[hdrLen:], []byte{0x80, 0x00, 0x00, 0x00})

	info, frame, err := ParseRadiotap(buf)
	if err != nil {
		t.Fatalf("ParseRadiotap should recover, got: %v", err)
	}
	if !info.Partial {
		t.Error("the walk stopped early but the result is not marked partial")
	}
	if !info.HasSignal {
		t.Fatal("the antenna signal was discarded even though it was decoded before the stop")
	}
	if info.SignalDBM != -52 {
		t.Errorf("SignalDBM = %d, want -52", info.SignalDBM)
	}
	if info.Freq != 2437 {
		t.Errorf("Freq = %d, want 2437", info.Freq)
	}
	if !info.Band2GHz() {
		t.Error("channel flags were lost")
	}
	if len(frame) != 4 {
		t.Errorf("frame body length = %d, want 4 — header length should still be usable", len(frame))
	}
}

// TestAFieldThatDoesNotFitIsNotInvented. The walk stopping is recoverable; reading past the
// header is not, and must never produce a signal.
func TestAFieldThatDoesNotFitIsNotInvented(t *testing.T) {
	const hdrLen = 12
	buf := make([]byte, hdrLen+4)
	buf[0] = radiotapVersion
	binary.LittleEndian.PutUint16(buf[2:4], hdrLen)
	// Claims a signal field, but the header ends where it would start.
	binary.LittleEndian.PutUint32(buf[4:8], (1<<bitExt)|(1<<bitDBMAntSignal))
	binary.LittleEndian.PutUint32(buf[8:12], 0)
	copy(buf[hdrLen:], []byte{0x80, 0x00, 0x00, 0x00})

	info, frame, err := ParseRadiotap(buf)
	if err != nil {
		t.Fatalf("ParseRadiotap should recover, got: %v", err)
	}
	if info.HasSignal {
		t.Error("a signal was reported from bytes past the end of the header")
	}
	if len(frame) != 4 {
		t.Errorf("frame body length = %d, want 4", len(frame))
	}
}

func TestMalformedHeaders(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want error
	}{
		{"empty", nil, ErrShortRadiotap},
		{"truncated preamble", []byte{0, 0, 8}, ErrShortRadiotap},
		{"bad version", []byte{99, 0, 8, 0, 0, 0, 0, 0}, ErrRadiotapVersion},
		{"length past buffer", []byte{0, 0, 0xFF, 0xFF, 0, 0, 0, 0}, ErrRadiotapLength},
		{"length below minimum", []byte{0, 0, 4, 0, 0, 0, 0, 0}, ErrRadiotapLength},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := ParseRadiotap(tc.buf)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestBitmapChainIsBounded guards against a malformed header that chains present words
// forever.
func TestBitmapChainIsBounded(t *testing.T) {
	hdrLen := 8 + 4*40
	buf := make([]byte, hdrLen)
	buf[0] = radiotapVersion
	binary.LittleEndian.PutUint16(buf[2:4], uint16(hdrLen))
	for off := 4; off+4 <= hdrLen; off += 4 {
		binary.LittleEndian.PutUint32(buf[off:off+4], 1<<bitExt)
	}
	if _, _, err := ParseRadiotap(buf); err == nil {
		t.Fatal("an unbounded present-bitmap chain was accepted")
	}
}

func TestStripDataPad(t *testing.T) {
	// A 26-byte QoS data header pads by 2 to reach a 32-bit boundary.
	hdr := make([]byte, 26)
	for i := range hdr {
		hdr[i] = byte(i)
	}
	payload := []byte{0xAA, 0xAA, 0x03}
	frame := append(append(append([]byte{}, hdr...), 0x00, 0x00), payload...)

	out := StripDataPad(frame, 26, true)
	if len(out) != len(hdr)+len(payload) {
		t.Fatalf("length = %d, want %d", len(out), len(hdr)+len(payload))
	}
	if string(out[26:]) != string(payload) {
		t.Errorf("payload = % x, want % x", out[26:], payload)
	}

	// A 24-byte header is already aligned, so nothing is removed.
	frame24 := append(make([]byte, 24), payload...)
	if got := StripDataPad(frame24, 24, true); len(got) != len(frame24) {
		t.Errorf("an already-aligned header was modified")
	}
	// And with the flag clear, nothing is touched.
	if got := StripDataPad(frame, 26, false); len(got) != len(frame) {
		t.Errorf("padding was removed when DataPad was not set")
	}
}

// TestRealWorldHeader parses a header captured from an ath9k adapter, as a check that the
// table matches what drivers actually emit rather than only what the test builder emits.
func TestRealWorldHeader(t *testing.T) {
	// present=0x0000482e selects FLAGS|RATE|CHANNEL|DBM_ANTSIGNAL|ANTENNA|RX_FLAGS.
	//
	// Field offsets, counting from the start of the header:
	//   8  FLAGS          align 1, 1 byte
	//   9  RATE           align 1, 1 byte
	//   10 CHANNEL        align 2, 4 bytes  (already even, no pad)
	//   14 DBM_ANTSIGNAL  align 1, 1 byte
	//   15 ANTENNA        align 1, 1 byte
	//   16 RX_FLAGS       align 2, 2 bytes  (already even, no pad)
	//   18 end of header
	raw, err := hex.DecodeString(
		"000012002e480000" + // version, pad, len=18, present
			"00" + // FLAGS = 0
			"02" + // RATE = 1 Mbps (500 kbps units)
			"6c09a000" + // CHANNEL: 2412 MHz, flags 0x00a0 (2GHz|CCK)
			"c9" + // DBM_ANTSIGNAL = -55
			"00" + // ANTENNA
			"0000" + // RX_FLAGS
			"8000000000000000000000000000000000000000000000000000", // beacon body
	)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	info, frame, err := ParseRadiotap(raw)
	if err != nil {
		t.Fatalf("ParseRadiotap: %v", err)
	}
	if info.Length != 18 {
		t.Errorf("Length = %d, want 18", info.Length)
	}
	if info.Freq != 2412 {
		t.Errorf("Freq = %d, want 2412", info.Freq)
	}
	if !info.HasSignal || info.SignalDBM != -55 {
		t.Errorf("SignalDBM = %d (has=%v), want -55", info.SignalDBM, info.HasSignal)
	}
	if info.RateKbps != 1000 {
		t.Errorf("RateKbps = %d, want 1000", info.RateKbps)
	}
	if len(frame) == 0 || frame[0] != 0x80 {
		t.Errorf("frame body does not start with a beacon: % x", frame)
	}
}
