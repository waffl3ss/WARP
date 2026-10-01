package capture

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPcapngStructure verifies the file against the block layout every reader expects.
// The archive is the backstop for a parser bug, so a file Wireshark cannot open is worthless
// exactly when it is needed most.
func TestPcapngStructure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")

	w, err := NewPcapngWriter(path, "warp/test")
	if err != nil {
		t.Fatalf("NewPcapngWriter: %v", err)
	}

	id, err := w.AddInterface("mon0", "phy0 survey")
	if err != nil {
		t.Fatalf("AddInterface: %v", err)
	}
	if id != 0 {
		t.Errorf("first interface ID = %d, want 0", id)
	}

	frame := append([]byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}, 0x80, 0x00, 0xAA)
	ts := time.Unix(1772000000, 123456000)
	if err := w.WriteFrame(id, ts, frame); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	blocks := walkBlocks(t, data)
	if len(blocks) != 3 {
		t.Fatalf("got %d blocks, want 3 (SHB, IDB, EPB)", len(blocks))
	}

	if blocks[0].typ != blockSectionHeader {
		t.Errorf("block 0 type = %#x, want section header", blocks[0].typ)
	}
	if magic := binary.LittleEndian.Uint32(blocks[0].body[0:4]); magic != byteOrderMagic {
		t.Errorf("byte-order magic = %#x", magic)
	}

	if blocks[1].typ != blockInterfaceDesc {
		t.Errorf("block 1 type = %#x, want interface description", blocks[1].typ)
	}
	if lt := binary.LittleEndian.Uint16(blocks[1].body[0:2]); lt != LinkTypeRadiotap {
		t.Errorf("link type = %d, want %d (radiotap)", lt, LinkTypeRadiotap)
	}

	epb := blocks[2]
	if epb.typ != blockEnhancedPacket {
		t.Fatalf("block 2 type = %#x, want enhanced packet", epb.typ)
	}
	if got := binary.LittleEndian.Uint32(epb.body[0:4]); got != 0 {
		t.Errorf("interface ID = %d, want 0", got)
	}

	// Timestamp is a 64-bit microsecond count split across two 32-bit fields.
	high := uint64(binary.LittleEndian.Uint32(epb.body[4:8]))
	low := uint64(binary.LittleEndian.Uint32(epb.body[8:12]))
	if got, want := high<<32|low, uint64(ts.UnixMicro()); got != want {
		t.Errorf("timestamp = %d, want %d", got, want)
	}

	capLen := binary.LittleEndian.Uint32(epb.body[12:16])
	origLen := binary.LittleEndian.Uint32(epb.body[16:20])
	if int(capLen) != len(frame) || int(origLen) != len(frame) {
		t.Errorf("lengths = %d/%d, want %d", capLen, origLen, len(frame))
	}
	if !bytes.Equal(epb.body[20:20+len(frame)], frame) {
		t.Error("frame payload does not round-trip")
	}
}

type pcapngBlock struct {
	typ  uint32
	body []byte
}

// walkBlocks parses the file the way a reader would, asserting the duplicated total-length
// field agrees. A mismatch there is what makes a file unopenable.
func walkBlocks(t *testing.T, data []byte) []pcapngBlock {
	t.Helper()

	var out []pcapngBlock
	for off := 0; off < len(data); {
		if off+12 > len(data) {
			t.Fatalf("truncated block header at offset %d", off)
		}
		typ := binary.LittleEndian.Uint32(data[off : off+4])
		total := int(binary.LittleEndian.Uint32(data[off+4 : off+8]))

		if total < 12 || off+total > len(data) {
			t.Fatalf("block at %d claims %d bytes, %d remain", off, total, len(data)-off)
		}
		if total%4 != 0 {
			t.Errorf("block at %d has length %d, which is not 4-byte aligned", off, total)
		}

		trailer := int(binary.LittleEndian.Uint32(data[off+total-4 : off+total]))
		if trailer != total {
			t.Errorf("block at %d: trailing length %d does not match header %d", off, trailer, total)
		}

		out = append(out, pcapngBlock{typ: typ, body: data[off+8 : off+total-4]})
		off += total
	}
	return out
}

func TestPcapngMultipleInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	w, _ := NewPcapngWriter(path, "warp/test")
	defer w.Close()

	// Each radio gets its own interface record, so frames stay attributable when several
	// adapters write to one file. RSSI is meaningless without knowing which radio heard it.
	id0, _ := w.AddInterface("mon0", "phy0")
	id1, _ := w.AddInterface("mon1", "phy1")
	if id0 == id1 {
		t.Fatalf("two interfaces got the same ID: %d", id0)
	}

	// Re-registering returns the existing ID rather than a duplicate record.
	again, _ := w.AddInterface("mon0", "phy0")
	if again != id0 {
		t.Errorf("re-registering mon0 returned %d, want %d", again, id0)
	}

	frame := []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00}
	w.WriteFrame(id0, time.Now(), frame)
	w.WriteFrame(id1, time.Now(), frame)
	w.Flush()

	frames, bytesWritten := w.Stats()
	if frames != 2 {
		t.Errorf("frames = %d, want 2", frames)
	}
	if bytesWritten != uint64(2*len(frame)) {
		t.Errorf("bytes = %d, want %d", bytesWritten, 2*len(frame))
	}
}

// TestPcapngPaddingKeepsAlignment: a frame whose length is not a multiple of four must still
// produce aligned blocks, or every following block is unreadable.
func TestPcapngPaddingKeepsAlignment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	w, _ := NewPcapngWriter(path, "warp/test")
	id, _ := w.AddInterface("mon0", "")

	// Lengths deliberately spanning every residue mod 4.
	for _, n := range []int{9, 10, 11, 12, 13} {
		frame := make([]byte, n)
		frame[2] = 0x08 // plausible radiotap length
		if err := w.WriteFrame(id, time.Now(), frame); err != nil {
			t.Fatalf("WriteFrame(%d bytes): %v", n, err)
		}
	}
	w.Close()

	data, _ := os.ReadFile(path)
	blocks := walkBlocks(t, data)
	if len(blocks) != 7 { // SHB + IDB + 5 packets
		t.Fatalf("got %d blocks, want 7", len(blocks))
	}
}

func TestPcapngFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	w, _ := NewPcapngWriter(path, "warp/test")
	defer w.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Raw capture contains client traffic.
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("capture file mode is %04o; group/other access must be denied", perm)
	}
}

func TestPcapngCloseIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.pcapng")
	w, _ := NewPcapngWriter(path, "warp/test")

	if err := w.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
