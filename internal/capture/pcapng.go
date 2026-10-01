package capture

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"time"
)

// pcapng block types (PCAP Next Generation, draft-tuexen-opsawg-pcapng).
const (
	blockSectionHeader   uint32 = 0x0A0D0D0A
	blockInterfaceDesc   uint32 = 0x00000001
	blockEnhancedPacket  uint32 = 0x00000006
	byteOrderMagic       uint32 = 0x1A2B3C4D
	sectionLengthUnknown uint64 = 0xFFFFFFFFFFFFFFFF
)

// LinkTypeRadiotap is LINKTYPE_IEEE802_11_RADIOTAP. Frames are stored with their radiotap
// header intact so signal and channel information survives into the archive.
const LinkTypeRadiotap uint16 = 127

// Option codes.
const (
	optEndOfOpt      uint16 = 0
	optComment       uint16 = 1
	optSHBHardware   uint16 = 2
	optSHBOS         uint16 = 3
	optSHBUserAppl   uint16 = 4
	optIfName        uint16 = 2
	optIfDescription uint16 = 3
	optIfTSResol     uint16 = 9
)

// DefaultSnapLen is 0: capture whole frames. Management frames are small and truncating one
// loses the information elements the fingerprint depends on.
const DefaultSnapLen uint32 = 0

// PcapngWriter writes captured frames to a pcapng file.
//
// Raw capture runs continuously alongside parsing so that a parser bug does not lose an
// engagement's data. Engagements run under a week and disk is not a constraint, so there is
// no rotation or duty-cycling: the file is simply appended to for the duration.
type PcapngWriter struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer

	interfaces  map[string]uint32
	nextIfaceID uint32
	frames      uint64
	bytes       uint64
}

// NewPcapngWriter creates a pcapng file and writes its section header.
func NewPcapngWriter(path, appName string) (*PcapngWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("capture: create %s: %w", path, err)
	}

	p := &PcapngWriter{
		f:          f,
		w:          bufio.NewWriterSize(f, 1<<20),
		interfaces: make(map[string]uint32),
	}
	if err := p.writeSectionHeader(appName); err != nil {
		f.Close()
		return nil, err
	}
	return p, nil
}

func (p *PcapngWriter) writeSectionHeader(appName string) error {
	body := make([]byte, 0, 64)
	body = binary.LittleEndian.AppendUint32(body, byteOrderMagic)
	body = binary.LittleEndian.AppendUint16(body, 1) // major
	body = binary.LittleEndian.AppendUint16(body, 0) // minor
	body = binary.LittleEndian.AppendUint64(body, sectionLengthUnknown)

	body = appendOption(body, optSHBOS, []byte("linux"))
	body = appendOption(body, optSHBUserAppl, []byte(appName))
	body = appendOption(body, optEndOfOpt, nil)

	return p.writeBlock(blockSectionHeader, body)
}

// AddInterface registers a capture interface and returns its pcapng interface ID.
//
// Each radio gets its own interface record so that, when frames from several adapters land in
// one file, a reader can still tell which radio heard what. RSSI is not comparable across
// radios, so losing that attribution would make the archive far less useful than it looks.
func (p *PcapngWriter) AddInterface(name, description string) (uint32, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if id, ok := p.interfaces[name]; ok {
		return id, nil
	}

	body := make([]byte, 0, 64)
	body = binary.LittleEndian.AppendUint16(body, LinkTypeRadiotap)
	body = binary.LittleEndian.AppendUint16(body, 0) // reserved
	body = binary.LittleEndian.AppendUint32(body, DefaultSnapLen)

	body = appendOption(body, optIfName, []byte(name))
	if description != "" {
		body = appendOption(body, optIfDescription, []byte(description))
	}
	// Timestamps are microseconds since the epoch.
	body = appendOption(body, optIfTSResol, []byte{6})
	body = appendOption(body, optEndOfOpt, nil)

	if err := p.writeBlock(blockInterfaceDesc, body); err != nil {
		return 0, err
	}

	id := p.nextIfaceID
	p.interfaces[name] = id
	p.nextIfaceID++
	return id, nil
}

// WriteFrame appends one captured frame, including its radiotap header.
func (p *PcapngWriter) WriteFrame(ifaceID uint32, ts time.Time, frame []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	usec := uint64(ts.UnixMicro())

	body := make([]byte, 0, 20+len(frame)+4)
	body = binary.LittleEndian.AppendUint32(body, ifaceID)
	body = binary.LittleEndian.AppendUint32(body, uint32(usec>>32))
	body = binary.LittleEndian.AppendUint32(body, uint32(usec))
	body = binary.LittleEndian.AppendUint32(body, uint32(len(frame))) // captured length
	body = binary.LittleEndian.AppendUint32(body, uint32(len(frame))) // original length
	body = append(body, frame...)
	body = pad32(body)

	if err := p.writeBlock(blockEnhancedPacket, body); err != nil {
		return err
	}
	p.frames++
	p.bytes += uint64(len(frame))
	return nil
}

// writeBlock frames a body with the block type and the duplicated total-length fields.
func (p *PcapngWriter) writeBlock(blockType uint32, body []byte) error {
	total := uint32(12 + len(body))

	hdr := make([]byte, 0, 8)
	hdr = binary.LittleEndian.AppendUint32(hdr, blockType)
	hdr = binary.LittleEndian.AppendUint32(hdr, total)
	if _, err := p.w.Write(hdr); err != nil {
		return fmt.Errorf("capture: write pcapng block header: %w", err)
	}
	if _, err := p.w.Write(body); err != nil {
		return fmt.Errorf("capture: write pcapng block body: %w", err)
	}

	trailer := binary.LittleEndian.AppendUint32(nil, total)
	if _, err := p.w.Write(trailer); err != nil {
		return fmt.Errorf("capture: write pcapng block trailer: %w", err)
	}
	return nil
}

// Flush pushes buffered frames to the file.
//
// The buffer is a throughput concession - fsyncing every frame on a busy channel is not
// viable. The archive is the backstop for a parser bug, not the primary record: hashes and
// the store are written synchronously elsewhere, so losing the last buffered frames to a
// power cut costs a fraction of a second of raw capture, not an engagement.
func (p *PcapngWriter) Flush() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.w.Flush(); err != nil {
		return fmt.Errorf("capture: flush pcapng: %w", err)
	}
	return nil
}

// Stats returns how much has been captured.
func (p *PcapngWriter) Stats() (frames, bytes uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.frames, p.bytes
}

// Close flushes and closes the file.
func (p *PcapngWriter) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.f == nil {
		return nil
	}
	if err := p.w.Flush(); err != nil {
		p.f.Close()
		p.f = nil
		return fmt.Errorf("capture: flush pcapng: %w", err)
	}
	err := p.f.Close()
	p.f = nil
	if err != nil {
		return fmt.Errorf("capture: close pcapng: %w", err)
	}
	return nil
}

// appendOption appends a pcapng option, padded to a 4-byte boundary.
func appendOption(b []byte, code uint16, value []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, code)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(value)))
	b = append(b, value...)
	return pad32(b)
}

// pad32 pads to the next 4-byte boundary.
func pad32(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}
