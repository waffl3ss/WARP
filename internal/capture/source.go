package capture

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Capture buffer sizing.
const (
	// maxFrameSize bounds one read. 802.11 frames top out well below this; the headroom
	// covers A-MSDU aggregation and a generous radiotap header.
	maxFrameSize = 8192

	// rcvBufBytes is the kernel receive buffer. A busy channel bursts hard, and the default
	// buffer drops frames silently - which on an engagement means a handshake that was in the
	// air and never reached the parser.
	rcvBufBytes = 8 << 20

	// readTimeout bounds how long a read blocks, so cancellation is observed promptly during
	// teardown rather than hanging until the next frame arrives.
	readTimeout = 250 * time.Millisecond
)

// Frame is one captured 802.11 frame with its radio metadata.
type Frame struct {
	// Raw is the complete buffer including the radiotap header, as written to the pcapng
	// archive.
	Raw []byte
	// Radiotap is the parsed radio metadata.
	Radiotap RadiotapInfo
	// Body is the 802.11 frame with the radiotap header removed and any FCS stripped.
	Body []byte
	// At is when the frame was read.
	At time.Time
	// RadioID identifies the adapter that heard it. Stamped on every observation because
	// RSSI is not comparable across radios.
	RadioID string
}

// Stats counts what a source has seen.
//
// Dropped frames are surfaced rather than hidden: a rising drop count means the channel is
// busier than the capture path can keep up with, and the operator needs to know that before
// concluding a network is quiet.
type Stats struct {
	Frames     uint64 `json:"frames"`
	Bytes      uint64 `json:"bytes"`
	BadFCS     uint64 `json:"bad_fcs"`
	ParseError uint64 `json:"parse_errors"`
	Dropped    uint64 `json:"dropped"`
}

// Source reads frames from a monitor-mode interface.
type Source struct {
	fd      int
	ifname  string
	radioID string

	frames     atomic.Uint64
	bytes      atomic.Uint64
	badFCS     atomic.Uint64
	parseError atomic.Uint64
	dropped    atomic.Uint64

	closed atomic.Bool
}

// ErrClosed is returned once a source has been closed.
var ErrClosed = errors.New("capture: source is closed")

// Open binds an AF_PACKET socket to a monitor-mode interface.
//
// Requires CAP_NET_ADMIN. The interface must already be in monitor mode and tuned - this
// package reads frames, it does not configure radios. That belongs to internal/radio, and
// keeping it there is what stops interface names leaking into the rest of the tool.
func Open(ifname string, ifindex int, radioID string) (*Source, error) {
	// ETH_P_ALL in network byte order, as the kernel expects for AF_PACKET.
	proto := int(htons(unix.ETH_P_ALL))

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("capture: open raw socket on %s: permission denied "+
				"(CAP_NET_ADMIN required - run warpd as root): %w", ifname, err)
		}
		return nil, fmt.Errorf("capture: open raw socket on %s: %w", ifname, err)
	}

	// Bind to this interface only. Without the bind the socket would receive from every
	// interface on the host, which on a multi-radio box silently mixes radios together and
	// destroys RSSI attribution.
	addr := &unix.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: ifindex}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("capture: bind to %s: %w", ifname, err)
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvBufBytes); err != nil {
		// Not fatal: a smaller buffer still works, it just drops more under load.
		_ = err
	}
	tv := unix.NsecToTimeval(int64(readTimeout))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("capture: set receive timeout on %s: %w", ifname, err)
	}

	return &Source{fd: fd, ifname: ifname, radioID: radioID}, nil
}

// Read returns the next frame.
//
// It returns (nil, nil) when the read timed out with no frame, which lets the caller check
// for cancellation without treating a quiet channel as an error.
func (s *Source) Read(buf []byte) (*Frame, error) {
	if s.closed.Load() {
		return nil, ErrClosed
	}
	if len(buf) < maxFrameSize {
		return nil, fmt.Errorf("capture: read buffer is %d bytes, need at least %d", len(buf), maxFrameSize)
	}

	n, _, err := unix.Recvfrom(s.fd, buf, 0)
	if err != nil {
		switch {
		case errors.Is(err, unix.EAGAIN), errors.Is(err, unix.EWOULDBLOCK), errors.Is(err, unix.EINTR):
			return nil, nil // timed out or interrupted; not an error
		case errors.Is(err, unix.EBADF), errors.Is(err, unix.ENOTSOCK):
			return nil, ErrClosed
		case errors.Is(err, unix.ENETDOWN):
			// The adapter was unplugged or rfkilled mid-run. Report it plainly rather than
			// spinning: the scheduler needs to know the radio is gone.
			return nil, fmt.Errorf("capture: interface %s went down: %w", s.ifname, err)
		}
		return nil, fmt.Errorf("capture: read from %s: %w", s.ifname, err)
	}
	if n == 0 {
		return nil, nil
	}

	at := time.Now()
	s.frames.Add(1)
	s.bytes.Add(uint64(n))

	raw := buf[:n]
	info, body, err := ParseRadiotap(raw)
	if err != nil {
		s.parseError.Add(1)
		return nil, nil
	}
	if info.BadFCS {
		// The driver already told us the frame is corrupt. Parsing it would produce
		// plausible-looking garbage: invented BSSIDs, wrong ESSIDs.
		s.badFCS.Add(1)
		return nil, nil
	}

	return &Frame{
		Raw:      raw,
		Radiotap: info,
		Body:     body,
		At:       at,
		RadioID:  s.radioID,
	}, nil
}

// Run reads frames until ctx is cancelled, passing each to fn.
//
// The buffer handed to fn is reused between calls. A consumer that retains any part of a
// frame past the callback must copy it.
func (s *Source) Run(ctx context.Context, fn func(*Frame) error) error {
	buf := make([]byte, maxFrameSize)

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		frame, err := s.Read(buf)
		if err != nil {
			if errors.Is(err, ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		if frame == nil {
			continue
		}
		if err := fn(frame); err != nil {
			return err
		}
	}
}

// Stats returns the source's counters, including kernel-reported drops.
func (s *Source) Stats() Stats {
	st := Stats{
		Frames:     s.frames.Load(),
		Bytes:      s.bytes.Load(),
		BadFCS:     s.badFCS.Load(),
		ParseError: s.parseError.Load(),
		Dropped:    s.dropped.Load(),
	}
	if drops, err := s.kernelDrops(); err == nil {
		st.Dropped = drops
	}
	return st
}

// kernelDrops reads and clears the kernel's drop counter for this socket.
//
// Reading is destructive - the kernel zeroes the counter - so the value is accumulated rather
// than reported raw.
func (s *Source) kernelDrops() (uint64, error) {
	if s.closed.Load() {
		return s.dropped.Load(), nil
	}
	stats, err := unix.GetsockoptTpacketStats(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return 0, err
	}
	if stats.Drops > 0 {
		s.dropped.Add(uint64(stats.Drops))
	}
	return s.dropped.Load(), nil
}

// Ifname returns the interface this source reads from.
func (s *Source) Ifname() string { return s.ifname }

// RadioID returns the adapter identifier stamped on frames from this source.
func (s *Source) RadioID() string { return s.radioID }

// Close releases the socket. Safe to call more than once.
func (s *Source) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	if err := unix.Close(s.fd); err != nil {
		return fmt.Errorf("capture: close %s: %w", s.ifname, err)
	}
	return nil
}

// htons converts a uint16 to network byte order.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
