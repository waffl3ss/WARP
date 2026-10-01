package inject

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/scope"
)

// Injector transmits frames on a monitor-mode interface.
//
// Construction requires a scope gate. That is not a convention - an Injector cannot be built
// without one, so a future attack module physically cannot skip authorization by forgetting
// to call the gate.
type Injector struct {
	fd      int
	ifname  string
	radioID string

	gate *scope.Gate

	seq    atomic.Uint32
	sent   atomic.Uint64
	denied atomic.Uint64

	mu     sync.Mutex
	closed bool
}

// ErrClosed is returned once an injector has been closed.
var ErrClosed = errors.New("inject: injector is closed")

// Open binds a transmit socket to a monitor-mode interface.
//
// The interface must already be in monitor mode with injection empirically verified - the
// scheduler will not hand out a transmitting role on an adapter whose injection has not been
// demonstrated, because the capability bitmap lies on several common chipsets.
func Open(ifname string, ifindex int, radioID string, gate *scope.Gate) (*Injector, error) {
	if gate == nil {
		return nil, errors.New("inject: refusing to build an injector with no scope gate")
	}

	proto := int(htons(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		if errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("inject: open transmit socket on %s: permission denied "+
				"(CAP_NET_ADMIN required - run warpd as root): %w", ifname, err)
		}
		return nil, fmt.Errorf("inject: open transmit socket on %s: %w", ifname, err)
	}

	addr := &unix.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: ifindex}
	if err := unix.Bind(fd, addr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("inject: bind to %s: %w", ifname, err)
	}

	return &Injector{fd: fd, ifname: ifname, radioID: radioID, gate: gate}, nil
}

// Request describes an authorized transmission.
type Request struct {
	// Module names the attack for the audit log.
	Module string
	// BSSID is the discovered target. Never a configured value.
	BSSID recon.MAC
	// ESSID is the network name observed at that BSSID. Authorization is decided on this.
	ESSID   string
	Channel int
	// Decloak routes the request to Gate.AuthorizeDecloak instead, which decides on the
	// operator's recorded confirmation at BSSID because a cloaked network has no name to
	// decide on. Exactly one caller sets it; see the gate method for why it exists.
	Decloak bool
}

// authorize runs req past the gate. The choice of method is here rather than at the call sites
// so that Send and Burst cannot drift apart on which requests get which decision.
func (i *Injector) authorize(ctx context.Context, req Request) error {
	if req.Decloak {
		return i.gate.AuthorizeDecloak(ctx, req.Module, req.BSSID.String(), req.ESSID,
			req.Channel, i.radioID)
	}
	return i.gate.AuthorizeTransmit(ctx, scope.Request{
		Module:  req.Module,
		BSSID:   req.BSSID.String(),
		ESSID:   req.ESSID,
		Channel: req.Channel,
		RadioID: i.radioID,
	})
}

// Send transmits a frame after clearing it with the scope gate.
//
// Every frame goes through here. The gate returns an error rather than a bool precisely so
// that a caller who ignores the result cannot transmit.
func (i *Injector) Send(ctx context.Context, req Request, frame []byte) error {
	if err := i.authorize(ctx, req); err != nil {
		i.denied.Add(1)
		return err
	}
	return i.sendUnauthorized(frame)
}

// sendUnauthorized writes a frame to the wire.
//
// Named to be uncomfortable to call. It exists because Send has already made the
// authorization decision and re-checking inside a burst loop would spam the audit log with
// hundreds of identical records for one operator action. Nothing outside this file may call
// it, and every caller must be inside a Send-authorized burst.
func (i *Injector) sendUnauthorized(frame []byte) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return ErrClosed
	}
	if _, err := unix.Write(i.fd, frame); err != nil {
		switch {
		case errors.Is(err, unix.ENETDOWN):
			return fmt.Errorf("inject: %s went down: %w", i.ifname, err)
		case errors.Is(err, unix.EMSGSIZE):
			return fmt.Errorf("inject: frame of %d bytes is too large for %s: %w",
				len(frame), i.ifname, err)
		}
		return fmt.Errorf("inject: transmit on %s: %w", i.ifname, err)
	}
	i.sent.Add(1)
	return nil
}

// NextSeq returns the next 802.11 sequence number.
func (i *Injector) NextSeq() uint16 {
	return uint16(i.seq.Add(1) & 0x0FFF)
}

// RadioID returns the adapter this injector transmits from.
func (i *Injector) RadioID() string { return i.radioID }

// Ifname returns the interface this injector transmits on.
func (i *Injector) Ifname() string { return i.ifname }

// Stats reports transmit counters.
type Stats struct {
	Sent   uint64 `json:"sent"`
	Denied uint64 `json:"denied_by_scope"`
}

// Stats returns the injector's counters.
//
// Denied is surfaced rather than hidden: a rising count means a module is repeatedly trying
// to transmit at something outside scope, which is a bug worth seeing.
func (i *Injector) Stats() Stats {
	return Stats{Sent: i.sent.Load(), Denied: i.denied.Load()}
}

// Close releases the socket. Safe to call more than once.
func (i *Injector) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.closed {
		return nil
	}
	i.closed = true
	if err := unix.Close(i.fd); err != nil {
		return fmt.Errorf("inject: close %s: %w", i.ifname, err)
	}
	return nil
}

// BurstOptions controls a repeated transmission.
type BurstOptions struct {
	// Count is how many frames to send.
	Count int
	// Interval is the delay between frames.
	Interval time.Duration
}

func (o BurstOptions) withDefaults() BurstOptions {
	if o.Count <= 0 {
		// Eight rather than four. A single pair of frames is regularly ignored - lost to a
		// collision, or arriving while the client is mid-transmit - and a burst that fails to
		// move the client produces a false negative that reads as a resilient network.
		o.Count = 8
	}
	if o.Interval <= 0 {
		o.Interval = 20 * time.Millisecond
	}
	return o
}

// Burst authorizes once and then transmits the frames produced by build.
//
// Authorization is checked once per burst rather than per frame: a burst is one operator
// action, and writing one audit record per action keeps the evidence log readable. Writing
// hundreds of identical records per deauthentication would make the log useless as evidence,
// which is the opposite of the point.
func (i *Injector) Burst(ctx context.Context, req Request, opts BurstOptions, build func(seq uint16) []byte) (int, error) {
	opts = opts.withDefaults()

	if err := i.authorize(ctx, req); err != nil {
		i.denied.Add(1)
		return 0, err
	}

	sent := 0
	for n := 0; n < opts.Count; n++ {
		if err := ctx.Err(); err != nil {
			return sent, err
		}
		if err := i.sendUnauthorized(build(i.NextSeq())); err != nil {
			return sent, err
		}
		sent++

		if n+1 < opts.Count {
			select {
			case <-ctx.Done():
				return sent, ctx.Err()
			case <-time.After(opts.Interval):
			}
		}
	}
	return sent, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
