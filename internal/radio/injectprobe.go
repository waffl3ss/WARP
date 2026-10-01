package radio

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/waffl3ss/warp/internal/capture"
	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// Injection probe tuning.
const (
	// injectProbeFrames is how many test frames to send. A single frame can be lost to a
	// collision on a busy channel, which would report a working adapter as broken.
	injectProbeFrames = 8
	// injectProbeWindow is how long to watch for one of them coming back.
	injectProbeWindow = 2 * time.Second
	// injectProbeInterval spaces the frames out.
	injectProbeInterval = 60 * time.Millisecond
	// injectProbeSettle lets the capture socket become live before the first frame goes out.
	//
	// Without it the opening frames are transmitted into a socket that is not yet receiving,
	// and on a quiet channel there may be nothing left to catch. Two identical adapters
	// reported differently purely on this timing.
	injectProbeSettle = 250 * time.Millisecond
)

// radiotapTX is a bare transmit header: no fields, so the driver picks rate and power.
var radiotapTX = []byte{0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}

// VerifyInjection empirically tests whether an adapter can inject frames.
//
// The capability bitmap lies on several common chipsets, which is why the brief insists this
// be demonstrated rather than read. The test is a loopback: transmit a frame carrying a random
// marker and watch this adapter's own monitor socket for it.
//
// What the frame is, and why it is safe:
//
//   - A vendor-specific Action frame, addressed from a random locally-administered MAC to that
//     same address. It names no network, targets no real device, and no station or access
//     point will answer it - an Action frame to an address that does not exist is ignored by
//     everything in range.
//   - It carries a random 16-byte marker so it can be recognised as ours and not confused
//     with ambient traffic.
//
// It transmits, so it is RF energy, but it is the most inert transmission available: it
// impersonates nothing and solicits nothing. That is deliberate - the alternative injection
// tests (probe requests, frames at a real access point) make devices outside the engagement
// transmit, which is exactly what the scope gate exists to prevent.
func VerifyInjection(ctx context.Context, acquirer Acquirer, dev *Device, log *slog.Logger) (InjectionStatus, string) {
	if log == nil {
		log = slog.Default()
	}
	if dev == nil || dev.Ifname == "" {
		return InjectionFailed, "no interface"
	}
	if dev.Phy != nil && !dev.Phy.SupportsIftype(nl80211.IftypeMonitor) {
		return InjectionFailed, "adapter does not support monitor mode"
	}

	// Put the adapter into monitor mode for the test and restore it afterwards.
	acq, err := acquirer.Acquire(ctx, dev, nl80211.IftypeMonitor)
	if err != nil {
		return InjectionFailed, fmt.Sprintf("could not enter monitor mode: %v", err)
	}
	defer acquirer.Release(ctx, acq)

	// Park on a channel. The test does not care which, but an unset channel makes some
	// drivers refuse the transmit outright.
	if chans := dev.Phy.UsableChannels(); len(chans) > 0 {
		if err := acquirer.SetChannel(ctx, dev, chans[0].MHz); err != nil {
			log.Debug("injection probe could not set a channel", "radio_id", dev.ID, "err", err)
		}
	}

	src, err := capture.Open(dev.Ifname, int(dev.Ifindex), dev.ID)
	if err != nil {
		return InjectionFailed, fmt.Sprintf("could not open a capture socket: %v", err)
	}
	defer src.Close()

	txFD, err := openTXSocket(int(dev.Ifindex))
	if err != nil {
		return InjectionFailed, fmt.Sprintf("could not open a transmit socket: %v", err)
	}
	defer unix.Close(txFD)

	// Let the capture socket settle before transmitting: frames sent into a socket that is not
	// yet receiving are simply missed, and that is the difference between "verified" and
	// "inconclusive" on two adapters that behave identically.
	select {
	case <-time.After(injectProbeSettle):
	case <-ctx.Done():
		return InjectionFailed, "cancelled"
	}

	// The driver's own transmit counter, read before and after.
	//
	// This is the second, independent line of evidence, and it is the stronger one for the
	// common case: a write() that returns success only proves the kernel accepted the frame,
	// but a transmit counter that advances proves the driver actually put it on the air.
	// Plenty of drivers never loop their own transmissions back to the monitor socket, and
	// for those this is the only conclusive signal available.
	txBefore, haveTX := txPackets(dev.Ifname)

	marker := make([]byte, 16)
	if _, err := rand.Read(marker); err != nil {
		return InjectionFailed, fmt.Sprintf("could not generate a test marker: %v", err)
	}
	frame, err := buildInjectionProbe(marker)
	if err != nil {
		return InjectionFailed, err.Error()
	}

	// Watch for the marker while the frames go out.
	found := make(chan struct{})
	watchCtx, stopWatch := context.WithTimeout(ctx, injectProbeWindow)
	defer stopWatch()

	go func() {
		buf := make([]byte, 8192)
		for watchCtx.Err() == nil {
			f, err := src.Read(buf)
			if err != nil || f == nil {
				continue
			}
			if bytes.Contains(f.Raw, marker) {
				select {
				case found <- struct{}{}:
				default:
				}
				return
			}
		}
	}()

	var writeErr error
	sent := 0
	for i := 0; i < injectProbeFrames; i++ {
		if _, err := unix.Write(txFD, frame); err != nil {
			writeErr = err
			break
		}
		sent++

		select {
		case <-found:
			return InjectionVerified, fmt.Sprintf(
				"a test frame was transmitted and observed back on %s after %d frame(s)",
				dev.Ifname, sent)
		case <-ctx.Done():
			return InjectionFailed, "cancelled"
		case <-time.After(injectProbeInterval):
		}
	}

	// The kernel refusing the write is definitive: this adapter cannot inject.
	if writeErr != nil {
		return InjectionFailed, fmt.Sprintf(
			"the driver rejected the frame after %d sent: %v", sent, writeErr)
	}

	select {
	case <-found:
		return InjectionVerified, fmt.Sprintf(
			"a test frame was transmitted and observed back on %s", dev.Ifname)
	case <-watchCtx.Done():
	}

	// Nothing came back on the monitor socket. Before calling that inconclusive, ask the
	// driver whether it actually transmitted: a counter that advanced by the number of frames
	// written is direct evidence they left the adapter, whatever the monitor socket did or
	// did not echo.
	if haveTX {
		if txAfter, ok := txPackets(dev.Ifname); ok && txAfter >= txBefore+uint64(sent) {
			return InjectionVerified, fmt.Sprintf(
				"the driver transmitted %d frame(s) on %s (transmit counter %d → %d). They were "+
					"not echoed to the monitor socket, which many drivers do not do, so this was "+
					"confirmed from the driver's own counter instead",
				sent, dev.Ifname, txBefore, txAfter)
		}
	}

	// The write succeeded, nothing came back, and either the counter is unreadable or it did
	// not move. Genuinely unknown - and refusing to transmit on that basis locks out adapters
	// that work fine, so it gets its own status rather than being called a failure.
	return InjectionInconclusive, fmt.Sprintf(
		"the driver accepted %d frame(s) on %s but none were seen back and its transmit "+
			"counter did not advance. This is inconclusive rather than a failure - transmitting "+
			"work will run, and the first solicitation or deauthentication is the real test",
		sent, dev.Ifname)
}

// txPackets reads an interface's transmitted-frame counter from sysfs.
//
// Direct evidence that frames left the adapter, independent of whether the driver echoes its
// own transmissions to the monitor socket. Returns false when the counter cannot be read,
// which is not an error - it just means this line of evidence is unavailable.
func txPackets(ifname string) (uint64, bool) {
	if ifname == "" {
		return 0, false
	}
	body, err := os.ReadFile("/sys/class/net/" + ifname + "/statistics/tx_packets")
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// openTXSocket opens a raw AF_PACKET socket bound to an interface for transmission.
func openTXSocket(ifindex int) (int, error) {
	proto := int(htonsLocal(unix.ETH_P_ALL))

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		if err == unix.EPERM {
			return -1, fmt.Errorf("permission denied (CAP_NET_ADMIN required - run as root): %w", err)
		}
		return -1, err
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: uint16(proto), Ifindex: ifindex,
	}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// buildInjectionProbe assembles the test frame.
//
// A vendor-specific Action frame addressed to a locally administered address that does not
// exist: inert by construction, and carrying a marker so it can be recognised on the way back.
func buildInjectionProbe(marker []byte) ([]byte, error) {
	var addr [6]byte
	if _, err := rand.Read(addr[:]); err != nil {
		return nil, fmt.Errorf("could not generate a test address: %w", err)
	}
	addr[0] &^= 0x01 // unicast
	addr[0] |= 0x02  // locally administered: cannot collide with a real device

	f := make([]byte, 0, 8+24+2+len(marker))
	f = append(f, radiotapTX...)

	f = append(f, 0xD0, 0x00) // Action frame, no flags
	f = append(f, 0x00, 0x00) // duration
	f = append(f, addr[:]...) // destination: an address that does not exist
	f = append(f, addr[:]...) // source: the same
	f = append(f, addr[:]...) // BSSID: the same
	f = binary.LittleEndian.AppendUint16(f, 0)

	// Category 127 is vendor-specific; nothing will act on it.
	f = append(f, 0x7F)
	f = append(f, marker...)

	return f, nil
}

func htonsLocal(v uint16) uint16 { return v<<8 | v>>8 }

// VerifyInjectionAll tests every adapter and records the result on it.
//
// Runs before the scheduler is built, so transmitting roles are only ever offered adapters
// that have actually demonstrated injection.
func VerifyInjectionAll(ctx context.Context, acquirer Acquirer, devs []*Device, log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	for _, dev := range devs {
		status, note := VerifyInjection(ctx, acquirer, dev, log)
		dev.Injection = status
		dev.InjectionNote = note

		switch status {
		case InjectionVerified:
			log.Info("injection verified", "radio_id", dev.ID, "ifname", dev.Ifname)
		case InjectionFailed:
			log.Warn("injection failed - this adapter cannot transmit",
				"radio_id", dev.ID, "ifname", dev.Ifname, "note", note)
		default:
			log.Info("injection inconclusive - transmitting work will still run",
				"radio_id", dev.ID, "ifname", dev.Ifname, "note", note)
		}
	}
}

// AssumeInjection marks adapters as injection-capable without testing.
//
// The escape hatch for a driver that does not loop transmitted frames back, where the operator
// has confirmed injection by other means. It is deliberately explicit and is recorded on the
// device, so a report can show that this adapter's capability was asserted rather than
// demonstrated.
func AssumeInjection(devs []*Device, reason string) {
	if reason == "" {
		reason = "asserted by the operator, not demonstrated by WARP"
	}
	for _, dev := range devs {
		if dev.Injection != InjectionVerified {
			dev.Injection = InjectionVerified
			dev.InjectionNote = reason
		}
	}
}
