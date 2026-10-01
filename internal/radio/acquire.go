package radio

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// Acquisition takes an adapter out from under the host's network management, puts it into the
// interface type a role needs, and restores it on release.
//
// The failure this code exists to prevent is a stranded adapter: an engagement that ends with
// three cards left in monitor mode and a laptop with no working wifi, at a client site. Every
// acquisition records what it changed so release can put it back, and release runs on
// SIGINT/SIGTERM as well as on the normal path.
type Acquisition struct {
	Device *Device
	// Iftype the adapter was placed into.
	Iftype nl80211.Iftype

	// prior records the state to restore.
	priorIftype nl80211.Iftype
	priorUp     bool
	nmReleased  bool
	// priorMAC is the adapter's original hardware address, restored on release when the
	// acquisition changed it for active-monitor injection.
	priorMAC net.HardwareAddr

	// Active reports whether the adapter is in active monitor mode - it ACKs frames addressed
	// to its own MAC, which is what lets an injected association complete.
	Active bool
	// StationMAC is the address the adapter now wears and must be transmitted from, when Active.
	StationMAC net.HardwareAddr
	// connected records that a kernel-driven association was issued (AcquireStation), so release
	// tears it down before restoring the interface. A card left associated to a client's network
	// is the same class of leak as one left in monitor mode.
	connected bool
	ifindex   uint32
	// station is the association's netlink socket, which owns the association and carries EAPOL
	// over the nl80211 control port. Closed on release, which also drops the association.
	station *nl80211.StationConn

	log      *slog.Logger
	released bool
	mu       sync.Mutex
}

// Acquirer configures adapters. It is an interface so the scheduler and daemon can be tested
// without hardware.
type Acquirer interface {
	Acquire(ctx context.Context, dev *Device, iftype nl80211.Iftype) (*Acquisition, error)
	// AcquireActiveMonitor puts an adapter into active monitor mode wearing the given station
	// MAC, so injected associations are acknowledged and can complete. A zero MAC means
	// generate one.
	AcquireActiveMonitor(ctx context.Context, dev *Device, sta net.HardwareAddr) (*Acquisition, error)
	// AcquireStation puts an adapter into managed mode and issues a kernel-driven association, so
	// the firmware acknowledges the access point the way it does for a real client. Used to
	// provoke a PMKID or certificate from a card that a second radio then captures.
	AcquireStation(ctx context.Context, dev *Device, params nl80211.ConnectParams) (*Acquisition, error)
	Release(ctx context.Context, a *Acquisition) error
	SetChannel(ctx context.Context, dev *Device, mhz int) error
	// CurrentFreq reports the centre frequency the adapter is actually tuned to right now, or 0 if
	// it cannot be read. It is used to verify a channel change took effect: some drivers accept a
	// SetChannel and silently ignore it after heavy mode-cycling (mt76), which a hunt would
	// otherwise experience as "locked to the channel but no frames".
	CurrentFreq(ctx context.Context, dev *Device) (int, error)
}

// NL80211Acquirer is the real implementation, backed by nl80211 and rtnetlink ioctls.
type NL80211Acquirer struct {
	log *slog.Logger

	mu   sync.Mutex
	conn *nl80211.Conn
}

// NewAcquirer builds an Acquirer. It does not connect until first use, so a daemon on a box
// with no wireless stack still starts and reports the problem clearly.
func NewAcquirer(log *slog.Logger) *NL80211Acquirer {
	if log == nil {
		log = slog.Default()
	}
	return &NL80211Acquirer{log: log}
}

func (a *NL80211Acquirer) connection() (*nl80211.Conn, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.conn != nil {
		return a.conn, nil
	}
	c, err := nl80211.Dial()
	if err != nil {
		return nil, err
	}
	a.conn = c
	return c, nil
}

// Close releases the netlink connection.
func (a *NL80211Acquirer) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.conn == nil {
		return nil
	}
	err := a.conn.Close()
	a.conn = nil
	return err
}

// Acquire prepares an adapter for a role.
//
// The sequence matters and is not negotiable on most drivers: stop the host's network manager
// from touching the interface, bring it administratively down, change the interface type,
// then bring it back up. Changing type on a live interface fails on nearly every driver, and
// the failure is a confusing EBUSY rather than anything that names the cause.
func (a *NL80211Acquirer) Acquire(ctx context.Context, dev *Device, iftype nl80211.Iftype) (*Acquisition, error) {
	return a.acquire(ctx, dev, iftype, nil)
}

// AcquireActiveMonitor puts an adapter into active monitor mode wearing a station MAC.
//
// Active monitor plus a matching MAC is what makes an injected association complete: the card
// acknowledges the access point's auth and assoc responses, which a passive monitor never does.
// See nl80211.Conn.SetMonitorActive.
func (a *NL80211Acquirer) AcquireActiveMonitor(ctx context.Context, dev *Device, sta net.HardwareAddr) (*Acquisition, error) {
	if len(sta) == 0 {
		m, err := randomStationMAC()
		if err != nil {
			return nil, err
		}
		sta = m
	}
	if len(sta) != 6 {
		return nil, fmt.Errorf("radio: station MAC must be 6 octets, got %d", len(sta))
	}
	return a.acquire(ctx, dev, nl80211.IftypeMonitor, sta)
}

// AcquireStation puts an adapter into managed (station) mode and issues a kernel-driven
// association to the network in params.
//
// This is the firmware-ACK path: the kernel's connection manager runs the auth/assoc exchange and
// the chip acknowledges the access point exactly as it does for a real client, which is the one
// thing the injected active-monitor path cannot reliably do. The association only has to *happen*
// - the frames it provokes (a PMKID-bearing M1, an enterprise RADIUS certificate) are read off a
// capture radio, not awaited here. The adapter wears a generated locally-administered MAC, never a
// real client's, and Release both disconnects and restores it.
//
// Needs a second adapter in monitor mode to capture what the association provokes; on a single
// adapter there is nothing left to listen with, and the caller falls back to active-monitor
// injection. This whole path requires real hardware to validate - see the hw-probe skill.
func (a *NL80211Acquirer) AcquireStation(ctx context.Context, dev *Device, params nl80211.ConnectParams) (*Acquisition, error) {
	sta, err := randomStationMAC()
	if err != nil {
		return nil, err
	}
	acq, err := a.acquire(ctx, dev, nl80211.IftypeStation, sta)
	if err != nil {
		return nil, err
	}

	// The association is driven on its own netlink socket, which owns it (so it also carries the
	// 802.1X control port over nl80211) and is kept on the acquisition for the EAPOL exchange and
	// for teardown. Associate blocks until the association actually completes, or fails with the
	// access point's status code.
	station, err := nl80211.Associate(acq.ifindex, params, stationConnectTimeout)
	if err != nil {
		a.Release(ctx, acq)
		return nil, fmt.Errorf("radio: associate %s to %q: %w", dev.Ifname, string(params.SSID), err)
	}
	acq.station = station
	acq.connected = true

	a.log.Info("radio associated",
		"radio_id", dev.ID, "ifname", dev.Ifname, "ssid", string(params.SSID),
		"station_mac", macString(acq.StationMAC))
	return acq, nil
}

// Station returns the association's control-port transport, or nil if this acquisition is not a
// station association. Its Send/Receive carry EAPOL over nl80211.
func (a *Acquisition) Station() *nl80211.StationConn { return a.station }

// stationConnectTimeout bounds how long AcquireStation waits for the kernel to finish the
// association. A real association completes in a second or two; this is generous enough for a busy
// access point and short enough to fail fast when it is refusing or out of range.
const stationConnectTimeout = 10 * time.Second

// acquire is the shared body. When sta is non-nil the adapter is put into active monitor mode
// wearing that address; otherwise it is an ordinary (passive) capture monitor or the requested
// iftype.
func (a *NL80211Acquirer) acquire(ctx context.Context, dev *Device, iftype nl80211.Iftype, sta net.HardwareAddr) (*Acquisition, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dev == nil || dev.Ifname == "" {
		return nil, errors.New("radio: cannot acquire an adapter with no interface")
	}

	conn, err := a.connection()
	if err != nil {
		return nil, err
	}

	if rf := RFKill(dev.ID); rf.Blocked() {
		return nil, fmt.Errorf("radio: %s is %s; clear it with `rfkill unblock wifi` before starting",
			dev.ID, rf)
	}

	acq := &Acquisition{Device: dev, Iftype: iftype, log: a.log}

	// Record the state to restore before changing anything.
	up, err := interfaceIsUp(dev.Ifname)
	if err != nil {
		return nil, err
	}
	acq.priorUp = up
	acq.priorIftype = currentIftype(conn, dev.Ifindex)

	// Ask NetworkManager to stop managing the interface. Without this it races us: it will
	// bring the card back up in managed mode partway through a capture, and the symptom is an
	// engagement that mysteriously stops seeing frames.
	if released, err := setNetworkManagerManaged(ctx, dev.Ifname, false); err != nil {
		a.log.Warn("could not tell NetworkManager to release the interface; "+
			"it may fight for control mid-capture",
			"ifname", dev.Ifname, "err", err)
	} else {
		acq.nmReleased = released
	}

	if err := setInterfaceUp(dev.Ifname, false); err != nil {
		a.restore(ctx, acq)
		return nil, err
	}

	// The MAC can only be changed while the interface is down, which it now is. Record the
	// original so release puts it back - a card left wearing a spoofed address after the
	// engagement is the same class of problem as one left in monitor mode.
	//
	// It must also be changed while the interface is in a mode whose ARPHRD is Ethernet. A
	// monitor netdev is ARPHRD_IEEE80211_RADIOTAP, and SIOCSIFHWADDR rejects an Ethernet
	// address on it with EINVAL - which is exactly what happened when a *borrowed* card, already
	// in monitor from recon, was handed to active-monitor injection. So flip to station first,
	// set the address, then to active monitor.
	if sta != nil {
		if prior, err := readMAC(dev.Ifname); err == nil {
			acq.priorMAC = prior
		}
		if err := conn.SetIftype(uint32(dev.Ifindex), nl80211.IftypeStation); err != nil {
			a.restore(ctx, acq)
			return nil, fmt.Errorf("radio: put %s into station mode to set its MAC: %w", dev.Ifname, err)
		}
		if err := setMAC(dev.Ifname, sta); err != nil {
			a.restore(ctx, acq)
			return nil, err
		}
		acq.StationMAC = append(net.HardwareAddr(nil), sta...)
	}

	acq.ifindex = uint32(dev.Ifindex)
	switch {
	case iftype == nl80211.IftypeStation:
		// Managed mode: the MAC step above already flipped it to station, but set it explicitly
		// so this does not depend on whether a MAC was requested. The association is issued
		// separately by AcquireStation.
		err = conn.SetIftype(uint32(dev.Ifindex), nl80211.IftypeStation)
	case sta != nil:
		err = conn.SetMonitorActive(uint32(dev.Ifindex))
		acq.Active = true
	case iftype == nl80211.IftypeMonitor:
		err = conn.SetMonitor(uint32(dev.Ifindex))
	default:
		err = conn.SetIftype(uint32(dev.Ifindex), iftype)
	}
	if err != nil {
		a.restore(ctx, acq)
		if acq.Active {
			return nil, fmt.Errorf("radio: put %s into active monitor mode: %w - "+
				"the driver may not support it (ath9k, mt76 and rt2800usb do)", dev.Ifname, err)
		}
		return nil, fmt.Errorf("radio: put %s into %s mode: %w", dev.Ifname, iftype, err)
	}

	if err := setInterfaceUp(dev.Ifname, true); err != nil {
		a.restore(ctx, acq)
		return nil, err
	}

	a.log.Info("radio acquired",
		"radio_id", dev.ID, "ifname", dev.Ifname, "iftype", iftype.String(),
		"active", acq.Active, "station_mac", macString(acq.StationMAC),
		"prior_iftype", acq.priorIftype.String(), "nm_released", acq.nmReleased)

	return acq, nil
}

func macString(m net.HardwareAddr) string {
	if len(m) == 0 {
		return ""
	}
	return m.String()
}

// randomStationMAC generates a locally-administered unicast address.
//
// Locally-administered (bit 1 of the first octet set) and unicast (bit 0 clear), so it cannot
// collide with a real manufacturer address and is never a multicast destination.
func randomStationMAC() (net.HardwareAddr, error) {
	m := make(net.HardwareAddr, 6)
	if _, err := rand.Read(m); err != nil {
		return nil, fmt.Errorf("radio: generate station MAC: %w", err)
	}
	m[0] = (m[0] | 0x02) &^ 0x01
	return m, nil
}

// Release restores an adapter to the state it was in before acquisition.
//
// Best-effort throughout: every step is attempted even if an earlier one failed, because a
// partial restore still beats leaving the card in monitor mode. Errors are logged rather than
// returned early for the same reason.
func (a *NL80211Acquirer) Release(ctx context.Context, acq *Acquisition) error {
	if acq == nil {
		return nil
	}
	acq.mu.Lock()
	if acq.released {
		acq.mu.Unlock()
		return nil
	}
	acq.released = true
	acq.mu.Unlock()

	return a.restore(ctx, acq)
}

func (a *NL80211Acquirer) restore(ctx context.Context, acq *Acquisition) error {
	dev := acq.Device
	var errs []error

	// A cancelled context must not prevent teardown: this runs on SIGTERM, when the daemon's
	// context is already dead.
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	conn, connErr := a.connection()
	if connErr != nil {
		errs = append(errs, connErr)
	}

	// Tear down a kernel-driven association *before* the interface is brought down and before the
	// mode changes, so the card is never left joined to a client's network. The station socket
	// owns the association, so closing it disconnects; it also carries the control port, so it
	// must go before anything else touches the interface. Order matters: a disconnect on an
	// already-downed interface is refused with "network is down".
	if acq.station != nil {
		if err := acq.station.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close station on %s: %w", dev.Ifname, err))
		}
		acq.station = nil
	} else if acq.connected && connErr == nil {
		if err := conn.Disconnect(acq.ifindex, 0); err != nil {
			errs = append(errs, fmt.Errorf("disconnect %s: %w", dev.Ifname, err))
		}
	}

	if err := setInterfaceUp(dev.Ifname, false); err != nil {
		errs = append(errs, err)
	}

	// Put the hardware address back, but only in a mode that accepts it. SIOCSIFHWADDR needs
	// an Ethernet-typed netdev, so if the card is in monitor (it is, for an active-monitor
	// acquisition) flip it to station first. A failure here must not abort the rest of the
	// restore: leaving the card up in the right mode with a spoofed MAC is far better than
	// leaving it down, which is what stranded wlan1 and broke every following operation.
	if len(acq.priorMAC) == 6 && connErr == nil {
		if err := conn.SetIftype(uint32(dev.Ifindex), nl80211.IftypeStation); err != nil {
			errs = append(errs, fmt.Errorf("station mode to restore MAC on %s: %w", dev.Ifname, err))
		} else if err := setMAC(dev.Ifname, acq.priorMAC); err != nil {
			errs = append(errs, fmt.Errorf("restore MAC on %s: %w", dev.Ifname, err))
		}
	}

	if connErr == nil {
		target := acq.priorIftype
		if target == nl80211.IftypeUnspecified {
			// Nothing was recorded; managed is the state a distro leaves an adapter in and is
			// the least surprising thing to hand back.
			target = nl80211.IftypeStation
		}
		// Restoring to monitor must go through SetMonitor, not a bare SetIftype: SetIftype sets
		// the type but not the monitor flags, and without NL80211_MNTR_FLAG_OTHER_BSS several
		// drivers deliver only frames addressed to the local station - so a recon card handed back
		// after a borrow captured almost nothing and read "0 frames" while sweeping. SetMonitor
		// puts the flags back exactly as the initial acquisition set them.
		var err error
		if target == nl80211.IftypeMonitor {
			err = conn.SetMonitor(uint32(dev.Ifindex))
		} else {
			err = conn.SetIftype(uint32(dev.Ifindex), target)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("restore %s to %s: %w", dev.Ifname, target, err))
		}
	}

	// Bring the interface back up whenever it was up before, regardless of any error above. A
	// card left administratively down is indistinguishable from a dead adapter and takes the
	// next deauth or capture down with it.
	if acq.priorUp {
		if err := setInterfaceUp(dev.Ifname, true); err != nil {
			errs = append(errs, err)
		}
	}

	if acq.nmReleased {
		if _, err := setNetworkManagerManaged(restoreCtx, dev.Ifname, true); err != nil {
			errs = append(errs, fmt.Errorf("return %s to NetworkManager: %w", dev.Ifname, err))
		}
	}

	if len(errs) > 0 {
		err := errors.Join(errs...)
		a.log.Error("radio release was incomplete - check `iw dev` for a stranded adapter",
			"radio_id", dev.ID, "ifname", dev.Ifname, "err", err)
		return fmt.Errorf("radio: release %s: %w", dev.Ifname, err)
	}

	a.log.Info("radio released", "radio_id", dev.ID, "ifname", dev.Ifname)
	return nil
}

// SetChannel tunes an adapter.
func (a *NL80211Acquirer) SetChannel(ctx context.Context, dev *Device, mhz int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	conn, err := a.connection()
	if err != nil {
		return err
	}
	// 20 MHz no-HT is the right width for monitor and injection work: a wider capture
	// bandwidth does not help frame capture and restricts which channels drivers accept.
	return conn.SetChannel(uint32(dev.Ifindex), mhz, nl80211.ChanWidth20NoHT)
}

// CurrentFreq reads the frequency the adapter is presently tuned to from nl80211. Returns 0 with a
// nil error when the driver does not report it - the caller treats that as "unknown" and skips any
// verification rather than crying wolf.
func (a *NL80211Acquirer) CurrentFreq(ctx context.Context, dev *Device) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	conn, err := a.connection()
	if err != nil {
		return 0, err
	}
	ifaces, err := conn.Interfaces()
	if err != nil {
		return 0, err
	}
	for _, i := range ifaces {
		if i.Index == uint32(dev.Ifindex) {
			return int(i.Freq), nil
		}
	}
	return 0, nil
}

// currentIftype reads an interface's current type, returning Unspecified if it cannot be
// determined. Used only to record what to restore.
func currentIftype(conn *nl80211.Conn, ifindex uint32) nl80211.Iftype {
	ifaces, err := conn.Interfaces()
	if err != nil {
		return nl80211.IftypeUnspecified
	}
	for _, i := range ifaces {
		if i.Index == ifindex {
			return i.Iftype
		}
	}
	return nl80211.IftypeUnspecified
}

// interfaceIsUp reports whether an interface is administratively up.
func interfaceIsUp(ifname string) (bool, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return false, fmt.Errorf("radio: open control socket: %w", err)
	}
	defer unix.Close(fd)

	req, err := unix.NewIfreq(ifname)
	if err != nil {
		return false, fmt.Errorf("radio: %q is not a valid interface name: %w", ifname, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, req); err != nil {
		return false, fmt.Errorf("radio: read flags for %s: %w", ifname, err)
	}
	return req.Uint16()&unix.IFF_UP != 0, nil
}

// setInterfaceUp brings an interface administratively up or down.
//
// Most drivers refuse an interface-type change while the interface is up, and the error is an
// EBUSY that names nothing.
func setInterfaceUp(ifname string, up bool) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("radio: open control socket: %w", err)
	}
	defer unix.Close(fd)

	req, err := unix.NewIfreq(ifname)
	if err != nil {
		return fmt.Errorf("radio: %q is not a valid interface name: %w", ifname, err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, req); err != nil {
		return fmt.Errorf("radio: read flags for %s: %w", ifname, err)
	}

	flags := req.Uint16()
	if up {
		flags |= unix.IFF_UP
	} else {
		flags &^= unix.IFF_UP
	}
	req.SetUint16(flags)

	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, req); err != nil {
		if errors.Is(err, unix.EPERM) {
			return fmt.Errorf("radio: bring %s %s: permission denied "+
				"(CAP_NET_ADMIN required - run warpd as root): %w", ifname, upDown(up), err)
		}
		return fmt.Errorf("radio: bring %s %s: %w", ifname, upDown(up), err)
	}
	return nil
}

func upDown(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

// readMAC returns an interface's current hardware address.
func readMAC(ifname string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("radio: read MAC of %s: %w", ifname, err)
	}
	return iface.HardwareAddr, nil
}

// setMAC changes an interface's hardware address. The interface must be down.
//
// The address the card ACKs on is its own, so active-monitor injection only works if the
// interface wears the station address the frames are sent from. This is the SIOCSIFHWADDR
// ioctl `ip link set dev X address` uses, issued in-process so the engagement box does not need
// iproute2 installed.
//
// The ifreq is built by hand rather than through unix.Ifreq because that type has no
// hardware-address setter across the versions we build against: the struct is a 16-byte
// interface name followed by a sockaddr whose family is ARPHRD_ETHER and whose first six data
// bytes are the address.
func setMAC(ifname string, mac net.HardwareAddr) error {
	if len(mac) != 6 {
		return fmt.Errorf("radio: %q is not a 6-octet MAC address", mac)
	}
	if len(ifname) >= unix.IFNAMSIZ {
		return fmt.Errorf("radio: interface name %q too long", ifname)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("radio: open control socket: %w", err)
	}
	defer unix.Close(fd)

	var req [unix.IFNAMSIZ + 24]byte
	copy(req[:unix.IFNAMSIZ], ifname)
	// sa_family (ARPHRD_ETHER) is a 2-byte host-order field at the start of the sockaddr.
	req[unix.IFNAMSIZ] = byte(unix.ARPHRD_ETHER)
	req[unix.IFNAMSIZ+1] = byte(unix.ARPHRD_ETHER >> 8)
	copy(req[unix.IFNAMSIZ+2:], mac)

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.SIOCSIFHWADDR), uintptr(unsafe.Pointer(&req[0])))
	if errno != 0 {
		if errno == unix.EPERM {
			return fmt.Errorf("radio: set MAC on %s: permission denied "+
				"(CAP_NET_ADMIN required): %w", ifname, errno)
		}
		return fmt.Errorf("radio: set MAC on %s: %w", ifname, errno)
	}
	return nil
}

// setNetworkManagerManaged asks NetworkManager to stop or resume managing an interface.
//
// This is WARP's one shell-out, and it is deliberately not part of the attack path: it is
// host environment management, on a par with rfkill. NetworkManager's only stable public
// control surface is D-Bus or nmcli, and pulling in a D-Bus stack for two calls is a poor
// trade against a binary that must stay small and static. A native D-Bus implementation can
// replace this without touching any caller.
//
// It degrades gracefully. A host without NetworkManager - which is common for a purpose-built
// NUC image - needs none of this, and a missing nmcli is reported as "nothing to do" rather
// than as a failure.
func setNetworkManagerManaged(ctx context.Context, ifname string, managed bool) (bool, error) {
	path, err := exec.LookPath("nmcli")
	if err != nil {
		// No NetworkManager tooling on this host; nothing is going to fight us for the
		// interface.
		return false, nil
	}

	state := "no"
	if managed {
		state = "yes"
	}

	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cctx, path, "device", "set", ifname, "managed", state)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// NetworkManager installed but not running is the common case on a purpose-built NUC or
		// a minimal Kali: nmcli exits non-zero saying so, and there is genuinely nothing to
		// release. Treat it as "nothing to do", not a warning worth printing on every acquire.
		if strings.Contains(string(out), "NetworkManager is not running") {
			return false, nil
		}
		return false, fmt.Errorf("nmcli device set %s managed %s: %w (%s)",
			ifname, state, err, trimOutput(out))
	}
	return true, nil
}

func trimOutput(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
