package radio

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// usbdevfsReset is the USBDEVFS_RESET ioctl: it re-enumerates a USB device from scratch, clearing
// a wedged firmware/driver state without unloading the module.
const usbdevfsReset = 0x5514

// ResetUSBAdapter power-cycles the USB device backing an interface, to recover an adapter that has
// stopped capturing after heavy mode-cycling (a well-known failure on mt76 and other USB parts:
// monitor mode stops delivering frames until the device is reset).
//
// It is driver-agnostic - a USB reset works for any USB Wi-Fi adapter (mt76, Ralink/Panda,
// rt2800usb, ath9k_htc, RTL) - and preserves the interface name and MAC. It does NOT preserve the
// phy index, which is re-created, so it must be run while no daemon holds the radio: recover
// between sessions, not mid-capture. A built-in (PCIe/SDIO) adapter is not USB and returns a clear
// error rather than a confusing ioctl failure.
func ResetUSBAdapter(ifname string) error {
	node, err := usbDeviceNode(ifname)
	if err != nil {
		return err
	}
	fd, err := unix.Open(node, unix.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("radio: open %s (need root): %w", node, err)
	}
	defer unix.Close(fd)
	if err := unix.IoctlSetInt(fd, usbdevfsReset, 0); err != nil {
		return fmt.Errorf("radio: USB reset %s: %w", node, err)
	}
	return nil
}

// IsUSBAdapter reports whether the interface is backed by a USB device (and so can be reset with
// ResetUSBAdapter). A built-in PCIe/SDIO adapter reports false.
func IsUSBAdapter(ifname string) bool {
	_, err := usbDeviceNode(ifname)
	return err == nil
}

// usbDeviceNode walks up from the interface's sysfs device link to the USB device that carries the
// bus/dev numbers and returns its /dev/bus/usb node path. /sys/class/net/<if>/device points at the
// driver's device; the USB device is a few levels up (the netdev → the USB interface → the USB
// device).
func usbDeviceNode(ifname string) (string, error) {
	if strings.ContainsAny(ifname, "/ \t") || ifname == "" {
		return "", fmt.Errorf("radio: invalid interface name %q", ifname)
	}
	start, err := filepath.EvalSymlinks(filepath.Join("/sys/class/net", ifname, "device"))
	if err != nil {
		return "", fmt.Errorf("radio: locate %s device: %w", ifname, err)
	}

	d := start
	for i := 0; i < 6; i++ {
		busPath := filepath.Join(d, "busnum")
		devPath := filepath.Join(d, "devnum")
		if fileExists(busPath) && fileExists(devPath) {
			bus, berr := readSysInt(busPath)
			num, derr := readSysInt(devPath)
			if berr != nil || derr != nil {
				return "", fmt.Errorf("radio: read USB bus/dev for %s: %v %v", ifname, berr, derr)
			}
			return fmt.Sprintf("/dev/bus/usb/%03d/%03d", bus, num), nil
		}
		d = filepath.Dir(d)
	}
	return "", fmt.Errorf("radio: %s is not a USB adapter (no USB device found) - only USB adapters "+
		"can be reset this way", ifname)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readSysInt(p string) (int, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
