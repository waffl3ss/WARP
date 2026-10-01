// Package precheck runs the host pre-flight an operator wants after a reboot, before starting a
// capture: are the radios present and unblocked, and is anything on the box going to fight WARP
// for control of them.
//
// It is deliberately separate from radio.Discover, which answers "what can these adapters do".
// This answers "is the host in a state where WARP can use them at all" - rfkill, NetworkManager,
// stray supplicants - and, for the problems it can fix, carries the fix so the caller can apply it
// after the operator has verified it. Nothing here fixes anything on its own; Run is read-only and
// each Check exposes its fix for the front end to confirm and invoke.
//
// Every action is a host-environment change on a par with rfkill and the one NetworkManager
// shell-out radio.acquire already makes - not engagement logic - so this lives outside the RPC
// surface, the same as `warp radios probe`.
package precheck

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/waffl3ss/warp/internal/radio"
)

// Level is how a check turned out.
type Level int

const (
	// OK: nothing to do.
	OK Level = iota
	// Info: a fact worth stating, not a problem.
	Info
	// Warn: a problem WARP cannot fix itself (a hardware switch, missing privileges).
	Warn
	// Fixable: a problem WARP can resolve, once the operator confirms.
	Fixable
	// Fail: a blocker - there is no point starting a capture until it is resolved.
	Fail
)

func (l Level) String() string {
	switch l {
	case OK:
		return "ok"
	case Info:
		return "info"
	case Warn:
		return "warn"
	case Fixable:
		return "fixable"
	case Fail:
		return "fail"
	default:
		return "?"
	}
}

// Check is one pre-flight result.
type Check struct {
	// Name is a short label, e.g. "wireless adapters".
	Name string
	// Level is the outcome.
	Level Level
	// Detail explains what was found, in a sentence an operator can act on.
	Detail string
	// Fix is a short imperative describing what applying the fix does. Empty unless the problem
	// is fixable.
	Fix string
	// apply performs the fix. nil unless the check is Fixable.
	apply func(context.Context) error
}

// Fixable reports whether this check carries a fix that can be applied.
func (c *Check) Fixable() bool { return c.apply != nil }

// Apply runs the fix, or is a no-op if there is none.
func (c *Check) Apply(ctx context.Context) error {
	if c.apply == nil {
		return nil
	}
	return c.apply(ctx)
}

// Run performs every read-only check in display order. It never changes anything.
func Run(ctx context.Context) []Check {
	devs, ifaces := discover(ctx)
	return []Check{
		checkPrivileges(),
		checkAdapters(devs),
		checkRFKill(devs),
		checkNetworkManager(ctx, ifaces),
		checkSupplicants(ctx),
	}
}

// discover enumerates adapters once, shared by the checks that need them. A failure (no wireless
// stack, no privileges to enumerate) yields empty slices; the adapters check reports it.
func discover(ctx context.Context) (devs []*radio.Device, ifaces []string) {
	disc, err := radio.Discover(ctx, radio.DiscoverOptions{})
	if err != nil || disc == nil {
		return nil, nil
	}
	for _, d := range disc.Devices {
		if d.Ifname != "" {
			ifaces = append(ifaces, d.Ifname)
		}
	}
	return disc.Devices, ifaces
}

// checkPrivileges: almost every fix, and all radio control, needs CAP_NET_ADMIN. Root is the
// simple way to have it.
func checkPrivileges() Check {
	if os.Geteuid() == 0 {
		return Check{Name: "privileges", Level: OK, Detail: "running as root"}
	}
	return Check{
		Name:   "privileges",
		Level:  Warn,
		Detail: "not running as root - radio control and every fix below need it; re-run with sudo",
	}
}

// checkAdapters: the whole point is moot without radios.
func checkAdapters(devs []*radio.Device) Check {
	if len(devs) == 0 {
		return Check{
			Name:  "wireless adapters",
			Level: Fail,
			Detail: "no usable wireless adapters found. If one is plugged in, it may still be " +
				"enumerating (replug it), rfkill-blocked (see below), or this may be a box with " +
				"no wireless stack. Compare against `iw dev`.",
		}
	}
	var parts []string
	for _, d := range devs {
		label := d.Ifname
		if label == "" {
			label = d.ID
		}
		if b := strings.Join(d.Bands(), "/"); b != "" {
			label += " (" + b + ")"
		}
		parts = append(parts, label)
	}
	return Check{
		Name:   "wireless adapters",
		Level:  OK,
		Detail: fmt.Sprintf("%d found: %s", len(devs), strings.Join(parts, ", ")),
	}
}

// checkRFKill: a soft block is the classic post-reboot gotcha and WARP can clear it; a hard block
// is a physical switch it cannot.
func checkRFKill(devs []*radio.Device) Check {
	var soft, hard []string
	for _, d := range devs {
		rf := radio.RFKill(d.ID)
		switch {
		case rf.Hard:
			hard = append(hard, d.ID)
		case rf.Soft:
			soft = append(soft, d.ID)
		}
	}

	switch {
	case len(hard) > 0:
		return Check{
			Name:  "rfkill",
			Level: Warn,
			Detail: fmt.Sprintf("%s hard-blocked - that is a physical switch or firmware block "+
				"WARP cannot clear. Flip the hardware switch or toggle it in the VM/BIOS.",
				strings.Join(hard, ", ")),
		}
	case len(soft) > 0:
		blocked := append([]string(nil), soft...)
		return Check{
			Name:  "rfkill",
			Level: Fixable,
			Detail: fmt.Sprintf("%s soft-blocked (a reboot often does this)",
				strings.Join(blocked, ", ")),
			Fix: "run `rfkill unblock wifi`",
			apply: func(ctx context.Context) error {
				return unblockWiFi(ctx)
			},
		}
	default:
		return Check{Name: "rfkill", Level: OK, Detail: "no radios are blocked"}
	}
}

// checkNetworkManager: if it is running it will try to manage the Wi-Fi interfaces and can bring
// them back to managed mode mid-capture. WARP already tells it to release them at acquire time,
// but doing it up front means one less surprise.
func checkNetworkManager(ctx context.Context, ifaces []string) Check {
	if !networkManagerRunning(ctx) {
		return Check{
			Name:   "networkmanager",
			Level:  OK,
			Detail: "not running - nothing will fight WARP for the interfaces",
		}
	}
	if _, err := exec.LookPath("nmcli"); err != nil {
		return Check{
			Name:  "networkmanager",
			Level: Warn,
			Detail: "NetworkManager is running but nmcli is not installed, so WARP cannot ask it " +
				"to release the interfaces. Stop it manually (`systemctl stop NetworkManager`) or " +
				"install nmcli.",
		}
	}
	targets := append([]string(nil), ifaces...)
	detail := "NetworkManager is running and may fight WARP for the Wi-Fi interfaces"
	if len(targets) > 0 {
		detail = fmt.Sprintf("%s (%s)", detail, strings.Join(targets, ", "))
	}
	return Check{
		Name:   "networkmanager",
		Level:  Fixable,
		Detail: detail,
		Fix:    "set the Wi-Fi interfaces unmanaged (`nmcli device set <if> managed no`)",
		apply: func(ctx context.Context) error {
			return unmanageInterfaces(ctx, targets)
		},
	}
}

// checkSupplicants: a wpa_supplicant left running on a card holds it in managed mode and races
// WARP's own association. Any is worth flagging.
func checkSupplicants(ctx context.Context) Check {
	pids := pgrep(ctx, "wpa_supplicant")
	svc := activeSupplicantServices(ctx)
	if len(pids) == 0 && len(svc) == 0 {
		return Check{Name: "supplicant", Level: OK, Detail: "no stray wpa_supplicant is running"}
	}

	// A bare pkill is not enough when wpa_supplicant is a systemd service: systemd restarts it
	// within seconds, it reclaims the card into managed mode, and the capture goes to 0 frames
	// while the association is fought over - exactly the "reverted to managed" symptom. Stop and
	// *mask* the service so it stays down for the engagement, then kill any remaining process.
	detail := fmt.Sprintf("wpa_supplicant is running (pid %s)", strings.Join(pids, ", "))
	fix := "stop it (`pkill wpa_supplicant`)"
	if len(svc) > 0 {
		detail = fmt.Sprintf("wpa_supplicant is running as a service (%s) - it will keep "+
			"reclaiming the Wi-Fi card into managed mode and fighting WARP's association",
			strings.Join(svc, ", "))
		fix = "stop and mask the service, then kill any process"
	}
	return Check{
		Name:   "supplicant",
		Level:  Fixable,
		Detail: detail,
		Fix:    fix,
		apply: func(ctx context.Context) error {
			for _, s := range svc {
				_ = run(ctx, "systemctl", "stop", s)
				_ = run(ctx, "systemctl", "mask", s)
			}
			// Best-effort kill of anything left; ignore "no process" exit.
			_ = run(ctx, "pkill", "-x", "wpa_supplicant")
			// Verify it is actually gone.
			if len(pgrep(ctx, "wpa_supplicant")) > 0 {
				return fmt.Errorf("precheck: wpa_supplicant is still running after stop/mask")
			}
			return nil
		},
	}
}

// activeSupplicantServices returns the systemd wpa_supplicant units that are active, so precheck
// can stop *and mask* them rather than only killing a process systemd will restart.
func activeSupplicantServices(ctx context.Context) []string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	var active []string
	for _, unit := range []string{"wpa_supplicant.service", "wpa_supplicant@wlan0.service", "wpa_supplicant@wlan1.service"} {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		out, _ := exec.CommandContext(cctx, "systemctl", "is-active", unit).Output()
		cancel()
		if strings.TrimSpace(string(out)) == "active" {
			active = append(active, unit)
		}
	}
	return active
}

// ---------------------------------------------------------------------------
// Fix actions and host probes
// ---------------------------------------------------------------------------

// unblockWiFi clears soft rfkill blocks. It prefers the rfkill tool and falls back to sysfs, which
// needs no extra package - a minimal image may not ship rfkill.
func unblockWiFi(ctx context.Context) error {
	if _, err := exec.LookPath("rfkill"); err == nil {
		return run(ctx, "rfkill", "unblock", "wifi")
	}
	// sysfs fallback: write 0 to every wlan rfkill node's soft block.
	nodes, _ := filepath.Glob("/sys/class/rfkill/rfkill*")
	var wrote bool
	for _, n := range nodes {
		typ, err := os.ReadFile(filepath.Join(n, "type"))
		if err != nil || strings.TrimSpace(string(typ)) != "wlan" {
			continue
		}
		if err := os.WriteFile(filepath.Join(n, "soft"), []byte("0"), 0o644); err == nil {
			wrote = true
		}
	}
	if !wrote {
		return fmt.Errorf("precheck: rfkill not installed and no writable wlan rfkill node found")
	}
	return nil
}

// unmanageInterfaces tells NetworkManager to stop managing each Wi-Fi interface. Errors are
// collected rather than aborting on the first: releasing three of four interfaces still helps.
func unmanageInterfaces(ctx context.Context, ifaces []string) error {
	if len(ifaces) == 0 {
		return fmt.Errorf("precheck: no Wi-Fi interfaces to release")
	}
	var failed []string
	for _, ifn := range ifaces {
		if err := run(ctx, "nmcli", "device", "set", ifn, "managed", "no"); err != nil {
			failed = append(failed, ifn)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("precheck: could not release %s", strings.Join(failed, ", "))
	}
	return nil
}

// networkManagerRunning reports whether a NetworkManager process is alive. Process-based rather
// than systemctl-based so it works on a box without systemd, and needs no privileges.
func networkManagerRunning(ctx context.Context) bool {
	return len(pgrep(ctx, "NetworkManager")) > 0
}

// pgrep returns the PIDs of processes whose name matches, or nil. It shells to pgrep where present
// and otherwise walks /proc, so a minimal image without procps still works.
func pgrep(ctx context.Context, name string) []string {
	if path, err := exec.LookPath("pgrep"); err == nil {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cctx, path, "-x", name).Output()
		if err != nil {
			return nil // non-zero exit means no match
		}
		return fields(out)
	}
	return pgrepProc(name)
}

// pgrepProc is the /proc fallback for pgrep.
func pgrepProc(name string) []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid := e.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(comm)) == name {
			pids = append(pids, pid)
		}
	}
	return pids
}

// run executes a host command, mapping a non-zero exit to an error carrying its output.
func run(ctx context.Context, name string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("%s: %w", name, err)
		}
		return fmt.Errorf("%s: %w (%s)", name, err, msg)
	}
	return nil
}

// fields splits command output into whitespace-separated tokens.
func fields(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			out = append(out, t)
		}
	}
	return out
}
