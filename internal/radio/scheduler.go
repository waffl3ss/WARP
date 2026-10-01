package radio

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// Radio count thresholds.
const (
	// MinimumRadios is what WARP genuinely cannot run without.
	MinimumRadios = 1

	// RecommendedRadios is where every capability is available concurrently. Below this WARP
	// still works: transmitting roles borrow the capture radio for the duration of a burst
	// rather than being refused. What is lost is *simultaneity* - recon pauses for a few
	// hundred milliseconds while a solicitation or deauthentication goes out - not capability.
	RecommendedRadios = 2
)

// ErrNoRadios is returned when discovery finds no usable adapter at all.
var ErrNoRadios = errors.New("radio: at least one usable adapter is required")

// UnsatisfiableError explains why a role could not be assigned.
//
// The brief requires a clear error rather than a silent fallback to an incapable adapter: a
// fallback produces a coverage picture that looks correct and is meaningless, and nobody
// notices until reporting.
type UnsatisfiableError struct {
	Role Role
	// PerDevice records why each adapter was rejected, in device order.
	PerDevice []string
}

func (e *UnsatisfiableError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "radio: cannot satisfy role %q", e.Role)
	if len(e.PerDevice) == 0 {
		b.WriteString(": no adapters present")
		return b.String()
	}
	b.WriteString(":")
	for _, r := range e.PerDevice {
		fmt.Fprintf(&b, "\n  - %s", r)
	}
	return b.String()
}

// Handle is a module's lease on a radio for a role.
//
// A module holds a Handle and asks it for the device it may use. It never learns an
// interface name from anywhere else.
type Handle struct {
	// Role this handle was acquired for.
	Role Role
	// Device serving the role.
	Device *Device
	// Iftype the device is configured into for this role.
	Iftype nl80211.Iftype
	// SharedChannel is true when this handle co-exists with another on the same phy and the
	// hardware only supports them on a single channel. The holder must follow the device's
	// channel rather than tuning independently - an AP and a monitor sharing one phy on an
	// mt76 part is the common case.
	SharedChannel bool

	// Borrowed is true when this handle reuses an interface another role already owns rather
	// than getting one of its own.
	//
	// This is how a single-adapter deployment stays fully capable: a solicitation or a
	// deauthentication borrows the capture radio for the length of its burst instead of being
	// refused. The holder must expect the interface to be shared, and the engine pauses
	// channel hopping for the duration so the burst does not go out on the wrong channel.
	Borrowed bool
	// BorrowedFrom names the role that actually owns the interface.
	BorrowedFrom Role

	sched    *Scheduler
	released bool
}

// Ifname returns the interface backing this handle.
//
// This is the only sanctioned way for a module to learn an interface name, and the name is
// valid only for the lifetime of the handle.
func (h *Handle) Ifname() string {
	if h == nil || h.Device == nil {
		return ""
	}
	return h.Device.Ifname
}

// Release returns the radio to the scheduler. It is safe to call more than once.
func (h *Handle) Release() {
	if h == nil || h.sched == nil {
		return
	}
	h.sched.release(h)
}

// Scheduler assigns radios to roles by capability and demand.
type Scheduler struct {
	mu       sync.Mutex
	devices  []*Device
	assigned map[string][]*Handle // device ID -> live handles
	// surveyDevice is the adapter pinned to RoleSurvey for the whole engagement. Once set it
	// is never changed, even across release and re-acquire, because RSSI is not comparable
	// across chipsets or antennas.
	surveyDevice string
	// disabled marks adapters the operator has switched off from the radios tab. A disabled
	// adapter is never a candidate for any role, so warpd stops touching it and frees the
	// interface for another tool - the point of having several cards plugged in and using only
	// some. Absent means enabled; the zero value is "everything on".
	disabled map[string]bool
	log      *slog.Logger
}

// NewScheduler builds a scheduler over the given adapters.
func NewScheduler(devices []*Device, log *slog.Logger) (*Scheduler, error) {
	if len(devices) < MinimumRadios {
		return nil, fmt.Errorf("%w: found %d", ErrNoRadios, len(devices))
	}
	if log == nil {
		log = slog.Default()
	}
	devs := make([]*Device, len(devices))
	copy(devs, devices)
	sortDevices(devs)

	return &Scheduler{
		devices:  devs,
		assigned: make(map[string][]*Handle),
		disabled: make(map[string]bool),
		log:      log,
	}, nil
}

// SetEnabled switches an adapter on or off. A disabled adapter is never assigned to a role, so
// warpd stops using it and leaves the interface free for another tool. Disabling the pinned
// survey adapter also un-pins survey, so it can move to another card when one is available.
// Returns false if the ID names no managed adapter.
func (s *Scheduler) SetEnabled(id string, on bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, dev := range s.devices {
		if dev.ID == id {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if on {
		delete(s.disabled, id)
	} else {
		s.disabled[id] = true
		if s.surveyDevice == id {
			s.surveyDevice = ""
		}
	}
	return true
}

// IsEnabled reports whether an adapter is available for assignment.
func (s *Scheduler) IsEnabled(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.disabled[id]
}

// Devices returns the adapters under management.
func (s *Scheduler) Devices() []*Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Device, len(s.devices))
	copy(out, s.devices)
	return out
}

// Acquire leases a radio for a role.
func (s *Scheduler) Acquire(ctx context.Context, role Role) (*Handle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec, ok := role.Spec()
	if !ok {
		return nil, fmt.Errorf("radio: unknown role %q", role)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// A pinned role may only ever be held once at a time, and always by the same adapter.
	if spec.Pinned {
		for _, handles := range s.assigned {
			for _, h := range handles {
				if h.Role == role {
					return nil, fmt.Errorf("radio: role %q is pinned and already held by %s", role, h.Device.ID)
				}
			}
		}
	}

	candidates, reasons := s.candidatesLocked(role, spec)
	if len(candidates) == 0 {
		// No adapter can host this role alongside what it is already doing. Before refusing,
		// see whether the role can borrow an interface that is already in the right mode.
		//
		// This is what makes a one-adapter kit fully capable rather than half-crippled: a
		// solicitation or deauthentication runs on the capture radio for the length of its
		// burst. What is lost is simultaneity, not capability, and the caller is told which.
		if h := s.borrowLocked(role, spec); h != nil {
			s.log.Info("radio borrowed",
				"role", role, "radio_id", h.Device.ID, "ifname", h.Device.Ifname,
				"from", h.BorrowedFrom)
			return h, nil
		}
		return nil, &UnsatisfiableError{Role: role, PerDevice: reasons}
	}

	best := candidates[0]
	h := &Handle{
		Role:          role,
		Device:        best.dev,
		Iftype:        spec.Iftype,
		SharedChannel: best.channels <= 1 && len(s.assigned[best.dev.ID]) > 0,
		sched:         s,
	}
	s.assigned[best.dev.ID] = append(s.assigned[best.dev.ID], h)

	// Once survey lands on an adapter, that adapter is survey's for the engagement.
	if spec.Pinned && s.surveyDevice == "" && role == RoleSurvey {
		s.surveyDevice = best.dev.ID
	}

	// If this handle must share a channel, so must the ones already on the device.
	if h.SharedChannel {
		for _, other := range s.assigned[best.dev.ID] {
			other.SharedChannel = true
		}
	}

	s.log.Info("radio assigned",
		"role", role, "radio_id", best.dev.ID, "ifname", best.dev.Ifname,
		"iftype", spec.Iftype.String(), "shared_channel", h.SharedChannel)

	return h, nil
}

// borrowLocked grants a role temporary use of an interface another role already owns.
//
// Borrowing is only possible when the interface is already in the mode the role needs - a
// monitor interface can carry a solicitation or a deauthentication, but nothing can borrow a
// monitor interface to run an access point, because that needs a mode change that would tear
// the capture out from under its owner.
//
// The lender must be preemptible. Survey is not: it is pinned for the engagement precisely so
// its observations stay comparable, and interrupting it to transmit would put gaps in the
// coverage picture at exactly the moments the operator was doing something interesting.
func (s *Scheduler) borrowLocked(role Role, spec RoleSpec) *Handle {
	if !spec.Borrowable {
		return nil
	}

	for _, dev := range s.devices {
		// The pinned survey adapter is never lent.
		if s.surveyDevice == dev.ID {
			continue
		}
		if ok, _ := dev.SupportsRole(role); !ok {
			continue
		}

		for _, owner := range s.assigned[dev.ID] {
			ownerSpec, ok := owner.Role.Spec()
			if !ok || !ownerSpec.Lendable {
				continue
			}
			// The mode must already match: borrowing must not reconfigure the interface.
			if owner.Iftype != spec.Iftype {
				continue
			}

			h := &Handle{
				Role:          role,
				Device:        dev,
				Iftype:        spec.Iftype,
				SharedChannel: true,
				Borrowed:      true,
				BorrowedFrom:  owner.Role,
				sched:         s,
			}
			s.assigned[dev.ID] = append(s.assigned[dev.ID], h)
			return h
		}
	}
	return nil
}

// iftypeHeldLocked reports which role already holds this adapter in the given mode, or "".
func (s *Scheduler) iftypeHeldLocked(dev *Device, want nl80211.Iftype) Role {
	for _, h := range s.assigned[dev.ID] {
		if h.Iftype == want {
			return h.Role
		}
	}
	return ""
}

// candidate is a device that can serve a role, with its assignment score.
type candidate struct {
	dev      *Device
	channels uint32 // independent channels the hardware supports for the resulting iftype set
	score    int    // lower is better
}

// candidatesLocked returns viable adapters best-first, plus a rejection reason per adapter
// that was ruled out.
func (s *Scheduler) candidatesLocked(role Role, spec RoleSpec) ([]candidate, []string) {
	var (
		out     []candidate
		reasons []string
	)

	for _, dev := range s.devices {
		// An adapter the operator switched off is never a candidate - warpd leaves it alone so
		// another tool can have it.
		if s.disabled[dev.ID] {
			reasons = append(reasons, fmt.Sprintf("%s: switched off from the radios tab", dev.ID))
			continue
		}

		// The pinned survey adapter is exclusive. Sharing its phy would let another role
		// retune it, and a survey whose radio changed channel or antenna mid-engagement
		// produces RSSI that cannot be compared to anything.
		if s.surveyDevice == dev.ID && role != RoleSurvey {
			reasons = append(reasons, fmt.Sprintf("%s: pinned to survey for the engagement", dev.ID))
			continue
		}

		if ok, why := dev.SupportsRole(role); !ok {
			reasons = append(reasons, fmt.Sprintf("%s: %s", dev.ID, why))
			continue
		}

		// One netdev per adapter per mode. A role wanting a mode this adapter is already in
		// does not get a second assignment - it borrows the existing interface instead.
		//
		// The kernel will happily claim it can host two monitor interfaces on one phy, because
		// on mt76 and similar parts monitor is a *software* iftype and sits outside the
		// advertised interface combinations altogether. There is no second netdev behind that
		// claim: acquiring it reconfigures the one wlan0 recon is already capturing on, which
		// downs the interface, kills the capture with "network is down", and leaves two owners
		// fighting over the iftype on release. It cost the whole capture for the rest of the
		// run, and the only clue was one ERROR line.
		//
		// A genuinely different mode alongside - AP plus monitor, where the hardware really
		// does advertise it - is a real second interface and still gets a real assignment.
		if occupied := s.iftypeHeldLocked(dev, spec.Iftype); occupied != "" {
			reasons = append(reasons, fmt.Sprintf(
				"%s: already in %s mode for %s; a second role in the same mode shares that "+
					"interface rather than reconfiguring it", dev.ID, spec.Iftype, occupied))
			continue
		}

		channels, ok, why := s.concurrencyLocked(dev, spec)
		if !ok {
			reasons = append(reasons, fmt.Sprintf("%s: %s", dev.ID, why))
			continue
		}

		out = append(out, candidate{dev: dev, channels: channels, score: s.scoreLocked(dev, role)})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score < out[j].score
		}
		return out[i].dev.ID < out[j].dev.ID
	})
	return out, reasons
}

// concurrencyLocked checks whether dev can host spec.Iftype alongside what it already hosts,
// and returns how many independent channels the hardware allows for that set.
func (s *Scheduler) concurrencyLocked(dev *Device, spec RoleSpec) (uint32, bool, string) {
	existing := s.assigned[dev.ID]
	if len(existing) == 0 {
		return 1, true, ""
	}
	if dev.Phy == nil {
		return 0, false, "no capability information for this adapter"
	}

	want := map[nl80211.Iftype]uint32{spec.Iftype: 1}
	var held []string
	for _, h := range existing {
		want[h.Iftype]++
		held = append(held, fmt.Sprintf("%s(%s)", h.Role, h.Iftype))
	}

	total := uint32(len(existing) + 1)
	// Prefer independent channels; fall back to a shared channel if that is all the hardware
	// offers. Reporting the best supported value lets the caller know which it got.
	for channels := total; channels >= 1; channels-- {
		if dev.Phy.SupportsConcurrent(want, channels) {
			return channels, true, ""
		}
	}
	return 0, false, fmt.Sprintf("hardware does not support %s alongside %s",
		spec.Iftype, strings.Join(held, "+"))
}

// scoreLocked ranks an adapter for a role. Lower is better.
//
// Two pressures: prefer an idle adapter over sharing a phy, and avoid burning a scarce
// capability on a role that does not need it - assigning plain recon to the only AP-capable
// or only 6 GHz adapter strands the rogue AP later with no clear reason why.
func (s *Scheduler) scoreLocked(dev *Device, role Role) int {
	score := 100 * len(s.assigned[dev.ID])

	if dev.Phy == nil {
		return score + 50
	}

	spec, _ := role.Spec()
	scarce := func(pred func(*Device) bool) int {
		n := 0
		for _, d := range s.devices {
			if pred(d) {
				n++
			}
		}
		return n
	}

	// Penalise using an AP-capable adapter for a role that does not need AP mode, in
	// proportion to how scarce that capability is.
	if spec.Iftype != nl80211.IftypeAP && dev.Phy.SupportsIftype(nl80211.IftypeAP) {
		if n := scarce(func(d *Device) bool {
			return d.Phy != nil && d.Phy.SupportsIftype(nl80211.IftypeAP)
		}); n > 0 {
			score += 20 / n
		}
	}
	// Same for 6 GHz, which few adapters have and which recon on 2.4 does not need.
	if dev.Phy.HasBand(nl80211.Band6GHz) {
		if n := scarce(func(d *Device) bool {
			return d.Phy != nil && d.Phy.HasBand(nl80211.Band6GHz)
		}); n > 0 {
			score += 20 / n
		}
	}
	// And for verified injection, which is the capability most often in short supply.
	if !spec.NeedsInjection && dev.Injection == InjectionVerified {
		if n := scarce(func(d *Device) bool { return d.Injection == InjectionVerified }); n > 0 {
			score += 30 / n
		}
	}

	return score
}

func (s *Scheduler) release(h *Handle) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if h.released {
		return
	}
	h.released = true

	handles := s.assigned[h.Device.ID]
	for i, other := range handles {
		if other == h {
			s.assigned[h.Device.ID] = append(handles[:i], handles[i+1:]...)
			break
		}
	}
	if len(s.assigned[h.Device.ID]) == 0 {
		delete(s.assigned, h.Device.ID)
	}

	s.log.Info("radio released", "role", h.Role, "radio_id", h.Device.ID)
}

// Assignment is the live role/radio mapping, for the REPL status header and `warp radios`.
type Assignment struct {
	Role          Role   `json:"role"`
	RadioID       string `json:"radio_id"`
	Ifname        string `json:"ifname"`
	Iftype        string `json:"iftype"`
	SharedChannel bool   `json:"shared_channel"`
}

// Assignments returns the current role assignments, ordered by radio then role.
func (s *Scheduler) Assignments() []Assignment {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Assignment
	for _, handles := range s.assigned {
		for _, h := range handles {
			out = append(out, Assignment{
				Role:          h.Role,
				RadioID:       h.Device.ID,
				Ifname:        h.Device.Ifname,
				Iftype:        h.Iftype.String(),
				SharedChannel: h.SharedChannel,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RadioID != out[j].RadioID {
			return out[i].RadioID < out[j].RadioID
		}
		return out[i].Role < out[j].Role
	})
	return out
}

// Capability describes whether something can be done with the hardware present.
type Capability struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	// Degraded means it works but not concurrently with capture.
	Degraded bool   `json:"degraded,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Capabilities reports what this set of adapters can and cannot do.
//
// The point is to answer "what am I giving up with the hardware I brought" before the
// engagement rather than during it. Nothing here is a mode: it is a description of the
// adapters present, and the code paths are identical either way.
func (s *Scheduler) Capabilities() []Capability {
	s.mu.Lock()
	defer s.mu.Unlock()

	n := len(s.devices)

	anyAP := false
	anyInjection := false
	anyInconclusive := false
	anyAPMonitor := false
	var injectionNotes []string
	for _, d := range s.devices {
		if d.Phy != nil && d.Phy.SupportsIftype(nl80211.IftypeAP) {
			anyAP = true
			if d.Phy.SupportsAPMonitorConcurrent() {
				anyAPMonitor = true
			}
		}
		if d.Injection.CanTransmit() {
			anyInjection = true
		}
		if d.Injection == InjectionInconclusive {
			anyInconclusive = true
		}
		// The reason a capability is unavailable is per-adapter, so carry the adapter's own
		// note rather than a generic sentence that sends the operator to the wrong command.
		if !d.Injection.CanTransmit() && d.InjectionNote != "" {
			injectionNotes = append(injectionNotes, d.ID+": "+d.InjectionNote)
		}
	}

	out := []Capability{
		{Name: "passive recon", Available: true},
		{Name: "survey walkthroughs", Available: true},
	}

	// Transmitting work needs a verified injection path. With one adapter it borrows the
	// capture radio, which pauses recon for the length of the burst.
	tx := Capability{Name: "PMKID solicitation / deauthentication", Available: anyInjection}
	switch {
	case !anyInjection:
		tx.Reason = "no adapter can transmit - " + strings.Join(injectionNotes, "; ")
		if len(injectionNotes) == 0 {
			tx.Reason = "no adapter has been injection-tested; restart warpd without " +
				"--skip-injection-test, or pass --assume-injection"
		}
	case anyInconclusive && n < RecommendedRadios:
		tx.Degraded = true
		tx.Reason = "runs on the capture radio, pausing recon for the length of each burst. " +
			"Injection was inconclusive at startup (the driver took the frame but does not " +
			"loop it back), so the first burst is the real test"
	case anyInconclusive:
		tx.Degraded = true
		tx.Reason = "injection was inconclusive at startup - the driver accepted the test " +
			"frame but does not loop it back, so the first burst is the real test"
	case n < RecommendedRadios:
		tx.Degraded = true
		tx.Reason = "runs on the capture radio, pausing recon for the length of each burst"
	}
	out = append(out, tx)

	hunt := Capability{Name: "hunt (direction finding)", Available: true}
	if n < RecommendedRadios {
		hunt.Degraded = true
		hunt.Reason = "locks the only adapter to one channel, so recon stops while you walk"
	}
	out = append(out, hunt)

	rogue := Capability{Name: "rogue AP / enterprise credential capture", Available: anyAP}
	switch {
	case !anyAP:
		rogue.Reason = "no adapter supports AP mode"
	case n < RecommendedRadios && !anyAPMonitor:
		rogue.Degraded = true
		rogue.Reason = "the only adapter cannot run AP and monitor together, so recon stops " +
			"while the access point is up"
	case n < RecommendedRadios:
		rogue.Degraded = true
		rogue.Reason = "shares one adapter with capture; both are held on the AP's channel"
	}
	out = append(out, rogue)

	concurrent := Capability{
		Name:      "simultaneous capture and active work",
		Available: n >= RecommendedRadios || anyAPMonitor,
	}
	if !concurrent.Available {
		concurrent.Reason = fmt.Sprintf(
			"%d adapter present; a second one removes every pause above", n)
	}
	out = append(out, concurrent)

	return out
}

// Degraded reports whether any capability is available but not concurrent.
func (s *Scheduler) Degraded() bool {
	for _, c := range s.Capabilities() {
		if c.Degraded || !c.Available {
			return true
		}
	}
	return false
}

// SurveyRadioID returns the adapter pinned to survey, or "" if survey has never been
// acquired. Every observation is stamped with this so a mixed-radio coverage picture is
// detectable at query time.
func (s *Scheduler) SurveyRadioID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.surveyDevice
}
