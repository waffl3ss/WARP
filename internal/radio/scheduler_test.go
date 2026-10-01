package radio

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testDevice builds an adapter with the given capabilities.
func testDevice(id string, index uint32, iftypes []nl80211.Iftype, inj InjectionStatus, combs []nl80211.IfaceCombination, bands ...nl80211.Band) *Device {
	phy := &nl80211.Wiphy{
		Index:            index,
		Name:             id,
		SupportedIftypes: iftypes,
		Combinations:     combs,
	}
	for _, b := range bands {
		phy.Bands = append(phy.Bands, nl80211.BandInfo{
			Band:  b,
			Name:  b.String(),
			Freqs: []nl80211.Frequency{{MHz: nl80211.FrequencyForChannel(6, b), Channel: 6}},
		})
	}
	// 2.4 GHz by default so HasBand and channel plans have something to work with.
	if len(bands) == 0 {
		phy.Bands = append(phy.Bands, nl80211.BandInfo{
			Band:  nl80211.Band2GHz,
			Name:  nl80211.Band2GHz.String(),
			Freqs: []nl80211.Frequency{{MHz: 2437, Channel: 6}},
		})
	}
	return &Device{ID: id, Phy: phy, Ifname: "if-" + id, Ifindex: index + 1, Injection: inj}
}

var monitorOnly = []nl80211.Iftype{nl80211.IftypeStation, nl80211.IftypeMonitor}
var monitorAndAP = []nl80211.Iftype{nl80211.IftypeStation, nl80211.IftypeMonitor, nl80211.IftypeAP}

// noConcurrency: one interface at a time.
var noConcurrency = []nl80211.IfaceCombination{{
	Limits:        []nl80211.IfaceLimit{{Max: 1, Types: monitorAndAP}},
	MaxInterfaces: 1,
	NumChannels:   1,
}}

// apPlusMonitor mirrors an mt76 part: AP and monitor together on one channel.
var apPlusMonitor = []nl80211.IfaceCombination{{
	Limits: []nl80211.IfaceLimit{
		{Max: 8, Types: []nl80211.Iftype{nl80211.IftypeAP, nl80211.IftypeMeshPoint}},
		{Max: 8, Types: []nl80211.Iftype{nl80211.IftypeStation}},
		{Max: 1, Types: []nl80211.Iftype{nl80211.IftypeMonitor}},
	},
	MaxInterfaces: 8,
	NumChannels:   1,
}}

// TestSingleRadioIsSupported: one adapter is a working kit, not a refused one. What a second
// adapter buys is simultaneity, not capability.
// TestDisabledAdapterIsNeverACandidate: an adapter switched off from the radios tab is released
// to another tool — the scheduler must not assign it any role until it is switched back on.
func TestDisabledAdapterIsNeverACandidate(t *testing.T) {
	two := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency),
		testDevice("phy1", 1, monitorOnly, InjectionVerified, noConcurrency),
	}
	s, err := NewScheduler(two, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	if !s.SetEnabled("phy0", false) {
		t.Fatal("SetEnabled returned false for a managed adapter")
	}
	if s.IsEnabled("phy0") {
		t.Error("phy0 still reads enabled after being switched off")
	}
	if s.SetEnabled("nope", false) {
		t.Error("SetEnabled accepted an unmanaged adapter id")
	}

	// Two acquisitions must both land on phy1 — phy0 is off and out of the running.
	a, err := s.Acquire(context.Background(), RoleRecon)
	if err != nil {
		t.Fatalf("recon could not acquire the one enabled adapter: %v", err)
	}
	if a.Device.ID != "phy1" {
		t.Errorf("recon landed on %q, want phy1 — phy0 is switched off", a.Device.ID)
	}

	// Switch it back on and it is a candidate again.
	s.SetEnabled("phy0", true)
	b, err := s.Acquire(context.Background(), RoleSurvey)
	if err != nil {
		t.Fatalf("survey could not acquire after re-enabling phy0: %v", err)
	}
	if b.Device.ID != "phy0" {
		t.Errorf("survey landed on %q, want the re-enabled phy0", b.Device.ID)
	}
}

func TestSingleRadioIsSupported(t *testing.T) {
	one := []*Device{testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency)}

	s, err := NewScheduler(one, quietLogger())
	if err != nil {
		t.Fatalf("a single adapter was refused: %v", err)
	}

	// Recon gets it, and a transmitting role borrows it rather than being turned away.
	recon, err := s.Acquire(context.Background(), RoleRecon)
	if err != nil {
		t.Fatalf("recon on a single adapter: %v", err)
	}
	solicit, err := s.Acquire(context.Background(), RoleSolicit)
	if err != nil {
		t.Fatalf("solicit could not borrow the only adapter: %v", err)
	}
	if !solicit.Borrowed {
		t.Error("solicit got a dedicated handle where it should have borrowed")
	}
	if solicit.BorrowedFrom != RoleRecon {
		t.Errorf("BorrowedFrom = %q, want recon", solicit.BorrowedFrom)
	}
	if solicit.Device.ID != recon.Device.ID {
		t.Error("the borrowed handle is not on the same adapter")
	}

	// No adapters at all is still an error: there is nothing to work with.
	if _, err := NewScheduler(nil, quietLogger()); !errors.Is(err, ErrNoRadios) {
		t.Fatalf("expected ErrNoRadios with no adapters, got %v", err)
	}
}

// TestBorrowingRequiresAMatchingMode: an access point cannot borrow a monitor interface,
// because bringing it up would tear the capture out from under its owner.
func TestBorrowingRequiresAMatchingMode(t *testing.T) {
	one := []*Device{testDevice("phy0", 0, monitorAndAP, InjectionVerified, noConcurrency)}
	s, _ := NewScheduler(one, quietLogger())

	if _, err := s.Acquire(context.Background(), RoleRecon); err != nil {
		t.Fatalf("acquire recon: %v", err)
	}

	// The rogue AP needs AP mode; the only interface is in monitor mode and cannot be lent.
	_, err := s.Acquire(context.Background(), RoleRogue)
	if err == nil {
		t.Fatal("the rogue AP borrowed a monitor interface")
	}
	var unsat *UnsatisfiableError
	if !errors.As(err, &unsat) {
		t.Fatalf("expected UnsatisfiableError, got %T: %v", err, err)
	}
}

// TestSurveyIsNeverLent: survey is pinned so its observations stay comparable, and
// interrupting it would put gaps in the coverage picture.
func TestSurveyIsNeverLent(t *testing.T) {
	one := []*Device{testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency)}
	s, _ := NewScheduler(one, quietLogger())

	if _, err := s.Acquire(context.Background(), RoleSurvey); err != nil {
		t.Fatalf("acquire survey: %v", err)
	}
	if _, err := s.Acquire(context.Background(), RoleSolicit); err == nil {
		t.Fatal("a transmitting role borrowed the pinned survey adapter")
	}
}

// TestSurveyRadioIsPinnedForTheEngagement is the RSSI-comparability guarantee. If survey
// migrates between adapters, the coverage picture looks correct and means nothing.
func TestSurveyRadioIsPinnedForTheEngagement(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency),
		testDevice("phy1", 1, monitorOnly, InjectionVerified, noConcurrency),
	}
	s, err := NewScheduler(devs, quietLogger())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	ctx := context.Background()

	survey, err := s.Acquire(ctx, RoleSurvey)
	if err != nil {
		t.Fatalf("acquire survey: %v", err)
	}
	pinned := survey.Device.ID
	if s.SurveyRadioID() != pinned {
		t.Fatalf("SurveyRadioID = %q, want %q", s.SurveyRadioID(), pinned)
	}

	// Survey may be held only once at a time.
	if _, err := s.Acquire(ctx, RoleSurvey); err == nil {
		t.Fatal("acquired survey twice concurrently")
	}

	// No other role may take the pinned adapter, even after survey is released.
	survey.Release()
	for i := 0; i < 4; i++ {
		h, err := s.Acquire(ctx, RoleRecon)
		if err != nil {
			t.Fatalf("acquire recon: %v", err)
		}
		if h.Device.ID == pinned {
			t.Fatalf("recon was assigned the pinned survey adapter %s", pinned)
		}
		h.Release()
	}

	// And survey comes back to the same adapter.
	again, err := s.Acquire(ctx, RoleSurvey)
	if err != nil {
		t.Fatalf("re-acquire survey: %v", err)
	}
	if again.Device.ID != pinned {
		t.Fatalf("survey moved adapters: was %s, now %s", pinned, again.Device.ID)
	}
}

// TestASecondRoleInTheSameModeBorrowsRatherThanReassigning.
//
// mt76 and similar parts report monitor as a *software* iftype, outside the advertised
// interface combinations entirely — so the concurrency check says yes to a second monitor
// interface that does not exist. The scheduler handed out a real assignment, the acquirer
// then reconfigured the one wlan0 recon was capturing on, and the capture died with
// "interface wlan0 went down: network is down" and never came back. Every subsequent
// solicitation ran against a tracker that had stopped being fed.
func TestASecondRoleInTheSameModeBorrowsRatherThanReassigning(t *testing.T) {
	// One adapter that claims it can host two interfaces at once.
	devs := []*Device{testDevice("phy0", 0, monitorOnly, InjectionVerified, apPlusMonitor)}
	s, err := NewScheduler(devs, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	recon, err := s.Acquire(ctx, RoleRecon)
	if err != nil {
		t.Fatalf("acquire recon: %v", err)
	}
	if recon.Borrowed {
		t.Fatal("the first monitor role should be a real assignment")
	}

	for _, role := range []Role{RoleSolicit, RoleDeauth, RoleHunt} {
		h, err := s.Acquire(ctx, role)
		if err != nil {
			t.Fatalf("%s could not take the capture radio: %v", role, err)
		}
		if !h.Borrowed {
			t.Errorf("%s got a second assignment on the same adapter in the same mode; "+
				"acquiring it would reconfigure the netdev recon is capturing on", role)
		}
		if h.BorrowedFrom != RoleRecon {
			t.Errorf("%s borrowed from %q, want recon", role, h.BorrowedFrom)
		}
		if h.Device.ID != recon.Device.ID {
			t.Errorf("%s landed on %s, not the adapter recon holds", role, h.Device.ID)
		}
		h.Release()
	}

	// Recon still owns the interface after every borrow has come and gone.
	if held := s.Assignments(); len(held) != 1 || held[0].Role != RoleRecon {
		t.Errorf("recon lost its assignment to a borrower: %+v", held)
	}
	recon.Release()
}

// TestADifferentModeAlongsideIsStillARealAssignment. The fix above must not collapse genuine
// concurrency: AP plus monitor on hardware that really advertises it is two interfaces, and
// borrowing there would need a mode change that tears the capture out from under its owner.
func TestADifferentModeAlongsideIsStillARealAssignment(t *testing.T) {
	devs := []*Device{testDevice("phy0", 0, monitorAndAP, InjectionVerified, apPlusMonitor)}
	s, err := NewScheduler(devs, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	recon, err := s.Acquire(ctx, RoleRecon)
	if err != nil {
		t.Fatal(err)
	}
	defer recon.Release()

	rogue, err := s.Acquire(ctx, RoleRogue)
	if err != nil {
		t.Fatalf("AP alongside monitor was refused on hardware that advertises it: %v", err)
	}
	defer rogue.Release()

	if rogue.Borrowed {
		t.Error("the rogue AP borrowed a monitor interface; that needs a mode change")
	}
	if rogue.Iftype == recon.Iftype {
		t.Error("the rogue AP was placed in monitor mode")
	}
}

// TestInconclusiveInjectionStillTransmits.
//
// "The driver accepted the frame but we never saw it come back" is not a failure — many
// drivers simply do not loop their own transmissions to the monitor socket. Treating that as
// a refusal locked WARP out of adapters that inject perfectly well, which is a worse outcome
// than transmitting with the uncertainty on the record.
func TestInconclusiveInjectionStillTransmits(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionInconclusive, noConcurrency),
	}
	devs[0].InjectionNote = "the driver accepted 8 frame(s) but none were seen back on wlan0"

	s, err := NewScheduler(devs, quietLogger())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	for _, role := range []Role{RoleSolicit, RoleDeauth} {
		h, err := s.Acquire(context.Background(), role)
		if err != nil {
			t.Fatalf("role %q was refused an adapter whose injection was merely inconclusive: %v",
				role, err)
		}
		h.Release()
	}

	// The uncertainty still has to reach the operator rather than being swallowed.
	var tx Capability
	for _, c := range s.Capabilities() {
		if strings.Contains(c.Name, "PMKID") {
			tx = c
		}
	}
	if !tx.Available {
		t.Fatal("transmitting is reported unavailable on an inconclusive adapter")
	}
	if !tx.Degraded {
		t.Error("inconclusive injection is reported as if it were confirmed")
	}
	if !strings.Contains(tx.Reason, "inconclusive") {
		t.Errorf("the capability does not say injection was inconclusive: %q", tx.Reason)
	}
}

// TestUntestedInjectionNamesTheFlagThatFixesIt. The old message told the operator to run
// `warp radios probe`, whose result lives in a different process and never reaches the
// daemon — so following it changed nothing.
func TestUntestedInjectionNamesTheFlagThatFixesIt(t *testing.T) {
	devs := []*Device{testDevice("phy0", 0, monitorOnly, InjectionUnverified, noConcurrency)}
	s, err := NewScheduler(devs, quietLogger())
	if err != nil {
		t.Fatal(err)
	}

	var tx Capability
	for _, c := range s.Capabilities() {
		if strings.Contains(c.Name, "PMKID") {
			tx = c
		}
	}
	if tx.Available {
		t.Fatal("an untested adapter was reported as able to transmit")
	}
	if strings.Contains(tx.Reason, "radios probe") {
		t.Errorf("the reason still points at a command that cannot change the outcome: %q", tx.Reason)
	}
	if !strings.Contains(tx.Reason, "--assume-injection") {
		t.Errorf("the reason does not name a flag that resolves it: %q", tx.Reason)
	}
}

// TestTransmittingRolesRequireVerifiedInjection asserts the capability bitmap is not trusted.
func TestTransmittingRolesRequireVerifiedInjection(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionUnverified, noConcurrency),
		testDevice("phy1", 1, monitorOnly, InjectionFailed, noConcurrency),
	}
	s, err := NewScheduler(devs, quietLogger())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	for _, role := range []Role{RoleSolicit, RoleDeauth} {
		_, err := s.Acquire(context.Background(), role)
		if err == nil {
			t.Fatalf("role %q was assigned an adapter with no verified injection", role)
		}
		var unsat *UnsatisfiableError
		if !errors.As(err, &unsat) {
			t.Fatalf("expected UnsatisfiableError, got %T: %v", err, err)
		}
		// The error must say why, per adapter — a bare "cannot satisfy" sends the operator
		// hunting through dmesg.
		joined := strings.Join(unsat.PerDevice, "\n")
		if !strings.Contains(joined, "has not been tested") || !strings.Contains(joined, "rejected an injected frame") {
			t.Fatalf("error does not explain both adapters:\n%v", err)
		}
	}

	// Passive roles are unaffected by injection status.
	if _, err := s.Acquire(context.Background(), RoleRecon); err != nil {
		t.Fatalf("recon should not require injection: %v", err)
	}
}

func TestUnsupportedIftypeIsRefusedClearly(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency),
		testDevice("phy1", 1, monitorOnly, InjectionVerified, noConcurrency),
	}
	s, _ := NewScheduler(devs, quietLogger())

	_, err := s.Acquire(context.Background(), RoleRogue) // needs AP mode
	if err == nil {
		t.Fatal("rogue AP was assigned an adapter with no AP support")
	}
	if !strings.Contains(err.Error(), "does not support AP mode") {
		t.Fatalf("error should name the missing capability, got: %v", err)
	}
}

// TestAPMonitorConcurrencyIsUsed asserts the interface-combination parsing actually buys us
// the extra logical radio the brief calls out.
func TestAPMonitorConcurrencyIsUsed(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency),
		testDevice("phy1", 1, monitorAndAP, InjectionVerified, apPlusMonitor),
	}
	s, _ := NewScheduler(devs, quietLogger())
	ctx := context.Background()

	// Occupy the monitor-only adapter so the AP-capable one must host both roles.
	recon, err := s.Acquire(ctx, RoleRecon)
	if err != nil {
		t.Fatalf("acquire recon: %v", err)
	}
	if recon.Device.ID != "phy0" {
		t.Fatalf("recon should prefer the less capable adapter, got %s", recon.Device.ID)
	}

	rogue, err := s.Acquire(ctx, RoleRogue)
	if err != nil {
		t.Fatalf("acquire rogue: %v", err)
	}
	hunt, err := s.Acquire(ctx, RoleHunt)
	if err != nil {
		t.Fatalf("AP+monitor concurrency was not used — hunt could not be placed alongside the rogue AP: %v", err)
	}
	if hunt.Device.ID != rogue.Device.ID {
		t.Fatalf("expected hunt to share phy1 with the rogue AP, got %s", hunt.Device.ID)
	}
	// The mt76 combination is #channels <= 1, so both must follow one channel.
	if !hunt.SharedChannel || !rogue.SharedChannel {
		t.Errorf("co-located handles on a single-channel combination must be marked shared: rogue=%v hunt=%v",
			rogue.SharedChannel, hunt.SharedChannel)
	}
}

// TestNoConcurrencyIsRefusedNotSilentlyShared asserts a part that cannot host two interfaces
// produces an error rather than a broken second assignment.
func TestNoConcurrencyIsRefusedNotSilentlyShared(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorAndAP, InjectionVerified, noConcurrency),
		testDevice("phy1", 1, monitorAndAP, InjectionVerified, noConcurrency),
	}
	s, _ := NewScheduler(devs, quietLogger())
	ctx := context.Background()

	held := make([]*Handle, 0, 2)
	for i := 0; i < 2; i++ {
		h, err := s.Acquire(ctx, RoleRecon)
		if err != nil {
			t.Fatalf("acquire recon %d: %v", i, err)
		}
		held = append(held, h)
	}
	if held[0].Device.ID == held[1].Device.ID {
		t.Fatal("two recon roles landed on one adapter that cannot host concurrent interfaces")
	}

	// Both adapters are busy and neither supports a second concurrent interface. A borrowable
	// role shares one rather than failing.
	hunt, err := s.Acquire(ctx, RoleHunt)
	if err != nil {
		t.Fatalf("hunt could not borrow: %v", err)
	}
	if !hunt.Borrowed {
		t.Error("hunt got a dedicated interface on hardware with no concurrency support")
	}
	hunt.Release()

	// A role that cannot borrow is still refused with a clear reason — no silent fallback to
	// an adapter that cannot serve it.
	_, err = s.Acquire(ctx, RoleClient)
	if err == nil {
		t.Fatal("a non-borrowable role was placed on hardware with no concurrency support")
	}
	if !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("error should explain the concurrency limit, got: %v", err)
	}

	held[0].Release()
	if _, err := s.Acquire(ctx, RoleHunt); err != nil {
		t.Fatalf("release did not free the adapter: %v", err)
	}
}

// TestScarceCapabilityIsNotBurned asserts recon does not consume the only AP-capable
// adapter, which would strand the rogue AP later for no visible reason.
func TestScarceCapabilityIsNotBurned(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorAndAP, InjectionVerified, noConcurrency), // the only AP-capable
		testDevice("phy1", 1, monitorOnly, InjectionVerified, noConcurrency),
		testDevice("phy2", 2, monitorOnly, InjectionVerified, noConcurrency),
	}
	s, _ := NewScheduler(devs, quietLogger())
	ctx := context.Background()

	recon, err := s.Acquire(ctx, RoleRecon)
	if err != nil {
		t.Fatalf("acquire recon: %v", err)
	}
	if recon.Device.ID == "phy0" {
		t.Error("recon consumed the only AP-capable adapter")
	}

	if _, err := s.Acquire(ctx, RoleRogue); err != nil {
		t.Fatalf("rogue AP could not be placed after recon: %v", err)
	}
}

func TestReleaseIsIdempotent(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency),
		testDevice("phy1", 1, monitorOnly, InjectionVerified, noConcurrency),
	}
	s, _ := NewScheduler(devs, quietLogger())

	h, err := s.Acquire(context.Background(), RoleRecon)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	h.Release()
	h.Release() // must not corrupt the assignment table
	var nilHandle *Handle
	nilHandle.Release()

	if got := len(s.Assignments()); got != 0 {
		t.Fatalf("expected no assignments after release, got %d", got)
	}
}

func TestAssignmentsReport(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency),
		testDevice("phy1", 1, monitorAndAP, InjectionVerified, apPlusMonitor),
	}
	s, _ := NewScheduler(devs, quietLogger())
	ctx := context.Background()

	if _, err := s.Acquire(ctx, RoleSurvey); err != nil {
		t.Fatalf("acquire survey: %v", err)
	}
	if _, err := s.Acquire(ctx, RoleRecon); err != nil {
		t.Fatalf("acquire recon: %v", err)
	}

	as := s.Assignments()
	if len(as) != 2 {
		t.Fatalf("expected 2 assignments, got %d", len(as))
	}
	for _, a := range as {
		if a.RadioID == "" || a.Ifname == "" || a.Iftype == "" {
			t.Errorf("assignment is missing display fields: %+v", a)
		}
	}
}

func TestUnknownRoleIsRejected(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency),
		testDevice("phy1", 1, monitorOnly, InjectionVerified, noConcurrency),
	}
	s, _ := NewScheduler(devs, quietLogger())

	if _, err := s.Acquire(context.Background(), Role("pwn")); err == nil {
		t.Fatal("unknown role was accepted")
	}
	if Role("pwn").Valid() {
		t.Error("Role.Valid accepted an unknown role")
	}
	for _, r := range AllRoles {
		if !r.Valid() {
			t.Errorf("role %q is in AllRoles but not Valid", r)
		}
	}
}

func TestAcquireHonoursContextCancellation(t *testing.T) {
	devs := []*Device{
		testDevice("phy0", 0, monitorOnly, InjectionVerified, noConcurrency),
		testDevice("phy1", 1, monitorOnly, InjectionVerified, noConcurrency),
	}
	s, _ := NewScheduler(devs, quietLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Acquire(ctx, RoleRecon); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
