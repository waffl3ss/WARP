package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/waffl3ss/warp/internal/recon"
	"github.com/waffl3ss/warp/internal/rpc"
)

// observeBeacon puts an access point into the daemon's tracker the way the air would.
//
// It goes in as a parsed beacon rather than by writing to the tracker's maps directly: active
// work always starts from something WARP heard, and a test that reaches around that would stop
// exercising the thing it is meant to protect.
func observeBeacon(t *testing.T, d *Daemon, bssid, essid string, channel int) recon.MAC {
	return observeBeaconMFP(t, d, bssid, essid, channel, false)
}

func observeBeaconMFP(t *testing.T, d *Daemon, bssid, essid string, channel int, mfpRequired bool) recon.MAC {
	t.Helper()

	addr, err := recon.ParseMAC(bssid)
	if err != nil {
		t.Fatalf("ParseMAC(%q): %v", bssid, err)
	}

	// Fixed fields: timestamp (8), beacon interval (2), capability info (2). Bit 4 of the
	// capability field is Privacy; left clear, so the network reads as open, which is
	// irrelevant here and keeps the fixture minimal.
	body := make([]byte, 12)
	body[8], body[9] = 0x64, 0x00 // 100 TU beacon interval

	// The SSID element. A cloaked network broadcasts it with zero length — that, not its
	// absence, is what "hidden" is on the wire.
	body = append(body, 0x00, byte(len(essid)))
	body = append(body, []byte(essid)...)

	// DS Parameter Set, so the AP has a channel to be held on.
	body = append(body, 0x03, 0x01, byte(channel))

	if mfpRequired {
		body[10] |= 0x10 // capability: Privacy
		body = append(body,
			0x30, 20, // RSN element
			0x01, 0x00, // version 1
			0x00, 0x0F, 0xAC, 0x04, // group cipher: CCMP
			0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // one pairwise cipher: CCMP
			0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, // one AKM: PSK
			0xC0, 0x00, // RSN capabilities: MFPC | MFPR
		)
	}

	f := &recon.Frame{
		Type:      recon.TypeManagement,
		Subtype:   recon.SubtypeBeacon,
		Addr1:     recon.Broadcast,
		Addr2:     addr,
		Addr3:     addr,
		HeaderLen: 24,
		Body:      body,
	}
	rt := recon.RadiotapMeta{
		RSSI: -55, HasRSSI: true,
		Freq: 2407 + channel*5, Channel: channel,
	}
	d.engine.Tracker().Observe(f, rt, "phy0", time.Now())

	if _, ok := d.engine.Tracker().AP(addr); !ok {
		t.Fatalf("the beacon fixture for %s did not land in the tracker", bssid)
	}
	return addr
}

// TestDecloakingOnlyActsOnADiscoveredBSSID.
//
// Decloaking is the one transmission not decided by an ESSID match, which makes it the one
// place a typed-in BSSID could get frames into the air at something WARP never heard. It must
// fail at the lookup.
func TestDecloakingOnlyActsOnADiscoveredBSSID(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI")

	err := c.Call(context.Background(), "decloak",
		map[string]any{"bssid": "a4:2b:8c:99:99:99"}, nil)
	if err == nil {
		t.Fatal("decloaking an unobserved BSSID succeeded")
	}
	var rerr *rpc.Error
	if !errors.As(err, &rerr) || rerr.Code != rpc.CodeNotFound {
		t.Fatalf("got %v, want a not-found error for an unobserved BSSID", err)
	}
}

// TestDecloakingRefusesANetworkThatIsNotHidden: there is nothing to recover, and the operator
// almost certainly meant `psk --deauth`.
func TestDecloakingRefusesANetworkThatIsNotHidden(t *testing.T) {
	d, c := startDaemon(t, "CORP-WIFI")
	observeBeacon(t, d, "a4:2b:8c:11:22:33", "CORP-WIFI", 6)

	err := c.Call(context.Background(), "decloak",
		map[string]any{"bssid": "a4:2b:8c:11:22:33"}, nil)
	if err == nil {
		t.Fatal("decloaking a named network succeeded")
	}
	if !strings.Contains(err.Error(), "CORP-WIFI") {
		t.Errorf("the refusal does not say what the network is already called: %v", err)
	}
}

// TestDecloakingDoesNotNeedAConfirmation.
//
// A hidden network may well be in scope, and there is no way to find out except by recovering
// the name. Requiring a confirmation first asked the operator to assert exactly the fact the
// tool was being asked to establish, which made the feature unusable for the case it exists
// for. The frames are still gated — a veto refuses, a named network refuses — and the audit
// record says plainly that there was no ESSID to decide on.
func TestDecloakingDoesNotNeedAConfirmation(t *testing.T) {
	d, c := startDaemon(t, "CORP-WIFI")
	observeBeacon(t, d, "a4:2b:8c:11:22:44", "", 6)

	var job Job
	err := c.Call(context.Background(), "decloak",
		map[string]any{"bssid": "a4:2b:8c:11:22:44"}, &job)
	if err != nil {
		t.Fatalf("decloaking an unconfirmed hidden network was refused: %v", err)
	}
	if job.ID == "" {
		t.Error("no job was started")
	}
}

// TestDecloakingStillHonoursAVeto: a veto only ever narrows scope, so it applies here too.
func TestDecloakingStillHonoursAVeto(t *testing.T) {
	d, c := startDaemon(t, "CORP-WIFI")
	addr := observeBeacon(t, d, "a4:2b:8c:11:22:66", "", 6)

	if err := d.ws.Gate.Reject(addr.String(), "", "the tenant upstairs"); err != nil {
		t.Fatalf("Reject: %v", err)
	}

	// The refusal comes from the gate at transmit time, inside the job, so the call itself
	// succeeds and the job carries the denial. Either shape is acceptable; what matters is
	// that nothing is authorized.
	var job Job
	if err := c.Call(context.Background(), "decloak",
		map[string]any{"bssid": addr.String()}, &job); err != nil {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var jobs []Job
		if err := c.Call(context.Background(), "jobs.list", nil, &jobs); err == nil {
			for _, j := range jobs {
				if j.ID != job.ID {
					continue
				}
				switch j.State {
				case JobDenied, JobFailed:
					return
				case JobDone:
					t.Fatal("a vetoed BSSID was decloaked")
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestDecloakingRefusesWhereManagementFramesAreProtected.
//
// 802.11w means associated clients ignore unprotected deauthentication, so they cannot be made
// to reassociate and the name will not appear. Transmitting anyway would waste airtime at a
// client site and report a false negative.
func TestDecloakingRefusesWhereManagementFramesAreProtected(t *testing.T) {
	d, c := startDaemon(t, "CORP-WIFI")
	addr := observeBeaconMFP(t, d, "a4:2b:8c:11:22:55", "", 6, true)

	// Confirm it, so the refusal that comes back is the 802.11w one and not the confirmation.
	if err := d.ws.Gate.Confirm(addr.String(), "", "test fixture"); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !mfpRequiredInTracker(t, d, addr) {
		t.Fatal("the beacon fixture's RSN capabilities did not parse as 802.11w required")
	}

	err := c.Call(context.Background(), "decloak", map[string]any{"bssid": addr.String()}, nil)
	if err == nil || !strings.Contains(err.Error(), "802.11w") {
		t.Fatalf("got %v, want a refusal naming 802.11w", err)
	}
}

func mfpRequiredInTracker(t *testing.T, d *Daemon, addr recon.MAC) bool {
	t.Helper()
	ap, ok := d.engine.Tracker().AP(addr)
	return ok && ap.Security.MFP == recon.MFPRequired
}

// TestSolicitationMirrorsTheAccessPointsOwnRSN.
//
// The association request used to advertise a guessed CCMP+PSK. An access point running SAE,
// transition mode, TKIP or enterprise rejects that outright with an invalid-AKMP status, and
// the rejection carries no PMKID — which reads as "this AP does not support PMKID" rather than
// as the mismatch it is. The AP states its own RSN in its beacon; mirror it.
func TestSolicitationMirrorsTheAccessPointsOwnRSN(t *testing.T) {
	d, _ := startDaemon(t, "CORP-WIFI")
	addr := observeBeaconMFP(t, d, "a4:2b:8c:11:22:77", "CORP-WIFI", 6, true)

	ap, ok := d.engine.Tracker().AP(addr)
	if !ok {
		t.Fatal("the beacon fixture did not land in the tracker")
	}
	if len(ap.Security.RSNElement) == 0 {
		t.Fatal("the access point's RSN element was not kept; solicitation has nothing to mirror")
	}

	// It must be the bytes off the air, not a reconstruction: the fixture's RSN advertises
	// 802.11w required, and a rebuilt element would lose that.
	if got := ap.Security.RSNElement; got[len(got)-2] != 0xC0 {
		t.Errorf("RSN capabilities = %#x, want the 0xC0 the beacon carried", got[len(got)-2])
	}
}

// TestJobResultsSayWhatHappened.
//
// "job 3 done: wps a4:2b:8c:11:22:33" is not an answer to "did the PIN come out". A completed
// job carries its own one-line summary so the log and the job list say what was found.
func TestJobResultsSayWhatHappened(t *testing.T) {
	var results []Summariser = []Summariser{
		CampaignResult{Outcome: "captured a handshake"},
		WPSResult{Outcome: "PIN not recovered; the nonces were sound"},
		HarvestResult{Outcome: "harvested CN=radius.acme.example"},
	}
	for _, r := range results {
		if r.Summary() == "" {
			t.Errorf("%T summarises to nothing", r)
		}
	}
}

// TestSAEIsExplainedRatherThanSilentlyFutile.
//
// A WPA3-SAE handshake is not crackable: the key comes out of the dragonfly exchange rather
// than PBKDF2 over a passphrase, so hashcat 22000 — which is exactly the PBKDF2 part — has
// nothing to attack. SAE also mandates 802.11w, so the deauthentication that would provoke a
// handshake is ignored. An operator spending airtime on that deserves to be told, not left to
// conclude the tool is broken.
func TestSAEIsExplainedRatherThanSilentlyFutile(t *testing.T) {
	sae := recon.AP{Security: recon.SecurityInfo{Class: recon.SecWPASAE}}
	why := crackableCheck(sae)
	if why == "" {
		t.Fatal("SAE produced no explanation")
	}
	for _, want := range []string{"not crackable", "802.11w", "pass"} {
		if !strings.Contains(why, want) {
			t.Errorf("the explanation does not mention %q: %s", want, why)
		}
	}

	// Transition mode is the case that IS worth attacking: clients on the PSK half still
	// produce crackable handshakes, and saying otherwise would talk the operator out of a
	// real finding.
	transition := recon.AP{Security: recon.SecurityInfo{
		Class: recon.SecWPASAE, Transition: true,
	}}
	if got := crackableCheck(transition); got != "" {
		t.Errorf("transition mode was warned about: %s", got)
	}

	// And ordinary PSK, which is the whole point of the tool, must say nothing at all.
	psk := recon.AP{Security: recon.SecurityInfo{Class: recon.SecWPAPSK}}
	if got := crackableCheck(psk); got != "" {
		t.Errorf("WPA-PSK was warned about: %s", got)
	}

	// Enterprise points at the right command rather than at a handshake that does not exist.
	ent := recon.AP{Security: recon.SecurityInfo{Class: recon.SecWPAEnterprise}}
	if got := crackableCheck(ent); !strings.Contains(got, "warp eap") {
		t.Errorf("enterprise does not point at the enterprise path: %s", got)
	}
}
