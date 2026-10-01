package daemon

import (
	"testing"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
	"github.com/waffl3ss/warp/internal/recon"
)

func testAPForConnect(class recon.Security) recon.AP {
	return recon.AP{
		BSSID:    recon.MAC{0x9c, 0xef, 0xd5, 0xfd, 0x0f, 0x42},
		ESSID:    "Waffles-Corp",
		Freq:     2437,
		Channel:  6,
		Security: recon.SecurityInfo{Class: class},
	}
}

// TestConnectParamsMirrorTheAdvertisedRSN builds the connect crypto from the access point's real
// RSN element rather than a guessed WPA2/CCMP, which is what stops an enterprise access point
// refusing the association with a bare status-1. It also checks 802.11w is carried, and that the
// four RSN-element bytes of a suite become the right nl80211 selector (00-0F-AC-04 → 0x000FAC04).
func TestConnectParamsMirrorTheAdvertisedRSN(t *testing.T) {
	// A WPA2-Enterprise RSN element: version, group CCMP, one pairwise CCMP, one AKM 802.1X,
	// RSN capabilities with MFP required + capable.
	rsn := []byte{
		0x01, 0x00, // version 1
		0x00, 0x0f, 0xac, 0x04, // group cipher CCMP
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, // 1 pairwise: CCMP
		0x01, 0x00, 0x00, 0x0f, 0xac, 0x01, // 1 AKM: 802.1X
		0xc0, 0x00, // RSN caps: MFPR|MFPC
	}
	ap := testAPForConnect(recon.SecWPAEnterprise)
	ap.Security.RSNElement = rsn
	ap.Security.MFP = recon.MFPRequired

	p, ok := connectParamsForAP(ap)
	if !ok {
		t.Fatal("enterprise AP should map to connect params")
	}
	if p.Group != 0x000FAC04 {
		t.Errorf("group cipher = %08x, want CCMP 0x000FAC04", p.Group)
	}
	if len(p.Pairwise) != 1 || p.Pairwise[0] != 0x000FAC04 {
		t.Errorf("pairwise = %v, want [CCMP]", p.Pairwise)
	}
	if len(p.AKMs) != 1 || p.AKMs[0] != 0x000FAC01 {
		t.Errorf("akm = %v, want [802.1X 0x000FAC01]", p.AKMs)
	}
	if p.MFP != nl80211.MFPRequired {
		t.Errorf("MFP = %d, want required (%d)", p.MFP, nl80211.MFPRequired)
	}
	if !p.ControlPortOverNL80211 {
		t.Error("enterprise must own the control port over nl80211")
	}
}

// TestMFPCapableDoesNotRequestOptional: an MFP-*capable* (not required) AP must not make WARP
// request NL80211_MFP_OPTIONAL, which returns -EOPNOTSUPP on drivers without the ext feature (mt76)
// and killed the cert harvest against a real enterprise AP. WARP abandons before the four-way, so a
// non-PMF association is correct; MFP-required still gets MFP_REQUIRED.
func TestMFPCapableDoesNotRequestOptional(t *testing.T) {
	ap := testAPForConnect(recon.SecWPAEnterprise)
	ap.Security.MFP = recon.MFPCapable
	p, ok := connectParamsForAP(ap)
	if !ok {
		t.Fatal("MFP-capable enterprise AP should map to connect params")
	}
	if p.MFP == nl80211.MFPOptional {
		t.Errorf("MFP = optional (%d) — that returns EOPNOTSUPP on mt76; want no MFP (%d)",
			nl80211.MFPOptional, nl80211.MFPNo)
	}
	if p.MFP != nl80211.MFPNo {
		t.Errorf("MFP = %d, want none (%d) for a capable-but-not-required AP", p.MFP, nl80211.MFPNo)
	}

	ap.Security.MFP = recon.MFPRequired
	if p, _ := connectParamsForAP(ap); p.MFP != nl80211.MFPRequired {
		t.Errorf("MFP-required AP: MFP = %d, want required (%d)", p.MFP, nl80211.MFPRequired)
	}
}

func TestConnectParamsForEnterprise(t *testing.T) {
	p, ok := connectParamsForAP(testAPForConnect(recon.SecWPAEnterprise))
	if !ok {
		t.Fatal("enterprise AP should map to connect params")
	}
	if string(p.SSID) != "Waffles-Corp" || p.FreqMHz != 2437 {
		t.Errorf("ssid/freq wrong: %q %d", p.SSID, p.FreqMHz)
	}
	if len(p.BSSID) != 6 || p.BSSID[0] != 0x9c {
		t.Errorf("bssid not carried: %x", p.BSSID)
	}
	if p.WPAVersions != nl80211.WPAVersion2 {
		t.Errorf("wpa version = %d, want WPA2", p.WPAVersions)
	}
	if len(p.AKMs) != 1 || p.AKMs[0] != nl80211.AKM8021X {
		t.Errorf("akm = %v, want 802.1X", p.AKMs)
	}
	if !p.ControlPortOverNL80211 {
		t.Error("enterprise must own the control port so our EAP-TLS client can reach the certificate")
	}
}

func TestConnectParamsForPSK(t *testing.T) {
	p, ok := connectParamsForAP(testAPForConnect(recon.SecWPAPSK))
	if !ok {
		t.Fatal("PSK AP should map to connect params")
	}
	if len(p.AKMs) != 1 || p.AKMs[0] != nl80211.AKMPSK {
		t.Errorf("akm = %v, want PSK", p.AKMs)
	}
	if p.ControlPortOverNL80211 {
		t.Error("PSK does not need the control port — the M1 is read as an ordinary EAPOL frame")
	}
}

func TestConnectParamsRefusesSAEAndWEP(t *testing.T) {
	for _, class := range []recon.Security{recon.SecWPASAE, recon.SecWEP, recon.SecUnknown} {
		if _, ok := connectParamsForAP(testAPForConnect(class)); ok {
			t.Errorf("%s should not map to a driveable association", class)
		}
	}
}

// TestConnectParamsSAETransitionAssociatesOnThePSKSide: a transition-mode BSS advertises SAE and
// PSK, and the PSK side sends a crackable PMKID. WARP must associate on it, offering only the PSK
// AKM (offering SAE too would invite the kernel to run dragonfly, which needs a passphrase).
func TestConnectParamsSAETransitionAssociatesOnThePSKSide(t *testing.T) {
	ap := testAPForConnect(recon.SecWPASAE)
	ap.Security.Transition = true

	p, ok := connectParamsForAP(ap)
	if !ok {
		t.Fatal("a transition-mode SAE/PSK AP should be driveable on the PSK side for a PMKID")
	}
	if len(p.AKMs) != 1 || p.AKMs[0] != nl80211.AKMPSK {
		t.Errorf("akm = %v, want PSK only (SAE would need a passphrase)", p.AKMs)
	}
}

func TestConnectParamsRefusesIncompleteAP(t *testing.T) {
	ap := testAPForConnect(recon.SecWPAEnterprise)
	ap.ESSID = ""
	if _, ok := connectParamsForAP(ap); ok {
		t.Error("an AP with no ESSID cannot be associated to")
	}
	ap = testAPForConnect(recon.SecWPAEnterprise)
	ap.Freq = 0
	if _, ok := connectParamsForAP(ap); ok {
		t.Error("an AP with no frequency cannot be associated to")
	}
}
