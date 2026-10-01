package recon

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Cipher suite selector types, under OUI 00-0F-AC (IEEE 802.11-2020 Table 9-149).
const (
	CipherUseGroup   uint8 = 0
	CipherWEP40      uint8 = 1
	CipherTKIP       uint8 = 2
	CipherCCMP128    uint8 = 4
	CipherWEP104     uint8 = 5
	CipherBIPCMAC128 uint8 = 6
	CipherNone       uint8 = 7
	CipherGCMP128    uint8 = 8
	CipherGCMP256    uint8 = 9
	CipherCCMP256    uint8 = 10
	CipherBIPGMAC128 uint8 = 11
	CipherBIPGMAC256 uint8 = 12
	CipherBIPCMAC256 uint8 = 13
)

// AKM suite selector types, under OUI 00-0F-AC (IEEE 802.11-2020 Table 9-151).
const (
	AKM8021X          uint8 = 1
	AKMPSK            uint8 = 2
	AKMFT8021X        uint8 = 3
	AKMFTPSK          uint8 = 4
	AKM8021XSHA256    uint8 = 5
	AKMPSKSHA256      uint8 = 6
	AKMTDLS           uint8 = 7
	AKMSAE            uint8 = 8
	AKMFTSAE          uint8 = 9
	AKMAPPeerKey      uint8 = 10
	AKM8021XSuiteB    uint8 = 11
	AKM8021XSuiteB192 uint8 = 12
	AKMFT8021XSHA384  uint8 = 13
	AKMFILSSHA256     uint8 = 14
	AKMFILSSHA384     uint8 = 15
	AKMFTFILSSHA256   uint8 = 16
	AKMFTFILSSHA384   uint8 = 17
	AKMOWE            uint8 = 18
	AKMFTPSKSHA384    uint8 = 19
	AKMPSKSHA384      uint8 = 20
)

func cipherName(t uint8) string {
	switch t {
	case CipherUseGroup:
		return "use-group"
	case CipherWEP40:
		return "WEP-40"
	case CipherTKIP:
		return "TKIP"
	case CipherCCMP128:
		return "CCMP-128"
	case CipherWEP104:
		return "WEP-104"
	case CipherBIPCMAC128:
		return "BIP-CMAC-128"
	case CipherNone:
		return "none"
	case CipherGCMP128:
		return "GCMP-128"
	case CipherGCMP256:
		return "GCMP-256"
	case CipherCCMP256:
		return "CCMP-256"
	case CipherBIPGMAC128:
		return "BIP-GMAC-128"
	case CipherBIPGMAC256:
		return "BIP-GMAC-256"
	case CipherBIPCMAC256:
		return "BIP-CMAC-256"
	default:
		return fmt.Sprintf("cipher-%d", t)
	}
}

func akmName(t uint8) string {
	switch t {
	case AKM8021X:
		return "802.1X"
	case AKMPSK:
		return "PSK"
	case AKMFT8021X:
		return "FT-802.1X"
	case AKMFTPSK:
		return "FT-PSK"
	case AKM8021XSHA256:
		return "802.1X-SHA256"
	case AKMPSKSHA256:
		return "PSK-SHA256"
	case AKMTDLS:
		return "TDLS"
	case AKMSAE:
		return "SAE"
	case AKMFTSAE:
		return "FT-SAE"
	case AKM8021XSuiteB:
		return "802.1X-Suite-B"
	case AKM8021XSuiteB192:
		return "802.1X-Suite-B-192"
	case AKMFT8021XSHA384:
		return "FT-802.1X-SHA384"
	case AKMFILSSHA256:
		return "FILS-SHA256"
	case AKMFILSSHA384:
		return "FILS-SHA384"
	case AKMFTFILSSHA256:
		return "FT-FILS-SHA256"
	case AKMFTFILSSHA384:
		return "FT-FILS-SHA384"
	case AKMOWE:
		return "OWE"
	case AKMFTPSKSHA384:
		return "FT-PSK-SHA384"
	case AKMPSKSHA384:
		return "PSK-SHA384"
	default:
		return fmt.Sprintf("akm-%d", t)
	}
}

// Suite is a cipher or AKM suite selector: a 3-byte OUI plus a type.
type Suite struct {
	OUI  [3]byte
	Type uint8
}

// IsStandard reports whether the suite uses the IEEE 00-0F-AC OUI rather than a vendor one.
func (s Suite) IsStandard() bool { return s.OUI == OUIIEEE }

// MFPState is the 802.11w management frame protection posture.
//
// This determines whether deauthentication will work, and it is a finding either way: MFP
// required is good practice worth noting, MFP absent is an exposure worth reporting.
type MFPState int

// MFP states.
const (
	// MFPAbsent means neither capable nor required - deauthentication will work.
	MFPAbsent MFPState = iota
	// MFPCapable means supported but not enforced. Clients that negotiate it are protected;
	// clients that do not remain deauthenticatable.
	MFPCapable
	// MFPRequired means enforced - deauthentication of associated clients will not work.
	MFPRequired
	// MFPUnknown means the frame carried no RSN element to read it from.
	MFPUnknown
)

func (m MFPState) String() string {
	switch m {
	case MFPAbsent:
		return "absent"
	case MFPCapable:
		return "capable"
	case MFPRequired:
		return "required"
	default:
		return "unknown"
	}
}

// MarshalText renders the state by name in JSON.
func (m MFPState) MarshalText() ([]byte, error) { return []byte(m.String()), nil }

// UnmarshalText parses the state back from its name, so a value that went out over JSON can be
// read in again. Without this, a client decoding the daemon's AP list - where MFP is a named
// string - fails outright ("cannot unmarshal string into MFPState"), which took the whole `aps`
// listing down with it.
func (m *MFPState) UnmarshalText(b []byte) error {
	switch string(b) {
	case "absent":
		*m = MFPAbsent
	case "capable":
		*m = MFPCapable
	case "required":
		*m = MFPRequired
	default:
		*m = MFPUnknown
	}
	return nil
}

// DeauthViable reports whether deauthentication can be expected to work.
//
// The deauth module consults this and logs a skip where 802.11w is required, rather than
// transmitting frames that will be silently ignored and wasting airtime at a client site.
func (m MFPState) DeauthViable() bool { return m != MFPRequired }

// RSNInfo is a parsed RSN or WPA information element.
type RSNInfo struct {
	// Version is the RSN element version, normally 1.
	Version uint16
	// WPA1 is true when this came from the vendor WPA element rather than the RSN element.
	WPA1 bool

	GroupCipher    Suite
	PairwiseCipher []Suite
	AKM            []Suite

	// Capabilities is the raw RSN capabilities field.
	Capabilities uint16
	HasCaps      bool

	// GroupMgmtCipher is the group management cipher, present only with MFP.
	GroupMgmtCipher Suite
	HasGroupMgmt    bool

	// PMKIDs carried in the element. Present in association frames, not beacons.
	PMKIDs [][]byte
}

// RSN capability bits.
const (
	rsnCapPreauth    = 0x0001
	rsnCapNoPairwise = 0x0002
	rsnCapMFPR       = 0x0040 // management frame protection required
	rsnCapMFPC       = 0x0080 // management frame protection capable
)

// MFP returns the management frame protection posture described by this element.
func (r *RSNInfo) MFP() MFPState {
	if r == nil {
		return MFPUnknown
	}
	// WPA1 predates 802.11w entirely.
	if r.WPA1 || !r.HasCaps {
		return MFPAbsent
	}
	switch {
	case r.Capabilities&rsnCapMFPR != 0:
		return MFPRequired
	case r.Capabilities&rsnCapMFPC != 0:
		return MFPCapable
	default:
		return MFPAbsent
	}
}

// nativeOUI is the OUI this element's suite selectors are defined under.
//
// RSN uses the IEEE 00-0F-AC OUI; the WPA1 vendor element predates that and uses Microsoft's
// 00-50-F2 with the same type numbering for the selectors it supports. Comparing a WPA1
// selector against the IEEE OUI silently classifies every WPA1 network as unknown.
func (r *RSNInfo) nativeOUI() [3]byte {
	if r.WPA1 {
		return OUIMicrosoft
	}
	return OUIIEEE
}

// isNative reports whether a suite selector uses this element's own OUI, and can therefore be
// interpreted against the standard type tables.
func (r *RSNInfo) isNative(s Suite) bool { return s.OUI == r.nativeOUI() }

// HasAKM reports whether the element advertises the given AKM type under its native OUI.
func (r *RSNInfo) HasAKM(t uint8) bool {
	if r == nil {
		return false
	}
	for _, a := range r.AKM {
		if r.isNative(a) && a.Type == t {
			return true
		}
	}
	return false
}

// HasCipher reports whether the element advertises the given pairwise cipher.
func (r *RSNInfo) HasCipher(t uint8) bool {
	if r == nil {
		return false
	}
	for _, c := range r.PairwiseCipher {
		if r.isNative(c) && c.Type == t {
			return true
		}
	}
	return false
}

// Enterprise reports whether any advertised AKM is 802.1X-based.
func (r *RSNInfo) Enterprise() bool {
	if r == nil {
		return false
	}
	for _, a := range r.AKM {
		if !r.isNative(a) {
			continue
		}
		switch a.Type {
		case AKM8021X, AKMFT8021X, AKM8021XSHA256, AKM8021XSuiteB, AKM8021XSuiteB192,
			AKMFT8021XSHA384, AKMFILSSHA256, AKMFILSSHA384, AKMFTFILSSHA256, AKMFTFILSSHA384:
			return true
		}
	}
	return false
}

// PSKBased reports whether any advertised AKM is pre-shared-key based.
func (r *RSNInfo) PSKBased() bool {
	if r == nil {
		return false
	}
	for _, a := range r.AKM {
		if !r.isNative(a) {
			continue
		}
		switch a.Type {
		case AKMPSK, AKMFTPSK, AKMPSKSHA256, AKMFTPSKSHA384, AKMPSKSHA384:
			return true
		}
	}
	return false
}

// CipherNames returns the pairwise cipher names for display.
func (r *RSNInfo) CipherNames() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.PairwiseCipher))
	for _, c := range r.PairwiseCipher {
		out = append(out, r.suiteName(c, cipherName))
	}
	return out
}

// GroupCipherName returns the group (broadcast) cipher name for display, or "" if unset.
func (r *RSNInfo) GroupCipherName() string {
	if r == nil || (r.GroupCipher == Suite{}) {
		return ""
	}
	return r.suiteName(r.GroupCipher, cipherName)
}

// AKMNames returns the AKM names for display.
func (r *RSNInfo) AKMNames() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.AKM))
	for _, a := range r.AKM {
		out = append(out, r.suiteName(a, akmName))
	}
	return out
}

// suiteName renders a selector, using the standard type table only when the selector uses
// this element's own OUI. A genuinely vendor-specific selector is shown as OUI/type rather
// than given a misleading standard name.
func (r *RSNInfo) suiteName(s Suite, table func(uint8) string) string {
	if r.isNative(s) {
		return table(s.Type)
	}
	return fmt.Sprintf("%02x:%02x:%02x/%d", s.OUI[0], s.OUI[1], s.OUI[2], s.Type)
}

// ParseRSN decodes an RSN element payload (element ID 48).
//
// Every field after the group cipher is optional, and real APs truncate the element at
// different points. Each section is therefore length-checked independently and a short
// element yields what was present rather than an error - a beacon that omits the RSN
// capabilities is perfectly legal, and refusing to parse it would drop the AP entirely.
func ParseRSN(b []byte) (*RSNInfo, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("recon: RSN element too short (%d bytes)", len(b))
	}

	r := &RSNInfo{Version: binary.LittleEndian.Uint16(b[0:2])}
	off := 2

	if off+4 > len(b) {
		return r, nil
	}
	r.GroupCipher = parseSuite(b[off:])
	off += 4

	pairwise, n, ok := parseSuiteList(b, off)
	if !ok {
		return r, nil
	}
	r.PairwiseCipher = pairwise
	off = n

	akm, n, ok := parseSuiteList(b, off)
	if !ok {
		return r, nil
	}
	r.AKM = akm
	off = n

	if off+2 > len(b) {
		return r, nil
	}
	r.Capabilities = binary.LittleEndian.Uint16(b[off : off+2])
	r.HasCaps = true
	off += 2

	// PMKID list. Present in EAPOL M1 and association requests, absent from beacons.
	if off+2 > len(b) {
		return r, nil
	}
	pmkidCount := int(binary.LittleEndian.Uint16(b[off : off+2]))
	off += 2
	for i := 0; i < pmkidCount; i++ {
		if off+16 > len(b) {
			return r, nil
		}
		r.PMKIDs = append(r.PMKIDs, append([]byte(nil), b[off:off+16]...))
		off += 16
	}

	if off+4 <= len(b) {
		r.GroupMgmtCipher = parseSuite(b[off:])
		r.HasGroupMgmt = true
	}

	return r, nil
}

// ParseWPA decodes a WPA1 vendor element payload (00:50:F2 subtype 1), with the leading OUI
// and subtype already removed.
func ParseWPA(b []byte) (*RSNInfo, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("recon: WPA element too short (%d bytes)", len(b))
	}

	r := &RSNInfo{Version: binary.LittleEndian.Uint16(b[0:2]), WPA1: true}
	off := 2

	if off+4 > len(b) {
		return r, nil
	}
	r.GroupCipher = parseSuite(b[off:])
	off += 4

	pairwise, n, ok := parseSuiteList(b, off)
	if !ok {
		return r, nil
	}
	r.PairwiseCipher = pairwise
	off = n

	akm, _, ok := parseSuiteList(b, off)
	if !ok {
		return r, nil
	}
	r.AKM = akm

	return r, nil
}

func parseSuite(b []byte) Suite {
	return Suite{OUI: [3]byte{b[0], b[1], b[2]}, Type: b[3]}
}

// parseSuiteList reads a count-prefixed list of suite selectors starting at off.
func parseSuiteList(b []byte, off int) ([]Suite, int, bool) {
	if off+2 > len(b) {
		return nil, off, false
	}
	count := int(binary.LittleEndian.Uint16(b[off : off+2]))
	off += 2

	// A corrupt count could otherwise drive a huge allocation.
	if count < 0 || off+count*4 > len(b) {
		return nil, off, false
	}

	out := make([]Suite, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, parseSuite(b[off:]))
		off += 4
	}
	return out, off, true
}

// Security is WARP's classification of a BSSID's encryption configuration.
type Security string

// Security classifications, as required by the brief.
const (
	SecOpen          Security = "open"
	SecOWE           Security = "owe"
	SecWEP           Security = "wep"
	SecWPAPSK        Security = "wpa_psk"
	SecWPASAE        Security = "wpa_sae"
	SecWPAEnterprise Security = "wpa_enterprise"
	SecWPA3Ent192    Security = "wpa3_enterprise_192"
	SecUnknown       Security = "unknown"
)

// SecurityInfo is the full encryption picture for a BSSID.
type SecurityInfo struct {
	Class     Security `json:"class"`
	MFP       MFPState `json:"mfp"`
	WPS       bool     `json:"wps"`
	WPSLocked bool     `json:"wps_locked"`
	Ciphers   []string `json:"ciphers,omitempty"`
	// GroupCipher is the broadcast/multicast cipher, kept separate from the pairwise Ciphers so the
	// encryption view can show it the way a beacon lays it out.
	GroupCipher string   `json:"group_cipher,omitempty"`
	AKMs        []string `json:"akms,omitempty"`
	// Transition is true for a BSS advertising both a legacy and a modern AKM (WPA2/WPA3
	// mixed mode), which is downgrade-attackable and is a finding.
	Transition bool `json:"transition_mode,omitempty"`
	// WPA1 is true when the key management came only from the legacy WPA vendor element (no RSN
	// element) - i.e. a WPA1 BSS. Both frontends label it so it is not mistaken for WPA2-PSK.
	WPA1 bool `json:"wpa1,omitempty"`

	// RSNElement is the access point's RSN element body, exactly as it broadcast it.
	//
	// Kept so an association request can mirror it. Offering a suite the access point does
	// not support gets the association rejected with an invalid-AKMP or invalid-pairwise
	// status, and the rejection carries no PMKID - which reads as "this AP does not do PMKID"
	// rather than as the mismatch it is. Guessing CCMP+PSK is right often enough to be
	// convincing and wrong often enough to lose whole networks: WPA3-SAE, transition mode,
	// TKIP and enterprise all advertise something else.
	//
	// Not serialised: it is wire data, it is already summarised in Ciphers and AKMs for
	// reporting, and it would be noise in every JSON payload.
	RSNElement []byte `json:"-"`
}

// Describe renders the security posture as a single operator-facing string.
func (s SecurityInfo) Describe() string {
	var b strings.Builder
	b.WriteString(string(s.Class))
	if len(s.Ciphers) > 0 {
		fmt.Fprintf(&b, " [%s]", strings.Join(s.Ciphers, ","))
	}
	if s.MFP != MFPAbsent && s.MFP != MFPUnknown {
		fmt.Fprintf(&b, " mfp=%s", s.MFP)
	}
	if s.WPS {
		b.WriteString(" WPS")
		if s.WPSLocked {
			b.WriteString("(locked)")
		}
	}
	if s.Transition {
		b.WriteString(" transition")
	}
	return b.String()
}

// ClassifySecurity determines a BSSID's encryption configuration from its elements and
// capability field.
//
// The Privacy capability bit alone cannot distinguish WEP from WPA: both set it. WEP is
// therefore identified as "privacy set, but neither an RSN nor a WPA element present", which
// is the only reliable signal available from a beacon.
func ClassifySecurity(ies IEs, capability uint16) SecurityInfo {
	info := SecurityInfo{Class: SecUnknown, MFP: MFPUnknown}
	info.WPS = ies.WPS()
	if locked, known := ies.WPSLocked(); known {
		info.WPSLocked = locked
	}

	rsn := extractRSN(ies)
	wpa := extractWPA(ies)

	if raw, ok := ies.Find(IERSN); ok && len(raw.Data) > 0 {
		// Copied: the IE points into the capture buffer, which is reused for the next frame.
		info.RSNElement = append([]byte(nil), raw.Data...)
	}

	privacy := capability&CapPrivacy != 0

	switch {
	case rsn == nil && wpa == nil && !privacy:
		info.Class = SecOpen
		info.MFP = MFPAbsent
		return info

	case rsn == nil && wpa == nil && privacy:
		// Privacy without any key-management element is WEP.
		info.Class = SecWEP
		info.MFP = MFPAbsent
		return info
	}

	// Prefer the RSN element where both are present (WPA/WPA2 mixed mode).
	primary := rsn
	if primary == nil {
		primary = wpa
	}
	info.MFP = primary.MFP()
	info.Ciphers = primary.CipherNames()
	info.GroupCipher = primary.GroupCipherName()
	info.AKMs = primary.AKMNames()

	switch {
	case primary.HasAKM(AKMOWE):
		info.Class = SecOWE
	case primary.HasAKM(AKM8021XSuiteB192):
		info.Class = SecWPA3Ent192
	case primary.Enterprise():
		info.Class = SecWPAEnterprise
	case primary.HasAKM(AKMSAE) || primary.HasAKM(AKMFTSAE):
		info.Class = SecWPASAE
		// SAE alongside PSK is WPA2/WPA3 transition mode: a client can be induced to use the
		// weaker of the two, so the PSK path remains attackable.
		if primary.PSKBased() {
			info.Transition = true
		}
	case primary.PSKBased():
		info.Class = SecWPAPSK
	default:
		info.Class = SecUnknown
	}

	// A BSS offering both WPA1 and WPA2 is also a downgrade case worth reporting.
	if rsn != nil && wpa != nil {
		info.Transition = true
	}

	// Pure WPA1: the key management came only from the legacy vendor element.
	if rsn == nil && wpa != nil {
		info.WPA1 = true
	}

	return info
}

// extractRSN returns the parsed RSN element, or nil if absent or unparseable.
func extractRSN(ies IEs) *RSNInfo {
	ie, ok := ies.Find(IERSN)
	if !ok {
		return nil
	}
	r, err := ParseRSN(ie.Data)
	if err != nil {
		return nil
	}
	return r
}

// extractWPA returns the parsed WPA1 vendor element, or nil if absent or unparseable.
func extractWPA(ies IEs) *RSNInfo {
	for _, v := range ies.VendorIEs() {
		if v.OUI != OUIMicrosoft || v.Subtype != msSubtypeWPA {
			continue
		}
		r, err := ParseWPA(v.Data)
		if err != nil {
			return nil
		}
		return r
	}
	return nil
}

// RSNPMKIDs returns any PMKIDs carried in an RSN element, deduplicated.
func RSNPMKIDs(ies IEs) [][]byte {
	r := extractRSN(ies)
	if r == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(r.PMKIDs))
	var out [][]byte
	for _, p := range r.PMKIDs {
		k := string(p)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out
}
