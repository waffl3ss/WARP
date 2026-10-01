package recon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Information element IDs (IEEE 802.11-2020 Table 9-92).
const (
	IESSID                 uint8 = 0
	IESupportedRates       uint8 = 1
	IEDSParameterSet       uint8 = 3
	IETIM                  uint8 = 5
	IECountry              uint8 = 7
	IEBSSLoad              uint8 = 11
	IEPowerConstraint      uint8 = 32
	IETPCReport            uint8 = 35
	IEERPInfo              uint8 = 42
	IEHTCapabilities       uint8 = 45
	IERSN                  uint8 = 48
	IEExtendedRates        uint8 = 50
	IESupportedOpClasses   uint8 = 59
	IEHTOperation          uint8 = 61
	IERMEnabledCaps        uint8 = 70
	IEMobilityDomain       uint8 = 54
	IEOverlappingBSSScan   uint8 = 74
	IEInterworking         uint8 = 107
	IEMeshID               uint8 = 114
	IEExtendedCapabilities uint8 = 127
	IEVHTCapabilities      uint8 = 191
	IEVHTOperation         uint8 = 192
	IEVendorSpecific       uint8 = 221
	IEElementExtension     uint8 = 255
)

// Element-extension IDs, used when ID == IEElementExtension.
const (
	IEExtHECapabilities  uint8 = 35
	IEExtHEOperation     uint8 = 36
	IEExtHE6GHzCaps      uint8 = 59
	IEExtEHTOperation    uint8 = 106
	IEExtEHTCapabilities uint8 = 108
)

// Well-known vendor OUIs.
var (
	OUIMicrosoft = [3]byte{0x00, 0x50, 0xf2} // WPA1, WPS, WMM
	OUIWiFiAlats = [3]byte{0x50, 0x6f, 0x9a} // Wi-Fi Alliance (P2P, Passpoint)
	OUIIEEE      = [3]byte{0x00, 0x0f, 0xac} // RSN suite selectors
)

// Microsoft vendor IE subtypes.
const (
	msSubtypeWPA = 1
	msSubtypeWMM = 2
	msSubtypeWPS = 4
)

// IE is one information element, kept exactly as it appeared on the wire.
type IE struct {
	ID uint8
	// ExtID is meaningful only when ID is IEElementExtension.
	ExtID uint8
	// Data is the element payload, excluding the ID/length header and, for extension
	// elements, excluding the extension ID.
	Data []byte
}

// IEs is an ordered list of information elements.
//
// Order is preserved deliberately. Vendors emit elements in a fixed order determined by their
// firmware, so the *sequence* of element IDs is one of the strongest components of a radio
// fingerprint - an impostor running hostapd emits a recognisably different order from a
// Cisco or Aruba AP even when every individual element matches.
type IEs []IE

// ErrTruncatedIE is returned when an element claims more bytes than remain.
var ErrTruncatedIE = errors.New("recon: truncated information element")

// ParseIEs decodes a sequence of information elements.
//
// A truncated trailing element returns the elements parsed so far along with the error, so a
// clipped capture still yields a usable BSSID record rather than nothing at all.
func ParseIEs(b []byte) (IEs, error) {
	var out IEs
	for off := 0; off < len(b); {
		if off+2 > len(b) {
			return out, ErrTruncatedIE
		}
		id, length := b[off], int(b[off+1])
		off += 2

		if off+length > len(b) {
			return out, ErrTruncatedIE
		}
		data := b[off : off+length]
		off += length

		ie := IE{ID: id, Data: data}
		if id == IEElementExtension {
			if length < 1 {
				return out, ErrTruncatedIE
			}
			ie.ExtID = data[0]
			ie.Data = data[1:]
		}
		out = append(out, ie)
	}
	return out, nil
}

// Find returns the first element with the given ID.
func (ies IEs) Find(id uint8) (IE, bool) {
	for _, ie := range ies {
		if ie.ID == id {
			return ie, true
		}
	}
	return IE{}, false
}

// FindExt returns the first element-extension with the given extension ID.
func (ies IEs) FindExt(extID uint8) (IE, bool) {
	for _, ie := range ies {
		if ie.ID == IEElementExtension && ie.ExtID == extID {
			return ie, true
		}
	}
	return IE{}, false
}

// Has reports whether an element with the given ID is present.
func (ies IEs) Has(id uint8) bool {
	_, ok := ies.Find(id)
	return ok
}

// SSID returns the network name and whether it was present and non-hidden.
//
// A hidden network beacons either a zero-length SSID or one filled with NUL bytes. Both are
// reported as absent: an unresolved hidden network must not match a scoped ESSID, and it
// stays passive-observation-only until a probe or association frame reveals the real name.
func (ies IEs) SSID() (string, bool) {
	ie, ok := ies.Find(IESSID)
	if !ok || len(ie.Data) == 0 {
		return "", false
	}
	allZero := true
	for _, b := range ie.Data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", false
	}
	return string(ie.Data), true
}

// Channel returns the channel from the DS Parameter Set or HT Operation element.
//
// The DS element is authoritative on 2.4 GHz. On 5/6 GHz many APs omit it and the channel
// must come from HT Operation, so both are consulted before falling back to the radiotap
// frequency.
func (ies IEs) Channel() (int, bool) {
	if ie, ok := ies.Find(IEDSParameterSet); ok && len(ie.Data) >= 1 {
		return int(ie.Data[0]), true
	}
	if ie, ok := ies.Find(IEHTOperation); ok && len(ie.Data) >= 1 {
		return int(ie.Data[0]), true
	}
	return 0, false
}

// Country returns the regulatory country code.
func (ies IEs) Country() (string, bool) {
	ie, ok := ies.Find(IECountry)
	if !ok || len(ie.Data) < 2 {
		return "", false
	}
	return string(ie.Data[:2]), true
}

// SupportedRates returns the basic and extended rate sets in units of 500 kbps, with the
// basic-rate flag bit preserved.
//
// The flag bit is kept rather than masked off because which rates an AP marks *basic* is part
// of its configuration, and therefore part of the fingerprint.
func (ies IEs) SupportedRates() []byte {
	var out []byte
	if ie, ok := ies.Find(IESupportedRates); ok {
		out = append(out, ie.Data...)
	}
	if ie, ok := ies.Find(IEExtendedRates); ok {
		out = append(out, ie.Data...)
	}
	return out
}

// VendorIE is a decoded vendor-specific element.
type VendorIE struct {
	OUI     [3]byte
	Subtype uint8
	Data    []byte
}

// OUIString renders the OUI in colon form.
func (v VendorIE) OUIString() string {
	return fmt.Sprintf("%02x:%02x:%02x", v.OUI[0], v.OUI[1], v.OUI[2])
}

// Key returns the fingerprint key for this vendor element: OUI plus subtype.
func (v VendorIE) Key() string {
	return fmt.Sprintf("%02x%02x%02x:%02x", v.OUI[0], v.OUI[1], v.OUI[2], v.Subtype)
}

// VendorIEs returns every vendor-specific element, in order.
//
// The *set* of vendor elements an AP emits is highly characteristic of its firmware - a Cisco
// AP advertises Cisco elements, an Aruba AP advertises Aruba ones, and a laptop running
// hostapd advertises almost none. This is the single most useful fingerprint component.
func (ies IEs) VendorIEs() []VendorIE {
	var out []VendorIE
	for _, ie := range ies {
		if ie.ID != IEVendorSpecific || len(ie.Data) < 4 {
			continue
		}
		out = append(out, VendorIE{
			OUI:     [3]byte{ie.Data[0], ie.Data[1], ie.Data[2]},
			Subtype: ie.Data[3],
			Data:    ie.Data[4:],
		})
	}
	return out
}

// WPS reports whether a WPS element is present, which is a finding in its own right.
func (ies IEs) WPS() bool {
	for _, v := range ies.VendorIEs() {
		if v.OUI == OUIMicrosoft && v.Subtype == msSubtypeWPS {
			return true
		}
	}
	return false
}

// WPSLocked reports whether WPS is present and its AP Setup Locked attribute is set.
//
// Unlocked WPS is materially worse than locked WPS - it is the online-PIN-attack case - so
// the two are distinguished rather than both reported as "WPS enabled".
func (ies IEs) WPSLocked() (locked bool, known bool) {
	const attrAPSetupLocked = 0x1057

	for _, v := range ies.VendorIEs() {
		if v.OUI != OUIMicrosoft || v.Subtype != msSubtypeWPS {
			continue
		}
		// WPS attributes are big-endian TLVs: type(2) + length(2) + value.
		for off := 0; off+4 <= len(v.Data); {
			typ := binary.BigEndian.Uint16(v.Data[off : off+2])
			l := int(binary.BigEndian.Uint16(v.Data[off+2 : off+4]))
			off += 4
			if off+l > len(v.Data) {
				return false, false
			}
			if typ == attrAPSetupLocked && l >= 1 {
				return v.Data[off] != 0, true
			}
			off += l
		}
	}
	return false, false
}

// HTCapabilities returns the raw HT capability info field.
func (ies IEs) HTCapabilities() (uint16, bool) {
	ie, ok := ies.Find(IEHTCapabilities)
	if !ok || len(ie.Data) < 2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(ie.Data[:2]), true
}

// VHTCapabilities returns the raw VHT capability info field.
func (ies IEs) VHTCapabilities() (uint32, bool) {
	ie, ok := ies.Find(IEVHTCapabilities)
	if !ok || len(ie.Data) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(ie.Data[:4]), true
}

// HasHE reports whether the AP advertises 802.11ax capability.
func (ies IEs) HasHE() bool {
	_, ok := ies.FindExt(IEExtHECapabilities)
	return ok
}

// HasEHT reports whether the AP advertises 802.11be capability.
func (ies IEs) HasEHT() bool {
	_, ok := ies.FindExt(IEExtEHTCapabilities)
	return ok
}

// IDs returns the element IDs in wire order, with extension elements rendered as 255.extID.
//
// This sequence is a fingerprint component in its own right - see the IEs doc comment.
func (ies IEs) IDs() []string {
	out := make([]string, 0, len(ies))
	for _, ie := range ies {
		if ie.ID == IEElementExtension {
			out = append(out, fmt.Sprintf("255.%d", ie.ExtID))
			continue
		}
		out = append(out, fmt.Sprintf("%d", ie.ID))
	}
	return out
}

// PHYModes names the 802.11 generations an access point advertises, newest first.
//
// Derived from the capability elements rather than from the rates, because the rates say what
// a station may transmit at and the elements say what the radio actually is. The band matters
// to the answer: 802.11b and g exist only at 2.4 GHz and 802.11a only at 5 GHz, so the same
// element set means different things in different places.
//
//	"ax/n/g"  a modern 2.4 GHz radio
//	"ac/n/a"  a typical 5 GHz radio
//	"g"       2.4 GHz with no HT at all - an old access point, and a finding on its own
//	"b"       DSSS rates only; genuinely ancient
func (ies IEs) PHYModes(band string) string {
	var modes []string

	if ies.HasEHT() {
		modes = append(modes, "be")
	}
	if ies.HasHE() {
		modes = append(modes, "ax")
	}
	if _, ok := ies.VHTCapabilities(); ok {
		// VHT is 5 GHz only in the standard. Some 2.4 GHz radios advertise it anyway
		// (Broadcom's "TurboQAM" and friends); reporting what was advertised is the honest
		// thing, and it is itself a distinguishing fingerprint.
		modes = append(modes, "ac")
	}
	if _, ok := ies.HTCapabilities(); ok {
		modes = append(modes, "n")
	}

	// The base PHY, which every access point has whether or not it says so.
	switch {
	case strings.HasPrefix(band, "5"), strings.HasPrefix(band, "6"):
		modes = append(modes, "a")
	default:
		// 2.4 GHz. OFDM rates mean 802.11g; only the DSSS rates means 802.11b and nothing more.
		if hasOFDMRate(ies.SupportedRates()) {
			modes = append(modes, "g")
		} else {
			modes = append(modes, "b")
		}
	}

	return strings.Join(modes, "/")
}

// dsssRates are the four 802.11b rates, in the 500 kbit/s units the rate elements use. Any
// rate outside this set is OFDM, which is 802.11g.
var dsssRates = map[byte]bool{2: true, 4: true, 11: true, 22: true}

func hasOFDMRate(rates []byte) bool {
	for _, r := range rates {
		// The top bit marks a basic rate and is not part of the value.
		if !dsssRates[r&0x7F] {
			return true
		}
	}
	return false
}
