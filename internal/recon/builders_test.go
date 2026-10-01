package recon

import "encoding/binary"

// Frame and element builders shared by the recon tests.
//
// Tests state what they mean — "a WPA2-Enterprise beacon with MFP required" — rather than
// carrying hand-assembled byte slices, so a failure points at the behaviour rather than at
// somebody's hex arithmetic.

func mac(s string) MAC {
	m, err := ParseMAC(s)
	if err != nil {
		panic("bad MAC in test fixture: " + s) //nolint:forbidigo // test fixture only
	}
	return m
}

// ie encodes one information element.
func ie(id uint8, data ...byte) []byte {
	out := []byte{id, byte(len(data))}
	return append(out, data...)
}

// extIE encodes an element-extension.
func extIE(extID uint8, data ...byte) []byte {
	body := append([]byte{extID}, data...)
	return append([]byte{IEElementExtension, byte(len(body))}, body...)
}

func ssidIE(essid string) []byte { return ie(IESSID, []byte(essid)...) }

// hiddenSSIDIE encodes a cloaked SSID of the given length, as APs that pad with NULs emit.
func hiddenSSIDIE(n int) []byte { return ie(IESSID, make([]byte, n)...) }

func dsIE(channel uint8) []byte { return ie(IEDSParameterSet, channel) }

func ratesIE(rates ...byte) []byte { return ie(IESupportedRates, rates...) }

func suite(oui [3]byte, t uint8) []byte { return []byte{oui[0], oui[1], oui[2], t} }

// rsnIE builds an RSN element. caps is appended only when hasCaps is set, mirroring the real
// world where the capabilities field is optional.
func rsnIE(group uint8, pairwise []uint8, akms []uint8, caps uint16, hasCaps bool) []byte {
	body := []byte{0x01, 0x00} // version 1
	body = append(body, suite(OUIIEEE, group)...)

	body = binary.LittleEndian.AppendUint16(body, uint16(len(pairwise)))
	for _, p := range pairwise {
		body = append(body, suite(OUIIEEE, p)...)
	}

	body = binary.LittleEndian.AppendUint16(body, uint16(len(akms)))
	for _, a := range akms {
		body = append(body, suite(OUIIEEE, a)...)
	}

	if hasCaps {
		body = binary.LittleEndian.AppendUint16(body, caps)
	}
	return ie(IERSN, body...)
}

// rsnIEWithPMKID builds an RSN element carrying a PMKID list, as appears in EAPOL M1.
func rsnIEWithPMKID(pmkids ...[]byte) []byte {
	body := []byte{0x01, 0x00}
	body = append(body, suite(OUIIEEE, CipherCCMP128)...)
	body = binary.LittleEndian.AppendUint16(body, 1)
	body = append(body, suite(OUIIEEE, CipherCCMP128)...)
	body = binary.LittleEndian.AppendUint16(body, 1)
	body = append(body, suite(OUIIEEE, AKMPSK)...)
	body = binary.LittleEndian.AppendUint16(body, 0) // capabilities
	body = binary.LittleEndian.AppendUint16(body, uint16(len(pmkids)))
	for _, p := range pmkids {
		body = append(body, p...)
	}
	return ie(IERSN, body...)
}

// wpaIE builds a WPA1 vendor element (00:50:F2 subtype 1).
func wpaIE(group uint8, pairwise []uint8, akms []uint8) []byte {
	body := []byte{OUIMicrosoft[0], OUIMicrosoft[1], OUIMicrosoft[2], msSubtypeWPA}
	body = append(body, 0x01, 0x00) // version 1
	body = append(body, suite(OUIMicrosoft, group)...)

	body = binary.LittleEndian.AppendUint16(body, uint16(len(pairwise)))
	for _, p := range pairwise {
		body = append(body, suite(OUIMicrosoft, p)...)
	}
	body = binary.LittleEndian.AppendUint16(body, uint16(len(akms)))
	for _, a := range akms {
		body = append(body, suite(OUIMicrosoft, a)...)
	}
	return ie(IEVendorSpecific, body...)
}

// wpsIE builds a WPS vendor element. When locked is set it carries the AP Setup Locked
// attribute.
func wpsIE(locked bool) []byte {
	body := []byte{OUIMicrosoft[0], OUIMicrosoft[1], OUIMicrosoft[2], msSubtypeWPS}
	// Version attribute, then optionally AP Setup Locked.
	body = append(body, 0x10, 0x4A, 0x00, 0x01, 0x10)
	if locked {
		body = append(body, 0x10, 0x57, 0x00, 0x01, 0x01)
	}
	return ie(IEVendorSpecific, body...)
}

// vendorIE builds an arbitrary vendor element, for fingerprint fixtures.
func vendorIE(oui [3]byte, subtype uint8, data ...byte) []byte {
	body := []byte{oui[0], oui[1], oui[2], subtype}
	return ie(IEVendorSpecific, append(body, data...)...)
}

func htCapIE(caps uint16) []byte {
	body := make([]byte, 26)
	binary.LittleEndian.PutUint16(body[0:2], caps)
	return ie(IEHTCapabilities, body...)
}

func vhtCapIE(caps uint32) []byte {
	body := make([]byte, 12)
	binary.LittleEndian.PutUint32(body[0:4], caps)
	return ie(IEVHTCapabilities, body...)
}

func heCapIE() []byte { return extIE(IEExtHECapabilities, make([]byte, 20)...) }

// beaconOpts describes a beacon to build.
type beaconOpts struct {
	bssid          MAC
	capability     uint16
	beaconInterval uint16
	ies            [][]byte
}

// buildBeacon assembles a complete beacon frame.
func buildBeacon(o beaconOpts) []byte {
	if o.beaconInterval == 0 {
		o.beaconInterval = 100
	}

	f := []byte{0x80, 0x00, 0x00, 0x00} // beacon, no flags, duration 0
	f = append(f, Broadcast[:]...)      // addr1: destination
	f = append(f, o.bssid[:]...)        // addr2: transmitter
	f = append(f, o.bssid[:]...)        // addr3: BSSID
	f = append(f, 0x00, 0x00)           // sequence control

	f = append(f, make([]byte, 8)...) // timestamp
	f = binary.LittleEndian.AppendUint16(f, o.beaconInterval)
	f = binary.LittleEndian.AppendUint16(f, o.capability)

	for _, e := range o.ies {
		f = append(f, e...)
	}
	return f
}

// buildProbeReq assembles a probe request from a station.
func buildProbeReq(src MAC, essid string) []byte {
	f := []byte{0x40, 0x00, 0x00, 0x00} // probe request
	f = append(f, Broadcast[:]...)
	f = append(f, src[:]...)
	f = append(f, Broadcast[:]...) // wildcard BSSID
	f = append(f, 0x00, 0x00)
	f = append(f, ssidIE(essid)...)
	f = append(f, ratesIE(0x82, 0x84)...)
	return f
}

// buildProbeResp assembles a probe response, which reveals a cloaked SSID.
func buildProbeResp(bssid, dst MAC, essid string, extra ...[]byte) []byte {
	f := []byte{0x50, 0x00, 0x00, 0x00} // probe response
	f = append(f, dst[:]...)
	f = append(f, bssid[:]...)
	f = append(f, bssid[:]...)
	f = append(f, 0x00, 0x00)

	f = append(f, make([]byte, 8)...)
	f = binary.LittleEndian.AppendUint16(f, 100)
	f = binary.LittleEndian.AppendUint16(f, CapESS|CapPrivacy)

	f = append(f, ssidIE(essid)...)
	for _, e := range extra {
		f = append(f, e...)
	}
	return f
}

// buildAssocReq assembles an association request from a station to an AP.
func buildAssocReq(bssid, sta MAC, essid string, extra ...[]byte) []byte {
	f := []byte{0x00, 0x00, 0x00, 0x00} // association request
	f = append(f, bssid[:]...)
	f = append(f, sta[:]...)
	f = append(f, bssid[:]...)
	f = append(f, 0x00, 0x00)

	f = binary.LittleEndian.AppendUint16(f, CapESS|CapPrivacy) // capability
	f = binary.LittleEndian.AppendUint16(f, 10)                // listen interval

	f = append(f, ssidIE(essid)...)
	for _, e := range extra {
		f = append(f, e...)
	}
	return f
}

// buildDataFrame assembles a data frame in the given DS direction.
func buildDataFrame(toDS, fromDS bool, addr1, addr2, addr3 MAC) []byte {
	var flags byte
	if toDS {
		flags |= 0x01
	}
	if fromDS {
		flags |= 0x02
	}
	f := []byte{0x08, flags, 0x00, 0x00} // data frame
	f = append(f, addr1[:]...)
	f = append(f, addr2[:]...)
	f = append(f, addr3[:]...)
	f = append(f, 0x00, 0x00)
	f = append(f, 0xAA, 0xAA, 0x03) // LLC/SNAP
	return f
}

// rssi builds radiotap metadata with a signal reading.
func rssi(dbm int8, channel int) RadiotapMeta {
	freq := 2407 + 5*channel
	return RadiotapMeta{RSSI: dbm, HasRSSI: true, Freq: freq, Channel: channel}
}

// noRSSI builds radiotap metadata from a driver that reported no antenna signal.
func noRSSI(channel int) RadiotapMeta {
	return RadiotapMeta{HasRSSI: false, Freq: 2407 + 5*channel, Channel: channel}
}
