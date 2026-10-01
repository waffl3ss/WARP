package report

import (
	"fmt"
	"strings"

	"github.com/waffl3ss/warp/internal/store"
)

// encryptionDetail renders a stored access point's parsed beacon security the way a `tshark -V` dump
// lays it out, so the JSON report carries the same packet-detail evidence the web "Encryption Packet"
// popup shows and a reporting platform can import it as one field. WARP parsed all of it off the air;
// nothing external runs. It works only from what the store persists - the group cipher suite and the
// WPS lock bit are not kept in the projection, so those lines are simply absent rather than guessed.
func encryptionDetail(ap store.APRow) string {
	const (
		i1  = "    "                 // top-level fields
		i2  = "            "         // element fields
		i3  = "                    " // AKM
		i4  = "                "     // MFP bits
		bar = "========================================================="
	)
	essid := ap.ESSID
	if essid == "" {
		essid = "(hidden)"
	}
	open := ap.SecurityClass == "" || ap.SecurityClass == "open"

	var L []string
	L = append(L, bar, "Detailed Encryption Information for SSID:  "+essid, bar)
	L = append(L, i1+"BSSID: "+ap.BSSID)
	if ap.Channel != 0 {
		ch := fmt.Sprintf("%d", ap.Channel)
		if ap.Band != "" {
			ch += " (" + ap.Band + ")"
		}
		L = append(L, i1+"Channel: "+ch)
	}
	if ap.LastSeen != "" {
		L = append(L, i1+"Last beacon seen: "+ap.LastSeen)
	}

	privBit, privMsg := "1", "AP/STA can support WEP"
	if open {
		privBit, privMsg = "0", "AP/STA cannot support WEP"
	}
	L = append(L, i2+".... .... ..."+privBit+" .... = Privacy: "+privMsg)
	L = append(L, i2+"SSID: "+ap.ESSID)

	if open {
		L = append(L, "")
		L = append(L, i1+"WPA Version: "+wpaVersionDetail(ap)+" (no RSN/WPA element)")
		return strings.Join(L, "\n")
	}

	if ciphers := splitTokens(ap.Ciphers); len(ciphers) > 0 {
		named := make([]string, 0, len(ciphers))
		for _, c := range ciphers {
			named = append(named, tsharkCipher(c))
		}
		L = append(L, i2+"Pairwise Cipher Suite List "+strings.Join(named, " "))
	}
	for _, a := range splitTokens(ap.AKMs) {
		L = append(L, i3+"Auth Key Management (AKM) type: "+tsharkAKM(a))
	}

	mfp := strings.ToLower(ap.MFP)
	required := strings.Contains(mfp, "require")
	capable := required || strings.Contains(mfp, "capab") || strings.Contains(mfp, "option")
	reqBit, reqStr := "0", "False"
	if required {
		reqBit, reqStr = "1", "True"
	}
	capBit, capStr := "0", "False"
	if capable {
		capBit, capStr = "1", "True"
	}
	L = append(L, i4+".... .... ."+reqBit+".. .... = Management Frame Protection Required: "+reqStr)
	L = append(L, i4+".... .... "+capBit+"... .... = Management Frame Protection Capable: "+capStr)

	wps := "not present"
	if ap.WPS {
		wps = "enabled"
	}
	L = append(L, i2+"WPS: "+wps)
	return strings.Join(L, "\n")
}

// wpaVersionDetail is the human WPA-version line for the encryption block, from what the projection
// keeps (class plus the transition flag; no legacy-WPA1 vendor-element bit is persisted).
func wpaVersionDetail(ap store.APRow) string {
	switch ap.SecurityClass {
	case "open", "":
		return "open (no encryption)"
	case "owe":
		return "OWE (enhanced open)"
	case "wep":
		return "WEP"
	case "wpa_sae", "wpa3":
		if ap.Transition {
			return "WPA3-SAE (WPA2/WPA3 transition)"
		}
		return "WPA3-Personal (SAE)"
	case "wpa_enterprise":
		return "WPA2-Enterprise (802.1X)"
	case "wpa3_enterprise_192":
		return "WPA3-Enterprise 192-bit (802.1X)"
	case "wpa_psk":
		if ap.Transition {
			return "WPA2-PSK (WPA2/WPA3 transition)"
		}
		return "WPA2-Personal (PSK)"
	default:
		return ap.SecurityClass
	}
}

// tsharkCipher renders a WARP cipher token the way tshark -V names the suite, matching the web popup.
func tsharkCipher(name string) string {
	if name == "" || strings.Contains(name, "/") { // vendor-specific: OUI/type, left as-is
		return name
	}
	m := map[string]string{
		"CCMP-128": "AES (CCM)", "CCMP-256": "AES (CCM-256)",
		"GCMP-128": "AES (GCM)", "GCMP-256": "AES (GCM-256)",
		"TKIP": "TKIP", "WEP-40": "WEP-40", "WEP-104": "WEP-104",
		"use-group": "Use group cipher suite",
	}
	suite := name
	if v, ok := m[name]; ok {
		suite = v
	}
	return "00:0f:ac (Ieee 802.11) " + suite
}

// tsharkAKM renders a WARP AKM token as tshark's "<name> (<suite number>)", matching the web popup.
func tsharkAKM(name string) string {
	type akm struct {
		label string
		n     int
	}
	m := map[string]akm{
		"802.1X": {"WPA", 1}, "PSK": {"PSK", 2}, "FT-802.1X": {"FT using 802.1X", 3},
		"FT-PSK": {"FT using PSK", 4}, "802.1X-SHA256": {"WPA (SHA256)", 5},
		"PSK-SHA256": {"PSK (SHA256)", 6}, "SAE": {"SAE (SHA256)", 8},
		"FT-SAE": {"FT using SAE (SHA256)", 9}, "802.1X-Suite-B": {"WPA (SuiteB)", 11},
		"802.1X-Suite-B-192": {"WPA (SuiteB-192)", 12}, "FT-802.1X-SHA384": {"FT using 802.1X (SHA384)", 13},
		"OWE": {"OWE", 18}, "FT-PSK-SHA384": {"FT using PSK (SHA384)", 19},
	}
	if e, ok := m[name]; ok {
		return fmt.Sprintf("%s (%d)", e.label, e.n)
	}
	return name
}

// splitTokens splits a stored comma/space/semicolon-delimited cipher or AKM list into its tokens.
func splitTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
}
