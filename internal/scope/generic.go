package scope

import "strings"

// genericESSIDs are common or vendor-default network names.
//
// These are the cases where a neighbour or another tenant legitimately broadcasts the same
// ESSID the client put in scope. ESSID match is our authorization, so a generic name means
// the match no longer uniquely identifies the client's equipment and active work could
// transmit at a device outside the engagement.
//
// Matching is exact (case-insensitive), not substring. "CORP-GUEST" is specific enough to
// identify the client; bare "Guest" is not. Substring matching would flag most real corporate
// guest networks and train the operator to acknowledge the warning without reading it, which
// is worse than not warning at all.
var genericESSIDs = map[string]struct{}{}

func init() {
	for _, s := range []string{
		// Generic descriptive names
		"guest", "guests", "guest wifi", "guest network", "visitor", "visitors",
		"wifi", "wi-fi", "wireless", "wlan", "network", "internet", "public",
		"free wifi", "freewifi", "hotspot", "home", "office", "lobby", "default",
		"test", "temp", "setup", "portal", "ap", "wireless network",

		// Vendor defaults
		"linksys", "netgear", "dlink", "d-link", "tplink", "tp-link", "tenda",
		"belkin", "asus", "zyxel", "buffalo", "trendnet", "actiontec", "arris",
		"motorola", "technicolor", "sagemcom", "ubee", "hitronhub", "orbi", "eero",
		"netgear-guest", "linksys-guest", "cisco", "meraki", "ruckus", "aruba",
		"openwrt", "dd-wrt", "ubnt", "unifi",

		// Carrier / venue SSIDs that appear nationwide
		"xfinitywifi", "attwifi", "att-wifi", "spectrumwifi", "optimumwifi",
		"cablewifi", "eduroam", "bt wi-fi", "btwifi-with-fon", "sky", "virginmedia",
		"starbucks", "gogoinflight", "boingo",

		// Printer / IoT defaults that are effectively universal
		"direct", "setup wizard", "hp-print", "hp-setup", "canon_ij", "epson",
		"chromecast", "roku", "sonos", "androidap", "iphone",
	} {
		genericESSIDs[s] = struct{}{}
	}
}

// IsGeneric reports whether essid is a common or vendor-default name that a neighbour could
// legitimately be broadcasting.
//
// This never blocks anything on its own - it drives the acknowledgment prompt at `warp init`
// so the residual risk is surfaced to a human and recorded in the audit log.
func IsGeneric(essid string) bool {
	_, ok := genericESSIDs[strings.ToLower(strings.TrimSpace(essid))]
	return ok
}

// GenericEntries returns the scoped ESSIDs that are generic, in scope order.
func (s *Set) GenericEntries() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, e := range s.entries {
		if IsGeneric(e) {
			out = append(out, e)
		}
	}
	return out
}
