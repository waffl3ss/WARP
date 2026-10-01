package nl80211

import "testing"

// TestConstantsMatchKernel pins the nl80211 command and attribute numbers to the values the kernel
// actually uses (verified against <linux/nl80211.h> with the compiler, not by counting the enum —
// the enum has alias entries and reserved gaps that make hand-counting drift, which is exactly how
// several of these were wrong: crypto attributes landed on the wrong numbers so a CONNECT never
// really offered WPA/802.1X, and the control-port attributes finally tripped ERANGE).
//
// These are stable UAPI: they do not change between kernels. If one of these fails, the constant
// was edited to a wrong value — re-verify with a one-line C program that prints the macro, do not
// "fix" the test.
func TestConstantsMatchKernel(t *testing.T) {
	cmds := map[string]int{
		"CmdGetWiphy": CmdGetWiphy, "CmdSetInterface": CmdSetInterface,
		"CmdGetStation": CmdGetStation, "CmdTriggerScan": CmdTriggerScan,
		"CmdAuthenticate": CmdAuthenticate, "CmdAssociate": CmdAssociate,
		"CmdDeauthenticate": CmdDeauthenticate, "CmdConnect": CmdConnect,
		"CmdDisconnect": CmdDisconnect, "CmdSetChannel": CmdSetChannel,
		"CmdControlPortFrame": CmdControlPortFrame,
	}
	wantCmds := map[string]int{
		"CmdGetWiphy": 1, "CmdSetInterface": 6, "CmdGetStation": 17, "CmdTriggerScan": 33,
		"CmdAuthenticate": 37, "CmdAssociate": 38, "CmdDeauthenticate": 39, "CmdConnect": 46,
		"CmdDisconnect": 48, "CmdSetChannel": 65, "CmdControlPortFrame": 129,
	}
	for name, got := range cmds {
		if got != wantCmds[name] {
			t.Errorf("%s = %d, kernel value is %d", name, got, wantCmds[name])
		}
	}

	attrs := map[string]int{
		"AttrIfindex": AttrIfindex, "AttrMAC": AttrMAC, "AttrIftype": AttrIftype,
		"AttrWiphyFreq": AttrWiphyFreq, "AttrIE": AttrIE, "AttrFrame": AttrFrame,
		"AttrSupportedCommands": AttrSupportedCommands, "AttrSSID": AttrSSID,
		"AttrAuthType": AttrAuthType, "AttrReasonCode": AttrReasonCode,
		"AttrStatusCode": AttrStatusCode, "AttrCipherSuitesPairwise": AttrCipherSuitesPairwise,
		"AttrCipherSuiteGroup": AttrCipherSuiteGroup, "AttrWPAVersions": AttrWPAVersions,
		"AttrAKMSuites": AttrAKMSuites, "AttrUseMFP": AttrUseMFP, "AttrControlPort": AttrControlPort,
		"AttrPrivacy": AttrPrivacy, "AttrControlPortEthertype": AttrControlPortEthertype,
		"AttrControlPortNoEncrypt": AttrControlPortNoEncrypt, "AttrFeatureFlags": AttrFeatureFlags,
		"AttrSocketOwner": AttrSocketOwner, "AttrControlPortOverNL80211": AttrControlPortOverNL80211,
		"AttrChannelWidth": AttrChannelWidth, "AttrCenterFreq1": AttrCenterFreq1,
		"AttrWDev": AttrWDev, "AttrInterfaceCombinations": AttrInterfaceCombinations,
	}
	wantAttrs := map[string]int{
		"AttrIfindex": 3, "AttrMAC": 6, "AttrIftype": 5, "AttrWiphyFreq": 38, "AttrIE": 42,
		"AttrFrame": 51, "AttrSupportedCommands": 50, "AttrSSID": 52, "AttrAuthType": 53,
		"AttrReasonCode": 54, "AttrStatusCode": 72, "AttrCipherSuitesPairwise": 73,
		"AttrCipherSuiteGroup": 74, "AttrWPAVersions": 75, "AttrAKMSuites": 76, "AttrUseMFP": 66,
		"AttrControlPort": 68, "AttrPrivacy": 70, "AttrControlPortEthertype": 102,
		"AttrControlPortNoEncrypt": 103, "AttrFeatureFlags": 143, "AttrSocketOwner": 204,
		"AttrControlPortOverNL80211": 264, "AttrChannelWidth": 159, "AttrCenterFreq1": 160,
		"AttrWDev": 153, "AttrInterfaceCombinations": 120,
	}
	for name, got := range attrs {
		if got != wantAttrs[name] {
			t.Errorf("%s = %d, kernel value is %d", name, got, wantAttrs[name])
		}
	}

	// No two attributes may share a number — the collision that hid AttrSupportedCommands behind
	// AttrFrame at 51 would have been caught here.
	seen := map[int]string{}
	for name, v := range attrs {
		if prev, dup := seen[v]; dup {
			t.Errorf("attribute value %d used by both %s and %s", v, prev, name)
		}
		seen[v] = name
	}
}
