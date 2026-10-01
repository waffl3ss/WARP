// Package nl80211 is a minimal, dependency-light client for the kernel's nl80211 generic
// netlink interface.
//
// It exists because WARP needs facts the common Go wifi libraries do not expose - in
// particular the full band/frequency table and the *valid interface combinations*, which are
// what tell us whether a phy can run AP and monitor concurrently. On mt76 and some ath9k
// parts that is effectively a free extra radio, and WARP's scheduler is built to use it.
//
// Only the subset WARP needs is implemented. Constants are transcribed from the kernel's
// include/uapi/linux/nl80211.h; the enum values are stable UAPI and must not be reordered.
package nl80211

// Generic netlink family name.
const FamilyName = "nl80211"

// Commands (enum nl80211_commands).
const (
	CmdGetWiphy         = 1
	CmdSetWiphy         = 2
	CmdNewWiphy         = 3
	CmdGetInterface     = 5
	CmdSetInterface     = 6
	CmdNewInterface     = 7
	CmdDelInterface     = 8
	CmdGetStation       = 17
	CmdTriggerScan      = 33
	CmdNewScanResults   = 34
	CmdScanAborted      = 35
	CmdAuthenticate     = 37
	CmdAssociate        = 38
	CmdDeauthenticate   = 39
	CmdConnect          = 46
	CmdDisconnect       = 48
	CmdSetChannel       = 65
	CmdControlPortFrame = 129
	CmdReqSetReg        = 27 // NL80211_CMD_REQ_SET_REG - request a regulatory-domain change
	CmdGetReg           = 31 // NL80211_CMD_GET_REG - read the current regulatory domain
)

// Attributes (enum nl80211_attrs).
const (
	AttrWiphy                  = 1
	AttrWiphyName              = 2
	AttrIfindex                = 3
	AttrIfname                 = 4
	AttrIftype                 = 5
	AttrMAC                    = 6
	AttrWiphyBands             = 22
	AttrMntrFlags              = 23
	AttrSupportedIftypes       = 32
	AttrWiphyFreq              = 38
	AttrWiphyChannelType       = 39
	AttrIE                     = 42
	AttrMaxNumScanSSIDs        = 43
	AttrScanFrequencies        = 44
	AttrScanSSIDs              = 45
	AttrFrame                  = 51
	AttrSupportedCommands      = 50
	AttrSSID                   = 52
	AttrAuthType               = 53
	AttrReasonCode             = 54
	AttrStatusCode             = 72
	AttrCipherSuitesPairwise   = 73
	AttrCipherSuiteGroup       = 74
	AttrWPAVersions            = 75
	AttrAKMSuites              = 76
	AttrUseMFP                 = 66
	AttrControlPort            = 68
	AttrPrivacy                = 70
	AttrControlPortEthertype   = 102
	AttrControlPortNoEncrypt   = 103
	AttrFeatureFlags           = 143
	AttrSocketOwner            = 204
	AttrControlPortOverNL80211 = 264
	AttrInterfaceCombinations  = 120
	AttrSoftwareIftypes        = 121
	AttrWDev                   = 153
	AttrChannelWidth           = 159
	AttrCenterFreq1            = 160
	AttrCenterFreq2            = 161
	AttrSplitWiphyDump         = 174
	AttrExtFeatures            = 217
	AttrRegAlpha2              = 33 // NL80211_ATTR_REG_ALPHA2 - ISO/IEC 3166-1 alpha-2 country code
	AttrWiphyFreqOffset        = 290
)

// Band attributes (enum nl80211_band_attr).
const (
	BandAttrFreqs      = 1
	BandAttrRates      = 2
	BandAttrHTMCSSet   = 3
	BandAttrHTCapa     = 4
	BandAttrVHTMCSSet  = 7
	BandAttrVHTCapa    = 8
	BandAttrIftypeData = 9
)

// Frequency attributes (enum nl80211_frequency_attr).
const (
	FreqAttrFreq       = 1
	FreqAttrDisabled   = 2
	FreqAttrNoIR       = 3
	FreqAttrRadar      = 5
	FreqAttrMaxTxPower = 6
)

// Bitrate attributes (enum nl80211_bitrate_attr).
const (
	BitrateAttrRate = 1 // u32, units of 100 kbps
)

// Interface combination attributes (enum nl80211_if_combination_attrs).
const (
	IfaceCombLimits          = 1
	IfaceCombMaxnum          = 2
	IfaceCombStaApBIMatch    = 3
	IfaceCombNumChannels     = 4
	IfaceCombRadarWidths     = 5
	IfaceCombRadarRegions    = 6
	IfaceCombBeaconIntMinGCD = 7
)

// Interface limit attributes (enum nl80211_iface_limit_attrs).
const (
	IfaceLimitMax   = 1
	IfaceLimitTypes = 2
)

// ChannelWidth values (enum nl80211_chan_width).
const (
	ChanWidth20NoHT = 0
	ChanWidth20     = 1
	ChanWidth40     = 2
	ChanWidth80     = 3
	ChanWidth80P80  = 4
	ChanWidth160    = 5
	ChanWidth5      = 6
	ChanWidth10     = 7
	ChanWidth320    = 13
)

// ChannelType values (enum nl80211_channel_type), used by the older SET_CHANNEL path.
const (
	ChanNoHT      = 0
	ChanHT20      = 1
	ChanHT40Minus = 2
	ChanHT40Plus  = 3
)

// Authentication types (enum nl80211_auth_type).
const (
	AuthTypeOpenSystem = 0
	AuthTypeSharedKey  = 1
	AuthTypeFT         = 2
	AuthTypeNetworkEAP = 3
	AuthTypeSAE        = 4
)

// WPA version bitmask (NL80211_WPA_VERSION_*).
const (
	WPAVersion1 = 1 << 0
	WPAVersion2 = 1 << 1
	WPAVersion3 = 1 << 2
)

// Management frame protection modes (enum nl80211_mfp), for NL80211_ATTR_USE_MFP. Zero is "no
// MFP"; the connect omits the attribute in that case rather than sending it explicitly.
const (
	MFPNo       = 0
	MFPRequired = 1
	MFPOptional = 2
)

// RSN cipher and AKM suite selectors, as they appear on the wire: the OUI 00-0F-AC in the top
// three bytes and the suite type in the low byte. These are the same 32-bit values an RSN
// information element carries, so a connection can offer exactly what the access point advertised.
const (
	CipherCCMP128 = 0x000FAC04
	CipherTKIP    = 0x000FAC02
	CipherGCMP256 = 0x000FAC09
	CipherCCMP256 = 0x000FAC0A

	AKM8021X = 0x000FAC01 // WPA-Enterprise (EAP)
	AKMPSK   = 0x000FAC02 // WPA-Personal
	AKMSAE   = 0x000FAC08 // WPA3-Personal
)

// EtherTypeEAPOL is the 802.1X control-port ethertype (0x888E), used so the kernel routes EAPOL
// to us over nl80211 rather than up the normal network stack.
const EtherTypeEAPOL = 0x888E

// Band is a radio band identifier (enum nl80211_band).
type Band uint32

// Band values.
const (
	Band2GHz  Band = 0
	Band5GHz  Band = 1
	Band60GHz Band = 2
	Band6GHz  Band = 3
	BandS1GHz Band = 4
	BandLC    Band = 5
)

// String returns the band name as it appears in reports.
func (b Band) String() string {
	switch b {
	case Band2GHz:
		return "2.4GHz"
	case Band5GHz:
		return "5GHz"
	case Band60GHz:
		return "60GHz"
	case Band6GHz:
		return "6GHz"
	case BandS1GHz:
		return "S1GHz"
	case BandLC:
		return "LC"
	default:
		return "band?"
	}
}

// Iftype is an interface type (enum nl80211_iftype).
type Iftype uint32

// Iftype values.
const (
	IftypeUnspecified Iftype = 0
	IftypeAdhoc       Iftype = 1
	IftypeStation     Iftype = 2
	IftypeAP          Iftype = 3
	IftypeAPVLAN      Iftype = 4
	IftypeWDS         Iftype = 5
	IftypeMonitor     Iftype = 6
	IftypeMeshPoint   Iftype = 7
	IftypeP2PClient   Iftype = 8
	IftypeP2PGo       Iftype = 9
	IftypeP2PDevice   Iftype = 10
	IftypeOCB         Iftype = 11
	IftypeNAN         Iftype = 12
)

// String returns the interface type name as `iw` spells it, so operators can compare output
// against `iw list` directly.
func (t Iftype) String() string {
	switch t {
	case IftypeUnspecified:
		return "unspecified"
	case IftypeAdhoc:
		return "IBSS"
	case IftypeStation:
		return "managed"
	case IftypeAP:
		return "AP"
	case IftypeAPVLAN:
		return "AP/VLAN"
	case IftypeWDS:
		return "WDS"
	case IftypeMonitor:
		return "monitor"
	case IftypeMeshPoint:
		return "mesh point"
	case IftypeP2PClient:
		return "P2P-client"
	case IftypeP2PGo:
		return "P2P-GO"
	case IftypeP2PDevice:
		return "P2P-device"
	case IftypeOCB:
		return "outside context of a BSS"
	case IftypeNAN:
		return "NAN"
	default:
		return "iftype?"
	}
}

// Monitor mode flags (enum nl80211_mntr_flags).
//
// MntrFlagOtherBSS is the one that matters: without it some drivers deliver only frames
// addressed to the local station, which silently produces an empty capture.
const (
	MntrFlagFCSFail    = 1
	MntrFlagPLCPFail   = 2
	MntrFlagControl    = 3
	MntrFlagOtherBSS   = 4
	MntrFlagCookFrames = 5
	MntrFlagActive     = 6
)
