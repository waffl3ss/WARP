package nl80211

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

// ErrUnavailable is returned when the kernel exposes no nl80211 generic netlink family.
//
// This is the expected result on a machine with no wireless stack at all - WSL2, a container
// without CAP_NET_ADMIN, a kernel built without cfg80211. It is reported distinctly so the
// CLI can say "this machine has no wireless stack" instead of a generic netlink error, which
// otherwise reads like a WARP bug.
var ErrUnavailable = errors.New("nl80211: not available on this kernel (no cfg80211/wireless stack)")

// Conn is a connection to the kernel's nl80211 interface.
type Conn struct {
	c   *genetlink.Conn
	fam genetlink.Family
}

// Dial connects to nl80211.
//
// Enumeration is readable by any user; changing interface type or channel requires
// CAP_NET_ADMIN. Dial itself does not require privileges, so the capability probe can run
// unprivileged and report what it found.
func Dial() (*Conn, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return nil, fmt.Errorf("nl80211: dial generic netlink: %w", err)
	}

	fam, err := c.GetFamily(FamilyName)
	if err != nil {
		c.Close()
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrUnavailable
		}
		return nil, fmt.Errorf("nl80211: look up family %q: %w", FamilyName, err)
	}
	return &Conn{c: c, fam: fam}, nil
}

// Close releases the netlink socket.
func (c *Conn) Close() error {
	if c == nil || c.c == nil {
		return nil
	}
	if err := c.c.Close(); err != nil {
		return fmt.Errorf("nl80211: close: %w", err)
	}
	return nil
}

// Wiphys enumerates every physical wireless device.
//
// The request sets NL80211_ATTR_SPLIT_WIPHY_DUMP, which is required to receive the full
// capability set: without it the kernel truncates each phy's attributes to fit one message
// and silently drops the tail - typically the interface combinations and the upper bands,
// which are exactly what WARP needs. Split responses are merged by phy index here.
func (c *Conn) Wiphys() ([]*Wiphy, error) {
	ae := netlink.NewAttributeEncoder()
	ae.Flag(AttrSplitWiphyDump, true)
	data, err := ae.Encode()
	if err != nil {
		return nil, fmt.Errorf("nl80211: encode wiphy request: %w", err)
	}

	msgs, err := c.c.Execute(
		genetlink.Message{
			Header: genetlink.Header{Command: CmdGetWiphy, Version: c.fam.Version},
			Data:   data,
		},
		c.fam.ID,
		netlink.Request|netlink.Dump,
	)
	if err != nil {
		return nil, fmt.Errorf("nl80211: dump wiphys: %w", err)
	}

	byIndex := make(map[uint32]*Wiphy)
	var order []uint32
	for _, m := range msgs {
		part, err := parseWiphy(m.Data)
		if err != nil {
			return nil, err
		}
		acc, ok := byIndex[part.Index]
		if !ok {
			acc = &Wiphy{Index: part.Index}
			byIndex[part.Index] = acc
			order = append(order, part.Index)
		}
		acc.merge(part)
	}

	out := make([]*Wiphy, 0, len(order))
	for _, idx := range order {
		w := byIndex[idx]
		if w.Name == "" {
			w.Name = fmt.Sprintf("phy%d", w.Index)
		}
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

// Interfaces enumerates every wireless netdev.
func (c *Conn) Interfaces() ([]*Interface, error) {
	msgs, err := c.c.Execute(
		genetlink.Message{
			Header: genetlink.Header{Command: CmdGetInterface, Version: c.fam.Version},
		},
		c.fam.ID,
		netlink.Request|netlink.Dump,
	)
	if err != nil {
		return nil, fmt.Errorf("nl80211: dump interfaces: %w", err)
	}

	out := make([]*Interface, 0, len(msgs))
	for _, m := range msgs {
		iface, err := parseInterface(m.Data)
		if err != nil {
			return nil, err
		}
		out = append(out, iface)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

func parseInterface(b []byte) (*Interface, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, fmt.Errorf("nl80211: decode interface attributes: %w", err)
	}

	iface := &Interface{}
	for ad.Next() {
		switch ad.Type() {
		case AttrIfindex:
			iface.Index = ad.Uint32()
		case AttrIfname:
			iface.Name = ad.String()
		case AttrWiphy:
			iface.Wiphy = ad.Uint32()
		case AttrIftype:
			iface.Iftype = Iftype(ad.Uint32())
		case AttrWDev:
			iface.WDev = ad.Uint64()
		case AttrWiphyFreq:
			iface.Freq = ad.Uint32()
		case AttrMAC:
			iface.MAC = net.HardwareAddr(append([]byte(nil), ad.Bytes()...))
		}
	}
	if err := ad.Err(); err != nil {
		return nil, fmt.Errorf("nl80211: decode interface attributes: %w", err)
	}
	return iface, nil
}

// SetIftype changes an interface's type. Requires CAP_NET_ADMIN.
//
// The interface must be administratively down for most drivers to accept this; bringing it
// down and back up is the caller's responsibility because the caller is also responsible for
// restoring the previous state on release.
func (c *Conn) SetIftype(ifindex uint32, t Iftype) error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrIfindex, ifindex)
	ae.Uint32(AttrIftype, uint32(t))
	return c.execute(CmdSetInterface, ae, "set interface type")
}

// SetMonitor puts an interface into monitor mode with the given monitor flags.
//
// MntrFlagOtherBSS is essential: several drivers otherwise deliver only frames addressed to
// the local station, which yields an empty capture that looks like a quiet RF environment
// rather than a misconfiguration.
func (c *Conn) SetMonitor(ifindex uint32, flags ...int) error {
	if len(flags) == 0 {
		flags = []int{MntrFlagOtherBSS, MntrFlagControl}
	}
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrIfindex, ifindex)
	ae.Uint32(AttrIftype, uint32(IftypeMonitor))
	ae.Nested(AttrMntrFlags, func(nae *netlink.AttributeEncoder) error {
		for _, f := range flags {
			nae.Flag(uint16(f), true)
		}
		return nil
	})
	return c.execute(CmdSetInterface, ae, "set monitor mode")
}

// SetMonitorActive puts an interface into *active* monitor mode.
//
// This is the difference between a capture radio and one that can complete a two-way
// authenticated exchange. A passive monitor never acknowledges the frames it receives - the
// firmware ignores anything not addressed to a MAC it is managing - so an access point we
// inject an association at sends its response, sees no ACK, retries, and gives up: hostapd logs
// "did not acknowledge authentication response" and the association never completes. PMKID
// solicitation and certificate harvesting both die there.
//
// NL80211_MNTR_FLAG_ACTIVE tells the driver to ACK frames addressed to the interface's own
// hardware address. Combined with setting that address to the station we transmit as (the
// caller's job), the card now acknowledges the access point exactly as a real client would, and
// the exchange runs to completion. This is what hcxdumptool does for PMKID and what makes an
// injected association work at all.
//
// Not every driver supports it - ath9k, ath9k_htc, mt76 and rt2800usb do, which covers the
// adapters in a pentester's kit. A driver that refuses returns an error the caller surfaces
// rather than silently falling back to a passive monitor that cannot do the job.
func (c *Conn) SetMonitorActive(ifindex uint32) error {
	return c.SetMonitor(ifindex,
		MntrFlagActive, MntrFlagOtherBSS, MntrFlagControl)
}

// SetChannel tunes an interface to a centre frequency at the given channel width.
//
// width is one of the ChanWidth* constants. ChanWidth20NoHT is the right choice for monitor
// and injection work: a wider capture bandwidth does not help frame capture and restricts
// which channels the driver will accept.
func (c *Conn) SetChannel(ifindex uint32, mhz int, width int) error {
	if mhz <= 0 {
		return fmt.Errorf("nl80211: set channel: invalid frequency %d MHz", mhz)
	}
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrIfindex, ifindex)
	ae.Uint32(AttrWiphyFreq, uint32(mhz))
	ae.Uint32(AttrChannelWidth, uint32(width))
	if width == ChanWidth20NoHT || width == ChanWidth20 {
		// Older drivers honour only the legacy channel-type attribute. Sending both is
		// harmless and covers the ath9k-era parts still in every pentester's kit bag.
		ae.Uint32(AttrWiphyChannelType, ChanNoHT)
		ae.Uint32(AttrCenterFreq1, uint32(mhz))
	}
	return c.execute(CmdSetChannel, ae, "set channel")
}

// ConnectParams describes a station-mode association the kernel drives on our behalf.
//
// This is the counterpart to the active-monitor injection path: instead of forging auth/assoc
// frames in monitor mode and hoping the driver acknowledges the replies, the interface is put in
// managed mode and the kernel's own connection manager runs the exchange. The firmware then
// acknowledges the access point exactly as it does for wpa_supplicant - which is the whole point,
// because the ACK is what an injected association could never reliably produce. The frames the
// association provokes (an M1 carrying a PMKID, or the RADIUS server's certificate) are read off a
// capture radio the same way as always.
type ConnectParams struct {
	// SSID is the network name to associate to. Required.
	SSID []byte
	// BSSID pins a specific access point (6 bytes). Optional; empty lets the kernel choose.
	BSSID []byte
	// FreqMHz is the channel centre frequency. Required.
	FreqMHz int
	// AuthType is one of the AuthType* constants; AuthTypeOpenSystem is correct for WPA2/WPA3.
	AuthType int
	// WPAVersions is a WPAVersion* bitmask, or 0 for an open network.
	WPAVersions int
	// Pairwise and Group are RSN cipher suite selectors; AKMs are the key-management selectors.
	// Mirror what the access point advertised so the association is not refused for offering a
	// suite it does not run.
	Pairwise []uint32
	Group    uint32
	AKMs     []uint32
	// MFP is the 802.11w mode to request: MFPRequired or MFPOptional. Zero omits the attribute
	// (no MFP). An access point that requires management frame protection refuses an association
	// that does not advertise it, which shows up as a bare status-1 refusal.
	MFP int
	// ControlPort tells the kernel that userspace owns the 802.1X control port: EAPOL frames (the
	// EAP an enterprise network carries, and the 4-way handshake's M1) are delivered to the
	// network device as ordinary 0x888E frames rather than consumed by the kernel, so a raw
	// packet socket bound to the interface both reads and writes them. This is how WARP runs its
	// own EAP-TLS client over a kernel-driven association to harvest the certificate - the
	// association is real (the firmware ACKs it), and the EAP exchange rides the control port.
	ControlPort bool
	// ControlPortOverNL80211 routes those EAPOL frames over the netlink socket instead of the
	// network device. Implies ControlPort. Not required for the packet-socket path and left off
	// there; kept for a future single-socket implementation.
	ControlPortOverNL80211 bool
	// ExtraIE is appended verbatim to the information elements in the association request, after
	// any RSN element WARP builds. It is how a WPS association carries its WSC IE: a WPS
	// enrollee/registrar associates open (no RSN) with this element present, which is what makes
	// the access point run EAP-WSC instead of the WPA 4-way handshake.
	ExtraIE []byte
	// ManualMLME drives the association with CMD_AUTHENTICATE + CMD_ASSOCIATE (userspace MLME)
	// instead of the CMD_CONNECT connection manager. The connection manager refuses an *open*
	// association to a secured access point, which is exactly what a WPS enrollee needs (open auth
	// carrying a WSC element); the manual path lets the open+WSC association go out the way reaver
	// does it, but kernel-driven so the firmware acknowledges the access point. Requires a driver
	// that advertises the authenticate/associate commands (mt76, ath9k(_htc), rt2800usb do).
	ManualMLME bool
}

// suiteBytes packs RSN suite selectors into the little-endian u32 array nl80211 expects.
func suiteBytes(suites []uint32) []byte {
	b := make([]byte, 4*len(suites))
	for i, s := range suites {
		binary.LittleEndian.PutUint32(b[i*4:], s)
	}
	return b
}

// connectAttrs builds the attribute set for CMD_CONNECT. Split out so its byte layout can be
// asserted offline - the association itself needs real hardware, but the request encoding does
// not, and a wrong attribute number or width is exactly the kind of bug that only surfaces as a
// silent failure on the air.
func connectAttrs(ifindex uint32, p ConnectParams) (*netlink.AttributeEncoder, error) {
	if len(p.SSID) == 0 {
		return nil, errors.New("nl80211: connect needs an SSID")
	}
	if p.FreqMHz <= 0 {
		return nil, fmt.Errorf("nl80211: connect: invalid frequency %d MHz", p.FreqMHz)
	}
	if len(p.BSSID) != 0 && len(p.BSSID) != 6 {
		return nil, fmt.Errorf("nl80211: connect: BSSID must be 6 bytes, got %d", len(p.BSSID))
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrIfindex, ifindex)
	ae.Uint32(AttrWiphyFreq, uint32(p.FreqMHz))
	ae.Bytes(AttrSSID, p.SSID)
	if len(p.BSSID) == 6 {
		ae.Bytes(AttrMAC, p.BSSID)
	}
	ae.Uint32(AttrAuthType, uint32(p.AuthType))

	if p.WPAVersions != 0 {
		// Privacy is the flag that says the network is encrypted; without it the kernel builds an
		// open-network association and the access point refuses.
		ae.Flag(AttrPrivacy, true)
		ae.Uint32(AttrWPAVersions, uint32(p.WPAVersions))
		if len(p.Pairwise) > 0 {
			ae.Bytes(AttrCipherSuitesPairwise, suiteBytes(p.Pairwise))
		}
		if p.Group != 0 {
			ae.Uint32(AttrCipherSuiteGroup, p.Group)
		}
		if len(p.AKMs) > 0 {
			ae.Bytes(AttrAKMSuites, suiteBytes(p.AKMs))
		}
		if p.MFP != 0 {
			ae.Uint32(AttrUseMFP, uint32(p.MFP))
		}
	}

	// Information elements for the association request. The RSN element is supplied explicitly
	// because several drivers (mt76, confirmed on real hardware) do not build it from the crypto
	// attributes above - the request would then go out with no security element and the access
	// point refuses it with 802.11 status 40. wpa_supplicant always builds and sends the RSN
	// element itself, and this does the same. ExtraIE (a WPS WSC element) is appended after it, or
	// stands alone on an open WPS association where there is no RSN.
	var ies []byte
	if p.WPAVersions != 0 {
		if ie := rsnIE(p); ie != nil {
			ies = append(ies, ie...)
		}
	}
	ies = append(ies, p.ExtraIE...)
	if len(ies) > 0 {
		ae.Bytes(AttrIE, ies)
	}

	if p.ControlPort || p.ControlPortOverNL80211 {
		// Userspace owns the control port: the kernel hands EAPOL to us rather than dropping it,
		// which is what lets our EAP-TLS client run over the association.
		ae.Flag(AttrControlPort, true)
		ae.Uint16(AttrControlPortEthertype, EtherTypeEAPOL)
	}
	if p.ControlPortOverNL80211 {
		ae.Flag(AttrControlPortOverNL80211, true)
		// The connection is torn down automatically if this socket closes, so a crash cannot
		// leave the card associated to a client network.
		ae.Flag(AttrSocketOwner, true)
	}

	return ae, nil
}

// RSN element element ID and management cipher.
const (
	elemIDRSN      = 48         // the RSN information element tag
	cipherBIPCMAC1 = 0x000FAC06 // BIP-CMAC-128, the default group management cipher for MFP
)

// rsnIE builds the RSN information element to place in the association request, from the selected
// crypto. Returns nil when there is no crypto to describe (an open network).
//
// Layout (802.11 RSN element body): version(2), group cipher(4), pairwise count(2) + suites,
// AKM count(2) + suites, RSN capabilities(2), and - only when management frame protection is
// offered - a PMKID count(2, zero here) and the group management cipher(4).
func rsnIE(p ConnectParams) []byte {
	if p.WPAVersions == 0 || len(p.Pairwise) == 0 || len(p.AKMs) == 0 || p.Group == 0 {
		return nil
	}
	var body []byte
	body = append(body, 0x01, 0x00) // version 1
	body = appendSuite(body, p.Group)
	body = append(body, byte(len(p.Pairwise)), 0x00)
	for _, s := range p.Pairwise {
		body = appendSuite(body, s)
	}
	body = append(body, byte(len(p.AKMs)), 0x00)
	for _, s := range p.AKMs {
		body = appendSuite(body, s)
	}

	// RSN capabilities: advertise management frame protection when it is in play. MFPC (capable)
	// is set for both required and optional; MFPR (required) only when the network requires it.
	var caps uint16
	switch p.MFP {
	case MFPRequired:
		caps |= 0x0080 | 0x0040 // MFPC | MFPR
	case MFPOptional:
		caps |= 0x0080 // MFPC
	}
	body = append(body, byte(caps), byte(caps>>8))

	if caps&0x0080 != 0 {
		// A PMKID count of zero, then the group management cipher, are required once MFPC is set.
		body = append(body, 0x00, 0x00)
		body = appendSuite(body, cipherBIPCMAC1)
	}

	ie := make([]byte, 0, 2+len(body))
	ie = append(ie, elemIDRSN, byte(len(body)))
	return append(ie, body...)
}

// appendSuite writes an RSN suite selector as it appears on the wire: the three-byte OUI followed
// by the one-byte type, which is the big-endian layout of the 32-bit selector (0x000FAC04 for
// CCMP becomes 00 0F AC 04).
func appendSuite(b []byte, s uint32) []byte {
	return append(b, byte(s>>24), byte(s>>16), byte(s>>8), byte(s))
}

// parseConnectEvent pulls the interface index and status code out of a CMD_CONNECT notification.
func parseConnectEvent(data []byte) (ifindex uint32, status uint16, haveIf, haveStatus bool) {
	ad, err := netlink.NewAttributeDecoder(data)
	if err != nil {
		return 0, 0, false, false
	}
	for ad.Next() {
		switch ad.Type() {
		case AttrIfindex:
			ifindex = ad.Uint32()
			haveIf = true
		case AttrStatusCode:
			status = ad.Uint16()
			haveStatus = true
		}
	}
	return ifindex, status, haveIf, haveStatus
}

// Disconnect issues NL80211_CMD_DISCONNECT, tearing down any association on the interface.
//
// reason is an 802.11 reason code, or 0 to send the kernel's default. Always paired with a
// preceding Connect so a card is never left associated to a client's network - same discipline as
// restoring monitor mode and the spoofed MAC after an injection burst.
func (c *Conn) Disconnect(ifindex uint32, reason uint16) error {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(AttrIfindex, ifindex)
	if reason != 0 {
		ae.Uint16(AttrReasonCode, reason)
	}
	return c.execute(CmdDisconnect, ae, "disconnect")
}

// GetRegDomain returns the current regulatory domain as an ISO 3166-1 alpha-2 country code, e.g.
// "US". "00" is the world/unset domain, under which the kernel marks the upper bands NoIR
// (receive-only) because it does not know which country's rules apply.
func (c *Conn) GetRegDomain() (string, error) {
	msgs, err := c.c.Execute(
		genetlink.Message{Header: genetlink.Header{Command: CmdGetReg, Version: c.fam.Version}},
		c.fam.ID,
		netlink.Request,
	)
	if err != nil {
		return "", fmt.Errorf("nl80211: get regulatory domain: %w", err)
	}
	for _, m := range msgs {
		ad, err := netlink.NewAttributeDecoder(m.Data)
		if err != nil {
			return "", fmt.Errorf("nl80211: decode regulatory reply: %w", err)
		}
		for ad.Next() {
			if ad.Type() == AttrRegAlpha2 {
				return strings.TrimRight(ad.String(), "\x00"), ad.Err()
			}
		}
		if err := ad.Err(); err != nil {
			return "", err
		}
	}
	return "", nil
}

// SetRegDomain requests a regulatory-domain change to the given alpha-2 country code. The kernel
// applies it asynchronously; a GetRegDomain shortly after confirms it took. Requires CAP_NET_ADMIN.
func (c *Conn) SetRegDomain(alpha2 string) error {
	if len(alpha2) != 2 {
		return fmt.Errorf("nl80211: regulatory domain must be a two-letter country code, got %q", alpha2)
	}
	ae := netlink.NewAttributeEncoder()
	ae.String(AttrRegAlpha2, strings.ToUpper(alpha2))
	return c.execute(CmdReqSetReg, ae, "set regulatory domain")
}

func (c *Conn) execute(cmd uint8, ae *netlink.AttributeEncoder, what string) error {
	data, err := ae.Encode()
	if err != nil {
		return fmt.Errorf("nl80211: encode %s request: %w", what, err)
	}
	_, err = c.c.Execute(
		genetlink.Message{
			Header: genetlink.Header{Command: cmd, Version: c.fam.Version},
			Data:   data,
		},
		c.fam.ID,
		netlink.Request|netlink.Acknowledge,
	)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("nl80211: %s: permission denied (CAP_NET_ADMIN required - run warpd as root): %w", what, err)
		}
		return fmt.Errorf("nl80211: %s: %w", what, err)
	}
	return nil
}
