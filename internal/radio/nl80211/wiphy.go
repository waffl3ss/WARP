package nl80211

import (
	"fmt"
	"net"
	"sort"

	"github.com/mdlayher/netlink"
)

// Frequency is one channel the hardware reports.
type Frequency struct {
	// MHz is the centre frequency.
	MHz int `json:"mhz"`
	// Channel is the IEEE channel number derived from MHz and the band.
	Channel int `json:"channel"`
	// Disabled means the channel is unusable in the current regulatory domain.
	Disabled bool `json:"disabled"`
	// NoIR means "no initiating radiation": passive scanning only, no transmission until a
	// beacon is heard. WARP must never solicit or inject on a NoIR channel.
	NoIR bool `json:"no_ir"`
	// Radar means DFS applies.
	Radar bool `json:"radar"`
	// MaxTxPowerdBm is the regulatory ceiling, converted from mBm.
	MaxTxPowerdBm float64 `json:"max_tx_power_dbm"`
}

// Usable reports whether WARP may transmit on this channel. NoIR and Disabled channels are
// receive-only; treating them as usable produces injection failures that look like driver
// bugs.
func (f Frequency) Usable() bool { return !f.Disabled && !f.NoIR }

// BandInfo is one supported band and its channels.
type BandInfo struct {
	Band     Band        `json:"band"`
	Name     string      `json:"name"`
	Freqs    []Frequency `json:"freqs"`
	Bitrates []float64   `json:"bitrates_mbps,omitempty"`
	HTCapa   uint16      `json:"ht_capa,omitempty"`
	VHTCapa  uint32      `json:"vht_capa,omitempty"`
	HasHE    bool        `json:"has_he"`
}

// IfaceLimit is one clause of an interface combination: at most Max interfaces drawn from
// Types.
type IfaceLimit struct {
	Max   uint32   `json:"max"`
	Types []Iftype `json:"types"`
}

// String renders the limit the way `iw list` does, e.g. "#{ AP, mesh point } <= 8".
func (l IfaceLimit) String() string {
	names := make([]string, len(l.Types))
	for i, t := range l.Types {
		names[i] = t.String()
	}
	return fmt.Sprintf("#{ %s } <= %d", joinComma(names), l.Max)
}

// IfaceCombination is one valid concurrent-interface configuration the hardware supports.
//
// This is the structure that tells WARP whether a single phy can host, say, an AP and a
// monitor interface at the same time - which on mt76 and some ath9k parts is effectively an
// extra logical radio. NumChannels matters just as much as the type limits: a combination
// permitting AP+monitor on `#channels <= 1` means both must sit on the same channel.
type IfaceCombination struct {
	Limits            []IfaceLimit `json:"limits"`
	MaxInterfaces     uint32       `json:"max_interfaces"`
	NumChannels       uint32       `json:"num_channels"`
	RadarDetectWidths uint32       `json:"radar_detect_widths,omitempty"`
	BeaconIntMinGCD   uint32       `json:"beacon_int_min_gcd,omitempty"`
	STAAPBIMatch      bool         `json:"sta_ap_bi_match,omitempty"`
}

// Supports reports whether this combination permits the requested set of concurrent
// interface types on the given number of distinct channels.
//
// want maps an interface type to how many of it are needed.
//
// Each requested interface must be charged to exactly one limit clause, and a clause's Max
// is shared across every type it lists. A type may appear in several clauses, which makes
// this an assignment problem rather than a subtraction: charging greedily in clause order
// can exhaust a clause that a later type needed and report infeasible when a valid
// assignment exists. That would silently cost us a concurrency the hardware actually has -
// on mt76 and some ath9k parts, AP+monitor on one phy is effectively a free extra radio.
//
// It is solved exactly as a max-flow: source → type (capacity = count needed) → clause
// (edge exists if the clause lists that type) → sink (capacity = clause Max). The request
// is feasible iff every unit of demand can be routed. The graphs are tiny - at most a
// handful of clauses and 13 interface types.
func (c IfaceCombination) Supports(want map[Iftype]uint32, channels uint32) bool {
	types := make([]Iftype, 0, len(want))
	var total uint32
	for t, n := range want {
		if n == 0 {
			continue
		}
		types = append(types, t)
		total += n
	}
	if total == 0 {
		return false
	}
	if total > c.MaxInterfaces || channels > c.NumChannels {
		return false
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

	// Node layout: 0 = source, [1..nT] = types, [nT+1..nT+nC] = clauses, last = sink.
	nT, nC := len(types), len(c.Limits)
	sink := nT + nC + 1
	n := sink + 1

	cap := make([][]int, n)
	for i := range cap {
		cap[i] = make([]int, n)
	}
	for i, t := range types {
		cap[0][1+i] = int(want[t])
		for j, lim := range c.Limits {
			for _, allowed := range lim.Types {
				if allowed == t {
					// A clause never admits more than its own Max, so the middle edge needs
					// no tighter bound than that.
					cap[1+i][1+nT+j] = int(lim.Max)
					break
				}
			}
		}
	}
	for j, lim := range c.Limits {
		cap[1+nT+j][sink] = int(lim.Max)
	}

	return maxFlow(cap, 0, sink) == int(total)
}

// maxFlow is Edmonds-Karp over a dense capacity matrix. The graphs here have at most ~20
// nodes, so the dense representation is the simplest thing that is obviously correct.
func maxFlow(cap [][]int, source, sink int) int {
	n := len(cap)
	flow := 0
	for {
		prev := make([]int, n)
		for i := range prev {
			prev[i] = -1
		}
		prev[source] = source

		queue := []int{source}
		for len(queue) > 0 && prev[sink] == -1 {
			u := queue[0]
			queue = queue[1:]
			for v := 0; v < n; v++ {
				if prev[v] == -1 && cap[u][v] > 0 {
					prev[v] = u
					queue = append(queue, v)
				}
			}
		}
		if prev[sink] == -1 {
			return flow
		}

		// Bottleneck along the augmenting path.
		bottleneck := int(^uint(0) >> 1)
		for v := sink; v != source; v = prev[v] {
			if c := cap[prev[v]][v]; c < bottleneck {
				bottleneck = c
			}
		}
		for v := sink; v != source; v = prev[v] {
			cap[prev[v]][v] -= bottleneck
			cap[v][prev[v]] += bottleneck
		}
		flow += bottleneck
	}
}

// String renders the combination the way `iw list` does, so operator-facing output can be
// diffed against ground truth during hardware validation.
func (c IfaceCombination) String() string {
	parts := make([]string, len(c.Limits))
	for i, l := range c.Limits {
		parts[i] = l.String()
	}
	return fmt.Sprintf("%s, total <= %d, #channels <= %d",
		joinComma(parts), c.MaxInterfaces, c.NumChannels)
}

// Wiphy is a physical wireless device and everything WARP needs to know about it.
type Wiphy struct {
	Index            uint32             `json:"index"`
	Name             string             `json:"name"`
	Bands            []BandInfo         `json:"bands"`
	SupportedIftypes []Iftype           `json:"supported_iftypes"`
	SoftwareIftypes  []Iftype           `json:"software_iftypes,omitempty"`
	Combinations     []IfaceCombination `json:"interface_combinations"`
	Commands         []uint32           `json:"-"`
	FeatureFlags     uint32             `json:"feature_flags,omitempty"`
	MaxScanSSIDs     uint8              `json:"max_scan_ssids,omitempty"`
}

// SupportsIftype reports whether the phy can be put into the given interface type.
func (w *Wiphy) SupportsIftype(t Iftype) bool {
	for _, s := range w.SupportedIftypes {
		if s == t {
			return true
		}
	}
	return false
}

// SupportsConcurrent reports whether the hardware permits the requested concurrent interface
// types across the given number of channels.
//
// Software interface types are subtracted from the demand first. The kernel advertises those
// separately as "can always be added" precisely because they cost no hardware resource, and
// they are frequently absent from the combination list entirely - mt76 parts list monitor as
// a software type and omit it from every combination clause. Checking the combinations alone
// would report AP+monitor as unsupported on an adapter that does it happily, and WARP would
// give up a free extra radio for no reason.
func (w *Wiphy) SupportsConcurrent(want map[Iftype]uint32, channels uint32) bool {
	effective := make(map[Iftype]uint32, len(want))
	for t, n := range want {
		if n == 0 || w.isSoftwareIftype(t) {
			continue
		}
		effective[t] = n
	}

	// Everything requested is software-addable, so no combination has to permit it.
	if len(effective) == 0 {
		for t := range want {
			if !w.SupportsIftype(t) {
				return false
			}
		}
		return true
	}

	for _, c := range w.Combinations {
		if c.Supports(effective, channels) {
			return true
		}
	}
	return false
}

// isSoftwareIftype reports whether an interface type can always be added regardless of the
// advertised combinations.
func (w *Wiphy) isSoftwareIftype(t Iftype) bool {
	for _, s := range w.SoftwareIftypes {
		if s == t {
			return true
		}
	}
	return false
}

// SupportsAPMonitorConcurrent is the specific capability the brief calls out: an extra
// logical radio obtained by running AP and monitor on one phy at once.
func (w *Wiphy) SupportsAPMonitorConcurrent() bool {
	return w.SupportsConcurrent(map[Iftype]uint32{IftypeAP: 1, IftypeMonitor: 1}, 1)
}

// HasBand reports whether the phy has any usable channel in the given band.
func (w *Wiphy) HasBand(b Band) bool {
	for _, band := range w.Bands {
		if band.Band != b {
			continue
		}
		for _, f := range band.Freqs {
			if f.Usable() {
				return true
			}
		}
	}
	return false
}

// SupportsBand reports whether the phy has any non-disabled channel on a band, even if every one
// is NoIR (receive-only). It answers "can this card see this band at all" - which is what the
// operator-facing band list should show - as distinct from HasBand, which answers "can it transmit
// there". A dual-band card under a world (country 00) regulatory domain has all of 5 GHz marked
// NoIR: HasBand is false, but the card plainly supports 5 GHz and WARP still sweeps it passively.
func (w *Wiphy) SupportsBand(b Band) bool {
	for _, band := range w.Bands {
		if band.Band != b {
			continue
		}
		for _, f := range band.Freqs {
			if !f.Disabled {
				return true
			}
		}
	}
	return false
}

// ReceiveOnlyBand reports whether a band is supported but has no transmit-usable channel - every
// channel is NoIR. That is the country-00 case: WARP can listen on the band but not transmit, so
// active work there is refused until the regulatory domain is set.
func (w *Wiphy) ReceiveOnlyBand(b Band) bool {
	return w.SupportsBand(b) && !w.HasBand(b)
}

// UsableChannels returns every channel the phy may transmit on, across all bands.
func (w *Wiphy) UsableChannels() []Frequency {
	var out []Frequency
	for _, band := range w.Bands {
		for _, f := range band.Freqs {
			if f.Usable() {
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MHz < out[j].MHz })
	return out
}

// Interface is a netdev (or wdev) belonging to a phy.
type Interface struct {
	Index  uint32           `json:"index"`
	Name   string           `json:"name"`
	Wiphy  uint32           `json:"wiphy"`
	Iftype Iftype           `json:"iftype"`
	MAC    net.HardwareAddr `json:"-"`
	WDev   uint64           `json:"wdev"`
	Freq   uint32           `json:"freq,omitempty"`
}

// parseWiphy decodes one GET_WIPHY response message.
//
// With SPLIT_WIPHY_DUMP the kernel spreads a single phy across several messages, so this
// returns a partial Wiphy that the caller merges by index. Attributes absent from a given
// message are simply left zero.
func parseWiphy(b []byte) (*Wiphy, error) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil, fmt.Errorf("decode wiphy attributes: %w", err)
	}

	w := &Wiphy{}
	for ad.Next() {
		switch ad.Type() {
		case AttrWiphy:
			w.Index = ad.Uint32()
		case AttrWiphyName:
			w.Name = ad.String()
		case AttrMaxNumScanSSIDs:
			w.MaxScanSSIDs = ad.Uint8()
		case AttrFeatureFlags:
			w.FeatureFlags = ad.Uint32()
		case AttrSupportedIftypes:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				w.SupportedIftypes = decodeIftypeSet(nad)
				return nil
			})
		case AttrSoftwareIftypes:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				w.SoftwareIftypes = decodeIftypeSet(nad)
				return nil
			})
		case AttrSupportedCommands:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					w.Commands = append(w.Commands, nad.Uint32())
				}
				return nad.Err()
			})
		case AttrWiphyBands:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				return decodeBands(nad, w)
			})
		case AttrInterfaceCombinations:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				return decodeCombinations(nad, w)
			})
		}
	}
	if err := ad.Err(); err != nil {
		return nil, fmt.Errorf("decode wiphy attributes: %w", err)
	}
	return w, nil
}

// decodeIftypeSet decodes a set of iftypes. The attribute *type* is the iftype and the
// payload is empty - it is a flag set, not a list of values.
func decodeIftypeSet(ad *netlink.AttributeDecoder) []Iftype {
	var out []Iftype
	for ad.Next() {
		out = append(out, Iftype(ad.Type()))
	}
	return out
}

func decodeBands(ad *netlink.AttributeDecoder, w *Wiphy) error {
	for ad.Next() {
		band := Band(ad.Type())
		info := BandInfo{Band: band, Name: band.String()}

		ad.Nested(func(bad *netlink.AttributeDecoder) error {
			for bad.Next() {
				switch bad.Type() {
				case BandAttrHTCapa:
					info.HTCapa = bad.Uint16()
				case BandAttrVHTCapa:
					info.VHTCapa = bad.Uint32()
				case BandAttrIftypeData:
					// Presence of iftype-data is how HE (802.11ax) capability is advertised.
					info.HasHE = true
				case BandAttrFreqs:
					bad.Nested(func(fad *netlink.AttributeDecoder) error {
						for fad.Next() {
							info.Freqs = append(info.Freqs, decodeFrequency(fad, band))
						}
						return fad.Err()
					})
				case BandAttrRates:
					bad.Nested(func(rad *netlink.AttributeDecoder) error {
						for rad.Next() {
							rad.Nested(func(one *netlink.AttributeDecoder) error {
								for one.Next() {
									if one.Type() == BitrateAttrRate {
										info.Bitrates = append(info.Bitrates, float64(one.Uint32())/10)
									}
								}
								return one.Err()
							})
						}
						return rad.Err()
					})
				}
			}
			return bad.Err()
		})

		w.Bands = append(w.Bands, info)
	}
	return ad.Err()
}

func decodeFrequency(ad *netlink.AttributeDecoder, band Band) Frequency {
	var f Frequency
	ad.Nested(func(one *netlink.AttributeDecoder) error {
		for one.Next() {
			switch one.Type() {
			case FreqAttrFreq:
				f.MHz = int(one.Uint32())
			case FreqAttrDisabled:
				f.Disabled = true
			case FreqAttrNoIR:
				f.NoIR = true
			case FreqAttrRadar:
				f.Radar = true
			case FreqAttrMaxTxPower:
				// Reported in mBm.
				f.MaxTxPowerdBm = float64(one.Uint32()) / 100
			}
		}
		return one.Err()
	})
	f.Channel = ChannelForFrequency(f.MHz, band)
	return f
}

func decodeCombinations(ad *netlink.AttributeDecoder, w *Wiphy) error {
	for ad.Next() {
		var comb IfaceCombination
		ad.Nested(func(cad *netlink.AttributeDecoder) error {
			for cad.Next() {
				switch cad.Type() {
				case IfaceCombMaxnum:
					comb.MaxInterfaces = cad.Uint32()
				case IfaceCombNumChannels:
					comb.NumChannels = cad.Uint32()
				case IfaceCombRadarWidths:
					comb.RadarDetectWidths = cad.Uint32()
				case IfaceCombBeaconIntMinGCD:
					comb.BeaconIntMinGCD = cad.Uint32()
				case IfaceCombStaApBIMatch:
					comb.STAAPBIMatch = true
				case IfaceCombLimits:
					cad.Nested(func(lad *netlink.AttributeDecoder) error {
						for lad.Next() {
							var lim IfaceLimit
							lad.Nested(func(one *netlink.AttributeDecoder) error {
								for one.Next() {
									switch one.Type() {
									case IfaceLimitMax:
										lim.Max = one.Uint32()
									case IfaceLimitTypes:
										one.Nested(func(tad *netlink.AttributeDecoder) error {
											lim.Types = decodeIftypeSet(tad)
											return tad.Err()
										})
									}
								}
								return one.Err()
							})
							comb.Limits = append(comb.Limits, lim)
						}
						return lad.Err()
					})
				}
			}
			return cad.Err()
		})
		w.Combinations = append(w.Combinations, comb)
	}
	return ad.Err()
}

// merge folds a partial wiphy from a split dump into an accumulated one.
//
// The kernel splits a phy across messages at arbitrary attribute boundaries, and a band's
// frequency list can itself be split, so bands merge by band ID rather than being appended.
// Getting this wrong yields a phy that appears to support only the last few channels the
// kernel happened to send - which looks like a regulatory restriction rather than a bug.
func (w *Wiphy) merge(part *Wiphy) {
	if part.Name != "" {
		w.Name = part.Name
	}
	if part.MaxScanSSIDs != 0 {
		w.MaxScanSSIDs = part.MaxScanSSIDs
	}
	if part.FeatureFlags != 0 {
		w.FeatureFlags = part.FeatureFlags
	}
	if len(part.SupportedIftypes) > 0 {
		w.SupportedIftypes = unionIftypes(w.SupportedIftypes, part.SupportedIftypes)
	}
	if len(part.SoftwareIftypes) > 0 {
		w.SoftwareIftypes = unionIftypes(w.SoftwareIftypes, part.SoftwareIftypes)
	}
	if len(part.Commands) > 0 {
		w.Commands = append(w.Commands, part.Commands...)
	}
	if len(part.Combinations) > 0 {
		// Combinations arrive whole within a message; a later message repeating them would
		// duplicate, so replace rather than append.
		w.Combinations = part.Combinations
	}

	for _, pb := range part.Bands {
		idx := -1
		for i := range w.Bands {
			if w.Bands[i].Band == pb.Band {
				idx = i
				break
			}
		}
		if idx < 0 {
			w.Bands = append(w.Bands, pb)
			continue
		}
		dst := &w.Bands[idx]
		dst.Freqs = append(dst.Freqs, pb.Freqs...)
		dst.Bitrates = append(dst.Bitrates, pb.Bitrates...)
		if pb.HTCapa != 0 {
			dst.HTCapa = pb.HTCapa
		}
		if pb.VHTCapa != 0 {
			dst.VHTCapa = pb.VHTCapa
		}
		if pb.HasHE {
			dst.HasHE = true
		}
	}
}

func unionIftypes(a, b []Iftype) []Iftype {
	seen := make(map[Iftype]struct{}, len(a)+len(b))
	out := make([]Iftype, 0, len(a)+len(b))
	for _, s := range [][]Iftype{a, b} {
		for _, t := range s {
			if _, ok := seen[t]; ok {
				continue
			}
			seen[t] = struct{}{}
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
