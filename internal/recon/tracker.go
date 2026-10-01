package recon

import (
	"sort"
	"sync"
	"time"

	"github.com/waffl3ss/warp/internal/radio/nl80211"
)

// AP is everything WARP has observed about one BSSID.
//
// Every field here is an observation. Nothing in this struct is a conclusion - no field says
// whether the AP is the client's, a neighbour's, or an impostor. That separation is required:
// a report must be able to show the evidence independently of the label.
type AP struct {
	BSSID MAC    `json:"bssid"`
	ESSID string `json:"essid"`
	// Hidden is true when the AP beacons a cloaked SSID. It stays true until a probe
	// response or association frame reveals the name, at which point ESSID is filled in and
	// ESSIDSource records how.
	Hidden bool `json:"hidden"`
	// Cloaked latches true the first time this access point is seen beaconing no SSID, and
	// never clears. Hidden goes false the moment the name is learned, which would otherwise
	// erase the fact that it was ever hidden - and "this network is cloaked, and here is its
	// name anyway" is a finding, not a detail.
	Cloaked     bool   `json:"cloaked,omitempty"`
	ESSIDSource string `json:"essid_source,omitempty"`

	Channel int    `json:"channel"`
	Freq    int    `json:"freq"`
	Band    string `json:"band"`
	// PHY is the 802.11 generations this access point advertises, newest first, e.g. "ax/n/g".
	//
	// Worth carrying next to the band because the two answer different questions. The band says
	// where it is; the PHY says what it is, and an estate with 802.11g-only access points still
	// on the floor is a finding on its own - old radios are old firmware, and they are usually
	// the ones with the weak WPS and the absent 802.11w.
	PHY string `json:"phy,omitempty"`

	// LastRSSI is the most recent signal; BestRSSI is the strongest ever seen, on the radio
	// named by BestRSSIRadio. RSSI is not comparable across radios, so the radio is carried
	// with the value rather than being dropped.
	LastRSSI      int8   `json:"last_rssi"`
	BestRSSI      int8   `json:"best_rssi"`
	BestRSSIRadio string `json:"best_rssi_radio,omitempty"`
	HasRSSI       bool   `json:"has_rssi"`

	Security    SecurityInfo `json:"security"`
	Fingerprint Fingerprint  `json:"fingerprint"`

	// FirstSeen and LastSeen are what a multi-day unattended run surfaces that a survey walk
	// structurally cannot: contractor hotspots, after-hours tethering, devices that only
	// appear at 0200.
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	Beacons    uint64   `json:"beacons"`
	ProbeResps uint64   `json:"probe_responses"`
	DataFrames uint64   `json:"data_frames"`
	OUI        string   `json:"oui"`
	LocalMAC   bool     `json:"locally_administered_mac,omitempty"`
	RadiosSeen []string `json:"radios_seen,omitempty"`
}

// Station is a client device.
type Station struct {
	MAC MAC `json:"mac"`
	// BSSID is the AP it is associated with, zero if unknown.
	BSSID     MAC       `json:"bssid,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`

	LastRSSI int8 `json:"last_rssi"`
	BestRSSI int8 `json:"best_rssi"`
	HasRSSI  bool `json:"has_rssi"`

	// ProbedESSIDs is every network this station has asked for by name. It leaks the
	// device's history of prior connections and is directly useful for targeting.
	ProbedESSIDs []string `json:"probed_essids,omitempty"`

	// Randomised reports a locally administered address. Modern phones randomise while
	// probing, so counting these as distinct devices wildly overcounts.
	Randomised bool   `json:"randomised_mac"`
	OUI        string `json:"oui"`
	Frames     uint64 `json:"frames"`
}

// Observation is a single timestamped signal reading, written to the store for the survey.
//
// It carries radio_id because RSSI is not comparable across chipsets or antennas, and the
// survey's localisation ranking is only defensible if mixed-radio data can be excluded at
// query time.
type Observation struct {
	Addr      MAC       `json:"addr"`
	IsAP      bool      `json:"is_ap"`
	RSSI      int8      `json:"rssi"`
	Freq      int       `json:"freq"`
	Channel   int       `json:"channel"`
	Timestamp time.Time `json:"ts"`
	RadioID   string    `json:"radio_id"`
	FrameType string    `json:"frame_type"`
}

// EventKind classifies a tracker event for the REPL scrollback.
type EventKind string

// Tracker event kinds.
const (
	EventNewAP         EventKind = "new_ap"
	EventNewStation    EventKind = "new_station"
	EventESSIDRevealed EventKind = "essid_revealed"
	EventAssociation   EventKind = "association"
)

// Event is something worth telling the operator about.
type Event struct {
	Kind    EventKind `json:"kind"`
	BSSID   MAC       `json:"bssid,omitempty"`
	Station MAC       `json:"station,omitempty"`
	ESSID   string    `json:"essid,omitempty"`
	Channel int       `json:"channel,omitempty"`
	RSSI    int8      `json:"rssi,omitempty"`
	Detail  string    `json:"detail,omitempty"`
}

// Tracker maintains the live picture of what is on the air.
//
// Everything observed is recorded, including neighbours and other tenants. Nothing is
// filtered out - the default state of an observed device is unclassified, not "neighbour",
// and that call belongs to the rogue package, not here.
type Tracker struct {
	mu       sync.RWMutex
	aps      map[MAC]*AP
	stations map[MAC]*Station

	// observations is an optional sink for per-frame signal readings.
	observations func(Observation)
}

// NewTracker builds an empty tracker. sink may be nil.
func NewTracker(sink func(Observation)) *Tracker {
	return &Tracker{
		aps:          make(map[MAC]*AP),
		stations:     make(map[MAC]*Station),
		observations: sink,
	}
}

// Observe folds one parsed frame into the picture and returns any notable events.
//
// radioID identifies the adapter that heard the frame; it is stamped on every observation.
func (t *Tracker) Observe(f *Frame, rt RadiotapMeta, radioID string, now time.Time) []Event {
	if f == nil {
		return nil
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var events []Event

	switch f.Type {
	case TypeManagement:
		events = append(events, t.observeManagement(f, rt, radioID, now)...)
	case TypeData:
		events = append(events, t.observeData(f, rt, radioID, now)...)
	case TypeControl:
		// Control frames carry no useful identity beyond the transmitter, but they do prove
		// a device is present and are worth an observation for hunt mode.
		if src, ok := f.Source(); ok && rt.HasRSSI {
			t.emitObservation(Observation{
				Addr: src, RSSI: rt.RSSI, Freq: rt.Freq, Channel: rt.Channel,
				Timestamp: now, RadioID: radioID, FrameType: "ctrl",
			})
		}
	}

	return events
}

// RadiotapMeta is the per-frame radio metadata the tracker needs.
//
// It is a small local struct rather than the capture package's type so that recon does not
// depend on capture - the parsers stay unit-testable without a capture stack.
type RadiotapMeta struct {
	RSSI    int8
	HasRSSI bool
	Freq    int
	Channel int
}

// bandOf picks the band a beacon's channel element should be interpreted in.
//
// The receiver's frequency is the right source for this: it can be off by a channel or two
// within a band, which does not matter here, but it is never off by a *band*. A card tuned to
// 2417 MHz has not heard a 5 GHz beacon.
//
// With no radiotap frequency at all, the channel number is the only clue. Above 14 means
// 5 GHz; 6 GHz numbering restarts at 1 and is indistinguishable from 2.4 GHz on the number
// alone, so the commoner band wins.
func bandOf(rtFreq, channel int) nl80211.Band {
	if rtFreq != 0 {
		return nl80211.BandForFrequency(rtFreq)
	}
	if channel > 14 {
		return nl80211.Band5GHz
	}
	return nl80211.Band2GHz
}

func (t *Tracker) observeManagement(f *Frame, rt RadiotapMeta, radioID string, now time.Time) []Event {
	var events []Event

	bssid, hasBSSID := f.BSSID()

	// Probe requests come from stations and name networks the device has used before.
	if f.Subtype == SubtypeProbeReq {
		src, ok := f.Source()
		if !ok {
			return nil
		}
		st, isNew := t.station(src, now)
		st.LastSeen = now
		st.Frames++
		t.applyStationRSSI(st, rt)

		if _, ies, ok := f.ManagementBody(); ok {
			if parsed, err := ParseIEs(ies); err == nil || len(parsed) > 0 {
				if essid, ok := parsed.SSID(); ok {
					if addUnique(&st.ProbedESSIDs, essid) {
						events = append(events, Event{
							Kind: EventNewStation, Station: src, ESSID: essid,
							Detail: "probed for " + essid,
						})
					}
				}
			}
		}
		if isNew {
			events = append(events, Event{Kind: EventNewStation, Station: src, RSSI: rt.RSSI})
		}
		t.emitObservation(Observation{
			Addr: src, RSSI: rt.RSSI, Freq: rt.Freq, Channel: rt.Channel,
			Timestamp: now, RadioID: radioID, FrameType: "probe-req",
		})
		return events
	}

	if !hasBSSID {
		return events
	}

	switch f.Subtype {
	case SubtypeBeacon, SubtypeProbeResp:
		ap, isNew := t.ap(bssid, now)
		ap.LastSeen = now
		if f.Subtype == SubtypeBeacon {
			ap.Beacons++
		} else {
			ap.ProbeResps++
		}
		t.applyAPRSSI(ap, rt, radioID)

		_, ies, ok := f.ManagementBody()
		if !ok {
			return events
		}
		parsed, _ := ParseIEs(ies)

		// Where the access point *is*, not where we happened to hear it.
		//
		// This distinction is not pedantic, it decides whether every transmitting attack
		// works. Radiotap reports the frequency the receiving card was tuned to at the moment
		// the frame arrived - and in 2.4 GHz the channels overlap by design, so a beacon from
		// channel 1 is comfortably audible while sweeping channel 2. Taking the frequency from
		// radiotap therefore recorded the *sweep's* channel: an AP on 1 came out as 2, one on
		// 6 as 7, one on 10 as 11. Every campaign then held the radios one channel off the
		// target and transmitted where nothing was listening, which is why solicitation never
		// produced a PMKID, why deauthentication worked at one network and not its neighbours,
		// and why the enterprise harvest never saw an EAP request.
		//
		// The DS Parameter Set (and the HT Operation primary channel) is the access point
		// stating its own channel in its own beacon. That is authoritative and it is what the
		// frequency must be derived from. Radiotap is still the best source for the *band* -
		// channel 6 is 2437 MHz in 2.4 GHz and 5980 MHz in 6 GHz, and the number alone cannot
		// tell them apart.
		if ch, ok := parsed.Channel(); ok {
			ap.Channel = ch
			if freq := nl80211.FrequencyForChannel(ch, bandOf(rt.Freq, ch)); freq != 0 {
				ap.Freq = freq
			}
		} else if rt.Channel != 0 {
			// No channel element - an uncommon beacon, and a probe response from a hidden
			// network sometimes. Radiotap is all there is, and being one channel out is better
			// than having none at all.
			ap.Channel = rt.Channel
			ap.Freq = rt.Freq
		}
		if ap.Freq != 0 {
			ap.Band = nl80211.BandForFrequency(ap.Freq).String()
		}
		ap.PHY = parsed.PHYModes(ap.Band)

		capability, _ := f.Capability()
		beaconInterval, _ := f.BeaconInterval()
		ap.Security = ClassifySecurity(parsed, capability)
		ap.Fingerprint = FingerprintFrom(parsed, capability, beaconInterval)

		if essid, ok := parsed.SSID(); ok && essid != "" {
			if ap.ESSID == "" {
				ap.ESSID = essid
				ap.Hidden = false
				ap.ESSIDSource = f.Subtype.ManagementName()
				if !isNew {
					events = append(events, Event{
						Kind: EventESSIDRevealed, BSSID: bssid, ESSID: essid,
						Detail: "revealed by " + f.Subtype.ManagementName(),
					})
				}
			} else if essid != ap.ESSID && f.Subtype == SubtypeBeacon {
				// The same BSSID is now beaconing a different name - a reconfiguration of that one
				// radio, not a second AP (a second AP would have a different BSSID). Track the
				// current name; the stale one would otherwise mislead scope matching and any
				// active work (an association or PMKID solicit built from the old ESSID fails).
				old := ap.ESSID
				ap.ESSID = essid
				ap.Hidden = false
				ap.ESSIDSource = f.Subtype.ManagementName()
				events = append(events, Event{
					Kind: EventESSIDRevealed, BSSID: bssid, ESSID: essid,
					Detail: "name changed from " + old,
				})
			}
		} else if f.Subtype == SubtypeBeacon {
			// A cloaked SSID stays passive-observation-only: it cannot match a scoped ESSID
			// until the real name is learned from a probe response or association.
			//
			// Cloaked latches on the beacon rather than on ESSID being empty, so it still
			// records the fact after the name is recovered - a decloaked network is one the
			// client believed was not advertising itself.
			ap.Cloaked = true
			if ap.ESSID == "" {
				ap.Hidden = true
			}
		}

		if isNew {
			events = append(events, Event{
				Kind: EventNewAP, BSSID: bssid, ESSID: ap.ESSID,
				Channel: ap.Channel, RSSI: rt.RSSI,
				Detail: ap.Security.Describe(),
			})
		}

		t.emitObservation(Observation{
			Addr: bssid, IsAP: true, RSSI: rt.RSSI, Freq: ap.Freq, Channel: ap.Channel,
			Timestamp: now, RadioID: radioID, FrameType: f.Subtype.ManagementName(),
		})

	case SubtypeAssocReq, SubtypeReassocReq:
		ap, _ := t.ap(bssid, now)
		ap.LastSeen = now

		src, ok := f.Source()
		if !ok {
			return events
		}
		st, isNew := t.station(src, now)
		st.LastSeen = now
		st.Frames++
		st.BSSID = bssid
		t.applyStationRSSI(st, rt)

		// An association request names the network the client is joining, which resolves a
		// hidden SSID.
		if _, ies, ok := f.ManagementBody(); ok {
			parsed, _ := ParseIEs(ies)
			if essid, ok := parsed.SSID(); ok {
				addUnique(&st.ProbedESSIDs, essid)
				if ap.ESSID == "" {
					ap.ESSID = essid
					ap.Hidden = false
					ap.ESSIDSource = "assoc-req"
					events = append(events, Event{
						Kind: EventESSIDRevealed, BSSID: bssid, ESSID: essid,
						Detail: "revealed by association request",
					})
				}
			}
		}

		events = append(events, Event{
			Kind: EventAssociation, BSSID: bssid, Station: src, ESSID: ap.ESSID,
			Detail: "association request",
		})
		if isNew {
			events = append(events, Event{Kind: EventNewStation, Station: src, RSSI: rt.RSSI})
		}

		t.emitObservation(Observation{
			Addr: src, RSSI: rt.RSSI, Freq: rt.Freq, Channel: ap.Channel,
			Timestamp: now, RadioID: radioID, FrameType: f.Subtype.ManagementName(),
		})

	default:
		// Auth, deauth, disassoc, action: prove presence and association without changing
		// the security picture.
		ap, isNew := t.ap(bssid, now)
		ap.LastSeen = now
		t.applyAPRSSI(ap, rt, radioID)
		if isNew {
			events = append(events, Event{Kind: EventNewAP, BSSID: bssid, Channel: ap.Channel})
		}

		if sta, ok := f.StationAddr(); ok {
			st, isNewSta := t.station(sta, now)
			st.LastSeen = now
			st.Frames++
			if st.BSSID.IsZero() {
				st.BSSID = bssid
			}
			t.applyStationRSSI(st, rt)
			if isNewSta {
				events = append(events, Event{Kind: EventNewStation, Station: sta, RSSI: rt.RSSI})
			}
		}
	}

	return events
}

func (t *Tracker) observeData(f *Frame, rt RadiotapMeta, radioID string, now time.Time) []Event {
	var events []Event

	bssid, ok := f.BSSID()
	if !ok {
		return nil
	}
	ap, isNew := t.ap(bssid, now)
	ap.LastSeen = now
	ap.DataFrames++
	t.applyAPRSSI(ap, rt, radioID)
	if isNew {
		events = append(events, Event{Kind: EventNewAP, BSSID: bssid, Channel: ap.Channel})
	}

	if sta, ok := f.StationAddr(); ok && sta != bssid {
		st, isNewSta := t.station(sta, now)
		st.LastSeen = now
		st.Frames++
		st.BSSID = bssid
		t.applyStationRSSI(st, rt)
		if isNewSta {
			events = append(events, Event{Kind: EventNewStation, Station: sta, RSSI: rt.RSSI})
		}
		t.emitObservation(Observation{
			Addr: sta, RSSI: rt.RSSI, Freq: rt.Freq, Channel: ap.Channel,
			Timestamp: now, RadioID: radioID, FrameType: "data",
		})
	}

	t.emitObservation(Observation{
		Addr: bssid, IsAP: true, RSSI: rt.RSSI, Freq: rt.Freq, Channel: ap.Channel,
		Timestamp: now, RadioID: radioID, FrameType: "data",
	})
	return events
}

// ap returns the record for a BSSID, creating it if new.
func (t *Tracker) ap(bssid MAC, now time.Time) (*AP, bool) {
	if ap, ok := t.aps[bssid]; ok {
		return ap, false
	}
	ap := &AP{
		BSSID:     bssid,
		FirstSeen: now,
		LastSeen:  now,
		OUI:       bssid.OUIString(),
		LocalMAC:  bssid.IsLocallyAdministered(),
	}
	t.aps[bssid] = ap
	return ap, true
}

func (t *Tracker) station(mac MAC, now time.Time) (*Station, bool) {
	if st, ok := t.stations[mac]; ok {
		return st, false
	}
	st := &Station{
		MAC:        mac,
		FirstSeen:  now,
		LastSeen:   now,
		OUI:        mac.OUIString(),
		Randomised: mac.IsRandomised(),
	}
	t.stations[mac] = st
	return st, true
}

// applyAPRSSI records a signal reading, keeping the best value and the radio that heard it.
func (t *Tracker) applyAPRSSI(ap *AP, rt RadiotapMeta, radioID string) {
	if radioID != "" {
		addUnique(&ap.RadiosSeen, radioID)
	}
	if !rt.HasRSSI {
		// A driver that reported no signal must not be recorded as 0 dBm, which would read as
		// an extremely strong signal and put the device in the wrong room.
		return
	}
	ap.LastRSSI = rt.RSSI
	if !ap.HasRSSI || rt.RSSI > ap.BestRSSI {
		ap.BestRSSI = rt.RSSI
		ap.BestRSSIRadio = radioID
	}
	ap.HasRSSI = true
}

func (t *Tracker) applyStationRSSI(st *Station, rt RadiotapMeta) {
	if !rt.HasRSSI {
		return
	}
	st.LastRSSI = rt.RSSI
	if !st.HasRSSI || rt.RSSI > st.BestRSSI {
		st.BestRSSI = rt.RSSI
	}
	st.HasRSSI = true
}

func (t *Tracker) emitObservation(o Observation) {
	if t.observations == nil || o.RSSI == 0 {
		return
	}
	t.observations(o)
}

// APs returns a snapshot of every observed BSSID, ordered by BSSID.
func (t *Tracker) APs() []AP {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]AP, 0, len(t.aps))
	for _, ap := range t.aps {
		out = append(out, *ap)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BSSID.String() < out[j].BSSID.String() })
	return out
}

// Stations returns a snapshot of every observed client.
func (t *Tracker) Stations() []Station {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]Station, 0, len(t.stations))
	for _, st := range t.stations {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC.String() < out[j].MAC.String() })
	return out
}

// AP returns one BSSID's record.
func (t *Tracker) AP(bssid MAC) (AP, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ap, ok := t.aps[bssid]
	if !ok {
		return AP{}, false
	}
	return *ap, true
}

// Station returns one client's record.
func (t *Tracker) Station(mac MAC) (Station, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	st, ok := t.stations[mac]
	if !ok {
		return Station{}, false
	}
	return *st, true
}

// APsForESSID returns every BSSID broadcasting the given ESSID.
//
// This is the population that rogue clustering operates on: all the APs claiming to be one
// network, from which the dominant fingerprint cluster is the client's real infrastructure.
func (t *Tracker) APsForESSID(essid string) []AP {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var out []AP
	for _, ap := range t.aps {
		if ap.ESSID == essid {
			out = append(out, *ap)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].BSSID.String() < out[j].BSSID.String() })
	return out
}

// Counts returns the number of tracked APs and stations, for the status header.
func (t *Tracker) Counts() (aps, stations int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.aps), len(t.stations)
}

// addUnique appends s to the list if not already present, returning whether it was added.
func addUnique(list *[]string, s string) bool {
	if s == "" {
		return false
	}
	for _, existing := range *list {
		if existing == s {
			return false
		}
	}
	*list = append(*list, s)
	return true
}
