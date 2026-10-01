package store

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NetXMLFile is the live Kismet-style netxml projection in the engagement directory. Like the CSV
// projections it is regenerated wholesale; per-capture and per-walkthrough snapshots are written
// separately, next to their pcap.
const NetXMLFile = "networks.netxml"

// ctime is the timestamp format Kismet's netxml uses in its first-time/last-time attributes.
const ctime = "Mon Jan _2 15:04:05 2006"

// WriteNetXML writes a Kismet-style netxml document at path: every observed access point as a
// wireless-network, with its SSID/encryption, channel, signal and associated clients. It is a
// projection of the store, so it is a snapshot of what has been observed at the moment it runs -
// the same data behind bssids.csv/clients.csv, in the XML shape survey tools import.
//
// Written atomically (temp file + rename) so a reader never sees a half-written document.
func (s *Store) WriteNetXML(ctx context.Context, path string) error {
	return s.writeNetXML(ctx, path, nil)
}

// WriteNetXMLForWalkthrough writes a netxml holding only the access points recorded during one
// walkthrough, so each pass gets its own netxml matching its pcap rather than the whole engagement's
// inventory.
func (s *Store) WriteNetXMLForWalkthrough(ctx context.Context, path string, id int64) error {
	devices, err := s.WalkthroughDevices(ctx, id)
	if err != nil {
		return err
	}
	keep := map[string]bool{}
	for _, d := range devices {
		if d.IsAP {
			keep[d.BSSID] = true
		}
	}
	return s.writeNetXML(ctx, path, keep)
}

// writeNetXML renders the netxml document. When apFilter is non-nil only access points whose BSSID
// is in it are included (their associated clients follow); a nil filter includes everything.
func (s *Store) writeNetXML(ctx context.Context, path string, apFilter map[string]bool) error {
	aps, err := s.APs(ctx, "")
	if err != nil {
		return err
	}
	if apFilter != nil {
		kept := aps[:0]
		for _, ap := range aps {
			if apFilter[ap.BSSID] {
				kept = append(kept, ap)
			}
		}
		aps = kept
	}
	stations, err := s.Stations(ctx)
	if err != nil {
		return err
	}

	// Group clients by the access point they are associated to.
	byAP := map[string][]StationRow{}
	for _, st := range stations {
		if st.BSSID != "" {
			byAP[st.BSSID] = append(byAP[st.BSSID], st)
		}
	}

	doc := netDetectionRun{
		Version:   "warp",
		StartTime: time.Now().Format(ctime),
	}
	for i, ap := range aps {
		n := netNetwork{
			Number:    i + 1,
			Type:      "infrastructure",
			FirstTime: netTime(ap.FirstSeen),
			LastTime:  netTime(ap.LastSeen),
			BSSID:     ap.BSSID,
			Manuf:     ap.OUI,
			Channel:   ap.Channel,
			Packets:   netPackets{Total: ap.Beacons},
			SSID: netSSID{
				Type:       "Beacon",
				FirstTime:  netTime(ap.FirstSeen),
				LastTime:   netTime(ap.LastSeen),
				Essid:      netEssid{Cloaked: boolStr(ap.Hidden), Value: ap.ESSID},
				Encryption: encryptionTags(ap),
			},
		}
		if ap.Channel > 0 {
			n.Freq = fmt.Sprintf("%d", channelToFreq(ap.Channel))
		}
		if ap.BestRSSI != nil {
			n.SNR = &netSNR{MaxSignal: *ap.BestRSSI}
		}
		for j, c := range byAP[ap.BSSID] {
			n.Clients = append(n.Clients, netClient{
				Number:    j + 1,
				Type:      "established",
				FirstTime: netTime(c.FirstSeen),
				LastTime:  netTime(c.LastSeen),
				MAC:       c.MAC,
				Manuf:     c.OUI,
			})
		}
		doc.Networks = append(doc.Networks, n)
	}

	body, err := xml.MarshalIndent(doc, "", " ")
	if err != nil {
		return fmt.Errorf("store: marshal netxml: %w", err)
	}
	out := append([]byte(xml.Header), body...)
	out = append(out, '\n')
	return writeFileAtomic(path, out)
}

// encryptionTags renders an access point's security posture as the <encryption> tags Kismet uses.
func encryptionTags(ap APRow) []string {
	var tags []string
	switch ap.SecurityClass {
	case "open":
		tags = append(tags, "None")
	case "wep":
		tags = append(tags, "WEP")
	case "wpa_enterprise":
		tags = append(tags, "WPA+EAP")
	case "wpa_sae", "wpa3":
		tags = append(tags, "WPA3+SAE")
	case "owe":
		tags = append(tags, "OWE")
	default:
		if ap.SecurityClass != "" {
			tags = append(tags, "WPA+PSK")
		}
	}
	for _, c := range strings.FieldsFunc(ap.Ciphers, splitList) {
		tags = append(tags, "WPA+"+c)
	}
	if ap.WPS {
		tags = append(tags, "WPS")
	}
	if len(tags) == 0 {
		tags = append(tags, "None")
	}
	return tags
}

func splitList(r rune) bool { return r == ',' || r == ' ' || r == ';' }

// netTime reformats a stored RFC3339 timestamp into Kismet's ctime attribute format, passing it
// through unchanged if it cannot be parsed.
func netTime(s string) string {
	t, err := time.Parse(timeFormat, s)
	if err != nil {
		return s
	}
	return t.Format(ctime)
}

// channelToFreq maps a 2.4/5 GHz channel number to its centre frequency for the freqmhz field.
func channelToFreq(ch int) int {
	switch {
	case ch == 14:
		return 2484
	case ch >= 1 && ch <= 13:
		return 2407 + ch*5
	default:
		return 5000 + ch*5
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".warp-netxml-*")
	if err != nil {
		return fmt.Errorf("store: create temp for %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("store: write %s: %w", path, err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("store: secure %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store: sync %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: close %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("store: rename into %s: %w", path, err)
	}
	return nil
}

// Kismet netxml document shapes. Only the widely-imported subset is emitted.

type netDetectionRun struct {
	XMLName   xml.Name     `xml:"detection-run"`
	Version   string       `xml:"kismet-version,attr"`
	StartTime string       `xml:"start-time,attr"`
	Networks  []netNetwork `xml:"wireless-network"`
}

type netNetwork struct {
	Number    int         `xml:"number,attr"`
	Type      string      `xml:"type,attr"`
	FirstTime string      `xml:"first-time,attr"`
	LastTime  string      `xml:"last-time,attr"`
	SSID      netSSID     `xml:"SSID"`
	BSSID     string      `xml:"BSSID"`
	Manuf     string      `xml:"manuf,omitempty"`
	Channel   int         `xml:"channel"`
	Freq      string      `xml:"freqmhz,omitempty"`
	SNR       *netSNR     `xml:"snr-info,omitempty"`
	Packets   netPackets  `xml:"packets"`
	Clients   []netClient `xml:"wireless-client"`
}

type netSSID struct {
	Type       string   `xml:"type"`
	FirstTime  string   `xml:"first-time,attr"`
	LastTime   string   `xml:"last-time,attr"`
	Essid      netEssid `xml:"essid"`
	Encryption []string `xml:"encryption"`
}

type netEssid struct {
	Cloaked string `xml:"cloaked,attr"`
	Value   string `xml:",chardata"`
}

type netSNR struct {
	MaxSignal int `xml:"max_signal_dbm"`
}

type netPackets struct {
	Total int64 `xml:"total"`
}

type netClient struct {
	Number    int    `xml:"number,attr"`
	Type      string `xml:"type,attr"`
	FirstTime string `xml:"first-time,attr"`
	LastTime  string `xml:"last-time,attr"`
	MAC       string `xml:"client-mac"`
	Manuf     string `xml:"client-manuf,omitempty"`
}
