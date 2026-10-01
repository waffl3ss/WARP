// Package rogue derives a baseline from the observed population and classifies devices
// against it.
//
// Core principle: list everything, classify only when certain. Every observed device is
// recorded and displayed, including neighbours and other tenants. Nothing is filtered out,
// and the default state of a device is *unclassified* - not "neighbour", which is itself a
// conclusion and usually an unsupported one.
//
// There is no client AP inventory and there never will be, so the baseline is derived: cluster
// every BSSID broadcasting a given scoped ESSID by radio fingerprint, and treat the dominant
// cluster as the client's infrastructure. Client fleets are homogeneous - same vendor, same
// firmware, same configuration - so an impostor falls outside the cluster it is pretending to
// belong to. That is a stronger signal than an inventory lookup, because it also catches an
// impostor that spoofed a legitimate BSSID.
package rogue

import (
	"fmt"
	"sort"

	"github.com/waffl3ss/warp/internal/recon"
)

// Clustering defaults.
const (
	// DefaultSimilarityThreshold is the fingerprint similarity above which two APs are taken
	// to be the same kind of device. Tuned so that a same-vendor model variant stays in the
	// cluster while a hostapd impostor does not.
	DefaultSimilarityThreshold = 0.75

	// DefaultMinPopulation is the smallest population from which a baseline may be derived.
	//
	// With two APs on an ESSID there is no way to tell which one is the impostor - the
	// "cluster" is a coin flip, and flagging either is a guess dressed up as a finding.
	DefaultMinPopulation = 3

	// DefaultDominanceRatio is the fraction of the population the largest cluster must hold
	// before it can be called the client's infrastructure.
	//
	// This is the guard against a genuinely mixed environment. A site with three vendors on
	// one ESSID has no dominant cluster, and calling the smallest group impostors would send
	// someone to tear down a legitimate access point.
	DefaultDominanceRatio = 0.6

	// minBaselineFleet is the smallest dominant cluster that can serve as a baseline. Two matching
	// access points are not a fleet: on a home/SMB mesh a two-vs-one split (two older nodes, one
	// newer generation) is routine and legitimate, and flagging the odd node is the false positive
	// that produces. Three matching access points make the baseline, not the outlier, the majority.
	minBaselineFleet = 3
)

// Config tunes the clustering.
type Config struct {
	SimilarityThreshold float64
	MinPopulation       int
	DominanceRatio      float64
}

func (c Config) withDefaults() Config {
	if c.SimilarityThreshold <= 0 {
		c.SimilarityThreshold = DefaultSimilarityThreshold
	}
	if c.MinPopulation <= 0 {
		c.MinPopulation = DefaultMinPopulation
	}
	if c.DominanceRatio <= 0 {
		c.DominanceRatio = DefaultDominanceRatio
	}
	return c
}

// Cluster is a group of APs with mutually similar fingerprints.
type Cluster struct {
	Members []recon.AP `json:"members"`
	// Representative is the fingerprint of the member with the most beacons observed, used
	// as the cluster's reference point when describing how an outlier differs.
	Representative recon.Fingerprint `json:"-"`
}

// Size returns the number of members.
func (c Cluster) Size() int { return len(c.Members) }

// BSSIDs returns the cluster members' addresses.
func (c Cluster) BSSIDs() []string {
	out := make([]string, 0, len(c.Members))
	for _, m := range c.Members {
		out = append(out, m.BSSID.String())
	}
	return out
}

// Outlier is an AP that falls outside the dominant cluster on its own ESSID.
type Outlier struct {
	AP recon.AP `json:"ap"`
	// Score is the similarity to the dominant cluster's representative.
	Score float64 `json:"score"`
	// Differences are the specific attributes that diverged. These are what a report cites:
	// "advertises no vendor elements where every other AP on this ESSID advertises three
	// Cisco elements" is defensible; "outlier score 0.42" is not.
	Differences []recon.Difference `json:"differences"`
}

// Analysis is the result of clustering one ESSID's population.
type Analysis struct {
	ESSID      string    `json:"essid"`
	Population int       `json:"population"`
	Clusters   []Cluster `json:"-"`
	// Dominant is the cluster taken to be the client's infrastructure, or nil if none
	// qualified.
	Dominant *Cluster  `json:"-"`
	Outliers []Outlier `json:"outliers,omitempty"`

	// Inconclusive means no baseline could be derived. Reason says why.
	//
	// This is a first-class outcome, not a failure. An inconclusive result is the correct
	// answer for a small or genuinely mixed population, and reporting it honestly is far more
	// useful than manufacturing a finding.
	Inconclusive bool   `json:"inconclusive"`
	Reason       string `json:"reason,omitempty"`
}

// DominantBSSIDs returns the addresses in the dominant cluster, if any.
func (a Analysis) DominantBSSIDs() []string {
	if a.Dominant == nil {
		return nil
	}
	return a.Dominant.BSSIDs()
}

// AnalyseESSID clusters every AP broadcasting one ESSID and identifies outliers.
func AnalyseESSID(essid string, aps []recon.AP, cfg Config) Analysis {
	cfg = cfg.withDefaults()
	a := Analysis{ESSID: essid, Population: len(aps)}

	// APs with no usable fingerprint carry no signal either way - typically only a truncated
	// frame was seen. Including them would make them look like outliers when the only thing
	// that is different is how much we heard.
	var usable []recon.AP
	for _, ap := range aps {
		if !ap.Fingerprint.Empty() {
			usable = append(usable, ap)
		}
	}

	if len(usable) < cfg.MinPopulation {
		a.Inconclusive = true
		a.Reason = fmt.Sprintf(
			"only %d access point(s) with a usable fingerprint broadcast %q; "+
				"at least %d are needed before a baseline can be derived",
			len(usable), essid, cfg.MinPopulation)
		return a
	}

	a.Clusters = clusterByFingerprint(usable, cfg.SimilarityThreshold)
	sort.Slice(a.Clusters, func(i, j int) bool {
		if a.Clusters[i].Size() != a.Clusters[j].Size() {
			return a.Clusters[i].Size() > a.Clusters[j].Size()
		}
		return a.Clusters[i].Members[0].BSSID.String() < a.Clusters[j].Members[0].BSSID.String()
	})

	largest := a.Clusters[0]
	ratio := float64(largest.Size()) / float64(len(usable))

	if ratio < cfg.DominanceRatio {
		// A genuinely heterogeneous population. This is the false-positive guard that
		// matters most: without it, a multi-vendor site produces "evil twin candidates" for
		// whichever vendor happens to be least common.
		a.Inconclusive = true
		a.Reason = fmt.Sprintf(
			"no dominant fingerprint cluster on %q: the largest of %d clusters holds %d of %d "+
				"access points (%.0f%%, below the %.0f%% required). The environment is genuinely "+
				"mixed, so no baseline can be derived and nothing is flagged",
			essid, len(a.Clusters), largest.Size(), len(usable), ratio*100, cfg.DominanceRatio*100)
		return a
	}

	// A baseline needs a real fleet behind it. Even with a dominant ratio, a two-vs-one split -
	// common on a home/SMB mesh where one node is a newer hardware generation than the other two -
	// is not enough evidence to call the odd one an impostor: with only two "matching" access
	// points you cannot tell the baseline from the outlier. Require at least three in the dominant
	// cluster before deriving one.
	if largest.Size() < minBaselineFleet {
		a.Inconclusive = true
		a.Reason = fmt.Sprintf(
			"baseline too small on %q: the dominant fingerprint is shared by only %d of %d access "+
				"points. A fleet of fewer than %d cannot distinguish an impostor from a legitimate "+
				"but different node (a newer mesh node, say), so nothing is flagged",
			essid, largest.Size(), len(usable), minBaselineFleet)
		return a
	}

	a.Dominant = &a.Clusters[0]

	for i := 1; i < len(a.Clusters); i++ {
		for _, member := range a.Clusters[i].Members {
			score, diffs := recon.Similarity(a.Dominant.Representative, member.Fingerprint)
			a.Outliers = append(a.Outliers, Outlier{
				AP: member, Score: score, Differences: diffs,
			})
		}
	}
	sort.Slice(a.Outliers, func(i, j int) bool { return a.Outliers[i].Score < a.Outliers[j].Score })

	return a
}

// clusterByFingerprint groups APs by transitive fingerprint similarity.
//
// Single-linkage connected components: two APs join the same cluster if they are similar
// enough to each other, and clusters merge transitively. That is the right shape here because
// a fleet may contain a chain of model variants that are each close to their neighbour
// without every pair being close, and splitting such a fleet would create phantom outliers.
func clusterByFingerprint(aps []recon.AP, threshold float64) []Cluster {
	n := len(aps)
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}

	var find func(int) int
	find = func(x int) int {
		for parent[x] != x {
			parent[x] = parent[parent[x]] // path halving
			x = parent[x]
		}
		return x
	}
	union := func(a, b int) {
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
	}

	for i := 0; i < n; i++ {
		for j := i + 1; j < n; j++ {
			// An identical fingerprint hash is the common case in a homogeneous fleet and
			// skips the more expensive comparison entirely.
			if aps[i].Fingerprint.Hash() == aps[j].Fingerprint.Hash() {
				union(i, j)
				continue
			}
			if score, _ := recon.Similarity(aps[i].Fingerprint, aps[j].Fingerprint); score >= threshold {
				union(i, j)
			}
		}
	}

	groups := make(map[int][]recon.AP)
	for i, ap := range aps {
		root := find(i)
		groups[root] = append(groups[root], ap)
	}

	out := make([]Cluster, 0, len(groups))
	for _, members := range groups {
		sort.Slice(members, func(i, j int) bool {
			return members[i].BSSID.String() < members[j].BSSID.String()
		})
		out = append(out, Cluster{
			Members:        members,
			Representative: representative(members),
		})
	}
	return out
}

// representative picks the fingerprint to compare outliers against: the member seen most
// often, on the grounds that it is the one we have the most complete picture of.
func representative(members []recon.AP) recon.Fingerprint {
	best := members[0]
	for _, m := range members[1:] {
		if m.Beacons > best.Beacons {
			best = m
		}
	}
	return best.Fingerprint
}
