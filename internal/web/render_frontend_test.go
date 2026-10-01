package web

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/dop251/goja"
)

// The frontend is executed here, not just parsed.
//
// A syntax check proves the file loads; it does not prove that rendering an access point with
// no ESSID, or a job that failed, or an empty findings list, gets through without throwing.
// Any one of those leaves the operator looking at a half-drawn page with no error visible,
// on a box they may only be able to reach over a tunnel. So the real script runs against a
// small DOM (testdata/domshim.js) with fixtures shaped exactly like the daemon's JSON.
//
// goja is a test-only dependency; nothing here enters the shipped binary.

// jsFixture mirrors what the daemon actually returns. Field names come from the Go structs'
// JSON tags, which is the contract this test exists to pin.
const jsFixture = `{
  "status": {
    "version": "v0.5.0", "commit": "a1b2c3d", "author": "@waffl3ss",
    "workspace": "/opt/eng/acme",
    "started_at": "2026-09-04T10:00:00Z",
    "uptime": "37m0s",
    "scope_essids": 4,
    "pending_acknowledgments": ["guest"],
    "survey_radio": "phy0",
    "capabilities": [
      {"name": "recon sweep", "available": true},
      {"name": "targeted deauthentication", "available": true, "degraded": true,
       "reason": "one adapter: the sweep pauses while a deauth transmits"},
      {"name": "evil-twin EAP harvest", "available": false,
       "reason": "needs a second adapter - this kit has one"}
    ],
    "recon": {
      "running": true, "aps": 3, "stations": 2,
      "radios": [
        {"radio_id": "phy0", "ifname": "wlan0", "role": "recon", "channel": 6,
         "bands": "2.4/5GHz", "capture": {"frames": 18422, "dropped": 3}},
        {"radio_id": "phy1", "ifname": "wlan1", "role": "survey", "channel": 44,
         "bands": "2.4/5GHz", "locked": true, "capture": {"frames": 900}}],
      "held_radios": ["phy1"],
      "handshake": {"sessions": 2, "pending_essid": 1}
    },
    "running_jobs": 1, "walkthrough": "3rd floor east",
    "pmkid_hashes": 2, "handshake_hashes": 1,
    "disk": {
      "path": "/opt/eng/acme",
      "total_bytes": 250000000000, "used_bytes": 100000000000,
      "free_bytes": 150000000000, "used_percent": 40.0,
      "engagement_bytes": 3221225472, "level": "ok"
    }
  },
  "certs": {
    "directory": "/opt/eng/acme/certs",
    "networks": {
      "ACME-CORP": [
        {"id": "a1b2c3d4e5f60718", "essid": "ACME-CORP", "source": "mimic",
         "source_detail": "mimicked from a harvested certificate",
         "subject": "CN=radius.acme.example ", "issuer": "CN=ACME Issuing CA",
         "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-09-01T00:00:00Z",
         "key_algorithm": "RSA", "key_bits": 2048,
         "fingerprint_sha256": "aabb", "created": "2026-09-04T10:00:00Z", "selected": true},
        {"id": "0011223344556677", "essid": "ACME-CORP", "source": "self-signed",
         "source_detail": "self-signed",
         "subject": "CN=radius.acme-corp", "issuer": "CN=acme-corp Root CA",
         "not_before": "2026-09-01T00:00:00Z", "not_after": "2027-09-01T00:00:00Z",
         "key_algorithm": "RSA", "key_bits": 2048,
         "fingerprint_sha256": "ccdd", "created": "2026-09-04T09:00:00Z", "selected": false}
      ],
      "ACME-GUEST": []
    }
  },
  "aps": [
    {"bssid": "a4:2b:8c:11:22:33", "essid": "ACME-CORP", "channel": 6, "band": "2.4 GHz",
     "last_rssi": -48, "best_rssi": -42, "has_rssi": true, "active": true, "last_seen_secs": 3,
     "in_scope": true, "beacons": 1204, "oui": "Cisco",
     "first_seen": "2026-09-04T10:02:00Z", "last_seen": "2026-09-04T10:37:00Z",
     "security": {"class": "wpa_psk", "mfp": "capable", "wps": true}},

    {"bssid": "a4:2b:8c:11:22:34", "essid": "ACME-CORP", "channel": 44, "band": "5 GHz",
     "last_rssi": -71, "best_rssi": -68, "has_rssi": true, "active": true, "last_seen_secs": 12,
     "in_scope": true, "beacons": 843,
     "last_seen": "2026-09-04T10:36:00Z",
     "security": {"class": "wpa_psk", "mfp": "required"}},

    {"bssid": "de:ad:be:ef:00:01", "channel": 1, "band": "2.4 GHz",
     "has_rssi": false, "active": false, "last_seen_secs": 240, "in_scope": false, "beacons": 12,
     "security": {"class": "open", "mfp": "unknown"}},

    {"bssid": "b0:b1:b2:c3:c4:c5", "essid": "ACME-BACKOFFICE", "channel": 3,
     "last_rssi": -59, "best_rssi": -55, "has_rssi": true, "active": true, "last_seen_secs": 8,
     "in_scope": true,
     "cloaked": true, "essid_source": "probe-response",
     "security": {"class": "wpa_psk", "mfp": "absent"}},

    {"bssid": "00:11:22:33:44:55", "essid": "ACME-GUEST", "channel": 11,
     "last_rssi": -66, "best_rssi": -61, "has_rssi": true, "active": true, "last_seen_secs": 5,
     "in_scope": true, "operator_rejected": true,
     "security": {"class": "wpa_sae", "mfp": "required", "transition_mode": true}}
  ],
  "stations": [
    {"mac": "3c:22:fb:aa:bb:cc", "bssid": "a4:2b:8c:11:22:33", "last_rssi": -55, "best_rssi": -50,
     "has_rssi": true, "active": true, "last_seen_secs": 4, "frames": 902, "oui": "Apple",
     "probed_essids": ["ACME-CORP", "Starbucks WiFi"]},
    {"mac": "8e:41:03:9f:2d:70", "has_rssi": false, "active": false, "last_seen_secs": 300,
     "frames": 41, "randomised_mac": true}
  ],
  "findings": [
    {"id": 1, "bssid": "a4:2b:8c:11:22:34", "essid": "ACME-CORP", "tier": "evidence",
     "label": "beacons a scoped name with a fingerprint unlike its peers",
     "rationale": "Same ESSID as the estate, but the vendor OUI and IE ordering differ.",
     "differences": ["vendor OUI", "beacon interval 102 vs 100 TU"], "score": 0.34},
    {"id": 2, "bssid": "de:ad:be:ef:00:01", "tier": "determined",
     "label": "answered a probe for a network that does not exist"}
  ],
  "unclassified": ["de:ad:be:ef:00:01"],
  "hashes": {
    "pmkid": 1, "handshake": 1, "out_of_scope": 1, "pending_essid": 0,
    "files": ["/opt/eng/acme/pmkid.22000", "/opt/eng/acme/handshakes.22000"],
    "out_of_scope_files": ["/opt/eng/acme/out-of-scope-pmkid.22000",
                           "/opt/eng/acme/out-of-scope-handshakes.22000"],
    "hashes": [
      {"kind": "pmkid", "essid": "ACME-CORP", "bssid": "a4:2b:8c:11:22:33", "channel": 6,
       "in_scope": true,
       "line": "WPA*01*deadbeefcafe*a42b8c112233*3c22fbaabbcc*41434d452d434f5250***",
       "at": "2026-09-04T10:20:00Z"},
      {"kind": "handshake", "essid": "ACME-CORP", "bssid": "a4:2b:8c:11:22:33",
       "station": "3c:22:fb:aa:bb:cc", "channel": 6, "in_scope": true,
       "line": "WPA*02*0011223344556677*a42b8c112233*3c22fbaabbcc*41434d452d434f5250*0102*00",
       "at": "2026-09-04T10:25:00Z"},
      {"kind": "handshake", "essid": "NEIGHBOUR-NET", "bssid": "b0:0b:1e:00:00:01",
       "station": "aa:bb:cc:dd:ee:ff", "channel": 11, "in_scope": false,
       "line": "WPA*02*ffeeddccbbaa9988*b00b1e000001*aabbccddeeff*4e454947484230*0102*00",
       "at": "2026-09-04T10:28:00Z"}
    ],
    "wps_keys": [
      {"bssid": "9c:ef:d5:fd:0f:42", "essid": "WPS-TEST", "pin": "22008992",
       "psk": "hunter2pass", "generator": "zero nonces", "at": "2026-09-04T10:30:00Z"}
    ]
  },
  "eap": {
    "running": true,
    "session": {"essid": "ACME-CORP", "channel": 6, "ifname": "wlan1",
                "certificate_source": "mimicked from a harvested certificate",
                "certificate_fingerprint": "aa:bb:cc"},
    "stats": {"requests": 4, "challenges": 3, "captured": 1, "certificate_refused": 2},
    "captured": [{"inner_identity": "acme\\\\jsmith", "outer_identity": "anonymous",
                  "method": "MSCHAPv2", "hash_line": "jsmith::::aabb::ccdd"}],
    "creds_file": "/opt/eng/acme/creds/mschapv2.5500"
  },
  "radios": [
    {"id": "phy0", "ifname": "wlan0", "driver": "mt76x2u", "mac": "00:c0:ca:11:22:33",
     "bands": ["2.4 GHz", "5 GHz"], "injection": "verified", "usable_channels": 37,
     "ap_monitor_concurrent": false,
     "supported_iftypes": ["station", "monitor"],
     "roles": [{"role": "recon", "capable": true},
               {"role": "rogue", "capable": false, "reason": "no AP mode on this adapter"}]},
    {"id": "phy1", "ifname": "wlan1", "driver": "ath9k_htc", "mac": "00:c0:ca:44:55:66",
     "bands": ["2.4 GHz"], "injection": "inconclusive", "usable_channels": 13,
     "ap_monitor_concurrent": true,
     "supported_iftypes": ["station", "monitor", "AP"],
     "roles": [{"role": "survey", "capable": true}, {"role": "rogue", "capable": true}]}
  ],
  "assignments": [
    {"role": "recon", "radio_id": "phy0", "ifname": "wlan0", "iftype": "monitor"},
    {"role": "survey", "radio_id": "phy1", "ifname": "wlan1", "iftype": "monitor"}
  ],
  "jobs": [
    {"id": "3", "kind": "solicit", "target": "a4:2b:8c:11:22:33", "state": "running",
     "started": "2026-09-04T10:36:20Z"},
    {"id": "2", "kind": "deauth", "target": "3c:22:fb:aa:bb:cc", "state": "denied",
     "started": "2026-09-04T10:31:00Z",
     "error": "802.11w is required at this BSSID; the frame was not transmitted"}
  ]
}`

// newJSRuntime loads the shim and the real app.js, then installs the fixture.
func newJSRuntime(t *testing.T, data string) *goja.Runtime {
	t.Helper()

	vm := goja.New()

	// The shim builds its document from the ids in the real index.html, so adding an element
	// to the markup makes it available here without touching the shim.
	index, err := assets.ReadFile("assets/index.html")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range regexp.MustCompile(`id="([A-Za-z0-9_-]+)"`).
		FindAllStringSubmatch(string(index), -1) {
		ids = append(ids, m[1])
	}
	if len(ids) < 8 {
		t.Fatalf("index.html defines only %d ids; the extraction is broken", len(ids))
	}
	if err := vm.Set("__shellIds", ids); err != nil {
		t.Fatal(err)
	}

	shim, err := os.ReadFile("testdata/domshim.js")
	if err != nil {
		t.Fatalf("read the DOM shim: %v", err)
	}
	if _, err := vm.RunString(string(shim)); err != nil {
		t.Fatalf("the DOM shim itself failed: %v", err)
	}

	app, err := assets.ReadFile("assets/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vm.RunString(string(app)); err != nil {
		t.Fatalf("app.js threw while loading, so the page would be blank:\n%v", err)
	}

	if _, err := vm.RunString(`S.data = ` + data + `;`); err != nil {
		t.Fatalf("install fixture: %v", err)
	}
	return vm
}

func jsRun(t *testing.T, vm *goja.Runtime, src string) goja.Value {
	t.Helper()
	v, err := vm.RunString(src)
	if err != nil {
		t.Fatalf("%s\n  threw: %v", strings.TrimSpace(src), err)
	}
	return v
}

// TestEveryTabRendersWithRealData is the headline: each tab draws without throwing, and the
// content that reaches the screen is the content the operator needs.
func TestEveryTabRendersWithRealData(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	cases := []struct {
		tab  string
		want []string
	}{
		{"overview", []string{"3rd floor east", "evil-twin EAP harvest",
			"needs a second adapter", "Start walkthrough", "Classify"}},
		{"aps", []string{"a4:2b:8c:11:22:33", "ACME-CORP", "<hidden>", "in scope", "vetoed"}},
		{"stations", []string{"3c:22:fb:aa:bb:cc", "Starbucks WiFi", "randomised MAC"}},
		{"findings", []string{"evidence", "determined", "fingerprint unlike its peers",
			"Unclassified"}},
		{"jobs", []string{"solicit", "denied", "802.11w is required"}},
		{"hashes", []string{"PMKID", "HANDSHAKE", "WPA*01*", "3c:22:fb:aa:bb:cc",
			"pmkid.22000", "does not crack", "incidental", "NEIGHBOUR-NET",
			"out-of-scope-pmkid.22000",
			// The enterprise half of the same tab.
			"Enterprise credentials", "MSCHAPv2", "jsmith"}},
		{"log", nil},
	}

	for _, c := range cases {
		t.Run(c.tab, func(t *testing.T) {
			jsRun(t, vm, `__render('`+c.tab+`')`)
			pane := jsRun(t, vm, `__text('pane')`).String()
			for _, w := range c.want {
				if !strings.Contains(pane, w) {
					t.Errorf("the %s tab does not show %q\n---\n%s", c.tab, w, pane)
				}
			}
		})
	}
}

// TestHeaderShowsWhatIsBlockingWork. A generic ESSID with no acknowledgment silently excludes
// a network from active work; if that is not on screen the operator spends an hour wondering
// why nothing happens at that name.
func TestHeaderShowsWhatIsBlockingWork(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('overview')`)

	banner := jsRun(t, vm, `__text('banner')`).String()
	for _, want := range []string{"guest", "unacknowledged", "evil-twin EAP harvest"} {
		if !strings.Contains(banner, want) {
			t.Errorf("the banner does not mention %q:\n%s", want, banner)
		}
	}

	pill := jsRun(t, vm, `__text('reconPill')`).String()
	if pill != "CAPTURING" {
		t.Errorf("the status pill reads %q while capture is running", pill)
	}

	stats := jsRun(t, vm, `__text('stats')`).String()
	for _, want := range []string{"pmkid", "handshakes", "findings", "wps", "evil twin"} {
		if !strings.Contains(stats, want) {
			t.Errorf("the header does not carry %q:\n%s", want, stats)
		}
	}
	// "EAPOL" is hashcat's name for the same thing and is correct, but it also names the
	// transport WPA-Enterprise carries EAP over. Operators read it as enterprise capture and
	// conclude the file is worthless, so nothing user-facing says it.
	if strings.Contains(strings.ToLower(stats), "eapol") {
		t.Error("the header still says EAPOL, which reads as enterprise EAP capture")
	}
}

// TestOutOfScopeAccessPointsOfferNoTransmittingWork. This is the scope gate expressed in the
// interface: a button that is refused server-side should not be presented as available.
func TestOutOfScopeAccessPointsOfferNoTransmittingWork(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `S.tab = 'aps'; S.sel.aps = 'de:ad:be:ef:00:01'; render();`)
	side := jsRun(t, vm, `__text('side')`).String()

	for _, forbidden := range []string{"Solicit PMKID", "deauth", "Exclude"} {
		if strings.Contains(side, forbidden) {
			t.Errorf("an out-of-scope AP offers %q:\n%s", forbidden, side)
		}
	}
	if !strings.Contains(side, "Out of scope") {
		t.Errorf("the detail panel does not say why there are no actions:\n%s", side)
	}
}

// TestHuntingIsOfferedOutOfScope.
//
// Hunting only listens — it locks a radio to a channel and reads signal strength — so it is
// not gated on scope anywhere in the daemon. Walking down an unaccounted-for transmitter in
// the client's footprint is the whole point of rogue hunting, and it is exactly the device
// that will never be in scope.
func TestHuntingIsOfferedOutOfScope(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `
	  globalThis.__calls = [];
	  api = function (path, opts) { __calls.push({path, opts}); return Promise.resolve({}); };
	  S.tab = 'aps'; S.sel.aps = 'de:ad:be:ef:00:01'; render();
	`)

	side := jsRun(t, vm, `__text('side')`).String()
	if !strings.Contains(side, "Hunt") {
		t.Fatalf("an out-of-scope AP offers no way to hunt it:\n%s", side)
	}

	jsRun(t, vm, `
	  document.querySelector('#side')
	    .find(n => n.tagName === 'BUTTON' && n.textContent === 'Hunt')
	    .fire('click');
	`)
	got := jsRun(t, vm, `JSON.stringify(__calls[0])`).String()
	if !strings.Contains(got, "/api/hunt/start") || !strings.Contains(got, "de:ad:be:ef:00:01") {
		t.Errorf("the hunt button did not start a hunt on the selected AP: %s", got)
	}
}

// TestDecloakedNetworksAreMarked. The client believes a cloaked network is not advertising
// itself; if WARP knows its name, saying so quietly in the listing is the point.
func TestDecloakedNetworksAreMarked(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('aps')`)

	marked := jsRun(t, vm, `
	  (function () {
	    const row = document.querySelector('#pane').findAll(n => n.tagName === 'TR')
	      .find(r => r.textContent.indexOf('ACME-BACKOFFICE') >= 0);
	    if (!row) return 'no row';
	    const mark = row.find(n => (n.className || '').indexOf('hidden-tag') >= 0);
	    return mark ? mark.getAttribute('title') : 'unmarked';
	  })()
	`).String()

	if !strings.Contains(marked, "probe-response") {
		t.Errorf("a decloaked network is not marked with how its name was learned: %q", marked)
	}

	// And a network that was never cloaked must not carry the mark, or it means nothing.
	plain := jsRun(t, vm, `
	  (function () {
	    const row = document.querySelector('#pane').findAll(n => n.tagName === 'TR')
	      .find(r => r.textContent.indexOf('a4:2b:8c:11:22:33') >= 0);
	    return row.find(n => (n.className || '').indexOf('hidden-tag') >= 0) ? 'marked' : 'clean';
	  })()
	`).String()
	if plain != "clean" {
		t.Error("an ordinary network was marked as decloaked")
	}
}

// TestProtectedManagementFramesReadAsWordsNotDashes. "off" is a finding; an em dash reads as
// "not applicable" and tells the operator nothing.
func TestProtectedManagementFramesReadAsWordsNotDashes(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('aps')`)
	pane := jsRun(t, vm, `__text('pane')`).String()

	if !strings.Contains(pane, "PMF") {
		t.Error("the access point listing has no PMF column")
	}
	for _, want := range []string{"off", "req"} {
		if !strings.Contains(pane, want) {
			t.Errorf("the PMF column never shows %q:\n%s", want, pane)
		}
	}
}

// TestSiteWideScopeIsImpossibleToMiss. A scope covering every network at a site is the widest
// authorization WARP has, and it must never be in force without saying so on screen.
func TestSiteWideScopeIsImpossibleToMiss(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `__render('overview')`)
	if got := jsRun(t, vm, `__text('sitewide')`).String(); got != "" {
		t.Errorf("an ordinary engagement shows a site-wide banner: %q", got)
	}

	jsRun(t, vm, `
	  S.data.status.site_wide_scope = true;
	  S.data.status.site_wide_justification = 'SoW 2026-114 §3, all wireless at the Reno DC';
	  render();
	`)
	banner := jsRun(t, vm, `__text('sitewide')`).String()
	if !strings.Contains(banner, "SITE-WIDE") {
		t.Errorf("a site-wide scope is not announced: %q", banner)
	}
	if !strings.Contains(banner, "SoW 2026-114") {
		t.Errorf("the banner does not quote the recorded justification: %q", banner)
	}
}

// TestProtectedManagementFramesAreExplained. Deauthentication against an 802.11w network
// does not work, and 802.11w-required is a hardening control (not an exposure) - so the panel
// explains it rather than offering a button that quietly does nothing.
func TestProtectedManagementFramesAreExplained(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `S.tab = 'aps'; S.sel.aps = 'a4:2b:8c:11:22:34'; render();`)
	side := jsRun(t, vm, `__text('side')`).String()

	if !strings.Contains(side, "802.11w") {
		t.Errorf("MFP is not explained on an mfp=required AP:\n%s", side)
	}
	if !strings.Contains(side, "Solicit PMKID") {
		t.Error("PMKID solicitation should still be offered: it does not depend on deauthentication")
	}
}

// TestInScopeAccessPointOffersPerClientDeauth: which client is knocked off is the operator's
// call, and the audit log will name it, so the interface must not pick one silently.
func TestInScopeAccessPointOffersPerClientDeauth(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `S.tab = 'aps'; S.sel.aps = 'a4:2b:8c:11:22:33'; render();`)
	side := jsRun(t, vm, `__text('side')`).String()

	for _, want := range []string{"Solicit PMKID", "Hunt", "3c:22:fb:aa:bb:cc", "deauth", "Exclude"} {
		if !strings.Contains(side, want) {
			t.Errorf("the detail panel is missing %q:\n%s", want, side)
		}
	}
}

// TestEvidenceIsLabelledAsEvidence. An unusual but legitimate AP produces the same signal as
// a rogue one. Presenting evidence as proof is how someone ends up unplugging a switch that
// belonged to the client.
func TestEvidenceIsLabelledAsEvidence(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `S.tab = 'findings'; S.sel.findings = 'a4:2b:8c:11:22:34|beacons a scoped name with a fingerprint unlike its peers'; render();`)
	side := jsRun(t, vm, `__text('side')`).String()

	for _, want := range []string{"EVIDENCE", "not proof", "Verify physically", "vendor OUI"} {
		if !strings.Contains(side, want) {
			t.Errorf("the finding panel is missing %q:\n%s", want, side)
		}
	}
}

// TestALiveHuntIsShownWhereverTheOperatorIs.
//
// Direction finding is done while walking, watching one number go up. If that number is on a
// tab the operator has to navigate to, the tool is not helping with the thing they are
// actually doing — so a live hunt takes a band across the top of every tab.
func TestALiveHuntIsShownWhereverTheOperatorIs(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `__render('aps')`)
	if got := jsRun(t, vm, `__text('hunts')`).String(); got != "" {
		t.Errorf("a hunt band appeared with no hunt running: %q", got)
	}

	jsRun(t, vm, `
	  S.data.hunts = [{
	    target: {addr: 'de:ad:be:ef:00:01', essid: '', channel: 1},
	    current_rssi: -61, has_signal: true, peak_rssi: -47, has_peak: true,
	    packets_per_sec: 12.4, stale: false,
	  }];
	  render();
	`)

	band := jsRun(t, vm, `__text('hunts')`).String()
	for _, want := range []string{"HUNTING", "de:ad:be:ef:00:01", "-61", "peak -47", "stop"} {
		if !strings.Contains(band, want) {
			t.Errorf("the hunt readout is missing %q:\n%s", want, band)
		}
	}

	// A target that has gone quiet has to say so rather than showing a stale number as if it
	// were live — walking towards a signal that is no longer there wastes the walk.
	jsRun(t, vm, `S.data.hunts[0].has_signal = false; render();`)
	if got := jsRun(t, vm, `__text('hunts')`).String(); !strings.Contains(got, "no frames yet") {
		t.Errorf("a silent target does not say so: %q", got)
	}
}

// TestAHandlerReturningSomethingOddDoesNotBlankThePage. A frontend that assumes every
// response is a list takes the whole interface down when one is not, and the operator sees a
// blank screen with nothing naming the call that failed.
func TestAHandlerReturningSomethingOddDoesNotBlankThePage(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  api = function () { return Promise.resolve({ok: true}); };
	  refresh();
	`)

	for _, tab := range []string{"overview", "aps", "stations", "hashes", "findings", "jobs"} {
		jsRun(t, vm, `__render('`+tab+`')`)
		if got := jsRun(t, vm, `__text('pane')`).String(); got == "" {
			t.Errorf("the %s tab rendered nothing after an unexpected response", tab)
		}
	}
}

// TestTheBuildCreditIsShown. Present but not loud: it sits beside live engagement data, so it
// must be findable without competing with the numbers an operator is actually reading.
func TestTheBuildCreditIsShown(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('overview')`)

	credit := jsRun(t, vm, `__text('credit')`).String()
	if !strings.Contains(credit, "@waffl3ss") {
		t.Errorf("the header carries no attribution: %q", credit)
	}
	if !strings.Contains(credit, "v0.5.0") {
		t.Errorf("the header does not say which version is running: %q", credit)
	}
	// The commit traces a finding back to the code that produced it, but nobody reads it while
	// working — it belongs in the tooltip, not the line.
	title := jsRun(t, vm, `document.querySelector('#credit').title`).String()
	if !strings.Contains(title, "a1b2c3d") {
		t.Errorf("the commit is not recoverable from the interface: %q", title)
	}
	if strings.Contains(credit, "a1b2c3d") {
		t.Error("the commit is on the header line, competing with live data")
	}
}

// TestImpersonationIsAnnouncedForAsLongAsItRuns.
//
// Beaconing someone's network name under WARP's control is the most consequential thing the
// tool does. It cannot be something the operator has to navigate to a tab to discover, and it
// cannot be possible to forget it is running.
func TestImpersonationIsAnnouncedForAsLongAsItRuns(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	// On every tab, not just one.
	for _, tab := range []string{"overview", "aps", "clients", "log"} {
		jsRun(t, vm, `__render('`+strings.Replace(tab, "clients", "stations", 1)+`')`)
		band := jsRun(t, vm, `__text('eap')`).String()
		if !strings.Contains(band, "IMPERSONATING") || !strings.Contains(band, "ACME-CORP") {
			t.Errorf("the %s tab does not announce the impersonation: %q", tab, band)
		}
	}

	band := jsRun(t, vm, `__text('eap')`).String()
	if !strings.Contains(band, "mimicked") {
		t.Errorf("the banner does not say which certificate is being presented: %q", band)
	}
	// A client refusing the certificate is correct behaviour, and must not read as a fault.
	if !strings.Contains(band, "refused the certificate") {
		t.Errorf("certificate refusals are not surfaced: %q", band)
	}
	// Naming it rather than a bare "stop": the banner is the one place this is always on
	// screen, and it is the control an operator reaches for in a hurry.
	if !strings.Contains(band, "Stop evil twin") {
		t.Errorf("the banner offers no clearly named way to stop it: %q", band)
	}

	// With no certificate refusals the optional span is dropped - and dropping it must not leave a
	// literal "null" in the banner (replaceChildren stringifies a null argument, unlike el()).
	jsRun(t, vm, `S.data.eap.stats.certificate_refused = 0; render();`)
	band = jsRun(t, vm, `__text('eap')`).String()
	if strings.Contains(band, "null") {
		t.Errorf("the banner shows a stray \"null\": %q", band)
	}
	if !strings.Contains(band, "captured") {
		t.Errorf("the banner lost the capture count: %q", band)
	}

	jsRun(t, vm, `S.data.eap = {running: false}; render();`)
	if got := jsRun(t, vm, `__text('eap')`).String(); got != "" {
		t.Errorf("the banner survived the capture stopping: %q", got)
	}
}

// TestEmptyStateSaysSoRatherThanShowingNothing.
func TestEmptyStateSaysSoRatherThanShowingNothing(t *testing.T) {
	vm := newJSRuntime(t, `{"status":null,"aps":[],"stations":[],"findings":[],"unclassified":[],"jobs":[]}`)

	for _, tab := range []string{"aps", "stations", "findings", "jobs"} {
		jsRun(t, vm, `__render('`+tab+`')`)
		pane := jsRun(t, vm, `__text('pane')`).String()
		if !strings.Contains(pane, "Nothing here yet") {
			t.Errorf("the empty %s tab renders %q", tab, pane)
		}
	}

	// The overview has no status at all yet; it must not throw on the way to saying so.
	jsRun(t, vm, `__render('overview')`)
	if got := jsRun(t, vm, `__text('pane')`).String(); !strings.Contains(got, "Loading") {
		t.Errorf("the overview with no status renders %q", got)
	}
}

// TestFilteringAndSortingActuallyWork — the two things an operator does constantly in a room
// with sixty access points in it.
func TestFilteringAndSortingActuallyWork(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `S.tab = 'aps'; S.filter.aps = 'GUEST'; render();`)
	pane := jsRun(t, vm, `__text('pane')`).String()
	if !strings.Contains(pane, "ACME-GUEST") {
		t.Errorf("filtering hid the row it should have kept:\n%s", pane)
	}
	if strings.Contains(pane, "de:ad:be:ef") {
		t.Errorf("filtering kept a row it should have hidden:\n%s", pane)
	}

	jsRun(t, vm, `S.filter.aps = 'no-such-network'; render();`)
	if got := jsRun(t, vm, `__text('pane')`).String(); !strings.Contains(got, "Nothing matches") {
		t.Errorf("an over-narrow filter renders %q", got)
	}

	// Sorting by signal must put the strongest first, not the alphabetically first.
	jsRun(t, vm, `S.filter.aps = ''; S.sort.aps = {key:'sig', dir:'asc'}; render();`)
	order := jsRun(t, vm, `
	  document.querySelector('#pane').findAll(n => n.tagName === 'TR')
	    .slice(1).map(r => r.children[0].textContent).join(',')
	`).String()
	if !strings.HasPrefix(order, "a4:2b:8c:11:22:33") {
		t.Errorf("sorting by signal put %s first; -48 dBm is the strongest", order)
	}

	// And a row with no signal at all sorts last rather than reading as very strong.
	if !strings.HasSuffix(order, "de:ad:be:ef:00:01") {
		t.Errorf("an AP with no RSSI did not sort last: %s", order)
	}
}

// TestScopedOnlyToggleFilters covers the checkbox that hides everything the engagement does
// not authorise work against.
func TestScopedOnlyToggleFilters(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `S.tab = 'aps'; S.scopedOnly = true; render();`)
	pane := jsRun(t, vm, `__text('pane')`).String()
	if strings.Contains(pane, "de:ad:be:ef") {
		t.Errorf("'in scope only' still shows an out-of-scope AP:\n%s", pane)
	}
	if !strings.Contains(pane, "ACME-CORP") {
		t.Errorf("'in scope only' hid a scoped AP:\n%s", pane)
	}
}

// TestClientsScopedOnlyToggleFilters covers the clients-tab filter: only clients associated to or
// probing for a scoped network when it is on.
func TestClientsScopedOnlyToggleFilters(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	// One in-scope client (on ACME-CORP), one not.
	jsRun(t, vm, `
	  S.data.stations = [
	    {mac:'3c:22:fb:aa:bb:cc', bssid:'a4:2b:8c:11:22:33', essid:'ACME-CORP', in_scope:true},
	    {mac:'8e:41:03:9f:2d:70', in_scope:false, randomised_mac:true}
	  ];
	  S.tab = 'stations'; S.stationsScopedOnly = true; render();`)
	pane := jsRun(t, vm, `__text('pane')`).String()
	if strings.Contains(pane, "8e:41:03:9f:2d:70") {
		t.Errorf("'in scope only' still shows an out-of-scope client:\n%s", pane)
	}
	if !strings.Contains(pane, "3c:22:fb:aa:bb:cc") {
		t.Errorf("'in scope only' hid a scoped client:\n%s", pane)
	}
}

// TestFindingsControlsAndScopeFilter: controls (passes) are shown apart from exposures, and the
// "in scope only" toggle narrows both the findings and the unclassified list to scoped networks.
func TestFindingsControlsAndScopeFilter(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `
	  S.data.aps = [
	    {bssid:'aa:aa:aa:aa:aa:01', essid:'ACME-CORP', in_scope:true, channel:6, band:'2.4GHz',
	     security:{class:'wpa2', ciphers:['CCMP-128'], akms:['PSK'], wps:true, wps_locked:false}}
	  ];
	  S.data.findings = [
	    {bssid:'aa:aa:aa:aa:aa:01', essid:'ACME-CORP', tier:'determined',
	     label:'WPS enabled and unlocked', rationale:'x', in_scope:true},
	    {bssid:'aa:aa:aa:aa:aa:02', essid:'NEIGHBOUR', tier:'determined',
	     label:'WEP encryption', rationale:'y', in_scope:false},
	    {bssid:'aa:aa:aa:aa:aa:03', essid:'ACME-CORP', tier:'control',
	     label:'WPS enabled and resistant to offline PIN recovery', rationale:'z', in_scope:true}
	  ];
	  S.tab = 'findings'; render();`)

	pane := jsRun(t, vm, `__text('pane')`).String()
	switch {
	case !strings.Contains(pane, "Controls"):
		t.Errorf("a control finding is not shown in its own section:\n%s", pane)
	case !strings.Contains(pane, "resistant to offline PIN recovery"):
		t.Errorf("the control finding label is missing:\n%s", pane)
	case !strings.Contains(pane, "WEP encryption"):
		t.Errorf("an exposure is missing before filtering:\n%s", pane)
	case !strings.Contains(pane, "Evidence"):
		t.Errorf("the collapsible Evidence block is missing from a finding:\n%s", pane)
	case !strings.Contains(pane, "Detailed Encryption Information"):
		t.Errorf("the Evidence block is missing the encryption detail:\n%s", pane)
	case !strings.Contains(pane, "Pairwise Cipher Suite List"):
		t.Errorf("the Evidence block is not in tshark packet-detail format:\n%s", pane)
	case !strings.Contains(pane, "AES (CCM)"):
		t.Errorf("the Evidence block did not render the cipher in tshark style:\n%s", pane)
	case !strings.Contains(pane, "Auth Key Management (AKM) type: PSK (2)"):
		t.Errorf("the Evidence block did not render the AKM in tshark style:\n%s", pane)
	case !strings.Contains(pane, "tshark -r"):
		t.Errorf("the Evidence block does not offer a manual pcap command:\n%s", pane)
	}

	// The finding groups render as collapsible <details> whose open state is driven from S.findOpen,
	// so a re-render (the background poll) does not collapse one the operator opened.
	tag := jsRun(t, vm, `
	  (document.querySelector('#pane').findAll(n => n.tagName === 'DETAILS')
	    .filter(d => (d.className||'').indexOf('finding-group') >= 0).length)`).String()
	if tag == "0" || tag == "" {
		t.Errorf("findings are not rendered as collapsible <details> (found %q)", tag)
	}

	// Turn on in-scope only: the out-of-scope WEP finding disappears; the scoped ones remain.
	jsRun(t, vm, `S.findingsScopedOnly = true; render();`)
	pane = jsRun(t, vm, `__text('pane')`).String()
	switch {
	case strings.Contains(pane, "WEP encryption"):
		t.Errorf("'in scope only' still shows an out-of-scope finding:\n%s", pane)
	case !strings.Contains(pane, "WPS enabled and unlocked"):
		t.Errorf("'in scope only' hid a scoped finding:\n%s", pane)
	case !strings.Contains(pane, "resistant to offline PIN recovery"):
		t.Errorf("'in scope only' hid a scoped control:\n%s", pane)
	}
}

// TestSelectingARowUpdatesTheDetailPanel drives the click handler rather than setting state,
// so the wiring between the table and the sidebar is covered too.
func TestSelectingARowUpdatesTheDetailPanel(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('aps')`)

	jsRun(t, vm, `
	  const rows = document.querySelector('#pane').findAll(n => n.tagName === 'TR').slice(1);
	  rows[0].fire('click');
	`)

	side := jsRun(t, vm, `__text('side')`).String()
	if !strings.Contains(side, "a4:2b:8c:11:22:33") {
		t.Errorf("clicking the first row did not select it:\n%s", side)
	}
	if jsRun(t, vm, `S.sel.aps`).String() != "a4:2b:8c:11:22:33" {
		t.Error("the click handler did not record the selection")
	}
}

// TestASelectionThatDisappearsDoesNotBreakTheView. APs come and go as the operator walks;
// the panel must say "select one", not throw.
func TestASelectionThatDisappearsDoesNotBreakTheView(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  S.tab = 'aps'; S.sel.aps = 'ff:ff:ff:ff:ff:ff';
	  S.sel.stations = 'ff:ff:ff:ff:ff:ff';
	  S.sel.findings = 'nope|nope';
	  S.sel.jobs = '999';
	`)

	for _, tab := range []string{"aps", "stations", "findings", "jobs"} {
		jsRun(t, vm, `__render('`+tab+`')`)
		if got := jsRun(t, vm, `__text('side')`).String(); !strings.Contains(got, "Select") {
			t.Errorf("a stale selection on %s renders %q", tab, got)
		}
	}
}

// TestActionButtonsPostToTheRightRoutes. The buttons are the whole point of a writable
// interface, so this drives them and checks where they went.
func TestActionButtonsPostToTheRightRoutes(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	// Replace the transport so nothing needs a server.
	jsRun(t, vm, `
	  globalThis.__calls = [];
	  api = function (path, opts) {
	    __calls.push({path: path, method: (opts && opts.method) || 'GET',
	                  body: (opts && opts.body) || null});
	    return Promise.resolve({ok: true});
	  };
	`)

	press := func(tab, label string) {
		t.Helper()
		jsRun(t, vm, `__render('`+tab+`')`)
		jsRun(t, vm, `
		  (function () {
		    const btn = document.querySelector('#pane')
		      .find(n => n.tagName === 'BUTTON' && n.textContent.indexOf(`+jsString(label)+`) >= 0);
		    if (!btn) throw new Error('no button labelled ' + `+jsString(label)+`);
		    btn.fire('click');
		  })();
		`)
	}

	// Capture start/stop lives in the top bar (rendered by render()'s header pass), not the pane.
	jsRun(t, vm, `
	  __render('overview');
	  (function () {
	    const btn = document.querySelector('#captureBtn');
	    if (!btn) throw new Error('no capture button in the top bar');
	    btn.fire('click');
	  })();
	`)
	press("overview", "Classify")
	press("overview", "Karma responder test")
	press("overview", "Export CSV")
	press("overview", "Write report")
	// The findings-tab classify button reads "Classify" on a clean slate (no findings in this
	// fixture) and "Re-classify" once findings exist; both drive /api/rogue/classify.
	press("findings", "Classify")

	var calls []struct {
		Path   string `json:"path"`
		Method string `json:"method"`
	}
	raw := jsRun(t, vm, `JSON.stringify(__calls)`).String()
	if err := json.Unmarshal([]byte(raw), &calls); err != nil {
		t.Fatalf("decode recorded calls: %v (%s)", err, raw)
	}

	want := map[string]bool{
		"/api/recon/stop": false, "/api/rogue/classify": false,
		"/api/rogue/karma-test": false, "/api/export/bundle": false, "/api/report": false,
	}
	for _, c := range calls {
		if _, ok := want[c.Path]; ok {
			want[c.Path] = true
		}
		rt, routed := routeTable[c.Path]
		if !routed {
			t.Errorf("a button called %s, which no route serves", c.Path)
			continue
		}
		// act() refreshes the listings after a successful action, so plain reads appear here
		// too; only the transmitting ones have to be POSTs.
		if rt.mutating && c.Method != "POST" {
			t.Errorf("%s was called with %s; it transmits or changes state", c.Path, c.Method)
		}
	}
	for p, hit := range want {
		if !hit {
			t.Errorf("no button reached %s", p)
		}
	}
}

// TestPerClientDeauthNamesTheClient: the request body has to carry the station, because that
// is what ends up in the audit log and in the report.
func TestPerClientDeauthNamesTheClient(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  globalThis.__calls = [];
	  api = function (path, opts) { __calls.push({path, opts}); return Promise.resolve({}); };
	  S.tab = 'aps'; S.sel.aps = 'a4:2b:8c:11:22:33'; render();
	  document.querySelector('#side')
	    .find(n => n.tagName === 'BUTTON' && n.textContent === 'deauth')
	    .fire('click', {stopPropagation() {}, preventDefault() {}});
	  // The deauth options modal is now open; confirm it (accepting the defaults).
	  document.querySelector('.modal-box')
	    .find(n => n.tagName === 'BUTTON' && n.textContent === 'Deauth')
	    .fire('click');
	`)

	body := jsRun(t, vm, `JSON.stringify(__calls[0])`).String()
	if !strings.Contains(body, "/api/psk/deauth") {
		t.Fatalf("the per-client deauth button went somewhere else: %s", body)
	}
	if !strings.Contains(body, "3c:22:fb:aa:bb:cc") {
		t.Errorf("the request does not name the client: %s", body)
	}
	if !strings.Contains(body, "a4:2b:8c:11:22:33") {
		t.Errorf("the request does not name the access point: %s", body)
	}
	// The options modal must pass the campaign size through, pre-filled with the defaults.
	if !strings.Contains(body, "\"count\":8") || !strings.Contains(body, "\"seconds\":20") {
		t.Errorf("the request does not carry the deauth count/duration: %s", body)
	}
}

// TestDeauthOptionsModalClampsDuration: an operator-entered duration over the 60s cap is clamped
// before the request goes out (the daemon caps it too, but the UI must not send an absurd value).
func TestDeauthOptionsModalClampsDuration(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  globalThis.__calls = [];
	  api = function (path, opts) { __calls.push({path, opts}); return Promise.resolve({}); };
	  S.tab = 'aps'; S.sel.aps = 'a4:2b:8c:11:22:33'; render();
	  document.querySelector('#side')
	    .find(n => n.tagName === 'BUTTON' && n.textContent === 'deauth')
	    .fire('click', {stopPropagation() {}, preventDefault() {}});
	  var box = document.querySelector('.modal-box');
	  var nums = box.findAll(n => n.tagName === 'INPUT');
	  nums[1].value = '999';  // duration, way over the cap
	  nums[0].value = '20';   // frames per burst
	  box.find(n => n.tagName === 'BUTTON' && n.textContent === 'Deauth').fire('click');
	`)
	body := jsRun(t, vm, `JSON.stringify(__calls[0])`).String()
	if !strings.Contains(body, "\"seconds\":60") {
		t.Errorf("duration was not clamped to the 60s cap: %s", body)
	}
	if !strings.Contains(body, "\"count\":20") {
		t.Errorf("frames-per-burst was not carried through: %s", body)
	}
}

// TestRefusalsReadAsRefusals, not as crashes. A scope denial is a correct outcome and the
// operator should not go debugging it.
func TestRefusalsReadAsRefusals(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  globalThis.__toasts = [];
	  toast = function (kind, title, msg) { __toasts.push([kind, title, msg]); };
	  api = function () {
	    const e = new Error('ESSID "NEIGHBOUR" is not in scope');
	    e.denied = true;
	    return Promise.reject(e);
	  };
	`)

	// act() awaits; goja drains the microtask queue when the job finishes, so the promise
	// settles before the next RunString observes __toasts.
	jsRun(t, vm, `act('t', '/api/psk/deauth', {}, 'sent')`)

	got := jsRun(t, vm, `JSON.stringify(__toasts)`).String()
	if !strings.Contains(got, "deny") {
		t.Errorf("a scope refusal was not shown as a refusal: %s", got)
	}
	if !strings.Contains(got, "not in scope") {
		t.Errorf("the reason for the refusal was lost: %s", got)
	}
}

// TestTheEventStreamAppendsToTheLog covers the SSE handler: events have to reach the log tab
// even when the operator is looking at another one.
func TestTheEventStreamAppendsToTheLog(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  S.tab = 'aps';
	  stream();
	  EventSource.last.onmessage({data: JSON.stringify(
	    {kind: 'pmkid', level: 'good', text: '[+] PMKID a4:2b:8c:11:22:33 ACME-CORP'})});
	  EventSource.last.onmessage({data: 'this is not json'});
	  __render('log');
	`)

	pane := jsRun(t, vm, `__text('pane')`).String()
	if !strings.Contains(pane, "PMKID a4:2b:8c:11:22:33") {
		t.Errorf("the event never reached the log:\n%s", pane)
	}
	if n := jsRun(t, vm, `S.log.length`).ToInteger(); n != 1 {
		t.Errorf("the log holds %d entries; a malformed frame should be dropped, not stored", n)
	}
}

// TestLoginFailureIsShownRatherThanSwallowed.
func TestLoginFailureIsShownRatherThanSwallowed(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  api = function () { return Promise.reject(new Error('invalid token')); };
	  document.querySelector('#token').value = 'wrong';
	  document.querySelector('#loginForm').fire('submit', {preventDefault() {}});
	`)

	if got := jsRun(t, vm, `__text('loginErr')`).String(); !strings.Contains(got, "invalid token") {
		t.Errorf("a rejected token produced no visible message: %q", got)
	}
}

// TestFilterFocusSurvivesARedraw. The page redraws under the operator's fingers every couple
// of seconds; losing the cursor after each keystroke would make the filter box unusable.
func TestFilterFocusSurvivesARedraw(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  __render('aps');
	  const input = document.querySelector('#pane')
	    .find(n => n.tagName === 'INPUT' && n.dataset.fkey === 'filter:aps');
	  if (!input) throw new Error('the filter box carries no focus key');
	  input.focus();
	  globalThis.__before = document.activeElement.dataset.fkey;
	  render();
	`)

	if got := jsRun(t, vm, `__before`).String(); got != "filter:aps" {
		t.Fatalf("focus key before the redraw was %q", got)
	}
	// The shim's querySelector only resolves ids, so focus restoration cannot be observed
	// here; what this pins is that the key exists and render() does not throw looking for it.
	if got := jsRun(t, vm, `document.activeElement.dataset.fkey`).String(); got != "filter:aps" {
		t.Errorf("focus was dropped by the redraw: %q", got)
	}
}

// TestRedrawIsSkippedWhenNothingChanged. Rebuilding the pane wipes any text the operator had
// selected, and a BSSID halfway through being copied is exactly what they select.
func TestRedrawIsSkippedWhenNothingChanged(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  globalThis.__renders = 0;
	  const real = render;
	  render = function () { __renders++; real(); };

	  const snapshot = JSON.parse(JSON.stringify(S.data));
	  api = function (path) {
	    switch (path) {
	      case '/api/status':   return Promise.resolve(snapshot.status);
	      case '/api/aps':      return Promise.resolve(snapshot.aps);
	      case '/api/stations': return Promise.resolve(snapshot.stations);
	      case '/api/findings': return Promise.resolve(
	        {findings: snapshot.findings, unclassified: snapshot.unclassified});
	      case '/api/jobs':     return Promise.resolve(snapshot.jobs);
	    }
	    return Promise.resolve(null);
	  };
	`)

	jsRun(t, vm, `refresh()`)
	first := jsRun(t, vm, `__renders`).ToInteger()
	if first != 1 {
		t.Fatalf("the first refresh rendered %d times, want 1", first)
	}

	jsRun(t, vm, `refresh()`)
	if got := jsRun(t, vm, `__renders`).ToInteger(); got != 1 {
		t.Errorf("an unchanged refresh redrew the page (%d renders)", got)
	}

	// And a real change still gets through.
	jsRun(t, vm, `snapshot.status.pmkid_hashes = 9; refresh()`)
	if got := jsRun(t, vm, `__renders`).ToInteger(); got != 2 {
		t.Errorf("a changed refresh did not redraw (%d renders)", got)
	}
}

// TestUptimeAloneDoesNotForceARedraw: uptime changes on every poll by definition, so it must
// not be what defeats the change check above.
func TestUptimeAloneDoesNotForceARedraw(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  globalThis.__renders = 0;
	  const real = render;
	  render = function () { __renders++; real(); };
	  const snapshot = JSON.parse(JSON.stringify(S.data));
	  let tick = 0;
	  api = function (path) {
	    switch (path) {
	      case '/api/status':
	        return Promise.resolve({...snapshot.status, uptime: (tick++) + 'm'});
	      case '/api/aps':      return Promise.resolve(snapshot.aps);
	      case '/api/stations': return Promise.resolve(snapshot.stations);
	      case '/api/findings': return Promise.resolve(
	        {findings: snapshot.findings, unclassified: snapshot.unclassified});
	      case '/api/jobs':     return Promise.resolve(snapshot.jobs);
	    }
	    return Promise.resolve(null);
	  };
	  refresh(); refresh(); refresh();
	`)

	if got := jsRun(t, vm, `__renders`).ToInteger(); got != 1 {
		t.Errorf("a ticking uptime redrew the page %d times", got)
	}
}

// jsString quotes a Go string as a JavaScript literal.
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestDiskUsageIsOnScreenAndTheBannerFiresAtNinety.
//
// A box that fills up stops capturing without an error, and nobody re-runs a capture they
// believe already happened. The figure has to be on the header at all times and the banner has
// to be unmissable at the threshold — with both halves the operator needs: how much room is
// left, and how much of it this engagement is responsible for.
func TestDiskUsageIsOnScreenAndTheBannerFiresAtNinety(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('overview')`)

	stats := jsRun(t, vm, `__text('stats')`).String()
	if !strings.Contains(stats, "40%") {
		t.Errorf("the disk percentage is not in the header stats: %q", stats)
	}
	if !strings.Contains(stats, "3.0 GB") {
		t.Errorf("what this engagement has written is not on screen: %q", stats)
	}
	if !strings.Contains(stats, "140 GB") {
		t.Errorf("the space remaining is not on screen: %q", stats)
	}

	// Nothing alarming at 40%.
	if banner := jsRun(t, vm, `__text('disk')`).String(); strings.TrimSpace(banner) != "" {
		t.Errorf("a healthy disk raised a banner: %q", banner)
	}

	// Now fill it.
	jsRun(t, vm, `
		S.data.status.disk = {
			path: '/opt/eng/acme',
			total_bytes: 250000000000, used_bytes: 231000000000,
			free_bytes: 19000000000, used_percent: 92.4,
			engagement_bytes: 3221225472, level: 'critical'
		};
		__render('overview');`)

	banner := jsRun(t, vm, `__text('disk')`).String()
	switch {
	case !strings.Contains(banner, "92.4%"):
		t.Errorf("the banner does not say how full it is: %q", banner)
	case !strings.Contains(banner, "17.7 GB"):
		t.Errorf("the banner does not say how much is left: %q", banner)
	case !strings.Contains(banner, "without an error"):
		t.Errorf("the banner does not say capture stops silently, which is the whole point: %q", banner)
	}
}

// TestDiskIsOmittedRatherThanShownAsZero.
//
// statfs can fail, and a daemon may predate the field. Rendering "0%" for "unknown" would read
// as an empty disk, which is precisely the wrong direction to be wrong in.
func TestDiskIsOmittedRatherThanShownAsZero(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `delete S.data.status.disk; __render('overview');`)

	stats := jsRun(t, vm, `__text('stats')`).String()
	if strings.Contains(stats, "disk") {
		t.Errorf("a missing disk figure was rendered anyway: %q", stats)
	}
	if banner := jsRun(t, vm, `__text('disk')`).String(); strings.TrimSpace(banner) != "" {
		t.Errorf("a missing disk figure raised a banner: %q", banner)
	}
}

// TestThePixieDustButtonIsOfferedOnlyWhereItCanWork.
//
// A button that is present on every row and refuses on nineteen of them teaches the operator
// to ignore it. WPS is offered where a WPS element was actually observed, and where the
// network is in scope — associating is transmission.
func TestThePixieDustButtonIsOfferedOnlyWhereItCanWork(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	// The fixture's first access point advertises WPS and is in scope.
	jsRun(t, vm, `S.tab = 'aps'; S.sel.aps = 'a4:2b:8c:11:22:33'; render();`)
	side := jsRun(t, vm, `__text('side')`).String()
	if !strings.Contains(side, "Pixie Dust") {
		t.Errorf("no Pixie Dust action on a scoped access point advertising WPS:\n%s", side)
	}
	if !strings.Contains(side, "Online PIN brute force is not offered") {
		t.Errorf("the pane does not say why online PIN recovery is absent:\n%s", side)
	}

	// A locked one still offers it, with the caveat: devices misreport this.
	jsRun(t, vm, `
	  S.data.aps[0].security.wps_locked = true;
	  S.tab = 'aps'; S.sel.aps = 'a4:2b:8c:11:22:33'; render();`)
	side = jsRun(t, vm, `__text('side')`).String()
	switch {
	case !strings.Contains(side, "locked"):
		t.Errorf("a locked access point does not say so:\n%s", side)
	case !strings.Contains(side, "pass"):
		t.Errorf("a locked access point is not described as a pass:\n%s", side)
	case !strings.Contains(side, "Pixie Dust"):
		t.Errorf("a locked access point offers no attempt at all:\n%s", side)
	}

	// An access point with no WPS element offers nothing.
	jsRun(t, vm, `S.tab = 'aps'; S.sel.aps = 'a4:2b:8c:11:22:34'; render();`)
	if side := jsRun(t, vm, `__text('side')`).String(); strings.Contains(side, "Pixie Dust") {
		t.Errorf("Pixie Dust offered on an access point with no WPS element:\n%s", side)
	}
}

// TestTheCertificateCloneButtonIsEnterpriseAndInScopeOnly.
func TestTheCertificateCloneButtonIsEnterpriseAndInScopeOnly(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `
	  S.data.aps[1].security.class = 'wpa_enterprise';
	  S.tab = 'aps'; S.sel.aps = 'a4:2b:8c:11:22:34'; render();`)
	side := jsRun(t, vm, `__text('side')`).String()
	if !strings.Contains(side, "Clone certificate") {
		t.Errorf("no clone action on a scoped enterprise network:\n%s", side)
	}
	if !strings.Contains(side, "own EAP-TLS client") {
		t.Errorf("the pane does not say the harvest runs its own EAP-TLS client:\n%s", side)
	}

	// Out of scope: explained, not offered. The harvest's deauth provoke is transmission.
	jsRun(t, vm, `
	  S.data.aps[1].in_scope = false;
	  S.tab = 'aps'; S.sel.aps = 'a4:2b:8c:11:22:34'; render();`)
	side = jsRun(t, vm, `__text('side')`).String()
	if strings.Contains(side, "Clone certificate") {
		t.Errorf("the clone action was offered out of scope:\n%s", side)
	}
	if !strings.Contains(side, "transmission") {
		t.Errorf("the refusal does not say why:\n%s", side)
	}

	// A PSK network has no RADIUS server and gets no enterprise section at all.
	jsRun(t, vm, `S.tab = 'aps'; S.sel.aps = 'b0:b1:b2:c3:c4:c5'; render();`)
	if side := jsRun(t, vm, `__text('side')`).String(); strings.Contains(side, "Clone certificate") {
		t.Errorf("the clone action was offered on a PSK network:\n%s", side)
	}
}

// TestDecloakIsOfferedWithoutAConfirmation.
//
// Invariant 1a: decloaking is not gated on an operator confirmation. A cloaked network has no name
// to match against scope, it may well be in scope, and there is no way to find out except by
// decloaking it — so the action is always available, in or out of scope, and `scope confirm` stays
// advisory (recorded as context, never a precondition). The pane must offer Decloak on a hidden
// network whether or not it has been confirmed. The one bar is 802.11w.
func TestDecloakIsOfferedWithoutAConfirmation(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	// The fixture's third access point has no ESSID and is not confirmed.
	jsRun(t, vm, `S.tab = 'aps'; S.sel.aps = 'de:ad:be:ef:00:01'; render();`)
	side := jsRun(t, vm, `__text('side')`).String()
	if !strings.Contains(side, "Decloak") {
		t.Errorf("decloak was not offered on an unconfirmed hidden network:\n%s", side)
	}
	// The confirmation is still reachable, but as an optional courtesy — not a gate.
	if !strings.Contains(side, "Confirm") {
		t.Errorf("the optional confirmation affordance is missing:\n%s", side)
	}

	// 802.11w is the one thing that removes it: protected clients ignore the deauthentication.
	jsRun(t, vm, `
	  S.data.aps[2].security = { class: 'wpa_enterprise', mfp: 'required' };
	  S.tab = 'aps'; S.sel.aps = 'de:ad:be:ef:00:01'; render();`)
	if side := jsRun(t, vm, `__text('side')`).String(); strings.Contains(side, "Decloak") {
		t.Errorf("decloak was offered on a network that requires 802.11w:\n%s", side)
	}
}

// TestTheRadiosTabExplainsWhatEachAdapterCanDo.
//
// The header shows what each card is doing; nothing said what it *can* do. On a kit where one
// adapter is 2.4-only, "the 5 GHz half of the estate is missing" and "that card cannot see it"
// are the same fact, and neither was on screen.
func TestTheRadiosTabExplainsWhatEachAdapterCanDo(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('radios')`)

	pane := jsRun(t, vm, `__text('pane')`).String()
	for _, want := range []string{
		"wlan0", "wlan1", // the interface name is the identity shown; the phy index is not
		"mt76x2u",        // driver
		"verified",       // injection demonstrated
		"inconclusive",   // and the state that is not a failure
		"no AP mode",     // why a role is unavailable
		"SURVEY",         // the adapter that is never lent
		"sweep channels", // the channel-management control
	} {
		if !strings.Contains(pane, want) {
			t.Errorf("the radios tab does not mention %q:\n%s", want, pane)
		}
	}

	// Empty state must say something rather than drawing nothing.
	jsRun(t, vm, `S.data.radios = []; __render('radios');`)
	if got := jsRun(t, vm, `__text('pane')`).String(); !strings.Contains(got, "No adapters") {
		t.Errorf("the empty radios tab renders %q", got)
	}
}

// TestTheEvilTwinTabShowsTheCertificateAndTheCredentials.
func TestTheEvilTwinTabShowsTheCertificateAndTheCredentials(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('eviltwin')`)

	pane := jsRun(t, vm, `__text('pane')`).String()
	switch {
	case !strings.Contains(pane, "IMPERSONATING ACME-CORP"):
		t.Errorf("the tab does not say what is being impersonated:\n%s", pane)
	case !strings.Contains(pane, "mimicked"):
		t.Errorf("the tab does not say which certificate is presented:\n%s", pane)
	case !strings.Contains(pane, "Stop evil twin"):
		t.Errorf("the tab offers no way to stop it:\n%s", pane)
	case !strings.Contains(pane, "jsmith"):
		t.Errorf("captured credentials are not shown:\n%s", pane)
	case !strings.Contains(pane, "correct"):
		t.Errorf("a certificate refusal is not described as correct client behaviour:\n%s", pane)
	}

	// Not running: it must offer a way to start, from the networks it can see.
	jsRun(t, vm, `
	  S.data.eap = {running: false};
	  S.data.aps[1].security.class = 'wpa_enterprise';
	  __render('eviltwin');`)
	pane = jsRun(t, vm, `__text('pane')`).String()
	if !strings.Contains(pane, "Clone certificate") || !strings.Contains(pane, "Start evil twin") {
		t.Errorf("the idle tab offers no way to begin:\n%s", pane)
	}
	if !strings.Contains(pane, "self-signed") {
		t.Errorf("the idle tab does not explain why cloning comes first:\n%s", pane)
	}
}

// TestTheCertificateLibraryIsManageableFromTheBrowser.
//
// The certificate is the pretext, and until it was a library the operator managed it was
// whatever the code happened to have: a mimic if a harvest had run, self-signed otherwise,
// decided at the moment the rogue started and invisible until afterwards.
func TestTheCertificateLibraryIsManageableFromTheBrowser(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('eviltwin')`)

	pane := jsRun(t, vm, `__text('pane')`).String()
	for _, want := range []string{
		"Certificate library",
		"ACME-CORP",
		"mimic",
		"self-signed",
		"CN=radius.acme.example", // the mimic's subject, mark and all
		"Generate a certificate", // the wizard
		"warp eap cert import",   // and how to bring one in from outside
	} {
		if !strings.Contains(pane, want) {
			t.Errorf("the library does not show %q:\n%s", want, pane)
		}
	}

	// A network with nothing prepared has to say what would happen instead, because that is
	// the answer to "why did the rogue present a self-signed certificate".
	if !strings.Contains(pane, "Nothing prepared") {
		t.Errorf("an empty network says nothing about it:\n%s", pane)
	}

	// The wizard's required field must be labelled as required.
	if !strings.Contains(pane, "Common name *") {
		t.Errorf("the wizard does not mark the common name as required:\n%s", pane)
	}
}

// TestTheCertificateWizardRefusesAnEmptyCommonName.
//
// It is what a trust prompt shows. A certificate without a plausible one is refused before
// anyone reads the rest of it, so generating one would be wasted work.
func TestTheCertificateWizardRefusesAnEmptyCommonName(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('eviltwin')`)

	// Open the wizard's Generate without filling anything in.
	jsRun(t, vm, `
		__posted = null;
		__click('Generate');`)

	if got := jsRun(t, vm, `__posted`); !goja.IsNull(got) && !goja.IsUndefined(got) {
		t.Errorf("a certificate with no common name was requested: %v", got)
	}
	// The refusal is now a styled modal, not a browser alert: its message lands in the DOM.
	if got := jsRun(t, vm, `(document.querySelector('.modal-msg') || {}).textContent || ''`).String(); !strings.Contains(got, "common name") {
		t.Errorf("the operator was not told why: %q", got)
	}
}

// TestTheRadiosTabCanPinAndUnpin.
//
// The channel plan sweeps, which is right for finding things and wrong for watching one. An
// operator who knows the target's channel had no way to park a card there — every hold in the
// tool was a side effect of running an attack and ended when the attack did.
func TestTheRadiosTabCanPinAndUnpin(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('radios')`)

	pane := jsRun(t, vm, `__text('pane')`).String()
	if !strings.Contains(pane, "Pin to channel") {
		t.Errorf("no way to pin an adapter:\n%s", pane)
	}

	// A pinned adapter says so, and offers the opposite.
	jsRun(t, vm, `
	  S.data.radios[0].pinned_channel = 36;
	  S.data.status.recon.radios[0].channel = 36;
	  __render('radios');`)
	pane = jsRun(t, vm, `__text('pane')`).String()
	switch {
	case !strings.Contains(pane, "Unpin from ch36"):
		t.Errorf("a pinned adapter offers no way back:\n%s", pane)
	case !strings.Contains(pane, "pinned by you, not sweeping"):
		t.Errorf("the pane does not say why it stopped sweeping:\n%s", pane)
	}
}

// TestTheClientPaneCanDeauthenticate.
//
// The browser could deauthenticate an entire access point but not one client, which is
// backwards: the targeted form is the more precise of the two and it was console-only.
func TestTheClientPaneCanDeauthenticate(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	// The fixture's first client is associated and in scope.
	jsRun(t, vm, `
	  S.data.stations[0].in_scope = true;
	  S.data.stations[0].essid = 'ACME-CORP';
	  S.tab = 'stations'; S.sel.stations = '3c:22:fb:aa:bb:cc'; render();`)
	side := jsRun(t, vm, `__text('side')`).String()
	if !strings.Contains(side, "Deauthenticate this client") {
		t.Errorf("no targeted deauthentication on the client pane:\n%s", side)
	}

	// 802.11w means it would be ignored — explained, not offered.
	jsRun(t, vm, `S.data.stations[0].mfp = 'required'; render();`)
	side = jsRun(t, vm, `__text('side')`).String()
	switch {
	case strings.Contains(side, "Deauthenticate this client"):
		t.Errorf("deauthentication offered where 802.11w is required:\n%s", side)
	case !strings.Contains(side, "802.11w"):
		t.Errorf("the pane does not say why:\n%s", side)
	}

	// An unassociated client has nothing to be deauthenticated from.
	jsRun(t, vm, `S.sel.stations = '8e:41:03:9f:2d:70'; render();`)
	side = jsRun(t, vm, `__text('side')`).String()
	if !strings.Contains(side, "Not associated") {
		t.Errorf("an unassociated client is not explained:\n%s", side)
	}
}

// TestWPSKeysAppearInCredentials proves a recovered WPS passphrase reaches the credentials tab —
// the recurring "it's in the job log but not the tab" report.
func TestWPSKeysAppearInCredentials(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `__render('hashes')`)
	pane := jsRun(t, vm, `__text('pane')`).String()
	if !strings.Contains(pane, "hunter2pass") {
		t.Errorf("the recovered WPS passphrase is not on the credentials tab:\n%s", pane)
	}
	if !strings.Contains(pane, "WPS-TEST") {
		t.Errorf("the WPS network name is not on the credentials tab")
	}
}

// TestWPSKeysSurviveEmptyHashList reproduces the bug where a WPS key recovered with no PMKID or
// handshake alongside it vanished from the web credentials tab: an empty PSK list serialises to
// JSON null, and the old refresh guard replaced the whole hashes object (dropping wps_keys) when
// .hashes was not an array. The credentials pane must still show the key.
func TestWPSKeysSurviveEmptyHashList(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	// Simulate the /api/hashes response the daemon returns with a WPS key but no PSK hashes:
	// hashes is null (a nil Go slice), wps_keys is present. Run the exact refresh normalisation.
	jsRun(t, vm, `
	  var resp = { hashes: null, wps_keys: [
	    { bssid: "9c:ef:d5:fd:0f:42", essid: "WPS-TEST", pin: "22008992", psk: "leaktest99",
	      generator: "zero nonces", at: "2026-09-04T10:30:00Z" } ] };
	  S.data.hashes = (resp && typeof resp === 'object')
	    ? Object.assign({}, resp, { hashes: Array.isArray(resp.hashes) ? resp.hashes : [] })
	    : { hashes: [] };
	  S.data.eap = { captured: [] };
	  __render('hashes');
	`)
	pane := jsRun(t, vm, `__text('pane')`).String()
	if !strings.Contains(pane, "leaktest99") {
		t.Errorf("a WPS key with no PSK hashes alongside it was dropped from the credentials tab:\n%s", pane)
	}
}

// TestMarkRogueDeviceTogglesAndColours: the AP detail pane offers "Mark Rogue Device", flips to
// "Unmark" once marked, flags the name as a potential rogue, and the table row carries the tag.
func TestMarkRogueDeviceTogglesAndColours(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	jsRun(t, vm, `S.tab='aps'; S.sel.aps='a4:2b:8c:11:22:33'; render();`)
	side := jsRun(t, vm, `__text('side')`).String()
	if !strings.Contains(side, "Mark Rogue Device") {
		t.Errorf("unmarked AP detail is missing the Mark Rogue Device button:\n%s", side)
	}
	if strings.Contains(side, "Unmark Rogue Device") {
		t.Errorf("unmarked AP already shows Unmark:\n%s", side)
	}

	jsRun(t, vm, `S.data.aps.find(a=>a.bssid==='a4:2b:8c:11:22:33').rogue=true; render();`)
	side = jsRun(t, vm, `__text('side')`).String()
	for _, want := range []string{"Unmark Rogue Device", "marked potential rogue"} {
		if !strings.Contains(side, want) {
			t.Errorf("marked AP detail missing %q:\n%s", want, side)
		}
	}

	pane := jsRun(t, vm, `__text('pane')`).String()
	if !strings.Contains(pane, "rogue") {
		t.Errorf("marked AP row is missing the rogue tag:\n%s", pane)
	}
}

// TestPotentialRogueEvidenceShowsManualLineNotEncryption: the evidence block chosen for an
// operator-marked potential rogue is the "manual evidence required" text, never the beacon
// encryption dump - even though a beacon record for that BSSID exists.
func TestPotentialRogueEvidenceShowsManualLineNotEncryption(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `globalThis.__blk = evidenceBlock('Potentially Rogue Device',
	  {bssid: 'de:ad:be:ef:00:01', channel: 1, band: '2.4 GHz',
	   security: {class: 'wpa_psk', ciphers: ['CCMP-128'], akms: ['PSK'], mfp: 'required'}}, '');`)
	blk := jsRun(t, vm, `__blk`).String()

	if !strings.Contains(blk, "Manual evidence required") {
		t.Errorf("rogue evidence is missing the manual line:\n%s", blk)
	}
	for _, forbidden := range []string{"Cipher Suite", "Privacy:", "Management Frame Protection"} {
		if strings.Contains(blk, forbidden) {
			t.Errorf("rogue evidence leaked encryption detail %q:\n%s", forbidden, blk)
		}
	}

	ptr := jsRun(t, vm, `evidencePointer('Potentially Rogue Device', null, '')`).String()
	if !strings.Contains(ptr, "Manual evidence required") {
		t.Errorf("rogue evidence pointer should call for manual evidence: %q", ptr)
	}
}

// TestRadioResetButtonUSBAndIdleGated: the per-radio Reset button appears only for a USB adapter, is
// enabled when capture is stopped and no jobs run, and is disabled otherwise.
func TestRadioResetButtonUSBAndIdleGated(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)

	// Locate the first Reset button in the radios pane and report its state.
	state := `(function(){var b=document.querySelector('#pane').find(function(n){
	  return n.tagName==='BUTTON' && n.textContent.indexOf('Reset')!==-1;});
	  return b?(b.getAttribute('disabled')?'disabled':'enabled'):'none';})()`

	// USB adapter, idle -> enabled.
	jsRun(t, vm, `S.data.radios[0].usb = true;
	  S.data.status.recon.running = false; S.data.status.running_jobs = 0;
	  S.tab='radios'; render();`)
	if got := jsRun(t, vm, state).String(); got != "enabled" {
		t.Errorf("USB adapter idle: reset button = %q, want enabled", got)
	}

	// Capture running -> disabled.
	jsRun(t, vm, `S.data.status.recon.running = true; render();`)
	if got := jsRun(t, vm, state).String(); got != "disabled" {
		t.Errorf("capture running: reset button = %q, want disabled", got)
	}

	// A job running -> disabled.
	jsRun(t, vm, `S.data.status.recon.running = false; S.data.status.running_jobs = 2; render();`)
	if got := jsRun(t, vm, state).String(); got != "disabled" {
		t.Errorf("job running: reset button = %q, want disabled", got)
	}

	// Not a USB adapter -> no button at all.
	jsRun(t, vm, `S.data.radios[0].usb = false; S.data.radios[1].usb = false;
	  S.data.status.running_jobs = 0; render();`)
	if got := jsRun(t, vm, state).String(); got != "none" {
		t.Errorf("non-USB adapter: reset button = %q, want none", got)
	}
}

// TestHuntAudibleToggleIsOnTheBarMutedByDefault: the speaker toggle appears on the hunt bar, starts
// muted, flips on click, and the beep-interval mapping mirrors the daemon (strong -> 60ms, weak ->
// 1500ms). The cue is a per-viewer convenience; it transmits nothing.
func TestHuntAudibleToggleIsOnTheBarMutedByDefault(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  S.data.hunts = [{target: {addr: 'de:ad:be:ef:00:01', channel: 6, radio_id: 'phy0'},
	    has_signal: true, current_rssi: -55, peak_rssi: -50, has_peak: true,
	    sparkline: [-60, -55], packets_per_sec: 12}];
	  renderHunts();
	`)

	find := `document.querySelector('#hunts').find(n => n.tagName==='BUTTON' && (n.className||'').indexOf('hunt-mute')>=0)`
	cls := jsRun(t, vm, `(function(){var b=`+find+`;return b?b.className:'none';})()`).String()
	if !strings.Contains(cls, "hunt-mute") {
		t.Fatalf("no speaker toggle on the hunt bar: %q", cls)
	}
	if !strings.Contains(cls, "muted") {
		t.Errorf("the toggle should start muted: class=%q", cls)
	}
	if got := jsRun(t, vm, `String(S.huntMuted)`).String(); got != "true" {
		t.Errorf("huntMuted default = %q, want true", got)
	}

	jsRun(t, vm, find+`.fire('click');`)
	if got := jsRun(t, vm, `String(S.huntMuted)`).String(); got != "false" {
		t.Errorf("after clicking the toggle huntMuted = %q, want false", got)
	}

	strong := jsRun(t, vm, `String(Math.round(huntSound.intervalMs(-30)))`).String()
	weak := jsRun(t, vm, `String(Math.round(huntSound.intervalMs(-90)))`).String()
	if strong != "60" || weak != "1500" {
		t.Errorf("beep interval mapping wrong: strong(-30)=%s want 60, weak(-90)=%s want 1500", strong, weak)
	}
}

// TestEvilTwinCredentialTableShowsTypeAndCleartext: the Evil Twin captured table has a Type column
// (CLEARTEXT vs MSCHAPv2) and shows the actual credential value for both - a cleartext capture must
// not render as a blank "Hash line" the way it used to.
func TestEvilTwinCredentialTableShowsTypeAndCleartext(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `
	  S.data.eap.captured = [
	    {inner_identity: 'ttlstest', outer_identity: 'anonymous', method: 'EAP-TTLS',
	     cleartext: 'Winter2026!', essid: 'CORP-TTLS-TEST'},
	    {inner_identity: 'acme\\jsmith', outer_identity: 'anonymous', method: 'MSCHAPv2',
	     hash_line: 'jsmith::::aabb::ccdd'}
	  ];
	  S.data.eap.cleartext_file = 'creds/cleartext.txt';
	  S.tab = 'eviltwin'; render();`)
	pane := jsRun(t, vm, `__text('pane')`).String()

	for _, want := range []string{"CLEARTEXT", "Winter2026!", "MSCHAPv2", "creds/cleartext.txt"} {
		if !strings.Contains(pane, want) {
			t.Errorf("Evil Twin credential table missing %q:\n%s", want, pane)
		}
	}
	// The header should say "Type", not "Hash line".
	if strings.Contains(pane, "Hash line") {
		t.Errorf("the table still has the old 'Hash line' column header:\n%s", pane)
	}
}

// TestEvilTwinShowsCertificateRejections: a client that validated and refused the cert is surfaced on
// the Evil Twin page as a running count, so the operator can track it (not a finding, not a capture).
func TestEvilTwinShowsCertificateRejections(t *testing.T) {
	vm := newJSRuntime(t, jsFixture)
	jsRun(t, vm, `S.data.eap.stats = {requests: 8, challenges: 6, captured: 0, certificate_refused: 2};
	  S.tab = 'eviltwin'; render();`)
	pane := jsRun(t, vm, `__text('pane')`).String()

	if !strings.Contains(pane, "certificate rejection") {
		t.Errorf("Evil Twin page does not surface certificate rejections:\n%s", pane)
	}
	if !strings.Contains(pane, "correctly configured") {
		t.Errorf("the rejection note should frame it as a correctly-configured client:\n%s", pane)
	}
}
