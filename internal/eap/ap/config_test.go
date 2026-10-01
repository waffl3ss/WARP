package ap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenConfig is the expected hostapd configuration.
//
// A golden file rather than a set of Contains checks: a silently wrong or missing directive
// produces an access point that comes up, beacons correctly, and never forwards a single EAP
// message — which looks like a broken RADIUS server rather than a bad config.
const goldenPath = "testdata/hostapd.conf.golden"

func testConfig() Config {
	return Config{
		Interface:    "wlan1",
		ESSID:        "CORP-8021X",
		Channel:      6,
		RADIUSAddr:   "127.0.0.1",
		RADIUSPort:   1812,
		RADIUSSecret: "warp-test-secret",
		CountryCode:  "GB",
	}
}

func TestRenderConfigGolden(t *testing.T) {
	got, err := RenderConfig(testConfig())
	if err != nil {
		t.Fatalf("RenderConfig: %v", err)
	}

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("create testdata: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Log("golden file updated")
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden file: %v\nrun with UPDATE_GOLDEN=1 to create it", err)
	}
	if got != string(want) {
		t.Errorf("generated config differs from the golden file.\n--- got ---\n%s\n--- want ---\n%s",
			got, want)
	}
}

// TestRelayDirectivesArePresent asserts the three lines that make hostapd forward EAP rather
// than terminate it. Losing any one of them is the failure this whole architecture depends on
// not happening.
func TestRelayDirectivesArePresent(t *testing.T) {
	got, err := RenderConfig(testConfig())
	if err != nil {
		t.Fatalf("RenderConfig: %v", err)
	}

	required := []string{
		"ieee8021x=1",
		"wpa_key_mgmt=WPA-EAP",
		"auth_server_addr=127.0.0.1",
		"auth_server_port=1812",
		"auth_server_shared_secret=warp-test-secret",
	}
	for _, line := range required {
		if !strings.Contains(got, line) {
			t.Errorf("config is missing %q; without it hostapd will not relay EAP to WARP", line)
		}
	}

	// hostapd's own EAP server must not be configured: that would terminate the exchange
	// inside hostapd and WARP would never see a credential.
	for _, forbidden := range []string{"eap_server=1", "eap_user_file", "ca_cert", "server_cert"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("config contains %q, which would make hostapd terminate EAP itself", forbidden)
		}
	}
}

func TestHWModeFollowsChannel(t *testing.T) {
	cfg := testConfig()

	cfg.Channel = 6
	got, _ := RenderConfig(cfg)
	if !strings.Contains(got, "hw_mode=g") {
		t.Error("channel 6 should select hw_mode=g")
	}

	cfg.Channel = 36
	got, _ = RenderConfig(cfg)
	if !strings.Contains(got, "hw_mode=a") {
		t.Error("channel 36 should select hw_mode=a")
	}

	// An explicit override wins.
	cfg.HWMode = "g"
	got, _ = RenderConfig(cfg)
	if !strings.Contains(got, "hw_mode=g") {
		t.Error("explicit hw_mode was ignored")
	}
}

// TestConfigRejectsInjection: a newline in any value would let it introduce an unrelated
// hostapd directive.
func TestConfigRejectsInjection(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Config)
	}{
		{"essid with a newline", func(c *Config) { c.ESSID = "CORP\neap_server=1" }},
		{"interface with a newline", func(c *Config) { c.Interface = "wlan1\nbssid=00:11:22:33:44:55" }},
		{"secret with a newline", func(c *Config) { c.RADIUSSecret = "s\nauth_server_addr=evil" }},
		{"country with a newline", func(c *Config) { c.CountryCode = "GB\nssid=other" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.mut(&cfg)
			if _, err := RenderConfig(cfg); err == nil {
				t.Fatal("a value containing a newline was accepted")
			}
		})
	}
}

// TestConfigRejectsUnprintableSecret guards the bug where a raw-random 16-byte RADIUS secret was
// written straight into hostapd.conf: a null, space or control byte in it truncated or mangled
// the config line, so hostapd keyed a different secret than the server and every
// Message-Authenticator failed — the evil twin authenticated nobody. The daemon now hex-encodes
// the secret; this asserts the generator refuses anything that would recreate the failure.
func TestConfigRejectsUnprintableSecret(t *testing.T) {
	bad := []struct {
		name   string
		secret string
	}{
		{"null byte", "abc\x00def"},
		{"space", "abc def"},
		{"tab", "abc\tdef"},
		{"raw random with a newline byte", string([]byte{0x1f, 0x0a, 0x9c, 0x40})},
		{"high byte", "abc\xffdef"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.RADIUSSecret = tc.secret
			if _, err := RenderConfig(cfg); err == nil {
				t.Fatalf("an unprintable secret %q was accepted", tc.secret)
			}
		})
	}

	// A hex secret, which is what the daemon now generates, must pass.
	cfg := testConfig()
	cfg.RADIUSSecret = "9f8c1a2b3d4e5f60718293a4b5c6d7e8"
	if _, err := RenderConfig(cfg); err != nil {
		t.Fatalf("a hex secret was rejected: %v", err)
	}
}

func TestConfigRequiresEssentials(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Config)
	}{
		{"no interface", func(c *Config) { c.Interface = "" }},
		{"no essid", func(c *Config) { c.ESSID = "" }},
		{"no channel", func(c *Config) { c.Channel = 0 }},
		{"no radius secret", func(c *Config) { c.RADIUSSecret = "" }},
		{"oversized essid", func(c *Config) { c.ESSID = strings.Repeat("x", 33) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.mut(&cfg)
			if _, err := RenderConfig(cfg); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestSSIDIsBroadcast: a client looking for this network has to be able to see it.
func TestSSIDIsBroadcast(t *testing.T) {
	got, _ := RenderConfig(testConfig())
	if !strings.Contains(got, "ignore_broadcast_ssid=0") {
		t.Error("the rogue AP must broadcast its SSID")
	}
}

// TestNoKarmaOrKnownBeaconDirectives: the rogue AP beacons exactly one scoped ESSID.
//
// hostapd has no karma mode, but a future edit could add multiple bss blocks or a wildcard
// SSID. Pinning the generated config to exactly one ssid= line makes that visible.
func TestExactlyOneSSIDIsBeaconed(t *testing.T) {
	got, err := RenderConfig(testConfig())
	if err != nil {
		t.Fatalf("RenderConfig: %v", err)
	}

	var ssidLines int
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "ssid=") {
			ssidLines++
		}
	}
	if ssidLines != 1 {
		t.Errorf("config declares %d SSIDs; the rogue AP beacons exactly one scoped ESSID", ssidLines)
	}
	if strings.Contains(got, "bss=") {
		t.Error("config declares an additional BSS")
	}
}

// ---------------------------------------------------------------------------
// hostapd log parsing
// ---------------------------------------------------------------------------

func TestParseHostapdLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    string
		wantMAC string
	}{
		{
			name: "station connected", want: EventClientJoin,
			line:    "wlan1: AP-STA-CONNECTED de:ad:be:ef:00:01",
			wantMAC: "de:ad:be:ef:00:01",
		},
		{
			name: "station disconnected", want: EventClientLeave,
			line:    "wlan1: AP-STA-DISCONNECTED de:ad:be:ef:00:01",
			wantMAC: "de:ad:be:ef:00:01",
		},
		{
			name: "association", want: EventClientJoin,
			line:    "wlan1: STA de:ad:be:ef:00:02 IEEE 802.11: associated",
			wantMAC: "de:ad:be:ef:00:02",
		},
		{
			name: "error", want: EventError,
			line: "Could not set channel for kernel driver",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := parseHostapdLine(tc.line)
			if !ok {
				t.Fatalf("line not recognised: %q", tc.line)
			}
			if ev.Kind != tc.want {
				t.Errorf("Kind = %q, want %q", ev.Kind, tc.want)
			}
			if tc.wantMAC != "" && ev.MAC != tc.wantMAC {
				t.Errorf("MAC = %q, want %q", ev.MAC, tc.wantMAC)
			}
		})
	}

	if _, ok := parseHostapdLine("random noise"); ok {
		t.Error("an unremarkable line produced an event")
	}
}

func TestClientTracking(t *testing.T) {
	h := NewHostapd(t.TempDir(), nil)

	h.applyEvent(Event{Kind: EventClientJoin, MAC: "de:ad:be:ef:00:01"})
	h.applyEvent(Event{Kind: EventClientJoin, MAC: "de:ad:be:ef:00:02"})

	if got := len(h.Clients()); got != 2 {
		t.Fatalf("tracking %d clients, want 2", got)
	}

	// A repeated join must not duplicate.
	h.applyEvent(Event{Kind: EventClientJoin, MAC: "de:ad:be:ef:00:01"})
	if got := len(h.Clients()); got != 2 {
		t.Errorf("a repeated join duplicated a client: %d", got)
	}

	h.applyEvent(Event{Kind: EventClientLeave, MAC: "de:ad:be:ef:00:01"})
	clients := h.Clients()
	if len(clients) != 1 || clients[0].MAC != "de:ad:be:ef:00:02" {
		t.Errorf("clients after a disconnect = %+v", clients)
	}
}

func TestStartRejectsBadConfig(t *testing.T) {
	h := NewHostapd(t.TempDir(), nil)

	if err := h.Start(t.Context(), Config{Interface: "wlan1"}); err == nil {
		t.Error("started an access point with no ESSID")
	}
	if err := h.Start(t.Context(), Config{ESSID: "CORP"}); err == nil {
		t.Error("started an access point with no interface")
	}
}
