package precheck

import (
	"context"
	"strings"
	"testing"

	"github.com/waffl3ss/warp/internal/radio"
)

func TestCheckAdaptersFailsWithNoRadios(t *testing.T) {
	c := checkAdapters(nil)
	if c.Level != Fail {
		t.Errorf("no adapters should be a blocker, got %s", c.Level)
	}
	if c.Fixable() {
		t.Error("missing hardware is not something WARP can fix")
	}
}

func TestCheckAdaptersListsWhatItFound(t *testing.T) {
	devs := []*radio.Device{
		{ID: "phy0", Ifname: "wlan0"},
		{ID: "phy1", Ifname: "wlan1"},
	}
	c := checkAdapters(devs)
	if c.Level != OK {
		t.Errorf("two adapters should be OK, got %s", c.Level)
	}
	if !strings.Contains(c.Detail, "wlan0") || !strings.Contains(c.Detail, "wlan1") {
		t.Errorf("detail should name the adapters: %q", c.Detail)
	}
}

func TestSupplicantAndNMChecksNeverPanic(t *testing.T) {
	// These shell out / read /proc; on any host they must return a well-formed Check, never panic.
	if c := checkSupplicants(context.Background()); c.Name != "supplicant" {
		t.Errorf("unexpected name %q", c.Name)
	}
	if c := checkNetworkManager(context.Background(), []string{"wlan0"}); c.Name != "networkmanager" {
		t.Errorf("unexpected name %q", c.Name)
	}
}

func TestRunReturnsEveryCheck(t *testing.T) {
	checks := Run(context.Background())
	want := map[string]bool{
		"privileges": false, "wireless adapters": false, "rfkill": false,
		"networkmanager": false, "supplicant": false,
	}
	for i := range checks {
		want[checks[i].Name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("Run did not include the %q check", name)
		}
	}
}

func TestLevelString(t *testing.T) {
	for l, s := range map[Level]string{OK: "ok", Warn: "warn", Fixable: "fixable", Fail: "fail", Info: "info"} {
		if got := l.String(); got != s {
			t.Errorf("Level(%d).String() = %q, want %q", l, got, s)
		}
	}
}
