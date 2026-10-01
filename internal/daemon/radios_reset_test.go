package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/waffl3ss/warp/internal/rpc"
)

// TestRadioResetIsWiredAndGated: the reset RPC resolves an adapter by id or interface name, and with
// capture stopped and no jobs it reaches the USB check (the fake adapters are not USB-backed, so it
// stops there rather than power-cycling anything in a unit test). An unknown adapter is a not-found.
func TestRadioResetIsWiredAndGated(t *testing.T) {
	_, c := startDaemon(t, "CORP-WIFI")
	ctx := context.Background()

	// Unknown adapter.
	err := c.Call(ctx, "radios.reset", map[string]any{"radio_id": "phy9"}, nil)
	var rerr *rpc.Error
	if !errors.As(err, &rerr) || rerr.Code != rpc.CodeNotFound {
		t.Fatalf("reset of an unknown radio = %v, want not-found", err)
	}

	// Known adapter, idle (capture stopped, no jobs): passes the idle gates and stops at the USB
	// check because the fake adapter has no USB backing. Resolving by interface name must work too.
	for _, target := range []string{"phy0", "if-phy0"} {
		err = c.Call(ctx, "radios.reset", map[string]any{"radio_id": target}, nil)
		if err == nil {
			t.Fatalf("reset(%q) unexpectedly succeeded on a fake adapter", target)
		}
		if !strings.Contains(err.Error(), "not a USB adapter") {
			t.Errorf("reset(%q) = %v, want it to reach the USB-adapter check", target, err)
		}
	}
}
